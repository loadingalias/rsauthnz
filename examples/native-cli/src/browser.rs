//! A browser approves the CLI key. Later calls use the same key and the saved account binding.
//!
//! By default the CLI listens on the loopback interface, opens the approval page in the browser of this computer, and
//! takes the one-use redirect code that the browser brings after the approval. With `--device-code`, the CLI polls
//! with its device code alone, for a browser on another computer.

use core::time::Duration;
use std::ffi::{OsStr, OsString};
use std::fs::{self, File};
use std::io::{self, IsTerminal as _, Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};

use bytes::Bytes;
use http::{Request, header};
use rsauthnz::agent::{DeviceCode, Loopback, RedirectCode, UserCode};
use rsauthnz::cbor::{self, Value};
use rsauthnz::cli::{self, Call, Challenge};
use rsauthnz::credential::Serial;
use rsauthnz::id::Id;
use rsauthnz::limits::Limits;
use rsauthnz::local::enroll::{CliId, ENROLLMENT_LIFETIME};
use rsauthnz::transition::OperationId;
use rscodec::base64::Profile::Url;
use rscrypto::{ChaCha20Rng, Sha256};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;
use tokio::time::{Instant, error::Elapsed, sleep_until, timeout, timeout_at};

use super::{Failure, clock, keys::Keys};

const BODY_MAX: usize = 16 * 1024;
const POLL_INTERVAL: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const USAGE: &str = "Use native-cli enroll DIRECTORY NAME [PORT] [--device-code] or native-cli status DIRECTORY.";
/// The path of the loopback address of the CLI.
const LOOPBACK_PATH: &str = "/approved";
/// The most bytes of the request head that the listener reads.
const HEAD_BYTES_MAX: usize = 8 * 1024;
/// The most connections with no request that the listener takes, such as a connection that a browser opens early.
const CONNECTIONS_MAX: usize = 8;

/// How the CLI learns of the approval.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Flow {
    /// The browser of this computer brings the redirect code to the listener of the CLI.
    Loopback,
    /// The CLI polls with its device code, for a browser on another computer.
    DeviceCode,
}

pub(super) fn run(
    command: &OsStr,
    mut args: impl Iterator<Item = OsString>,
    mut random: ChaCha20Rng,
) -> Result<(), Failure> {
    let directory = args.next().ok_or(USAGE)?;
    let directory = Path::new(&directory);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()?;
    match command.to_str() {
        Some("enroll") => {
            let name = args.next().ok_or(USAGE)?;
            let name = name.to_str().ok_or("the device name needs UTF-8 text")?;
            let (mut port, mut flow) = (None, Flow::Loopback);
            for arg in args {
                match arg.to_str().ok_or(USAGE)? {
                    "--device-code" if flow == Flow::Loopback => flow = Flow::DeviceCode,
                    text if port.is_none() => {
                        port = Some(text.parse::<u16>().ok().filter(|port| *port != 0).ok_or(USAGE)?)
                    }
                    _ => return Err(USAGE.into()),
                }
            }
            runtime.block_on(enroll(directory, name, port.unwrap_or(8080), flow, &mut random))
        }
        Some("status") if args.next().is_none() => {
            let saved = read(directory, "binding")?;
            let Value::Array(fields) = decode(&saved)? else {
                return Err("invalid CLI binding".into());
            };
            let [Value::Unsigned(port), account, Value::Unsigned(serial)] = fields.as_slice() else {
                return Err("invalid CLI binding".into());
            };
            let id = CliId {
                account: Id::from_cbor(account)?,
                serial: Serial(*serial),
            };
            let keys = Keys::open(directory, "holder", &mut random)?;
            runtime.block_on(async {
                let mut client = Client::connect(u16::try_from(*port)?).await?;
                let credential = match read(directory, "credential") {
                    Ok(credential) => credential,
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {
                        recover(&mut client, directory, &id, &keys).await?
                    }
                    Err(error) => return Err(error.into()),
                };
                status(&mut client, &keys, &id, &credential, &mut random).await
            })
        }
        _ => Err(USAGE.into()),
    }
}

/// A connection serves the polls and the signed call. A fresh connection can look up a lost finish.
struct Client {
    port: u16,
    sender: h2::client::SendRequest<Bytes>,
}

impl Client {
    async fn connect(port: u16) -> Result<Self, Failure> {
        timeout(REQUEST_TIMEOUT, async {
            let tcp = tokio::net::TcpStream::connect((core::net::Ipv4Addr::LOCALHOST, port)).await?;
            let (sender, connection) = h2::client::handshake(tcp).await?;
            tokio::spawn(connection);
            Ok(Self { port, sender })
        })
        .await?
    }

    async fn post(&mut self, path: &str, fields: Vec<Value<'_>>) -> Result<Vec<u8>, Failure> {
        let bytes = cbor::encode(&Value::Array(fields), Limits::default())?;
        let request = Request::post(format!("http://localhost:{}/cli/{path}", self.port))
            .header(header::CONTENT_TYPE, "application/cbor")
            .body(())?;
        timeout(REQUEST_TIMEOUT, async {
            let mut sender = self.sender.clone().ready().await?;
            let (reply, mut stream) = sender.send_request(request, false)?;
            stream.send_data(bytes.into(), true)?;
            let reply = reply.await?;
            let status = reply.status();
            let mut body = reply.into_body();
            let mut bytes = Vec::new();
            while let Some(chunk) = body.data().await {
                let chunk = chunk?;
                if chunk.len() > BODY_MAX - bytes.len() {
                    return Err("the response exceeds the size limit".into());
                }
                bytes.extend_from_slice(&chunk);
                body.flow_control().release_capacity(chunk.len())?;
            }
            if !status.is_success() {
                return Err(format!("the authority refused {path} (HTTP {status})").into());
            }
            Ok(bytes)
        })
        .await?
    }
}

fn decode(bytes: &[u8]) -> Result<Value<'_>, Failure> {
    Ok(cbor::decode(bytes, Limits::default())?)
}

fn content(bytes: &[u8]) -> Result<&[u8], Failure> {
    match decode(bytes)? {
        Value::Bytes(content) => Ok(content),
        _ => Err("expected a byte string from the authority".into()),
    }
}

/// Read one bounded file from the private directory.
fn read(directory: &Path, name: &str) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(directory.join(name))?
        .take((BODY_MAX + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > BODY_MAX {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the CLI file exceeds the size limit",
        ));
    }
    Ok(bytes)
}

/// Publish the complete file in the same directory. Only the first enrollment can publish its binding.
fn save(directory: &Path, name: &str, bytes: &[u8]) -> io::Result<()> {
    let pending = directory.join(format!("{name}.{}.tmp", std::process::id()));
    let mut file = File::create_new(&pending)?;
    let result = (|| {
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        match fs::hard_link(&pending, directory.join(name)) {
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists && name == "credential" => {}
            other => other?,
        }
        #[cfg(unix)]
        File::open(directory)?.sync_all()?;
        Ok(())
    })();
    fs::remove_file(pending)?;
    result
}

#[expect(
    clippy::print_stdout,
    reason = "the CLI shows the code, the key fingerprint, and the approving account"
)]
async fn enroll(directory: &Path, name: &str, port: u16, flow: Flow, random: &mut ChaCha20Rng) -> Result<(), Failure> {
    if directory.join("binding").try_exists()? {
        return Err("this directory already has an approval. Run native-cli status with this directory.".into());
    }
    let mut client = Client::connect(port).await?;
    let keys = Keys::open(directory, "holder", random)?;
    let public = keys.handle.public_key();
    // The listener starts before the request, so that the request names its address. The OS chooses the port.
    let listener = match flow {
        Flow::Loopback => Some(TcpListener::bind((core::net::Ipv4Addr::LOCALHOST, 0)).await?),
        Flow::DeviceCode => None,
    };
    let loopback = match &listener {
        Some(listener) => {
            let port = listener.local_addr()?.port();
            Some(Loopback::parse(&format!("http://127.0.0.1:{port}{LOOPBACK_PATH}"))?)
        }
        None => None,
    };
    let deadline = Instant::now() + ENROLLMENT_LIFETIME;
    let address = loopback
        .as_ref()
        .map_or(Value::Null, |loopback| Value::Text(loopback.as_str()));
    let response = client
        .post("enroll", vec![Value::Text(name), Value::Bytes(&public), address])
        .await?;
    let Value::Array(fields) = decode(&response)? else {
        return Err("invalid enrollment response".into());
    };
    let [Value::Text(code), Value::Bytes(device)] = fields.as_slice() else {
        return Err("invalid enrollment response".into());
    };
    let code = UserCode::parse(code)?.text();
    let device = DeviceCode::from_bytes((*device).try_into()?);
    let fingerprint = Sha256::digest(&public);
    let mut text = [0; 43];
    Url.encode(&fingerprint, &mut text)?;
    let page = match flow {
        Flow::Loopback => format!("http://localhost:{port}/cli?code={code}"),
        Flow::DeviceCode => format!("http://localhost:{port}/cli"),
    };
    println!("Open {page}");
    println!("User code {code}");
    println!("Key fingerprint {}", str::from_utf8(&text)?);
    io::stdout().flush()?;
    let redirect = match listener {
        Some(listener) => {
            // A run with no terminal, such as a script, prints the address and opens no browser.
            if io::stdout().is_terminal()
                && let Err(error) = open(&page)
            {
                println!("The browser did not open ({error}). Open the address in a browser on this computer.");
            }
            Some(receive(listener, deadline).await?)
        }
        None => None,
    };
    let (id, name) = approval(&mut client, &code, &device, redirect.as_ref(), deadline).await?;
    let binding = cbor::encode(
        &Value::Array(vec![
            Value::Unsigned(u64::from(port)),
            id.account.to_cbor(),
            Value::Unsigned(id.serial.0),
        ]),
        Limits::default(),
    )?;
    save(directory, "binding", &binding)?;
    println!("Approved account {name} ({})", id.account);
    let reply = client
        .post(
            "finish",
            vec![
                Value::Text(&code),
                Value::Bytes(device.as_bytes()),
                id.account.to_cbor(),
                code_value(redirect.as_ref()),
            ],
        )
        .await;
    let credential = match reply.as_deref().ok().and_then(|bytes| content(bytes).ok()) {
        Some(credential) => {
            save(directory, "credential", credential)?;
            credential.to_vec()
        }
        None => {
            client = Client::connect(port).await?;
            recover(&mut client, directory, &id, &keys).await?
        }
    };
    status(&mut client, &keys, &id, &credential, random).await
}

/// The redirect code of a loopback request, or null.
fn code_value(redirect: Option<&RedirectCode>) -> Value<'_> {
    redirect.map_or(Value::Null, |redirect| Value::Bytes(redirect.as_bytes()))
}

/// Opens `address` in the default browser of this computer. The CLI does not wait for the browser.
fn open(address: &str) -> io::Result<()> {
    let (program, arguments): (&str, &[&str]) = cfg_select! {
        target_os = "macos" => ("open", &[]),
        windows => ("rundll32", &["url.dll,FileProtocolHandler"]),
        _ => ("xdg-open", &[]),
    };
    let mut child = Command::new(program)
        .args(arguments)
        .arg(address)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    // An opener can wait for the browser to close, so a thread reaps it, and the CLI goes on.
    std::thread::spawn(move || drop(child.wait()));
    Ok(())
}

/// The redirect code that the browser brings to `listener`. The listener answers the first request and closes, so it
/// takes one request. A connection that closes, or sends nothing within `REQUEST_TIMEOUT`, does not count. The listener
/// ends at `deadline`.
async fn receive(listener: TcpListener, deadline: Instant) -> Result<RedirectCode, Failure> {
    for _ in 0..CONNECTIONS_MAX {
        let (mut stream, _) = timeout_at(deadline, listener.accept()).await.map_err(
            |_| "the approval did not reach the CLI before the end of the request. Start enrollment again.",
        )??;
        let until = deadline.min(Instant::now() + REQUEST_TIMEOUT);
        let mut head = vec![0; HEAD_BYTES_MAX];
        let mut len = 0;
        // Read the complete head, so that the close after the answer resets no connection that has unread bytes.
        while len < head.len() && !head[..len].ends_with(b"\r\n\r\n") {
            match timeout_at(until, stream.read(&mut head[len..])).await {
                Ok(Ok(read)) if read > 0 => len += read,
                _ => break,
            }
        }
        if len == 0 {
            continue;
        }
        let code = redirect_code(&head[..len]);
        let (status, text) = match code {
            Some(_) => ("200 OK", "Approved. Return to your terminal."),
            None => (
                "400 Bad Request",
                "This address takes only the redirect of an approval.",
            ),
        };
        let answer = format!(
            "HTTP/1.1 {status}\r\nContent-Type: text/plain; charset=utf-8\r\nCache-Control: no-store\r\n\
             Connection: close\r\nContent-Length: {}\r\n\r\n{text}",
            text.len()
        );
        // The answer only informs the human. The CLI goes on after a failed write.
        drop(
            timeout_at(until, async {
                stream.write_all(answer.as_bytes()).await?;
                stream.shutdown().await
            })
            .await,
        );
        return code.ok_or_else(|| "the browser brought no redirect code. Start enrollment again.".into());
    }
    Err("the listener had too many connections with no request. Start enrollment again.".into())
}

/// The redirect code of the request line `GET /approved?code=<base64url> HTTP/1.1` at the start of `head`.
fn redirect_code(head: &[u8]) -> Option<RedirectCode> {
    let line = head.split(|byte| *byte == b'\r').next()?;
    let (method, rest) = line.split_once(|byte| *byte == b' ')?;
    let (target, _) = rest.split_once(|byte| *byte == b' ')?;
    let code = target.strip_prefix(format!("{LOOPBACK_PATH}?code=").as_bytes())?;
    (method == b"GET" && Url.decoded_len(code).ok()? == 32).then_some(())?;
    let mut bytes = [0; 32];
    Url.decode(code, &mut bytes).ok()?;
    Some(RedirectCode::from_bytes(bytes))
}

/// Poll once more at the deadline. The authority can accept approval during the last sleep. A loopback CLI polls once,
/// with the redirect code of the approval.
async fn approval(
    client: &mut Client,
    code: &str,
    device: &DeviceCode,
    redirect: Option<&RedirectCode>,
    deadline: Instant,
) -> Result<(CliId, String), Failure> {
    let fields = || vec![Value::Text(code), Value::Bytes(device.as_bytes()), code_value(redirect)];
    loop {
        let final_poll = Instant::now() >= deadline;
        let response = match client.post("poll", fields()).await {
            Err(error) if error.is::<h2::Error>() || error.is::<Elapsed>() => {
                sleep_until((Instant::now() + POLL_INTERVAL).min(deadline)).await;
                *client = Client::connect(client.port).await?;
                client.post("poll", fields()).await?
            }
            result => result?,
        };
        match decode(&response)? {
            Value::Null if final_poll => return Err("the approval code expired. Start enrollment again.".into()),
            Value::Null => sleep_until((Instant::now() + POLL_INTERVAL).min(deadline)).await,
            Value::Array(fields) => {
                let [account, Value::Unsigned(serial), Value::Text(name)] = fields.as_slice() else {
                    return Err("invalid approval".into());
                };
                return Ok((
                    CliId {
                        account: Id::from_cbor(account)?,
                        serial: Serial(*serial),
                    },
                    (*name).to_owned(),
                ));
            }
            _ => return Err("invalid poll response".into()),
        }
    }
}

fn binding<'a>(id: &'a CliId, public: &'a [u8]) -> Vec<Value<'a>> {
    vec![id.account.to_cbor(), Value::Unsigned(id.serial.0), Value::Bytes(public)]
}

async fn recover(client: &mut Client, directory: &Path, id: &CliId, keys: &Keys) -> Result<Vec<u8>, Failure> {
    let response = client
        .post("credential", binding(id, &keys.handle.public_key()))
        .await
        .map_err(|error| {
            format!("{error}. Check the saved binding with native-cli status. A new enrollment needs a fresh approval.")
        })?;
    let credential = content(&response)?;
    save(directory, "credential", credential)?;
    Ok(credential.to_vec())
}

#[expect(
    clippy::print_stdout,
    reason = "the CLI prints the account of its admitted status call"
)]
async fn status(
    client: &mut Client,
    keys: &Keys,
    id: &CliId,
    credential: &[u8],
    random: &mut ChaCha20Rng,
) -> Result<(), Failure> {
    let response = client.post("challenge", binding(id, &keys.handle.public_key())).await?;
    let challenge: [u8; 32] = content(&response)?.try_into()?;
    let mut operation = [0; 32];
    random.fill_bytes(&mut operation);
    let call = Call::new(
        Challenge::from_bytes(challenge),
        OperationId::new(&operation)?,
        &Value::Text("status"),
        Limits::default(),
    )?;
    let proof = cli::prove(
        &keys.custody,
        &keys.handle,
        credential,
        &Id::new("web", "app")?,
        &call,
        clock(),
        random,
    )?;
    let response = client
        .post(
            "status",
            vec![
                Value::Bytes(credential),
                Value::Bytes(&proof),
                Value::Bytes(&challenge),
                Value::Bytes(&operation),
            ],
        )
        .await?;
    if Id::from_cbor(&decode(&response)?)? != id.account {
        return Err("the admitted account differs from the approved account".into());
    }
    println!("Status admitted for {}", id.account);
    Ok(())
}

#[cfg(test)]
mod tests {
    use core::net::Ipv4Addr;
    use core::time::Duration;

    use rscodec::base64::Profile::Url;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::time::Instant;

    use super::receive;

    /// A connection that closes with no request does not count. The listener answers the first request, and then
    /// closes: a later connection refuses, so no second request can bring another code.
    #[tokio::test]
    async fn the_listener_takes_one_request_and_then_refuses_connections() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let mut text = [0; 43];
        Url.encode(&[7; 32], &mut text).unwrap();
        let request = format!(
            "GET /approved?code={} HTTP/1.1\r\nHost: {address}\r\n\r\n",
            str::from_utf8(&text).unwrap()
        );
        let browser = async {
            drop(TcpStream::connect(address).await.unwrap());
            let mut stream = TcpStream::connect(address).await.unwrap();
            stream.write_all(request.as_bytes()).await.unwrap();
            let mut answer = String::new();
            stream.read_to_string(&mut answer).await.unwrap();
            answer
        };
        let (received, answer) = tokio::join!(receive(listener, Instant::now() + Duration::from_secs(30)), browser);
        assert!(answer.starts_with("HTTP/1.1 200 OK\r\n"), "{answer}");
        assert_eq!(received.unwrap().as_bytes(), &[7; 32]);
        TcpStream::connect(address).await.unwrap_err();
    }

    /// With no request, the listener ends at its deadline, and then refuses connections.
    #[tokio::test]
    async fn the_listener_ends_at_its_deadline() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let deadline = Instant::now() + Duration::from_millis(200);
        receive(listener, deadline).await.unwrap_err();
        assert!(Instant::now() >= deadline);
        TcpStream::connect(address).await.unwrap_err();
    }
}
