//! A browser approves the CLI key. Later calls use the same key and the saved account binding.

use core::time::Duration;
use std::ffi::{OsStr, OsString};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::Path;

use bytes::Bytes;
use http::{Request, header};
use rsauthnz::cbor::{self, Value};
use rsauthnz::cli::{self, Call, Challenge};
use rsauthnz::credential::Serial;
use rsauthnz::id::Id;
use rsauthnz::limits::Limits;
use rsauthnz::local::enroll::{CliId, DeviceCode, ENROLLMENT_LIFETIME, UserCode};
use rsauthnz::transition::OperationId;
use rscodec::base64::Profile::Url;
use rscrypto::{ChaCha20Rng, Sha256};
use tokio::time::{Instant, error::Elapsed, sleep_until, timeout};

use super::{Failure, clock, keys::Keys};

const BODY_MAX: usize = 16 * 1024;
const POLL_INTERVAL: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const USAGE: &str = "Use native-cli enroll DIRECTORY NAME [PORT] or native-cli status DIRECTORY.";

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
            let port = args.next().map_or(Ok(8080), |port| {
                port.to_str().ok_or(USAGE)?.parse::<u16>().map_err(|_| USAGE)
            })?;
            if args.next().is_some() || port == 0 {
                return Err(USAGE.into());
            }
            runtime.block_on(enroll(directory, name, port, &mut random))
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
async fn enroll(directory: &Path, name: &str, port: u16, random: &mut ChaCha20Rng) -> Result<(), Failure> {
    if directory.join("binding").try_exists()? {
        return Err("this directory already has an approval. Run native-cli status with this directory.".into());
    }
    let mut client = Client::connect(port).await?;
    let keys = Keys::open(directory, "holder", random)?;
    let public = keys.handle.public_key();
    let response = client
        .post("enroll", vec![Value::Text(name), Value::Bytes(&public)])
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
    println!("Open http://localhost:{port}/cli");
    println!("User code {code}");
    println!("Key fingerprint {}", str::from_utf8(&text)?);
    io::stdout().flush()?;
    let (id, name) = approval(&mut client, &code, &device).await?;
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

/// Poll once more at the deadline. The authority can accept approval during the last sleep.
async fn approval(client: &mut Client, code: &str, device: &DeviceCode) -> Result<(CliId, String), Failure> {
    let fields = || vec![Value::Text(code), Value::Bytes(device.as_bytes())];
    let deadline = Instant::now() + ENROLLMENT_LIFETIME;
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
        clock()?,
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
