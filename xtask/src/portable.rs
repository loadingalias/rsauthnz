//! `cargo xtask portable`: the portable core in a dedicated browser Worker in Chrome, Firefox, and Safari, and its
//! builds for iOS and Android (docs/content/portable-core.md).
//!
//! The command builds the consumer `xtask/portable` for `wasm32-unknown-unknown` and checks the module: no import,
//! no shared memory, and its two exports. It checks the crates and the features of the closure, runs the native test,
//! and builds the consumer for each mobile target. Then it serves the page, the Worker, and the module on a loopback
//! port, runs each browser with a temporary profile, and compares the report of each browser with
//! `xtask/portable/report.txt`. Chrome and Firefox run headless with no driver. Safari has no headless mode, so the
//! command opens one session of the system `safaridriver`, which needs `safaridriver --enable` once.

use core::net::Ipv4Addr;
use core::time::Duration;
use std::collections::HashMap;
use std::fs;
use std::io::{self, Read as _, Write as _};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::thread;
use std::time::Instant;

use super::{Failure, Repo, step};

/// The expected report of each host.
const EXPECTED: &str = include_str!("../portable/report.txt");
/// The page and the dedicated Worker.
const PAGE: &str = include_str!("../portable/www/index.html");
const WORKER: &str = include_str!("../portable/www/worker.js");

/// The crates of the closure of the consumer on `wasm32-unknown-unknown`. A new crate fails the check until it is
/// reviewed and added here.
const CLOSURE: [&str; 6] = [
    "rsauthnz",
    "rsauthnz-conformance",
    "rsauthnz-portable",
    "rscodec",
    "rscrypto",
    "rstypes",
];

/// The mobile targets, which build and run nothing.
const MOBILE: [&str; 2] = ["aarch64-apple-ios", "aarch64-linux-android"];

/// The exports of the module: its memory and the two functions of the Worker.
const EXPORTS: [&str; 3] = ["memory", "rsauthnz_portable_report", "rsauthnz_portable_run"];

/// The time from the start of a browser to its report.
const REPORT_TIMEOUT: Duration = Duration::from_secs(180);

/// The time from the start of `safaridriver` to its port.
const DRIVER_TIMEOUT: Duration = Duration::from_secs(20);

/// The most bytes of a request to the server: the report of a browser has some hundred.
const REQUEST_BYTES_MAX: usize = 64 * 1024;

/// The reports that the server received, by the name of the browser.
type Reports = Arc<(Mutex<HashMap<String, String>>, Condvar)>;

impl Repo {
    /// Runs each check of the portable core. It takes no arguments.
    pub(super) fn portable(&self, args: &[String]) -> Result<(), Failure> {
        if let Some(arg) = args.first() {
            return Err(Failure::new(format!("portable takes no arguments, not `{arg}`")));
        }
        step(
            "wasm32",
            // Only the module is a cdylib: a cdylib on another target, such as the musl target of CI, is dropped
            // with a warning.
            &mut self.cargo(&[
                "rustc",
                "--locked",
                "--release",
                "--quiet",
                "-p",
                "rsauthnz-portable",
                "--lib",
                "--target",
                "wasm32-unknown-unknown",
                "--crate-type",
                "cdylib",
            ]),
        )?;
        let module = self
            .root
            .join("target/wasm32-unknown-unknown/release/rsauthnz_portable.wasm");
        let wasm = fs::read(&module).map_err(|error| Failure::new(format!("{}: {error}", module.display())))?;
        eprintln!("── module");
        check_module(&wasm)?;
        eprintln!(
            "   ok: {} bytes, no import, no shared memory, exports {}",
            wasm.len(),
            EXPORTS.join(", ")
        );
        self.closure()?;
        step(
            "native",
            &mut self.cargo(&["nextest", "run", "--locked", "-p", "rsauthnz-portable"]),
        )?;
        for target in MOBILE {
            step(
                target,
                &mut self.cargo(&[
                    "build",
                    "--locked",
                    "--quiet",
                    "-p",
                    "rsauthnz-portable",
                    "--lib",
                    "--target",
                    target,
                ]),
            )?;
        }
        self.browsers(wasm)
    }

    /// Checks that the closure of the consumer on `wasm32-unknown-unknown` has exactly the crates of [`CLOSURE`], and
    /// that the core has no native custody, and prints each crate with its features.
    fn closure(&self) -> Result<(), Failure> {
        eprintln!("── closure");
        let output = self
            .cargo(&[
                "tree",
                "--locked",
                "-p",
                "rsauthnz-portable",
                "--target",
                "wasm32-unknown-unknown",
                "-e",
                "normal",
                "--prefix",
                "none",
                "--no-dedupe",
                "--format",
                "{p} [{f}]",
            ])
            .output()
            .map_err(|error| Failure::new(format!("closure: cannot start cargo tree: {error}")))?;
        if !output.status.success() {
            return Err(Failure::new(format!(
                "closure: cargo tree failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }
        let text = String::from_utf8_lossy(&output.stdout);
        for line in check_closure(&text)? {
            eprintln!("   {line}");
        }
        Ok(())
    }

    /// Serves the page, the Worker, and `wasm`, and runs each browser.
    fn browsers(&self, wasm: Vec<u8>) -> Result<(), Failure> {
        let listener =
            TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(|error| Failure::new(format!("serve: {error}")))?;
        let port = listener
            .local_addr()
            .map_err(|error| Failure::new(format!("serve: {error}")))?
            .port();
        let reports: Reports = Arc::default();
        let served = Arc::clone(&reports);
        thread::spawn(move || serve(&listener, &wasm, &served));
        let profiles = self.root.join("target/portable");
        let mut failed = Vec::new();
        for browser in [Browser::Chrome, Browser::Firefox, Browser::Safari] {
            let name = browser.name();
            eprintln!("── {name}");
            let started = Instant::now();
            let url = format!("http://127.0.0.1:{port}/?browser={name}");
            let profile = profiles.join(name);
            let result = browser
                .run(&url, &profile, &reports)
                .and_then(|(report, version)| compare(name, &report).map(|agent| format!("{version}; {agent}")));
            if let Err(error) = fs::remove_dir_all(&profile)
                && error.kind() != io::ErrorKind::NotFound
            {
                return Err(Failure::new(format!("{}: {error}", profile.display())));
            }
            match result {
                Ok(agent) => eprintln!("   ok in {:.2}s: {agent}", started.elapsed().as_secs_f64()),
                Err(failure) => {
                    eprintln!("   FAIL: {}", failure.message);
                    failed.push(name);
                }
            }
        }
        // The parent of the profiles is empty after the last browser.
        if let Err(error) = fs::remove_dir(&profiles)
            && error.kind() != io::ErrorKind::NotFound
        {
            return Err(Failure::new(format!("{}: {error}", profiles.display())));
        }
        if failed.is_empty() {
            Ok(())
        } else {
            Err(Failure::new(format!(
                "portable: {} did not give the expected report",
                failed.join(", ")
            )))
        }
    }
}

/// Checks the output `text` of `cargo tree --format "{p} [{f}]"`: its crates are exactly those of [`CLOSURE`], and the
/// core has no `native-custody` feature. It gives each distinct line, in order.
fn check_closure(text: &str) -> Result<Vec<&str>, Failure> {
    let mut lines: Vec<&str> = text.lines().filter(|line| !line.is_empty()).collect();
    lines.sort_unstable();
    lines.dedup();
    let mut names: Vec<&str> = lines
        .iter()
        .filter_map(|line| line.split_once(' ').map(|(name, _)| name))
        .collect();
    names.dedup();
    if names != CLOSURE {
        return Err(Failure::new(format!(
            "closure: the crates are {names:?}, not {CLOSURE:?}; review each new crate"
        )));
    }
    let core = lines
        .iter()
        .find(|line| line.starts_with("rsauthnz v"))
        .ok_or_else(|| Failure::new("closure: no rsauthnz".to_owned()))?;
    if core.contains("native-custody") {
        return Err(Failure::new(format!("closure: the core has native custody: {core}")));
    }
    Ok(lines)
}

/// Checks the WebAssembly `module`: a version 1 binary with no import, a memory that is not shared, and exactly the
/// exports of [`EXPORTS`].
fn check_module(module: &[u8]) -> Result<(), Failure> {
    let fail = |cause: &str| Failure::new(format!("module: {cause}"));
    let rest = module
        .strip_prefix(b"\0asm\x01\0\0\0")
        .ok_or_else(|| fail("not a WebAssembly binary of version 1"))?;
    let mut exports = Vec::new();
    let mut at = 0;
    while at < rest.len() {
        let id = rest[at];
        let (size, start) = leb(rest, at + 1).ok_or_else(|| fail("a section has no size"))?;
        let end = start
            .checked_add(size)
            .filter(|end| *end <= rest.len())
            .ok_or_else(|| fail("a section passes the end"))?;
        let section = &rest[start..end];
        match id {
            2 => return Err(fail("it has an import section")),
            5 => {
                // The flags of the first memory: bit 1 marks a shared memory.
                let flags = *section.get(1).ok_or_else(|| fail("an empty memory section"))?;
                if flags & 0x02 != 0 {
                    return Err(fail("its memory is shared"));
                }
            }
            7 => {
                let (count, mut cursor) = leb(section, 0).ok_or_else(|| fail("an export section has no count"))?;
                for _ in 0..count {
                    let (len, name) = leb(section, cursor).ok_or_else(|| fail("an export has no name"))?;
                    let after = name
                        .checked_add(len)
                        .filter(|after| *after <= section.len())
                        .ok_or_else(|| fail("an export name passes the end"))?;
                    exports.push(String::from_utf8_lossy(&section[name..after]).into_owned());
                    // The kind byte, then the index.
                    let (_, next) = leb(section, after + 1).ok_or_else(|| fail("an export has no index"))?;
                    cursor = next;
                }
            }
            _ => {}
        }
        at = end;
    }
    exports.sort_unstable();
    if exports != EXPORTS {
        return Err(fail(&format!("its exports are {exports:?}, not {EXPORTS:?}")));
    }
    Ok(())
}

/// The unsigned LEB128 value at `at` in `bytes`, and the offset after it.
fn leb(bytes: &[u8], at: usize) -> Option<(usize, usize)> {
    let mut value = 0_usize;
    for (index, byte) in bytes.get(at..)?.iter().take(5).enumerate() {
        value |= usize::from(byte & 0x7f) << (7 * index);
        if byte & 0x80 == 0 {
            return Some((value, at + index + 1));
        }
    }
    None
}

/// Compares the report of the browser `name`, after its first line with its user agent, with [`EXPECTED`]. It gives
/// the user agent.
fn compare(name: &str, report: &str) -> Result<String, Failure> {
    let (agent, body) = report.split_once('\n').unwrap_or((report, ""));
    if body == EXPECTED {
        return Ok(agent.to_owned());
    }
    let mut diff = format!("{name} ({agent}) gave another report:");
    for (expected, line) in EXPECTED.lines().zip(body.lines().chain(core::iter::repeat(""))) {
        if expected != line {
            diff.push_str(&format!("\n     expected: {expected}\n     got:      {line}"));
        }
    }
    for extra in body.lines().skip(EXPECTED.lines().count()) {
        diff.push_str(&format!("\n     extra:    {extra}"));
    }
    Err(Failure::new(diff))
}

/// A browser of the profile.
#[derive(Clone, Copy)]
enum Browser {
    Chrome,
    Firefox,
    Safari,
}

impl Browser {
    const fn name(self) -> &'static str {
        match self {
            Self::Chrome => "chrome",
            Self::Firefox => "firefox",
            Self::Safari => "safari",
        }
    }

    /// Opens `url` with the temporary profile `profile`, and gives the report that the server receives and the version
    /// of the browser. It stops the browser after the report or the timeout.
    fn run(self, url: &str, profile: &Path, reports: &Reports) -> Result<(String, String), Failure> {
        fs::create_dir_all(profile).map_err(|error| Failure::new(format!("{}: {error}", profile.display())))?;
        match self {
            Self::Chrome => {
                let program = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
                let version = version(program)?;
                let mut command = Command::new(program);
                command
                    .arg("--headless=new")
                    .arg(dir_arg("--user-data-dir=", profile))
                    .args(["--no-first-run", "--no-default-browser-check", url]);
                with_child(command, |_| wait_report(reports, self.name())).map(|report| (report, version))
            }
            Self::Firefox => {
                let program = "/Applications/Firefox.app/Contents/MacOS/firefox";
                let version = version(program)?;
                let mut command = Command::new(program);
                command
                    .args(["--headless", "--no-remote", "--profile"])
                    .arg(profile)
                    .arg(url);
                with_child(command, |_| wait_report(reports, self.name())).map(|report| (report, version))
            }
            Self::Safari => {
                let port = free_port()?;
                let mut command = Command::new("/usr/bin/safaridriver");
                command.args(["--port", &port.to_string()]);
                with_child(command, |_| {
                    wait_port(port)?;
                    let created = webdriver(
                        port,
                        "POST",
                        "/session",
                        r#"{"capabilities":{"alwaysMatch":{"browserName":"safari"}}}"#,
                    )?;
                    let session = json_string(&created, "sessionId")
                        .ok_or_else(|| Failure::new(format!("safaridriver gave no session: {created}")))?;
                    let version = format!(
                        "Safari {}",
                        json_string(&created, "browserVersion").unwrap_or("of no version")
                    );
                    let path = format!("/session/{session}");
                    let report = webdriver(port, "POST", &format!("{path}/url"), &format!(r#"{{"url":"{url}"}}"#))
                        .and_then(|_| wait_report(reports, self.name()));
                    let closed = webdriver(port, "DELETE", &path, "");
                    let report = report?;
                    closed?;
                    Ok((report, version))
                })
            }
        }
    }
}

/// The output of `program --version`, such as `Google Chrome 158.0.8127.37`.
fn version(program: &str) -> Result<String, Failure> {
    let output = Command::new(program)
        .arg("--version")
        .stdin(Stdio::null())
        .output()
        .map_err(|error| Failure::new(format!("cannot start {program}: {error}")))?;
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

/// The argument `prefix` and the path `dir`.
fn dir_arg(prefix: &str, dir: &Path) -> std::ffi::OsString {
    let mut arg = std::ffi::OsString::from(prefix);
    arg.push(dir);
    arg
}

/// Starts `command` with no output, runs `work`, and then stops the process and waits for it.
fn with_child<T>(mut command: Command, work: impl FnOnce(&mut Child) -> Result<T, Failure>) -> Result<T, Failure> {
    let program = PathBuf::from(command.get_program());
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| Failure::new(format!("cannot start {}: {error}", program.display())))?;
    let result = work(&mut child);
    let stopped = child.kill().and_then(|()| child.wait());
    let result = result?;
    stopped.map_err(|error| Failure::new(format!("cannot stop {}: {error}", program.display())))?;
    Ok(result)
}

/// Waits until the server has the report of `browser`, or the timeout.
fn wait_report(reports: &Reports, browser: &str) -> Result<String, Failure> {
    let (map, arrived) = &**reports;
    let deadline = Instant::now() + REPORT_TIMEOUT;
    let mut map = map.lock().unwrap_or_else(PoisonError::into_inner);
    loop {
        if let Some(report) = map.remove(browser) {
            return Ok(report);
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(Failure::new(format!(
                "{browser} gave no report in {}s",
                REPORT_TIMEOUT.as_secs()
            )));
        }
        map = arrived
            .wait_timeout(map, left)
            .unwrap_or_else(PoisonError::into_inner)
            .0;
    }
}

/// A free loopback port.
fn free_port() -> Result<u16, Failure> {
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .and_then(|listener| listener.local_addr())
        .map(|address| address.port())
        .map_err(|error| Failure::new(format!("no free port: {error}")))
}

/// Waits until a server listens on `port`, or the timeout.
fn wait_port(port: u16) -> Result<(), Failure> {
    let deadline = Instant::now() + DRIVER_TIMEOUT;
    while TcpStream::connect((Ipv4Addr::LOCALHOST, port)).is_err() {
        if Instant::now() >= deadline {
            return Err(Failure::new(format!(
                "safaridriver did not listen in {}s; run `safaridriver --enable` once",
                DRIVER_TIMEOUT.as_secs()
            )));
        }
        thread::sleep(Duration::from_millis(100));
    }
    Ok(())
}

/// Sends one W3C WebDriver request to the driver on `port`, and gives the body of a 200 response.
fn webdriver(port: u16, method: &str, path: &str, body: &str) -> Result<String, Failure> {
    let fail = |error: io::Error| Failure::new(format!("safaridriver {method} {path}: {error}"));
    let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).map_err(fail)?;
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .map_err(fail)?;
    let mut response = String::new();
    stream.read_to_string(&mut response).map_err(fail)?;
    let (head, body) = response.split_once("\r\n\r\n").unwrap_or((&response, ""));
    if !head.starts_with("HTTP/1.1 200") {
        return Err(Failure::new(format!("safaridriver {method} {path}: {head}: {body}")));
    }
    Ok(body.to_owned())
}

/// The string value of the first member `name` of the JSON text `json`. A WebDriver session ID has no escape.
fn json_string<'j>(json: &'j str, name: &str) -> Option<&'j str> {
    let (_, after) = json.split_once(&format!("\"{name}\":\""))?;
    after.split_once('"').map(|(value, _)| value)
}

/// Serves the page, the Worker, and `wasm` on `listener`, and keeps each report that a browser posts.
fn serve(listener: &TcpListener, wasm: &[u8], reports: &Reports) {
    for stream in listener.incoming().flatten() {
        // A request that fails ends its connection; the browser that sent it gives no report, and its run fails.
        let _ignored = respond(stream, wasm, reports);
    }
}

/// Reads one request from `stream`, and answers it.
fn respond(mut stream: TcpStream, wasm: &[u8], reports: &Reports) -> io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut request = Vec::new();
    let mut buffer = [0; 4096];
    let (head, body_start) = loop {
        let read = stream.read(&mut buffer)?;
        if read == 0 || request.len() + read > REQUEST_BYTES_MAX {
            return Err(io::Error::other("an incomplete or long request"));
        }
        request.extend_from_slice(&buffer[..read]);
        if let Some(end) = request.windows(4).position(|window| window == b"\r\n\r\n") {
            break (String::from_utf8_lossy(&request[..end]).into_owned(), end + 4);
        }
    };
    let mut lines = head.lines();
    let target = lines.next().unwrap_or_default();
    let mut words = target.split(' ');
    let (method, path) = (words.next().unwrap_or_default(), words.next().unwrap_or_default());
    let length = lines
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.trim().parse::<usize>().ok())
        .unwrap_or(0);
    if body_start + length > REQUEST_BYTES_MAX {
        return Err(io::Error::other("a long request"));
    }
    while request.len() < body_start + length {
        let read = stream.read(&mut buffer)?;
        if read == 0 {
            return Err(io::Error::other("an incomplete body"));
        }
        request.extend_from_slice(&buffer[..read]);
    }
    let (route, query) = path.split_once('?').unwrap_or((path, ""));
    let (status, kind, content): (&str, &str, &[u8]) = match (method, route) {
        ("GET", "/") => ("200 OK", "text/html; charset=utf-8", PAGE.as_bytes()),
        ("GET", "/worker.js") => ("200 OK", "text/javascript", WORKER.as_bytes()),
        ("GET", "/portable.wasm") => ("200 OK", "application/wasm", wasm),
        ("POST", "/report") => {
            let browser = query.strip_prefix("browser=").unwrap_or(query).to_owned();
            let report = String::from_utf8_lossy(&request[body_start..body_start + length]).into_owned();
            let (map, arrived) = &**reports;
            map.lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(browser, report);
            arrived.notify_all();
            ("204 No Content", "text/plain", b"")
        }
        _ => ("404 Not Found", "text/plain", b"not found"),
    };
    write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: {kind}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        content.len()
    )?;
    stream.write_all(content)?;
    stream.shutdown(Shutdown::Write)
}

#[cfg(test)]
mod tests {
    //! The checks of the module and of the closure: each one refuses what the portable core must not have.

    use super::{check_closure, check_module};

    /// A module of version 1 with `sections`: the id and the content of each one, in order.
    fn module(sections: &[(u8, &[u8])]) -> Vec<u8> {
        let mut module = b"\0asm\x01\0\0\0".to_vec();
        for (id, content) in sections {
            module.push(*id);
            module.push(u8::try_from(content.len()).expect("a short section"));
            module.extend_from_slice(content);
        }
        module
    }

    /// One memory of one page with the flags `flags`.
    fn memory(flags: u8) -> Vec<u8> {
        vec![1, flags, 1, 1]
    }

    /// The exports of the consumer: the memory, then the two functions.
    fn exports() -> Vec<u8> {
        let mut section = vec![3];
        for (name, kind) in [
            (&b"memory"[..], 2),
            (b"rsauthnz_portable_report", 0),
            (b"rsauthnz_portable_run", 0),
        ] {
            section.push(u8::try_from(name.len()).expect("a short name"));
            section.extend_from_slice(name);
            section.extend_from_slice(&[kind, 0]);
        }
        section
    }

    #[test]
    fn a_module_with_an_import_or_a_shared_memory_or_another_export_fails_the_check() {
        let exports = exports();
        let unshared = memory(0);
        assert!(check_module(&module(&[(5, &unshared), (7, &exports)])).is_ok());
        // The import `env.f` of a function of type 0.
        let import = [1, 3, b'e', b'n', b'v', 1, b'f', 0, 0];
        let refusals = [
            module(&[(2, &import), (5, &unshared), (7, &exports)]),
            module(&[(5, &memory(3)), (7, &exports)]),
            module(&[(5, &unshared), (7, &[0])]),
            b"\0asm\x02\0\0\0".to_vec(),
        ];
        for refused in refusals {
            assert!(check_module(&refused).is_err(), "{refused:02x?}");
        }
    }

    #[test]
    fn a_closure_with_another_crate_or_native_custody_fails_the_check() {
        let closure = "\
rsauthnz v0.1.0 (/r) [default]
rsauthnz-conformance v0.1.0 (/r/c) []
rsauthnz-portable v0.0.0 (/r/p) []
rscodec v0.1.0 (git) [hex]
rscrypto v0.12.0 (git) [sha2]
rstypes v0.1.0 (git) []
";
        assert_eq!(check_closure(closure).map(|lines| lines.len()).ok(), Some(6));
        let other = format!("{closure}libc v0.2.0 []\n");
        let custody = closure.replace("[default]", "[default,native-custody]");
        for refused in [other.as_str(), custody.as_str(), "rsauthnz-portable v0.0.0 (/r/p) []\n"] {
            assert!(check_closure(refused).is_err(), "{refused}");
        }
    }
}
