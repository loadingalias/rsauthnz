//! The load generator of the resource runs: the example on a loopback port as its binaries serve it, HTTP/2 clients,
//! and an open-loop load with corrected latency.

use core::net::SocketAddr;
use core::num::NonZeroUsize;
use core::sync::atomic::{AtomicU64, Ordering};
use core::time::Duration;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Bytes;
use http::{Request, StatusCode};
use rsauthnz::store::{Kind, Store as _};
use rsauthnz::time::{Reading, ReadingSource};
use rsauthnz_conformance::memory::Memory;
use rscrypto::ChaCha20Rng;
use tokio::sync::oneshot;

/// The origin of the site of each run.
pub(crate) const ORIGIN: &str = "http://localhost:8080";

/// The example on a loopback port, as its binaries serve it: `web::serve` on a thread with its own runtime, and the
/// clock of the system.
pub(crate) struct Host {
    pub(crate) address: SocketAddr,
    stop: oneshot::Sender<()>,
    server: JoinHandle<std::io::Result<()>>,
    issuer_dir: std::path::PathBuf,
}

impl Host {
    /// Starts the example on `store`.
    pub(crate) fn start(store: Memory) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let issuer_dir = std::env::temp_dir().join(format!(
            "rsauthnz-web-load-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let clock: web::Clock = Arc::new(|| {
            let now = SystemTime::now().duration_since(UNIX_EPOCH).expect("a time after 1970");
            Reading::new(now, Some(Duration::from_secs(1)), ReadingSource::SystemClock)
        });
        let store = store.with_clock(Arc::clone(&clock));
        let app = web::App::new(ORIGIN, store, clock, ChaCha20Rng::from_seed([5; 32]), &issuer_dir).expect("the app");
        let app = Arc::new(app);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a listener");
        listener.set_nonblocking(true).expect("a listener that does not block");
        let address = listener.local_addr().expect("an address");
        let (stop, stopped) = oneshot::channel();
        let server = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .enable_time()
                .build()?;
            runtime.block_on(async move {
                let listener = tokio::net::TcpListener::from_std(listener)?;
                let shutdown = async {
                    stopped.await.expect("the run stops the server");
                };
                web::serve(listener, web::router(Arc::clone(&app)), &app, shutdown).await
            })
        });
        Self {
            address,
            stop,
            server,
            issuer_dir,
        }
    }

    /// Stops the server as Ctrl-C does. Gives the result of `web::serve` after the thread of the server ends. The
    /// wait does not block the runtime of the caller: the server ends a connection only after its client answers.
    pub(crate) async fn stop(self) -> std::io::Result<()> {
        self.stop.send(()).expect("the server runs");
        let server = self.server;
        let result = tokio::task::spawn_blocking(move || server.join().expect("the thread of the server"))
            .await
            .expect("the wait for the server");
        std::fs::remove_dir_all(&self.issuer_dir).expect("remove the issuer directory");
        result
    }
}

/// One HTTP/2 connection of a client. Its clones share the connection.
#[derive(Clone)]
pub(crate) struct Client(h2::client::SendRequest<Bytes>);

impl Client {
    /// A new connection to `address`.
    pub(crate) async fn connect(address: SocketAddr) -> Self {
        let tcp = tokio::net::TcpStream::connect(address).await.expect("a connection");
        tcp.set_nodelay(true).expect("no delay");
        let (client, connection) = h2::client::handshake(tcp).await.expect("an HTTP/2 connection");
        tokio::spawn(async move {
            // The connection ends when the server stops.
            let _closed = connection.await;
        });
        Self(client)
    }

    /// The status and the body of the response to a `POST` of `body` to `path`, from a page of the site `origin`.
    pub(crate) async fn post(&self, path: &str, origin: &str, body: Bytes) -> (StatusCode, Vec<u8>) {
        let site = if origin == ORIGIN { "same-origin" } else { "cross-site" };
        let request = Request::post(format!("http://localhost{path}"))
            .header("origin", origin)
            .header("sec-fetch-site", site)
            .header("content-type", "application/json")
            .body(())
            .expect("a request");
        let mut client = self.0.clone().ready().await.expect("a ready client");
        let (response, mut stream) = client.send_request(request, false).expect("a stream");
        stream.send_data(body, true).expect("the body");
        let response = response.await.expect("a response");
        let status = response.status();
        let mut body = response.into_body();
        let mut bytes = Vec::new();
        while let Some(chunk) = body.data().await {
            let chunk = chunk.expect("a chunk");
            body.flow_control().release_capacity(chunk.len()).expect("capacity");
            bytes.extend_from_slice(&chunk);
        }
        (status, bytes)
    }
}

/// One request of a load: its status, and the time from its planned start to the end of its response. The time has
/// each wait of the client too, so a late start does not hide a slow server.
pub(crate) type Sample = (StatusCode, Duration);

/// An open-loop load: `rate` requests in each second for `time`, in steps of one millisecond. Each request starts at
/// its planned time, also when an earlier response is late. `request` gives the status of the request with a number.
pub(crate) async fn load<F>(rate: u32, time: Duration, request: impl Fn(u64) -> F) -> Vec<Sample>
where
    F: Future<Output = StatusCode> + Send + 'static,
{
    let mut step = tokio::time::interval(Duration::from_millis(1));
    let steps = u64::try_from(time.as_millis()).expect("a short load");
    let mut requests = Vec::new();
    let mut sent = 0;
    for elapsed in 1..=steps {
        let planned = step.tick().await;
        let due = elapsed * u64::from(rate) / 1_000;
        for number in sent..due {
            let request = request(number);
            requests.push(tokio::spawn(async move { (request.await, planned.elapsed()) }));
        }
        sent = due;
    }
    let mut samples = Vec::with_capacity(requests.len());
    for request in requests {
        samples.push(request.await.expect("a request of the load"));
    }
    samples
}

/// The times of the samples of `samples` with a status that `keep` takes, in order.
pub(crate) fn times(samples: &[Sample], keep: impl Fn(StatusCode) -> bool) -> Vec<Duration> {
    let mut times: Vec<_> = samples
        .iter()
        .filter(|(status, _)| keep(*status))
        .map(|(_, time)| *time)
        .collect();
    times.sort_unstable();
    times
}

/// The percentile `percent` of the ordered `times`: the smallest time that is at least as large as that share of
/// them. No time gives zero.
pub(crate) fn percentile(times: &[Duration], percent: usize) -> Duration {
    let rank = (times.len() * percent).div_ceil(100).max(1);
    times.get(rank - 1).copied().unwrap_or_default()
}

/// The records of `memory` that have an end: the retained state that the expiry pass removes.
pub(crate) async fn ending(memory: &Memory) -> usize {
    let mut records = 0;
    for kind in Kind::ALL {
        let prefix = kind.key(&[]).expect("a prefix");
        let page = memory.clone().range(&prefix, None, NonZeroUsize::MAX).await;
        records += page
            .expect("a range")
            .iter()
            .filter(|(_, record)| record.end.is_some())
            .count();
    }
    records
}

/// The records of `memory`.
pub(crate) async fn records(memory: &Memory) -> usize {
    let mut records = 0;
    for kind in Kind::ALL {
        let prefix = kind.key(&[]).expect("a prefix");
        let page = memory.clone().range(&prefix, None, NonZeroUsize::MAX).await;
        records += page.expect("a range").len();
    }
    records
}
