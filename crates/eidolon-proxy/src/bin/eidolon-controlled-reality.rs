use std::{
    env,
    fs::File,
    io::{self, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::{Component, Path, PathBuf},
    process::ExitCode,
    sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc::{self, Receiver, SyncSender, TrySendError},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
};

use eidolon_proxy::controlled_reality_backend::{
    serve_render_connection, ControlledRealityBackendAuthSecret,
    ControlledRealityBackendConnectionOutcome, ControlledRealityBackendReplayCache,
};
use serde_json::json;

const DEFAULT_LISTEN_ADDR: &str = "127.0.0.1:9103";
const CONNECTION_WORKER_COUNT: usize = 32;
const CONNECTION_QUEUE_CAPACITY: usize = 32;
const AUDIT_QUEUE_CAPACITY: usize = 128;
const ENCODED_AUTH_SECRET_BYTES: usize = 64;
const MAX_AUTH_SECRET_FILE_BYTES: usize = ENCODED_AUTH_SECRET_BYTES + 1;

fn main() -> ExitCode {
    run_cli(env::args().skip(1))
}

fn run_cli<I, S>(args: I) -> ExitCode
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    match CliAction::from_args(args) {
        Ok(CliAction::Help) => {
            println!("{}", usage());
            ExitCode::SUCCESS
        }
        Ok(CliAction::Run(config)) => match run_server(config) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("error: {error}");
                ExitCode::FAILURE
            }
        },
        Err(error) => {
            eprintln!("error: {error}\n\n{}", usage());
            ExitCode::from(2)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ServerConfig {
    auth_secret_path: PathBuf,
    listen_addr: SocketAddr,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CliAction {
    Run(ServerConfig),
    Help,
}

impl CliAction {
    fn from_args<I, S>(args: I) -> Result<Self, String>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut auth_secret_path = None;
        let mut listen_addr = None;
        let mut owned_cluster_lab = false;
        let mut args = args.into_iter().map(Into::into).peekable();

        while let Some(arg) = args.next() {
            if arg == "-h" || arg == "--help" {
                return Ok(Self::Help);
            }
            let (flag, inline_value) = split_option(&arg)?;
            match flag {
                "--auth-secret-file" => {
                    let value = option_value(flag, inline_value, &mut args)?;
                    let path = parse_auth_secret_path(&value)?;
                    set_once(&mut auth_secret_path, flag, path)?;
                }
                "--listen-addr" => {
                    let value = option_value(flag, inline_value, &mut args)?;
                    set_once(&mut listen_addr, flag, value)?;
                }
                "--owned-cluster-lab" => {
                    if inline_value.is_some() {
                        return Err(format!("option `{flag}` does not accept a value"));
                    }
                    if owned_cluster_lab {
                        return Err(format!("duplicate option `{flag}`"));
                    }
                    owned_cluster_lab = true;
                }
                _ if flag.starts_with('-') => {
                    return Err(format!("unknown option `{flag}`"));
                }
                _ => return Err(format!("unexpected positional argument `{flag}`")),
            }
        }

        let auth_secret_path =
            auth_secret_path.ok_or_else(|| "missing required `--auth-secret-file`".to_string())?;
        if auth_secret_path.as_os_str().is_empty() {
            return Err("auth secret file path cannot be empty".to_string());
        }
        let listen_addr = listen_addr.unwrap_or_else(|| DEFAULT_LISTEN_ADDR.to_string());
        let listen_addr = listen_addr
            .parse::<SocketAddr>()
            .map_err(|_| format!("invalid listen address `{listen_addr}`"))?;
        validate_listen_addr(listen_addr, owned_cluster_lab)?;

        Ok(Self::Run(ServerConfig {
            auth_secret_path,
            listen_addr,
        }))
    }
}

fn split_option(arg: &str) -> Result<(&str, Option<String>), String> {
    if let Some((flag, value)) = arg.split_once('=') {
        if flag.is_empty() || value.is_empty() {
            return Err(format!("invalid option `{arg}`"));
        }
        Ok((flag, Some(value.to_string())))
    } else {
        Ok((arg, None))
    }
}

fn option_value<I>(
    flag: &str,
    inline_value: Option<String>,
    args: &mut std::iter::Peekable<I>,
) -> Result<String, String>
where
    I: Iterator<Item = String>,
{
    if let Some(value) = inline_value {
        return Ok(value);
    }
    let value = args
        .next()
        .ok_or_else(|| format!("missing value for `{flag}`"))?;
    if value.starts_with('-') {
        return Err(format!("missing value for `{flag}`"));
    }
    Ok(value)
}

fn set_once<T>(slot: &mut Option<T>, flag: &str, value: T) -> Result<(), String> {
    if slot.replace(value).is_some() {
        return Err(format!("duplicate option `{flag}`"));
    }
    Ok(())
}

fn validate_listen_addr(address: SocketAddr, owned_cluster_lab: bool) -> Result<(), String> {
    if address.port() == 0 {
        return Err("listen address port must not be 0".to_string());
    }
    if !address.ip().is_loopback() && !owned_cluster_lab {
        return Err(
            "non-loopback listen addresses require explicit `--owned-cluster-lab`".to_string(),
        );
    }
    Ok(())
}

fn parse_auth_secret_path(value: &str) -> Result<PathBuf, String> {
    // foxguard: ignore[rs/no-path-traversal] - validated as absolute and parent-free below.
    let path = Path::new(value);
    if !path.is_absolute() {
        return Err("auth secret file path must be absolute".to_string());
    }
    if path
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err("auth secret file path must not contain `..` components".to_string());
    }
    Ok(path.to_path_buf())
}

fn run_server(config: ServerConfig) -> io::Result<()> {
    let secret = Arc::new(load_auth_secret(&config.auth_secret_path)?);
    let listener = TcpListener::bind(config.listen_addr)?;
    let audit = AuditSink::start()?;
    let worker_audit = audit.clone();
    let replay_cache = Arc::new(ControlledRealityBackendReplayCache::new());
    let workers = BoundedWorkerPool::new(
        CONNECTION_WORKER_COUNT,
        CONNECTION_QUEUE_CAPACITY,
        "controlled-reality-connection",
        move |job: ConnectionJob| {
            let outcome = serve_render_connection(job.stream, &secret, &replay_cache);
            match outcome {
                ControlledRealityBackendConnectionOutcome::HealthCheck => {}
                ControlledRealityBackendConnectionOutcome::Served { request_id, status } => {
                    worker_audit.try_emit(AuditEvent::new(
                        "served",
                        Some(request_id.0),
                        Some(status),
                        None,
                        job.peer,
                    ));
                }
                ControlledRealityBackendConnectionOutcome::Rejected { reason } => {
                    worker_audit.try_emit(AuditEvent::new(
                        "rejected",
                        reason
                            .authenticated_request_id()
                            .map(|request_id| request_id.0),
                        None,
                        Some(reason.audit_code()),
                        job.peer,
                    ));
                }
            }
        },
    )?;

    for stream in listener.incoming() {
        let stream = match stream {
            Ok(stream) => stream,
            Err(_) => {
                audit.try_emit(AuditEvent::new(
                    "rejected",
                    None,
                    None,
                    Some("accept_failed"),
                    None,
                ));
                continue;
            }
        };
        let peer = stream.peer_addr().ok().map(|peer| peer.to_string());
        let job = ConnectionJob { stream, peer };
        if let Err(error) = workers.try_dispatch(job) {
            let (reason, job) = match error {
                DispatchError::Full(job) => ("connection_queue_full", job),
                DispatchError::Disconnected(job) => ("connection_workers_unavailable", job),
            };
            audit.try_emit(AuditEvent::new("quota", None, None, Some(reason), job.peer));
        };
    }
    Ok(())
}

fn load_auth_secret(path: &Path) -> io::Result<ControlledRealityBackendAuthSecret> {
    let file = File::open(path)?;
    if !file.metadata()?.is_file() {
        return Err(invalid_secret(
            "auth secret path must identify a regular file",
        ));
    }
    let mut encoded = Vec::with_capacity(MAX_AUTH_SECRET_FILE_BYTES + 1);
    file.take((MAX_AUTH_SECRET_FILE_BYTES + 1) as u64)
        .read_to_end(&mut encoded)?;
    let secret = decode_auth_secret(&encoded);
    encoded.fill(0);
    let secret = secret?;
    ControlledRealityBackendAuthSecret::new(secret).map_err(|_| {
        invalid_secret("auth secret must decode to 32 nontrivial bytes of key material")
    })
}

fn decode_auth_secret(encoded: &[u8]) -> io::Result<Vec<u8>> {
    let encoded = match encoded {
        bytes if bytes.len() == ENCODED_AUTH_SECRET_BYTES => bytes,
        bytes
            if bytes.len() == MAX_AUTH_SECRET_FILE_BYTES
                && bytes.last().is_some_and(|byte| *byte == b'\n') =>
        {
            &bytes[..ENCODED_AUTH_SECRET_BYTES]
        }
        _ => {
            return Err(invalid_secret(
                "auth secret file must contain exactly 64 hexadecimal characters and an optional single newline",
            ));
        }
    };
    let mut decoded = Vec::with_capacity(ENCODED_AUTH_SECRET_BYTES / 2);
    for pair in encoded.chunks_exact(2) {
        let high = decode_hex_nibble(pair[0]).ok_or_else(|| {
            invalid_secret("auth secret file contains a non-hexadecimal character")
        })?;
        let low = decode_hex_nibble(pair[1]).ok_or_else(|| {
            invalid_secret("auth secret file contains a non-hexadecimal character")
        })?;
        decoded.push((high << 4) | low);
    }
    Ok(decoded)
}

fn decode_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn invalid_secret(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

struct ConnectionJob {
    stream: TcpStream,
    peer: Option<String>,
}

#[derive(Debug)]
enum DispatchError<T> {
    Full(T),
    Disconnected(T),
}

struct BoundedWorkerPool<T> {
    sender: SyncSender<T>,
    _workers: Vec<JoinHandle<()>>,
}

impl<T: Send + 'static> BoundedWorkerPool<T> {
    fn new<F>(
        worker_count: usize,
        queue_capacity: usize,
        thread_name_prefix: &str,
        handler: F,
    ) -> io::Result<Self>
    where
        F: Fn(T) + Send + Sync + 'static,
    {
        if worker_count == 0 || queue_capacity == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "worker and queue capacities must be positive",
            ));
        }
        let (sender, receiver) = mpsc::sync_channel(queue_capacity);
        let receiver = Arc::new(Mutex::new(receiver));
        let handler = Arc::new(handler);
        let mut workers: Vec<JoinHandle<()>> = Vec::with_capacity(worker_count);
        for index in 0..worker_count {
            let receiver = Arc::clone(&receiver);
            let handler = Arc::clone(&handler);
            let worker = match thread::Builder::new()
                .name(format!("{thread_name_prefix}-{index}"))
                .spawn(move || worker_loop(receiver, handler))
            {
                Ok(worker) => worker,
                Err(error) => {
                    drop(sender);
                    for worker in workers {
                        let _ = worker.join();
                    }
                    return Err(error);
                }
            };
            workers.push(worker);
        }
        Ok(Self {
            sender,
            _workers: workers,
        })
    }

    fn try_dispatch(&self, job: T) -> Result<(), DispatchError<T>> {
        self.sender.try_send(job).map_err(|error| match error {
            TrySendError::Full(job) => DispatchError::Full(job),
            TrySendError::Disconnected(job) => DispatchError::Disconnected(job),
        })
    }
}

fn worker_loop<T, F>(receiver: Arc<Mutex<Receiver<T>>>, handler: Arc<F>)
where
    T: Send + 'static,
    F: Fn(T) + Send + Sync + 'static,
{
    loop {
        let job = match receiver.lock() {
            Ok(receiver) => receiver.recv(),
            Err(_) => return,
        };
        match job {
            Ok(job) => handler(job),
            Err(_) => return,
        }
    }
}

#[derive(Debug)]
struct AuditEvent {
    event: &'static str,
    request_id: Option<uuid::Uuid>,
    status: Option<u16>,
    reason: Option<&'static str>,
    peer: Option<String>,
}

impl AuditEvent {
    fn new(
        event: &'static str,
        request_id: Option<uuid::Uuid>,
        status: Option<u16>,
        reason: Option<&'static str>,
        peer: Option<String>,
    ) -> Self {
        Self {
            event,
            request_id,
            status,
            reason,
            peer,
        }
    }
}

#[derive(Clone)]
struct AuditSink {
    sender: SyncSender<AuditEvent>,
    dropped: Arc<AtomicUsize>,
}

impl AuditSink {
    fn start() -> io::Result<Self> {
        let (sender, receiver) = mpsc::sync_channel(AUDIT_QUEUE_CAPACITY);
        let dropped = Arc::new(AtomicUsize::new(0));
        let writer_dropped = Arc::clone(&dropped);
        thread::Builder::new()
            .name("controlled-reality-audit".to_string())
            .spawn(move || {
                let stdout = io::stdout();
                write_audit_events(receiver, writer_dropped, stdout.lock());
            })?;
        Ok(Self { sender, dropped })
    }

    fn try_emit(&self, event: AuditEvent) -> bool {
        match self.sender.try_send(event) {
            Ok(()) => true,
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                false
            }
        }
    }
}

fn write_audit_events(
    receiver: Receiver<AuditEvent>,
    dropped: Arc<AtomicUsize>,
    mut writer: impl Write,
) {
    while let Ok(event) = receiver.recv() {
        let dropped_audits_before = dropped.swap(0, Ordering::AcqRel);
        let record = json!({
            "schema_version": 1,
            "component": "eidolon-controlled-reality",
            "event": event.event,
            "request_id": event.request_id,
            "status": event.status,
            "reason": event.reason,
            "peer": event.peer,
            "dropped_audits_before": dropped_audits_before,
        });
        if writeln!(writer, "{record}")
            .and_then(|_| writer.flush())
            .is_err()
        {
            dropped.fetch_add(dropped_audits_before.saturating_add(1), Ordering::Relaxed);
        }
    }
}

fn usage() -> &'static str {
    "\
Usage: eidolon-controlled-reality --auth-secret-file <PATH> [OPTIONS]

Options:
  --auth-secret-file <PATH>
                         Dedicated HMAC key: exactly 64 hex characters
  --listen-addr <ADDR>   Listen address [default: 127.0.0.1:9103]
  --owned-cluster-lab    Permit a non-loopback listen address in an owned lab
  -h, --help             Show this help text"
}

#[cfg(test)]
mod tests {
    use std::{
        env, fs,
        sync::{atomic::Ordering, Condvar},
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    use super::*;

    const TEST_SECRET: &[u8] = b"0123456789abcdef0123456789abcdef";
    const TEST_SECRET_HEX: &str =
        "3031323334353637383961626364656630313233343536373839616263646566";

    #[test]
    fn non_loopback_requires_owned_cluster_lab() {
        let error = CliAction::from_args([
            "--auth-secret-file",
            "/tmp/test-secret",
            "--listen-addr",
            "0.0.0.0:9103",
        ])
        .expect_err("non-loopback should be gated");
        assert!(error.contains("--owned-cluster-lab"));

        let action = CliAction::from_args([
            "--auth-secret-file",
            "/tmp/test-secret",
            "--listen-addr",
            "0.0.0.0:9103",
            "--owned-cluster-lab",
        ])
        .expect("owned lab should allow non-loopback");
        assert!(matches!(action, CliAction::Run(_)));
    }

    #[test]
    fn auth_secret_path_requires_an_absolute_normalized_shape() {
        for path in ["relative-secret", "/var/run/eidolon/../secret"] {
            let error = CliAction::from_args(["--auth-secret-file", path])
                .expect_err("unsafe secret path shape should be rejected");
            assert!(error.contains("auth secret file path"));
        }
        assert!(CliAction::from_args([
            "--auth-secret-file",
            "/var/run/secrets/eidolon/renderer-auth",
        ])
        .is_ok());
    }

    #[test]
    fn worker_pool_is_fixed_and_rejects_when_its_queue_is_full() {
        let released = Arc::new((Mutex::new(false), Condvar::new()));
        let worker_released = Arc::clone(&released);
        let (started_sender, started_receiver) = mpsc::channel();
        let pool = BoundedWorkerPool::new(1, 1, "bounded-worker-test", move |job| {
            started_sender
                .send(job)
                .expect("test receiver should remain available");
            let (lock, wake) = &*worker_released;
            let guard = lock.lock().expect("release lock should be available");
            drop(
                wake.wait_while(guard, |released| !*released)
                    .expect("release lock should remain available"),
            );
        })
        .expect("worker pool should start");

        pool.try_dispatch(1)
            .expect("worker should accept first job");
        assert_eq!(
            started_receiver
                .recv_timeout(Duration::from_secs(1))
                .expect("worker should start first job"),
            1
        );
        pool.try_dispatch(2).expect("queue should accept one job");
        assert!(matches!(pool.try_dispatch(3), Err(DispatchError::Full(3))));
        assert_eq!(pool._workers.len(), 1);

        let (lock, wake) = &*released;
        *lock.lock().expect("release lock should be available") = true;
        wake.notify_all();
        assert_eq!(
            started_receiver
                .recv_timeout(Duration::from_secs(1))
                .expect("worker should drain queued job"),
            2
        );
    }

    #[test]
    fn audit_queue_drops_instead_of_blocking_when_full() {
        let (sender, _receiver) = mpsc::sync_channel(1);
        let dropped = Arc::new(AtomicUsize::new(0));
        let sink = AuditSink {
            sender,
            dropped: Arc::clone(&dropped),
        };
        let event = || AuditEvent::new("served", None, Some(200), None, None);

        assert!(sink.try_emit(event()));
        assert!(!sink.try_emit(event()));
        assert_eq!(dropped.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn audit_writer_reports_prior_drops_without_sensitive_fields() {
        let (sender, receiver) = mpsc::sync_channel(1);
        let dropped = Arc::new(AtomicUsize::new(2));
        sender
            .send(AuditEvent::new(
                "rejected",
                None,
                None,
                Some("malformed_frame"),
                Some("127.0.0.1:1234".to_string()),
            ))
            .expect("audit fixture should enqueue");
        drop(sender);
        let mut output = Vec::new();
        write_audit_events(receiver, Arc::clone(&dropped), &mut output);

        let record: serde_json::Value =
            serde_json::from_slice(&output).expect("audit output should be JSON");
        assert_eq!(record["dropped_audits_before"], 2);
        assert_eq!(record["peer"], "127.0.0.1:1234");
        assert!(record.get("secret").is_none());
    }

    #[test]
    fn failed_audit_write_preserves_prior_drop_count() {
        struct FailingWriter;

        impl Write for FailingWriter {
            fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
                Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "intentional test failure",
                ))
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        let (sender, receiver) = mpsc::sync_channel(1);
        let dropped = Arc::new(AtomicUsize::new(2));
        sender
            .send(AuditEvent::new("served", None, Some(200), None, None))
            .expect("audit fixture should enqueue");
        drop(sender);

        write_audit_events(receiver, Arc::clone(&dropped), FailingWriter);

        assert_eq!(dropped.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn secret_decoder_accepts_exact_hex_with_optional_newline_and_mixed_case() {
        assert_eq!(
            decode_auth_secret(TEST_SECRET_HEX.as_bytes()).expect("lowercase hex should decode"),
            TEST_SECRET
        );
        assert_eq!(
            decode_auth_secret(TEST_SECRET_HEX.to_ascii_uppercase().as_bytes())
                .expect("uppercase hex should decode"),
            TEST_SECRET
        );
        assert_eq!(
            decode_auth_secret(format!("{TEST_SECRET_HEX}\n").as_bytes())
                .expect("one trailing newline should be accepted"),
            TEST_SECRET
        );
    }

    #[test]
    fn secret_decoder_rejects_ambiguous_or_malformed_encodings() {
        for encoded in [
            TEST_SECRET_HEX.as_bytes()[..63].to_vec(),
            format!("{TEST_SECRET_HEX}0").into_bytes(),
            format!("{TEST_SECRET_HEX}\r\n").into_bytes(),
            format!("{TEST_SECRET_HEX}\n\n").into_bytes(),
            format!("g{}", &TEST_SECRET_HEX[1..]).into_bytes(),
        ] {
            let error = decode_auth_secret(&encoded).expect_err("encoding should be rejected");
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        }
    }

    #[test]
    fn secret_file_read_is_bounded() {
        let secret_path = unique_temp_path();
        fs::write(&secret_path, vec![b'a'; MAX_AUTH_SECRET_FILE_BYTES + 16])
            .expect("oversized fixture should write");
        let error = load_auth_secret(&secret_path).expect_err("oversized secret should fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        fs::remove_file(secret_path).expect("secret fixture should be removed");
    }

    #[test]
    fn secret_loader_rejects_trivial_decoded_key() {
        let secret_path = unique_temp_path();
        fs::write(&secret_path, "00".repeat(32)).expect("trivial fixture should write");
        let error = load_auth_secret(&secret_path).expect_err("trivial key should fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(!error.to_string().contains(&"00".repeat(8)));
        fs::remove_file(secret_path).expect("secret fixture should be removed");
    }

    #[test]
    fn cli_entrypoint_rejects_invalid_secret_encoding() {
        let secret_path = unique_temp_path();
        fs::write(&secret_path, TEST_SECRET).expect("invalid fixture should write");
        let exit = run_cli([
            "--auth-secret-file".to_string(),
            secret_path.to_string_lossy().into_owned(),
        ]);
        assert_eq!(exit, ExitCode::FAILURE);
        fs::remove_file(secret_path).expect("secret fixture should be removed");
    }

    fn unique_temp_path() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be available")
            .as_nanos();
        env::temp_dir().join(format!(
            "eidolon-controlled-reality-secret-{}-{nanos}",
            std::process::id()
        ))
    }
}
