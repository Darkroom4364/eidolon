//! C3a: bounded capacity and slow/partial-client cleanup through the actual
//! production listener and production upstream dispatcher. This is finite
//! lifecycle regression evidence, not load, latency, RSS, or soak evidence.

use std::{
    io::ErrorKind,
    net::SocketAddr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

use bytes::Bytes;
use hyper::{http::uri::Authority, StatusCode};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    runtime::Handle,
    sync::{mpsc, oneshot, watch},
    task::{JoinHandle, JoinSet},
    time::{sleep, timeout},
};

use super::{
    dispatch_production_upstream, serve_production_http1_inner, ProductionPreServiceRejection,
    ProductionProcessorError, ProductionRejectedRequest, ProductionRequestContext,
    ProductionRequestProcessor, ProductionResponse, ProductionRuntimeConfig,
    ProductionRuntimeError, ProductionUpstreamConfig, ProductionUpstreamTarget,
};
use crate::production_http::{ProductionHttpRequest, ProductionRequestRejection};

const OPERATION_BUDGET: Duration = Duration::from_secs(5);
const TEST_BUDGET: Duration = Duration::from_secs(20);
const CAPTURE_LIMIT: usize = 16 * 1024;
const STAGE_DEADLINE: Duration = Duration::from_secs(1);
const DRIP_INTERVAL: Duration = Duration::from_millis(100);
// Twelve paced writes take at least 1.2 seconds. A stage timer incorrectly
// restarted by the final write would not expire until about 2.1 seconds, so
// this bound distinguishes one absolute stage budget with scheduler margin.
const STAGE_TERMINAL_BOUND: Duration = Duration::from_millis(1_700);
const MAX_DRIP_ATTEMPT_GAP: Duration = Duration::from_millis(250);
const MIN_DRIP_WRITES: usize = 8;
// Header parsing and body collection have separate stage timers. This is a
// generous composed upper bound (two one-second stages plus one second of
// scheduler/socket margin), not one accept-to-body absolute deadline.
const COMPOSED_HEAD_BODY_BOUND: Duration = Duration::from_secs(3);

#[derive(Clone, Debug, PartialEq, Eq)]
struct RecordedUpstreamRequest {
    method: String,
    target: String,
    body: Vec<u8>,
    wire: Vec<u8>,
}

struct ReadyUpstreamRequest {
    request: RecordedUpstreamRequest,
    release: Option<oneshot::Sender<()>>,
}

impl ReadyUpstreamRequest {
    fn release(mut self) {
        self.release
            .take()
            .expect("captured upstream request should have one release")
            .send(())
            .expect("owned upstream connection should await release");
    }
}

fn head_end(wire: &[u8]) -> Option<usize> {
    wire.windows(4)
        .position(|bytes| bytes == b"\r\n\r\n")
        .map(|position| position + 4)
}

fn terminal_reset(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        ErrorKind::BrokenPipe
            | ErrorKind::ConnectionAborted
            | ErrorKind::ConnectionReset
            | ErrorKind::NotConnected
            | ErrorKind::UnexpectedEof
    )
}

struct AbortOnDropTask<T> {
    task: Option<JoinHandle<T>>,
}

impl<T> AbortOnDropTask<T> {
    fn new(task: JoinHandle<T>) -> Self {
        Self { task: Some(task) }
    }

    async fn join(mut self, description: &str) -> T {
        let result = timeout(
            OPERATION_BUDGET,
            self.task
                .as_mut()
                .expect("abort-on-drop task should remain owned"),
        )
        .await;
        match result {
            Ok(result) => {
                drop(
                    self.task
                        .take()
                        .expect("completed task should remain owned"),
                );
                result.unwrap_or_else(|error| panic!("{description} task failed: {error}"))
            }
            Err(_) => {
                self.task
                    .as_ref()
                    .expect("timed-out task should remain owned")
                    .abort();
                let _ = timeout(
                    OPERATION_BUDGET,
                    self.task
                        .as_mut()
                        .expect("aborted task should remain owned"),
                )
                .await;
                panic!("{description} task did not join within five seconds");
            }
        }
    }
}

impl<T> Drop for AbortOnDropTask<T> {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

async fn read_capped_piece(stream: &mut TcpStream, wire: &mut Vec<u8>) -> usize {
    let mut buffer = [0_u8; 1024];
    let count = match stream.read(&mut buffer).await {
        Ok(count) => count,
        Err(error) if terminal_reset(&error) => 0,
        Err(error) => panic!("owned socket read failed: {error}"),
    };
    assert!(
        wire.len() + count <= CAPTURE_LIMIT,
        "owned capture exceeded {CAPTURE_LIMIT} bytes"
    );
    wire.extend_from_slice(&buffer[..count]);
    count
}

async fn capture_upstream_connection(
    mut stream: TcpStream,
    ready: mpsc::Sender<ReadyUpstreamRequest>,
    completed_count: Arc<AtomicUsize>,
) -> RecordedUpstreamRequest {
    timeout(OPERATION_BUDGET, async move {
        let mut wire = Vec::new();
        let end = loop {
            if let Some(end) = head_end(&wire) {
                break end;
            }
            assert_ne!(
                read_capped_piece(&mut stream, &mut wire).await,
                0,
                "production client closed before its complete upstream head"
            );
        };
        let (method, target, body_len) = {
            let head =
                std::str::from_utf8(&wire[..end]).expect("fixture upstream head should be ASCII");
            let mut lines = head[..head.len() - 4].split("\r\n");
            let request_line = lines
                .next()
                .expect("captured upstream request should have a request line")
                .split(' ')
                .collect::<Vec<_>>();
            assert_eq!(request_line.len(), 3, "canonical upstream request line");
            assert_eq!(request_line[2], "HTTP/1.1");
            let headers = lines
                .map(|line| {
                    let (name, value) = line
                        .split_once(':')
                        .expect("captured upstream header should contain a separator");
                    (name, value.trim())
                })
                .collect::<Vec<_>>();
            let lengths = headers
                .iter()
                .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                .map(|(_, value)| *value)
                .collect::<Vec<_>>();
            assert_eq!(lengths.len(), 1, "one canonical upstream content length");
            let body_len = lengths[0]
                .parse::<usize>()
                .expect("upstream content length should be decimal");
            assert!(body_len <= CAPTURE_LIMIT - end, "bounded upstream body");
            assert!(
                headers
                    .iter()
                    .all(|(name, _)| !name.eq_ignore_ascii_case("transfer-encoding")),
                "production client must not send transfer encoding"
            );
            (
                request_line[0].to_string(),
                request_line[1].to_string(),
                body_len,
            )
        };
        while wire.len() < end + body_len {
            assert_ne!(
                read_capped_piece(&mut stream, &mut wire).await,
                0,
                "production client closed before its complete upstream body"
            );
        }
        assert_eq!(
            wire.len(),
            end + body_len,
            "recorder captured extra bytes before releasing one request"
        );
        let request = RecordedUpstreamRequest {
            method,
            target,
            body: wire[end..].to_vec(),
            wire: wire.clone(),
        };
        completed_count.fetch_add(1, Ordering::SeqCst);
        let (release, released) = oneshot::channel();
        if ready
            .send(ReadyUpstreamRequest {
                request: request.clone(),
                release: Some(release),
            })
            .await
            .is_ok()
        {
            let _ = released.await;
        }

        let response_body = request.target.as_bytes();
        let response = [
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                response_body.len()
            )
            .into_bytes(),
            response_body.to_vec(),
        ]
        .concat();
        stream
            .write_all(&response)
            .await
            .expect("owned upstream response should write");
        stream
            .shutdown()
            .await
            .expect("owned upstream response should finish");
        while read_capped_piece(&mut stream, &mut wire).await != 0 {}
        assert_eq!(
            wire.len(),
            end + body_len,
            "production client sent an extra upstream request"
        );
        request
    })
    .await
    .expect("owned upstream exchange should finish within five seconds")
}

struct UpstreamRecorder {
    address: SocketAddr,
    completed_count: Arc<AtomicUsize>,
    ready: Option<mpsc::Receiver<ReadyUpstreamRequest>>,
    stop: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<Vec<RecordedUpstreamRequest>>>,
}

impl UpstreamRecorder {
    async fn start() -> Self {
        let listener = timeout(OPERATION_BUDGET, TcpListener::bind("127.0.0.1:0"))
            .await
            .expect("owned recorder bind should be bounded")
            .expect("owned recorder should bind");
        let address = listener
            .local_addr()
            .expect("owned recorder should have an address");
        let completed_count = Arc::new(AtomicUsize::new(0));
        let task_count = Arc::clone(&completed_count);
        let (ready_tx, ready) = mpsc::channel(4);
        let (stop, mut stopped) = oneshot::channel();
        let task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            let mut records = Vec::new();
            loop {
                tokio::select! {
                    biased;
                    _ = &mut stopped => break,
                    result = connections.join_next(), if !connections.is_empty() => {
                        records.push(
                            result
                                .expect("owned upstream connection set should yield a task")
                                .expect("owned upstream connection task should join"),
                        );
                    }
                    accepted = listener.accept() => {
                        let (stream, _) = accepted.expect("owned recorder should accept");
                        assert!(records.len() + connections.len() < 4, "at most four upstream peers");
                        connections.spawn(capture_upstream_connection(
                            stream,
                            ready_tx.clone(),
                            Arc::clone(&task_count),
                        ));
                    }
                }
            }

            // The production listener is already quiescent when stop is sent.
            // Drain the concrete accept queue, then join every capture; a
            // negative accept timeout is never the zero-upstream oracle.
            let listener = listener
                .into_std()
                .expect("owned recorder should convert for queue drain");
            loop {
                match listener.accept() {
                    Ok((stream, _)) => {
                        assert!(
                            records.len() + connections.len() < 4,
                            "at most four upstream peers"
                        );
                        stream
                            .set_nonblocking(true)
                            .expect("queued upstream stream should stay nonblocking");
                        connections.spawn(capture_upstream_connection(
                            TcpStream::from_std(stream)
                                .expect("queued upstream stream should convert"),
                            ready_tx.clone(),
                            Arc::clone(&task_count),
                        ));
                    }
                    Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                    Err(error) => panic!("owned upstream accept queue drain failed: {error}"),
                }
            }
            drop(listener);
            drop(ready_tx);
            while let Some(result) = timeout(OPERATION_BUDGET, connections.join_next())
                .await
                .expect("owned upstream connection join should be bounded")
            {
                records.push(result.expect("owned upstream connection should not panic"));
            }
            records
        });
        Self {
            address,
            completed_count,
            ready: Some(ready),
            stop: Some(stop),
            task: Some(task),
        }
    }

    fn completed_count(&self) -> usize {
        self.completed_count.load(Ordering::SeqCst)
    }

    async fn next_ready(&mut self) -> ReadyUpstreamRequest {
        timeout(
            OPERATION_BUDGET,
            self.ready
                .as_mut()
                .expect("recorder readiness receiver should remain owned")
                .recv(),
        )
        .await
        .expect("complete upstream capture should arrive within five seconds")
        .expect("recorder should remain live until listener shutdown")
    }

    async fn finish(mut self) -> Vec<RecordedUpstreamRequest> {
        self.stop
            .take()
            .expect("recorder should have one stop signal")
            .send(())
            .expect("owned recorder should remain live through shutdown");
        // Dropping unconsumed release handles makes even a failing test's
        // already-captured connections recoverable before the bounded join.
        drop(self.ready.take());
        AbortOnDropTask::new(self.task.take().expect("recorder should have one task"))
            .join("owned recorder")
            .await
    }
}

impl Drop for UpstreamRecorder {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct CounterSnapshot {
    normal_process: usize,
    request_rejections: Vec<ProductionRequestRejection>,
    pre_service_rejections: Vec<ProductionPreServiceRejection>,
    current_processors: usize,
    peak_processors: usize,
    peak_connection_tasks: usize,
    upstream_requests: usize,
}

#[derive(Default)]
struct ProcessorObservations {
    normal_process: AtomicUsize,
    request_rejections: Mutex<Vec<ProductionRequestRejection>>,
    pre_service_rejections: Mutex<Vec<ProductionPreServiceRejection>>,
    current_processors: AtomicUsize,
    peak_processors: AtomicUsize,
}

struct ActiveProcessor<'a>(&'a AtomicUsize);

impl Drop for ActiveProcessor<'_> {
    fn drop(&mut self) {
        let previous = self.0.fetch_sub(1, Ordering::SeqCst);
        assert!(previous > 0, "processor activity count must not underflow");
    }
}

struct CountingForwardingProcessor {
    runtime: Handle,
    upstream: ProductionUpstreamTarget,
    observations: Arc<ProcessorObservations>,
}

impl ProductionRequestProcessor for CountingForwardingProcessor {
    fn process(
        &self,
        request: ProductionHttpRequest,
        context: ProductionRequestContext,
    ) -> Result<ProductionResponse, ProductionProcessorError> {
        self.observations
            .normal_process
            .fetch_add(1, Ordering::SeqCst);
        let current = self
            .observations
            .current_processors
            .fetch_add(1, Ordering::SeqCst)
            + 1;
        self.observations
            .peak_processors
            .fetch_max(current, Ordering::SeqCst);
        let _active = ActiveProcessor(&self.observations.current_processors);
        self.runtime
            .block_on(dispatch_production_upstream(
                &request,
                &self.upstream,
                ProductionUpstreamConfig {
                    connect_timeout: Duration::from_secs(1),
                    response_timeout: OPERATION_BUDGET,
                    dispatch_timeout: OPERATION_BUDGET,
                    max_response_body_bytes: CAPTURE_LIMIT,
                },
                context.request_deadline,
            ))
            .map_err(|_| ProductionProcessorError::Failed)
    }

    fn reject(
        &self,
        rejection: ProductionRequestRejection,
        _request: ProductionRejectedRequest,
        _context: ProductionRequestContext,
    ) -> Result<ProductionResponse, ProductionProcessorError> {
        self.observations
            .request_rejections
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(rejection);
        Ok(ProductionResponse::new(
            StatusCode::from_u16(rejection.response_status())
                .expect("production rejection status should be valid"),
            Bytes::new(),
        ))
    }

    fn reject_pre_service(
        &self,
        rejection: ProductionPreServiceRejection,
        _context: ProductionRequestContext,
    ) -> Result<(), ProductionProcessorError> {
        self.observations
            .pre_service_rejections
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(rejection);
        Ok(())
    }
}

struct LifecycleHarness {
    address: SocketAddr,
    observations: Arc<ProcessorObservations>,
    connection_tasks: watch::Receiver<usize>,
    connection_task_peak: Arc<AtomicUsize>,
    body_collection_started: Option<oneshot::Receiver<()>>,
    shutdown: Option<oneshot::Sender<()>>,
    server: Option<JoinHandle<Result<(), ProductionRuntimeError>>>,
    recorder: Option<UpstreamRecorder>,
}

impl LifecycleHarness {
    async fn start(
        capacity: usize,
        request_timeout: Duration,
        observe_body_collection: bool,
    ) -> Self {
        assert!((1..=2).contains(&capacity), "C3a task bound is one or two");
        let recorder = UpstreamRecorder::start().await;
        let listener = timeout(OPERATION_BUDGET, TcpListener::bind("127.0.0.1:0"))
            .await
            .expect("production listener bind should be bounded")
            .expect("production listener should bind");
        let address = listener
            .local_addr()
            .expect("production listener should have an address");
        let observations = Arc::new(ProcessorObservations::default());
        let processor: Arc<dyn ProductionRequestProcessor> =
            Arc::new(CountingForwardingProcessor {
                runtime: Handle::current(),
                upstream: ProductionUpstreamTarget::new(
                    format!("recorder.owned.test:{}", recorder.address.port())
                        .parse::<Authority>()
                        .expect("owned recorder authority should parse"),
                    vec![recorder.address],
                )
                .expect("owned recorder target should configure"),
                observations: Arc::clone(&observations),
            });
        let (shutdown, stopped) = oneshot::channel();
        let (connection_task_tx, connection_tasks) = watch::channel(0);
        let connection_task_peak = Arc::new(AtomicUsize::new(0));
        let (body_collection_started, body_collection_receiver) = if observe_body_collection {
            let (started, receiver) = oneshot::channel();
            (Some(Arc::new(Mutex::new(Some(started)))), Some(receiver))
        } else {
            (None, None)
        };
        let server = tokio::spawn(serve_production_http1_inner(
            listener,
            ProductionRuntimeConfig {
                max_concurrent_connections: capacity,
                request_timeout,
                processor_timeout: OPERATION_BUDGET,
                shutdown_grace: Duration::from_secs(2),
            },
            processor,
            async move {
                let _ = stopped.await;
            },
            body_collection_started,
            Some(connection_task_tx),
            Some(Arc::clone(&connection_task_peak)),
        ));
        Self {
            address,
            observations,
            connection_tasks,
            connection_task_peak,
            body_collection_started: body_collection_receiver,
            shutdown: Some(shutdown),
            server: Some(server),
            recorder: Some(recorder),
        }
    }

    async fn connect_and_wait_for_tasks(&mut self, expected: usize) -> TcpStream {
        let stream = timeout(OPERATION_BUDGET, TcpStream::connect(self.address))
            .await
            .expect("downstream connect should finish within five seconds")
            .expect("downstream should connect to the owned production listener");
        self.wait_for_tasks(expected).await;
        stream
    }

    async fn wait_for_tasks(&mut self, expected: usize) {
        let observed = timeout(OPERATION_BUDGET, async {
            self.connection_tasks
                .wait_for(|count| *count == expected)
                .await
                .map(|_| ())
        })
        .await;
        match observed {
            Ok(result) => result.expect("production task watch should remain open"),
            Err(_) => panic!(
                "timed out waiting for {expected} production task(s); observed {}",
                *self.connection_tasks.borrow()
            ),
        }
        assert!(
            *self.connection_tasks.borrow() <= 2,
            "C3a must never retain more than two production connection tasks"
        );
    }

    async fn wait_for_body_collection(&mut self) {
        timeout(
            OPERATION_BUDGET,
            self.body_collection_started
                .take()
                .expect("this C3a case should own one body-start signal"),
        )
        .await
        .expect("body collection should start within five seconds")
        .expect("body collection signal should be delivered");
    }

    async fn next_upstream(&mut self) -> ReadyUpstreamRequest {
        self.recorder
            .as_mut()
            .expect("owned recorder should remain available")
            .next_ready()
            .await
    }

    fn snapshot(&self) -> CounterSnapshot {
        CounterSnapshot {
            normal_process: self.observations.normal_process.load(Ordering::SeqCst),
            request_rejections: self
                .observations
                .request_rejections
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone(),
            pre_service_rejections: self
                .observations
                .pre_service_rejections
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone(),
            current_processors: self.observations.current_processors.load(Ordering::SeqCst),
            peak_processors: self.observations.peak_processors.load(Ordering::SeqCst),
            peak_connection_tasks: self.connection_task_peak.load(Ordering::SeqCst),
            upstream_requests: self
                .recorder
                .as_ref()
                .expect("owned recorder should remain available")
                .completed_count(),
        }
    }

    async fn finish(mut self) -> Vec<RecordedUpstreamRequest> {
        self.shutdown
            .take()
            .expect("production listener should have one shutdown signal")
            .send(())
            .expect("production listener should remain live through clean shutdown");
        AbortOnDropTask::new(
            self.server
                .take()
                .expect("production listener should have one task"),
        )
        .join("production listener")
        .await
        .expect("production listener should drain cleanly");
        self.recorder
            .take()
            .expect("harness should own one upstream recorder")
            .finish()
            .await
    }
}

impl Drop for LifecycleHarness {
    fn drop(&mut self) {
        if let Some(server) = &self.server {
            server.abort();
        }
        // UpstreamRecorder's Drop aborts its accept tree on assertion unwind.
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TerminalKind {
    Eof,
    Reset,
}

#[derive(Debug, PartialEq, Eq)]
struct TerminalResponse {
    bytes: Vec<u8>,
    terminal: TerminalKind,
}

async fn read_terminal_response(stream: &mut TcpStream) -> TerminalResponse {
    timeout(OPERATION_BUDGET, async {
        let mut bytes = Vec::new();
        let mut buffer = [0_u8; 1024];
        loop {
            match stream.read(&mut buffer).await {
                Ok(0) => {
                    return TerminalResponse {
                        bytes,
                        terminal: TerminalKind::Eof,
                    };
                }
                Ok(count) => {
                    assert!(
                        bytes.len() + count <= CAPTURE_LIMIT,
                        "downstream response exceeded {CAPTURE_LIMIT} bytes"
                    );
                    bytes.extend_from_slice(&buffer[..count]);
                }
                Err(error) if terminal_reset(&error) => {
                    return TerminalResponse {
                        bytes,
                        terminal: TerminalKind::Reset,
                    };
                }
                Err(error) => panic!("downstream response read failed: {error}"),
            }
        }
    })
    .await
    .expect("downstream peer must reach EOF/reset, not a timeout")
}

async fn write_all_bounded(stream: &mut TcpStream, bytes: &[u8]) {
    timeout(OPERATION_BUDGET, stream.write_all(bytes))
        .await
        .expect("downstream write should finish within five seconds")
        .expect("downstream write should succeed");
}

async fn attempt_write_then_terminal(stream: &mut TcpStream, bytes: &[u8]) -> TerminalResponse {
    match timeout(OPERATION_BUDGET, stream.write_all(bytes)).await {
        Ok(Ok(())) => read_terminal_response(stream).await,
        Ok(Err(error)) if terminal_reset(&error) => TerminalResponse {
            bytes: Vec::new(),
            terminal: TerminalKind::Reset,
        },
        Ok(Err(error)) => panic!("cap+1 write failed unexpectedly: {error}"),
        Err(_) => panic!("cap+1 write did not terminate within five seconds"),
    }
}

async fn write_one_byte_drip(stream: &mut TcpStream, bytes: &[u8]) -> usize {
    assert!(bytes.len() <= 32, "drip fixture is capped at 32 writes");
    let mut completed = 0;
    let started = Instant::now();
    let mut previous_attempt = started;
    for (index, byte) in bytes.iter().enumerate() {
        let attempt = Instant::now();
        if index > 0 {
            assert!(
                attempt.duration_since(previous_attempt) <= MAX_DRIP_ATTEMPT_GAP,
                "drip scheduling gap exceeded 250 ms and invalidated paced-progress evidence"
            );
        }
        previous_attempt = attempt;
        match timeout(
            OPERATION_BUDGET,
            stream.write_all(std::slice::from_ref(byte)),
        )
        .await
        .expect("one-byte drip write should be bounded")
        {
            Ok(()) => completed += 1,
            Err(error) if terminal_reset(&error) => break,
            Err(error) => panic!("one-byte drip write failed unexpectedly: {error}"),
        }
        // This fixed pacing is the behavior under test. Individual client
        // writes make no claim about TCP or Hyper read segmentation.
        sleep(DRIP_INTERVAL).await;
    }
    assert!(
        completed >= MIN_DRIP_WRITES,
        "drip case must sustain at least {MIN_DRIP_WRITES} paced writes"
    );
    assert!(
        started.elapsed() >= DRIP_INTERVAL * (MIN_DRIP_WRITES as u32 - 1),
        "drip fixture did not span its required paced-progress window"
    );
    completed
}

fn request(target: &str) -> Vec<u8> {
    format!("GET {target} HTTP/1.1\r\nHost: proxy.owned.test\r\nConnection: close\r\n\r\n")
        .into_bytes()
}

fn assert_upstream_request(request: &RecordedUpstreamRequest, target: &str) {
    assert_eq!(request.method, "GET");
    assert_eq!(request.target, target);
    assert!(request.body.is_empty());
    assert!(request.wire.len() <= CAPTURE_LIMIT);
}

fn response_header_values<'a>(head: &'a str, name: &str) -> Vec<&'a str> {
    head.split("\r\n")
        .skip(1)
        .filter_map(|line| line.split_once(':'))
        .filter(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.trim())
        .collect()
}

fn assert_http_response(response: &TerminalResponse, status: u16, body: &[u8]) {
    let end = head_end(&response.bytes).expect("response should contain one complete head");
    let head = std::str::from_utf8(&response.bytes[..end - 4])
        .expect("fixture response head should be ASCII");
    assert!(
        head.starts_with(&format!("HTTP/1.1 {status} ")),
        "unexpected downstream status: {response:?}"
    );
    assert_eq!(
        response_header_values(head, "content-length"),
        [body.len().to_string().as_str()],
        "response should contain one exact content length"
    );
    assert_eq!(
        response_header_values(head, "connection"),
        ["close"],
        "fixture asks the production listener to close"
    );
    assert!(
        response_header_values(head, "transfer-encoding").is_empty(),
        "bounded fixed response should not use transfer encoding"
    );
    assert_eq!(&response.bytes[end..], body, "exact downstream body");
}

fn assert_record_targets(records: &[RecordedUpstreamRequest], expected: &[&str]) {
    let mut actual = records
        .iter()
        .map(|record| record.target.as_str())
        .collect::<Vec<_>>();
    let mut expected = expected.to_vec();
    actual.sort_unstable();
    expected.sort_unstable();
    assert_eq!(actual, expected, "joined complete upstream request set");
    for record in records {
        assert_upstream_request(record, &record.target);
    }
}

async fn recovery_exchange(harness: &mut LifecycleHarness, target: &str) -> TerminalResponse {
    let mut client = harness.connect_and_wait_for_tasks(1).await;
    write_all_bounded(&mut client, &request(target)).await;
    let capture = harness.next_upstream().await;
    assert_upstream_request(&capture.request, target);
    capture.release();
    let response = read_terminal_response(&mut client).await;
    assert_http_response(&response, 200, target.as_bytes());
    harness.wait_for_tasks(0).await;
    response
}

async fn exact_capacity_case() {
    const FIRST: &str = "/capacity/one";
    const SECOND: &str = "/capacity/two";
    const RECOVERED: &str = "/capacity/recovered";
    let mut harness = LifecycleHarness::start(2, Duration::from_secs(2), false).await;

    let mut first = harness.connect_and_wait_for_tasks(1).await;
    write_all_bounded(&mut first, &request(FIRST)).await;
    let first_capture = harness.next_upstream().await;
    assert_upstream_request(&first_capture.request, FIRST);

    let mut second = harness.connect_and_wait_for_tasks(2).await;
    write_all_bounded(&mut second, &request(SECOND)).await;
    let second_capture = harness.next_upstream().await;
    assert_upstream_request(&second_capture.request, SECOND);

    assert_eq!(
        harness.snapshot(),
        CounterSnapshot {
            normal_process: 2,
            request_rejections: Vec::new(),
            pre_service_rejections: Vec::new(),
            current_processors: 2,
            peak_processors: 2,
            peak_connection_tasks: 2,
            upstream_requests: 2,
        },
        "both permits are owned only after two complete upstream captures"
    );

    let mut excess = timeout(OPERATION_BUDGET, TcpStream::connect(harness.address))
        .await
        .expect("cap+1 connect should terminate within five seconds")
        .expect("cap+1 downstream peer must successfully connect");
    let excess_outcome =
        attempt_write_then_terminal(&mut excess, &request("/capacity/excess")).await;
    assert!(
        excess_outcome.bytes.is_empty(),
        "cap+1 must close/reset without response bytes: {excess_outcome:?}"
    );
    harness.wait_for_tasks(2).await;
    assert_eq!(
        harness.snapshot(),
        CounterSnapshot {
            normal_process: 2,
            request_rejections: Vec::new(),
            pre_service_rejections: Vec::new(),
            current_processors: 2,
            peak_processors: 2,
            peak_connection_tasks: 2,
            upstream_requests: 2,
        },
        "terminal cap+1 handling must create zero excess work"
    );

    first_capture.release();
    let first_response = read_terminal_response(&mut first).await;
    assert_http_response(&first_response, 200, FIRST.as_bytes());
    harness.wait_for_tasks(1).await;
    assert_eq!(harness.snapshot().current_processors, 1);

    let mut recovered = harness.connect_and_wait_for_tasks(2).await;
    write_all_bounded(&mut recovered, &request(RECOVERED)).await;
    let recovered_capture = harness.next_upstream().await;
    assert_upstream_request(&recovered_capture.request, RECOVERED);
    assert_eq!(
        harness.snapshot(),
        CounterSnapshot {
            normal_process: 3,
            request_rejections: Vec::new(),
            pre_service_rejections: Vec::new(),
            current_processors: 2,
            peak_processors: 2,
            peak_connection_tasks: 2,
            upstream_requests: 3,
        },
        "one released slot must admit exactly one replacement request"
    );

    second_capture.release();
    recovered_capture.release();
    let second_response = read_terminal_response(&mut second).await;
    let recovered_response = read_terminal_response(&mut recovered).await;
    assert_http_response(&second_response, 200, SECOND.as_bytes());
    assert_http_response(&recovered_response, 200, RECOVERED.as_bytes());
    harness.wait_for_tasks(0).await;
    assert_eq!(
        harness.snapshot(),
        CounterSnapshot {
            normal_process: 3,
            request_rejections: Vec::new(),
            pre_service_rejections: Vec::new(),
            current_processors: 0,
            peak_processors: 2,
            peak_connection_tasks: 2,
            upstream_requests: 3,
        },
        "all capacity work must quiesce with peak exactly two"
    );
    let records = harness.finish().await;
    assert_record_targets(&records, &[FIRST, SECOND, RECOVERED]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn exact_capacity_overload_has_zero_excess_work_and_recovers() {
    timeout(TEST_BUDGET, exact_capacity_case())
        .await
        .expect("exact-capacity C3a case exceeded 20 seconds");
}

#[derive(Clone, Copy, Debug)]
enum SlowHeadShape {
    Idle,
    ByteDrip,
}

async fn slow_head_case(shape: SlowHeadShape) {
    let recovery_target = match shape {
        SlowHeadShape::Idle => "/recovery/idle",
        SlowHeadShape::ByteDrip => "/recovery/header-drip",
    };
    let mut harness = LifecycleHarness::start(1, STAGE_DEADLINE, false).await;
    let mut client = harness.connect_and_wait_for_tasks(1).await;
    let stage_started = Instant::now();
    if matches!(shape, SlowHeadShape::ByteDrip) {
        let prefix = b"GET /header-drip HTTP/1.1\r\n";
        let completed = write_one_byte_drip(&mut client, &prefix[..12]).await;
        assert!(completed <= 12, "finite header drip write count");
    }
    let outcome = read_terminal_response(&mut client).await;
    assert!(
        outcome.bytes.is_empty(),
        "slow head must terminate without response bytes: {shape:?} {outcome:?}"
    );
    assert!(
        stage_started.elapsed() <= STAGE_TERMINAL_BOUND,
        "{shape:?} exceeded one absolute header-stage budget"
    );
    harness.wait_for_tasks(0).await;
    assert_eq!(
        harness.snapshot(),
        CounterSnapshot {
            normal_process: 0,
            request_rejections: Vec::new(),
            pre_service_rejections: vec![ProductionPreServiceRejection::HeaderReadTimedOut],
            current_processors: 0,
            peak_processors: 0,
            peak_connection_tasks: 1,
            upstream_requests: 0,
        },
        "slow head must release capacity with one exact pre-service timeout"
    );

    recovery_exchange(&mut harness, recovery_target).await;
    assert_eq!(
        harness.snapshot(),
        CounterSnapshot {
            normal_process: 1,
            request_rejections: Vec::new(),
            pre_service_rejections: vec![ProductionPreServiceRejection::HeaderReadTimedOut],
            current_processors: 0,
            peak_processors: 1,
            peak_connection_tasks: 1,
            upstream_requests: 1,
        },
        "same listener must recover after the slow-head timeout"
    );
    let records = harness.finish().await;
    assert_record_targets(&records, &[recovery_target]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn idle_and_header_byte_drip_deadlines_release_capacity_and_recover() {
    timeout(TEST_BUDGET, async {
        slow_head_case(SlowHeadShape::Idle).await;
        slow_head_case(SlowHeadShape::ByteDrip).await;
    })
    .await
    .expect("idle/header-drip C3a cases exceeded 20 seconds");
}

async fn body_drip_case() {
    const RECOVERY: &str = "/recovery/body-drip";
    let mut harness = LifecycleHarness::start(1, STAGE_DEADLINE, true).await;
    let mut client = harness.connect_and_wait_for_tasks(1).await;
    let admitted = Instant::now();
    // Spend part of the independent head stage before completing a small
    // Content-Length head. The body stage begins only at the signal below.
    sleep(Duration::from_millis(400)).await;
    write_all_bounded(
        &mut client,
        b"POST /body-drip HTTP/1.1\r\nHost: proxy.owned.test\r\nContent-Length: 16\r\nConnection: close\r\n\r\n",
    )
    .await;
    harness.wait_for_body_collection().await;
    let body_stage_started = Instant::now();
    let completed = write_one_byte_drip(&mut client, b"abcdefghijkl").await;
    assert!(completed <= 12, "body drip must remain below length 16");
    let response = read_terminal_response(&mut client).await;
    assert_http_response(&response, 408, b"");
    assert!(
        body_stage_started.elapsed() <= STAGE_TERMINAL_BOUND,
        "positive body progress reset the absolute body-stage budget"
    );
    harness.wait_for_tasks(0).await;
    assert!(
        admitted.elapsed() <= COMPOSED_HEAD_BODY_BOUND,
        "separate head and body stages exceeded the generous composed bound"
    );
    assert_eq!(
        harness.snapshot(),
        CounterSnapshot {
            normal_process: 0,
            request_rejections: vec![ProductionRequestRejection::RequestTimedOut],
            pre_service_rejections: Vec::new(),
            current_processors: 0,
            peak_processors: 0,
            peak_connection_tasks: 1,
            upstream_requests: 0,
        },
        "body-stage timeout must not become normal or upstream work"
    );

    recovery_exchange(&mut harness, RECOVERY).await;
    assert_eq!(
        harness.snapshot(),
        CounterSnapshot {
            normal_process: 1,
            request_rejections: vec![ProductionRequestRejection::RequestTimedOut],
            pre_service_rejections: Vec::new(),
            current_processors: 0,
            peak_processors: 1,
            peak_connection_tasks: 1,
            upstream_requests: 1,
        },
        "same listener must recover after body-stage timeout"
    );
    let records = harness.finish().await;
    assert_record_targets(&records, &[RECOVERY]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn head_then_body_byte_drip_has_composed_stage_bound_and_recovers() {
    timeout(TEST_BUDGET, body_drip_case())
        .await
        .expect("body-drip C3a case exceeded 20 seconds");
}

async fn partial_body_case(body: &[u8], recovery_target: &str) {
    assert!(matches!(body.len(), 0 | 2), "C1 partial-body shapes");
    let mut harness = LifecycleHarness::start(1, Duration::from_secs(2), true).await;
    let mut client = harness.connect_and_wait_for_tasks(1).await;
    write_all_bounded(
        &mut client,
        b"POST /partial HTTP/1.1\r\nHost: proxy.owned.test\r\nContent-Length: 4\r\nConnection: close\r\n\r\n",
    )
    .await;
    harness.wait_for_body_collection().await;
    write_all_bounded(&mut client, body).await;
    timeout(OPERATION_BUDGET, client.shutdown())
        .await
        .expect("partial client half-close should be bounded")
        .expect("partial client should half-close its write side");
    let response = read_terminal_response(&mut client).await;
    assert_http_response(&response, 200, b"");
    harness.wait_for_tasks(0).await;
    assert_eq!(
        harness.snapshot(),
        CounterSnapshot {
            normal_process: 0,
            request_rejections: Vec::new(),
            pre_service_rejections: Vec::new(),
            current_processors: 0,
            peak_processors: 0,
            peak_connection_tasks: 1,
            upstream_requests: 0,
        },
        "partial-body EOF is neither timeout nor successful processing"
    );

    recovery_exchange(&mut harness, recovery_target).await;
    assert_eq!(
        harness.snapshot(),
        CounterSnapshot {
            normal_process: 1,
            request_rejections: Vec::new(),
            pre_service_rejections: Vec::new(),
            current_processors: 0,
            peak_processors: 1,
            peak_connection_tasks: 1,
            upstream_requests: 1,
        },
        "same listener must recover after partial-body EOF"
    );
    let records = harness.finish().await;
    assert_record_targets(&records, &[recovery_target]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn partial_body_disconnect_releases_capacity_and_same_listener_recovers() {
    timeout(TEST_BUDGET, async {
        partial_body_case(b"", "/recovery/partial-zero").await;
        partial_body_case(b"bo", "/recovery/partial-two").await;
    })
    .await
    .expect("partial-body C3a cases exceeded 20 seconds");
}
