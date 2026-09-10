//! C3a/C3b/C3c: bounded capacity, slow/partial-client cleanup, connection reuse,
//! version-rejection recovery, and isolated shutdown through the production listener and
//! production upstream dispatcher. This is finite lifecycle regression
//! evidence, not load, latency, RSS, or soak evidence.

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
    ShutdownObservation,
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
    async fn start(peer_limit: usize) -> Self {
        assert!((1..=4).contains(&peer_limit), "bounded upstream peer limit");
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
                        assert!(records.len() + connections.len() < peer_limit, "upstream peer limit exceeded");
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
                            records.len() + connections.len() < peer_limit,
                            "upstream peer limit exceeded"
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
    connection_tasks_started: Arc<AtomicUsize>,
    closed_admission_service_calls: Arc<AtomicUsize>,
    body_collection_started: Option<oneshot::Receiver<()>>,
    shutdown: Option<oneshot::Sender<()>>,
    shutdown_started: Option<oneshot::Receiver<()>>,
    server: Option<JoinHandle<Result<(), ProductionRuntimeError>>>,
    recorder: Option<UpstreamRecorder>,
}

impl LifecycleHarness {
    async fn start(
        capacity: usize,
        request_timeout: Duration,
        observe_body_collection: bool,
    ) -> Self {
        Self::start_with_shutdown_grace(
            capacity,
            request_timeout,
            observe_body_collection,
            Duration::from_secs(2),
            4,
        )
        .await
    }

    async fn start_with_shutdown_grace(
        capacity: usize,
        request_timeout: Duration,
        observe_body_collection: bool,
        shutdown_grace: Duration,
        upstream_peer_limit: usize,
    ) -> Self {
        assert!((1..=2).contains(&capacity), "C3a task bound is one or two");
        let recorder = UpstreamRecorder::start(upstream_peer_limit).await;
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
        let (shutdown_observed, shutdown_started) = oneshot::channel();
        let (connection_task_tx, connection_tasks) = watch::channel(0);
        let connection_task_peak = Arc::new(AtomicUsize::new(0));
        let connection_tasks_started = Arc::new(AtomicUsize::new(0));
        let closed_admission_service_calls = Arc::new(AtomicUsize::new(0));
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
                shutdown_grace,
            },
            processor,
            async move {
                let _ = stopped.await;
            },
            body_collection_started,
            Some(connection_task_tx),
            Some(Arc::clone(&connection_task_peak)),
            Some(ShutdownObservation {
                started: shutdown_observed,
                connection_tasks_started: Arc::clone(&connection_tasks_started),
                closed_admission_service_calls: Arc::clone(&closed_admission_service_calls),
            }),
        ));
        Self {
            address,
            observations,
            connection_tasks,
            connection_task_peak,
            connection_tasks_started,
            closed_admission_service_calls,
            body_collection_started: body_collection_receiver,
            shutdown: Some(shutdown),
            shutdown_started: Some(shutdown_started),
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

    async fn begin_shutdown(&mut self) -> Instant {
        let requested = Instant::now();
        self.shutdown
            .take()
            .expect("production listener should have one shutdown signal")
            .send(())
            .expect("production listener should remain live through clean shutdown");
        timeout(
            OPERATION_BUDGET,
            self.shutdown_started
                .take()
                .expect("production listener should have one shutdown-started signal"),
        )
        .await
        .expect("production admission closure should be bounded")
        .expect("admission must close, drain must be sent, and listener dropped");
        requested
    }

    async fn finish_shutdown(
        mut self,
        expected: Result<(), ProductionRuntimeError>,
    ) -> Vec<RecordedUpstreamRequest> {
        assert!(self.shutdown.is_none(), "shutdown sender must be consumed");
        assert!(
            self.shutdown_started.is_none(),
            "actual shutdown start must be observed before joining"
        );
        self.wait_for_tasks(0).await;
        // Keep abort-on-drop ownership across the bounded join and any outer
        // cancellation. A drained task count alone is not the server result.
        let result = AbortOnDropTask::new(
            self.server
                .take()
                .expect("production listener should have one task"),
        )
        .join("production listener")
        .await;
        assert_eq!(result, expected, "exact production shutdown result");
        assert_eq!(*self.connection_tasks.borrow(), 0, "joined connection set");
        self.recorder
            .take()
            .expect("harness should own one upstream recorder")
            .finish()
            .await
    }

    async fn finish(mut self) -> Vec<RecordedUpstreamRequest> {
        self.begin_shutdown().await;
        // C3a/C3b retain their clean-result oracle and finish the recorder
        // only after the production listener has joined.
        self.finish_shutdown(Ok(())).await
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

async fn observe_terminal_response_after_write(
    stream: &mut TcpStream,
    write_result: std::io::Result<()>,
) -> TerminalResponse {
    match write_result {
        Ok(()) => {}
        Err(error) if terminal_reset(&error) => {}
        Err(error) => panic!("cap+1 write failed unexpectedly: {error}"),
    }
    // A terminal write error does not prove that the peer sent no response:
    // bytes may already be queued on the receive side. Both allowed write
    // outcomes must therefore traverse the same bounded, capped read oracle.
    read_terminal_response(stream).await
}

async fn attempt_write_then_terminal(stream: &mut TcpStream, bytes: &[u8]) -> TerminalResponse {
    let write_result = timeout(OPERATION_BUDGET, stream.write_all(bytes))
        .await
        .expect("cap+1 write did not terminate within five seconds");
    observe_terminal_response_after_write(stream, write_result).await
}

async fn write_reset_oracle_preserves_buffered_response_bytes() {
    const BUFFERED_RESPONSE: &[u8] =
        b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 4\r\nConnection: close\r\n\r\nbusy";
    let listener = timeout(OPERATION_BUDGET, TcpListener::bind("127.0.0.1:0"))
        .await
        .expect("oracle listener bind should be bounded")
        .expect("oracle listener should bind");
    let address = listener
        .local_addr()
        .expect("oracle listener should have an address");
    let writer = AbortOnDropTask::new(tokio::spawn(async move {
        let (mut stream, _) = timeout(OPERATION_BUDGET, listener.accept())
            .await
            .expect("oracle accept should be bounded")
            .expect("oracle listener should accept one peer");
        timeout(OPERATION_BUDGET, stream.write_all(BUFFERED_RESPONSE))
            .await
            .expect("buffered oracle response write should be bounded")
            .expect("buffered oracle response should write");
        timeout(OPERATION_BUDGET, stream.shutdown())
            .await
            .expect("oracle writer shutdown should be bounded")
            .expect("oracle writer should shut down");
    }));
    let mut client = timeout(OPERATION_BUDGET, TcpStream::connect(address))
        .await
        .expect("oracle client connect should be bounded")
        .expect("oracle client should connect");
    writer.join("buffered-response oracle writer").await;

    let outcome = observe_terminal_response_after_write(
        &mut client,
        Err(std::io::Error::new(
            ErrorKind::ConnectionReset,
            "synthetic terminal write result",
        )),
    )
    .await;
    assert_eq!(
        outcome.bytes, BUFFERED_RESPONSE,
        "terminal write errors must not fabricate an empty receive result"
    );
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
    timeout(TEST_BUDGET, async {
        write_reset_oracle_preserves_buffered_response_bytes().await;
        exact_capacity_case().await;
    })
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

mod c3b {
    use super::*;

    #[derive(Default)]
    pub(super) struct ResponseFrames {
        // Keep the entire peer capture, including consumed frames, under one
        // aggregate cap. Advancing the cursor never discards following bytes
        // or resets the byte budget between keep-alive/pipelined responses.
        wire: Vec<u8>,
        consumed: usize,
        terminal: Option<TerminalKind>,
    }

    pub(super) struct ResponseFrame<'a> {
        pub(super) head: &'a str,
        body: &'a [u8],
    }

    impl ResponseFrames {
        async fn read_more(&mut self, stream: &mut TcpStream) {
            assert!(
                self.terminal.is_none(),
                "EOF/reset is terminal for this peer"
            );
            let mut buffer = [0_u8; 1024];
            match timeout(OPERATION_BUDGET, stream.read(&mut buffer))
                .await
                .expect("downstream frame read must finish within five seconds")
            {
                Ok(0) => self.terminal = Some(TerminalKind::Eof),
                Ok(count) => {
                    assert!(
                        self.wire.len() + count <= CAPTURE_LIMIT,
                        "aggregate downstream peer capture exceeded {CAPTURE_LIMIT} bytes"
                    );
                    self.wire.extend_from_slice(&buffer[..count]);
                }
                Err(error) if terminal_reset(&error) => self.terminal = Some(TerminalKind::Reset),
                Err(error) => panic!("downstream frame read failed: {error}"),
            }
        }

        pub(super) async fn next_frame(&mut self, stream: &mut TcpStream) -> ResponseFrame<'_> {
            assert!(
                self.terminal.is_none(),
                "cannot parse another frame after EOF/reset"
            );
            let start = self.consumed;
            let (end, frame_end) = timeout(OPERATION_BUDGET, async {
                let end = loop {
                    if let Some(relative_end) = head_end(&self.wire[start..]) {
                        break start + relative_end;
                    }
                    self.read_more(stream).await;
                    assert!(
                        self.terminal.is_none(),
                        "peer terminated before a complete response head: {:?}",
                        self.wire
                    );
                };
                let body_len = {
                    let head = std::str::from_utf8(&self.wire[start..end - 4])
                        .expect("response head should be ASCII");
                    assert!(head.is_ascii(), "response head should be ASCII");
                    let mut lines = head.split("\r\n");
                    let status = lines.next().expect("response must have a status line");
                    assert!(
                        status.starts_with("HTTP/1.1 ") || status.starts_with("HTTP/1.0 "),
                        "unexpected response version: {status}"
                    );
                    let mut content_length = None;
                    for line in lines {
                        let (name, value) = line
                            .split_once(':')
                            .expect("response header must contain a separator");
                        assert!(
                            !name.eq_ignore_ascii_case("transfer-encoding"),
                            "fixed-length response must not contain transfer encoding"
                        );
                        if name.eq_ignore_ascii_case("content-length") {
                            assert!(content_length.is_none(), "exactly one content length");
                            let value = value.trim_matches([' ', '\t']);
                            assert!(
                                !value.is_empty()
                                    && value.bytes().all(|byte| byte.is_ascii_digit()),
                                "content length must contain only decimal digits"
                            );
                            content_length = Some(
                                value
                                    .parse::<usize>()
                                    .expect("content length must not overflow"),
                            );
                        }
                    }
                    content_length.expect("response must contain one content length")
                };
                assert!(
                    body_len <= CAPTURE_LIMIT - end,
                    "response body must fit in the remaining aggregate peer budget"
                );
                let frame_end = end + body_len;
                while self.wire.len() < frame_end {
                    self.read_more(stream).await;
                    assert!(
                        self.terminal.is_none(),
                        "peer terminated before the declared response body was complete"
                    );
                }
                (end, frame_end)
            })
            .await
            .expect("one complete downstream response frame must arrive within five seconds");
            self.consumed = frame_end;
            ResponseFrame {
                head: std::str::from_utf8(&self.wire[start..end - 4])
                    .expect("validated response head should remain ASCII"),
                body: &self.wire[end..frame_end],
            }
        }

        pub(super) async fn next_frame_or_terminal(
            &mut self,
            stream: &mut TcpStream,
        ) -> Option<ResponseFrame<'_>> {
            assert!(
                self.terminal.is_none(),
                "optional frame check must start before EOF/reset"
            );
            if self.consumed == self.wire.len() {
                self.read_more(stream).await;
                if self.terminal.is_some() {
                    assert_eq!(
                        self.consumed,
                        self.wire.len(),
                        "terminal close cannot hide buffered response bytes"
                    );
                    return None;
                }
            }
            Some(self.next_frame(stream).await)
        }

        pub(super) async fn expect_terminal(&mut self, stream: &mut TcpStream) -> TerminalKind {
            assert_eq!(
                self.consumed,
                self.wire.len(),
                "extra response bytes were buffered after the final expected frame: {:?}",
                &self.wire[self.consumed..]
            );
            self.read_more(stream).await;
            assert_eq!(
                self.consumed,
                self.wire.len(),
                "extra response bytes arrived after the final expected frame: {:?}",
                &self.wire[self.consumed..]
            );
            self.terminal
                .expect("peer must reach terminal EOF/reset, never a timeout")
        }
    }

    pub(super) fn assert_frame(frame: &ResponseFrame<'_>, status_line: &str, body: &[u8]) {
        assert_eq!(frame.head.split("\r\n").next(), Some(status_line));
        assert_eq!(
            frame.body, body,
            "exact distinguishable downstream response body"
        );
    }

    fn reuse_request(target: &str, close: bool) -> Vec<u8> {
        if close {
            request(target)
        } else {
            format!("GET {target} HTTP/1.1\r\nHost: proxy.owned.test\r\n\r\n").into_bytes()
        }
    }

    fn assert_normal_work(harness: &LifecycleHarness, total: usize, current: usize) {
        assert_eq!(
            harness.snapshot(),
            CounterSnapshot {
                normal_process: total,
                request_rejections: Vec::new(),
                pre_service_rejections: Vec::new(),
                current_processors: current,
                peak_processors: 1,
                peak_connection_tasks: 1,
                upstream_requests: total,
            },
            "exactly-once serial processing and complete upstream work"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn three_sequential_keep_alive_requests_and_fresh_connection_recover() {
        timeout(TEST_BUDGET, async {
            const TARGETS: [&str; 3] = ["/sequential/one", "/sequential/two", "/sequential/three"];
            const RECOVERY: &str = "/recovery/sequential";
            let mut harness = LifecycleHarness::start(1, OPERATION_BUDGET, false).await;
            let mut client = harness.connect_and_wait_for_tasks(1).await;
            let mut responses = ResponseFrames::default();

            for (index, target) in TARGETS.iter().enumerate() {
                let close = index == TARGETS.len() - 1;
                // Each preceding frame has been fully parsed before this
                // bounded application write on the same TCP connection.
                write_all_bounded(&mut client, &reuse_request(target, close)).await;
                let capture = harness.next_upstream().await;
                assert_upstream_request(&capture.request, target);
                harness.wait_for_tasks(1).await;
                assert_normal_work(&harness, index + 1, 1);
                capture.release();

                let frame = responses.next_frame(&mut client).await;
                assert_frame(&frame, "HTTP/1.1 200 OK", target.as_bytes());
                if close {
                    assert_eq!(response_header_values(frame.head, "connection"), ["close"]);
                } else {
                    assert!(response_header_values(frame.head, "connection").is_empty());
                    harness.wait_for_tasks(1).await;
                }
                assert_normal_work(&harness, index + 1, 0);
            }
            responses.expect_terminal(&mut client).await;
            harness.wait_for_tasks(0).await;
            assert_normal_work(&harness, 3, 0);
            drop(client);

            recovery_exchange(&mut harness, RECOVERY).await;
            assert_normal_work(&harness, 4, 0);
            let records = harness.finish().await;
            assert_record_targets(&records, &[TARGETS[0], TARGETS[1], TARGETS[2], RECOVERY]);
        })
        .await
        .expect("sequential keep-alive C3b case exceeded 20 seconds");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn three_pipelined_requests_are_ordered_once_and_fresh_connection_recovers() {
        timeout(TEST_BUDGET, async {
            const TARGETS: [&str; 3] = ["/pipeline/one", "/pipeline/two", "/pipeline/three"];
            const RECOVERY: &str = "/recovery/pipeline";
            let mut harness = LifecycleHarness::start(1, OPERATION_BUDGET, false).await;
            let mut client = harness.connect_and_wait_for_tasks(1).await;
            let pipeline = TARGETS
                .iter()
                .enumerate()
                .flat_map(|(index, target)| reuse_request(target, index == TARGETS.len() - 1))
                .collect::<Vec<_>>();
            assert!(
                pipeline.len() <= CAPTURE_LIMIT,
                "bounded complete pipeline write"
            );
            // One application write of three complete requests, with no claim
            // about TCP segmentation or Hyper's individual reads.
            write_all_bounded(&mut client, &pipeline).await;
            for (index, target) in TARGETS.iter().enumerate() {
                let capture = harness.next_upstream().await;
                assert_upstream_request(&capture.request, target);
                harness.wait_for_tasks(1).await;
                assert_normal_work(&harness, index + 1, 1);
                capture.release();
            }

            // Delay downstream reads until all three captures are released;
            // one peer buffer retains any coalesced following response bytes.
            let mut responses = ResponseFrames::default();
            for (index, target) in TARGETS.iter().enumerate() {
                let frame = responses.next_frame(&mut client).await;
                assert_frame(&frame, "HTTP/1.1 200 OK", target.as_bytes());
                if index == TARGETS.len() - 1 {
                    assert_eq!(response_header_values(frame.head, "connection"), ["close"]);
                } else {
                    assert!(response_header_values(frame.head, "connection").is_empty());
                }
            }
            // Check both already-buffered bytes and the next bounded socket
            // read. Even a partial fourth response fails; timeout cannot pass.
            responses.expect_terminal(&mut client).await;
            harness.wait_for_tasks(0).await;
            assert_normal_work(&harness, 3, 0);
            drop(client);

            recovery_exchange(&mut harness, RECOVERY).await;
            assert_normal_work(&harness, 4, 0);
            let records = harness.finish().await;
            assert_record_targets(&records, &[TARGETS[0], TARGETS[1], TARGETS[2], RECOVERY]);
        })
        .await
        .expect("ordinary pipeline C3b case exceeded 20 seconds");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn raw_http10_rejection_releases_task_and_listener_recovers() {
        timeout(TEST_BUDGET, async {
            const RECOVERY: &str = "/recovery/http10";
            let mut harness = LifecycleHarness::start(1, OPERATION_BUDGET, false).await;
            let mut client = harness.connect_and_wait_for_tasks(1).await;
            write_all_bounded(
                &mut client,
                b"GET /version/http10 HTTP/1.0\r\nHost: proxy.owned.test\r\nConnection: close\r\n\r\n",
            )
            .await;
            let mut responses = ResponseFrames::default();
            let frame = responses.next_frame(&mut client).await;
            assert_frame(&frame, "HTTP/1.0 400 Bad Request", b"");
            // HTTP/1.0 defaults to close; Hyper need not add a close header.
            assert!(response_header_values(frame.head, "connection").is_empty());
            responses.expect_terminal(&mut client).await;
            harness.wait_for_tasks(0).await;
            assert_eq!(
                harness.snapshot(),
                CounterSnapshot {
                    normal_process: 0,
                    request_rejections: vec![ProductionRequestRejection::UnsupportedHttpVersion],
                    pre_service_rejections: Vec::new(),
                    current_processors: 0,
                    peak_processors: 0,
                    peak_connection_tasks: 1,
                    upstream_requests: 0,
                },
                "raw HTTP/1.0 must reach typed policy once and release without normal work"
            );
            drop(client);

            recovery_exchange(&mut harness, RECOVERY).await;
            assert_eq!(
                harness.snapshot(),
                CounterSnapshot {
                    normal_process: 1,
                    request_rejections: vec![ProductionRequestRejection::UnsupportedHttpVersion],
                    pre_service_rejections: Vec::new(),
                    current_processors: 0,
                    peak_processors: 1,
                    peak_connection_tasks: 1,
                    upstream_requests: 1,
                },
                "same listener must recover after exact HTTP/1.0 policy rejection"
            );
            let records = harness.finish().await;
            assert_record_targets(&records, &[RECOVERY]);
        })
        .await
        .expect("raw HTTP/1.0 C3b case exceeded 20 seconds");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn raw_http2_preface_rejection_releases_task_and_listener_recovers() {
        timeout(TEST_BUDGET, async {
            const PREFACE: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
            const RECOVERY: &str = "/recovery/http2-preface";
            let mut harness = LifecycleHarness::start(1, OPERATION_BUDGET, false).await;
            let mut client = harness.connect_and_wait_for_tasks(1).await;
            write_all_bounded(&mut client, PREFACE).await;
            let mut responses = ResponseFrames::default();
            // The pre-service hook has no HTTP response channel. Require
            // zero wire bytes and terminal EOF/reset through the same reader.
            responses.expect_terminal(&mut client).await;
            harness.wait_for_tasks(0).await;
            assert_eq!(
                harness.snapshot(),
                CounterSnapshot {
                    normal_process: 0,
                    request_rejections: Vec::new(),
                    pre_service_rejections: vec![ProductionPreServiceRejection::Http2Preface],
                    current_processors: 0,
                    peak_processors: 0,
                    peak_connection_tasks: 1,
                    upstream_requests: 0,
                },
                "raw HTTP/2 preface must reject once before request policy and release the task"
            );
            drop(client);

            recovery_exchange(&mut harness, RECOVERY).await;
            assert_eq!(
                harness.snapshot(),
                CounterSnapshot {
                    normal_process: 1,
                    request_rejections: Vec::new(),
                    pre_service_rejections: vec![ProductionPreServiceRejection::Http2Preface],
                    current_processors: 0,
                    peak_processors: 1,
                    peak_connection_tasks: 1,
                    upstream_requests: 1,
                },
                "same listener must recover after exact HTTP/2 pre-service rejection"
            );
            let records = harness.finish().await;
            assert_record_targets(&records, &[RECOVERY]);
        })
        .await
        .expect("raw HTTP/2-preface C3b case exceeded 20 seconds");
    }
}

mod c3c {
    use super::{c3b::assert_frame, c3b::ResponseFrames, *};

    const CLEAN_GRACE: Duration = Duration::from_secs(3);
    const BODY_ONLY_GRACE: Duration = Duration::from_millis(200);
    const POST_TARGET: &str = "/shutdown/body";
    const POST_HEAD: &[u8] = b"POST /shutdown/body HTTP/1.1\r\nHost: proxy.owned.test\r\nContent-Length: 1\r\nConnection: close\r\n\r\n";

    async fn start(capacity: usize, body: bool, grace: Duration) -> LifecycleHarness {
        LifecycleHarness::start_with_shutdown_grace(capacity, OPERATION_BUDGET, body, grace, 1)
            .await
    }

    fn assert_work(harness: &LifecycleHarness, total: usize, current: usize, tasks: usize) {
        assert!(
            total <= 1,
            "at most one complete upstream request per C3c case"
        );
        assert_eq!(
            harness.snapshot(),
            CounterSnapshot {
                normal_process: total,
                request_rejections: Vec::new(),
                pre_service_rejections: Vec::new(),
                current_processors: current,
                peak_processors: total,
                peak_connection_tasks: tasks,
                upstream_requests: total,
            },
            "exact C3c work and zero rejection hooks"
        );
        assert_eq!(
            harness.connection_tasks_started.load(Ordering::SeqCst),
            tasks,
            "total spawned tasks must not hide a late task below the retained peak"
        );
    }

    fn assert_held_shutdown(harness: &LifecycleHarness, started: Instant) {
        assert!(harness.shutdown.is_none() && harness.shutdown_started.is_none());
        assert_eq!(*harness.connection_tasks.borrow(), 1);
        assert_eq!(harness.snapshot().current_processors, 1);
        // Admission/listener closure, the joined idle task (when present),
        // and the held complete capture are positive checkpoints. This is a
        // pending-state check at that fence, not a negative timeout oracle.
        assert!(
            !harness.server.as_ref().expect("owned server").is_finished(),
            "shutdown must remain pending on the held synchronous processor"
        );
        assert!(
            started.elapsed() < CLEAN_GRACE,
            "release must be within grace"
        );
    }

    async fn exact_response_then_terminal(client: &mut TcpStream, target: &str) {
        let mut responses = ResponseFrames::default();
        let frame = responses.next_frame(client).await;
        assert_frame(&frame, "HTTP/1.1 200 OK", target.as_bytes());
        assert_eq!(response_header_values(frame.head, "connection"), ["close"]);
        responses.expect_terminal(client).await;
    }

    async fn late_connection_attempt(address: SocketAddr) -> bool {
        match timeout(OPERATION_BUDGET, TcpStream::connect(address))
            .await
            .expect("late connect must resolve without timeout")
        {
            Err(error)
                if error.kind() == ErrorKind::ConnectionRefused || terminal_reset(&error) =>
            {
                eprintln!("C3c late TCP attempt: {:?}; request writes=0", error.kind());
                false
            }
            Err(error) => panic!("late connect failed unexpectedly: {error}"),
            Ok(mut client) => {
                let bytes = request("/shutdown/late");
                assert!(bytes.len() <= CAPTURE_LIMIT);
                let write_result = timeout(OPERATION_BUDGET, client.write_all(&bytes))
                    .await
                    .expect("late request write must be bounded");
                let write_completed = write_result.is_ok();
                // Even a write reset must read any buffered response bytes.
                let response =
                    observe_terminal_response_after_write(&mut client, write_result).await;
                assert!(
                    response.bytes.is_empty(),
                    "late peer response: {response:?}"
                );
                eprintln!(
                    "C3c late TCP attempt: connected; request writes=1, complete writes={write_completed}, terminal={:?}, response bytes=0",
                    response.terminal
                );
                true
            }
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn accepted_idle_and_late_shutdown_drains_only_accepted_work() {
        timeout(TEST_BUDGET, async {
            const TARGET: &str = "/shutdown/accepted";
            let mut harness = start(2, false, CLEAN_GRACE).await;
            let mut accepted = harness.connect_and_wait_for_tasks(1).await;
            write_all_bounded(&mut accepted, &request(TARGET)).await;
            let capture = harness.next_upstream().await;
            assert_upstream_request(&capture.request, TARGET);
            let expected_record = capture.request.clone();

            let mut idle = harness.connect_and_wait_for_tasks(2).await;
            assert_work(&harness, 1, 1, 2);
            let started = harness.begin_shutdown().await;
            let idle_response = read_terminal_response(&mut idle).await;
            assert!(idle_response.bytes.is_empty(), "idle peer: {idle_response:?}");
            harness.wait_for_tasks(1).await;
            assert_work(&harness, 1, 1, 2);

            // The third TCP attempt is after the shutdown acknowledgment. It
            // is never counted as an accepted production peer or request.
            let late_connected = late_connection_attempt(harness.address).await;
            harness.wait_for_tasks(1).await;
            assert_work(&harness, 1, 1, 2);
            assert_held_shutdown(&harness, started);
            capture.release();

            exact_response_then_terminal(&mut accepted, TARGET).await;
            harness.wait_for_tasks(0).await;
            assert_work(&harness, 1, 0, 2);
            assert_eq!(
                harness
                    .closed_admission_service_calls
                    .load(Ordering::SeqCst),
                0,
                "idle and late peers must not reach closed-admission service"
            );
            let records = harness.finish_shutdown(Ok(())).await;
            assert_eq!(records, [expected_record], "only the accepted target upstream");
            eprintln!(
                "C3c accepted/idle/late: connection attempts=3, successful TCP connects={}, accepted tasks=2, accepted-peer request attempts=1, late request writes={}, complete upstream requests={}",
                2 + usize::from(late_connected),
                usize::from(late_connected),
                records.len()
            );
        })
        .await
        .expect("accepted/idle/late C3c case exceeded 20 seconds");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn queued_pipeline_shutdown_never_dispatches_second_request() {
        timeout(TEST_BUDGET, async {
            const FIRST: &str = "/shutdown/pipeline/first";
            const PIPELINE: &[u8] = b"GET /shutdown/pipeline/first HTTP/1.1\r\nHost: proxy.owned.test\r\nConnection: keep-alive\r\n\r\nGET /shutdown/pipeline/second HTTP/1.1\r\nHost: proxy.owned.test\r\nConnection: close\r\n\r\n";
            let mut harness = start(1, false, CLEAN_GRACE).await;
            let mut client = harness.connect_and_wait_for_tasks(1).await;
            assert!(PIPELINE.len() <= CAPTURE_LIMIT);
            // Exactly one finite application write, not a TCP segmentation claim.
            write_all_bounded(&mut client, PIPELINE).await;
            let capture = harness.next_upstream().await;
            assert_upstream_request(&capture.request, FIRST);
            let expected_record = capture.request.clone();
            assert_work(&harness, 1, 1, 1);
            let started = harness.begin_shutdown().await;
            harness.wait_for_tasks(1).await;
            assert_work(&harness, 1, 1, 1);
            assert_eq!(
                harness
                    .closed_admission_service_calls
                    .load(Ordering::SeqCst),
                0,
                "queued request must not reach closed admission before release"
            );
            assert_held_shutdown(&harness, started);
            capture.release();

            let mut responses = ResponseFrames::default();
            let first = responses.next_frame(&mut client).await;
            assert_frame(&first, "HTTP/1.1 200 OK", FIRST.as_bytes());
            assert!(response_header_values(first.head, "connection").is_empty());
            // Hyper may either dispatch the already-buffered second head to
            // the closed gate in the same poll or yield first and observe
            // drain. Correlate the complete wire with the observed phase;
            // neither branch accepts partial/trailing bytes or hidden work.
            let second_response = match responses.next_frame_or_terminal(&mut client).await {
                None => false,
                Some(second) => {
                    assert_frame(&second, "HTTP/1.1 503 Service Unavailable", b"");
                    assert_eq!(
                        response_header_values(second.head, "content-length"),
                        ["0"]
                    );
                    assert_eq!(
                        response_header_values(second.head, "connection"),
                        ["close"]
                    );
                    responses.expect_terminal(&mut client).await;
                    true
                }
            };
            harness.wait_for_tasks(0).await;
            assert_work(&harness, 1, 0, 1);
            let closed_admission_calls = harness
                .closed_admission_service_calls
                .load(Ordering::SeqCst);
            assert!(
                matches!(
                    (closed_admission_calls, second_response),
                    (0, false) | (1, true)
                ),
                "wire outcome must match the exact closed-admission service phase: calls={closed_admission_calls}, second_response={second_response}"
            );
            let records = harness.finish_shutdown(Ok(())).await;
            assert_eq!(records, [expected_record], "queued second target must never forward");
            eprintln!(
                "C3c pipeline: connection attempts=1, accepted tasks=1, request attempts=2 in one write, complete upstream requests={}, closed-admission service calls={closed_admission_calls}, wire={}",
                records.len(),
                if second_response {
                    "200 then empty 503 then EOF/reset"
                } else {
                    "200 then EOF/reset"
                }
            );
        })
        .await
        .expect("queued pipeline shutdown C3c case exceeded 20 seconds");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn body_completed_after_shutdown_within_grace_is_processed_once() {
        timeout(TEST_BUDGET, async {
            let mut harness = start(1, true, CLEAN_GRACE).await;
            let mut client = harness.connect_and_wait_for_tasks(1).await;
            write_all_bounded(&mut client, POST_HEAD).await;
            harness.wait_for_body_collection().await;
            assert_work(&harness, 0, 0, 1);
            let started = harness.begin_shutdown().await;
            harness.wait_for_tasks(1).await;
            assert_work(&harness, 0, 0, 1);

            write_all_bounded(&mut client, b"x").await;
            assert!(started.elapsed() < CLEAN_GRACE, "body byte must complete within grace");
            let capture = harness.next_upstream().await;
            assert_eq!(capture.request.method, "POST");
            assert_eq!(capture.request.target, POST_TARGET);
            assert_eq!(capture.request.body, b"x");
            let expected_record = capture.request.clone();
            assert_work(&harness, 1, 1, 1);
            assert_held_shutdown(&harness, started);
            capture.release();

            exact_response_then_terminal(&mut client, POST_TARGET).await;
            harness.wait_for_tasks(0).await;
            assert_work(&harness, 1, 0, 1);
            assert_eq!(
                harness
                    .closed_admission_service_calls
                    .load(Ordering::SeqCst),
                0,
                "completed body request must not reach closed admission"
            );
            let records = harness.finish_shutdown(Ok(())).await;
            assert_eq!(records, [expected_record], "one exact POST target and body");
            eprintln!(
                "C3c body within grace: connection attempts=1, accepted tasks=1, request attempts=1, head writes=1, body writes=1, complete upstream requests={}",
                records.len()
            );
        })
        .await
        .expect("body completion within grace C3c case exceeded 20 seconds");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn body_only_grace_expiry_aborts_without_processor_or_upstream_work() {
        timeout(TEST_BUDGET, async {
            let mut harness = start(1, true, BODY_ONLY_GRACE).await;
            let mut client = harness.connect_and_wait_for_tasks(1).await;
            write_all_bounded(&mut client, POST_HEAD).await;
            harness.wait_for_body_collection().await;
            assert_work(&harness, 0, 0, 1);
            harness.begin_shutdown().await;
            // Keep the write side open and withhold the sole declared byte.
            // The 200 ms drain grace is separate from the five-second body
            // timer. No early half-close or coupled synchronous work is used.
            let response = read_terminal_response(&mut client).await;
            assert!(response.bytes.is_empty(), "body-only expiry response: {response:?}");
            harness.wait_for_tasks(0).await;
            assert_work(&harness, 0, 0, 1);
            assert_eq!(
                harness
                    .closed_admission_service_calls
                    .load(Ordering::SeqCst),
                0,
                "withheld body must not create a closed-admission service call"
            );
            let records = harness
                .finish_shutdown(Err(ProductionRuntimeError::DrainDeadlineExceeded))
                .await;
            assert!(records.is_empty(), "body-only expiry must have an empty joined recorder");
            eprintln!(
                "C3c body-only expiry: connection attempts=1, accepted tasks=1, incomplete request attempts=1, head writes=1, body writes=0, complete upstream requests=0, result=DrainDeadlineExceeded"
            );
        })
        .await
        .expect("body-only grace expiry C3c case exceeded 20 seconds");
    }
}
