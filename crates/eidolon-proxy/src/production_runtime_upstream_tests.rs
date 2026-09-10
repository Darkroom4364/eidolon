//! C2: actual production HTTP/1 client -> owned raw responders, directly and
//! through the public production listener. The listener processor records the
//! typed result before applying main.rs's upstream failure -> Failed mapping.
//! This is not the Lab decoder or the complete production lifecycle/profile.

use std::{
    io::ErrorKind,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use bytes::Bytes;
use hyper::{header::HOST, Request, StatusCode};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    runtime::Handle,
    sync::oneshot,
    task::JoinSet,
    time::{sleep, timeout},
};

use super::{
    dispatch_production_upstream, serve_production_http1, ProductionPreServiceRejection,
    ProductionProcessorError, ProductionRejectedRequest, ProductionRequestContext,
    ProductionRequestProcessor, ProductionResponse, ProductionRuntimeConfig,
    ProductionUpstreamConfig, ProductionUpstreamError, ProductionUpstreamTarget,
};
use crate::production_http::{
    ProductionHttpPolicy, ProductionHttpRequest, ProductionInboundBody, ProductionRequestRejection,
};

const IO_BUDGET: Duration = Duration::from_secs(15);
const CAPTURE_LIMIT: usize = 4096;
const BODY_CAP: usize = 8;
const REQUEST_TARGET: &str = "/c2/commit?case=owned";
const REQUEST_BODY: &[u8] = b"commit\0\xff";
const CONTROL_RESPONSE: &[u8] =
    b"HTTP/1.1 201 Created\r\nContent-Length: 2\r\nX-End-To-End: preserved\r\n\r\nok";
const FIRST_CONTROL_RESPONSE: &[u8] =
    b"HTTP/1.1 201 Created\r\nContent-Length: 2\r\nX-C2-Recorder: first\r\n\r\na1";
const SECOND_CONTROL_RESPONSE: &[u8] =
    b"HTTP/1.1 202 Accepted\r\nContent-Length: 2\r\nX-C2-Recorder: second\r\n\r\nb2";

type DispatchResult = Result<ProductionResponse, ProductionUpstreamError>;

#[derive(Clone)]
struct Reply {
    // These are application writes/progress points, not TCP or peer read boundaries.
    pieces: Vec<(Duration, Vec<u8>)>,
    close_write: bool,
}

impl Reply {
    fn complete(wire: impl Into<Vec<u8>>) -> Self {
        Self {
            pieces: vec![(Duration::ZERO, wire.into())],
            close_write: true,
        }
    }

    fn held(wire: &[u8]) -> Self {
        Self {
            pieces: vec![(Duration::ZERO, wire.to_vec())],
            close_write: false,
        }
    }
}

#[derive(Debug)]
struct CapturedConnection {
    wire: Vec<u8>,
    request_completed: Instant,
    progress: Vec<Instant>,
}

fn head_end(wire: &[u8]) -> Option<usize> {
    wire.windows(4)
        .position(|bytes| bytes == b"\r\n\r\n")
        .map(|position| position + 4)
}

fn headers(wire: &[u8]) -> Vec<(&str, &str)> {
    let end = head_end(wire).expect("complete HTTP fixture head");
    std::str::from_utf8(&wire[..end - 4])
        .expect("ASCII fixture head")
        .split("\r\n")
        .skip(1)
        .map(|line| {
            let (name, value) = line.split_once(':').expect("fixture header separator");
            (name, value.trim())
        })
        .collect()
}

fn values<'a>(headers: &[(&str, &'a str)], name: &str) -> Vec<&'a str> {
    headers
        .iter()
        .filter(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| *value)
        .collect()
}

async fn read_piece(stream: &mut TcpStream, wire: &mut Vec<u8>) -> usize {
    let mut buffer = [0; 512];
    let count = match stream.read(&mut buffer).await {
        Ok(count) => count,
        Err(error) if error.kind() == ErrorKind::ConnectionReset => 0,
        Err(error) => panic!("owned socket read failed: {error}"),
    };
    assert!(
        wire.len() + count <= CAPTURE_LIMIT,
        "capture exceeded bound"
    );
    wire.extend_from_slice(&buffer[..count]);
    count
}

async fn capture_connection(mut stream: TcpStream, reply: Reply) -> CapturedConnection {
    timeout(IO_BUDGET, async move {
        let mut wire = Vec::new();
        let end = loop {
            if let Some(end) = head_end(&wire) {
                break end;
            }
            assert_ne!(
                read_piece(&mut stream, &mut wire).await,
                0,
                "missing request head"
            );
        };
        let fields = headers(&wire);
        let lengths = values(&fields, "content-length");
        assert_eq!(lengths.len(), 1, "one canonical upstream request length");
        let length: usize = lengths[0].parse().expect("decimal request length");
        assert!(
            length <= CAPTURE_LIMIT - end,
            "request body exceeds fixture bound"
        );
        assert!(values(&fields, "transfer-encoding").is_empty());
        while wire.len() < end + length {
            assert_ne!(
                read_piece(&mut stream, &mut wire).await,
                0,
                "incomplete request body"
            );
        }
        let request_completed = Instant::now();
        let mut progress = Vec::new();
        // Do not reply until one complete method/target/body has been observed.
        for (delay, bytes) in reply.pieces {
            sleep(delay).await;
            stream
                .write_all(&bytes)
                .await
                .expect("owned response write");
            progress.push(Instant::now());
        }
        if reply.close_write {
            stream.shutdown().await.expect("owned response EOF");
        }
        // Keep recording through client EOF/reset, including any unexpected
        // second request on this connection. Returning also drops the stream.
        while read_piece(&mut stream, &mut wire).await != 0 {}
        CapturedConnection {
            wire,
            request_completed,
            progress,
        }
    })
    .await
    .expect("owned connection must quiesce within its bound")
}

struct Recorder {
    address: SocketAddr,
    stop: oneshot::Sender<()>,
    task: JoinSet<Vec<CapturedConnection>>,
}

impl Recorder {
    async fn start(reply: Reply) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("owned recorder bind");
        let address = listener.local_addr().unwrap();
        let (stop, mut stopped) = oneshot::channel();
        let mut task = JoinSet::new();
        task.spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    biased;
                    _ = &mut stopped => break,
                    accepted = listener.accept() => {
                        let (stream, _) = accepted.expect("owned recorder accept");
                        assert!(connections.len() < 4, "bounded endpoint connection count");
                        connections.spawn(capture_connection(stream, reply.clone()));
                    }
                }
            }
            // Stop is sent only after owned dispatch/listener work completes.
            // Drain already queued connections synchronously before closing the
            // listener: a negative timed accept alone would miss late replay.
            let listener = listener.into_std().unwrap();
            loop {
                match listener.accept() {
                    Ok((stream, _)) => {
                        assert!(connections.len() < 4, "bounded endpoint connection count");
                        stream.set_nonblocking(true).unwrap();
                        connections.spawn(capture_connection(
                            TcpStream::from_std(stream).unwrap(),
                            reply.clone(),
                        ));
                    }
                    Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                    Err(error) => panic!("owned queue drain failed: {error}"),
                }
            }
            drop(listener);
            let mut captures = Vec::new();
            while let Some(result) = timeout(IO_BUDGET, connections.join_next())
                .await
                .expect("bounded connection join")
            {
                captures.push(result.expect("owned connection task"));
            }
            captures
        });
        Self {
            address,
            stop,
            task,
        }
    }

    async fn finish(mut self) -> Vec<CapturedConnection> {
        self.stop
            .send(())
            .expect("recorder remains owned until shutdown");
        timeout(IO_BUDGET, self.task.join_next())
            .await
            .expect("bounded recorder join")
            .expect("one recorder task")
            .expect("recorder task succeeds")
    }
}

fn target(addresses: Vec<SocketAddr>) -> ProductionUpstreamTarget {
    ProductionUpstreamTarget::new("upstream.test".parse().unwrap(), addresses).unwrap()
}

fn request() -> ProductionHttpRequest {
    ProductionHttpPolicy
        .adapt(
            Request::builder()
                .method("POST")
                .uri(REQUEST_TARGET)
                .header(HOST, "proxy.test")
                .header("content-length", REQUEST_BODY.len())
                .body(ProductionInboundBody::new(Bytes::from_static(REQUEST_BODY)))
                .unwrap(),
        )
        .unwrap()
}

fn upstream_config() -> ProductionUpstreamConfig {
    ProductionUpstreamConfig {
        connect_timeout: Duration::from_secs(2),
        response_timeout: Duration::from_secs(6),
        dispatch_timeout: Duration::from_secs(8),
        max_response_body_bytes: BODY_CAP,
    }
}

struct ForwardingProcessor {
    handle: Handle,
    upstream: ProductionUpstreamTarget,
    config: ProductionUpstreamConfig,
    results: Mutex<Vec<DispatchResult>>,
}

impl ProductionRequestProcessor for ForwardingProcessor {
    fn process(
        &self,
        request: ProductionHttpRequest,
        context: ProductionRequestContext,
    ) -> Result<ProductionResponse, ProductionProcessorError> {
        let result = self.handle.block_on(dispatch_production_upstream(
            &request,
            &self.upstream,
            self.config,
            context.request_deadline,
        ));
        self.results.lock().unwrap().push(result.clone());
        // main.rs: process_request maps dispatch error to io::Error, then
        // ProductionLifecycleProcessor maps it to Failed. The public listener
        // owns the empty-500 serialization. No fixture-selected HTTP status.
        result.map_err(|_| ProductionProcessorError::Failed)
    }

    fn reject(
        &self,
        rejection: ProductionRequestRejection,
        _: ProductionRejectedRequest,
        _: ProductionRequestContext,
    ) -> Result<ProductionResponse, ProductionProcessorError> {
        panic!("valid C2 fixture rejected by policy: {rejection:?}");
    }

    fn reject_pre_service(
        &self,
        rejection: ProductionPreServiceRejection,
        _: ProductionRequestContext,
    ) -> Result<(), ProductionProcessorError> {
        panic!("valid C2 fixture rejected before service: {rejection:?}");
    }
}

async fn through_listener(
    upstream: ProductionUpstreamTarget,
    config: ProductionUpstreamConfig,
    request_budget: Duration,
) -> (DispatchResult, Vec<u8>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("owned public listener bind");
    let address = listener.local_addr().unwrap();
    let processor = Arc::new(ForwardingProcessor {
        handle: Handle::current(),
        upstream,
        config,
        results: Mutex::new(Vec::new()),
    });
    let (stop, stopped) = oneshot::channel();
    let mut server = JoinSet::new();
    server.spawn(serve_production_http1(
        listener,
        ProductionRuntimeConfig {
            max_concurrent_connections: 1,
            request_timeout: Duration::from_secs(5),
            processor_timeout: request_budget,
            shutdown_grace: Duration::from_secs(5),
        },
        processor.clone(),
        async move {
            let _ = stopped.await;
        },
    ));
    let wire = timeout(IO_BUDGET, async {
        let mut client = TcpStream::connect(address).await.expect("downstream connect");
        let mut request = format!("POST {REQUEST_TARGET} HTTP/1.1\r\nHost: proxy.test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", REQUEST_BODY.len()).into_bytes();
        request.extend_from_slice(REQUEST_BODY);
        client.write_all(&request).await.expect("downstream request write");
        let mut wire = Vec::new();
        while read_piece(&mut client, &mut wire).await != 0 {}
        wire
    }).await.expect("bounded public listener exchange");
    stop.send(()).expect("listener shutdown signal");
    timeout(IO_BUDGET, server.join_next())
        .await
        .expect("bounded listener join")
        .expect("one listener task")
        .expect("listener task joins")
        .expect("listener drains");
    let mut results = processor.results.lock().unwrap();
    assert_eq!(
        results.len(),
        1,
        "exactly one actual dispatch per listener request"
    );
    (results.remove(0), wire)
}

#[derive(Debug, Clone, Copy)]
enum Layer {
    Direct,
    Listener,
}

struct Case {
    name: &'static str,
    reply: Reply,
    expected: Result<(u16, Vec<u8>), ProductionUpstreamError>,
    config: ProductionUpstreamConfig,
    request_budget: Duration,
    kept: Vec<(&'static str, &'static str)>,
    removed: Vec<&'static str>,
}

impl Case {
    fn success(name: &'static str, wire: impl Into<Vec<u8>>, status: u16, body: &[u8]) -> Self {
        Self {
            name,
            reply: Reply::complete(wire),
            expected: Ok((status, body.to_vec())),
            config: upstream_config(),
            request_budget: Duration::from_secs(10),
            kept: Vec::new(),
            removed: Vec::new(),
        }
    }

    fn error(name: &'static str, wire: &[u8], error: ProductionUpstreamError) -> Self {
        Self {
            expected: Err(error),
            ..Self::success(name, wire, 200, b"")
        }
    }
}

fn assert_request(capture: &CapturedConnection) {
    let end = head_end(&capture.wire).unwrap();
    assert!(capture
        .wire
        .starts_with(format!("POST {REQUEST_TARGET} HTTP/1.1\r\n").as_bytes()));
    assert_eq!(
        &capture.wire[end..],
        REQUEST_BODY,
        "one complete body and no second request/trailing bytes on this connection"
    );
    assert_eq!(values(&headers(&capture.wire), "host"), ["upstream.test"]);
    assert_eq!(values(&headers(&capture.wire), "content-length"), ["8"]);
}

fn assert_downstream(wire: &[u8], status: u16, body: &[u8]) {
    assert!(
        wire.starts_with(format!("HTTP/1.1 {status} ").as_bytes()),
        "wire: {wire:?}"
    );
    let end = head_end(wire).expect("complete downstream response head");
    let fields = headers(wire);
    assert_eq!(
        values(&fields, "content-length"),
        [body.len().to_string().as_str()],
        "downstream must emit exactly one length for the collected body"
    );
    assert!(values(&fields, "transfer-encoding").is_empty());
    assert_eq!(
        &wire[end..],
        body,
        "no partial upstream body or extra response bytes"
    );
}

async fn run_case(case: &Case, layer: Layer) {
    let first = Recorder::start(case.reply.clone()).await;
    let second = Recorder::start(Reply::complete(CONTROL_RESPONSE)).await;
    let upstream = target(vec![first.address, second.address]);
    let (result, downstream) = match layer {
        Layer::Direct => (
            timeout(
                IO_BUDGET,
                dispatch_production_upstream(
                    &request(),
                    &upstream,
                    case.config,
                    Instant::now() + case.request_budget,
                ),
            )
            .await
            .expect("bounded direct dispatch"),
            None,
        ),
        Layer::Listener => {
            let (result, wire) = through_listener(upstream, case.config, case.request_budget).await;
            (result, Some(wire))
        }
    };
    let completed = Instant::now();
    // Finalize only after dispatch's in-task Hyper driver has dropped, and (for
    // Listener) public serving/drain has joined. finish drains pending accepts
    // and joins every connection through EOF/reset before counts are asserted.
    let first = first.finish().await;
    let second = second.finish().await;
    assert_eq!(
        first.len(),
        1,
        "{} {layer:?}: first connection count",
        case.name
    );
    assert!(
        second.is_empty(),
        "{} {layer:?}: post-send fallback access",
        case.name
    );
    assert_request(&first[0]);
    assert_eq!(
        first[0].progress.len(),
        case.reply.pieces.len(),
        "{}: synchronized response progress",
        case.name
    );
    assert!(first[0].request_completed <= first[0].progress[0]);
    if !case.reply.close_write {
        assert!(
            first[0]
                .progress
                .iter()
                .all(|progress| *progress <= completed),
            "held response progress must precede cancellation"
        );
    }
    match &case.expected {
        Err(expected) => {
            assert_eq!(result, Err(*expected), "{} {layer:?}", case.name);
            if let Some(wire) = downstream {
                assert_downstream(&wire, 500, b"");
            }
        }
        Ok((status, body)) => {
            let response =
                result.unwrap_or_else(|error| panic!("{} {layer:?}: {error:?}", case.name));
            assert_eq!(response.status.as_u16(), *status, "{} {layer:?}", case.name);
            assert_eq!(&response.body[..], body, "{} {layer:?}", case.name);
            for name in ["content-length", "transfer-encoding", "connection"] {
                assert!(
                    !response.headers.contains_key(name),
                    "{}: typed {name}",
                    case.name
                );
            }
            for name in &case.removed {
                assert!(
                    !response.headers.contains_key(*name),
                    "{}: leaked {name}",
                    case.name
                );
            }
            for (name, _) in &case.kept {
                let expected: Vec<_> = case
                    .kept
                    .iter()
                    .filter(|(key, _)| key == name)
                    .map(|(_, value)| *value)
                    .collect();
                let actual: Vec<_> = response
                    .headers
                    .get_all(*name)
                    .iter()
                    .map(|value| value.to_str().expect("ASCII control header"))
                    .collect();
                assert_eq!(actual, expected, "{}: typed {name} values", case.name);
            }
            if let Some(wire) = downstream {
                assert_downstream(&wire, *status, body);
                let fields = headers(&wire);
                for name in &case.removed {
                    assert!(
                        values(&fields, name).is_empty(),
                        "{}: downstream leaked {name}",
                        case.name
                    );
                }
                for (name, _) in &case.kept {
                    let expected: Vec<_> = case
                        .kept
                        .iter()
                        .filter(|(key, _)| key == name)
                        .map(|(_, value)| *value)
                        .collect();
                    assert_eq!(
                        values(&fields, name),
                        expected,
                        "{}: downstream {name} values",
                        case.name
                    );
                }
            }
        }
    }
}

async fn matrix(cases: Vec<Case>) {
    for case in cases {
        for layer in [Layer::Direct, Layer::Listener] {
            run_case(&case, layer).await;
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upstream_malformed_and_truncated_responses_do_not_replay() {
    use ProductionUpstreamError::{ResponseBodyFailed, ResponseFailed};
    matrix(vec![
        Case::error(
            "malformed_status",
            b"NOT-HTTP 200 OK\r\n\r\n",
            ResponseFailed,
        ),
        Case::error(
            "invalid_status_code",
            b"HTTP/1.1 xyz Nope\r\n\r\n",
            ResponseFailed,
        ),
        Case::error(
            "malformed_header_name",
            b"HTTP/1.1 200 OK\r\nBad Header: x\r\n\r\n",
            ResponseFailed,
        ),
        Case::error(
            "malformed_header_value",
            b"HTTP/1.1 200 OK\r\nX-Bad: a\0b\r\n\r\n",
            ResponseFailed,
        ),
        Case::error(
            "invalid_cl",
            b"HTTP/1.1 200 OK\r\nContent-Length: nope\r\n\r\n",
            ResponseFailed,
        ),
        Case::error(
            "negative_cl",
            b"HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n",
            ResponseFailed,
        ),
        Case::error(
            "overflow_cl",
            b"HTTP/1.1 200 OK\r\nContent-Length: 18446744073709551616\r\n\r\n",
            ResponseFailed,
        ),
        Case::error(
            "conflicting_cl",
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\nok",
            ResponseFailed,
        ),
        Case::error(
            "conflicting_list_cl",
            b"HTTP/1.1 200 OK\r\nContent-Length: 2, 3\r\n\r\nok",
            ResponseFailed,
        ),
        Case::error(
            "http10_te",
            b"HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
            ResponseFailed,
        ),
        Case::error(
            "truncated_fixed",
            b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nok",
            ResponseBodyFailed,
        ),
        Case::error(
            "truncated_chunk_data",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nok",
            ResponseBodyFailed,
        ),
        Case::error(
            "missing_final_chunk",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n",
            ResponseBodyFailed,
        ),
        Case::error(
            "invalid_chunk_size",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nx\r\n",
            ResponseBodyFailed,
        ),
    ])
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upstream_framing_acceptance_is_distinct_from_strict_ingress() {
    matrix(vec![
        Case::success("equal_duplicate_cl", b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\nok", 200, b"ok"),
        Case::success("numerically_equal_duplicate_cl", b"HTTP/1.1 200 OK\r\nContent-Length: 02\r\nContent-Length: 2\r\n\r\nok", 200, b"ok"),
        Case::success("equal_list_cl", b"HTTP/1.1 200 OK\r\nContent-Length: 2, 02\r\n\r\nok", 200, b"ok"),
        Case::success("cl_then_te", b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n", 200, b"ok"),
        Case::success("te_then_cl", b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 0\r\n\r\n2\r\nok\r\n0\r\n\r\n", 200, b"ok"),
        Case::success("nonchunked_te_close_delimited", b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\nopaque", 200, b"opaque"),
        Case::success("final_chunked_te", b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n", 200, b"ok"),
        Case::success("nonfinal_chunked_te", b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, gzip\r\n\r\nopaque", 200, b"opaque"),
    ]).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upstream_decoded_body_cap_and_empty_controls() {
    let mut cases = Vec::new();
    for framing in ["fixed", "chunked", "close"] {
        for length in [0, BODY_CAP, BODY_CAP + 1] {
            let body = &b"a\0\xffbcdefg"[..length];
            let wire = match framing {
                "fixed" => [
                    format!("HTTP/1.1 201 Created\r\nContent-Length: {length}\r\n\r\n")
                        .into_bytes(),
                    body.to_vec(),
                ]
                .concat(),
                "chunked" => {
                    let mut wire =
                        b"HTTP/1.1 201 Created\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
                    // Multiple chunks exercise remaining-budget accounting
                    // after a prior decoded frame, without assuming read splits.
                    for chunk in body.chunks(4) {
                        wire.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
                        wire.extend_from_slice(chunk);
                        wire.extend_from_slice(b"\r\n");
                    }
                    wire.extend_from_slice(b"0\r\n\r\n");
                    wire
                }
                "close" => [b"HTTP/1.1 201 Created\r\n\r\n".to_vec(), body.to_vec()].concat(),
                _ => unreachable!(),
            };
            let mut case = Case::success(framing, wire, 201, body);
            if length > BODY_CAP {
                case.expected = Err(ProductionUpstreamError::ResponseBodyTooLarge);
            }
            cases.push(case);
        }
    }
    matrix(cases).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upstream_informational_and_hop_header_controls() {
    let mut hops = Case::success("connection_nominations", b"HTTP/1.1 202 Accepted\r\nContent-Length: 2\r\nCoNnEcTiOn: X-Remove, KEEP-ALIVE\r\nConnection: x-Second, x-remove\r\nX-Remove: first\r\nx-remove: second\r\nX-Second: nominated\r\nKeep-Alive: timeout=99\r\nProxy-Authenticate: fixture\r\nProxy-Authorization: fixture\r\nTE: trailers\r\nTrailer: X-Trailer\r\nUpgrade: fixture\r\nX-End-To-End: one\r\nX-End-To-End: two\r\nETag: \"c2\"\r\n\r\nok", 202, b"ok");
    hops.removed = vec![
        "x-remove",
        "x-second",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "upgrade",
    ];
    hops.kept = vec![
        ("x-end-to-end", "one"),
        ("x-end-to-end", "two"),
        ("etag", "\"c2\""),
    ];
    let mut informational = Case::success("100_103_final", b"HTTP/1.1 100 Continue\r\nX-Interim: continue\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: </hint>; rel=preload\r\n\r\nHTTP/1.1 203 Non-Authoritative Information\r\nContent-Length: 2\r\nX-End-To-End: final\r\n\r\nok", 203, b"ok");
    informational.removed = vec!["x-interim", "link"];
    informational.kept = vec![("x-end-to-end", "final")];
    matrix(vec![informational, hops]).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upstream_protocol_switch_is_rejected_without_replay() {
    matrix(vec![Case::error(
        "unsupported_101",
        b"HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: fixture\r\n\r\n",
        ProductionUpstreamError::ResponseFailed,
    )])
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upstream_proxy_connection_is_not_forwarded() {
    let mut case = Case::success("proxy_connection", b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\npRoXy-CoNnEcTiOn: keep-alive\r\nProxy-Connection: close\r\nX-End-To-End: preserved\r\n\r\nok", 200, b"ok");
    case.removed = vec!["proxy-connection"];
    case.kept = vec![("x-end-to-end", "preserved")];
    matrix(vec![case]).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upstream_stage_and_absolute_deadlines_do_not_replay() {
    let mut cases = Vec::new();
    for (name, wire) in [
        (
            "held_head",
            b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nX-Held: ".as_slice(),
        ),
        (
            "held_fixed_body",
            b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\na".as_slice(),
        ),
        (
            "held_chunked_body",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\na".as_slice(),
        ),
    ] {
        for absolute in [false, true] {
            let error = if absolute {
                ProductionUpstreamError::DispatchTimedOut
            } else {
                ProductionUpstreamError::ResponseTimedOut
            };
            let mut case = Case::error(name, wire, error);
            case.reply = Reply::held(wire);
            if absolute {
                case.config.dispatch_timeout = Duration::from_secs(2);
            } else {
                case.config.response_timeout = Duration::from_secs(1);
            }
            cases.push(case);
        }
    }
    for incoming_deadline in [false, true] {
        let mut case = Case::error(
            if incoming_deadline {
                "incoming_deadline_across_progress"
            } else {
                "dispatch_deadline_across_progress"
            },
            b"",
            ProductionUpstreamError::DispatchTimedOut,
        );
        case.reply = Reply {
            pieces: vec![
                (
                    Duration::from_secs(1),
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec(),
                ),
                (Duration::from_secs(1), b"1\r\na\r\n".to_vec()),
            ],
            close_write: false,
        };
        if incoming_deadline {
            case.request_budget = Duration::from_secs(3);
        } else {
            case.config.dispatch_timeout = Duration::from_secs(3);
        }
        cases.push(case);
    }
    matrix(cases).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upstream_recorders_and_connect_failure_fallback_are_live() {
    let first = Recorder::start(Reply::complete(FIRST_CONTROL_RESPONSE)).await;
    let second = Recorder::start(Reply::complete(SECOND_CONTROL_RESPONSE)).await;
    // Port zero never denotes a connectable TCP service, so this fails before
    // an HTTP request can be sent without relying on a bind/drop race.
    let refused_address = "127.0.0.1:0".parse().unwrap();
    assert_eq!(
        timeout(
            IO_BUDGET,
            dispatch_production_upstream(
                &request(),
                &target(vec![refused_address]),
                upstream_config(),
                Instant::now() + Duration::from_secs(10)
            )
        )
        .await
        .expect("bounded refused-address control"),
        Err(ProductionUpstreamError::ConnectFailed),
        "the port-zero address must fail before any HTTP send",
    );
    for layer in [Layer::Direct, Layer::Listener] {
        for (addresses, expected_status, expected_body, expected_recorder) in [
            (
                vec![first.address, second.address],
                StatusCode::CREATED,
                b"a1".as_slice(),
                "first",
            ),
            (
                vec![second.address, first.address],
                StatusCode::ACCEPTED,
                b"b2".as_slice(),
                "second",
            ),
            (
                vec![refused_address, second.address],
                StatusCode::ACCEPTED,
                b"b2".as_slice(),
                "second",
            ),
        ] {
            let upstream = target(addresses);
            let response = match layer {
                Layer::Direct => timeout(
                    IO_BUDGET,
                    dispatch_production_upstream(
                        &request(),
                        &upstream,
                        upstream_config(),
                        Instant::now() + Duration::from_secs(10),
                    ),
                )
                .await
                .expect("bounded positive dispatch")
                .expect("positive response"),
                Layer::Listener => {
                    let (result, wire) =
                        through_listener(upstream, upstream_config(), Duration::from_secs(10))
                            .await;
                    assert_downstream(&wire, expected_status.as_u16(), expected_body);
                    result.expect("positive listener dispatch")
                }
            };
            assert_eq!(response.status, expected_status);
            assert_eq!(&response.body[..], expected_body);
            assert_eq!(response.headers["x-c2-recorder"], expected_recorder);
        }
    }
    let first = first.finish().await;
    let second = second.finish().await;
    assert_eq!(first.len(), 2);
    assert_eq!(second.len(), 4);
    for capture in first.iter().chain(&second) {
        assert_request(capture);
    }
}
