//! C1 equivalence: raw production ingress -> strict policy -> production client
//! -> owned raw HTTP recorder. No Lab parser or forwarding implementation here.

use std::{
    io::ErrorKind,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use bytes::Bytes;
use hyper::StatusCode;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    runtime::Handle,
    sync::{oneshot, watch},
    task::JoinHandle,
    time::timeout,
};

use super::{
    dispatch_production_upstream, serve_production_http1_inner, ProductionPreServiceRejection,
    ProductionProcessorError, ProductionRejectedRequest, ProductionRequestContext,
    ProductionRequestProcessor, ProductionResponse, ProductionRuntimeConfig,
    ProductionRuntimeError, ProductionUpstreamConfig, ProductionUpstreamTarget,
};
use crate::production_http::{ProductionHttpRequest, ProductionRequestRejection};

const IO_BUDGET: Duration = Duration::from_secs(5);
const MAX_CAPTURE_BYTES: usize = 16 * 1024;
const RECORDER_RESPONSE: &[u8] =
    b"HTTP/1.1 201 Created\r\nContent-Length: 8\r\nConnection: close\r\n\r\nrecorded";

#[derive(Clone, Debug, PartialEq, Eq)]
struct ValidatedFields {
    method: String,
    target: String,
    body: Vec<u8>,
}

#[derive(Clone, Debug, Default)]
struct Observations {
    validated: Vec<ValidatedFields>,
    policy: Vec<ProductionRequestRejection>,
    transport: Vec<ProductionPreServiceRejection>,
}

struct ForwardingProcessor {
    runtime: Handle,
    upstream: ProductionUpstreamTarget,
    observations: Mutex<Observations>,
}

impl ProductionRequestProcessor for ForwardingProcessor {
    fn process(
        &self,
        request: ProductionHttpRequest,
        context: ProductionRequestContext,
    ) -> Result<ProductionResponse, ProductionProcessorError> {
        self.observations
            .lock()
            .unwrap()
            .validated
            .push(ValidatedFields {
                method: request.method().to_string(),
                target: request.target().to_string(),
                body: request.body().to_vec(),
            });
        self.runtime
            .block_on(dispatch_production_upstream(
                &request,
                &self.upstream,
                ProductionUpstreamConfig {
                    connect_timeout: Duration::from_secs(1),
                    response_timeout: Duration::from_secs(2),
                    dispatch_timeout: Duration::from_secs(3),
                    max_response_body_bytes: MAX_CAPTURE_BYTES,
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
        self.observations.lock().unwrap().policy.push(rejection);
        Ok(ProductionResponse::new(
            StatusCode::from_u16(rejection.response_status()).unwrap(),
            Bytes::new(),
        ))
    }

    fn reject_pre_service(
        &self,
        rejection: ProductionPreServiceRejection,
        _context: ProductionRequestContext,
    ) -> Result<(), ProductionProcessorError> {
        self.observations.lock().unwrap().transport.push(rejection);
        Ok(())
    }
}

#[derive(Debug)]
struct RecordedRequest {
    wire: Vec<u8>,
    fields: ValidatedFields,
    headers: Vec<(String, String)>,
}

impl RecordedRequest {
    fn values(&self, name: &str) -> Vec<&str> {
        self.headers
            .iter()
            .filter(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
            .collect()
    }
}

// This reader inspects bytes emitted by the real production client. It only
// accepts the small fixed-length HTTP fixture envelope; it does not construct
// or normalize requests on behalf of the proxy.
async fn record_http_request(mut stream: TcpStream) -> RecordedRequest {
    let mut wire = Vec::new();
    let mut buffer = [0; 1024];
    let head_end = loop {
        if let Some(index) = wire.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
            break index + 4;
        }
        let count = stream.read(&mut buffer).await.unwrap();
        assert_ne!(count, 0, "upstream disconnected before its request head");
        wire.extend_from_slice(&buffer[..count]);
        assert!(
            wire.len() <= MAX_CAPTURE_BYTES,
            "upstream capture exceeded bound"
        );
    };
    let head = std::str::from_utf8(&wire[..head_end]).unwrap();
    let mut lines = head[..head.len() - 4].split("\r\n");
    let request_line: Vec<_> = lines.next().unwrap().split(' ').collect();
    assert_eq!(request_line.len(), 3);
    assert_eq!(request_line[2], "HTTP/1.1");
    let mut record = RecordedRequest {
        wire: Vec::new(),
        fields: ValidatedFields {
            method: request_line[0].to_string(),
            target: request_line[1].to_string(),
            body: Vec::new(),
        },
        headers: lines
            .map(|line| {
                let (name, value) = line.split_once(':').expect("upstream header separator");
                (name.to_string(), value.trim().to_string())
            })
            .collect(),
    };
    let lengths = record.values("content-length");
    assert_eq!(
        lengths.len(),
        1,
        "production client must send exactly one length"
    );
    let length: usize = lengths[0].parse().expect("upstream length is decimal");
    assert!(length <= MAX_CAPTURE_BYTES - head_end);
    assert!(record.values("transfer-encoding").is_empty());
    while wire.len() < head_end + length {
        let count = stream.read(&mut buffer).await.unwrap();
        assert_ne!(count, 0, "upstream disconnected before its complete body");
        wire.extend_from_slice(&buffer[..count]);
        assert!(
            wire.len() <= MAX_CAPTURE_BYTES,
            "upstream capture exceeded bound"
        );
    }
    assert_eq!(
        wire.len(),
        head_end + length,
        "unexpected extra upstream bytes"
    );
    record.fields.body = wire[head_end..].to_vec();
    record.wire = wire;
    stream.write_all(RECORDER_RESPONSE).await.unwrap();
    // Dispatch drops its connection after receiving this bounded response. Check
    // for any later extra bytes too, without waiting on an unbounded read_to_end.
    assert_eq!(
        stream.read(&mut buffer).await.unwrap(),
        0,
        "extra upstream request"
    );
    record
}

async fn run_recorder(
    listener: TcpListener,
    mut stop: oneshot::Receiver<()>,
) -> Vec<RecordedRequest> {
    let mut records = Vec::new();
    let mut quiescent = false;
    loop {
        let accepted = if quiescent {
            // The production listener has joined every connection and processor.
            // Drain any connection already queued before that completion fence.
            match timeout(Duration::from_millis(25), listener.accept()).await {
                Ok(accepted) => accepted,
                Err(_) => break,
            }
        } else {
            tokio::select! {
                _ = &mut stop => {
                    quiescent = true;
                    continue;
                }
                accepted = timeout(IO_BUDGET, listener.accept()) => {
                    accepted.expect("recorder accept exceeded case budget")
                }
            }
        };
        let (stream, _) = accepted.unwrap();
        assert!(
            records.len() < 4,
            "unexpected repeated upstream connections"
        );
        records.push(
            timeout(IO_BUDGET, record_http_request(stream))
                .await
                .expect("upstream request/response/close exceeded budget"),
        );
    }
    records
}

struct IngressHarness {
    address: SocketAddr,
    processor: Arc<ForwardingProcessor>,
    body_started: Option<oneshot::Receiver<()>>,
    connection_count: watch::Receiver<usize>,
    stop_server: Option<oneshot::Sender<()>>,
    server: JoinHandle<Result<(), ProductionRuntimeError>>,
    stop_recorder: Option<oneshot::Sender<()>>,
    recorder: JoinHandle<Vec<RecordedRequest>>,
}

impl IngressHarness {
    async fn start() -> Self {
        let upstream = timeout(IO_BUDGET, TcpListener::bind("127.0.0.1:0"))
            .await
            .unwrap()
            .expect("owned HTTP recorder should bind");
        let upstream_address = upstream.local_addr().unwrap();
        let listener = timeout(IO_BUDGET, TcpListener::bind("127.0.0.1:0"))
            .await
            .unwrap()
            .expect("production listener should bind");
        let address = listener.local_addr().unwrap();
        let processor = Arc::new(ForwardingProcessor {
            runtime: Handle::current(),
            upstream: ProductionUpstreamTarget::new(
                format!("recorder.owned.test:{}", upstream_address.port())
                    .parse()
                    .unwrap(),
                vec![upstream_address],
            )
            .unwrap(),
            observations: Mutex::new(Observations::default()),
        });
        let (stop_server, stopped) = oneshot::channel();
        let (body_signal, body_started) = oneshot::channel();
        let (connection_count_tx, connection_count) = watch::channel(0);
        let server = tokio::spawn(serve_production_http1_inner(
            listener,
            ProductionRuntimeConfig {
                max_concurrent_connections: 4,
                request_timeout: Duration::from_secs(2),
                processor_timeout: Duration::from_secs(3),
                shutdown_grace: Duration::from_secs(2),
            },
            processor.clone(),
            async move {
                let _ = stopped.await;
            },
            Some(Arc::new(Mutex::new(Some(body_signal)))),
            Some(connection_count_tx),
            None,
        ));
        let (stop_recorder, stopped) = oneshot::channel();
        let recorder = tokio::spawn(run_recorder(upstream, stopped));
        Self {
            address,
            processor,
            body_started: Some(body_started),
            connection_count,
            stop_server: Some(stop_server),
            server,
            stop_recorder: Some(stop_recorder),
            recorder,
        }
    }

    async fn exchange(&mut self, request: &[u8], writes: Writes, disconnect_body: bool) -> Vec<u8> {
        let mut stream = timeout(IO_BUDGET, TcpStream::connect(self.address))
            .await
            .unwrap()
            .unwrap();
        timeout(IO_BUDGET, async {
            self.connection_count
                .wait_for(|count| *count == 1)
                .await
                .expect("listener must observe admission before client writes");
            let head_end = request
                .windows(4)
                .position(|bytes| bytes == b"\r\n\r\n")
                .unwrap()
                + 4;
            let ends = match writes {
                Writes::Complete => vec![request.len()],
                Writes::Fragmented => vec![1, head_end / 2, head_end - 1, request.len()],
            };
            let mut start = 0;
            for end in ends {
                match stream.write_all(&request[start..end]).await {
                    Ok(()) => (),
                    Err(error)
                        if matches!(
                            error.kind(),
                            ErrorKind::BrokenPipe | ErrorKind::ConnectionReset
                        ) =>
                    {
                        break
                    }
                    Err(error) => panic!("raw request write failed: {error}"),
                }
                start = end;
                // A scheduling opportunity, not a claim about TCP/server read boundaries.
                if matches!(writes, Writes::Fragmented) {
                    tokio::task::yield_now().await;
                }
            }
            if disconnect_body {
                self.body_started
                    .take()
                    .unwrap()
                    .await
                    .expect("body collection must start before EOF");
                stream.shutdown().await.unwrap();
            }
            let mut response = Vec::new();
            let mut buffer = [0; 1024];
            loop {
                match stream.read(&mut buffer).await {
                    Ok(0) => break,
                    Ok(count) => response.extend_from_slice(&buffer[..count]),
                    Err(error) if error.kind() == ErrorKind::ConnectionReset => break,
                    Err(error) => panic!("raw response read failed: {error}"),
                }
                assert!(
                    response.len() <= MAX_CAPTURE_BYTES,
                    "response exceeded capture bound"
                );
            }
            // EOF alone does not prove the pre-service hook completed. Observe
            // reaping while admission is still open, so shutdown cannot suppress
            // a late rejection hook (including the no-hook disconnect control).
            self.connection_count
                .wait_for(|count| *count == 0)
                .await
                .expect("connection must finish and reap before shutdown");
            response
        })
        .await
        .expect("admission/raw exchange/body signal/reaping exceeded budget")
    }

    async fn finish(mut self) -> (Observations, Vec<RecordedRequest>, String) {
        self.stop_server.take().unwrap().send(()).unwrap();
        timeout(IO_BUDGET, &mut self.server)
            .await
            .expect("production shutdown exceeded budget")
            .expect("production task panicked")
            .expect("production drain failed");
        self.stop_recorder.take().unwrap().send(()).unwrap();
        let records = timeout(IO_BUDGET, &mut self.recorder)
            .await
            .expect("recorder shutdown exceeded budget")
            .expect("recorder task panicked");
        let observed = self.processor.observations.lock().unwrap().clone();
        (
            observed,
            records,
            self.processor.upstream.authority.to_string(),
        )
    }
}

impl Drop for IngressHarness {
    fn drop(&mut self) {
        // Also bound task lifetime when an assertion or timeout unwinds a test.
        self.server.abort();
        self.recorder.abort();
    }
}

#[derive(Clone, Copy, Debug)]
enum Writes {
    Complete,
    Fragmented,
}

fn raw_request(method: &str, target: &str, headers: &[u8], body: &[u8]) -> Vec<u8> {
    let mut request = format!("{method} {target} HTTP/1.1\r\n").into_bytes();
    request.extend_from_slice(headers);
    request.extend_from_slice(b"Connection: close\r\n\r\n");
    request.extend_from_slice(body);
    request
}

async fn accepted(
    request: &[u8],
    writes: Writes,
    method: &str,
    target: &str,
    body: &[u8],
) -> RecordedRequest {
    let mut harness = IngressHarness::start().await;
    let response = harness.exchange(request, writes, false).await;
    let (observed, mut upstream, authority) = harness.finish().await;
    assert!(
        response.starts_with(b"HTTP/1.1 201 Created\r\n"),
        "{response:?}"
    );
    assert!(
        response.ends_with(b"\r\n\r\nrecorded"),
        "recorder response must reach the caller"
    );
    let expected = ValidatedFields {
        method: method.to_string(),
        target: target.to_string(),
        body: body.to_vec(),
    };
    assert_eq!(
        observed.validated.as_slice(),
        std::slice::from_ref(&expected)
    );
    assert!(observed.policy.is_empty(), "{observed:?}");
    assert!(observed.transport.is_empty(), "{observed:?}");
    assert_eq!(upstream.len(), 1, "exactly one real upstream HTTP request");
    let record = upstream.pop().unwrap();
    assert_eq!(
        record.fields, expected,
        "validated fields must arrive unchanged"
    );
    assert_eq!(record.values("host"), [authority]);
    assert_eq!(record.values("content-length"), [body.len().to_string()]);
    assert!(record
        .wire
        .starts_with(format!("{method} {target} HTTP/1.1\r\n").as_bytes()));
    record
}

async fn positive_control(writes: Writes) {
    accepted(
        &raw_request(
            "POST",
            "/control?label=~&slash=%2F",
            b"Host: proxy.owned.test\r\nContent-Length: 4\r\n",
            b"body",
        ),
        writes,
        "POST",
        "/control?label=~&slash=%2F",
        b"body",
    )
    .await;
}

#[derive(Clone, Copy, Debug)]
enum Rejected {
    Policy(ProductionRequestRejection),
    Transport,
}

async fn rejected(name: &str, request: &[u8], writes: Writes, expected: Rejected) {
    let mut harness = IngressHarness::start().await;
    let response = harness.exchange(request, writes, false).await;
    let (observed, upstream, _) = harness.finish().await;
    assert!(
        observed.validated.is_empty(),
        "{name}/{writes:?}: validated processing: {observed:?}"
    );
    assert!(
        upstream.is_empty(),
        "{name}/{writes:?}: upstream requests: {upstream:?}"
    );
    assert!(
        response.starts_with(b"HTTP/1.1 400 Bad Request\r\n"),
        "{name}/{writes:?}: {response:?}"
    );
    match expected {
        Rejected::Policy(reason) => {
            assert_eq!(observed.policy, [reason], "{name}/{writes:?}");
            assert!(
                observed.transport.is_empty(),
                "{name}/{writes:?}: {observed:?}"
            );
        }
        Rejected::Transport => {
            assert!(
                observed.policy.is_empty(),
                "{name}/{writes:?}: {observed:?}"
            );
            assert_eq!(
                observed.transport,
                [ProductionPreServiceRejection::MalformedTransport],
                "{name}/{writes:?}"
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn raw_host_authority_matrix() {
    use ProductionRequestRejection::{InvalidHost, MissingHost, MultipleHostHeaders};
    for writes in [Writes::Complete, Writes::Fragmented] {
        for host in [
            "proxy.owned.test",
            "proxy.owned.test:8080",
            "127.0.0.1",
            "127.0.0.1:8080",
            "[::1]",
            "[::1]:8080",
        ] {
            accepted(
                &raw_request("GET", "/host", format!("Host: {host}\r\n").as_bytes(), b""),
                writes,
                "GET",
                "/host",
                b"",
            )
            .await;
        }
        for (name, fields, reason) in [
            ("missing", &b""[..], MissingHost),
            (
                "duplicate same",
                &b"Host: proxy.owned.test\r\nhOsT: proxy.owned.test\r\n"[..],
                MultipleHostHeaders,
            ),
            (
                "duplicate conflicting",
                &b"Host: proxy.owned.test\r\nHost: other.owned.test\r\n"[..],
                MultipleHostHeaders,
            ),
            ("empty", &b"Host:\r\n"[..], InvalidHost),
            ("OWS only", &b"Host: \t \r\n"[..], InvalidHost),
            ("non-ASCII", &b"Host: \x80\r\n"[..], InvalidHost),
        ] {
            rejected(
                name,
                &raw_request("GET", "/host", fields, b""),
                writes,
                Rejected::Policy(reason),
            )
            .await;
        }
        rejected(
            "Host control byte",
            &raw_request("GET", "/host", b"Host: bad\x00host\r\n", b""),
            writes,
            Rejected::Transport,
        )
        .await;
        for host in [
            "user@proxy.owned.test",
            "proxy.owned.test:0",
            "proxy.owned.test:",
            "proxy.owned.test:65536",
            "proxy.owned.test:invalid",
            "[::1",
            "::1",
            "[not-ipv6]",
            "proxy.owned.test/path",
            "proxy%2eowned.test",
            "bad host",
        ] {
            rejected(
                host,
                &raw_request("GET", "/host", format!("Host: {host}\r\n").as_bytes(), b""),
                writes,
                Rejected::Policy(InvalidHost),
            )
            .await;
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn raw_target_forms_and_canonical_forwarding_matrix() {
    for writes in [Writes::Complete, Writes::Fragmented] {
        for (method, target, canonical) in [
            (
                "GET",
                "/canonical/path?label=~&slash=%2F",
                "/canonical/path?label=~&slash=%2F",
            ),
            (
                "GET",
                "/api/recon%63ile/%7e?label=%7e&slash=%2f&literal=%252f",
                "/api/reconcile/~?label=~&slash=%2F&literal=%252f",
            ),
            ("OPTIONS", "*", "*"),
        ] {
            accepted(
                &raw_request(method, target, b"Host: proxy.owned.test\r\n", b""),
                writes,
                method,
                canonical,
                b"",
            )
            .await;
        }
        for (method, target) in [
            ("GET", "http://proxy.owned.test/target?x=1"),
            ("GET", "http://other.owned.test/target?x=1"),
            ("GET", "https://proxy.owned.test/target"),
            ("GET", "proxy.owned.test:443"),
            ("GET", "*"),
            ("GET", "//other.owned.test/path"),
            ("GET", "/a//b"),
            ("GET", "/a/./b"),
            ("GET", "/a/../b"),
            ("GET", "/docs;parameter"),
            ("GET", "/a/%2e%2E/b"),
            ("GET", "/a%2fb"),
            ("GET", "/a%5cb"),
            ("GET", "/a%252fb"),
            ("GET", "/a%00b"),
            ("GET", "/a%FFb"),
            ("GET", "/bad%"),
            ("GET", "/bad%GG"),
            ("GET", "/path?q=%"),
        ] {
            rejected(
                target,
                &raw_request(method, target, b"Host: proxy.owned.test\r\n", b""),
                writes,
                Rejected::Policy(ProductionRequestRejection::InvalidTargetForm),
            )
            .await;
        }
        rejected(
            "CONNECT authority",
            &raw_request(
                "CONNECT",
                "proxy.owned.test:443",
                b"Host: proxy.owned.test\r\n",
                b"",
            ),
            writes,
            Rejected::Policy(ProductionRequestRejection::UnsupportedConnect),
        )
        .await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn raw_duplicate_content_length_is_rejected_before_dispatch() {
    for writes in [Writes::Complete, Writes::Fragmented] {
        positive_control(writes).await;
        for (fields, body) in [
            ("Content-Length: 0\r\nContent-Length: 0\r\n", &b""[..]),
            ("Content-Length: 4\r\ncOnTeNt-LeNgTh: 4\r\n", &b"body"[..]),
            (
                "Content-Length: 04\r\nContent-Length: 4\r\nContent-Length: 004\r\n",
                &b"body"[..],
            ),
        ] {
            rejected(
                fields,
                &raw_request(
                    "POST",
                    "/length",
                    format!("Host: proxy.owned.test\r\n{fields}").as_bytes(),
                    body,
                ),
                writes,
                Rejected::Policy(ProductionRequestRejection::MultipleContentLengths),
            )
            .await;
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn raw_invalid_and_conflicting_content_length_transport_matrix() {
    for writes in [Writes::Complete, Writes::Fragmented] {
        positive_control(writes).await;
        for fields in [
            "Content-Length: 4\r\nContent-Length: 5\r\n",
            "Content-Length: 5\r\nContent-Length: 4\r\n",
            "Content-Length: 4\r\nContent-Length: 4\r\nContent-Length: 5\r\n",
            "Content-Length: invalid\r\n",
            "Content-Length:\r\n",
            "Content-Length: -1\r\n",
            "Content-Length: +4\r\n",
            "Content-Length: 18446744073709551616\r\n",
            "Content-Length: 4, 4\r\n",
            "Content-Length: 4, 5\r\n",
            "Content-Length: 4\r\nContent-Length: invalid\r\n",
        ] {
            rejected(
                fields,
                &raw_request(
                    "POST",
                    "/length",
                    format!("Host: proxy.owned.test\r\n{fields}").as_bytes(),
                    b"body!",
                ),
                writes,
                Rejected::Transport,
            )
            .await;
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn raw_content_length_transfer_encoding_both_orders_are_rejected() {
    for writes in [Writes::Complete, Writes::Fragmented] {
        positive_control(writes).await;
        for fields in [
            "Content-Length: 4\r\nTransfer-Encoding: chunked\r\n",
            "Transfer-Encoding: chunked\r\nContent-Length: 4\r\n",
            "Content-Length: 4\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n",
            "Transfer-Encoding: chunked\r\nContent-Length: 4\r\nContent-Length: 4\r\n",
        ] {
            rejected(
                fields,
                &raw_request(
                    "POST",
                    "/framing",
                    format!("Host: proxy.owned.test\r\n{fields}").as_bytes(),
                    b"4\r\nbody\r\n0\r\n\r\n",
                ),
                writes,
                Rejected::Policy(ProductionRequestRejection::UnsupportedTransferEncoding),
            )
            .await;
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn raw_truncated_body_disconnect_has_no_validated_or_upstream_work() {
    for writes in [Writes::Complete, Writes::Fragmented] {
        positive_control(writes).await;
        for body in [&b""[..], &b"bo"[..]] {
            let mut harness = IngressHarness::start().await;
            let response = harness
                .exchange(
                    &raw_request(
                        "POST",
                        "/truncated",
                        b"Host: proxy.owned.test\r\nContent-Length: 4\r\n",
                        body,
                    ),
                    writes,
                    true,
                )
                .await;
            let (observed, upstream, _) = harness.finish().await;
            assert!(observed.validated.is_empty(), "{observed:?}");
            assert!(upstream.is_empty(), "{upstream:?}");
            assert!(
                observed.policy.is_empty(),
                "disconnect is not a policy rejection: {observed:?}"
            );
            assert!(
                observed.transport.is_empty(),
                "disconnect is not malformed transport: {observed:?}"
            );
            // The existing disconnect path returns an empty 200 before closing;
            // this is not successful processing or an upstream response. Keep
            // the zero-work and no-audit assertions above distinct from status.
            let response = std::str::from_utf8(&response).unwrap();
            let (head, body) = response.split_once("\r\n\r\n").unwrap();
            assert!(head.starts_with("HTTP/1.1 200 OK\r\n"), "{response:?}");
            assert!(head
                .lines()
                .any(|line| line.eq_ignore_ascii_case("connection: close")));
            assert_eq!(
                head.lines()
                    .filter(|line| line.to_ascii_lowercase().starts_with("content-length:"))
                    .collect::<Vec<_>>(),
                ["content-length: 0"],
            );
            assert!(body.is_empty(), "disconnect response must have no body");
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn raw_forwarding_preserves_fields_and_strips_protected_headers() {
    for writes in [Writes::Complete, Writes::Fragmented] {
        for (method, body) in [
            ("GET", &b""[..]),
            ("POST", &b"body\0\xff\r\n"[..]),
            ("PATCH", &b"patch"[..]),
        ] {
            let headers = format!(
                "Host: inbound.owned.test:8123\r\nContent-Length: {:04}\r\n\
                 Connection: X-Remove, kEeP-aLiVe, Content-Length, Host\r\n\
                 cOnNeCtIoN: x-SECOND\r\nX-Remove: first\r\nx-remove: second\r\nX-Second: third\r\n\
                 Keep-Alive: timeout=9\r\nProxy-Connection: keep-alive\r\nTE: trailers\r\n\
                 Proxy-Authenticate: fixture\r\nProxy-Authorization: fixture\r\n\
                 X-Eidolon-Internal: synthetic\r\nx-EiDoLoN-Test: synthetic\r\n\
                 Content-Type: application/octet-stream\r\nX-End-To-End: first\r\nx-end-to-end: second\r\nX-Eidolon: ordinary\r\n",
                body.len(),
            );
            let record = accepted(
                &raw_request(
                    method,
                    "/forward/%7e?slash=%2f&label=%7e",
                    headers.as_bytes(),
                    body,
                ),
                writes,
                method,
                "/forward/~?slash=%2F&label=~",
                body,
            )
            .await;
            for name in [
                "connection",
                "x-remove",
                "x-second",
                "keep-alive",
                "proxy-connection",
                "te",
                "trailer",
                "transfer-encoding",
                "upgrade",
                "proxy-authenticate",
                "proxy-authorization",
            ] {
                assert!(
                    record.values(name).is_empty(),
                    "forwarded {name}: {record:?}"
                );
            }
            assert!(
                record
                    .headers
                    .iter()
                    .all(|(name, _)| !name.to_ascii_lowercase().starts_with("x-eidolon-")),
                "{record:?}"
            );
            assert_eq!(record.values("content-type"), ["application/octet-stream"]);
            assert_eq!(record.values("x-end-to-end"), ["first", "second"]);
            assert_eq!(record.values("x-eidolon"), ["ordinary"]);
        }
    }
}
