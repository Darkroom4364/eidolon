//! Raw-wire production ingress controls; the protected listener records only
//! validated processor dispatch. Transport rejection audit hooks are separate.

use std::{
    io::Write,
    net::SocketAddr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use bytes::Bytes;
use hyper::StatusCode;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    task::JoinHandle,
    time::{sleep, timeout},
};

use super::{
    serve_production_http1, serve_production_http1_with_body_collection_signal,
    ProductionPreServiceRejection, ProductionProcessorError, ProductionRejectedRequest,
    ProductionRequestContext, ProductionRequestProcessor, ProductionResponse,
    ProductionRuntimeConfig, ProductionRuntimeError,
};
use crate::production_http::{
    ProductionHttpRequest, ProductionRequestRejection, MAX_PRODUCTION_BODY_BYTES,
    MAX_PRODUCTION_HEADER_BYTES, MAX_PRODUCTION_HEADER_COUNT,
};

const BOUNDARY_OBSERVATION_TIMEOUT: Duration = Duration::from_secs(2);

struct BoundaryProbeProcessor {
    upstream_probe: SocketAddr,
    process_count: AtomicUsize,
    rejections: Mutex<Vec<ProductionRequestRejection>>,
    pre_service_rejections: Mutex<Vec<ProductionPreServiceRejection>>,
}

impl BoundaryProbeProcessor {
    fn new(upstream_probe: SocketAddr) -> Self {
        Self {
            upstream_probe,
            process_count: AtomicUsize::new(0),
            rejections: Mutex::new(Vec::new()),
            pre_service_rejections: Mutex::new(Vec::new()),
        }
    }

    fn rejections(&self) -> Vec<ProductionRequestRejection> {
        self.rejections
            .lock()
            .expect("boundary rejection recorder should lock")
            .clone()
    }

    fn pre_service_rejections(&self) -> Vec<ProductionPreServiceRejection> {
        self.pre_service_rejections
            .lock()
            .expect("boundary pre-service recorder should lock")
            .clone()
    }
}

impl ProductionRequestProcessor for BoundaryProbeProcessor {
    fn process(
        &self,
        request: ProductionHttpRequest,
        _context: ProductionRequestContext,
    ) -> Result<ProductionResponse, ProductionProcessorError> {
        self.process_count.fetch_add(1, Ordering::SeqCst);
        let target = request.target().to_string();
        let mut probe = std::net::TcpStream::connect_timeout(
            &self.upstream_probe,
            BOUNDARY_OBSERVATION_TIMEOUT,
        )
        .map_err(|_| ProductionProcessorError::Failed)?;
        probe
            .set_write_timeout(Some(BOUNDARY_OBSERVATION_TIMEOUT))
            .map_err(|_| ProductionProcessorError::Failed)?;
        probe
            .write_all(target.as_bytes())
            .map_err(|_| ProductionProcessorError::Failed)?;
        Ok(ProductionResponse::new(StatusCode::OK, Bytes::new()))
    }

    fn reject(
        &self,
        rejection: ProductionRequestRejection,
        _request: ProductionRejectedRequest,
        _context: ProductionRequestContext,
    ) -> Result<ProductionResponse, ProductionProcessorError> {
        self.rejections
            .lock()
            .expect("boundary rejection recorder should lock")
            .push(rejection);
        Ok(ProductionResponse::new(
            StatusCode::BAD_REQUEST,
            Bytes::new(),
        ))
    }

    fn reject_pre_service(
        &self,
        rejection: ProductionPreServiceRejection,
        _context: ProductionRequestContext,
    ) -> Result<(), ProductionProcessorError> {
        self.pre_service_rejections
            .lock()
            .expect("boundary pre-service recorder should lock")
            .push(rejection);
        Ok(())
    }
}

fn boundary_runtime_config(request_timeout: Duration) -> ProductionRuntimeConfig {
    ProductionRuntimeConfig {
        max_concurrent_connections: 8,
        request_timeout,
        processor_timeout: Duration::from_secs(1),
        shutdown_grace: Duration::from_secs(1),
    }
}

async fn start_boundary_listener(
    processor: Arc<BoundaryProbeProcessor>,
    request_timeout: Duration,
) -> (
    SocketAddr,
    oneshot::Sender<()>,
    JoinHandle<Result<(), ProductionRuntimeError>>,
) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("boundary listener should bind");
    let address = listener
        .local_addr()
        .expect("boundary listener should have an address");
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let processor: Arc<dyn ProductionRequestProcessor> = processor;
    let server = tokio::spawn(serve_production_http1(
        listener,
        boundary_runtime_config(request_timeout),
        processor,
        async move {
            let _ = shutdown_rx.await;
        },
    ));
    (address, shutdown_tx, server)
}

async fn start_boundary_listener_with_body_signal(
    processor: Arc<BoundaryProbeProcessor>,
    request_timeout: Duration,
) -> (
    SocketAddr,
    oneshot::Sender<()>,
    oneshot::Receiver<()>,
    JoinHandle<Result<(), ProductionRuntimeError>>,
) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("boundary listener should bind");
    let address = listener
        .local_addr()
        .expect("boundary listener should have an address");
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let (body_started_tx, body_started_rx) = oneshot::channel();
    let processor: Arc<dyn ProductionRequestProcessor> = processor;
    let server = tokio::spawn(serve_production_http1_with_body_collection_signal(
        listener,
        boundary_runtime_config(request_timeout),
        processor,
        async move {
            let _ = shutdown_rx.await;
        },
        body_started_tx,
    ));
    (address, shutdown_tx, body_started_rx, server)
}

async fn stop_boundary_listener(
    shutdown_tx: oneshot::Sender<()>,
    server: JoinHandle<Result<(), ProductionRuntimeError>>,
) {
    shutdown_tx
        .send(())
        .expect("boundary listener should receive shutdown");
    timeout(BOUNDARY_OBSERVATION_TIMEOUT, server)
        .await
        .expect("boundary listener should stop promptly")
        .expect("boundary listener task should join")
        .expect("boundary listener should drain cleanly");
}

async fn wait_for_boundary_observation(description: &str, predicate: impl Fn() -> bool) {
    timeout(BOUNDARY_OBSERVATION_TIMEOUT, async {
        while !predicate() {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting for {description}"));
}

async fn send_complete_raw_request(address: SocketAddr, request: &[u8]) -> Vec<u8> {
    let mut client = TcpStream::connect(address)
        .await
        .expect("boundary client should connect");
    client
        .write_all(request)
        .await
        .expect("boundary client should write request");
    let mut response = Vec::new();
    timeout(
        BOUNDARY_OBSERVATION_TIMEOUT,
        client.read_to_end(&mut response),
    )
    .await
    .expect("boundary listener should close complete request")
    .expect("boundary client should read response");
    response
}

async fn send_raw_request_for_rejection(address: SocketAddr, request: &[u8]) -> Vec<u8> {
    let mut client = TcpStream::connect(address)
        .await
        .expect("boundary client should connect");
    client
        .write_all(request)
        .await
        .expect("boundary client should write rejected request");
    let mut response = Vec::new();
    let read_result = timeout(
        BOUNDARY_OBSERVATION_TIMEOUT,
        client.read_to_end(&mut response),
    )
    .await
    .expect("boundary listener should close rejected request");
    if let Err(error) = read_result {
        assert_eq!(
            error.kind(),
            std::io::ErrorKind::ConnectionReset,
            "boundary client should only see a reset after a transport rejection"
        );
    }
    response
}

async fn send_raw_request_split_across_writes(
    address: SocketAddr,
    request: &[u8],
    split_at: usize,
) -> Vec<u8> {
    assert!(
        (1..request.len()).contains(&split_at),
        "raw request split must divide the request"
    );
    let mut client = TcpStream::connect(address)
        .await
        .expect("boundary client should connect");
    client
        .write_all(&request[..split_at])
        .await
        .expect("boundary client should write first request fragment");
    // Exercise a delayed write at the cap boundary. TCP writes do not dictate
    // socket-read boundaries; the vendor capacity probe is deterministic.
    sleep(Duration::from_millis(100)).await;
    client
        .write_all(&request[split_at..])
        .await
        .expect("boundary client should write second request fragment");
    let mut response = Vec::new();
    let read_result = timeout(
        BOUNDARY_OBSERVATION_TIMEOUT,
        client.read_to_end(&mut response),
    )
    .await
    .expect("boundary listener should close fragmented request");
    if let Err(error) = read_result {
        assert_eq!(
            error.kind(),
            std::io::ErrorKind::ConnectionReset,
            "boundary client should only see a reset after a fragmented rejection"
        );
    }
    response
}

async fn assert_protected_probe_target(upstream_probe: &TcpListener, expected_target: &[u8]) {
    let (mut probe, _) = timeout(BOUNDARY_OBSERVATION_TIMEOUT, upstream_probe.accept())
        .await
        .expect("valid request should reach protected upstream probe")
        .expect("protected upstream probe should accept valid request");
    let mut observed_target = Vec::new();
    timeout(
        BOUNDARY_OBSERVATION_TIMEOUT,
        probe.read_to_end(&mut observed_target),
    )
    .await
    .expect("protected upstream probe should read valid target")
    .expect("protected upstream probe target should read");
    assert_eq!(observed_target, expected_target);
}

fn raw_request_with_total_headers(total_headers: usize) -> Vec<u8> {
    const REQUIRED_HEADERS: usize = 2; // Host and Connection
    assert!(
        total_headers >= REQUIRED_HEADERS,
        "raw HTTP/1.1 request needs Host and Connection headers"
    );

    let mut request = b"GET /normal HTTP/1.1\r\nHost: proxy.local\r\n".to_vec();
    for index in 0..total_headers - REQUIRED_HEADERS {
        request.extend_from_slice(format!("X-{index}: x\r\n").as_bytes());
    }
    request.extend_from_slice(b"Connection: close\r\n\r\n");
    request
}

fn raw_http1_head_with_leading_ows_padding(
    request_line: &[u8],
    total_head_bytes: usize,
) -> Vec<u8> {
    let mut request = request_line.to_vec();
    request.extend_from_slice(b"\r\nHost: proxy.local\r\nConnection: close\r\nX-Pad:");
    const HEADER_SUFFIX: &[u8] = b"x\r\n\r\n";
    let padding_bytes = total_head_bytes
        .checked_sub(request.len() + HEADER_SUFFIX.len())
        .expect("raw HTTP/1.1 head limit should fit the fixed request");
    assert!(
        padding_bytes > 0,
        "raw HTTP/1.1 head must contain leading OWS padding"
    );
    request.resize(request.len() + padding_bytes, b' ');
    request.extend_from_slice(HEADER_SUFFIX);
    assert_eq!(request.len(), total_head_bytes);
    assert!(request.ends_with(b"\r\n\r\n"));
    request
}

#[derive(Clone, Copy)]
enum BoundaryUnsafeOutcome {
    Rejected(ProductionRequestRejection),
    PreService(ProductionPreServiceRejection),
}

struct BoundaryUnsafeCase {
    name: &'static str,
    request: Vec<u8>,
    outcome: BoundaryUnsafeOutcome,
}

async fn assert_boundary_unsafe_case(
    address: SocketAddr,
    processor: &BoundaryProbeProcessor,
    case: BoundaryUnsafeCase,
) {
    let process_count_before = processor.process_count.load(Ordering::SeqCst);
    let rejections_before = processor.rejections().len();
    let pre_service_before = processor.pre_service_rejections().len();
    send_complete_raw_request(address, &case.request).await;

    match case.outcome {
        BoundaryUnsafeOutcome::Rejected(expected) => {
            wait_for_boundary_observation(case.name, || {
                processor.rejections().len() > rejections_before
            })
            .await;
            assert_eq!(
                &processor.rejections()[rejections_before..],
                &[expected],
                "{} should produce exactly one expected request rejection",
                case.name
            );
            assert_eq!(
                processor.pre_service_rejections().len(),
                pre_service_before,
                "{} should not become a pre-service rejection",
                case.name
            );
        }
        BoundaryUnsafeOutcome::PreService(expected) => {
            wait_for_boundary_observation(case.name, || {
                processor.pre_service_rejections().len() > pre_service_before
            })
            .await;
            assert_eq!(
                &processor.pre_service_rejections()[pre_service_before..],
                &[expected],
                "{} should produce exactly one expected pre-service rejection",
                case.name
            );
            assert_eq!(
                processor.rejections().len(),
                rejections_before,
                "{} should not enter the request rejection hook",
                case.name
            );
        }
    }
    assert_eq!(
        processor.process_count.load(Ordering::SeqCst),
        process_count_before,
        "{} reached processor work",
        case.name
    );
}

async fn assert_raw_head_limit_rejected_before_service(
    address: SocketAddr,
    processor: &BoundaryProbeProcessor,
    name: &str,
    request: &[u8],
    split_at: Option<usize>,
) {
    let process_count_before = processor.process_count.load(Ordering::SeqCst);
    let rejections_before = processor.rejections().len();
    let pre_service_before = processor.pre_service_rejections().len();
    let response = match split_at {
        Some(split_at) => send_raw_request_split_across_writes(address, request, split_at).await,
        None => send_raw_request_for_rejection(address, request).await,
    };

    wait_for_boundary_observation(name, || {
        processor.process_count.load(Ordering::SeqCst) > process_count_before
            || processor.rejections().len() > rejections_before
            || processor.pre_service_rejections().len() > pre_service_before
    })
    .await;
    assert_eq!(
        processor.process_count.load(Ordering::SeqCst),
        process_count_before,
        "{name} reached processor work rather than the raw transport limit"
    );
    assert_eq!(
        processor.rejections().len(),
        rejections_before,
        "{name} entered the request rejection hook"
    );
    assert_eq!(
        &processor.pre_service_rejections()[pre_service_before..],
        &[ProductionPreServiceRejection::HeadersTooLarge],
        "{name} should produce exactly one header-limit transport rejection"
    );
    assert!(
        response.starts_with(b"HTTP/1.1 431"),
        "{name} should return HTTP 431, got {}",
        String::from_utf8_lossy(&response)
    );
}

async fn assert_raw_head_cap_matrix(split_at: Option<usize>) {
    assert_eq!(MAX_PRODUCTION_HEADER_BYTES, 65_536);
    let upstream_probe = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("protected upstream probe should bind");
    let processor = Arc::new(BoundaryProbeProcessor::new(
        upstream_probe
            .local_addr()
            .expect("protected upstream probe should have an address"),
    ));
    let (address, shutdown_tx, server) =
        start_boundary_listener(Arc::clone(&processor), Duration::from_secs(1)).await;

    for (name, request_line) in [
        ("OWS-padded GET", b"GET /normal HTTP/1.1".as_slice()),
        (
            "leading CRLF and OWS",
            b"\r\nGET /normal HTTP/1.1".as_slice(),
        ),
    ] {
        // Include the literal leading CRLF, request line, normalized-away OWS,
        // and terminating CRLFCRLF in the same raw byte budget.
        let exact =
            raw_http1_head_with_leading_ows_padding(request_line, MAX_PRODUCTION_HEADER_BYTES);
        let process_count_before = processor.process_count.load(Ordering::SeqCst);
        let rejections_before = processor.rejections().len();
        let pre_service_before = processor.pre_service_rejections().len();
        let response = match split_at {
            Some(split_at) => send_raw_request_split_across_writes(address, &exact, split_at).await,
            None => send_complete_raw_request(address, &exact).await,
        };
        assert!(
            response.starts_with(b"HTTP/1.1 200"),
            "{name} at exact cap: {response:?}"
        );
        assert_eq!(
            processor.process_count.load(Ordering::SeqCst),
            process_count_before + 1
        );
        assert_eq!(processor.rejections().len(), rejections_before);
        assert_eq!(processor.pre_service_rejections().len(), pre_service_before);
        assert_protected_probe_target(&upstream_probe, b"/normal").await;

        let oversized =
            raw_http1_head_with_leading_ows_padding(request_line, MAX_PRODUCTION_HEADER_BYTES + 1);
        assert_raw_head_limit_rejected_before_service(
            address, &processor, name, &oversized, split_at,
        )
        .await;
    }

    let oversized_connect = raw_http1_head_with_leading_ows_padding(
        b"CONNECT proxy.local:443 HTTP/1.1",
        MAX_PRODUCTION_HEADER_BYTES + 1,
    );
    assert_raw_head_limit_rejected_before_service(
        address,
        &processor,
        "oversized CONNECT",
        &oversized_connect,
        split_at,
    )
    .await;

    stop_boundary_listener(shutdown_tx, server).await;
    assert_eq!(processor.process_count.load(Ordering::SeqCst), 2);
    assert!(processor.rejections().is_empty());
    assert_eq!(
        processor.pre_service_rejections(),
        vec![ProductionPreServiceRejection::HeadersTooLarge; 3]
    );
    assert!(
        timeout(Duration::from_millis(250), upstream_probe.accept())
            .await
            .is_err(),
        "over-cap heads must cause zero protected upstream connections"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn raw_hyper_ingress_enforces_raw_head_cap_complete_write() {
    assert_raw_head_cap_matrix(None).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn raw_hyper_ingress_enforces_raw_head_cap_fragmented_writes() {
    assert_raw_head_cap_matrix(Some(MAX_PRODUCTION_HEADER_BYTES - 1)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn raw_hyper_ingress_rejects_unsafe_requests_before_the_protected_upstream_probe() {
    let upstream_probe = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("protected upstream probe should bind");
    let processor = Arc::new(BoundaryProbeProcessor::new(
        upstream_probe
            .local_addr()
            .expect("protected upstream probe should have an address"),
    ));
    let (address, shutdown_tx, server) =
        start_boundary_listener(Arc::clone(&processor), Duration::from_secs(1)).await;

    send_complete_raw_request(
        address,
        b"GET /api/v2/import/recon%63ile?label=%7e HTTP/1.1\r\nHost: proxy.local\r\nConnection: close\r\n\r\n",
    )
    .await;
    wait_for_boundary_observation("the valid canonical request", || {
        processor.process_count.load(Ordering::SeqCst) == 1
    })
    .await;
    assert_protected_probe_target(&upstream_probe, b"/api/v2/import/reconcile?label=~").await;

    let exact_header_limit = raw_request_with_total_headers(MAX_PRODUCTION_HEADER_COUNT);
    send_complete_raw_request(address, &exact_header_limit).await;
    wait_for_boundary_observation("the exact header-count limit request", || {
        processor.process_count.load(Ordering::SeqCst) == 2
    })
    .await;
    assert_protected_probe_target(&upstream_probe, b"/normal").await;

    let too_many_headers = raw_request_with_total_headers(MAX_PRODUCTION_HEADER_COUNT + 1);
    let cases = vec![
        BoundaryUnsafeCase {
            name: "malformed transport",
            request: b"GET /normal HTTP/1.1\r\nHost: proxy.local\r\nBad Header: x\r\nConnection: close\r\n\r\n".to_vec(),
            outcome: BoundaryUnsafeOutcome::PreService(
                ProductionPreServiceRejection::MalformedTransport,
            ),
        },
        BoundaryUnsafeCase {
            name: "HTTP/2 preface",
            request: b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec(),
            outcome: BoundaryUnsafeOutcome::PreService(
                ProductionPreServiceRejection::Http2Preface,
            ),
        },
        BoundaryUnsafeCase {
            name: "header count limit",
            request: too_many_headers,
            outcome: BoundaryUnsafeOutcome::PreService(
                ProductionPreServiceRejection::HeadersTooLarge,
            ),
        },
        BoundaryUnsafeCase {
            name: "ambiguous target",
            request: b"GET //proxy.local/normal HTTP/1.1\r\nHost: proxy.local\r\nConnection: close\r\n\r\n".to_vec(),
            outcome: BoundaryUnsafeOutcome::Rejected(
                ProductionRequestRejection::InvalidTargetForm,
            ),
        },
        BoundaryUnsafeCase {
            name: "CONNECT",
            request: b"CONNECT proxy.local:443 HTTP/1.1\r\nHost: proxy.local\r\nConnection: close\r\n\r\n".to_vec(),
            outcome: BoundaryUnsafeOutcome::Rejected(
                ProductionRequestRejection::UnsupportedConnect,
            ),
        },
        BoundaryUnsafeCase {
            name: "upgrade",
            request: b"GET /normal HTTP/1.1\r\nHost: proxy.local\r\nConnection: Upgrade, close\r\nUpgrade: websocket\r\n\r\n".to_vec(),
            outcome: BoundaryUnsafeOutcome::Rejected(
                ProductionRequestRejection::UnsupportedUpgrade,
            ),
        },
        BoundaryUnsafeCase {
            name: "expectation",
            request: b"GET /normal HTTP/1.1\r\nHost: proxy.local\r\nExpect: 100-continue\r\nConnection: close\r\n\r\n".to_vec(),
            outcome: BoundaryUnsafeOutcome::Rejected(
                ProductionRequestRejection::UnsupportedExpectation,
            ),
        },
        BoundaryUnsafeCase {
            name: "transfer encoding",
            request: b"POST /normal HTTP/1.1\r\nHost: proxy.local\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n0\r\n\r\n".to_vec(),
            outcome: BoundaryUnsafeOutcome::Rejected(
                ProductionRequestRejection::UnsupportedTransferEncoding,
            ),
        },
        BoundaryUnsafeCase {
            name: "trailer declaration",
            request: b"POST /normal HTTP/1.1\r\nHost: proxy.local\r\nTrailer: x-checksum\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
            outcome: BoundaryUnsafeOutcome::Rejected(
                ProductionRequestRejection::UnsupportedTrailers,
            ),
        },
    ];
    for case in cases {
        assert_boundary_unsafe_case(address, &processor, case).await;
    }

    stop_boundary_listener(shutdown_tx, server).await;
    assert!(
        timeout(Duration::from_millis(250), upstream_probe.accept())
            .await
            .is_err(),
        "unsafe raw-wire traffic must not open a protected upstream probe connection"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn raw_hyper_ingress_times_out_held_open_header_and_body_before_the_protected_upstream_probe()
{
    let upstream_probe = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("protected upstream probe should bind");
    let processor = Arc::new(BoundaryProbeProcessor::new(
        upstream_probe
            .local_addr()
            .expect("protected upstream probe should have an address"),
    ));
    let (address, shutdown_tx, body_started, server) = start_boundary_listener_with_body_signal(
        Arc::clone(&processor),
        Duration::from_millis(150),
    )
    .await;
    let header_rejections_before = processor.rejections().len();
    let header_pre_service_before = processor.pre_service_rejections().len();

    let mut incomplete_header = TcpStream::connect(address)
        .await
        .expect("boundary client should connect for incomplete header");
    incomplete_header
        .write_all(b"GET /normal HTTP/1.1\r\nHost: proxy.local\r\n")
        .await
        .expect("boundary client should write incomplete header");
    wait_for_boundary_observation("incomplete header timeout", || {
        processor.pre_service_rejections().len() > header_pre_service_before
    })
    .await;
    assert_eq!(
        &processor.pre_service_rejections()[header_pre_service_before..],
        &[ProductionPreServiceRejection::HeaderReadTimedOut],
        "incomplete header should produce exactly one timeout rejection"
    );
    assert_eq!(
        processor.rejections().len(),
        header_rejections_before,
        "incomplete header should not enter the request rejection hook"
    );
    drop(incomplete_header);
    let body_rejections_before = processor.rejections().len();
    let body_pre_service_before = processor.pre_service_rejections().len();

    let mut incomplete_body = TcpStream::connect(address)
        .await
        .expect("boundary client should connect for incomplete body");
    incomplete_body
        .write_all(
            b"POST /normal HTTP/1.1\r\nHost: proxy.local\r\nContent-Length: 1\r\nConnection: close\r\n\r\n",
        )
        .await
        .expect("boundary client should write incomplete body header");
    timeout(BOUNDARY_OBSERVATION_TIMEOUT, body_started)
        .await
        .expect("boundary listener should begin body collection")
        .expect("boundary body collection signal should arrive");
    wait_for_boundary_observation("incomplete body timeout", || {
        processor.rejections().len() > body_rejections_before
    })
    .await;
    assert_eq!(
        &processor.rejections()[body_rejections_before..],
        &[ProductionRequestRejection::RequestTimedOut],
        "incomplete body should produce exactly one timeout rejection"
    );
    assert_eq!(
        processor.pre_service_rejections().len(),
        body_pre_service_before,
        "incomplete body should not enter the pre-service rejection hook"
    );
    drop(incomplete_body);

    assert_eq!(
        processor.process_count.load(Ordering::SeqCst),
        0,
        "held-open incomplete requests must not reach processor work"
    );
    stop_boundary_listener(shutdown_tx, server).await;
    assert!(
        timeout(Duration::from_millis(250), upstream_probe.accept())
            .await
            .is_err(),
        "held-open incomplete requests must not open a protected upstream probe connection"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn raw_hyper_ingress_rejects_an_oversized_collected_body_before_the_protected_upstream_probe()
{
    let upstream_probe = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("protected upstream probe should bind");
    let processor = Arc::new(BoundaryProbeProcessor::new(
        upstream_probe
            .local_addr()
            .expect("protected upstream probe should have an address"),
    ));
    let (address, shutdown_tx, server) =
        start_boundary_listener(Arc::clone(&processor), Duration::from_secs(5)).await;
    let body_rejections_before = processor.rejections().len();
    let body_pre_service_before = processor.pre_service_rejections().len();
    let mut client = TcpStream::connect(address)
        .await
        .expect("boundary client should connect for oversized body");
    client
        .write_all(
            format!(
                "POST /normal HTTP/1.1\r\nHost: proxy.local\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                MAX_PRODUCTION_BODY_BYTES + 1
            )
            .as_bytes(),
        )
        .await
        .expect("boundary client should write oversized body header");
    let body = vec![b'x'; MAX_PRODUCTION_BODY_BYTES + 1];
    // The listener may close immediately after consuming the over-limit
    // byte. The typed rejection below proves it consumed that byte rather
    // than treating a client EOF as coverage.
    let _ = timeout(Duration::from_secs(5), client.write_all(&body))
        .await
        .expect("boundary client should make bounded oversized-body progress");
    wait_for_boundary_observation("oversized body rejection", || {
        processor.rejections().len() > body_rejections_before
    })
    .await;
    assert_eq!(
        &processor.rejections()[body_rejections_before..],
        &[ProductionRequestRejection::BodyTooLarge],
        "oversized body should produce exactly one body-limit rejection"
    );
    assert_eq!(
        processor.pre_service_rejections().len(),
        body_pre_service_before,
        "oversized body should not enter the pre-service rejection hook"
    );
    drop(client);

    assert_eq!(
        processor.process_count.load(Ordering::SeqCst),
        0,
        "oversized body must not reach processor work"
    );
    stop_boundary_listener(shutdown_tx, server).await;
    assert!(
        timeout(Duration::from_millis(250), upstream_probe.accept())
            .await
            .is_err(),
        "oversized body must not open a protected upstream probe connection"
    );
}
