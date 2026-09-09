//! Feature-gated in-memory driver for the production HTTP/1 fuzz target.
//!
//! This module is not part of the default production build. It deliberately
//! reuses the runtime's exact body collector and transport classifier, then
//! crosses the public production adapter. It does not exercise the TCP accept
//! loop, admission limits, wall-clock request deadlines, processor, upstream,
//! or audit path.

use std::{
    collections::VecDeque,
    convert::Infallible,
    future::Future,
    io,
    pin::Pin,
    sync::atomic::{AtomicBool, Ordering},
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::{Duration, Instant},
};

use bytes::Bytes;
use http_body_util::Full;
use hyper::{
    header::{CONNECTION, CONTENT_LENGTH, EXPECT, HOST, TRAILER, TRANSFER_ENCODING, UPGRADE},
    server::conn::http1,
    service::service_fn,
    Request, Response,
};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::{
    collect_inbound_body, pre_service_transport_rejection, InboundBodyCollectionError,
    ProductionPreServiceRejection,
};
use crate::{
    http_request::{canonical_request_target, RequestTargetMode},
    production_http::{
        ProductionHttpPolicy, ProductionHttpRequest, ProductionRequestRejection,
        MAX_PRODUCTION_BODY_BYTES, MAX_PRODUCTION_HEADER_BYTES, MAX_PRODUCTION_HEADER_COUNT,
    },
};

/// One byte beyond the production raw-head cap keeps the C1 cap edge reachable
/// while bounding per-input memory and work. Larger bodies remain deterministic
/// C1 coverage, not this fuzz target's claim.
pub const MAX_FUZZ_INPUT_BYTES: usize = MAX_PRODUCTION_HEADER_BYTES + 1;

const MAX_CAPTURED_RESPONSE_BYTES: usize = 4 * 1024;
const INPUT_DEADLINE: Duration = Duration::from_millis(250);
const FRAGMENT_WIDTHS: [usize; 8] = [1, 3, 7, 2, 11, 5, 17, 13];
const MAX_FRAGMENTED_CHUNKS: usize = 64;

thread_local! {
    static FUZZ_RUNTIME: tokio::runtime::Runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .expect("fuzz driver runtime must build");
}

/// Stable request-layer result. Payload-bearing parser errors are deliberately
/// not retained.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestOutcome {
    NoCompleteRequest,
    ClientDisconnected,
    PolicyRejected(ProductionRequestRejection),
    Accepted(AcceptedRequest),
}

/// Bounded accepted fields needed to prove canonicalization and delivery
/// equivalence. Header order and multiplicity are retained.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedRequest {
    pub method: String,
    pub target: String,
    pub version: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// Stable connection completion class. This mirrors the production
/// pre-service hook without comparing Hyper error strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionOutcome {
    Clean,
    PreServiceRejected(ProductionPreServiceRejection),
    Incomplete,
    OtherTransportFailure,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    pub request: RequestOutcome,
    pub connection: ConnectionOutcome,
    pub response_bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DriverError {
    InputTooLarge { actual: usize, maximum: usize },
    InputTimedOut,
    MoreThanOneRequest(usize),
    ResponseCaptureExceeded,
    AcceptedInvariant(&'static str),
}

#[derive(Debug, Clone, Copy)]
enum DeliverySchedule {
    Whole,
    Fragmented,
}

/// Evaluate the input under whole and deterministic fragmented delivery.
/// Callers must require exact equality; a timeout or driver error is a failing
/// fuzz input, never an accepted result.
pub fn evaluate_both(input: &[u8]) -> Result<(Observation, Observation), DriverError> {
    if input.len() > MAX_FUZZ_INPUT_BYTES {
        return Err(DriverError::InputTooLarge {
            actual: input.len(),
            maximum: MAX_FUZZ_INPUT_BYTES,
        });
    }
    let (whole, fragmented) = block_on(async {
        let whole = evaluate(input, DeliverySchedule::Whole).await?;
        let fragmented = evaluate(input, DeliverySchedule::Fragmented).await?;
        Ok::<_, DriverError>((whole, fragmented))
    })?;
    if let RequestOutcome::Accepted(request) = &whole.request {
        assert_accepted_invariants(request)?;
    }
    if let RequestOutcome::Accepted(request) = &fragmented.request {
        assert_accepted_invariants(request)?;
    }
    Ok((whole, fragmented))
}

fn block_on<F: Future>(future: F) -> F::Output {
    FUZZ_RUNTIME.with(|runtime| runtime.block_on(future))
}

async fn evaluate(input: &[u8], schedule: DeliverySchedule) -> Result<Observation, DriverError> {
    let response_bytes = Arc::new(Mutex::new(Vec::new()));
    let response_overflow = Arc::new(AtomicBool::new(false));
    let io = ScriptedIo::new(
        delivery_chunks(input, schedule),
        Arc::clone(&response_bytes),
        Arc::clone(&response_overflow),
    );
    let requests = Arc::new(Mutex::new(Vec::new()));
    let service_requests = Arc::clone(&requests);
    let service = service_fn(move |request| {
        let requests = Arc::clone(&service_requests);
        async move {
            let outcome = observe_request(request).await;
            requests
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(outcome);
            let mut response = Response::new(Full::new(Bytes::new()));
            *response.status_mut() = hyper::StatusCode::NO_CONTENT;
            response
                .headers_mut()
                .insert(CONNECTION, hyper::header::HeaderValue::from_static("close"));
            Ok::<_, Infallible>(response)
        }
    });

    let mut builder = http1::Builder::new();
    builder.max_headers(MAX_PRODUCTION_HEADER_COUNT);
    builder.max_buf_size(MAX_PRODUCTION_HEADER_BYTES);
    builder.auto_date_header(false);
    builder.keep_alive(false);
    let connection =
        complete_within_input_deadline(builder.serve_connection(TokioIo::new(io), service)).await?;
    if response_overflow.load(Ordering::SeqCst) {
        return Err(DriverError::ResponseCaptureExceeded);
    }
    let response_bytes = response_bytes
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone();
    let requests = requests
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone();
    if requests.len() > 1 {
        return Err(DriverError::MoreThanOneRequest(requests.len()));
    }
    let request = requests
        .into_iter()
        .next()
        .unwrap_or(RequestOutcome::NoCompleteRequest);
    let connection = match connection {
        Ok(()) => ConnectionOutcome::Clean,
        Err(error) => match pre_service_transport_rejection(&error) {
            Some(rejection) => ConnectionOutcome::PreServiceRejected(rejection),
            None if error.is_incomplete_message() || error.is_closed() => {
                ConnectionOutcome::Incomplete
            }
            None => ConnectionOutcome::OtherTransportFailure,
        },
    };
    Ok(Observation {
        request,
        connection,
        response_bytes,
    })
}

async fn complete_within_input_deadline<F>(future: F) -> Result<F::Output, DriverError>
where
    F: Future,
{
    let started = Instant::now();
    let output = tokio::time::timeout(INPUT_DEADLINE, future)
        .await
        .map_err(|_| DriverError::InputTimedOut)?;
    if started.elapsed() > INPUT_DEADLINE {
        return Err(DriverError::InputTimedOut);
    }
    Ok(output)
}

async fn observe_request(request: Request<hyper::body::Incoming>) -> RequestOutcome {
    let (parts, body) = request.into_parts();
    let body = collect_inbound_body(
        body,
        #[cfg(test)]
        None,
    )
    .await;
    let body = match body {
        Ok(body) => body,
        Err(InboundBodyCollectionError::ClientDisconnected) => {
            return RequestOutcome::ClientDisconnected;
        }
        Err(InboundBodyCollectionError::Rejected(rejection)) => {
            return RequestOutcome::PolicyRejected(rejection);
        }
    };
    match ProductionHttpPolicy.adapt(Request::from_parts(parts, body)) {
        Ok(request) => RequestOutcome::Accepted(accepted_request(request)),
        Err(rejection) => RequestOutcome::PolicyRejected(rejection),
    }
}

fn accepted_request(request: ProductionHttpRequest) -> AcceptedRequest {
    AcceptedRequest {
        method: request.method().to_string(),
        target: request.target().to_string(),
        version: request.version().as_str().to_string(),
        headers: request
            .headers()
            .iter()
            .map(|header| (header.name().to_string(), header.value().to_string()))
            .collect(),
        body: request.body().to_vec(),
    }
}

fn assert_accepted_invariants(request: &AcceptedRequest) -> Result<(), DriverError> {
    if request.version != "HTTP/1.1" {
        return Err(DriverError::AcceptedInvariant(
            "accepted version is not HTTP/1.1",
        ));
    }
    if request.method.eq_ignore_ascii_case("CONNECT") {
        return Err(DriverError::AcceptedInvariant(
            "CONNECT reached accepted output",
        ));
    }
    if request.target == "*" {
        if !request.method.eq_ignore_ascii_case("OPTIONS") {
            return Err(DriverError::AcceptedInvariant(
                "non-OPTIONS asterisk target reached accepted output",
            ));
        }
    } else if !request.target.starts_with('/') || request.target.starts_with("//") {
        return Err(DriverError::AcceptedInvariant(
            "accepted target is not strict origin form",
        ));
    }
    let lifecycle = crate::http_request::HttpRequest {
        method: request.method.clone(),
        target: request.target.clone(),
        version: crate::http_request::HttpVersion::Http11,
        headers: request
            .headers
            .iter()
            .map(|(name, value)| crate::http_request::HttpHeader {
                name: name.clone(),
                value: value.clone(),
            })
            .collect(),
        body: request.body.clone(),
    };
    if canonical_request_target(&lifecycle, RequestTargetMode::OriginOnly)
        .ok()
        .as_deref()
        != Some(request.target.as_str())
    {
        return Err(DriverError::AcceptedInvariant(
            "accepted target is not canonical and idempotent",
        ));
    }
    if request.headers.len() > MAX_PRODUCTION_HEADER_COUNT {
        return Err(DriverError::AcceptedInvariant(
            "accepted header count exceeds production cap",
        ));
    }
    let encoded_head_len = request
        .method
        .len()
        .saturating_add(request.target.len())
        .saturating_add(16)
        .saturating_add(
            request
                .headers
                .iter()
                .map(|(name, value)| name.len().saturating_add(value.len()).saturating_add(4))
                .fold(0_usize, usize::saturating_add),
        )
        .saturating_add(2);
    if encoded_head_len > MAX_PRODUCTION_HEADER_BYTES {
        return Err(DriverError::AcceptedInvariant(
            "accepted encoded head exceeds production cap",
        ));
    }
    if request.body.len() > MAX_PRODUCTION_BODY_BYTES {
        return Err(DriverError::AcceptedInvariant(
            "accepted body exceeds production cap",
        ));
    }
    let host_count = request
        .headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case(HOST.as_str()))
        .count();
    if host_count != 1 {
        return Err(DriverError::AcceptedInvariant(
            "accepted output does not contain exactly one Host",
        ));
    }
    let unsupported_header = request.headers.iter().any(|(name, _)| {
        [UPGRADE, EXPECT, TRANSFER_ENCODING, TRAILER]
            .iter()
            .any(|blocked| name.eq_ignore_ascii_case(blocked.as_str()))
    });
    let connection_upgrade = request.headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case(CONNECTION.as_str())
            && value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
    });
    if unsupported_header || connection_upgrade {
        return Err(DriverError::AcceptedInvariant(
            "unsupported protocol header reached accepted output",
        ));
    }
    let content_lengths = request
        .headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case(CONTENT_LENGTH.as_str()))
        .map(|(_, value)| value.as_str())
        .collect::<Vec<_>>();
    match content_lengths.as_slice() {
        [] if request.body.is_empty() => {}
        [value] if value.parse::<usize>().ok() == Some(request.body.len()) => {}
        _ => {
            return Err(DriverError::AcceptedInvariant(
                "accepted body and Content-Length do not agree exactly",
            ));
        }
    }
    Ok(())
}

fn delivery_chunks(input: &[u8], schedule: DeliverySchedule) -> Vec<Vec<u8>> {
    match schedule {
        DeliverySchedule::Whole => (!input.is_empty())
            .then(|| input.to_vec())
            .into_iter()
            .collect(),
        DeliverySchedule::Fragmented => {
            let mut chunks = Vec::new();
            let mut offset = 0;
            let mut width_index = 0;
            while offset < input.len() {
                if chunks.len() + 1 == MAX_FRAGMENTED_CHUNKS {
                    chunks.push(input[offset..].to_vec());
                    break;
                }
                let width = FRAGMENT_WIDTHS[width_index % FRAGMENT_WIDTHS.len()];
                let end = offset.saturating_add(width).min(input.len());
                chunks.push(input[offset..end].to_vec());
                offset = end;
                width_index += 1;
            }
            chunks
        }
    }
}

struct ScriptedIo {
    chunks: VecDeque<Vec<u8>>,
    chunk_offset: usize,
    yield_before_next_chunk: bool,
    yield_before_eof: bool,
    response_bytes: Arc<Mutex<Vec<u8>>>,
    response_overflow: Arc<AtomicBool>,
}

impl ScriptedIo {
    fn new(
        chunks: Vec<Vec<u8>>,
        response_bytes: Arc<Mutex<Vec<u8>>>,
        response_overflow: Arc<AtomicBool>,
    ) -> Self {
        let chunks = VecDeque::from(chunks);
        let yield_before_next_chunk = !chunks.is_empty();
        Self {
            chunks,
            chunk_offset: 0,
            yield_before_next_chunk,
            yield_before_eof: false,
            response_bytes,
            response_overflow,
        }
    }
}

impl AsyncRead for ScriptedIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buffer.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if self.yield_before_next_chunk {
            self.yield_before_next_chunk = false;
            context.waker().wake_by_ref();
            return Poll::Pending;
        }
        if self.chunks.is_empty() && self.yield_before_eof {
            self.yield_before_eof = false;
            context.waker().wake_by_ref();
            return Poll::Pending;
        }
        let Some(chunk) = self.chunks.front() else {
            return Poll::Ready(Ok(()));
        };
        let chunk_len = chunk.len();
        let available = &chunk[self.chunk_offset..];
        let amount = available.len().min(buffer.remaining());
        buffer.put_slice(&available[..amount]);
        self.chunk_offset += amount;
        if self.chunk_offset == chunk_len {
            self.chunks.pop_front();
            self.chunk_offset = 0;
            self.yield_before_next_chunk = !self.chunks.is_empty();
            self.yield_before_eof = self.chunks.is_empty();
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for ScriptedIo {
    fn poll_write(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut captured = self
            .response_bytes
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(remaining) = MAX_CAPTURED_RESPONSE_BYTES.checked_sub(captured.len()) else {
            self.response_overflow.store(true, Ordering::SeqCst);
            return Poll::Ready(Err(io::Error::other("fuzz response capture exceeded")));
        };
        if bytes.len() > remaining {
            self.response_overflow.store(true, Ordering::SeqCst);
            return Poll::Ready(Err(io::Error::other("fuzz response capture exceeded")));
        }
        captured.extend_from_slice(bytes);
        Poll::Ready(Ok(bytes.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{
        complete_within_input_deadline, delivery_chunks, evaluate_both, ConnectionOutcome,
        DeliverySchedule, RequestOutcome, INPUT_DEADLINE, MAX_FRAGMENTED_CHUNKS,
        MAX_FUZZ_INPUT_BYTES,
    };
    use crate::{
        production_http::ProductionRequestRejection,
        production_runtime::ProductionPreServiceRejection,
    };

    fn assert_equivalent(input: &[u8]) -> super::Observation {
        let (whole, fragmented) = evaluate_both(input).expect("driver should complete");
        assert_eq!(whole, fragmented, "delivery schedules must agree");
        whole
    }

    #[test]
    fn valid_and_canonicalized_requests_are_equivalent() {
        let observed = assert_equivalent(
            b"GET /fuzz/recon%63ile/%7e?slash=%2f HTTP/1.1\r\nHost: proxy.owned.test\r\nConnection: close\r\n\r\n",
        );
        let RequestOutcome::Accepted(request) = observed.request else {
            panic!("valid request should adapt: {observed:?}");
        };
        assert_eq!(request.method, "GET");
        assert_eq!(request.target, "/fuzz/reconcile/~?slash=%2F");
        assert_eq!(request.version, "HTTP/1.1");
        assert_eq!(observed.connection, ConnectionOutcome::Clean);
    }

    #[test]
    fn parser_and_policy_rejections_remain_distinct() {
        let parser = assert_equivalent(
            b"POST / HTTP/1.1\r\nHost: proxy.owned.test\r\nContent-Length: 1\r\nContent-Length: 2\r\nConnection: close\r\n\r\nx",
        );
        assert_eq!(parser.request, RequestOutcome::NoCompleteRequest);
        assert_eq!(
            parser.connection,
            ConnectionOutcome::PreServiceRejected(
                ProductionPreServiceRejection::MalformedTransport
            )
        );

        let policy = assert_equivalent(
            b"GET http://proxy.owned.test/ HTTP/1.1\r\nHost: proxy.owned.test\r\nConnection: close\r\n\r\n",
        );
        assert_eq!(
            policy.request,
            RequestOutcome::PolicyRejected(ProductionRequestRejection::InvalidTargetForm)
        );
    }

    #[test]
    fn malformed_partial_head_is_segmentation_invariant_at_eof() {
        let observed = assert_equivalent(b".\n");
        assert_eq!(observed.request, RequestOutcome::NoCompleteRequest);
        assert_eq!(
            observed.connection,
            ConnectionOutcome::PreServiceRejected(
                ProductionPreServiceRejection::MalformedTransport
            )
        );
        assert!(observed.response_bytes.starts_with(b"HTTP/1.1 400 "));
    }

    #[test]
    fn malformed_partial_head_is_segmentation_invariant_at_raw_head_limit() {
        let mut input = b".\n".to_vec();
        input.resize(MAX_FUZZ_INPUT_BYTES - 1, b'a');
        let observed = assert_equivalent(&input);
        assert_eq!(observed.request, RequestOutcome::NoCompleteRequest);
        assert_eq!(
            observed.connection,
            ConnectionOutcome::PreServiceRejected(
                ProductionPreServiceRejection::MalformedTransport
            )
        );
        assert!(observed.response_bytes.starts_with(b"HTTP/1.1 400 "));
    }

    #[test]
    fn valid_partial_head_at_raw_limit_remains_too_large() {
        let mut input = b"GET /".to_vec();
        input.resize(MAX_FUZZ_INPUT_BYTES - 1, b'a');
        let observed = assert_equivalent(&input);
        assert_eq!(observed.request, RequestOutcome::NoCompleteRequest);
        assert_eq!(
            observed.connection,
            ConnectionOutcome::PreServiceRejected(ProductionPreServiceRejection::HeadersTooLarge)
        );
        assert!(observed.response_bytes.starts_with(b"HTTP/1.1 431 "));
    }

    #[test]
    fn raw_fragment_is_rejected_before_uri_normalization() {
        let observed = assert_equivalent(
            b"GET /qualification/raw#fragment HTTP/1.1\r\nHost: proxy.fuzz.test\r\n\r\n",
        );
        assert_eq!(observed.request, RequestOutcome::NoCompleteRequest);
        assert_eq!(
            observed.connection,
            ConnectionOutcome::PreServiceRejected(
                ProductionPreServiceRejection::MalformedTransport
            )
        );
        assert!(observed.response_bytes.starts_with(b"HTTP/1.1 400 "));
    }

    #[test]
    fn fragment_rejection_preserves_original_position_for_preface_classification() {
        let observed = assert_equivalent(
            b"GET /qualification/raw#fragment HTTP/1.1\r\nHost: proxy.fuzz.test\r\n\r\nPRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
        );
        assert_eq!(observed.request, RequestOutcome::NoCompleteRequest);
        assert_eq!(
            observed.connection,
            ConnectionOutcome::PreServiceRejected(
                ProductionPreServiceRejection::MalformedTransport
            )
        );
        assert!(observed.response_bytes.starts_with(b"HTTP/1.1 400 "));
    }

    #[test]
    fn framing_rejection_cannot_promote_buffered_preface() {
        let observed = assert_equivalent(
            b"POST / HTTP/1.1\r\nHost: proxy.fuzz.test\r\nContent-Length: 0\r\nContent-Length: 1\r\n\r\nPRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
        );
        assert_eq!(observed.request, RequestOutcome::NoCompleteRequest);
        assert_eq!(
            observed.connection,
            ConnectionOutcome::PreServiceRejected(
                ProductionPreServiceRejection::MalformedTransport
            )
        );
        assert!(observed.response_bytes.starts_with(b"HTTP/1.1 400 "));
    }

    #[test]
    fn prefixed_http2_preface_is_segmentation_invariant() {
        let observed = assert_equivalent(b"\nPRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
        assert_eq!(observed.request, RequestOutcome::NoCompleteRequest);
        assert_eq!(
            observed.connection,
            ConnectionOutcome::PreServiceRejected(
                ProductionPreServiceRejection::MalformedTransport
            )
        );
        assert!(observed.response_bytes.starts_with(b"HTTP/1.1 400 "));
    }

    #[test]
    fn connect_spelling_is_rejected_case_insensitively() {
        for method in ["connect", "Connect"] {
            let input = format!("{method} / HTTP/1.1\r\nHost: proxy.fuzz.test\r\n\r\n");
            let observed = assert_equivalent(input.as_bytes());
            assert_eq!(
                observed.request,
                RequestOutcome::PolicyRejected(ProductionRequestRejection::UnsupportedConnect)
            );
            assert_eq!(observed.connection, ConnectionOutcome::Clean);
        }
    }

    #[test]
    fn non_yielding_completion_after_deadline_fails() {
        let result = super::block_on(complete_within_input_deadline(async {
            std::thread::sleep(INPUT_DEADLINE + Duration::from_millis(50));
        }));
        assert_eq!(result, Err(super::DriverError::InputTimedOut));
    }

    #[test]
    fn driver_rejects_inputs_above_its_exact_cap() {
        let input = vec![b'a'; MAX_FUZZ_INPUT_BYTES + 1];
        assert!(matches!(
            evaluate_both(&input),
            Err(super::DriverError::InputTooLarge {
                actual,
                maximum: MAX_FUZZ_INPUT_BYTES
            }) if actual == MAX_FUZZ_INPUT_BYTES + 1
        ));
    }

    #[test]
    fn delivery_schedules_preserve_input_with_bounded_chunk_count() {
        let input = vec![b'x'; MAX_FUZZ_INPUT_BYTES];
        let whole = delivery_chunks(&input, DeliverySchedule::Whole);
        assert_eq!(whole.len(), 1);
        assert_eq!(whole.concat(), input);

        let fragmented = delivery_chunks(&input, DeliverySchedule::Fragmented);
        assert_eq!(fragmented.len(), MAX_FRAGMENTED_CHUNKS);
        assert!(fragmented.iter().all(|chunk| !chunk.is_empty()));
        assert_eq!(fragmented.concat(), input);
    }
}
