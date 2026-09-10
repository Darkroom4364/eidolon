use std::{
    convert::Infallible,
    error::Error,
    fmt,
    future::Future,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use bytes::{Bytes, BytesMut};
use http_body_util::{BodyExt, Full};
use hyper::{
    body::Incoming,
    client::conn::http1 as client_http1,
    header::{
        HeaderMap, HeaderName, HeaderValue, CONNECTION, CONTENT_LENGTH, HOST, PROXY_AUTHENTICATE,
        PROXY_AUTHORIZATION, TE, TRAILER, TRANSFER_ENCODING, UPGRADE,
    },
    http::uri::Authority,
    server::conn::http1 as server_http1,
    service::service_fn,
    Request, Response, StatusCode, Version,
};
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{watch, OwnedSemaphorePermit, Semaphore},
    task::JoinSet,
    time::{timeout, timeout_at},
};

use crate::production_http::{
    ProductionHttpPolicy, ProductionHttpRequest, ProductionInboundBody, ProductionRequestRejection,
    MAX_PRODUCTION_BODY_BYTES, MAX_PRODUCTION_HEADER_BYTES, MAX_PRODUCTION_HEADER_COUNT,
};

const DEFAULT_MAX_CONCURRENT_CONNECTIONS: usize = 64;
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_PROCESSOR_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_UPSTREAM_RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_UPSTREAM_DISPATCH_TIMEOUT: Duration = Duration::from_secs(29);
const DEFAULT_MAX_UPSTREAM_RESPONSE_BODY_BYTES: usize = MAX_PRODUCTION_BODY_BYTES;
pub const DEFAULT_PRODUCTION_SHUTDOWN_GRACE: Duration = Duration::from_secs(60);
pub const MAX_PRODUCTION_SHUTDOWN_GRACE: Duration = Duration::from_secs(300);
pub const MAX_PRODUCTION_UPSTREAM_ADDRESSES: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProductionRuntimeConfig {
    pub max_concurrent_connections: usize,
    pub request_timeout: Duration,
    /// Absolute request budget supplied to typed outbound dispatch. It does
    /// not interrupt synchronous processor work already in progress.
    pub processor_timeout: Duration,
    /// Grace period for a successful drain of already-admitted connections.
    /// Expiry reports failure, then waits for non-cancellable accepted work to
    /// quiesce before returning.
    pub shutdown_grace: Duration,
}

impl Default for ProductionRuntimeConfig {
    fn default() -> Self {
        Self {
            max_concurrent_connections: DEFAULT_MAX_CONCURRENT_CONNECTIONS,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            processor_timeout: DEFAULT_PROCESSOR_TIMEOUT,
            shutdown_grace: DEFAULT_PRODUCTION_SHUTDOWN_GRACE,
        }
    }
}

impl ProductionRuntimeConfig {
    fn is_valid(self) -> bool {
        self.max_concurrent_connections > 0
            && !self.request_timeout.is_zero()
            && !self.processor_timeout.is_zero()
            && !self.shutdown_grace.is_zero()
            && self.shutdown_grace <= MAX_PRODUCTION_SHUTDOWN_GRACE
    }
}

/// Production ingress context. `request_deadline` bounds outbound work but
/// cannot interrupt arbitrary synchronous lifecycle work already in progress.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProductionRequestContext {
    pub peer_addr: Option<SocketAddr>,
    pub request_deadline: Instant,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Bytes,
}

impl ProductionResponse {
    pub fn new(status: StatusCode, body: impl Into<Bytes>) -> Self {
        Self {
            status,
            headers: HeaderMap::new(),
            body: body.into(),
        }
    }
}

/// Sanitized marker for a rejected inbound request. It carries no request
/// target, method, headers, or body to the processor hook.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProductionRejectedRequest {
    _private: (),
}

impl ProductionRejectedRequest {
    const fn sanitized() -> Self {
        Self { _private: () }
    }
}

/// Stable, payload-free classification for a connection rejected by Hyper
/// before it can invoke the request service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProductionPreServiceRejection {
    HeadersTooLarge,
    Http2Preface,
    MalformedTransport,
    HeaderReadTimedOut,
}

impl ProductionPreServiceRejection {
    pub const fn audit_code(self) -> &'static str {
        match self {
            Self::HeadersTooLarge => "headers_too_large",
            Self::Http2Preface => "http2_preface",
            Self::MalformedTransport => "malformed_transport",
            Self::HeaderReadTimedOut => "header_read_timed_out",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProductionProcessorError {
    Failed,
    Unavailable,
}

impl ProductionProcessorError {
    const fn response_status(self) -> StatusCode {
        match self {
            Self::Failed => StatusCode::INTERNAL_SERVER_ERROR,
            Self::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
        }
    }
}

impl fmt::Display for ProductionProcessorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Failed => "processor_failed",
            Self::Unavailable => "processor_unavailable",
        })
    }
}

impl Error for ProductionProcessorError {}

pub trait ProductionRequestProcessor: Send + Sync + 'static {
    fn process(
        &self,
        request: ProductionHttpRequest,
        context: ProductionRequestContext,
    ) -> Result<ProductionResponse, ProductionProcessorError>;

    fn reject(
        &self,
        rejection: ProductionRequestRejection,
        request: ProductionRejectedRequest,
        context: ProductionRequestContext,
    ) -> Result<ProductionResponse, ProductionProcessorError>;

    fn reject_pre_service(
        &self,
        rejection: ProductionPreServiceRejection,
        context: ProductionRequestContext,
    ) -> Result<(), ProductionProcessorError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProductionRuntimeError {
    InvalidConfiguration,
    CurrentThreadRuntimeUnsupported,
    AcceptFailed,
    DrainDeadlineExceeded,
}

impl fmt::Display for ProductionRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidConfiguration => "invalid_production_runtime_configuration",
            Self::CurrentThreadRuntimeUnsupported => {
                "production_runtime_requires_multi_thread_tokio"
            }
            Self::AcceptFailed => "production_listener_accept_failed",
            Self::DrainDeadlineExceeded => "drain_deadline_exceeded",
        })
    }
}

impl Error for ProductionRuntimeError {}
#[cfg(test)]
type BodyCollectionStarted = Arc<Mutex<Option<tokio::sync::oneshot::Sender<()>>>>;

/// Serve the Hyper HTTP/1.1 production ingress until `shutdown` resolves.
/// This API requires Tokio's multi-thread runtime because synchronous
/// processor calls use a non-detachable `block_in_place` boundary.
pub async fn serve_production_http1<F>(
    listener: TcpListener,
    config: ProductionRuntimeConfig,
    processor: Arc<dyn ProductionRequestProcessor>,
    shutdown: F,
) -> Result<(), ProductionRuntimeError>
where
    F: Future<Output = ()> + Send,
{
    serve_production_http1_inner(
        listener,
        config,
        processor,
        shutdown,
        #[cfg(test)]
        None,
        #[cfg(test)]
        None,
    )
    .await
}

#[cfg(test)]
async fn serve_production_http1_with_body_collection_signal<F>(
    listener: TcpListener,
    config: ProductionRuntimeConfig,
    processor: Arc<dyn ProductionRequestProcessor>,
    shutdown: F,
    body_collection_started: tokio::sync::oneshot::Sender<()>,
) -> Result<(), ProductionRuntimeError>
where
    F: Future<Output = ()> + Send,
{
    serve_production_http1_inner(
        listener,
        config,
        processor,
        shutdown,
        Some(Arc::new(Mutex::new(Some(body_collection_started)))),
        None,
    )
    .await
}

async fn serve_production_http1_inner<F>(
    listener: TcpListener,
    config: ProductionRuntimeConfig,
    processor: Arc<dyn ProductionRequestProcessor>,
    shutdown: F,
    #[cfg(test)] body_collection_started: Option<BodyCollectionStarted>,
    #[cfg(test)] connection_task_count: Option<watch::Sender<usize>>,
) -> Result<(), ProductionRuntimeError>
where
    F: Future<Output = ()> + Send,
{
    if !config.is_valid() {
        return Err(ProductionRuntimeError::InvalidConfiguration);
    }
    if matches!(
        tokio::runtime::Handle::try_current().map(|handle| handle.runtime_flavor()),
        Ok(tokio::runtime::RuntimeFlavor::CurrentThread)
    ) {
        return Err(ProductionRuntimeError::CurrentThreadRuntimeUnsupported);
    }

    let permits = Arc::new(Semaphore::new(config.max_concurrent_connections));
    let processor_permits = Arc::new(Semaphore::new(config.max_concurrent_connections));
    let admission_gate = Arc::new(AdmissionGate::default());
    let (drain_sender, _) = watch::channel(false);
    let mut connections = JoinSet::new();
    tokio::pin!(shutdown);
    loop {
        // Observe the actual set, including completed but unjoined tasks.
        #[cfg(test)]
        if let Some(count) = &connection_task_count {
            count.send_replace(connections.len());
        }
        tokio::select! {
            biased;
            _ = &mut shutdown => break,
            // Completed tasks retain allocations until joined. Reap before
            // accepting more; each reap shrinks the set, with shutdown first.
            // The guard prevents an empty set from spinning and blocking accepts.
            _ = connections.join_next(), if !connections.is_empty() => {}
            accepted = listener.accept() => {
                let (stream, peer_addr) = accepted.map_err(|_| ProductionRuntimeError::AcceptFailed)?;
                let Ok(permit) = permits.clone().try_acquire_owned() else {
                    drop(stream);
                    continue;
                };
                let processor = Arc::clone(&processor);
                let processor_permits = Arc::clone(&processor_permits);
                let admission_gate = Arc::clone(&admission_gate);
                let drain = ConnectionDrain {
                    receiver: drain_sender.subscribe(),
                    #[cfg(test)]
                    body_collection_started: body_collection_started.clone(),
                };
                connections.spawn(async move {
                    let _permit = permit;
                    serve_connection(
                        stream,
                        peer_addr,
                        config,
                        processor,
                        processor_permits,
                        admission_gate,
                        drain,
                    )
                    .await;
                });
            }
        }
    }

    admission_gate.close();
    let _ = drain_sender.send(true);
    drop(listener);
    let deadline = tokio::time::Instant::now() + config.shutdown_grace;
    while !connections.is_empty() {
        tokio::select! {
            _ = connections.join_next() => {}
            _ = tokio::time::sleep_until(deadline) => {
                connections.abort_all();
                // `block_in_place` work cannot be canceled. Report the missed
                // deadline only after every accepted connection has quiesced.
                while connections.join_next().await.is_some() {}
                return Err(ProductionRuntimeError::DrainDeadlineExceeded);
            }
        }
    }

    Ok(())
}

#[derive(Default)]
struct AdmissionGate {
    state: Mutex<AdmissionState>,
}

#[derive(Default)]
struct AdmissionState {
    closed: bool,
    in_flight: usize,
}

struct AdmissionGuard {
    gate: Arc<AdmissionGate>,
}

impl AdmissionGate {
    fn try_acquire(self: &Arc<Self>) -> Option<AdmissionGuard> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.closed {
            return None;
        }
        state.in_flight += 1;
        Some(AdmissionGuard {
            gate: Arc::clone(self),
        })
    }

    fn close(&self) {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .closed = true;
    }
}

impl Drop for AdmissionGuard {
    fn drop(&mut self) {
        let mut state = self
            .gate
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        debug_assert!(state.in_flight > 0, "admission guard underflow");
        state.in_flight = state.in_flight.saturating_sub(1);
    }
}
struct ConnectionDrain {
    receiver: watch::Receiver<bool>,
    #[cfg(test)]
    body_collection_started: Option<BodyCollectionStarted>,
}

async fn serve_connection(
    stream: TcpStream,
    peer_addr: SocketAddr,
    config: ProductionRuntimeConfig,
    processor: Arc<dyn ProductionRequestProcessor>,
    processor_permits: Arc<Semaphore>,
    admission_gate: Arc<AdmissionGate>,
    mut drain: ConnectionDrain,
) {
    let rejected_processor = Arc::clone(&processor);
    let rejected_processor_permits = Arc::clone(&processor_permits);
    let rejected_admission_gate = Arc::clone(&admission_gate);
    #[cfg(test)]
    let body_collection_started = drain.body_collection_started.clone();
    let service = service_fn(move |request| {
        let admission = admission_gate.try_acquire();
        let processor = Arc::clone(&processor);
        let processor_permits = Arc::clone(&processor_permits);
        #[cfg(test)]
        let body_collection_started = body_collection_started.clone();
        async move {
            let Some(_admission) = admission else {
                return Ok::<_, Infallible>(admission_closed_response());
            };
            Ok::<_, Infallible>(
                handle_request(
                    request,
                    peer_addr,
                    config,
                    processor,
                    processor_permits,
                    #[cfg(test)]
                    body_collection_started,
                )
                .await,
            )
        }
    });
    let mut builder = server_http1::Builder::new();
    builder.max_headers(MAX_PRODUCTION_HEADER_COUNT);
    // The pinned Hyper read-budget repair enforces this on raw head bytes,
    // including leading empty lines and OWS removed before policy validation.
    builder.max_buf_size(MAX_PRODUCTION_HEADER_BYTES);
    builder.timer(TokioTimer::new());
    builder.header_read_timeout(config.request_timeout);
    let connection = builder.serve_connection(TokioIo::new(stream), service);
    tokio::pin!(connection);
    let result = if *drain.receiver.borrow_and_update() {
        connection.as_mut().graceful_shutdown();
        connection.as_mut().await
    } else {
        tokio::select! {
            result = connection.as_mut() => result,
            _ = drain.receiver.changed() => {
                connection.as_mut().graceful_shutdown();
                connection.as_mut().await
            }
        }
    };
    if let Err(error) = result {
        if let Some(rejection) = pre_service_transport_rejection(&error) {
            reject_pre_service_transport(
                rejected_processor,
                rejected_processor_permits,
                rejected_admission_gate,
                rejection,
                peer_addr,
            )
            .await;
        }
    }
}

fn admission_closed_response() -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::new()));
    *response.status_mut() = StatusCode::SERVICE_UNAVAILABLE;
    response
        .headers_mut()
        .insert(CONNECTION, HeaderValue::from_static("close"));
    response
}

fn pre_service_transport_rejection(error: &hyper::Error) -> Option<ProductionPreServiceRejection> {
    if error.is_parse_too_large() {
        Some(ProductionPreServiceRejection::HeadersTooLarge)
    } else if error.is_parse_version_h2() {
        Some(ProductionPreServiceRejection::Http2Preface)
    } else if error.is_parse() {
        Some(ProductionPreServiceRejection::MalformedTransport)
    } else if error.is_timeout() {
        Some(ProductionPreServiceRejection::HeaderReadTimedOut)
    } else {
        None
    }
}

/// Acquire a processor permit without a panic path. The semaphores outlive
/// the listener and are never closed, so acquisition cannot fail; if that
/// invariant is ever broken the caller fails closed with a typed
/// `Unavailable` mapping instead of panicking.
async fn acquire_processor_permit(
    permits: &Arc<Semaphore>,
) -> Result<OwnedSemaphorePermit, ProductionProcessorError> {
    permits
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| ProductionProcessorError::Unavailable)
}

async fn reject_pre_service_transport(
    processor: Arc<dyn ProductionRequestProcessor>,
    processor_permits: Arc<Semaphore>,
    admission_gate: Arc<AdmissionGate>,
    rejection: ProductionPreServiceRejection,
    peer_addr: SocketAddr,
) {
    let Some(_admission) = admission_gate.try_acquire() else {
        return;
    };
    // A pre-service rejection has no response channel; if the permit
    // invariant is ever broken there is no response to fail closed with.
    let Ok(processor_permit) = acquire_processor_permit(&processor_permits).await else {
        return;
    };
    let _ = tokio::task::block_in_place(move || {
        let _processor_permit = processor_permit;
        processor.reject_pre_service(
            rejection,
            ProductionRequestContext {
                peer_addr: Some(peer_addr),
                request_deadline: Instant::now(),
            },
        )
    });
}

async fn handle_request(
    request: Request<Incoming>,
    peer_addr: SocketAddr,
    config: ProductionRuntimeConfig,
    processor: Arc<dyn ProductionRequestProcessor>,
    processor_permits: Arc<Semaphore>,
    #[cfg(test)] body_collection_started: Option<BodyCollectionStarted>,
) -> Response<Full<Bytes>> {
    let request_deadline = Instant::now()
        .checked_add(config.processor_timeout)
        .unwrap_or_else(Instant::now);
    let context = ProductionRequestContext {
        peer_addr: Some(peer_addr),
        request_deadline,
    };
    let (parts, body) = request.into_parts();
    let adapted = match timeout(
        config.request_timeout,
        collect_inbound_body(
            body,
            #[cfg(test)]
            body_collection_started,
        ),
    )
    .await
    {
        Ok(Ok(body)) => ProductionHttpPolicy.adapt(Request::from_parts(parts, body)),
        Ok(Err(InboundBodyCollectionError::ClientDisconnected)) => {
            return Response::new(Full::new(Bytes::new()));
        }
        Ok(Err(InboundBodyCollectionError::Rejected(rejection))) => Err(rejection),
        Err(_) => Err(ProductionRequestRejection::RequestTimedOut),
    };

    let response = match adapted {
        Ok(request) => {
            let processor_permit = match acquire_processor_permit(&processor_permits).await {
                Ok(permit) => permit,
                Err(error) => return response_to_hyper(finish_processor_result(Err(error))),
            };
            finish_processor_result(tokio::task::block_in_place(move || {
                let _processor_permit = processor_permit;
                processor.process(request, context)
            }))
        }
        Err(rejection) => {
            let processor_permit = match acquire_processor_permit(&processor_permits).await {
                Ok(permit) => permit,
                Err(error) => return response_to_hyper(finish_processor_result(Err(error))),
            };
            finish_processor_result(tokio::task::block_in_place(move || {
                let _processor_permit = processor_permit;
                processor.reject(rejection, ProductionRejectedRequest::sanitized(), context)
            }))
        }
    };
    response_to_hyper(response)
}

enum InboundBodyCollectionError {
    ClientDisconnected,
    Rejected(ProductionRequestRejection),
}

/// Only known peer-close forms are suppressed. Hyper's HTTP/1 decoder reports
/// EOF before an advertised body length as `UnexpectedEof`; malformed body data
/// retains a distinct error kind and remains a boundary rejection.
fn is_client_body_disconnect(error: &hyper::Error) -> bool {
    error.is_incomplete_message()
        || error.is_closed()
        || error
            .source()
            .and_then(|source| source.downcast_ref::<std::io::Error>())
            .is_some_and(|source| source.kind() == std::io::ErrorKind::UnexpectedEof)
}

async fn collect_inbound_body(
    mut body: Incoming,
    #[cfg(test)] body_collection_started: Option<BodyCollectionStarted>,
) -> Result<ProductionInboundBody, InboundBodyCollectionError> {
    #[cfg(test)]
    if let Some(body_collection_started) = body_collection_started {
        if let Some(sender) = body_collection_started
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
        {
            let _ = sender.send(());
        }
    }
    let mut collected = BytesMut::new();
    let mut trailers_observed = false;
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|error| {
            if is_client_body_disconnect(&error) {
                InboundBodyCollectionError::ClientDisconnected
            } else {
                InboundBodyCollectionError::Rejected(ProductionRequestRejection::BodyReadFailed)
            }
        })?;
        match frame.into_data() {
            Ok(data) => {
                let remaining = MAX_PRODUCTION_BODY_BYTES
                    .checked_sub(collected.len())
                    .ok_or(InboundBodyCollectionError::Rejected(
                        ProductionRequestRejection::BodyTooLarge,
                    ))?;
                if data.len() > remaining {
                    return Err(InboundBodyCollectionError::Rejected(
                        ProductionRequestRejection::BodyTooLarge,
                    ));
                }
                collected.extend_from_slice(&data);
            }
            Err(frame) => {
                if frame.into_trailers().is_ok() {
                    trailers_observed = true;
                }
            }
        }
    }

    if trailers_observed {
        Ok(ProductionInboundBody::with_observed_trailers(
            collected.freeze(),
        ))
    } else {
        Ok(ProductionInboundBody::new(collected.freeze()))
    }
}

fn finish_processor_result(
    result: Result<ProductionResponse, ProductionProcessorError>,
) -> ProductionResponse {
    match result {
        Ok(response) => response,
        Err(error) => ProductionResponse::new(error.response_status(), Bytes::new()),
    }
}

fn response_to_hyper(mut response: ProductionResponse) -> Response<Full<Bytes>> {
    sanitize_response_headers(&mut response.headers);
    response.headers.remove(CONTENT_LENGTH);
    let mut output = Response::new(Full::new(response.body));
    *output.status_mut() = response.status;
    *output.headers_mut() = response.headers;
    output
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionUpstreamTarget {
    pub authority: Authority,
    pub connect_addrs: Vec<SocketAddr>,
}

impl ProductionUpstreamTarget {
    pub fn new(
        authority: Authority,
        connect_addrs: Vec<SocketAddr>,
    ) -> Result<Self, ProductionUpstreamError> {
        if connect_addrs.is_empty() {
            return Err(ProductionUpstreamError::NoResolvedAddresses);
        }
        if connect_addrs.len() > MAX_PRODUCTION_UPSTREAM_ADDRESSES {
            return Err(ProductionUpstreamError::TooManyResolvedAddresses);
        }

        Ok(Self {
            authority,
            connect_addrs,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProductionUpstreamConfig {
    pub connect_timeout: Duration,
    pub response_timeout: Duration,
    /// Total budget for every address attempt and all typed HTTP work.
    pub dispatch_timeout: Duration,
    pub max_response_body_bytes: usize,
}

impl Default for ProductionUpstreamConfig {
    fn default() -> Self {
        Self {
            connect_timeout: DEFAULT_UPSTREAM_CONNECT_TIMEOUT,
            response_timeout: DEFAULT_UPSTREAM_RESPONSE_TIMEOUT,
            dispatch_timeout: DEFAULT_UPSTREAM_DISPATCH_TIMEOUT,
            max_response_body_bytes: DEFAULT_MAX_UPSTREAM_RESPONSE_BODY_BYTES,
        }
    }
}

impl ProductionUpstreamConfig {
    fn is_valid(self) -> bool {
        !self.connect_timeout.is_zero()
            && !self.response_timeout.is_zero()
            && !self.dispatch_timeout.is_zero()
            && self.max_response_body_bytes > 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProductionUpstreamError {
    InvalidConfiguration,
    InvalidRequest,
    NoResolvedAddresses,
    TooManyResolvedAddresses,
    DispatchTimedOut,
    ConnectTimedOut,
    ConnectFailed,
    HandshakeFailed,
    ResponseTimedOut,
    ResponseFailed,
    ResponseBodyTooLarge,
    ResponseBodyFailed,
}

impl fmt::Display for ProductionUpstreamError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidConfiguration => "invalid_production_upstream_configuration",
            Self::InvalidRequest => "invalid_production_upstream_request",
            Self::NoResolvedAddresses => "production_upstream_resolved_to_no_addresses",
            Self::TooManyResolvedAddresses => "production_upstream_resolved_to_too_many_addresses",
            Self::DispatchTimedOut => "production_upstream_dispatch_timed_out",
            Self::ConnectTimedOut => "production_upstream_connect_timed_out",
            Self::ConnectFailed => "production_upstream_connect_failed",
            Self::HandshakeFailed => "production_upstream_handshake_failed",
            Self::ResponseTimedOut => "production_upstream_response_timed_out",
            Self::ResponseFailed => "production_upstream_response_failed",
            Self::ResponseBodyTooLarge => "production_upstream_response_body_too_large",
            Self::ResponseBodyFailed => "production_upstream_response_body_failed",
        })
    }
}

impl Error for ProductionUpstreamError {}

/// Build the only HTTP/1.1 request shape that may be sent to a production
/// upstream. It replaces Host and Content-Length and removes hop-by-hop and
/// internal Eidolon headers.
pub fn prepare_upstream_request(
    request: &ProductionHttpRequest,
    target: &ProductionUpstreamTarget,
) -> Result<Request<Full<Bytes>>, ProductionUpstreamError> {
    let mut output = Request::builder()
        .method(request.method())
        .uri(request.target())
        .version(Version::HTTP_11)
        .body(Full::new(request.body_bytes()))
        .map_err(|_| ProductionUpstreamError::InvalidRequest)?;

    let headers = output.headers_mut();
    headers.insert(
        HOST,
        HeaderValue::from_str(target.authority.as_str())
            .map_err(|_| ProductionUpstreamError::InvalidRequest)?,
    );
    headers.insert(
        CONTENT_LENGTH,
        HeaderValue::from_str(&request.body().len().to_string())
            .map_err(|_| ProductionUpstreamError::InvalidRequest)?,
    );

    let connection_nominated_headers = connection_nominated_headers(request);
    for header in request.headers() {
        if should_skip_forwarded_header(header.name(), &connection_nominated_headers) {
            continue;
        }
        let name = HeaderName::from_bytes(header.name().as_bytes())
            .map_err(|_| ProductionUpstreamError::InvalidRequest)?;
        let value = HeaderValue::from_str(header.value())
            .map_err(|_| ProductionUpstreamError::InvalidRequest)?;
        headers.append(name, value);
    }

    Ok(output)
}

/// Dispatch one validated request through Hyper's typed HTTP/1.1 client. Each
/// resolved address is attempted in order within the remaining request budget,
/// preserving fallback without allowing retries to outlive the processor that
/// owns it.
pub async fn dispatch_production_upstream(
    request: &ProductionHttpRequest,
    target: &ProductionUpstreamTarget,
    config: ProductionUpstreamConfig,
    request_deadline: Instant,
) -> Result<ProductionResponse, ProductionUpstreamError> {
    if !config.is_valid() {
        return Err(ProductionUpstreamError::InvalidConfiguration);
    }
    if target.connect_addrs.is_empty() {
        return Err(ProductionUpstreamError::NoResolvedAddresses);
    }
    if target.connect_addrs.len() > MAX_PRODUCTION_UPSTREAM_ADDRESSES {
        return Err(ProductionUpstreamError::TooManyResolvedAddresses);
    }
    let remaining_budget = request_deadline
        .checked_duration_since(Instant::now())
        .ok_or(ProductionUpstreamError::DispatchTimedOut)?;
    let deadline = tokio::time::Instant::now() + remaining_budget.min(config.dispatch_timeout);

    timeout_at(
        deadline,
        dispatch_production_upstream_within_deadline(request, target, config),
    )
    .await
    .unwrap_or(Err(ProductionUpstreamError::DispatchTimedOut))
}

async fn dispatch_production_upstream_within_deadline(
    request: &ProductionHttpRequest,
    target: &ProductionUpstreamTarget,
    config: ProductionUpstreamConfig,
) -> Result<ProductionResponse, ProductionUpstreamError> {
    let mut last_pre_commit_error = None;
    for address in &target.connect_addrs {
        match dispatch_production_upstream_to_address(request, target, *address, config).await {
            Ok(response) => return Ok(response),
            Err(
                error @ (ProductionUpstreamError::ConnectTimedOut
                | ProductionUpstreamError::ConnectFailed
                | ProductionUpstreamError::HandshakeFailed),
            ) => last_pre_commit_error = Some(error),
            Err(error) => return Err(error),
        }
    }
    // The caller rejects empty address sets before dispatch, so the loop
    // always produces one result; fall back to a typed connect failure
    // rather than panicking if that invariant is ever broken.
    Err(last_pre_commit_error.unwrap_or(ProductionUpstreamError::ConnectFailed))
}

async fn dispatch_production_upstream_to_address(
    request: &ProductionHttpRequest,
    target: &ProductionUpstreamTarget,
    address: SocketAddr,
    config: ProductionUpstreamConfig,
) -> Result<ProductionResponse, ProductionUpstreamError> {
    let request = prepare_upstream_request(request, target)?;
    let stream = timeout(config.connect_timeout, TcpStream::connect(address))
        .await
        .map_err(|_| ProductionUpstreamError::ConnectTimedOut)?
        .map_err(|_| ProductionUpstreamError::ConnectFailed)?;
    let (mut sender, connection) = client_http1::handshake(TokioIo::new(stream))
        .await
        .map_err(|_| ProductionUpstreamError::HandshakeFailed)?;
    let response_future = async move {
        let response = match timeout(config.response_timeout, sender.send_request(request)).await {
            Ok(Ok(response)) => response,
            Ok(Err(_)) => return Err(ProductionUpstreamError::ResponseFailed),
            Err(_) => return Err(ProductionUpstreamError::ResponseTimedOut),
        };
        if response.status() == StatusCode::SWITCHING_PROTOCOLS {
            return Err(ProductionUpstreamError::ResponseFailed);
        }
        drop(sender);
        let (parts, body) = response.into_parts();
        let body = match timeout(
            config.response_timeout,
            collect_upstream_response_body(body, config.max_response_body_bytes),
        )
        .await
        {
            Ok(Ok(body)) => body,
            Ok(Err(error)) => return Err(error),
            Err(_) => return Err(ProductionUpstreamError::ResponseTimedOut),
        };

        let mut headers = parts.headers;
        sanitize_response_headers(&mut headers);
        headers.remove(CONTENT_LENGTH);
        Ok(ProductionResponse {
            status: parts.status,
            headers,
            body,
        })
    };
    tokio::pin!(response_future);
    tokio::pin!(connection);
    // Drive the Hyper connection in this dispatch task. Cancellation drops both
    // branches together instead of leaving a detached driver task behind.
    let mut connection_finished = false;
    loop {
        tokio::select! {
            biased;
            result = &mut response_future => break result,
            _ = &mut connection, if !connection_finished => {
                connection_finished = true;
            }
        }
    }
}

async fn collect_upstream_response_body(
    mut body: Incoming,
    max_response_body_bytes: usize,
) -> Result<Bytes, ProductionUpstreamError> {
    let mut collected = BytesMut::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| ProductionUpstreamError::ResponseBodyFailed)?;
        if let Ok(data) = frame.into_data() {
            let remaining = max_response_body_bytes
                .checked_sub(collected.len())
                .ok_or(ProductionUpstreamError::ResponseBodyTooLarge)?;
            if data.len() > remaining {
                return Err(ProductionUpstreamError::ResponseBodyTooLarge);
            }
            collected.extend_from_slice(&data);
        }
    }
    Ok(collected.freeze())
}

fn connection_nominated_headers(request: &ProductionHttpRequest) -> Vec<String> {
    request
        .headers()
        .iter()
        .filter(|header| header.name().eq_ignore_ascii_case(CONNECTION.as_str()))
        .flat_map(|header| header.value().split(','))
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_string)
        .collect()
}

fn should_skip_forwarded_header(name: &str, connection_nominated_headers: &[String]) -> bool {
    name.eq_ignore_ascii_case(HOST.as_str())
        || name.eq_ignore_ascii_case(CONTENT_LENGTH.as_str())
        || name.eq_ignore_ascii_case(CONNECTION.as_str())
        || name.eq_ignore_ascii_case("proxy-connection")
        || name.eq_ignore_ascii_case("keep-alive")
        || name.eq_ignore_ascii_case(PROXY_AUTHENTICATE.as_str())
        || name.eq_ignore_ascii_case(PROXY_AUTHORIZATION.as_str())
        || name.eq_ignore_ascii_case(TE.as_str())
        || name.eq_ignore_ascii_case(TRAILER.as_str())
        || name.eq_ignore_ascii_case(TRANSFER_ENCODING.as_str())
        || name.eq_ignore_ascii_case(UPGRADE.as_str())
        || name
            .as_bytes()
            .get(.."x-eidolon-".len())
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"x-eidolon-"))
        || connection_nominated_headers
            .iter()
            .any(|header| name.eq_ignore_ascii_case(header))
}

fn sanitize_response_headers(headers: &mut HeaderMap) {
    let connection_nominated_headers = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .filter_map(|name| HeaderName::from_bytes(name.as_bytes()).ok())
        .collect::<Vec<_>>();
    for name in connection_nominated_headers {
        headers.remove(name);
    }
    for name in [
        CONNECTION,
        PROXY_AUTHENTICATE,
        PROXY_AUTHORIZATION,
        TE,
        TRAILER,
        TRANSFER_ENCODING,
        UPGRADE,
    ] {
        headers.remove(name);
    }
    headers.remove("keep-alive");
    headers.remove("proxy-connection");
}

#[cfg(test)]
#[path = "production_runtime_boundary_tests.rs"]
mod boundary_tests;

#[cfg(test)]
#[path = "production_runtime_ingress_tests.rs"]
mod ingress_tests;

#[cfg(test)]
#[path = "production_runtime_upstream_tests.rs"]
mod upstream_tests;

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc, Mutex,
        },
        time::Duration,
    };

    use bytes::Bytes;
    use hyper::{
        header::{CONTENT_LENGTH, HOST},
        http::uri::Authority,
        Request, StatusCode, Version,
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        sync::{oneshot, watch, Semaphore},
        time::{timeout, Instant},
    };

    use super::{
        acquire_processor_permit, dispatch_production_upstream,
        dispatch_production_upstream_within_deadline, reject_pre_service_transport,
        serve_connection, serve_production_http1, serve_production_http1_inner,
        serve_production_http1_with_body_collection_signal, AdmissionGate, ConnectionDrain,
        ProductionPreServiceRejection, ProductionProcessorError, ProductionRejectedRequest,
        ProductionRequestContext, ProductionRequestProcessor, ProductionResponse,
        ProductionRuntimeConfig, ProductionRuntimeError, ProductionUpstreamConfig,
        ProductionUpstreamError, ProductionUpstreamTarget,
    };
    use crate::production_http::{
        ProductionHttpPolicy, ProductionHttpRequest, ProductionInboundBody,
        ProductionRequestRejection,
    };

    #[tokio::test(flavor = "current_thread")]
    async fn serve_production_http1_rejects_current_thread_runtime() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("production listener should bind");
        let (_release_tx, release_rx) = std::sync::mpsc::channel();
        let error = serve_production_http1(
            listener,
            ProductionRuntimeConfig::default(),
            Arc::new(DelayedProcessor {
                started: Mutex::new(None),
                release: Mutex::new(release_rx),
                invocations: AtomicUsize::new(0),
                completed: AtomicUsize::new(0),
            }),
            std::future::pending(),
        )
        .await
        .expect_err("current-thread runtime must fail before serving");

        assert_eq!(
            error,
            ProductionRuntimeError::CurrentThreadRuntimeUnsupported
        );
    }

    #[tokio::test]
    async fn committed_post_response_drop_never_retries_next_address() {
        let first_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("first upstream should bind");
        let first_address = first_listener
            .local_addr()
            .expect("first upstream should have an address");
        let second_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("second upstream should bind");
        let second_address = second_listener
            .local_addr()
            .expect("second upstream should have an address");

        let (first_request_sent, first_request_received) = oneshot::channel();
        let first = tokio::spawn(async move {
            let (mut stream, _) = first_listener
                .accept()
                .await
                .expect("first upstream should accept");
            let mut received = Vec::new();
            let mut chunk = [0_u8; 1024];
            loop {
                let count = stream
                    .read(&mut chunk)
                    .await
                    .expect("first upstream should read");
                if count == 0 {
                    break;
                }
                received.extend_from_slice(&chunk[..count]);
                if received
                    .windows(b"\r\n\r\n".len())
                    .position(|window| window == b"\r\n\r\n")
                    .is_some_and(|header_end| received.len() >= header_end + b"\r\n\r\n".len() + 7)
                {
                    break;
                }
            }
            first_request_sent
                .send(received)
                .expect("test should await first request");
        });
        let second = tokio::spawn(async move {
            timeout(Duration::from_millis(250), second_listener.accept())
                .await
                .is_ok()
        });

        let request = ProductionHttpPolicy
            .adapt(
                Request::builder()
                    .method("POST")
                    .uri("/non-idempotent")
                    .version(Version::HTTP_11)
                    .header(HOST, "proxy.local")
                    .header(CONTENT_LENGTH, "7")
                    .body(ProductionInboundBody::new(Bytes::from_static(b"commit!")))
                    .expect("test request should build"),
            )
            .expect("test request should adapt");
        let target = ProductionUpstreamTarget::new(
            "upstream.test"
                .parse::<Authority>()
                .expect("test authority should parse"),
            vec![first_address, second_address],
        )
        .expect("test target should accept the two-address fallback");

        let result = dispatch_production_upstream(
            &request,
            &target,
            ProductionUpstreamConfig {
                connect_timeout: Duration::from_secs(1),
                response_timeout: Duration::from_secs(1),
                dispatch_timeout: Duration::from_secs(1),
                max_response_body_bytes: 1024,
            },
            std::time::Instant::now() + Duration::from_secs(1),
        )
        .await;

        assert_eq!(result, Err(ProductionUpstreamError::ResponseFailed));
        let first_request = first_request_received
            .await
            .expect("first upstream should record the request");
        assert!(first_request.windows(4).any(|window| window == b"POST"));
        assert!(first_request
            .windows(b"commit!".len())
            .any(|window| window == b"commit!"));
        first.await.expect("first upstream task should finish");
        assert!(!second.await.expect("second upstream task should finish"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn total_dispatch_deadline_stops_fallback_and_releases_processor_permit() {
        let stalled_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("stalled upstream should bind");
        let stalled_address = stalled_listener
            .local_addr()
            .expect("stalled upstream should have an address");
        let fallback_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("fallback upstream should bind");
        let fallback_address = fallback_listener
            .local_addr()
            .expect("fallback upstream should have an address");
        let (first_request_sent, first_request_received) = oneshot::channel();
        let stalled = tokio::spawn(async move {
            let (mut stream, _) = stalled_listener
                .accept()
                .await
                .expect("stalled upstream should accept");
            let mut buffer = [0_u8; 1024];
            let received = stream
                .read(&mut buffer)
                .await
                .expect("stalled upstream should receive the request");
            assert!(
                received > 0,
                "stalled upstream should receive request bytes"
            );
            first_request_sent
                .send(())
                .expect("test should await stalled request");
            let mut trailing = [0_u8; 1];
            timeout(Duration::from_secs(1), stream.read(&mut trailing))
                .await
                .expect("dispatch cancellation should close the upstream connection")
                .expect("stalled upstream should observe the connection close")
                == 0
        });
        let fallback = tokio::spawn(async move {
            timeout(Duration::from_millis(300), fallback_listener.accept())
                .await
                .is_ok()
        });

        let request = ProductionHttpPolicy
            .adapt(
                Request::builder()
                    .method("GET")
                    .uri("/normal")
                    .version(Version::HTTP_11)
                    .header(HOST, "proxy.local")
                    .body(ProductionInboundBody::new(Bytes::new()))
                    .expect("test request should build"),
            )
            .expect("test request should adapt");
        let target = ProductionUpstreamTarget::new(
            "upstream.test"
                .parse::<Authority>()
                .expect("test authority should parse"),
            vec![stalled_address, fallback_address],
        )
        .expect("test target should accept bounded fallback");
        let processor_permits = Arc::new(Semaphore::new(1));
        let processor_permit = processor_permits
            .clone()
            .acquire_owned()
            .await
            .expect("processor permit should be available");
        let runtime_handle = tokio::runtime::Handle::current();
        let started = Instant::now();
        let result = tokio::task::block_in_place(move || {
            let _processor_permit = processor_permit;
            runtime_handle.block_on(dispatch_production_upstream(
                &request,
                &target,
                ProductionUpstreamConfig {
                    connect_timeout: Duration::from_secs(1),
                    response_timeout: Duration::from_secs(1),
                    dispatch_timeout: Duration::from_millis(100),
                    max_response_body_bytes: 1024,
                },
                std::time::Instant::now() + Duration::from_secs(1),
            ))
        });

        first_request_received
            .await
            .expect("first address should receive the request before stalling");
        assert_eq!(result, Err(ProductionUpstreamError::DispatchTimedOut));
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "total dispatch deadline must bound all typed upstream work"
        );
        assert!(
            !fallback.await.expect("fallback listener should finish"),
            "a total dispatch timeout must not continue to later addresses"
        );
        let _released_permit = timeout(Duration::from_millis(50), processor_permits.acquire())
            .await
            .expect("completed blocking dispatch should release its processor permit")
            .expect("processor permit owner should outlive the test");
        assert!(
            timeout(Duration::from_millis(250), stalled)
                .await
                .expect("structured upstream driver should quiesce")
                .expect("stalled upstream task should join"),
            "dispatch deadline must stop the upstream connection driver before returning"
        );
    }
    struct DelayedProcessor {
        started: Mutex<Option<oneshot::Sender<()>>>,
        release: Mutex<std::sync::mpsc::Receiver<()>>,
        invocations: AtomicUsize,
        completed: AtomicUsize,
    }

    impl ProductionRequestProcessor for DelayedProcessor {
        fn process(
            &self,
            _request: ProductionHttpRequest,
            _context: ProductionRequestContext,
        ) -> Result<ProductionResponse, ProductionProcessorError> {
            self.invocations.fetch_add(1, Ordering::SeqCst);
            if let Some(started) = self
                .started
                .lock()
                .expect("delayed processor start signal should lock")
                .take()
            {
                let _ = started.send(());
            }
            self.release
                .lock()
                .expect("delayed processor release signal should lock")
                .recv()
                .expect("test should release delayed processor");
            self.completed.fetch_add(1, Ordering::SeqCst);
            Ok(ProductionResponse::new(StatusCode::OK, Bytes::new()))
        }

        fn reject(
            &self,
            _rejection: ProductionRequestRejection,
            _request: ProductionRejectedRequest,
            _context: ProductionRequestContext,
        ) -> Result<ProductionResponse, ProductionProcessorError> {
            Ok(ProductionResponse::new(
                StatusCode::BAD_REQUEST,
                Bytes::new(),
            ))
        }

        fn reject_pre_service(
            &self,
            _rejection: ProductionPreServiceRejection,
            _context: ProductionRequestContext,
        ) -> Result<(), ProductionProcessorError> {
            Ok(())
        }
    }

    #[derive(Default)]
    struct CountingProcessor {
        invocations: AtomicUsize,
        pre_service_invocations: AtomicUsize,
    }

    impl ProductionRequestProcessor for CountingProcessor {
        fn process(
            &self,
            _request: ProductionHttpRequest,
            _context: ProductionRequestContext,
        ) -> Result<ProductionResponse, ProductionProcessorError> {
            self.invocations.fetch_add(1, Ordering::SeqCst);
            Ok(ProductionResponse::new(StatusCode::OK, Bytes::new()))
        }

        fn reject(
            &self,
            _rejection: ProductionRequestRejection,
            _request: ProductionRejectedRequest,
            _context: ProductionRequestContext,
        ) -> Result<ProductionResponse, ProductionProcessorError> {
            Ok(ProductionResponse::new(
                StatusCode::BAD_REQUEST,
                Bytes::new(),
            ))
        }

        fn reject_pre_service(
            &self,
            _rejection: ProductionPreServiceRejection,
            _context: ProductionRequestContext,
        ) -> Result<(), ProductionProcessorError> {
            self.pre_service_invocations.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn completed_connection_tasks_are_reaped_while_listener_is_running() {
        const CONNECTIONS: usize = 128;
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("production listener should bind");
        let address = listener
            .local_addr()
            .expect("production listener should have an address");
        let processor = Arc::new(CountingProcessor::default());
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let (task_count_tx, mut task_count_rx) = watch::channel(0);
        let server = tokio::spawn(serve_production_http1_inner(
            listener,
            ProductionRuntimeConfig {
                max_concurrent_connections: 1,
                shutdown_grace: Duration::from_secs(1),
                ..ProductionRuntimeConfig::default()
            },
            processor.clone(),
            async move {
                let _ = shutdown_rx.await;
            },
            None,
            Some(task_count_tx),
        ));

        // Use real loopback connections and observe JoinSet retention directly,
        // without allocator/RSS thresholds or sleeps that depend on the platform.
        timeout(Duration::from_secs(15), async {
            for completed in 1..=CONNECTIONS {
                let mut client = TcpStream::connect(address)
                    .await
                    .expect("client should connect after the previous task was reaped");
                task_count_rx
                    .wait_for(|count| *count == 1)
                    .await
                    .expect("listener should track the admitted connection");
                client
                    .write_all(
                        b"GET /normal HTTP/1.1\r\nHost: proxy.local\r\nConnection: close\r\n\r\n",
                    )
                    .await
                    .expect("client should write");
                let mut response = Vec::new();
                client
                    .read_to_end(&mut response)
                    .await
                    .expect("completed connection should close cleanly");
                assert!(response.starts_with(b"HTTP/1.1 200"));

                // EOF alone does not prove the task allocation was reclaimed.
                // Require the set to empty before any new accept or shutdown.
                let reaped = timeout(
                    Duration::from_secs(2),
                    task_count_rx.wait_for(|count| *count == 0),
                )
                .await
                .is_ok_and(|result| result.is_ok());
                assert!(
                    reaped,
                    "after {completed} closed connections, listener still retains {} task(s) before shutdown",
                    *task_count_rx.borrow()
                );
            }
        })
        .await
        .expect("sequential connection churn must make bounded progress");

        assert!(!server.is_finished(), "listener must still be serving");
        assert_eq!(processor.invocations.load(Ordering::SeqCst), CONNECTIONS);
        shutdown_tx
            .send(())
            .expect("test should stop the production listener");
        timeout(Duration::from_secs(2), server)
            .await
            .expect("shutdown should finish with an empty connection set")
            .expect("production server should join")
            .expect("production server should stop cleanly");
    }

    struct DeadlineExpiredBeforeDispatchProcessor {
        upstream: ProductionUpstreamTarget,
        config: ProductionUpstreamConfig,
        runtime_handle: tokio::runtime::Handle,
    }

    impl ProductionRequestProcessor for DeadlineExpiredBeforeDispatchProcessor {
        fn process(
            &self,
            request: ProductionHttpRequest,
            context: ProductionRequestContext,
        ) -> Result<ProductionResponse, ProductionProcessorError> {
            std::thread::sleep(Duration::from_millis(50));
            match self.runtime_handle.block_on(dispatch_production_upstream(
                &request,
                &self.upstream,
                self.config,
                context.request_deadline,
            )) {
                Err(ProductionUpstreamError::DispatchTimedOut) => Ok(ProductionResponse::new(
                    StatusCode::GATEWAY_TIMEOUT,
                    Bytes::new(),
                )),
                _ => Err(ProductionProcessorError::Failed),
            }
        }

        fn reject(
            &self,
            _rejection: ProductionRequestRejection,
            _request: ProductionRejectedRequest,
            _context: ProductionRequestContext,
        ) -> Result<ProductionResponse, ProductionProcessorError> {
            Ok(ProductionResponse::new(
                StatusCode::BAD_REQUEST,
                Bytes::new(),
            ))
        }

        fn reject_pre_service(
            &self,
            _rejection: ProductionPreServiceRejection,
            _context: ProductionRequestContext,
        ) -> Result<(), ProductionProcessorError> {
            Ok(())
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn handler_waits_for_delayed_processor_before_responding_and_releasing_permit() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("production listener should bind");
        let address = listener
            .local_addr()
            .expect("production listener should have an address");
        let (started_tx, started_rx) = oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let processor = Arc::new(DelayedProcessor {
            started: Mutex::new(Some(started_tx)),
            release: Mutex::new(release_rx),
            invocations: AtomicUsize::new(0),
            completed: AtomicUsize::new(0),
        });
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let server = tokio::spawn(serve_production_http1(
            listener,
            ProductionRuntimeConfig {
                max_concurrent_connections: 1,
                request_timeout: Duration::from_secs(1),
                processor_timeout: Duration::from_millis(10),
                shutdown_grace: Duration::from_secs(1),
            },
            processor,
            async move {
                let _ = shutdown_rx.await;
            },
        ));

        let mut first = TcpStream::connect(address)
            .await
            .expect("first client should connect");
        first
            .write_all(b"GET /normal HTTP/1.1\r\nHost: proxy.local\r\nConnection: close\r\n\r\n")
            .await
            .expect("first client should write");
        started_rx
            .await
            .expect("delayed processor should start before assertions");

        let mut first_buffer = [0_u8; 128];
        assert!(
            timeout(Duration::from_millis(100), first.read(&mut first_buffer))
                .await
                .is_err(),
            "the handler must not emit a response while its processor closure runs"
        );

        let mut second = TcpStream::connect(address)
            .await
            .expect("second client should connect");
        second
            .write_all(b"GET /normal HTTP/1.1\r\nHost: proxy.local\r\nConnection: close\r\n\r\n")
            .await
            .expect("second client should write");
        let mut second_buffer = [0_u8; 128];
        match timeout(Duration::from_millis(100), second.read(&mut second_buffer)).await {
            Ok(Ok(0)) | Ok(Err(_)) => {}
            Ok(Ok(_)) => panic!("connection permit must reject a request while processor runs"),
            Err(_) => panic!("connection permit must not queue a request while processor runs"),
        }

        release_tx
            .send(())
            .expect("test should release delayed processor");
        let mut response = Vec::new();
        timeout(Duration::from_secs(1), first.read_to_end(&mut response))
            .await
            .expect("processor completion should release the first response")
            .expect("first response should read");
        assert!(
            response.starts_with(b"HTTP/1.1 200"),
            "first response should arrive only after processor completion"
        );

        shutdown_tx
            .send(())
            .expect("test should stop the production listener");
        server
            .await
            .expect("production server should join")
            .expect("production server should stop cleanly");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn graceful_shutdown_drains_accepted_response_before_returning() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("production listener should bind");
        let address = listener
            .local_addr()
            .expect("production listener should have an address");
        let (started_tx, started_rx) = oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let processor = Arc::new(DelayedProcessor {
            started: Mutex::new(Some(started_tx)),
            release: Mutex::new(release_rx),
            invocations: AtomicUsize::new(0),
            completed: AtomicUsize::new(0),
        });
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let mut server = tokio::spawn(serve_production_http1(
            listener,
            ProductionRuntimeConfig {
                max_concurrent_connections: 1,
                request_timeout: Duration::from_secs(1),
                processor_timeout: Duration::from_secs(1),
                shutdown_grace: Duration::from_secs(1),
            },
            processor.clone(),
            async move {
                let _ = shutdown_rx.await;
            },
        ));

        let mut client = TcpStream::connect(address)
            .await
            .expect("client should connect");
        client
            .write_all(b"GET /normal HTTP/1.1\r\nHost: proxy.local\r\nConnection: close\r\n\r\n")
            .await
            .expect("client should write");
        started_rx
            .await
            .expect("processor should start before shutdown");
        shutdown_tx
            .send(())
            .expect("test should start graceful shutdown");
        assert!(
            timeout(Duration::from_millis(100), &mut server)
                .await
                .is_err(),
            "shutdown must wait for an accepted request to complete"
        );

        release_tx
            .send(())
            .expect("test should release the accepted request");
        let mut response = Vec::new();
        timeout(Duration::from_secs(1), client.read_to_end(&mut response))
            .await
            .expect("accepted response should complete during drain")
            .expect("accepted response should read");
        assert!(
            response.starts_with(b"HTTP/1.1 200"),
            "graceful drain must preserve the accepted response"
        );
        server
            .await
            .expect("production server should join")
            .expect("production server should drain cleanly");
        assert_eq!(
            processor.invocations.load(Ordering::SeqCst),
            1,
            "graceful shutdown must not re-run accepted work"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn graceful_shutdown_closes_idle_keep_alive_connection() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("production listener should bind");
        let address = listener
            .local_addr()
            .expect("production listener should have an address");
        let processor = Arc::new(CountingProcessor::default());
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let server = tokio::spawn(serve_production_http1(
            listener,
            ProductionRuntimeConfig {
                max_concurrent_connections: 1,
                request_timeout: Duration::from_secs(1),
                processor_timeout: Duration::from_secs(1),
                shutdown_grace: Duration::from_secs(1),
            },
            processor.clone(),
            async move {
                let _ = shutdown_rx.await;
            },
        ));

        let mut client = TcpStream::connect(address)
            .await
            .expect("client should connect");
        client
            .write_all(
                b"GET /normal HTTP/1.1\r\nHost: proxy.local\r\nConnection: keep-alive\r\n\r\n",
            )
            .await
            .expect("client should write");
        let mut first_response = [0_u8; 256];
        let received = timeout(Duration::from_secs(1), client.read(&mut first_response))
            .await
            .expect("keep-alive response should arrive")
            .expect("keep-alive response should read");
        assert!(
            first_response[..received].starts_with(b"HTTP/1.1 200"),
            "first keep-alive response should succeed"
        );

        shutdown_tx
            .send(())
            .expect("test should start graceful shutdown");
        let mut remaining = Vec::new();
        timeout(Duration::from_secs(1), client.read_to_end(&mut remaining))
            .await
            .expect("graceful shutdown should close idle keep-alive")
            .expect("idle keep-alive should close cleanly");
        server
            .await
            .expect("production server should join")
            .expect("production server should drain idle connection");
        assert_eq!(processor.invocations.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn closed_admission_denies_pipelined_service_without_processor_work() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("production listener should bind");
        let address = listener
            .local_addr()
            .expect("production listener should have an address");
        let admission_gate = Arc::new(AdmissionGate::default());
        let (started_tx, started_rx) = oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let processor = Arc::new(DelayedProcessor {
            started: Mutex::new(Some(started_tx)),
            release: Mutex::new(release_rx),
            invocations: AtomicUsize::new(0),
            completed: AtomicUsize::new(0),
        });
        let (_drain_sender, drain) = watch::channel(false);
        let server = tokio::spawn({
            let admission_gate = Arc::clone(&admission_gate);
            let processor = Arc::clone(&processor);
            async move {
                let (stream, peer_addr) = listener
                    .accept()
                    .await
                    .expect("production listener should accept");
                serve_connection(
                    stream,
                    peer_addr,
                    ProductionRuntimeConfig::default(),
                    processor,
                    Arc::new(Semaphore::new(1)),
                    admission_gate,
                    ConnectionDrain {
                        receiver: drain,
                        body_collection_started: None,
                    },
                )
                .await;
            }
        });

        let mut client = TcpStream::connect(address)
            .await
            .expect("client should connect");
        client
            .write_all(
                b"GET /accepted-before-close HTTP/1.1\r\nHost: proxy.local\r\nConnection: keep-alive\r\n\r\n",
            )
            .await
            .expect("client should write accepted request");
        started_rx
            .await
            .expect("first request should enter the processor");
        admission_gate.close();
        client
            .write_all(
                b"GET /pipelined-after-close HTTP/1.1\r\nHost: proxy.local\r\nConnection: close\r\n\r\n",
            )
            .await
            .expect("client should write pipelined request after admission closes");
        release_tx
            .send(())
            .expect("test should release the accepted request");

        let mut response = Vec::new();
        timeout(Duration::from_secs(1), client.read_to_end(&mut response))
            .await
            .expect("closed admission should finish the connection")
            .expect("closed admission response should read");
        assert!(
            response.starts_with(b"HTTP/1.1 200"),
            "the admitted request must complete first"
        );
        assert!(
            response
                .windows(b"HTTP/1.1 503".len())
                .any(|status| status == b"HTTP/1.1 503"),
            "the pipelined request after admission closes must receive the fixed rejection"
        );
        server.await.expect("connection task should join");
        assert_eq!(
            processor.invocations.load(Ordering::SeqCst),
            1,
            "only the request admitted before closure may reach the processor"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pre_service_rejection_skips_processor_after_admission_closes() {
        let processor = Arc::new(CountingProcessor::default());
        let processor_permits = Arc::new(Semaphore::new(1));
        let admission_gate = Arc::new(AdmissionGate::default());
        let peer_addr = "127.0.0.1:8080".parse().expect("peer address should parse");

        reject_pre_service_transport(
            processor.clone(),
            Arc::clone(&processor_permits),
            Arc::clone(&admission_gate),
            ProductionPreServiceRejection::MalformedTransport,
            peer_addr,
        )
        .await;
        assert_eq!(
            processor.pre_service_invocations.load(Ordering::SeqCst),
            1,
            "the open admission control path must invoke the pre-service hook"
        );

        admission_gate.close();
        reject_pre_service_transport(
            processor.clone(),
            processor_permits,
            admission_gate,
            ProductionPreServiceRejection::HeadersTooLarge,
            peer_addr,
        )
        .await;
        assert_eq!(
            processor.pre_service_invocations.load(Ordering::SeqCst),
            1,
            "a post-close transport rejection must not invoke the processor hook"
        );
        assert_eq!(processor.invocations.load(Ordering::SeqCst), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shutdown_deadline_aborts_observed_cancellable_body_collection_then_waits_for_side_effect_quiescence(
    ) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("production listener should bind");
        let address = listener
            .local_addr()
            .expect("production listener should have an address");
        let (started_tx, started_rx) = oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let processor = Arc::new(DelayedProcessor {
            started: Mutex::new(Some(started_tx)),
            release: Mutex::new(release_rx),
            invocations: AtomicUsize::new(0),
            completed: AtomicUsize::new(0),
        });
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let (body_collection_started_tx, body_collection_started_rx) = oneshot::channel();
        let server = tokio::spawn(serve_production_http1_with_body_collection_signal(
            listener,
            ProductionRuntimeConfig {
                max_concurrent_connections: 2,
                request_timeout: Duration::from_secs(5),
                processor_timeout: Duration::from_secs(1),
                shutdown_grace: Duration::from_millis(100),
            },
            processor.clone(),
            async move {
                let _ = shutdown_rx.await;
            },
            body_collection_started_tx,
        ));

        let mut pending_client = TcpStream::connect(address)
            .await
            .expect("pending client should connect");
        pending_client
            .write_all(
                b"POST /pending HTTP/1.1\r\nHost: proxy.local\r\nContent-Length: 1\r\nConnection: close\r\n\r\n",
            )
            .await
            .expect("pending client should start an incomplete accepted request");
        timeout(Duration::from_secs(1), body_collection_started_rx)
            .await
            .expect("server should enter the incomplete request body collection before shutdown")
            .expect("body collection signal should be delivered");

        let mut client = TcpStream::connect(address)
            .await
            .expect("client should connect");
        client
            .write_all(b"GET /normal HTTP/1.1\r\nHost: proxy.local\r\nConnection: close\r\n\r\n")
            .await
            .expect("client should write");
        started_rx
            .await
            .expect("processor should start before shutdown");
        shutdown_tx
            .send(())
            .expect("test should start graceful shutdown");

        let mut pending_buffer = [0_u8; 1];
        let pending_connection_terminated = matches!(
            timeout(
                Duration::from_millis(500),
                pending_client.read(&mut pending_buffer),
            )
            .await,
            Ok(Ok(0)) | Ok(Err(_))
        );
        let server_still_draining = !server.is_finished();
        let completed_before_release = processor.completed.load(Ordering::SeqCst);
        release_tx
            .send(())
            .expect("test should release the delayed side effect");
        assert!(
            pending_connection_terminated,
            "deadline abort must terminate the observed accepted connection"
        );
        assert!(
            server_still_draining,
            "deadline failure must wait for non-cancellable accepted work to quiesce"
        );
        assert_eq!(
            completed_before_release, 0,
            "the accepted synchronous side effect must still be active before release"
        );
        assert_eq!(
            timeout(Duration::from_secs(1), server)
                .await
                .expect("quiesced deadline failure should resolve")
                .expect("production server should join"),
            Err(ProductionRuntimeError::DrainDeadlineExceeded)
        );
        assert_eq!(
            processor.completed.load(Ordering::SeqCst),
            1,
            "deadline failure must not return before accepted side effects complete"
        );
        assert_eq!(processor.invocations.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn handler_does_not_connect_upstream_after_pre_dispatch_budget_expires() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("upstream listener should bind");
        let upstream_address = upstream_listener
            .local_addr()
            .expect("upstream listener should have an address");
        let upstream_attempted = tokio::spawn(async move {
            timeout(Duration::from_millis(250), upstream_listener.accept())
                .await
                .is_ok()
        });
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("production listener should bind");
        let address = listener
            .local_addr()
            .expect("production listener should have an address");
        let processor = Arc::new(DeadlineExpiredBeforeDispatchProcessor {
            upstream: ProductionUpstreamTarget::new(
                "upstream.test"
                    .parse::<Authority>()
                    .expect("upstream authority should parse"),
                vec![upstream_address],
            )
            .expect("upstream target should configure"),
            config: ProductionUpstreamConfig {
                connect_timeout: Duration::from_secs(1),
                response_timeout: Duration::from_secs(1),
                dispatch_timeout: Duration::from_secs(1),
                max_response_body_bytes: 1024,
            },
            runtime_handle: tokio::runtime::Handle::current(),
        });
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let server = tokio::spawn(serve_production_http1(
            listener,
            ProductionRuntimeConfig {
                max_concurrent_connections: 1,
                request_timeout: Duration::from_secs(1),
                processor_timeout: Duration::from_millis(20),
                shutdown_grace: Duration::from_secs(1),
            },
            processor,
            async move {
                let _ = shutdown_rx.await;
            },
        ));

        let mut client = TcpStream::connect(address)
            .await
            .expect("client should connect");
        client
            .write_all(b"GET /normal HTTP/1.1\r\nHost: proxy.local\r\nConnection: close\r\n\r\n")
            .await
            .expect("client should write");
        let mut response = Vec::new();
        timeout(Duration::from_secs(1), client.read_to_end(&mut response))
            .await
            .expect("handler should return after lifecycle completion")
            .expect("response should read");

        assert!(
            response.starts_with(b"HTTP/1.1 504"),
            "expired typed outbound budget should fail closed"
        );
        assert!(
            !upstream_attempted
                .await
                .expect("upstream recorder should finish"),
            "expired pre-dispatch budget must prevent any upstream connection"
        );

        shutdown_tx
            .send(())
            .expect("test should stop the production listener");
        server
            .await
            .expect("production server should join")
            .expect("production server should stop cleanly");
    }

    struct AlwaysFailProcessor {
        invocations: Mutex<usize>,
    }

    impl ProductionRequestProcessor for AlwaysFailProcessor {
        fn process(
            &self,
            _request: ProductionHttpRequest,
            _context: ProductionRequestContext,
        ) -> Result<ProductionResponse, ProductionProcessorError> {
            *self
                .invocations
                .lock()
                .expect("invocation count should lock") += 1;
            Err(ProductionProcessorError::Failed)
        }

        fn reject(
            &self,
            _rejection: ProductionRequestRejection,
            _request: ProductionRejectedRequest,
            _context: ProductionRequestContext,
        ) -> Result<ProductionResponse, ProductionProcessorError> {
            Ok(ProductionResponse::new(
                StatusCode::BAD_REQUEST,
                Bytes::new(),
            ))
        }

        fn reject_pre_service(
            &self,
            _rejection: ProductionPreServiceRejection,
            _context: ProductionRequestContext,
        ) -> Result<(), ProductionProcessorError> {
            Ok(())
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn failed_processor_returns_empty_500_once_without_retry() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("production listener should bind");
        let address = listener
            .local_addr()
            .expect("production listener should have an address");
        let processor = Arc::new(AlwaysFailProcessor {
            invocations: Mutex::new(0),
        });
        let invocations = Arc::clone(&processor);
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let server = tokio::spawn(serve_production_http1(
            listener,
            ProductionRuntimeConfig::default(),
            processor,
            async move {
                let _ = shutdown_rx.await;
            },
        ));

        let mut client = TcpStream::connect(address)
            .await
            .expect("client should connect");
        client
            .write_all(b"GET /normal HTTP/1.1\r\nHost: proxy.local\r\nConnection: close\r\n\r\n")
            .await
            .expect("client should write");
        let mut response = Vec::new();
        timeout(Duration::from_secs(5), client.read_to_end(&mut response))
            .await
            .expect("failed processor should still respond")
            .expect("response should read");

        assert!(
            response.starts_with(b"HTTP/1.1 500"),
            "processor failure should keep the empty 500 outcome"
        );
        let body_start = response
            .windows(b"\r\n\r\n".len())
            .position(|window| window == b"\r\n\r\n")
            .expect("response should end headers")
            + b"\r\n\r\n".len();
        assert_eq!(&response[body_start..], b"", "500 body should stay empty");
        assert_eq!(
            *invocations
                .invocations
                .lock()
                .expect("invocation count should lock"),
            1,
            "a failed processor must not be retried or re-dispatched"
        );

        shutdown_tx
            .send(())
            .expect("test should stop the production listener");
        server
            .await
            .expect("production server should join")
            .expect("production server should stop cleanly");
    }

    #[tokio::test]
    async fn closed_processor_permit_semaphore_maps_to_unavailable_without_panic() {
        let permits = Arc::new(Semaphore::new(1));
        permits.close();

        let result = acquire_processor_permit(&permits).await;

        assert!(
            matches!(result, Err(ProductionProcessorError::Unavailable)),
            "a closed permit semaphore must fail closed without panicking"
        );
    }

    #[tokio::test]
    async fn empty_upstream_address_set_returns_typed_connect_failure_without_panic() {
        let request = ProductionHttpPolicy
            .adapt(
                Request::builder()
                    .method("GET")
                    .uri("/normal")
                    .version(Version::HTTP_11)
                    .header(HOST, "proxy.local")
                    .body(ProductionInboundBody::new(Bytes::new()))
                    .expect("test request should build"),
            )
            .expect("test request should adapt");
        // The public constructor rejects empty address sets; build the
        // impossible shape directly to prove the fallback cannot panic.
        let target = ProductionUpstreamTarget {
            authority: "upstream.test"
                .parse::<Authority>()
                .expect("test authority should parse"),
            connect_addrs: Vec::new(),
        };

        let result = dispatch_production_upstream_within_deadline(
            &request,
            &target,
            ProductionUpstreamConfig::default(),
        )
        .await;

        assert_eq!(result, Err(ProductionUpstreamError::ConnectFailed));
    }
}
