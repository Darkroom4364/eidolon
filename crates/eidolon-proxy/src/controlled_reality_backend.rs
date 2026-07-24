use std::{
    collections::HashMap,
    fmt,
    io::{Read, Write},
    net::{Shutdown, SocketAddr, TcpStream, ToSocketAddrs},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use eidolon_core::RequestId;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::{
    controlled_reality::{
        ControlledRealityRenderedResponse, ControlledRealityRequestKind,
        ControlledRealityResourceDescriptor, ControlledRealityResponder,
    },
    policy_store::ControlledRealityProgress,
};

pub const CONTROLLED_REALITY_BACKEND_SCHEMA_VERSION: u16 = 1;
pub const MAX_CONTROLLED_REALITY_BACKEND_FRAME_BYTES: usize = 64 * 1024;
pub const MIN_CONTROLLED_REALITY_BACKEND_SECRET_BYTES: usize = 32;
pub const MAX_CONTROLLED_REALITY_BACKEND_REPLAY_ENTRIES: usize = 4_096;
/// Requests and responses outside this symmetric clock-skew window are rejected.
pub const CONTROLLED_REALITY_BACKEND_FRESHNESS_WINDOW: Duration = Duration::from_secs(30);
pub const CONTROLLED_REALITY_BACKEND_IO_TIMEOUT: Duration = Duration::from_secs(2);

const REQUEST_AUTH_DOMAIN: &[u8] = b"eidolon:controlled-reality:render-request:v1\0";
const RESPONSE_AUTH_DOMAIN: &[u8] = b"eidolon:controlled-reality:render-response:v1\0";

type HmacSha256 = Hmac<Sha256>;

pub struct ControlledRealityBackendAuthSecret(Vec<u8>);

impl ControlledRealityBackendAuthSecret {
    pub fn new(secret: Vec<u8>) -> Result<Self, ControlledRealityBackendError> {
        if secret.len() < MIN_CONTROLLED_REALITY_BACKEND_SECRET_BYTES
            || secret.iter().all(u8::is_ascii_whitespace)
            || secret
                .first()
                .is_some_and(|first| secret.iter().all(|byte| byte == first))
        {
            return Err(ControlledRealityBackendError::WeakSecret);
        }
        Ok(Self(secret))
    }

    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for ControlledRealityBackendAuthSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ControlledRealityBackendAuthSecret(<redacted>)")
    }
}

impl Drop for ControlledRealityBackendAuthSecret {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

#[derive(Debug, Clone)]
pub struct ControlledRealityBackendClient {
    address: SocketAddr,
    secret: Arc<ControlledRealityBackendAuthSecret>,
}

impl ControlledRealityBackendClient {
    pub fn new(address: SocketAddr, secret: ControlledRealityBackendAuthSecret) -> Self {
        Self {
            address,
            secret: Arc::new(secret),
        }
    }

    pub fn from_target(
        target: &str,
        secret: ControlledRealityBackendAuthSecret,
    ) -> Result<Self, ControlledRealityBackendError> {
        let address = target
            .to_socket_addrs()
            .map_err(|_| ControlledRealityBackendError::ResolutionFailed)?
            .next()
            .ok_or(ControlledRealityBackendError::ResolutionFailed)?;
        Ok(Self::new(address, secret))
    }

    pub fn render(
        &self,
        request_id: RequestId,
        request_kind: ControlledRealityRequestKind,
        progress: ControlledRealityProgress,
        resources: Option<ControlledRealityResourceDescriptor>,
    ) -> Result<VerifiedControlledRealityRenderResponse, ControlledRealityBackendError> {
        let request = SignedControlledRealityRenderRequest::new(
            &self.secret,
            request_id,
            current_unix_secs()?,
            request_kind,
            progress,
            resources,
        )?;
        let mut stream =
            TcpStream::connect_timeout(&self.address, CONTROLLED_REALITY_BACKEND_IO_TIMEOUT)
                .map_err(|_| ControlledRealityBackendError::ConnectFailed)?;
        stream
            .set_read_timeout(Some(CONTROLLED_REALITY_BACKEND_IO_TIMEOUT))
            .and_then(|_| stream.set_write_timeout(Some(CONTROLLED_REALITY_BACKEND_IO_TIMEOUT)))
            .map_err(|_| ControlledRealityBackendError::ConnectFailed)?;
        write_render_request(&mut stream, &request)?;
        stream
            .shutdown(Shutdown::Write)
            .map_err(|_| ControlledRealityBackendError::WriteFailed)?;
        let response = read_render_response(&mut stream)?;
        verify_render_response(&self.secret, &response, &request, current_unix_secs()?)
    }
}

#[derive(Debug)]
pub struct ControlledRealityBackendReplayCache {
    entries: Mutex<HashMap<RequestId, u64>>,
    max_entries: usize,
}

impl ControlledRealityBackendReplayCache {
    pub fn new() -> Self {
        Self::with_capacity(MAX_CONTROLLED_REALITY_BACKEND_REPLAY_ENTRIES)
    }

    fn with_capacity(max_entries: usize) -> Self {
        Self {
            entries: Mutex::new(HashMap::with_capacity(max_entries)),
            max_entries,
        }
    }

    fn register(
        &self,
        request: &SignedControlledRealityRenderRequest,
        now_unix_secs: u64,
    ) -> Result<(), ControlledRealityBackendError> {
        let request_id = request.request_id;
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| ControlledRealityBackendError::ReplayCacheUnavailable { request_id })?;
        entries.retain(|_, expires_at| *expires_at >= now_unix_secs);
        if entries.contains_key(&request_id) {
            return Err(ControlledRealityBackendError::ReplayDetected { request_id });
        }
        if entries.len() >= self.max_entries {
            return Err(ControlledRealityBackendError::ReplayCacheSaturated { request_id });
        }

        let expires_at = request
            .issued_at_unix_secs
            .saturating_add(CONTROLLED_REALITY_BACKEND_FRESHNESS_WINDOW.as_secs());
        entries.insert(request_id, expires_at);
        Ok(())
    }
}

impl Default for ControlledRealityBackendReplayCache {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedControlledRealityRenderRequest {
    pub schema_version: u16,
    pub request_id: RequestId,
    pub issued_at_unix_secs: u64,
    pub request_kind: ControlledRealityRequestKind,
    pub progress: ControlledRealityProgress,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<ControlledRealityResourceDescriptor>,
    pub auth_tag: String,
}

impl SignedControlledRealityRenderRequest {
    pub fn new(
        secret: &ControlledRealityBackendAuthSecret,
        request_id: RequestId,
        issued_at_unix_secs: u64,
        request_kind: ControlledRealityRequestKind,
        progress: ControlledRealityProgress,
        resources: Option<ControlledRealityResourceDescriptor>,
    ) -> Result<Self, ControlledRealityBackendError> {
        let mut request = Self {
            schema_version: CONTROLLED_REALITY_BACKEND_SCHEMA_VERSION,
            request_id,
            issued_at_unix_secs,
            request_kind,
            progress,
            resources,
            auth_tag: String::new(),
        };
        request.auth_tag = request_auth_tag(secret, &request)?;
        Ok(request)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedControlledRealityRenderResponse {
    pub schema_version: u16,
    pub request_id: RequestId,
    pub request_auth_tag: String,
    pub issued_at_unix_secs: u64,
    pub status: u16,
    pub body: String,
    pub auth_tag: String,
}

impl SignedControlledRealityRenderResponse {
    fn new(
        secret: &ControlledRealityBackendAuthSecret,
        request: &SignedControlledRealityRenderRequest,
        issued_at_unix_secs: u64,
        rendered: ControlledRealityRenderedResponse,
    ) -> Result<Self, ControlledRealityBackendError> {
        let body = String::from_utf8(rendered.body)
            .map_err(|_| ControlledRealityBackendError::InvalidRenderedBody)?;
        let mut response = Self {
            schema_version: CONTROLLED_REALITY_BACKEND_SCHEMA_VERSION,
            request_id: request.request_id,
            request_auth_tag: request.auth_tag.clone(),
            issued_at_unix_secs,
            status: rendered.status,
            body,
            auth_tag: String::new(),
        };
        response.auth_tag = response_auth_tag(secret, &response)?;
        Ok(response)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedControlledRealityRenderResponse {
    pub request_id: RequestId,
    pub status: u16,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlledRealityBackendError {
    WeakSecret,
    ResolutionFailed,
    ConnectFailed,
    SchemaMismatch,
    AuthenticationFailed,
    StaleMessage,
    RequestIdMismatch,
    RequestBindingMismatch,
    InvalidResourceDescriptor,
    InvalidRenderedBody,
    InvalidResponseStatus,
    ResponseSemanticsMismatch,
    AuthenticatedSchemaMismatch { request_id: RequestId },
    AuthenticatedStaleMessage { request_id: RequestId },
    AuthenticatedInvalidResourceDescriptor { request_id: RequestId },
    ReplayDetected { request_id: RequestId },
    ReplayCacheSaturated { request_id: RequestId },
    ReplayCacheUnavailable { request_id: RequestId },
    AuthenticatedResponseGenerationFailed { request_id: RequestId },
    AuthenticatedWriteFailed { request_id: RequestId },
    OversizedFrame,
    MultipleFrames,
    MalformedFrame,
    ReadFailed,
    WriteFailed,
    ClockUnavailable,
}

impl ControlledRealityBackendError {
    pub fn audit_code(self) -> &'static str {
        match self {
            Self::WeakSecret => "weak_secret",
            Self::ResolutionFailed => "resolution_failed",
            Self::ConnectFailed => "connect_failed",
            Self::SchemaMismatch => "schema_mismatch",
            Self::AuthenticationFailed => "authentication_failed",
            Self::StaleMessage => "stale_message",
            Self::RequestIdMismatch => "request_id_mismatch",
            Self::RequestBindingMismatch => "request_binding_mismatch",
            Self::InvalidResourceDescriptor => "invalid_resource_descriptor",
            Self::InvalidRenderedBody => "invalid_rendered_body",
            Self::InvalidResponseStatus => "invalid_response_status",
            Self::ResponseSemanticsMismatch => "response_semantics_mismatch",
            Self::AuthenticatedSchemaMismatch { .. } => "schema_mismatch",
            Self::AuthenticatedStaleMessage { .. } => "stale_message",
            Self::AuthenticatedInvalidResourceDescriptor { .. } => "invalid_resource_descriptor",
            Self::ReplayDetected { .. } => "replay_detected",
            Self::ReplayCacheSaturated { .. } => "replay_cache_saturated",
            Self::ReplayCacheUnavailable { .. } => "replay_cache_unavailable",
            Self::AuthenticatedResponseGenerationFailed { .. } => "response_generation_failed",
            Self::AuthenticatedWriteFailed { .. } => "write_failed",
            Self::OversizedFrame => "oversized_frame",
            Self::MultipleFrames => "multiple_frames",
            Self::MalformedFrame => "malformed_frame",
            Self::ReadFailed => "read_failed",
            Self::WriteFailed => "write_failed",
            Self::ClockUnavailable => "clock_unavailable",
        }
    }

    pub fn authenticated_request_id(self) -> Option<RequestId> {
        match self {
            Self::AuthenticatedSchemaMismatch { request_id }
            | Self::AuthenticatedStaleMessage { request_id }
            | Self::AuthenticatedInvalidResourceDescriptor { request_id }
            | Self::ReplayDetected { request_id }
            | Self::ReplayCacheSaturated { request_id }
            | Self::ReplayCacheUnavailable { request_id }
            | Self::AuthenticatedResponseGenerationFailed { request_id }
            | Self::AuthenticatedWriteFailed { request_id } => Some(request_id),
            _ => None,
        }
    }
}

impl fmt::Display for ControlledRealityBackendError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.audit_code())
    }
}

impl std::error::Error for ControlledRealityBackendError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlledRealityBackendConnectionOutcome {
    HealthCheck,
    Served {
        request_id: RequestId,
        status: u16,
    },
    Rejected {
        reason: ControlledRealityBackendError,
    },
}

impl ControlledRealityBackendConnectionOutcome {
    pub fn rejected_request_id(self) -> Option<RequestId> {
        match self {
            Self::Rejected { reason } => reason.authenticated_request_id(),
            Self::HealthCheck | Self::Served { .. } => None,
        }
    }
}

#[derive(Serialize)]
struct RequestAuthPayload<'a> {
    schema_version: u16,
    request_id: RequestId,
    issued_at_unix_secs: u64,
    request_kind: ControlledRealityRequestKind,
    progress: ControlledRealityProgress,
    resources: &'a Option<ControlledRealityResourceDescriptor>,
}

#[derive(Serialize)]
struct ResponseAuthPayload<'a> {
    schema_version: u16,
    request_id: RequestId,
    request_auth_tag: &'a str,
    issued_at_unix_secs: u64,
    status: u16,
    body: &'a str,
}

pub fn current_unix_secs() -> Result<u64, ControlledRealityBackendError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| ControlledRealityBackendError::ClockUnavailable)
}

pub fn verify_render_request(
    secret: &ControlledRealityBackendAuthSecret,
    request: &SignedControlledRealityRenderRequest,
    now_unix_secs: u64,
) -> Result<(), ControlledRealityBackendError> {
    verify_tag(
        secret,
        REQUEST_AUTH_DOMAIN,
        &request_auth_payload(request)?,
        &request.auth_tag,
    )?;
    if request.schema_version != CONTROLLED_REALITY_BACKEND_SCHEMA_VERSION {
        return Err(ControlledRealityBackendError::AuthenticatedSchemaMismatch {
            request_id: request.request_id,
        });
    }
    verify_freshness(request.issued_at_unix_secs, now_unix_secs).map_err(|error| match error {
        ControlledRealityBackendError::StaleMessage => {
            ControlledRealityBackendError::AuthenticatedStaleMessage {
                request_id: request.request_id,
            }
        }
        _ => error,
    })?;
    if request
        .resources
        .as_ref()
        .is_some_and(|resources| !resources.has_valid_artifact_digest())
    {
        return Err(
            ControlledRealityBackendError::AuthenticatedInvalidResourceDescriptor {
                request_id: request.request_id,
            },
        );
    }
    if request.progress.origin_request_id.is_some() != request.resources.is_some() {
        return Err(
            ControlledRealityBackendError::AuthenticatedInvalidResourceDescriptor {
                request_id: request.request_id,
            },
        );
    }
    Ok(())
}

pub fn verify_render_response(
    secret: &ControlledRealityBackendAuthSecret,
    response: &SignedControlledRealityRenderResponse,
    expected_request: &SignedControlledRealityRenderRequest,
    now_unix_secs: u64,
) -> Result<VerifiedControlledRealityRenderResponse, ControlledRealityBackendError> {
    verify_tag(
        secret,
        RESPONSE_AUTH_DOMAIN,
        &response_auth_payload(response)?,
        &response.auth_tag,
    )?;
    if response.schema_version != CONTROLLED_REALITY_BACKEND_SCHEMA_VERSION {
        return Err(ControlledRealityBackendError::SchemaMismatch);
    }
    verify_freshness(response.issued_at_unix_secs, now_unix_secs)?;
    if response.request_id != expected_request.request_id {
        return Err(ControlledRealityBackendError::RequestIdMismatch);
    }
    verify_render_request(secret, expected_request, now_unix_secs)?;
    if response.request_auth_tag != expected_request.auth_tag {
        return Err(ControlledRealityBackendError::RequestBindingMismatch);
    }
    if !matches!(response.status, 200 | 202 | 404 | 405 | 409) {
        return Err(ControlledRealityBackendError::InvalidResponseStatus);
    }
    serde_json::from_str::<serde_json::Value>(&response.body)
        .map_err(|_| ControlledRealityBackendError::InvalidRenderedBody)?;
    let expected = ControlledRealityResponder.render(
        expected_request.request_kind,
        expected_request.progress,
        expected_request.resources.as_ref(),
    );
    if response.status != expected.status || response.body.as_bytes() != expected.body {
        return Err(ControlledRealityBackendError::ResponseSemanticsMismatch);
    }

    Ok(VerifiedControlledRealityRenderResponse {
        request_id: response.request_id,
        status: response.status,
        body: response.body.as_bytes().to_vec(),
    })
}

pub fn process_render_request(
    secret: &ControlledRealityBackendAuthSecret,
    replay_cache: &ControlledRealityBackendReplayCache,
    request: &SignedControlledRealityRenderRequest,
    now_unix_secs: u64,
) -> Result<SignedControlledRealityRenderResponse, ControlledRealityBackendError> {
    verify_render_request(secret, request, now_unix_secs)?;
    replay_cache.register(request, now_unix_secs)?;
    let rendered = ControlledRealityResponder.render(
        request.request_kind,
        request.progress,
        request.resources.as_ref(),
    );
    SignedControlledRealityRenderResponse::new(secret, request, now_unix_secs, rendered).map_err(
        |_| ControlledRealityBackendError::AuthenticatedResponseGenerationFailed {
            request_id: request.request_id,
        },
    )
}

pub fn write_render_request(
    writer: &mut impl Write,
    request: &SignedControlledRealityRenderRequest,
) -> Result<(), ControlledRealityBackendError> {
    write_json_frame(writer, request)
}

pub fn read_render_response(
    reader: &mut impl Read,
) -> Result<SignedControlledRealityRenderResponse, ControlledRealityBackendError> {
    let Some(payload) = read_json_frame(reader)? else {
        return Err(ControlledRealityBackendError::MalformedFrame);
    };
    serde_json::from_slice(&payload).map_err(|_| ControlledRealityBackendError::MalformedFrame)
}

pub fn serve_render_connection(
    mut stream: TcpStream,
    secret: &ControlledRealityBackendAuthSecret,
    replay_cache: &ControlledRealityBackendReplayCache,
) -> ControlledRealityBackendConnectionOutcome {
    if stream
        .set_read_timeout(Some(CONTROLLED_REALITY_BACKEND_IO_TIMEOUT))
        .and_then(|_| stream.set_write_timeout(Some(CONTROLLED_REALITY_BACKEND_IO_TIMEOUT)))
        .is_err()
    {
        return ControlledRealityBackendConnectionOutcome::Rejected {
            reason: ControlledRealityBackendError::ReadFailed,
        };
    }

    let payload = match read_json_frame(&mut stream) {
        Ok(None) => return ControlledRealityBackendConnectionOutcome::HealthCheck,
        Ok(Some(payload)) => payload,
        Err(reason) => {
            return ControlledRealityBackendConnectionOutcome::Rejected { reason };
        }
    };
    let request: SignedControlledRealityRenderRequest = match serde_json::from_slice(&payload) {
        Ok(request) => request,
        Err(_) => {
            return ControlledRealityBackendConnectionOutcome::Rejected {
                reason: ControlledRealityBackendError::MalformedFrame,
            };
        }
    };
    let now_unix_secs = match current_unix_secs() {
        Ok(now) => now,
        Err(reason) => {
            return ControlledRealityBackendConnectionOutcome::Rejected { reason };
        }
    };
    let response = match process_render_request(secret, replay_cache, &request, now_unix_secs) {
        Ok(response) => response,
        Err(reason) => {
            return ControlledRealityBackendConnectionOutcome::Rejected { reason };
        }
    };
    if write_json_frame(&mut stream, &response).is_err() {
        return ControlledRealityBackendConnectionOutcome::Rejected {
            reason: ControlledRealityBackendError::AuthenticatedWriteFailed {
                request_id: request.request_id,
            },
        };
    }
    let _ = stream.shutdown(Shutdown::Write);

    ControlledRealityBackendConnectionOutcome::Served {
        request_id: request.request_id,
        status: response.status,
    }
}

fn request_auth_tag(
    secret: &ControlledRealityBackendAuthSecret,
    request: &SignedControlledRealityRenderRequest,
) -> Result<String, ControlledRealityBackendError> {
    sign(secret, REQUEST_AUTH_DOMAIN, &request_auth_payload(request)?)
}

fn response_auth_tag(
    secret: &ControlledRealityBackendAuthSecret,
    response: &SignedControlledRealityRenderResponse,
) -> Result<String, ControlledRealityBackendError> {
    sign(
        secret,
        RESPONSE_AUTH_DOMAIN,
        &response_auth_payload(response)?,
    )
}

fn request_auth_payload(
    request: &SignedControlledRealityRenderRequest,
) -> Result<Vec<u8>, ControlledRealityBackendError> {
    serde_json::to_vec(&RequestAuthPayload {
        schema_version: request.schema_version,
        request_id: request.request_id,
        issued_at_unix_secs: request.issued_at_unix_secs,
        request_kind: request.request_kind,
        progress: request.progress,
        resources: &request.resources,
    })
    .map_err(|_| ControlledRealityBackendError::MalformedFrame)
}

fn response_auth_payload(
    response: &SignedControlledRealityRenderResponse,
) -> Result<Vec<u8>, ControlledRealityBackendError> {
    serde_json::to_vec(&ResponseAuthPayload {
        schema_version: response.schema_version,
        request_id: response.request_id,
        request_auth_tag: &response.request_auth_tag,
        issued_at_unix_secs: response.issued_at_unix_secs,
        status: response.status,
        body: &response.body,
    })
    .map_err(|_| ControlledRealityBackendError::MalformedFrame)
}

fn sign(
    secret: &ControlledRealityBackendAuthSecret,
    domain: &[u8],
    payload: &[u8],
) -> Result<String, ControlledRealityBackendError> {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|_| ControlledRealityBackendError::AuthenticationFailed)?;
    mac.update(domain);
    mac.update(payload);
    Ok(hex_encode(&mac.finalize().into_bytes()))
}

fn verify_tag(
    secret: &ControlledRealityBackendAuthSecret,
    domain: &[u8],
    payload: &[u8],
    encoded_tag: &str,
) -> Result<(), ControlledRealityBackendError> {
    let tag =
        hex_decode_32(encoded_tag).ok_or(ControlledRealityBackendError::AuthenticationFailed)?;
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|_| ControlledRealityBackendError::AuthenticationFailed)?;
    mac.update(domain);
    mac.update(payload);
    mac.verify_slice(&tag)
        .map_err(|_| ControlledRealityBackendError::AuthenticationFailed)
}

fn verify_freshness(
    issued_at_unix_secs: u64,
    now_unix_secs: u64,
) -> Result<(), ControlledRealityBackendError> {
    if issued_at_unix_secs.abs_diff(now_unix_secs)
        > CONTROLLED_REALITY_BACKEND_FRESHNESS_WINDOW.as_secs()
    {
        return Err(ControlledRealityBackendError::StaleMessage);
    }
    Ok(())
}

fn write_json_frame(
    writer: &mut impl Write,
    value: &impl Serialize,
) -> Result<(), ControlledRealityBackendError> {
    let mut frame =
        serde_json::to_vec(value).map_err(|_| ControlledRealityBackendError::MalformedFrame)?;
    if frame.len() > MAX_CONTROLLED_REALITY_BACKEND_FRAME_BYTES {
        return Err(ControlledRealityBackendError::OversizedFrame);
    }
    frame.push(b'\n');
    writer
        .write_all(&frame)
        .map_err(|_| ControlledRealityBackendError::WriteFailed)
}

fn read_json_frame(
    reader: &mut impl Read,
) -> Result<Option<Vec<u8>>, ControlledRealityBackendError> {
    let mut bytes = Vec::new();
    reader
        .take((MAX_CONTROLLED_REALITY_BACKEND_FRAME_BYTES + 2) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| ControlledRealityBackendError::ReadFailed)?;
    if bytes.is_empty() {
        return Ok(None);
    }
    if bytes.len() > MAX_CONTROLLED_REALITY_BACKEND_FRAME_BYTES + 1 {
        return Err(ControlledRealityBackendError::OversizedFrame);
    }
    if bytes.last() != Some(&b'\n') {
        return Err(ControlledRealityBackendError::MalformedFrame);
    }
    bytes.pop();
    if bytes.len() > MAX_CONTROLLED_REALITY_BACKEND_FRAME_BYTES {
        return Err(ControlledRealityBackendError::OversizedFrame);
    }
    if bytes.is_empty() {
        return Err(ControlledRealityBackendError::MalformedFrame);
    }
    if bytes.contains(&b'\n') {
        return Err(ControlledRealityBackendError::MultipleFrames);
    }
    Ok(Some(bytes))
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn hex_decode_32(encoded: &str) -> Option<[u8; 32]> {
    if encoded.len() != 64 {
        return None;
    }
    let mut decoded = [0_u8; 32];
    for (index, pair) in encoded.as_bytes().chunks_exact(2).enumerate() {
        decoded[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Some(decoded)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeSet,
        io::Cursor,
        net::{TcpListener, TcpStream},
        sync::{Arc, Barrier},
        thread,
    };

    use eidolon_core::{ControlledRealityWorkflowState, SessionId};
    use uuid::Uuid;

    use super::*;

    fn secret() -> ControlledRealityBackendAuthSecret {
        ControlledRealityBackendAuthSecret::new(b"0123456789abcdef0123456789abcdef".to_vec())
            .expect("test secret should be accepted")
    }

    fn other_secret() -> ControlledRealityBackendAuthSecret {
        ControlledRealityBackendAuthSecret::new(b"fedcba9876543210fedcba9876543210".to_vec())
            .expect("test secret should be accepted")
    }

    fn replay_cache() -> ControlledRealityBackendReplayCache {
        ControlledRealityBackendReplayCache::new()
    }

    fn fixture(
        issued_at_unix_secs: u64,
    ) -> (
        SignedControlledRealityRenderRequest,
        ControlledRealityResourceDescriptor,
    ) {
        let origin_request_id = RequestId::new();
        let resources =
            ControlledRealityResourceDescriptor::for_session(SessionId::new(), origin_request_id)
                .expect("generated resources should satisfy the typed contract");
        let progress = ControlledRealityProgress {
            depth: 2,
            from_state: ControlledRealityWorkflowState::Queued,
            to_state: ControlledRealityWorkflowState::Completed,
            origin_request_id: Some(origin_request_id),
        };
        let request = SignedControlledRealityRenderRequest::new(
            &secret(),
            RequestId::new(),
            issued_at_unix_secs,
            ControlledRealityRequestKind::StatusRead,
            progress,
            Some(resources.clone()),
        )
        .expect("request should sign");
        (request, resources)
    }

    fn fixed_fixture() -> SignedControlledRealityRenderRequest {
        let request_id = RequestId(
            Uuid::parse_str("11111111-1111-4111-8111-111111111111")
                .expect("fixed request id should parse"),
        );
        let origin_request_id = RequestId(
            Uuid::parse_str("22222222-2222-4222-8222-222222222222")
                .expect("fixed origin request id should parse"),
        );
        let session_id = SessionId(
            Uuid::parse_str("33333333-3333-4333-8333-333333333333")
                .expect("fixed session id should parse"),
        );
        let resources =
            ControlledRealityResourceDescriptor::for_session(session_id, origin_request_id)
                .expect("generated resources should satisfy the typed contract");
        SignedControlledRealityRenderRequest::new(
            &secret(),
            request_id,
            1_700_000_000,
            ControlledRealityRequestKind::StatusRead,
            ControlledRealityProgress {
                depth: 2,
                from_state: ControlledRealityWorkflowState::Queued,
                to_state: ControlledRealityWorkflowState::Completed,
                origin_request_id: Some(origin_request_id),
            },
            Some(resources),
        )
        .expect("fixed request should sign")
    }

    fn connection_outcome(
        request: &SignedControlledRealityRenderRequest,
        cache: Arc<ControlledRealityBackendReplayCache>,
    ) -> ControlledRealityBackendConnectionOutcome {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let address = listener
            .local_addr()
            .expect("listener address should exist");
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("connection should arrive");
            serve_render_connection(stream, &secret(), &cache)
        });
        let mut stream = TcpStream::connect(address).expect("client should connect");
        write_render_request(&mut stream, request).expect("request should write");
        stream
            .shutdown(Shutdown::Write)
            .expect("request side should close");

        server.join().expect("server should finish")
    }

    #[test]
    fn valid_signed_round_trip_uses_one_bounded_frame() {
        let now = current_unix_secs().expect("clock should be available");
        let (request, _) = fixture(now);
        let request_id = request.request_id;
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let address = listener
            .local_addr()
            .expect("listener address should exist");
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("connection should arrive");
            let cache = replay_cache();
            serve_render_connection(stream, &secret(), &cache)
        });

        let mut stream = TcpStream::connect(address).expect("client should connect");
        write_render_request(&mut stream, &request).expect("request should write");
        stream
            .shutdown(Shutdown::Write)
            .expect("request side should close");
        let response = read_render_response(&mut stream).expect("response should parse");
        let verified = verify_render_response(&secret(), &response, &request, now)
            .expect("response should verify");

        assert_eq!(verified.request_id, request_id);
        assert_eq!(verified.status, 200);
        assert!(String::from_utf8(verified.body)
            .expect("body should be utf8")
            .contains(r#""status":"completed""#));
        assert_eq!(
            server.join().expect("server should finish"),
            ControlledRealityBackendConnectionOutcome::Served {
                request_id,
                status: 200,
            }
        );
    }

    #[test]
    fn client_returns_only_a_verified_renderer_response() {
        let now = current_unix_secs().expect("clock should be available");
        let (request, resources) = fixture(now);
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let address = listener
            .local_addr()
            .expect("listener address should exist");
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("connection should arrive");
            serve_render_connection(stream, &secret(), &replay_cache())
        });
        let client = ControlledRealityBackendClient::new(address, secret());

        let rendered = client
            .render(
                request.request_id,
                request.request_kind,
                request.progress,
                Some(resources),
            )
            .expect("client should verify the renderer response");

        assert_eq!(rendered.request_id, request.request_id);
        assert_eq!(rendered.status, 200);
        assert_eq!(
            server.join().expect("server should finish"),
            ControlledRealityBackendConnectionOutcome::Served {
                request_id: request.request_id,
                status: 200,
            }
        );
    }

    #[test]
    fn client_reports_connection_failure_without_retrying() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let address = listener
            .local_addr()
            .expect("listener address should exist");
        drop(listener);
        let client = ControlledRealityBackendClient::new(address, secret());
        let (request, resources) = fixture(current_unix_secs().expect("clock should be available"));

        assert_eq!(
            client.render(
                request.request_id,
                request.request_kind,
                request.progress,
                Some(resources),
            ),
            Err(ControlledRealityBackendError::ConnectFailed)
        );
    }

    #[test]
    fn tampered_request_is_rejected() {
        let now = 1_000_000;
        let (mut request, _) = fixture(now);
        request.progress.depth += 1;

        let error = verify_render_request(&secret(), &request, now)
            .expect_err("tampered request must be rejected");
        assert_eq!(error, ControlledRealityBackendError::AuthenticationFailed);
        assert_eq!(error.authenticated_request_id(), None);
    }

    #[test]
    fn wrong_secret_is_rejected() {
        let now = 1_000_000;
        let (request, _) = fixture(now);

        assert_eq!(
            verify_render_request(&other_secret(), &request, now),
            Err(ControlledRealityBackendError::AuthenticationFailed)
        );
    }

    #[test]
    fn stale_request_is_rejected_after_authentication() {
        let issued_at = 1_000_000;
        let (request, _) = fixture(issued_at);

        let error = verify_render_request(
            &secret(),
            &request,
            issued_at + CONTROLLED_REALITY_BACKEND_FRESHNESS_WINDOW.as_secs() + 1,
        )
        .expect_err("stale request must be rejected");
        assert_eq!(
            error,
            ControlledRealityBackendError::AuthenticatedStaleMessage {
                request_id: request.request_id,
            }
        );
        assert_eq!(error.authenticated_request_id(), Some(request.request_id));
    }

    #[test]
    fn mismatched_response_request_id_is_rejected() {
        let now = 1_000_000;
        let (request, _) = fixture(now);
        let response = process_render_request(&secret(), &replay_cache(), &request, now)
            .expect("response should be generated");
        let (other_request, _) = fixture(now);

        assert_eq!(
            verify_render_response(&secret(), &response, &other_request, now),
            Err(ControlledRealityBackendError::RequestIdMismatch)
        );
    }

    #[test]
    fn authenticated_but_semantically_different_response_is_rejected() {
        let now = 1_000_000;
        let (request, _) = fixture(now);
        let response = SignedControlledRealityRenderResponse::new(
            &secret(),
            &request,
            now,
            ControlledRealityRenderedResponse {
                status: 404,
                body: br#"{"status":"not_found","synthetic":true,"write_committed":false}"#
                    .to_vec(),
            },
        )
        .expect("different response should sign");

        assert_eq!(
            verify_render_response(&secret(), &response, &request, now),
            Err(ControlledRealityBackendError::ResponseSemanticsMismatch)
        );
    }

    #[test]
    fn response_is_bound_to_the_exact_authenticated_request() {
        let now = 1_000_000;
        let (request, _) = fixture(now);
        let response = process_render_request(&secret(), &replay_cache(), &request, now)
            .expect("response should be generated");
        let other_request = SignedControlledRealityRenderRequest::new(
            &secret(),
            request.request_id,
            now,
            ControlledRealityRequestKind::UnknownResource,
            ControlledRealityProgress {
                depth: 0,
                from_state: ControlledRealityWorkflowState::Ready,
                to_state: ControlledRealityWorkflowState::Ready,
                origin_request_id: None,
            },
            None,
        )
        .expect("second request should sign");

        assert_eq!(
            verify_render_response(&secret(), &response, &other_request, now),
            Err(ControlledRealityBackendError::RequestBindingMismatch)
        );
    }

    #[test]
    fn tampered_and_stale_responses_are_rejected() {
        let now = 1_000_000;
        let (request, _) = fixture(now);
        let response = process_render_request(&secret(), &replay_cache(), &request, now)
            .expect("response should be generated");
        let mut tampered = response.clone();
        tampered.body.push(' ');

        assert_eq!(
            verify_render_response(&secret(), &tampered, &request, now),
            Err(ControlledRealityBackendError::AuthenticationFailed)
        );
        let mut rebound = response.clone();
        rebound.request_auth_tag = other_secret()
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(
            verify_render_response(&secret(), &rebound, &request, now),
            Err(ControlledRealityBackendError::AuthenticationFailed)
        );
        assert_eq!(
            verify_render_response(
                &secret(),
                &response,
                &request,
                now + CONTROLLED_REALITY_BACKEND_FRESHNESS_WINDOW.as_secs() + 1,
            ),
            Err(ControlledRealityBackendError::StaleMessage)
        );
    }

    #[test]
    fn fresh_response_cannot_revive_a_stale_request() {
        let issued_at = 1_000_000;
        let now = issued_at + CONTROLLED_REALITY_BACKEND_FRESHNESS_WINDOW.as_secs() + 1;
        let (request, _) = fixture(issued_at);
        let rendered = ControlledRealityResponder.render(
            request.request_kind,
            request.progress,
            request.resources.as_ref(),
        );
        let response =
            SignedControlledRealityRenderResponse::new(&secret(), &request, now, rendered)
                .expect("fresh response should sign");

        assert_eq!(
            verify_render_response(&secret(), &response, &request, now),
            Err(ControlledRealityBackendError::AuthenticatedStaleMessage {
                request_id: request.request_id,
            })
        );
    }

    #[test]
    fn resource_presence_must_match_workflow_origin() {
        let now = 1_000_000;
        let (request, _) = fixture(now);
        let request = SignedControlledRealityRenderRequest::new(
            &secret(),
            request.request_id,
            now,
            request.request_kind,
            request.progress,
            None,
        )
        .expect("inconsistent request should still serialize and sign");

        assert_eq!(
            verify_render_request(&secret(), &request, now),
            Err(
                ControlledRealityBackendError::AuthenticatedInvalidResourceDescriptor {
                    request_id: request.request_id,
                }
            )
        );
    }

    #[test]
    fn replayed_request_is_rejected_before_a_second_render() {
        let now = 1_000_000;
        let (request, _) = fixture(now);
        let cache = replay_cache();

        process_render_request(&secret(), &cache, &request, now)
            .expect("first request should render");
        let error = process_render_request(&secret(), &cache, &request, now)
            .expect_err("replay must be rejected");

        assert_eq!(
            error,
            ControlledRealityBackendError::ReplayDetected {
                request_id: request.request_id,
            }
        );
        assert_eq!(error.authenticated_request_id(), Some(request.request_id));
    }

    #[test]
    fn connection_rejections_correlate_only_authenticated_requests() {
        let now = current_unix_secs().expect("clock should be available");
        let cache = Arc::new(replay_cache());
        let (request, _) = fixture(now);

        assert!(matches!(
            connection_outcome(&request, Arc::clone(&cache)),
            ControlledRealityBackendConnectionOutcome::Served { request_id, .. }
                if request_id == request.request_id
        ));
        let replay = connection_outcome(&request, Arc::clone(&cache));
        assert_eq!(replay.rejected_request_id(), Some(request.request_id));
        assert!(matches!(
            replay,
            ControlledRealityBackendConnectionOutcome::Rejected {
                reason: ControlledRealityBackendError::ReplayDetected { request_id },
            } if request_id == request.request_id
        ));

        let (mut unauthenticated, _) = fixture(now);
        unauthenticated.progress.depth += 1;
        let rejected = connection_outcome(&unauthenticated, Arc::new(replay_cache()));
        assert_eq!(rejected.rejected_request_id(), None);
        assert_eq!(
            rejected,
            ControlledRealityBackendConnectionOutcome::Rejected {
                reason: ControlledRealityBackendError::AuthenticationFailed,
            }
        );
    }

    #[test]
    fn concurrent_replays_have_exactly_one_winner() {
        const WORKERS: usize = 16;

        let now = 1_000_000;
        let (request, _) = fixture(now);
        let request = Arc::new(request);
        let cache = Arc::new(replay_cache());
        let barrier = Arc::new(Barrier::new(WORKERS));
        let workers = (0..WORKERS)
            .map(|_| {
                let request = Arc::clone(&request);
                let cache = Arc::clone(&cache);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    process_render_request(&secret(), &cache, &request, now)
                })
            })
            .collect::<Vec<_>>();

        let mut served = 0;
        let mut replayed = 0;
        for worker in workers {
            match worker.join().expect("worker should not panic") {
                Ok(_) => served += 1,
                Err(ControlledRealityBackendError::ReplayDetected { request_id })
                    if request_id == request.request_id =>
                {
                    replayed += 1;
                }
                Err(error) => panic!("unexpected worker error: {error:?}"),
            }
        }

        assert_eq!(served, 1);
        assert_eq!(replayed, WORKERS - 1);
    }

    #[test]
    fn replay_cache_is_bounded_without_evicting_live_entries() {
        let now = 1_000_000;
        let cache = ControlledRealityBackendReplayCache::with_capacity(1);
        let (first, _) = fixture(now);
        let (second, _) = fixture(now);

        process_render_request(&secret(), &cache, &first, now)
            .expect("first request should render");
        assert_eq!(
            process_render_request(&secret(), &cache, &second, now),
            Err(ControlledRealityBackendError::ReplayCacheSaturated {
                request_id: second.request_id,
            })
        );
        assert_eq!(
            process_render_request(&secret(), &cache, &first, now),
            Err(ControlledRealityBackendError::ReplayDetected {
                request_id: first.request_id,
            })
        );
    }

    #[test]
    fn expired_replay_entries_are_reclaimed() {
        let issued_at = 1_000_000;
        let later = issued_at + CONTROLLED_REALITY_BACKEND_FRESHNESS_WINDOW.as_secs() + 1;
        let cache = ControlledRealityBackendReplayCache::with_capacity(1);
        let (first, _) = fixture(issued_at);
        process_render_request(&secret(), &cache, &first, issued_at)
            .expect("first request should render");
        let replacement = SignedControlledRealityRenderRequest::new(
            &secret(),
            first.request_id,
            later,
            first.request_kind,
            first.progress,
            first.resources.clone(),
        )
        .expect("replacement request should sign");

        process_render_request(&secret(), &cache, &replacement, later)
            .expect("expired replay entry should be reclaimed");
    }

    #[test]
    fn future_dated_request_stays_replay_blocked_for_its_full_validity() {
        let now = 1_000_000;
        let issued_at = now + CONTROLLED_REALITY_BACKEND_FRESHNESS_WINDOW.as_secs();
        let (request, _) = fixture(issued_at);
        let cache = replay_cache();
        process_render_request(&secret(), &cache, &request, now)
            .expect("request at the future freshness boundary should render once");

        let later = now + CONTROLLED_REALITY_BACKEND_FRESHNESS_WINDOW.as_secs() + 1;
        assert_eq!(
            process_render_request(&secret(), &cache, &request, later),
            Err(ControlledRealityBackendError::ReplayDetected {
                request_id: request.request_id,
            })
        );
    }

    #[test]
    fn oversized_malformed_and_multiple_frames_are_rejected() {
        let oversized = vec![b'x'; MAX_CONTROLLED_REALITY_BACKEND_FRAME_BYTES + 2];
        assert_eq!(
            read_json_frame(&mut Cursor::new(oversized)),
            Err(ControlledRealityBackendError::OversizedFrame)
        );
        assert_eq!(
            read_json_frame(&mut Cursor::new(b"{}\n{}".to_vec())),
            Err(ControlledRealityBackendError::MalformedFrame)
        );
        assert_eq!(
            read_json_frame(&mut Cursor::new(b"{}\n{}\n".to_vec())),
            Err(ControlledRealityBackendError::MultipleFrames)
        );
    }

    #[test]
    fn bare_connect_eof_is_health_check_noise() {
        assert_eq!(
            read_json_frame(&mut Cursor::new(Vec::<u8>::new())),
            Ok(None)
        );
    }

    #[test]
    fn transport_schema_has_no_raw_sensitive_request_fields() {
        let (request, _) = fixture(1_000_000);
        let value = serde_json::to_value(request).expect("request should serialize");
        let object = value.as_object().expect("request should be an object");
        let actual = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
        let expected = [
            "auth_tag",
            "issued_at_unix_secs",
            "progress",
            "request_id",
            "request_kind",
            "resources",
            "schema_version",
        ]
        .into_iter()
        .collect::<BTreeSet<_>>();

        assert_eq!(actual, expected);
        let mut all_keys = BTreeSet::new();
        collect_object_keys(&value, &mut all_keys);
        for forbidden in [
            "session_id",
            "method",
            "path",
            "query",
            "headers",
            "body",
            "cookie",
            "bait_proof",
            "upstream",
            "credentials",
            "surface_action",
            "routing_decision",
        ] {
            assert!(!all_keys.contains(forbidden), "{forbidden} leaked");
        }
    }

    #[test]
    fn protocol_v1_request_and_response_json_are_golden() {
        // Split deterministic digests so secret scanners do not mistake test
        // vectors for live credentials while the exact wire bytes stay pinned.
        const GOLDEN_REQUEST_JSON: &str = concat!(
            r#"{"schema_version":1,"request_id":"11111111-1111-4111-8111-111111111111","issued_at_unix_secs":1700000000,"request_kind":"status_read","progress":{"depth":2,"from_state":"queued","to_state":"completed","origin_request_id":"22222222-2222-4222-8222-222222222222"},"resources":{"job_id":"job_beccf226853a0dc0","artifact":{"artifact_id":"artifact_7d61b5ad29559602","sha256":""#,
            "a4f5e4b3",
            "d9ba4b0a",
            "9838876c",
            "5fcbd6cf",
            "85f04e16",
            "174dfa60",
            "c02c27b5",
            "cea51fb7",
            r#""}},"auth_tag":""#,
            "3969a9ea",
            "0b8fc700",
            "381598df",
            "293937af",
            "44be8655",
            "f596e747",
            "8c5f3d17",
            "afc27274",
            r#""}"#,
        );
        const GOLDEN_RESPONSE_JSON: &str = concat!(
            r#"{"schema_version":1,"request_id":"11111111-1111-4111-8111-111111111111","request_auth_tag":""#,
            "3969a9ea",
            "0b8fc700",
            "381598df",
            "293937af",
            "44be8655",
            "f596e747",
            "8c5f3d17",
            "afc27274",
            r#"","issued_at_unix_secs":1700000000,"status":200,"body":"{\"action_depth\":2,\"artifact\":{\"artifact_id\":\"artifact_7d61b5ad29559602\",\"path\":\"/api/v2/import/reconcile/jobs/job_beccf226853a0dc0/result\",\"sha256\":\""#,
            "a4f5e4b3",
            "d9ba4b0a",
            "9838876c",
            "5fcbd6cf",
            "85f04e16",
            "174dfa60",
            "c02c27b5",
            "cea51fb7",
            r#"\"},\"job_id\":\"job_beccf226853a0dc0\",\"path\":\"/api/v2/import/reconcile\",\"status\":\"completed\",\"status_path\":\"/api/v2/import/reconcile/jobs/job_beccf226853a0dc0\",\"synthetic\":true,\"write_committed\":false}","auth_tag":""#,
            "be2bc0d2",
            "fb46950d",
            "04de1d82",
            "342da429",
            "49b229e8",
            "415bc523",
            "044598f1",
            "9d0c9545",
            r#""}"#,
        );

        let request = fixed_fixture();
        let response = process_render_request(
            &secret(),
            &replay_cache(),
            &request,
            request.issued_at_unix_secs,
        )
        .expect("golden response should render");
        let request_json = serde_json::to_string(&request).expect("request should serialize");
        let response_json = serde_json::to_string(&response).expect("response should serialize");

        assert_eq!(request_json, GOLDEN_REQUEST_JSON);
        assert_eq!(response_json, GOLDEN_RESPONSE_JSON);
        assert_eq!(
            serde_json::from_str::<SignedControlledRealityRenderRequest>(GOLDEN_REQUEST_JSON)
                .expect("golden request should decode"),
            request
        );
        assert_eq!(
            serde_json::from_str::<SignedControlledRealityRenderResponse>(GOLDEN_RESPONSE_JSON)
                .expect("golden response should decode"),
            response
        );
    }

    #[test]
    fn remote_render_is_deterministic_and_matches_local_renderer() {
        let now = 1_000_000;
        let (request, resources) = fixture(now);
        let local = ControlledRealityResponder.render(
            request.request_kind,
            request.progress,
            Some(&resources),
        );
        let signed = process_render_request(&secret(), &replay_cache(), &request, now)
            .expect("remote response should render");
        let verified = verify_render_response(&secret(), &signed, &request, now)
            .expect("remote response should verify");

        assert_eq!(verified.status, local.status);
        assert_eq!(verified.body, local.body);
    }

    #[test]
    fn weak_secrets_are_rejected_and_debug_is_redacted() {
        assert_eq!(
            ControlledRealityBackendAuthSecret::new(vec![b'a'; 31])
                .expect_err("short secret must fail"),
            ControlledRealityBackendError::WeakSecret
        );
        assert_eq!(
            ControlledRealityBackendAuthSecret::new(vec![b'a'; 32])
                .expect_err("single-byte repeated secret must fail"),
            ControlledRealityBackendError::WeakSecret
        );
        assert_eq!(
            format!("{:?}", secret()),
            "ControlledRealityBackendAuthSecret(<redacted>)"
        );
    }

    fn collect_object_keys<'a>(value: &'a serde_json::Value, keys: &mut BTreeSet<&'a str>) {
        match value {
            serde_json::Value::Object(object) => {
                for (key, value) in object {
                    keys.insert(key);
                    collect_object_keys(value, keys);
                }
            }
            serde_json::Value::Array(values) => {
                for value in values {
                    collect_object_keys(value, keys);
                }
            }
            _ => {}
        }
    }
}
