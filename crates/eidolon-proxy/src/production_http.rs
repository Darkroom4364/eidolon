use std::{error::Error, fmt};

use bytes::Bytes;
use hyper::{
    header::{CONNECTION, CONTENT_LENGTH, EXPECT, HOST, TRAILER, TRANSFER_ENCODING, UPGRADE},
    Method, Request, Version,
};

use crate::http_request::{
    canonical_request_target, HttpHeader, HttpRequest, RequestTargetMode, RequestTargetRejection,
    MAX_HTTP_BODY_BYTES, MAX_HTTP_HEADER_BYTES,
};

pub const MAX_PRODUCTION_HEADER_COUNT: usize = 100;
pub const MAX_PRODUCTION_HEADER_BYTES: usize = MAX_HTTP_HEADER_BYTES;
pub const MAX_PRODUCTION_BODY_BYTES: usize = MAX_HTTP_BODY_BYTES;

/// Production exposes HTTP/1.1 only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProductionHttpVersion {
    Http11,
}

impl ProductionHttpVersion {
    pub const fn as_str(self) -> &'static str {
        "HTTP/1.1"
    }
}

/// Bytes and trailer presence observed while Hyper collected an inbound body.
///
/// Trailer values are deliberately never retained: unsupported trailers cannot
/// reach a processor hook or a rejection audit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionInboundBody {
    bytes: Bytes,
    trailers_observed: bool,
}

impl ProductionInboundBody {
    pub fn new(bytes: impl Into<Bytes>) -> Self {
        Self {
            bytes: bytes.into(),
            trailers_observed: false,
        }
    }

    pub fn with_observed_trailers(bytes: impl Into<Bytes>) -> Self {
        Self {
            bytes: bytes.into(),
            trailers_observed: true,
        }
    }
}

/// The fixed production transport policy. It admits HTTP/1.1 only; the Lab
/// parser and serializer are outside this boundary.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProductionHttpPolicy;

/// Request accepted by the production adapter after all boundary validation.
///
/// Its internal parsed request remains private so callers cannot create an
/// upstream-eligible request without crossing this boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionHttpRequest {
    request: HttpRequest,
    body: Bytes,
}

impl ProductionHttpRequest {
    pub fn method(&self) -> &str {
        self.request.method()
    }

    pub fn target(&self) -> &str {
        self.request.target()
    }

    pub const fn version(&self) -> ProductionHttpVersion {
        ProductionHttpVersion::Http11
    }

    pub fn headers(&self) -> &[HttpHeader] {
        self.request.headers()
    }

    pub fn body(&self) -> &[u8] {
        &self.body
    }

    pub fn body_bytes(&self) -> Bytes {
        self.body.clone()
    }

    /// Return a validated request with the named end-to-end headers removed.
    /// This preserves the cache-proof boundary without exposing a constructor.
    pub fn without_headers_case_insensitive(&self, names: &[&str]) -> Self {
        let mut request = self.request.clone();
        request.headers.retain(|header| {
            !names
                .iter()
                .any(|name| header.name.eq_ignore_ascii_case(name))
        });
        Self {
            request,
            body: self.body.clone(),
        }
    }

    /// Return a lifecycle-owned view for the existing session, policy, surface,
    /// and audit pipeline. The typed body stays private for Hyper upstream
    /// dispatch; this one copy keeps the Lab request representation isolated.
    pub fn to_lifecycle_request(&self) -> HttpRequest {
        let mut request = self.request.clone();
        request.body = self.body.to_vec();
        request
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProductionRequestRejection {
    UnsupportedHttpVersion,
    UnsupportedConnect,
    UnsupportedUpgrade,
    UnsupportedExpectation,
    UnsupportedTransferEncoding,
    UnsupportedTrailers,
    InvalidTargetForm,
    MissingHost,
    MultipleHostHeaders,
    InvalidHost,
    NonAsciiHeaderValue,
    TooManyHeaders,
    HeadersTooLarge,
    BodyTooLarge,
    MissingContentLength,
    InvalidContentLength,
    MultipleContentLengths,
    ContentLengthMismatch,
    RequestTimedOut,
    BodyReadFailed,
}

impl ProductionRequestRejection {
    pub const fn audit_code(self) -> &'static str {
        match self {
            Self::UnsupportedHttpVersion => "unsupported_http_version",
            Self::UnsupportedConnect => "unsupported_connect",
            Self::UnsupportedUpgrade => "unsupported_upgrade",
            Self::UnsupportedExpectation => "unsupported_expectation",
            Self::UnsupportedTransferEncoding => "unsupported_transfer_encoding",
            Self::UnsupportedTrailers => "unsupported_trailers",
            Self::InvalidTargetForm => "invalid_target_form",
            Self::MissingHost => "missing_host",
            Self::MultipleHostHeaders => "multiple_host_headers",
            Self::InvalidHost => "invalid_host",
            Self::NonAsciiHeaderValue => "non_ascii_header_value",
            Self::TooManyHeaders => "too_many_headers",
            Self::HeadersTooLarge => "headers_too_large",
            Self::BodyTooLarge => "body_too_large",
            Self::MissingContentLength => "missing_content_length",
            Self::InvalidContentLength => "invalid_content_length",
            Self::MultipleContentLengths => "multiple_content_lengths",
            Self::ContentLengthMismatch => "content_length_mismatch",
            Self::RequestTimedOut => "request_timed_out",
            Self::BodyReadFailed => "body_read_failed",
        }
    }

    pub const fn response_status(self) -> u16 {
        match self {
            Self::BodyTooLarge => 413,
            Self::UnsupportedExpectation => 417,
            Self::RequestTimedOut => 408,
            _ => 400,
        }
    }
}

impl fmt::Display for ProductionRequestRejection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.audit_code())
    }
}

impl Error for ProductionRequestRejection {}

/// Adapt a collected Hyper request with the fixed production HTTP/1.1 policy.
///
/// This compatibility entry point is for fully collected byte bodies. The
/// production listener uses [`ProductionHttpPolicy::adapt`] so trailer
/// presence stays visible to the boundary.
pub fn adapt_hyper_request<B>(
    request: Request<B>,
) -> Result<ProductionHttpRequest, ProductionRequestRejection>
where
    B: AsRef<[u8]>,
{
    let (parts, body) = request.into_parts();
    ProductionHttpPolicy.adapt(Request::from_parts(
        parts,
        ProductionInboundBody::new(Bytes::copy_from_slice(body.as_ref())),
    ))
}

impl ProductionHttpPolicy {
    pub fn adapt(
        self,
        request: Request<ProductionInboundBody>,
    ) -> Result<ProductionHttpRequest, ProductionRequestRejection> {
        if request.version() != Version::HTTP_11 {
            return Err(ProductionRequestRejection::UnsupportedHttpVersion);
        }
        if request.method() == Method::CONNECT {
            return Err(ProductionRequestRejection::UnsupportedConnect);
        }
        if request.body().trailers_observed {
            return Err(ProductionRequestRejection::UnsupportedTrailers);
        }

        let target = request.uri().to_string();
        let header_count = request.headers().iter().count();
        if header_count > MAX_PRODUCTION_HEADER_COUNT {
            return Err(ProductionRequestRejection::TooManyHeaders);
        }
        if encoded_head_len(&request, &target)? > MAX_PRODUCTION_HEADER_BYTES {
            return Err(ProductionRequestRejection::HeadersTooLarge);
        }

        reject_unsupported_protocol_headers(&request)?;

        let body = request.body().bytes.clone();
        if body.len() > MAX_PRODUCTION_BODY_BYTES {
            return Err(ProductionRequestRejection::BodyTooLarge);
        }
        validate_content_length(&request, body.len())?;

        let headers = request
            .headers()
            .iter()
            .map(|(name, value)| {
                let value = value.to_str().map_err(|_| {
                    if name == HOST {
                        ProductionRequestRejection::InvalidHost
                    } else {
                        ProductionRequestRejection::NonAsciiHeaderValue
                    }
                })?;
                Ok(HttpHeader {
                    name: name.as_str().to_string(),
                    value: value.to_string(),
                })
            })
            .collect::<Result<Vec<_>, ProductionRequestRejection>>()?;

        let mut adapted = HttpRequest {
            method: request.method().as_str().to_string(),
            target,
            version: crate::http_request::HttpVersion::Http11,
            headers,
            body: Vec::new(),
        };
        adapted.target = canonical_request_target(&adapted, RequestTargetMode::OriginOnly)
            .map_err(map_target_rejection)?;
        Ok(ProductionHttpRequest {
            request: adapted,
            body,
        })
    }
}

fn encoded_head_len<B>(
    request: &Request<B>,
    target: &str,
) -> Result<usize, ProductionRequestRejection> {
    let mut total = request
        .method()
        .as_str()
        .len()
        .checked_add(target.len())
        .and_then(|value| value.checked_add(16))
        .ok_or(ProductionRequestRejection::HeadersTooLarge)?;

    for (name, header_value) in request.headers() {
        total = total
            .checked_add(name.as_str().len())
            .and_then(|total| total.checked_add(header_value.as_bytes().len()))
            .and_then(|value| value.checked_add(4))
            .ok_or(ProductionRequestRejection::HeadersTooLarge)?;
    }

    total
        .checked_add(2)
        .ok_or(ProductionRequestRejection::HeadersTooLarge)
}

fn reject_unsupported_protocol_headers<B>(
    request: &Request<B>,
) -> Result<(), ProductionRequestRejection> {
    if request.headers().contains_key(UPGRADE)
        || request
            .headers()
            .get_all(CONNECTION)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .flat_map(|value| value.split(','))
            .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
    {
        return Err(ProductionRequestRejection::UnsupportedUpgrade);
    }
    if request.headers().contains_key(EXPECT) {
        return Err(ProductionRequestRejection::UnsupportedExpectation);
    }
    if request.headers().contains_key(TRANSFER_ENCODING) {
        return Err(ProductionRequestRejection::UnsupportedTransferEncoding);
    }
    if request.headers().contains_key(TRAILER) {
        return Err(ProductionRequestRejection::UnsupportedTrailers);
    }
    Ok(())
}

fn map_target_rejection(rejection: RequestTargetRejection) -> ProductionRequestRejection {
    match rejection {
        RequestTargetRejection::MissingHost => ProductionRequestRejection::MissingHost,
        RequestTargetRejection::MultipleHostHeaders => {
            ProductionRequestRejection::MultipleHostHeaders
        }
        RequestTargetRejection::InvalidHost(_) | RequestTargetRejection::AuthorityMismatch => {
            ProductionRequestRejection::InvalidHost
        }
        RequestTargetRejection::InvalidTarget(_) => ProductionRequestRejection::InvalidTargetForm,
    }
}

fn validate_content_length<B>(
    request: &Request<B>,
    body_len: usize,
) -> Result<(), ProductionRequestRejection> {
    let content_lengths = request.headers().get_all(CONTENT_LENGTH);
    let mut content_lengths = content_lengths.iter();
    let declared = content_lengths.next();
    if content_lengths.next().is_some() {
        return Err(ProductionRequestRejection::MultipleContentLengths);
    }

    let Some(declared) = declared else {
        return if body_len == 0 {
            Ok(())
        } else {
            Err(ProductionRequestRejection::MissingContentLength)
        };
    };
    let declared = declared
        .to_str()
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .ok_or(ProductionRequestRejection::InvalidContentLength)?;
    if declared > MAX_PRODUCTION_BODY_BYTES {
        return Err(ProductionRequestRejection::BodyTooLarge);
    }
    if declared != body_len {
        return Err(ProductionRequestRejection::ContentLengthMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use hyper::{
        header::{HeaderName, HeaderValue},
        Method, Request, Version,
    };

    use super::{
        adapt_hyper_request, encoded_head_len, ProductionHttpVersion, ProductionRequestRejection,
        MAX_PRODUCTION_BODY_BYTES, MAX_PRODUCTION_HEADER_BYTES, MAX_PRODUCTION_HEADER_COUNT,
    };

    fn request(method: Method, target: &str, body: Vec<u8>) -> Request<Vec<u8>> {
        let body_len = body.len();
        let mut builder = Request::builder()
            .method(method)
            .uri(target)
            .version(Version::HTTP_11)
            .header("host", "proxy.local");
        if body_len > 0 {
            builder = builder.header("content-length", body_len.to_string());
        }
        builder.body(body).expect("request should build")
    }

    fn assert_rejected_before_dispatch(
        request: Request<Vec<u8>>,
        expected: ProductionRequestRejection,
    ) {
        let dispatched = Cell::new(false);
        let result = adapt_hyper_request(request).map(|_| dispatched.set(true));
        assert_eq!(result, Err(expected));
        assert!(!dispatched.get(), "rejected request reached dispatch");
    }

    #[test]
    fn adapts_valid_http11_request_without_losing_typed_fields() {
        let request = Request::builder()
            .method("POST")
            .uri("/api/v1/imports?dry_run=true")
            .version(Version::HTTP_11)
            .header("host", "proxy.local")
            .header("content-type", "application/json")
            .header("content-length", "2")
            .body(br#"{}"#.to_vec())
            .expect("request should build");

        let adapted = adapt_hyper_request(request).expect("request should adapt");

        assert_eq!(adapted.method(), "POST");
        assert_eq!(adapted.target(), "/api/v1/imports?dry_run=true");
        assert_eq!(adapted.version(), ProductionHttpVersion::Http11);
        assert_eq!(adapted.body(), br#"{}"#);
        assert!(adapted
            .headers()
            .iter()
            .any(|header| header.name() == "content-type" && header.value() == "application/json"));
    }

    #[test]
    fn supports_only_http11() {
        let mut http10_request = request(Method::GET, "/docs", Vec::new());
        *http10_request.version_mut() = Version::HTTP_10;
        assert_rejected_before_dispatch(
            http10_request,
            ProductionRequestRejection::UnsupportedHttpVersion,
        );

        for version in [Version::HTTP_2, Version::HTTP_3] {
            let mut request = request(Method::GET, "/docs", Vec::new());
            *request.version_mut() = version;
            assert_rejected_before_dispatch(
                request,
                ProductionRequestRejection::UnsupportedHttpVersion,
            );
        }
    }

    #[test]
    fn rejects_connect_upgrades_expectations_and_unsupported_framing() {
        let connect = request(Method::CONNECT, "proxy.local:443", Vec::new());
        assert_rejected_before_dispatch(connect, ProductionRequestRejection::UnsupportedConnect);

        for (name, value, expected) in [
            (
                "upgrade",
                "websocket",
                ProductionRequestRejection::UnsupportedUpgrade,
            ),
            (
                "connection",
                "keep-alive, Upgrade",
                ProductionRequestRejection::UnsupportedUpgrade,
            ),
            (
                "expect",
                "100-continue",
                ProductionRequestRejection::UnsupportedExpectation,
            ),
            (
                "transfer-encoding",
                "chunked",
                ProductionRequestRejection::UnsupportedTransferEncoding,
            ),
            (
                "trailer",
                "x-checksum",
                ProductionRequestRejection::UnsupportedTrailers,
            ),
        ] {
            let mut request = request(Method::POST, "/api/v1/imports", Vec::new());
            request.headers_mut().append(
                HeaderName::from_bytes(name.as_bytes()).expect("header name should parse"),
                HeaderValue::from_str(value).expect("header value should parse"),
            );
            assert_rejected_before_dispatch(request, expected);
        }
    }

    #[test]
    fn rejects_unsupported_or_ambiguous_target_forms() {
        let non_options_asterisk = request(Method::GET, "*", Vec::new());
        assert_rejected_before_dispatch(
            non_options_asterisk,
            ProductionRequestRejection::InvalidTargetForm,
        );

        for target in [
            "proxy.local:443",
            "http://proxy.local/docs",
            "https://proxy.local/docs",
            "//proxy.local/docs",
        ] {
            let request = request(Method::GET, target, Vec::new());
            assert_rejected_before_dispatch(request, ProductionRequestRejection::InvalidTargetForm);
        }

        let options = request(Method::OPTIONS, "*", Vec::new());
        assert!(adapt_hyper_request(options).is_ok());

        for target in [
            "/a/../b",
            "/api%2Fops",
            "/a//b",
            "/docs;parameter",
            "/%2e%2e/etc",
        ] {
            let request = request(Method::GET, target, Vec::new());
            assert_rejected_before_dispatch(request, ProductionRequestRejection::InvalidTargetForm);
        }
    }

    #[test]
    fn returns_the_shared_canonical_target() {
        let request = request(
            Method::GET,
            "/api/v2/import/recon%63ile?label=%7e",
            Vec::new(),
        );
        let adapted = adapt_hyper_request(request).expect("canonical target should adapt");

        assert_eq!(
            adapted.target(),
            "/api/v2/import/reconcile?label=~",
            "production dispatch must consume the shared canonical spelling"
        );
    }

    #[test]
    fn rejects_missing_duplicate_empty_and_non_ascii_host() {
        let mut missing = request(Method::GET, "/docs", Vec::new());
        missing.headers_mut().remove("host");
        assert_rejected_before_dispatch(missing, ProductionRequestRejection::MissingHost);

        let mut duplicate = request(Method::GET, "/docs", Vec::new());
        duplicate
            .headers_mut()
            .append("host", HeaderValue::from_static("other.local"));
        assert_rejected_before_dispatch(duplicate, ProductionRequestRejection::MultipleHostHeaders);

        let mut empty = request(Method::GET, "/docs", Vec::new());
        empty
            .headers_mut()
            .insert("host", HeaderValue::from_static(""));
        assert_rejected_before_dispatch(empty, ProductionRequestRejection::InvalidHost);

        let mut non_ascii = request(Method::GET, "/docs", Vec::new());
        non_ascii.headers_mut().insert(
            "host",
            HeaderValue::from_bytes(&[0x80]).expect("opaque header bytes should build"),
        );
        assert_rejected_before_dispatch(non_ascii, ProductionRequestRejection::InvalidHost);

        for value in [
            "user@proxy.local",
            "proxy.local:0",
            "proxy.local:invalid",
            "[::1",
            "proxy.local/path",
        ] {
            let mut malformed = request(Method::GET, "/docs", Vec::new());
            malformed.headers_mut().insert(
                "host",
                HeaderValue::from_str(value).expect("opaque Host value should build"),
            );
            assert_rejected_before_dispatch(malformed, ProductionRequestRejection::InvalidHost);
        }
    }

    #[test]
    fn accepts_valid_dns_ip_and_port_host_authorities() {
        for value in [
            "proxy.local",
            "proxy.local:8080",
            "127.0.0.1",
            "127.0.0.1:8080",
            "[::1]",
            "[::1]:8080",
        ] {
            let mut request = request(Method::GET, "/docs", Vec::new());
            request.headers_mut().insert(
                "host",
                HeaderValue::from_str(value).expect("valid Host value should build"),
            );
            adapt_hyper_request(request).expect("valid Host authority should adapt");
        }
    }

    #[test]
    fn rejects_non_ascii_end_to_end_header_values() {
        let mut request = request(Method::GET, "/docs", Vec::new());
        request.headers_mut().insert(
            "x-test",
            HeaderValue::from_bytes(&[0x80]).expect("opaque header bytes should build"),
        );
        assert_rejected_before_dispatch(request, ProductionRequestRejection::NonAsciiHeaderValue);
    }

    #[test]
    fn enforces_header_count_and_encoded_size_limits() {
        let mut exact_count = request(Method::GET, "/docs", Vec::new());
        for index in 0..MAX_PRODUCTION_HEADER_COUNT - 1 {
            let name = HeaderName::from_bytes(format!("x-exact-{index}").as_bytes())
                .expect("header name should parse");
            exact_count
                .headers_mut()
                .insert(name, HeaderValue::from_static("1"));
        }
        adapt_hyper_request(exact_count).expect("exact header count limit should be accepted");

        let mut too_many = request(Method::GET, "/docs", Vec::new());
        for index in 0..MAX_PRODUCTION_HEADER_COUNT {
            let name = HeaderName::from_bytes(format!("x-limit-{index}").as_bytes())
                .expect("header name should parse");
            too_many
                .headers_mut()
                .insert(name, HeaderValue::from_static("1"));
        }
        assert_rejected_before_dispatch(too_many, ProductionRequestRejection::TooManyHeaders);

        let mut too_large = request(Method::GET, "/docs", Vec::new());
        let value = "a".repeat(MAX_PRODUCTION_HEADER_BYTES);
        too_large.headers_mut().insert(
            "x-large",
            HeaderValue::from_str(&value).expect("large header should build"),
        );
        assert_rejected_before_dispatch(too_large, ProductionRequestRejection::HeadersTooLarge);

        let mut exact_size = request(Method::GET, "/docs", Vec::new());
        let target = exact_size.uri().to_string();
        let current_size =
            encoded_head_len(&exact_size, &target).expect("base request size should fit");
        let padding_name = "x-pad";
        let padding_len = MAX_PRODUCTION_HEADER_BYTES
            .checked_sub(current_size + padding_name.len() + 4)
            .expect("production header budget should fit padding");
        exact_size.headers_mut().insert(
            padding_name,
            HeaderValue::from_str(&"a".repeat(padding_len))
                .expect("exact-limit header should build"),
        );
        assert_eq!(
            encoded_head_len(&exact_size, &target).expect("exact request size should calculate"),
            MAX_PRODUCTION_HEADER_BYTES
        );
        adapt_hyper_request(exact_size).expect("exact header byte limit should be accepted");
    }

    #[test]
    fn enforces_unambiguous_bounded_content_length() {
        let mut missing = request(Method::POST, "/api/v1/imports", b"data".to_vec());
        missing.headers_mut().remove("content-length");
        assert_rejected_before_dispatch(missing, ProductionRequestRejection::MissingContentLength);

        let mut invalid = request(Method::POST, "/api/v1/imports", Vec::new());
        invalid
            .headers_mut()
            .insert("content-length", HeaderValue::from_static("invalid"));
        assert_rejected_before_dispatch(invalid, ProductionRequestRejection::InvalidContentLength);

        let mut duplicate = request(Method::POST, "/api/v1/imports", b"data".to_vec());
        duplicate
            .headers_mut()
            .append("content-length", HeaderValue::from_static("4"));
        assert_rejected_before_dispatch(
            duplicate,
            ProductionRequestRejection::MultipleContentLengths,
        );

        let mut mismatch = request(Method::POST, "/api/v1/imports", b"data".to_vec());
        mismatch
            .headers_mut()
            .insert("content-length", HeaderValue::from_static("3"));
        assert_rejected_before_dispatch(
            mismatch,
            ProductionRequestRejection::ContentLengthMismatch,
        );

        let mut declared_too_large = request(Method::POST, "/api/v1/imports", Vec::new());
        declared_too_large.headers_mut().insert(
            "content-length",
            HeaderValue::from_str(&(MAX_PRODUCTION_BODY_BYTES + 1).to_string())
                .expect("length should build"),
        );
        assert_rejected_before_dispatch(
            declared_too_large,
            ProductionRequestRejection::BodyTooLarge,
        );
    }

    #[test]
    fn rejects_actual_body_above_limit_before_dispatch() {
        let exact = request(
            Method::POST,
            "/api/v1/imports",
            vec![b'x'; MAX_PRODUCTION_BODY_BYTES],
        );
        assert_eq!(
            adapt_hyper_request(exact)
                .expect("exact body limit should be accepted")
                .body()
                .len(),
            MAX_PRODUCTION_BODY_BYTES
        );

        let body = vec![b'x'; MAX_PRODUCTION_BODY_BYTES + 1];
        let request = request(Method::POST, "/api/v1/imports", body);
        assert_rejected_before_dispatch(request, ProductionRequestRejection::BodyTooLarge);
    }

    #[test]
    fn rejection_statuses_are_explicit_and_safe_to_expose() {
        assert_eq!(
            ProductionRequestRejection::BodyTooLarge.response_status(),
            413
        );
        assert_eq!(
            ProductionRequestRejection::UnsupportedExpectation.response_status(),
            417
        );
        assert_eq!(
            ProductionRequestRejection::UnsupportedUpgrade.response_status(),
            400
        );
        assert_eq!(
            ProductionRequestRejection::UnsupportedUpgrade.to_string(),
            "unsupported_upgrade"
        );
    }
}
