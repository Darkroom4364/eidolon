use std::{error::Error, fmt};

use http::uri::Authority;
use hyper::{
    header::{CONNECTION, CONTENT_LENGTH, EXPECT, HOST, TRAILER, TRANSFER_ENCODING, UPGRADE},
    Method, Request, Version,
};

pub const MAX_PRODUCTION_HEADER_COUNT: usize = 100;
pub const MAX_PRODUCTION_HEADER_BYTES: usize = 64 * 1024;
pub const MAX_PRODUCTION_BODY_BYTES: usize = 10 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProductionHttpVersion {
    Http10,
    Http11,
}

impl ProductionHttpVersion {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Http10 => "HTTP/1.0",
            Self::Http11 => "HTTP/1.1",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionHttpHeader {
    name: String,
    value: String,
}

impl ProductionHttpHeader {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn value(&self) -> &str {
        &self.value
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionHttpRequest {
    method: String,
    target: String,
    version: ProductionHttpVersion,
    headers: Vec<ProductionHttpHeader>,
    body: Vec<u8>,
}

impl ProductionHttpRequest {
    pub fn method(&self) -> &str {
        &self.method
    }

    pub fn target(&self) -> &str {
        &self.target
    }

    pub fn version(&self) -> ProductionHttpVersion {
        self.version
    }

    pub fn headers(&self) -> &[ProductionHttpHeader] {
        &self.headers
    }

    pub fn body(&self) -> &[u8] {
        &self.body
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
}

impl ProductionRequestRejection {
    pub fn audit_code(self) -> &'static str {
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
        }
    }

    pub fn response_status(self) -> u16 {
        match self {
            Self::BodyTooLarge => 413,
            Self::UnsupportedExpectation => 417,
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

/// Convert a request parsed by Hyper into the only request shape that the
/// production policy path may consume. The runtime activation slice will
/// collect Hyper's body into bytes before calling this boundary.
///
/// This adapter deliberately supports less than Hyper can parse. Unsupported
/// protocol features fail before request evaluation or upstream dispatch.
pub fn adapt_hyper_request<B>(
    request: Request<B>,
) -> Result<ProductionHttpRequest, ProductionRequestRejection>
where
    B: AsRef<[u8]>,
{
    let version = match request.version() {
        Version::HTTP_10 => ProductionHttpVersion::Http10,
        Version::HTTP_11 => ProductionHttpVersion::Http11,
        _ => return Err(ProductionRequestRejection::UnsupportedHttpVersion),
    };
    if request.method() == Method::CONNECT {
        return Err(ProductionRequestRejection::UnsupportedConnect);
    }

    let target = request.uri().to_string();
    validate_target_form(request.method(), &target)?;

    let header_count = request.headers().iter().count();
    if header_count > MAX_PRODUCTION_HEADER_COUNT {
        return Err(ProductionRequestRejection::TooManyHeaders);
    }
    if encoded_head_len(&request, &target)? > MAX_PRODUCTION_HEADER_BYTES {
        return Err(ProductionRequestRejection::HeadersTooLarge);
    }

    reject_unsupported_protocol_headers(&request)?;
    validate_host(&request)?;

    let body = request.body().as_ref();
    if body.len() > MAX_PRODUCTION_BODY_BYTES {
        return Err(ProductionRequestRejection::BodyTooLarge);
    }
    validate_content_length(&request, body.len())?;

    let headers = request
        .headers()
        .iter()
        .map(|(name, value)| {
            let value = value
                .to_str()
                .map_err(|_| ProductionRequestRejection::NonAsciiHeaderValue)?;
            Ok(ProductionHttpHeader {
                name: name.as_str().to_string(),
                value: value.to_string(),
            })
        })
        .collect::<Result<Vec<_>, ProductionRequestRejection>>()?;

    Ok(ProductionHttpRequest {
        method: request.method().as_str().to_string(),
        target,
        version,
        headers,
        body: body.to_vec(),
    })
}

fn validate_target_form(method: &Method, target: &str) -> Result<(), ProductionRequestRejection> {
    if target == "*" {
        return if method == Method::OPTIONS {
            Ok(())
        } else {
            Err(ProductionRequestRejection::InvalidTargetForm)
        };
    }
    if target.starts_with('/') && !target.starts_with("//") {
        return Ok(());
    }
    Err(ProductionRequestRejection::InvalidTargetForm)
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

fn validate_host<B>(request: &Request<B>) -> Result<(), ProductionRequestRejection> {
    let hosts = request.headers().get_all(HOST);
    let mut hosts = hosts.iter();
    let host = hosts
        .next()
        .ok_or(ProductionRequestRejection::MissingHost)?;
    if hosts.next().is_some() {
        return Err(ProductionRequestRejection::MultipleHostHeaders);
    }
    let host = host
        .to_str()
        .map_err(|_| ProductionRequestRejection::InvalidHost)?;
    let authority = host
        .parse::<Authority>()
        .map_err(|_| ProductionRequestRejection::InvalidHost)?;
    let canonical_len = authority.host().len()
        + authority
            .port()
            .map(|port| 1 + port.as_str().len())
            .unwrap_or(0);
    if host.contains('@')
        || authority.port_u16() == Some(0)
        || canonical_len != authority.as_str().len()
    {
        return Err(ProductionRequestRejection::InvalidHost);
    }
    Ok(())
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
        adapt_hyper_request, ProductionHttpVersion, ProductionRequestRejection,
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
    fn supports_only_http10_and_http11() {
        let mut http10_request = request(Method::GET, "/docs", Vec::new());
        *http10_request.version_mut() = Version::HTTP_10;
        assert_eq!(
            adapt_hyper_request(http10_request)
                .expect("HTTP/1.0 request should adapt")
                .version(),
            ProductionHttpVersion::Http10
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
