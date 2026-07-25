use std::{
    error::Error,
    fmt,
    net::{IpAddr, Ipv6Addr},
};

pub const MAX_HTTP_HEADER_BYTES: usize = 64 * 1024;
pub const MAX_HTTP_BODY_BYTES: usize = 10 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpVersion {
    Http10,
    Http11,
}

impl HttpVersion {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Http10 => "HTTP/1.0",
            Self::Http11 => "HTTP/1.1",
        }
    }
}

impl fmt::Display for HttpVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpHeader {
    pub name: String,
    pub value: String,
}

impl HttpHeader {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn value(&self) -> &str {
        &self.value
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Parsed request data before canonical target validation.
///
/// Transport adapters must not treat this type itself as proof that a request
/// is safe to dispatch.
pub struct HttpRequest {
    pub method: String,
    pub target: String,
    pub version: HttpVersion,
    pub headers: Vec<HttpHeader>,
    pub body: Vec<u8>,
}

impl HttpRequest {
    pub fn method(&self) -> &str {
        &self.method
    }

    pub fn target(&self) -> &str {
        &self.target
    }

    pub fn version(&self) -> HttpVersion {
        self.version
    }

    pub fn headers(&self) -> &[HttpHeader] {
        &self.headers
    }

    pub fn body(&self) -> &[u8] {
        &self.body
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestTargetMode {
    OriginOnly,
    OriginOrAbsoluteHttp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestTargetRejection {
    InvalidTarget(&'static str),
    MissingHost,
    MultipleHostHeaders,
    InvalidHost(&'static str),
    AuthorityMismatch,
}

impl fmt::Display for RequestTargetRejection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTarget(message) | Self::InvalidHost(message) => {
                formatter.write_str(message)
            }
            Self::MissingHost => {
                formatter.write_str("HTTP request must contain exactly one Host header")
            }
            Self::MultipleHostHeaders => {
                formatter.write_str("HTTP request must contain exactly one Host header")
            }
            Self::AuthorityMismatch => {
                formatter.write_str("HTTP absolute-form authority conflicts with the Host header")
            }
        }
    }
}

impl Error for RequestTargetRejection {}

/// Return the single target representation used by policy, forwarding,
/// logging, and export after validating the request's Host relationship.
pub fn canonical_request_target(
    request: &HttpRequest,
    mode: RequestTargetMode,
) -> Result<String, RequestTargetRejection> {
    if request.target == "*" && !request.method.eq_ignore_ascii_case("OPTIONS") {
        return Err(RequestTargetRejection::InvalidTarget(
            "HTTP asterisk-form request target is only valid for OPTIONS",
        ));
    }
    if mode == RequestTargetMode::OriginOnly
        && request.target != "*"
        && !request.target.starts_with('/')
    {
        return Err(RequestTargetRejection::InvalidTarget(
            "HTTP request target must use origin-form",
        ));
    }

    let target = canonicalize_request_target(&request.target)?;
    let host_header = validated_request_host_header(request)?;
    let host_authority = normalized_request_authority(host_header)?;
    if let Some(target_authority) = request_host_from_target(&request.target) {
        if mode == RequestTargetMode::OriginOnly {
            return Err(RequestTargetRejection::InvalidTarget(
                "HTTP request target must use origin-form",
            ));
        }
        let target_authority = normalized_request_authority(target_authority)?;
        if target_authority != host_authority {
            return Err(RequestTargetRejection::AuthorityMismatch);
        }
    }

    Ok(target)
}

pub fn validated_request_host_header(
    request: &HttpRequest,
) -> Result<&str, RequestTargetRejection> {
    let mut host_headers = request
        .headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("host"))
        .map(|header| header.value.trim());
    let host = host_headers
        .next()
        .ok_or(RequestTargetRejection::MissingHost)?;
    if host_headers.next().is_some() {
        return Err(RequestTargetRejection::MultipleHostHeaders);
    }
    validate_request_authority(host)?;
    Ok(host)
}

pub fn normalized_request_host(request: &HttpRequest) -> Result<String, RequestTargetRejection> {
    let host = validated_request_host_header(request)?;
    normalized_request_authority(host).map(|authority| authority.0)
}

/// Canonicalize a target without decoding reserved bytes or guessing how an
/// upstream server would interpret an ambiguous spelling.
pub fn canonicalize_request_target(target: &str) -> Result<String, RequestTargetRejection> {
    if target
        .bytes()
        .any(|byte| matches!(byte, 0x00..=0x20 | 0x7F..=0xFF))
    {
        return Err(RequestTargetRejection::InvalidTarget(
            "HTTP request target contains whitespace, control, or non-ASCII bytes",
        ));
    }
    if target.contains('\\') {
        return Err(RequestTargetRejection::InvalidTarget(
            "HTTP request target must not contain backslashes",
        ));
    }
    if target.contains('#') {
        return Err(RequestTargetRejection::InvalidTarget(
            "HTTP request target must not contain a fragment",
        ));
    }

    let normalized = request_target_origin_form(target)?;
    if normalized == "*" {
        return Ok(normalized);
    }

    let (raw_path, query) = match normalized.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (normalized.as_str(), None),
    };
    if raw_path.starts_with("//") {
        return Err(RequestTargetRejection::InvalidTarget(
            "HTTP request target path must not start with `//`",
        ));
    }

    let mut path = String::with_capacity(raw_path.len());
    let raw_bytes = raw_path.as_bytes();
    let mut index = 0;
    while index < raw_bytes.len() {
        let byte = raw_bytes[index];
        match byte {
            b'%' => {
                if index + 2 >= raw_bytes.len() {
                    return Err(RequestTargetRejection::InvalidTarget(
                        "HTTP request target contains a truncated percent encoding",
                    ));
                }
                let high = hex_value(raw_bytes[index + 1]).ok_or(
                    RequestTargetRejection::InvalidTarget(
                        "HTTP request target contains an invalid percent encoding",
                    ),
                )?;
                let low = hex_value(raw_bytes[index + 2]).ok_or(
                    RequestTargetRejection::InvalidTarget(
                        "HTTP request target contains an invalid percent encoding",
                    ),
                )?;
                let decoded = (high << 4) | low;
                if is_unreserved_path_byte(decoded) {
                    path.push(decoded as char);
                } else {
                    return Err(RequestTargetRejection::InvalidTarget(
                        "HTTP request target contains a percent-encoded byte outside the unreserved set",
                    ));
                }
                index += 3;
            }
            _ => {
                if !is_raw_path_byte(byte) {
                    return Err(RequestTargetRejection::InvalidTarget(
                        "HTTP request target path contains a character outside the URI path grammar",
                    ));
                }
                path.push(byte as char);
                index += 1;
            }
        }
    }

    if path.contains("//") {
        return Err(RequestTargetRejection::InvalidTarget(
            "HTTP request target path must not contain empty interior segments (`//`)",
        ));
    }
    if path
        .split('/')
        .any(|segment| segment == "." || segment == "..")
    {
        return Err(RequestTargetRejection::InvalidTarget(
            "HTTP request target path must not contain dot segments",
        ));
    }

    Ok(match query {
        Some(query) => format!("{path}?{}", canonicalize_request_query(query)?),
        None => path,
    })
}

fn canonicalize_request_query(query: &str) -> Result<String, RequestTargetRejection> {
    let bytes = query.as_bytes();
    let mut canonical = String::with_capacity(query.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            if !is_raw_query_byte(bytes[index]) {
                return Err(RequestTargetRejection::InvalidTarget(
                    "HTTP request query contains a character outside the URI query grammar",
                ));
            }
            canonical.push(bytes[index] as char);
            index += 1;
            continue;
        }
        if index + 2 >= bytes.len() {
            return Err(RequestTargetRejection::InvalidTarget(
                "HTTP request query contains a truncated percent encoding",
            ));
        }
        let high = hex_value(bytes[index + 1]).ok_or(RequestTargetRejection::InvalidTarget(
            "HTTP request query contains an invalid percent encoding",
        ))?;
        let low = hex_value(bytes[index + 2]).ok_or(RequestTargetRejection::InvalidTarget(
            "HTTP request query contains an invalid percent encoding",
        ))?;
        let decoded = (high << 4) | low;
        if is_unreserved_path_byte(decoded) {
            canonical.push(decoded as char);
        } else {
            const HEX: &[u8; 16] = b"0123456789ABCDEF";
            canonical.push('%');
            canonical.push(HEX[(decoded >> 4) as usize] as char);
            canonical.push(HEX[(decoded & 0x0F) as usize] as char);
        }
        index += 3;
    }
    Ok(canonical)
}

fn request_target_origin_form(target: &str) -> Result<String, RequestTargetRejection> {
    if target.is_empty() {
        return Err(RequestTargetRejection::InvalidTarget(
            "HTTP request target cannot be empty",
        ));
    }
    if target == "*" {
        return Ok(target.to_string());
    }
    if target.starts_with('/') {
        return Ok(target.to_string());
    }

    let Some(rest) = target.strip_prefix("http://") else {
        return Err(RequestTargetRejection::InvalidTarget(
            "HTTP request target must be origin-form or http absolute-form",
        ));
    };
    let suffix_index = rest
        .char_indices()
        .find_map(|(index, character)| matches!(character, '/' | '?').then_some(index))
        .unwrap_or(rest.len());
    let authority = &rest[..suffix_index];
    validate_request_authority(authority)?;

    let suffix = &rest[suffix_index..];
    if suffix.is_empty() {
        Ok("/".to_string())
    } else if suffix.starts_with('?') {
        Ok(format!("/{suffix}"))
    } else {
        Ok(suffix.to_string())
    }
}

fn normalized_request_authority(authority: &str) -> Result<(String, u16), RequestTargetRejection> {
    let (host, port) = validate_request_authority(authority)?;
    Ok((host.to_ascii_lowercase(), port.unwrap_or(80)))
}

fn validate_request_authority(
    authority: &str,
) -> Result<(&str, Option<u16>), RequestTargetRejection> {
    if authority.is_empty() {
        return Err(RequestTargetRejection::InvalidHost(
            "HTTP request authority must not be empty",
        ));
    }
    if authority.contains('@') || authority.contains('%') {
        return Err(RequestTargetRejection::InvalidHost(
            "HTTP request authority must not contain userinfo or percent encoding",
        ));
    }

    let (host, port) = parse_request_authority(authority)?;
    if port == Some(0) {
        return Err(RequestTargetRejection::InvalidHost(
            "HTTP request authority port must not be 0",
        ));
    }

    if authority.starts_with('[') {
        host.parse::<Ipv6Addr>().map_err(|_| {
            RequestTargetRejection::InvalidHost(
                "HTTP bracketed authority must contain a valid IPv6 address",
            )
        })?;
        return Ok((host, port));
    }
    if host.parse::<IpAddr>().is_ok() {
        return Ok((host, port));
    }
    if host.split('.').any(|label| {
        label.is_empty()
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            || !label
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
            || !label
                .as_bytes()
                .last()
                .is_some_and(u8::is_ascii_alphanumeric)
    }) {
        return Err(RequestTargetRejection::InvalidHost(
            "HTTP request authority has an invalid host",
        ));
    }

    Ok((host, port))
}

fn parse_request_authority(authority: &str) -> Result<(&str, Option<u16>), RequestTargetRejection> {
    if let Some(rest) = authority.strip_prefix('[') {
        let Some(close_index) = rest.find(']') else {
            return Err(RequestTargetRejection::InvalidHost(
                "HTTP IPv6 authority must close the `]` bracket",
            ));
        };
        let host = &rest[..close_index];
        let suffix = &rest[close_index + 1..];
        let port = if suffix.is_empty() {
            None
        } else if let Some(raw_port) = suffix.strip_prefix(':') {
            Some(parse_request_port(raw_port)?)
        } else {
            return Err(RequestTargetRejection::InvalidHost(
                "HTTP authority must put the port after the IPv6 host bracket",
            ));
        };
        if host.is_empty() {
            return Err(RequestTargetRejection::InvalidHost(
                "HTTP request authority host must not be empty",
            ));
        }
        return Ok((host, port));
    }

    if authority.matches(':').count() > 1 {
        return Err(RequestTargetRejection::InvalidHost(
            "HTTP IPv6 authority hosts must be bracketed",
        ));
    }
    if let Some((host, raw_port)) = authority.rsplit_once(':') {
        if host.is_empty() {
            return Err(RequestTargetRejection::InvalidHost(
                "HTTP request authority host must not be empty",
            ));
        }
        return Ok((host, Some(parse_request_port(raw_port)?)));
    }
    Ok((authority, None))
}

fn parse_request_port(raw: &str) -> Result<u16, RequestTargetRejection> {
    if raw.is_empty() {
        return Err(RequestTargetRejection::InvalidHost(
            "HTTP request authority port must not be empty",
        ));
    }
    raw.parse::<u16>().map_err(|_| {
        RequestTargetRejection::InvalidHost("HTTP request authority port must be a valid TCP port")
    })
}

fn request_host_from_target(target: &str) -> Option<&str> {
    let rest = target.strip_prefix("http://")?;
    let end = rest
        .char_indices()
        .find_map(|(index, character)| matches!(character, '/' | '?').then_some(index))
        .unwrap_or(rest.len());
    Some(&rest[..end])
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn is_unreserved_path_byte(byte: u8) -> bool {
    matches!(
        byte,
        b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~'
    )
}

fn is_sub_delimiter(byte: u8) -> bool {
    matches!(
        byte,
        b'!' | b'$' | b'&' | b'\'' | b'(' | b')' | b'*' | b'+' | b',' | b';' | b'='
    )
}

fn is_raw_path_byte(byte: u8) -> bool {
    is_unreserved_path_byte(byte)
        || (is_sub_delimiter(byte) && byte != b';')
        || matches!(byte, b':' | b'@' | b'/')
}

fn is_raw_query_byte(byte: u8) -> bool {
    is_raw_path_byte(byte) || byte == b'?'
}

#[cfg(test)]
mod tests {
    use super::{
        canonical_request_target, canonicalize_request_target, HttpHeader, HttpRequest,
        HttpVersion, RequestTargetMode, RequestTargetRejection,
    };

    fn request(method: &str, target: &str, host: &str) -> HttpRequest {
        HttpRequest {
            method: method.to_string(),
            target: target.to_string(),
            version: HttpVersion::Http11,
            headers: vec![HttpHeader {
                name: "Host".to_string(),
                value: host.to_string(),
            }],
            body: Vec::new(),
        }
    }

    #[test]
    fn both_modes_share_canonical_origin_form_validation() {
        let request = request("GET", "/api/v2/import/recon%63ile?x=%7e", "proxy.local");
        for mode in [
            RequestTargetMode::OriginOnly,
            RequestTargetMode::OriginOrAbsoluteHttp,
        ] {
            assert_eq!(
                canonical_request_target(&request, mode).expect("target should validate"),
                "/api/v2/import/reconcile?x=~"
            );
        }
    }

    #[test]
    fn absolute_form_is_an_explicit_lab_compatibility_difference() {
        let request = request("GET", "http://proxy.local/docs", "proxy.local:80");
        assert_eq!(
            canonical_request_target(&request, RequestTargetMode::OriginOrAbsoluteHttp)
                .expect("matching absolute form should validate"),
            "/docs"
        );
        assert!(matches!(
            canonical_request_target(&request, RequestTargetMode::OriginOnly),
            Err(RequestTargetRejection::InvalidTarget(_))
        ));
    }

    #[test]
    fn rejects_host_confusion_and_ambiguous_targets() {
        let mismatch = request("GET", "http://proxy.local/docs", "other.local");
        assert_eq!(
            canonical_request_target(&mismatch, RequestTargetMode::OriginOrAbsoluteHttp),
            Err(RequestTargetRejection::AuthorityMismatch)
        );

        for target in [
            "/a/../b",
            "/api%2Fops",
            "/docs#fragment",
            "/a//b",
            "/docs;parameter",
        ] {
            assert!(
                canonicalize_request_target(target).is_err(),
                "{target} must be rejected"
            );
        }
    }

    #[test]
    fn canonicalization_is_idempotent_for_every_accepted_ascii_percent_byte() {
        for byte in 0_u8..=127 {
            let target = format!("/a%{byte:02X}b");
            if let Ok(canonical) = canonicalize_request_target(&target) {
                assert_eq!(
                    canonicalize_request_target(&canonical)
                        .expect("canonical target should remain valid"),
                    canonical
                );
            }
        }
    }
}
