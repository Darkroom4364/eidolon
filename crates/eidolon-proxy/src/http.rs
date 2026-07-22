//! HTTP/1.1 request and response protocol handling for the proxy.

use std::{
    fmt,
    io::{self, Read, Write},
    net::IpAddr,
};

pub const DEFAULT_HTTP_PORT: u16 = 80;
pub const MAX_HEADER_BYTES: usize = 64 * 1024;
pub const MAX_BODY_BYTES: usize = 10 * 1024 * 1024;

/// Loopback HTTP upstream target URL parts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamTarget {
    pub raw: String,
    pub authority: String,
    pub connect_addr: String,
}

impl fmt::Display for UpstreamTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.raw)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequest {
    pub method: String,
    pub target: String,
    pub version: String,
    pub headers: Vec<HttpHeader>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpHeader {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub version: String,
    pub status: u16,
    pub reason: String,
    pub headers: Vec<HttpHeader>,
    pub body: Vec<u8>,
}

impl HttpRequest {
    pub fn to_upstream_bytes(&self, upstream: &UpstreamTarget) -> io::Result<Vec<u8>> {
        let target = normalize_request_target(&self.target)?;
        let connection_nominated_headers = connection_nominated_headers(&self.headers);
        let should_emit_content_length = !self.body.is_empty()
            || self
                .headers
                .iter()
                .any(|header| header.name.eq_ignore_ascii_case("content-length"));
        let mut bytes = Vec::new();

        write!(
            bytes,
            "{} {} {}\r\nHost: {}\r\nConnection: close\r\n",
            self.method, target, self.version, upstream.authority
        )?;

        if should_emit_content_length {
            write!(bytes, "Content-Length: {}\r\n", self.body.len())?;
        }

        for header in &self.headers {
            if should_skip_forwarded_header(&header.name, &connection_nominated_headers) {
                continue;
            }

            write!(bytes, "{}: {}\r\n", header.name, header.value)?;
        }

        bytes.extend_from_slice(b"\r\n");
        bytes.extend_from_slice(&self.body);
        Ok(bytes)
    }
}

impl HttpResponse {
    pub fn to_http_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        write!(
            bytes,
            "{} {} {}\r\n",
            self.version, self.status, self.reason
        )
        .expect("writing to Vec should not fail");

        for header in &self.headers {
            write!(bytes, "{}: {}\r\n", header.name, header.value)
                .expect("writing to Vec should not fail");
        }

        bytes.extend_from_slice(b"\r\n");
        bytes.extend_from_slice(&self.body);
        bytes
    }

    pub fn set_header(&mut self, name: impl Into<String>, value: impl Into<String>) {
        let name = name.into();
        let value = value.into();
        self.remove_header(&name);
        self.headers.push(HttpHeader { name, value });
    }

    pub fn remove_header(&mut self, name: &str) {
        self.headers
            .retain(|header| !header.name.eq_ignore_ascii_case(name));
    }

    pub fn append_header(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.headers.push(HttpHeader {
            name: name.into(),
            value: value.into(),
        });
    }
}

pub fn read_http_request<R>(reader: &mut R) -> io::Result<Option<HttpRequest>>
where
    R: Read,
{
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 1024];
    let header_end = loop {
        let bytes_read = reader.read(&mut chunk)?;
        if bytes_read == 0 {
            if buffer.is_empty() {
                return Ok(None);
            }

            return Err(invalid_data(
                "connection closed before HTTP headers completed",
            ));
        }

        buffer.extend_from_slice(&chunk[..bytes_read]);
        if buffer.len() > MAX_HEADER_BYTES {
            return Err(invalid_data("HTTP request headers exceed size limit"));
        }

        if let Some(header_end) = find_header_end(&buffer) {
            break header_end;
        }
    };

    let head = &buffer[..header_end - 4];
    let mut request = parse_http_request_head(head)?;
    let content_length = request_content_length(&request)?;
    if content_length > MAX_BODY_BYTES {
        return Err(invalid_data("HTTP request body exceeds size limit"));
    }

    let body_start = header_end;
    request
        .body
        .extend_from_slice(&buffer[body_start..buffer.len().min(body_start + content_length)]);

    while request.body.len() < content_length {
        let remaining = content_length - request.body.len();
        let read_len = remaining.min(chunk.len());
        let bytes_read = reader.read(&mut chunk[..read_len])?;
        if bytes_read == 0 {
            return Err(invalid_data("connection closed before HTTP body completed"));
        }

        request.body.extend_from_slice(&chunk[..bytes_read]);
    }

    Ok(Some(request))
}

pub fn read_http_response<R>(reader: &mut R) -> io::Result<HttpResponse>
where
    R: Read,
{
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 1024];
    let header_end = loop {
        let bytes_read = reader.read(&mut chunk)?;
        if bytes_read == 0 {
            return Err(invalid_data(
                "connection closed before HTTP response headers completed",
            ));
        }

        buffer.extend_from_slice(&chunk[..bytes_read]);
        if buffer.len() > MAX_HEADER_BYTES {
            return Err(invalid_data("HTTP response headers exceed size limit"));
        }

        if let Some(header_end) = find_header_end(&buffer) {
            break header_end;
        }
    };

    let head = &buffer[..header_end - 4];
    let mut response = parse_http_response_head(head)?;
    let body_start = header_end;
    response.body.extend_from_slice(&buffer[body_start..]);

    match response_transfer_coding(&response)? {
        ResponseTransferCoding::Identity => {
            if let Some(content_length) = response_content_length(&response)? {
                if content_length > MAX_BODY_BYTES {
                    return Err(invalid_data("HTTP response body exceeds size limit"));
                }

                if response.body.len() > content_length {
                    response.body.truncate(content_length);
                }

                while response.body.len() < content_length {
                    let remaining = content_length - response.body.len();
                    let read_len = remaining.min(chunk.len());
                    let bytes_read = reader.read(&mut chunk[..read_len])?;
                    if bytes_read == 0 {
                        return Err(invalid_data(
                            "connection closed before HTTP response body completed",
                        ));
                    }

                    response.body.extend_from_slice(&chunk[..bytes_read]);
                }
            } else {
                while response.body.len() <= MAX_BODY_BYTES {
                    let bytes_read = reader.read(&mut chunk)?;
                    if bytes_read == 0 {
                        return Ok(response);
                    }

                    response.body.extend_from_slice(&chunk[..bytes_read]);
                }

                return Err(invalid_data("HTTP response body exceeds size limit"));
            }
        }
        ResponseTransferCoding::Chunked => {
            response.body = read_chunked_response_body(reader, response.body)?;
        }
    }

    Ok(response)
}

pub fn parse_http_request_head(head: &[u8]) -> io::Result<HttpRequest> {
    let head = std::str::from_utf8(head).map_err(|_| invalid_data("HTTP headers are not UTF-8"))?;
    let mut lines = head.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| invalid_data("missing HTTP request line"))?;
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts
        .next()
        .ok_or_else(|| invalid_data("missing HTTP method"))?;
    let target = request_parts
        .next()
        .ok_or_else(|| invalid_data("missing HTTP request target"))?;
    let version = request_parts
        .next()
        .ok_or_else(|| invalid_data("missing HTTP version"))?;

    if request_parts.next().is_some() {
        return Err(invalid_data("HTTP request line has too many fields"));
    }

    if !version.starts_with("HTTP/") {
        return Err(invalid_data("HTTP version must start with HTTP/"));
    }

    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }

        let Some((name, value)) = line.split_once(':') else {
            return Err(invalid_data("HTTP header is missing `:`"));
        };

        let name = name.trim();
        if name.is_empty() {
            return Err(invalid_data("HTTP header name cannot be empty"));
        }

        headers.push(HttpHeader {
            name: name.to_string(),
            value: value.trim().to_string(),
        });
    }

    Ok(HttpRequest {
        method: method.to_string(),
        target: target.to_string(),
        version: version.to_string(),
        headers,
        body: Vec::new(),
    })
}

pub fn parse_http_response_head(head: &[u8]) -> io::Result<HttpResponse> {
    let head = std::str::from_utf8(head)
        .map_err(|_| invalid_data("HTTP response headers are not UTF-8"))?;
    let mut lines = head.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| invalid_data("missing HTTP response status line"))?;
    let mut status_parts = status_line.splitn(3, ' ');
    let version = status_parts
        .next()
        .ok_or_else(|| invalid_data("missing HTTP response version"))?;
    let status = status_parts
        .next()
        .ok_or_else(|| invalid_data("missing HTTP response status"))?;
    let reason = status_parts.next().unwrap_or_default();

    if !version.starts_with("HTTP/") {
        return Err(invalid_data("HTTP response version must start with HTTP/"));
    }

    let status = status
        .parse::<u16>()
        .map_err(|error| invalid_data(format!("invalid HTTP response status: {error}")))?;

    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }

        let Some((name, value)) = line.split_once(':') else {
            return Err(invalid_data("HTTP response header is missing `:`"));
        };

        let name = name.trim();
        if name.is_empty() {
            return Err(invalid_data("HTTP response header name cannot be empty"));
        }

        headers.push(HttpHeader {
            name: name.to_string(),
            value: value.trim().to_string(),
        });
    }

    Ok(HttpResponse {
        version: version.to_string(),
        status,
        reason: reason.to_string(),
        headers,
        body: Vec::new(),
    })
}

pub fn request_content_length(request: &HttpRequest) -> io::Result<usize> {
    if request.headers.iter().any(|header| {
        header.name.eq_ignore_ascii_case("transfer-encoding")
            && header.value.to_ascii_lowercase().contains("chunked")
    }) {
        return Err(invalid_data(
            "chunked request bodies are not supported by the v0 proxy",
        ));
    }

    let mut content_length = None;
    for header in &request.headers {
        if header.name.eq_ignore_ascii_case("content-length") {
            let parsed = header
                .value
                .parse::<usize>()
                .map_err(|error| invalid_data(format!("invalid Content-Length: {error}")))?;
            if content_length.is_some_and(|existing| existing != parsed) {
                return Err(invalid_data("conflicting request Content-Length headers"));
            }
            content_length = Some(parsed);
        }
    }

    Ok(content_length.unwrap_or(0))
}

pub fn response_content_length(response: &HttpResponse) -> io::Result<Option<usize>> {
    let mut content_length = None;
    for header in &response.headers {
        if header.name.eq_ignore_ascii_case("content-length") {
            let parsed = header
                .value
                .parse::<usize>()
                .map_err(|error| invalid_data(format!("invalid Content-Length: {error}")))?;
            if content_length.is_some_and(|existing| existing != parsed) {
                return Err(invalid_data("conflicting upstream Content-Length headers"));
            }
            content_length = Some(parsed);
        }
    }

    Ok(content_length)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseTransferCoding {
    Identity,
    Chunked,
}

pub fn response_transfer_coding(response: &HttpResponse) -> io::Result<ResponseTransferCoding> {
    let codings: Vec<String> = response
        .headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("transfer-encoding"))
        .flat_map(|header| header.value.split(','))
        .map(|coding| coding.trim().to_ascii_lowercase())
        .filter(|coding| !coding.is_empty())
        .collect();

    match codings.as_slice() {
        [] => Ok(ResponseTransferCoding::Identity),
        [coding] if coding == "chunked" => Ok(ResponseTransferCoding::Chunked),
        _ => Err(invalid_data(format!(
            "unsupported upstream Transfer-Encoding: {}",
            codings.join(", ")
        ))),
    }
}

pub fn read_chunked_response_body<R>(reader: &mut R, mut buffer: Vec<u8>) -> io::Result<Vec<u8>>
where
    R: Read,
{
    let mut body = Vec::new();

    loop {
        let size_line = read_crlf_line(reader, &mut buffer)?;
        let chunk_size = parse_chunk_size(&size_line)?;

        if chunk_size == 0 {
            loop {
                let trailer_line = read_crlf_line(reader, &mut buffer)?;
                if trailer_line.is_empty() {
                    return Ok(body);
                }
            }
        }

        let body_len = body
            .len()
            .checked_add(chunk_size)
            .ok_or_else(|| invalid_data("HTTP response body exceeds size limit"))?;
        if body_len > MAX_BODY_BYTES {
            return Err(invalid_data("HTTP response body exceeds size limit"));
        }

        let chunk_with_crlf = chunk_size
            .checked_add(2)
            .ok_or_else(|| invalid_data("HTTP response chunk exceeds size limit"))?;
        ensure_buffer_len(reader, &mut buffer, chunk_with_crlf)?;
        body.extend(buffer.drain(..chunk_size));
        if buffer.drain(..2).ne(b"\r\n".iter().copied()) {
            return Err(invalid_data("invalid chunked response body"));
        }
    }
}

pub fn read_crlf_line<R>(reader: &mut R, buffer: &mut Vec<u8>) -> io::Result<Vec<u8>>
where
    R: Read,
{
    loop {
        if let Some(line_end) = find_crlf(buffer) {
            let line = buffer[..line_end].to_vec();
            buffer.drain(..line_end + 2);
            return Ok(line);
        }

        if buffer.len() > MAX_HEADER_BYTES {
            return Err(invalid_data("chunked response metadata exceeds size limit"));
        }

        read_more(reader, buffer)?;
    }
}

pub fn ensure_buffer_len<R>(reader: &mut R, buffer: &mut Vec<u8>, len: usize) -> io::Result<()>
where
    R: Read,
{
    while buffer.len() < len {
        read_more(reader, buffer)?;
    }

    Ok(())
}

pub fn read_more<R>(reader: &mut R, buffer: &mut Vec<u8>) -> io::Result<()>
where
    R: Read,
{
    let mut chunk = [0_u8; 1024];
    let bytes_read = reader.read(&mut chunk)?;
    if bytes_read == 0 {
        return Err(invalid_data(
            "connection closed before chunked HTTP response body completed",
        ));
    }

    buffer.extend_from_slice(&chunk[..bytes_read]);
    Ok(())
}

pub fn parse_chunk_size(line: &[u8]) -> io::Result<usize> {
    let line = std::str::from_utf8(line)
        .map_err(|_| invalid_data("chunked response size line is not UTF-8"))?;
    let size = line
        .split_once(';')
        .map_or(line, |(size, _extension)| size)
        .trim();

    if size.is_empty() {
        return Err(invalid_data("missing chunked response size"));
    }

    usize::from_str_radix(size, 16)
        .map_err(|error| invalid_data(format!("invalid chunked response size: {error}")))
}

pub fn find_crlf(buffer: &[u8]) -> Option<usize> {
    buffer.windows(2).position(|window| window == b"\r\n")
}

pub fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)
}

pub fn normalize_request_target(target: &str) -> io::Result<&str> {
    if target.is_empty() {
        return Err(invalid_data("HTTP request target cannot be empty"));
    }

    if target.starts_with('/') {
        return Ok(target);
    }

    if let Some(rest) = target.strip_prefix("http://") {
        return Ok(match rest.find('/') {
            Some(index) => &rest[index..],
            None => "/",
        });
    }

    if target == "*" {
        return Ok(target);
    }

    Err(invalid_data(
        "HTTP request target must be origin-form or http absolute-form",
    ))
}

pub fn effective_request_host(request: &HttpRequest) -> Option<String> {
    request_host_from_target(&request.target)
        .or_else(|| {
            request
                .headers
                .iter()
                .find(|header| header.name.eq_ignore_ascii_case("host"))
                .map(|header| header.value.as_str())
        })
        .and_then(normalize_request_host)
}

pub fn request_host_from_target(target: &str) -> Option<&str> {
    let rest = target.strip_prefix("http://")?;
    Some(match rest.split_once('/') {
        Some((authority, _)) => authority,
        None => rest,
    })
}

pub fn normalize_request_host(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }

    let bracketless = value
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(value);
    if bracketless.parse::<IpAddr>().is_ok() {
        return Some(bracketless.to_ascii_lowercase());
    }

    parse_authority(value)
        .ok()
        .map(|(host, _)| host.to_ascii_lowercase())
}

pub fn connection_nominated_headers(headers: &[HttpHeader]) -> Vec<String> {
    headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("connection"))
        .flat_map(|header| header.value.split(','))
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_string)
        .collect()
}

pub fn should_skip_forwarded_header(name: &str, connection_nominated_headers: &[String]) -> bool {
    name.eq_ignore_ascii_case("host")
        || name.eq_ignore_ascii_case("content-length")
        || name.eq_ignore_ascii_case("connection")
        || name.eq_ignore_ascii_case("proxy-connection")
        || name.eq_ignore_ascii_case("keep-alive")
        || name.eq_ignore_ascii_case("proxy-authenticate")
        || name.eq_ignore_ascii_case("proxy-authorization")
        || name.eq_ignore_ascii_case("te")
        || name.eq_ignore_ascii_case("trailer")
        || name.eq_ignore_ascii_case("transfer-encoding")
        || name.eq_ignore_ascii_case("upgrade")
        || name.to_ascii_lowercase().starts_with("x-eidolon-")
        || connection_nominated_headers
            .iter()
            .any(|header| name.eq_ignore_ascii_case(header))
}

pub fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

pub fn parse_authority(authority: &str) -> Result<(&str, Option<u16>), io::Error> {
    if let Some(rest) = authority.strip_prefix('[') {
        let Some(close_index) = rest.find(']') else {
            return Err(invalid_data(
                "IPv6 upstream target hosts must close the `]` bracket",
            ));
        };
        let host = &rest[..close_index];
        let suffix = &rest[close_index + 1..];
        let port = if suffix.is_empty() {
            None
        } else if let Some(raw_port) = suffix.strip_prefix(':') {
            Some(parse_port(raw_port, "upstream target port")?)
        } else {
            return Err(invalid_data(
                "upstream target must put the port after the IPv6 host bracket",
            ));
        };

        if host.is_empty() {
            return Err(invalid_data("upstream target host cannot be empty"));
        }

        return Ok((host, port));
    }

    if authority.matches(':').count() > 1 {
        return Err(invalid_data(
            "IPv6 upstream target hosts must be bracketed, for example http://[::1]:9001",
        ));
    }

    if let Some((host, raw_port)) = authority.rsplit_once(':') {
        if host.is_empty() {
            return Err(invalid_data("upstream target host cannot be empty"));
        }

        return Ok((host, Some(parse_port(raw_port, "upstream target port")?)));
    }

    Ok((authority, None))
}

fn parse_port(raw: &str, label: &str) -> Result<u16, io::Error> {
    if raw.is_empty() {
        return Err(invalid_data(format!("{label} cannot be empty")));
    }

    raw.parse::<u16>()
        .map_err(|error| invalid_data(format!("{label} must be a valid TCP port: {error}")))
}
