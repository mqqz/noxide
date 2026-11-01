use super::{
    Discard, Error, Response,
    config::{BearerSecret, Endpoint, IdempotencyKey, JsonBody, MAX_HEADERS, MAX_RESPONSE},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    time::{Instant, timeout_at},
};

#[derive(Clone, Copy)]
enum Framing {
    Empty,
    Length(usize),
    Chunked,
    Close,
}
struct Head {
    status: u16,
    retry_after: Option<u32>,
    framing: Framing,
}

async fn head<R: AsyncRead + Unpin>(reader: &mut R, budget: &mut usize) -> Result<Head, Error> {
    let mut bytes = Vec::new();
    loop {
        if *budget == 0 {
            return Err(Error::ResponseLimit);
        }
        let byte = reader.read_u8().await.map_err(|_| Error::Http)?;
        *budget -= 1;
        bytes.push(byte);
        if bytes.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut response = httparse::Response::new(&mut headers);
    if !matches!(response.parse(&bytes),Ok(httparse::Status::Complete(n)) if n==bytes.len()) {
        return Err(Error::Http);
    }
    if !matches!(response.version, Some(0 | 1)) {
        return Err(Error::Http);
    }
    let status = response
        .code
        .filter(|n| (100..=599).contains(n))
        .ok_or(Error::Http)?;
    let mut length = None;
    let mut chunked = false;
    let mut retry_after = None;
    let mut saw_retry = false;
    for header in response.headers.iter() {
        if header.name.eq_ignore_ascii_case("content-length") {
            if length.is_some() {
                return Err(Error::Http);
            }
            let value = std::str::from_utf8(header.value.trim_ascii()).map_err(|_| Error::Http)?;
            if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                return Err(Error::Http);
            }
            length = Some(value.parse::<usize>().unwrap_or(usize::MAX));
        } else if header.name.eq_ignore_ascii_case("transfer-encoding") {
            if chunked || !header.value.trim_ascii().eq_ignore_ascii_case(b"chunked") {
                return Err(Error::Http);
            }
            chunked = true;
        } else if header.name.eq_ignore_ascii_case("retry-after") {
            if saw_retry {
                retry_after = None;
                continue;
            }
            saw_retry = true;
            if let Ok(value) = std::str::from_utf8(header.value)
                && !value.is_empty()
                && value.len() <= 5
                && value.bytes().all(|b| b.is_ascii_digit())
            {
                retry_after = value.parse::<u32>().ok().filter(|n| *n <= 86_400);
            }
        }
    }
    if chunked && length.is_some() {
        return Err(Error::Http);
    }
    let framing = if status < 200 || status == 204 {
        if chunked || length.is_some_and(|n| n != 0) {
            return Err(Error::Http);
        }
        Framing::Empty
    } else if chunked {
        Framing::Chunked
    } else if let Some(n) = length {
        Framing::Length(n)
    } else {
        Framing::Close
    };
    Ok(Head {
        status,
        retry_after,
        framing,
    })
}

struct Body<'a, R> {
    reader: &'a mut R,
    remaining: usize,
}
impl<R: AsyncRead + Unpin> Body<'_, R> {
    async fn byte(&mut self) -> Result<u8, Error> {
        if self.remaining == 0 {
            return Err(Error::ResponseLimit);
        }
        let b = self.reader.read_u8().await.map_err(|_| Error::Http)?;
        self.remaining -= 1;
        Ok(b)
    }
    async fn line(&mut self, limit: usize) -> Result<Vec<u8>, Error> {
        let mut line = Vec::new();
        loop {
            if line.len() == limit {
                return Err(Error::ResponseLimit);
            }
            let b = self.byte().await?;
            line.push(b);
            if b == b'\n' {
                if line.len() < 2 || line[line.len() - 2] != b'\r' {
                    return Err(Error::Http);
                }
                line.truncate(line.len() - 2);
                return Ok(line);
            }
        }
    }
    async fn discard(&mut self, mut bytes: usize) -> Result<(), Error> {
        if bytes > self.remaining {
            return Err(Error::ResponseLimit);
        }
        let mut buffer = [0; 1_024];
        while bytes > 0 {
            let size = bytes.min(buffer.len());
            self.reader
                .read_exact(&mut buffer[..size])
                .await
                .map_err(|_| Error::Http)?;
            self.remaining -= size;
            bytes -= size;
        }
        Ok(())
    }
}
fn token(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}
async fn discard<R: AsyncRead + Unpin>(reader: &mut R, framing: Framing) -> Result<(), Error> {
    let mut body = Body {
        reader,
        remaining: MAX_RESPONSE,
    };
    match framing {
        Framing::Empty => Ok(()),
        Framing::Length(n) => body.discard(n).await,
        Framing::Close => {
            let mut buffer = [0; 1_024];
            loop {
                if body.remaining == 0 {
                    return Err(Error::ResponseLimit);
                }
                let size = buffer.len().min(body.remaining);
                let n = body
                    .reader
                    .read(&mut buffer[..size])
                    .await
                    .map_err(|_| Error::Http)?;
                if n == 0 {
                    return Ok(());
                }
                body.remaining -= n;
            }
        }
        Framing::Chunked => {
            for _ in 0..256 {
                let line = body.line(128).await?;
                // Extensions are unsupported and rejected rather than skipped;
                // both chunk count and framing bytes consume hard limits.
                if line.is_empty() || line.len() > 16 || !line.iter().all(|b| b.is_ascii_hexdigit())
                {
                    return Err(Error::Http);
                }
                let text = std::str::from_utf8(&line).map_err(|_| Error::Http)?;
                let n = usize::from_str_radix(text, 16).map_err(|_| Error::Http)?;
                if n == 0 {
                    for _ in 0..16 {
                        let trailer = body.line(1_024).await?;
                        if trailer.is_empty() {
                            return Ok(());
                        }
                        let colon = trailer.iter().position(|b| *b == b':').ok_or(Error::Http)?;
                        if colon == 0
                            || !trailer[..colon].iter().all(|b| token(*b))
                            || !trailer[colon + 1..]
                                .iter()
                                .all(|b| matches!(b, b'\t' | b' '..=b'~'))
                        {
                            return Err(Error::Http);
                        }
                        let name =
                            std::str::from_utf8(&trailer[..colon]).map_err(|_| Error::Http)?;
                        if [
                            "content-length",
                            "transfer-encoding",
                            "host",
                            "authorization",
                        ]
                        .iter()
                        .any(|n| name.eq_ignore_ascii_case(n))
                        {
                            return Err(Error::Http);
                        }
                    }
                    return Err(Error::ResponseLimit);
                }
                body.discard(n).await?;
                if body.byte().await? != b'\r' || body.byte().await? != b'\n' {
                    return Err(Error::Http);
                }
            }
            Err(Error::ResponseLimit)
        }
    }
}

pub(super) async fn post<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    endpoint: &Endpoint,
    body: &JsonBody,
    key: &IdempotencyKey,
    secret: Option<&BearerSecret>,
    deadline: Instant,
) -> Result<Response, Error> {
    let final_head=timeout_at(deadline,async {
        let mut request=format!("POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nAccept: application/json\r\nContent-Length: {}\r\nConnection: close\r\nIdempotency-Key: {}\r\n",endpoint.path(),endpoint.authority(),body.bytes().len(),key.value());
        if let Some(secret)=secret {request.push_str("Authorization: Bearer ");request.push_str(secret.value());request.push_str("\r\n");}
        request.push_str("\r\n");
        if request.len()>4_096 {return Err(Error::Header);}
        stream.write_all(request.as_bytes()).await.map_err(|_|Error::Http)?;
        stream.write_all(body.bytes()).await.map_err(|_|Error::Http)?;
        stream.flush().await.map_err(|_|Error::Http)?;
        Ok::<_,Error>(stream)
    }).await.map_err(|_|Error::Deadline)??;
    let mut reader = final_head;
    let received = timeout_at(deadline, async {
        let mut budget = MAX_HEADERS;
        for _ in 0..3 {
            let head = head(&mut reader, &mut budget).await?;
            if head.status >= 200 {
                return Ok(head);
            }
            if !matches!(head.status, 100 | 102 | 103) {
                return Err(Error::Http);
            }
        }
        Err(Error::ResponseLimit)
    })
    .await
    .map_err(|_| Error::Deadline)??;
    if (300..400).contains(&received.status) {
        return Err(Error::Redirect(received.status));
    }
    let discarded = match timeout_at(deadline, discard(&mut reader, received.framing)).await {
        Ok(Ok(())) => Discard::Complete,
        Ok(Err(Error::ResponseLimit)) => Discard::LimitExceeded,
        Ok(Err(_)) => Discard::Invalid,
        Err(_) => Discard::Deadline,
    };
    Ok(Response {
        status: received.status,
        retry_after_seconds: received.retry_after,
        discard: discarded,
    })
}
