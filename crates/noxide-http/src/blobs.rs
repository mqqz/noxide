use super::*;
use crate::application::blobs::PreparedUpload;
use anyhow::Context;
use hyper::body::Body as _;
use noxide_blobs::multipart::{Boundary, PrefixDecoder};
use std::{pin::Pin, sync::atomic::AtomicBool};

async fn next(
    body: &mut axum::body::Body,
    deadline: tokio::time::Instant,
) -> Result<Option<axum::body::Bytes>> {
    let frame = tokio::time::timeout_at(
        deadline,
        std::future::poll_fn(|cx| Pin::new(&mut *body).poll_frame(cx)),
    )
    .await?;
    match frame {
        None => Ok(None),
        Some(frame) => {
            let bytes = frame?
                .into_data()
                .map_err(|_| anyhow::anyhow!("multipart trailers denied"))?;
            ensure!(
                bytes.len() <= noxide_protocol::blobs::TRANSFER_BUFFER_BYTES,
                "multipart frame limit"
            );
            Ok(Some(bytes))
        }
    }
}
fn failure(error: anyhow::Error, presentation: &crate::Presentation) -> Response {
    if let Some(error) = error.downcast_ref::<RequestError>() {
        return super::error(
            match error {
                RequestError::Authentication => RequestError::Authentication,
                RequestError::Busy => RequestError::Busy,
                RequestError::OutcomeUnknown => RequestError::OutcomeUnknown,
                _ => RequestError::InvalidRequest,
            },
            &presentation.login_path,
        );
    }
    StatusCode::BAD_REQUEST.into_response()
}
pub(super) async fn upload(gateway: Arc<Gateway>, request: Request) -> Response {
    let app = gateway.app.clone();
    let presentation = &app.presentation;
    let result: Result<Response> = async {
        let binding: u32 = request
            .uri()
            .path()
            .strip_prefix(&format!("{}/", presentation.action_path))
            .context("invalid upload path")?
            .parse()?;
        let action = crate::manifest::web_action(&app.manifest, binding)?;
        let op = crate::manifest::operation(&app.manifest, action.steps[0].operation)?;
        let cookie = cookie(
            request.headers(),
            if crate::manifest::anonymous_action(op) {
                &presentation.anonymous_cookie
            } else {
                &presentation.session_cookie
            },
        )?;
        let boundary = Boundary::content_type(
            request
                .headers()
                .get(header::CONTENT_TYPE)
                .context("missing multipart type")?
                .to_str()?,
        )?;
        let mut decoder = PrefixDecoder::new(boundary, app.multipart_spec(binding)?);
        let prefix_deadline = crate::database::lifecycle::RequestScope::current_work_deadline()
            .context("upload outside request")?;
        let mut body = request.into_body();
        let (ready, buffered) = loop {
            let bytes = next(&mut body, prefix_deadline)
                .await?
                .context("truncated multipart prefix")?;
            let progress = decoder.push(&bytes)?;
            if let Some(ready) = progress.ready {
                break (ready, bytes.slice(progress.consumed..));
            }
        };
        decoder.finish()?;
        let mut values = ready.values.clone();
        let prepared = app
            .prepare_upload(&cookie, binding, &values, ready.filename.clone())
            .await?;
        let file = app
            .blobs
            .as_ref()
            .context("blob runtime missing")?
            .policy
            .uploads
            .iter()
            .find(|u| u.web_binding == binding)
            .context("upload declaration missing")?
            .input
            .clone();
        let transfer = app.blob_phase(Duration::from_millis(
            noxide_protocol::blobs::TRANSFER_TOTAL_MILLIS,
        ));
        let handle = match prepared {
            PreparedUpload::Existing {
                input,
                replay: true,
            } => {
                values.remove("_upload");
                let csrf = values
                    .remove(&presentation.csrf_field)
                    .context("missing csrf")?;
                let submission = values
                    .remove(&presentation.submission_field)
                    .context("missing submission")?;
                values.insert(file, input);
                let response = app
                    .submit(&cookie, binding, &submission, &csrf, values)
                    .await?;
                let mut response = rendered(response, gateway.origin.secure, presentation);
                response
                    .headers_mut()
                    .insert(header::CONNECTION, HeaderValue::from_static("close"));
                return Ok(response);
            }
            PreparedUpload::Created(row, lease) => {
                let blobs = app.blobs.as_ref().context("blob runtime missing")?;
                let store = blobs.store.clone();
                let key = row.metadata.key.clone();
                let limit = row.metadata.reserved;
                let mut file_decoder = ready.into_body();
                let (send, mut receive) =
                    tokio::sync::mpsc::channel::<Option<axum::body::Bytes>>(1);
                let runtime = tokio::runtime::Handle::current();
                let deadline = transfer.work_deadline();
                let job = blobs.uploads.try_start(
                    key.clone(),
                    row.metadata.generation,
                    deadline.into_std(),
                    Arc::new(AtomicBool::new(false)),
                    move |guard| {
                        let mut pending = store.begin(key, limit, guard.clone())?;
                        loop {
                            guard.check()?;
                            let idle = deadline.min(
                                tokio::time::Instant::now()
                                    + Duration::from_millis(
                                        noxide_protocol::blobs::DOWNLOAD_IDLE_MILLIS,
                                    ),
                            );
                            let chunk = runtime
                                .block_on(tokio::time::timeout_at(idle, receive.recv()))?
                                .context("upload stream cancelled")?;
                            match chunk {
                                Some(bytes) => {
                                    file_decoder.push(&bytes, |bytes| pending.write_chunk(bytes))?
                                }
                                None => {
                                    file_decoder.finish()?;
                                    return pending.finalize();
                                }
                            }
                        }
                    },
                )?;
                let _publication = PublicationLease(job.witness());
                blobs
                    .workers
                    .lock()
                    .unwrap()
                    .insert(row.metadata.key.as_str().into(), job.witness());
                lease.dispatched();
                let object = transfer
                    .run(async {
                        if !buffered.is_empty() {
                            send.send(Some(buffered)).await?;
                        }
                        loop {
                            let idle = deadline.min(
                                tokio::time::Instant::now()
                                    + Duration::from_millis(
                                        noxide_protocol::blobs::DOWNLOAD_IDLE_MILLIS,
                                    ),
                            );
                            match next(&mut body, idle).await? {
                                Some(bytes) if bytes.is_empty() => continue,
                                Some(bytes) => {
                                    tokio::time::timeout_at(idle, send.send(Some(bytes))).await??
                                }
                                None => break,
                            }
                        }
                        tokio::time::timeout_at(deadline, send.send(None)).await??;
                        drop(send);
                        job.finish().await
                    })
                    .await?;
                let final_phase = app.blob_phase(app.blob_action_limit());
                return final_phase
                    .run(async {
                        let handle = app.publish_upload(&row, object).await?;
                        values.remove("_upload");
                        let csrf = values
                            .remove(&presentation.csrf_field)
                            .context("missing csrf")?;
                        let submission = values
                            .remove(&presentation.submission_field)
                            .context("missing submission")?;
                        values.insert(file, handle);
                        submit(&gateway, &cookie, binding, &submission, &csrf, values).await
                    })
                    .await;
            }
            PreparedUpload::Existing {
                input,
                replay: false,
            } => input,
            PreparedUpload::Absent => String::new(),
        };
        // A retry/optional absence still requires a syntactically complete sole
        // final file part containing zero bytes, never a second replacement.
        let mut file_decoder = ready.into_body();
        transfer
            .run(async {
                file_decoder.push(&buffered, |_| anyhow::bail!("unexpected upload bytes"))?;
                while let Some(bytes) = next(
                    &mut body,
                    transfer.work_deadline().min(
                        tokio::time::Instant::now()
                            + Duration::from_millis(noxide_protocol::blobs::DOWNLOAD_IDLE_MILLIS),
                    ),
                )
                .await?
                {
                    file_decoder.push(&bytes, |_| anyhow::bail!("unexpected upload bytes"))?;
                }
                file_decoder.finish()
            })
            .await?;
        let final_phase = app.blob_phase(app.blob_action_limit());
        final_phase
            .run(async {
                values.remove("_upload");
                let csrf = values
                    .remove(&presentation.csrf_field)
                    .context("missing csrf")?;
                let submission = values
                    .remove(&presentation.submission_field)
                    .context("missing submission")?;
                values.insert(file, handle);
                submit(&gateway, &cookie, binding, &submission, &csrf, values).await
            })
            .await
    }
    .await;
    match result {
        Ok(response) => response,
        Err(error) => {
            let mut response = failure(error, presentation);
            response
                .headers_mut()
                .insert(header::CONNECTION, HeaderValue::from_static("close"));
            response
        }
    }
}
async fn submit(
    gateway: &Gateway,
    cookie: &str,
    binding: u32,
    submission: &str,
    csrf: &str,
    values: noxide_protocol::Fields,
) -> Result<Response> {
    match gateway
        .app
        .submit(cookie, binding, submission, csrf, values.clone())
        .await
    {
        Ok(value) => Ok(rendered(
            value,
            gateway.origin.secure,
            &gateway.app.presentation,
        )),
        Err(e) => {
            let unknown = matches!(e, RequestError::OutcomeUnknown);
            match gateway
                .app
                .recover_form(cookie, binding, submission, csrf, &values, unknown)
                .await
            {
                Ok(value) => Ok(rendered(
                    value,
                    gateway.origin.secure,
                    &gateway.app.presentation,
                )),
                Err(_) => Err(e.into()),
            }
        }
    }
}

pub(super) async fn download(gateway: Arc<Gateway>, request: Request) -> Response {
    let result: Result<Response> = async {
        ensure!(
            request.method() == axum::http::Method::GET
                && !request.headers().contains_key(header::RANGE),
            "unsupported download request"
        );
        ensure!(
            !request.headers().contains_key(header::TRANSFER_ENCODING)
                && request
                    .headers()
                    .get_all(header::CONTENT_LENGTH)
                    .iter()
                    .all(|v| v.as_bytes() == b"0"),
            "download body denied"
        );
        let query = request
            .uri()
            .query()
            .context("download ticket missing")?
            .to_owned();
        ensure!(query.len() <= 8192, "download ticket limit");
        let mut params = url::form_urlencoded::parse(query.as_bytes());
        let (name, ticket) = params.next().context("download ticket missing")?;
        ensure!(
            name == "ticket" && params.next().is_none(),
            "invalid download query"
        );
        let ticket = ticket.into_owned();
        let _ = params;
        let session = cookie(request.headers(), &gateway.app.presentation.session_cookie).ok();
        drop(request);
        let download = gateway
            .app
            .open_download(session.as_deref(), &ticket)
            .await?;
        let disposition = download.filename.disposition();
        let length = download.bytes;
        let mut opened = download.opened;
        let (send, receive) = tokio::sync::mpsc::channel(1);
        let runtime = tokio::runtime::Handle::current();
        let blobs = gateway.app.blobs.as_ref().context("blob runtime missing")?;
        let native_permit = download.permit.clone();
        let lease = Arc::new(StreamLease {
            permit: Mutex::new(Some(download.permit)),
            cancelled: download.cancelled.clone(),
            idle: Mutex::new(download.deadline.min(
                tokio::time::Instant::now()
                    + Duration::from_millis(noxide_protocol::blobs::DOWNLOAD_IDLE_MILLIS),
            )),
            outer: download.deadline,
            changed: tokio::sync::Notify::new(),
            done: AtomicBool::new(false),
            expired: AtomicBool::new(false),
        });
        let job = blobs.downloads.try_start(
            download.key,
            download.generation,
            download.deadline.into_std(),
            download.cancelled,
            move |guard| {
                let _permit = native_permit;
                let mut budget = noxide_blobs::transport::TransferBudget::new(
                    std::time::Instant::now(),
                    download.deadline.into_std(),
                    length,
                )?;
                let mut buffer = Box::new([0u8; noxide_protocol::blobs::TRANSFER_BUFFER_BYTES]);
                while !budget.complete() {
                    guard.check()?;
                    budget.check(std::time::Instant::now())?;
                    let bytes = opened.read_chunk(&mut *buffer)?;
                    ensure!(bytes != 0, "truncated blob object");
                    let deadline = budget.deadline();
                    runtime.block_on(tokio::time::timeout_at(
                        deadline.into(),
                        send.send(axum::body::Bytes::copy_from_slice(&buffer[..bytes])),
                    ))??;
                    budget.progress(std::time::Instant::now(), bytes)?;
                }
                Ok(())
            },
        )?;
        let watchdog = lease.clone();
        tokio::spawn(async move {
            loop {
                let changed = watchdog.changed.notified();
                let deadline = *watchdog.idle.lock().unwrap();
                if watchdog.done.load(std::sync::atomic::Ordering::Acquire) {
                    return;
                }
                tokio::select! {
                    _ = changed => {},
                    _ = tokio::time::sleep_until(deadline) => {
                        if tokio::time::Instant::now() >= *watchdog.idle.lock().unwrap() {
                            watchdog.expired.store(true,std::sync::atomic::Ordering::Release);
                            watchdog.finish();
                            return;
                        }
                    }
                }
            }
        });
        let body = DownloadBody {
            receive,
            job: Some(job),
            lease,
            remaining: length,
            failed: false,
        };
        let mut response = Response::new(axum::body::Body::new(body));
        let headers = response.headers_mut();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(noxide_blobs::transport::CONTENT_TYPE),
        );
        headers.insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static(noxide_blobs::transport::CACHE_CONTROL),
        );
        headers.insert(
            "x-content-type-options",
            HeaderValue::from_static(noxide_blobs::transport::NOSNIFF),
        );
        headers.insert(
            header::CONTENT_DISPOSITION,
            HeaderValue::from_str(&disposition)?,
        );
        headers.insert(
            header::CONTENT_LENGTH,
            HeaderValue::from_str(&length.to_string())?,
        );
        headers.insert(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(noxide_blobs::transport::CSP),
        );
        Ok(response)
    }
    .await;
    match result {
        Ok(response) => response,
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}
struct StreamLease {
    permit: Mutex<Option<Arc<tokio::sync::OwnedSemaphorePermit>>>,
    cancelled: Arc<AtomicBool>,
    idle: Mutex<tokio::time::Instant>,
    outer: tokio::time::Instant,
    changed: tokio::sync::Notify,
    done: AtomicBool,
    expired: AtomicBool,
}
impl StreamLease {
    fn finish(&self) {
        self.done.store(true, std::sync::atomic::Ordering::Release);
        self.cancelled
            .store(true, std::sync::atomic::Ordering::Release);
        self.permit.lock().unwrap().take();
        self.changed.notify_one();
    }
    fn progress(&self) {
        *self.idle.lock().unwrap() = self.outer.min(
            tokio::time::Instant::now()
                + Duration::from_millis(noxide_protocol::blobs::DOWNLOAD_IDLE_MILLIS),
        );
        self.changed.notify_one();
    }
}
struct DownloadBody {
    lease: Arc<StreamLease>,
    receive: tokio::sync::mpsc::Receiver<axum::body::Bytes>,
    job: Option<noxide_blobs::io::IoJob<()>>,
    remaining: u64,
    failed: bool,
}
impl hyper::body::Body for DownloadBody {
    type Data = axum::body::Bytes;
    type Error = std::io::Error;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<std::result::Result<hyper::body::Frame<Self::Data>, Self::Error>>>
    {
        use std::task::Poll;
        if self
            .lease
            .expired
            .load(std::sync::atomic::Ordering::Acquire)
        {
            self.job.take();
            if self.failed {
                return Poll::Ready(None);
            }
            self.failed = true;
            return Poll::Ready(Some(Err(std::io::Error::other("blob transfer deadline"))));
        }
        match self.receive.poll_recv(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(bytes)) => {
                let Some(remaining) = self.remaining.checked_sub(bytes.len() as u64) else {
                    self.failed = true;
                    return Poll::Ready(Some(Err(std::io::Error::other("blob length exceeded"))));
                };
                self.remaining = remaining;
                self.lease.progress();
                Poll::Ready(Some(Ok(hyper::body::Frame::data(bytes))))
            }
            Poll::Ready(None) => {
                self.job.take();
                self.lease.finish();
                if self.remaining != 0 && !self.failed {
                    self.failed = true;
                    Poll::Ready(Some(Err(std::io::Error::other("blob stream incomplete"))))
                } else {
                    Poll::Ready(None)
                }
            }
        }
    }
    fn size_hint(&self) -> hyper::body::SizeHint {
        hyper::body::SizeHint::with_exact(self.remaining)
    }
}

impl Drop for DownloadBody {
    fn drop(&mut self) {
        self.lease.finish();
    }
}

struct PublicationLease(noxide_blobs::io::IoWitness);
impl Drop for PublicationLease {
    fn drop(&mut self) {
        self.0.cancel();
    }
}
