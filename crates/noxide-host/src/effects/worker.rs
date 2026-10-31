//! Status-first classification. A body-discard failure never retries known 2xx.
use super::{
    store::DeliveryResult,
    transport::{Error, Response},
};
pub(crate) fn classify(result: Result<Response, Error>) -> DeliveryResult {
    match result {
        Ok(response) if (200..300).contains(&response.status) => DeliveryResult::Delivered,
        Ok(response) if response.status == 429 || (500..600).contains(&response.status) => {
            DeliveryResult::Retry {
                retry_after_seconds: response.retry_after_seconds,
            }
        }
        Ok(_) | Err(Error::Redirect(_)) => DeliveryResult::Terminal,
        Err(_) => DeliveryResult::Retry {
            retry_after_seconds: None,
        },
    }
}
