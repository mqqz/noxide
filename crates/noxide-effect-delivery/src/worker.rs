//! Status-first classification. A body-discard failure never retries known 2xx.
use crate::transport::{Error, Response};
use noxide_effects::DeliveryResult;
pub fn classify(result: Result<Response, Error>) -> DeliveryResult {
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
#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::Discard;
    #[test]
    fn known_status_precedes_discard_and_only_transient_statuses_retry() {
        for discard in [
            Discard::Complete,
            Discard::Invalid,
            Discard::LimitExceeded,
            Discard::Deadline,
        ] {
            assert!(matches!(
                classify(Ok(Response {
                    status: 204,
                    retry_after_seconds: None,
                    discard
                })),
                DeliveryResult::Delivered
            ));
        }
        for status in [429, 500, 503] {
            assert!(matches!(
                classify(Ok(Response {
                    status,
                    retry_after_seconds: Some(120),
                    discard: Discard::Complete
                })),
                DeliveryResult::Retry {
                    retry_after_seconds: Some(120)
                }
            ));
        }
        for status in [400, 401, 403, 404] {
            assert!(matches!(
                classify(Ok(Response {
                    status,
                    retry_after_seconds: None,
                    discard: Discard::Complete
                })),
                DeliveryResult::Terminal
            ));
        }
        assert!(matches!(
            classify(Err(Error::Redirect(302))),
            DeliveryResult::Terminal
        ));
        assert!(matches!(
            classify(Err(Error::Deadline)),
            DeliveryResult::Retry {
                retry_after_seconds: None
            }
        ));
    }
}
