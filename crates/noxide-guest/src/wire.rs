//! The messages between the server and a guest worker. Everything a worker sends
//! is untrusted: a guest that escaped Wasmtime controls these bytes, so decoding
//! bounds every length and rejects anything malformed.
use anyhow::{Result, bail, ensure};
use noxide_protocol::{MAX_IR_BYTES, MAX_REQUEST_BYTES, MAX_RESULT_BYTES};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const MAX_BODY: usize = max(max(MAX_IR_BYTES, MAX_REQUEST_BYTES), MAX_RESULT_BYTES);
/// Tag plus the largest fixed fields of any message.
const MAX_FRAME: usize = MAX_BODY + 32;

const fn max(left: usize, right: usize) -> usize {
    if left > right { left } else { right }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ToWorker {
    Run {
        fuel: u64,
        calls: u32,
        wall_millis: u64,
        request: Vec<u8>,
    },
    /// The answer to a storage call. A refusal carries no reason: the server keeps
    /// the error, and the guest only learns that the call failed.
    Reply(Option<Vec<u8>>),
}

#[derive(Debug, PartialEq, Eq)]
pub enum FromWorker {
    Invoke {
        operation: u32,
        target: u64,
    },
    FollowSource {
        resource: u32,
        id: u64,
    },
    Follow {
        operation: u32,
    },
    Done {
        fuel_left: u64,
        calls_left: u32,
        outcome: Outcome,
    },
}

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Output(Vec<u8>),
    Deadline,
    Failed,
}

struct Fields<'a>(&'a [u8]);
impl<'a> Fields<'a> {
    fn take<const N: usize>(&mut self) -> Result<[u8; N]> {
        ensure!(self.0.len() >= N, "truncated worker message");
        let (head, tail) = self.0.split_at(N);
        self.0 = tail;
        Ok(head.try_into()?)
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take()?))
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.take()?))
    }
    fn end(self) -> Result<()> {
        ensure!(self.0.is_empty(), "trailing worker message bytes");
        Ok(())
    }
}

impl ToWorker {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        match self {
            Self::Run {
                fuel,
                calls,
                wall_millis,
                request,
            } => {
                ensure!(request.len() <= MAX_REQUEST_BYTES, "request limit");
                out.push(1);
                out.extend_from_slice(&fuel.to_le_bytes());
                out.extend_from_slice(&calls.to_le_bytes());
                out.extend_from_slice(&wall_millis.to_le_bytes());
                out.extend_from_slice(request);
            }
            Self::Reply(Some(bytes)) => {
                ensure!(bytes.len() <= MAX_RESULT_BYTES, "result limit");
                out.push(2);
                out.extend_from_slice(bytes);
            }
            Self::Reply(None) => out.push(3),
        }
        Ok(out)
    }
    pub fn decode(frame: &[u8]) -> Result<Self> {
        let (tag, rest) = frame
            .split_first()
            .ok_or_else(|| anyhow::anyhow!("empty message"))?;
        let mut fields = Fields(rest);
        Ok(match tag {
            1 => Self::Run {
                fuel: fields.u64()?,
                calls: fields.u32()?,
                wall_millis: fields.u64()?,
                request: fields.0.to_vec(),
            },
            2 => Self::Reply(Some(rest.to_vec())),
            3 => {
                fields.end()?;
                Self::Reply(None)
            }
            _ => bail!("unknown server message"),
        })
    }
}

impl FromWorker {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        match self {
            Self::Invoke { operation, target } => {
                out.push(1);
                out.extend_from_slice(&operation.to_le_bytes());
                out.extend_from_slice(&target.to_le_bytes());
            }
            Self::FollowSource { resource, id } => {
                out.push(2);
                out.extend_from_slice(&resource.to_le_bytes());
                out.extend_from_slice(&id.to_le_bytes());
            }
            Self::Follow { operation } => {
                out.push(3);
                out.extend_from_slice(&operation.to_le_bytes());
            }
            Self::Done {
                fuel_left,
                calls_left,
                outcome,
            } => {
                out.push(match outcome {
                    Outcome::Output(_) => 4,
                    Outcome::Deadline => 5,
                    Outcome::Failed => 6,
                });
                out.extend_from_slice(&fuel_left.to_le_bytes());
                out.extend_from_slice(&calls_left.to_le_bytes());
                if let Outcome::Output(bytes) = outcome {
                    ensure!(bytes.len() <= MAX_IR_BYTES, "output limit");
                    out.extend_from_slice(bytes);
                }
            }
        }
        Ok(out)
    }
    pub fn decode(frame: &[u8]) -> Result<Self> {
        let (tag, rest) = frame
            .split_first()
            .ok_or_else(|| anyhow::anyhow!("empty message"))?;
        let mut fields = Fields(rest);
        let message = match tag {
            1 => Self::Invoke {
                operation: fields.u32()?,
                target: fields.u64()?,
            },
            2 => Self::FollowSource {
                resource: fields.u32()?,
                id: fields.u64()?,
            },
            3 => Self::Follow {
                operation: fields.u32()?,
            },
            4..=6 => {
                let fuel_left = fields.u64()?;
                let calls_left = fields.u32()?;
                let outcome = match tag {
                    4 => {
                        ensure!(fields.0.len() <= MAX_IR_BYTES, "output limit");
                        let bytes = fields.0.to_vec();
                        fields.0 = &[];
                        Outcome::Output(bytes)
                    }
                    5 => Outcome::Deadline,
                    _ => Outcome::Failed,
                };
                Self::Done {
                    fuel_left,
                    calls_left,
                    outcome,
                }
            }
            _ => bail!("unknown worker message"),
        };
        fields.end()?;
        Ok(message)
    }
}

pub async fn send(stream: &mut (impl AsyncWrite + Unpin), body: &[u8]) -> Result<()> {
    ensure!(body.len() <= MAX_FRAME, "message limit");
    let mut frame = Vec::with_capacity(body.len() + 4);
    frame.extend_from_slice(&(body.len() as u32).to_le_bytes());
    frame.extend_from_slice(body);
    stream.write_all(&frame).await?;
    Ok(())
}

/// The length is checked before anything is allocated for it.
pub async fn receive(stream: &mut (impl AsyncRead + Unpin)) -> Result<Vec<u8>> {
    let length = stream.read_u32_le().await? as usize;
    ensure!(length <= MAX_FRAME, "message limit");
    let mut body = vec![0; length];
    stream.read_exact(&mut body).await?;
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_round_trip() {
        for message in [
            FromWorker::Invoke {
                operation: 3,
                target: 9,
            },
            FromWorker::FollowSource { resource: 1, id: 2 },
            FromWorker::Follow { operation: 4 },
            FromWorker::Done {
                fuel_left: 5,
                calls_left: 6,
                outcome: Outcome::Output(vec![7]),
            },
            FromWorker::Done {
                fuel_left: 5,
                calls_left: 6,
                outcome: Outcome::Deadline,
            },
            FromWorker::Done {
                fuel_left: 5,
                calls_left: 6,
                outcome: Outcome::Failed,
            },
        ] {
            assert_eq!(
                FromWorker::decode(&message.encode().unwrap()).unwrap(),
                message
            );
        }
        for message in [
            ToWorker::Run {
                fuel: 1,
                calls: 2,
                wall_millis: 3,
                request: vec![4],
            },
            ToWorker::Reply(Some(vec![5])),
            ToWorker::Reply(None),
        ] {
            assert_eq!(
                ToWorker::decode(&message.encode().unwrap()).unwrap(),
                message
            );
        }
    }

    #[test]
    fn malformed_worker_messages_are_rejected() {
        let invoke = FromWorker::Invoke {
            operation: 1,
            target: 2,
        }
        .encode()
        .unwrap();
        for frame in [&[][..], &[0], &[99, 1], &invoke[..5]] {
            assert!(FromWorker::decode(frame).is_err());
        }
        let mut trailing = invoke;
        trailing.push(0);
        assert!(FromWorker::decode(&trailing).is_err());
        let mut failed = vec![6];
        failed.extend_from_slice(&[0; 12]);
        failed.push(1);
        assert!(FromWorker::decode(&failed).is_err());
    }

    #[tokio::test]
    async fn an_oversized_length_is_rejected_before_allocating() {
        let frame = u32::MAX.to_le_bytes();
        let mut reader = &frame[..];
        assert!(receive(&mut reader).await.is_err());
    }
}
