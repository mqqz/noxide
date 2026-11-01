//! Conservative creation-order frontier used before token AND or Authority.
//! This only merges bounded facts; it creates no allowance or authorization.
use anyhow::{Result, ensure};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Key {
    pub sequence: u64,
    pub record: u64,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Seed {
    pub key: Key,
    pub incarnation: String,
    pub revision: i64,
}
pub struct Stream {
    pub field: u8,
    pub limit: usize,
    pub rows: Vec<Seed>,
}
pub struct Frontier {
    pub candidates: Vec<Seed>,
    /// Largest fully known prefix across all streams, not largest fetched key.
    /// Caller advances only through candidates actually consumed from that prefix.
    pub cutoff: Option<Key>,
    pub exhausted: bool,
    /// Internal work accounting only. Aliases are included, never refunded.
    pub planned_work: usize,
    pub observed_work: usize,
}
pub fn seal(
    streams: &[Stream],
    previous: Option<Key>,
    descending: bool,
    checkpoint: &mut impl FnMut() -> Result<()>,
) -> Result<Frontier> {
    checkpoint()?;
    ensure!(
        !streams.is_empty() && streams.len() <= 4,
        "posting stream count"
    );
    let mut fields = BTreeSet::new();
    let mut planned_work = 0usize;
    let mut observed_work = 0usize;
    let mut cutoff: Option<Key> = None;
    let mut merged: BTreeMap<Key, Seed> = BTreeMap::new();
    let mut identities: BTreeMap<u64, Key> = BTreeMap::new();
    let advances = |left: Key, right: Key| {
        if descending {
            left > right
        } else {
            left < right
        }
    };
    for stream in streams {
        checkpoint()?;
        ensure!(
            stream.field < 4 && fields.insert(stream.field),
            "posting stream field"
        );
        ensure!(
            (1..=64).contains(&stream.limit) && stream.rows.len() <= stream.limit,
            "posting stream window"
        );
        planned_work = planned_work
            .checked_add(stream.limit)
            .ok_or_else(|| anyhow::anyhow!("posting work overflow"))?;
        observed_work = observed_work
            .checked_add(stream.rows.len())
            .ok_or_else(|| anyhow::anyhow!("posting work overflow"))?;
        ensure!(planned_work <= 256, "posting work limit");
        let mut last = previous;
        for (index, seed) in stream.rows.iter().enumerate() {
            if index.is_multiple_of(64) {
                checkpoint()?;
            }
            ensure!(
                seed.key.sequence > 0
                    && seed.key.sequence <= i64::MAX as u64
                    && seed.key.record > 0
                    && seed.key.record <= i64::MAX as u64,
                "posting identity"
            );
            ensure!(
                seed.revision > 0 && !seed.incarnation.is_empty() && seed.incarnation.len() <= 64,
                "posting metadata"
            );
            if let Some(last) = last {
                ensure!(advances(last, seed.key), "posting stream order");
            }
            last = Some(seed.key);
            if let Some(key) = identities.insert(seed.key.record, seed.key) {
                ensure!(key == seed.key, "posting identity key mismatch");
            }
            if let Some(previous) = merged.insert(seed.key, seed.clone()) {
                ensure!(previous == *seed, "posting alias metadata mismatch");
            }
        }
        if stream.rows.len() == stream.limit {
            let boundary = stream.rows.last().expect("positive stream window").key;
            cutoff = Some(cutoff.map_or(boundary, |cutoff| {
                if descending {
                    cutoff.max(boundary)
                } else {
                    cutoff.min(boundary)
                }
            }));
        }
    }
    let mut candidates = Vec::new();
    for (index, seed) in merged.into_values().enumerate() {
        if index.is_multiple_of(64) {
            checkpoint()?;
        }
        if cutoff.is_none_or(|cutoff| !advances(cutoff, seed.key)) {
            candidates.push(seed);
        }
    }
    if descending {
        candidates.reverse();
    }
    checkpoint()?;
    Ok(Frontier {
        candidates,
        cutoff,
        exhausted: cutoff.is_none(),
        planned_work,
        observed_work,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn seal(streams: &[Stream], previous: Option<Key>, descending: bool) -> Result<Frontier> {
        super::seal(streams, previous, descending, &mut || Ok(()))
    }
    fn seed(sequence: u64) -> Seed {
        Seed {
            key: Key {
                sequence,
                record: sequence + 100,
            },
            incarnation: "incarnation".into(),
            revision: 1,
        }
    }
    fn stream(field: u8, limit: usize, keys: &[u64]) -> Stream {
        Stream {
            field,
            limit,
            rows: keys.iter().copied().map(seed).collect(),
        }
    }
    fn keys(frontier: &Frontier) -> Vec<u64> {
        frontier
            .candidates
            .iter()
            .map(|seed| seed.key.sequence)
            .collect()
    }

    #[test]
    fn empty_visible_prefix_cannot_skip_deferred_matches_in_another_field() {
        let first = seal(&[stream(0, 2, &[1, 2]), stream(1, 2, &[3, 4])], None, false).unwrap();
        assert_eq!(keys(&first), [1, 2]);
        assert_eq!(first.cutoff, Some(seed(2).key));
        assert!(!first.exhausted);
        // Both first-frontier rows may fail AND/current authorization. The empty
        // result advances through2; it must never jump to the fetched key4.
        let second = seal(
            &[stream(0, 2, &[]), stream(1, 2, &[3, 4])],
            first.cutoff,
            false,
        )
        .unwrap();
        assert_eq!(keys(&second), [3, 4]);
        let end = seal(
            &[stream(0, 2, &[]), stream(1, 2, &[])],
            second.cutoff,
            false,
        )
        .unwrap();
        assert!(end.exhausted && end.candidates.is_empty());
    }
    #[test]
    fn descending_aliases_keep_conservative_cutoff_and_full_raw_work() {
        let first = seal(&[stream(0, 2, &[6, 4]), stream(1, 2, &[6, 5])], None, true).unwrap();
        assert_eq!(keys(&first), [6, 5]);
        assert_eq!(first.cutoff, Some(seed(5).key));
        assert_eq!(first.planned_work, 4);
        assert_eq!(first.observed_work, 4);
        let next = seal(&[stream(0, 2, &[4]), stream(1, 2, &[])], first.cutoff, true).unwrap();
        assert_eq!(keys(&next), [4]);
        assert!(next.exhausted);
        assert_eq!(next.planned_work, 4);
        assert_eq!(next.observed_work, 1);
        let mut mismatch = stream(1, 2, &[6]);
        mismatch.rows[0].revision = 2;
        assert!(seal(&[stream(0, 2, &[6]), mismatch], None, true).is_err());
    }
    #[test]
    fn malformed_or_unbounded_frontiers_never_return_a_truncated_prefix() {
        for streams in [
            vec![],
            vec![stream(0, 0, &[])],
            vec![stream(0, 65, &[])],
            vec![stream(0, 1, &[1, 2])],
            vec![stream(0, 2, &[2, 1])],
            vec![stream(0, 2, &[1, 1])],
            vec![stream(0, 2, &[]), stream(0, 2, &[])],
            vec![stream(4, 1, &[])],
            vec![stream(0, 1, &[0])],
        ] {
            assert!(seal(&streams, None, false).is_err());
        }
        assert!(seal(&[stream(0, 1, &[2])], Some(seed(2).key), false).is_err());
        let mut malformed = stream(0, 1, &[1]);
        malformed.rows[0].incarnation = "x".repeat(65);
        assert!(seal(&[malformed], None, false).is_err());
        let mut malformed = stream(0, 1, &[1]);
        malformed.rows[0].key.record = u64::MAX;
        assert!(seal(&[malformed], None, false).is_err());
        let mut malformed = stream(0, 1, &[1]);
        malformed.rows[0].revision = 0;
        assert!(seal(&[malformed], None, false).is_err());
        let maximum = seal(
            &(0..4)
                .map(|field| stream(field, 64, &[]))
                .collect::<Vec<_>>(),
            None,
            false,
        )
        .unwrap();
        assert_eq!(maximum.planned_work, 256);
        assert_eq!(maximum.observed_work, 0);
        assert!(maximum.exhausted);
    }
    #[test]
    fn interrupted_work_never_returns_a_frontier_or_changes_the_original_error() {
        let streams: Vec<_> = (0..4)
            .map(|field| {
                stream(
                    field,
                    64,
                    &(1..=64)
                        .map(|key| key + u64::from(field) * 64)
                        .collect::<Vec<_>>(),
                )
            })
            .collect();
        let mut checkpoints = 0;
        super::seal(&streams, None, false, &mut || {
            checkpoints += 1;
            Ok(())
        })
        .unwrap();
        for stop in 1..=checkpoints {
            let mut calls = 0;
            let result = super::seal(&streams, None, false, &mut || {
                calls += 1;
                if calls == stop {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Interrupted,
                        "original work owner",
                    )
                    .into());
                }
                Ok(())
            });
            let error = result.err().expect("no partial frontier");
            assert_eq!(
                error.downcast_ref::<std::io::Error>().unwrap().kind(),
                std::io::ErrorKind::Interrupted
            );
            assert_eq!(calls, stop);
        }
    }
}
