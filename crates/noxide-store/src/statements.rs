//! Every fixed statement the layers above the store may run. They cannot write
//! their own: only this crate can construct a `Statement`.
pub mod accounts;
pub mod blobs;
pub mod effects;
pub mod jobs;

use crate::database::{Param, Sql, Transaction};
use anyhow::Result;

/// A statement with `P` parameters returning `C` text columns. The compiler
/// rejects a call with the wrong number of either.
#[derive(Clone, Debug)]
pub struct Statement<const P: usize, const C: usize> {
    text: Sql,
}

impl<const P: usize, const C: usize> Statement<P, C> {
    pub(crate) const fn new(text: &'static str) -> Self {
        assert!(
            placeholders(text.as_bytes()) == P,
            "statement parameter count"
        );
        Self {
            text: Sql::statement(text),
        }
    }

    /// A statement whose text depends on the provider or a bounded column.
    pub(crate) fn built(text: Sql) -> Self {
        assert!(
            placeholders(text.as_str().as_bytes()) == P,
            "statement parameter count"
        );
        Self { text }
    }
}

/// The highest `$n` placeholder.
const fn placeholders(text: &[u8]) -> usize {
    let (mut index, mut highest) = (0, 0);
    while index < text.len() {
        if text[index] == b'$' {
            let mut number = 0;
            index += 1;
            while index < text.len() && text[index].is_ascii_digit() {
                number = number * 10 + (text[index] - b'0') as usize;
                index += 1;
            }
            if number > highest {
                highest = number;
            }
        } else {
            index += 1;
        }
    }
    highest
}

impl Transaction {
    pub async fn run<const P: usize>(
        &mut self,
        statement: &Statement<P, 0>,
        params: &[Param; P],
    ) -> Result<u64> {
        self.execute(statement.text.clone(), params).await
    }

    pub async fn rows<const P: usize, const C: usize>(
        &mut self,
        statement: &Statement<P, C>,
        params: &[Param; P],
    ) -> Result<Vec<[String; C]>> {
        self.fetch(statement.text.clone(), params).await
    }
}
