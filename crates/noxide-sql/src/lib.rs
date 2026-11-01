//! The only way to make SQL text in Noxide. A [`Sql`] value is composed from
//! string literals, checked identifiers, numbers and other `Sql` values, so runtime
//! data cannot become statement text; it travels as bound [`Param`]s. No function
//! here accepts a runtime string as text, and the store accepts nothing but `Sql`.
//!
//! Runtime strings do not compile, in any position:
//! ```compile_fail
//! let table = String::from("records");
//! noxide_sql::sql!("SELECT 1 FROM {table}");
//! ```
//! ```compile_fail
//! fn query(table: &str) -> noxide_sql::Sql {
//!     noxide_sql::sql!("SELECT 1 FROM {table}")
//! }
//! ```
//! ```compile_fail
//! let text = String::from("SELECT 1");
//! noxide_sql::sql!(text);
//! ```
//! ```compile_fail
//! fn statement(text: String) -> noxide_sql::Sql {
//!     text.into()
//! }
//! ```
#![forbid(unsafe_code)]
#[cfg(test)]
extern crate self as noxide_sql;
use anyhow::{Result, ensure};
use std::{borrow::Cow, fmt};

pub use noxide_sql_macros::sql;

/// A bound statement parameter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Param {
    Text(String),
    Number(i64),
}
impl From<&str> for Param {
    fn from(s: &str) -> Self {
        Self::Text(s.into())
    }
}
impl From<String> for Param {
    fn from(s: String) -> Self {
        Self::Text(s)
    }
}
impl From<i64> for Param {
    fn from(n: i64) -> Self {
        Self::Number(n)
    }
}

/// Statement text. Holds no connection and grants no authority.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Sql(Cow<'static, str>);

impl Sql {
    pub const fn empty() -> Self {
        Self(Cow::Borrowed(""))
    }
    pub const fn statement(text: &'static str) -> Self {
        Self(Cow::Borrowed(text))
    }
    /// An unquoted identifier: ASCII letters, digits and underscores, at most 64
    /// bytes, not starting with a digit.
    pub fn identifier(name: &str) -> Result<Self> {
        ensure!(
            !name.is_empty()
                && name.len() <= 64
                && !name.starts_with(|c: char| c.is_ascii_digit())
                && name.bytes().all(|b| b == b'_' || b.is_ascii_alphanumeric()),
            "invalid SQL identifier"
        );
        Ok(Self(Cow::Owned(name.to_owned())))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    pub fn push(&mut self, part: impl SqlArg) {
        let mut out = std::mem::take(&mut self.0).into_owned();
        part.piece().write(&mut out);
        self.0 = Cow::Owned(out);
    }
    pub fn join<T: SqlArg>(parts: impl IntoIterator<Item = T>, separator: &'static str) -> Self {
        let mut out = String::new();
        for (index, part) in parts.into_iter().enumerate() {
            if index > 0 {
                out.push_str(separator);
            }
            part.piece().write(&mut out);
        }
        Self(Cow::Owned(out))
    }
    #[doc(hidden)]
    pub fn __assemble(pieces: &[Piece<'_>]) -> Self {
        let mut out = String::new();
        for piece in pieces {
            piece.write(&mut out);
        }
        Self(Cow::Owned(out))
    }
}
impl fmt::Display for Sql {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl From<&'static str> for Sql {
    fn from(text: &'static str) -> Self {
        Self::statement(text)
    }
}
impl From<&&'static str> for Sql {
    fn from(text: &&'static str) -> Self {
        Self::statement(text)
    }
}
impl From<&Sql> for Sql {
    fn from(sql: &Sql) -> Self {
        sql.clone()
    }
}
impl PartialEq<str> for Sql {
    fn eq(&self, other: &str) -> bool {
        self.as_str() == other
    }
}
impl PartialEq<&str> for Sql {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}
impl PartialEq<String> for Sql {
    fn eq(&self, other: &String) -> bool {
        self.as_str() == other
    }
}
#[cfg(feature = "test-support")]
impl From<String> for Sql {
    fn from(text: String) -> Self {
        Self(Cow::Owned(text))
    }
}
#[cfg(feature = "test-support")]
impl From<&String> for Sql {
    fn from(text: &String) -> Self {
        Self(Cow::Owned(text.clone()))
    }
}

/// `Sql::join` as a method on a list of fragments.
pub trait JoinSql {
    fn joined(&self, separator: &'static str) -> Sql;
}
impl JoinSql for [Sql] {
    fn joined(&self, separator: &'static str) -> Sql {
        Sql::join(self, separator)
    }
}

#[doc(hidden)]
pub enum Piece<'a> {
    Text(&'static str),
    Sql(&'a str),
    Number(i128),
}
impl Piece<'_> {
    fn write(&self, out: &mut String) {
        match self {
            Self::Text(text) => out.push_str(text),
            Self::Sql(text) => out.push_str(text),
            Self::Number(number) => out.push_str(&number.to_string()),
        }
    }
}

/// What may appear in SQL text. Deliberately not implemented for `String` or
/// non-`'static` `&str`.
pub trait SqlArg {
    fn piece(&self) -> Piece<'_>;
}
impl SqlArg for Sql {
    fn piece(&self) -> Piece<'_> {
        Piece::Sql(&self.0)
    }
}
impl SqlArg for &'static str {
    fn piece(&self) -> Piece<'_> {
        Piece::Text(self)
    }
}
impl<T: SqlArg> SqlArg for &T {
    fn piece(&self) -> Piece<'_> {
        (**self).piece()
    }
}
macro_rules! numbers {
    ($($number:ty),*) => {$(impl SqlArg for $number {
        fn piece(&self) -> Piece<'_> {
            Piece::Number(*self as i128)
        }
    })*};
}
numbers!(i16, i32, i64, u8, u16, u32, u64, usize);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn templates_compose_literals_numbers_and_fragments() {
        let column = Sql::identifier("created_seq").unwrap();
        let (limit, placeholder) = (32_u8, 2_usize);
        let clause = sql!("{column}>${placeholder}");
        let statement = sql!(
            "SELECT '{{}}',{column} FROM t WHERE resource=$1 AND {clause} AND x='{}' LIMIT {limit}",
            "literal"
        );
        assert_eq!(
            statement.as_str(),
            "SELECT '{}',created_seq FROM t WHERE resource=$1 AND created_seq>$2 AND x='literal' LIMIT 32"
        );
    }
    #[test]
    fn identifiers_reject_everything_but_plain_names() {
        for bad in ["", "1a", "a b", "a'", "a;--", "a\"", "é", &"a".repeat(65)] {
            assert!(Sql::identifier(bad).is_err(), "{bad}");
        }
        assert!(Sql::identifier("nx_m_1f").is_ok());
    }
    #[test]
    fn join_and_push_build_lists() {
        let mut list = Sql::join([sql!("a"), sql!("b")], ",");
        list.push(",c");
        assert_eq!(list.as_str(), "a,b,c");
    }
}
