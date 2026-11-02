//! Statements over application records.
use super::{Param, Result, Sql, Transaction, sql};
use crate::policy::AuthorizedFilter;

/// One policy-filtered, bounded read of `nx_records`. `$1` must bind `storage`.
pub struct RecordScan<'a> {
    pub columns: Sql,
    pub storage: i64,
    pub filter: &'a AuthorizedFilter,
    /// Further conditions, each starting with ` AND `.
    pub restrictions: Sql,
    pub order: Sql,
    pub limit: usize,
}

impl RecordScan<'_> {
    /// `restrictions` stay in their own parentheses, so they can narrow the
    /// filter but never widen it.
    fn sql(&self) -> Sql {
        let Self {
            columns,
            storage,
            filter,
            restrictions,
            order,
            limit,
        } = self;
        let filter = filter.sql();
        sql!(
            "SELECT {columns} FROM nx_records WHERE resource=$1 AND resource={storage} AND ({filter}) AND (1=1{restrictions}) ORDER BY {order} LIMIT {limit}"
        )
    }
}

impl Transaction {
    pub async fn scan_records<const N: usize>(
        &mut self,
        scan: RecordScan<'_>,
        params: &[Param],
    ) -> Result<Vec<[String; N]>> {
        anyhow::ensure!(
            params.first() == Some(&Param::Number(scan.storage)),
            "record scan storage parameter"
        );
        self.fetch(scan.sql(), params).await
    }
}
