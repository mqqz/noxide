//! Application records, receipts and search postings.
use super::Statement;
use crate::database::{Param, Sql, Transaction, sql};
use crate::policy::AuthorizedFilter;
use crate::sql::JoinSql;
use anyhow::Result;

pub fn record_by_id(tx: &Transaction) -> Statement<2, 6> {
    let fields = tx.bounded_text("fields", 20_000);
    let incarnation = tx.bounded_text("incarnation", 64);
    Statement::built(sql!(
        "SELECT COALESCE(owner,''),tenant,{fields}, {incarnation},CAST(revision AS TEXT),COALESCE(CAST(cap_version AS TEXT),'') FROM nx_records WHERE resource=$1 AND id=$2"
    ))
}

pub fn child_referencing(storage: i64, field: &Sql) -> Statement<1, 1> {
    Statement::built(sql!(
        "SELECT CAST(id AS TEXT) FROM nx_records WHERE resource={storage} AND {field}=$1 LIMIT 1"
    ))
}

pub fn receipt(tx: &Transaction, maximum: usize) -> Statement<1, 4> {
    let outcome = tx.bounded_text("outcome", maximum);
    Statement::built(sql!(
        "SELECT subject,contract,input,{outcome} FROM nx_receipts WHERE nonce=$1"
    ))
}

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

    /// Load records by id with no policy filter. The caller must authorize every
    /// returned row before use.
    pub async fn records_by_ids<const N: usize>(
        &mut self,
        columns: &Sql,
        storage: i64,
        ids: &[i64],
    ) -> Result<Vec<[String; N]>> {
        let mut params = Vec::with_capacity(ids.len() + 1);
        params.push(Param::Number(storage));
        let mut slots = Vec::with_capacity(ids.len());
        for id in ids {
            params.push(Param::Number(*id));
            slots.push(sql!("${}", params.len()));
        }
        let slots = slots.joined(",");
        let limit = ids.len();
        self.fetch(
            sql!(
                "SELECT {columns} FROM nx_records WHERE resource=$1 AND resource={storage} AND id IN ({slots}) LIMIT {limit}"
            ),
            &params,
        )
        .await
    }

    /// Candidate identities from the posting index; `$1..$3` bind the resource,
    /// field and token, which fix the index prefix before the ordered limit.
    pub async fn posting_candidates(
        &mut self,
        restrictions: &Sql,
        direction: &'static str,
        limit: usize,
        params: &[Param],
    ) -> Result<Vec<[String; 4]>> {
        self.fetch(
            sql!(
                "SELECT CAST(p.created_seq AS TEXT),CAST(p.record_id AS TEXT),p.incarnation,CAST(p.revision AS TEXT) FROM nx_search_postings p WHERE p.resource=$1 AND p.field=$2 AND p.token=$3{restrictions} ORDER BY p.created_seq {direction},p.record_id {direction} LIMIT {limit}"
            ),
            params,
        )
        .await
    }

    /// Which of a sealed set of records hold every token.
    pub async fn postings_matching_all(
        &mut self,
        records: &Sql,
        fields: &Sql,
        tokens: &Sql,
        count: usize,
        params: &[Param],
    ) -> Result<Vec<[String; 3]>> {
        self.fetch(
            sql!(
                "SELECT CAST(record_id AS TEXT),incarnation,CAST(revision AS TEXT) FROM nx_search_postings WHERE resource=$1 AND record_id IN ({records}) AND field IN ({fields}) AND token IN ({tokens}) GROUP BY record_id,incarnation,revision HAVING COUNT(DISTINCT token)={count} LIMIT 64"
            ),
            params,
        )
        .await
    }

    /// Evaluate a membership predicate for each requested reference.
    pub async fn membership_witnesses(
        &mut self,
        requested: &Sql,
        predicate: &Sql,
        limit: usize,
        params: &[Param],
    ) -> Result<Vec<[String; 2]>> {
        let statement = sql!(
            "WITH requested AS ({requested}) SELECT reference_id,CASE WHEN {predicate} THEN '1' ELSE '0' END FROM requested LIMIT {limit}"
        );
        self.fetch(statement, params).await
    }
}
pub const ACTIVE_ACCOUNT_TENANT: Statement<1, 1> =
    Statement::new("SELECT tenant FROM nx_accounts WHERE id=$1 AND state='active' AND tenant<>''");
pub const ACTIVE_ACCOUNT_IN_TENANT: Statement<2, 1> =
    Statement::new("SELECT id FROM nx_accounts WHERE id=$1 AND state='active' AND tenant=$2");
pub const OWNER_RECORD_QUOTA: Statement<2, 1> = Statement::new(
    "SELECT CAST(COUNT(*) AS TEXT) FROM (SELECT id FROM nx_records WHERE resource=$1 AND owner=$2 LIMIT 10000) AS quota",
);
pub const INSERT_UNOWNED_RECORD: Statement<5, 0> = Statement::new(
    "INSERT INTO nx_records(resource,id,owner,tenant,fields,incarnation,revision,cap_version,created_seq) VALUES($1,$2,NULL,'',$3,$4,1,1,$5)",
);
pub const INSERT_OWNED_RECORD: Statement<7, 0> = Statement::new(
    "INSERT INTO nx_records(resource,id,owner,tenant,fields,incarnation,revision,created_seq) VALUES($1,$2,$3,$4,$5,$6,1,$7)",
);
pub const UPDATE_RECORD: Statement<6, 0> = Statement::new(
    "UPDATE nx_records SET fields=$5,revision=$6 WHERE resource=$1 AND id=$2 AND incarnation=$3 AND revision=$4",
);
pub const DELETE_RECORD: Statement<4, 0> = Statement::new(
    "DELETE FROM nx_records WHERE resource=$1 AND id=$2 AND incarnation=$3 AND revision=$4",
);
pub const READY_SEARCH_STATE: Statement<1, 2> = Statement::new(
    "SELECT tokenizer,declaration FROM nx_search_state WHERE resource=$1 AND version=1 AND state='ready'",
);
pub const RECORD_SEQUENCE: Statement<4, 1> = Statement::new(
    "SELECT CAST(created_seq AS TEXT) FROM nx_records WHERE resource=$1 AND id=$2 AND incarnation=$3 AND revision=$4",
);
pub const CLAIM_CAPABILITY_RECEIPT: Statement<5, 0> = Statement::new(
    "INSERT INTO nx_receipts(nonce,subject,contract,action,input,outcome,expires) VALUES($1,$2,$3,0,$4,'',$5) ON CONFLICT(nonce) DO NOTHING",
);
pub const ADVANCE_CAPABILITY_VERSION: Statement<4, 0> = Statement::new(
    "UPDATE nx_records SET cap_version=$1 WHERE resource=$2 AND id=$3 AND cap_version=$4",
);
pub const SET_RECEIPT_OUTCOME: Statement<2, 0> =
    Statement::new("UPDATE nx_receipts SET outcome=$1 WHERE nonce=$2");

pub const CLAIM_ACTION_RECEIPT: Statement<6, 0> = Statement::new(
    "INSERT INTO nx_receipts(nonce,subject,contract,action,input,outcome,expires) VALUES($1,$2,$3,$4,$5,'',$6) ON CONFLICT(nonce) DO NOTHING",
);
