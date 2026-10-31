//! Fixed bounded jobs metadata; schema activation is coordinator-owned.
use super::{Backend, Transaction};
use anyhow::{Result, ensure};
pub(super) const TABLES: &[super::blob_layout::Table] = &[
    (
        "nx_job_runtime",
        &[
            ("singleton", "BIGINT"),
            ("deployment", "TEXT"),
            ("contract", "TEXT"),
            ("epoch", "TEXT"),
            ("state", "TEXT"),
            ("pending_limit", "BIGINT"),
            ("tenant_limit", "BIGINT"),
            ("concurrency", "BIGINT"),
        ],
    ),
    (
        "nx_job_queue",
        &[("singleton", "BIGINT"), ("claim_seq", "BIGINT")],
    ),
    (
        "nx_job_grants",
        &[
            ("deployment", "TEXT"),
            ("tenant", "TEXT"),
            ("worker", "TEXT"),
            ("version", "BIGINT"),
            ("contract", "TEXT"),
            ("epoch", "TEXT"),
            ("state", "TEXT"),
            ("declaration", "TEXT"),
        ],
    ),
    (
        "nx_job_tenants",
        &[
            ("deployment", "TEXT"),
            ("tenant", "TEXT"),
            ("claim_seq", "BIGINT"),
        ],
    ),
    (
        "nx_jobs",
        &[
            ("id", "TEXT"),
            ("deployment", "TEXT"),
            ("tenant", "TEXT"),
            ("origin", "TEXT"),
            ("ordinal", "BIGINT"),
            ("worker", "TEXT"),
            ("action", "BIGINT"),
            ("contract", "TEXT"),
            ("epoch", "TEXT"),
            ("grant_version", "BIGINT"),
            ("payload", "TEXT"),
            ("payload_digest", "TEXT"),
            ("due_ms", "BIGINT"),
            ("eligible_ms", "BIGINT"),
            ("first_eligible_ms", "BIGINT"),
            ("attempts", "BIGINT"),
            ("fence", "BIGINT"),
            ("lease_until_ms", "BIGINT"),
            ("state", "TEXT"),
            ("reason", "TEXT"),
            ("reconciled_from", "TEXT"),
        ],
    ),
    (
        "nx_job_recurring",
        &[
            ("deployment", "TEXT"),
            ("tenant", "TEXT"),
            ("name", "TEXT"),
            ("contract", "TEXT"),
            ("epoch", "TEXT"),
            ("grant_version", "BIGINT"),
            ("version", "BIGINT"),
            ("state", "TEXT"),
            ("next_ms", "BIGINT"),
            ("cutoff_ms", "BIGINT"),
            ("cutoff_seq", "BIGINT"),
            ("cursor", "TEXT"),
        ],
    ),
    (
        "nx_job_occurrences",
        &[
            ("deployment", "TEXT"),
            ("tenant", "TEXT"),
            ("schedule", "TEXT"),
            ("occurrence", "TEXT"),
            ("job", "TEXT"),
        ],
    ),
];
const SQLITE: &[&str] = &[
    "CREATE TABLE nx_job_runtime (singleton BIGINT PRIMARY KEY CHECK(typeof(singleton)='integer' AND singleton=1),deployment TEXT NOT NULL CHECK(length(CAST(deployment AS BLOB))>=1 AND length(CAST(deployment AS BLOB))<=64 AND instr(deployment,char(0))=0),contract TEXT NOT NULL CHECK(length(CAST(contract AS BLOB))>=1 AND length(CAST(contract AS BLOB))<=64 AND instr(contract,char(0))=0),epoch TEXT NOT NULL CHECK(length(CAST(epoch AS BLOB))>=1 AND length(CAST(epoch AS BLOB))<=64 AND instr(epoch,char(0))=0),state TEXT NOT NULL CHECK(state IN ('active','paused')),pending_limit BIGINT NOT NULL CHECK(typeof(pending_limit)='integer' AND pending_limit>=1 AND pending_limit<=1000),tenant_limit BIGINT NOT NULL CHECK(typeof(tenant_limit)='integer' AND tenant_limit>=1 AND tenant_limit<=1000),concurrency BIGINT NOT NULL CHECK(typeof(concurrency)='integer' AND concurrency>=1 AND concurrency<=2),CHECK(tenant_limit<=pending_limit))",
    "CREATE TABLE nx_job_queue (singleton BIGINT PRIMARY KEY CHECK(typeof(singleton)='integer' AND singleton=1),claim_seq BIGINT NOT NULL CHECK(typeof(claim_seq)='integer' AND claim_seq>=0))",
    "CREATE TABLE nx_job_grants (deployment TEXT NOT NULL CHECK(length(CAST(deployment AS BLOB))>=1 AND length(CAST(deployment AS BLOB))<=64 AND instr(deployment,char(0))=0),tenant TEXT NOT NULL CHECK(length(CAST(tenant AS BLOB))>=0 AND length(CAST(tenant AS BLOB))<=64 AND instr(tenant,char(0))=0),worker TEXT NOT NULL CHECK(length(CAST(worker AS BLOB))>=1 AND length(CAST(worker AS BLOB))<=64 AND instr(worker,char(0))=0),version BIGINT NOT NULL CHECK(typeof(version)='integer' AND version>=1),contract TEXT NOT NULL CHECK(length(CAST(contract AS BLOB))>=1 AND length(CAST(contract AS BLOB))<=64 AND instr(contract,char(0))=0),epoch TEXT NOT NULL CHECK(length(CAST(epoch AS BLOB))>=1 AND length(CAST(epoch AS BLOB))<=64 AND instr(epoch,char(0))=0),state TEXT NOT NULL CHECK(state IN ('active','revoked')),declaration TEXT NOT NULL CHECK(length(CAST(declaration AS BLOB))>=2 AND length(CAST(declaration AS BLOB))<=16384 AND instr(declaration,char(0))=0 AND json_valid(declaration) AND json_type(declaration)='object'),PRIMARY KEY(deployment,tenant,worker))",
    "CREATE TABLE nx_job_tenants (deployment TEXT NOT NULL CHECK(length(CAST(deployment AS BLOB))>=1 AND length(CAST(deployment AS BLOB))<=64 AND instr(deployment,char(0))=0),tenant TEXT NOT NULL CHECK(length(CAST(tenant AS BLOB))>=0 AND length(CAST(tenant AS BLOB))<=64 AND instr(tenant,char(0))=0),claim_seq BIGINT NOT NULL CHECK(typeof(claim_seq)='integer' AND claim_seq>=0),PRIMARY KEY(deployment,tenant))",
    "CREATE TABLE nx_jobs (id TEXT NOT NULL CHECK(length(CAST(id AS BLOB))>=1 AND length(CAST(id AS BLOB))<=64 AND instr(id,char(0))=0),deployment TEXT NOT NULL CHECK(length(CAST(deployment AS BLOB))>=1 AND length(CAST(deployment AS BLOB))<=64 AND instr(deployment,char(0))=0),tenant TEXT NOT NULL CHECK(length(CAST(tenant AS BLOB))>=0 AND length(CAST(tenant AS BLOB))<=64 AND instr(tenant,char(0))=0),origin TEXT NOT NULL CHECK(length(CAST(origin AS BLOB))>=1 AND length(CAST(origin AS BLOB))<=128 AND instr(origin,char(0))=0),ordinal BIGINT NOT NULL CHECK(typeof(ordinal)='integer' AND ordinal>=0 AND ordinal<=1),worker TEXT NOT NULL CHECK(length(CAST(worker AS BLOB))>=1 AND length(CAST(worker AS BLOB))<=64 AND instr(worker,char(0))=0),action BIGINT NOT NULL CHECK(typeof(action)='integer' AND action>=1),contract TEXT NOT NULL CHECK(length(CAST(contract AS BLOB))>=1 AND length(CAST(contract AS BLOB))<=64 AND instr(contract,char(0))=0),epoch TEXT NOT NULL CHECK(length(CAST(epoch AS BLOB))>=1 AND length(CAST(epoch AS BLOB))<=64 AND instr(epoch,char(0))=0),grant_version BIGINT NOT NULL CHECK(typeof(grant_version)='integer' AND grant_version>=1),payload TEXT NOT NULL CHECK(length(CAST(payload AS BLOB))>=2 AND length(CAST(payload AS BLOB))<=16384 AND instr(payload,char(0))=0 AND json_valid(payload) AND json_type(payload)='object'),payload_digest TEXT NOT NULL CHECK(length(CAST(payload_digest AS BLOB))>=1 AND length(CAST(payload_digest AS BLOB))<=64 AND instr(payload_digest,char(0))=0),due_ms BIGINT NOT NULL CHECK(typeof(due_ms)='integer' AND due_ms>=0),eligible_ms BIGINT NOT NULL CHECK(typeof(eligible_ms)='integer' AND eligible_ms>=0),first_eligible_ms BIGINT NOT NULL CHECK(typeof(first_eligible_ms)='integer' AND first_eligible_ms>=0),attempts BIGINT NOT NULL CHECK(typeof(attempts)='integer' AND attempts>=0 AND attempts<=5),fence BIGINT NOT NULL CHECK(typeof(fence)='integer' AND fence>=0),lease_until_ms BIGINT NOT NULL CHECK(typeof(lease_until_ms)='integer' AND lease_until_ms>=0),state TEXT NOT NULL CHECK(state IN ('pending','running','succeeded','rejected','dead','paused')),reason TEXT NOT NULL CHECK(length(CAST(reason AS BLOB))>=0 AND length(CAST(reason AS BLOB))<=24576 AND instr(reason,char(0))=0),reconciled_from TEXT CHECK(length(CAST(reconciled_from AS BLOB))>=1 AND length(CAST(reconciled_from AS BLOB))<=64 AND instr(reconciled_from,char(0))=0),PRIMARY KEY(id),UNIQUE(deployment,origin,ordinal),FOREIGN KEY(deployment,tenant) REFERENCES nx_job_tenants(deployment,tenant),FOREIGN KEY(reconciled_from) REFERENCES nx_jobs(id))",
    "CREATE TABLE nx_job_recurring (deployment TEXT NOT NULL CHECK(length(CAST(deployment AS BLOB))>=1 AND length(CAST(deployment AS BLOB))<=64 AND instr(deployment,char(0))=0),tenant TEXT NOT NULL CHECK(length(CAST(tenant AS BLOB))>=0 AND length(CAST(tenant AS BLOB))<=64 AND instr(tenant,char(0))=0),name TEXT NOT NULL CHECK(length(CAST(name AS BLOB))>=1 AND length(CAST(name AS BLOB))<=64 AND instr(name,char(0))=0),contract TEXT NOT NULL CHECK(length(CAST(contract AS BLOB))>=1 AND length(CAST(contract AS BLOB))<=64 AND instr(contract,char(0))=0),epoch TEXT NOT NULL CHECK(length(CAST(epoch AS BLOB))>=1 AND length(CAST(epoch AS BLOB))<=64 AND instr(epoch,char(0))=0),grant_version BIGINT NOT NULL CHECK(typeof(grant_version)='integer' AND grant_version>=1),version BIGINT NOT NULL CHECK(typeof(version)='integer' AND version>=1),state TEXT NOT NULL CHECK(state IN ('active','paused')),next_ms BIGINT NOT NULL CHECK(typeof(next_ms)='integer' AND next_ms>=0),cutoff_ms BIGINT NOT NULL CHECK(typeof(cutoff_ms)='integer' AND cutoff_ms>=0),cutoff_seq BIGINT NOT NULL CHECK(typeof(cutoff_seq)='integer' AND cutoff_seq>=0),cursor TEXT NOT NULL CHECK(length(CAST(cursor AS BLOB))>=0 AND length(CAST(cursor AS BLOB))<=4096 AND instr(cursor,char(0))=0),PRIMARY KEY(deployment,tenant,name))",
    "CREATE TABLE nx_job_occurrences (deployment TEXT NOT NULL CHECK(length(CAST(deployment AS BLOB))>=1 AND length(CAST(deployment AS BLOB))<=64 AND instr(deployment,char(0))=0),tenant TEXT NOT NULL CHECK(length(CAST(tenant AS BLOB))>=0 AND length(CAST(tenant AS BLOB))<=64 AND instr(tenant,char(0))=0),schedule TEXT NOT NULL CHECK(length(CAST(schedule AS BLOB))>=1 AND length(CAST(schedule AS BLOB))<=64 AND instr(schedule,char(0))=0),occurrence TEXT NOT NULL CHECK(length(CAST(occurrence AS BLOB))>=1 AND length(CAST(occurrence AS BLOB))<=64 AND instr(occurrence,char(0))=0),job TEXT NOT NULL CHECK(length(CAST(job AS BLOB))>=1 AND length(CAST(job AS BLOB))<=64 AND instr(job,char(0))=0),PRIMARY KEY(deployment,tenant,schedule,occurrence),FOREIGN KEY(job) REFERENCES nx_jobs(id))",
];
const POSTGRES: &[&str] = &[
    "CREATE TABLE nx_job_runtime (singleton BIGINT PRIMARY KEY CHECK(singleton=1),deployment TEXT NOT NULL CHECK(octet_length(deployment)>=1 AND octet_length(deployment)<=64),contract TEXT NOT NULL CHECK(octet_length(contract)>=1 AND octet_length(contract)<=64),epoch TEXT NOT NULL CHECK(octet_length(epoch)>=1 AND octet_length(epoch)<=64),state TEXT NOT NULL CHECK(state IN ('active','paused')),pending_limit BIGINT NOT NULL CHECK(pending_limit>=1 AND pending_limit<=1000),tenant_limit BIGINT NOT NULL CHECK(tenant_limit>=1 AND tenant_limit<=1000),concurrency BIGINT NOT NULL CHECK(concurrency>=1 AND concurrency<=2),CHECK(tenant_limit<=pending_limit))",
    "CREATE TABLE nx_job_queue (singleton BIGINT PRIMARY KEY CHECK(singleton=1),claim_seq BIGINT NOT NULL CHECK(claim_seq>=0))",
    "CREATE TABLE nx_job_grants (deployment TEXT NOT NULL CHECK(octet_length(deployment)>=1 AND octet_length(deployment)<=64),tenant TEXT NOT NULL CHECK(octet_length(tenant)>=0 AND octet_length(tenant)<=64),worker TEXT NOT NULL CHECK(octet_length(worker)>=1 AND octet_length(worker)<=64),version BIGINT NOT NULL CHECK(version>=1),contract TEXT NOT NULL CHECK(octet_length(contract)>=1 AND octet_length(contract)<=64),epoch TEXT NOT NULL CHECK(octet_length(epoch)>=1 AND octet_length(epoch)<=64),state TEXT NOT NULL CHECK(state IN ('active','revoked')),declaration TEXT NOT NULL CHECK(octet_length(declaration)>=2 AND octet_length(declaration)<=16384 AND jsonb_typeof(declaration::jsonb)='object'),PRIMARY KEY(deployment,tenant,worker))",
    "CREATE TABLE nx_job_tenants (deployment TEXT NOT NULL CHECK(octet_length(deployment)>=1 AND octet_length(deployment)<=64),tenant TEXT NOT NULL CHECK(octet_length(tenant)>=0 AND octet_length(tenant)<=64),claim_seq BIGINT NOT NULL CHECK(claim_seq>=0),PRIMARY KEY(deployment,tenant))",
    "CREATE TABLE nx_jobs (id TEXT NOT NULL CHECK(octet_length(id)>=1 AND octet_length(id)<=64),deployment TEXT NOT NULL CHECK(octet_length(deployment)>=1 AND octet_length(deployment)<=64),tenant TEXT NOT NULL CHECK(octet_length(tenant)>=0 AND octet_length(tenant)<=64),origin TEXT NOT NULL CHECK(octet_length(origin)>=1 AND octet_length(origin)<=128),ordinal BIGINT NOT NULL CHECK(ordinal>=0 AND ordinal<=1),worker TEXT NOT NULL CHECK(octet_length(worker)>=1 AND octet_length(worker)<=64),action BIGINT NOT NULL CHECK(action>=1),contract TEXT NOT NULL CHECK(octet_length(contract)>=1 AND octet_length(contract)<=64),epoch TEXT NOT NULL CHECK(octet_length(epoch)>=1 AND octet_length(epoch)<=64),grant_version BIGINT NOT NULL CHECK(grant_version>=1),payload TEXT NOT NULL CHECK(octet_length(payload)>=2 AND octet_length(payload)<=16384 AND jsonb_typeof(payload::jsonb)='object'),payload_digest TEXT NOT NULL CHECK(octet_length(payload_digest)>=1 AND octet_length(payload_digest)<=64),due_ms BIGINT NOT NULL CHECK(due_ms>=0),eligible_ms BIGINT NOT NULL CHECK(eligible_ms>=0),first_eligible_ms BIGINT NOT NULL CHECK(first_eligible_ms>=0),attempts BIGINT NOT NULL CHECK(attempts>=0 AND attempts<=5),fence BIGINT NOT NULL CHECK(fence>=0),lease_until_ms BIGINT NOT NULL CHECK(lease_until_ms>=0),state TEXT NOT NULL CHECK(state IN ('pending','running','succeeded','rejected','dead','paused')),reason TEXT NOT NULL CHECK(octet_length(reason)>=0 AND octet_length(reason)<=24576),reconciled_from TEXT CHECK(octet_length(reconciled_from)>=1 AND octet_length(reconciled_from)<=64),PRIMARY KEY(id),UNIQUE(deployment,origin,ordinal),FOREIGN KEY(deployment,tenant) REFERENCES nx_job_tenants(deployment,tenant),FOREIGN KEY(reconciled_from) REFERENCES nx_jobs(id))",
    "CREATE TABLE nx_job_recurring (deployment TEXT NOT NULL CHECK(octet_length(deployment)>=1 AND octet_length(deployment)<=64),tenant TEXT NOT NULL CHECK(octet_length(tenant)>=0 AND octet_length(tenant)<=64),name TEXT NOT NULL CHECK(octet_length(name)>=1 AND octet_length(name)<=64),contract TEXT NOT NULL CHECK(octet_length(contract)>=1 AND octet_length(contract)<=64),epoch TEXT NOT NULL CHECK(octet_length(epoch)>=1 AND octet_length(epoch)<=64),grant_version BIGINT NOT NULL CHECK(grant_version>=1),version BIGINT NOT NULL CHECK(version>=1),state TEXT NOT NULL CHECK(state IN ('active','paused')),next_ms BIGINT NOT NULL CHECK(next_ms>=0),cutoff_ms BIGINT NOT NULL CHECK(cutoff_ms>=0),cutoff_seq BIGINT NOT NULL CHECK(cutoff_seq>=0),cursor TEXT NOT NULL CHECK(octet_length(cursor)>=0 AND octet_length(cursor)<=4096),PRIMARY KEY(deployment,tenant,name))",
    "CREATE TABLE nx_job_occurrences (deployment TEXT NOT NULL CHECK(octet_length(deployment)>=1 AND octet_length(deployment)<=64),tenant TEXT NOT NULL CHECK(octet_length(tenant)>=0 AND octet_length(tenant)<=64),schedule TEXT NOT NULL CHECK(octet_length(schedule)>=1 AND octet_length(schedule)<=64),occurrence TEXT NOT NULL CHECK(octet_length(occurrence)>=1 AND octet_length(occurrence)<=64),job TEXT NOT NULL CHECK(octet_length(job)>=1 AND octet_length(job)<=64),PRIMARY KEY(deployment,tenant,schedule,occurrence),FOREIGN KEY(job) REFERENCES nx_jobs(id))",
];
pub(super) const INDEXES: &[(&str, &str)] = &[
    (
        "nx_jobs_eligible",
        "CREATE INDEX nx_jobs_eligible ON nx_jobs(deployment,state,eligible_ms,id)",
    ),
    (
        "nx_jobs_quota",
        "CREATE INDEX nx_jobs_quota ON nx_jobs(state,tenant)",
    ),
];
const PG_CONSTRAINTS: &[(&str, &str, &str, &str)] = &[
    ("nx_job_runtime", "p", "PRIMARY KEY(singleton)", ""),
    ("nx_job_runtime", "c", "CHECK(singleton=1)", ""),
    (
        "nx_job_runtime",
        "c",
        "CHECK(octet_length(deployment)>=1 AND octet_length(deployment)<=64)",
        "",
    ),
    (
        "nx_job_runtime",
        "c",
        "CHECK(octet_length(contract)>=1 AND octet_length(contract)<=64)",
        "",
    ),
    (
        "nx_job_runtime",
        "c",
        "CHECK(octet_length(epoch)>=1 AND octet_length(epoch)<=64)",
        "",
    ),
    (
        "nx_job_runtime",
        "c",
        "CHECK(state=ANY(ARRAY['active'::text,'paused'::text]))",
        "",
    ),
    (
        "nx_job_runtime",
        "c",
        "CHECK(pending_limit>=1 AND pending_limit<=1000)",
        "",
    ),
    (
        "nx_job_runtime",
        "c",
        "CHECK(tenant_limit>=1 AND tenant_limit<=1000)",
        "",
    ),
    (
        "nx_job_runtime",
        "c",
        "CHECK(concurrency>=1 AND concurrency<=2)",
        "",
    ),
    (
        "nx_job_runtime",
        "c",
        "CHECK(tenant_limit<=pending_limit)",
        "",
    ),
    ("nx_job_queue", "p", "PRIMARY KEY(singleton)", ""),
    ("nx_job_queue", "c", "CHECK(singleton=1)", ""),
    ("nx_job_queue", "c", "CHECK(claim_seq>=0)", ""),
    (
        "nx_job_grants",
        "c",
        "CHECK(octet_length(deployment)>=1 AND octet_length(deployment)<=64)",
        "",
    ),
    (
        "nx_job_grants",
        "c",
        "CHECK(octet_length(tenant)>=0 AND octet_length(tenant)<=64)",
        "",
    ),
    (
        "nx_job_grants",
        "c",
        "CHECK(octet_length(worker)>=1 AND octet_length(worker)<=64)",
        "",
    ),
    ("nx_job_grants", "c", "CHECK(version>=1)", ""),
    (
        "nx_job_grants",
        "c",
        "CHECK(octet_length(contract)>=1 AND octet_length(contract)<=64)",
        "",
    ),
    (
        "nx_job_grants",
        "c",
        "CHECK(octet_length(epoch)>=1 AND octet_length(epoch)<=64)",
        "",
    ),
    (
        "nx_job_grants",
        "c",
        "CHECK(state=ANY(ARRAY['active'::text,'revoked'::text]))",
        "",
    ),
    (
        "nx_job_grants",
        "c",
        "CHECK(octet_length(declaration)>=2 AND octet_length(declaration)<=16384 AND jsonb_typeof(declaration::jsonb)='object')",
        "",
    ),
    (
        "nx_job_grants",
        "p",
        "PRIMARY KEY(deployment,tenant,worker)",
        "",
    ),
    (
        "nx_job_tenants",
        "c",
        "CHECK(octet_length(deployment)>=1 AND octet_length(deployment)<=64)",
        "",
    ),
    (
        "nx_job_tenants",
        "c",
        "CHECK(octet_length(tenant)>=0 AND octet_length(tenant)<=64)",
        "",
    ),
    ("nx_job_tenants", "c", "CHECK(claim_seq>=0)", ""),
    ("nx_job_tenants", "p", "PRIMARY KEY(deployment,tenant)", ""),
    (
        "nx_jobs",
        "c",
        "CHECK(octet_length(id)>=1 AND octet_length(id)<=64)",
        "",
    ),
    (
        "nx_jobs",
        "c",
        "CHECK(octet_length(deployment)>=1 AND octet_length(deployment)<=64)",
        "",
    ),
    (
        "nx_jobs",
        "c",
        "CHECK(octet_length(tenant)>=0 AND octet_length(tenant)<=64)",
        "",
    ),
    (
        "nx_jobs",
        "c",
        "CHECK(octet_length(origin)>=1 AND octet_length(origin)<=128)",
        "",
    ),
    ("nx_jobs", "c", "CHECK(ordinal>=0 AND ordinal<=1)", ""),
    (
        "nx_jobs",
        "c",
        "CHECK(octet_length(worker)>=1 AND octet_length(worker)<=64)",
        "",
    ),
    ("nx_jobs", "c", "CHECK(action>=1)", ""),
    (
        "nx_jobs",
        "c",
        "CHECK(octet_length(contract)>=1 AND octet_length(contract)<=64)",
        "",
    ),
    (
        "nx_jobs",
        "c",
        "CHECK(octet_length(epoch)>=1 AND octet_length(epoch)<=64)",
        "",
    ),
    ("nx_jobs", "c", "CHECK(grant_version>=1)", ""),
    (
        "nx_jobs",
        "c",
        "CHECK(octet_length(payload)>=2 AND octet_length(payload)<=16384 AND jsonb_typeof(payload::jsonb)='object')",
        "",
    ),
    (
        "nx_jobs",
        "c",
        "CHECK(octet_length(payload_digest)>=1 AND octet_length(payload_digest)<=64)",
        "",
    ),
    ("nx_jobs", "c", "CHECK(due_ms>=0)", ""),
    ("nx_jobs", "c", "CHECK(eligible_ms>=0)", ""),
    ("nx_jobs", "c", "CHECK(first_eligible_ms>=0)", ""),
    ("nx_jobs", "c", "CHECK(attempts>=0 AND attempts<=5)", ""),
    ("nx_jobs", "c", "CHECK(fence>=0)", ""),
    ("nx_jobs", "c", "CHECK(lease_until_ms>=0)", ""),
    (
        "nx_jobs",
        "c",
        "CHECK(state=ANY(ARRAY['pending'::text,'running'::text,'succeeded'::text,'rejected'::text,'dead'::text,'paused'::text]))",
        "",
    ),
    (
        "nx_jobs",
        "c",
        "CHECK(octet_length(reason)>=0 AND octet_length(reason)<=24576)",
        "",
    ),
    (
        "nx_jobs",
        "c",
        "CHECK(octet_length(reconciled_from)>=1 AND octet_length(reconciled_from)<=64)",
        "",
    ),
    ("nx_jobs", "p", "PRIMARY KEY(id)", ""),
    ("nx_jobs", "u", "UNIQUE(deployment,origin,ordinal)", ""),
    (
        "nx_jobs",
        "f",
        "FOREIGN KEY(deployment,tenant) REFERENCES nx_job_tenants(deployment,tenant)",
        "nx_job_tenants",
    ),
    (
        "nx_jobs",
        "f",
        "FOREIGN KEY(reconciled_from) REFERENCES nx_jobs(id)",
        "nx_jobs",
    ),
    (
        "nx_job_recurring",
        "c",
        "CHECK(octet_length(deployment)>=1 AND octet_length(deployment)<=64)",
        "",
    ),
    (
        "nx_job_recurring",
        "c",
        "CHECK(octet_length(tenant)>=0 AND octet_length(tenant)<=64)",
        "",
    ),
    (
        "nx_job_recurring",
        "c",
        "CHECK(octet_length(name)>=1 AND octet_length(name)<=64)",
        "",
    ),
    (
        "nx_job_recurring",
        "c",
        "CHECK(octet_length(contract)>=1 AND octet_length(contract)<=64)",
        "",
    ),
    (
        "nx_job_recurring",
        "c",
        "CHECK(octet_length(epoch)>=1 AND octet_length(epoch)<=64)",
        "",
    ),
    ("nx_job_recurring", "c", "CHECK(grant_version>=1)", ""),
    ("nx_job_recurring", "c", "CHECK(version>=1)", ""),
    (
        "nx_job_recurring",
        "c",
        "CHECK(state=ANY(ARRAY['active'::text,'paused'::text]))",
        "",
    ),
    ("nx_job_recurring", "c", "CHECK(next_ms>=0)", ""),
    ("nx_job_recurring", "c", "CHECK(cutoff_ms>=0)", ""),
    ("nx_job_recurring", "c", "CHECK(cutoff_seq>=0)", ""),
    (
        "nx_job_recurring",
        "c",
        "CHECK(octet_length(cursor)>=0 AND octet_length(cursor)<=4096)",
        "",
    ),
    (
        "nx_job_recurring",
        "p",
        "PRIMARY KEY(deployment,tenant,name)",
        "",
    ),
    (
        "nx_job_occurrences",
        "c",
        "CHECK(octet_length(deployment)>=1 AND octet_length(deployment)<=64)",
        "",
    ),
    (
        "nx_job_occurrences",
        "c",
        "CHECK(octet_length(tenant)>=0 AND octet_length(tenant)<=64)",
        "",
    ),
    (
        "nx_job_occurrences",
        "c",
        "CHECK(octet_length(schedule)>=1 AND octet_length(schedule)<=64)",
        "",
    ),
    (
        "nx_job_occurrences",
        "c",
        "CHECK(octet_length(occurrence)>=1 AND octet_length(occurrence)<=64)",
        "",
    ),
    (
        "nx_job_occurrences",
        "c",
        "CHECK(octet_length(job)>=1 AND octet_length(job)<=64)",
        "",
    ),
    (
        "nx_job_occurrences",
        "p",
        "PRIMARY KEY(deployment,tenant,schedule,occurrence)",
        "",
    ),
    (
        "nx_job_occurrences",
        "f",
        "FOREIGN KEY(job) REFERENCES nx_jobs(id)",
        "nx_jobs",
    ),
];

pub(super) fn table_sql(tx: &Transaction) -> Result<&'static [&'static str]> {
    match tx.backend {
        Backend::Sqlite(_) => Ok(SQLITE),
        Backend::Postgres(_) => Ok(POSTGRES),
        Backend::Closed => anyhow::bail!("closed job metadata transaction"),
    }
}
// Only these fixed host DDL declarations are compared. Preserve literal bytes.
fn ddl_key(sql: &str) -> String {
    let mut out = String::new();
    let mut quote = None;
    for c in sql.chars() {
        if let Some(q) = quote {
            out.push(c);
            if c == q {
                quote = None
            }
        } else if matches!(c, '\'' | '"') {
            quote = Some(c);
            out.push(c)
        } else if !c.is_ascii_whitespace() && !matches!(c, '(' | ')' | ';') {
            out.push(c.to_ascii_lowercase())
        }
    }
    out.replace("'::text", "'")
}
impl Transaction {
    pub(crate) async fn check_job_layout(&mut self) -> Result<()> {
        for ((name, _), sql) in TABLES.iter().zip(SQLITE) {
            match self.backend {
                Backend::Sqlite(_) => {
                    let actual=self.fetch::<1>("SELECT CASE WHEN length(CAST(sql AS BLOB))<=16384 THEN sql ELSE NULL END FROM sqlite_schema WHERE type='table' AND name=$1",&[(*name).into()]).await?;
                    ensure!(
                        actual.len() == 1 && ddl_key(&actual[0][0]) == ddl_key(sql),
                        "invalid job metadata constraints in {name}"
                    );
                }
                Backend::Postgres(_) => {
                    let rows=self.fetch::<6>("SELECT CAST(c.contype AS TEXT),CASE WHEN octet_length(pg_catalog.pg_get_constraintdef(c.oid))<=4096 THEN pg_catalog.pg_get_constraintdef(c.oid) ELSE NULL END,CASE WHEN c.convalidated AND c.conenforced AND NOT c.condeferrable AND NOT c.condeferred THEN '1' ELSE '0' END,n.nspname,COALESCE(rn.nspname,''),COALESCE(r.relname,'') FROM pg_catalog.pg_constraint c JOIN pg_catalog.pg_class t ON t.oid=c.conrelid JOIN pg_catalog.pg_namespace n ON n.oid=t.relnamespace LEFT JOIN pg_catalog.pg_class r ON r.oid=c.confrelid LEFT JOIN pg_catalog.pg_namespace rn ON rn.oid=r.relnamespace WHERE n.nspname=current_schema() AND t.relname=$1 AND c.contype IN ('p','u','f','c') ORDER BY c.oid LIMIT 33",&[(*name).into()]).await?;
                    let mut actual = Vec::new();
                    for [kind, definition, valid, namespace, target_namespace, target] in rows {
                        ensure!(valid == "1", "inactive job metadata constraint");
                        if kind == "f" {
                            ensure!(
                                namespace == target_namespace,
                                "foreign job metadata namespace"
                            );
                        }
                        actual.push((kind, ddl_key(&definition), target));
                    }
                    let mut expected = PG_CONSTRAINTS
                        .iter()
                        .filter(|(table, ..)| table == name)
                        .map(|(_, kind, definition, target)| {
                            (kind.to_string(), ddl_key(definition), target.to_string())
                        })
                        .collect::<Vec<_>>();
                    actual.sort();
                    expected.sort();
                    ensure!(
                        actual == expected,
                        "invalid job metadata constraints in {name}"
                    );
                }
                Backend::Closed => anyhow::bail!("closed job metadata transaction"),
            }
        }
        for (name, expected) in INDEXES {
            let rows = match self.backend {
                Backend::Sqlite(_) => self.fetch::<4>("SELECT tbl_name,CASE WHEN length(CAST(sql AS BLOB))<=4096 THEN sql ELSE NULL END,'','1' FROM sqlite_schema WHERE type='index' AND name=$1", &[(*name).into()]).await?,
                Backend::Postgres(_) => self.fetch::<4>("SELECT t.relname,CASE WHEN octet_length(pg_catalog.pg_get_indexdef(i.indexrelid))<=4096 THEN pg_catalog.pg_get_indexdef(i.indexrelid) ELSE NULL END,pg_catalog.quote_ident(ts.nspname),CASE WHEN i.indisvalid AND i.indisready AND i.indislive AND NOT i.indisunique AND NOT i.indisexclusion AND i.indpred IS NULL THEN '1' ELSE '0' END FROM pg_catalog.pg_index i JOIN pg_catalog.pg_class n ON n.oid=i.indexrelid JOIN pg_catalog.pg_class t ON t.oid=i.indrelid JOIN pg_catalog.pg_namespace s ON s.oid=n.relnamespace JOIN pg_catalog.pg_namespace ts ON ts.oid=t.relnamespace WHERE s.nspname=current_schema() AND ts.oid=s.oid AND n.relname=$1", &[(*name).into()]).await?,
                Backend::Closed => anyhow::bail!("closed job metadata transaction"),
            };
            let [[table, definition, namespace, usable]] = rows.as_slice() else {
                anyhow::bail!("missing job metadata index");
            };
            let expected = if namespace.is_empty() {
                (*expected).to_owned()
            } else {
                expected.replace(
                    " ON nx_jobs(",
                    &format!(" ON {namespace}.nx_jobs USING btree ("),
                )
            };
            ensure!(
                table == "nx_jobs" && usable == "1" && ddl_key(definition) == ddl_key(&expected),
                "wrong job metadata index shape {name}"
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
