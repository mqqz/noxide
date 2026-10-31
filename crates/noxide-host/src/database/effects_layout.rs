//! Fixed native outbox metadata. Epoch authority remains nx_job_runtime.
use super::{Backend, Transaction};
use anyhow::{Result, ensure};
pub(super) const TABLES: &[super::blob_layout::Table] = &[
    (
        "nx_effect_queue",
        &[
            ("singleton", "BIGINT"),
            ("claim_seq", "BIGINT"),
            ("store_id", "TEXT"),
            ("owner_directory", "TEXT"),
            ("pending_limit", "BIGINT"),
            ("tenant_limit", "BIGINT"),
            ("concurrency", "BIGINT"),
        ],
    ),
    (
        "nx_effect_grants",
        &[
            ("deployment", "TEXT"),
            ("tenant", "TEXT"),
            ("endpoint", "TEXT"),
            ("version", "BIGINT"),
            ("contract", "TEXT"),
            ("epoch", "TEXT"),
            ("state", "TEXT"),
            ("declaration", "TEXT"),
        ],
    ),
    (
        "nx_effect_secrets",
        &[
            ("deployment", "TEXT"),
            ("slot", "TEXT"),
            ("version", "BIGINT"),
            ("contract", "TEXT"),
            ("epoch", "TEXT"),
            ("state", "TEXT"),
        ],
    ),
    (
        "nx_effect_tenants",
        &[
            ("deployment", "TEXT"),
            ("tenant", "TEXT"),
            ("claim_seq", "BIGINT"),
        ],
    ),
    (
        "nx_outbox",
        &[
            ("id", "TEXT"),
            ("deployment", "TEXT"),
            ("tenant", "TEXT"),
            ("origin", "TEXT"),
            ("ordinal", "BIGINT"),
            ("endpoint", "TEXT"),
            ("contract", "TEXT"),
            ("epoch", "TEXT"),
            ("grant_version", "BIGINT"),
            ("secret_version", "BIGINT"),
            ("payload", "TEXT"),
            ("payload_digest", "TEXT"),
            ("eligible_ms", "BIGINT"),
            ("first_eligible_ms", "BIGINT"),
            ("attempts", "BIGINT"),
            ("fence", "BIGINT"),
            ("lease_until_ms", "BIGINT"),
            ("round", "BIGINT"),
            ("state", "TEXT"),
            ("reason", "TEXT"),
        ],
    ),
];
const SQLITE: &[&str] = &[
    "CREATE TABLE nx_effect_queue (singleton BIGINT NOT NULL CHECK(typeof(singleton)='integer' AND singleton=1),claim_seq BIGINT NOT NULL CHECK(typeof(claim_seq)='integer' AND claim_seq>=0),store_id TEXT NOT NULL CHECK(length(CAST(store_id AS BLOB))>=1 AND length(CAST(store_id AS BLOB))<=64 AND instr(store_id,char(0))=0),owner_directory TEXT NOT NULL CHECK(length(CAST(owner_directory AS BLOB))>=1 AND length(CAST(owner_directory AS BLOB))<=64 AND instr(owner_directory,char(0))=0),pending_limit BIGINT NOT NULL CHECK(typeof(pending_limit)='integer' AND pending_limit>=1 AND pending_limit<=1000),tenant_limit BIGINT NOT NULL CHECK(typeof(tenant_limit)='integer' AND tenant_limit>=1 AND tenant_limit<=1000),concurrency BIGINT NOT NULL CHECK(typeof(concurrency)='integer' AND concurrency>=1 AND concurrency<=2),PRIMARY KEY(singleton),CHECK(tenant_limit<=pending_limit))",
    "CREATE TABLE nx_effect_grants (deployment TEXT NOT NULL CHECK(length(CAST(deployment AS BLOB))>=1 AND length(CAST(deployment AS BLOB))<=64 AND instr(deployment,char(0))=0),tenant TEXT NOT NULL CHECK(length(CAST(tenant AS BLOB))>=0 AND length(CAST(tenant AS BLOB))<=64 AND instr(tenant,char(0))=0),endpoint TEXT NOT NULL CHECK(length(CAST(endpoint AS BLOB))>=1 AND length(CAST(endpoint AS BLOB))<=64 AND instr(endpoint,char(0))=0),version BIGINT NOT NULL CHECK(typeof(version)='integer' AND version>=1),contract TEXT NOT NULL CHECK(length(CAST(contract AS BLOB))>=1 AND length(CAST(contract AS BLOB))<=64 AND instr(contract,char(0))=0),epoch TEXT NOT NULL CHECK(length(CAST(epoch AS BLOB))>=1 AND length(CAST(epoch AS BLOB))<=64 AND instr(epoch,char(0))=0),state TEXT NOT NULL CHECK(state IN ('active','revoked')),declaration TEXT NOT NULL CHECK(length(CAST(declaration AS BLOB))>=2 AND length(CAST(declaration AS BLOB))<=16384 AND instr(declaration,char(0))=0 AND json_valid(declaration) AND json_type(declaration)='object'),PRIMARY KEY(deployment,tenant,endpoint))",
    "CREATE TABLE nx_effect_secrets (deployment TEXT NOT NULL CHECK(length(CAST(deployment AS BLOB))>=1 AND length(CAST(deployment AS BLOB))<=64 AND instr(deployment,char(0))=0),slot TEXT NOT NULL CHECK(length(CAST(slot AS BLOB))>=1 AND length(CAST(slot AS BLOB))<=64 AND instr(slot,char(0))=0),version BIGINT NOT NULL CHECK(typeof(version)='integer' AND version>=1),contract TEXT NOT NULL CHECK(length(CAST(contract AS BLOB))>=1 AND length(CAST(contract AS BLOB))<=64 AND instr(contract,char(0))=0),epoch TEXT NOT NULL CHECK(length(CAST(epoch AS BLOB))>=1 AND length(CAST(epoch AS BLOB))<=64 AND instr(epoch,char(0))=0),state TEXT NOT NULL CHECK(state IN ('active','revoked')),PRIMARY KEY(deployment,slot))",
    "CREATE TABLE nx_effect_tenants (deployment TEXT NOT NULL CHECK(length(CAST(deployment AS BLOB))>=1 AND length(CAST(deployment AS BLOB))<=64 AND instr(deployment,char(0))=0),tenant TEXT NOT NULL CHECK(length(CAST(tenant AS BLOB))>=0 AND length(CAST(tenant AS BLOB))<=64 AND instr(tenant,char(0))=0),claim_seq BIGINT NOT NULL CHECK(typeof(claim_seq)='integer' AND claim_seq>=0),PRIMARY KEY(deployment,tenant))",
    "CREATE TABLE nx_outbox (id TEXT NOT NULL CHECK(length(CAST(id AS BLOB))>=1 AND length(CAST(id AS BLOB))<=64 AND instr(id,char(0))=0),deployment TEXT NOT NULL CHECK(length(CAST(deployment AS BLOB))>=1 AND length(CAST(deployment AS BLOB))<=64 AND instr(deployment,char(0))=0),tenant TEXT NOT NULL CHECK(length(CAST(tenant AS BLOB))>=0 AND length(CAST(tenant AS BLOB))<=64 AND instr(tenant,char(0))=0),origin TEXT NOT NULL CHECK(length(CAST(origin AS BLOB))>=1 AND length(CAST(origin AS BLOB))<=128 AND instr(origin,char(0))=0),ordinal BIGINT NOT NULL CHECK(typeof(ordinal)='integer' AND ordinal>=0 AND ordinal<=1),endpoint TEXT NOT NULL CHECK(length(CAST(endpoint AS BLOB))>=1 AND length(CAST(endpoint AS BLOB))<=64 AND instr(endpoint,char(0))=0),contract TEXT NOT NULL CHECK(length(CAST(contract AS BLOB))>=1 AND length(CAST(contract AS BLOB))<=64 AND instr(contract,char(0))=0),epoch TEXT NOT NULL CHECK(length(CAST(epoch AS BLOB))>=1 AND length(CAST(epoch AS BLOB))<=64 AND instr(epoch,char(0))=0),grant_version BIGINT NOT NULL CHECK(typeof(grant_version)='integer' AND grant_version>=1),secret_version BIGINT NOT NULL CHECK(typeof(secret_version)='integer' AND secret_version>=0),payload TEXT NOT NULL CHECK(length(CAST(payload AS BLOB))>=2 AND length(CAST(payload AS BLOB))<=196608 AND instr(payload,char(0))=0 AND json_valid(payload) AND json_type(payload)='object'),payload_digest TEXT NOT NULL CHECK(length(CAST(payload_digest AS BLOB))>=1 AND length(CAST(payload_digest AS BLOB))<=64 AND instr(payload_digest,char(0))=0),eligible_ms BIGINT NOT NULL CHECK(typeof(eligible_ms)='integer' AND eligible_ms>=0),first_eligible_ms BIGINT NOT NULL CHECK(typeof(first_eligible_ms)='integer' AND first_eligible_ms>=0),attempts BIGINT NOT NULL CHECK(typeof(attempts)='integer' AND attempts>=0 AND attempts<=5),fence BIGINT NOT NULL CHECK(typeof(fence)='integer' AND fence>=0),lease_until_ms BIGINT NOT NULL CHECK(typeof(lease_until_ms)='integer' AND lease_until_ms>=0),round BIGINT NOT NULL CHECK(typeof(round)='integer' AND round>=0),state TEXT NOT NULL CHECK(state IN ('pending','running','delivered','dead','paused','cancelled')),reason TEXT NOT NULL CHECK(length(CAST(reason AS BLOB))>=0 AND length(CAST(reason AS BLOB))<=64 AND instr(reason,char(0))=0),PRIMARY KEY(id),UNIQUE(deployment,tenant,origin,ordinal),FOREIGN KEY(deployment,tenant) REFERENCES nx_effect_tenants(deployment,tenant))",
];
const POSTGRES: &[&str] = &[
    "CREATE TABLE nx_effect_queue (singleton BIGINT NOT NULL CHECK(singleton=1),claim_seq BIGINT NOT NULL CHECK(claim_seq>=0),store_id TEXT NOT NULL CHECK(octet_length(store_id)>=1 AND octet_length(store_id)<=64),owner_directory TEXT NOT NULL CHECK(octet_length(owner_directory)>=1 AND octet_length(owner_directory)<=64),pending_limit BIGINT NOT NULL CHECK(pending_limit>=1 AND pending_limit<=1000),tenant_limit BIGINT NOT NULL CHECK(tenant_limit>=1 AND tenant_limit<=1000),concurrency BIGINT NOT NULL CHECK(concurrency>=1 AND concurrency<=2),PRIMARY KEY(singleton),CHECK(tenant_limit<=pending_limit))",
    "CREATE TABLE nx_effect_grants (deployment TEXT NOT NULL CHECK(octet_length(deployment)>=1 AND octet_length(deployment)<=64),tenant TEXT NOT NULL CHECK(octet_length(tenant)>=0 AND octet_length(tenant)<=64),endpoint TEXT NOT NULL CHECK(octet_length(endpoint)>=1 AND octet_length(endpoint)<=64),version BIGINT NOT NULL CHECK(version>=1),contract TEXT NOT NULL CHECK(octet_length(contract)>=1 AND octet_length(contract)<=64),epoch TEXT NOT NULL CHECK(octet_length(epoch)>=1 AND octet_length(epoch)<=64),state TEXT NOT NULL CHECK(state IN ('active','revoked')),declaration TEXT NOT NULL CHECK(octet_length(declaration)>=2 AND octet_length(declaration)<=16384 AND jsonb_typeof(declaration::jsonb)='object'),PRIMARY KEY(deployment,tenant,endpoint))",
    "CREATE TABLE nx_effect_secrets (deployment TEXT NOT NULL CHECK(octet_length(deployment)>=1 AND octet_length(deployment)<=64),slot TEXT NOT NULL CHECK(octet_length(slot)>=1 AND octet_length(slot)<=64),version BIGINT NOT NULL CHECK(version>=1),contract TEXT NOT NULL CHECK(octet_length(contract)>=1 AND octet_length(contract)<=64),epoch TEXT NOT NULL CHECK(octet_length(epoch)>=1 AND octet_length(epoch)<=64),state TEXT NOT NULL CHECK(state IN ('active','revoked')),PRIMARY KEY(deployment,slot))",
    "CREATE TABLE nx_effect_tenants (deployment TEXT NOT NULL CHECK(octet_length(deployment)>=1 AND octet_length(deployment)<=64),tenant TEXT NOT NULL CHECK(octet_length(tenant)>=0 AND octet_length(tenant)<=64),claim_seq BIGINT NOT NULL CHECK(claim_seq>=0),PRIMARY KEY(deployment,tenant))",
    "CREATE TABLE nx_outbox (id TEXT NOT NULL CHECK(octet_length(id)>=1 AND octet_length(id)<=64),deployment TEXT NOT NULL CHECK(octet_length(deployment)>=1 AND octet_length(deployment)<=64),tenant TEXT NOT NULL CHECK(octet_length(tenant)>=0 AND octet_length(tenant)<=64),origin TEXT NOT NULL CHECK(octet_length(origin)>=1 AND octet_length(origin)<=128),ordinal BIGINT NOT NULL CHECK(ordinal>=0 AND ordinal<=1),endpoint TEXT NOT NULL CHECK(octet_length(endpoint)>=1 AND octet_length(endpoint)<=64),contract TEXT NOT NULL CHECK(octet_length(contract)>=1 AND octet_length(contract)<=64),epoch TEXT NOT NULL CHECK(octet_length(epoch)>=1 AND octet_length(epoch)<=64),grant_version BIGINT NOT NULL CHECK(grant_version>=1),secret_version BIGINT NOT NULL CHECK(secret_version>=0),payload TEXT NOT NULL CHECK(octet_length(payload)>=2 AND octet_length(payload)<=196608 AND jsonb_typeof(payload::jsonb)='object'),payload_digest TEXT NOT NULL CHECK(octet_length(payload_digest)>=1 AND octet_length(payload_digest)<=64),eligible_ms BIGINT NOT NULL CHECK(eligible_ms>=0),first_eligible_ms BIGINT NOT NULL CHECK(first_eligible_ms>=0),attempts BIGINT NOT NULL CHECK(attempts>=0 AND attempts<=5),fence BIGINT NOT NULL CHECK(fence>=0),lease_until_ms BIGINT NOT NULL CHECK(lease_until_ms>=0),round BIGINT NOT NULL CHECK(round>=0),state TEXT NOT NULL CHECK(state IN ('pending','running','delivered','dead','paused','cancelled')),reason TEXT NOT NULL CHECK(octet_length(reason)>=0 AND octet_length(reason)<=64),PRIMARY KEY(id),UNIQUE(deployment,tenant,origin,ordinal),FOREIGN KEY(deployment,tenant) REFERENCES nx_effect_tenants(deployment,tenant))",
];
pub(super) const INDEXES: &[(&str, &str)] = &[
    (
        "nx_outbox_eligible",
        "CREATE INDEX nx_outbox_eligible ON nx_outbox(deployment,state,eligible_ms,id)",
    ),
    (
        "nx_outbox_quota",
        "CREATE INDEX nx_outbox_quota ON nx_outbox(state,tenant)",
    ),
];
const PG_CONSTRAINTS: &[(&str, &str, &str, &str)] = &[
    ("nx_effect_queue", "c", "CHECK(singleton=1)", ""),
    ("nx_effect_queue", "c", "CHECK(claim_seq>=0)", ""),
    (
        "nx_effect_queue",
        "c",
        "CHECK(octet_length(store_id)>=1 AND octet_length(store_id)<=64)",
        "",
    ),
    (
        "nx_effect_queue",
        "c",
        "CHECK(octet_length(owner_directory)>=1 AND octet_length(owner_directory)<=64)",
        "",
    ),
    (
        "nx_effect_queue",
        "c",
        "CHECK(pending_limit>=1 AND pending_limit<=1000)",
        "",
    ),
    (
        "nx_effect_queue",
        "c",
        "CHECK(tenant_limit>=1 AND tenant_limit<=1000)",
        "",
    ),
    (
        "nx_effect_queue",
        "c",
        "CHECK(concurrency>=1 AND concurrency<=2)",
        "",
    ),
    ("nx_effect_queue", "p", "PRIMARY KEY(singleton)", ""),
    (
        "nx_effect_queue",
        "c",
        "CHECK(tenant_limit<=pending_limit)",
        "",
    ),
    (
        "nx_effect_grants",
        "c",
        "CHECK(octet_length(deployment)>=1 AND octet_length(deployment)<=64)",
        "",
    ),
    (
        "nx_effect_grants",
        "c",
        "CHECK(octet_length(tenant)>=0 AND octet_length(tenant)<=64)",
        "",
    ),
    (
        "nx_effect_grants",
        "c",
        "CHECK(octet_length(endpoint)>=1 AND octet_length(endpoint)<=64)",
        "",
    ),
    ("nx_effect_grants", "c", "CHECK(version>=1)", ""),
    (
        "nx_effect_grants",
        "c",
        "CHECK(octet_length(contract)>=1 AND octet_length(contract)<=64)",
        "",
    ),
    (
        "nx_effect_grants",
        "c",
        "CHECK(octet_length(epoch)>=1 AND octet_length(epoch)<=64)",
        "",
    ),
    (
        "nx_effect_grants",
        "c",
        "CHECK(state=ANY(ARRAY['active'::text,'revoked'::text]))",
        "",
    ),
    (
        "nx_effect_grants",
        "c",
        "CHECK(octet_length(declaration)>=2 AND octet_length(declaration)<=16384 AND jsonb_typeof(declaration::jsonb)='object')",
        "",
    ),
    (
        "nx_effect_grants",
        "p",
        "PRIMARY KEY(deployment,tenant,endpoint)",
        "",
    ),
    (
        "nx_effect_secrets",
        "c",
        "CHECK(octet_length(deployment)>=1 AND octet_length(deployment)<=64)",
        "",
    ),
    (
        "nx_effect_secrets",
        "c",
        "CHECK(octet_length(slot)>=1 AND octet_length(slot)<=64)",
        "",
    ),
    ("nx_effect_secrets", "c", "CHECK(version>=1)", ""),
    (
        "nx_effect_secrets",
        "c",
        "CHECK(octet_length(contract)>=1 AND octet_length(contract)<=64)",
        "",
    ),
    (
        "nx_effect_secrets",
        "c",
        "CHECK(octet_length(epoch)>=1 AND octet_length(epoch)<=64)",
        "",
    ),
    (
        "nx_effect_secrets",
        "c",
        "CHECK(state=ANY(ARRAY['active'::text,'revoked'::text]))",
        "",
    ),
    ("nx_effect_secrets", "p", "PRIMARY KEY(deployment,slot)", ""),
    (
        "nx_effect_tenants",
        "c",
        "CHECK(octet_length(deployment)>=1 AND octet_length(deployment)<=64)",
        "",
    ),
    (
        "nx_effect_tenants",
        "c",
        "CHECK(octet_length(tenant)>=0 AND octet_length(tenant)<=64)",
        "",
    ),
    ("nx_effect_tenants", "c", "CHECK(claim_seq>=0)", ""),
    (
        "nx_effect_tenants",
        "p",
        "PRIMARY KEY(deployment,tenant)",
        "",
    ),
    (
        "nx_outbox",
        "c",
        "CHECK(octet_length(id)>=1 AND octet_length(id)<=64)",
        "",
    ),
    (
        "nx_outbox",
        "c",
        "CHECK(octet_length(deployment)>=1 AND octet_length(deployment)<=64)",
        "",
    ),
    (
        "nx_outbox",
        "c",
        "CHECK(octet_length(tenant)>=0 AND octet_length(tenant)<=64)",
        "",
    ),
    (
        "nx_outbox",
        "c",
        "CHECK(octet_length(origin)>=1 AND octet_length(origin)<=128)",
        "",
    ),
    ("nx_outbox", "c", "CHECK(ordinal>=0 AND ordinal<=1)", ""),
    (
        "nx_outbox",
        "c",
        "CHECK(octet_length(endpoint)>=1 AND octet_length(endpoint)<=64)",
        "",
    ),
    (
        "nx_outbox",
        "c",
        "CHECK(octet_length(contract)>=1 AND octet_length(contract)<=64)",
        "",
    ),
    (
        "nx_outbox",
        "c",
        "CHECK(octet_length(epoch)>=1 AND octet_length(epoch)<=64)",
        "",
    ),
    ("nx_outbox", "c", "CHECK(grant_version>=1)", ""),
    ("nx_outbox", "c", "CHECK(secret_version>=0)", ""),
    (
        "nx_outbox",
        "c",
        "CHECK(octet_length(payload)>=2 AND octet_length(payload)<=196608 AND jsonb_typeof(payload::jsonb)='object')",
        "",
    ),
    (
        "nx_outbox",
        "c",
        "CHECK(octet_length(payload_digest)>=1 AND octet_length(payload_digest)<=64)",
        "",
    ),
    ("nx_outbox", "c", "CHECK(eligible_ms>=0)", ""),
    ("nx_outbox", "c", "CHECK(first_eligible_ms>=0)", ""),
    ("nx_outbox", "c", "CHECK(attempts>=0 AND attempts<=5)", ""),
    ("nx_outbox", "c", "CHECK(fence>=0)", ""),
    ("nx_outbox", "c", "CHECK(lease_until_ms>=0)", ""),
    ("nx_outbox", "c", "CHECK(round>=0)", ""),
    (
        "nx_outbox",
        "c",
        "CHECK(state=ANY(ARRAY['pending'::text,'running'::text,'delivered'::text,'dead'::text,'paused'::text,'cancelled'::text]))",
        "",
    ),
    (
        "nx_outbox",
        "c",
        "CHECK(octet_length(reason)>=0 AND octet_length(reason)<=64)",
        "",
    ),
    ("nx_outbox", "p", "PRIMARY KEY(id)", ""),
    (
        "nx_outbox",
        "u",
        "UNIQUE(deployment,tenant,origin,ordinal)",
        "",
    ),
    (
        "nx_outbox",
        "f",
        "FOREIGN KEY(deployment,tenant) REFERENCES nx_effect_tenants(deployment,tenant)",
        "nx_effect_tenants",
    ),
];
pub(super) fn table_sql(tx: &Transaction) -> Result<&'static [&'static str]> {
    match tx.backend {
        Backend::Sqlite(_) => Ok(SQLITE),
        Backend::Postgres(_) => Ok(POSTGRES),
        Backend::Closed => anyhow::bail!("closed effect metadata transaction"),
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
    pub(crate) async fn check_effect_layout(&mut self) -> Result<()> {
        for ((name, _), sql) in TABLES.iter().zip(SQLITE) {
            match self.backend {
                Backend::Sqlite(_) => {
                    let actual=self.fetch::<1>("SELECT CASE WHEN length(CAST(sql AS BLOB))<=16384 THEN sql ELSE NULL END FROM sqlite_schema WHERE type='table' AND name=$1",&[(*name).into()]).await?;
                    ensure!(
                        actual.len() == 1 && ddl_key(&actual[0][0]) == ddl_key(sql),
                        "invalid effect metadata constraints in {name}"
                    );
                }
                Backend::Postgres(_) => {
                    let rows=self.fetch::<6>("SELECT CAST(c.contype AS TEXT),CASE WHEN octet_length(pg_catalog.pg_get_constraintdef(c.oid))<=4096 THEN pg_catalog.pg_get_constraintdef(c.oid) ELSE NULL END,CASE WHEN c.convalidated AND c.conenforced AND NOT c.condeferrable AND NOT c.condeferred THEN '1' ELSE '0' END,n.nspname,COALESCE(rn.nspname,''),COALESCE(r.relname,'') FROM pg_catalog.pg_constraint c JOIN pg_catalog.pg_class t ON t.oid=c.conrelid JOIN pg_catalog.pg_namespace n ON n.oid=t.relnamespace LEFT JOIN pg_catalog.pg_class r ON r.oid=c.confrelid LEFT JOIN pg_catalog.pg_namespace rn ON rn.oid=r.relnamespace WHERE n.nspname=current_schema() AND t.relname=$1 AND c.contype IN ('p','u','f','c') ORDER BY c.oid LIMIT 33",&[(*name).into()]).await?;
                    let mut actual = Vec::new();
                    for [kind, definition, valid, namespace, target_namespace, target] in rows {
                        ensure!(valid == "1", "inactive effect metadata constraint");
                        if kind == "f" {
                            ensure!(
                                namespace == target_namespace,
                                "foreign effect metadata namespace"
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
                        "invalid effect metadata constraints in {name}"
                    );
                }
                Backend::Closed => anyhow::bail!("closed effect metadata transaction"),
            }
        }
        for (name, expected) in INDEXES {
            let rows = match self.backend {
                Backend::Sqlite(_) => self.fetch::<4>("SELECT tbl_name,CASE WHEN length(CAST(sql AS BLOB))<=4096 THEN sql ELSE NULL END,'','1' FROM sqlite_schema WHERE type='index' AND name=$1", &[(*name).into()]).await?,
                Backend::Postgres(_) => self.fetch::<4>("SELECT t.relname,CASE WHEN octet_length(pg_catalog.pg_get_indexdef(i.indexrelid))<=4096 THEN pg_catalog.pg_get_indexdef(i.indexrelid) ELSE NULL END,pg_catalog.quote_ident(ts.nspname),CASE WHEN i.indisvalid AND i.indisready AND i.indislive AND NOT i.indisunique AND NOT i.indisexclusion AND i.indpred IS NULL THEN '1' ELSE '0' END FROM pg_catalog.pg_index i JOIN pg_catalog.pg_class n ON n.oid=i.indexrelid JOIN pg_catalog.pg_class t ON t.oid=i.indrelid JOIN pg_catalog.pg_namespace s ON s.oid=n.relnamespace JOIN pg_catalog.pg_namespace ts ON ts.oid=t.relnamespace WHERE s.nspname=current_schema() AND ts.oid=s.oid AND n.relname=$1", &[(*name).into()]).await?,
                Backend::Closed => anyhow::bail!("closed effect metadata transaction"),
            };
            let [[table, definition, namespace, usable]] = rows.as_slice() else {
                anyhow::bail!("missing effect metadata index");
            };
            let expected = if namespace.is_empty() {
                (*expected).to_owned()
            } else {
                expected.replace(
                    " ON nx_outbox(",
                    &format!(" ON {namespace}.nx_outbox USING btree ("),
                )
            };
            ensure!(
                table == "nx_outbox" && usable == "1" && ddl_key(definition) == ddl_key(&expected),
                "wrong effect metadata index shape {name}"
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
