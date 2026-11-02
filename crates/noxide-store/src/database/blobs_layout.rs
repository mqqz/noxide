//! Fixed blob metadata layout. No blob authority is enabled by these tables.
use super::{Backend, Transaction};
use crate::sql::{JoinSql, sql};
use anyhow::{Context, Result, ensure};

pub(super) type Table = (&'static str, &'static [(&'static str, &'static str)]);
pub(super) const TABLES: &[Table] = &[
    (
        "nx_blob_store",
        &[
            ("singleton", "BIGINT"),
            ("identity", "TEXT"),
            ("pair_id", "TEXT"),
            ("pair_state", "TEXT"),
            ("serial", "BIGINT"),
            ("reserved_bytes", "BIGINT"),
            ("used_bytes", "BIGINT"),
            ("objects", "BIGINT"),
            ("anonymous_reserved_bytes", "BIGINT"),
            ("anonymous_used_bytes", "BIGINT"),
        ],
    ),
    (
        "nx_blob_subjects",
        &[
            ("subject", "TEXT"),
            ("anonymous", "BIGINT"),
            ("reserved_bytes", "BIGINT"),
            ("used_bytes", "BIGINT"),
            ("objects", "BIGINT"),
        ],
    ),
    (
        "nx_blobs",
        &[
            ("slot", "TEXT"),
            ("blob_ref", "TEXT"),
            ("upload_handle", "TEXT"),
            ("object_key", "TEXT"),
            ("subject", "TEXT"),
            ("context", "TEXT"),
            ("input", "TEXT"),
            ("anonymous", "BIGINT"),
            ("state", "TEXT"),
            ("generation", "BIGINT"),
            ("reserved_bytes", "BIGINT"),
            ("actual_bytes", "BIGINT"),
            ("sha256", "TEXT"),
            ("filename", "TEXT"),
            ("created_ms", "BIGINT"),
            ("expires_ms", "BIGINT"),
            ("owner_resource", "BIGINT"),
            ("owner_id", "BIGINT"),
            ("owner_incarnation", "TEXT"),
            ("owner_field", "TEXT"),
            ("claimed_ms", "BIGINT"),
            ("owner_process", "TEXT"),
        ],
    ),
    (
        "nx_blob_orphans",
        &[
            ("object_key", "TEXT"),
            ("generation", "BIGINT"),
            ("state", "TEXT"),
            ("first_seen_ms", "BIGINT"),
            ("claimed_ms", "BIGINT"),
            ("charged_bytes", "BIGINT"),
            ("charged_objects", "BIGINT"),
            ("owner_process", "TEXT"),
        ],
    ),
];
pub(super) const TABLE_SQL: &[&str] = &[
    "CREATE TABLE nx_blob_store (singleton BIGINT PRIMARY KEY CHECK(singleton=1), identity TEXT NOT NULL, pair_id TEXT NOT NULL, pair_state TEXT NOT NULL CHECK(pair_state IN ('pending','paired')), serial BIGINT NOT NULL CHECK(serial>0), reserved_bytes BIGINT NOT NULL CHECK(reserved_bytes>=0), used_bytes BIGINT NOT NULL CHECK(used_bytes>=0), objects BIGINT NOT NULL CHECK(objects>=0), anonymous_reserved_bytes BIGINT NOT NULL CHECK(anonymous_reserved_bytes>=0), anonymous_used_bytes BIGINT NOT NULL CHECK(anonymous_used_bytes>=0))",
    "CREATE TABLE nx_blob_subjects (subject TEXT PRIMARY KEY NOT NULL, anonymous BIGINT NOT NULL CHECK(anonymous IN (0,1)), reserved_bytes BIGINT NOT NULL CHECK(reserved_bytes>=0), used_bytes BIGINT NOT NULL CHECK(used_bytes>=0), objects BIGINT NOT NULL CHECK(objects>=0))",
    "CREATE TABLE nx_blobs (slot TEXT PRIMARY KEY NOT NULL, blob_ref TEXT NOT NULL, upload_handle TEXT NOT NULL, object_key TEXT NOT NULL, subject TEXT NOT NULL, context TEXT NOT NULL, input TEXT NOT NULL, anonymous BIGINT NOT NULL CHECK(anonymous IN (0,1)), state TEXT NOT NULL CHECK(state IN ('uploading','staged','attached','unreferenced','deleting','deleted')), generation BIGINT NOT NULL CHECK(generation>0), reserved_bytes BIGINT NOT NULL CHECK(reserved_bytes>=0), actual_bytes BIGINT NOT NULL CHECK(actual_bytes>=0), sha256 TEXT NOT NULL, filename TEXT NOT NULL, created_ms BIGINT NOT NULL CHECK(created_ms>=0), expires_ms BIGINT NOT NULL CHECK(expires_ms>=created_ms), owner_resource BIGINT NOT NULL, owner_id BIGINT NOT NULL, owner_incarnation TEXT NOT NULL, owner_field TEXT NOT NULL, claimed_ms BIGINT NOT NULL CHECK(claimed_ms>=0), owner_process TEXT NOT NULL)",
    "CREATE TABLE nx_blob_orphans (object_key TEXT PRIMARY KEY NOT NULL, generation BIGINT NOT NULL CHECK(generation>0), state TEXT NOT NULL CHECK(state IN ('observed','deleting')), first_seen_ms BIGINT NOT NULL CHECK(first_seen_ms>=0), claimed_ms BIGINT NOT NULL CHECK(claimed_ms>=0), charged_bytes BIGINT NOT NULL CHECK(charged_bytes>=0), charged_objects BIGINT NOT NULL CHECK(charged_objects>0), owner_process TEXT NOT NULL)",
];
pub(super) const INDEXES: &[(&str, &str)] = &[
    (
        "nx_blobs_subject_live",
        "CREATE INDEX nx_blobs_subject_live ON nx_blobs(subject,slot) WHERE state IN ('uploading','staged')",
    ),
    (
        "nx_blobs_anonymous_live",
        "CREATE INDEX nx_blobs_anonymous_live ON nx_blobs(anonymous,slot) WHERE state IN ('uploading','staged')",
    ),
    (
        "nx_blobs_expiry",
        "CREATE INDEX nx_blobs_expiry ON nx_blobs(state,expires_ms,slot)",
    ),
    (
        "nx_blobs_claimed",
        "CREATE INDEX nx_blobs_claimed ON nx_blobs(state,claimed_ms,slot)",
    ),
    (
        "nx_blobs_owner",
        "CREATE INDEX nx_blobs_owner ON nx_blobs(owner_resource,owner_id,owner_incarnation,owner_field)",
    ),
    (
        "nx_blobs_attached_field",
        "CREATE UNIQUE INDEX nx_blobs_attached_field ON nx_blobs(owner_resource,owner_id,owner_incarnation,owner_field) WHERE state='attached'",
    ),
    (
        "nx_blob_orphans_due",
        "CREATE INDEX nx_blob_orphans_due ON nx_blob_orphans(state,first_seen_ms,object_key)",
    ),
    (
        "nx_blobs_ref",
        "CREATE UNIQUE INDEX nx_blobs_ref ON nx_blobs(blob_ref)",
    ),
    (
        "nx_blobs_handle",
        "CREATE UNIQUE INDEX nx_blobs_handle ON nx_blobs(upload_handle)",
    ),
    (
        "nx_blobs_key",
        "CREATE UNIQUE INDEX nx_blobs_key ON nx_blobs(object_key)",
    ),
];

// Only fixed host-generated column indexes and literal state predicates are
// admitted here. Provider formatting differs in parentheses, whitespace and
// casts on text literals; operators, columns, collations and extra clauses stay
// significant. This is not a general SQL equivalence checker.
fn ddl_key(sql: &str) -> String {
    let mut result = String::new();
    let mut quote = None;
    for c in sql.chars() {
        if let Some(q) = quote {
            result.push(c);
            if c == q {
                quote = None;
            }
        } else if matches!(c, '\'' | '"') {
            quote = Some(c);
            result.push(c);
        } else if !c.is_ascii_whitespace() && !matches!(c, '(' | ')' | ';') {
            result.push(c.to_ascii_lowercase());
        }
    }
    result.replace("'::text", "'")
}

impl Transaction {
    /// Startup/activation only. Data requests use the deployment/schema fence,
    /// never catalog scans. Column layout is checked by the framework initializer.
    pub async fn check_blob_layout(&mut self) -> Result<()> {
        let keys = match self.backend {
            Backend::Closed => anyhow::bail!("closed transaction"),
            Backend::Sqlite(_) => {
                "SELECT m.name,p.name,CAST(p.pk AS TEXT) FROM sqlite_schema m JOIN pragma_table_info(m.name) p WHERE m.type='table' AND m.name IN ('nx_blob_store','nx_blob_subjects','nx_blobs','nx_blob_orphans') AND p.pk>0 ORDER BY m.name,p.pk LIMIT 5"
            }
            Backend::Postgres(_) => {
                "SELECT t.table_name,k.column_name,CAST(k.ordinal_position AS TEXT) FROM information_schema.table_constraints t JOIN information_schema.key_column_usage k ON k.constraint_catalog=t.constraint_catalog AND k.constraint_schema=t.constraint_schema AND k.constraint_name=t.constraint_name AND k.table_schema=t.table_schema AND k.table_name=t.table_name WHERE t.table_schema=current_schema() AND t.constraint_type='PRIMARY KEY' AND t.table_name IN ('nx_blob_store','nx_blob_subjects','nx_blobs','nx_blob_orphans') ORDER BY t.table_name,k.ordinal_position LIMIT 5"
            }
        };
        let actual = self.fetch::<3>(keys, &[]).await?;
        let expected: Vec<[String; 3]> = [
            ("nx_blob_orphans", "object_key"),
            ("nx_blob_store", "singleton"),
            ("nx_blob_subjects", "subject"),
            ("nx_blobs", "slot"),
        ]
        .into_iter()
        .map(|(table, key)| [table.into(), key.into(), "1".into()])
        .collect();
        ensure!(actual == expected, "invalid blob metadata primary keys");

        let names = INDEXES
            .iter()
            .map(|(name, _)| sql!("'{name}'"))
            .collect::<Vec<_>>()
            .joined(",");
        let sql = match self.backend {
            Backend::Closed => anyhow::bail!("closed transaction"),
            Backend::Sqlite(_) => sql!(
                "SELECT name,CASE WHEN length(CAST(sql AS BLOB))<=2048 THEN sql ELSE NULL END,'','1' FROM sqlite_schema WHERE type='index' AND name IN ({names}) ORDER BY name LIMIT 11"
            ),
            Backend::Postgres(_) => sql!(
                "SELECT x.relname,CASE WHEN octet_length(pg_catalog.pg_get_indexdef(i.indexrelid))<=2048 THEN pg_catalog.pg_get_indexdef(i.indexrelid) ELSE NULL END,pg_catalog.quote_ident(n.nspname),CASE WHEN i.indisvalid AND i.indisready AND i.indislive AND NOT i.indisexclusion THEN '1' ELSE '0' END FROM pg_catalog.pg_index i JOIN pg_catalog.pg_class t ON t.oid=i.indrelid JOIN pg_catalog.pg_namespace n ON n.oid=t.relnamespace JOIN pg_catalog.pg_class x ON x.oid=i.indexrelid WHERE n.nspname=current_schema() AND x.relname IN ({names}) ORDER BY x.relname LIMIT 11"
            ),
        };
        let mut actual: std::collections::BTreeMap<_, _> = self
            .fetch::<4>(&sql, &[])
            .await?
            .into_iter()
            .map(|[name, ddl, namespace, usable]| (name, (ddl, namespace, usable)))
            .collect();
        ensure!(
            actual.len() == INDEXES.len(),
            "missing blob metadata indexes"
        );
        for (name, expected) in INDEXES {
            let (ddl, namespace, usable) = actual
                .remove(*name)
                .context("missing blob metadata index")?;
            let expected = if namespace.is_empty() {
                (*expected).to_owned()
            } else {
                // The namespace comes from the provider; the owning table
                // remains pinned by our declaration. A same-named index on
                // an unrelated table must never satisfy this requirement.
                let logical = if expected.contains(" ON nx_blobs(") {
                    "nx_blobs"
                } else {
                    "nx_blob_orphans"
                };
                expected
                    .replace(
                        &format!(" ON {logical}("),
                        &format!(" ON {namespace}.{logical} USING btree ("),
                    )
                    .replace(
                        "state IN ('uploading','staged')",
                        "state = ANY (ARRAY['uploading'::text, 'staged'::text])",
                    )
            };
            ensure!(
                usable == "1" && ddl_key(&ddl) == ddl_key(&expected),
                "invalid blob metadata index {name}"
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
