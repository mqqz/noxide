//! Fixed search metadata. These tables do not enable query admission.
use super::{Backend, Transaction};
use anyhow::{Context, Result, ensure};

pub(super) const TABLES: &[super::blob_layout::Table] = &[
    (
        "nx_search_state",
        &[
            ("resource", "BIGINT"),
            ("tokenizer", "TEXT"),
            ("declaration", "TEXT"),
            ("version", "BIGINT"),
            ("state", "TEXT"),
        ],
    ),
    (
        "nx_search_postings",
        &[
            ("resource", "BIGINT"),
            ("record_id", "BIGINT"),
            ("field", "BIGINT"),
            ("token", "TEXT"),
            ("incarnation", "TEXT"),
            ("revision", "BIGINT"),
            ("created_seq", "BIGINT"),
        ],
    ),
];

const SQLITE: &[&str] = &[
    "CREATE TABLE nx_search_state (resource BIGINT PRIMARY KEY NOT NULL REFERENCES nx_resource_catalog(storage_id), tokenizer TEXT NOT NULL CHECK(length(CAST(tokenizer AS BLOB))>=1 AND length(CAST(tokenizer AS BLOB))<=256), declaration TEXT NOT NULL CHECK(length(CAST(declaration AS BLOB))>=2 AND length(CAST(declaration AS BLOB))<=4096 AND json_valid(declaration) AND json_type(declaration)='object'), version BIGINT NOT NULL CHECK(version=1), state TEXT NOT NULL CHECK(state IN ('building','ready')))",
    "CREATE TABLE nx_search_postings (resource BIGINT NOT NULL REFERENCES nx_search_state(resource), record_id BIGINT NOT NULL CHECK(record_id>0), field BIGINT NOT NULL CHECK(field>=0 AND field<4), token TEXT COLLATE BINARY NOT NULL CHECK(length(CAST(token AS BLOB))>=1 AND length(CAST(token AS BLOB))<=256 AND length(token)<=64 AND instr(token,char(0))=0), incarnation TEXT NOT NULL CHECK(length(CAST(incarnation AS BLOB))>=1 AND length(CAST(incarnation AS BLOB))<=64), revision BIGINT NOT NULL CHECK(revision>=1), created_seq BIGINT NOT NULL CHECK(created_seq>0), PRIMARY KEY(resource,record_id,field,token), FOREIGN KEY(resource,record_id) REFERENCES nx_records(resource,id) ON DELETE CASCADE)",
];
const POSTGRES: &[&str] = &[
    "CREATE TABLE nx_search_state (resource BIGINT PRIMARY KEY NOT NULL REFERENCES nx_resource_catalog(storage_id), tokenizer TEXT NOT NULL CHECK(octet_length(tokenizer)>=1 AND octet_length(tokenizer)<=256), declaration TEXT NOT NULL CHECK(octet_length(declaration)>=2 AND octet_length(declaration)<=4096 AND jsonb_typeof(declaration::jsonb)='object'), version BIGINT NOT NULL CHECK(version=1), state TEXT NOT NULL CHECK(state IN ('building','ready')))",
    "CREATE TABLE nx_search_postings (resource BIGINT NOT NULL REFERENCES nx_search_state(resource), record_id BIGINT NOT NULL CHECK(record_id>0), field BIGINT NOT NULL CHECK(field>=0 AND field<4), token TEXT COLLATE \"C\" NOT NULL CHECK(octet_length(token)>=1 AND octet_length(token)<=256 AND length(token)<=64), incarnation TEXT NOT NULL CHECK(octet_length(incarnation)>=1 AND octet_length(incarnation)<=64), revision BIGINT NOT NULL CHECK(revision>=1), created_seq BIGINT NOT NULL CHECK(created_seq>0), PRIMARY KEY(resource,record_id,field,token), FOREIGN KEY(resource,record_id) REFERENCES nx_records(resource,id) ON DELETE CASCADE)",
];
pub(super) const INDEXES: &[(&str, &str)] = &[(
    "nx_search_tokens",
    "CREATE INDEX nx_search_tokens ON nx_search_postings(resource,field,token,created_seq,record_id)",
)];

pub(super) fn table_sql(tx: &Transaction) -> Result<&'static [&'static str]> {
    match tx.backend {
        Backend::Closed => anyhow::bail!("closed transaction"),
        Backend::Sqlite(_) => Ok(SQLITE),
        Backend::Postgres(_) => Ok(POSTGRES),
    }
}

// Only the fixed declarations above are compared. This removes provider
// formatting, not arbitrary SQL syntax or operators. Literal contents remain
// significant; text casts emitted around the fixed PostgreSQL literals do not.
fn ddl_key(sql: &str) -> String {
    let mut output = String::new();
    let mut quote = None;
    for character in sql.chars() {
        if let Some(delimiter) = quote {
            output.push(character);
            if character == delimiter {
                quote = None;
            }
        } else if matches!(character, '\'' | '"') {
            quote = Some(character);
            output.push(character);
        } else if !character.is_ascii_whitespace() && !matches!(character, '(' | ')' | ';') {
            output.push(character.to_ascii_lowercase());
        }
    }
    output.replace("'::text", "'")
}

// Table, native constraint kind, fixed definition, referenced table (if any).
const PG_CONSTRAINTS: &[(&str, &str, &str, &str)] = &[
    ("nx_search_state", "p", "PRIMARY KEY(resource)", ""),
    (
        "nx_search_state",
        "f",
        "FOREIGN KEY(resource) REFERENCES nx_resource_catalog(storage_id)",
        "nx_resource_catalog",
    ),
    (
        "nx_search_state",
        "c",
        "CHECK(octet_length(tokenizer)>=1 AND octet_length(tokenizer)<=256)",
        "",
    ),
    (
        "nx_search_state",
        "c",
        "CHECK(octet_length(declaration)>=2 AND octet_length(declaration)<=4096 AND jsonb_typeof(declaration::jsonb)='object')",
        "",
    ),
    ("nx_search_state", "c", "CHECK(version=1)", ""),
    (
        "nx_search_state",
        "c",
        "CHECK(state=ANY(ARRAY['building'::text,'ready'::text]))",
        "",
    ),
    (
        "nx_search_postings",
        "p",
        "PRIMARY KEY(resource,record_id,field,token)",
        "",
    ),
    (
        "nx_search_postings",
        "f",
        "FOREIGN KEY(resource) REFERENCES nx_search_state(resource)",
        "nx_search_state",
    ),
    (
        "nx_search_postings",
        "f",
        "FOREIGN KEY(resource,record_id) REFERENCES nx_records(resource,id) ON DELETE CASCADE",
        "nx_records",
    ),
    ("nx_search_postings", "c", "CHECK(record_id>0)", ""),
    ("nx_search_postings", "c", "CHECK(field>=0 AND field<4)", ""),
    (
        "nx_search_postings",
        "c",
        "CHECK(octet_length(token)>=1 AND octet_length(token)<=256 AND length(token)<=64)",
        "",
    ),
    (
        "nx_search_postings",
        "c",
        "CHECK(octet_length(incarnation)>=1 AND octet_length(incarnation)<=64)",
        "",
    ),
    ("nx_search_postings", "c", "CHECK(revision>=1)", ""),
    ("nx_search_postings", "c", "CHECK(created_seq>0)", ""),
];

impl Transaction {
    /// Operator startup only; ordinary requests do not scan provider catalogs.
    pub(crate) async fn check_search_layout(&mut self) -> Result<()> {
        match self.backend {
            Backend::Closed => anyhow::bail!("closed transaction"),
            Backend::Sqlite(_) => {
                let rows = self.fetch::<2>("SELECT name,CASE WHEN length(CAST(sql AS BLOB))<=4096 THEN sql ELSE NULL END FROM sqlite_schema WHERE type='table' AND name IN ('nx_search_state','nx_search_postings') ORDER BY name LIMIT 3", &[]).await?;
                let mut expected: Vec<_> = TABLES
                    .iter()
                    .zip(SQLITE)
                    .map(|((name, _), sql)| [(*name).to_owned(), ddl_key(sql)])
                    .collect();
                expected.sort();
                let actual: Vec<_> = rows
                    .into_iter()
                    .map(|[name, sql]| [name, ddl_key(&sql)])
                    .collect();
                ensure!(
                    actual == expected,
                    "invalid search metadata table constraints"
                );
            }
            Backend::Postgres(_) => {
                let rows = self.fetch::<7>("SELECT t.relname,CAST(c.contype AS TEXT),CASE WHEN octet_length(pg_catalog.pg_get_constraintdef(c.oid))<=2048 THEN pg_catalog.pg_get_constraintdef(c.oid) ELSE NULL END,CASE WHEN c.convalidated AND c.conenforced AND NOT c.condeferrable AND NOT c.condeferred THEN '1' ELSE '0' END,pg_catalog.quote_ident(n.nspname),COALESCE(rn.nspname,''),COALESCE(r.relname,'') FROM pg_catalog.pg_constraint c JOIN pg_catalog.pg_class t ON t.oid=c.conrelid JOIN pg_catalog.pg_namespace n ON n.oid=t.relnamespace LEFT JOIN pg_catalog.pg_class r ON r.oid=c.confrelid LEFT JOIN pg_catalog.pg_namespace rn ON rn.oid=r.relnamespace WHERE n.nspname=current_schema() AND t.relname IN ('nx_search_state','nx_search_postings') AND c.contype IN ('p','f','c') ORDER BY t.relname,c.oid LIMIT 16", &[]).await?;
                ensure!(
                    rows.len() == PG_CONSTRAINTS.len(),
                    "search metadata constraint count"
                );
                let mut actual = Vec::new();
                for [
                    table,
                    kind,
                    definition,
                    valid,
                    namespace,
                    target_namespace,
                    target,
                ] in rows
                {
                    ensure!(valid == "1", "inactive search metadata constraint");
                    if kind == "f" {
                        ensure!(
                            target_namespace == namespace
                                || format!("\"{}\"", target_namespace.replace('"', "\"\""))
                                    == namespace,
                            "foreign search metadata namespace"
                        );
                    }
                    actual.push((table, kind, ddl_key(&definition), target));
                }
                actual.sort();
                let mut expected: Vec<_> = PG_CONSTRAINTS
                    .iter()
                    .map(|(table, kind, definition, target)| {
                        (
                            (*table).to_owned(),
                            (*kind).to_owned(),
                            ddl_key(definition),
                            (*target).to_owned(),
                        )
                    })
                    .collect();
                expected.sort();
                ensure!(actual == expected, "invalid search metadata constraints");
            }
        }
        let sql = match self.backend {
            Backend::Closed => anyhow::bail!("closed transaction"),
            Backend::Sqlite(_) => {
                "SELECT sql,'','1' FROM sqlite_schema WHERE type='index' AND name='nx_search_tokens' AND tbl_name='nx_search_postings' LIMIT 2"
            }
            Backend::Postgres(_) => {
                "SELECT pg_catalog.pg_get_indexdef(i.indexrelid),pg_catalog.quote_ident(n.nspname),CASE WHEN i.indisvalid AND i.indisready AND i.indislive AND NOT i.indisunique AND NOT i.indisexclusion AND i.indcollation[2]='pg_catalog.\"C\"'::regcollation THEN '1' ELSE '0' END FROM pg_catalog.pg_index i JOIN pg_catalog.pg_class t ON t.oid=i.indrelid JOIN pg_catalog.pg_namespace n ON n.oid=t.relnamespace JOIN pg_catalog.pg_class x ON x.oid=i.indexrelid WHERE n.nspname=current_schema() AND t.relname='nx_search_postings' AND x.relname='nx_search_tokens' LIMIT 2"
            }
        };
        let rows = self.fetch::<3>(sql, &[]).await?;
        ensure!(rows.len() == 1, "missing search token index");
        let [actual, namespace, valid] = rows.first().context("search index missing")?;
        let expected = if namespace.is_empty() {
            INDEXES[0].1.to_owned()
        } else {
            INDEXES[0].1.replace(
                " ON nx_search_postings(",
                &format!(" ON {namespace}.nx_search_postings USING btree ("),
            )
        };
        ensure!(
            valid == "1" && ddl_key(actual) == ddl_key(&expected),
            "invalid search token index"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod adversarial_tests;
