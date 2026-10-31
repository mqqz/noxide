//! Verify the fixed native shapes emitted by the single query index registry.
use super::*;
use crate::query_plan::{IndexRequirement, NativeProvider};
use std::collections::{BTreeMap, BTreeSet};

struct Definition {
    sql: String,
    namespace: String,
    usable: bool,
}

// Only host-generated index DDL is compared. Parentheses and outside whitespace
// are provider formatting; operators, identifiers and literal contents remain
// significant. PostgreSQL's text-literal cast is skipped after its closing quote,
// never by replacing a substring inside the literal.
fn ddl_key(sql: &str, storage: i64) -> String {
    let mut chars = sql.chars().peekable();
    let mut key = String::new();
    while let Some(c) = chars.next() {
        if matches!(c, '\'' | '"') {
            let start = key.len();
            key.push(c);
            while let Some(next) = chars.next() {
                key.push(next);
                if next == c {
                    if chars.peek() == Some(&c) {
                        key.push(chars.next().unwrap());
                    } else {
                        break;
                    }
                }
            }
            if c == '\'' {
                let numeric = key[start..] == format!("'{storage}'");
                let cast = if numeric { "::bigint" } else { "::text" };
                let mut lookahead = chars.clone();
                if lookahead.by_ref().take(cast.len()).collect::<String>() == cast
                    && lookahead
                        .peek()
                        .is_none_or(|next| !next.is_ascii_alphanumeric() && *next != '_')
                {
                    if numeric {
                        key.truncate(start);
                        key.push_str(&storage.to_string());
                    }
                    chars = lookahead;
                }
            }
        } else if !c.is_ascii_whitespace() && !matches!(c, '(' | ')' | ';') {
            key.push(c.to_ascii_lowercase());
        }
    }
    key
}

impl Transaction {
    async fn query_definitions(&mut self) -> Result<BTreeMap<String, Definition>> {
        let sql = match self.query_provider()? {
            NativeProvider::Sqlite => {
                "SELECT name,CASE WHEN length(CAST(sql AS BLOB))<=8192 THEN sql ELSE NULL END,'','1' FROM sqlite_schema WHERE type='index' AND (name GLOB 'nx_q_*' OR name='nx_search_tokens') ORDER BY name LIMIT 130"
            }
            NativeProvider::Postgres => {
                "SELECT x.relname,CASE WHEN octet_length(pg_catalog.pg_get_indexdef(i.indexrelid))<=8192 THEN pg_catalog.pg_get_indexdef(i.indexrelid) ELSE NULL END,pg_catalog.quote_ident(n.nspname),CASE WHEN i.indisvalid AND i.indisready AND i.indislive AND NOT i.indisunique AND NOT i.indisexclusion THEN '1' ELSE '0' END FROM pg_catalog.pg_index i JOIN pg_catalog.pg_class t ON t.oid=i.indrelid JOIN pg_catalog.pg_namespace n ON n.oid=t.relnamespace JOIN pg_catalog.pg_class x ON x.oid=i.indexrelid JOIN pg_catalog.pg_namespace xn ON xn.oid=x.relnamespace WHERE xn.nspname=current_schema() AND (left(x.relname,5)='nx_q_' OR x.relname='nx_search_tokens') ORDER BY x.relname LIMIT 130"
            }
        };
        let rows = self.fetch::<4>(sql, &[]).await?;
        // Sixteen resources, eight shapes each, plus the fixed posting index.
        ensure!(rows.len() <= 129, "derived query index catalog limit");
        let mut definitions = BTreeMap::new();
        for [name, sql, namespace, usable] in rows {
            ensure!(
                name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_'),
                "invalid derived index name"
            );
            ensure!(
                definitions
                    .insert(
                        name,
                        Definition {
                            sql,
                            namespace,
                            usable: usable == "1"
                        }
                    )
                    .is_none(),
                "duplicate derived index"
            );
        }
        Ok(definitions)
    }

    pub(super) async fn query_indexes(&mut self) -> Result<Vec<String>> {
        Ok(self
            .query_definitions()
            .await?
            .into_keys()
            .filter(|name| name.starts_with("nx_q_"))
            .collect())
    }

    fn verify_query_definition(
        &self,
        requirement: &IndexRequirement,
        storage: i64,
        actual: &Definition,
    ) -> Result<()> {
        let mut expected = requirement.native_sql(self.query_provider()?, storage)?;
        if !actual.namespace.is_empty() {
            // Namespace formatting is native, but the expected owning table is
            // fixed by the approved registry, never inferred from actual DDL.
            let table = requirement.table.name();
            expected = expected.replacen(
                &format!(" ON {table}("),
                &format!(" ON {}.{table} USING btree (", actual.namespace),
                1,
            );
            let provider = self.query_provider()?;
            let numeric_fields = requirement
                .columns
                .iter()
                .filter_map(|column| {
                    if let crate::policy::IndexColumn::Timestamp(field) = column {
                        Some(field.as_str())
                    } else {
                        None
                    }
                })
                .chain(match &requirement.order {
                    crate::query_plan::IndexOrder::Scalar {
                        field,
                        representation: crate::query_plan::ScalarRepresentation::Numeric,
                    } => Some(field.as_str()),
                    _ => None,
                });
            for field in numeric_fields {
                let expression = provider.field_expression(field)?;
                expected = expected.replace(
                    &format!("CAST({expression} AS BIGINT)"),
                    &format!("({expression})::bigint"),
                );
            }
        }
        ensure!(
            actual.usable && ddl_key(&actual.sql, storage) == ddl_key(&expected, storage),
            "invalid derived index {} for queries {:?}; run noxide schema indexes CONFIG",
            requirement.name(storage),
            requirement.queries,
        );
        Ok(())
    }

    pub(super) async fn validate_query_indexes(
        &mut self,
        manifest: &noxide_protocol::Manifest,
    ) -> Result<()> {
        let existing = self.query_definitions().await?;
        let mut required_records = BTreeSet::new();
        let mut verified = BTreeSet::new();
        for requirement in crate::query_plan::required_indexes(manifest)? {
            let storage = self.storage_key(&requirement.resource).await?;
            let name = requirement.name(storage);
            if name.starts_with("nx_q_") {
                required_records.insert(name.clone());
            }
            if !verified.insert(name.clone()) {
                continue;
            }
            let actual = existing.get(&name).with_context(|| {
                format!("missing derived index {name} for queries {:?}; run noxide schema indexes CONFIG", requirement.queries)
            })?;
            self.verify_query_definition(&requirement, storage, actual)?;
        }
        ensure!(
            existing
                .keys()
                .filter(|name| name.starts_with("nx_q_"))
                .cloned()
                .collect::<BTreeSet<_>>()
                == required_records,
            "obsolete derived query indexes; run noxide schema indexes CONFIG"
        );
        Ok(())
    }

    pub(super) async fn reconcile_query_indexes(
        &mut self,
        manifest: &noxide_protocol::Manifest,
    ) -> Result<()> {
        let existing = self.query_definitions().await?;
        let mut required = BTreeSet::new();
        for requirement in crate::query_plan::required_indexes(manifest)? {
            let storage = self.storage_key(&requirement.resource).await?;
            let name = requirement.name(storage);
            if !required.insert(name.clone()) {
                continue;
            }
            if let Some(actual) = existing.get(&name) {
                self.verify_query_definition(&requirement, storage, actual)?;
            } else {
                self.execute(
                    &requirement.native_sql(self.query_provider()?, storage)?,
                    &[],
                )
                .await?;
            }
        }
        for name in existing.keys().filter(|name| name.starts_with("nx_q_")) {
            if !required.contains(name) {
                self.execute(&format!("DROP INDEX {name}"), &[]).await?;
            }
        }
        self.validate_query_indexes(manifest).await
    }
}

#[cfg(test)]
mod tests;
