//! Operator-only activation and startup verification of declared native uniqueness.
use super::*;
use noxide_protocol::{Fields, Resource};
use serde::de::{MapAccess, Visitor};
use std::fmt;

/// SQL providers disagree about duplicate JSON keys. Reject them before either
/// JSON extraction or a migration can erase the ambiguity. Values remain strings.
pub fn parse_fields(raw: &str) -> Result<Fields> {
    struct FieldMap;
    impl<'de> Visitor<'de> for FieldMap {
        type Value = Fields;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("an object with distinct string fields")
        }
        fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> std::result::Result<Fields, M::Error> {
            let mut fields = Fields::new();
            while let Some((key, value)) = map.next_entry::<String, String>()? {
                if fields.insert(key, value).is_some() {
                    return Err(serde::de::Error::custom("duplicate stored field"));
                }
            }
            Ok(fields)
        }
    }
    let mut decoder = serde_json::Deserializer::from_str(raw);
    let fields = serde::Deserializer::deserialize_map(&mut decoder, FieldMap)?;
    decoder.end()?;
    Ok(fields)
}

// Compare provider-rendered DDL with host-generated DDL. Parentheses and token
// spacing differ in pg_get_indexdef; quoted text, operators, casts, column order,
// collation, opclasses, predicates and extra clauses remain significant.
fn ddl_key(sql: &str) -> String {
    let mut result = String::new();
    let mut quote = None;
    for c in sql.chars() {
        if let Some(q) = quote {
            result.push(c);
            if c == q {
                quote = None;
            }
        } else if c == '\'' || c == '"' {
            quote = Some(c);
            result.push(c);
        } else if !c.is_ascii_whitespace() && !matches!(c, '(' | ')' | ';') {
            result.push(c.to_ascii_lowercase());
        }
    }
    // PostgreSQL adds this cast to JSON key literals, whose spelling is a host-
    // validated identifier. It does not change extraction semantics.
    result.replace("'::text", "'")
}

impl Transaction {
    pub(super) async fn preflight_membership(&mut self, resources: &[Resource]) -> Result<()> {
        for resource in resources.iter().filter(|r| !r.unique.is_empty()) {
            self.validate_resource_rows(resource).await?;
        }
        Ok(())
    }

    pub(super) async fn validate_resource_rows(&mut self, resource: &Resource) -> Result<()> {
        let storage = self.storage_key(&resource.name).await?;
        let mut cursor = 0i64;
        let size = match self.backend {
            Backend::Closed => unreachable!("closed maintenance transaction"),
            Backend::Sqlite(_) => "length(CAST(fields AS BLOB))",
            Backend::Postgres(_) => "pg_catalog.octet_length(fields)",
        };
        let fields = self.bounded_text("fields", 32_768);
        // First limit the candidate window, then retain its byte-bounded
        // prefix. The first row is always returned (NULL if oversized), so
        // malformed data cannot masquerade as end-of-stream. Include 20
        // bytes per id below the driver's 64 KiB total-result limit.
        let sql = sql!(
            "WITH page AS (SELECT id,fields,{size} AS bytes FROM nx_records WHERE resource=$1 AND id>$2 ORDER BY id LIMIT 64), costed AS (SELECT id,fields,SUM(bytes+20) OVER(ORDER BY id ROWS UNBOUNDED PRECEDING) AS total,ROW_NUMBER() OVER(ORDER BY id) AS position FROM page) SELECT CAST(id AS TEXT),{fields} FROM costed WHERE total<=60000 OR position=1 ORDER BY id"
        );
        loop {
            let rows = self
                .fetch::<2>(&sql, &[storage.into(), cursor.into()])
                .await?;
            if rows.is_empty() {
                break;
            }
            for [id, raw] in rows {
                let id = id.parse::<i64>()?;
                let fields = parse_fields(&raw)?;
                crate::manifest::validate_fields(resource, &fields)?;
                for tuple in &resource.unique {
                    crate::membership::canonical_tuple(resource, tuple, &fields)?;
                }
                cursor = id;
            }
        }
        Ok(())
    }

    async fn membership_indexes(&mut self) -> Result<Vec<String>> {
        let sql = match self.backend {
            Backend::Closed => unreachable!("closed maintenance transaction"),
            Backend::Sqlite(_) => {
                "SELECT name FROM sqlite_schema WHERE type='index' AND name GLOB 'nx_m_*' LIMIT 65"
            }
            Backend::Postgres(_) => {
                "SELECT indexname FROM pg_catalog.pg_indexes WHERE schemaname=current_schema() AND left(indexname,5)='nx_m_' LIMIT 65"
            }
        };
        let rows = self.fetch::<1>(sql, &[]).await?;
        ensure!(rows.len() <= 64, "membership index catalog limit");
        Ok(rows.into_iter().map(|[n]| n).collect())
    }

    async fn membership_definitions(&mut self) -> Result<Vec<[String; 4]>> {
        let sql = match self.backend {
            Backend::Closed => unreachable!("closed maintenance transaction"),
            Backend::Sqlite(_) => {
                "SELECT name,CASE WHEN length(CAST(sql AS BLOB))<=4096 THEN sql ELSE NULL END,'','1' FROM sqlite_schema WHERE type='index' AND name GLOB 'nx_m_*' LIMIT 65"
            }
            Backend::Postgres(_) => {
                "SELECT x.relname,CASE WHEN octet_length(pg_catalog.pg_get_indexdef(i.indexrelid))<=4096 THEN pg_catalog.pg_get_indexdef(i.indexrelid) ELSE NULL END,pg_catalog.quote_ident(n.nspname) || '.nx_records',CASE WHEN i.indisvalid AND i.indisready AND i.indislive AND i.indisunique AND NOT i.indisexclusion THEN '1' ELSE '0' END FROM pg_catalog.pg_index i JOIN pg_catalog.pg_class t ON t.oid=i.indrelid JOIN pg_catalog.pg_namespace n ON n.oid=t.relnamespace JOIN pg_catalog.pg_class x ON x.oid=i.indexrelid WHERE n.nspname=current_schema() AND left(x.relname,5)='nx_m_' LIMIT 65"
            }
        };
        let rows = self.fetch::<4>(sql, &[]).await?;
        ensure!(rows.len() <= 64, "membership index catalog limit");
        Ok(rows)
    }

    pub(super) async fn validate_membership_indexes(
        &mut self,
        resources: &[Resource],
    ) -> Result<()> {
        let mut actual: std::collections::BTreeMap<_, _> = self
            .membership_definitions()
            .await?
            .into_iter()
            .map(|[name, ddl, table, usable]| (name, (ddl, table, usable)))
            .collect();
        for resource in resources.iter().filter(|r| !r.unique.is_empty()) {
            let storage = self.storage_key(&resource.name).await?;
            for tuple in &resource.unique {
                let name = crate::membership::unique_index_name(storage, tuple)?;
                let expected = crate::membership::unique_index_sql(
                    self.query_provider()?,
                    resource,
                    storage,
                    tuple,
                )?;
                let (definition, table, usable) = actual.remove(&name).with_context(|| {
                    format!(
                        "missing membership unique index {name}; run noxide schema indexes CONFIG"
                    )
                })?;
                let expected = if table.is_empty() {
                    expected.to_string()
                } else {
                    expected
                        .as_str()
                        .replace(" ON nx_records(", &format!(" ON {table} USING btree ("))
                };
                // pg_get_indexdef quotes BIGINT constants beyond INT4 range.
                let definition =
                    definition.replace(&format!("'{storage}'::bigint"), &storage.to_string());
                ensure!(
                    usable == "1" && ddl_key(&definition) == ddl_key(&expected),
                    "invalid membership unique index {name}; run noxide schema indexes CONFIG"
                );
            }
        }
        ensure!(
            actual.is_empty(),
            "unexpected membership unique indexes; run noxide schema indexes CONFIG"
        );
        Ok(())
    }

    pub(super) async fn drop_membership_indexes(&mut self) -> Result<()> {
        for name in self.membership_indexes().await? {
            ensure!(
                name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_'),
                "invalid membership index name"
            );
            self.execute(&sql!("DROP INDEX {}", Sql::identifier(&name)?), &[])
                .await?;
        }
        Ok(())
    }

    /// Initial empty catalog binding may create declared indexes, but must never
    /// repair or remove an existing definition outside the operator schema gate.
    pub(super) async fn initial_membership_indexes(
        &mut self,
        resources: &[Resource],
    ) -> Result<()> {
        ensure!(
            self.membership_indexes().await?.is_empty(),
            "unexpected membership indexes on unbound storage; run operator schema maintenance"
        );
        self.create_membership_indexes(resources).await?;
        self.validate_membership_indexes(resources).await
    }

    async fn create_membership_indexes(&mut self, resources: &[Resource]) -> Result<()> {
        for resource in resources.iter().filter(|r| !r.unique.is_empty()) {
            let storage = self.storage_key(&resource.name).await?;
            for tuple in &resource.unique {
                self.execute(
                    &crate::membership::unique_index_sql(
                        self.query_provider()?,
                        resource,
                        storage,
                        tuple,
                    )?,
                    &[],
                )
                .await?;
            }
        }
        Ok(())
    }

    /// Caller holds begin_schema's operator gate. No ordinary startup repairs.
    pub(super) async fn reconcile_membership_indexes(
        &mut self,
        resources: &[Resource],
    ) -> Result<()> {
        self.preflight_membership(resources).await?;
        // Rebuilding within the same transaction verifies native duplicate
        // rejection and removes obsolete/spoofed definitions atomically.
        self.drop_membership_indexes().await?;
        self.create_membership_indexes(resources).await?;
        self.validate_membership_indexes(resources).await
    }
}

#[cfg(test)]
mod tests;
