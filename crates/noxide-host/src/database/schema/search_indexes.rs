//! Explicit search activation and rebuilds within the existing operator fence.
use super::*;
use crate::query_plan::NativeProvider;
use noxide_protocol::{Manifest, Resource, query::SearchIndex};
use std::collections::BTreeMap;

impl Transaction {
    async fn search_states(&mut self) -> Result<BTreeMap<i64, (String, SearchIndex, String)>> {
        let tokenizer = self.bounded_text("tokenizer", 256);
        let declaration = self.bounded_text("declaration", 4096);
        let rows = self.fetch::<5>(&sql!("SELECT CAST(resource AS TEXT),{tokenizer},{declaration},CAST(version AS TEXT),state FROM nx_search_state ORDER BY resource LIMIT 17"), &[]).await?;
        ensure!(rows.len() <= 16, "search state limit");
        let mut states = BTreeMap::new();
        for [resource, tokenizer, declaration, version, state] in rows {
            ensure!(version == "1", "unsupported search index version");
            let resource = resource.parse::<i64>()?;
            ensure!(
                resource > 0
                    && states
                        .insert(
                            resource,
                            (tokenizer, serde_json::from_str(&declaration)?, state)
                        )
                        .is_none(),
                "duplicate search state"
            );
        }
        Ok(states)
    }

    pub(super) async fn initialize_search_states(&mut self, manifest: &Manifest) -> Result<()> {
        self.check_search_resources(&manifest.resources, true).await
    }

    pub(super) async fn validate_search_states(&mut self, manifest: &Manifest) -> Result<()> {
        self.validate_search_resources(&manifest.resources).await
    }

    pub(super) async fn validate_search_resources(&mut self, resources: &[Resource]) -> Result<()> {
        self.check_search_resources(resources, false).await
    }

    async fn check_search_resources(
        &mut self,
        resources: &[Resource],
        create_empty: bool,
    ) -> Result<()> {
        let mut states = self.search_states().await?;
        for resource in resources {
            let Some(index) = &resource.search else {
                continue;
            };
            crate::search::require_tokenizer(&index.tokenizer)?;
            let storage = self.storage_key(&resource.name).await?;
            if let Some((tokenizer, declaration, state)) = states.remove(&storage) {
                ensure!(
                    tokenizer == index.tokenizer && declaration == *index && state == "ready",
                    "search index requires explicit reconciliation"
                );
            } else {
                ensure!(create_empty, "search index is not activated");
                let rows = self
                    .fetch::<1>(
                        "SELECT CAST(id AS TEXT) FROM nx_records WHERE resource=$1 LIMIT 1",
                        &[storage.into()],
                    )
                    .await?;
                ensure!(
                    rows.is_empty(),
                    "populated resource requires an explicit AddSearchIndex migration"
                );
                self.execute("INSERT INTO nx_search_state(resource,tokenizer,declaration,version,state) VALUES($1,$2,$3,1,'ready')", &[storage.into(), index.tokenizer.as_str().into(), serde_json::to_string(index)?.into()]).await?;
            }
        }
        ensure!(
            states.is_empty(),
            "undeclared search index requires an explicit RemoveSearchIndex migration"
        );
        Ok(())
    }

    pub(super) async fn remove_search_index(&mut self, storage: i64) -> Result<()> {
        self.execute(
            "DELETE FROM nx_search_postings WHERE resource=$1",
            &[storage.into()],
        )
        .await?;
        let removed = self
            .execute(
                "DELETE FROM nx_search_state WHERE resource=$1",
                &[storage.into()],
            )
            .await?;
        ensure!(removed == 1, "search index is missing");
        Ok(())
    }

    pub(super) async fn rebuild_search_index(&mut self, resource: &Resource) -> Result<()> {
        let checkpoint = self.operator_checkpoint()?;
        let index = resource
            .search
            .as_ref()
            .context("missing target search declaration")?;
        crate::search::require_tokenizer(&index.tokenizer)?;
        let storage = self.storage_key(&resource.name).await?;
        self.execute("INSERT INTO nx_search_state(resource,tokenizer,declaration,version,state) VALUES($1,$2,$3,1,'building') ON CONFLICT(resource) DO UPDATE SET tokenizer=excluded.tokenizer,declaration=excluded.declaration,version=1,state='building'", &[storage.into(), index.tokenizer.as_str().into(), serde_json::to_string(index)?.into()]).await?;
        // One bounded identity page and one canonical row are retained at a time.
        let mut after = 0i64;
        loop {
            checkpoint.checkpoint()?;
            let rows = self.fetch::<1>("SELECT CAST(id AS TEXT) FROM nx_records WHERE resource=$1 AND id>$2 ORDER BY id LIMIT 64", &[storage.into(), after.into()]).await?;
            if rows.is_empty() {
                break;
            }
            for [id] in rows {
                checkpoint.checkpoint()?;
                let id = id.parse::<i64>()?;
                let fields = self.bounded_text("fields", 32768);
                let incarnation = self.bounded_text("incarnation", 64);
                let rows = self.fetch::<4>(&sql!("SELECT {fields},{incarnation},CAST(revision AS TEXT),CAST(created_seq AS TEXT) FROM nx_records WHERE resource=$1 AND id=$2"), &[storage.into(), id.into()]).await?;
                let [fields, incarnation, revision, created_seq] = rows
                    .into_iter()
                    .next()
                    .context("search record disappeared")?;
                let fields: noxide_protocol::Fields = serde_json::from_str(&fields)?;
                crate::manifest::validate_fields(resource, &fields)?;
                let values: Vec<_> = index
                    .fields
                    .iter()
                    .map(|field| fields.get(field).map(String::as_str))
                    .collect();
                let indexed =
                    crate::search::indexed_record(&values, index.max_bytes as usize, &mut || {
                        checkpoint.checkpoint()
                    })?;
                let prepared =
                    crate::search::PreparedPostings::new(&indexed, || checkpoint.checkpoint())?;
                replace_postings(
                    self,
                    storage,
                    id,
                    &incarnation,
                    revision.parse()?,
                    created_seq.parse()?,
                    &prepared,
                )
                .await?;
                after = id;
            }
        }
        checkpoint.checkpoint()?;
        let ready = self.execute("UPDATE nx_search_state SET state='ready' WHERE resource=$1 AND tokenizer=$2 AND declaration=$3 AND version=1 AND state='building'", &[storage.into(), index.tokenizer.as_str().into(), serde_json::to_string(index)?.into()]).await?;
        ensure!(ready == 1, "search rebuild state changed");
        Ok(())
    }
}

/// Shared operator/runtime helper. Caller owns activation and the current transaction.
pub(crate) async fn replace_postings(
    tx: &mut Transaction,
    storage: i64,
    id: i64,
    incarnation: &str,
    revision: i64,
    created_seq: i64,
    prepared: &crate::search::PreparedPostings,
) -> Result<()> {
    ensure!(
        storage > 0
            && id > 0
            && revision > 0
            && created_seq > 0
            && !incarnation.is_empty()
            && incarnation.len() <= 64,
        "posting metadata"
    );
    tx.execute(
        "DELETE FROM nx_search_postings WHERE resource=$1 AND record_id=$2",
        &[storage.into(), id.into()],
    )
    .await?;
    if prepared.count() == 0 {
        return Ok(());
    }
    let pair = match tx.query_provider()? {
        NativeProvider::Sqlite => {
            "SELECT CAST(json_extract(value,'$[0]') AS BIGINT),json_extract(value,'$[1]') FROM json_each($5)"
        }
        NativeProvider::Postgres => {
            "SELECT CAST(value->>0 AS BIGINT),value->>1 FROM jsonb_array_elements(CAST($5 AS jsonb)) AS pair(value)"
        }
    };
    let sql = sql!(
        "INSERT INTO nx_search_postings(resource,record_id,field,token,incarnation,revision,created_seq) SELECT $1,$2,p.field,p.token,$3,$4,$6 FROM ({pair}) AS p(field,token) JOIN nx_records r ON r.resource=$1 AND r.id=$2 AND r.incarnation=$3 AND r.revision=$4 AND r.created_seq=$6"
    );
    // SQLite does not accept derived-table column aliases.
    let sql = match tx.query_provider()? {
        NativeProvider::Sqlite => Sql::statement(
            "INSERT INTO nx_search_postings(resource,record_id,field,token,incarnation,revision,created_seq) SELECT $1,$2,CAST(json_extract(p.value,'$[0]') AS BIGINT),json_extract(p.value,'$[1]'),$3,$4,$6 FROM json_each($5) p JOIN nx_records r ON r.resource=$1 AND r.id=$2 AND r.incarnation=$3 AND r.revision=$4 AND r.created_seq=$6",
        ),
        NativeProvider::Postgres => sql,
    };
    let count = tx
        .execute(
            &sql,
            &[
                storage.into(),
                id.into(),
                incarnation.into(),
                revision.into(),
                prepared.payload().into(),
                created_seq.into(),
            ],
        )
        .await?;
    ensure!(
        count == u64::try_from(prepared.count())?,
        "search posting mutation count"
    );
    Ok(())
}

#[cfg(test)]
mod tests;
