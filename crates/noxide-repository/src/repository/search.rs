//! Search updates share the resource mutation and receipt transaction.
use super::*;
use crate::database::{lifecycle::RequestScope, schema::replace_postings};
use noxide_store::statements::records as stmt;

impl Effects {
    pub(super) async fn update_search(
        &mut self,
        resource: u32,
        storage: i64,
        id: u64,
        incarnation: &str,
        revision: i64,
        fields: &Fields,
    ) -> Result<()> {
        let schema = manifest::resource(&self.manifest, resource)?;
        let Some(index) = &schema.search else {
            return Ok(());
        };
        crate::search::require_tokenizer(&index.tokenizer)?;
        let values: Vec<_> = index
            .fields
            .iter()
            .map(|field| fields.get(field).map(String::as_str))
            .collect();
        let indexed = crate::search::indexed_record(
            &values,
            index.max_bytes as usize,
            &mut RequestScope::checkpoint_current,
        )?;
        let payload =
            crate::search::PreparedPostings::new(&indexed, RequestScope::checkpoint_current)?;
        // Check activation inside the same transaction before modifying postings.
        let state = self
            .tx
            .rows(&stmt::READY_SEARCH_STATE, &[storage.into()])
            .await?;
        ensure!(
            state.len() == 1
                && state[0][0] == index.tokenizer
                && serde_json::from_str::<query::SearchIndex>(&state[0][1])? == *index,
            "search index is not activated"
        );
        let rows = self
            .tx
            .rows(
                &stmt::RECORD_SEQUENCE,
                &[
                    storage.into(),
                    i64::try_from(id)?.into(),
                    incarnation.into(),
                    revision.into(),
                ],
            )
            .await?;
        let created_seq: i64 = rows
            .first()
            .ok_or_else(|| anyhow::anyhow!("search row disappeared"))?[0]
            .parse()?;
        replace_postings(
            &mut self.tx,
            storage,
            i64::try_from(id)?,
            incarnation,
            revision,
            created_seq,
            &payload,
        )
        .await?;
        Ok(())
    }
}
