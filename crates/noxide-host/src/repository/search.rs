//! Search updates share the resource mutation and receipt transaction.
use super::*;
use crate::{database::lifecycle::RequestScope, query_plan::NativeProvider};

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
        let state = self.tx.fetch::<2>("SELECT tokenizer,declaration FROM nx_search_state WHERE resource=$1 AND version=1 AND state='ready'", &[storage.into()]).await?;
        ensure!(
            state.len() == 1
                && state[0][0] == index.tokenizer
                && serde_json::from_str::<query::SearchIndex>(&state[0][1])? == *index,
            "search index is not activated"
        );
        let rows = self.tx.fetch::<1>("SELECT CAST(created_seq AS TEXT) FROM nx_records WHERE resource=$1 AND id=$2 AND incarnation=$3 AND revision=$4", &[storage.into(), i64::try_from(id)?.into(), incarnation.into(), revision.into()]).await?;
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

/// Shared operator/runtime leaf. Caller owns activation and the current transaction.
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
    let sql = format!(
        "INSERT INTO nx_search_postings(resource,record_id,field,token,incarnation,revision,created_seq) SELECT $1,$2,p.field,p.token,$3,$4,$6 FROM ({pair}) AS p(field,token) JOIN nx_records r ON r.resource=$1 AND r.id=$2 AND r.incarnation=$3 AND r.revision=$4 AND r.created_seq=$6"
    );
    // SQLite does not accept derived-table column aliases.
    let sql = match tx.query_provider()? {
            NativeProvider::Sqlite => "INSERT INTO nx_search_postings(resource,record_id,field,token,incarnation,revision,created_seq) SELECT $1,$2,CAST(json_extract(p.value,'$[0]') AS BIGINT),json_extract(p.value,'$[1]'),$3,$4,$6 FROM json_each($5) p JOIN nx_records r ON r.resource=$1 AND r.id=$2 AND r.incarnation=$3 AND r.revision=$4 AND r.created_seq=$6".to_owned(),
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
