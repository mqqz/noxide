//! Blob store pairing, quota counters and blob metadata.
use super::Statement;
use crate::database::{Param, Sql, Transaction, sql};
use crate::sql::JoinSql;
use anyhow::Result;

fn row_columns(tx: &Transaction) -> Sql {
    const TEXT: &[(&str, usize)] = &[
        ("slot", 64),
        ("blob_ref", 67),
        ("upload_handle", 67),
        ("object_key", 64),
        ("subject", 64),
        ("context", 64),
        ("input", 64),
        ("state", 16),
        ("sha256", 64),
        ("filename", 80),
        ("owner_incarnation", 64),
        ("owner_field", 32),
        ("owner_process", 64),
    ];
    const ORDER: &[&str] = &[
        "slot",
        "blob_ref",
        "upload_handle",
        "object_key",
        "subject",
        "context",
        "input",
        "anonymous",
        "state",
        "generation",
        "reserved_bytes",
        "actual_bytes",
        "sha256",
        "filename",
        "created_ms",
        "expires_ms",
        "owner_resource",
        "owner_id",
        "owner_incarnation",
        "owner_field",
        "claimed_ms",
        "owner_process",
    ];
    ORDER
        .iter()
        .map(|column| {
            if let Some((_, maximum)) = TEXT.iter().find(|(name, _)| name == column) {
                tx.bounded_text(column, *maximum)
            } else {
                tx.bounded_text(sql!("CAST({column} AS TEXT)"), 20)
            }
        })
        .collect::<Vec<_>>()
        .joined(",")
}

enum CounterTable {
    Store,
    Subject,
}

fn counter_predicate(table: CounterTable) -> Sql {
    let (prefix, columns): (&'static str, &[&'static str]) = match table {
        CounterTable::Store => (
            "nx_blob_store",
            &[
                "serial",
                "reserved_bytes",
                "used_bytes",
                "objects",
                "anonymous_reserved_bytes",
                "anonymous_used_bytes",
            ],
        ),
        CounterTable::Subject => (
            "nx_blob_subjects",
            &["reserved_bytes", "used_bytes", "objects"],
        ),
    };
    columns
        .iter()
        .map(|column| {
            sql!("CAST({prefix}.{column} AS TEXT)=CAST(CAST({prefix}.{column} AS BIGINT) AS TEXT)")
        })
        .collect::<Vec<_>>()
        .joined(" AND ")
}

pub fn pair_record(tx: &Transaction) -> Statement<0, 10> {
    let text = [("identity", 64), ("pair_id", 64), ("pair_state", 7)]
        .iter()
        .map(|(name, max)| tx.bounded_text(name, *max))
        .collect::<Vec<_>>()
        .joined(",");
    let counters = [
        "serial",
        "reserved_bytes",
        "used_bytes",
        "objects",
        "anonymous_reserved_bytes",
        "anonymous_used_bytes",
    ]
    .iter()
    .map(|name| tx.bounded_text(sql!("CAST({name} AS TEXT)"), 20))
    .collect::<Vec<_>>()
    .joined(",");
    Statement::built(sql!(
        "SELECT {text},{counters},CASE WHEN EXISTS(SELECT 1 FROM nx_blobs) OR EXISTS(SELECT 1 FROM nx_blob_subjects) OR EXISTS(SELECT 1 FROM nx_blob_orphans) THEN '0' ELSE '1' END FROM nx_blob_store WHERE singleton=1"
    ))
}

pub fn blob_page(tx: &Transaction) -> Statement<1, 22> {
    let columns = row_columns(tx);
    Statement::built(sql!(
        "SELECT {columns} FROM nx_blobs WHERE slot>$1 ORDER BY slot LIMIT 16"
    ))
}

#[derive(Clone, Copy)]
pub enum BlobIdentity {
    Slot,
    Reference,
    ObjectKey,
}

pub fn blob_by(tx: &Transaction, identity: BlobIdentity) -> Statement<1, 22> {
    let select = row_columns(tx);
    let column = match identity {
        BlobIdentity::Slot => "slot",
        BlobIdentity::Reference => "blob_ref",
        BlobIdentity::ObjectKey => "object_key",
    };
    Statement::built(sql!("SELECT {select} FROM nx_blobs WHERE {column}=$1"))
}

pub fn reserve_store() -> Statement<10, 1> {
    Statement::built(sql!(
        "UPDATE nx_blob_store SET reserved_bytes=reserved_bytes+$2,objects=objects+1,anonymous_reserved_bytes=anonymous_reserved_bytes+$3,serial=serial+1 WHERE singleton=1 AND identity=$1 AND pair_state='paired' AND NOT EXISTS(SELECT 1 FROM nx_blob_orphans) AND serial<9223372036854775807 AND reserved_bytes<=$4-used_bytes-$2 AND objects<$5 AND ($6=0 OR anonymous_reserved_bytes<=$7-anonymous_used_bytes-$2) AND (SELECT COUNT(*) FROM (SELECT slot FROM nx_blobs WHERE subject=$8 AND state IN ('uploading','staged') LIMIT 5) subject_stages)<$9 AND ($6=0 OR (SELECT COUNT(*) FROM (SELECT slot FROM nx_blobs WHERE anonymous=1 AND state IN ('uploading','staged') LIMIT 17) deployment_stages)<$10) AND {} RETURNING CAST(serial AS TEXT)",
        counter_predicate(CounterTable::Store)
    ))
}

pub fn reserve_subject() -> Statement<4, 1> {
    Statement::built(sql!(
        "INSERT INTO nx_blob_subjects(subject,anonymous,reserved_bytes,used_bytes,objects) VALUES($1,$2,$3,0,1) ON CONFLICT(subject) DO UPDATE SET reserved_bytes=nx_blob_subjects.reserved_bytes+$3,objects=nx_blob_subjects.objects+1 WHERE nx_blob_subjects.anonymous=$2 AND nx_blob_subjects.objects<65536 AND ($2=0 OR nx_blob_subjects.reserved_bytes<=$4-nx_blob_subjects.used_bytes-$3) AND {} RETURNING subject",
        counter_predicate(CounterTable::Subject)
    ))
}

pub fn stage_store() -> Statement<4, 0> {
    Statement::built(sql!(
        "UPDATE nx_blob_store SET reserved_bytes=reserved_bytes-$2,used_bytes=used_bytes+$3,anonymous_reserved_bytes=anonymous_reserved_bytes-$2*$4,anonymous_used_bytes=anonymous_used_bytes+$3*$4,serial=serial+1 WHERE singleton=1 AND identity=$1 AND pair_state='paired' AND reserved_bytes>=$2 AND anonymous_reserved_bytes>=$2*$4 AND objects>0 AND serial<9223372036854775807 AND used_bytes<=9223372036854775807-$3 AND anonymous_used_bytes<=9223372036854775807-$3*$4 AND {}",
        counter_predicate(CounterTable::Store)
    ))
}

pub fn stage_subject() -> Statement<4, 0> {
    Statement::built(sql!(
        "UPDATE nx_blob_subjects SET reserved_bytes=reserved_bytes-$2,used_bytes=used_bytes+$3 WHERE subject=$1 AND anonymous=$4 AND reserved_bytes>=$2 AND objects>0 AND used_bytes<=9223372036854775807-$3 AND {}",
        counter_predicate(CounterTable::Subject)
    ))
}

pub fn release_store() -> Statement<4, 0> {
    Statement::built(sql!(
        "UPDATE nx_blob_store SET reserved_bytes=reserved_bytes-$2,used_bytes=used_bytes-$3,objects=objects-1,anonymous_reserved_bytes=anonymous_reserved_bytes-$2*$4,anonymous_used_bytes=anonymous_used_bytes-$3*$4,serial=serial+1 WHERE singleton=1 AND identity=$1 AND pair_state='paired' AND reserved_bytes>=$2 AND used_bytes>=$3 AND objects>0 AND anonymous_reserved_bytes>=$2*$4 AND anonymous_used_bytes>=$3*$4 AND serial<9223372036854775807 AND {}",
        counter_predicate(CounterTable::Store)
    ))
}

pub fn release_subject() -> Statement<4, 0> {
    Statement::built(sql!(
        "UPDATE nx_blob_subjects SET reserved_bytes=reserved_bytes-$2,used_bytes=used_bytes-$3,objects=objects-1 WHERE subject=$1 AND anonymous=$4 AND reserved_bytes>=$2 AND used_bytes>=$3 AND objects>0 AND {}",
        counter_predicate(CounterTable::Subject)
    ))
}

pub fn delete_empty_subject() -> Statement<1, 0> {
    Statement::built(sql!(
        "DELETE FROM nx_blob_subjects WHERE subject=$1 AND reserved_bytes=0 AND used_bytes=0 AND objects=0 AND {}",
        counter_predicate(CounterTable::Subject)
    ))
}

pub fn lock_staged(tx: &Transaction) -> Statement<6, 22> {
    let columns = row_columns(tx);
    Statement::built(sql!(
        "UPDATE nx_blobs SET generation=generation WHERE upload_handle=$1 AND state='staged' AND slot=$2 AND subject=$3 AND context=$4 AND input=$5 AND expires_ms>$6 RETURNING {columns}"
    ))
}

pub fn attached_blobs(tx: &Transaction, limit: usize) -> Statement<3, 4> {
    let slot = tx.bounded_text("slot", 64);
    let field = tx.bounded_text("owner_field", 32);
    let reference = tx.bounded_text("blob_ref", 67);
    let generation = tx.bounded_text("CAST(generation AS TEXT)", 20);
    Statement::built(sql!(
        "SELECT {slot},{field},{reference},{generation} FROM nx_blobs WHERE state='attached' AND owner_resource=$1 AND owner_id=$2 AND owner_incarnation=$3 ORDER BY slot LIMIT {limit}"
    ))
}

impl Transaction {
    /// Mark each selected blob of one owner unreferenced, fenced by generation.
    /// `owner` binds the resource, id and incarnation.
    pub async fn unreference_blobs(
        &mut self,
        owner: [Param; 3],
        selected: &[(Param, Param)],
    ) -> Result<u64> {
        let mut params = owner.to_vec();
        let mut clauses = Vec::with_capacity(selected.len());
        for (slot, generation) in selected {
            params.push(slot.clone());
            params.push(generation.clone());
            let (slot, generation) = (params.len() - 1, params.len());
            clauses.push(sql!("(slot=${slot} AND generation=${generation})"));
        }
        let selected = clauses.joined(" OR ");
        self.execute(
            sql!(
                "UPDATE nx_blobs SET state='unreferenced',generation=generation+1 WHERE state='attached' AND owner_resource=$1 AND owner_id=$2 AND owner_incarnation=$3 AND ({selected})"
            ),
            &params,
        )
        .await
    }
}
pub const INSERT_PENDING_PAIR: Statement<2, 0> = Statement::new(
    "INSERT INTO nx_blob_store(singleton,identity,pair_id,pair_state,serial,reserved_bytes,used_bytes,objects,anonymous_reserved_bytes,anonymous_used_bytes) SELECT 1,$1,$2,'pending',1,0,0,0,0,0 WHERE NOT EXISTS(SELECT 1 FROM nx_blobs) AND NOT EXISTS(SELECT 1 FROM nx_blob_subjects) AND NOT EXISTS(SELECT 1 FROM nx_blob_orphans) ON CONFLICT(singleton) DO NOTHING",
);
pub const COMPLETE_PAIR: Statement<2, 0> = Statement::new(
    "UPDATE nx_blob_store SET pair_state='paired',serial=serial+1 WHERE singleton=1 AND identity=$1 AND pair_id=$2 AND pair_state='pending' AND serial<9223372036854775807 AND reserved_bytes=0 AND used_bytes=0 AND objects=0 AND anonymous_reserved_bytes=0 AND anonymous_used_bytes=0 AND NOT EXISTS(SELECT 1 FROM nx_blobs) AND NOT EXISTS(SELECT 1 FROM nx_blob_subjects) AND NOT EXISTS(SELECT 1 FROM nx_blob_orphans)",
);
pub const INSERT_BLOB: Statement<13, 0> = Statement::new(
    "INSERT INTO nx_blobs(slot,blob_ref,upload_handle,object_key,subject,context,input,anonymous,state,generation,reserved_bytes,actual_bytes,sha256,filename,created_ms,expires_ms,owner_resource,owner_id,owner_incarnation,owner_field,claimed_ms,owner_process) SELECT $1,$2,$3,$4,$5,$6,$7,$8,'uploading',1,$9,0,'',$10,$11,$12,0,0,'','',0,$13 WHERE NOT EXISTS(SELECT 1 FROM nx_blob_orphans WHERE object_key=$4) ON CONFLICT(slot) DO NOTHING",
);
pub const STAGE_BLOB: Statement<11, 0> = Statement::new(
    "UPDATE nx_blobs SET state='staged',generation=$2,reserved_bytes=0,actual_bytes=$3,sha256=$4,upload_handle=$5 WHERE slot=$1 AND state='uploading' AND generation=$6 AND owner_process=$7 AND expires_ms>$8 AND subject=$9 AND context=$10 AND input=$11",
);
pub const ATTACH_BLOB: Statement<8, 0> = Statement::new(
    "UPDATE nx_blobs SET state='attached',generation=$2,owner_resource=$3,owner_id=$4,owner_incarnation=$5,owner_field=$6 WHERE slot=$1 AND state='staged' AND generation=$7 AND upload_handle=$8",
);
pub const CLAIM_FOR_DELETION: Statement<7, 0> = Statement::new(
    "UPDATE nx_blobs SET state='deleting',generation=$2,claimed_ms=$3,owner_process=$4 WHERE slot=$1 AND state=$5 AND generation=$6 AND owner_process=$7",
);
pub const MARK_DELETED: Statement<5, 0> = Statement::new(
    "UPDATE nx_blobs SET state='deleted',generation=$2,reserved_bytes=0,actual_bytes=0,claimed_ms=$3 WHERE slot=$1 AND state='deleting' AND generation=$4 AND owner_process=$5",
);
pub const PAIRED_IDENTITY: Statement<1, 1> = Statement::new(
    "SELECT identity FROM nx_blob_store WHERE singleton=1 AND identity=$1 AND pair_state='paired'",
);
pub const INSERT_ORPHAN: Statement<5, 0> = Statement::new(
    "INSERT INTO nx_blob_orphans(object_key,generation,state,first_seen_ms,claimed_ms,charged_bytes,charged_objects,owner_process) SELECT $1,1,'observed',$2,0,$3,$4,$5 WHERE NOT EXISTS(SELECT 1 FROM nx_blobs WHERE object_key=$1) ON CONFLICT(object_key) DO NOTHING",
);
pub const CHARGE_ORPHAN: Statement<3, 0> = Statement::new(
    "UPDATE nx_blob_store SET used_bytes=used_bytes+$2,objects=objects+$3,serial=serial+1 WHERE singleton=1 AND identity=$1 AND pair_state='paired' AND used_bytes<=9223372036854775807-$2 AND objects<=9223372036854775807-$3 AND serial<9223372036854775807",
);
pub const LOCK_PAIRED_STORE: Statement<1, 0> = Statement::new(
    "UPDATE nx_blob_store SET serial=serial WHERE singleton=1 AND identity=$1 AND pair_state='paired'",
);
