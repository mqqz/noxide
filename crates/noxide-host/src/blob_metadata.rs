//! Provider-portable blob metadata. Every statement uses the existing
//! transaction-owned root statement meter; no independent upload allowance. Caller owns commit/rollback/unknown-outcome recovery. These methods
//! perform no filesystem work and mint no acknowledged-commit proof.
use crate::{
    blob_state::{
        Association, Commitment, GcClaim, Generation, Metadata, State, Transition, UploadBinding,
    },
    blob_store::{
        DurableObject, DurablePairMarker, IoGuard, ObjectKey, PairId, PairObservation, PairPhase,
        PairRecord, PairStep,
    },
    blob_transport::AttachmentName,
    database::{Param, Transaction},
};
use anyhow::{Context, Result, ensure};
use noxide_protocol::{
    blobs::{
        AnonymousCapabilityQuota, BlobPolicy, BlobRef, MAX_UPLOAD_BYTES, STAGE_LIFETIME_MILLIS,
        UploadHandle,
    },
    time::{Duration, Timestamp},
};

pub(crate) struct MetadataContext<'a> {
    pub(crate) tx: &'a mut Transaction,
}
impl MetadataContext<'_> {
    async fn execute(&mut self, sql: &str, params: &[Param]) -> Result<u64> {
        self.tx.execute(sql, params).await
    }
    async fn fetch<const N: usize>(
        &mut self,
        sql: &str,
        params: &[Param],
    ) -> Result<Vec<[String; N]>> {
        self.tx.fetch(sql, params).await
    }
    /// Startup only, after check_blob_layout. Observation was captured outside
    /// this transaction under the retained exclusive store lease. A newly
    /// inserted PENDING record MUST commit with known acknowledgement before
    /// the runtime follows this data proposal with any filesystem marker write.
    pub(crate) async fn prepare_pair(
        &mut self,
        observation: &PairObservation,
    ) -> Result<PairPreparation> {
        if let Some(record) = self.pair_record().await? {
            let step = observation.decide(Some(&record))?;
            return Ok(PairPreparation {
                record,
                step,
                pending_inserted: false,
            });
        }
        ensure!(
            observation.decide(None)? == PairStep::CreatePending,
            "unsafe new store pairing"
        );
        let pair = PairId::random()?;
        let store = observation.store_identity().clone();
        let changed=self.execute("INSERT INTO nx_blob_store(singleton,identity,pair_id,pair_state,serial,reserved_bytes,used_bytes,objects,anonymous_reserved_bytes,anonymous_used_bytes) SELECT 1,$1,$2,'pending',1,0,0,0,0,0 WHERE NOT EXISTS(SELECT 1 FROM nx_blobs) AND NOT EXISTS(SELECT 1 FROM nx_blob_subjects) AND NOT EXISTS(SELECT 1 FROM nx_blob_orphans) ON CONFLICT(singleton) DO NOTHING",&[store.as_str().into(),pair.as_str().into()]).await?;
        ensure!(changed == 1, "store pairing raced or metadata exists");
        let record = PairRecord {
            store,
            pair: pair.clone(),
            phase: PairPhase::Pending,
            empty_metadata: true,
        };
        Ok(PairPreparation {
            record,
            step: PairStep::InstallMarker(pair),
            pending_inserted: true,
        })
    }
    async fn pair_record(&mut self) -> Result<Option<PairRecord>> {
        let text = [("identity", 64), ("pair_id", 64), ("pair_state", 7)]
            .iter()
            .map(|(name, max)| self.tx.bounded_text(name, *max))
            .collect::<Vec<_>>()
            .join(",");
        let counters = [
            "serial",
            "reserved_bytes",
            "used_bytes",
            "objects",
            "anonymous_reserved_bytes",
            "anonymous_used_bytes",
        ]
        .iter()
        .map(|name| self.tx.bounded_text(&format!("CAST({name} AS TEXT)"), 20))
        .collect::<Vec<_>>()
        .join(",");
        let rows=self.fetch::<10>(&format!("SELECT {text},{counters},CASE WHEN EXISTS(SELECT 1 FROM nx_blobs) OR EXISTS(SELECT 1 FROM nx_blob_subjects) OR EXISTS(SELECT 1 FROM nx_blob_orphans) THEN '0' ELSE '1' END FROM nx_blob_store WHERE singleton=1"),&[]).await?;
        ensure!(rows.len() <= 1, "duplicate store pairing");
        let Some(
            [
                store,
                pair,
                phase,
                serial,
                reserved,
                used,
                objects,
                anonymous_reserved,
                anonymous_used,
                empty,
            ],
        ) = rows.into_iter().next()
        else {
            return Ok(None);
        };
        ensure!(integer(&serial)? > 0, "invalid blob store serial");
        let (reserved, used, objects, anonymous_reserved, anonymous_used) = (
            unsigned(&reserved)?,
            unsigned(&used)?,
            unsigned(&objects)?,
            unsigned(&anonymous_reserved)?,
            unsigned(&anonymous_used)?,
        );
        ensure!(
            reserved
                .checked_add(used)
                .is_some_and(|n| n <= noxide_protocol::blobs::MAX_APP_BLOB_BYTES)
                && objects <= u64::from(noxide_protocol::blobs::MAX_APP_BLOB_OBJECTS)
                && anonymous_reserved <= reserved
                && anonymous_used <= used
                && anonymous_reserved
                    .checked_add(anonymous_used)
                    .is_some_and(|n| n <= noxide_protocol::blobs::MAX_ANONYMOUS_BYTES)
                && (objects > 0 || (reserved == 0 && used == 0)),
            "invalid blob store counters"
        );
        let phase = match phase.as_str() {
            "pending" => PairPhase::Pending,
            "paired" => PairPhase::Paired,
            _ => anyhow::bail!("invalid store pairing phase"),
        };
        let empty_metadata = empty == "1" && objects == 0 && reserved == 0 && used == 0;
        ensure!(
            phase != PairPhase::Pending || empty_metadata,
            "pending pairing contains metadata or charges"
        );
        Ok(Some(PairRecord {
            store: ObjectKey::parse(store)?,
            pair: PairId::parse(pair)?,
            phase,
            empty_metadata,
        }))
    }
    /// Marker evidence proves file+directory durability, not this transaction's
    /// eventual commit. The caller still requires authoritative acknowledgement
    /// and final healthy lifecycle activation before serving or starting GC.
    pub(crate) async fn acknowledge_pair(&mut self, marker: &DurablePairMarker) -> Result<()> {
        let changed=self.execute("UPDATE nx_blob_store SET pair_state='paired',serial=serial+1 WHERE singleton=1 AND identity=$1 AND pair_id=$2 AND pair_state='pending' AND serial<9223372036854775807 AND reserved_bytes=0 AND used_bytes=0 AND objects=0 AND anonymous_reserved_bytes=0 AND anonymous_used_bytes=0 AND NOT EXISTS(SELECT 1 FROM nx_blobs) AND NOT EXISTS(SELECT 1 FROM nx_blob_subjects) AND NOT EXISTS(SELECT 1 FROM nx_blob_orphans)",&[marker.store().as_str().into(),marker.pair().as_str().into()]).await?;
        if changed == 0 {
            let row = self.pair_record().await?.context("store pairing missing")?;
            ensure!(
                row.store == *marker.store()
                    && row.pair == *marker.pair()
                    && row.phase == PairPhase::Paired,
                "store pairing acknowledgement mismatch"
            );
        } else {
            ensure!(changed == 1, "duplicate pairing acknowledgement");
        }
        Ok(())
    }
    pub(crate) async fn slot(&mut self, slot: &Commitment) -> Result<Option<BlobRow>> {
        self.load("slot", slot.as_str()).await
    }
    pub(crate) async fn reference(&mut self, reference: &BlobRef) -> Result<Option<BlobRow>> {
        self.load("blob_ref", reference.as_str()).await
    }
    pub(crate) async fn object(&mut self, key: &ObjectKey) -> Result<Option<BlobRow>> {
        self.load("object_key", key.as_str()).await
    }
    pub(crate) async fn page(&mut self, after: &str) -> Result<Vec<BlobRow>> {
        let columns = self.row_columns();
        self.fetch::<22>(
            &format!("SELECT {columns} FROM nx_blobs WHERE slot>$1 ORDER BY slot LIMIT 16"),
            &[after.into()],
        )
        .await?
        .into_iter()
        .map(BlobRow::parse)
        .collect()
    }
    async fn load(&mut self, column: &str, value: &str) -> Result<Option<BlobRow>> {
        ensure!(
            matches!(column, "slot" | "blob_ref" | "object_key"),
            "invalid metadata lookup"
        );
        let select = self.row_columns();
        let rows = self
            .fetch::<22>(
                &format!("SELECT {select} FROM nx_blobs WHERE {column}=$1"),
                &[value.into()],
            )
            .await?;
        ensure!(rows.len() <= 1, "duplicate blob identity");
        rows.into_iter().next().map(BlobRow::parse).transpose()
    }
    fn row_columns(&self) -> String {
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
                    self.tx.bounded_text(column, *maximum)
                } else {
                    self.tx.bounded_text(&format!("CAST({column} AS TEXT)"), 20)
                }
            })
            .collect::<Vec<_>>()
            .join(",")
    }
    /// Caller has already verified origin/CSRF/session/submission/upload ticket,
    /// probed the existing semantic receipt and serialized the stable nonce.
    /// Existing slot is returned WITHOUT a fresh charge or file rewrite.
    pub(crate) async fn reserve(&mut self, request: Reservation<'_>) -> Result<ReservationOutcome> {
        request
            .policy
            .validate_limits()
            .map_err(anyhow::Error::msg)?;
        ensure!(
            (1..=request.policy.limits.file_bytes).contains(&request.limit),
            "upload reservation ceiling"
        );
        if let Some(existing) = self.slot(&request.binding.slot).await? {
            ensure!(
                existing.metadata.binding == request.binding,
                "foreign upload slot"
            );
            return Ok(ReservationOutcome::Existing(existing));
        }
        let anonymous = request.capability.is_some();
        let anon_bytes = if anonymous { request.limit } else { 0 };
        let (deployment_stages, deployment_bytes, cap_stages, cap_bytes) = match request.capability
        {
            Some(cap) => {
                cap.validate().map_err(anyhow::Error::msg)?;
                let deployment = request
                    .policy
                    .anonymous
                    .context("anonymous upload not declared")?;
                ensure!(
                    request.limit <= cap.bytes && request.limit <= deployment.bytes,
                    "anonymous file exceeds quota"
                );
                (deployment.stages, deployment.bytes, cap.stages, cap.bytes)
            }
            None => (1, 1, request.policy.limits.live_stages, u64::MAX),
        };
        let stages = cap_stages.min(request.policy.limits.live_stages);
        let changed=self.fetch::<1>(&format!("UPDATE nx_blob_store SET reserved_bytes=reserved_bytes+$2,objects=objects+1,anonymous_reserved_bytes=anonymous_reserved_bytes+$3,serial=serial+1 WHERE singleton=1 AND identity=$1 AND pair_state='paired' AND NOT EXISTS(SELECT 1 FROM nx_blob_orphans) AND serial<9223372036854775807 AND reserved_bytes<=$4-used_bytes-$2 AND objects<$5 AND ($6=0 OR anonymous_reserved_bytes<=$7-anonymous_used_bytes-$2) AND (SELECT COUNT(*) FROM (SELECT slot FROM nx_blobs WHERE subject=$8 AND state IN ('uploading','staged') LIMIT 5) subject_stages)<$9 AND ($6=0 OR (SELECT COUNT(*) FROM (SELECT slot FROM nx_blobs WHERE anonymous=1 AND state IN ('uploading','staged') LIMIT 17) deployment_stages)<$10) AND {} RETURNING CAST(serial AS TEXT)", counter_predicate(CounterTable::Store)),&[
            request.store.as_str().into(),number(request.limit)?,number(anon_bytes)?,number(request.policy.limits.app_bytes)?,i64::from(request.policy.limits.objects).into(),i64::from(anonymous).into(),number(deployment_bytes)?,request.binding.subject.as_str().into(),i64::from(stages).into(),i64::from(deployment_stages).into()]).await?;
        ensure!(changed.len() == 1, "blob app quota unavailable");
        let changed=self.fetch::<1>(&format!("INSERT INTO nx_blob_subjects(subject,anonymous,reserved_bytes,used_bytes,objects) VALUES($1,$2,$3,0,1) ON CONFLICT(subject) DO UPDATE SET reserved_bytes=nx_blob_subjects.reserved_bytes+$3,objects=nx_blob_subjects.objects+1 WHERE nx_blob_subjects.anonymous=$2 AND nx_blob_subjects.objects<65536 AND ($2=0 OR nx_blob_subjects.reserved_bytes<=$4-nx_blob_subjects.used_bytes-$3) AND {} RETURNING subject", counter_predicate(CounterTable::Subject)),&[
            request.binding.subject.as_str().into(),i64::from(anonymous).into(),number(request.limit)?,number(cap_bytes.min(i64::MAX as u64))?]).await?;
        ensure!(changed.len() == 1, "blob subject quota unavailable");
        let key = ObjectKey::random()?;
        let blob = BlobRef::parse(format!("b1_{}", ObjectKey::random()?.as_str()))
            .map_err(anyhow::Error::msg)?;
        let handle = UploadHandle::parse(format!("u1_{}", ObjectKey::random()?.as_str()))
            .map_err(anyhow::Error::msg)?;
        let expires = request
            .now
            .checked_add(Duration::from_millis(STAGE_LIFETIME_MILLIS)?)?;
        let row = BlobRow {
            metadata: Metadata {
                blob,
                handle,
                key,
                binding: request.binding,
                state: State::Uploading,
                generation: Generation::parse(1)?,
                expires,
                reserved: request.limit,
                bytes: 0,
                digest: None,
                association: None,
            },
            anonymous,
            filename: request.filename,
            created: request.now,
            claimed: Timestamp::UNIX_EPOCH,
            process: request.process.clone(),
        };
        let m = &row.metadata;
        let inserted=self.execute("INSERT INTO nx_blobs(slot,blob_ref,upload_handle,object_key,subject,context,input,anonymous,state,generation,reserved_bytes,actual_bytes,sha256,filename,created_ms,expires_ms,owner_resource,owner_id,owner_incarnation,owner_field,claimed_ms,owner_process) SELECT $1,$2,$3,$4,$5,$6,$7,$8,'uploading',1,$9,0,'',$10,$11,$12,0,0,'','',0,$13 WHERE NOT EXISTS(SELECT 1 FROM nx_blob_orphans WHERE object_key=$4) ON CONFLICT(slot) DO NOTHING",&[
            m.binding.slot.as_str().into(),m.blob.as_str().into(),m.handle.as_str().into(),m.key.as_str().into(),m.binding.subject.as_str().into(),m.binding.context.as_str().into(),m.binding.input.as_str().into(),i64::from(anonymous).into(),number(m.reserved)?,row.filename.as_str().into(),row.created.unix_millis().into(),m.expires.unix_millis().into(),row.process.as_str().into()]).await?;
        ensure!(
            inserted == 1,
            "upload slot raced or object identity unavailable"
        );
        Ok(ReservationOutcome::Created(row))
    }
    /// Actual I/O completion is not publication authority by itself. Caller
    /// checks current request/worker/process ownership and treats unknown commit
    /// as unknown, never as an aborted stage or permission to release quota.
    pub(crate) async fn publish(
        &mut self,
        row: &BlobRow,
        object: DurableObject,
        now: Timestamp,
        store: &ObjectKey,
        guard: &IoGuard,
    ) -> Result<BlobRow> {
        guard.check()?;
        let transition =
            row.metadata
                .stage(row.metadata.generation, object, now, &row.metadata.binding)?;
        let next = &transition.next;
        ensure!(
            transition.quota_delta()
                == (
                    -i64::try_from(row.metadata.reserved)?,
                    i64::try_from(next.bytes)?,
                    0
                ),
            "upload quota transition mismatch"
        );
        let anonymous = i64::from(row.anonymous);
        let changed=self.execute(&format!("UPDATE nx_blob_store SET reserved_bytes=reserved_bytes-$2,used_bytes=used_bytes+$3,anonymous_reserved_bytes=anonymous_reserved_bytes-$2*$4,anonymous_used_bytes=anonymous_used_bytes+$3*$4,serial=serial+1 WHERE singleton=1 AND identity=$1 AND pair_state='paired' AND reserved_bytes>=$2 AND anonymous_reserved_bytes>=$2*$4 AND objects>0 AND serial<9223372036854775807 AND used_bytes<=9223372036854775807-$3 AND anonymous_used_bytes<=9223372036854775807-$3*$4 AND {}", counter_predicate(CounterTable::Store)),&[store.as_str().into(),number(row.metadata.reserved)?,number(next.bytes)?,anonymous.into()]).await?;
        ensure!(changed == 1, "blob app reservation mismatch");
        guard.check()?;
        let changed=self.execute(&format!("UPDATE nx_blob_subjects SET reserved_bytes=reserved_bytes-$2,used_bytes=used_bytes+$3 WHERE subject=$1 AND anonymous=$4 AND reserved_bytes>=$2 AND objects>0 AND used_bytes<=9223372036854775807-$3 AND {}", counter_predicate(CounterTable::Subject)),&[row.metadata.binding.subject.as_str().into(),number(row.metadata.reserved)?,number(next.bytes)?,anonymous.into()]).await?;
        ensure!(changed == 1, "blob subject reservation mismatch");
        guard.check()?;
        let changed=self.execute("UPDATE nx_blobs SET state='staged',generation=$2,reserved_bytes=0,actual_bytes=$3,sha256=$4,upload_handle=$5 WHERE slot=$1 AND state='uploading' AND generation=$6 AND owner_process=$7 AND expires_ms>$8 AND subject=$9 AND context=$10 AND input=$11",&[
            next.binding.slot.as_str().into(),next.generation.value().into(),number(next.bytes)?,hex(&next.digest.context("missing finalized digest")?).into(),next.handle.as_str().into(),transition.expected.value().into(),row.process.as_str().into(),now.unix_millis().into(),next.binding.subject.as_str().into(),next.binding.context.as_str().into(),next.binding.input.as_str().into()]).await?;
        ensure!(changed == 1, "upload publication fence rejected");
        guard.check()?;
        Ok(BlobRow {
            metadata: transition.next,
            ..row.clone()
        })
    }
    /// MUST run only after existing core receipt claim/recovery, in its SAME tx.
    /// SQL locks the actual current stage; the returned token cannot authorize a
    /// different nonce/session/form/field or stand in for current action policy.
    pub(crate) async fn lock_stage(
        &mut self,
        handle: &UploadHandle,
        binding: &UploadBinding,
        now: Timestamp,
    ) -> Result<LockedStage> {
        let columns = self.row_columns();
        let rows=self.fetch::<22>(&format!("UPDATE nx_blobs SET generation=generation WHERE upload_handle=$1 AND state='staged' AND slot=$2 AND subject=$3 AND context=$4 AND input=$5 AND expires_ms>$6 RETURNING {columns}"),&[
            handle.as_str().into(),binding.slot.as_str().into(),binding.subject.as_str().into(),binding.context.as_str().into(),binding.input.as_str().into(),now.unix_millis().into()]).await?;
        ensure!(
            rows.len() == 1,
            "upload handle is foreign, expired or already attached"
        );
        let row = BlobRow::parse(rows.into_iter().next().unwrap())?;
        Ok(LockedStage(row))
    }
    pub(crate) async fn associate(
        &mut self,
        locked: LockedStage,
        association: Association,
        now: Timestamp,
    ) -> Result<BlobRef> {
        let row = locked.0;
        let transition = row.metadata.attach(
            row.metadata.generation,
            now,
            &row.metadata.binding,
            &row.metadata.handle,
            association.clone(),
        )?;
        let changed=self.execute("UPDATE nx_blobs SET state='attached',generation=$2,owner_resource=$3,owner_id=$4,owner_incarnation=$5,owner_field=$6 WHERE slot=$1 AND state='staged' AND generation=$7 AND upload_handle=$8",&[
            row.metadata.binding.slot.as_str().into(),transition.next.generation.value().into(),association.resource.into(),association.id.into(),association.incarnation.into(),association.field.into(),transition.expected.value().into(),row.metadata.handle.as_str().into()]).await?;
        ensure!(changed == 1, "upload association fence rejected");
        Ok(row.metadata.blob)
    }
    /// Same resource deletion tx. No filesystem work or physical charge release.
    pub(crate) async fn detach_resource(
        &mut self,
        resource: i64,
        id: i64,
        incarnation: &str,
        expected: &std::collections::BTreeMap<String, BlobRef>,
    ) -> Result<()> {
        ensure!(
            resource > 0
                && id > 0
                && !incarnation.is_empty()
                && incarnation.len() <= 64
                && expected.len() <= 8,
            "invalid blob detachment scope"
        );
        let slot = self.tx.bounded_text("slot", 64);
        let field = self.tx.bounded_text("owner_field", 32);
        let reference = self.tx.bounded_text("blob_ref", 67);
        let generation = self.tx.bounded_text("CAST(generation AS TEXT)", 20);
        // Bound the selected keys BEFORE any UPDATE, including malformed owners
        // with extra associations. Returning fewer than expected also rejects.
        let limit = expected.len() + 1;
        let rows=self.fetch::<4>(&format!("SELECT {slot},{field},{reference},{generation} FROM nx_blobs WHERE state='attached' AND owner_resource=$1 AND owner_id=$2 AND owner_incarnation=$3 ORDER BY slot LIMIT {limit}"),&[resource.into(),id.into(),incarnation.into()]).await?;
        ensure!(
            rows.len() == expected.len(),
            "blob detachment association mismatch"
        );
        let mut seen = std::collections::BTreeSet::new();
        let mut params = vec![resource.into(), id.into(), incarnation.into()];
        let mut selected = Vec::new();
        for [slot, field, reference, generation] in rows {
            let slot = Commitment::parse(slot)?;
            let reference = BlobRef::parse(reference).map_err(anyhow::Error::msg)?;
            let generation = Generation::parse(integer(&generation)?)?;
            ensure!(
                generation.value() < i64::MAX
                    && seen.insert(field.clone())
                    && expected.get(&field) == Some(&reference),
                "foreign or exhausted blob association during deletion"
            );
            let first = params.len() + 1;
            params.push(slot.as_str().into());
            params.push(generation.value().into());
            selected.push(format!("(slot=${first} AND generation=${})", first + 1));
        }
        if selected.is_empty() {
            return Ok(());
        }
        let changed=self.execute(&format!("UPDATE nx_blobs SET state='unreferenced',generation=generation+1 WHERE state='attached' AND owner_resource=$1 AND owner_id=$2 AND owner_incarnation=$3 AND ({})",selected.join(" OR ")),&params).await?;
        ensure!(
            changed == expected.len() as u64,
            "blob detachment fence rejected"
        );
        Ok(())
    }
    /// Claim only an expired Staged or Unreferenced row. The returned pure claim
    /// is not dispatch authority until the enclosing transaction is ACKED.
    pub(crate) async fn claim_collectable(
        &mut self,
        row: &BlobRow,
        process: &ObjectKey,
        now: Timestamp,
    ) -> Result<(BlobRow, GcClaim)> {
        let (transition, claim) = row.metadata.claim(row.metadata.generation, now)?;
        let next = self.persist_claim(row, &transition, process, now).await?;
        Ok((next, claim))
    }
    /// A matching completed worker is mandatory for this process's Uploading
    /// rows. Prior-process recovery uses a separate exclusive-store fence path;
    /// an arbitrary process identifier must never substitute for that proof.
    pub(crate) async fn claim_stopped_upload(
        &mut self,
        row: &BlobRow,
        process: &ObjectKey,
        now: Timestamp,
        stopped: &crate::blob_io::StoppedIo,
    ) -> Result<(BlobRow, GcClaim)> {
        ensure!(&row.process == process, "foreign blob upload process");
        let (transition, claim) =
            row.metadata
                .claim_stopped_upload(row.metadata.generation, now, stopped)?;
        let next = self.persist_claim(row, &transition, process, now).await?;
        Ok((next, claim))
    }
    /// Persist only state-machine-generated claims. Caller must KNOW this claim
    /// committed before dispatching unlink; no commit proof is minted here.
    async fn persist_claim(
        &mut self,
        row: &BlobRow,
        transition: &Transition,
        process: &ObjectKey,
        now: Timestamp,
    ) -> Result<BlobRow> {
        ensure!(
            row.metadata.generation == transition.expected
                && row.metadata.key == transition.next.key,
            "foreign metadata transition"
        );
        ensure!(
            transition.next.state == State::Deleting,
            "invalid GC claim state"
        );
        let changed=self.execute("UPDATE nx_blobs SET state='deleting',generation=$2,claimed_ms=$3,owner_process=$4 WHERE slot=$1 AND state=$5 AND generation=$6 AND owner_process=$7",&[
            row.metadata.binding.slot.as_str().into(),transition.next.generation.value().into(),now.unix_millis().into(),process.as_str().into(),state(row.metadata.state).into(),transition.expected.value().into(),row.process.as_str().into()]).await?;
        ensure!(changed == 1, "blob GC claim fence rejected");
        Ok(BlobRow {
            metadata: transition.next.clone(),
            claimed: now,
            process: process.clone(),
            ..row.clone()
        })
    }
    /// Only after acknowledged directory-fsynced unlink under a committed GC
    /// claim. Unknown acknowledgement never authorizes another decrement.
    pub(crate) async fn deleted(
        &mut self,
        row: &BlobRow,
        claim: &GcClaim,
        store: &ObjectKey,
        now: Timestamp,
    ) -> Result<BlobRow> {
        let transition = row.metadata.deleted(claim)?;
        ensure!(
            transition.quota_delta()
                == (
                    -i64::try_from(row.metadata.reserved)?,
                    -i64::try_from(row.metadata.bytes)?,
                    -1
                ),
            "deletion quota transition mismatch"
        );
        let r = number(row.metadata.reserved)?;
        let u = number(row.metadata.bytes)?;
        let anonymous = i64::from(row.anonymous);
        let changed=self.execute(&format!("UPDATE nx_blob_store SET reserved_bytes=reserved_bytes-$2,used_bytes=used_bytes-$3,objects=objects-1,anonymous_reserved_bytes=anonymous_reserved_bytes-$2*$4,anonymous_used_bytes=anonymous_used_bytes-$3*$4,serial=serial+1 WHERE singleton=1 AND identity=$1 AND pair_state='paired' AND reserved_bytes>=$2 AND used_bytes>=$3 AND objects>0 AND anonymous_reserved_bytes>=$2*$4 AND anonymous_used_bytes>=$3*$4 AND serial<9223372036854775807 AND {}", counter_predicate(CounterTable::Store)),&[store.as_str().into(),r.clone(),u.clone(),anonymous.into()]).await?;
        ensure!(changed == 1, "blob deletion app counter mismatch");
        let changed=self.execute(&format!("UPDATE nx_blob_subjects SET reserved_bytes=reserved_bytes-$2,used_bytes=used_bytes-$3,objects=objects-1 WHERE subject=$1 AND anonymous=$4 AND reserved_bytes>=$2 AND used_bytes>=$3 AND objects>0 AND {}", counter_predicate(CounterTable::Subject)),&[row.metadata.binding.subject.as_str().into(),r,u,anonymous.into()]).await?;
        ensure!(changed == 1, "blob deletion subject counter mismatch");
        let changed=self.execute("UPDATE nx_blobs SET state='deleted',generation=$2,reserved_bytes=0,actual_bytes=0,claimed_ms=$3 WHERE slot=$1 AND state='deleting' AND generation=$4 AND owner_process=$5",&[row.metadata.binding.slot.as_str().into(),transition.next.generation.value().into(),now.unix_millis().into(),transition.expected.value().into(),row.process.as_str().into()]).await?;
        ensure!(changed == 1, "blob deletion fence rejected");
        self.execute(&format!("DELETE FROM nx_blob_subjects WHERE subject=$1 AND reserved_bytes=0 AND used_bytes=0 AND objects=0 AND {}", counter_predicate(CounterTable::Subject)),&[row.metadata.binding.subject.as_str().into()]).await?;
        Ok(BlobRow {
            metadata: transition.next,
            claimed: now,
            ..row.clone()
        })
    }
}

pub(crate) struct Reservation<'a> {
    pub(crate) binding: UploadBinding,
    pub(crate) filename: AttachmentName,
    pub(crate) limit: u64,
    pub(crate) now: Timestamp,
    pub(crate) policy: &'a BlobPolicy,
    pub(crate) capability: Option<AnonymousCapabilityQuota>,
    pub(crate) store: &'a ObjectKey,
    pub(crate) process: &'a ObjectKey,
}
pub(crate) enum ReservationOutcome {
    Created(BlobRow),
    Existing(BlobRow),
}
pub(crate) struct LockedStage(BlobRow);
impl LockedStage {
    pub(crate) fn blob(&self) -> &BlobRef {
        &self.0.metadata.blob
    }
    pub(crate) fn row(&self) -> &BlobRow {
        &self.0
    }
}
#[derive(Clone)]
pub(crate) struct BlobRow {
    pub(crate) metadata: Metadata,
    pub(crate) anonymous: bool,
    pub(crate) filename: AttachmentName,
    pub(crate) created: Timestamp,
    pub(crate) claimed: Timestamp,
    pub(crate) process: ObjectKey,
}
impl BlobRow {
    fn parse(row: [String; 22]) -> Result<Self> {
        let [
            slot,
            blob,
            handle,
            key,
            subject,
            context,
            input,
            anonymous,
            stored_state,
            generation,
            reserved,
            bytes,
            digest,
            filename,
            created,
            expires,
            resource,
            id,
            incarnation,
            field,
            claimed,
            process,
        ] = row;
        let state = match stored_state.as_str() {
            "uploading" => State::Uploading,
            "staged" => State::Staged,
            "attached" => State::Attached,
            "unreferenced" => State::Unreferenced,
            "deleting" => State::Deleting,
            "deleted" => State::Deleted,
            _ => anyhow::bail!("invalid blob state"),
        };
        let created = Timestamp::from_unix_millis(integer(&created)?)?;
        let expires = Timestamp::from_unix_millis(integer(&expires)?)?;
        ensure!(
            created.checked_add(Duration::from_millis(STAGE_LIFETIME_MILLIS)?)? == expires,
            "invalid upload lifetime"
        );
        let owner_resource = integer(&resource)?;
        let owner_id = integer(&id)?;
        let association =
            if owner_resource == 0 && owner_id == 0 && incarnation.is_empty() && field.is_empty() {
                None
            } else {
                ensure!(
                    owner_resource > 0
                        && owner_id > 0
                        && !incarnation.is_empty()
                        && incarnation.len() <= 64
                        && noxide_protocol::identifier(&field),
                    "invalid blob owner"
                );
                Some(Association {
                    resource: owner_resource,
                    id: owner_id,
                    incarnation,
                    field,
                })
            };
        if let Some(owner) = &association {
            owner.validate()?;
        }
        let reserved = unsigned(&reserved)?;
        let bytes = unsigned(&bytes)?;
        ensure!(
            reserved <= MAX_UPLOAD_BYTES && bytes <= MAX_UPLOAD_BYTES,
            "invalid stored blob size"
        );
        let digest = if digest.is_empty() {
            None
        } else {
            Some(hash(&digest)?)
        };
        let metadata = Metadata {
            blob: BlobRef::parse(blob).map_err(anyhow::Error::msg)?,
            handle: UploadHandle::parse(handle).map_err(anyhow::Error::msg)?,
            key: ObjectKey::parse(key)?,
            binding: UploadBinding {
                slot: Commitment::parse(slot)?,
                subject: Commitment::parse(subject)?,
                context: Commitment::parse(context)?,
                input: Commitment::parse(input)?,
            },
            state,
            generation: Generation::parse(integer(&generation)?)?,
            expires,
            reserved,
            bytes,
            digest,
            association,
        };
        match metadata.state {
            State::Uploading => ensure!(
                metadata.reserved > 0
                    && metadata.bytes == 0
                    && metadata.digest.is_none()
                    && metadata.association.is_none(),
                "invalid Uploading metadata"
            ),
            State::Staged => ensure!(
                metadata.reserved == 0
                    && metadata.digest.is_some()
                    && metadata.association.is_none(),
                "invalid Staged metadata"
            ),
            State::Attached | State::Unreferenced => ensure!(
                metadata.reserved == 0
                    && metadata.digest.is_some()
                    && metadata.association.is_some(),
                "invalid attached metadata"
            ),
            State::Deleting => ensure!(
                (metadata.reserved > 0
                    && metadata.bytes == 0
                    && metadata.digest.is_none()
                    && metadata.association.is_none())
                    || (metadata.reserved == 0 && metadata.digest.is_some()),
                "invalid deleting metadata"
            ),
            State::Deleted => ensure!(
                metadata.reserved == 0 && metadata.bytes == 0,
                "invalid deleted charge"
            ),
        }
        if metadata.state != State::Deleted {
            if let Some(digest) = metadata.digest {
                ensure!(
                    metadata.expected_handle(metadata.bytes, digest)? == metadata.handle,
                    "finalized handle does not match immutable object"
                );
            }
        }
        let name = AttachmentName::normalize(&filename)?;
        ensure!(name.as_str() == filename, "invalid stored filename");
        Ok(Self {
            metadata,
            anonymous: match anonymous.as_str() {
                "0" => false,
                "1" => true,
                _ => anyhow::bail!("invalid anonymous metadata"),
            },
            filename: name,
            created,
            claimed: Timestamp::from_unix_millis(integer(&claimed)?)?,
            process: ObjectKey::parse(process)?,
        })
    }
}
fn number(value: u64) -> Result<Param> {
    Ok(Param::Number(
        i64::try_from(value).context("blob integer overflow")?,
    ))
}
fn integer(value: &str) -> Result<i64> {
    let number = value.parse::<i64>().context("invalid blob integer")?;
    ensure!(
        number >= 0 && number.to_string() == value,
        "noncanonical blob integer"
    );
    Ok(number)
}
fn unsigned(value: &str) -> Result<u64> {
    Ok(u64::try_from(integer(value)?)?)
}
fn state(value: State) -> &'static str {
    match value {
        State::Uploading => "uploading",
        State::Staged => "staged",
        State::Attached => "attached",
        State::Unreferenced => "unreferenced",
        State::Deleting => "deleting",
        State::Deleted => "deleted",
    }
}
fn hex(value: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for byte in value {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 15) as usize] as char);
    }
    out
}
fn hash(value: &str) -> Result<[u8; 32]> {
    ensure!(value.len() == 64, "invalid blob digest");
    let mut out = [0; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let digit = |b: u8| -> Result<u8> {
            match b {
                b'0'..=b'9' => Ok(b - b'0'),
                b'a'..=b'f' => Ok(b - b'a' + 10),
                _ => anyhow::bail!("invalid blob digest"),
            }
        };
        out[index] = digit(pair[0])? * 16 + digit(pair[1])?;
    }
    Ok(out)
}

// SQLite affinity alone does not prove stored BIGINT values are integers.
// Reject malformed/REAL counters BEFORE arithmetic can silently coerce them.
// All identifiers here are static framework constants, never guest values.
enum CounterTable {
    Store,
    Subject,
}
fn counter_predicate(table: CounterTable) -> String {
    let (prefix, columns): (&str, &[&str]) = match table {
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
            format!(
                "CAST({prefix}.{column} AS TEXT)=CAST(CAST({prefix}.{column} AS BIGINT) AS TEXT)"
            )
        })
        .collect::<Vec<_>>()
        .join(" AND ")
}

// This is a transaction proposal, never a commit acknowledgement or Ready token.
pub(crate) struct PairPreparation {
    pub(crate) record: PairRecord,
    pub(crate) step: PairStep,
    pub(crate) pending_inserted: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    fn staged_values() -> [String; 22] {
        let binding = UploadBinding {
            slot: Commitment::parse("a".repeat(64)).unwrap(),
            subject: Commitment::parse("b".repeat(64)).unwrap(),
            context: Commitment::parse("c".repeat(64)).unwrap(),
            input: Commitment::parse("d".repeat(64)).unwrap(),
        };
        let metadata = Metadata {
            blob: BlobRef::parse(format!("b1_{}", "e".repeat(64))).unwrap(),
            handle: UploadHandle::parse(format!("u1_{}", "f".repeat(64))).unwrap(),
            key: ObjectKey::parse("1".repeat(64)).unwrap(),
            binding,
            state: State::Staged,
            generation: Generation::parse(2).unwrap(),
            expires: Timestamp::from_unix_millis(901000).unwrap(),
            reserved: 0,
            bytes: 3,
            digest: Some([2; 32]),
            association: None,
        };
        let handle = metadata.expected_handle(3, [2; 32]).unwrap();
        [
            metadata.binding.slot.as_str().into(),
            metadata.blob.as_str().into(),
            handle.as_str().into(),
            metadata.key.as_str().into(),
            metadata.binding.subject.as_str().into(),
            metadata.binding.context.as_str().into(),
            metadata.binding.input.as_str().into(),
            "0".into(),
            "staged".into(),
            "2".into(),
            "0".into(),
            "3".into(),
            hex(&[2; 32]),
            "report.html".into(),
            "1000".into(),
            "901000".into(),
            "0".into(),
            "0".into(),
            "".into(),
            "".into(),
            "0".into(),
            "3".repeat(64),
        ]
    }
    #[test]
    fn stored_row_requires_canonical_finalized_identity_and_fixed_expiry() {
        let valid = staged_values();
        let row = BlobRow::parse(valid.clone()).unwrap();
        assert_eq!(row.metadata.bytes, 3);
        assert_eq!(row.metadata.state, State::Staged);
        assert_eq!(row.filename.as_str(), "report.html");
        for (column, value) in [
            (0, "9".repeat(64)),
            (1, format!("b1_{}", "9".repeat(64))),
            (2, format!("u1_{}", "9".repeat(64))),
            (3, "9".repeat(64)),
            (12, "9".repeat(64)),
            (15, "901001".into()),
            (14, "-1".into()),
            (13, "../report.html".into()),
            (21, "x".repeat(64)),
            (7, "2".into()),
        ] {
            let mut bad = valid.clone();
            bad[column] = value;
            assert!(BlobRow::parse(bad).is_err(), "column {column}");
        }
    }
    #[test]
    fn stored_state_and_association_shapes_fail_closed() {
        let valid = staged_values();
        for (column, value) in [
            (8, "uploading"),
            (8, "attached"),
            (8, "unreferenced"),
            (8, "deleted"),
            (8, "unknown"),
            (9, "0"),
            (9, "0002"),
            (10, "1"),
            (11, "10485761"),
            (16, "1"),
            (17, "1"),
            (18, "incarnation"),
            (19, "attachment"),
        ] {
            let mut bad = valid.clone();
            bad[column] = value.into();
            assert!(BlobRow::parse(bad).is_err(), "column {column}={value}");
        }
        let mut attached = valid.clone();
        attached[8] = "attached".into();
        attached[16] = "1".into();
        attached[17] = "2".into();
        attached[18] = "incarnation".into();
        attached[19] = "attachment".into();
        BlobRow::parse(attached.clone()).unwrap();
        attached[18] = "bad\nincarnation".into();
        assert!(BlobRow::parse(attached).is_err());
    }
    #[test]
    fn provider_integer_and_digest_decoders_do_not_coerce_or_wrap() {
        for bad in ["-1", "+1", "01", "1.0", "1e3", "9223372036854775808", ""] {
            assert!(integer(bad).is_err());
        }
        assert_eq!(integer("9223372036854775807").unwrap(), i64::MAX);
        assert_eq!(integer("0").unwrap(), 0);
        assert_eq!(hash(&hex(&[0xab; 32])).unwrap(), [0xab; 32]);
        for bad in [
            "A".repeat(64),
            "0".repeat(63),
            "0".repeat(65),
            "x".repeat(64),
        ] {
            assert!(hash(&bad).is_err());
        }
    }
}

impl MetadataContext<'_> {
    /// Caller retains this process's exclusive store lease. A prior process can
    /// no longer have a file descriptor or native worker on that store.
    pub(crate) async fn recover_prior_upload(
        &mut self,
        row: &BlobRow,
        fence: &crate::blob_store::ProcessFence,
        now: Timestamp,
    ) -> Result<(BlobRow, GcClaim)> {
        let process = fence.process();
        let paired = self.fetch::<1>("SELECT identity FROM nx_blob_store WHERE singleton=1 AND identity=$1 AND pair_state='paired'", &[fence.store().as_str().into()]).await?;
        ensure!(
            paired.len() == 1,
            "blob process fence belongs to another store"
        );
        ensure!(
            &row.process != process,
            "live process upload cannot be abandoned"
        );
        let (transition, claim) = row.metadata.recover_prior_upload()?;
        let next = self.persist_claim(row, &transition, process, now).await?;
        Ok((next, claim))
    }
    pub(crate) async fn resume_deletion(
        &mut self,
        row: &BlobRow,
        fence: &crate::blob_store::ProcessFence,
        now: Timestamp,
        stopped: Option<&crate::blob_io::StoppedIo>,
    ) -> Result<(BlobRow, GcClaim)> {
        let process = fence.process();
        let paired = self.fetch::<1>("SELECT identity FROM nx_blob_store WHERE singleton=1 AND identity=$1 AND pair_state='paired'", &[fence.store().as_str().into()]).await?;
        ensure!(
            paired.len() == 1,
            "blob process fence belongs to another store"
        );
        ensure!(
            &row.process != process
                || stopped
                    .is_some_and(|s| s.key() == &row.metadata.key
                        && s.generation() == row.metadata.generation),
            "deletion worker may still be running"
        );
        let (transition, claim) = row.metadata.resume_deletion()?;
        let next = self.persist_claim(row, &transition, process, now).await?;
        Ok((next, claim))
    }
    pub(crate) async fn quarantine_unknown(
        &mut self,
        key: &ObjectKey,
        bytes: u64,
        paths: u8,
        store: &ObjectKey,
        process: &ObjectKey,
        now: Timestamp,
    ) -> Result<()> {
        ensure!((1..=2).contains(&paths), "invalid orphan evidence");
        let inserted = self.execute("INSERT INTO nx_blob_orphans(object_key,generation,state,first_seen_ms,claimed_ms,charged_bytes,charged_objects,owner_process) SELECT $1,1,'observed',$2,0,$3,$4,$5 WHERE NOT EXISTS(SELECT 1 FROM nx_blobs WHERE object_key=$1) ON CONFLICT(object_key) DO NOTHING", &[key.as_str().into(), now.unix_millis().into(), number(bytes)?, i64::from(paths).into(), process.as_str().into()]).await?;
        if inserted == 1 {
            let changed = self.execute("UPDATE nx_blob_store SET used_bytes=used_bytes+$2,objects=objects+$3,serial=serial+1 WHERE singleton=1 AND identity=$1 AND pair_state='paired' AND used_bytes<=9223372036854775807-$2 AND objects<=9223372036854775807-$3 AND serial<9223372036854775807", &[store.as_str().into(), number(bytes)?, i64::from(paths).into()]).await?;
            ensure!(changed == 1, "orphan quota accounting overflow");
        }
        Ok(())
    }
}
