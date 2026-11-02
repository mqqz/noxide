//! Outbox captures, endpoint grants, secrets and the delivery queue.
use super::Statement;
use crate::{
    database::{Transaction, sql},
    query_plan::NativeProvider,
};
use anyhow::Result;
use noxide_protocol::effects::MAX_CAPTURE_BYTES;

fn lock_on_postgres(tx: &Transaction, lock: &'static str) -> Result<&'static str> {
    Ok(match tx.query_provider()? {
        NativeProvider::Postgres => lock,
        NativeProvider::Sqlite => "",
    })
}

pub fn locked_runtime(tx: &Transaction) -> Result<Statement<0, 4>> {
    let suffix = lock_on_postgres(tx, " FOR SHARE")?;
    Ok(Statement::built(sql!(
        "SELECT deployment,contract,epoch,state FROM nx_job_runtime WHERE singleton=1 AND EXISTS(SELECT 1 FROM nx_deployment WHERE singleton=1 AND generation=nx_job_runtime.deployment){suffix}"
    )))
}

pub fn locked_grant(tx: &Transaction) -> Result<Statement<3, 5>> {
    let suffix = lock_on_postgres(tx, " FOR SHARE")?;
    let declaration = tx.bounded_text("declaration", 16384);
    Ok(Statement::built(sql!(
        "SELECT {declaration},state,CAST(version AS TEXT),contract,epoch FROM nx_effect_grants WHERE deployment=$1 AND tenant=$2 AND endpoint=$3{suffix}"
    )))
}

pub fn locked_secret(tx: &Transaction) -> Result<Statement<2, 4>> {
    let suffix = lock_on_postgres(tx, " FOR SHARE")?;
    Ok(Statement::built(sql!(
        "SELECT CAST(version AS TEXT),state,contract,epoch FROM nx_effect_secrets WHERE deployment=$1 AND slot=$2{suffix}"
    )))
}

pub fn next_claimable(tx: &Transaction) -> Result<Statement<5, 4>> {
    let suffix = lock_on_postgres(tx, " FOR UPDATE OF o SKIP LOCKED")?;
    Ok(Statement::built(sql!(
        "SELECT o.id,o.tenant,CAST(o.fence AS TEXT),CAST(o.attempts AS TEXT) FROM nx_outbox o JOIN nx_effect_tenants t ON t.deployment=o.deployment AND t.tenant=o.tenant WHERE o.deployment=$1 AND ((o.state='pending' AND o.eligible_ms<=$2) OR (o.state='running' AND o.lease_until_ms<=$2)) AND o.id<>$3 AND o.id<>$4 AND $5<(SELECT concurrency FROM nx_effect_queue WHERE singleton=1) ORDER BY t.claim_seq,o.eligible_ms,o.id LIMIT 1{suffix}"
    )))
}

pub fn claimed_capture(tx: &Transaction) -> Statement<4, 15> {
    let payload = tx.bounded_text("payload", MAX_CAPTURE_BYTES);
    Statement::built(sql!(
        "SELECT {payload},payload_digest,state,CAST(attempts AS TEXT),CAST(first_eligible_ms AS TEXT),CAST(eligible_ms AS TEXT),contract,epoch,CAST(grant_version AS TEXT),CAST(secret_version AS TEXT),CAST(lease_until_ms AS TEXT),origin,CAST(ordinal AS TEXT),endpoint,CAST(fence AS TEXT) FROM nx_outbox WHERE id=$1 AND deployment=$2 AND tenant=$3 AND fence=$4"
    ))
}

pub fn capture_payload(tx: &Transaction) -> Statement<1, 2> {
    let payload = tx.bounded_text("payload", MAX_CAPTURE_BYTES);
    Statement::built(sql!(
        "SELECT {payload},payload_digest FROM nx_outbox WHERE id=$1"
    ))
}

pub const LOCK_QUEUE: Statement<0, 0> =
    Statement::new("UPDATE nx_effect_queue SET claim_seq=claim_seq WHERE singleton=1");
pub const CAPTURE_DIGEST: Statement<1, 1> =
    Statement::new("SELECT payload_digest FROM nx_outbox WHERE id=$1");
pub const ACTIVE_COUNTS: Statement<1, 4> = Statement::new(
    "SELECT CAST(COUNT(*) AS TEXT),CAST(COALESCE(SUM(CASE WHEN tenant=$1 THEN 1 ELSE 0 END),0) AS TEXT),CAST((SELECT pending_limit FROM nx_effect_queue WHERE singleton=1) AS TEXT),CAST((SELECT tenant_limit FROM nx_effect_queue WHERE singleton=1) AS TEXT) FROM (SELECT tenant FROM nx_outbox WHERE state IN ('pending','running','paused') LIMIT 1001) AS active_effects",
);
pub const ENSURE_TENANT: Statement<2, 0> = Statement::new(
    "INSERT INTO nx_effect_tenants(deployment,tenant,claim_seq) VALUES($1,$2,0) ON CONFLICT(deployment,tenant) DO NOTHING",
);
pub const INSERT_CAPTURE: Statement<13, 0> = Statement::new(
    "INSERT INTO nx_outbox(id,deployment,tenant,origin,ordinal,endpoint,contract,epoch,grant_version,secret_version,payload,payload_digest,eligible_ms,first_eligible_ms,attempts,fence,lease_until_ms,round,state,reason) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$13,0,0,0,0,'pending','')",
);
pub const QUEUE_FOR_OWNER: Statement<1, 1> = Statement::new(
    "SELECT CAST(singleton AS TEXT) FROM nx_effect_queue WHERE singleton=1 AND owner_directory=$1",
);
pub const ADVANCE_CLAIM_SEQUENCE: Statement<1, 0> = Statement::new(
    "UPDATE nx_effect_queue SET claim_seq=claim_seq+1 WHERE singleton=1 AND owner_directory=$1 AND claim_seq<9223372036854775807",
);
pub const CLAIM_CAPTURE: Statement<5, 0> = Statement::new(
    "UPDATE nx_outbox SET state='running',fence=$1,lease_until_ms=$2,attempts=CASE WHEN attempts<5 THEN attempts+1 ELSE attempts END WHERE id=$3 AND deployment=$4 AND fence=$5",
);
pub const RECORD_TENANT_CLAIM: Statement<2, 0> = Statement::new(
    "UPDATE nx_effect_tenants SET claim_seq=(SELECT claim_seq FROM nx_effect_queue WHERE singleton=1) WHERE deployment=$1 AND tenant=$2",
);
pub const LOCK_FENCE: Statement<4, 0> = Statement::new(
    "UPDATE nx_outbox SET fence=fence WHERE id=$1 AND deployment=$2 AND tenant=$3 AND fence=$4",
);
pub const FINISH_RUNNING: Statement<7, 0> = Statement::new(
    "UPDATE nx_outbox SET state=$1,reason=$2,eligible_ms=$3,lease_until_ms=0 WHERE id=$4 AND deployment=$5 AND tenant=$6 AND state='running' AND fence=$7",
);
pub const RELEASE_AFTER_PREFLIGHT: Statement<5, 0> = Statement::new(
    "UPDATE nx_outbox SET state='pending',reason='preflight_unavailable',lease_until_ms=0,attempts=attempts-$1 WHERE id=$2 AND deployment=$3 AND tenant=$4 AND state='running' AND fence=$5",
);
pub const MARK_DELIVERED: Statement<6, 0> = Statement::new(
    "UPDATE nx_outbox SET state='delivered',reason='',lease_until_ms=0,eligible_ms=$1 WHERE id=$2 AND deployment=$3 AND tenant=$4 AND fence=$5 AND epoch=$6",
);
pub const RUNTIME_FOR_DEPLOYMENT: Statement<1, 3> = Statement::new(
    "SELECT contract,epoch,state FROM nx_job_runtime WHERE singleton=1 AND deployment=$1 AND EXISTS(SELECT 1 FROM nx_deployment WHERE singleton=1 AND generation=$1)",
);
pub const QUEUE_OWNER: Statement<0, 2> =
    Statement::new("SELECT store_id,owner_directory FROM nx_effect_queue WHERE singleton=1");
pub const INSERT_QUEUE: Statement<5, 0> = Statement::new(
    "INSERT INTO nx_effect_queue(singleton,claim_seq,store_id,owner_directory,pending_limit,tenant_limit,concurrency) VALUES(1,0,$1,$2,$3,$4,$5)",
);
pub const SET_QUEUE_OWNER: Statement<2, 0> =
    Statement::new("UPDATE nx_effect_queue SET store_id=$1,owner_directory=$2 WHERE singleton=1");
pub const SET_QUEUE_LIMITS: Statement<3, 0> = Statement::new(
    "UPDATE nx_effect_queue SET pending_limit=$1,tenant_limit=$2,concurrency=$3 WHERE singleton=1",
);
pub const SECRET: Statement<2, 3> = Statement::new(
    "SELECT CAST(version AS TEXT),contract,epoch FROM nx_effect_secrets WHERE deployment=$1 AND slot=$2",
);
pub const UPSERT_SECRET: Statement<6, 0> = Statement::new(
    "INSERT INTO nx_effect_secrets(deployment,slot,version,contract,epoch,state) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(deployment,slot) DO UPDATE SET version=$3,contract=$4,epoch=$5,state=$6",
);
pub const GRANT: Statement<3, 4> = Statement::new(
    "SELECT CAST(version AS TEXT),contract,epoch,declaration FROM nx_effect_grants WHERE deployment=$1 AND tenant=$2 AND endpoint=$3",
);
pub const UPSERT_GRANT: Statement<8, 0> = Statement::new(
    "INSERT INTO nx_effect_grants(deployment,tenant,endpoint,version,contract,epoch,state,declaration) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(deployment,tenant,endpoint) DO UPDATE SET version=$4,contract=$5,epoch=$6,state=$7,declaration=$8",
);
pub const LOCK_RUNTIME: Statement<1, 0> = Statement::new(
    "UPDATE nx_job_runtime SET state=state WHERE singleton=1 AND deployment=$1 AND EXISTS(SELECT 1 FROM nx_deployment WHERE singleton=1 AND generation=$1)",
);
pub const RUNTIME_CONTRACT: Statement<0, 2> =
    Statement::new("SELECT contract,epoch FROM nx_job_runtime WHERE singleton=1");
pub const LIST_CAPTURES: Statement<1, 8> = Statement::new(
    "SELECT id,deployment,tenant,endpoint,state,CAST(attempts AS TEXT),CAST(round AS TEXT),CAST(eligible_ms AS TEXT) FROM nx_outbox WHERE id>$1 ORDER BY id LIMIT 100",
);
pub const CANCEL_CAPTURE: Statement<1, 0> = Statement::new(
    "UPDATE nx_outbox SET state='cancelled',reason='operator_cancelled',lease_until_ms=0 WHERE id=$1 AND state IN ('pending','running','paused','dead')",
);
pub const REVOKE_GRANT: Statement<3, 0> = Statement::new(
    "UPDATE nx_effect_grants SET state='revoked',version=version+1 WHERE deployment=$1 AND tenant=$2 AND endpoint=$3 AND version<9223372036854775807",
);
pub const PAUSE_REVOKED_ENDPOINT: Statement<2, 0> = Statement::new(
    "UPDATE nx_outbox SET state='paused',reason='endpoint_revoked',lease_until_ms=0 WHERE tenant=$1 AND endpoint=$2 AND state IN ('pending','running')",
);
pub const REVOKE_SECRET: Statement<2, 0> = Statement::new(
    "UPDATE nx_effect_secrets SET state='revoked',version=version+1 WHERE deployment=$1 AND slot=$2 AND version<9223372036854775807",
);
pub const DEPLOYMENT_GRANTS: Statement<1, 3> = Statement::new(
    "SELECT tenant,endpoint,declaration FROM nx_effect_grants WHERE deployment=$1 ORDER BY tenant,endpoint LIMIT 65",
);
pub const PAUSE_ENDPOINT: Statement<3, 0> = Statement::new(
    "UPDATE nx_outbox SET state='paused',reason=$1,lease_until_ms=0 WHERE tenant=$2 AND endpoint=$3 AND state IN ('pending','running')",
);
pub const ACTIVATE_GRANT: Statement<6, 0> = Statement::new(
    "UPDATE nx_effect_grants SET state='active',version=version+1,contract=$1,epoch=$2 WHERE deployment=$3 AND tenant=$4 AND endpoint=$5 AND declaration=$6 AND version<9223372036854775807",
);
pub const PAUSE_CHANGED_ENDPOINT: Statement<2, 0> = Statement::new(
    "UPDATE nx_outbox SET state='paused',reason='grant_changed',lease_until_ms=0 WHERE tenant=$1 AND endpoint=$2 AND state IN ('pending','running')",
);
pub const ACTIVATE_RUNTIME: Statement<0, 0> =
    Statement::new("UPDATE nx_job_runtime SET state='active' WHERE singleton=1");
pub const ACTIVATE_SECRET: Statement<4, 0> = Statement::new(
    "UPDATE nx_effect_secrets SET state='active',version=version+1,contract=$1,epoch=$2 WHERE deployment=$3 AND slot=$4 AND version<9223372036854775807",
);
pub const CAPTURE_RETRY_STATE: Statement<1, 4> = Statement::new(
    "SELECT state,CAST(attempts AS TEXT),CAST(first_eligible_ms AS TEXT),CAST(round AS TEXT) FROM nx_outbox WHERE id=$1",
);
pub const RESCHEDULE_CAPTURE: Statement<10, 0> = Statement::new(
    "UPDATE nx_outbox SET deployment=$1,contract=$2,epoch=$3,grant_version=$4,secret_version=$5,state='pending',reason='',eligible_ms=$6,first_eligible_ms=$7,attempts=$8,lease_until_ms=0,round=$9,fence=fence+1 WHERE id=$10 AND fence<9223372036854775807",
);
