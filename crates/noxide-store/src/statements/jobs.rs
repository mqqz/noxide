//! Job queue, grants, recurring schedules and the job runtime.
use super::Statement;
use crate::{
    database::{Transaction, sql},
    query_plan::NativeProvider,
};
use anyhow::Result;
use noxide_protocol::{MAX_RESULT_BYTES, jobs::MAX_JOB_BYTES};

fn share_lock(tx: &Transaction) -> Result<&'static str> {
    Ok(match tx.query_provider()? {
        NativeProvider::Postgres => " FOR SHARE",
        NativeProvider::Sqlite => "",
    })
}

pub fn runtime_snapshot(tx: &Transaction) -> Result<Statement<0, 7>> {
    let lock = share_lock(tx)?;
    Ok(Statement::built(sql!(
        "SELECT deployment,contract,epoch,state,CAST(pending_limit AS TEXT),CAST(tenant_limit AS TEXT),CAST(concurrency AS TEXT) FROM nx_job_runtime WHERE singleton=1 AND EXISTS(SELECT 1 FROM nx_deployment WHERE singleton=1 AND generation=nx_job_runtime.deployment){lock}"
    )))
}

pub fn locked_grant(tx: &Transaction) -> Result<Statement<3, 5>> {
    let payload = tx.bounded_text("declaration", MAX_JOB_BYTES);
    let lock = share_lock(tx)?;
    Ok(Statement::built(sql!(
        "SELECT {payload},state,CAST(version AS TEXT),contract,epoch FROM nx_job_grants WHERE deployment=$1 AND tenant=$2 AND worker=$3{lock}"
    )))
}

pub fn claimed_job(tx: &Transaction) -> Statement<3, 17> {
    let payload = tx.bounded_text("payload", MAX_JOB_BYTES);
    Statement::built(sql!(
        "SELECT {payload},payload_digest,state,CAST(attempts AS TEXT),CAST(first_eligible_ms AS TEXT),CAST(fence AS TEXT),CAST(lease_until_ms AS TEXT),contract,epoch,worker,CAST(action AS TEXT),CAST(grant_version AS TEXT),CAST(due_ms AS TEXT),CAST(eligible_ms AS TEXT),origin,CAST(ordinal AS TEXT),COALESCE(reconciled_from,'') FROM nx_jobs WHERE id=$1 AND deployment=$2 AND tenant=$3"
    ))
}

pub fn job_receipt(tx: &Transaction) -> Statement<1, 5> {
    let outcome = tx.bounded_text("outcome", MAX_RESULT_BYTES);
    Statement::built(sql!(
        "SELECT subject,contract,CAST(action AS TEXT),input,{outcome} FROM nx_receipts WHERE nonce=$1"
    ))
}

pub fn next_claimable(tx: &Transaction) -> Result<Statement<3, 5>> {
    let lock = match tx.query_provider()? {
        NativeProvider::Postgres => " FOR UPDATE OF j SKIP LOCKED",
        NativeProvider::Sqlite => "",
    };
    Ok(Statement::built(sql!(
        "SELECT j.id,j.tenant,CAST(j.fence AS TEXT),CAST(j.attempts AS TEXT),j.state FROM nx_jobs j JOIN nx_job_tenants t ON t.deployment=j.deployment AND t.tenant=j.tenant WHERE j.deployment=$1 AND ((j.state='running' AND j.lease_until_ms<=$2) OR (j.state='pending' AND j.eligible_ms<=$2 AND $3=1)) ORDER BY t.claim_seq,j.eligible_ms,j.id LIMIT 1{lock}"
    )))
}

pub fn recurring_schedule(tx: &Transaction) -> Statement<3, 9> {
    let cursor = tx.bounded_text("cursor", 4096);
    Statement::built(sql!(
        "SELECT contract,epoch,CAST(grant_version AS TEXT),CAST(version AS TEXT),state,CAST(next_ms AS TEXT),CAST(cutoff_ms AS TEXT),CAST(cutoff_seq AS TEXT),{cursor} FROM nx_job_recurring WHERE deployment=$1 AND tenant=$2 AND name=$3"
    ))
}

pub fn reconciliation_job(tx: &Transaction) -> Statement<1, 3> {
    let payload = tx.bounded_text("payload", MAX_JOB_BYTES);
    Statement::built(sql!(
        "SELECT {payload},payload_digest,state FROM nx_jobs WHERE id=$1"
    ))
}

pub const LOCK_JOB_FENCE: Statement<4, 0> = Statement::new(
    "UPDATE nx_jobs SET fence=fence WHERE id=$1 AND deployment=$2 AND tenant=$3 AND fence=$4",
);
pub const FINISH_RUNNING_JOB: Statement<7, 0> = Statement::new(
    "UPDATE nx_jobs SET state=$1,reason=$2,eligible_ms=$3,lease_until_ms=0 WHERE id=$4 AND deployment=$5 AND tenant=$6 AND state='running' AND fence=$7",
);
pub const LOCK_QUEUE: Statement<0, 0> =
    Statement::new("UPDATE nx_job_queue SET claim_seq=claim_seq WHERE singleton=1");
pub const JOB_PAYLOAD_DIGEST: Statement<1, 1> =
    Statement::new("SELECT payload_digest FROM nx_jobs WHERE id=$1");
pub const ACTIVE_JOB_COUNTS: Statement<1, 2> = Statement::new(
    "SELECT CAST(COUNT(*) AS TEXT),CAST(COALESCE(SUM(CASE WHEN tenant=$1 THEN 1 ELSE 0 END),0) AS TEXT) FROM (SELECT tenant FROM nx_jobs WHERE state IN ('pending','running','paused') LIMIT 1001) AS active_jobs",
);
pub const ENSURE_TENANT: Statement<2, 0> = Statement::new(
    "INSERT INTO nx_job_tenants(deployment,tenant,claim_seq) VALUES($1,$2,0) ON CONFLICT(deployment,tenant) DO NOTHING",
);
pub const INSERT_JOB: Statement<15, 0> = Statement::new(
    "INSERT INTO nx_jobs(id,deployment,tenant,origin,ordinal,worker,action,contract,epoch,grant_version,payload,payload_digest,due_ms,eligible_ms,first_eligible_ms,attempts,fence,lease_until_ms,state,reason,reconciled_from) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$14,0,0,0,'pending','',NULLIF($15,''))",
);
pub const ADVANCE_CLAIM_SEQUENCE: Statement<1, 0> = Statement::new(
    "UPDATE nx_job_queue SET claim_seq=claim_seq+1 WHERE singleton=1 AND claim_seq<9223372036854775807 AND EXISTS(SELECT 1 FROM nx_job_runtime WHERE singleton=1 AND deployment=$1 AND state='active' AND EXISTS(SELECT 1 FROM nx_deployment WHERE singleton=1 AND generation=nx_job_runtime.deployment))",
);
pub const RUNNING_JOB_COUNT: Statement<0, 1> = Statement::new(
    "SELECT CAST(COUNT(*) AS TEXT) FROM (SELECT id FROM nx_jobs WHERE state='running' LIMIT 3) AS running_jobs",
);
pub const CLAIM_JOB: Statement<7, 0> = Statement::new(
    "UPDATE nx_jobs SET state='running',fence=$1,lease_until_ms=$2,attempts=$3 WHERE id=$4 AND deployment=$5 AND fence=$6 AND state=$7",
);
pub const RECORD_TENANT_CLAIM: Statement<2, 0> = Statement::new(
    "UPDATE nx_job_tenants SET claim_seq=(SELECT claim_seq FROM nx_job_queue WHERE singleton=1) WHERE deployment=$1 AND tenant=$2",
);
pub const LOCK_RECURRING: Statement<3, 0> = Statement::new(
    "UPDATE nx_job_recurring SET version=version WHERE deployment=$1 AND tenant=$2 AND name=$3",
);
pub const PAUSE_RECURRING: Statement<3, 0> = Statement::new(
    "UPDATE nx_job_recurring SET state='paused' WHERE deployment=$1 AND tenant=$2 AND name=$3",
);
pub const CREATION_COUNTER: Statement<0, 1> =
    Statement::new("SELECT CAST(value AS TEXT) FROM nx_creation_counter WHERE singleton=1");
pub const OCCURRENCE_JOB: Statement<4, 1> = Statement::new(
    "SELECT job FROM nx_job_occurrences WHERE deployment=$1 AND tenant=$2 AND schedule=$3 AND occurrence=$4",
);
pub const INSERT_OCCURRENCE: Statement<5, 0> = Statement::new(
    "INSERT INTO nx_job_occurrences(deployment,tenant,schedule,occurrence,job) VALUES($1,$2,$3,$4,$5)",
);
pub const ADVANCE_RECURRING_CURSOR: Statement<8, 0> = Statement::new(
    "UPDATE nx_job_recurring SET version=version+1,next_ms=$1,cutoff_ms=$2,cutoff_seq=$3,cursor=$4 WHERE deployment=$5 AND tenant=$6 AND name=$7 AND version=$8 AND state='active' AND version<9223372036854775807",
);
pub const ADVANCE_RECURRING_DUE: Statement<8, 0> = Statement::new(
    "UPDATE nx_job_recurring SET version=version+1,next_ms=$1 WHERE deployment=$2 AND tenant=$3 AND name=$4 AND version=$5 AND state='active' AND version<9223372036854775807 AND cutoff_ms=$6 AND cutoff_seq=$7 AND cursor=$8",
);
pub const LOCK_RUNTIME_FOR_DEPLOYMENT: Statement<1, 0> = Statement::new(
    "UPDATE nx_job_runtime SET state=state WHERE singleton=1 AND deployment=$1 AND EXISTS(SELECT 1 FROM nx_deployment WHERE singleton=1 AND generation=$1)",
);
pub const RUNTIME_STATE: Statement<0, 3> =
    Statement::new("SELECT contract,epoch,state FROM nx_job_runtime WHERE singleton=1");
pub const INSERT_RUNTIME: Statement<7, 0> = Statement::new(
    "INSERT INTO nx_job_runtime(singleton,deployment,contract,epoch,state,pending_limit,tenant_limit,concurrency) VALUES(1,$1,$2,$3,$4,$5,$6,$7) ON CONFLICT(singleton) DO NOTHING",
);
pub const LOCK_RUNTIME: Statement<0, 0> =
    Statement::new("UPDATE nx_job_runtime SET state=state WHERE singleton=1");
pub const RUNTIME: Statement<0, 7> = Statement::new(
    "SELECT deployment,contract,epoch,state,CAST(pending_limit AS TEXT),CAST(tenant_limit AS TEXT),CAST(concurrency AS TEXT) FROM nx_job_runtime WHERE singleton=1",
);
pub const PAUSE_ALL_JOBS: Statement<0, 0> = Statement::new(
    "UPDATE nx_jobs SET state='paused',reason='approval_changed',lease_until_ms=0 WHERE state IN ('pending','running')",
);
pub const PAUSE_ALL_RECURRING: Statement<0, 0> =
    Statement::new("UPDATE nx_job_recurring SET state='paused' WHERE state='active'");
pub const REVOKE_ALL_GRANTS: Statement<0, 0> =
    Statement::new("UPDATE nx_job_grants SET state='revoked' WHERE state='active'");
pub const UPDATE_RUNTIME: Statement<7, 0> = Statement::new(
    "UPDATE nx_job_runtime SET deployment=$1,contract=$2,epoch=$3,state=$4,pending_limit=$5,tenant_limit=$6,concurrency=$7 WHERE singleton=1",
);
pub const ENSURE_QUEUE: Statement<0, 0> = Statement::new(
    "INSERT INTO nx_job_queue(singleton,claim_seq) VALUES(1,0) ON CONFLICT(singleton) DO NOTHING",
);
pub const GRANT: Statement<3, 3> = Statement::new(
    "SELECT CAST(version AS TEXT),declaration,state FROM nx_job_grants WHERE deployment=$1 AND tenant=$2 AND worker=$3",
);
pub const UPSERT_GRANT: Statement<8, 0> = Statement::new(
    "INSERT INTO nx_job_grants(deployment,tenant,worker,version,contract,epoch,state,declaration) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(deployment,tenant,worker) DO UPDATE SET version=$4,contract=$5,epoch=$6,state=$7,declaration=$8",
);
pub const UPSERT_RECURRING_WITH_STATE: Statement<7, 0> = Statement::new(
    "INSERT INTO nx_job_recurring(deployment,tenant,name,contract,epoch,grant_version,version,state,next_ms,cutoff_ms,cutoff_seq,cursor) VALUES($1,$2,$3,$4,$5,$6,1,$7,0,0,0,'') ON CONFLICT(deployment,tenant,name) DO UPDATE SET contract=$4,epoch=$5,grant_version=$6,version=nx_job_recurring.version+1,state=$7,next_ms=0,cutoff_ms=0,cutoff_seq=0,cursor=''",
);
pub const REVOKE_GRANT: Statement<3, 0> = Statement::new(
    "UPDATE nx_job_grants SET state='revoked' WHERE deployment=$1 AND tenant=$2 AND worker=$3",
);
pub const PAUSE_WORKER_JOBS_REVOKED: Statement<3, 0> = Statement::new(
    "UPDATE nx_jobs SET state='paused',reason='grant_revoked',lease_until_ms=0 WHERE deployment=$1 AND tenant=$2 AND worker=$3 AND state IN ('pending','running')",
);
pub const PAUSE_TENANT_RECURRING: Statement<2, 0> =
    Statement::new("UPDATE nx_job_recurring SET state='paused' WHERE deployment=$1 AND tenant=$2");
pub const GRANT_VERSION: Statement<3, 1> = Statement::new(
    "SELECT CAST(version AS TEXT) FROM nx_job_grants WHERE deployment=$1 AND tenant=$2 AND worker=$3",
);
pub const REPLACE_GRANT: Statement<7, 0> = Statement::new(
    "UPDATE nx_job_grants SET version=$1,contract=$2,epoch=$3,state='active',declaration=$4 WHERE deployment=$5 AND tenant=$6 AND worker=$7",
);
pub const PAUSE_WORKER_JOBS_CHANGED: Statement<3, 0> = Statement::new(
    "UPDATE nx_jobs SET state='paused',reason='grant_changed',lease_until_ms=0 WHERE deployment=$1 AND tenant=$2 AND worker=$3 AND state IN ('pending','running')",
);
pub const UPSERT_ACTIVE_RECURRING: Statement<6, 0> = Statement::new(
    "INSERT INTO nx_job_recurring(deployment,tenant,name,contract,epoch,grant_version,version,state,next_ms,cutoff_ms,cutoff_seq,cursor) VALUES($1,$2,$3,$4,$5,$6,1,'active',0,0,0,'') ON CONFLICT(deployment,tenant,name) DO UPDATE SET contract=$4,epoch=$5,grant_version=$6,version=nx_job_recurring.version+1,state='active',next_ms=0,cutoff_ms=0,cutoff_seq=0,cursor=''",
);
pub const ACTIVATE_RUNTIME: Statement<0, 0> =
    Statement::new("UPDATE nx_job_runtime SET state='active' WHERE singleton=1");
pub const CANCEL_JOB: Statement<1, 0> = Statement::new(
    "UPDATE nx_jobs SET state='rejected',reason='operator_cancelled',lease_until_ms=0 WHERE id=$1 AND state IN ('pending','running','paused','dead')",
);
pub const PAUSE_RUNTIME_FOR_EPOCH: Statement<1, 0> =
    Statement::new("UPDATE nx_job_runtime SET epoch=$1,state='paused' WHERE singleton=1");
pub const REVOKE_DEPLOYMENT_GRANTS: Statement<1, 0> =
    Statement::new("UPDATE nx_job_grants SET state='revoked' WHERE deployment=$1");
pub const PAUSE_DEPLOYMENT_JOBS: Statement<1, 0> = Statement::new(
    "UPDATE nx_jobs SET state='paused',reason='restore_reconciliation',lease_until_ms=0 WHERE deployment=$1 AND state IN ('pending','running')",
);
pub const PAUSE_DEPLOYMENT_RECURRING: Statement<1, 0> =
    Statement::new("UPDATE nx_job_recurring SET state='paused' WHERE deployment=$1");
pub const LIST_JOBS: Statement<2, 9> = Statement::new(
    "SELECT id,deployment,tenant,worker,CAST(action AS TEXT),state,CAST(attempts AS TEXT),CAST(due_ms AS TEXT),CAST(eligible_ms AS TEXT) FROM nx_jobs WHERE EXISTS(SELECT 1 FROM nx_job_runtime r JOIN nx_deployment d ON d.singleton=r.singleton AND d.generation=r.deployment WHERE r.singleton=1 AND r.deployment=$1) AND id>$2 ORDER BY id LIMIT 100",
);
pub const LOCK_RECONCILABLE_JOB: Statement<3, 0> = Statement::new(
    "UPDATE nx_jobs SET fence=fence WHERE deployment=$1 AND id=$2 AND payload_digest=$3 AND state IN ('paused','dead','rejected')",
);
pub const RECONCILE_JOB: Statement<2, 0> = Statement::new(
    "UPDATE nx_jobs SET state='rejected',reason='operator_reconciled',lease_until_ms=0 WHERE id=$1 AND deployment=$2",
);
