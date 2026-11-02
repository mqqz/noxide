//! Accounts, sessions, invites and role assignments.
use super::Statement;
use crate::database::{Transaction, sql};

pub fn session_roles(limit: usize) -> Statement<1, 2> {
    Statement::built(sql!(
        "SELECT name,tenant FROM nx_roles WHERE principal=$1 LIMIT {limit}"
    ))
}

pub fn account_tenant(tx: &Transaction) -> Statement<1, 1> {
    let tenant = tx.bounded_text("tenant", 32);
    Statement::built(sql!(
        "SELECT {tenant} FROM nx_accounts WHERE id=$1 AND state<>'deleted'"
    ))
}

pub fn role_assignments(tx: &Transaction, limit: usize) -> Statement<1, 2> {
    let name = tx.bounded_text("name", 32);
    let tenant = tx.bounded_text("tenant", 32);
    Statement::built(sql!(
        "SELECT {name},{tenant} FROM nx_roles WHERE principal=$1 ORDER BY name,tenant LIMIT {limit}"
    ))
}

pub const INSERT_INVITE: Statement<3, 0> =
    Statement::new("INSERT INTO nx_invites(code_hash,issuer,expires) VALUES($1,$2,$3)");
pub const ACCOUNT_BY_LOGIN: Statement<1, 1> =
    Statement::new("SELECT id FROM nx_accounts WHERE login_name=$1 AND state<>'deleted'");
pub const SET_ACCOUNT_STATE: Statement<2, 0> = Statement::new(
    "UPDATE nx_accounts SET state=$2,epoch=epoch+1 WHERE id=$1 AND state<>'deleted' AND epoch<9223372036854775807",
);
pub const DELETE_SESSIONS: Statement<1, 0> =
    Statement::new("DELETE FROM nx_sessions WHERE principal=$1");
pub const DELETE_ROLES: Statement<1, 0> = Statement::new("DELETE FROM nx_roles WHERE principal=$1");
pub const ERASE_CREDENTIALS: Statement<1, 0> =
    Statement::new("UPDATE nx_accounts SET login_name=NULL,password=NULL,tenant='' WHERE id=$1");
pub const CREDENTIALS_BY_LOGIN: Statement<1, 4> = Statement::new(
    "SELECT password,tenant,CAST(epoch AS TEXT),id FROM nx_accounts WHERE login_name=$1 AND state='active'",
);
pub const INSERT_SESSION: Statement<4, 0> =
    Statement::new("INSERT INTO nx_sessions(id,principal,epoch,expires) VALUES($1,$2,$3,$4)");
pub const SESSION_ACCOUNT: Statement<3, 2> = Statement::new(
    "SELECT a.id,a.tenant FROM nx_sessions s JOIN nx_accounts a ON a.id=s.principal WHERE s.id=$1 AND s.principal=$2 AND s.epoch=a.epoch AND a.state='active' AND s.expires>$3",
);
pub const REDEEM_INVITE: Statement<3, 0> = Statement::new(
    "UPDATE nx_invites SET redeemed_at=$1,redeemed_by=$2 WHERE code_hash=$3 AND redeemed_at IS NULL AND expires>$1",
);
pub const INSERT_ACCOUNT: Statement<4, 0> = Statement::new(
    "INSERT INTO nx_accounts(id,login_name,password,tenant,state,epoch) VALUES($1,$2,$3,$4,'active',1) ON CONFLICT(id) DO NOTHING",
);
pub const INSERT_ROLE: Statement<3, 0> =
    Statement::new("INSERT INTO nx_roles(principal,name,tenant) VALUES($1,$2,$3)");
pub const DELETE_ROLE: Statement<3, 0> =
    Statement::new("DELETE FROM nx_roles WHERE principal=$1 AND name=$2 AND tenant=$3");
pub const DELETE_SESSION: Statement<1, 0> = Statement::new("DELETE FROM nx_sessions WHERE id=$1");
