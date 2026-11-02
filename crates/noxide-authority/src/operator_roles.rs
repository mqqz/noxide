//! Trusted operator APIs. These are deliberately absent from the guest interface.
use crate::{Database, auth::MAX_ROLES, database::Transaction, manifest::identifier};
use anyhow::{Context, Result, ensure};
use noxide_store::statements::accounts as stmt;
use std::time::{Duration, Instant};

/// Global and tenant assignments are distinct policy authorities.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RoleScope<'a> {
    Global,
    Tenant(&'a str),
}
impl<'a> RoleScope<'a> {
    fn tenant(self) -> Result<&'a str> {
        match self {
            Self::Global => Ok(""),
            Self::Tenant(tenant) => {
                ensure!(identifier(tenant), "invalid role tenant");
                Ok(tenant)
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoleAssignment {
    pub name: String,
    /// Empty for a global assignment; otherwise the exact tenant identifier.
    pub tenant: String,
}

async fn account(tx: &mut Transaction, user: &str) -> Result<String> {
    let query = stmt::account_tenant(tx);
    let rows = tx.rows(&query, &[user.into()]).await?;
    let [tenant] = rows.first().context("account does not exist")?;
    ensure!(
        tenant.is_empty() || identifier(tenant),
        "invalid stored account tenant"
    );
    Ok(tenant.clone())
}

pub async fn assignments(tx: &mut Transaction, user: &str) -> Result<Vec<RoleAssignment>> {
    let query = stmt::role_assignments(tx, MAX_ROLES + 1);
    let rows = tx.rows(&query, &[user.into()]).await?;
    rows.into_iter()
        .map(|[name, tenant]| {
            ensure!(
                identifier(&name) && (tenant.is_empty() || identifier(&tenant)),
                "invalid stored role assignment"
            );
            Ok(RoleAssignment { name, tenant })
        })
        .collect()
}

#[allow(async_fn_in_trait)]
pub trait RoleAdmin {
    async fn list_roles(&self, user: &str) -> Result<Vec<RoleAssignment>>;
    async fn revoke_role(&self, user: &str, role: &str, scope: RoleScope<'_>) -> Result<bool>;
    async fn grant_role(&self, user: &str, role: &str, scope: RoleScope<'_>) -> Result<bool>;
}

impl RoleAdmin for Database {
    /// Grant an exact assignment using trusted operator database credentials.
    /// No deployment activation is required. A commit error has an indeterminate
    /// outcome: reconcile current assignments before retrying against other operators.
    async fn grant_role(&self, user: &str, role: &str, scope: RoleScope<'_>) -> Result<bool> {
        ensure!(
            crate::auth::account_id(user) && identifier(role),
            "invalid user or role identifier"
        );
        let tenant = scope.tenant()?;
        let mut tx = self.begin(Instant::now() + Duration::from_secs(5)).await?;
        tx.check_storage().await?;
        let account_tenant = account(&mut tx, user).await?;
        ensure!(
            tenant.is_empty() || tenant == account_tenant,
            "tenant grant must match the account tenant"
        );
        let roles = assignments(&mut tx, user).await?;
        #[cfg(any(test, feature = "test-support"))]
        after_assignments().await;
        let changed = !roles.iter().any(|r| r.name == role && r.tenant == tenant);
        if changed {
            ensure!(roles.len() < MAX_ROLES, "role assignment limit reached");
            tx.run(
                &stmt::INSERT_ROLE,
                &[user.into(), role.into(), tenant.into()],
            )
            .await?;
        }
        tx.commit().await.context("role grant commit failed; outcome may be indeterminate; reconcile assignments before retrying")?;
        Ok(changed)
    }

    /// Revoke only the requested assignment, including obsolete tenant scopes.
    async fn revoke_role(&self, user: &str, role: &str, scope: RoleScope<'_>) -> Result<bool> {
        ensure!(
            crate::auth::account_id(user) && identifier(role),
            "invalid user or role identifier"
        );
        let tenant = scope.tenant()?;
        let mut tx = self.begin(Instant::now() + Duration::from_secs(5)).await?;
        tx.check_storage().await?;
        account(&mut tx, user).await?;
        let changed = tx
            .run(
                &stmt::DELETE_ROLE,
                &[user.into(), role.into(), tenant.into()],
            )
            .await?
            != 0;
        tx.commit().await.context("role revocation commit failed; outcome may be indeterminate; reconcile assignments before retrying")?;
        Ok(changed)
    }

    /// Read one account's bounded assignments in deterministic order.
    async fn list_roles(&self, user: &str) -> Result<Vec<RoleAssignment>> {
        ensure!(crate::auth::account_id(user), "invalid user identifier");
        let mut tx = self
            .begin_read(Instant::now() + Duration::from_secs(5))
            .await?;
        tx.check_storage().await?;
        account(&mut tx, user).await?;
        let roles = assignments(&mut tx, user).await?;
        ensure!(
            roles.len() <= MAX_ROLES,
            "role assignment limit exceeded in storage"
        );
        tx.commit().await?;
        Ok(roles)
    }
}

#[cfg(any(test, feature = "test-support"))]
tokio::task_local! { pub static READ_BARRIER: std::sync::Arc<tokio::sync::Barrier>; }
#[cfg(any(test, feature = "test-support"))]
async fn after_assignments() {
    if let Ok(gate) = READ_BARRIER.try_with(Clone::clone) {
        gate.wait().await;
    }
}
