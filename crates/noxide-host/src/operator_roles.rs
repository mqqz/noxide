//! Trusted operator APIs. These are deliberately absent from the guest interface.
use crate::{Database, auth::MAX_ROLES, database::Transaction, manifest::identifier};
use anyhow::{Context, Result, ensure};
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
    let tenant = tx.bounded_text("tenant", 32);
    let rows = tx
        .fetch::<1>(
            &format!("SELECT {tenant} FROM nx_accounts WHERE id=$1 AND state<>'deleted'"),
            &[user.into()],
        )
        .await?;
    let [tenant] = rows.first().context("account does not exist")?;
    ensure!(
        tenant.is_empty() || identifier(tenant),
        "invalid stored account tenant"
    );
    Ok(tenant.clone())
}

pub(crate) async fn assignments(tx: &mut Transaction, user: &str) -> Result<Vec<RoleAssignment>> {
    let name = tx.bounded_text("name", 32);
    let tenant = tx.bounded_text("tenant", 32);
    let rows = tx.fetch::<2>(&format!("SELECT {name},{tenant} FROM nx_roles WHERE principal=$1 ORDER BY name,tenant LIMIT {}", MAX_ROLES + 1), &[user.into()]).await?;
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

impl Database {
    /// Grant an exact assignment using trusted operator database credentials.
    /// No deployment activation is required. A commit error has an indeterminate
    /// outcome: reconcile current assignments before retrying against other operators.
    pub async fn grant_role(&self, user: &str, role: &str, scope: RoleScope<'_>) -> Result<bool> {
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
        #[cfg(test)]
        tests::after_assignments().await;
        let changed = !roles.iter().any(|r| r.name == role && r.tenant == tenant);
        if changed {
            ensure!(roles.len() < MAX_ROLES, "role assignment limit reached");
            tx.execute(
                "INSERT INTO nx_roles(principal,name,tenant) VALUES($1,$2,$3)",
                &[user.into(), role.into(), tenant.into()],
            )
            .await?;
        }
        tx.commit().await.context("role grant commit failed; outcome may be indeterminate; reconcile assignments before retrying")?;
        Ok(changed)
    }

    /// Revoke only the requested assignment, including obsolete tenant scopes.
    pub async fn revoke_role(&self, user: &str, role: &str, scope: RoleScope<'_>) -> Result<bool> {
        ensure!(
            crate::auth::account_id(user) && identifier(role),
            "invalid user or role identifier"
        );
        let tenant = scope.tenant()?;
        let mut tx = self.begin(Instant::now() + Duration::from_secs(5)).await?;
        tx.check_storage().await?;
        account(&mut tx, user).await?;
        let changed = tx
            .execute(
                "DELETE FROM nx_roles WHERE principal=$1 AND name=$2 AND tenant=$3",
                &[user.into(), role.into(), tenant.into()],
            )
            .await?
            != 0;
        tx.commit().await.context("role revocation commit failed; outcome may be indeterminate; reconcile assignments before retrying")?;
        Ok(changed)
    }

    /// Read one account's bounded assignments in deterministic order.
    pub async fn list_roles(&self, user: &str) -> Result<Vec<RoleAssignment>> {
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

#[cfg(test)]
mod tests;
