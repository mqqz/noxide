use crate::{
    Database,
    database::{Param, Transaction},
    security::{HostKeys, Token, TokenKind},
};
use anyhow::{Result, ensure};
use argon2::{
    Argon2, PasswordHasher, PasswordVerifier,
    password_hash::{PasswordHash, SaltString, rand_core::OsRng},
};

#[derive(Clone, Debug)]
pub(crate) struct Principal {
    pub id: String,
    pub tenant: String,
    pub roles: Vec<(String, String)>,
}

impl Database {
    /// Operator-only provisioning; never linked into an application component.
    pub async fn create_account(&self, id: &str, password: &str, tenant: &str) -> Result<()> {
        ensure!(
            crate::manifest::identifier(id)
                && (tenant.is_empty() || crate::manifest::identifier(tenant)),
            "invalid account scope"
        );
        ensure!(
            (12..=256).contains(&password.len()),
            "password must contain 12 to 256 bytes"
        );
        let password = password.to_owned();
        let hash = tokio::task::spawn_blocking(move || {
            Argon2::default()
                .hash_password(password.as_bytes(), &SaltString::generate(&mut OsRng))
                .map(|h| h.to_string())
                .map_err(|_| anyhow::anyhow!("password hashing failed"))
        })
        .await??;
        let mut tx = self
            .begin(std::time::Instant::now() + std::time::Duration::from_secs(5))
            .await?;
        tx.execute(
            "INSERT INTO nx_accounts(id,password,tenant,epoch) VALUES($1,$2,$3,1)",
            &[id.into(), hash.into(), tenant.into()],
        )
        .await?;
        tx.commit().await
    }
}

pub(crate) async fn login(
    tx: &mut Transaction,
    keys: &HostKeys,
    id: &str,
    password: &str,
    now: i64,
    permit: tokio::sync::OwnedSemaphorePermit,
) -> Result<String> {
    ensure!(
        crate::manifest::identifier(id) && password.len() <= 256,
        "invalid credentials"
    );
    let rows = tx
        .fetch::<3>(
            "SELECT password,tenant,CAST(epoch AS TEXT) FROM nx_accounts WHERE id=$1",
            &[id.into()],
        )
        .await?;
    let row = rows.first();
    // An unknown account still incurs the same bounded password work.
    let hash=row.map(|r|r[0].clone()).unwrap_or_else(||"$argon2id$v=19$m=19456,t=2,p=1$bm94aWRlLWR1bW15LXNhbHQ$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into());
    let password = password.to_owned();
    tokio::task::spawn_blocking(move || {
        // Cancellation cannot release capacity while this worker is running.
        let _permit = permit;
        let parsed =
            PasswordHash::new(&hash).map_err(|_| anyhow::anyhow!("invalid credentials"))?;
        ensure!(
            parsed.algorithm.as_str() == "argon2id"
                && parsed.version == Some(19)
                && parsed.params.get_decimal("m") == Some(19456)
                && parsed.params.get_decimal("t") == Some(2)
                && parsed.params.get_decimal("p") == Some(1),
            "unsupported password work policy"
        );
        Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .map_err(|_| anyhow::anyhow!("invalid credentials"))
    })
    .await??;
    let row = row.ok_or_else(|| anyhow::anyhow!("invalid credentials"))?;
    let (token, signed) = keys.issue(TokenKind::Session, id, now, 3600)?;
    tx.execute(
        "INSERT INTO nx_sessions(id,principal,epoch,expires) VALUES($1,$2,$3,$4)",
        &[
            token.nonce.into(),
            id.into(),
            Param::Number(row[2].parse()?),
            Param::Number(token.expires),
        ],
    )
    .await?;
    Ok(signed)
}

pub(crate) async fn authenticate(
    tx: &mut Transaction,
    keys: &HostKeys,
    cookie: &str,
    now: i64,
) -> Result<(Token, Principal)> {
    let token = keys.verify(cookie, now)?;
    ensure!(token.kind == TokenKind::Session, "wrong token kind");
    let rows=tx.fetch::<2>("SELECT a.id,a.tenant FROM nx_sessions s JOIN nx_accounts a ON a.id=s.principal WHERE s.id=$1 AND s.principal=$2 AND s.epoch=a.epoch AND s.expires>$3",&[token.nonce.as_str().into(),token.subject.as_str().into(),Param::Number(now)]).await?;
    let row = rows
        .first()
        .ok_or_else(|| anyhow::anyhow!("authentication required"))?;
    let roles = tx
        .fetch::<2>(
            "SELECT name,tenant FROM nx_roles WHERE principal=$1 LIMIT 33",
            &[row[0].as_str().into()],
        )
        .await?;
    ensure!(roles.len() <= 32, "role limit");
    Ok((
        token,
        Principal {
            id: row[0].clone(),
            tenant: row[1].clone(),
            roles: roles.into_iter().map(|[r, t]| (r, t)).collect(),
        },
    ))
}
