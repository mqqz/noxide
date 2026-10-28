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

#[derive(Clone, Copy, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Registration {
    #[default]
    Closed,
    Invite,
    Open,
}

#[derive(Clone, Debug)]
pub(crate) enum Principal {
    Anonymous,
    User(User),
}
impl Principal {
    pub(crate) fn user(&self) -> Result<&User> {
        match self {
            Self::User(user) => Ok(user),
            Self::Anonymous => anyhow::bail!("policy denied"),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct User {
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
        tx.check_storage().await?;
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
    permits: crate::runtime::limiter::HashPermits,
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
        let hash_permits = permits;
        hash_permits.enter();
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

#[derive(Debug)]
pub(crate) enum AuthError {
    Invalid,
    Unavailable,
}
impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Invalid => "authentication required",
            Self::Unavailable => "authentication unavailable",
        })
    }
}
impl std::error::Error for AuthError {}

pub(crate) async fn authenticate(
    tx: &mut Transaction,
    keys: &HostKeys,
    cookie: &str,
    now: i64,
) -> std::result::Result<(Token, Principal), AuthError> {
    let token = keys.verify(cookie, now).map_err(|_| AuthError::Invalid)?;
    if token.kind != TokenKind::Session {
        return Err(AuthError::Invalid);
    }
    let rows=tx.fetch::<2>("SELECT a.id,a.tenant FROM nx_sessions s JOIN nx_accounts a ON a.id=s.principal WHERE s.id=$1 AND s.principal=$2 AND s.epoch=a.epoch AND s.expires>$3",&[token.nonce.as_str().into(),token.subject.as_str().into(),Param::Number(now)]).await.map_err(|_| AuthError::Unavailable)?;
    let row = rows.first().ok_or(AuthError::Invalid)?;
    let roles = tx
        .fetch::<2>(
            "SELECT name,tenant FROM nx_roles WHERE principal=$1 LIMIT 33",
            &[row[0].as_str().into()],
        )
        .await
        .map_err(|_| AuthError::Unavailable)?;
    if roles.len() > 32 {
        return Err(AuthError::Invalid);
    }
    Ok((
        token,
        Principal::User(User {
            id: row[0].clone(),
            tenant: row[1].clone(),
            roles: roles.into_iter().map(|[r, t]| (r, t)).collect(),
        }),
    ))
}

impl Database {
    /// Mint an operator invitation. Only its SHA-256 digest is persisted.
    pub async fn mint_invite(&self, expires_days: Option<u64>) -> Result<String> {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        let code = crate::security::random_id()?;
        let lifetime = match expires_days {
            Some(days) => days
                .checked_mul(86400)
                .ok_or_else(|| anyhow::anyhow!("invite expiry overflow"))?,
            None => crate::runtime::limiter::INVITE_DEFAULT_EXPIRY.as_secs(),
        };
        let lifetime: i64 = lifetime.try_into()?;
        let mut tx = self
            .begin(std::time::Instant::now() + std::time::Duration::from_secs(5))
            .await?;
        tx.check_storage().await?;
        let now = crate::security::observe_clock(&mut tx, crate::security::now()?).await?;
        let expires = now
            .checked_add(lifetime)
            .ok_or_else(|| anyhow::anyhow!("invite expiry overflow"))?;
        tx.execute(
            "INSERT INTO nx_invites(code_hash,issuer,expires) VALUES($1,$2,$3)",
            &[
                URL_SAFE_NO_PAD.encode(invite_hash(&code)).into(),
                "operator".into(),
                expires.into(),
            ],
        )
        .await?;
        tx.commit().await?;
        Ok(code)
    }
}
fn invite_hash(code: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(code.as_bytes()).into()
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn register(
    tx: &mut Transaction,
    mode: Registration,
    id: &str,
    password: &str,
    invite: Option<&str>,
    now: i64,
    permits: crate::runtime::limiter::HashPermits,
) -> Result<()> {
    ensure!(
        mode != Registration::Closed
            && crate::manifest::identifier(id)
            && (12..=256).contains(&password.len()),
        "registration failed"
    );
    ensure!(
        mode != Registration::Invite || invite.is_some_and(|code| code.len() <= 256),
        "registration failed"
    );
    let password = password.to_owned();
    let hash = tokio::task::spawn_blocking(move || {
        let hash_permits = permits;
        hash_permits.enter();
        Argon2::default()
            .hash_password(password.as_bytes(), &SaltString::generate(&mut OsRng))
            .map(|hash| hash.to_string())
            .map_err(|_| anyhow::anyhow!("registration failed"))
    })
    .await??;
    // The account and redemption are one atomic unit. Insert first to satisfy
    // redeemed_by's immediate foreign key; failed redemption rolls it back.
    tx.execute(
        "INSERT INTO nx_accounts(id,password,tenant,epoch) VALUES($1,$2,'',1)",
        &[id.into(), hash.into()],
    )
    .await?;
    if mode == Registration::Invite {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        let hash = URL_SAFE_NO_PAD.encode(invite_hash(
            invite.ok_or_else(|| anyhow::anyhow!("registration failed"))?,
        ));
        ensure!(tx.execute("UPDATE nx_invites SET redeemed_at=$1,redeemed_by=$2 WHERE code_hash=$3 AND redeemed_at IS NULL AND expires>$1",&[now.into(),id.into(),hash.into()]).await? == 1,"registration failed");
    }
    Ok(())
}
