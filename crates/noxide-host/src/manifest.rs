use anyhow::{Result, bail, ensure};
use noxide_protocol::*;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub fn parse(bytes: &[u8]) -> Result<Manifest> {
    ensure!(bytes.len() <= MAX_MANIFEST_BYTES, "manifest limit");
    let manifest: Manifest = serde_json::from_slice(bytes)?;
    validate(&manifest)?;
    Ok(manifest)
}

pub fn digest(manifest: &Manifest) -> Result<[u8; 32]> {
    validate(manifest)?;
    Ok(Sha256::digest(serde_json::to_vec(manifest)?).into())
}

fn unique(ids: impl Iterator<Item = u32>) -> Result<()> {
    let mut seen = BTreeSet::new();
    for id in ids {
        ensure!(id != 0 && seen.insert(id), "duplicate or zero identifier");
    }
    Ok(())
}

pub fn identifier(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 32
        && name.as_bytes()[0].is_ascii_lowercase()
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

pub fn validate(m: &Manifest) -> Result<()> {
    ensure!(m.version == VERSION, "unsupported manifest version");
    ensure!(
        !m.resources.is_empty() && m.resources.len() <= 16,
        "resource limit"
    );
    ensure!(!m.routes.is_empty() && m.routes.len() <= 32, "route limit");
    ensure!(
        m.operations.len() <= 64 && m.actions.len() <= 32,
        "contract limit"
    );
    unique(m.resources.iter().map(|x| x.id))?;
    unique(m.operations.iter().map(|x| x.id))?;
    unique(m.routes.iter().map(|x| x.id))?;
    unique(m.actions.iter().map(|x| x.id))?;
    for r in &m.resources {
        ensure!(
            identifier(&r.name) && !r.fields.is_empty() && r.fields.len() <= 8,
            "invalid resource"
        );
        let mut fields = BTreeSet::new();
        for f in &r.fields {
            ensure!(
                identifier(&f.name) && fields.insert(&f.name),
                "invalid field"
            );
            ensure!(f.max_bytes > 0 && f.max_bytes <= 4096, "field limit");
            ensure!(
                !f.label.is_empty()
                    && f.label.len() <= 128
                    && !f.label.chars().any(char::is_control),
                "invalid label"
            );
        }
        ensure!(
            r.fields.iter().map(|f| f.max_bytes as usize).sum::<usize>() <= 8192,
            "record limit"
        );
    }
    for op in &m.operations {
        ensure!(
            m.resources.iter().any(|r| r.id == op.resource),
            "unknown resource"
        );
        ensure!(
            !op.policy.any.is_empty() && op.policy.any.len() <= 8,
            "invalid policy"
        );
        for rule in &op.policy.any {
            ensure!(!rule.is_empty() && rule.len() <= 4, "invalid policy rule");
            for p in rule {
                if let Predicate::Role { name, .. } = p {
                    ensure!(identifier(name), "invalid role");
                }
            }
        }
    }
    let mut paths = BTreeSet::new();
    for r in &m.routes {
        ensure!(
            r.path.starts_with('/') && r.path.len() <= 64 && paths.insert(&r.path),
            "invalid route path"
        );
        ensure!(
            r.path == "/" || (identifier(&r.path[1..]) && !r.path.ends_with('/')),
            "invalid route path"
        );
        ensure!(
            !matches!(r.path.as_str(), "/login" | "/logout"),
            "reserved route"
        );
        unique(r.operations.iter().copied())?;
        unique(r.forms.iter().copied())?;
        ensure!(
            r.resource.is_some() || r.operations.len() <= 1,
            "a list route has one cursor scope"
        );
        for id in &r.operations {
            let op = operation(m, *id)?;
            ensure!(
                matches!(
                    (&op.kind, r.resource.is_some()),
                    (OperationKind::List, false) | (OperationKind::Read, true)
                ),
                "route operation mismatch"
            );
            ensure!(
                r.resource.is_none_or(|resource| resource == op.resource),
                "route resource mismatch"
            );
        }
        if let Some(id) = r.resource {
            resource(m, id)?;
            ensure!(
                !r.operations.is_empty(),
                "record route requires a read operation"
            );
        }
        for id in &r.forms {
            let a = action(m, *id)?;
            let op = operation(m, a.operation)?;
            if op.kind != OperationKind::Create {
                ensure!(
                    r.resource == Some(op.resource),
                    "mutation form requires its record route"
                );
            }
        }
    }
    ensure!(
        m.routes
            .iter()
            .any(|r| r.path == "/" && r.resource.is_none()),
        "missing index route"
    );
    for a in &m.actions {
        ensure!(
            a.version > 0
                && !a.name.is_empty()
                && a.name.len() <= 64
                && !a.name.chars().any(char::is_control),
            "invalid action"
        );
        let op = operation(m, a.operation)?;
        let fields = action_fields(m, a)?;
        match op.kind {
            OperationKind::Create => ensure!(
                fields.len() == resource(m, op.resource)?.fields.len(),
                "creation requires every field"
            ),
            OperationKind::Update => ensure!(!fields.is_empty(), "update requires writable fields"),
            OperationKind::Delete => ensure!(fields.is_empty(), "delete has no writable fields"),
            _ => anyhow::bail!("action must declare a mutation"),
        }
        if let Some(inspect) = &a.inspect {
            let read = operation(m, inspect.operation)?;
            ensure!(
                op.kind != OperationKind::Create
                    && read.kind == OperationKind::Read
                    && read.resource == op.resource,
                "invalid inspection operation"
            );
            ensure!(!inspect.fields.is_empty(), "empty inspection");
            projected_fields(resource(m, op.resource)?, &inspect.fields)?;
        }
        let r = route(m, a.redirect)?;
        ensure!(
            if op.kind == OperationKind::Delete {
                r.resource.is_none()
            } else {
                r.resource == Some(op.resource)
            },
            "invalid outcome route"
        );
    }
    Ok(())
}

pub fn operation(m: &Manifest, id: u32) -> Result<&Operation> {
    m.operations
        .iter()
        .find(|o| o.id == id)
        .ok_or_else(|| anyhow::anyhow!("unknown operation"))
}
pub fn resource(m: &Manifest, id: u32) -> Result<&Resource> {
    m.resources
        .iter()
        .find(|o| o.id == id)
        .ok_or_else(|| anyhow::anyhow!("unknown resource"))
}
pub fn route(m: &Manifest, id: u32) -> Result<&Route> {
    m.routes
        .iter()
        .find(|o| o.id == id)
        .ok_or_else(|| anyhow::anyhow!("unknown route"))
}
pub fn action(m: &Manifest, id: u32) -> Result<&Action> {
    m.actions
        .iter()
        .find(|o| o.id == id)
        .ok_or_else(|| anyhow::anyhow!("unknown action"))
}
pub fn validate_fields(resource: &Resource, fields: &Fields) -> Result<()> {
    ensure!(fields.len() == resource.fields.len(), "unexpected fields");
    for f in &resource.fields {
        validate_field(f, fields)?;
    }
    Ok(())
}

fn projected_fields<'a>(resource: &'a Resource, names: &[String]) -> Result<Vec<&'a TextField>> {
    ensure!(
        names.len() <= resource.fields.len(),
        "field projection limit"
    );
    let mut seen = BTreeSet::new();
    names
        .iter()
        .map(|name| {
            ensure!(seen.insert(name), "duplicate projected field");
            resource
                .fields
                .iter()
                .find(|field| &field.name == name)
                .ok_or_else(|| anyhow::anyhow!("unknown projected field"))
        })
        .collect()
}

pub(crate) fn action_fields<'a>(m: &'a Manifest, action: &Action) -> Result<Vec<&'a TextField>> {
    projected_fields(
        resource(m, operation(m, action.operation)?.resource)?,
        &action.fields,
    )
}

pub(crate) fn validate_input(m: &Manifest, action: &Action, fields: &Fields) -> Result<()> {
    let declared = action_fields(m, action)?;
    ensure!(fields.len() == declared.len(), "unexpected action fields");
    for field in declared {
        validate_field(field, fields)?;
    }
    Ok(())
}

fn validate_field(f: &TextField, fields: &Fields) -> Result<()> {
    let Some(value) = fields.get(&f.name) else {
        bail!("missing field")
    };
    ensure!(
        !value.trim().is_empty() && value.len() <= f.max_bytes as usize,
        "field length"
    );
    ensure!(
        !value
            .chars()
            .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t')),
        "invalid field text"
    );
    Ok(())
}
