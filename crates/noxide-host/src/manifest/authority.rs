//! Independent admission for resource lifecycle and specialized membership.
use super::*;

pub(super) fn validate(m: &Manifest) -> Result<()> {
    for resource in &m.resources {
        crate::expiry::validate(resource)?;
        crate::membership::validate_unique(resource)?;
    }
    for operation in &m.operations {
        crate::membership::plans(m, operation)?;
    }
    Ok(())
}
