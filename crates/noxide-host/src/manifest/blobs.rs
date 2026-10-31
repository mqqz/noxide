//! Independent admission for one immutable attachment through one host upload.
use super::*;
pub(super) fn validate_blobs(m: &Manifest) -> Result<()> {
    let has_opaque = m.resources.iter().flat_map(|r| &r.fields).any(|f| {
        matches!(
            f.kind,
            FieldKind::Blob { .. } | FieldKind::UploadHandle { .. }
        )
    }) || m.actions.iter().flat_map(|a| &a.inputs).any(|i| {
        matches!(
            i.kind,
            FieldKind::Blob { .. } | FieldKind::UploadHandle { .. }
        )
    });
    let Some(policy) = &m.blobs else {
        ensure!(!has_opaque, "blob declarations require an approved policy");
        return Ok(());
    };
    policy.validate_limits().map_err(anyhow::Error::msg)?;
    unique(policy.uploads.iter().map(|u| u.id))?;
    let mut names = BTreeSet::new();
    let mut actions = BTreeSet::new();
    let mut bindings = BTreeSet::new();
    for upload in &policy.uploads {
        ensure!(
            identifier(&upload.name)
                && names.insert(&upload.name)
                && bindings.insert(upload.web_binding),
            "duplicate upload binding"
        );
        let binding = web_binding(m, upload.web_binding)?;
        let action = action(m, binding.action)?;
        ensure!(actions.insert(action.id), "one upload binding per action");
        let input = action
            .inputs
            .iter()
            .find(|i| i.name == upload.input)
            .ok_or_else(|| anyhow::anyhow!("unknown upload input"))?;
        let FieldKind::UploadHandle { max_bytes } = input.kind else {
            anyhow::bail!("upload requires an UploadHandle input");
        };
        ensure!(
            max_bytes > 0 && max_bytes <= policy.limits.file_bytes,
            "upload input exceeds policy"
        );
        let mut uses = 0;
        for step in &action.steps {
            let operation = operation(m, step.operation)?;
            for assignment in &step.assign {
                if matches!(&assignment.change, Change::Set(Value::Input(name)) if name == &input.name)
                {
                    let field = resource(m, operation.resource)?
                        .fields
                        .iter()
                        .find(|f| f.name == assignment.field)
                        .ok_or_else(|| anyhow::anyhow!("unknown blob destination"))?;
                    ensure!(
                        operation.kind == OperationKind::Create
                            && matches!(field.kind,FieldKind::Blob { max_bytes: limit } if max_bytes <= limit)
                            && (!input.optional || field.optional),
                        "upload requires a compatible create Blob destination"
                    );
                    uses += 1;
                }
            }
        }
        ensure!(uses == 1, "an upload attaches exactly once");
        let anonymous = anonymous_action(operation(m, action.steps[0].operation)?);
        ensure!(
            anonymous == upload.anonymous.is_some(),
            "anonymous upload requires explicit capability quota"
        );
        if anonymous {
            ensure!(
                action.steps.len() == 1 && policy.anonymous.is_some(),
                "anonymous upload requires deployment limits and one create"
            );
        }
        // Additional web bindings cannot admit the same upload action under a
        // different nonce/ticket contract.
        ensure!(
            m.web_bindings
                .iter()
                .filter(|b| b.action == action.id)
                .count()
                == 1,
            "upload action has one web binding"
        );
    }
    for action in &m.actions {
        let opaque: Vec<_> = action
            .inputs
            .iter()
            .filter(|i| matches!(i.kind, FieldKind::UploadHandle { .. }))
            .collect();
        ensure!(
            opaque.len() <= 1 && (opaque.is_empty() || actions.contains(&action.id)),
            "unbound upload input"
        );
    }
    Ok(())
}
