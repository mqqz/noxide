use anyhow::{Result, ensure};
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

fn validate_selection(m: &Manifest, op: &Operation) -> Result<()> {
    ensure!(
        op.filter.is_empty() || op.kind == OperationKind::List,
        "filter requires list"
    );
    ensure!(
        op.disclose.is_empty() || (op.kind == OperationKind::List && is_public(op)),
        "disclose requires public list"
    );
    ensure!(op.filter.len() <= 4, "filter limit");
    let resource = resource(m, op.resource)?;
    let mut filtered = BTreeSet::new();
    let mut inferred = BTreeSet::new();
    for condition in &op.filter {
        ensure!(
            filtered.insert(condition.field.as_str()),
            "duplicate filter field"
        );
        let field = resource
            .fields
            .iter()
            .find(|f| f.name == condition.field)
            .ok_or_else(|| anyhow::anyhow!("unknown filter field"))?;
        ensure!(
            matches!(field.kind, FieldKind::Boolean | FieldKind::Choice { .. }),
            "invalid filter kind"
        );
        match &condition.equals {
            Operand::Literal(value) => ensure!(
                field.canonical(value).is_ok_and(|v| v == *value),
                "noncanonical filter value"
            ),
            Operand::Param(name) => ensure!(
                identifier(name) && name != "cursor",
                "invalid filter parameter"
            ),
        }
        ensure!(
            op.visibility
                .as_ref()
                .is_none_or(|v| v.field != condition.field),
            "filter duplicates visibility"
        );
        if is_public(op)
            && op
                .fields
                .as_ref()
                .is_none_or(|p| !p.contains(&condition.field))
        {
            inferred.insert(condition.field.as_str());
        }
    }
    let disclosed: BTreeSet<_> = op.disclose.iter().map(String::as_str).collect();
    ensure!(
        disclosed.len() == op.disclose.len() && disclosed == inferred,
        "invalid filter disclosure"
    );
    Ok(())
}

pub(crate) fn parameter_fields<'a>(
    m: &'a Manifest,
    route: &Route,
) -> Result<std::collections::BTreeMap<&'a str, &'a TextField>> {
    let mut fields: std::collections::BTreeMap<&str, &TextField> =
        std::collections::BTreeMap::new();
    for id in &route.operations {
        let op = operation(m, *id)?;
        let resource = resource(m, op.resource)?;
        for condition in &op.filter {
            if let Operand::Param(name) = &condition.equals {
                ensure!(route.params.contains(name), "undeclared route parameter");
                let field = resource
                    .fields
                    .iter()
                    .find(|f| f.name == condition.field)
                    .ok_or_else(|| anyhow::anyhow!("unknown filter field"))?;
                if let Some(previous) = fields.get(name.as_str()) {
                    ensure!(previous.kind == field.kind, "inconsistent parameter kind");
                    if !previous.optional {
                        continue;
                    }
                }
                fields.insert(name.as_str(), field);
            }
        }
    }
    Ok(fields)
}
fn validate_route_params(m: &Manifest, route: &Route) -> Result<()> {
    ensure!(
        route.path != "/" || route.params.is_empty(),
        "index route cannot declare parameters"
    );
    let names: BTreeSet<_> = route.params.iter().collect();
    ensure!(
        route.params.len() <= 4
            && names.len() == route.params.len()
            && names
                .iter()
                .all(|name| identifier(name) && name.as_str() != "cursor"),
        "invalid route parameters"
    );
    let fields = parameter_fields(m, route)?;
    ensure!(fields.len() == route.params.len(), "unused route parameter");
    Ok(())
}
pub(crate) fn validate_params(m: &Manifest, route: &Route, values: &Fields) -> Result<()> {
    ensure!(
        values.len() == route.params.len()
            && route.params.iter().all(|name| values.contains_key(name)),
        "invalid route parameters"
    );
    for id in &route.operations {
        let op = operation(m, *id)?;
        let resource = resource(m, op.resource)?;
        for condition in &op.filter {
            if let Operand::Param(name) = &condition.equals {
                let field = resource
                    .fields
                    .iter()
                    .find(|f| f.name == condition.field)
                    .ok_or_else(|| anyhow::anyhow!("unknown filter field"))?;
                let value = values
                    .get(name)
                    .ok_or_else(|| anyhow::anyhow!("missing route parameter"))?;
                ensure!(
                    field.canonical(value).is_ok_and(|v| v == *value),
                    "invalid route parameter"
                );
            }
        }
    }
    Ok(())
}

pub(crate) fn is_preview(op: &Operation) -> bool {
    op.list.as_ref().is_some_and(|s| s.preview.is_some())
}
fn selection_equal(left: &Operation, right: &Operation) -> bool {
    let fields = |op: &Operation| {
        op.filter
            .iter()
            .map(|c| (c.field.clone(), c.equals.clone()))
            .collect::<std::collections::BTreeMap<_, _>>()
    };
    fields(left) == fields(right)
}

fn unique(ids: impl Iterator<Item = u32>) -> Result<()> {
    let mut seen = BTreeSet::new();
    for id in ids {
        ensure!(id != 0 && seen.insert(id), "duplicate or zero identifier");
    }
    Ok(())
}

pub use noxide_protocol::identifier;

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
    let mut resource_keys = BTreeSet::new();
    for r in &m.resources {
        for field in &r.fields {
            if let Some(value) = &field.initial {
                ensure!(
                    !field.optional
                        && matches!(field.kind, FieldKind::Boolean | FieldKind::Choice { .. }),
                    "initial requires a non-optional boolean or choice"
                );
                ensure!(
                    field.canonical(value).as_ref().ok() == Some(value),
                    "invalid initial value"
                );
            }
        }
        ensure!(
            identifier(&r.name)
                && resource_keys.insert(&r.name)
                && !r.fields.is_empty()
                && r.fields.len() <= 8,
            "invalid resource"
        );
        ensure!(
            r.fields
                .iter()
                .filter(|f| matches!(f.kind, FieldKind::Reference { .. }))
                .count()
                <= 1,
            "one reference per resource"
        );
        ensure!(
            r.fields
                .iter()
                .filter(|f| matches!(f.kind, FieldKind::Account { .. }))
                .count()
                <= 4,
            "account field limit"
        );
        let mut fields = BTreeSet::new();
        for f in &r.fields {
            ensure!(
                identifier(&f.name) && fields.insert(&f.name),
                "invalid field"
            );
            ensure!(f.max_bytes > 0 && f.max_bytes <= 4096, "field limit");
            match &f.kind {
                FieldKind::Reference { resource: key } => {
                    ensure!(
                        !f.optional && f.initial.is_none() && f.max_bytes >= 19,
                        "reference must be required without defaults and hold an ID"
                    );
                    ensure!(
                        m.resources.iter().any(|target| &target.name == key),
                        "unknown reference resource"
                    );
                }
                FieldKind::Account { .. } => ensure!(
                    !f.optional && f.initial.is_none() && f.max_bytes >= 43,
                    "account fields must be required without defaults"
                ),
                FieldKind::Text => {}
                FieldKind::Boolean => ensure!(f.max_bytes >= 5, "boolean field budget"),
                FieldKind::Integer { min, max } => {
                    ensure!(
                        f.max_bytes >= 20 && min.zip(*max).is_none_or(|(min, max)| min <= max),
                        "integer schema"
                    );
                }
                FieldKind::Choice { variants } => {
                    ensure!(!variants.is_empty() && variants.len() <= 32, "choice limit");
                    let mut keys = BTreeSet::new();
                    for v in variants {
                        ensure!(
                            identifier(&v.key)
                                && keys.insert(&v.key)
                                && v.key.len() <= f.max_bytes as usize,
                            "choice key"
                        );
                        ensure!(
                            !v.label.is_empty()
                                && v.label.len() <= 128
                                && !v.label.chars().any(char::is_control),
                            "choice label"
                        );
                    }
                }
            }
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
    for r in &m.resources {
        if let Some(gate) = &r.gate {
            let field =
                reference_field(r).ok_or_else(|| anyhow::anyhow!("gate requires reference"))?;
            ensure!(gate.field == field.name, "gate must name reference");
            let target = reference_resource(m, r.id)?.expect("reference target");
            ensure!(target.gate.is_none(), "gate target cannot have a gate");
            for predicate in [&gate.visible, &gate.create_when] {
                let field = target
                    .fields
                    .iter()
                    .find(|f| f.name == predicate.field)
                    .ok_or_else(|| anyhow::anyhow!("unknown gate predicate field"))?;
                ensure!(
                    matches!(field.kind, FieldKind::Boolean | FieldKind::Choice { .. })
                        && field
                            .canonical(&predicate.equals)
                            .is_ok_and(|v| v == predicate.equals),
                    "invalid gate predicate"
                );
            }
        }
    }
    for op in &m.operations {
        ensure!(
            op.scope.is_none() || op.kind == OperationKind::List,
            "scope requires list"
        );
        ensure!(
            op.via.is_none() || op.kind == OperationKind::Read,
            "via requires read"
        );
        ensure!(
            op.scope.is_none() || op.via.is_none(),
            "scope and via are exclusive"
        );
        let r = resource(m, op.resource)?;
        if let Some(scope) = &op.scope {
            ensure!(
                reference_field(r).is_some_and(|f| &f.name == scope),
                "scope requires reference field"
            );
        }
        if op.kind == OperationKind::List
            && let Some(gate) = &r.gate
        {
            ensure!(
                op.scope.as_ref() == Some(&gate.field),
                "gated list requires scope"
            );
        }
        if let Some(via) = &op.via {
            let source = operation(m, via.source)?;
            ensure!(
                source.via.is_none()
                    && matches!(source.kind, OperationKind::Read | OperationKind::List),
                "invalid follow source"
            );
            let source_resource = resource(m, source.resource)?;
            ensure!(
                reference_field(source_resource).is_some_and(|f| f.name == via.field)
                    && reference_resource(m, source.resource)?
                        .is_some_and(|target| target.id == op.resource),
                "invalid follow reference"
            );
            ensure!(
                source
                    .fields
                    .as_ref()
                    .is_none_or(|fields| fields.contains(&via.field)),
                "follow source projection hides reference"
            );
        }
        if let Some(bind) = &op.bind {
            ensure!(
                op.kind == OperationKind::Create
                    && reference_field(r).is_some_and(|field| field.name == bind.field),
                "bind requires reference create"
            );
            let eligible = operation(m, bind.eligible)?;
            ensure!(
                eligible.kind == OperationKind::Read
                    && eligible.via.is_none()
                    && reference_resource(m, op.resource)?
                        .is_some_and(|target| target.id == eligible.resource),
                "invalid binding eligibility"
            );
        } else {
            ensure!(
                op.kind != OperationKind::Create || reference_field(r).is_none(),
                "reference create requires bind"
            );
        }
        validate_selection(m, op)?;
        if op.kind == OperationKind::List {
            crate::query_plan::compile(m, op)?;
        }
        ensure!(
            op.list
                .as_ref()
                .is_none_or(|s| op.kind == OperationKind::List && (1..=20).contains(&s.page_size)),
            "invalid list settings"
        );
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
                if let Predicate::PrincipalIs { field } = p {
                    ensure!(
                        matches!(op.kind, OperationKind::Read | OperationKind::List),
                        "principal_is requires read or list"
                    );
                    ensure!(
                        resource(m, op.resource)?.fields.iter().any(
                            |f| f.name == *field && matches!(f.kind, FieldKind::Account { .. })
                        ),
                        "principal_is requires an account field"
                    );
                }
                if let Predicate::Role { name, .. } = p {
                    ensure!(identifier(name), "invalid role");
                }
            }
        }
    }
    for op in &m.operations {
        if is_public(op) {
            ensure!(
                op.policy.any == [vec![Predicate::Public]],
                "public policy must stand alone"
            );
            if op.kind == OperationKind::Create {
                ensure!(
                    op.visibility.is_none() && op.fields.is_none(),
                    "public create cannot project or filter"
                );
                continue;
            }
            ensure!(
                matches!(op.kind, OperationKind::List | OperationKind::Read),
                "public operations must read"
            );
            let visibility = op
                .visibility
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("public visibility required"))?;
            let resource = resource(m, op.resource)?;
            let field = resource
                .fields
                .iter()
                .find(|field| field.name == visibility.field)
                .ok_or_else(|| anyhow::anyhow!("unknown visibility field"))?;
            ensure!(
                matches!(field.kind, FieldKind::Boolean | FieldKind::Choice { .. }),
                "visibility must be boolean or choice"
            );
            ensure!(
                field
                    .canonical(&visibility.equals)
                    .is_ok_and(|v| v == visibility.equals),
                "visibility must be canonical"
            );
            let fields = op
                .fields
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("public fields required"))?;
            ensure!(!fields.is_empty(), "empty public fields");
            projected_fields(resource, fields)?;
        } else {
            ensure!(
                op.visibility.is_none() && op.fields.is_none(),
                "private operations cannot declare public visibility or fields"
            );
        }
    }
    for op in &m.operations {
        if is_capability(op) {
            ensure!(
                op.policy.any == [vec![Predicate::Capability]]
                    && matches!(op.kind, OperationKind::Update | OperationKind::Delete),
                "capability policy requires standalone update or delete"
            );
        }
    }
    let mut paths = BTreeSet::new();
    crate::query_plan::required_indexes(m)?;
    for r in &m.routes {
        validate_route_params(m, r)?;
        crate::render::validate_path(r)?;
        ensure!(paths.insert(&r.path), "duplicate route path");
        for other in &m.routes {
            if other.id != r.id {
                ensure!(
                    !crate::render::paths_overlap(r, other),
                    "ambiguous route patterns"
                );
            }
        }
        unique(r.operations.iter().copied())?;
        unique(r.forms.iter().copied())?;
        if r.access == Access::Public {
            ensure!(r.forms.is_empty(), "public routes cannot have forms");
            for id in &r.operations {
                ensure!(
                    is_public(operation(m, *id)?),
                    "public routes require public operations"
                );
            }
        }
        let lists: Vec<_> = r
            .operations
            .iter()
            .map(|id| operation(m, *id))
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .filter(|op| op.kind == OperationKind::List)
            .collect();
        ensure!(lists.len() <= 4, "route list limit");
        ensure!(
            lists.iter().filter(|op| !is_preview(op)).count() <= 1,
            "route paginated list limit"
        );
        ensure!(
            lists
                .iter()
                .map(|op| op.list.as_ref().map_or(3, |s| s.page_size) as usize)
                .sum::<usize>()
                <= 40,
            "route list row budget"
        );
        for op in &lists {
            if let Some(see_all) = op
                .list
                .as_ref()
                .and_then(|s| s.preview.as_ref())
                .and_then(|p| p.see_all)
            {
                let destination = route(m, see_all)?;
                ensure!(
                    destination
                        .params
                        .iter()
                        .all(|name| r.params.contains(name)),
                    "preview destination parameters"
                );
                let source_fields = parameter_fields(m, r)?;
                for (name, target) in parameter_fields(m, destination)? {
                    let source = source_fields
                        .get(name)
                        .ok_or_else(|| anyhow::anyhow!("preview destination parameters"))?;
                    ensure!(
                        source.kind == target.kind && (!source.optional || target.optional),
                        "incompatible preview destination parameter"
                    );
                }
                ensure!(
                    destination
                        .operations
                        .iter()
                        .filter_map(|id| operation(m, *id).ok())
                        .any(|full| full.kind == OperationKind::List
                            && !is_preview(full)
                            && full.resource == op.resource
                            && full.policy == op.policy
                            && full.visibility == op.visibility
                            && full.scope == op.scope
                            && selection_equal(full, op)),
                    "invalid preview destination"
                );
            }
        }
        for id in &r.operations {
            let op = operation(m, *id)?;
            if let Some(via) = &op.via {
                ensure!(
                    r.operations.contains(&via.source),
                    "follow route requires source"
                );
            } else if op.kind == OperationKind::List {
                let target = if op.scope.is_some() {
                    reference_resource(m, op.resource)?.map(|p| p.id)
                } else {
                    None
                };
                ensure!(
                    r.resource == target,
                    "list requires scope route or collection route"
                );
            } else {
                ensure!(
                    op.kind == OperationKind::Read && r.resource == Some(op.resource),
                    "route operation mismatch"
                );
            }
        }
        if let Some(id) = r.resource {
            resource(m, id)?;
            ensure!(
                r.operations.iter().any(|id| operation(m, *id)
                    .is_ok_and(|op| op.kind == OperationKind::Read
                        && op.via.is_none()
                        && op.resource == r.resource.unwrap())),
                "record route requires a read operation"
            );
        }
        for id in &r.forms {
            let a = action(m, *id)?;
            if let Some(target) = signed_resource(m, a)? {
                ensure!(
                    r.resource == Some(target),
                    "mutation form requires its signed target route"
                );
            }
            for step in &a.steps {
                let op = operation(m, step.operation)?;
                if step
                    .assign
                    .iter()
                    .any(|assignment| matches!(assignment.change, Change::Set(Value::SignedTarget)))
                {
                    let bind = op
                        .bind
                        .as_ref()
                        .ok_or_else(|| anyhow::anyhow!("reference create requires bind"))?;
                    ensure!(
                        r.operations.contains(&bind.eligible),
                        "binding eligibility must be on form route"
                    );
                }
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
        validate_action(m, a)?;
    }
    Ok(())
}

pub(crate) fn signed_resource(m: &Manifest, action: &Action) -> Result<Option<u32>> {
    signed_resource_parts(m, &action.steps, action.inspect.as_ref())
}

pub(crate) fn signed_resource_parts(
    m: &Manifest,
    steps: &[Step],
    inspect: Option<&Inspection>,
) -> Result<Option<u32>> {
    let mut signed = None;
    let mut include = |resource| -> Result<()> {
        ensure!(
            signed.is_none_or(|previous| previous == resource),
            "inconsistent signed target resource"
        );
        signed = Some(resource);
        Ok(())
    };
    for step in steps {
        let op = operation(m, step.operation)?;
        if step.target == Target::Signed {
            include(op.resource)?;
        }
        for assignment in &step.assign {
            if assignment.change == Change::Set(Value::SignedTarget) {
                let target = reference_resource(m, op.resource)?
                    .ok_or_else(|| anyhow::anyhow!("signed target requires reference"))?;
                include(target.id)?;
            }
        }
    }
    if let Some(inspect) = inspect {
        include(operation(m, inspect.operation)?.resource)?;
    }
    Ok(signed)
}

fn validate_action(m: &Manifest, a: &Action) -> Result<()> {
    ensure!(
        a.version > 0
            && !a.name.is_empty()
            && a.name.len() <= 64
            && !a.name.chars().any(char::is_control),
        "invalid action"
    );
    ensure!((1..=4).contains(&a.steps.len()), "transaction step limit");
    let signed = signed_resource(m, a)?;
    let mut names = BTreeSet::new();
    for input in &a.inputs {
        ensure!(
            identifier(&input.name) && names.insert(input.name.as_str()),
            "invalid or duplicate input"
        );
        validate_input_schema(input)?;
    }
    ensure!(
        a.inputs
            .iter()
            .map(|input| input.max_bytes as usize)
            .sum::<usize>()
            <= MAX_INPUT_BYTES,
        "action input limit"
    );
    let mut used = BTreeSet::new();
    let mut creates = 0;
    let mut exact = false;
    for (index, step) in a.steps.iter().enumerate() {
        let op = operation(m, step.operation)?;
        let resource = resource(m, op.resource)?;
        if a.steps.len() > 1 {
            ensure!(
                !is_public(op) && !is_capability(op),
                "multi-step action cannot use public or capability operations"
            );
        }
        match op.kind {
            OperationKind::Create => {
                creates += 1;
                ensure!(creates <= 2, "transaction create limit");
                ensure!(step.target == Target::None, "create has no target");
                ensure!(!step.assign.is_empty(), "create requires writable fields");
            }
            OperationKind::Update => {
                ensure!(
                    step.target == Target::Signed,
                    "update requires signed target"
                );
                ensure!(!step.assign.is_empty(), "update requires writable fields");
            }
            OperationKind::Delete => {
                ensure!(a.steps.len() == 1, "delete must be the only step");
                ensure!(
                    step.target == Target::Signed && step.assign.is_empty(),
                    "delete requires signed target and no assignments"
                );
                exact = true;
            }
            _ => anyhow::bail!("action must declare a mutation"),
        }
        let mut assigned = BTreeSet::new();
        for assignment in &step.assign {
            ensure!(assigned.insert(&assignment.field), "duplicate assignment");
            ensure!(
                !matches!(
                    assignment.field.as_str(),
                    "owner" | "tenant" | "id" | "incarnation" | "revision"
                ),
                "protected assignment"
            );
            let field = resource
                .fields
                .iter()
                .find(|field| field.name == assignment.field)
                .ok_or_else(|| anyhow::anyhow!("unknown or protected assignment"))?;
            ensure!(
                op.kind != OperationKind::Create || field.initial.is_none(),
                "initial value is host-applied"
            );
            ensure!(
                op.kind == OperationKind::Create
                    || !matches!(field.kind, FieldKind::Account { .. }),
                "account fields are immutable"
            );
            ensure!(
                op.kind != OperationKind::Update
                    || !matches!(field.kind, FieldKind::Reference { .. }),
                "reference is immutable"
            );
            match &assignment.change {
                Change::Set(value) => {
                    exact |= op.kind == OperationKind::Update;
                    match value {
                        Value::Input(name) => {
                            let input = a
                                .inputs
                                .iter()
                                .find(|input| input.name == *name)
                                .ok_or_else(|| anyhow::anyhow!("undeclared input"))?;
                            ensure!(
                                input_fits(input, field),
                                "input domain does not fit destination"
                            );
                            used.insert(name.as_str());
                        }
                        Value::Constant(value) => {
                            ensure!(
                                !matches!(field.kind, FieldKind::Reference { .. }),
                                "reference requires a declared target"
                            );
                            validate_value(field, value)?;
                        }
                        Value::SignedTarget => {
                            ensure!(
                                reference_field(resource)
                                    .is_some_and(|reference| reference.name == field.name),
                                "signed target requires reference field"
                            );
                            ensure!(
                                reference_resource(m, resource.id)?.map(|target| target.id)
                                    == signed
                                    && signed.is_some(),
                                "wrong signed reference type"
                            );
                        }
                        Value::Created(created) => {
                            let created = usize::from(*created);
                            ensure!(
                                created < index,
                                "created reference must name an earlier step"
                            );
                            let source = operation(m, a.steps[created].operation)?;
                            ensure!(
                                source.kind == OperationKind::Create,
                                "created reference requires create step"
                            );
                            ensure!(
                                reference_field(resource)
                                    .is_some_and(|reference| reference.name == field.name)
                                    && reference_resource(m, resource.id)?
                                        .is_some_and(|target| target.id == source.resource),
                                "wrong created reference type"
                            );
                        }
                    }
                }
                Change::Decrease { by, rejection } | Change::Increase { by, rejection } => {
                    ensure!(
                        op.kind == OperationKind::Update && step.target == Target::Signed,
                        "adjustments require signed update steps"
                    );
                    let FieldKind::Integer {
                        min: Some(min),
                        max: Some(max),
                    } = field.kind
                    else {
                        anyhow::bail!("adjustment requires bounded integer field");
                    };
                    let input = a
                        .inputs
                        .iter()
                        .find(|input| input.name == *by)
                        .ok_or_else(|| anyhow::anyhow!("undeclared adjustment input"))?;
                    let FieldKind::Integer {
                        min: Some(amount_min),
                        max: Some(amount_max),
                    } = input.kind
                    else {
                        anyhow::bail!("adjustment requires bounded integer input");
                    };
                    ensure!(
                        !input.optional
                            && amount_min >= 1
                            && i128::from(amount_max) <= i128::from(max) - i128::from(min),
                        "invalid adjustment amount domain"
                    );
                    ensure!(
                        names.contains(rejection.input.as_str()),
                        "undeclared rejection input"
                    );
                    ensure!(
                        !rejection.message.is_empty()
                            && rejection.message.len() <= 256
                            && !rejection
                                .message
                                .chars()
                                .any(|c| c.is_control() && !matches!(c, '\n' | '\t')),
                        "invalid guard rejection message"
                    );
                    used.insert(by.as_str());
                }
            }
        }
        if op.kind == OperationKind::Create {
            let writable = resource
                .fields
                .iter()
                .filter(|field| field.initial.is_none())
                .count();
            ensure!(
                step.assign.len() == writable,
                "creation requires every writable field"
            );
        }
    }
    ensure!(
        !exact || a.revision == Revision::Exact,
        "identity revision is weaker than required exact revision"
    );
    ensure!(used == names, "unused action input");
    if let Some(inspect) = &a.inspect {
        let read = operation(m, inspect.operation)?;
        ensure!(!is_public(read), "inspection cannot use a public operation");
        ensure!(
            read.kind == OperationKind::Read && read.via.is_none() && Some(read.resource) == signed,
            "invalid inspection operation"
        );
        ensure!(!inspect.fields.is_empty(), "empty inspection");
        projected_fields(resource(m, read.resource)?, &inspect.fields)?;
    }
    validate_layout(m, a)?;
    let destination = route(m, a.redirect.route())?;
    ensure!(
        destination.params.is_empty(),
        "mutation redirect requires an unparameterized route"
    );
    if a.steps.len() == 1
        && operation(m, a.steps[0].operation)?.kind == OperationKind::Delete
        && matches!(
            a.redirect.source,
            RedirectSource::Signed | RedirectSource::Step(0)
        )
    {
        ensure!(
            destination.resource.is_none(),
            "delete destination requires collection route"
        );
        return Ok(());
    }
    let destination_resource = match &a.redirect.source {
        RedirectSource::Signed => {
            signed.ok_or_else(|| anyhow::anyhow!("redirect requires signed target"))?
        }
        RedirectSource::Step(index) | RedirectSource::Reference { step: index, .. } => {
            let step = a
                .steps
                .get(usize::from(*index))
                .ok_or_else(|| anyhow::anyhow!("redirect step out of range"))?;
            let op = operation(m, step.operation)?;
            if let RedirectSource::Reference { field, .. } = &a.redirect.source {
                ensure!(
                    reference_field(resource(m, op.resource)?)
                        .is_some_and(|reference| reference.name == *field),
                    "redirect requires reference field"
                );
                ensure!(
                    destination
                        .operations
                        .iter()
                        .filter(|id| operation(m, **id)
                            .is_ok_and(|read| read.kind == OperationKind::Read
                                && read.via.is_none()
                                && Some(read.resource) == destination.resource))
                        .count()
                        == 1,
                    "parent destination requires one unambiguous resource read"
                );
                reference_resource(m, op.resource)?
                    .expect("validated reference")
                    .id
            } else if op.kind == OperationKind::Delete {
                ensure!(
                    destination.resource.is_none(),
                    "delete destination requires collection route"
                );
                return Ok(());
            } else {
                op.resource
            }
        }
    };
    ensure!(
        destination.resource == Some(destination_resource),
        "invalid outcome route"
    );
    Ok(())
}

fn validate_input_schema(input: &Input) -> Result<()> {
    ensure!(
        !input.label.is_empty()
            && input.label.len() <= 128
            && !input.label.chars().any(char::is_control),
        "invalid input label"
    );
    ensure!(
        input.max_bytes > 0 && input.max_bytes <= 4096,
        "input byte limit"
    );
    match &input.kind {
        FieldKind::Text => {}
        FieldKind::Boolean => ensure!(input.max_bytes >= 5, "boolean input budget"),
        FieldKind::Integer { min, max } => ensure!(
            input.max_bytes >= 20 && min.zip(*max).is_none_or(|(min, max)| min <= max),
            "integer input schema"
        ),
        FieldKind::Choice { variants } => {
            ensure!(
                !variants.is_empty() && variants.len() <= 32,
                "choice input limit"
            );
            let mut keys = BTreeSet::new();
            for variant in variants {
                ensure!(
                    identifier(&variant.key)
                        && keys.insert(&variant.key)
                        && variant.key.len() <= input.max_bytes as usize,
                    "choice input key"
                );
                ensure!(
                    !variant.label.is_empty()
                        && variant.label.len() <= 128
                        && !variant.label.chars().any(char::is_control),
                    "choice input label"
                );
            }
        }
        FieldKind::Account { .. } => ensure!(
            input.max_bytes >= 43 && !input.optional,
            "account inputs must be required and hold an ID"
        ),
        FieldKind::Reference { .. } => anyhow::bail!("invalid input kind"),
    }
    Ok(())
}

fn input_fits(input: &Input, field: &TextField) -> bool {
    if input.optional && !field.optional {
        return false;
    }
    match (&input.kind, &field.kind) {
        (FieldKind::Text, FieldKind::Text) => input.max_bytes <= field.max_bytes,
        (FieldKind::Boolean, FieldKind::Boolean) => true,
        (FieldKind::Account { scope: input }, FieldKind::Account { scope }) => input == scope,
        (
            FieldKind::Integer {
                min: input_min,
                max: input_max,
            },
            FieldKind::Integer { min, max },
        ) => {
            input_min.unwrap_or(i64::MIN) >= min.unwrap_or(i64::MIN)
                && input_max.unwrap_or(i64::MAX) <= max.unwrap_or(i64::MAX)
        }
        (FieldKind::Choice { variants: input }, FieldKind::Choice { variants }) => input
            .iter()
            .all(|input| variants.iter().any(|variant| variant.key == input.key)),
        _ => false,
    }
}

pub(crate) fn reference_field(resource: &Resource) -> Option<&TextField> {
    resource
        .fields
        .iter()
        .find(|f| matches!(f.kind, FieldKind::Reference { .. }))
}
pub(crate) fn reference_resource(m: &Manifest, child: u32) -> Result<Option<&Resource>> {
    match reference_field(resource(m, child)?) {
        Some(TextField {
            kind: FieldKind::Reference { resource: key, .. },
            ..
        }) => Ok(Some(
            m.resources
                .iter()
                .find(|r| &r.name == key)
                .ok_or_else(|| anyhow::anyhow!("unknown parent"))?,
        )),
        _ => Ok(None),
    }
}
pub(crate) fn gate_permits(resource: &Resource, target: &Fields, write: bool) -> bool {
    resource.gate.as_ref().is_none_or(|gate| {
        target.get(&gate.visible.field) == Some(&gate.visible.equals)
            && (!write || target.get(&gate.create_when.field) == Some(&gate.create_when.equals))
    })
}

pub(crate) fn is_public(op: &Operation) -> bool {
    op.policy
        .any
        .iter()
        .flatten()
        .any(|p| *p == Predicate::Public)
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

pub(crate) fn action_fields<'a>(_m: &Manifest, action: &'a Action) -> Result<Vec<&'a Input>> {
    Ok(action.inputs.iter().collect())
}

pub(crate) fn validate_input(_m: &Manifest, action: &Action, fields: &Fields) -> Result<()> {
    validate_inputs(&action.inputs, fields)
}

pub(crate) fn validate_inputs(inputs: &[Input], fields: &Fields) -> Result<()> {
    ensure!(fields.len() == inputs.len(), "unexpected action fields");
    for input in inputs {
        let value = fields
            .get(&input.name)
            .ok_or_else(|| anyhow::anyhow!("missing input"))?;
        ensure!(
            input
                .canonical(value)
                .is_ok_and(|canonical| canonical == *value),
            "noncanonical action input"
        );
    }
    Ok(())
}

pub fn validate_value(field: &TextField, value: &str) -> Result<()> {
    let canonical = field.canonical(value).map_err(anyhow::Error::msg)?;
    ensure!(canonical == value, "noncanonical stored value");
    Ok(())
}

fn validate_field(f: &TextField, fields: &Fields) -> Result<()> {
    let value = fields
        .get(&f.name)
        .ok_or_else(|| anyhow::anyhow!("missing field"))?;
    validate_value(f, value)
}

/// Normalize browser input once, before receipt binding and guest execution.
pub fn canonical_input(m: &Manifest, action: &Action, input: &Fields) -> Result<Fields> {
    ensure!(
        input
            .keys()
            .all(|key| action.inputs.iter().any(|input| input.name == *key)),
        "unexpected action field"
    );
    action_fields(m, action)?
        .into_iter()
        .map(|field| {
            let raw = match input.get(&field.name) {
                Some(value) => value.as_str(),
                None if field.optional => "",
                None if field.kind == FieldKind::Boolean => "false",
                None => return Err(anyhow::anyhow!("missing required field")),
            };
            let value = field.canonical(raw).map_err(anyhow::Error::msg)?;
            Ok((field.name.clone(), value))
        })
        .collect()
}

fn validate_layout(m: &Manifest, action: &Action) -> Result<()> {
    if action.layout.is_empty() {
        return Ok(());
    }
    crate::form_layout::validate(m, action, &action.layout)
}

pub(crate) fn is_capability(op: &Operation) -> bool {
    op.policy
        .any
        .iter()
        .flatten()
        .any(|p| matches!(p, Predicate::Capability))
}
pub(crate) fn anonymous_action(op: &Operation) -> bool {
    (is_public(op) && op.kind == OperationKind::Create) || is_capability(op)
}

#[cfg(test)]
mod tests {
    #[test]
    fn host_rejects_forged_selection_and_disclosure() {
        let mut m = crate::parent_tests::declarations();
        m.resources[0]
            .fields
            .push(field("archived", FieldKind::Boolean, false));
        add_input(
            &mut m.actions[0],
            &m.resources[0].fields.last().unwrap().clone(),
        );
        m.operations[0].filter = vec![Condition {
            field: "archived".into(),
            equals: Operand::Literal("false".into()),
        }];
        m.operations[0].disclose = vec!["archived".into()];
        validate(&m).unwrap();
        let rejects = |bad: Manifest| assert!(validate(&bad).is_err());
        let mut bad = m.clone();
        bad.operations[1].filter = bad.operations[0].filter.clone();
        rejects(bad);
        let mut bad = m.clone();
        bad.operations[1].disclose = vec!["archived".into()];
        rejects(bad);
        let mut bad = m.clone();
        bad.operations[0].filter = vec![m.operations[0].filter[0].clone(); 5];
        rejects(bad);
        let mut bad = m.clone();
        bad.operations[0]
            .filter
            .push(m.operations[0].filter[0].clone());
        rejects(bad);
        for name in ["missing", "body", "thread", "published"] {
            let mut bad = m.clone();
            bad.operations[0].filter[0].field = name.into();
            bad.operations[0].disclose = vec![name.into()];
            rejects(bad);
        }
        for value in ["False", "0", " true "] {
            let mut bad = m.clone();
            bad.operations[0].filter[0].equals = Operand::Literal(value.into());
            rejects(bad);
        }
        for kind in [
            FieldKind::Integer {
                min: None,
                max: None,
            },
            FieldKind::Account {
                scope: AccountScope::SameTenant,
            },
        ] {
            let mut bad = m.clone();
            bad.resources[0].fields.last_mut().unwrap().kind = kind;
            rejects(bad);
        }
        let mut bad = m.clone();
        bad.operations[0].disclose.clear();
        rejects(bad);
        let mut bad = m.clone();
        bad.operations[0].disclose.push("body".into());
        rejects(bad);
        let mut bad = m.clone();
        bad.operations[0].disclose.push("archived".into());
        rejects(bad);
        let mut bad = m.clone();
        bad.operations[0]
            .fields
            .as_mut()
            .unwrap()
            .push("archived".into());
        rejects(bad);
        let mut bad = m.clone();
        bad.operations[0].policy.any = vec![vec![Predicate::Owner]];
        bad.operations[0].visibility = None;
        bad.operations[0].fields = None;
        rejects(bad);
        let mut selected = m.operations[0].clone();
        selected.filter[0].equals = Operand::Literal("true".into());
        let mut changed = m.clone();
        changed.operations[0] = selected;
        assert_ne!(digest(&m).unwrap(), digest(&changed).unwrap());
    }

    #[test]
    fn query_contract_bytes_and_digests_match_recorded_fixtures() {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        let root =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/fixtures/queries");
        for line in include_str!("../../../tools/fixtures/queries/digests.txt").lines() {
            let (name, expected) = line.split_once(' ').unwrap();
            let bytes = std::fs::read(root.join(name)).unwrap();
            let manifest = parse(&bytes).unwrap();
            assert_eq!(serde_json::to_vec(&manifest).unwrap(), bytes, "{name}");
            assert_eq!(
                URL_SAFE_NO_PAD.encode(digest(&manifest).unwrap()),
                expected,
                "{name}"
            );
        }
    }

    use super::*;

    fn field(name: &str, kind: FieldKind, optional: bool) -> TextField {
        TextField {
            name: name.into(),
            label: name.into(),
            max_bytes: 200,
            kind,
            optional,
            initial: None,
        }
    }

    fn add_input(action: &mut Action, field: &TextField) {
        action.inputs.push(Input {
            name: field.name.clone(),
            label: field.label.clone(),
            kind: field.kind.clone(),
            optional: field.optional,
            max_bytes: field.max_bytes,
        });
        action.steps[0].assign.push(Assignment {
            field: field.name.clone(),
            change: Change::Set(Value::Input(field.name.clone())),
        });
    }

    fn schema(fields: Vec<TextField>) -> Manifest {
        let mut manifest = crate::test_support::manifest();
        manifest.actions[0].inputs.clear();
        manifest.actions[0].steps[0].assign.clear();
        for field in &fields {
            add_input(&mut manifest.actions[0], field);
        }
        manifest.resources[0].fields = fields;
        validate(&manifest).unwrap();
        manifest
    }

    #[test]
    fn canonical_input_fills_only_schema_defined_absence() {
        let manifest = schema(vec![
            field("done", FieldKind::Boolean, false),
            field("flag", FieldKind::Boolean, true),
            field("details", FieldKind::Text, true),
            field(
                "estimate",
                FieldKind::Integer {
                    min: None,
                    max: None,
                },
                true,
            ),
        ]);
        let action = &manifest.actions[0];
        let input = canonical_input(&manifest, action, &Fields::new()).unwrap();
        assert_eq!(
            input,
            Fields::from([
                ("done".into(), "false".into()),
                ("flag".into(), "".into()),
                ("details".into(), "".into()),
                ("estimate".into(), "".into()),
            ])
        );
        validate_input(&manifest, action, &input).unwrap();
        assert!(
            canonical_input(
                &manifest,
                action,
                &Fields::from([("foreign".into(), "x".into())])
            )
            .is_err()
        );
        let required = schema(vec![field("body", FieldKind::Text, false)]);
        assert!(canonical_input(&required, &required.actions[0], &Fields::new()).is_err());
    }

    #[test]
    fn integer_forms_have_one_canonical_value_and_checked_bounds() {
        let manifest = schema(vec![field(
            "estimate",
            FieldKind::Integer {
                min: Some(-5),
                max: Some(10),
            },
            false,
        )]);
        let action = &manifest.actions[0];
        let canonical = |raw: &str| {
            canonical_input(
                &manifest,
                action,
                &Fields::from([("estimate".into(), raw.into())]),
            )
        };
        assert_eq!(canonical("+01").unwrap(), canonical("1").unwrap());
        assert_eq!(canonical("-0").unwrap()["estimate"], "0");
        for valid in ["-5", "10"] {
            assert!(canonical(valid).is_ok());
        }
        for invalid in [
            "-6",
            "11",
            "9223372036854775808",
            "-9223372036854775809",
            "1.0",
            "1e0",
            " 1",
            "",
        ] {
            assert!(canonical(invalid).is_err(), "{invalid}");
        }
        // Stored values are stricter than transport input: canonicalize once,
        // then reject any noncanonical value crossing back from persistence.
        assert!(validate_value(&manifest.resources[0].fields[0], "+01").is_err());
    }

    #[test]
    fn text_canonicalization_preserves_whitespace_and_normalizes_newlines() {
        let manifest = schema(vec![field("body", FieldKind::Text, false)]);
        let action = &manifest.actions[0];
        let input = canonical_input(
            &manifest,
            action,
            &Fields::from([("body".into(), " \r\nline\r\t ".into())]),
        )
        .unwrap();
        assert_eq!(input["body"], " \nline\n\t ");
        let whitespace = canonical_input(
            &manifest,
            action,
            &Fields::from([("body".into(), "   ".into())]),
        )
        .unwrap();
        assert_eq!(whitespace["body"], "   ");
        assert!(
            canonical_input(
                &manifest,
                action,
                &Fields::from([("body".into(), "\0".into())])
            )
            .is_err()
        );
        assert!(
            canonical_input(
                &manifest,
                action,
                &Fields::from([("body".into(), "é".repeat(101))])
            )
            .is_err()
        );
    }

    #[test]
    fn enum_keys_and_boolean_encoding_are_host_validated() {
        let manifest = schema(vec![
            field(
                "priority",
                FieldKind::Choice {
                    variants: vec![ChoiceVariant {
                        key: "high".into(),
                        label: "High priority".into(),
                    }],
                },
                false,
            ),
            field("done", FieldKind::Boolean, false),
        ]);
        let action = &manifest.actions[0];
        let canonical = canonical_input(
            &manifest,
            action,
            &Fields::from([
                ("priority".into(), "high".into()),
                ("done".into(), "on".into()),
            ]),
        )
        .unwrap();
        assert_eq!(canonical["done"], "true");
        for invalid in ["High priority", "unknown", ""] {
            assert!(
                canonical_input(
                    &manifest,
                    action,
                    &Fields::from([("priority".into(), invalid.into())])
                )
                .is_err()
            );
        }
        assert!(
            canonical_input(
                &manifest,
                action,
                &Fields::from([
                    ("priority".into(), "high".into()),
                    ("done".into(), "yes".into()),
                ])
            )
            .is_err()
        );
    }

    fn layout_field(name: &str, control: Control) -> FormInstruction {
        FormInstruction::Field {
            name: name.into(),
            control,
        }
    }

    fn submit() -> FormInstruction {
        FormInstruction::Submit {
            label: "Save changes".into(),
        }
    }

    #[test]
    fn optional_boolean_requires_a_control_that_represents_unset() {
        let mut manifest = schema(vec![field("flag", FieldKind::Boolean, true)]);
        manifest.actions[0].layout = vec![layout_field("flag", Control::Select), submit()];
        validate(&manifest).unwrap();
        manifest.actions[0].layout[0] = layout_field("flag", Control::Checkbox);
        assert!(validate(&manifest).is_err());
        manifest.resources[0].fields[0].optional = false;
        manifest.actions[0].inputs[0].optional = false;
        validate(&manifest).unwrap();
        manifest.actions[0].layout[0] = layout_field("flag", Control::Select);
        assert!(validate(&manifest).is_err());
    }

    #[test]
    fn blueprint_requires_exactly_the_declared_fields_and_one_submit() {
        let mut manifest = schema(vec![field("body", FieldKind::Text, false)]);
        manifest.actions[0].layout = vec![
            FormInstruction::Begin(Container::Section),
            FormInstruction::Text("Review changes".into()),
            layout_field("body", Control::Textarea { rows: 12 }),
            submit(),
            FormInstruction::End,
        ];
        validate(&manifest).unwrap();
        for invalid in [
            vec![submit()],
            vec![
                layout_field("body", Control::Auto),
                layout_field("body", Control::Auto),
                submit(),
            ],
            vec![layout_field("foreign", Control::Auto), submit()],
            vec![layout_field("body", Control::Auto)],
            vec![layout_field("body", Control::Auto), submit(), submit()],
            vec![
                FormInstruction::Begin(Container::Paragraph),
                layout_field("body", Control::Auto),
                FormInstruction::End,
                submit(),
            ],
            vec![
                layout_field("body", Control::Textarea { rows: 0 }),
                submit(),
            ],
            vec![
                FormInstruction::Begin(Container::Section),
                layout_field("body", Control::Auto),
                submit(),
            ],
        ] {
            manifest.actions[0].layout = invalid;
            assert!(validate(&manifest).is_err());
        }
    }

    #[test]
    fn admission_checks_explicit_paths_and_overlaps() {
        let mut manifest = crate::test_support::manifest();
        manifest.routes[1].path = "/notes/{note}".into();
        validate(&manifest).unwrap();
        let mut duplicate = manifest.routes[1].clone();
        duplicate.id = 3;
        duplicate.path = "/notes/{other}".into();
        manifest.routes.push(duplicate);
        assert!(validate(&manifest).is_err());
        manifest.routes[2].path = "/notes".into();
        assert!(validate(&manifest).is_err());
        manifest.routes.pop();
        manifest.routes[1].path = "/notes/{one}/{two}".into();
        assert!(validate(&manifest).is_err());
        manifest.routes[1].path = "/notes/{note}".into();
        let mut reserved = manifest.routes[0].clone();
        reserved.id = 3;
        reserved.path = "/login".into();
        manifest.routes.push(reserved);
        validate(&manifest).unwrap();
        assert!(crate::Presentation::default().validate(&manifest).is_err());
    }
}

#[cfg(test)]
mod pagination_tests {
    use super::*;
    #[test]
    fn host_rejects_forged_list_settings_and_contract_binds_page_size() {
        let mut m = crate::test_support::manifest();
        m.operations[0].list = Some(ListSettings {
            preview: None,
            order: ListOrder::CreatedAsc,
            page_size: 20,
        });
        validate(&m).unwrap();
        let original = digest(&m).unwrap();
        m.operations[0].list.as_mut().unwrap().page_size = 3;
        assert_ne!(digest(&m).unwrap(), original);
        for size in [0, 21, 255] {
            m.operations[0].list.as_mut().unwrap().page_size = size;
            assert!(validate(&m).is_err());
        }
        m.operations[0].list = None;
        m.operations[1].list = Some(ListSettings {
            preview: None,
            order: ListOrder::CreatedAsc,
            page_size: 3,
        });
        assert!(validate(&m).is_err());
    }
}

#[cfg(test)]
mod initial_tests {
    use super::*;
    fn declarations() -> Manifest {
        let mut m = crate::test_support::manifest();
        m.resources[0].fields.push(TextField {
            name: "published".into(),
            label: "Published".into(),
            kind: FieldKind::Boolean,
            optional: false,
            initial: Some("true".into()),
            max_bytes: 5,
        });
        m
    }
    #[test]
    fn initial_admission_and_digest_boundaries() {
        let m = declarations();
        validate(&m).unwrap();
        for value in ["on", "TRUE", "", "false "] {
            let mut bad = m.clone();
            bad.resources[0].fields[1].initial = Some(value.into());
            assert!(validate(&bad).is_err(), "{value}");
        }
        for kind in [
            FieldKind::Text,
            FieldKind::Integer {
                min: Some(0),
                max: Some(10),
            },
            FieldKind::Choice { variants: vec![] },
        ] {
            let mut bad = m.clone();
            bad.resources[0].fields[1].kind = kind;
            assert!(validate(&bad).is_err());
        }
        let mut choice = m.clone();
        choice.resources[0].fields[1].kind = FieldKind::Choice {
            variants: vec![
                ChoiceVariant {
                    key: "draft".into(),
                    label: "Draft".into(),
                },
                ChoiceVariant {
                    key: "live".into(),
                    label: "Live".into(),
                },
            ],
        };
        assert!(validate(&choice).is_err());
        choice.resources[0].fields[1].initial = Some("draft".into());
        validate(&choice).unwrap();
        let mut parent = m.clone();
        parent.resources[0].fields[1].kind = FieldKind::Reference {
            resource: "notes".into(),
        };
        assert!(
            validate(&parent)
                .unwrap_err()
                .to_string()
                .contains("initial requires")
        );
        let mut bad = m.clone();
        bad.resources[0].fields[1].optional = true;
        assert!(validate(&bad).is_err());
        bad = m.clone();
        bad.resources[0].fields[1].max_bytes = 3;
        assert!(validate(&bad).is_err());
        bad = m.clone();
        bad.actions[0].steps[0].assign.push(Assignment {
            field: "published".into(),
            change: Change::Set(Value::Constant("true".into())),
        });
        assert!(
            validate(&bad)
                .unwrap_err()
                .to_string()
                .contains("initial value is host-applied")
        );
        bad = m.clone();
        bad.actions[0].inputs.clear();
        bad.actions[0].steps[0].assign.clear();
        bad.resources[0].fields.remove(0);
        assert!(
            validate(&bad)
                .unwrap_err()
                .to_string()
                .contains("create requires writable fields")
        );
        for value in ["on", "false"] {
            assert!(
                canonical_input(
                    &m,
                    &m.actions[0],
                    &Fields::from([
                        ("body".into(), "hello".into()),
                        ("published".into(), value.into())
                    ])
                )
                .is_err()
            );
        }
        let mut changed = m.clone();
        changed.resources[0].fields[1].initial = Some("false".into());
        assert_ne!(digest(&m).unwrap(), digest(&changed).unwrap());
        assert_eq!(
            crate::schema::digest(&m.resources).unwrap(),
            crate::schema::digest(&changed.resources).unwrap()
        );
    }
}

#[cfg(test)]
mod transaction_tests {
    use super::*;

    fn field(name: &str, kind: FieldKind, max_bytes: u32) -> TextField {
        TextField {
            name: name.into(),
            label: name.into(),
            kind,
            max_bytes,
            optional: false,
            initial: None,
        }
    }
    fn set(field: &str, value: Value) -> Assignment {
        Assignment {
            field: field.into(),
            change: Change::Set(value),
        }
    }
    fn declarations() -> Manifest {
        let mut m = crate::test_support::manifest();
        m.resources[0].fields = vec![field(
            "stock",
            FieldKind::Integer {
                min: Some(0),
                max: Some(10),
            },
            20,
        )];
        m.resources.push(Resource {
            gate: None,
            id: 2,
            name: "orders".into(),
            fields: vec![
                field(
                    "quantity",
                    FieldKind::Integer {
                        min: Some(1),
                        max: Some(10),
                    },
                    20,
                ),
                field(
                    "product",
                    FieldKind::Reference {
                        resource: "notes".into(),
                    },
                    19,
                ),
            ],
        });
        m.resources.push(Resource {
            gate: None,
            id: 3,
            name: "order_notes".into(),
            fields: vec![
                field("body", FieldKind::Text, 200),
                field(
                    "order",
                    FieldKind::Reference {
                        resource: "orders".into(),
                    },
                    19,
                ),
            ],
        });
        m.operations[2].kind = OperationKind::Update;
        let mut order_create = m.operations[2].clone();
        order_create.id = 4;
        order_create.resource = 2;
        order_create.kind = OperationKind::Create;
        order_create.bind = Some(Bind {
            field: "product".into(),
            eligible: 2,
        });
        let mut order_read = m.operations[1].clone();
        order_read.id = 5;
        order_read.resource = 2;
        let mut note_create = order_create.clone();
        note_create.id = 6;
        note_create.resource = 3;
        note_create.bind = Some(Bind {
            field: "order".into(),
            eligible: 5,
        });
        let mut note_read = order_read.clone();
        note_read.id = 7;
        note_read.resource = 3;
        m.operations
            .extend([order_create, order_read, note_create, note_read]);
        m.routes[0].forms.clear();
        m.routes[1].forms = vec![1];
        let mut order_route = m.routes[1].clone();
        order_route.id = 3;
        order_route.path = "/orders/{order}".into();
        order_route.resource = Some(2);
        order_route.operations = vec![5];
        order_route.forms.clear();
        let mut note_route = order_route.clone();
        note_route.id = 4;
        note_route.path = "/order_notes/{note}".into();
        note_route.resource = Some(3);
        note_route.operations = vec![7];
        m.routes.extend([order_route, note_route]);
        let a = &mut m.actions[0];
        a.inputs = vec![
            Input {
                name: "quantity".into(),
                label: "Quantity".into(),
                kind: FieldKind::Integer {
                    min: Some(1),
                    max: Some(10),
                },
                optional: false,
                max_bytes: 20,
            },
            Input {
                name: "body".into(),
                label: "Body".into(),
                kind: FieldKind::Text,
                optional: false,
                max_bytes: 200,
            },
        ];
        a.revision = Revision::Identity;
        a.redirect = Redirect {
            route: 3,
            source: RedirectSource::Step(1),
        };
        a.steps = vec![
            Step {
                operation: 3,
                target: Target::Signed,
                assign: vec![Assignment {
                    field: "stock".into(),
                    change: Change::Decrease {
                        by: "quantity".into(),
                        rejection: GuardRejection {
                            input: "quantity".into(),
                            message: "Not enough stock".into(),
                        },
                    },
                }],
            },
            Step {
                operation: 4,
                target: Target::None,
                assign: vec![
                    set("quantity", Value::Input("quantity".into())),
                    set("product", Value::SignedTarget),
                ],
            },
            Step {
                operation: 6,
                target: Target::None,
                assign: vec![
                    set("body", Value::Input("body".into())),
                    set("order", Value::Created(1)),
                ],
            },
        ];
        validate(&m).unwrap();
        m
    }

    #[test]
    fn transaction_admission_allows_initialized_field_updates_and_account_create_inputs() {
        let mut initialized = crate::test_support::manifest();
        initialized.resources[0].fields.push(TextField {
            name: "published".into(),
            label: "Published".into(),
            kind: FieldKind::Boolean,
            optional: false,
            initial: Some("false".into()),
            max_bytes: 5,
        });
        validate(&initialized).unwrap();
        let mut forbidden = initialized.clone();
        forbidden.actions[0].steps[0]
            .assign
            .push(set("published", Value::Constant("true".into())));
        assert!(
            validate(&forbidden)
                .unwrap_err()
                .to_string()
                .contains("initial value")
        );
        initialized.operations[2].kind = OperationKind::Update;
        initialized.actions[0].steps[0].target = Target::Signed;
        initialized.actions[0].steps[0]
            .assign
            .push(set("published", Value::Constant("true".into())));
        initialized.routes[0].forms.clear();
        initialized.routes[1].forms = vec![1];
        initialized.actions[0].redirect.source = RedirectSource::Signed;
        validate(&initialized).unwrap();

        let mut account = crate::test_support::manifest();
        let recipient = field(
            "recipient",
            FieldKind::Account {
                scope: AccountScope::SameTenant,
            },
            43,
        );
        account.resources[0].fields.push(recipient.clone());
        account.actions[0].inputs.push(Input {
            name: recipient.name.clone(),
            label: recipient.label.clone(),
            kind: recipient.kind.clone(),
            optional: false,
            max_bytes: 43,
        });
        account.actions[0].steps[0]
            .assign
            .push(set("recipient", Value::Input("recipient".into())));
        validate(&account).unwrap();
        account.operations[2].kind = OperationKind::Update;
        account.actions[0].steps[0].target = Target::Signed;
        account.routes[0].forms.clear();
        account.routes[1].forms = vec![1];
        account.actions[0].redirect.source = RedirectSource::Signed;
        assert!(
            validate(&account)
                .unwrap_err()
                .to_string()
                .contains("account fields are immutable")
        );
    }

    #[test]
    fn transaction_admission_rejects_step_create_and_delete_combinations() {
        let m = declarations();
        let mut bad = m.clone();
        bad.actions[0].steps.clear();
        assert!(validate(&bad).is_err());
        let mut bad = m.clone();
        bad.actions[0].steps = vec![m.actions[0].steps[0].clone(); 5];
        assert!(validate(&bad).is_err());
        let mut bad = m.clone();
        bad.actions[0].steps.push(m.actions[0].steps[2].clone());
        assert!(
            validate(&bad)
                .unwrap_err()
                .to_string()
                .contains("create limit")
        );
        let mut bad = m.clone();
        bad.operations[2].kind = OperationKind::Delete;
        bad.actions[0].steps[0].assign.clear();
        bad.actions[0].revision = Revision::Exact;
        assert!(
            validate(&bad)
                .unwrap_err()
                .to_string()
                .contains("only step")
        );
        for (index, target) in [(0, Target::None), (1, Target::Signed)] {
            let mut bad = m.clone();
            bad.actions[0].steps[index].target = target;
            assert!(validate(&bad).is_err());
        }
        let mut bad = m.clone();
        bad.operations[2].kind = OperationKind::Read;
        assert!(validate(&bad).is_err());
    }

    #[test]
    fn transaction_admission_rejects_forward_wrong_and_constant_references() {
        let m = declarations();
        for value in [
            Value::Created(2),
            Value::Created(3),
            Value::Created(0),
            Value::SignedTarget,
            Value::Constant("1".into()),
            Value::Input("body".into()),
        ] {
            let mut bad = m.clone();
            bad.actions[0].steps[2].assign[1].change = Change::Set(value);
            assert!(validate(&bad).is_err());
        }
        let mut bad = m.clone();
        bad.actions[0].steps[2].assign[0].change = Change::Set(Value::Created(1));
        assert!(validate(&bad).is_err());
        let mut bad = m.clone();
        bad.routes[1].operations.clear();
        assert!(validate(&bad).is_err());
        let mut bad = m.clone();
        bad.operations[3].bind.as_mut().unwrap().eligible = 5;
        assert!(validate(&bad).is_err());
    }

    #[test]
    fn transaction_admission_rejects_duplicate_protected_and_missing_assignments() {
        let m = declarations();
        let mut bad = m.clone();
        bad.actions[0].steps[1].assign[1] = bad.actions[0].steps[1].assign[0].clone();
        assert!(validate(&bad).is_err());
        for name in [
            "owner",
            "tenant",
            "id",
            "incarnation",
            "revision",
            "missing",
        ] {
            let mut bad = m.clone();
            bad.actions[0].steps[1].assign[0].field = name.into();
            if name != "missing" {
                bad.resources[1].fields[0].name = name.into();
            }
            assert!(validate(&bad).is_err(), "{name}");
        }
        let mut bad = m.clone();
        bad.resources[1].fields[0].initial = Some("1".into());
        assert!(validate(&bad).is_err());
        let mut bad = m.clone();
        bad.resources[1].fields[0].kind = FieldKind::Account {
            scope: AccountScope::SameTenant,
        };
        bad.resources[1].fields[0].max_bytes = 43;
        assert!(validate(&bad).is_err());
        let mut bad = m.clone();
        bad.actions[0].steps[1].assign.pop();
        assert!(validate(&bad).is_err());
        let mut bad = m.clone();
        bad.actions[0].steps[0].assign.clear();
        assert!(validate(&bad).is_err());
        let mut bad = m.clone();
        bad.actions[0].steps[0].operation = 999;
        assert!(validate(&bad).is_err());
        let mut bad = m.clone();
        bad.operations[3].kind = OperationKind::Update;
        bad.operations[3].bind = None;
        bad.actions[0].steps[1].target = Target::Signed;
        assert!(validate(&bad).is_err());
    }

    #[test]
    fn transaction_admission_rejects_undeclared_unused_duplicate_and_invalid_inputs() {
        let m = declarations();
        let mut bad = m.clone();
        bad.actions[0].steps[1].assign[0].change = Change::Set(Value::Input("missing".into()));
        assert!(validate(&bad).is_err());
        let mut bad = m.clone();
        bad.actions[0].inputs.push(Input {
            name: "unused".into(),
            ..m.actions[0].inputs[1].clone()
        });
        assert!(validate(&bad).is_err());
        let mut bad = m.clone();
        bad.actions[0].inputs.push(m.actions[0].inputs[0].clone());
        assert!(validate(&bad).is_err());
        for kind in [
            FieldKind::Account {
                scope: AccountScope::SameTenant,
            },
            FieldKind::Reference {
                resource: "notes".into(),
            },
            FieldKind::Integer {
                min: Some(10),
                max: Some(1),
            },
            FieldKind::Choice { variants: vec![] },
        ] {
            let mut bad = m.clone();
            bad.actions[0].inputs[1].kind = kind;
            assert!(validate(&bad).is_err());
        }
        for bytes in [0, 201, 4097] {
            let mut bad = m.clone();
            bad.actions[0].inputs[1].max_bytes = bytes;
            assert!(validate(&bad).is_err());
        }
        let mut bad = m.clone();
        bad.actions[0].inputs[1].optional = true;
        assert!(validate(&bad).is_err());
    }

    #[test]
    fn transaction_admission_rejects_create_unbounded_noninteger_and_invalid_adjustments() {
        let m = declarations();
        let guard = m.actions[0].steps[0].assign[0].change.clone();
        let mut bad = m.clone();
        bad.actions[0].steps[1].assign[0].change = guard;
        assert!(
            validate(&bad)
                .unwrap_err()
                .to_string()
                .contains("signed update")
        );
        for kind in [
            FieldKind::Text,
            FieldKind::Integer {
                min: None,
                max: Some(10),
            },
            FieldKind::Integer {
                min: Some(0),
                max: None,
            },
        ] {
            let mut bad = m.clone();
            bad.resources[0].fields[0].kind = kind;
            assert!(validate(&bad).is_err());
        }
        for min in [None, Some(0), Some(-1)] {
            let mut bad = m.clone();
            bad.actions[0].inputs[0].kind = FieldKind::Integer { min, max: Some(10) };
            assert!(validate(&bad).is_err());
        }
        for max in [None, Some(11)] {
            let mut bad = m.clone();
            bad.actions[0].inputs[0].kind = FieldKind::Integer { min: Some(1), max };
            assert!(validate(&bad).is_err());
        }
        let mut bad = m.clone();
        bad.actions[0].inputs[0].optional = true;
        assert!(validate(&bad).is_err());
        let mut bad = m.clone();
        if let Change::Decrease { rejection, .. } = &mut bad.actions[0].steps[0].assign[0].change {
            rejection.input = "missing".into();
        }
        assert!(validate(&bad).is_err());
        let mut bad = m.clone();
        if let Change::Decrease { by, .. } = &mut bad.actions[0].steps[0].assign[0].change {
            *by = "missing".into();
        }
        assert!(validate(&bad).is_err());
    }

    #[test]
    fn transaction_admission_checks_revision_and_multistep_authority() {
        let m = declarations();
        let mut bad = m.clone();
        bad.actions[0].steps[0].assign[0].change = Change::Set(Value::Constant("5".into()));
        assert!(
            validate(&bad)
                .unwrap_err()
                .to_string()
                .contains("exact revision")
        );
        bad.actions[0].revision = Revision::Exact;
        validate(&bad).unwrap();
        for predicate in [Predicate::Public, Predicate::Capability] {
            let mut bad = m.clone();
            if predicate == Predicate::Public {
                bad.operations[3].policy.any = vec![vec![predicate]];
            } else {
                bad.operations[2].policy.any = vec![vec![predicate]];
            }
            assert!(
                validate(&bad)
                    .unwrap_err()
                    .to_string()
                    .contains("multi-step")
            );
        }
    }

    #[test]
    fn transaction_input_domains_fit_integer_text_choice_and_optionality() {
        let integer = field(
            "quantity",
            FieldKind::Integer {
                min: Some(-10),
                max: Some(10),
            },
            20,
        );
        let mut input = Input {
            name: "quantity".into(),
            label: "Quantity".into(),
            kind: FieldKind::Integer {
                min: Some(-5),
                max: Some(5),
            },
            optional: false,
            max_bytes: 20,
        };
        assert!(input_fits(&input, &integer));
        for kind in [
            FieldKind::Integer {
                min: Some(-11),
                max: Some(5),
            },
            FieldKind::Integer {
                min: Some(-5),
                max: Some(11),
            },
            FieldKind::Integer {
                min: None,
                max: Some(5),
            },
            FieldKind::Boolean,
        ] {
            input.kind = kind;
            assert!(!input_fits(&input, &integer));
        }
        let choice = field(
            "state",
            FieldKind::Choice {
                variants: vec![
                    ChoiceVariant {
                        key: "draft".into(),
                        label: "Draft".into(),
                    },
                    ChoiceVariant {
                        key: "live".into(),
                        label: "Live".into(),
                    },
                ],
            },
            20,
        );
        input.kind = FieldKind::Choice {
            variants: vec![ChoiceVariant {
                key: "draft".into(),
                label: "Different presentation".into(),
            }],
        };
        assert!(input_fits(&input, &choice));
        input.kind = FieldKind::Choice {
            variants: vec![ChoiceVariant {
                key: "missing".into(),
                label: "Missing".into(),
            }],
        };
        assert!(!input_fits(&input, &choice));
        let text = field("body", FieldKind::Text, 20);
        input.kind = FieldKind::Text;
        input.max_bytes = 21;
        assert!(!input_fits(&input, &text));
        input.max_bytes = 20;
        input.optional = true;
        assert!(!input_fits(&input, &text));
    }

    #[test]
    fn transaction_adjustment_span_uses_i128_and_inputs_are_shared() {
        let mut m = declarations();
        m.resources[0].fields[0].kind = FieldKind::Integer {
            min: Some(i64::MIN),
            max: Some(i64::MAX),
        };
        m.resources[1].fields[0].kind = FieldKind::Integer {
            min: Some(1),
            max: Some(i64::MAX),
        };
        m.actions[0].inputs[0].kind = FieldKind::Integer {
            min: Some(1),
            max: Some(i64::MAX),
        };
        validate(&m).unwrap();
        let input = canonical_input(
            &m,
            &m.actions[0],
            &Fields::from([
                ("quantity".into(), "+01".into()),
                ("body".into(), "note".into()),
            ]),
        )
        .unwrap();
        assert_eq!(input.len(), 2);
        assert_eq!(input["quantity"], "1");
        for invalid in ["0", "-1", "9223372036854775808"] {
            assert!(
                canonical_input(
                    &m,
                    &m.actions[0],
                    &Fields::from([
                        ("quantity".into(), invalid.into()),
                        ("body".into(), "note".into())
                    ])
                )
                .is_err()
            );
        }
    }

    #[test]
    fn transaction_digest_covers_input_assignment_constant_order_guard_revision_inspection_redirect()
     {
        let m = declarations();
        let original = digest(&m).unwrap();
        let changed = |bad: Manifest| assert_ne!(digest(&bad).unwrap(), original);
        let mut bad = m.clone();
        bad.actions[0].inputs[1].label = "Order note".into();
        changed(bad);
        let mut bad = m.clone();
        bad.actions[0].steps[1].assign.swap(0, 1);
        changed(bad);
        let mut bad = m.clone();
        bad.actions[0].steps[2].assign[0].change = Change::Set(Value::Constant("note".into()));
        bad.actions[0].inputs.pop();
        changed(bad);
        let mut bad = m.clone();
        bad.actions[0].steps.swap(0, 1);
        bad.actions[0].steps[2].assign[1].change = Change::Set(Value::Created(0));
        bad.actions[0].redirect.source = RedirectSource::Step(0);
        changed(bad);
        let mut bad = m.clone();
        if let Change::Decrease { rejection, .. } = &mut bad.actions[0].steps[0].assign[0].change {
            rejection.message = "Out of stock".into();
        }
        changed(bad);
        let mut bad = m.clone();
        bad.actions[0].revision = Revision::Exact;
        changed(bad);
        let mut bad = m.clone();
        bad.actions[0].inspect = Some(Inspection {
            operation: 2,
            fields: vec!["stock".into()],
        });
        changed(bad);
        let mut bad = m.clone();
        bad.actions[0].redirect = Redirect {
            route: 2,
            source: RedirectSource::Signed,
        };
        changed(bad);
    }
}
