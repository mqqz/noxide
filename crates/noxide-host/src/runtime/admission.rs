use anyhow::{Result, ensure};
use wasmparser::{
    ComponentAlias, ComponentExternalKind, ComponentInstance, ComponentOuterAliasKind,
    ComponentTypeRef, Instance, Payload,
};

const MAX_EXPANDED_INSTANCES: usize = 1024;
const MAX_EXPANDED_COMPONENT_BYTES: usize = 8 * 1024 * 1024;
const MAX_COMPONENT_DEPTH: usize = 32;

#[derive(Clone, Copy)]
struct Expansion {
    instances: usize,
    bytes: usize,
}

impl Expansion {
    fn add(&mut self, other: Self) -> Result<()> {
        self.instances = self.instances.saturating_add(other.instances);
        self.bytes = self.bytes.saturating_add(other.bytes);
        ensure!(
            self.instances <= MAX_EXPANDED_INSTANCES,
            "expanded instance limit"
        );
        ensure!(
            self.bytes <= MAX_EXPANDED_COMPONENT_BYTES,
            "expanded component byte limit"
        );
        Ok(())
    }
}

struct Scope {
    expansion: Expansion,
    components: Vec<Expansion>,
}

impl Scope {
    fn new(bytes: usize) -> Self {
        Self {
            expansion: Expansion {
                instances: 1,
                bytes,
            },
            components: Vec::new(),
        }
    }

    fn component(&self, index: u32) -> Result<Expansion> {
        self.components
            .get(index as usize)
            .copied()
            .ok_or_else(|| anyhow::anyhow!("invalid component index during admission"))
    }
}

// Summarize definitions in binary order, without materializing the expanded
// graph. Each instantiation adds the callee's entire cost, even for empty
// components. Definitions and outer aliases can only refer to earlier, finished
// definitions, so each summary is final and this pass is linear in input size.
// Component-valued imports and instance aliases need argument-sensitive analysis;
// fail closed on those rather than assigning them an unsound zero cost.
struct ExpansionBudget {
    scopes: Vec<Scope>,
    in_core_module: bool,
}

impl ExpansionBudget {
    fn new(bytes: usize) -> Self {
        Self {
            scopes: vec![Scope::new(bytes)],
            in_core_module: false,
        }
    }

    fn payload(&mut self, payload: &Payload<'_>) -> Result<()> {
        if self.in_core_module {
            if matches!(payload, Payload::End(_)) {
                self.in_core_module = false;
            }
            return Ok(());
        }
        let scope = self
            .scopes
            .last_mut()
            .ok_or_else(|| anyhow::anyhow!("missing component scope"))?;
        match payload {
            Payload::ModuleSection { .. } => self.in_core_module = true,
            Payload::ComponentSection {
                unchecked_range, ..
            } => {
                ensure!(
                    self.scopes.len() < MAX_COMPONENT_DEPTH,
                    "component nesting limit"
                );
                self.scopes.push(Scope::new(unchecked_range.len()));
            }
            Payload::End(_) => {
                let finished = self.scopes.pop().unwrap();
                if let Some(parent) = self.scopes.last_mut() {
                    parent.components.push(finished.expansion);
                }
            }
            Payload::ComponentInstanceSection(section) => {
                for instance in section.clone() {
                    if let ComponentInstance::Instantiate {
                        component_index, ..
                    } = instance?
                    {
                        scope.expansion.add(scope.component(component_index)?)?;
                    }
                }
            }
            Payload::InstanceSection(section) => {
                for instance in section.clone() {
                    if matches!(instance?, Instance::Instantiate { .. }) {
                        scope.expansion.add(Expansion {
                            instances: 1,
                            bytes: 0,
                        })?;
                    }
                }
            }
            Payload::ComponentAliasSection(section) => {
                for alias in section.clone() {
                    match alias? {
                        ComponentAlias::Outer {
                            kind: ComponentOuterAliasKind::Component,
                            count,
                            index,
                        } => {
                            let outer = self
                                .scopes
                                .len()
                                .checked_sub(count as usize)
                                .and_then(|remaining| remaining.checked_sub(1))
                                .ok_or_else(|| anyhow::anyhow!("invalid outer component alias"))?;
                            let expansion = self.scopes[outer].component(index)?;
                            self.scopes.last_mut().unwrap().components.push(expansion);
                        }
                        ComponentAlias::InstanceExport {
                            kind: ComponentExternalKind::Component,
                            ..
                        } => {
                            anyhow::bail!("component-valued instance aliases are not admitted");
                        }
                        _ => {}
                    }
                }
            }
            Payload::ComponentImportSection(section) => {
                for import in section.clone() {
                    ensure!(
                        !matches!(import?.ty, ComponentTypeRef::Component(_)),
                        "component-valued imports are not admitted"
                    );
                }
            }
            Payload::ComponentExportSection(section) => {
                for export in section.clone() {
                    let export = export?;
                    if export.kind == ComponentExternalKind::Component {
                        // Component exports also append an alias to the index space.
                        scope.components.push(scope.component(export.index)?);
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }
}

pub(super) fn check(bytes: &[u8]) -> Result<()> {
    ensure!(
        bytes.starts_with(b"\0asm\x0d\0\x01\0") && bytes.len() <= 2 * 1024 * 1024,
        "not an admitted portable component"
    );
    let mut functions = 0u32;
    let mut operators = 0usize;
    let mut expansion = ExpansionBudget::new(bytes.len());
    for payload in wasmparser::Parser::new(0).parse_all(bytes) {
        let payload = payload?;
        expansion.payload(&payload)?;
        match payload {
            wasmparser::Payload::FunctionSection(s) => {
                functions = functions
                    .checked_add(s.count())
                    .ok_or_else(|| anyhow::anyhow!("function limit"))?;
                ensure!(functions <= 4096, "function limit");
            }
            wasmparser::Payload::CodeSectionEntry(body) => {
                let reader = body.get_operators_reader()?;
                for op in reader {
                    op?;
                    operators += 1;
                    ensure!(operators <= 500_000, "code limit");
                }
            }
            wasmparser::Payload::ComponentCanonicalSection(section) => {
                for function in section {
                    match function? {
                        wasmparser::CanonicalFunction::Lift { options, .. }
                        | wasmparser::CanonicalFunction::Lower { options, .. } => {
                            ensure!(
                                !options.iter().any(|o| matches!(
                                    o,
                                    wasmparser::CanonicalOption::PostReturn(_)
                                        | wasmparser::CanonicalOption::Async
                                        | wasmparser::CanonicalOption::Callback(_)
                                        | wasmparser::CanonicalOption::Gc
                                )),
                                "unsupported canonical cleanup or concurrency"
                            );
                        }
                        _ => anyhow::bail!("unsupported canonical resource or concurrency"),
                    }
                }
            }
            _ => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{MAX_COMPONENT_DEPTH, MAX_EXPANDED_INSTANCES, check};
    use crate::runtime::{Limits, Runtime};

    const HANDLE: &str = r#"
        (core module $m (func (export "handle")))
        (core instance $i (instantiate $m))
        (func (export "handle") (canon lift (core func $i "handle")))"#;

    fn binary(source: &str) -> Vec<u8> {
        let bytes = wat::parse_str(source).unwrap();
        wasmparser::Validator::new().validate_all(&bytes).unwrap();
        bytes
    }

    fn doubling_component(levels: usize) -> Vec<u8> {
        let mut source = String::from("(component (component $c0)");
        for level in 1..=levels {
            source.push_str(&format!(
                "(component $c{level}
                    (alias outer 1 $c{} (component $previous))
                    (instance (instantiate $previous))
                    (instance (instantiate $previous)))",
                level - 1,
            ));
        }
        source.push_str(&format!("(instance (instantiate $c{levels})) {HANDLE})"));
        binary(&source)
    }

    #[test]
    fn rejects_exponential_expansion_without_compiling() {
        for levels in [22, 27, 64] {
            let bytes = doubling_component(levels);
            assert!(bytes.len() < 8192);
            assert_eq!(
                check(&bytes).unwrap_err().to_string(),
                "expanded instance limit"
            );
            assert_eq!(
                Runtime::compile(&bytes, Limits::default())
                    .err()
                    .unwrap()
                    .to_string(),
                "expanded instance limit"
            );
        }
    }

    #[test]
    fn admits_small_component_expansion() {
        Runtime::compile(&doubling_component(5), Limits::default()).unwrap();
    }

    #[test]
    fn repeated_instances_count_separately_at_the_boundary() {
        for (extra, admitted) in [(1, true), (2, false)] {
            for (definition, instantiate) in [
                ("(component $c)", "(instance (instantiate $c))"),
                ("(core module $m)", "(core instance (instantiate $m))"),
            ] {
                let bytes = binary(&format!(
                    "(component
                        (component $group {definition} {})
                        (instance (instantiate $group))
                        (instance (instantiate $group))
                        (component $empty) {})",
                    instantiate.repeat(MAX_EXPANDED_INSTANCES / 2 - 2),
                    "(instance (instantiate $empty))".repeat(extra),
                ));
                let result = check(&bytes);
                if admitted {
                    result.unwrap();
                } else {
                    assert_eq!(result.unwrap_err().to_string(), "expanded instance limit");
                }
            }
        }
    }

    #[test]
    fn counts_core_instances_inside_repeated_components() {
        // One root plus 512 * (one component + one core instance) exceeds 1024.
        let bytes = binary(&format!(
            "(component (component $c (core module $m) (core instance (instantiate $m))) {})",
            "(instance (instantiate $c))".repeat(512),
        ));
        assert_eq!(
            check(&bytes).unwrap_err().to_string(),
            "expanded instance limit"
        );
    }

    #[test]
    fn bounds_expanded_bytes_even_with_few_instances() {
        let bytes = binary(&format!(
            "(component (component $c (core module (data \"{}\"))) {})",
            "a".repeat(256 * 1024),
            "(instance (instantiate $c))".repeat(32),
        ));
        assert!(bytes.len() < 2 * 1024 * 1024);
        assert_eq!(
            check(&bytes).unwrap_err().to_string(),
            "expanded component byte limit"
        );
    }

    #[test]
    fn tracks_outer_aliases_and_component_export_indices() {
        let bytes = binary(&format!(
            r#"(component (component $outer
            (component $leaf (core module))
            (export "leaf" (component $leaf))
            (component $parent
                (component $child
                    (alias outer 2 1 (component $a))
                    (alias outer 0 $a (component $b))
                    (instance (instantiate $b)))
                (instance (instantiate $child)))
            (instance (instantiate $parent)))
            (instance (instantiate $outer)) {HANDLE})"#
        ));
        Runtime::compile(&bytes, Limits::default()).unwrap();

        // The export creates component index 1. Its cost must follow that alias,
        // rather than accidentally reading the cheap definition at index 2.
        let bytes = binary(&format!(
            r#"(component
            (component $large (component $leaf) {})
            (export "large" (component $large))
            (component)
            (instance (instantiate 1))
            (instance (instantiate 1)))"#,
            "(instance (instantiate $leaf))".repeat(512),
        ));
        assert_eq!(
            check(&bytes).unwrap_err().to_string(),
            "expanded instance limit"
        );
    }

    #[test]
    fn rejects_component_values_that_require_argument_sensitive_analysis() {
        for source in [
            r#"(component (import "dependency" (component)))"#,
            r#"(component (component (import "dependency" (component))))"#,
        ] {
            assert_eq!(
                check(&binary(source)).unwrap_err().to_string(),
                "component-valued imports are not admitted"
            );
        }
        for source in [
            r#"(component
                (import "host" (instance $i (export "child" (component))))
                (alias export $i "child" (component)))"#,
            r#"(component
                (component $c)
                (instance $i (export "child" (component $c)))
                (alias export $i "child" (component)))"#,
            r#"(component
                (component $c (component $child) (export "child" (component $child)))
                (instance $i (instantiate $c))
                (alias export $i "child" (component)))"#,
        ] {
            assert_eq!(
                check(&binary(source)).unwrap_err().to_string(),
                "component-valued instance aliases are not admitted"
            );
        }
    }

    #[test]
    fn bounds_lexical_nesting() {
        for (depth, admitted) in [
            (MAX_COMPONENT_DEPTH, true),
            (MAX_COMPONENT_DEPTH + 1, false),
        ] {
            let bytes = binary(&format!(
                "{}{}",
                "(component ".repeat(depth),
                ")".repeat(depth)
            ));
            let result = check(&bytes);
            if admitted {
                result.unwrap();
            } else {
                assert_eq!(result.unwrap_err().to_string(), "component nesting limit");
            }
        }
    }

    #[test]
    fn rejects_invalid_references_without_panicking() {
        for source in [
            "(component (instance (instantiate 4294967295)))",
            "(component (alias outer 4294967295 0 (component)))",
            "(component (alias outer 0 4294967295 (component)))",
            "(component (export \"missing\" (component 4294967295)))",
        ] {
            assert!(check(&wat::parse_str(source).unwrap()).is_err());
        }
        let mut bytes = doubling_component(2);
        bytes.pop();
        assert!(check(&bytes).is_err());
    }
}
