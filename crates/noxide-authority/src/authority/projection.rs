//! Opaque canonical facts for candidate policy/expiry only. Never a Read grant.
use super::*;
use noxide_protocol::{
    OperationKind, Predicate, Resource, TextField, membership::RelatedTarget,
    query::AggregateFunction,
};
use std::{collections::BTreeSet, sync::Arc};

struct Shape {
    contract: String,
    consumer: Operation,
    source: Operation,
    resource: Resource,
    fields: Vec<TextField>,
}
pub(crate) struct Spec(Arc<Shape>);
/// Native protected columns are supplied by a bounded internal SQL projection.
/// Guest record fields cannot substitute owner, tenant or row identity.
pub(crate) struct NativeFacts {
    pub id: u64,
    pub owner: String,
    pub tenant: String,
    pub incarnation: String,
    pub revision: i64,
    pub created_sequence: u64,
}
pub(crate) struct InternalFacts {
    shape: Arc<Shape>,
    epoch: Arc<()>,
    principal: crate::auth::PrincipalKey,
    native: NativeFacts,
    fields: Fields,
}
impl InternalFacts {
    pub(crate) fn native(&self) -> &NativeFacts {
        &self.native
    }
    pub(crate) fn selected(&self) -> &Fields {
        &self.fields
    }
}
impl Spec {
    pub(crate) fn aggregate(
        manifest: &Manifest,
        consumer: &Operation,
        contract: &str,
    ) -> Result<Self> {
        ensure!(
            consumer.kind == OperationKind::Aggregate,
            "aggregate facts purpose"
        );
        let aggregate = consumer
            .query
            .as_ref()
            .and_then(|query| query.aggregate.as_ref())
            .context("aggregate facts source")?;
        let source = manifest::operation(manifest, aggregate.source)?;
        let operand = match &aggregate.function {
            AggregateFunction::Count => None,
            AggregateFunction::Sum { field }
            | AggregateFunction::Min { field }
            | AggregateFunction::Max { field } => Some(field.as_str()),
        };
        Self::build(manifest, consumer, source, contract, operand)
    }
    #[cfg(test)]
    pub(crate) fn candidates(
        manifest: &Manifest,
        source: &Operation,
        contract: &str,
    ) -> Result<Self> {
        let extended = source
            .query
            .as_ref()
            .is_some_and(|query| query.search.is_some() || query.range.is_some())
            || source
                .list
                .as_ref()
                .is_some_and(|list| matches!(list.order, noxide_protocol::ListOrder::Field { .. }));
        ensure!(extended, "ordinary row query cannot request partial facts");
        Self::build(manifest, source, source, contract, None)
    }
    fn build(
        manifest: &Manifest,
        consumer: &Operation,
        source: &Operation,
        contract: &str,
        operand: Option<&str>,
    ) -> Result<Self> {
        ensure!(!contract.is_empty(), "facts contract required");
        ensure!(
            source.kind == OperationKind::List,
            "facts require List metadata"
        );
        ensure!(
            manifest::operation(manifest, consumer.id)? == consumer
                && manifest::operation(manifest, source.id)? == source,
            "facts operation mismatch"
        );
        let resource = manifest::resource(manifest, source.resource)?;
        let mut names = BTreeSet::new();
        for predicate in source.policy.any.iter().flatten() {
            match predicate {
                Predicate::PrincipalIs { field } => {
                    names.insert(field.as_str());
                }
                Predicate::ExistsRelated(related) => {
                    if let RelatedTarget::Reference { field } = &related.target {
                        names.insert(field.as_str());
                    }
                }
                _ => {}
            }
        }
        if let Some(expiry) = &resource.expiry {
            names.insert(expiry.field.as_str());
        }
        if let Some(gate) = &resource.gate {
            names.insert(gate.field.as_str());
        }
        if let Some(scope) = &source.scope {
            names.insert(scope.as_str());
        }
        if let Some(visibility) = &source.visibility {
            names.insert(visibility.field.as_str());
        }
        for filter in &source.filter {
            names.insert(filter.field.as_str());
        }
        if let Some(list) = &source.list
            && let noxide_protocol::ListOrder::Field { field, .. } = &list.order
        {
            names.insert(field.as_str());
        }
        if let Some(range) = source.query.as_ref().and_then(|query| query.range.as_ref()) {
            names.insert(range.field.as_str());
        }
        if let Some(operand) = operand {
            names.insert(operand);
        }
        let fields = names
            .into_iter()
            .map(|name| {
                resource
                    .fields
                    .iter()
                    .find(|field| field.name == name)
                    .cloned()
                    .context("unknown eligibility fact")
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self(Arc::new(Shape {
            contract: contract.into(),
            consumer: consumer.clone(),
            source: source.clone(),
            resource: resource.clone(),
            fields,
        })))
    }
    pub(crate) fn fields(&self) -> &[TextField] {
        &self.0.fields
    }
    pub(crate) fn validate(
        &self,
        authority: &Authority,
        principal: &Principal,
        native: NativeFacts,
        fields: Fields,
    ) -> Result<InternalFacts> {
        ensure!(
            authority
                .deployment
                .as_ref()
                .is_some_and(|deployment| deployment.contract == self.0.contract),
            "facts deployment contract mismatch"
        );
        ensure!(
            native.id > 0
                && native.id <= i64::MAX as u64
                && native.created_sequence > 0
                && native.created_sequence <= i64::MAX as u64,
            "facts native identity"
        );
        ensure!(
            native.revision > 0 && !native.incarnation.is_empty() && native.incarnation.len() <= 64,
            "facts native incarnation/revision"
        );
        ensure!(
            native.owner.is_empty() || noxide_protocol::account_id(&native.owner),
            "facts native owner"
        );
        ensure!(
            native.tenant.is_empty() || manifest::identifier(&native.tenant),
            "facts native tenant"
        );
        ensure!(
            fields.len() == self.0.fields.len(),
            "unexpected/missing eligibility facts"
        );
        for field in &self.0.fields {
            let value = fields
                .get(&field.name)
                .context("missing eligibility fact")?;
            ensure!(
                field
                    .canonical(value)
                    .is_ok_and(|canonical| canonical == *value),
                "noncanonical eligibility fact"
            );
        }
        Ok(InternalFacts {
            shape: Arc::clone(&self.0),
            epoch: Arc::clone(&authority.projection_epoch),
            principal: principal_key(principal),
            native,
            fields,
        })
    }
    fn check_binding(
        &self,
        authority: &Authority,
        manifest: &Manifest,
        principal: &Principal,
        facts: &[InternalFacts],
    ) -> Result<()> {
        ensure!(
            authority
                .deployment
                .as_ref()
                .is_some_and(|deployment| deployment.contract == self.0.contract),
            "facts deployment contract mismatch"
        );
        ensure!(
            manifest::operation(manifest, self.0.consumer.id)? == &self.0.consumer
                && manifest::operation(manifest, self.0.source.id)? == &self.0.source
                && manifest::resource(manifest, self.0.resource.id)? == &self.0.resource,
            "facts current declaration mismatch"
        );
        ensure!(
            facts.iter().all(|fact| Arc::ptr_eq(&fact.shape, &self.0)),
            "facts spec mismatch"
        );
        ensure!(
            facts
                .iter()
                .all(|fact| Arc::ptr_eq(&fact.epoch, &authority.projection_epoch)),
            "stale facts attempt/mutation epoch"
        );
        ensure!(
            facts
                .iter()
                .all(|fact| fact.principal == principal_key(principal)),
            "facts principal mismatch"
        );
        Ok(())
    }
}
fn principal_key(principal: &Principal) -> crate::auth::PrincipalKey {
    principal.authority_key()
}
impl Authority {
    /// Policy+expiry only: caller still needs fresh visibility/gate/scope/selection
    /// before touching an approved operand or producing output. No Record exists.
    pub(crate) async fn candidate_policy(
        &mut self,
        tx: &mut Transaction,
        manifest: &Manifest,
        principal: &Principal,
        spec: &Spec,
        facts: &[InternalFacts],
        calls: &mut usize,
    ) -> Result<Vec<bool>> {
        ensure!(
            facts.len() <= membership::MAX_BATCH,
            "authority batch limit"
        );
        spec.check_binding(self, manifest, principal, facts)?;
        let rows: Vec<_> = facts
            .iter()
            .map(|fact| Row {
                id: fact.native.id,
                owner: &fact.native.owner,
                tenant: &fact.native.tenant,
                fields: &fact.fields,
            })
            .collect();
        self.evaluate_policy_expiry(tx, manifest, principal, &spec.0.source, &rows, calls)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use noxide_protocol::{
        AccountScope, Condition, FieldKind, Gate, ListOrder, ListSettings, Operand, Policy,
        Visibility,
        expiry::ResourceExpiry,
        membership::{ExistsRelated, MembershipLiteral},
        query::{Aggregate, Bound, Direction, Query, Range, SortMode},
        time::Duration,
    };
    fn field(name: &str, kind: FieldKind, optional: bool) -> TextField {
        let max_bytes = match &kind {
            FieldKind::Text => 512,
            FieldKind::Account { .. } => 43,
            FieldKind::Boolean => 5,
            _ => 20,
        };
        TextField {
            immutable: false,
            kind,
            optional,
            initial: None,
            name: name.into(),
            label: name.into(),
            max_bytes,
        }
    }
    fn fixture() -> (Manifest, Operation, Fields) {
        let mut m = crate::test_support::manifest();
        m.resources[0].fields = vec![
            field("body", FieldKind::Text, false),
            field(
                "recipient",
                FieldKind::Account {
                    scope: AccountScope::SameTenant,
                },
                false,
            ),
            field(
                "parent",
                FieldKind::Reference {
                    resource: "notes".into(),
                },
                false,
            ),
            field("expires", FieldKind::Timestamp, false),
            field(
                "rank",
                FieldKind::Integer {
                    min: None,
                    max: None,
                },
                false,
            ),
            field(
                "score",
                FieldKind::Integer {
                    min: None,
                    max: None,
                },
                false,
            ),
            field("marker", FieldKind::Boolean, true),
            field("published", FieldKind::Boolean, false),
        ];
        m.resources[0].expiry = Some(ResourceExpiry {
            field: "expires".into(),
            max_after: Duration::from_millis(10_000).unwrap(),
        });
        m.resources[0].gate = Some(Gate {
            field: "parent".into(),
            visible: Visibility {
                field: "published".into(),
                equals: "true".into(),
            },
            create_when: Visibility {
                field: "published".into(),
                equals: "true".into(),
            },
        });
        let source = &mut m.operations[0];
        source.policy = Policy {
            any: vec![
                vec![Predicate::Owner],
                vec![
                    Predicate::SameTenant,
                    Predicate::PrincipalIs {
                        field: "recipient".into(),
                    },
                ],
                vec![Predicate::ExistsRelated(ExistsRelated {
                    resource: "memberships".into(),
                    reference: "workspace".into(),
                    target: RelatedTarget::Reference {
                        field: "parent".into(),
                    },
                    account: "account".into(),
                    conditions: BTreeMap::from([(
                        "active".into(),
                        MembershipLiteral::Boolean(true),
                    )]),
                })],
            ],
        };
        source.scope = Some("parent".into());
        source.filter = vec![Condition {
            field: "marker".into(),
            equals: Operand::Literal("".into()),
        }];
        source.list = Some(ListSettings {
            preview: None,
            order: ListOrder::Field {
                field: "rank".into(),
                direction: Direction::Ascending,
                mode: SortMode::LiveView,
            },
            page_size: 3,
        });
        source.query = Some(Query {
            range: Some(Range {
                field: "rank".into(),
                lower: Some(Bound {
                    value: Operand::Literal("0".into()),
                    inclusive: true,
                }),
                upper: None,
            }),
            ..Default::default()
        });
        let mut aggregate = source.clone();
        aggregate.id = 900;
        aggregate.kind = OperationKind::Aggregate;
        aggregate.list = None;
        aggregate.query = Some(Query {
            aggregate: Some(Aggregate {
                source: source.id,
                function: AggregateFunction::Sum {
                    field: "score".into(),
                },
            }),
            ..Default::default()
        });
        m.operations.push(aggregate.clone());
        let fields = Fields::from([
            ("body".into(), "non-eligibility business data".into()),
            ("recipient".into(), format!("{}A", "C".repeat(42))),
            ("parent".into(), "1".into()),
            ("expires".into(), "10000".into()),
            ("rank".into(), "3".into()),
            ("score".into(), "4".into()),
            ("marker".into(), "".into()),
            ("published".into(), "true".into()),
        ]);
        (m, aggregate, fields)
    }
    fn authority() -> Authority {
        Authority::new(
            None,
            DeploymentScope {
                contract: "contract".into(),
                incarnation: "deployment".into(),
                generation: "generation".into(),
            },
        )
    }
    fn native() -> NativeFacts {
        NativeFacts {
            id: 9,
            owner: "A".repeat(43),
            tenant: "team".into(),
            incarnation: "row".into(),
            revision: 1,
            created_sequence: 1,
        }
    }
    fn project(spec: &Spec, full: &Fields) -> Fields {
        spec.fields()
            .iter()
            .map(|field| (field.name.clone(), full[&field.name].clone()))
            .collect()
    }
    #[test]
    fn all_or_branches_and_selection_operand_facts_are_required_without_dummy_defaults() {
        let (mut m, aggregate, full) = fixture();
        manifest::validate_fields(&m.resources[0], &full).unwrap();
        let spec = Spec::aggregate(&m, &aggregate, "contract").unwrap();
        assert_eq!(
            spec.fields()
                .iter()
                .map(|field| field.name.as_str())
                .collect::<Vec<_>>(),
            ["expires", "marker", "parent", "rank", "recipient", "score"]
        );
        let fields = project(&spec, &full);
        assert!(
            spec.validate(
                &authority(),
                &Principal::Anonymous,
                native(),
                fields.clone()
            )
            .is_ok()
        );
        for name in ["expires", "marker", "parent", "rank", "recipient", "score"] {
            let mut missing = fields.clone();
            missing.remove(name);
            assert!(
                spec.validate(&authority(), &Principal::Anonymous, native(), missing)
                    .is_err()
            );
        }
        for (name, value) in [
            ("expires", "-1"),
            ("marker", "on"),
            ("parent", "01"),
            ("rank", "03"),
            ("recipient", "unknown"),
        ] {
            let mut forged = fields.clone();
            forged.insert(name.into(), value.into());
            assert!(
                spec.validate(&authority(), &Principal::Anonymous, native(), forged)
                    .is_err()
            );
        }
        // Public visibility is a separate repository check; its input must still
        // be present even though this API grants only policy+expiry.
        m.operations[0].policy = Policy {
            any: vec![vec![Predicate::Public]],
        };
        m.operations[0].visibility = Some(Visibility {
            field: "published".into(),
            equals: "true".into(),
        });
        let public = Spec::candidates(&m, &m.operations[0], "contract").unwrap();
        assert!(
            public
                .fields()
                .iter()
                .any(|field| field.name == "published")
        );
    }
    #[test]
    fn partial_facts_cannot_request_read_create_or_mutation_purposes() {
        let (m, aggregate, _) = fixture();
        for kind in [
            OperationKind::Read,
            OperationKind::Create,
            OperationKind::Update,
            OperationKind::Delete,
        ] {
            let mut forged = m.clone();
            forged.operations[0].kind = kind.clone();
            assert!(Spec::candidates(&forged, &forged.operations[0], "contract").is_err());
            let mut forged_consumer = aggregate.clone();
            forged_consumer.kind = kind;
            assert!(Spec::aggregate(&m, &forged_consumer, "contract").is_err());
        }
        let mut ordinary = m.clone();
        ordinary.operations[0].query = None;
        ordinary.operations[0].list.as_mut().unwrap().order = ListOrder::CreatedAsc;
        assert!(Spec::candidates(&ordinary, &ordinary.operations[0], "contract").is_err());
        assert!(Spec::aggregate(&m, &aggregate, "").is_err());
    }
    #[test]
    fn request_mutation_spec_and_declaration_binding_fail_closed() {
        let (m, aggregate, full) = fixture();
        let spec = Spec::aggregate(&m, &aggregate, "contract").unwrap();
        let mut context = authority();
        let fact = spec
            .validate(
                &context,
                &Principal::Anonymous,
                native(),
                project(&spec, &full),
            )
            .unwrap();
        spec.check_binding(
            &context,
            &m,
            &Principal::Anonymous,
            std::slice::from_ref(&fact),
        )
        .unwrap();
        let other_principal = Principal::User(crate::auth::User {
            id: "A".repeat(43),
            tenant: "team".into(),
            roles: vec![],
        });
        assert!(
            spec.check_binding(&context, &m, &other_principal, std::slice::from_ref(&fact))
                .is_err()
        );
        context.clear_witnesses();
        spec.check_binding(
            &context,
            &m,
            &Principal::Anonymous,
            std::slice::from_ref(&fact),
        )
        .unwrap();
        assert!(
            spec.check_binding(
                &authority(),
                &m,
                &Principal::Anonymous,
                std::slice::from_ref(&fact)
            )
            .is_err()
        );
        let other = Spec::aggregate(&m, &aggregate, "contract").unwrap();
        assert!(
            other
                .check_binding(
                    &context,
                    &m,
                    &Principal::Anonymous,
                    std::slice::from_ref(&fact)
                )
                .is_err()
        );
        let mut changed = m.clone();
        changed.operations[0].policy.any.clear();
        assert!(
            spec.check_binding(
                &context,
                &changed,
                &Principal::Anonymous,
                std::slice::from_ref(&fact)
            )
            .is_err()
        );
        context.invalidate();
        assert!(
            spec.check_binding(
                &context,
                &m,
                &Principal::Anonymous,
                std::slice::from_ref(&fact)
            )
            .is_err()
        );
        let mut malformed = native();
        malformed.revision = 0;
        assert!(
            spec.validate(
                &context,
                &Principal::Anonymous,
                malformed,
                project(&spec, &full)
            )
            .is_err()
        );
        let mut malformed = native();
        malformed.owner = "guest-owner".into();
        assert!(
            spec.validate(
                &context,
                &Principal::Anonymous,
                malformed,
                project(&spec, &full)
            )
            .is_err()
        );
    }
    #[test]
    fn ordinary_predicate_truth_matches_full_fields_but_is_not_full_read_authority() {
        let (m, aggregate, full) = fixture();
        let spec = Spec::aggregate(&m, &aggregate, "contract").unwrap();
        let fact = spec
            .validate(
                &authority(),
                &Principal::Anonymous,
                native(),
                project(&spec, &full),
            )
            .unwrap();
        let row = native();
        for (id, tenant, expected) in [
            (row.owner.as_str(), "team", true),
            (row.owner.as_str(), "elsewhere", true),
            (full["recipient"].as_str(), "team", true),
            (full["recipient"].as_str(), "elsewhere", false),
            ("outsider", "team", false),
        ] {
            let principal = Principal::User(crate::auth::User {
                id: id.into(),
                tenant: tenant.into(),
                roles: vec![],
            });
            for fields in [&full, &fact.fields] {
                assert_eq!(
                    policy::allowed(
                        &spec.0.source.policy,
                        &principal,
                        policy::Row {
                            owner: &row.owner,
                            tenant: &row.tenant,
                            fields
                        }
                    ),
                    expected
                );
            }
        }
        // This metadata-only proof never invokes membership, gate, visibility or
        // durable expiry. Their full provider differential gate remains pending.
        let mut noncanonical = full.clone();
        noncanonical.insert("body".into(), "".into());
        assert!(manifest::validate_fields(&m.resources[0], &noncanonical).is_err());
        assert!(
            spec.validate(
                &authority(),
                &Principal::Anonymous,
                native(),
                project(&spec, &noncanonical)
            )
            .is_ok()
        );
        // A fact proof assumes host-maintained canonical stored rows; it cannot
        // assert omitted non-eligibility data or turn into a Record/StoredRecord.
    }
}
