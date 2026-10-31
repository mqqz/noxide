use noxide::__private::{
    Policy, Predicate,
    expiry::ResourceExpiry,
    membership::{ExistsRelated, MembershipLiteral, MembershipUnique, RelatedTarget},
};
use noxide::{
    AccountId, ActionType, Choice, Duration, Id, QueryType, Resource, ResourceType, Timestamp,
    WebActionType, action, query,
};
use std::collections::BTreeMap;

#[derive(Resource)]
#[resource(key = "workspaces")]
pub struct Workspace {
    #[id]
    pub id: Id<Self>,
    #[field(max_bytes = 100)]
    pub title: String,
}

#[derive(Choice, Clone, Copy)]
pub enum Role {
    #[choice(key = "admin", label = "Administrator")]
    Admin,
    #[choice(key = "member", label = "Member")]
    Member,
}

#[derive(Resource)]
#[resource(
    key = "memberships",
    unique(workspace, account),
    expiry(expires_at, max_after_seconds = 3600)
)]
pub struct Membership {
    #[id]
    pub id: Id<Self>,
    #[field(key = "workspace_ref")]
    pub workspace: Id<Workspace>,
    #[field(scope = same_tenant)]
    pub account: AccountId,
    #[field()]
    pub role: Role,
    #[field()]
    pub active: bool,
    #[field()]
    pub expires_at: Timestamp,
}

#[derive(Resource)]
#[resource(key = "documents", expiry(expires_at))]
pub struct Document {
    #[id]
    pub id: Id<Self>,
    #[field()]
    pub workspace: Id<Workspace>,
    #[field()]
    pub expires_at: Timestamp,
}

#[query(read(Workspace), allow = exists_related(Membership,
    reference = workspace, target = self_record, account = account,
    conditions(role = Role::Admin, active = true)))]
struct AdminWorkspace;

#[query(read(Document), allow = exists_related(Membership,
    reference = workspace, target = reference(workspace), account = account,
    conditions(active = true, role = Role::Member)))]
struct MemberDocument;

#[query(read(Workspace), allow = owner)]
struct OwnedWorkspace;

mod show {
    pub fn id() -> u32 {
        99
    }
}

#[action(update(Document), fields(expires_at),
    allow = exists_related(Membership, reference = workspace,
        target = reference(workspace), account = account, conditions(role = Role::Admin)),
    redirect = show)]
struct ExtendDocument;

#[action(inputs(), transaction(update(Document, target,
    set(expires_at = transaction_time() + seconds(60)),
    allow = exists_related(Membership, reference = workspace,
        target = reference(workspace), account = account, conditions(role = Role::Admin)))),
    allow = owner, redirect = show(target))]
struct ExtendDocumentStep;

#[action(inputs(title: String = 100), transaction(
    workspace = create(Workspace, set(title = title)),
    create(Membership, set(workspace = workspace, account = principal(), role = "admin",
        active = true, expires_at = transaction_time() + seconds(3600)),
        eligible = OwnedWorkspace, allow = principal_is(account))),
    allow = owner, redirect = show(workspace))]
struct BootstrapWorkspace;

#[action(inputs(recipient: AccountId = same_tenant), transaction(
    create(Membership, set(workspace = target, account = recipient, role = "member",
        active = true, expires_at = transaction_time() + seconds(60)), eligible = OwnedWorkspace)),
    allow = owner, redirect = show(target))]
struct InviteMember;

#[test]
fn scoped_account_input_matches_explicit_input_and_operation() {
    use noxide::__private::{
        AccountScope, Change, FieldKind, Input, Operation, OperationKind, Value,
    };
    let definition = InviteMember::definition();
    assert_eq!(
        definition.inputs,
        vec![Input {
            name: "recipient".into(),
            label: "Recipient".into(),
            kind: FieldKind::Account {
                scope: AccountScope::SameTenant
            },
            optional: false,
            max_bytes: 43,
        }]
    );
    assert_eq!(
        InviteMember::operations(),
        vec![
            Operation {
                query: None,
                id: noxide::stable_id(concat!("mutation:", module_path!(), "::InviteMember:0u8")),
                resource: Membership::definition().id,
                kind: OperationKind::Create,
                policy: Policy {
                    any: vec![vec![Predicate::Owner]]
                },
                bind: BTreeMap::from([("workspace_ref".into(), OwnedWorkspace::operation().id)]),
                scope: None,
                via: None,
                filter: vec![],
                disclose: vec![],
                list: None,
                visibility: None,
                fields: None,
            },
            OwnedWorkspace::operation()
        ]
    );
    assert_eq!(
        definition.steps[0]
            .assign
            .iter()
            .find(|a| a.field == "account")
            .unwrap()
            .change,
        Change::Set(Value::Input("recipient".into()))
    );
}

#[test]
fn membership_and_lifecycle_lower_to_explicit_canonical_contract() {
    let membership = Membership::definition();
    assert_eq!(
        membership.unique,
        vec![MembershipUnique {
            reference: "workspace_ref".into(),
            account: "account".into()
        }]
    );
    assert_eq!(
        membership.expiry,
        Some(ResourceExpiry {
            field: "expires_at".into(),
            max_after: Duration::from_secs(3600).unwrap()
        })
    );
    assert_eq!(
        Document::definition().expiry.unwrap().max_after.as_millis(),
        noxide::__private::expiry::MAX_EXPIRY_MILLIS
    );
    assert_eq!(
        AdminWorkspace::operation().policy,
        Policy {
            any: vec![vec![Predicate::ExistsRelated(ExistsRelated {
                resource: "memberships".into(),
                reference: "workspace_ref".into(),
                target: RelatedTarget::SelfRecord,
                account: "account".into(),
                conditions: BTreeMap::from([
                    ("active".into(), MembershipLiteral::Boolean(true)),
                    ("role".into(), MembershipLiteral::Choice("admin".into()))
                ]),
            })]]
        }
    );
    let member = MemberDocument::operation();
    let Predicate::ExistsRelated(related) = &member.policy.any[0][0] else {
        panic!("membership predicate")
    };
    assert_eq!(
        related.target,
        RelatedTarget::Reference {
            field: "workspace".into()
        }
    );
    assert_eq!(
        related.conditions["role"],
        MembershipLiteral::Choice("member".into())
    );
    assert_eq!(MemberDocument::policy_resources(), vec![membership]);
}

#[test]
fn action_membership_metadata_and_bootstrap_lower_without_membership_reads() {
    let expected = Membership::definition();
    assert!(ExtendDocument::resources().contains(&expected));
    assert!(ExtendDocumentStep::resources().contains(&expected));
    let declarations = noxide::TargetDeclarations::new().page::<AdminWorkspace>(
        "workspace",
        noxide::__private::Revision::Exact,
        &["title"],
    );
    assert!(declarations.resources.contains(&expected));
    assert!(
        declarations
            .operations
            .iter()
            .all(|op| op.resource != expected.id)
    );
    let bootstrap = BootstrapWorkspace::definition();
    let membership = &bootstrap.steps[1];
    use noxide::__private::{Change, Literal, Value};
    assert!(
        membership
            .assign
            .iter()
            .any(|assignment| assignment.field == "workspace_ref"
                && assignment.change == Change::Set(Value::Created(0)))
    );
    assert!(
        membership
            .assign
            .iter()
            .any(|assignment| assignment.field == "account"
                && assignment.change == Change::Set(Value::Principal))
    );
    assert!(
        membership
            .assign
            .iter()
            .any(|assignment| assignment.field == "role"
                && assignment.change
                    == Change::Set(Value::Literal(Literal::Choice("admin".into()))))
    );
    let operations = BootstrapWorkspace::operations();
    assert_eq!(
        operations
            .iter()
            .find(|op| op.id == membership.operation)
            .unwrap()
            .policy
            .any,
        vec![vec![Predicate::PrincipalIs {
            field: "account".into()
        }]]
    );
    assert!(operations.iter().all(|op| op.resource != expected.id
        || !matches!(
            op.kind,
            noxide::__private::OperationKind::Read | noxide::__private::OperationKind::List
        )));
    assert_eq!(BootstrapWorkspace::web_binding().action, bootstrap.id);
}
