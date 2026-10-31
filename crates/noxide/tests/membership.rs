use noxide::__private::{
    Policy, Predicate,
    expiry::ResourceExpiry,
    membership::{ExistsRelated, MembershipLiteral, MembershipUnique, RelatedTarget},
};
use noxide::{
    AccountId, Choice, Duration, Id, QueryType, Resource, ResourceType, Timestamp, query,
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
