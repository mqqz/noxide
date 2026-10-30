use noxide::__private::{AccountScope, FieldKind, Fields, Predicate, Record};
use noxide::{AccountId, FieldValue, Id, QueryType, Resource, ResourceType, query};
#[derive(Resource)]
#[resource(key = "assignments")]
struct Assignment {
    #[id]
    id: Id<Self>,
    #[field(key = "assignee", scope = same_tenant)]
    user: AccountId,
}
#[query(read(Assignment), allow = any(owner, all(principal_is(user), same_tenant)))]
struct ReadAssignment;
#[test]
fn account_reference_lowering_preserves_field_keys_and_identity() {
    let id: AccountId = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        .parse()
        .unwrap();
    assert!("alice".parse::<AccountId>().is_err());
    assert!(
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB"
            .parse::<AccountId>()
            .is_err()
    );
    let definition = Assignment::definition();
    assert_eq!(
        definition.fields[0].kind,
        FieldKind::Account {
            scope: AccountScope::SameTenant
        }
    );
    assert_eq!(
        ReadAssignment::operation().policy.any[1],
        vec![
            Predicate::PrincipalIs {
                field: "assignee".into()
            },
            Predicate::SameTenant
        ]
    );
    let record = Assignment::from_record(Record {
        resource: definition.id,
        id: 7,
        fields: Fields::from([("assignee".into(), id.encode())]),
    });
    assert_eq!(record.id.get(), 7);
    assert_eq!(record.user, id);
}
