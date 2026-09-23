use noxide_protocol::*;

pub fn manifest() -> Manifest {
    let owner = Policy {
        any: vec![vec![Predicate::Owner]],
    };
    Manifest {
        version: VERSION,
        resources: vec![Resource {
            id: 1,
            name: "notes".into(),
            fields: vec![TextField {
                name: "body".into(),
                label: "Note".into(),
                max_bytes: 4096,
            }],
        }],
        operations: vec![
            Operation {
                id: 1,
                resource: 1,
                kind: OperationKind::List,
                policy: owner.clone(),
            },
            Operation {
                id: 2,
                resource: 1,
                kind: OperationKind::Read,
                policy: owner.clone(),
            },
            Operation {
                id: 3,
                resource: 1,
                kind: OperationKind::Create,
                policy: owner,
            },
        ],
        routes: vec![
            Route {
                id: 1,
                path: "/".into(),
                record: false,
                operations: vec![1],
                forms: vec![1],
            },
            Route {
                id: 2,
                path: "/notes".into(),
                record: true,
                operations: vec![2],
                forms: vec![],
            },
        ],
        actions: vec![Action {
            id: 1,
            version: 1,
            name: "Save note".into(),
            operation: 3,
            redirect: 2,
        }],
    }
}
