use super::prelude::*;
use crate::auth::AccountAdmin as _;
use crate::{Database, HostKeys, runtime::Limits, test_support as fixture};
use noxide_protocol::*;
use std::{sync::Arc, time::Duration};

#[tokio::test]
async fn http_picker_submits_and_replays_without_javascript() {
    use axum::{
        body::{Body, to_bytes},
        http::Request,
    };
    use tower::ServiceExt;
    let case = Case::new(None, declarations()).await;
    let router = crate::router(
        case.app.clone(),
        crate::Origin::parse("http://localhost:8080").unwrap(),
    );
    let page = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/")
                .header("Host", "localhost:8080")
                .header("Cookie", format!("session={}", case.alice))
                .extension(crate::Peer::Local)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(page.status(), 200);
    let page = String::from_utf8(
        to_bytes(page.into_body(), MAX_RESULT_BYTES)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    let mut fields = input(&page);
    fields.insert("_submission".into(), fixture::hidden(&page, "_submission"));
    fields.insert("_csrf".into(), fixture::hidden(&page, "_csrf"));
    let mut body = url::form_urlencoded::Serializer::new(String::new());
    for (name, value) in fields {
        body.append_pair(&name, &value);
    }
    let body = body.finish();
    let mut location = None;
    for _ in 0..2 {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/actions/1")
                    .header("Host", "localhost:8080")
                    .header("Origin", "http://localhost:8080")
                    .header("Cookie", format!("session={}", case.alice))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .extension(crate::Peer::Local)
                    .body(Body::from(body.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 303);
        let next = response
            .headers()
            .get("location")
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        if let Some(location) = &location {
            assert_eq!(location, &next);
        }
        location = Some(next);
    }
}

fn declarations() -> Manifest {
    let mut m = fixture::manifest();
    m.operations[0].list = Some(ListSettings {
        preview: None,
        order: ListOrder::CreatedAsc,
        page_size: 2,
    });
    let names = ["a", "b", "c", "d"];
    m.resources.push(Resource {
        search: None,
        expiry: None,
        unique: Vec::new(),
        id: 2,
        name: "links".into(),
        gate: None,
        fields: names
            .iter()
            .map(|name| TextField {
                immutable: false,
                name: (*name).into(),
                label: (*name).into(),
                kind: FieldKind::Reference {
                    resource: "notes".into(),
                },
                optional: false,
                initial: None,
                max_bytes: 20,
            })
            .collect(),
    });
    let mut create = m.operations[2].clone();
    create.id = 4;
    create.resource = 2;
    create.bind = names.iter().map(|name| ((*name).into(), 2)).collect();
    let mut read = m.operations[1].clone();
    read.id = 5;
    read.resource = 2;
    m.operations.extend([create, read]);
    m.routes.push(Route {
        id: 3,
        path: "/links/{link}".into(),
        resource: Some(2),
        operations: vec![5],
        forms: vec![],
        params: vec![],
        access: Access::Authenticated,
    });
    m.web_bindings[0].redirect.route = 3;
    m.actions[0].inputs.clear();
    m.actions[0].targets = names
        .iter()
        .map(|name| selected(name, Revision::Identity))
        .collect();
    m.actions[0].steps = vec![Step {
        guards: vec![],
        operation: 4,
        target: Target::None,
        assign: names
            .iter()
            .map(|name| Assignment {
                field: (*name).into(),
                change: Change::Set(Value::Target((*name).into())),
            })
            .collect(),
    }];
    let mut delete = m.operations[2].clone();
    delete.id = 6;
    delete.kind = OperationKind::Delete;
    m.operations.push(delete);
    m.actions.push(Action {
        id: 2,
        version: 1,
        name: "Delete note".into(),
        inputs: vec![],
        targets: vec![selected("a", Revision::Exact)],
        steps: vec![Step {
            guards: vec![],
            operation: 6,
            target: Target::Named("a".into()),
            assign: vec![],
        }],
    });
    m.web_bindings.push(WebBinding {
        id: 2,
        version: 1,
        action: 2,
        layout: vec![],
        redirect: Redirect {
            route: 1,
            source: RedirectSource::Step(0),
        },
    });
    m.routes[0].forms.push(2);
    manifest::validate(&m).unwrap();
    m
}

struct Case {
    _temp: tempfile::TempDir,
    app: Arc<Application>,
    alice: String,
}

impl Case {
    async fn new(db: Option<Database>, m: Manifest) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let db = db.unwrap_or_else(|| Database::sqlite(temp.path().join("targets.db")));
        db.initialize().await.unwrap();
        let user = db
            .create_account("alice", "target test password", "team")
            .await
            .unwrap();
        db.create_account("bob", "target test password", "team")
            .await
            .unwrap();
        let app = Arc::new(
            Application::new(
                &fixture::component(None),
                &serde_json::to_vec(&m).unwrap(),
                manifest::digest(&m).unwrap(),
                db.clone(),
                HostKeys::generate().unwrap(),
                Limits::default(),
                crate::DeploymentResources {
                    effects: None,
                    jobs: None,
                    assets: crate::assets::AssetBundle::default(),
                    blobs: None,
                },
            )
            .unwrap(),
        );
        app.activate().await.unwrap();
        let mut tx = db
            .begin(std::time::Instant::now() + Duration::from_secs(5))
            .await
            .unwrap();
        let storage = tx.storage_resource(&m, 1).await.unwrap();
        for id in 1i64..=2 {
            tx.allocate_creation().await.unwrap();
            let mut fields = Fields::from([(
                "body".into(),
                if id == 1 {
                    "<script>private label</script>".into()
                } else {
                    "second".into()
                },
            )]);
            for field in &m.resources[0].fields {
                if let Some(value) = &field.initial {
                    fields.insert(field.name.clone(), value.clone());
                }
            }
            tx.execute("INSERT INTO nx_records(resource,id,owner,tenant,fields,incarnation,revision,created_seq) VALUES($1,$2,$3,'team',$4,'seed',1,(SELECT value FROM nx_creation_counter WHERE singleton=1))",&[storage.into(),id.into(),user.as_str().into(),serde_json::to_string(&fields).unwrap().into()]).await.unwrap();
        }
        tx.commit().await.unwrap();
        let mut cookies = Vec::new();
        for name in ["alice", "bob"] {
            let c = app.login_challenge().await.unwrap();
            cookies.push(
                app.login(&c.cookie, &c.csrf, name, "target test password")
                    .await
                    .unwrap(),
            );
        }
        Self {
            _temp: temp,
            app,
            alice: cookies.remove(0),
        }
    }
}

fn selected(name: &str, revision: Revision) -> ActionTarget {
    ActionTarget {
        name: name.into(),
        resource: 1,
        source: TargetSource::Selected {
            query: 1,
            eligible: 2,
            label: vec!["body".into()],
        },
        revision,
        projection: Some(Inspection {
            operation: 2,
            fields: vec!["body".into()],
        }),
        inspect: None,
    }
}

fn input(page: &str) -> Fields {
    ["a", "b", "c", "d"]
        .into_iter()
        .map(|name| (format!("_target_{name}"), handles(page, name)[0].clone()))
        .collect()
}

fn handles(page: &str, name: &str) -> Vec<String> {
    page.split_once(&format!("name=\"_target_{name}\""))
        .unwrap()
        .1
        .split_once("</select>")
        .unwrap()
        .0
        .split("<option value=\"")
        .skip(2)
        .map(|option| option.split('"').next().unwrap().into())
        .collect()
}
