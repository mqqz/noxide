//! Provider-paired price, transition, proposed-row and expression boundary proofs.
use super::*;
use crate::{Database, HostKeys, runtime::Limits, test_support as fixture};
use noxide_protocol::*;
use std::{sync::Arc, time::Duration};

fn declarations() -> Manifest {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tools/fixtures/queries/example-reservations.json");
    manifest::parse(&std::fs::read(path).unwrap()).unwrap()
}
fn action<'a>(m: &'a Manifest, name: &str) -> &'a Action {
    m.actions.iter().find(|action| action.name == name).unwrap()
}
fn resource(m: &Manifest, name: &str) -> u32 {
    m.resources
        .iter()
        .find(|resource| resource.name == name)
        .unwrap()
        .id
}
fn binding(m: &Manifest, name: &str) -> u32 {
    let id = action(m, name).id;
    m.web_bindings
        .iter()
        .find(|binding| binding.action == id)
        .unwrap()
        .id
}
fn route(m: &Manifest, name: &str) -> u32 {
    let id = resource(m, name);
    m.routes
        .iter()
        .find(|route| route.resource == Some(id))
        .unwrap()
        .id
}
fn component(m: &Manifest, read_routes: bool) -> Vec<u8> {
    fn emit(bytes: &[u8]) -> String {
        bytes
            .chunks(8)
            .map(|chunk| {
                let mut word = [0; 8];
                word[..chunk.len()].copy_from_slice(chunk);
                format!(
                    "i64.const {} i32.const {} call $emit\n",
                    i64::from_le_bytes(word),
                    chunk.len()
                )
            })
            .collect()
    }
    let offset = format!("{{\"version\":{VERSION},\"kind\":{{\"route\":").len();
    let mut branches = emit(
        &serde_json::to_vec(&ResponseIntent::NotFound(Document::new(
            "Not found",
            vec![],
        )))
        .unwrap(),
    );
    for route in m.routes.iter().rev() {
        let bytes = format!("{}}}", route.id).into_bytes();
        let mut condition = String::new();
        for (index, chunk) in bytes.chunks(8).enumerate() {
            let mut word = [0; 8];
            word[..chunk.len()].copy_from_slice(chunk);
            let mask = if chunk.len() == 8 {
                -1
            } else {
                ((1u64 << (chunk.len() * 8)) - 1) as i64
            };
            condition.push_str(&format!(
                "i32.const {} call $request i64.const {mask} i64.and i64.const {} i64.eq\n",
                offset + index * 8,
                i64::from_le_bytes(word)
            ));
            if index > 0 {
                condition.push_str("i32.and\n");
            }
        }
        let mut page = emit(
            &serde_json::to_vec(&ResponseIntent::Page(Document::new(
                "Computation fixture",
                route
                    .forms
                    .iter()
                    .map(|action| Instruction::Form { action: *action })
                    .collect(),
            )))
            .unwrap(),
        );
        if read_routes
            && let Some(read) = route
                .operations
                .iter()
                .filter_map(|id| m.operations.iter().find(|op| op.id == *id))
                .find(|op| op.kind == OperationKind::Read && Some(op.resource) == route.resource)
        {
            let target_offset = format!(
                "{{\"version\":{VERSION},\"kind\":{{\"route\":{}}},\"target\":",
                route.id
            )
            .len();
            let not_found = emit(
                &serde_json::to_vec(&ResponseIntent::NotFound(Document::new(
                    "Not found",
                    vec![],
                )))
                .unwrap(),
            );
            page = format!(
                r#"i64.const 0 local.set $target i32.const {target_offset} local.set $pos
                block $end_digits loop $digits
                  local.get $pos call $request i32.wrap_i64 i32.const 255 i32.and local.tee $digit i32.const 48 i32.lt_u br_if $end_digits
                  local.get $digit i32.const 57 i32.gt_u br_if $end_digits
                  local.get $target i64.const 10 i64.mul local.get $digit i32.const 48 i32.sub i64.extend_i32_u i64.add local.set $target
                  local.get $pos i32.const 1 i32.add local.set $pos br $digits
                end end
                i32.const {operation} local.get $target call $invoke i32.const 4 i32.eq
                if {not_found} else {page} end"#,
                operation = read.id
            );
        }
        branches = format!("{condition} if {page} else {branches} end");
    }
    let kind = format!("{{\"version\":{VERSION},\"kind\":{{").len() + 1;
    let execute = emit(&serde_json::to_vec(&ResponseIntent::Execute).unwrap());
    wat::parse_str(format!(r#"(component
      (import "noxide:application/host@0.1.0" (instance $h (export "emit" (func (param "word" u64) (param "length" u32))) (export "request-chunk" (func (param "offset" u32) (result u64))) (export "invoke" (func (param "operation" u32) (param "target" u64) (result u32)))))
      (alias export $h "emit" (func $emit)) (core func $emit (canon lower (func $emit)))
      (alias export $h "request-chunk" (func $request)) (core func $request (canon lower (func $request)))
      (alias export $h "invoke" (func $invoke)) (core func $invoke (canon lower (func $invoke)))
      (core module $m (import "h" "invoke" (func $invoke (param i32 i64) (result i32))) (import "h" "emit" (func $emit (param i64 i32))) (import "h" "request" (func $request (param i32) (result i64)))
        (func (export "handle") (local $target i64) (local $pos i32) (local $digit i32) i32.const {kind} call $request i32.wrap_i64 i32.const 255 i32.and i32.const 97 i32.eq if {execute} else {branches} end))
      (core instance $i (instantiate $m (with "h" (instance (export "emit" (func $emit)) (export "request" (func $request)) (export "invoke" (func $invoke))))))
      (func (export "handle") (canon lift (core func $i "handle"))))"#)).unwrap()
}
pub(super) struct Case {
    _temp: tempfile::TempDir,
    pub(super) db: Database,
    pub(super) app: Arc<Application>,
    pub(super) alice: String,
    pub(super) bob: String,
    pub(super) eve: String,
    pub(super) accounts: std::collections::BTreeMap<String, String>,
    pub(super) clock: Option<crate::application::clock::ClockService>,
}
impl Case {
    pub(super) async fn new(db: Option<Database>, m: Manifest) -> Self {
        Self::new_internal(db, m, false).await
    }
    pub(super) async fn indexed(db: Option<Database>, m: Manifest) -> Self {
        Self::new_internal(db, m, true).await
    }
    async fn new_internal(db: Option<Database>, m: Manifest, indexes: bool) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let db = db.unwrap_or_else(|| Database::sqlite(temp.path().join("computations.db")));
        db.initialize().await.unwrap();
        if indexes {
            db.reconcile_query_indexes(&m).await.unwrap();
        }
        let mut accounts = std::collections::BTreeMap::new();
        for (name, tenant) in [("alice", "team"), ("bob", "team"), ("eve", "other")] {
            accounts.insert(
                name.into(),
                db.create_account(name, "computation test password", tenant)
                    .await
                    .unwrap(),
            );
        }
        let app = Arc::new(
            Application::new(
                &component(&m, indexes),
                &serde_json::to_vec(&m).unwrap(),
                manifest::digest(&m).unwrap(),
                db.clone(),
                HostKeys::generate().unwrap(),
                Limits::default(),
                crate::DeploymentResources {
                    jobs: None,
                    assets: crate::assets::AssetBundle::default(),
                    blobs: None,
                },
            )
            .unwrap(),
        );
        app.activate().await.unwrap();
        let clock = Some(app.start_clock_service().unwrap());
        if m.resources
            .iter()
            .any(|resource| resource.name == "products")
        {
            let mut tx = db
                .begin(std::time::Instant::now() + Duration::from_secs(5))
                .await
                .unwrap();
            let storage = tx
                .storage_resource(&m, resource(&m, "products"))
                .await
                .unwrap();
            tx.allocate_creation().await.unwrap();
            let mut fields = Fields::from([
                ("name".into(), "Last product".into()),
                ("stock".into(), "10".into()),
                ("price_minor".into(), "125".into()),
                ("currency".into(), "sar".into()),
                ("active".into(), "true".into()),
            ]);
            let schema = manifest::resource(&m, resource(&m, "products")).unwrap();
            if schema.fields.iter().any(|field| field.name == "recipient") {
                fields.insert("recipient".into(), accounts["alice"].clone());
            }
            for field in &schema.fields {
                if let Some(value) = &field.initial {
                    fields.insert(field.name.clone(), value.clone());
                }
            }
            manifest::validate_fields(schema, &fields).unwrap();
            tx.execute("INSERT INTO nx_records(resource,id,owner,tenant,fields,incarnation,revision,created_seq) VALUES($1,42,$2,'team',$3,'product',1,(SELECT value FROM nx_creation_counter WHERE singleton=1))",&[storage.into(),accounts["alice"].as_str().into(),serde_json::to_string(&fields).unwrap().into()]).await.unwrap();
            tx.commit().await.unwrap();
        }
        let mut cookies = Vec::new();
        for name in ["alice", "bob", "eve"] {
            let challenge = app.login_challenge().await.unwrap();
            cookies.push(
                app.login(
                    &challenge.cookie,
                    &challenge.csrf,
                    name,
                    "computation test password",
                )
                .await
                .unwrap(),
            );
        }
        Self {
            _temp: temp,
            db,
            app,
            alice: cookies.remove(0),
            bob: cookies.remove(0),
            eve: cookies.remove(0),
            accounts,
            clock,
        }
    }
    pub(super) async fn close(mut self) {
        if let Some(clock) = self.clock.take() {
            clock.shutdown().await.unwrap();
        }
    }
    pub(super) async fn form(&self, cookie: &str, name: &str, target: u64) -> (String, String) {
        let binding = binding(&self.app.manifest, name);
        let route = self
            .app
            .manifest
            .routes
            .iter()
            .find(|route| route.forms.contains(&binding))
            .unwrap();
        let page = self
            .app
            .view(cookie, route.id, route.resource.map(|_| target))
            .await
            .unwrap();
        let html = String::from_utf8(page.body).unwrap();
        let form = html
            .split_once(&format!("action=\"/actions/{binding}\""))
            .unwrap_or_else(|| panic!("missing {name} form"))
            .1;
        (
            fixture::hidden(form, "_submission"),
            fixture::hidden(form, "_csrf"),
        )
    }
    pub(super) async fn submit(
        &self,
        cookie: &str,
        name: &str,
        form: &(String, String),
        input: Fields,
    ) -> std::result::Result<crate::render::Rendered, RequestError> {
        self.app
            .submit(
                cookie,
                binding(&self.app.manifest, name),
                &form.0,
                &form.1,
                input,
            )
            .await
    }
    pub(super) async fn records(&self, name: &str) -> Vec<(u64, Fields, i64)> {
        let mut tx = self
            .db
            .begin_read(std::time::Instant::now() + Duration::from_secs(3))
            .await
            .unwrap();
        let storage = tx
            .storage_resource(&self.app.manifest, resource(&self.app.manifest, name))
            .await
            .unwrap();
        let rows=tx.fetch::<3>("SELECT CAST(id AS TEXT),fields,CAST(revision AS TEXT) FROM nx_records WHERE resource=$1 ORDER BY id",&[storage.into()]).await.unwrap();
        tx.commit().await.unwrap();
        rows.into_iter()
            .map(|[id, fields, revision]| {
                (
                    id.parse().unwrap(),
                    serde_json::from_str(&fields).unwrap(),
                    revision.parse().unwrap(),
                )
            })
            .collect()
    }
    pub(super) async fn counts(&self) -> (u64, u64) {
        let mut tx = self
            .db
            .begin_read(std::time::Instant::now() + Duration::from_secs(3))
            .await
            .unwrap();
        let rows=tx.fetch::<2>("SELECT CAST((SELECT COUNT(*) FROM nx_records) AS TEXT),CAST((SELECT COUNT(*) FROM nx_receipts) AS TEXT)",&[]).await.unwrap();
        tx.commit().await.unwrap();
        (rows[0][0].parse().unwrap(), rows[0][1].parse().unwrap())
    }
    async fn product(&self, field: &str, value: &str) {
        let mut tx = self
            .db
            .begin(std::time::Instant::now() + Duration::from_secs(3))
            .await
            .unwrap();
        let storage = tx
            .storage_resource(&self.app.manifest, resource(&self.app.manifest, "products"))
            .await
            .unwrap();
        let stored = repository::load(
            &mut tx,
            &self.app.manifest,
            resource(&self.app.manifest, "products"),
            42,
        )
        .await
        .unwrap()
        .unwrap();
        let mut fields = stored.record.fields;
        fields.insert(field.into(), value.into());
        tx.execute(
            "UPDATE nx_records SET fields=$1,revision=revision+1 WHERE resource=$2 AND id=42",
            &[
                serde_json::to_string(&fields).unwrap().into(),
                storage.into(),
            ],
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }
}
fn quantity(value: &str) -> Fields {
    Fields::from([("quantity".into(), value.into())])
}

async fn reservation_contract(db: Option<Database>) {
    let case = Case::new(db, declarations()).await;
    let original = case.form(&case.bob, "Reserve", 42).await;
    assert!(matches!(
        case.submit(&case.eve, "Reserve", &original, quantity("1"))
            .await,
        Err(RequestError::InvalidRequest)
    ));
    assert!(matches!(
        case.submit(&case.alice, "Reserve", &original, quantity("1"))
            .await,
        Err(RequestError::InvalidRequest)
    ));
    let mut forged = quantity("3");
    forged.insert("total_minor".into(), "1".into());
    assert!(matches!(
        case.submit(&case.bob, "Reserve", &original, forged).await,
        Err(RequestError::InvalidRequest)
    ));

    let saved = case
        .submit(&case.bob, "Reserve", &original, quantity("3"))
        .await
        .unwrap();
    assert_eq!(saved.status, 303);
    let orders = case.records("orders").await;
    assert_eq!(orders.len(), 1);
    let (id, order, _) = &orders[0];
    assert_eq!(order["product"], "42");
    assert_eq!(order["quantity"], "3");
    assert_eq!(order["unit_price_minor"], "125");
    assert_eq!(order["total_minor"], "375");
    assert_eq!(order["currency"], "sar");
    assert_eq!(
        order["expires_at"].parse::<i64>().unwrap() - order["reserved_at"].parse::<i64>().unwrap(),
        900000
    );
    assert_eq!(case.records("products").await[0].1["stock"], "7");
    assert!(matches!(
        case.submit(&case.bob, "Reserve", &original, quantity("2"))
            .await,
        Err(RequestError::InvalidRequest)
    ));
    let replay = case
        .submit(&case.bob, "Reserve", &original, quantity("3"))
        .await
        .unwrap();
    assert_eq!(replay.location, saved.location);
    let first = case.form(&case.bob, "Cancel", *id).await;
    let other = case.form(&case.bob, "Cancel", *id).await;
    let cancelled = case
        .submit(&case.bob, "Cancel", &first, Fields::new())
        .await
        .unwrap();
    assert_eq!(cancelled.status, 303);
    assert_eq!(case.records("products").await[0].1["stock"], "10");
    assert_eq!(case.records("orders").await[0].1["status"], "cancelled");
    assert_eq!(
        case.submit(&case.bob, "Cancel", &first, Fields::new())
            .await
            .unwrap()
            .status,
        303
    );
    assert_eq!(
        case.submit(&case.bob, "Cancel", &other, Fields::new())
            .await
            .unwrap()
            .status,
        409
    );
    let fresh = case.form(&case.bob, "Cancel", *id).await;
    let guard = case
        .submit(&case.bob, "Cancel", &fresh, Fields::new())
        .await
        .unwrap();
    assert_eq!(guard.status, 422);
    assert!(
        String::from_utf8(guard.body)
            .unwrap()
            .contains("no longer pending")
    );
    assert_eq!(case.records("products").await[0].1["stock"], "10");
    assert_eq!(case.counts().await, (2, 2));
    case.close().await;
}
#[tokio::test]
async fn sqlite_authoritative_price_cancellation_and_replay() {
    reservation_contract(None).await;
}

async fn rollback_contract(db: Option<Database>) {
    let case = Case::new(db, declarations()).await;
    let stale = case.form(&case.bob, "Reserve", 42).await;
    case.product("price_minor", "150").await;
    assert_eq!(
        case.submit(&case.bob, "Reserve", &stale, quantity("1"))
            .await
            .unwrap()
            .status,
        409
    );
    assert_eq!(case.counts().await, (1, 0));
    let fresh = case.form(&case.bob, "Reserve", 42).await;
    let unknown = crate::failure_tests::lose_commit_ack(case.submit(
        &case.bob,
        "Reserve",
        &fresh,
        quantity("1"),
    ))
    .await;
    assert!(matches!(unknown, Err(RequestError::OutcomeUnknown)));
    assert_eq!(case.counts().await, (2, 1));
    assert_eq!(
        case.submit(&case.bob, "Reserve", &fresh, quantity("1"))
            .await
            .unwrap()
            .status,
        303
    );
    let committed = fresh.clone();
    let id = case.records("orders").await[0].0;
    let cancel = case.form(&case.bob, "Cancel", id).await;
    case.product("stock", "1000").await;
    assert_eq!(
        case.submit(&case.bob, "Cancel", &cancel, Fields::new())
            .await
            .unwrap()
            .status,
        422
    );
    assert_eq!(case.records("orders").await[0].1["status"], "pending");
    assert_eq!(case.counts().await, (2, 1));
    // A stale/unavailable lifecycle clock cannot undo or re-execute committed work.
    let fresh = case.form(&case.bob, "Reserve", 42).await;
    case.app.lifecycle_clock.quarantine();
    assert_eq!(
        case.submit(&case.bob, "Reserve", &committed, quantity("1"))
            .await
            .unwrap()
            .status,
        303
    );
    assert!(matches!(
        case.submit(&case.bob, "Reserve", &fresh, quantity("1"))
            .await,
        Err(RequestError::Busy)
    ));
    assert_eq!(case.counts().await, (2, 1));
    case.close().await;
}
#[tokio::test]
async fn sqlite_reviewed_price_rollback_unknown_commit_and_clock() {
    rollback_contract(None).await;
}

#[test]
fn admission_rejects_forged_types_review_projections_current_reads_and_limits() {
    let m = declarations();
    let ri = m.actions.iter().position(|a| a.name == "Reserve").unwrap();
    let ci = m.actions.iter().position(|a| a.name == "Cancel").unwrap();
    let mut bad = m.clone();
    bad.actions[ri].targets[0].revision = Revision::Identity;
    assert!(
        manifest::validate(&bad)
            .unwrap_err()
            .to_string()
            .contains("reviewed source")
    );
    let mut bad = m.clone();
    bad.actions[ri].targets[0]
        .projection
        .as_mut()
        .unwrap()
        .fields
        .retain(|field| field != "price_minor");
    assert!(manifest::validate(&bad).is_err());
    let mut bad = m.clone();
    let target = bad.actions[ci]
        .targets
        .iter_mut()
        .find(|target| target.name == "order")
        .unwrap();
    target
        .projection
        .as_mut()
        .unwrap()
        .fields
        .retain(|field| field != "status");
    assert!(manifest::validate(&bad).is_err());
    let mut bad = m.clone();
    bad.actions[ri].steps[1]
        .assign
        .iter_mut()
        .find(|a| a.field == "total_minor")
        .unwrap()
        .change = Change::Set(Value::SnapshotField {
        target: "product".into(),
        field: "currency".into(),
        reviewed: true,
    });
    assert!(manifest::validate(&bad).is_err());
    for current in [
        Value::CurrentField {
            target: "product".into(),
            field: "price_minor".into(),
        },
        Value::Add {
            left: Box::new(Value::CurrentField {
                target: "product".into(),
                field: "price_minor".into(),
            }),
            right: Box::new(Value::Literal(Literal::Integer(1))),
        },
    ] {
        let mut bad = m.clone();
        bad.actions[ri].steps[1]
            .assign
            .iter_mut()
            .find(|a| a.field == "total_minor")
            .unwrap()
            .change = Change::Set(current);
        assert!(manifest::validate(&bad).is_err());
    }
    let mut bad = m.clone();
    let Change::Decrease { by, .. } = &mut bad.actions[ri].steps[0].assign[0].change else {
        unreachable!()
    };
    *by = Value::CurrentField {
        target: "product".into(),
        field: "price_minor".into(),
    };
    assert!(manifest::validate(&bad).is_err());
    let mut bad = m.clone();
    bad.actions[ci].steps[0].guards[0].condition = GuardCondition::Compare {
        left: Value::CurrentField {
            target: "product".into(),
            field: "price_minor".into(),
        },
        comparison: Comparison::Equal,
        right: Value::Literal(Literal::Integer(1)),
    };
    assert!(manifest::validate(&bad).is_err());
    let mut deep = Value::Literal(Literal::Integer(1));
    for _ in 0..8 {
        deep = Value::Add {
            left: Box::new(deep),
            right: Box::new(Value::Literal(Literal::Integer(1))),
        }
    }
    let mut bad = m.clone();
    bad.actions[ri].steps[1]
        .assign
        .iter_mut()
        .find(|a| a.field == "total_minor")
        .unwrap()
        .change = Change::Set(deep);
    assert!(
        manifest::validate(&bad)
            .unwrap_err()
            .to_string()
            .contains("node/depth")
    );
    fn tree(depth: u8) -> Value {
        if depth == 0 {
            Value::Literal(Literal::Integer(1))
        } else {
            Value::Add {
                left: Box::new(tree(depth - 1)),
                right: Box::new(tree(depth - 1)),
            }
        }
    }
    let mut bad = m.clone();
    let Change::Decrease { by, .. } = &mut bad.actions[ri].steps[0].assign[0].change else {
        unreachable!()
    };
    *by = tree(6);
    assert!(
        manifest::validate(&bad)
            .unwrap_err()
            .to_string()
            .contains("node/depth")
    );
    let mut bad = m.clone();
    let guard = bad.actions[ci].steps[0].guards[0].clone();
    bad.actions[ci].steps[0].guards = vec![guard; 9];
    assert!(
        manifest::validate(&bad)
            .unwrap_err()
            .to_string()
            .contains("guard count")
    );
    let mut bad = m.clone();
    bad.actions[ci].steps[0].guards[0].rejection.input = Some("caller_quantity".into());
    assert!(manifest::validate(&bad).is_err());
    let mut bad = m.clone();
    bad.actions[ci].steps[0].assign[0].change = Change::Set(Value::Principal);
    assert!(manifest::validate(&bad).is_err());
    let original = manifest::digest(&m).unwrap();
    let mut reordered = m.clone();
    reordered.actions[ri].steps[1].assign.reverse();
    assert_eq!(original, manifest::digest(&reordered).unwrap());
    let mut changed = m.clone();
    if let Change::Set(Value::SnapshotField { reviewed, .. }) = &mut changed.actions[ri].steps[1]
        .assign
        .iter_mut()
        .find(|a| a.field == "currency")
        .unwrap()
        .change
    {
        *reviewed = false;
    }
    assert_ne!(original, manifest::digest(&changed).unwrap());
    let mut changed = m.clone();
    changed.actions[ri].steps.reverse();
    changed
        .web_bindings
        .iter_mut()
        .find(|b| b.action == m.actions[ri].id)
        .unwrap()
        .redirect
        .source = RedirectSource::Step(0);
    assert_ne!(original, manifest::digest(&changed).unwrap());
    let disclosures = manifest::action_disclosures(&m, m.actions[ri].id).unwrap();
    assert!(disclosures.iter().any(|disclosure|matches!(&disclosure.source,manifest::ComputationSource::Snapshot{field,reviewed:true,..}if field=="price_minor")&&disclosure.destination_field.as_deref()==Some("total_minor")));
}

fn snapshot_plan() -> Manifest {
    let mut m = declarations();
    let product = resource(&m, "products");
    m.resources
        .iter_mut()
        .find(|r| r.id == product)
        .unwrap()
        .fields
        .iter_mut()
        .find(|f| f.name == "price_minor")
        .unwrap()
        .kind = FieldKind::Integer {
        min: Some(0),
        max: Some(1000),
    };
    for action in &mut m.actions {
        for input in &mut action.inputs {
            if input.name == "price_minor" {
                input.kind = FieldKind::Integer {
                    min: Some(0),
                    max: Some(1000),
                }
            }
        }
    }
    let edit = action(&m, "Edit product").steps[0].operation;
    let ri = m.actions.iter().position(|a| a.name == "Reserve").unwrap();
    let a = &mut m.actions[ri];
    a.targets[0]
        .projection
        .as_mut()
        .unwrap()
        .fields
        .push("stock".into());
    let compare = |left, right| Guard {
        condition: GuardCondition::Compare {
            left,
            comparison: Comparison::Equal,
            right: Value::Literal(Literal::Integer(right)),
        },
        rejection: GuardRejection {
            input: None,
            message: "Current stock guard failed.".into(),
        },
    };
    a.steps[0].operation = edit;
    a.steps[0].assign = vec![
        Assignment {
            field: "stock".into(),
            change: Change::Set(Value::SnapshotField {
                target: "product".into(),
                field: "price_minor".into(),
                reviewed: true,
            }),
        },
        Assignment {
            field: "price_minor".into(),
            change: Change::Set(Value::Literal(Literal::Integer(126))),
        },
    ];
    a.steps[0].guards.push(compare(
        Value::CurrentField {
            target: "product".into(),
            field: "stock".into(),
        },
        10,
    ));
    a.steps.insert(
        1,
        Step {
            operation: edit,
            target: Target::Named("product".into()),
            guards: vec![Guard {
                condition: GuardCondition::All(vec![
                    compare(
                        Value::CurrentField {
                            target: "product".into(),
                            field: "stock".into(),
                        },
                        125,
                    )
                    .condition,
                    compare(
                        Value::SnapshotField {
                            target: "product".into(),
                            field: "stock".into(),
                            reviewed: false,
                        },
                        10,
                    )
                    .condition,
                ]),
                rejection: GuardRejection {
                    input: None,
                    message: "Current/snapshot distinction failed.".into(),
                },
            }],
            assign: vec![
                Assignment {
                    field: "stock".into(),
                    change: Change::Set(Value::SnapshotField {
                        target: "product".into(),
                        field: "stock".into(),
                        reviewed: false,
                    }),
                },
                Assignment {
                    field: "price_minor".into(),
                    change: Change::Set(Value::Literal(Literal::Integer(127))),
                },
            ],
        },
    );
    m.web_bindings
        .iter_mut()
        .find(|binding| binding.action == m.actions[ri].id)
        .unwrap()
        .redirect
        .source = RedirectSource::Step(2);
    manifest::validate(&m).unwrap();
    m
}
#[tokio::test]
async fn initial_snapshots_current_guards_self_writes_and_assignment_order_are_distinct() {
    let original = snapshot_plan();
    let digest = manifest::digest(&original).unwrap();
    for reversed in [false, true] {
        let mut m = original.clone();
        if reversed {
            for step in &mut m
                .actions
                .iter_mut()
                .find(|a| a.name == "Reserve")
                .unwrap()
                .steps
            {
                step.assign.reverse();
            }
        }
        assert_eq!(manifest::digest(&m).unwrap(), digest);
        let case = Case::new(None, m).await;
        let form = case.form(&case.alice, "Reserve", 42).await;
        assert_eq!(
            case.submit(&case.alice, "Reserve", &form, quantity("1"))
                .await
                .unwrap()
                .status,
            303
        );
        let product = case.records("products").await;
        assert_eq!(product[0].1["stock"], "10");
        assert_eq!(product[0].1["price_minor"], "127");
        assert_eq!(product[0].2, 3);
        let order = case.records("orders").await;
        assert_eq!(order[0].1["unit_price_minor"], "125");
        case.close().await;
    }
}

fn proposed_manifest(principal: bool) -> Manifest {
    let mut m = declarations();
    let product = resource(&m, "products");
    m.resources
        .iter_mut()
        .find(|r| r.id == product)
        .unwrap()
        .fields
        .extend([
            TextField {
                immutable: false,
                name: "recipient".into(),
                label: "Recipient".into(),
                kind: FieldKind::Account {
                    scope: AccountScope::SameTenant,
                },
                optional: false,
                initial: None,
                max_bytes: 43,
            },
            TextField {
                immutable: false,
                name: "marker".into(),
                label: "Marker".into(),
                kind: FieldKind::Boolean,
                optional: false,
                initial: Some("true".into()),
                max_bytes: 32,
            },
        ]);
    let create = action(&m, "Create product").steps[0].operation;
    m.operations
        .iter_mut()
        .find(|o| o.id == create)
        .unwrap()
        .policy = Policy {
        any: vec![vec![
            Predicate::SameTenant,
            Predicate::PrincipalIs {
                field: "recipient".into(),
            },
        ]],
    };
    let mut order = action(&m, "Reserve").steps[1].clone();
    for assignment in &mut order.assign {
        assignment.change = Change::Set(match assignment.field.as_str() {
            "product" => Value::Created(0),
            "quantity" => Value::Literal(Literal::Integer(1)),
            "unit_price_minor" | "total_minor" => Value::Literal(Literal::Integer(125)),
            "currency" => Value::Literal(Literal::Choice("sar".into())),
            _ => {
                if let Change::Set(value) = &assignment.change {
                    value.clone()
                } else {
                    unreachable!()
                }
            }
        });
    }
    let a = m
        .actions
        .iter_mut()
        .find(|a| a.name == "Create product")
        .unwrap();
    if !principal {
        a.inputs.push(Input {
            name: "recipient".into(),
            label: "Recipient".into(),
            kind: FieldKind::Account {
                scope: AccountScope::SameTenant,
            },
            optional: false,
            max_bytes: 43,
        });
    }
    a.steps[0].assign.push(Assignment {
        field: "recipient".into(),
        change: Change::Set(if principal {
            Value::Principal
        } else {
            Value::Input("recipient".into())
        }),
    });
    a.steps.push(order);
    let id = a.id;
    let destination = route(&m, "orders");
    let binding = m.web_bindings.iter_mut().find(|b| b.action == id).unwrap();
    binding.redirect.route = destination;
    binding.redirect.source = RedirectSource::Step(1);
    manifest::validate(&m).unwrap();
    m
}
fn product_input() -> Fields {
    Fields::from([
        ("name".into(), "Created product".into()),
        ("stock".into(), "1".into()),
        ("price_minor".into(), "125".into()),
        ("currency".into(), "sar".into()),
        ("active".into(), "true".into()),
    ])
}
async fn proposed_contract(db: Option<Database>) {
    let case = Case::new(db, proposed_manifest(false)).await;
    let form = case.form(&case.alice, "Create product", 0).await;
    for account in [
        case.accounts["bob"].clone(),
        case.accounts["eve"].clone(),
        "A".repeat(43),
    ] {
        let mut fields = product_input();
        fields.insert("recipient".into(), account);
        let denied = case
            .submit(&case.alice, "Create product", &form, fields)
            .await
            .unwrap();
        assert_eq!(denied.status, 404);
        assert_eq!(case.counts().await, (1, 0));
    }
    let mut tx = case
        .db
        .begin(std::time::Instant::now() + Duration::from_secs(3))
        .await
        .unwrap();
    tx.execute(
        "UPDATE nx_accounts SET state='disabled' WHERE id=$1",
        &[case.accounts["bob"].as_str().into()],
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let mut fields = product_input();
    fields.insert("recipient".into(), case.accounts["bob"].clone());
    assert_eq!(
        case.submit(&case.alice, "Create product", &form, fields)
            .await
            .unwrap()
            .status,
        404
    );
    let mut fields = product_input();
    fields.insert("recipient".into(), case.accounts["alice"].clone());
    assert_eq!(
        case.submit(&case.alice, "Create product", &form, fields.clone())
            .await
            .unwrap()
            .status,
        303
    );
    assert_eq!(
        case.submit(&case.alice, "Create product", &form, fields)
            .await
            .unwrap()
            .status,
        303
    );
    let products = case.records("products").await;
    let created = products.iter().find(|row| row.0 != 42).unwrap();
    assert_eq!(created.1["recipient"], case.accounts["alice"]);
    assert_eq!(created.1["marker"], "true");
    assert_eq!(
        case.records("orders").await[0].1["product"],
        created.0.to_string()
    );
    assert_eq!(case.counts().await, (3, 1));
    case.close().await;
}
#[tokio::test]
async fn sqlite_canonical_proposed_row_account_policy_and_created_reference() {
    proposed_contract(None).await;
    let case = Case::new(None, proposed_manifest(true)).await;
    let form = case.form(&case.alice, "Create product", 0).await;
    assert_eq!(
        case.submit(&case.alice, "Create product", &form, product_input())
            .await
            .unwrap()
            .status,
        303
    );
    let product = case
        .records("products")
        .await
        .into_iter()
        .find(|row| row.0 != 42)
        .unwrap();
    assert_eq!(product.1["recipient"], case.accounts["alice"]);
    case.close().await;
}
async fn overflow_contract(db: Option<Database>) {
    let mut m = declarations();
    for r in &mut m.resources {
        for field in &mut r.fields {
            if matches!(
                field.name.as_str(),
                "price_minor" | "unit_price_minor" | "total_minor"
            ) {
                field.kind = FieldKind::Integer {
                    min: Some(0),
                    max: Some(i64::MAX),
                };
            }
        }
    }
    for a in &mut m.actions {
        for input in &mut a.inputs {
            if input.name == "price_minor" {
                input.kind = FieldKind::Integer {
                    min: Some(0),
                    max: Some(i64::MAX),
                };
            }
        }
    }
    let total = &mut m
        .actions
        .iter_mut()
        .find(|a| a.name == "Reserve")
        .unwrap()
        .steps[1]
        .assign
        .iter_mut()
        .find(|a| a.field == "total_minor")
        .unwrap()
        .change;
    let Change::Set(value) = total else {
        unreachable!()
    };
    let original = value.clone();
    *value = Value::Subtract {
        left: Box::new(Value::Add {
            left: Box::new(original),
            right: Box::new(Value::Literal(Literal::Integer(7))),
        }),
        right: Box::new(Value::Literal(Literal::Integer(7))),
    };
    manifest::validate(&m).unwrap();
    let case = Case::new(db, m).await;
    let first = case.form(&case.bob, "Reserve", 42).await;
    assert_eq!(
        case.submit(&case.bob, "Reserve", &first, quantity("2"))
            .await
            .unwrap()
            .status,
        303
    );
    assert_eq!(case.records("orders").await[0].1["total_minor"], "250");
    case.product("price_minor", &i64::MAX.to_string()).await;
    let form = case.form(&case.bob, "Reserve", 42).await;
    assert!(matches!(
        case.submit(&case.bob, "Reserve", &form, quantity("2"))
            .await,
        Err(RequestError::InvalidRequest)
    ));
    assert_eq!(case.records("products").await[0].1["stock"], "8");
    assert_eq!(case.counts().await, (2, 1));
    case.close().await;
}
#[tokio::test]
async fn sqlite_checked_expression_overflow_rolls_back_prior_step() {
    overflow_contract(None).await;
}
async fn concurrent_contract(db: Option<Database>) {
    let case = Case::new(db, declarations()).await;
    case.product("stock", "1").await;
    let a = case.form(&case.bob, "Reserve", 42).await;
    let b = case.form(&case.alice, "Reserve", 42).await;
    let (a, b) = tokio::join!(
        case.submit(&case.bob, "Reserve", &a, quantity("1")),
        case.submit(&case.alice, "Reserve", &b, quantity("1"))
    );
    let a = a.unwrap();
    let b = b.unwrap();
    assert!(matches!((a.status, b.status), (303, 409) | (409, 303)));
    assert_eq!(case.counts().await, (2, 1));
    let owner = if a.status == 303 {
        &case.bob
    } else {
        &case.alice
    };
    let id = case.records("orders").await[0].0;
    let form = case.form(owner, "Cancel", id).await;
    let (a, b) = tokio::join!(
        case.submit(owner, "Cancel", &form, Fields::new()),
        case.submit(owner, "Cancel", &form, Fields::new())
    );
    assert_eq!(a.unwrap().status, 303);
    assert_eq!(b.unwrap().status, 303);
    assert_eq!(case.records("products").await[0].1["stock"], "1");
    assert_eq!(case.counts().await, (2, 2));
    case.close().await;
}
#[tokio::test]
async fn sqlite_review_conflict_and_same_token_cancellation_converge() {
    concurrent_contract(None).await;
}
#[tokio::test]
#[ignore = "requires NOXIDE_TEST_POSTGRES disposable server"]
async fn postgres_computed_reservation_proposed_row_overflow_and_concurrency() {
    use sqlx::Connection;
    let url = std::env::var("NOXIDE_TEST_POSTGRES").unwrap();
    let mut admin = sqlx::PgConnection::connect(&url).await.unwrap();
    for index in 0..5 {
        let name = format!("nx_compute_{}_{}", std::process::id(), index);
        sqlx::query(&format!("CREATE DATABASE {name}"))
            .execute(&mut admin)
            .await
            .unwrap();
        let mut case = url::Url::parse(&url).unwrap();
        case.set_path(&format!("/{name}"));
        let db = Some(Database::postgres(case.as_str()).unwrap());
        match index {
            0 => reservation_contract(db).await,
            1 => rollback_contract(db).await,
            2 => proposed_contract(db).await,
            3 => overflow_contract(db).await,
            _ => concurrent_contract(db).await,
        };
        sqlx::query(&format!("DROP DATABASE {name} WITH (FORCE)"))
            .execute(&mut admin)
            .await
            .unwrap();
    }
}

#[test]
fn zero_input_headless_expiry_contract_has_no_web_or_synthetic_route() {
    let mut m = declarations();
    let mut expiry = action(&m, "Cancel").clone();
    expiry.id = 991;
    expiry.name = "Expire reservation".into();
    let order_resource = resource(&m, "orders");
    let eligible = m
        .operations
        .iter()
        .find(|o| o.resource == order_resource && o.kind == OperationKind::Read)
        .unwrap()
        .id;
    let mut list = m
        .operations
        .iter()
        .find(|operation| operation.id == eligible)
        .unwrap()
        .clone();
    list.id = 992;
    list.kind = OperationKind::List;
    list.list = Some(ListSettings {
        preview: None,
        order: ListOrder::CreatedAsc,
        page_size: 20,
    });
    let query = list.id;
    m.operations.push(list);
    expiry
        .targets
        .iter_mut()
        .find(|t| t.name == "order")
        .unwrap()
        .source = TargetSource::Selected {
        query,
        eligible,
        label: vec!["status".into()],
    };
    expiry.steps[0].guards.push(Guard {
        condition: GuardCondition::Compare {
            left: Value::CurrentField {
                target: "order".into(),
                field: "expires_at".into(),
            },
            comparison: Comparison::LessOrEqual,
            right: Value::TransactionTime,
        },
        rejection: GuardRejection {
            input: None,
            message: "Not expired".into(),
        },
    });
    expiry.steps[0].assign[0].change =
        Change::Set(Value::Literal(Literal::Choice("expired".into())));
    m.actions = vec![expiry];
    m.routes.clear();
    m.web_bindings.clear();
    manifest::validate(&m).unwrap();
    assert!(ActionCore::of(&m.actions[0]).unwrap().uses_time());
    assert!(m.actions[0].inputs.is_empty());
}
#[tokio::test]
async fn timestamp_overflow_is_checked_before_order_write() {
    let mut m = declarations();
    let a = m.actions.iter_mut().find(|a| a.name == "Reserve").unwrap();
    a.steps[1]
        .assign
        .iter_mut()
        .find(|a| a.field == "expires_at")
        .unwrap()
        .change = Change::Set(Value::Add {
        left: Box::new(Value::Literal(Literal::Timestamp(
            noxide_protocol::time::Timestamp::from_unix_millis(i64::MAX).unwrap(),
        ))),
        right: Box::new(Value::Literal(Literal::Duration(
            noxide_protocol::time::Duration::from_secs(1).unwrap(),
        ))),
    });
    manifest::validate(&m).unwrap();
    let case = Case::new(None, m).await;
    let form = case.form(&case.bob, "Reserve", 42).await;
    assert!(matches!(
        case.submit(&case.bob, "Reserve", &form, quantity("1"))
            .await,
        Err(RequestError::InvalidRequest)
    ));
    assert_eq!(case.counts().await, (1, 0));
    assert_eq!(case.records("products").await[0].1["stock"], "10");
    case.close().await;
}
