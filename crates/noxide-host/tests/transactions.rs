#[allow(dead_code)]
mod support;

use noxide_host::{Application, Database, HostKeys, manifest, runtime::Limits};
use noxide_protocol::*;
use sqlx::{Connection, Row};
use std::{sync::Arc, time::Duration};

fn declarations() -> Manifest {
    let mut m: Manifest = serde_json::from_value(serde_json::json!({
        "version": VERSION,
        "resources": [
            {"id":1,"name":"products","fields":[
                {"kind":{"integer":{"min":0,"max":10}},"optional":false,"initial":null,"name":"stock","label":"Stock","max_bytes":20},
                {"kind":"boolean","optional":false,"initial":null,"name":"open","label":"Open","max_bytes":5},
                {"kind":{"integer":{"min":i64::MIN,"max":i64::MAX}},"optional":false,"initial":null,"name":"counter","label":"Counter","max_bytes":20}]},
            {"id":2,"name":"orders","fields":[
                {"kind":{"integer":{"min":1,"max":10}},"optional":false,"initial":null,"name":"quantity","label":"Quantity","max_bytes":20},
                {"kind":{"reference":{"resource":"products"}},"optional":false,"initial":null,"name":"product","label":"Product","max_bytes":19}],
                "gate":{"field":"product","visible":{"field":"open","equals":"true"},"create_when":{"field":"open","equals":"true"}}},
            {"id":3,"name":"order_notes","fields":[
                {"kind":"text","optional":false,"initial":null,"name":"body","label":"Note","max_bytes":200},
                {"kind":{"reference":{"resource":"orders"}},"optional":false,"initial":null,"name":"order","label":"Order","max_bytes":19}]}
        ],
        "operations":[
            {"id":1,"resource":1,"kind":"read","policy":{"any":[["owner"]]}},
            {"id":2,"resource":1,"kind":"update","policy":{"any":[["owner",{"role":{"name":"stock","tenant_scoped":false}}]]}},
            {"id":3,"resource":2,"kind":"create","policy":{"any":[["owner"]]},"bind":{"field":"product","eligible":1}},
            {"id":4,"resource":2,"kind":"read","policy":{"any":[["owner"]]}},
            {"id":5,"resource":3,"kind":"create","policy":{"any":[["owner",{"role":{"name":"notes","tenant_scoped":false}}]]},"bind":{"field":"order","eligible":4}},
            {"id":6,"resource":3,"kind":"read","policy":{"any":[["owner"]]}}
        ],
        "routes":[
            {"id":1,"path":"/","resource":null,"operations":[],"forms":[]},
            {"id":2,"path":"/products/{product}","resource":1,"operations":[1],"forms":[1,2,3,4,5,6,7,8]},
            {"id":3,"path":"/orders/{order}","resource":2,"operations":[4],"forms":[]},
            {"id":4,"path":"/order_notes/{note}","resource":3,"operations":[6],"forms":[]}
        ],
        "actions": [
            {"id":1,"version":1,"name":"Place order","revision":"identity","layout":[],"inspect":null,
             "inputs":[{"name":"quantity","label":"Quantity","kind":{"integer":{"min":1,"max":10}},"optional":false,"max_bytes":20},{"name":"body","label":"Note","kind":"text","optional":false,"max_bytes":200}],
             "steps":[
                {"operation":2,"target":"signed","assign":[{"field":"stock","change":{"decrease":{"by":"quantity","rejection":{"input":"quantity","message":"Not enough stock"}}}}]},
                {"operation":3,"target":"none","assign":[{"field":"quantity","change":{"set":{"input":"quantity"}}},{"field":"product","change":{"set":"signed_target"}}]},
                {"operation":5,"target":"none","assign":[{"field":"body","change":{"set":{"input":"body"}}},{"field":"order","change":{"set":{"created":1}}}]}],
             "redirect":{"route":3,"source":{"step":1}}},
            {"id":2,"version":1,"name":"Edit stock","revision":"exact","layout":[],"inspect":{"operation":1,"fields":["stock"]},
             "inputs":[{"name":"stock","label":"Stock","kind":{"integer":{"min":0,"max":10}},"optional":false,"max_bytes":20}],
             "steps":[{"operation":2,"target":"signed","assign":[{"field":"stock","change":{"set":{"input":"stock"}}}]}],
             "redirect":{"route":2,"source":"signed"}},
            {"id":3,"version":1,"name":"Two signed steps","revision":"identity","layout":[],"inspect":null,
             "inputs":[{"name":"quantity","label":"Quantity","kind":{"integer":{"min":1,"max":10}},"optional":false,"max_bytes":20}],
             "steps":[
                {"operation":2,"target":"signed","assign":[{"field":"stock","change":{"increase":{"by":"quantity","rejection":{"input":"quantity","message":"Stock limit"}}}}]},
                {"operation":2,"target":"signed","assign":[{"field":"stock","change":{"decrease":{"by":"quantity","rejection":{"input":"quantity","message":"Not enough stock"}}}}]}],
             "redirect":{"route":2,"source":"signed"}},
            {"id":4,"version":1,"name":"Open then order","revision":"exact","layout":[],"inspect":null,
             "inputs":[{"name":"quantity","label":"Quantity","kind":{"integer":{"min":1,"max":10}},"optional":false,"max_bytes":20}],
             "steps":[
                {"operation":2,"target":"signed","assign":[{"field":"open","change":{"set":{"constant":"true"}}}]},
                {"operation":3,"target":"none","assign":[{"field":"quantity","change":{"set":{"input":"quantity"}}},{"field":"product","change":{"set":"signed_target"}}]}],
             "redirect":{"route":3,"source":{"step":1}}},
            {"id":5,"version":1,"name":"Close then order","revision":"exact","layout":[],"inspect":null,
             "inputs":[{"name":"quantity","label":"Quantity","kind":{"integer":{"min":1,"max":10}},"optional":false,"max_bytes":20}],
             "steps":[
                {"operation":2,"target":"signed","assign":[{"field":"open","change":{"set":{"constant":"false"}}}]},
                {"operation":3,"target":"none","assign":[{"field":"quantity","change":{"set":{"input":"quantity"}}},{"field":"product","change":{"set":"signed_target"}}]}],
             "redirect":{"route":3,"source":{"step":1}}},
            {"id":6,"version":1,"name":"Increase counter","revision":"identity","layout":[],"inspect":null,
             "inputs":[{"name":"quantity","label":"Quantity","kind":{"integer":{"min":1,"max":10}},"optional":false,"max_bytes":20}],
             "steps":[{"operation":2,"target":"signed","assign":[{"field":"counter","change":{"increase":{"by":"quantity","rejection":{"input":"quantity","message":"Counter upper bound"}}}}]}],
             "redirect":{"route":2,"source":"signed"}},
            {"id":7,"version":1,"name":"Decrease counter","revision":"identity","layout":[],"inspect":null,
             "inputs":[{"name":"quantity","label":"Quantity","kind":{"integer":{"min":1,"max":10}},"optional":false,"max_bytes":20}],
             "steps":[{"operation":2,"target":"signed","assign":[{"field":"counter","change":{"decrease":{"by":"quantity","rejection":{"input":"quantity","message":"Counter lower bound"}}}}]}],
             "redirect":{"route":2,"source":"signed"}},
            {"id":8,"version":1,"name":"Increase stock","revision":"identity","layout":[],"inspect":null,
             "inputs":[{"name":"quantity","label":"Quantity","kind":{"integer":{"min":1,"max":10}},"optional":false,"max_bytes":20}],
             "steps":[{"operation":2,"target":"signed","assign":[{"field":"stock","change":{"increase":{"by":"quantity","rejection":{"input":"quantity","message":"Stock upper bound"}}}}]}],
             "redirect":{"route":2,"source":"signed"}}
        ]
    })).unwrap();
    for (id, count) in [(9, 2), (10, 3)] {
        let mut action = m.actions[2].clone();
        action.id = id;
        action.name = format!("Guard rollback {count}");
        action.steps = vec![m.actions[0].steps[0].clone(); count];
        m.actions.push(action);
    }
    let mut guarded_route = m.routes[1].clone();
    guarded_route.id = 5;
    guarded_route.path = "/guardedproducts/{product}".into();
    guarded_route.forms = vec![9, 10];
    m.routes.push(guarded_route);
    m
}

fn emit(bytes: &[u8]) -> String {
    bytes
        .chunks(8)
        .map(|part| {
            let mut word = [0; 8];
            word[..part.len()].copy_from_slice(part);
            format!(
                "i64.const {} i32.const {} call $emit\n",
                i64::from_le_bytes(word),
                part.len()
            )
        })
        .collect()
}

fn component(mode: &str) -> Vec<u8> {
    let page = serde_json::to_vec(&ResponseIntent::Page(Document::new(
        "Product",
        (1..=8).map(|action| Instruction::Form { action }).collect(),
    )))
    .unwrap();
    let decision = match mode {
        "reject" => emit(
            br#"{"rejected":{"field_errors":{"quantity":"Try again"},"message":"Nothing saved"}}"#,
        ),
        "trap" => "unreachable".into(),
        "deadline" => "(loop $forever br $forever)".into(),
        "invoke" => "i32.const 2 i64.const 0 call $invoke drop".into(),
        "follow-source" => "i32.const 1 i64.const 42 call $follow_source".into(),
        "follow" => "i32.const 1 call $follow drop".into(),
        "page" => emit(
            &serde_json::to_vec(&ResponseIntent::Page(Document::new(
                "Wrong decision",
                vec![],
            )))
            .unwrap(),
        ),
        "guest-outcome" => {
            emit(br#"{"created":{"resource":2,"id":1,"destination":{"route":3,"target":1}}}"#)
        }
        _ => emit(br#""execute""#),
    };
    let guarded_page = serde_json::to_vec(&ResponseIntent::Page(Document::new(
        "Guarded product",
        vec![
            Instruction::Form { action: 9 },
            Instruction::Form { action: 10 },
        ],
    )))
    .unwrap();
    let route = br#"{"version":1,"kind":{"route":"#.len();
    let kind = br#"{"version":1,"kind":{"#.len() + 1;
    wat::parse_str(format!(r#"(component
      (import "noxide:application/host@0.1.0" (instance $h
        (export "emit" (func (param "word" u64) (param "length" u32)))
        (export "request-chunk" (func (param "offset" u32) (result u64)))
        (export "invoke" (func (param "operation" u32) (param "target" u64) (result u32)))
        (export "follow-source" (func (param "resource" u32) (param "id" u64)))
        (export "follow" (func (param "operation" u32) (result u32)))))
      (alias export $h "emit" (func $emit)) (core func $emit (canon lower (func $emit)))
      (alias export $h "request-chunk" (func $request)) (core func $request (canon lower (func $request)))
      (alias export $h "invoke" (func $invoke)) (core func $invoke (canon lower (func $invoke)))
      (alias export $h "follow-source" (func $follow_source)) (core func $follow_source (canon lower (func $follow_source)))
      (alias export $h "follow" (func $follow)) (core func $follow (canon lower (func $follow)))
      (core module $m
        (import "h" "emit" (func $emit (param i64 i32)))
        (import "h" "request" (func $request (param i32) (result i64)))
        (import "h" "invoke" (func $invoke (param i32 i64) (result i32)))
        (import "h" "follow-source" (func $follow_source (param i32 i64)))
        (import "h" "follow" (func $follow (param i32) (result i32)))
        (func (export "handle")
          i32.const {kind} call $request i32.wrap_i64 i32.const 255 i32.and i32.const 97 i32.eq
          if {decision} else
            i32.const {route} call $request i32.wrap_i64 i32.const 255 i32.and i32.const 53 i32.eq
            if {guarded_page} else {page} end
          end))
      (core instance $i (instantiate $m (with "h" (instance
        (export "emit" (func $emit)) (export "request" (func $request))
        (export "invoke" (func $invoke)) (export "follow-source" (func $follow_source))
        (export "follow" (func $follow))))))
      (func (export "handle") (canon lift (core func $i "handle"))))"#, page=emit(&page),guarded_page=emit(&guarded_page))).unwrap()
}

enum Inspect {
    Sqlite(sqlx::SqliteConnection),
    Postgres(sqlx::PgConnection),
}
impl Inspect {
    async fn execute(&mut self, sql: &str) {
        match self {
            Self::Sqlite(c) => {
                sqlx::query(sql).execute(c).await.unwrap();
            }
            Self::Postgres(c) => {
                sqlx::query(sql).execute(c).await.unwrap();
            }
        }
    }
    async fn rows(&mut self, sql: &str, columns: usize) -> Vec<Vec<String>> {
        match self {
            Self::Sqlite(c) => sqlx::query(sql)
                .fetch_all(c)
                .await
                .unwrap()
                .iter()
                .map(|row| {
                    (0..columns)
                        .map(|index| row.get::<String, _>(index))
                        .collect()
                })
                .collect(),
            Self::Postgres(c) => sqlx::query(sql)
                .fetch_all(c)
                .await
                .unwrap()
                .iter()
                .map(|row| {
                    (0..columns)
                        .map(|index| row.get::<String, _>(index))
                        .collect()
                })
                .collect(),
        }
    }
    async fn state(&mut self) -> Vec<Vec<String>> {
        self.rows("SELECT CAST(resource AS TEXT),CAST(id AS TEXT),fields,incarnation,CAST(revision AS TEXT),(SELECT CAST(COUNT(*) AS TEXT) FROM nx_receipts),(SELECT CAST(value AS TEXT) FROM nx_creation_counter WHERE singleton=1) FROM nx_records ORDER BY resource,id", 7).await
    }
    async fn product(&mut self) -> (Fields, i64) {
        let rows = self
            .rows(
                "SELECT fields,CAST(revision AS TEXT) FROM nx_records WHERE resource=(SELECT storage_id FROM nx_resource_catalog WHERE resource_key='products') AND id=42",
                2,
            )
            .await;
        (
            serde_json::from_str(&rows[0][0]).unwrap(),
            rows[0][1].parse().unwrap(),
        )
    }
    async fn reset_product(&mut self, stock: i64, open: bool, counter: i64) {
        self.execute(&format!("UPDATE nx_records SET fields='{{\"stock\":\"{stock}\",\"open\":\"{open}\",\"counter\":\"{counter}\"}}' WHERE resource=(SELECT storage_id FROM nx_resource_catalog WHERE resource_key='products') AND id=42")).await;
    }
}

struct Case {
    db: Database,
    inspect: Inspect,
    app: Arc<Application>,
    alice: String,
    keys: Vec<u8>,
    _dir: Option<tempfile::TempDir>,
    postgres: Option<(sqlx::PgConnection, String)>,
}
impl Case {
    async fn sqlite() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("transactions.db");
        let db = Database::sqlite(&path);
        db.initialize().await.unwrap();
        let inspect = Inspect::Sqlite(
            sqlx::SqliteConnection::connect_with(
                &sqlx::sqlite::SqliteConnectOptions::new().filename(&path),
            )
            .await
            .unwrap(),
        );
        Self::new(db, inspect, Some(dir), None).await
    }
    async fn postgres() -> Self {
        let url = std::env::var("NOXIDE_TEST_POSTGRES").unwrap();
        let mut admin = sqlx::PgConnection::connect(&url).await.unwrap();
        let name = format!(
            "noxide_transactions_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        sqlx::query(&format!("CREATE DATABASE {name}"))
            .execute(&mut admin)
            .await
            .unwrap();
        let mut case = url::Url::parse(&url).unwrap();
        case.set_path(&format!("/{name}"));
        let db = Database::postgres(case.as_str()).unwrap();
        db.initialize().await.unwrap();
        let inspect = Inspect::Postgres(sqlx::PgConnection::connect(case.as_str()).await.unwrap());
        Self::new(db, inspect, None, Some((admin, name))).await
    }
    async fn new(
        db: Database,
        mut inspect: Inspect,
        dir: Option<tempfile::TempDir>,
        postgres: Option<(sqlx::PgConnection, String)>,
    ) -> Self {
        db.create_account("alice", "twelve word password", "one")
            .await
            .unwrap();
        db.create_account("bob", "another secure password", "one")
            .await
            .unwrap();
        let keys = serde_json::to_vec(&HostKeys::generate().unwrap()).unwrap();
        let app = Self::host(&db, &keys, "execute").await;
        inspect.execute("INSERT INTO nx_roles(principal,name,tenant) VALUES((SELECT id FROM nx_accounts WHERE login_name='alice'),'stock',''),((SELECT id FROM nx_accounts WHERE login_name='alice'),'notes','')").await;
        inspect
            .execute("UPDATE nx_creation_counter SET value=1 WHERE singleton=1")
            .await;
        inspect.execute("INSERT INTO nx_records(resource,id,owner,tenant,fields,incarnation,revision,created_seq) VALUES((SELECT storage_id FROM nx_resource_catalog WHERE resource_key='products'),42,(SELECT id FROM nx_accounts WHERE login_name='alice'),'one','{\"stock\":\"1\",\"open\":\"true\",\"counter\":\"0\"}','product-incarnation',1,1)").await;
        let challenge = app.login_challenge().await.unwrap();
        let alice = app
            .login(
                &challenge.cookie,
                &challenge.csrf,
                "alice",
                "twelve word password",
            )
            .await
            .unwrap();
        Self {
            db,
            inspect,
            app,
            alice,
            keys,
            _dir: dir,
            postgres,
        }
    }
    async fn host(db: &Database, keys: &[u8], mode: &str) -> Arc<Application> {
        let m = declarations();
        manifest::validate(&m).unwrap();
        let limits = if mode == "deadline" {
            Limits {
                fuel: 100_000_000,
                wall_time: Duration::from_millis(20),
                ..Limits::default()
            }
        } else {
            Limits::default()
        };
        let app = Arc::new(
            Application::new(
                &component(mode),
                &serde_json::to_vec(&m).unwrap(),
                manifest::digest(&m).unwrap(),
                db.clone(),
                serde_json::from_slice(keys).unwrap(),
                limits,
            )
            .unwrap(),
        );
        app.activate().await.unwrap();
        app
    }
    async fn form(&self, action: u32) -> (String, String, String) {
        let html = String::from_utf8(
            self.app
                .view(&self.alice, if action >= 9 { 5 } else { 2 }, Some(42))
                .await
                .unwrap()
                .body,
        )
        .unwrap();
        let part = html
            .split_once(&format!("action=\"/actions/{action}\""))
            .unwrap_or_else(|| panic!("missing form {action}: {html}"))
            .1
            .split_once("</form>")
            .unwrap()
            .0;
        (
            support::hidden(part, "_submission"),
            support::hidden(part, "_csrf"),
            part.into(),
        )
    }
    async fn cleanup(mut self) {
        if let Some((mut admin, name)) = self.postgres.take() {
            drop(self.app);
            drop(self.inspect);
            drop(self.db);
            sqlx::query(&format!("DROP DATABASE {name} WITH (FORCE)"))
                .execute(&mut admin)
                .await
                .unwrap();
        }
    }
}

fn order(quantity: &str, body: &str) -> Fields {
    Fields::from([
        ("quantity".into(), quantity.into()),
        ("body".into(), body.into()),
    ])
}
fn amount(value: &str) -> Fields {
    Fields::from([("quantity".into(), value.into())])
}

async fn concurrent_orders(mut case: Case, same_token: bool) {
    let (first, csrf, html) = case.form(1).await;
    assert_eq!(html.matches("name=\"quantity\"").count(), 1);
    let second = if same_token {
        first.clone()
    } else {
        case.form(1).await.0
    };
    let restarted = Case::host(&case.db, &case.keys, "execute").await;
    let first_input = order("+01", "first\r\nnote");
    let second_input = if same_token {
        order("1", "first\nnote")
    } else {
        order("1", "second note")
    };
    let (left, right) = tokio::join!(
        case.app
            .submit(&case.alice, 1, &first, &csrf, first_input.clone()),
        restarted.submit(&case.alice, 1, &second, &csrf, second_input)
    );
    let left = left.unwrap();
    let right = right.unwrap();
    if same_token {
        assert_eq!(left.status, 303);
        assert_eq!(right.status, 303);
        assert_eq!(left.location, right.location);
    } else {
        let mut status = [left.status, right.status];
        status.sort();
        assert_eq!(status, [303, 422]);
        let rejection = if left.status == 422 { left } else { right };
        assert!(
            String::from_utf8(rejection.body)
                .unwrap()
                .contains("Not enough stock")
        );
    }
    let state = case.inspect.state().await;
    assert_eq!(state.len(), 3, "one product, one order, one note");
    assert!(state.iter().all(|row| row[5] == "1"));
    let (product, revision) = case.inspect.product().await;
    assert_eq!(product["stock"], "0");
    assert_eq!(revision, 2);
    let receipts = case
        .inspect
        .rows("SELECT outcome FROM nx_receipts", 1)
        .await;
    let receipt: serde_json::Value = serde_json::from_str(&receipts[0][0]).unwrap();
    assert_eq!(receipt["outcomes"].as_array().unwrap().len(), 3);
    for outcome in receipt["outcomes"].as_array().unwrap() {
        assert!(!outcome["incarnation"].as_str().unwrap().is_empty());
    }
    let outcomes = receipt["outcomes"].as_array().unwrap();
    let order_id = outcomes[1]["id"].as_u64().unwrap();
    let order_rows = case.inspect.rows("SELECT fields FROM nx_records WHERE resource=(SELECT storage_id FROM nx_resource_catalog WHERE resource_key='orders')", 1).await;
    let order_fields: Fields = serde_json::from_str(&order_rows[0][0]).unwrap();
    assert_eq!(order_fields["quantity"], "1");
    assert_eq!(order_fields["product"], "42");
    let note_rows = case.inspect.rows("SELECT fields FROM nx_records WHERE resource=(SELECT storage_id FROM nx_resource_catalog WHERE resource_key='order_notes')", 1).await;
    let note_fields: Fields = serde_json::from_str(&note_rows[0][0]).unwrap();
    assert_eq!(note_fields["order"], order_id.to_string());
    if same_token {
        assert_eq!(note_fields["body"], "first\nnote");
        // The caller discarded the first delivery. A new host recovers every
        // result from the receipt, despite changed destination read authority.
        case.inspect.execute("UPDATE nx_records SET owner=(SELECT id FROM nx_accounts WHERE login_name='bob') WHERE resource=(SELECT storage_id FROM nx_resource_catalog WHERE resource_key='orders')").await;
        let before = case.inspect.state().await;
        let recovered = restarted
            .submit(&case.alice, 1, &first, &csrf, first_input)
            .await
            .unwrap();
        assert_eq!(recovered.status, 200);
        assert!(recovered.location.is_none());
        assert_eq!(case.inspect.state().await, before);
    }
    case.cleanup().await;
}

async fn revisions_and_guards(mut case: Case) {
    case.inspect.reset_product(3, true, 0).await;
    let (edit, csrf, _) = case.form(2).await;
    let (identity, _, _) = case.form(1).await;
    let (other, _, _) = case.form(1).await;
    assert_eq!(
        case.app
            .submit(&case.alice, 1, &other, &csrf, order("1", "first order"))
            .await
            .unwrap()
            .status,
        303
    );
    assert_eq!(
        case.app
            .submit(
                &case.alice,
                2,
                &edit,
                &csrf,
                Fields::from([("stock".into(), "8".into())])
            )
            .await
            .unwrap()
            .status,
        409
    );
    assert_eq!(
        case.app
            .submit(&case.alice, 1, &identity, &csrf, order("1", "second order"))
            .await
            .unwrap()
            .status,
        303
    );
    assert_eq!(case.inspect.product().await.0["stock"], "1");
    let (_, revision) = case.inspect.product().await;
    let (two, csrf, _) = case.form(3).await;
    assert_eq!(
        case.app
            .submit(&case.alice, 3, &two, &csrf, amount("1"))
            .await
            .unwrap()
            .status,
        303
    );
    let (product, next) = case.inspect.product().await;
    assert_eq!(product["stock"], "1");
    assert_eq!(
        next,
        revision + 2,
        "each signed step reloads the prior step's revision"
    );
    for (action, stock, counter, message) in [
        (1, 0, 0, "Not enough stock"),
        (8, 10, 0, "Stock upper bound"),
        (6, 1, i64::MAX, "Counter upper bound"),
        (7, 1, i64::MIN, "Counter lower bound"),
        (9, 1, 0, "Not enough stock"),
        (10, 2, 0, "Not enough stock"),
    ] {
        case.inspect.reset_product(stock, true, counter).await;
        let (token, csrf, _) = case.form(action).await;
        let before = case.inspect.state().await;
        let input = if action == 1 {
            order("1", "guard failure")
        } else {
            amount("1")
        };
        let response = case
            .app
            .submit(&case.alice, action, &token, &csrf, input)
            .await
            .unwrap();
        assert_eq!(response.status, 422);
        assert!(String::from_utf8(response.body).unwrap().contains(message));
        assert_eq!(case.inspect.state().await, before);
    }
    case.inspect.reset_product(1, true, i64::MAX - 1).await;
    let (token, csrf, _) = case.form(6).await;
    assert_eq!(
        case.app
            .submit(&case.alice, 6, &token, &csrf, amount("1"))
            .await
            .unwrap()
            .status,
        303
    );
    assert_eq!(
        case.inspect.product().await.0["counter"],
        i64::MAX.to_string()
    );
    case.inspect.reset_product(1, true, i64::MIN + 1).await;
    let (token, csrf, _) = case.form(7).await;
    assert_eq!(
        case.app
            .submit(&case.alice, 7, &token, &csrf, amount("1"))
            .await
            .unwrap()
            .status,
        303
    );
    assert_eq!(
        case.inspect.product().await.0["counter"],
        i64::MIN.to_string()
    );
    case.cleanup().await;
}

async fn rollback_and_authorization(mut case: Case) {
    // The later create gate reads the product after the first update.
    case.inspect.reset_product(1, false, 0).await;
    let (token, csrf, _) = case.form(4).await;
    assert_eq!(
        case.app
            .submit(&case.alice, 4, &token, &csrf, amount("1"))
            .await
            .unwrap()
            .status,
        303
    );
    assert_eq!(case.inspect.product().await.0["open"], "true");
    let (second, csrf, _) = case.form(5).await;
    let before = case.inspect.state().await;
    let unavailable = case
        .app
        .submit(&case.alice, 5, &second, &csrf, amount("1"))
        .await
        .unwrap();
    assert_eq!(unavailable.status, 404);
    assert_eq!(
        case.inspect.state().await,
        before,
        "failure at second step rolls back first update"
    );
    let (third, csrf, _) = case.form(1).await;
    case.inspect
        .execute("DELETE FROM nx_roles WHERE name='notes'")
        .await;
    let before = case.inspect.state().await;
    let denied = case
        .app
        .submit(
            &case.alice,
            1,
            &third,
            &csrf,
            order("1", "third step denial"),
        )
        .await
        .unwrap();
    assert_eq!(denied.status, 404);
    assert_eq!(
        case.inspect.state().await,
        before,
        "third step denial rolls back update and order"
    );
    // A failed attempt keeps its original token usable against current state.
    case.inspect.execute("INSERT INTO nx_roles(principal,name,tenant) VALUES((SELECT id FROM nx_accounts WHERE login_name='alice'),'notes','')").await;
    assert_eq!(
        case.app
            .submit(
                &case.alice,
                1,
                &third,
                &csrf,
                order("1", "third step denial")
            )
            .await
            .unwrap()
            .status,
        303
    );
    case.inspect.reset_product(0, true, 0).await;
    let (first, csrf, _) = case.form(1).await;
    case.inspect
        .execute("DELETE FROM nx_roles WHERE name='stock'")
        .await;
    let before = case.inspect.state().await;
    let unauthorized = case
        .app
        .submit(
            &case.alice,
            1,
            &first,
            &csrf,
            order("1", "first step denial"),
        )
        .await
        .unwrap();
    assert_eq!(unauthorized.status, 404);
    assert!(
        !String::from_utf8(unauthorized.body.clone())
            .unwrap()
            .contains("Not enough stock")
    );
    assert_eq!(case.inspect.state().await, before);
    case.inspect
        .execute("DELETE FROM nx_records WHERE resource=(SELECT storage_id FROM nx_resource_catalog WHERE resource_key='products') AND id=42")
        .await;
    let missing = case
        .app
        .submit(
            &case.alice,
            1,
            &first,
            &csrf,
            order("1", "first step denial"),
        )
        .await
        .unwrap();
    assert_eq!(missing.status, unauthorized.status);
    assert_eq!(missing.body, unauthorized.body);
    assert_eq!(
        denied.body, unauthorized.body,
        "later policy denial is indistinguishable from missing target"
    );
    case.cleanup().await;
}

async fn guest_failures(mut case: Case) {
    for mode in [
        "reject",
        "trap",
        "deadline",
        "invoke",
        "follow-source",
        "follow",
        "page",
        "guest-outcome",
    ] {
        case.app = Case::host(&case.db, &case.keys, mode).await;
        let (token, csrf, _) = case.form(1).await;
        let before = case.inspect.state().await;
        let result = case
            .app
            .submit(&case.alice, 1, &token, &csrf, order("1", "guest failure"))
            .await;
        if mode == "reject" {
            let response = result.unwrap();
            assert_eq!(response.status, 422);
            let html = String::from_utf8(response.body).unwrap();
            assert!(html.contains("Nothing saved"));
            assert_eq!(support::hidden(&html, "_submission"), token);
        } else {
            assert!(result.is_err(), "{mode}");
        }
        assert_eq!(
            case.inspect.state().await,
            before,
            "{mode} rolls back receipt claim and all mutations"
        );
    }
    case.cleanup().await;
}

#[tokio::test]
async fn sqlite_last_unit_orders() {
    concurrent_orders(Case::sqlite().await, false).await;
}
#[tokio::test]
async fn sqlite_same_token_concurrency_and_recovery() {
    concurrent_orders(Case::sqlite().await, true).await;
}
#[tokio::test]
async fn sqlite_transaction_revisions_and_guards() {
    revisions_and_guards(Case::sqlite().await).await;
}
#[tokio::test]
async fn sqlite_transaction_rollback_and_authorization() {
    rollback_and_authorization(Case::sqlite().await).await;
}
#[tokio::test]
async fn sqlite_action_guest_failures() {
    guest_failures(Case::sqlite().await).await;
}

#[tokio::test]
#[ignore = "requires NOXIDE_TEST_POSTGRES with CREATE DATABASE on PostgreSQL 18"]
async fn postgres_last_unit_orders() {
    concurrent_orders(Case::postgres().await, false).await;
}
#[tokio::test]
#[ignore = "requires NOXIDE_TEST_POSTGRES with CREATE DATABASE on PostgreSQL 18"]
async fn postgres_same_token_concurrency_and_recovery() {
    concurrent_orders(Case::postgres().await, true).await;
}
#[tokio::test]
#[ignore = "requires NOXIDE_TEST_POSTGRES with CREATE DATABASE on PostgreSQL 18"]
async fn postgres_transaction_revisions_and_guards() {
    revisions_and_guards(Case::postgres().await).await;
}
#[tokio::test]
#[ignore = "requires NOXIDE_TEST_POSTGRES with CREATE DATABASE on PostgreSQL 18"]
async fn postgres_transaction_rollback_and_authorization() {
    rollback_and_authorization(Case::postgres().await).await;
}
#[tokio::test]
#[ignore = "requires NOXIDE_TEST_POSTGRES with CREATE DATABASE on PostgreSQL 18"]
async fn postgres_action_guest_failures() {
    guest_failures(Case::postgres().await).await;
}

async fn contract_changes_invalidate_tokens(mut case: Case) {
    for scenario in 0..8 {
        case.app = Case::host(&case.db, &case.keys, "execute").await;
        let action = if scenario == 2 { 4 } else { 1 };
        let (token, csrf, _) = case.form(action).await;
        let before = case.inspect.state().await;
        let mut changed = declarations();
        match scenario {
            0 => changed.actions[0].inputs[1].max_bytes = 199,
            1 => changed.actions[0].steps[1].assign.swap(0, 1),
            2 => {
                changed.actions[3].steps[0].assign[0].change =
                    Change::Set(Value::Constant("false".into()))
            }
            3 => {
                changed.actions[0].steps.swap(0, 1);
                changed.actions[0].steps[2].assign[1].change = Change::Set(Value::Created(0));
                changed.actions[0].redirect.source = RedirectSource::Step(0);
            }
            4 => {
                let Change::Decrease { rejection, .. } =
                    &mut changed.actions[0].steps[0].assign[0].change
                else {
                    unreachable!()
                };
                rejection.message = "Inventory unavailable".into();
            }
            5 => changed.actions[0].revision = Revision::Exact,
            6 => {
                changed.actions[0].inspect = Some(Inspection {
                    operation: 1,
                    fields: vec!["stock".into()],
                })
            }
            7 => {
                changed.actions[0].redirect = Redirect {
                    route: 2,
                    source: RedirectSource::Signed,
                }
            }
            _ => unreachable!(),
        }
        let changed = Application::new(
            &component("execute"),
            &serde_json::to_vec(&changed).unwrap(),
            manifest::digest(&changed).unwrap(),
            case.db.clone(),
            serde_json::from_slice(&case.keys).unwrap(),
            Limits::default(),
        )
        .unwrap();
        changed.activate().await.unwrap();
        let input = if action == 4 {
            amount("1")
        } else {
            order("1", "unchanged input")
        };
        assert!(
            matches!(
                changed
                    .submit(&case.alice, action, &token, &csrf, input)
                    .await,
                Err(noxide_host::RequestError::InvalidRequest)
            ),
            "changed contract scenario {scenario}"
        );
        assert_eq!(
            case.inspect.state().await,
            before,
            "changed contract scenario {scenario}"
        );
    }
    case.cleanup().await;
}

#[tokio::test]
async fn sqlite_transaction_contract_changes_invalidate_tokens() {
    contract_changes_invalidate_tokens(Case::sqlite().await).await;
}

#[tokio::test]
#[ignore = "requires NOXIDE_TEST_POSTGRES with CREATE DATABASE on PostgreSQL 18"]
async fn postgres_transaction_contract_changes_invalidate_tokens() {
    contract_changes_invalidate_tokens(Case::postgres().await).await;
}
