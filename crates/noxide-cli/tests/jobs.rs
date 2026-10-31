#![cfg(unix)]
#[allow(dead_code)]
#[path = "../../noxide-host/tests/support/mod.rs"]
mod support;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use noxide::{CalculatedStep, guards, values};
use noxide_host::{
    Application, Database, DeploymentResources, HostKeys, JobDeployment, JobGrant, JobLimits,
    runtime::Limits,
};
use noxide_protocol::{jobs::*, *};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

const PRIVATE_BODY: &str = "PRIVATE_CLI_JOB_BODY";
const REJECTION: &str = "Private declared rejection";
fn declarations() -> Manifest {
    let mut m = support::manifest();
    let mut read = m.operations[1].clone();
    read.id = 4;
    read.policy = Policy {
        any: vec![vec![
            Predicate::Service {
                worker: "repair".into(),
            },
            Predicate::SameTenant,
        ]],
    };
    let mut update = read.clone();
    update.id = 5;
    update.kind = OperationKind::Update;
    m.operations.extend([read, update]);
    m.actions.push(Action {
        id: 2,
        version: 1,
        name: "Finish note".into(),
        inputs: vec![],
        targets: vec![ActionTarget {
            name: "record".into(),
            resource: 1,
            source: TargetSource::Service { eligible: 4 },
            revision: Revision::Identity,
            projection: Some(Inspection {
                operation: 4,
                fields: vec!["body".into()],
            }),
            inspect: None,
        }],
        steps: vec![
            CalculatedStep::new(5, Target::Named("record".into()))
                .guard(guards::require(
                    guards::equal(
                        values::current("record", "body"),
                        values::text(PRIVATE_BODY),
                    ),
                    None,
                    REJECTION,
                ))
                .set("body", values::text("finished"))
                .finish(),
        ],
    });
    m.jobs = Some(JobContract {
        workers: vec![Worker {
            name: "repair".into(),
            actions: vec![WorkerAction {
                action: 2,
                targets: BTreeMap::from([(
                    "record".into(),
                    WorkerTarget {
                        resource: 1,
                        eligible: 4,
                    },
                )]),
            }],
        }],
        schedules: vec![Schedule {
            source_action: 1,
            ordinal: 0,
            worker: "repair".into(),
            action: 2,
            targets: BTreeMap::from([("record".into(), ScheduledTarget::Created(0))]),
            inputs: BTreeMap::new(),
            due_at: Value::TransactionTime,
        }],
        recurring: vec![],
    });
    m
}

/// Read-only audit of this isolated fixture; operator writes always use the CLI.
async fn snapshot(root: &Path) -> serde_json::Value {
    let output = tokio::process::Command::new("python3").args(["-c", r#"
import json, sqlite3, sys, urllib.parse
cx = sqlite3.connect('file:' + urllib.parse.quote(sys.argv[1]) + '?mode=ro', uri=True)
records = [(json.loads(fields), revision, incarnation) for fields, revision, incarnation in cx.execute('SELECT fields,revision,incarnation FROM nx_records')]
jobs = [dict(id=identity, state=state, parent=parent) for identity,state,parent in cx.execute('SELECT id,state,reconciled_from FROM nx_jobs ORDER BY id')]
print(json.dumps(dict(records=records,jobs=jobs,receipts=cx.execute('SELECT COUNT(*) FROM nx_receipts').fetchone()[0],runtime=cx.execute('SELECT state FROM nx_job_runtime WHERE singleton=1').fetchone()[0])))
"#]).arg(root.join("runtime.db")).output().await.unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}
async fn cli(
    config: &Path,
    command: &str,
    args: &[&str],
    secrets: &[&str],
    success: bool,
) -> String {
    let output = tokio::process::Command::new(env!("CARGO_BIN_EXE_noxide"))
        .arg("jobs")
        .arg(command)
        .arg(config)
        .args(args)
        .output()
        .await
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    for secret in secrets {
        assert!(
            !stdout.contains(secret) && !stderr.contains(secret),
            "CLI disclosed private fixture data"
        );
    }
    assert_eq!(output.status.success(), success, "jobs {command}: {stderr}");
    stdout.trim().to_owned()
}
fn listing(raw: &str) -> serde_json::Value {
    let value: serde_json::Value = serde_json::from_str(raw).unwrap();
    let expected = BTreeSet::from([
        "action",
        "attempts",
        "deployment",
        "due",
        "eligible",
        "id",
        "state",
        "tenant",
        "worker",
    ]);
    for job in value["jobs"].as_array().unwrap() {
        assert_eq!(
            job.as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            expected
        );
    }
    value
}

#[tokio::test]
async fn actual_jobs_cli_reconciles_explicitly_and_preserves_fork_pause() {
    use std::os::unix::fs::PermissionsExt;
    let evidence = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/capability-evidence/p10-cli-fixtures");
    std::fs::create_dir_all(&evidence).unwrap();
    let root = tempfile::Builder::new()
        .prefix("operator-")
        .tempdir_in(evidence)
        .unwrap()
        .keep();
    eprintln!("retained actual jobs CLI fixture: {}", root.display());
    let db = Database::sqlite(root.join("runtime.db"));
    db.initialize().await.unwrap();
    db.create_account("alice", "private CLI test password", "team")
        .await
        .unwrap();
    let m = declarations();
    let deployment = JobDeployment {
        grants: vec![JobGrant {
            worker: "repair".into(),
            tenant: "team".into(),
            actions: BTreeSet::from([2]),
        }],
        limits: JobLimits::default(),
    };
    let approved = noxide_host::deployment::approval_digest(&m, None, Some(&deployment)).unwrap();
    let component = support::component(None);
    let manifest_bytes = serde_json::to_vec(&m).unwrap();
    let keys = serde_json::to_vec(&HostKeys::generate().unwrap()).unwrap();
    let config = root.join("config.json");
    for (name, bytes) in [
        ("app.wasm", component.as_slice()),
        ("manifest.json", manifest_bytes.as_slice()),
        ("keys.json", keys.as_slice()),
    ] {
        std::fs::write(root.join(name), bytes).unwrap();
    }
    std::fs::set_permissions(
        root.join("keys.json"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    std::fs::write(&config, serde_json::to_vec(&serde_json::json!({
        "database":{"sqlite":"runtime.db"},"keys":"keys.json","component":"app.wasm","manifest":"manifest.json","jobs":deployment,
        "approved_contract":URL_SAFE_NO_PAD.encode(approved),"origin":"http://localhost:8080","listen":{"tcp":"127.0.0.1:8080"}
    })).unwrap()).unwrap();
    let app = Application::new(
        &component,
        &manifest_bytes,
        approved,
        db,
        serde_json::from_slice(&keys).unwrap(),
        Limits::default(),
        DeploymentResources {
            assets: Default::default(),
            blobs: None,
            jobs: Some(deployment),
        },
    )
    .unwrap();
    app.activate().await.unwrap();
    let challenge = app.login_challenge().await.unwrap();
    let cookie = app
        .login(
            &challenge.cookie,
            &challenge.csrf,
            "alice",
            "private CLI test password",
        )
        .await
        .unwrap();
    let page = app.view(&cookie, 1, None).await.unwrap();
    let html = String::from_utf8(page.body).unwrap();
    let submission = support::hidden(&html, "_submission");
    let csrf = support::hidden(&html, "_csrf");
    app.submit(
        &cookie,
        1,
        &submission,
        &csrf,
        Fields::from([("body".into(), PRIVATE_BODY.into())]),
    )
    .await
    .unwrap();
    drop(app);
    let initial = snapshot(&root).await;
    assert_eq!(initial["receipts"], 1);
    assert_eq!(initial["records"][0][0]["body"], PRIVATE_BODY);
    let seal = initial["records"][0][2].as_str().unwrap();
    let key_value: serde_json::Value = serde_json::from_slice(&keys).unwrap();
    let private_key = key_value["key"].to_string();
    let serialized_keys = String::from_utf8(keys).unwrap();
    let secrets = [
        PRIVATE_BODY,
        REJECTION,
        seal,
        cookie.as_str(),
        submission.as_str(),
        csrf.as_str(),
        serialized_keys.as_str(),
        private_key.as_str(),
    ];
    let inspected = listing(&cli(&config, "inspect", &[], &secrets, true).await);
    let original = inspected["jobs"][0]["id"].as_str().unwrap().to_owned();
    assert_eq!(inspected["jobs"][0]["state"], "pending");
    cli(&config, "revoke", &["team", "repair"], &secrets, true).await;
    assert_eq!(
        cli(&config, "worker-once", &[], &secrets, true).await,
        "idle"
    );
    assert_eq!(snapshot(&root).await["records"], initial["records"]);
    cli(&config, "fork", &[], &secrets, true).await;
    let restarted = listing(&cli(&config, "inspect", &[], &secrets, true).await);
    assert_eq!(restarted["jobs"][0]["state"], "paused");
    assert_eq!(
        snapshot(&root).await["runtime"],
        "paused",
        "same config must not silently undo a fork"
    );
    cli(&config, "worker-once", &[], &secrets, false).await;
    assert_eq!(snapshot(&root).await["receipts"], 1);
    cli(&config, "grant", &["team", "repair"], &secrets, true).await;
    assert_eq!(
        snapshot(&root).await["jobs"][0]["state"],
        "paused",
        "grant cannot silently rebind old captures"
    );
    cli(&config, "cancel", &[&original], &secrets, true).await;
    let reconciled: serde_json::Value =
        serde_json::from_str(&cli(&config, "reconcile", &[&original], &secrets, true).await)
            .unwrap();
    let replacement = reconciled["reconciled"]["id"].as_str().unwrap();
    assert_ne!(replacement, original);
    assert_eq!(
        cli(&config, "worker-once", &[], &secrets, true).await,
        "completed"
    );
    assert_eq!(
        cli(&config, "worker-once", &[], &secrets, true).await,
        "idle"
    );
    let final_state = snapshot(&root).await;
    assert_eq!(final_state["records"].as_array().unwrap().len(), 1);
    assert_eq!(final_state["records"][0][0]["body"], "finished");
    assert_eq!(final_state["records"][0][1], 2);
    assert_eq!(final_state["receipts"], 2);
    let jobs = final_state["jobs"].as_array().unwrap();
    assert_eq!(jobs.len(), 2);
    let old = jobs.iter().find(|row| row["id"] == original).unwrap();
    assert_eq!(old["state"], "rejected");
    let new = jobs.iter().find(|row| row["id"] == replacement).unwrap();
    assert_eq!(new["state"], "succeeded");
    assert_eq!(new["parent"], original);
    assert_eq!(
        listing(&cli(&config, "inspect", &[], &secrets, true).await)["jobs"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
}
