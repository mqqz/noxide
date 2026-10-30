//! Mutation response preparation and bounded post-commit navigation.
//!
//! Action owns authorization, mutation and atomic receipt persistence; submission
//! owns canonicalization and the web response binding. `prepare_response` may
//! prepare recovery/handover data before commitment; callers deliver it only after commit confirmation or a verified
//! committed receipt. An unknown commit outcome stays in receipt recovery.
//! `finish_navigation` resolves presentation after commitment and cannot undo the write.
//! Parent destination checks use fresh read authority and the captured incarnation;
//! a child edit credential never grants parent read authority.
use super::*;

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SemanticReceipt {
    pub version: u32,
    pub outcomes: Vec<MutationOutcome>,
    pub source: RedirectSource,
    pub destination: Option<ReferenceDestination>,
    pub handover: Option<EditReceipt>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ReferenceDestination {
    route: u32,
    resource: u32,
    id: u64,
    incarnation: String,
}
pub(super) struct Prepared {
    pub fallback: Rendered,
    navigation: Option<(ReferenceDestination, auth::Principal, bool)>,
}
impl Prepared {
    pub fn ready(fallback: Rendered) -> Self {
        Self {
            fallback,
            navigation: None,
        }
    }
}
pub(super) fn success() -> Rendered {
    Rendered { status: 200, body: b"<!doctype html><html lang=\"en\"><title>Success</title><main><h1>Changes saved</h1></main></html>".to_vec(), location: None, anonymous_cookie: None }
}
impl Application {
    pub(super) fn committed_recovery(
        &self,
        action: &Action,
        submission: &str,
        csrf: &str,
        input: &Fields,
    ) -> Result<Prepared> {
        Ok(Prepared::ready(render::recovery(
            &self.presentation,
            &self.manifest,
            action.id,
            &FormCredentials {
                csrf: csrf.into(),
                submission: submission.into(),
                values: Fields::new(),
            },
            input,
            render::Recovery::Committed,
        )?))
    }

    pub(super) async fn capture_destination(
        &self,
        tx: &mut Transaction,
        action: ActionCore<'_>,
        signed: Option<&RecordTarget>,
        original: Option<&StoredRecord>,
        outcomes: &[MutationOutcome],
    ) -> Result<Option<ReferenceDestination>> {
        if action.destination_resource.is_none() {
            return Ok(None);
        }
        let (resource, id, incarnation) = match action.source {
            RedirectSource::Signed => {
                let signed =
                    signed.ok_or_else(|| anyhow::anyhow!("missing signed navigation source"))?;
                (signed.resource, signed.id, signed.incarnation.clone())
            }
            RedirectSource::Step(index) => {
                let outcome = outcomes
                    .get(usize::from(*index))
                    .ok_or_else(|| anyhow::anyhow!("missing navigation outcome"))?;
                (outcome.resource, outcome.id, outcome.incarnation.clone())
            }
            RedirectSource::Reference { step, field } => {
                let outcome = outcomes
                    .get(usize::from(*step))
                    .ok_or_else(|| anyhow::anyhow!("missing reference outcome"))?;
                let source = if outcome.kind == MutationKind::Deleted {
                    original.cloned()
                } else {
                    repository::load(tx, &self.manifest, outcome.resource, outcome.id).await?
                }
                .ok_or_else(|| anyhow::anyhow!("missing reference source"))?;
                ensure!(
                    source.incarnation == outcome.incarnation,
                    "navigation source changed"
                );
                let parent = manifest::reference_resource(&self.manifest, outcome.resource)?
                    .ok_or_else(|| anyhow::anyhow!("missing reference schema"))?;
                let id = source
                    .record
                    .fields
                    .get(field)
                    .ok_or_else(|| anyhow::anyhow!("missing reference value"))?
                    .parse()?;
                let destination = repository::load(tx, &self.manifest, parent.id, id)
                    .await?
                    .ok_or_else(|| anyhow::anyhow!("missing reference destination"))?;
                (parent.id, id, destination.incarnation)
            }
        };
        ensure!(
            action.destination_resource == Some(resource),
            "navigation resource differs"
        );
        Ok(Some(ReferenceDestination {
            route: action.destination_route,
            resource,
            id,
            incarnation,
        }))
    }

    pub(super) async fn prepare_response(
        &self,
        tx: &mut Transaction,
        action: &Action,
        target: Option<&RecordTarget>,
        payload: &str,
        principal: &auth::Principal,
    ) -> Result<Prepared> {
        let receipt: SemanticReceipt = serde_json::from_str(payload)?;
        ensure!(
            receipt.version == 1
                && receipt.outcomes.len() == action.steps.len()
                && receipt.source == action.redirect.source,
            "receipt contract differs"
        );
        for (outcome, step) in receipt.outcomes.iter().zip(&action.steps) {
            let op = manifest::operation(&self.manifest, step.operation)?;
            let kind = match op.kind {
                OperationKind::Create => MutationKind::Created,
                OperationKind::Update => MutationKind::Updated,
                OperationKind::Delete => MutationKind::Deleted,
                _ => anyhow::bail!("invalid mutation receipt"),
            };
            ensure!(
                outcome.kind == kind
                    && outcome.resource == op.resource
                    && outcome.id > 0
                    && outcome.id <= i64::MAX as u64
                    && !outcome.incarnation.is_empty()
                    && outcome.incarnation.len() <= 64,
                "invalid mutation identity"
            );
            if step.target == Target::Signed
                && let Some(target) = target
            {
                ensure!(
                    outcome.resource == target.resource
                        && outcome.id == target.id
                        && outcome.incarnation == target.incarnation,
                    "receipt signed target differs"
                );
            }
        }
        let public_create = action.steps.iter().enumerate().find(|(_, step)| {
            manifest::operation(&self.manifest, step.operation)
                .is_ok_and(|op| op.kind == OperationKind::Create && manifest::is_public(op))
        });
        ensure!(
            public_create.is_some() == receipt.handover.is_some(),
            "receipt handover differs"
        );
        let handover = receipt.handover.is_some();
        let fallback = if let Some(edit) = &receipt.handover {
            let outcome = &receipt.outcomes[public_create.expect("handover operation").0];
            ensure!(
                edit.resource == outcome.resource
                    && edit.id == outcome.id
                    && edit.incarnation == outcome.incarnation,
                "handover identity differs"
            );
            self.edit_handover(tx, edit, None).await?
        } else {
            success()
        };
        let route = manifest::route(&self.manifest, action.redirect.route())?;
        if let Some(destination) = receipt.destination {
            ensure!(
                route.resource == Some(destination.resource) && destination.route == route.id,
                "receipt destination differs"
            );
            Ok(Prepared {
                fallback,
                navigation: Some((destination, principal.clone(), handover)),
            })
        } else {
            ensure!(route.resource.is_none(), "receipt destination missing");
            if handover
                || route.access == Access::Authenticated
                    && matches!(principal, auth::Principal::Anonymous)
            {
                return Ok(Prepared::ready(fallback));
            }
            Ok(Prepared::ready(render::render(
                &ResponseIntent::Redirect(RouteRef {
                    route: route.id,
                    target: None,
                    params: Default::default(),
                }),
                &RenderContext {
                    presentation: &self.presentation,
                    manifest: Some(&self.manifest),
                    ..RenderContext::empty()
                },
            )?))
        }
    }
    pub(super) async fn finish_navigation(
        &self,
        mut prepared: Prepared,
        deadline: Instant,
    ) -> Rendered {
        #[cfg(test)]
        {
            let barrier = self.postcommit_barrier.lock().unwrap().take();
            if let Some((committed, resume)) = barrier {
                committed.notify_one();
                resume.notified().await;
            }
        }
        let Some((destination, principal, handover)) = prepared.navigation.take() else {
            return prepared.fallback;
        };
        if Instant::now() >= deadline {
            return prepared.fallback;
        }
        // Navigation calls are reserved once, including a possible destination gate.
        // Capture is charged separately on every mutation attempt.
        let resolved = timeout_at(deadline, async {
            let mut tx = self.database.begin_read(deadline.into_std()).await?;
            let route = manifest::route(&self.manifest, destination.route)?;
            let principal = if route.access == Access::Public {
                auth::Principal::Anonymous
            } else {
                principal
            };
            if route.access == Access::Authenticated
                && matches!(principal, auth::Principal::Anonymous)
            {
                return Ok::<_, anyhow::Error>(None);
            }
            let record = repository::authorize_page_resource(
                &mut tx,
                &self.manifest,
                &principal,
                route,
                destination.resource,
                destination.id,
                Some(&destination.incarnation),
            )
            .await?;
            // The destination's read policy owns visibility, including private
            // owner/moderator views. Child-list visibility grants no authority here.
            let allowed = record.is_some();
            tx.commit().await?;
            if !allowed {
                return Ok(None);
            }
            Ok(Some(render::resolve(
                &self.manifest,
                &RouteRef {
                    params: Default::default(),
                    route: destination.route,
                    target: Some(destination.id),
                },
            )?))
        })
        .await;
        if let Ok(Ok(Some(url))) = resolved {
            if handover {
                if let Ok(response) = render::handover_continue(&prepared.fallback, &url) {
                    return response;
                }
            } else {
                return Rendered {
                    status: 303,
                    body: Vec::new(),
                    location: Some(url),
                    anonymous_cookie: None,
                };
            }
        }
        prepared.fallback
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{parent_tests, test_support as fixture};
    use std::time::Duration;

    #[test]
    fn semantic_receipt_shapes_round_trip() {
        // Current ordinary and reference receipts round-trip.
        // Keys and identifiers are test data.
        for raw in [
            r#"{"version":1,"outcomes":[{"kind":"created","resource":7,"id":9,"incarnation":"test"}],"source":{"step":0},"destination":null,"handover":{"resource":7,"id":9,"incarnation":"test","cap_version":2,"key_id":3}}"#,
            r#"{"version":1,"outcomes":[{"kind":"created","resource":7,"id":9,"incarnation":"test"}],"source":{"reference":{"step":0,"field":"thread"}},"destination":{"route":5,"resource":6,"id":8,"incarnation":"test-incarnation"},"handover":null}"#,
            r#"{"version":1,"outcomes":[{"kind":"deleted","resource":7,"id":9,"incarnation":"test"}],"source":"signed","destination":null,"handover":null}"#,
        ] {
            let receipt: SemanticReceipt = serde_json::from_str(raw).unwrap();
            assert_eq!(
                serde_json::to_value(receipt).unwrap(),
                serde_json::from_str::<serde_json::Value>(raw).unwrap()
            );
        }
        for raw in [
            r#"{"kind":"updated","resource":7,"id":9,"incarnation":"test"}"#,
            r#"{"kind":"deleted","resource":7,"id":9,"incarnation":"test"}"#,
        ] {
            let outcome: MutationOutcome = serde_json::from_str(raw).unwrap();
            assert_eq!(
                serde_json::to_value(outcome).unwrap(),
                serde_json::from_str::<serde_json::Value>(raw).unwrap()
            );
        }
        assert!(
            serde_json::from_str::<SemanticReceipt>(
                r#"{"version":1,"outcome":{},"destination":null,"extra":true}"#
            )
            .is_err()
        );
        for raw in [
            r#"{"route":4,"source":"signed"}"#,
            r#"{"route":5,"source":{"reference":{"step":0,"field":"thread"}}}"#,
        ] {
            let redirect: Redirect = serde_json::from_str(raw).unwrap();
            assert_eq!(
                serde_json::to_value(redirect).unwrap(),
                serde_json::from_str::<serde_json::Value>(raw).unwrap()
            );
        }
        assert!(
            serde_json::from_str::<Redirect>(r#"{"field":"thread","route":5,"extra":true}"#)
                .is_err()
        );
    }

    #[tokio::test]
    async fn private_parent_navigation_matches_owner_and_moderator_reads() {
        let tmp = tempfile::tempdir().unwrap();
        private_parent_case(Database::sqlite(tmp.path().join("private-parent.db"))).await;
    }

    async fn private_parent_case(db: Database) {
        db.initialize().await.unwrap();
        let mut m = parent_tests::declarations();
        m.actions[0].redirect = Redirect {
            route: 3,
            source: RedirectSource::Reference {
                step: 0,
                field: "thread".into(),
            },
        };
        let read = &mut m.operations[3];
        read.policy = Policy {
            any: vec![
                vec![Predicate::Owner],
                vec![Predicate::Role {
                    name: "moderator".into(),
                    tenant_scoped: true,
                }],
            ],
        };
        read.visibility = None;
        read.fields = None;
        m.routes[2].access = Access::Authenticated;
        let app = Application::new(
            &fixture::component(None),
            &serde_json::to_vec(&m).unwrap(),
            manifest::digest(&m).unwrap(),
            db.clone(),
            HostKeys::generate().unwrap(),
            Limits::default(),
        )
        .unwrap();
        app.activate().await.unwrap();
        parent_tests::seed(&db, &m).await;
        parent_tests::set_parent(&db, &m, false, false).await;
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut tx = db.begin(deadline.into_std()).await.unwrap();
        tx.execute(
            "INSERT INTO nx_accounts(id,password,tenant,state,epoch) VALUES('alice','unused','one','active',1)",
            &[],
        )
        .await
        .unwrap();
        let storage = tx.storage_resource(&m, 2).await.unwrap();
        tx.execute(
            "UPDATE nx_records SET owner='alice',tenant='one' WHERE resource=$1",
            &[storage.into()],
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        for (id, tenant, moderator, expected) in [
            ("alice", "one", false, true),
            ("mod", "one", true, true),
            ("stranger", "one", false, false),
            ("mod", "two", true, false),
            ("", "", false, false),
        ] {
            let principal = if id.is_empty() {
                auth::Principal::Anonymous
            } else {
                auth::Principal::User(auth::User {
                    id: id.into(),
                    tenant: tenant.into(),
                    roles: if moderator {
                        vec![("moderator".into(), tenant.into())]
                    } else {
                        vec![]
                    },
                })
            };
            let mut tx = db.begin_read(deadline.into_std()).await.unwrap();
            let normal = repository::read_resource(&mut tx, &m, &principal, &m.operations[3], 10)
                .await
                .unwrap();
            assert_eq!(normal.is_some(), expected);
            tx.commit().await.unwrap();
            // Exercise the post-commit response path, not just its read helper.
            // The parent is unpublished, so the child's visibility predicate fails.
            let response = app
                .finish_navigation(
                    Prepared {
                        fallback: success(),
                        navigation: Some((
                            ReferenceDestination {
                                route: 3,
                                resource: 2,
                                id: 10,
                                incarnation: "parent".into(),
                            },
                            principal,
                            false,
                        )),
                    },
                    deadline,
                )
                .await;
            assert_eq!(
                response.location.as_deref(),
                expected.then_some("/threads/10")
            );
            assert_eq!(response.status, if expected { 303 } else { 200 });
        }
    }

    #[tokio::test]
    async fn capability_update_and_delete_do_not_authorize_private_parent() {
        let tmp = tempfile::tempdir().unwrap();
        capability_case(Database::sqlite(tmp.path().join("mutations.db"))).await;
    }
    async fn capability_case(db: Database) {
        db.initialize().await.unwrap();
        let mut m = parent_tests::declarations();
        m.operations.iter_mut().find(|op| op.id == 4).unwrap().id = 6;
        m.routes[2].operations = vec![6, 1];
        m.operations[2].bind.as_mut().unwrap().eligible = 6;
        for (id, kind) in [(4, OperationKind::Update), (5, OperationKind::Delete)] {
            m.operations.push(Operation {
                bind: None,
                scope: None,
                via: None,
                filter: Vec::new(),
                disclose: Vec::new(),
                list: None,
                id,
                resource: 1,
                kind,
                policy: Policy {
                    any: vec![vec![Predicate::Capability]],
                },
                visibility: None,
                fields: None,
            });
            let mut action = fixture::action(
                id - 2,
                "Change reply",
                id,
                Target::Signed,
                &m.resources[0],
                if id == 4 { &["body"] } else { &[] },
                3,
            );
            action.redirect.source = RedirectSource::Reference {
                step: 0,
                field: "thread".into(),
            };
            m.actions.push(action);
        }
        m.routes[1].forms = vec![2, 3];
        m.routes[1].access = Access::PublicOptional;
        let app = Application::new(
            &crate::anonymous_tests::component(),
            &serde_json::to_vec(&m).unwrap(),
            manifest::digest(&m).unwrap(),
            db.clone(),
            HostKeys::generate().unwrap(),
            Limits::default(),
        )
        .unwrap();
        app.activate().await.unwrap();
        parent_tests::seed(&db, &m).await;
        parent_tests::set_parent(&db, &m, false, false).await;
        let now = security::now().unwrap();
        let (session, cookie) = app.keys.issue(TokenKind::Anonymous, "", now, 900).unwrap();
        for action_id in [2, 3] {
            let mut tx = db
                .begin((Instant::now() + Duration::from_secs(5)).into_std())
                .await
                .unwrap();
            let stored = repository::load(&mut tx, &m, 1, 12).await.unwrap().unwrap();
            let storage = tx.storage_resource(&m, 1).await.unwrap() as u32;
            tx.commit().await.unwrap();
            let secret = app
                .keys
                .edit_secret(app.keys.signing_edit_key().unwrap(), storage, 12, 1)
                .unwrap();
            let target = RecordTarget {
                resource: 1,
                id: 12,
                route: 2,
                incarnation: stored.incarnation,
                revision: stored.revision,
            };
            let action = manifest::action(&m, action_id).unwrap();
            let credentials = app
                .credentials(action, &session, now, Some(target), Fields::new())
                .unwrap();
            let input = if action_id == 2 {
                Fields::from([("body".into(), "updated".into())])
            } else {
                Fields::new()
            };
            let response = app
                .submit_with_capability(
                    &cookie,
                    action_id,
                    &credentials.submission,
                    &credentials.csrf,
                    input.clone(),
                    Some(&secret),
                )
                .await
                .unwrap();
            assert_eq!(response.status, 200);
            assert!(response.location.is_none());
            assert!(!String::from_utf8_lossy(&response.body).contains("/threads/10"));
            let replay = app
                .submit_with_capability(
                    &cookie,
                    action_id,
                    &credentials.submission,
                    &credentials.csrf,
                    input,
                    Some(&secret),
                )
                .await
                .unwrap();
            assert_eq!(response.body, replay.body);
        }
        let mut tx = db
            .begin_read((Instant::now() + Duration::from_secs(5)).into_std())
            .await
            .unwrap();
        assert!(
            repository::load(&mut tx, &m, 1, 12)
                .await
                .unwrap()
                .is_none()
        );
        tx.commit().await.unwrap();
    }

    #[tokio::test]
    async fn postcommit_lookup_failure_and_deadline_preserve_handover() {
        let tmp = tempfile::tempdir().unwrap();
        fault_case(Database::sqlite(tmp.path().join("fault.db"))).await;
    }
    async fn fault_case(db: Database) {
        let (app, m) = parent_tests::redirect_app(db.clone()).await;
        let page = app.view_page(None, 3, Some(10), None).await.unwrap();
        let cookie = page.anonymous_cookie.unwrap();
        let body = String::from_utf8(page.body).unwrap();
        let submission = fixture::hidden(&body, "_submission");
        let csrf = fixture::hidden(&body, "_csrf");
        let input = Fields::from([
            ("body".into(), "committed".into()),
            ("published".into(), "true".into()),
        ]);
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut budget =
            super::super::submission::ExecutionBudget::new(app.runtime.limits(), deadline);
        let (tx, prepared) = app
            .prepare(
                &cookie,
                1,
                &submission,
                &csrf,
                &input,
                &super::super::submission::input_digest(
                    ActionCore::of(&m, &m.actions[0]).unwrap(),
                    &input,
                )
                .unwrap(),
                None,
                &mut budget,
            )
            .await
            .unwrap();
        let fallback = prepared.fallback.body.clone();
        assert!(String::from_utf8_lossy(&fallback).contains("<pre>"));
        tx.unwrap().commit().await.unwrap();
        // The mutation is committed before the destination infrastructure fails.
        let mut tx = db.begin(deadline.into_std()).await.unwrap();
        tx.execute("ALTER TABLE nx_records RENAME TO nx_records_offline", &[])
            .await
            .unwrap();
        tx.commit().await.unwrap();
        let response = app.finish_navigation(prepared, deadline).await;
        assert_eq!(response.body, fallback);
        assert_eq!(response.status, 200);
        let recovery = app
            .submit(&cookie, 1, &submission, &csrf, input.clone())
            .await
            .unwrap();
        let recovery = String::from_utf8(recovery.body).unwrap();
        assert!(recovery.contains("Recover edit secret"));
        assert_eq!(fixture::hidden(&recovery, "_submission"), submission);
        assert_eq!(fixture::hidden(&recovery, "_csrf"), csrf);
        let mut tx = db.begin(deadline.into_std()).await.unwrap();
        tx.execute("ALTER TABLE nx_records_offline RENAME TO nx_records", &[])
            .await
            .unwrap();
        tx.commit().await.unwrap();
        let recovered = app
            .submit(&cookie, 1, &submission, &csrf, input)
            .await
            .unwrap();
        let secret = String::from_utf8(fallback.clone())
            .unwrap()
            .split("<pre>")
            .nth(1)
            .unwrap()
            .split("</pre>")
            .next()
            .unwrap()
            .to_string();
        assert!(String::from_utf8_lossy(&recovered.body).contains(&secret));
        let mut tx = db.begin_read(deadline.into_std()).await.unwrap();
        let payload = app
            .load_receipt(
                &mut tx,
                &app.keys
                    .verify(&submission, security::now().unwrap())
                    .unwrap()
                    .nonce,
                &app.keys
                    .anonymous(&cookie, security::now().unwrap())
                    .unwrap()
                    .nonce,
            )
            .await
            .unwrap()
            .unwrap()[1]
            .clone();
        let prepared = app
            .prepare_response(
                &mut tx,
                &m.actions[0],
                None,
                &payload,
                &auth::Principal::Anonymous,
            )
            .await
            .unwrap();
        tx.commit().await.unwrap();
        let response = app
            .finish_navigation(prepared, Instant::now() - Duration::from_millis(1))
            .await;
        assert_eq!(response.body, fallback);
    }
    #[tokio::test]
    #[ignore = "requires NOXIDE_TEST_POSTGRES with CREATE DATABASE on a disposable cluster"]
    async fn postgres_capability_mutations_and_postcommit_fault_recovery() {
        use sqlx::Connection;
        let url = std::env::var("NOXIDE_TEST_POSTGRES").unwrap();
        let mut admin = sqlx::PgConnection::connect(&url).await.unwrap();
        for case in ["capability", "fault", "private_parent"] {
            let name = format!(
                "nx_redirect_{case}_{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            );
            sqlx::query(&format!("CREATE DATABASE {name}"))
                .execute(&mut admin)
                .await
                .unwrap();
            let mut case_url = url::Url::parse(&url).unwrap();
            case_url.set_path(&format!("/{name}"));
            let db = Database::postgres(case_url.as_str()).unwrap();
            if case == "capability" {
                capability_case(db).await;
            } else if case == "private_parent" {
                private_parent_case(db).await;
            } else {
                fault_case(db).await;
            }
            sqlx::query(&format!("DROP DATABASE {name} WITH (FORCE)"))
                .execute(&mut admin)
                .await
                .unwrap();
        }
    }
}
