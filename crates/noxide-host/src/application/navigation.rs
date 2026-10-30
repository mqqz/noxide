//! Mutation response preparation and bounded post-commit navigation.
//!
//! Submission owns canonicalization, authorization, mutation and atomic receipt
//! persistence. `prepare_response` may prepare recovery/handover data before
//! commitment; callers deliver it only after commit confirmation or a verified
//! committed receipt. An unknown commit outcome stays in receipt recovery.
//! `finish_navigation` resolves presentation after commitment and cannot undo the write.
//! Parent destination checks use fresh read authority and the captured incarnation;
//! a child edit credential never grants parent read authority.
use super::*;

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SemanticReceipt {
    pub version: u32,
    pub outcome: SemanticOutcome,
    pub destination: Option<ParentDestination>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub(super) enum SemanticOutcome {
    Edit(EditReceipt),
    Mutation(ResponseIntent),
}
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ParentDestination {
    route: u32,
    resource: u32,
    id: u64,
    incarnation: String,
}
pub(super) struct Prepared {
    pub fallback: Rendered,
    navigation: Option<(ParentDestination, auth::Principal, bool)>,
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
        action: &Action,
        stored: Option<&StoredRecord>,
    ) -> Result<Option<ParentDestination>> {
        let Redirect::Parent { parent: route } = action.redirect else {
            return Ok(None);
        };
        let op = manifest::operation(&self.manifest, action.operation)?;
        let parent = manifest::parent_resource(&self.manifest, op.resource)?
            .ok_or_else(|| anyhow::anyhow!("missing parent"))?;
        let stored = stored.ok_or_else(|| anyhow::anyhow!("missing relationship snapshot"))?;
        let field = manifest::parent_field(manifest::resource(&self.manifest, op.resource)?)
            .expect("validated parent");
        let id = if op.kind == OperationKind::Create {
            stored.record.id
        } else {
            stored
                .record
                .fields
                .get(&field.name)
                .ok_or_else(|| anyhow::anyhow!("missing parent ID"))?
                .parse()?
        };
        let parent_record = repository::load(tx, &self.manifest, parent.id, id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("missing parent"))?;
        Ok(Some(ParentDestination {
            route,
            resource: parent.id,
            id,
            incarnation: parent_record.incarnation,
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
        let decoded = serde_json::from_str::<SemanticReceipt>(payload).ok();
        let semantic_outcome = decoded
            .as_ref()
            .map(|receipt| serde_json::to_string(&receipt.outcome))
            .transpose()?;
        let (outcome, destination) = match decoded.as_ref() {
            Some(receipt) => {
                ensure!(receipt.version == 1, "invalid receipt version");
                (
                    semantic_outcome.as_deref().expect("decoded outcome"),
                    receipt.destination.as_ref(),
                )
            }
            None => (payload, None),
        };
        if !matches!(action.redirect, Redirect::Parent { .. }) {
            ensure!(destination.is_none(), "unexpected parent destination");
            return Ok(Prepared::ready(
                self.receipt_response(tx, action, target, outcome).await?,
            ));
        }
        let destination =
            destination.ok_or_else(|| anyhow::anyhow!("missing parent destination"))?;
        let op = manifest::operation(&self.manifest, action.operation)?;
        ensure!(
            destination.route == action.redirect.route()
                && Some(destination.resource)
                    == manifest::parent_resource(&self.manifest, op.resource)?.map(|p| p.id),
            "receipt destination differs"
        );
        let handover = manifest::is_public(op) && op.kind == OperationKind::Create;
        let fallback = if handover {
            let receipt: EditReceipt = serde_json::from_str(outcome)?;
            ensure!(receipt.resource == op.resource, "receipt resource differs");
            self.edit_handover(tx, &receipt, None).await?
        } else {
            // Validate the original mutation identity before using its receipt.
            self.receipt(action, target, outcome)?;
            success()
        };
        let destination = ParentDestination {
            route: destination.route,
            resource: destination.resource,
            id: destination.id,
            incarnation: destination.incarnation.clone(),
        };
        Ok(Prepared {
            fallback,
            navigation: Some((destination, principal.clone(), handover)),
        })
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
        // Four navigation calls are reserved once for this request. Capture is
        // charged separately on each mutation attempt; this path loads one record.
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
    fn frozen_receipt_wire_formats_round_trip() {
        // Existing receipt representations, including the ordinary pre-envelope
        // mutation format, remain decodable. Keys and identifiers are test data.
        for raw in [
            r#"{"version":1,"outcome":{"resource":7,"id":9,"cap_version":2,"key_id":3},"destination":null}"#,
            r#"{"version":1,"outcome":{"created":{"resource":7,"id":9,"destination":{"route":4,"target":9}}},"destination":{"route":5,"resource":6,"id":8,"incarnation":"test-incarnation"}}"#,
            r#"{"version":1,"outcome":{"deleted":{"resource":7,"id":9,"destination":{"route":4,"target":null}}},"destination":null}"#,
        ] {
            let receipt: SemanticReceipt = serde_json::from_str(raw).unwrap();
            assert_eq!(
                serde_json::to_value(receipt).unwrap(),
                serde_json::from_str::<serde_json::Value>(raw).unwrap()
            );
        }
        for raw in [
            r#"{"updated":{"resource":7,"id":9,"destination":{"route":4,"target":9}}}"#,
            r#"{"deleted":{"resource":7,"id":9,"destination":{"route":4,"target":null}}}"#,
        ] {
            let outcome: SemanticOutcome = serde_json::from_str(raw).unwrap();
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
        for raw in ["4", r#"{"parent":5}"#] {
            let redirect: Redirect = serde_json::from_str(raw).unwrap();
            assert_eq!(
                serde_json::to_value(redirect).unwrap(),
                serde_json::from_str::<serde_json::Value>(raw).unwrap()
            );
        }
        assert!(serde_json::from_str::<Redirect>(r#"{"parent":5,"extra":true}"#).is_err());
    }

    #[tokio::test]
    async fn private_parent_navigation_matches_owner_and_moderator_reads() {
        let tmp = tempfile::tempdir().unwrap();
        private_parent_case(Database::sqlite(tmp.path().join("private-parent.db"))).await;
    }

    async fn private_parent_case(db: Database) {
        db.initialize().await.unwrap();
        let mut m = parent_tests::declarations();
        m.actions[0].redirect = Redirect::Parent { parent: 3 };
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
                            ParentDestination {
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
        for (id, kind) in [(4, OperationKind::Update), (5, OperationKind::Delete)] {
            m.operations.push(Operation {
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
            m.actions.push(Action {
                id: id - 2,
                version: 1,
                name: "Change reply".into(),
                operation: id,
                redirect: Redirect::Parent { parent: 3 },
                fields: if id == 4 { vec!["body".into()] } else { vec![] },
                layout: vec![],
                inspect: None,
            });
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
                &super::super::submission::input_digest(&m.actions[0], &input).unwrap(),
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
