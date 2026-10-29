use super::*;

impl Database {
    /// Rehearse the full transition with real data, then roll back every write.
    pub async fn schema_check(
        &self,
        target: &noxide_protocol::Manifest,
        migration: &crate::schema::Migration,
    ) -> Result<()> {
        crate::manifest::validate(target)?;
        let mut tx = self.begin_schema().await?;
        tx.check_storage().await?;
        let result = tx.apply_schema(target, migration).await;
        tx.rollback().await?;
        result
    }

    /// Apply a bounded declarative transition while application requests are fenced.
    pub async fn schema_apply(
        &self,
        target: &noxide_protocol::Manifest,
        migration: &crate::schema::Migration,
    ) -> Result<()> {
        crate::manifest::validate(target)?;
        let mut tx = self.begin_schema().await?;
        tx.check_storage().await?;
        let result = tx.apply_schema(target, migration).await;
        match result {
            Ok(()) => tx.commit().await,
            Err(error) => {
                tx.rollback().await?;
                Err(error)
            }
        }
    }
}

impl Transaction {
    pub(super) async fn schema_definition(
        &mut self,
    ) -> Result<
        Option<(
            Vec<noxide_protocol::Resource>,
            Vec<crate::schema::AppliedMigration>,
        )>,
    > {
        let definition = self.bounded_text("definition", noxide_protocol::MAX_MANIFEST_BYTES);
        let history = self.bounded_text("history", 32_768);
        let rows = self
            .fetch::<2>(
                &format!(
                    "SELECT {definition},{history} FROM nx_schema_definition WHERE singleton=1"
                ),
                &[],
            )
            .await?;
        rows.first()
            .map(|[definition, history]| {
                Ok((
                    serde_json::from_str(definition)?,
                    serde_json::from_str(history)?,
                ))
            })
            .transpose()
    }

    async fn store_schema(
        &mut self,
        resources: &[noxide_protocol::Resource],
        history: &[crate::schema::AppliedMigration],
    ) -> Result<()> {
        let resources = crate::schema::normalized(resources);
        let definition = serde_json::to_string(&resources)?;
        let history = serde_json::to_string(history)?;
        ensure!(
            definition.len() <= noxide_protocol::MAX_MANIFEST_BYTES && history.len() <= 32_768,
            "stored schema history limit"
        );
        self.execute("INSERT INTO nx_schema_definition(singleton,definition,history) VALUES(1,$1,$2) ON CONFLICT(singleton) DO UPDATE SET definition=excluded.definition,history=excluded.history", &[definition.into(),history.into()]).await?;
        Ok(())
    }

    async fn next_storage_id(&mut self) -> Result<i64> {
        let rows = self
            .fetch::<1>(
                "SELECT CAST(COALESCE(MAX(storage_id),0) AS TEXT) FROM nx_resource_catalog",
                &[],
            )
            .await?;
        rows[0][0]
            .parse::<i64>()?
            .checked_add(1)
            .context("resource identity exhausted")
    }

    pub(crate) async fn storage_resource(
        &mut self,
        manifest: &noxide_protocol::Manifest,
        bundle_resource: u32,
    ) -> Result<i64> {
        let key = &crate::manifest::resource(manifest, bundle_resource)?.name;
        self.storage_key(key).await
    }

    async fn storage_key(&mut self, key: &str) -> Result<i64> {
        let rows = self
            .fetch::<1>(
                "SELECT CAST(storage_id AS TEXT) FROM nx_resource_catalog WHERE resource_key=$1",
                &[key.into()],
            )
            .await?;
        rows.first().context("resource schema is not bound")?[0]
            .parse::<i64>()
            .map_err(Into::into)
    }

    pub(crate) async fn check_schema(
        &mut self,
        manifest: &noxide_protocol::Manifest,
    ) -> Result<()> {
        let (resources, _) = self
            .schema_definition()
            .await?
            .context("application schema is not bound")?;
        ensure!(
            crate::schema::digest(&resources)? == crate::schema::digest(&manifest.resources)?,
            "stored schema differs from approved resource contract; an explicit migration is required"
        );
        for resource in &manifest.resources {
            self.storage_resource(manifest, resource.id).await?;
        }
        Ok(())
    }

    pub(crate) async fn bind_schema(&mut self, manifest: &noxide_protocol::Manifest) -> Result<()> {
        if self.schema_definition().await?.is_some() {
            return self.check_schema(manifest).await;
        }
        ensure!(
            self.fetch::<1>("SELECT CAST(COUNT(*) AS TEXT) FROM nx_records", &[])
                .await?[0][0]
                == "0"
                && self
                    .fetch::<1>(
                        "SELECT CAST(COUNT(*) AS TEXT) FROM nx_resource_catalog",
                        &[]
                    )
                    .await?[0][0]
                    == "0",
            "cannot bind nonempty storage without an application schema"
        );
        for resource in crate::schema::normalized(&manifest.resources) {
            let id = self.next_storage_id().await?;
            self.execute(
                "INSERT INTO nx_resource_catalog(storage_id,resource_key) VALUES($1,$2)",
                &[id.into(), resource.name.into()],
            )
            .await?;
        }
        self.store_schema(&manifest.resources, &[]).await
    }

    pub(super) async fn row_fields(
        &mut self,
        storage: i64,
        id: i64,
    ) -> Result<noxide_protocol::Fields> {
        let value = self.bounded_text("fields", 32_768);
        let rows = self
            .fetch::<1>(
                &format!("SELECT {value} FROM nx_records WHERE resource=$1 AND id=$2"),
                &[storage.into(), id.into()],
            )
            .await?;
        serde_json::from_str(
            &rows
                .first()
                .context("record disappeared during migration")?[0],
        )
        .map_err(Into::into)
    }

    async fn transform_records(
        &mut self,
        storage: i64,
        mut transform: impl FnMut(&mut noxide_protocol::Fields) -> Result<()>,
    ) -> Result<()> {
        let mut cursor = 0i64;
        loop {
            // Page only identities, then fetch each bounded record. Even a full
            // page of maximum-sized records never accumulates in host memory.
            let rows = self.fetch::<1>("SELECT CAST(id AS TEXT) FROM nx_records WHERE resource=$1 AND id>$2 ORDER BY nx_records.id LIMIT 64", &[storage.into(),cursor.into()]).await?;
            if rows.is_empty() {
                break;
            }
            for [id] in rows {
                let id = id.parse::<i64>()?;
                let mut fields = self.row_fields(storage, id).await?;
                transform(&mut fields)?;
                let value = serde_json::to_string(&fields)?;
                ensure!(value.len() <= 32_768, "migrated record limit");
                self.execute(
                    "UPDATE nx_records SET fields=$3 WHERE resource=$1 AND id=$2",
                    &[storage.into(), id.into(), value.into()],
                )
                .await?;
                cursor = id;
            }
        }
        Ok(())
    }

    async fn validate_stored_resources(
        &mut self,
        resources: &[noxide_protocol::Resource],
    ) -> Result<()> {
        for resource in resources {
            let storage = self.storage_key(&resource.name).await?;
            self.transform_records(storage, |fields| {
                crate::manifest::validate_fields(resource, fields)
            })
            .await?;
        }
        Ok(())
    }

    async fn apply_schema(
        &mut self,
        target: &noxide_protocol::Manifest,
        migration: &crate::schema::Migration,
    ) -> Result<()> {
        use crate::schema::{self, Conversion, MigrationOp};
        let migration_digest = migration.validate()?;
        let (source, mut history) = self
            .schema_definition()
            .await?
            .context("application schema must be bound before migration")?;
        let current = schema::digest(&source)?;
        ensure!(
            schema::digest(&target.resources)? == migration.to,
            "migration target differs from approved bundle schema"
        );
        if current == migration.to
            && history
                .last()
                .is_some_and(|last| last.digest == migration_digest)
        {
            return Ok(());
        }
        ensure!(
            current == migration.from,
            "migration predecessor does not match stored schema"
        );
        ensure!(history.len() < 128, "migration history limit");
        schema::transition(&source, &target.resources, &migration.operations)?;
        for op in &migration.operations {
            match op {
                MigrationOp::AddResource { resource } => {
                    let id = self.next_storage_id().await?;
                    self.execute(
                        "INSERT INTO nx_resource_catalog(storage_id,resource_key) VALUES($1,$2)",
                        &[id.into(), resource.as_str().into()],
                    )
                    .await?;
                }
                MigrationOp::DropResource { resource } => {
                    let id = self.storage_key(resource).await?;
                    self.execute("DELETE FROM nx_records WHERE resource=$1", &[id.into()])
                        .await?;
                    self.execute(
                        "UPDATE nx_resource_catalog SET resource_key=$2 WHERE storage_id=$1",
                        &[id.into(), format!("__retired_{id}").into()],
                    )
                    .await?;
                }
                MigrationOp::RenameResource { from, to } => {
                    self.execute(
                        "UPDATE nx_resource_catalog SET resource_key=$2 WHERE resource_key=$1",
                        &[from.as_str().into(), to.as_str().into()],
                    )
                    .await?;
                }
                MigrationOp::AddField {
                    resource,
                    field,
                    value,
                } => {
                    let id = self.storage_key(resource).await?;
                    let declaration =
                        schema::field(schema::resource(&target.resources, resource)?, field)?;
                    let value = declaration.canonical(value).map_err(anyhow::Error::msg)?;
                    self.transform_records(id, |fields| {
                        ensure!(
                            fields.insert(field.clone(), value.clone()).is_none(),
                            "stored field already exists"
                        );
                        Ok(())
                    })
                    .await?;
                }
                MigrationOp::DropField { resource, field } => {
                    let id = self.storage_key(resource).await?;
                    self.transform_records(id, |fields| {
                        ensure!(fields.remove(field).is_some(), "stored field is missing");
                        Ok(())
                    })
                    .await?;
                }
                MigrationOp::RenameField { resource, from, to } => {
                    let id = self.storage_key(resource).await?;
                    self.transform_records(id, |fields| {
                        let value = fields.remove(from).context("stored field is missing")?;
                        ensure!(
                            fields.insert(to.clone(), value).is_none(),
                            "stored destination field exists"
                        );
                        Ok(())
                    })
                    .await?;
                }
                MigrationOp::ConvertField {
                    resource,
                    field,
                    conversion,
                } => {
                    let id = self.storage_key(resource).await?;
                    let destination =
                        schema::field(schema::resource(&target.resources, resource)?, field)?;
                    self.transform_records(id, |fields| {
                        let value = fields.get_mut(field).context("stored field is missing")?;
                        if !(value.is_empty() && destination.optional) {
                            *value = match conversion {
                                Conversion::TextToInteger => value
                                    .parse::<i64>()
                                    .context("text cannot be converted losslessly to integer")?
                                    .to_string(),
                                Conversion::IntegerToText => value
                                    .parse::<i64>()
                                    .context("invalid stored integer")?
                                    .to_string(),
                            };
                        }
                        destination.canonical(value).map_err(anyhow::Error::msg)?;
                        Ok(())
                    })
                    .await?;
                }
                MigrationOp::MapChoices {
                    resource,
                    field,
                    mapping,
                } => {
                    let id = self.storage_key(resource).await?;
                    self.transform_records(id, |fields| {
                        let value = fields.get_mut(field).context("stored field is missing")?;
                        if let Some(mapped) = mapping.get(value) {
                            *value = mapped.clone();
                        }
                        Ok(())
                    })
                    .await?;
                }
                MigrationOp::ChangeField { .. } => {}
            }
        }
        self.validate_stored_resources(&target.resources).await?;
        history.push(schema::AppliedMigration {
            from: migration.from.clone(),
            to: migration.to.clone(),
            digest: migration_digest,
        });
        self.store_schema(&target.resources, &history).await?;
        self.execute(
            "UPDATE nx_deployment SET generation=$1",
            &[crate::security::random_id()?.into()],
        )
        .await?;
        Ok(())
    }
}
