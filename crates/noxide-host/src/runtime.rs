mod admission;

use anyhow::{Result, ensure};
use noxide_protocol::*;
use std::{sync::Arc, time::Duration};
use tokio::{sync::Semaphore, time::Instant};
use wasmtime::component::{Component, InstancePre, Linker};
use wasmtime::{Config, Engine, ResourceLimiter, Store, StoreContextMut, WasmFeatures};

#[derive(Clone, Debug)]
pub struct Limits {
    pub memory_bytes: usize,
    pub fuel: u64,
    pub host_calls: u32,
    pub wall_time: Duration,
    pub concurrency: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            memory_bytes: 64 * 1024 * 1024,
            fuel: 10_000_000,
            host_calls: 32_768,
            wall_time: Duration::from_secs(2),
            concurrency: 16,
        }
    }
}

struct MemoryBudget {
    maximum: usize,
    allocated: usize,
}
impl ResourceLimiter for MemoryBudget {
    fn memory_growing(
        &mut self,
        current: usize,
        desired: usize,
        _: Option<usize>,
    ) -> wasmtime::Result<bool> {
        let delta = desired.saturating_sub(current);
        wasmtime::ensure!(
            delta <= self.maximum.saturating_sub(self.allocated),
            "guest memory limit"
        );
        self.allocated += delta;
        Ok(true)
    }
    fn table_growing(
        &mut self,
        _: usize,
        desired: usize,
        _: Option<usize>,
    ) -> wasmtime::Result<bool> {
        wasmtime::ensure!(desired <= 4096, "guest table limit");
        Ok(true)
    }
    fn instances(&self) -> usize {
        8
    }
    fn memories(&self) -> usize {
        4
    }
    fn tables(&self) -> usize {
        4
    }
}

pub(crate) struct State {
    active: bool,
    memory: MemoryBudget,
    request: Vec<u8>,
    output: Vec<u8>,
    result: Vec<u8>,
    calls: u32,
    deadline: Instant,
    effects: Option<crate::repository::Effects>,
    failure: Option<anyhow::Error>,
}
impl State {
    fn charge(&mut self) -> wasmtime::Result<()> {
        wasmtime::ensure!(self.active, "capability unavailable in this phase");
        wasmtime::ensure!(
            self.calls > 0 && Instant::now() < self.deadline,
            "host budget exceeded"
        );
        self.calls -= 1;
        Ok(())
    }
}

fn chunk(bytes: &[u8], offset: u32) -> wasmtime::Result<u64> {
    let start = offset as usize;
    wasmtime::ensure!(start < bytes.len(), "invalid buffer offset");
    let slice = &bytes[start..bytes.len().min(start + 8)];
    let mut value = [0; 8];
    value[..slice.len()].copy_from_slice(slice);
    Ok(u64::from_le_bytes(value))
}

#[derive(Clone)]
pub struct Runtime {
    engine: Engine,
    instance: Arc<InstancePre<State>>,
    limits: Limits,
    permits: Arc<Semaphore>,
}

pub(crate) struct Attempt {
    pub result: Result<ResponseIntent>,
    pub effects: Option<crate::repository::Effects>,
    pub fuel_left: u64,
    pub calls_left: u32,
}

impl Runtime {
    /// Admission accepts portable binary components only and bounds component
    /// expansion before invoking Wasmtime. Compilation is synchronous; run it
    /// before listening for requests, within the deployment's process limits.
    pub fn compile(bytes: &[u8], limits: Limits) -> Result<Self> {
        ensure!(
            (1..=64).contains(&limits.concurrency)
                && (65_536..=128 * 1024 * 1024).contains(&limits.memory_bytes)
                && (1..=100_000_000).contains(&limits.fuel)
                && (1..=65_536).contains(&limits.host_calls)
                && !limits.wall_time.is_zero()
                && limits.wall_time <= Duration::from_secs(10),
            "invalid runtime limits"
        );
        admission::check(bytes)?;
        let mut config = Config::new();
        config
            .consume_fuel(true)
            .async_stack_zeroing(true)
            .max_wasm_stack(256 * 1024);
        config.wasm_features(
            WasmFeatures::THREADS
                | WasmFeatures::SHARED_EVERYTHING_THREADS
                | WasmFeatures::MEMORY64
                | WasmFeatures::GC,
            false,
        );
        config
            .memory_reservation(128 * 1024 * 1024)
            .memory_guard_size(64 * 1024);
        let engine = Engine::new(&config).map_err(|e| anyhow::anyhow!(e.to_string()))?;
        let component =
            Component::new(&engine, bytes).map_err(|e| anyhow::anyhow!(e.to_string()))?;
        let ty = component.component_type();
        let Some(export) = ty.get_export(&engine, "handle") else {
            anyhow::bail!("missing handle export")
        };
        let wasmtime::component::types::ComponentItem::ComponentFunc(handle) = export.ty else {
            anyhow::bail!("handle is not a function")
        };
        ensure!(
            handle.params().len() == 0 && handle.results().len() == 0,
            "handle must have the scalar unit contract"
        );
        for (name, _) in component.component_type().imports(&engine) {
            ensure!(
                name == "noxide:application/host@0.1.0",
                "unapproved component import"
            );
        }
        let mut linker: Linker<State> = Linker::new(&engine);
        let mut host = linker
            .instance("noxide:application/host@0.1.0")
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;
        host.func_wrap(
            "request-length",
            |mut cx: StoreContextMut<State>, (): ()| {
                let s = cx.data_mut();
                s.charge()?;
                Ok((s.request.len() as u32,))
            },
        )
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
        host.func_wrap(
            "request-chunk",
            |mut cx: StoreContextMut<State>, (offset,): (u32,)| {
                let s = cx.data_mut();
                s.charge()?;
                Ok((chunk(&s.request, offset)?,))
            },
        )
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
        host.func_wrap(
            "emit",
            |mut cx: StoreContextMut<State>, (word, length): (u64, u32)| {
                let s = cx.data_mut();
                s.charge()?;
                wasmtime::ensure!(
                    (1..=8).contains(&length) && s.output.len() + length as usize <= MAX_IR_BYTES,
                    "output limit"
                );
                s.output
                    .extend_from_slice(&word.to_le_bytes()[..length as usize]);
                Ok(())
            },
        )
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
        host.func_wrap(
            "result-chunk",
            |mut cx: StoreContextMut<State>, (offset,): (u32,)| {
                let s = cx.data_mut();
                s.charge()?;
                Ok((chunk(&s.result, offset)?,))
            },
        )
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
        host.func_wrap_async(
            "invoke",
            |mut cx: StoreContextMut<State>, (operation, target): (u32, u64)| {
                Box::new(async move {
                    let s = cx.data_mut();
                    s.charge()?;
                    let Some(effects) = s.effects.as_mut() else {
                        wasmtime::bail!("no repository grant")
                    };
                    match effects.invoke(operation, target).await {
                        Ok(bytes) => {
                            s.result = bytes;
                            Ok((s.result.len() as u32,))
                        }
                        Err(error) => {
                            s.failure = Some(error);
                            wasmtime::bail!("repository operation failed")
                        }
                    }
                })
            },
        )
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
        let instance = linker
            .instantiate_pre(&component)
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;
        Ok(Self {
            engine,
            instance: Arc::new(instance),
            permits: Arc::new(Semaphore::new(limits.concurrency)),
            limits,
        })
    }

    pub async fn render_only(&self, request: RequestView) -> Result<ResponseIntent> {
        self.run(
            request,
            None,
            self.limits.fuel,
            self.limits.host_calls,
            Instant::now() + self.limits.wall_time,
        )
        .await
        .result
    }

    pub(crate) fn limits(&self) -> &Limits {
        &self.limits
    }

    pub(crate) async fn run(
        &self,
        request: RequestView,
        effects: Option<crate::repository::Effects>,
        fuel: u64,
        calls: u32,
        deadline: Instant,
    ) -> Attempt {
        let mut attempt = Attempt {
            result: Err(anyhow::anyhow!("runtime initialization")),
            effects,
            fuel_left: fuel,
            calls_left: calls,
        };
        attempt.result = self.run_inner(request, &mut attempt, deadline).await;
        attempt
    }

    async fn run_inner(
        &self,
        request: RequestView,
        attempt: &mut Attempt,
        deadline: Instant,
    ) -> Result<ResponseIntent> {
        let _permit = self
            .permits
            .try_acquire()
            .map_err(|_| anyhow::anyhow!("runtime capacity"))?;
        let request = serde_json::to_vec(&request)?;
        ensure!(request.len() <= MAX_INPUT_BYTES, "request limit");
        let mut store = Store::new(
            &self.engine,
            State {
                active: false,
                memory: MemoryBudget {
                    maximum: self.limits.memory_bytes,
                    allocated: 0,
                },
                request,
                output: Vec::new(),
                result: Vec::new(),
                calls: attempt.calls_left,
                deadline,
                effects: attempt.effects.take(),
                failure: None,
            },
        );
        store.limiter(|s| &mut s.memory);
        store
            .set_fuel(attempt.fuel_left)
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;
        store
            .fuel_async_yield_interval(Some(10_000))
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;
        let run = async {
            let instance = self.instance.instantiate_async(&mut store).await?;
            let handle = instance.get_typed_func::<(), ()>(&mut store, "handle")?;
            store.data_mut().active = true;
            let result = handle.call_async(&mut store, ()).await;
            store.data_mut().active = false;
            result?;
            Ok::<(), wasmtime::Error>(())
        };
        let execution = tokio::time::timeout_at(deadline, run).await;
        attempt.fuel_left = store.get_fuel().unwrap_or(0);
        attempt.calls_left = store.data().calls;
        let mut state = store.into_data();
        attempt.effects = state.effects.take();
        if let Some(error) = state.failure {
            return Err(error);
        }
        execution
            .map_err(|_| anyhow::anyhow!("guest deadline"))?
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;
        decode_response(&state.output).map_err(anyhow::Error::msg)
    }
}
