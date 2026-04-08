use crate::dns;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::sync::Arc;
use wasmtime::*;

const WASM_PAGE_SIZE: usize = 65_536;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WasmPacketStatus {
    Continue,
    Respond,
}

pub struct WasmRunOutcome {
    pub status: WasmPacketStatus,
    pub packet: Vec<u8>,
}

#[derive(Clone)]
pub struct WasmHostContext {
    local_hosts: HashMap<String, IpAddr>,
    remote_hosts: Arc<RwLock<HashMap<String, IpAddr>>>,
    local_ttl_seconds: u32,
    remote_ttl_seconds: u32,
}

impl WasmHostContext {
    pub fn new(
        local_hosts: HashMap<String, IpAddr>,
        remote_hosts: Arc<RwLock<HashMap<String, IpAddr>>>,
        local_ttl_seconds: u32,
        remote_ttl_seconds: u32,
    ) -> Self {
        Self {
            local_hosts,
            remote_hosts,
            local_ttl_seconds,
            remote_ttl_seconds,
        }
    }

    fn lookup_host(&self, fqdn: &str) -> Option<(IpAddr, u32)> {
        if let Some(ip_addr) = self.local_hosts.get(fqdn).copied() {
            return Some((ip_addr, self.local_ttl_seconds));
        }
        self.remote_hosts
            .read()
            .get(fqdn)
            .copied()
            .map(|ip_addr| (ip_addr, self.remote_ttl_seconds))
    }

    fn resolve_override_response(&self, packet: &[u8]) -> io::Result<Option<Vec<u8>>> {
        let normalized_question = dns::normalize(packet, true)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        let fqdn = dns::qname_to_fqdn(&normalized_question.qname)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?
            .to_ascii_lowercase();
        let Some((ip_addr, ttl)) = self.lookup_host(&fqdn) else {
            return Ok(None);
        };
        dns::build_address_packet(&normalized_question, ip_addr, ttl)
            .map(Some)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
    }
}

#[derive(Clone)]
struct WasmStoreData {
    host: Arc<WasmHostContext>,
}

pub struct Sandbox {
    engine: Engine,
    host: Arc<WasmHostContext>,
}

impl Sandbox {
    pub fn new(host: Arc<WasmHostContext>) -> Self {
        let engine = Engine::default();
        Self { engine, host }
    }

    pub fn run_plugin(
        &self,
        wasm_bytes: &[u8],
        export_name: &str,
        packet: &[u8],
    ) -> anyhow::Result<Option<WasmRunOutcome>> {
        let mut store = Store::new(
            &self.engine,
            WasmStoreData {
                host: self.host.clone(),
            },
        );
        let module = Module::from_binary(&self.engine, wasm_bytes)?;
        let mut linker = Linker::new(&self.engine);
        linker.func_wrap(
            "env",
            "balancedns_host_resolve_override",
            wasm_host_resolve_override,
        )?;

        let instance = linker.instantiate(&mut store, &module)?;
        let Some(func) = instance.get_func(&mut store, export_name) else {
            return Ok(None);
        };
        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or_else(|| anyhow::anyhow!("failed to find memory export"))?;

        ensure_memory_capacity(&memory, &mut store, packet.len())?;
        memory.write(&mut store, 0, packet)?;

        let (status, output_len) = if let Ok(run) = func.typed::<(i32, i32), i64>(&store) {
            unpack_result(run.call(&mut store, (0, packet.len() as i32))?)?
        } else {
            let run = func.typed::<(i32, i32), i32>(&store)?;
            let output_len = run.call(&mut store, (0, packet.len() as i32))?;
            if output_len < 0 {
                return Err(anyhow::anyhow!("Wasm component returned a negative output length"));
            }
            (WasmPacketStatus::Continue, output_len as usize)
        };

        ensure_memory_bounds(&memory, &store, output_len)?;
        let mut result = vec![0u8; output_len];
        memory.read(&store, 0, &mut result)?;

        Ok(Some(WasmRunOutcome {
            status,
            packet: result,
        }))
    }
}

fn unpack_result(raw: i64) -> anyhow::Result<(WasmPacketStatus, usize)> {
    let raw = raw as u64;
    let status = match (raw >> 32) as u32 {
        0 => WasmPacketStatus::Continue,
        1 => WasmPacketStatus::Respond,
        other => {
            return Err(anyhow::anyhow!(
                "Wasm component returned unsupported status {}",
                other
            ))
        }
    };
    Ok((status, raw as u32 as usize))
}

fn ensure_memory_capacity<T: 'static>(
    memory: &Memory,
    mut store: impl AsContextMut<Data = T>,
    required_len: usize,
) -> anyhow::Result<()> {
    let current_len = memory.data_size(store.as_context());
    if required_len <= current_len {
        return Ok(());
    }
    let additional = required_len - current_len;
    let pages = ((additional + WASM_PAGE_SIZE - 1) / WASM_PAGE_SIZE) as u64;
    memory.grow(&mut store, pages)?;
    Ok(())
}

fn ensure_memory_bounds<T: 'static>(
    memory: &Memory,
    store: impl AsContext<Data = T>,
    required_len: usize,
) -> anyhow::Result<()> {
    let current_len = memory.data_size(store);
    if required_len > current_len {
        return Err(anyhow::anyhow!(
            "Wasm component returned {} bytes but memory holds only {} bytes",
            required_len,
            current_len
        ));
    }
    Ok(())
}

fn wasm_host_resolve_override(mut caller: Caller<'_, WasmStoreData>, ptr: i32, len: i32) -> i32 {
    if ptr < 0 || len < 0 {
        return -1;
    }

    let Some(Extern::Memory(memory)) = caller.get_export("memory") else {
        return -1;
    };

    let start = ptr as usize;
    let input_len = len as usize;
    let end = match start.checked_add(input_len) {
        Some(end) => end,
        None => return -1,
    };

    let packet = {
        let data = memory.data(&caller);
        if end > data.len() {
            return -1;
        }
        data[start..end].to_vec()
    };

    let response = match caller.data().host.resolve_override_response(&packet) {
        Ok(Some(response)) => response,
        Ok(None) => return 0,
        Err(_) => return -1,
    };

    if ensure_memory_capacity(&memory, &mut caller, start + response.len()).is_err() {
        return -1;
    }
    if memory.write(&mut caller, start, &response).is_err() {
        return -1;
    }

    response.len() as i32
}
