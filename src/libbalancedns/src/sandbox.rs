use log::info;
use wasmtime::*;

pub struct Sandbox {
    engine: Engine,
}

impl Sandbox {
    pub fn new() -> Self {
        let engine = Engine::default();
        Self { engine }
    }

    pub fn run_plugin(&self, wasm_bytes: &[u8], packet: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut store = Store::new(&self.engine, ());
        let module = Module::from_binary(&self.engine, wasm_bytes)?;

        // 1. Hostcalls implementation
        let mut linker = Linker::new(&self.engine);
        linker.func_wrap(
            "env",
            "host_crypto_op",
            |_caller: Caller<'_, ()>, _ptr: i32, _len: i32| {
                // Implementation of heavy crypto delegated to host
                info!("Hostcall: crypto_op called from Wasm");
                0
            },
        )?;

        // 2. Zero-copy memory (shared memory simulation)
        // In a real implementation, we would export a buffer from Wasm or use a SharedMemory

        let instance = linker.instantiate(&mut store, &module)?;
        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or_else(|| anyhow::anyhow!("failed to find memory export"))?;

        // Write packet to Wasm memory
        memory.write(&mut store, 0, packet)?;

        let run = instance.get_typed_func::<(i32, i32), i32>(&mut store, "plugin_entry")?;
        let _new_len = run.call(&mut store, (0, packet.len() as i32))?;

        // Read modified packet back
        let mut result = vec![0u8; packet.len()];
        memory.read(&store, 0, &mut result)?;

        Ok(result)
    }
}
