use crate::config::{LuaComponentConfig, LuaSandboxConfig};
use crate::dns;
use crate::lua_plugin::{HookOutcome, LuaScriptEngine};
use libloading::Library;
use std::panic::AssertUnwindSafe;
use std::slice;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

const COMPONENT_MAX_PACKET_BYTES: usize = dns::DNS_MAX_PACKET_SIZE;
const COMPONENT_FAILURE_DISABLE_THRESHOLD: usize = 8;

pub enum PacketAction {
    Continue(Vec<u8>),
    Respond(Vec<u8>),
}

#[repr(C)]
struct PluginOutput {
    ptr: *mut u8,
    len: usize,
}

type HookFn = unsafe extern "C" fn(*const u8, usize, *mut PluginOutput) -> i32;
type FreeFn = unsafe extern "C" fn(*mut u8, usize);

pub struct PluginLibrary {
    path: String,
    library: Library,
    disabled: AtomicBool,
    consecutive_failures: AtomicUsize,
}

unsafe impl Send for PluginLibrary {}
unsafe impl Sync for PluginLibrary {}

enum PluginComponent {
    Native(PluginLibrary),
    Lua(LuaScriptEngine),
}

pub struct PluginManager {
    components: Vec<PluginComponent>,
}

impl PluginManager {
    pub fn from_config(
        plugin_paths: &[String],
        lua_components: &[LuaComponentConfig],
        lua_sandbox: &LuaSandboxConfig,
    ) -> Self {
        let mut components = Vec::new();

        for path in plugin_paths {
            match unsafe { Library::new(path) } {
                Ok(library) => {
                    info!("Loaded native plugin [{}]", path);
                    components.push(PluginComponent::Native(PluginLibrary {
                        path: path.clone(),
                        library,
                        disabled: AtomicBool::new(false),
                        consecutive_failures: AtomicUsize::new(0),
                    }));
                }
                Err(err) => {
                    error!("Unable to load native plugin [{}]: {}", path, err);
                }
            }
        }

        for component in lua_components {
            if !component.enabled {
                info!("Skipping disabled Lua component [{}]", component.path);
                continue;
            }
            match LuaScriptEngine::from_config(component, lua_sandbox) {
                Ok(script) => {
                    info!("Loaded Lua component [{}]", component.path);
                    components.push(PluginComponent::Lua(script));
                }
                Err(err) => {
                    error!("Unable to load Lua component [{}]: {}", component.path, err);
                }
            }
        }

        PluginManager { components }
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.components.is_empty()
    }

    pub fn apply_pre_query(&self, packet: &[u8]) -> Option<PacketAction> {
        if self.components.is_empty() {
            return None;
        }
        let mut current: Option<Vec<u8>> = None;
        for component in &self.components {
            let input = current.as_deref().unwrap_or(packet);
            match component.apply_pre_query(input) {
                None => {}
                Some(PacketAction::Continue(updated)) => {
                    current = Some(updated);
                }
                Some(PacketAction::Respond(updated)) => {
                    return Some(PacketAction::Respond(updated));
                }
            }
        }
        current.map(PacketAction::Continue)
    }

    pub fn apply_post_response(&self, packet: &[u8]) -> Vec<u8> {
        if self.components.is_empty() {
            return packet.to_vec();
        }
        let mut current = packet.to_vec();
        for component in &self.components {
            match component.apply_post_response(&current) {
                None => {}
                Some(PacketAction::Continue(updated)) | Some(PacketAction::Respond(updated)) => {
                    current = updated;
                }
            }
        }
        current
    }
}

impl PluginComponent {
    fn apply_pre_query(&self, packet: &[u8]) -> Option<PacketAction> {
        match self {
            PluginComponent::Native(plugin) => {
                plugin.call_hook_safe(b"balancedns_plugin_pre_query", packet)
            }
            PluginComponent::Lua(script) => script.apply_pre_query(packet).map(map_lua_outcome),
        }
    }

    fn apply_post_response(&self, packet: &[u8]) -> Option<PacketAction> {
        match self {
            PluginComponent::Native(plugin) => {
                plugin.call_hook_safe(b"balancedns_plugin_post_response", packet)
            }
            PluginComponent::Lua(script) => script.apply_post_response(packet).map(map_lua_outcome),
        }
    }
}

impl PluginLibrary {
    #[inline]
    fn is_disabled(&self) -> bool {
        self.disabled.load(Ordering::Relaxed)
    }

    fn call_hook_safe(&self, symbol_name: &[u8], packet: &[u8]) -> Option<PacketAction> {
        if self.is_disabled() {
            return None;
        }
        if packet.len() > COMPONENT_MAX_PACKET_BYTES {
            self.record_failure("input packet exceeds component sandbox limit");
            return None;
        }

        let hook = match unsafe { self.library.get::<HookFn>(symbol_name) } {
            Ok(hook) => hook,
            Err(_) => return None,
        };

        let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
            let mut output = PluginOutput {
                ptr: std::ptr::null_mut(),
                len: 0,
            };
            let status = unsafe { hook(packet.as_ptr(), packet.len(), &mut output) };
            (status, output)
        }));

        match result {
            Ok((status, output)) => {
                let action = match status {
                    0 => {
                        if output.ptr.is_null() || output.len == 0 {
                            Ok(None)
                        } else {
                            self.try_take_output(output)
                                .map(|bytes| Some(PacketAction::Continue(bytes)))
                        }
                    }
                    1 => {
                        if output.ptr.is_null() || output.len == 0 {
                            Err("component returned an empty response".to_owned())
                        } else {
                            self.try_take_output(output)
                                .map(|bytes| Some(PacketAction::Respond(bytes)))
                        }
                    }
                    _ => Err("component returned an unsupported status".to_owned()),
                };

                match action {
                    Ok(action) => {
                        self.record_success();
                        action
                    }
                    Err(err) => {
                        self.record_failure(&err);
                        None
                    }
                }
            }
            Err(panic_info) => {
                self.record_failure(&format!("component panicked: {:?}", panic_info));
                None
            }
        }
    }

    fn try_take_output(&self, output: PluginOutput) -> Result<Vec<u8>, String> {
        std::panic::catch_unwind(AssertUnwindSafe(|| {
            let free_fn = unsafe { self.library.get::<FreeFn>(b"balancedns_plugin_free") }
                .map_err(|_| {
                    format!(
                        "component [{}] does not export balancedns_plugin_free",
                        self.path
                    )
                })
                .ok();
            let bytes = unsafe { slice::from_raw_parts(output.ptr, output.len) }.to_vec();
            if let Some(free_fn) = free_fn {
                unsafe { free_fn(output.ptr, output.len) };
            }
            if bytes.len() > COMPONENT_MAX_PACKET_BYTES {
                return Err("component output exceeds sandbox limit".to_owned());
            }
            Ok(bytes)
        }))
        .unwrap_or_else(|panic_info| {
            Err(format!(
                "component [{}] caused memory error in take_output: {:?}",
                self.path, panic_info
            ))
        })
    }

    fn record_success(&self) {
        self.consecutive_failures.store(0, Ordering::Relaxed);
    }

    fn record_failure(&self, message: &str) {
        let failures = self.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;
        if failures >= COMPONENT_FAILURE_DISABLE_THRESHOLD {
            if !self.disabled.swap(true, Ordering::Relaxed) {
                error!(
                    "Native component [{}] was disabled after {} consecutive failures: {}",
                    self.path, failures, message
                );
            }
        } else {
            error!(
                "Native component [{}] failed (#{}/{}): {}",
                self.path, failures, COMPONENT_FAILURE_DISABLE_THRESHOLD, message
            );
        }
    }
}

fn map_lua_outcome(outcome: HookOutcome) -> PacketAction {
    match outcome {
        HookOutcome::Continue(packet) => PacketAction::Continue(packet),
        HookOutcome::Respond(packet) => PacketAction::Respond(packet),
    }
}
