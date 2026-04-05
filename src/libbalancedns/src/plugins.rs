use libloading::Library;
use std::slice;

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
}

unsafe impl Send for PluginLibrary {}
unsafe impl Sync for PluginLibrary {}

pub struct PluginManager {
    plugins: Vec<PluginLibrary>,
}

impl PluginManager {
    pub fn from_paths(paths: &[String]) -> Self {
        let mut plugins = Vec::new();
        for path in paths {
            match unsafe { Library::new(path) } {
                Ok(library) => {
                    info!("Loaded plugin [{}]", path);
                    plugins.push(PluginLibrary {
                        path: path.clone(),
                        library,
                    });
                }
                Err(err) => {
                    error!("Unable to load plugin [{}]: {}", path, err);
                }
            }
        }
        PluginManager { plugins }
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.plugins.is_empty()
    }

    pub fn apply_pre_query(&self, packet: &[u8]) -> Option<PacketAction> {
        if self.plugins.is_empty() {
            return None;
        }
        let mut current: Option<Vec<u8>> = None;
        for plugin in &self.plugins {
            let input = current.as_deref().unwrap_or(packet);
            match plugin.call_hook(b"balancedns_plugin_pre_query", input) {
                None => {}
                Some(PacketAction::Continue(updated)) => {
                    current = Some(updated);
                }
                Some(PacketAction::Respond(updated)) => {
                    return Some(PacketAction::Respond(updated));
                }
            }
        }
        match current {
            Some(updated) => Some(PacketAction::Continue(updated)),
            None => None,
        }
    }

    pub fn apply_post_response(&self, packet: &[u8]) -> Vec<u8> {
        if self.plugins.is_empty() {
            return packet.to_vec();
        }
        let mut current = packet.to_vec();
        for plugin in &self.plugins {
            match plugin.call_hook(b"balancedns_plugin_post_response", &current) {
                None => {}
                Some(PacketAction::Continue(updated)) | Some(PacketAction::Respond(updated)) => {
                    current = updated;
                }
            }
        }
        current
    }
}

impl PluginLibrary {
    fn call_hook(&self, symbol_name: &[u8], packet: &[u8]) -> Option<PacketAction> {
        let hook = match unsafe { self.library.get::<HookFn>(symbol_name) } {
            Ok(hook) => hook,
            Err(_) => return None,
        };
        let mut output = PluginOutput {
            ptr: std::ptr::null_mut(),
            len: 0,
        };
        let result = unsafe { hook(packet.as_ptr(), packet.len(), &mut output) };
        match result {
            0 => {
                if output.ptr.is_null() || output.len == 0 {
                    None
                } else {
                    Some(PacketAction::Continue(self.take_output(output)))
                }
            }
            1 => {
                if output.ptr.is_null() || output.len == 0 {
                    error!("Plugin [{}] returned an empty response", self.path);
                    None
                } else {
                    Some(PacketAction::Respond(self.take_output(output)))
                }
            }
            _ => {
                error!("Plugin [{}] returned an unsupported status", self.path);
                None
            }
        }
    }

    fn take_output(&self, output: PluginOutput) -> Vec<u8> {
        let free_fn = unsafe { self.library.get::<FreeFn>(b"balancedns_plugin_free" ) }.map_err(
            |_| format!("Plugin [{}] does not export balancedns_plugin_free", self.path),
        ).ok();
        let bytes = unsafe { slice::from_raw_parts(output.ptr, output.len) }.to_vec();
        if let Some(free_fn) = free_fn {
            unsafe { free_fn(output.ptr, output.len) };
        }
        bytes
    }
}
