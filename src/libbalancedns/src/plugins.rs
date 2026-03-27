use libloading::Library;
use std::io::{self, Error, ErrorKind};
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

    pub fn apply_pre_query(&self, packet: &[u8]) -> io::Result<Option<PacketAction>> {
        self.apply(packet, b"balancedns_plugin_pre_query")
    }

    pub fn apply_post_response(&self, packet: &[u8]) -> io::Result<Vec<u8>> {
        let mut current = packet.to_vec();
        for plugin in &self.plugins {
            match plugin.call_hook(b"balancedns_plugin_post_response", &current)? {
                None => {}
                Some(PacketAction::Continue(updated)) | Some(PacketAction::Respond(updated)) => {
                    current = updated;
                }
            }
        }
        Ok(current)
    }

    fn apply(&self, packet: &[u8], symbol_name: &[u8]) -> io::Result<Option<PacketAction>> {
        let mut current = packet.to_vec();
        let mut changed = false;
        for plugin in &self.plugins {
            match plugin.call_hook(symbol_name, &current)? {
                None => {}
                Some(PacketAction::Continue(updated)) => {
                    current = updated;
                    changed = true;
                }
                Some(PacketAction::Respond(updated)) => {
                    return Ok(Some(PacketAction::Respond(updated)));
                }
            }
        }
        if changed {
            Ok(Some(PacketAction::Continue(current)))
        } else {
            Ok(None)
        }
    }
}

impl PluginLibrary {
    fn call_hook(&self, symbol_name: &[u8], packet: &[u8]) -> io::Result<Option<PacketAction>> {
        let hook = match unsafe { self.library.get::<HookFn>(symbol_name) } {
            Ok(hook) => hook,
            Err(_) => return Ok(None),
        };
        let mut output = PluginOutput {
            ptr: std::ptr::null_mut(),
            len: 0,
        };
        let result = unsafe { hook(packet.as_ptr(), packet.len(), &mut output) };
        match result {
            0 => {
                if output.ptr.is_null() || output.len == 0 {
                    Ok(None)
                } else {
                    Ok(Some(PacketAction::Continue(self.take_output(output)?)))
                }
            }
            1 => {
                if output.ptr.is_null() || output.len == 0 {
                    Err(Error::new(
                        ErrorKind::InvalidData,
                        format!("Plugin [{}] returned an empty response", self.path),
                    ))
                } else {
                    Ok(Some(PacketAction::Respond(self.take_output(output)?)))
                }
            }
            _ => Err(Error::new(
                ErrorKind::InvalidData,
                format!("Plugin [{}] returned an unsupported status", self.path),
            )),
        }
    }

    fn take_output(&self, output: PluginOutput) -> io::Result<Vec<u8>> {
        let free_fn = unsafe { self.library.get::<FreeFn>(b"balancedns_plugin_free") }.map_err(
            |_| {
                Error::new(
                    ErrorKind::InvalidData,
                    format!("Plugin [{}] does not export balancedns_plugin_free", self.path),
                )
            },
        )?;
        let bytes = unsafe { slice::from_raw_parts(output.ptr, output.len) }.to_vec();
        unsafe { free_fn(output.ptr, output.len) };
        Ok(bytes)
    }
}
