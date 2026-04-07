use crate::dns;
use libloading::Library;
use std::ffi::{c_char, c_int, c_void, CString};
use std::fs;
use std::io;
use std::ptr;
use std::slice;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

const LUA_OK: c_int = 0;
const LUA_MULTRET: c_int = -1;
const LUA_TNIL: c_int = 0;
const LUA_TBOOLEAN: c_int = 1;
const LUA_TSTRING: c_int = 4;
const LUA_MASKCOUNT: c_int = 1 << 3;
const LUA_MAX_PACKET_BYTES: usize = dns::DNS_MAX_PACKET_SIZE;
const LUA_FAILURE_DISABLE_THRESHOLD: usize = 8;
const LUA_INIT_INSTRUCTION_LIMIT: c_int = 500_000;
const LUA_HOOK_INSTRUCTION_LIMIT: c_int = 100_000;

type LuaInteger = i64;

enum LuaState {}
enum LuaDebug {}

type LuaNewStateFn = unsafe extern "C" fn() -> *mut LuaState;
type LuaCloseFn = unsafe extern "C" fn(*mut LuaState);
type LuaLOpenLibsFn = unsafe extern "C" fn(*mut LuaState);
type LuaLoadBufferXFn = unsafe extern "C" fn(
    *mut LuaState,
    *const c_char,
    usize,
    *const c_char,
    *const c_char,
) -> c_int;
type LuaPCallKFn =
    unsafe extern "C" fn(*mut LuaState, c_int, c_int, c_int, isize, *const c_void) -> c_int;
type LuaGetGlobalFn = unsafe extern "C" fn(*mut LuaState, *const c_char) -> c_int;
type LuaSetGlobalFn = unsafe extern "C" fn(*mut LuaState, *const c_char);
type LuaPushLStringFn = unsafe extern "C" fn(*mut LuaState, *const c_char, usize) -> *const c_char;
type LuaPushBooleanFn = unsafe extern "C" fn(*mut LuaState, c_int);
type LuaPushIntegerFn = unsafe extern "C" fn(*mut LuaState, LuaInteger);
type LuaPushNilFn = unsafe extern "C" fn(*mut LuaState);
type LuaPushCClosureFn = unsafe extern "C" fn(*mut LuaState, LuaCFunction, c_int);
type LuaNewTableFn = unsafe extern "C" fn(*mut LuaState);
type LuaSetFieldFn = unsafe extern "C" fn(*mut LuaState, c_int, *const c_char);
type LuaToLStringFn = unsafe extern "C" fn(*mut LuaState, c_int, *mut usize) -> *const c_char;
type LuaToBooleanFn = unsafe extern "C" fn(*mut LuaState, c_int) -> c_int;
type LuaToIntegerXFn = unsafe extern "C" fn(*mut LuaState, c_int, *mut c_int) -> LuaInteger;
type LuaTypeFn = unsafe extern "C" fn(*mut LuaState, c_int) -> c_int;
type LuaSetTopFn = unsafe extern "C" fn(*mut LuaState, c_int);
type LuaErrorFn = unsafe extern "C" fn(*mut LuaState) -> c_int;
type LuaSetHookFn = unsafe extern "C" fn(*mut LuaState, Option<LuaHookFn>, c_int, c_int);

type LuaCFunction = unsafe extern "C" fn(*mut LuaState) -> c_int;
type LuaHookFn = unsafe extern "C" fn(*mut LuaState, *mut LuaDebug);

#[derive(Debug)]
pub enum HookOutcome {
    Continue(Vec<u8>),
    Respond(Vec<u8>),
}

pub struct LuaScriptEngine {
    path: String,
    api: Arc<LuaApi>,
    state: Mutex<LuaStateHandle>,
    disabled: AtomicBool,
    consecutive_failures: AtomicUsize,
}

struct LuaApi {
    _library: Library,
    new_state: LuaNewStateFn,
    close: LuaCloseFn,
    open_libs: LuaLOpenLibsFn,
    load_buffer: LuaLoadBufferXFn,
    pcall: LuaPCallKFn,
    get_global: LuaGetGlobalFn,
    set_global: LuaSetGlobalFn,
    push_lstring: LuaPushLStringFn,
    push_boolean: LuaPushBooleanFn,
    push_integer: LuaPushIntegerFn,
    push_nil: LuaPushNilFn,
    push_cclosure: LuaPushCClosureFn,
    new_table: LuaNewTableFn,
    set_field: LuaSetFieldFn,
    to_lstring: LuaToLStringFn,
    to_boolean: LuaToBooleanFn,
    to_integer: LuaToIntegerXFn,
    type_of: LuaTypeFn,
    set_top: LuaSetTopFn,
    error: LuaErrorFn,
    set_hook: LuaSetHookFn,
}

struct LuaStateHandle {
    state: *mut LuaState,
    api: Arc<LuaApi>,
}

unsafe impl Send for LuaStateHandle {}

impl Drop for LuaStateHandle {
    fn drop(&mut self) {
        if !self.state.is_null() {
            unsafe { (self.api.close)(self.state) };
        }
    }
}

struct LuaCallbackApi {
    push_lstring: LuaPushLStringFn,
    push_integer: LuaPushIntegerFn,
    push_nil: LuaPushNilFn,
    to_lstring: LuaToLStringFn,
    to_integer: LuaToIntegerXFn,
}

struct LuaHookApi {
    push_lstring: LuaPushLStringFn,
    error: LuaErrorFn,
}

static LUA_CALLBACK_API: OnceLock<LuaCallbackApi> = OnceLock::new();
static LUA_HOOK_API: OnceLock<LuaHookApi> = OnceLock::new();

impl LuaScriptEngine {
    pub fn from_path(path: &str) -> io::Result<Self> {
        let api = Arc::new(LuaApi::load()?);
        let state = unsafe { (api.new_state)() };
        if state.is_null() {
            return Err(io::Error::other("Lua returned a null state"));
        }

        let handle = LuaStateHandle {
            state,
            api: api.clone(),
        };
        let engine = Self {
            path: path.to_owned(),
            api,
            state: Mutex::new(handle),
            disabled: AtomicBool::new(false),
            consecutive_failures: AtomicUsize::new(0),
        };
        engine.initialize(path)?;
        Ok(engine)
    }

    #[inline]
    pub fn is_disabled(&self) -> bool {
        self.disabled.load(Ordering::Relaxed)
    }

    pub fn apply_pre_query(&self, packet: &[u8]) -> Option<HookOutcome> {
        self.call_hook("balancedns_pre_query", packet)
    }

    pub fn apply_post_response(&self, packet: &[u8]) -> Option<HookOutcome> {
        self.call_hook("balancedns_post_response", packet)
    }

    fn initialize(&self, path: &str) -> io::Result<()> {
        let source = fs::read(path)?;
        let handle = self.state.lock().unwrap();
        let state = handle.state;

        unsafe {
            (self.api.open_libs)(state);
        }
        self.sandbox_globals(state)?;
        self.register_balancedns_api(state)?;
        self.load_chunk(state, &source, path, LUA_INIT_INSTRUCTION_LIMIT)
    }

    fn sandbox_globals(&self, state: *mut LuaState) -> io::Result<()> {
        for global_name in [
            "os",
            "io",
            "package",
            "debug",
            "dofile",
            "loadfile",
            "require",
            "collectgarbage",
        ] {
            let global_name = c_string(global_name)?;
            unsafe {
                (self.api.push_nil)(state);
                (self.api.set_global)(state, global_name.as_ptr());
            }
        }
        Ok(())
    }

    fn register_balancedns_api(&self, state: *mut LuaState) -> io::Result<()> {
        unsafe {
            (self.api.new_table)(state);
            self.set_callback(state, "qname", lua_balancedns_qname)?;
            self.set_callback(state, "qtype", lua_balancedns_qtype)?;
            self.set_callback(state, "tid", lua_balancedns_tid)?;
            self.set_callback(state, "rcode", lua_balancedns_rcode)?;
            self.set_callback(state, "len", lua_balancedns_len)?;
            self.set_callback(state, "hex", lua_balancedns_hex)?;
            self.set_callback(state, "from_hex", lua_balancedns_from_hex)?;
            self.set_callback(state, "log", lua_balancedns_log)?;
            let table_name = c_string("balancedns")?;
            (self.api.set_global)(state, table_name.as_ptr());
        }
        Ok(())
    }

    unsafe fn set_callback(
        &self,
        state: *mut LuaState,
        field_name: &str,
        callback: LuaCFunction,
    ) -> io::Result<()> {
        let field_name = c_string(field_name)?;
        (self.api.push_cclosure)(state, callback, 0);
        (self.api.set_field)(state, -2, field_name.as_ptr());
        Ok(())
    }

    fn load_chunk(
        &self,
        state: *mut LuaState,
        chunk: &[u8],
        chunk_name: &str,
        instruction_limit: c_int,
    ) -> io::Result<()> {
        let chunk_name = c_string(chunk_name)?;
        unsafe {
            (self.api.set_top)(state, 0);
            let status = (self.api.load_buffer)(
                state,
                chunk.as_ptr() as *const c_char,
                chunk.len(),
                chunk_name.as_ptr(),
                ptr::null(),
            );
            if status != LUA_OK {
                let err = self.take_lua_error(state);
                (self.api.set_top)(state, 0);
                return Err(io::Error::new(io::ErrorKind::InvalidData, err));
            }

            (self.api.set_hook)(
                state,
                Some(lua_instruction_limit_hook),
                LUA_MASKCOUNT,
                instruction_limit,
            );
            let status = (self.api.pcall)(state, 0, 0, 0, 0, ptr::null());
            (self.api.set_hook)(state, None, 0, 0);
            if status != LUA_OK {
                let err = self.take_lua_error(state);
                (self.api.set_top)(state, 0);
                return Err(io::Error::new(io::ErrorKind::InvalidData, err));
            }
            (self.api.set_top)(state, 0);
        }
        Ok(())
    }

    fn call_hook(&self, hook_name: &str, packet: &[u8]) -> Option<HookOutcome> {
        if self.is_disabled() {
            return None;
        }
        if packet.len() > LUA_MAX_PACKET_BYTES {
            self.record_failure("input packet exceeds Lua sandbox limit");
            return None;
        }

        match self.call_hook_inner(hook_name, packet) {
            Ok(result) => {
                self.record_success();
                result
            }
            Err(err) => {
                self.record_failure(&err.to_string());
                None
            }
        }
    }

    fn call_hook_inner(&self, hook_name: &str, packet: &[u8]) -> io::Result<Option<HookOutcome>> {
        let hook_name = c_string(hook_name)?;
        let handle = self.state.lock().unwrap();
        let state = handle.state;

        unsafe {
            (self.api.set_top)(state, 0);
            (self.api.get_global)(state, hook_name.as_ptr());
            if (self.api.type_of)(state, -1) == LUA_TNIL {
                (self.api.set_top)(state, 0);
                return Ok(None);
            }

            (self.api.push_lstring)(state, packet.as_ptr() as *const c_char, packet.len());
            (self.api.set_hook)(
                state,
                Some(lua_instruction_limit_hook),
                LUA_MASKCOUNT,
                LUA_HOOK_INSTRUCTION_LIMIT,
            );
            let status = (self.api.pcall)(state, 1, 2, 0, 0, ptr::null());
            (self.api.set_hook)(state, None, 0, 0);
            if status != LUA_OK {
                let err = self.take_lua_error(state);
                (self.api.set_top)(state, 0);
                return Err(io::Error::other(err));
            }

            let respond = (self.api.to_boolean)(state, -1) != 0;
            let first_value_type = (self.api.type_of)(state, -2);
            let outcome = match first_value_type {
                LUA_TNIL => None,
                LUA_TSTRING => {
                    let output = self.to_vec(state, -2)?;
                    if output.len() > LUA_MAX_PACKET_BYTES {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "Lua component returned a packet that exceeds the sandbox limit",
                        ));
                    }
                    if respond {
                        Some(HookOutcome::Respond(output))
                    } else {
                        Some(HookOutcome::Continue(output))
                    }
                }
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Lua hook must return nil or a Lua string as the first value",
                    ))
                }
            };
            (self.api.set_top)(state, 0);
            Ok(outcome)
        }
    }

    fn take_lua_error(&self, state: *mut LuaState) -> String {
        unsafe {
            self.to_vec(state, -1)
                .ok()
                .and_then(|bytes| String::from_utf8(bytes).ok())
                .unwrap_or_else(|| "Unknown Lua error".to_owned())
        }
    }

    unsafe fn to_vec(&self, state: *mut LuaState, index: c_int) -> io::Result<Vec<u8>> {
        let mut len = 0usize;
        let ptr = (self.api.to_lstring)(state, index, &mut len);
        if ptr.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Lua value is not a string",
            ));
        }
        Ok(slice::from_raw_parts(ptr as *const u8, len).to_vec())
    }

    fn record_success(&self) {
        self.consecutive_failures.store(0, Ordering::Relaxed);
    }

    fn record_failure(&self, message: &str) {
        let failures = self.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;
        if failures >= LUA_FAILURE_DISABLE_THRESHOLD {
            if !self.disabled.swap(true, Ordering::Relaxed) {
                error!(
                    "Lua component [{}] was disabled after {} consecutive failures: {}",
                    self.path, failures, message
                );
            }
        } else {
            error!(
                "Lua component [{}] failed (#{}/{}): {}",
                self.path, failures, LUA_FAILURE_DISABLE_THRESHOLD, message
            );
        }
    }
}

impl LuaApi {
    fn load() -> io::Result<Self> {
        let candidates = [
            "liblua5.4.so",
            "liblua5.4.dylib",
            "liblua.5.4.dylib",
            "liblua5.3.so",
            "liblua5.3.dylib",
            "liblua.so",
            "liblua.dylib",
        ];

        let mut last_error = None;
        for candidate in candidates {
            let library = match unsafe { Library::new(candidate) } {
                Ok(library) => library,
                Err(err) => {
                    last_error = Some(err.to_string());
                    continue;
                }
            };

            let api = unsafe {
                Self {
                    new_state: load_symbol(&library, b"luaL_newstate")?,
                    close: load_symbol(&library, b"lua_close")?,
                    open_libs: load_symbol(&library, b"luaL_openlibs")?,
                    load_buffer: load_symbol(&library, b"luaL_loadbufferx")?,
                    pcall: load_symbol(&library, b"lua_pcallk")?,
                    get_global: load_symbol(&library, b"lua_getglobal")?,
                    set_global: load_symbol(&library, b"lua_setglobal")?,
                    push_lstring: load_symbol(&library, b"lua_pushlstring")?,
                    push_boolean: load_symbol(&library, b"lua_pushboolean")?,
                    push_integer: load_symbol(&library, b"lua_pushinteger")?,
                    push_nil: load_symbol(&library, b"lua_pushnil")?,
                    push_cclosure: load_symbol(&library, b"lua_pushcclosure")?,
                    new_table: load_symbol(&library, b"lua_newtable")?,
                    set_field: load_symbol(&library, b"lua_setfield")?,
                    to_lstring: load_symbol(&library, b"lua_tolstring")?,
                    to_boolean: load_symbol(&library, b"lua_toboolean")?,
                    to_integer: load_symbol(&library, b"lua_tointegerx")?,
                    type_of: load_symbol(&library, b"lua_type")?,
                    set_top: load_symbol(&library, b"lua_settop")?,
                    error: load_symbol(&library, b"lua_error")?,
                    set_hook: load_symbol(&library, b"lua_sethook")?,
                    _library: library,
                }
            };

            let _ = LUA_CALLBACK_API.set(LuaCallbackApi {
                push_lstring: api.push_lstring,
                push_integer: api.push_integer,
                push_nil: api.push_nil,
                to_lstring: api.to_lstring,
                to_integer: api.to_integer,
            });
            let _ = LUA_HOOK_API.set(LuaHookApi {
                push_lstring: api.push_lstring,
                error: api.error,
            });

            info!(
                "Loaded Lua runtime [{}] for BalanceDNS Lua components",
                candidate
            );
            return Ok(api);
        }

        Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "Unable to locate a supported Lua shared library: {}",
                last_error.unwrap_or_else(|| "no candidate matched".to_owned())
            ),
        ))
    }
}

unsafe fn load_symbol<T: Copy>(library: &Library, symbol: &[u8]) -> io::Result<T> {
    library
        .get::<T>(symbol)
        .map(|symbol| *symbol)
        .map_err(|err| io::Error::other(err.to_string()))
}

unsafe extern "C" fn lua_instruction_limit_hook(state: *mut LuaState, _debug: *mut LuaDebug) {
    if let Some(api) = LUA_HOOK_API.get() {
        let message = b"BalanceDNS Lua sandbox: instruction limit exceeded";
        (api.push_lstring)(state, message.as_ptr() as *const c_char, message.len());
        (api.error)(state);
    }
}

unsafe extern "C" fn lua_balancedns_qname(state: *mut LuaState) -> c_int {
    match lua_string_arg(state, 1).and_then(|packet| packet_qname_string(&packet)) {
        Some(name) => lua_push_bytes(state, name.as_bytes()),
        None => lua_push_nil(state),
    }
    1
}

unsafe extern "C" fn lua_balancedns_qtype(state: *mut LuaState) -> c_int {
    match lua_string_arg(state, 1).and_then(|packet| packet_qtype_value(&packet)) {
        Some(value) => lua_push_integer(state, value as LuaInteger),
        None => lua_push_nil(state),
    }
    1
}

unsafe extern "C" fn lua_balancedns_tid(state: *mut LuaState) -> c_int {
    match lua_string_arg(state, 1).and_then(|packet| packet_tid_value(&packet)) {
        Some(value) => lua_push_integer(state, value as LuaInteger),
        None => lua_push_nil(state),
    }
    1
}

unsafe extern "C" fn lua_balancedns_rcode(state: *mut LuaState) -> c_int {
    match lua_string_arg(state, 1).and_then(|packet| packet_rcode_value(&packet)) {
        Some(value) => lua_push_integer(state, value as LuaInteger),
        None => lua_push_nil(state),
    }
    1
}

unsafe extern "C" fn lua_balancedns_len(state: *mut LuaState) -> c_int {
    match lua_string_arg(state, 1) {
        Some(packet) => lua_push_integer(state, packet.len() as LuaInteger),
        None => lua_push_nil(state),
    }
    1
}

unsafe extern "C" fn lua_balancedns_hex(state: *mut LuaState) -> c_int {
    match lua_string_arg(state, 1) {
        Some(packet) => {
            let hex = hex_encode(&packet);
            lua_push_bytes(state, hex.as_bytes());
        }
        None => lua_push_nil(state),
    }
    1
}

unsafe extern "C" fn lua_balancedns_from_hex(state: *mut LuaState) -> c_int {
    match lua_string_arg(state, 1).and_then(hex_decode) {
        Some(bytes) => lua_push_bytes(state, &bytes),
        None => lua_push_nil(state),
    }
    1
}

unsafe extern "C" fn lua_balancedns_log(state: *mut LuaState) -> c_int {
    if let Some(message) = lua_string_arg(state, 1).and_then(|bytes| String::from_utf8(bytes).ok())
    {
        info!("Lua component: {}", message);
    }
    lua_push_nil(state);
    1
}

unsafe fn lua_string_arg(state: *mut LuaState, index: c_int) -> Option<Vec<u8>> {
    let api = LUA_CALLBACK_API.get()?;
    let mut len = 0usize;
    let ptr = (api.to_lstring)(state, index, &mut len);
    if ptr.is_null() {
        return None;
    }
    Some(slice::from_raw_parts(ptr as *const u8, len).to_vec())
}

unsafe fn lua_push_bytes(state: *mut LuaState, bytes: &[u8]) {
    if let Some(api) = LUA_CALLBACK_API.get() {
        (api.push_lstring)(state, bytes.as_ptr() as *const c_char, bytes.len());
    }
}

unsafe fn lua_push_integer(state: *mut LuaState, value: LuaInteger) {
    if let Some(api) = LUA_CALLBACK_API.get() {
        (api.push_integer)(state, value);
    }
}

unsafe fn lua_push_nil(state: *mut LuaState) {
    if let Some(api) = LUA_CALLBACK_API.get() {
        (api.push_nil)(state);
    }
}

fn packet_qname_string(packet: &[u8]) -> Option<String> {
    dns::normalize(packet, true)
        .or_else(|_| dns::normalize(packet, false))
        .ok()
        .and_then(|normalized| dns::qname_to_fqdn(&normalized.qname).ok())
}

fn packet_qtype_value(packet: &[u8]) -> Option<u16> {
    dns::normalize(packet, true)
        .or_else(|_| dns::normalize(packet, false))
        .ok()
        .map(|normalized| normalized.qtype)
}

fn packet_tid_value(packet: &[u8]) -> Option<u16> {
    if packet.len() >= dns::DNS_HEADER_SIZE {
        Some(dns::tid(packet))
    } else {
        None
    }
}

fn packet_rcode_value(packet: &[u8]) -> Option<u8> {
    if packet.len() >= dns::DNS_HEADER_SIZE {
        Some(dns::rcode(packet))
    } else {
        None
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = Vec::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize]);
        out.push(HEX[(byte & 0x0f) as usize]);
    }
    String::from_utf8(out).unwrap_or_default()
}

fn hex_decode(bytes: Vec<u8>) -> Option<Vec<u8>> {
    let bytes = bytes
        .into_iter()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect::<Vec<_>>();
    if bytes.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for chunk in bytes.chunks_exact(2) {
        let hi = hex_value(chunk[0])?;
        let lo = hex_value(chunk[1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn c_string(value: &str) -> io::Result<CString> {
    CString::new(value)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "string contains NUL byte"))
}
