use libloading::Library;
use std::ffi::{c_char, c_int, c_void, CString};
use std::io;
use std::ptr;
use std::slice;
use toml::value::Table as TomlTable;
use toml::Value as TomlValue;

const LUA_OK: c_int = 0;
const LUA_MULTRET: c_int = -1;
const LUA_TNIL: c_int = 0;
const LUA_TBOOLEAN: c_int = 1;
const LUA_TNUMBER: c_int = 3;
const LUA_TSTRING: c_int = 4;
const LUA_TTABLE: c_int = 5;

type LuaInteger = i64;
type LuaNumber = f64;

enum LuaState {}

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
type LuaTypeFn = unsafe extern "C" fn(*mut LuaState, c_int) -> c_int;
type LuaToLStringFn = unsafe extern "C" fn(*mut LuaState, c_int, *mut usize) -> *const c_char;
type LuaToBooleanFn = unsafe extern "C" fn(*mut LuaState, c_int) -> c_int;
type LuaToIntegerXFn = unsafe extern "C" fn(*mut LuaState, c_int, *mut c_int) -> LuaInteger;
type LuaToNumberXFn = unsafe extern "C" fn(*mut LuaState, c_int, *mut c_int) -> LuaNumber;
type LuaIsIntegerFn = unsafe extern "C" fn(*mut LuaState, c_int) -> c_int;
type LuaGetTopFn = unsafe extern "C" fn(*mut LuaState) -> c_int;
type LuaSetTopFn = unsafe extern "C" fn(*mut LuaState, c_int);
type LuaPushNilFn = unsafe extern "C" fn(*mut LuaState);
type LuaNextFn = unsafe extern "C" fn(*mut LuaState, c_int) -> c_int;

struct LuaConfigApi {
    _library: Library,
    new_state: LuaNewStateFn,
    close: LuaCloseFn,
    open_libs: LuaLOpenLibsFn,
    load_buffer: LuaLoadBufferXFn,
    pcall: LuaPCallKFn,
    get_global: LuaGetGlobalFn,
    type_of: LuaTypeFn,
    to_lstring: LuaToLStringFn,
    to_boolean: LuaToBooleanFn,
    to_integer: LuaToIntegerXFn,
    to_number: LuaToNumberXFn,
    is_integer: LuaIsIntegerFn,
    get_top: LuaGetTopFn,
    set_top: LuaSetTopFn,
    push_nil: LuaPushNilFn,
    next: LuaNextFn,
}

struct LuaStateHandle {
    state: *mut LuaState,
    api: LuaConfigApi,
}

impl Drop for LuaStateHandle {
    fn drop(&mut self) {
        if !self.state.is_null() {
            unsafe { (self.api.close)(self.state) };
        }
    }
}

pub(crate) fn load_lua_config_value(source: &str, chunk_name: &str) -> io::Result<TomlValue> {
    let api = LuaConfigApi::load()?;
    let state = unsafe { (api.new_state)() };
    if state.is_null() {
        return Err(io::Error::other("Lua returned a null state"));
    }
    let handle = LuaStateHandle { state, api };

    unsafe {
        (handle.api.open_libs)(handle.state);
        let chunk_name = c_string(chunk_name)?;
        let status = (handle.api.load_buffer)(
            handle.state,
            source.as_ptr() as *const c_char,
            source.len(),
            chunk_name.as_ptr(),
            ptr::null(),
        );
        if status != LUA_OK {
            let err = lua_error_string(&handle.api, handle.state);
            return Err(io::Error::new(io::ErrorKind::InvalidData, err));
        }

        let status = (handle.api.pcall)(handle.state, 0, LUA_MULTRET, 0, 0, ptr::null());
        if status != LUA_OK {
            let err = lua_error_string(&handle.api, handle.state);
            return Err(io::Error::new(io::ErrorKind::InvalidData, err));
        }

        let result_count = (handle.api.get_top)(handle.state);
        if result_count > 0 && (handle.api.type_of)(handle.state, -1) == LUA_TTABLE {
            return lua_to_toml(&handle.api, handle.state, -1);
        }

        (handle.api.set_top)(handle.state, 0);
        for global_name in ["balancedns", "config"] {
            let global_name = c_string(global_name)?;
            (handle.api.get_global)(handle.state, global_name.as_ptr());
            if (handle.api.type_of)(handle.state, -1) == LUA_TTABLE {
                return lua_to_toml(&handle.api, handle.state, -1);
            }
            (handle.api.set_top)(handle.state, 0);
        }
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "config.lua must return a table or assign one to global `balancedns`/`config`",
    ))
}

impl LuaConfigApi {
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
                    type_of: load_symbol(&library, b"lua_type")?,
                    to_lstring: load_symbol(&library, b"lua_tolstring")?,
                    to_boolean: load_symbol(&library, b"lua_toboolean")?,
                    to_integer: load_symbol(&library, b"lua_tointegerx")?,
                    to_number: load_symbol(&library, b"lua_tonumberx")?,
                    is_integer: load_symbol(&library, b"lua_isinteger")?,
                    get_top: load_symbol(&library, b"lua_gettop")?,
                    set_top: load_symbol(&library, b"lua_settop")?,
                    push_nil: load_symbol(&library, b"lua_pushnil")?,
                    next: load_symbol(&library, b"lua_next")?,
                    _library: library,
                }
            };
            info!("Loaded Lua runtime [{}] for config.lua support", candidate);
            return Ok(api);
        }

        Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "Unable to locate a supported Lua shared library for config.lua: {}",
                last_error.unwrap_or_else(|| "no candidate matched".to_owned())
            ),
        ))
    }
}

unsafe fn lua_to_toml(
    api: &LuaConfigApi,
    state: *mut LuaState,
    index: c_int,
) -> io::Result<TomlValue> {
    match (api.type_of)(state, index) {
        LUA_TNIL => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "config.lua values cannot be nil",
        )),
        LUA_TBOOLEAN => Ok(TomlValue::Boolean((api.to_boolean)(state, index) != 0)),
        LUA_TNUMBER => {
            if (api.is_integer)(state, index) != 0 {
                let mut is_num = 0;
                let value = (api.to_integer)(state, index, &mut is_num);
                if is_num == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Invalid integer in config.lua",
                    ));
                }
                Ok(TomlValue::Integer(value))
            } else {
                let mut is_num = 0;
                let value = (api.to_number)(state, index, &mut is_num);
                if is_num == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Invalid float in config.lua",
                    ));
                }
                Ok(TomlValue::Float(value))
            }
        }
        LUA_TSTRING => Ok(TomlValue::String(lua_string(api, state, index)?)),
        LUA_TTABLE => lua_table_to_toml(api, state, index),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "config.lua supports only nil, booleans, numbers, strings, arrays, and tables",
        )),
    }
}

unsafe fn lua_table_to_toml(
    api: &LuaConfigApi,
    state: *mut LuaState,
    index: c_int,
) -> io::Result<TomlValue> {
    let table_index = lua_absindex(api, state, index);
    let mut array_entries = Vec::new();
    let mut object_entries = TomlTable::new();
    let mut saw_array_keys = false;
    let mut saw_object_keys = false;

    (api.push_nil)(state);
    while (api.next)(state, table_index) != 0 {
        let value = lua_to_toml(api, state, -1)?;
        match (api.type_of)(state, -2) {
            LUA_TSTRING => {
                saw_object_keys = true;
                let key = lua_string(api, state, -2)?;
                object_entries.insert(key, value);
            }
            LUA_TNUMBER => {
                if (api.is_integer)(state, -2) == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "config.lua array indexes must be positive integers",
                    ));
                }
                let mut is_num = 0;
                let key = (api.to_integer)(state, -2, &mut is_num);
                if is_num == 0 || key <= 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "config.lua array indexes must be positive integers",
                    ));
                }
                saw_array_keys = true;
                array_entries.push((key, value));
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "config.lua table keys must be strings or positive integer indexes",
                ))
            }
        }
        (api.set_top)(state, -2);
    }

    if saw_array_keys && saw_object_keys {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "config.lua tables cannot mix string keys and array indexes",
        ));
    }
    if saw_array_keys {
        array_entries.sort_by_key(|(idx, _)| *idx);
        let mut array = Vec::with_capacity(array_entries.len());
        for (expected, (actual, value)) in (1_i64..).zip(array_entries.into_iter()) {
            if actual != expected {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "config.lua arrays must be contiguous and 1-based",
                ));
            }
            array.push(value);
        }
        return Ok(TomlValue::Array(array));
    }
    Ok(TomlValue::Table(object_entries))
}

unsafe fn lua_error_string(api: &LuaConfigApi, state: *mut LuaState) -> String {
    lua_string(api, state, -1).unwrap_or_else(|_| "Unknown Lua error".to_owned())
}

unsafe fn lua_string(api: &LuaConfigApi, state: *mut LuaState, index: c_int) -> io::Result<String> {
    let mut len = 0usize;
    let ptr = (api.to_lstring)(state, index, &mut len);
    if ptr.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "config.lua value is not a string",
        ));
    }
    String::from_utf8(slice::from_raw_parts(ptr as *const u8, len).to_vec()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "config.lua strings must be valid UTF-8",
        )
    })
}

fn c_string(value: &str) -> io::Result<CString> {
    CString::new(value)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "string contains NUL byte"))
}

unsafe fn load_symbol<T: Copy>(library: &Library, symbol: &[u8]) -> io::Result<T> {
    library
        .get::<T>(symbol)
        .map(|symbol| *symbol)
        .map_err(|err| io::Error::other(err.to_string()))
}

unsafe fn lua_absindex(api: &LuaConfigApi, state: *mut LuaState, index: c_int) -> c_int {
    if index > 0 {
        index
    } else {
        (api.get_top)(state) + index + 1
    }
}
