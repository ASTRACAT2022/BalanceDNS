#![no_std]

use core::panic::PanicInfo;

const STATUS_CONTINUE: u32 = 0;
const STATUS_RESPOND: u32 = 1;

#[link(wasm_import_module = "env")]
extern "C" {
    fn balancedns_host_resolve_override(ptr: i32, len: i32) -> i32;
}

// Keep a dedicated scratch region so the module always exports linear memory
// large enough for DNS packets and synthesized responses.
#[no_mangle]
pub static mut BALANCEDNS_WASM_MEMORY_ANCHOR: [u8; 65_535] = [0; 65_535];

#[no_mangle]
pub extern "C" fn balancedns_plugin_pre_query(ptr: i32, len: i32) -> i64 {
    if ptr < 0 || len < 0 {
        return pack_result(STATUS_CONTINUE, 0);
    }

    let response_len = unsafe { balancedns_host_resolve_override(ptr, len) };
    if response_len > 0 {
        pack_result(STATUS_RESPOND, response_len as u32)
    } else {
        pack_result(STATUS_CONTINUE, len as u32)
    }
}

const fn pack_result(status: u32, len: u32) -> i64 {
    (((status as u64) << 32) | (len as u64)) as i64
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    loop {}
}
