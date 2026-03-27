#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate libbalancedns;

use libbalancedns::dns;

fuzz_target!(|data: &[u8]| { let _ = dns::question(data); });
