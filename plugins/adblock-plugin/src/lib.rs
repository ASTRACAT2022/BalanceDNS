use once_cell::sync::Lazy;
use std::collections::HashSet;
use std::net::IpAddr;
use std::ptr;
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Duration;

const BLOCKLIST_URL: &str =
    "https://raw.githubusercontent.com/Zalexanninev15/NoADS_RU/main/ads_list.txt";
const REFRESH_SECONDS: u64 = 300;
const DNS_HEADER_SIZE: usize = 12;

struct Question {
    id: u16,
    flags: u16,
    question_end: usize,
    fqdn: String,
}

#[repr(C)]
pub struct PluginOutput {
    pub ptr: *mut u8,
    pub len: usize,
}

struct State {
    blocked: RwLock<HashSet<String>>,
}

static STATE: Lazy<Arc<State>> = Lazy::new(|| {
    let state = Arc::new(State {
        blocked: RwLock::new(HashSet::new()),
    });
    let _ = refresh_blocklist(&state);
    let background_state = Arc::clone(&state);
    thread::spawn(move || loop {
        thread::sleep(Duration::from_secs(REFRESH_SECONDS));
        let _ = refresh_blocklist(&background_state);
    });
    state
});

#[no_mangle]
pub extern "C" fn balancedns_plugin_pre_query(
    input: *const u8,
    input_len: usize,
    output: *mut PluginOutput,
) -> i32 {
    if input.is_null() || output.is_null() || input_len == 0 {
        return 0;
    }
    let packet = unsafe { std::slice::from_raw_parts(input, input_len) };
    let question = match parse_question(packet) {
        Ok(question) => question,
        Err(_) => return 0,
    };
    if !is_blocked(&question.fqdn, &STATE.blocked.read().unwrap()) {
        return 0;
    }
    let response = build_nxdomain_response(packet, &question);
    write_output(output, response);
    1
}

#[no_mangle]
pub extern "C" fn balancedns_plugin_free(ptr: *mut u8, len: usize) {
    if ptr.is_null() || len == 0 {
        return;
    }
    unsafe {
        let _ = Vec::from_raw_parts(ptr, len, len);
    }
}

fn refresh_blocklist(state: &State) -> Result<(), String> {
    let body = ureq::get(BLOCKLIST_URL)
        .timeout(Duration::from_secs(30))
        .call()
        .map_err(|err| err.to_string())?
        .into_string()
        .map_err(|err| err.to_string())?;
    let blocked = parse_blocklist(&body);
    *state.blocked.write().unwrap() = blocked;
    Ok(())
}

fn parse_blocklist(body: &str) -> HashSet<String> {
    let mut blocked = HashSet::new();
    for line in body.lines() {
        let line = strip_comment(line).trim();
        if line.is_empty() {
            continue;
        }
        let tokens = line.split_whitespace().collect::<Vec<&str>>();
        if tokens.is_empty() {
            continue;
        }
        if tokens[0].parse::<IpAddr>().is_ok() {
            for name in &tokens[1..] {
                blocked.insert(normalize_domain(name));
            }
            continue;
        }
        if tokens.len() == 2 && tokens[1].parse::<IpAddr>().is_ok() {
            blocked.insert(normalize_domain(tokens[0]));
            continue;
        }
        blocked.insert(normalize_domain(tokens[0]));
    }
    blocked
}

fn is_blocked(fqdn: &str, blocked: &HashSet<String>) -> bool {
    let mut current = fqdn.trim_end_matches('.');
    loop {
        let candidate = format!("{}.", current);
        if blocked.contains(&candidate) {
            return true;
        }
        match current.find('.') {
            Some(index) => current = &current[index + 1..],
            None => return false,
        }
    }
}

fn normalize_domain(value: &str) -> String {
    let mut normalized = value.trim().trim_matches('`').trim().to_ascii_lowercase();
    if !normalized.ends_with('.') {
        normalized.push('.');
    }
    normalized
}

fn strip_comment(line: &str) -> &str {
    match line.find('#') {
        Some(index) => &line[..index],
        None => line,
    }
}

fn write_output(output: *mut PluginOutput, packet: Vec<u8>) {
    let boxed = packet.into_boxed_slice();
    let len = boxed.len();
    let ptr = Box::into_raw(boxed) as *mut u8;
    unsafe {
        ptr::write(output, PluginOutput { ptr, len });
    }
}

fn parse_question(packet: &[u8]) -> Result<Question, ()> {
    if packet.len() < DNS_HEADER_SIZE {
        return Err(());
    }
    let qdcount = read_u16(packet, 4)?;
    if qdcount == 0 {
        return Err(());
    }
    let (fqdn, offset) = parse_name(packet, DNS_HEADER_SIZE)?;
    if offset + 4 > packet.len() {
        return Err(());
    }
    Ok(Question {
        id: read_u16(packet, 0)?,
        flags: read_u16(packet, 2)?,
        question_end: offset + 4,
        fqdn,
    })
}

fn parse_name(packet: &[u8], mut offset: usize) -> Result<(String, usize), ()> {
    let mut labels = Vec::new();
    loop {
        if offset >= packet.len() {
            return Err(());
        }
        let label_len = packet[offset] as usize;
        offset += 1;
        if label_len == 0 {
            break;
        }
        if label_len & 0xc0 != 0 {
            return Err(());
        }
        if offset + label_len > packet.len() {
            return Err(());
        }
        let label = std::str::from_utf8(&packet[offset..offset + label_len]).map_err(|_| ())?;
        labels.push(label.to_ascii_lowercase());
        offset += label_len;
    }
    let mut fqdn = labels.join(".");
    fqdn.push('.');
    Ok((fqdn, offset))
}

fn build_nxdomain_response(packet: &[u8], question: &Question) -> Vec<u8> {
    let mut response = Vec::with_capacity(question.question_end);
    response.extend_from_slice(&question.id.to_be_bytes());
    let flags = 0x8003u16 | (question.flags & 0x0100);
    response.extend_from_slice(&flags.to_be_bytes());
    response.extend_from_slice(&1u16.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
    response.extend_from_slice(&packet[DNS_HEADER_SIZE..question.question_end]);
    response
}

fn read_u16(packet: &[u8], offset: usize) -> Result<u16, ()> {
    if offset + 2 > packet.len() {
        return Err(());
    }
    Ok(u16::from_be_bytes([packet[offset], packet[offset + 1]]))
}
