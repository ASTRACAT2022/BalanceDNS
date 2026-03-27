use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::net::IpAddr;
use std::ptr;
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Duration;

const HOSTS_URL: &str =
    "https://raw.githubusercontent.com/ASTRACAT2022/host-DNS/refs/heads/main/bypass";
const REFRESH_SECONDS: u64 = 300;
const TTL_SECONDS: u32 = 60;
const DNS_HEADER_SIZE: usize = 12;
const DNS_TYPE_A: u16 = 1;
const DNS_TYPE_AAAA: u16 = 28;

struct Question {
    id: u16,
    flags: u16,
    qtype: u16,
    qclass: u16,
    fqdn: String,
    question_end: usize,
}

#[repr(C)]
pub struct PluginOutput {
    pub ptr: *mut u8,
    pub len: usize,
}

struct State {
    hosts: RwLock<HashMap<String, IpAddr>>,
}

static STATE: Lazy<Arc<State>> = Lazy::new(|| {
    let state = Arc::new(State {
        hosts: RwLock::new(HashMap::new()),
    });
    let _ = refresh_hosts(&state);
    let background_state = Arc::clone(&state);
    thread::spawn(move || loop {
        thread::sleep(Duration::from_secs(REFRESH_SECONDS));
        let _ = refresh_hosts(&background_state);
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
    let ip_addr = match STATE.hosts.read().unwrap().get(&question.fqdn).copied() {
        Some(ip_addr) => ip_addr,
        None => return 0,
    };
    let matches_qtype = match ip_addr {
        IpAddr::V4(_) => question.qtype == DNS_TYPE_A,
        IpAddr::V6(_) => question.qtype == DNS_TYPE_AAAA,
    };
    if !matches_qtype {
        return 0;
    }
    let response = build_address_response(packet, &question, ip_addr, TTL_SECONDS);
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

fn refresh_hosts(state: &State) -> Result<(), String> {
    let body = ureq::get(HOSTS_URL)
        .timeout(Duration::from_secs(30))
        .call()
        .map_err(|err| err.to_string())?
        .into_string()
        .map_err(|err| err.to_string())?;
    let hosts = parse_hosts_mapping(&body);
    *state.hosts.write().unwrap() = hosts;
    Ok(())
}

fn parse_hosts_mapping(body: &str) -> HashMap<String, IpAddr> {
    let mut hosts = HashMap::new();
    for line in body.lines() {
        let line = strip_comment(line).trim();
        if line.is_empty() {
            continue;
        }
        let tokens = line.split_whitespace().collect::<Vec<&str>>();
        if tokens.len() == 1 {
            continue;
        }
        let (ip_str, names) = if tokens[0].parse::<IpAddr>().is_ok() {
            (tokens[0], &tokens[1..])
        } else if tokens[tokens.len() - 1].parse::<IpAddr>().is_ok() {
            (tokens[tokens.len() - 1], &tokens[..tokens.len() - 1])
        } else if tokens.len() == 2 {
            (tokens[1], &tokens[..1])
        } else {
            continue;
        };
        if let Ok(ip_addr) = ip_str.parse::<IpAddr>() {
            for name in names {
                hosts.insert(normalize_domain(name), ip_addr);
            }
        }
    }
    hosts
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
        qtype: read_u16(packet, offset)?,
        qclass: read_u16(packet, offset + 2)?,
        fqdn,
        question_end: offset + 4,
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

fn build_address_response(
    packet: &[u8],
    question: &Question,
    ip_addr: IpAddr,
    ttl: u32,
) -> Vec<u8> {
    let mut response = Vec::with_capacity(question.question_end + 32);
    response.extend_from_slice(&question.id.to_be_bytes());
    let flags = 0x8000u16 | (question.flags & 0x0100);
    response.extend_from_slice(&flags.to_be_bytes());
    response.extend_from_slice(&1u16.to_be_bytes());
    response.extend_from_slice(&1u16.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
    response.extend_from_slice(&packet[DNS_HEADER_SIZE..question.question_end]);
    response.extend_from_slice(&0xc00cu16.to_be_bytes());
    response.extend_from_slice(&question.qtype.to_be_bytes());
    response.extend_from_slice(&question.qclass.to_be_bytes());
    response.extend_from_slice(&ttl.to_be_bytes());
    match ip_addr {
        IpAddr::V4(ip_addr) => {
            response.extend_from_slice(&(4u16).to_be_bytes());
            response.extend_from_slice(&ip_addr.octets());
        }
        IpAddr::V6(ip_addr) => {
            response.extend_from_slice(&(16u16).to_be_bytes());
            response.extend_from_slice(&ip_addr.octets());
        }
    }
    response
}

fn read_u16(packet: &[u8], offset: usize) -> Result<u16, ()> {
    if offset + 2 > packet.len() {
        return Err(());
    }
    Ok(u16::from_be_bytes([packet[offset], packet[offset + 1]]))
}
