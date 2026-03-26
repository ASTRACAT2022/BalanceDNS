pub fn read_id(packet: &[u8]) -> Option<u16> {
    if packet.len() < 2 {
        return None;
    }
    Some(u16::from_be_bytes([packet[0], packet[1]]))
}

pub fn write_id(packet: &mut [u8], id: u16) -> bool {
    if packet.len() < 2 {
        return false;
    }
    let bytes = id.to_be_bytes();
    packet[0] = bytes[0];
    packet[1] = bytes[1];
    true
}

pub fn read_qtype(packet: &[u8]) -> Option<u16> {
    let mut offset = 12;
    offset = skip_name(packet, offset)?;
    let qtype = read_u16(packet, offset)?;
    Some(qtype)
}

pub fn read_qname_qtype_qclass(packet: &[u8]) -> Option<(String, u16, u16)> {
    if packet.len() < 12 {
        return None;
    }
    let (name, offset) = read_name(packet, 12)?;
    let qtype = read_u16(packet, offset)?;
    let qclass = read_u16(packet, offset + 2)?;
    Some((name, qtype, qclass))
}

#[derive(Clone)]
pub enum Answers {
    A(Vec<std::net::Ipv4Addr>),
    AAAA(Vec<std::net::Ipv6Addr>),
}

impl Answers {
    pub fn is_empty(&self) -> bool {
        match self {
            Answers::A(v) => v.is_empty(),
            Answers::AAAA(v) => v.is_empty(),
        }
    }
}

pub fn build_answer_response(
    query: &[u8],
    name: &str,
    qtype: u16,
    answers: Answers,
    ttl_seconds: u32,
) -> Option<Vec<u8>> {
    use trust_dns_proto::{
        op::{Message, MessageType, OpCode, Query},
        rr::{Name, RData, Record, RecordType},
    };

    let id = read_id(query)?;
    let flags = u16::from_be_bytes([*query.get(2)?, *query.get(3)?]);
    let rd = (flags & 0x0100) != 0;

    let name = Name::from_ascii(name).ok()?;
    let record_type = match qtype {
        1 => RecordType::A,
        28 => RecordType::AAAA,
        _ => return None,
    };

    let mut msg = Message::new();
    msg.set_id(id);
    msg.set_message_type(MessageType::Response);
    msg.set_op_code(OpCode::Query);
    msg.set_recursion_desired(rd);
    msg.set_recursion_available(true);
    msg.add_query(Query::query(name.clone(), record_type));

    match answers {
        Answers::A(v4s) => {
            for ip in v4s {
                let mut rec = Record::new();
                rec.set_name(name.clone());
                rec.set_ttl(ttl_seconds as u32);
                rec.set_record_type(RecordType::A);
                rec.set_data(Some(RData::A(trust_dns_proto::rr::rdata::A(ip))));
                msg.add_answer(rec);
            }
        }
        Answers::AAAA(v6s) => {
            for ip in v6s {
                let mut rec = Record::new();
                rec.set_name(name.clone());
                rec.set_ttl(ttl_seconds as u32);
                rec.set_record_type(RecordType::AAAA);
                rec.set_data(Some(RData::AAAA(trust_dns_proto::rr::rdata::AAAA(ip))));
                msg.add_answer(rec);
            }
        }
    }

    msg.to_vec().ok()
}

fn read_u16(packet: &[u8], offset: usize) -> Option<u16> {
    let b0 = *packet.get(offset)?;
    let b1 = *packet.get(offset + 1)?;
    Some(u16::from_be_bytes([b0, b1]))
}

fn read_name(packet: &[u8], mut offset: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut jumped = false;
    let mut end_offset = None;
    let mut seen = 0usize;

    loop {
        let len = *packet.get(offset)?;
        if len & 0b1100_0000 == 0b1100_0000 {
            let b1 = *packet.get(offset + 1)?;
            let ptr = (((len & 0b0011_1111) as usize) << 8) | (b1 as usize);
            if !jumped {
                end_offset = Some(offset + 2);
                jumped = true;
            }
            offset = ptr;
            seen += 1;
            if seen > 16 {
                return None;
            }
            continue;
        }

        if len == 0 {
            let end = if jumped { end_offset? } else { offset + 1 };
            let mut out = if labels.is_empty() {
                ".".to_string()
            } else {
                labels.join(".")
            };
            if !out.ends_with('.') {
                out.push('.');
            }
            return Some((out.to_ascii_lowercase(), end));
        }

        let start = offset + 1;
        let next = start + (len as usize);
        if next > packet.len() {
            return None;
        }
        let label = std::str::from_utf8(&packet[start..next]).ok()?;
        labels.push(label.to_string());
        offset = next;
        if jumped {
            seen += 1;
            if seen > 256 {
                return None;
            }
        }
    }
}

fn skip_name(packet: &[u8], mut offset: usize) -> Option<usize> {
    let mut jumped = false;
    let mut end_offset = None;
    let mut seen = 0;

    loop {
        let len = *packet.get(offset)?;

        if len & 0b1100_0000 == 0b1100_0000 {
            let b1 = *packet.get(offset + 1)?;
            let ptr = (((len & 0b0011_1111) as usize) << 8) | (b1 as usize);
            if !jumped {
                end_offset = Some(offset + 2);
                jumped = true;
            }
            offset = ptr;
            seen += 1;
            if seen > 16 {
                return None;
            }
            continue;
        }

        if len == 0 {
            if jumped {
                return end_offset;
            }
            return Some(offset + 1);
        }

        let next = offset + 1 + (len as usize);
        if next > packet.len() {
            return None;
        }
        offset = next;
        if jumped {
            seen += 1;
            if seen > 256 {
                return None;
            }
        }
    }
}
