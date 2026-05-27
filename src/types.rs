use std::fmt::{Debug, Display};
use std::net::Ipv4Addr;

use bytes::Bytes;

pub struct DNSHeader {
    pub id: u16,
    pub flags: u16,
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
}

pub struct DNSQuestion {
    pub qname: Bytes,
    pub qtype: u16,
    pub qclass: u16,
}

pub struct DNSAnswer {
    pub name: Bytes,
    pub atype: u16,
    pub aclass: u16,
    pub ttl: u32,
    pub rdata: RData,
}

pub enum RData {
    A(Ipv4Addr),
    Unkownn(Bytes),
}

impl Debug for DNSHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DNSHeader")
            .field("id", &self.id)
            .field("flags", &format_args!("{:#06x}", self.flags))
            .field("qdcount", &self.qdcount)
            .field("ancount", &self.ancount)
            .field("nscount", &self.nscount)
            .field("arcount", &self.arcount)
            .finish()
    }
}

impl Display for DNSQuestion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut parts = Vec::new();
        let mut pos = 0;
        while pos < self.qname.len() {
            let len = self.qname[pos] as usize;
            if len == 0 {
                break;
            }
            pos += 1;
            if pos + len <= self.qname.len() {
                parts.push(String::from_utf8_lossy(&self.qname[pos..pos + len]).to_string());
            }
            pos += len;
        }
        write!(
            f,
            "{} (Type: {}, Class: {})",
            parts.join("."),
            self.qtype,
            self.qclass
        )
    }
}

impl Display for DNSAnswer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut parts = Vec::new();
        let mut pos = 0;
        while pos < self.name.len() {
            let len = self.name[pos] as usize;
            if len == 0 {
                break;
            }
            pos += 1;
            if pos + len <= self.name.len() {
                parts.push(String::from_utf8_lossy(&self.name[pos..pos + len]).to_string());
            }
            pos += len;
        }
        write!(
            f,
            "{} (Type: {}, Class: {}, TTL: {}, RDATA: {})",
            parts.join("."),
            self.atype,
            self.aclass,
            self.ttl,
            self.rdata
        )
    }
}

impl Display for RData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RData::A(ip) => write!(f, "{}", ip),
            RData::Unkownn(data) => write!(f, "{:02x?}", data),
        }
    }
}

pub fn parse_dns_header(buf: &[u8]) -> Option<DNSHeader> {
    if buf.len() < 12 {
        return None;
    }
    Some(DNSHeader {
        id: u16::from_be_bytes([buf[0], buf[1]]),
        flags: u16::from_be_bytes([buf[2], buf[3]]),
        qdcount: u16::from_be_bytes([buf[4], buf[5]]),
        ancount: u16::from_be_bytes([buf[6], buf[7]]),
        nscount: u16::from_be_bytes([buf[8], buf[9]]),
        arcount: u16::from_be_bytes([buf[10], buf[11]]),
    })
}

pub fn parse_dns_question(buf: &Bytes, offset: usize) -> Option<(DNSQuestion, usize)> {
    let mut pos = offset;
    let start = offset;
    while pos < buf.len() {
        let len = buf[pos] as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        pos += 1;
        if pos + len > buf.len() {
            return None;
        }
        pos += len;
    }
    if pos + 4 > buf.len() {
        return None;
    }
    let qname_parts = buf.slice(start..pos);
    let qtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
    let qclass = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]);
    Some((
        DNSQuestion {
            qname: qname_parts,
            qtype,
            qclass,
        },
        pos + 4,
    ))
}

pub fn parse_dns_answer(buf: &Bytes, offset: usize) -> Option<(DNSAnswer, usize)> {
    let mut pos = offset;
    let start = offset;
    let mut next_pos = None;
    let mut jump_count = 0;

    while pos < buf.len() {
        let len = buf[pos] as usize;

        if len & 0xC0 == 0xC0 {
            if jump_count > 5 {
                return None;
            }
            if pos + 1 >= buf.len() {
                return None;
            }

            let offset_bytes = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
            let pointer_offset = (offset_bytes & 0x3FFF) as usize;

            if next_pos.is_none() {
                next_pos = Some(pos + 2);
            }

            pos = pointer_offset;
            jump_count += 1;
            continue;
        }

        if len == 0 {
            pos += 1;
            break;
        }

        pos += 1;
        if pos + len > buf.len() {
            return None;
        }
        pos += len;
    }

    let final_pos = next_pos.unwrap_or(pos);
    let name_end = next_pos.unwrap_or(pos);
    let name_parts = buf.slice(start..name_end);

    if final_pos + 10 > buf.len() {
        return None;
    }

    let atype = u16::from_be_bytes([buf[final_pos], buf[final_pos + 1]]);
    let aclass = u16::from_be_bytes([buf[final_pos + 2], buf[final_pos + 3]]);
    let ttl = u32::from_be_bytes([
        buf[final_pos + 4],
        buf[final_pos + 5],
        buf[final_pos + 6],
        buf[final_pos + 7],
    ]);
    let rdlength = u16::from_be_bytes([buf[final_pos + 8], buf[final_pos + 9]]) as usize;

    if final_pos + 10 + rdlength > buf.len() {
        return None;
    }

    let rdata_raw = buf.slice(final_pos + 10..final_pos + 10 + rdlength);

    let rdata = match atype {
        1 if rdlength == 4 => RData::A(Ipv4Addr::new(
            rdata_raw[0],
            rdata_raw[1],
            rdata_raw[2],
            rdata_raw[3],
        )),
        _ => RData::Unkownn(rdata_raw),
    };

    Some((
        DNSAnswer {
            name: name_parts,
            atype,
            aclass,
            ttl,
            rdata,
        },
        final_pos + 10 + rdlength,
    ))
}
