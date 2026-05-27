use std::collections::HashMap;
use std::fmt::{Debug, Display};
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use bytes::Bytes;
use lru::LruCache;

pub struct DNSHeader {
    pub id: u16,
    pub flags: u16,
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
}

#[derive(Clone, Debug, Hash, Eq, PartialEq)]
pub struct DNSQuestion {
    pub qname: String,
    pub qtype: u16,
    pub qclass: u16,
}
pub type DNSCacheKey = DNSQuestion;

#[derive(Clone, Debug)]
pub struct DNSAnswer {
    pub name: String,
    pub atype: u16,
    pub aclass: u16,
    pub ttl: u32,
    pub rdata: RData,
}

#[derive(Clone, Debug)]
pub struct DNSCacheEntry {
    pub expire_at: Instant,
    pub raw: Bytes,
}

#[derive(Clone, Debug)]
pub enum RData {
    A(Ipv4Addr),
    Unknown(Bytes),
}

impl DNSQuestion {
    pub fn key(&self) -> DNSCacheKey {
        DNSCacheKey {
            qname: self.qname.to_lowercase(),
            qtype: self.qtype,
            qclass: self.qclass,
        }
    }
}

impl DNSAnswer {
    pub fn key(&self) -> DNSCacheKey {
        DNSCacheKey {
            qname: self.name.to_lowercase(),
            qtype: self.atype,
            qclass: self.aclass,
        }
    }
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
        write!(
            f,
            "{} (Type: {}, Class: {})",
            self.qname, self.qtype, self.qclass
        )
    }
}

impl Display for DNSAnswer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} (Type: {}, Class: {}, TTL: {}, RDATA: {})",
            self.name, self.atype, self.aclass, self.ttl, self.rdata
        )
    }
}

impl Display for RData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RData::A(ip) => write!(f, "{}", ip),
            RData::Unknown(data) => write!(f, "{:02x?}", data),
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
    let (qname, mut pos) = parse_dns_name(buf, offset)?;

    if pos + 4 > buf.len() {
        return None;
    }

    let qtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
    pos += 2;

    let qclass = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
    pos += 2;

    Some((
        DNSQuestion {
            qname,
            qtype,
            qclass,
        },
        pos,
    ))
}

pub fn parse_dns_answer(buf: &Bytes, offset: usize) -> Option<(DNSAnswer, usize)> {
    let (name, mut pos) = parse_dns_name(buf, offset)?;

    if pos + 10 > buf.len() {
        return None;
    }

    let atype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
    pos += 2;

    let aclass = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
    pos += 2;

    let ttl = u32::from_be_bytes([buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]]);
    pos += 4;

    let rdlength = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
    pos += 2;

    if pos + rdlength > buf.len() {
        return None;
    }

    let rdata_raw = buf.slice(pos..pos + rdlength);

    let rdata = match atype {
        1 if rdlength == 4 => RData::A(Ipv4Addr::new(
            rdata_raw[0],
            rdata_raw[1],
            rdata_raw[2],
            rdata_raw[3],
        )),
        _ => RData::Unknown(rdata_raw),
    };

    Some((
        DNSAnswer {
            name,
            atype,
            aclass,
            ttl,
            rdata,
        },
        pos + rdlength,
    ))
}

pub fn get_cached_entry<'a>(
    cache: &'a mut LruCache<DNSCacheKey, DNSCacheEntry>,
    key: &DNSCacheKey,
) -> Option<&'a DNSCacheEntry> {
    let expired = match cache.peek(key) {
        Some(entry) => Instant::now() > entry.expire_at,
        None => return None,
    };

    if expired {
        println!("Cache expired for key: {:?}", key);
        cache.pop(key);
        return None;
    }

    cache.get(key)
}

pub fn put_cached_response(
    cache: &mut LruCache<DNSCacheKey, DNSCacheEntry>,
    questions: &[DNSQuestion],
    answers: &[DNSAnswer],
    raw: Bytes,
) {
    let mut bucket: HashMap<DNSCacheKey, Vec<DNSAnswer>> = HashMap::new();

    for answer in answers {
        bucket.entry(answer.key()).or_default().push(answer.clone());
    }

    for question in questions {
        let key = question.key();

        if let Some(matched_answers) = bucket.remove(&key) {
            let min_ttl = matched_answers.iter().map(|a| a.ttl).min().unwrap_or(0);

            if min_ttl == 0 {
                continue;
            }

            let entry = DNSCacheEntry {
                expire_at: Instant::now() + Duration::from_secs(min_ttl as u64),
                raw: raw.clone(),
            };

            cache.put(key, entry);
        }
    }
}

fn parse_dns_name(buf: &Bytes, offset: usize) -> Option<(String, usize)> {
    let mut pos = offset;
    let mut labels = Vec::new();
    let mut jumped = false;
    let mut next_pos = offset;
    let mut jump_count = 0;

    loop {
        if pos >= buf.len() {
            return None;
        }

        let len = buf[pos];

        if len & 0xC0 == 0xC0 {
            if pos + 1 >= buf.len() {
                return None;
            }

            if jump_count > 8 {
                return None;
            }

            let pointer = (((len & 0x3F) as usize) << 8) | buf[pos + 1] as usize;

            if !jumped {
                next_pos = pos + 2;
            }

            pos = pointer;
            jumped = true;
            jump_count += 1;
            continue;
        }

        if len == 0 {
            if !jumped {
                next_pos = pos + 1;
            }
            break;
        }

        let label_len = len as usize;
        pos += 1;

        if pos + label_len > buf.len() {
            return None;
        }

        let label = std::str::from_utf8(&buf[pos..pos + label_len]).ok()?;
        labels.push(label.to_string());
        pos += label_len;
    }

    Some((labels.join("."), next_pos))
}
