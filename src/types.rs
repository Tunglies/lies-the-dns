use std::fmt::{Debug, Display};
use std::net::Ipv4Addr;

pub struct DNSHeader {
    pub id: u16,
    pub flags: u16,
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
}

pub struct DNSQuestion<'a> {
    pub qname: Vec<&'a [u8]>,
    pub qtype: u16,
    pub qclass: u16,
}

pub struct DNSAnswer<'a> {
    pub name: Vec<&'a [u8]>,
    pub atype: u16,
    pub aclass: u16,
    pub ttl: u32,
    pub rdata: RData<'a>,
}

pub enum RData<'a> {
    A(Ipv4Addr),
    Unkownn(&'a [u8]),
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

impl Display for DNSQuestion<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (i, label) in self.qname.iter().enumerate() {
            if i > 0 {
                write!(f, ".")?;
            }
            write!(f, "{}", String::from_utf8_lossy(label))?;
        }
        write!(f, " (Type: {}, Class: {})", self.qtype, self.qclass)
    }
}

impl Display for DNSAnswer<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (i, label) in self.name.iter().enumerate() {
            if i > 0 {
                write!(f, ".")?;
            }
            write!(f, "{}", String::from_utf8_lossy(label))?;
        }

        write!(
            f,
            " (Type: {}, Class: {}, TTL: {}, RDATA: {})",
            self.atype, self.aclass, self.ttl, self.rdata
        )
    }
}

impl Display for RData<'_> {
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

pub fn parse_dns_question<'a>(buf: &'a [u8], offset: usize) -> Option<(DNSQuestion<'a>, usize)> {
    let mut pos = offset;
    let mut qname_parts = Vec::new();
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
        qname_parts.push(&buf[pos..pos + len]);
        pos += len;
    }
    if pos + 4 > buf.len() {
        return None;
    }
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

pub fn parse_dns_answer<'a>(buf: &'a [u8], offset: usize) -> Option<(DNSAnswer<'a>, usize)> {
    let mut pos = offset;
    let mut name_parts = Vec::new();
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
        name_parts.push(&buf[pos..pos + len]);
        pos += len;
    }

    let final_pos = next_pos.unwrap_or(pos);

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

    let rdata_raw = &buf[final_pos + 10..final_pos + 10 + rdlength];

    // TODO: Support more record types to parse atype and rdata properly
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
