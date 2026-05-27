use std::fmt::{Debug, Display};

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

pub fn parse_dns_question<'a>(buf: &'a [u8]) -> Option<(DNSQuestion<'a>, usize)> {
    let mut pos = 12;
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
