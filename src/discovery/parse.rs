//! Parse mDNS response packets into resource records.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::error::{Error, Result};

const TYPE_A: u16 = 1;
const TYPE_PTR: u16 = 12;
const TYPE_TXT: u16 = 16;
const TYPE_AAAA: u16 = 28;
const TYPE_SRV: u16 = 33;

/// A resource record we care about for AirPlay discovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rr {
    Ptr { name: String, target: String },
    Srv { name: String, port: u16, target: String },
    Txt { name: String, pairs: Vec<(String, String)> },
    A { name: String, addr: Ipv4Addr },
    Aaaa { name: String, addr: Ipv6Addr },
}

fn u16_at(data: &[u8], pos: usize) -> Result<u16> {
    let b = data
        .get(pos..pos + 2)
        .ok_or_else(|| Error::Discovery("truncated integer".into()))?;
    Ok(u16::from_be_bytes([b[0], b[1]]))
}

/// Read a (possibly compressed) DNS name starting at `pos`. Returns the decoded
/// name and the offset of the byte just past the name in the original stream.
fn read_name(data: &[u8], pos: usize) -> Result<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut cur = pos;
    let mut end_after = pos;
    let mut jumped = false;
    for _ in 0..128 {
        let len = *data
            .get(cur)
            .ok_or_else(|| Error::Discovery("name past end".into()))?;
        if len == 0 {
            if !jumped {
                end_after = cur + 1;
            }
            return Ok((labels.join("."), end_after));
        }
        if len & 0xC0 == 0xC0 {
            let lo = *data
                .get(cur + 1)
                .ok_or_else(|| Error::Discovery("pointer past end".into()))?;
            let ptr = (usize::from(len & 0x3F) << 8) | usize::from(lo);
            if !jumped {
                end_after = cur + 2;
            }
            jumped = true;
            cur = ptr;
            continue;
        }
        if len & 0xC0 != 0 {
            // Only the 0x00 (label) and 0xC0 (pointer) forms are valid; the
            // 0x40/0x80 prefixes are reserved.
            return Err(Error::Discovery("reserved label prefix".into()));
        }
        let start = cur + 1;
        let end = start + usize::from(len);
        let label = data
            .get(start..end)
            .ok_or_else(|| Error::Discovery("label past end".into()))?;
        labels.push(String::from_utf8_lossy(label).into_owned());
        cur = end;
        if !jumped {
            end_after = cur;
        }
    }
    Err(Error::Discovery("name loop limit".into()))
}

fn parse_txt(rdata: &[u8]) -> Vec<(String, String)> {
    let mut pairs = Vec::new();
    let mut i = 0;
    while i < rdata.len() {
        let len = usize::from(rdata[i]);
        i += 1;
        let Some(chunk) = rdata.get(i..i + len) else {
            break;
        };
        i += len;
        let s = String::from_utf8_lossy(chunk);
        match s.split_once('=') {
            Some((k, v)) => pairs.push((k.to_string(), v.to_string())),
            None if !s.is_empty() => pairs.push((s.into_owned(), String::new())),
            None => {}
        }
    }
    pairs
}

fn parse_rdata(data: &[u8], name: String, rtype: u16, rdstart: usize, rdlen: usize) -> Option<Rr> {
    let rdata = data.get(rdstart..rdstart + rdlen)?;
    match rtype {
        TYPE_PTR if rdlen >= 1 => {
            let (target, _) = read_name(data, rdstart).ok()?;
            Some(Rr::Ptr { name, target })
        }
        // 6 bytes of priority/weight/port plus at least a root label.
        TYPE_SRV if rdlen >= 7 => {
            let port = u16_at(data, rdstart + 4).ok()?;
            let (target, _) = read_name(data, rdstart + 6).ok()?;
            Some(Rr::Srv { name, port, target })
        }
        TYPE_TXT => Some(Rr::Txt {
            name,
            pairs: parse_txt(rdata),
        }),
        TYPE_A if rdlen == 4 => Some(Rr::A {
            name,
            addr: Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]),
        }),
        TYPE_AAAA if rdlen == 16 => {
            let mut o = [0u8; 16];
            o.copy_from_slice(rdata);
            Some(Rr::Aaaa {
                name,
                addr: Ipv6Addr::from(o),
            })
        }
        _ => None,
    }
}

/// Decode all answer/authority/additional records in a response, skipping
/// records whose type we do not handle.
pub fn parse_message(data: &[u8]) -> Result<Vec<Rr>> {
    if data.len() < 12 {
        return Err(Error::Discovery("short header".into()));
    }
    let qd = u16_at(data, 4)?;
    // Widen before summing: three u16 counts can overflow a u16 on a malformed
    // packet and panic in debug builds.
    let total = usize::from(u16_at(data, 6)?)
        + usize::from(u16_at(data, 8)?)
        + usize::from(u16_at(data, 10)?);
    let mut pos = 12;
    for _ in 0..qd {
        let (_, next) = read_name(data, pos)?;
        pos = next + 4; // qtype + qclass
    }
    let mut out = Vec::new();
    for _ in 0..total {
        let (name, next) = read_name(data, pos)?;
        let rtype = u16_at(data, next)?;
        let rdlen = usize::from(u16_at(data, next + 8)?);
        let rdstart = next + 10;
        if rdstart + rdlen > data.len() {
            return Err(Error::Discovery("rdata past end".into()));
        }
        if let Some(rr) = parse_rdata(data, name, rtype, rdstart, rdlen) {
            out.push(rr);
        }
        pos = rdstart + rdlen;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn push_name(buf: &mut Vec<u8>, name: &str) {
        for label in name.split('.').filter(|l| !l.is_empty()) {
            buf.push(label.len() as u8);
            buf.extend_from_slice(label.as_bytes());
        }
        buf.push(0);
    }

    fn header(buf: &mut Vec<u8>, an: u16) {
        buf.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // id + flags + qdcount=0
        buf.extend_from_slice(&an.to_be_bytes()); // ancount
        buf.extend_from_slice(&[0, 0, 0, 0]); // ns + ar
    }

    fn record(buf: &mut Vec<u8>, name: &str, rtype: u16, rdata: &[u8]) {
        push_name(buf, name);
        buf.extend_from_slice(&rtype.to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes()); // class IN
        buf.extend_from_slice(&120u32.to_be_bytes()); // ttl
        buf.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        buf.extend_from_slice(rdata);
    }

    #[test]
    fn parses_ptr_srv_txt_a() {
        let mut buf = Vec::new();
        header(&mut buf, 4);
        let mut ptr = Vec::new();
        push_name(&mut ptr, "Bedroom._airplay._tcp.local");
        record(&mut buf, "_airplay._tcp.local", TYPE_PTR, &ptr);

        let mut srv = Vec::new();
        srv.extend_from_slice(&[0, 0, 0, 0]); // priority + weight
        srv.extend_from_slice(&7000u16.to_be_bytes());
        push_name(&mut srv, "Bedroom.local");
        record(&mut buf, "Bedroom._airplay._tcp.local", TYPE_SRV, &srv);

        let txt = b"\x0amodel=J305\x13features=0x445D0A00";
        record(&mut buf, "Bedroom._airplay._tcp.local", TYPE_TXT, txt);
        record(&mut buf, "Bedroom.local", TYPE_A, &[192, 168, 50, 129]);

        let rrs = parse_message(&buf).expect("parse");
        assert!(rrs.contains(&Rr::Srv {
            name: "Bedroom._airplay._tcp.local".into(),
            port: 7000,
            target: "Bedroom.local".into(),
        }));
        assert!(rrs.contains(&Rr::A {
            name: "Bedroom.local".into(),
            addr: Ipv4Addr::new(192, 168, 50, 129),
        }));
        let has_model = rrs.iter().any(|rr| {
            matches!(rr, Rr::Txt { pairs, .. }
                if pairs.contains(&("model".into(), "J305".into())))
        });
        assert!(has_model);
    }

    #[test]
    fn resolves_name_compression() {
        // Lay down a real name, then a second name that is only a pointer to it.
        let mut buf = Vec::new();
        let base = buf.len();
        push_name(&mut buf, "Bedroom.local");
        let ptr_at = buf.len();
        buf.push(0xC0);
        buf.push(base as u8);

        let (direct, _) = read_name(&buf, base).expect("direct name");
        assert_eq!(direct, "Bedroom.local");

        let (via_ptr, next) = read_name(&buf, ptr_at).expect("pointer name");
        assert_eq!(via_ptr, "Bedroom.local");
        assert_eq!(next, ptr_at + 2, "offset advances past the 2-byte pointer");
    }

    #[test]
    fn rejects_reserved_label_prefix() {
        // 0x40 is a reserved label prefix (neither a length nor a pointer).
        let buf = [0x40u8, 0x01, b'x', 0x00];
        assert!(read_name(&buf, 0).is_err());
    }
}
