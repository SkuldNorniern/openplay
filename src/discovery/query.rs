//! Build mDNS query packets.

/// DNS `PTR` record type.
const TYPE_PTR: u16 = 12;
/// `IN` class with the mDNS "unicast response requested" (QU) bit set, so
/// responders answer directly to our ephemeral source port instead of the
/// multicast group. This lets us receive without binding port 5353.
const QCLASS_IN_QU: u16 = 0x8001;

/// Encode a dotted DNS name (e.g. `_airplay._tcp.local`) into length-prefixed
/// labels terminated by a zero byte.
pub(crate) fn encode_name(name: &str, out: &mut Vec<u8>) {
    for label in name.split('.') {
        if label.is_empty() {
            continue;
        }
        let bytes = label.as_bytes();
        // DNS labels max out at 63 bytes. Service names are static constants far
        // below that, so an overlong label is a caller bug — skip it rather than
        // emit a length byte that disagrees with the payload.
        if bytes.len() > 63 {
            continue;
        }
        out.push(bytes.len() as u8);
        out.extend_from_slice(bytes);
    }
    out.push(0);
}

/// Build a single mDNS query carrying one PTR question per service name.
pub fn build_query(services: &[&str]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(32 + services.len() * 24);
    // Header: id=0, flags=0, qdcount=services, an/ns/ar=0.
    buf.extend_from_slice(&0u16.to_be_bytes()); // id
    buf.extend_from_slice(&0u16.to_be_bytes()); // flags
    buf.extend_from_slice(&(services.len() as u16).to_be_bytes()); // qdcount
    buf.extend_from_slice(&0u16.to_be_bytes()); // ancount
    buf.extend_from_slice(&0u16.to_be_bytes()); // nscount
    buf.extend_from_slice(&0u16.to_be_bytes()); // arcount
    for name in services {
        encode_name(name, &mut buf);
        buf.extend_from_slice(&TYPE_PTR.to_be_bytes());
        buf.extend_from_slice(&QCLASS_IN_QU.to_be_bytes());
    }
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_has_one_question_with_qu_bit() {
        let q = build_query(&["_raop._tcp.local"]);
        assert_eq!(u16::from_be_bytes([q[4], q[5]]), 1, "qdcount");
        // Encoded name: 5 raop, 4 _tcp, 5 local, terminator.
        assert_eq!(&q[12..18], b"\x05_raop");
        let tail = &q[q.len() - 4..];
        assert_eq!(u16::from_be_bytes([tail[0], tail[1]]), TYPE_PTR);
        assert_eq!(u16::from_be_bytes([tail[2], tail[3]]), QCLASS_IN_QU);
    }
}
