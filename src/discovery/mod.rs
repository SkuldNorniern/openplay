//! mDNS service discovery for AirPlay receivers.
//!
//! Sends multicast PTR queries with the unicast-response bit set and collects
//! answers on an ephemeral port, so it never needs to bind port 5353. Bind to a
//! specific LAN address to keep queries off other interfaces (e.g. a VPN).

mod parse;
mod query;

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tokio::time::timeout;

use crate::error::Result;
use parse::{Rr, parse_message};
pub use query::build_query;

/// AirPlay 2 control service.
pub const SERVICE_AIRPLAY: &str = "_airplay._tcp.local";
/// Legacy RAOP / AirTunes audio service.
pub const SERVICE_RAOP: &str = "_raop._tcp.local";

const MDNS_GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const MDNS_PORT: u16 = 5353;

/// A discovered AirPlay receiver.
#[derive(Debug, Clone)]
pub struct ServiceRecord {
    /// Service instance name (the label before the service type).
    pub instance: String,
    /// Target host name (`*.local`).
    pub host: String,
    /// Service port.
    pub port: u16,
    /// Resolved addresses for `host`.
    pub addrs: Vec<IpAddr>,
    /// TXT key/value metadata (`features`, `pk`, `model`, ...).
    pub txt: BTreeMap<String, String>,
}

/// Discover receivers for the given service names, collecting responses for
/// `wait`. Bind to `bind` (a LAN address) to pin the egress interface.
pub async fn browse(
    services: &[&str],
    bind: Option<Ipv4Addr>,
    wait: Duration,
) -> Result<Vec<ServiceRecord>> {
    let local = SocketAddr::from((bind.unwrap_or(Ipv4Addr::UNSPECIFIED), 0));
    let sock = UdpSocket::bind(local).await?;
    sock.send_to(&build_query(services), (MDNS_GROUP, MDNS_PORT))
        .await?;

    let mut agg = Aggregator::default();
    let deadline = Instant::now() + wait;
    let mut buf = vec![0u8; 9000];
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        match timeout(remaining, sock.recv_from(&mut buf)).await {
            Ok(recv) => {
                let (n, _) = recv?;
                if let Ok(records) = parse_message(&buf[..n]) {
                    agg.ingest(records);
                }
            }
            Err(_) => break,
        }
    }
    Ok(agg.finish(services))
}

/// Accumulates records across responses and joins them by instance/host.
#[derive(Default)]
struct Aggregator {
    ptr: Vec<(String, String)>,               // service type -> instance
    srv: BTreeMap<String, (u16, String)>,     // instance -> (port, host)
    txt: BTreeMap<String, Vec<(String, String)>>, // instance -> pairs
    addrs: BTreeMap<String, Vec<IpAddr>>,     // host -> addrs
}

impl Aggregator {
    fn ingest(&mut self, records: Vec<Rr>) {
        for rr in records {
            match rr {
                Rr::Ptr { name, target } => self.ptr.push((name, target)),
                Rr::Srv { name, port, target } => {
                    self.srv.insert(name, (port, target));
                }
                Rr::Txt { name, pairs } => {
                    self.txt.insert(name, pairs);
                }
                Rr::A { name, addr } => self.add_addr(name, addr.into()),
                Rr::Aaaa { name, addr } => self.add_addr(name, addr.into()),
            }
        }
    }

    fn add_addr(&mut self, host: String, addr: IpAddr) {
        let list = self.addrs.entry(host).or_default();
        // Repeated responses re-announce the same addresses; keep them unique.
        if !list.contains(&addr) {
            list.push(addr);
        }
    }

    fn finish(self, services: &[&str]) -> Vec<ServiceRecord> {
        let mut out = Vec::new();
        for (instance, (port, host)) in &self.srv {
            if !self.instance_matches(instance, services) {
                continue;
            }
            out.push(ServiceRecord {
                instance: instance_label(instance),
                host: host.clone(),
                port: *port,
                addrs: self.addrs.get(host).cloned().unwrap_or_default(),
                txt: self
                    .txt
                    .get(instance)
                    .map(|p| p.iter().cloned().collect())
                    .unwrap_or_default(),
            });
        }
        out
    }

    fn instance_matches(&self, instance: &str, services: &[&str]) -> bool {
        // Require the label boundary so `x_airplay._tcp.local` does not match
        // `_airplay._tcp.local`.
        services
            .iter()
            .any(|s| instance.ends_with(&format!(".{s}")))
            || self.ptr.iter().any(|(_, t)| t == instance)
    }
}

/// Strip the trailing `._service._tcp.local` from an instance name.
fn instance_label(instance: &str) -> String {
    match instance.find("._") {
        Some(i) => instance[..i].to_string(),
        None => instance.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn joins_srv_txt_and_addr_by_instance() {
        let mut agg = Aggregator::default();
        agg.ingest(vec![
            Rr::Srv {
                name: "Bedroom._airplay._tcp.local".into(),
                port: 7000,
                target: "Bedroom.local".into(),
            },
            Rr::Txt {
                name: "Bedroom._airplay._tcp.local".into(),
                pairs: vec![("model".into(), "J305".into())],
            },
            Rr::A {
                name: "Bedroom.local".into(),
                addr: Ipv4Addr::new(192, 168, 50, 129),
            },
        ]);
        let recs = agg.finish(&[SERVICE_AIRPLAY]);
        assert_eq!(recs.len(), 1);
        let r = &recs[0];
        assert_eq!(r.instance, "Bedroom");
        assert_eq!(r.port, 7000);
        assert_eq!(r.addrs, vec![IpAddr::from(Ipv4Addr::new(192, 168, 50, 129))]);
        assert_eq!(r.txt.get("model").map(String::as_str), Some("J305"));
    }

    #[test]
    fn rejects_suffix_without_label_boundary() {
        let mut agg = Aggregator::default();
        agg.ingest(vec![Rr::Srv {
            name: "bogusx_airplay._tcp.local".into(),
            port: 7000,
            target: "bogus.local".into(),
        }]);
        assert!(agg.finish(&[SERVICE_AIRPLAY]).is_empty());
    }

    #[test]
    fn dedups_repeated_addresses() {
        let mut agg = Aggregator::default();
        let a = Rr::A {
            name: "Bedroom.local".into(),
            addr: Ipv4Addr::new(10, 0, 0, 5),
        };
        agg.ingest(vec![a.clone()]);
        agg.ingest(vec![a]);
        assert_eq!(agg.addrs.get("Bedroom.local").map(Vec::len), Some(1));
    }
}
