//! AirPlay receivers as seen from discovery: who they are and what they can do.
//!
//! This is the shape a pairing UI or a system audio driver lists to the user,
//! so it holds plain values only and no live connection.

use std::fmt;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use crate::discovery::{self, SERVICE_AIRPLAY, ServiceRecord};
use crate::error::Result;

/// The 64-bit AirPlay `features` mask a receiver advertises.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Features(u64);

/// Feature bits openplay acts on, with the names used in reports.
const NAMED_BITS: [(u32, &str); 7] = [
    (0, "video"),
    (7, "screen-mirroring"),
    (9, "audio"),
    (40, "buffered-audio"),
    (41, "ptp"),
    (46, "homekit-pairing"),
    (48, "transient-pairing"),
];

impl Features {
    pub fn from_bits(bits: u64) -> Self {
        Self(bits)
    }

    /// Parse the TXT form: `0xLOW` or `0xLOW,0xHIGH`, two 32-bit halves.
    pub fn parse_txt(text: &str) -> Option<Self> {
        let mut halves = text.split(',');
        let low = parse_hex_u32(halves.next()?)?;
        let high = match halves.next() {
            Some(high) => parse_hex_u32(high)?,
            None => 0,
        };
        if halves.next().is_some() {
            return None;
        }
        Some(Self(u64::from(high) << 32 | u64::from(low)))
    }

    pub fn bits(self) -> u64 {
        self.0
    }

    pub fn has(self, bit: u32) -> bool {
        bit < 64 && self.0 & (1 << bit) != 0
    }

    pub fn audio(self) -> bool {
        self.has(9)
    }

    pub fn screen_mirroring(self) -> bool {
        self.has(7)
    }

    pub fn buffered_audio(self) -> bool {
        self.has(40)
    }

    pub fn ptp(self) -> bool {
        self.has(41)
    }

    pub fn transient_pairing(self) -> bool {
        self.has(48)
    }

    /// Names of the known bits that are set, in bit order.
    pub fn names(self) -> Vec<&'static str> {
        NAMED_BITS
            .iter()
            .filter(|(bit, _)| self.has(*bit))
            .map(|(_, name)| *name)
            .collect()
    }
}

fn parse_hex_u32(text: &str) -> Option<u32> {
    let digits = text
        .trim()
        .strip_prefix("0x")
        .or_else(|| text.trim().strip_prefix("0X"))?;
    u32::from_str_radix(digits, 16).ok()
}

/// Broad receiver family, from the model identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceKind {
    HomePod,
    AppleTv,
    Mac,
    Other,
}

impl DeviceKind {
    pub fn from_model(model: &str) -> Self {
        if model.starts_with("AudioAccessory") {
            Self::HomePod
        } else if model.starts_with("AppleTV") {
            Self::AppleTv
        } else if model.starts_with("Mac") || model.starts_with("iMac") {
            Self::Mac
        } else {
            Self::Other
        }
    }
}

impl fmt::Display for DeviceKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::HomePod => "HomePod",
            Self::AppleTv => "Apple TV",
            Self::Mac => "Mac",
            Self::Other => "AirPlay receiver",
        })
    }
}

/// One receiver found on the network.
#[derive(Debug, Clone)]
pub struct Device {
    pub name: String,
    /// Control address: an IPv4 address when the receiver has one.
    pub addr: SocketAddr,
    pub model: Option<String>,
    pub kind: DeviceKind,
    /// AirPlay version (`srcvers`), e.g. `980.77.2`.
    pub airplay_version: Option<String>,
    /// OS version (`osvers`), when advertised.
    pub os_version: Option<String>,
    pub device_id: Option<String>,
    pub features: Features,
    /// A password is set on the receiver (`pw=true`).
    pub password_required: bool,
}

impl Device {
    /// Build from an `_airplay._tcp` record. Returns `None` without an address.
    pub fn from_record(record: &ServiceRecord) -> Option<Self> {
        let ip = record
            .addrs
            .iter()
            .find(|addr| addr.is_ipv4())
            .or(record.addrs.first())
            .copied()?;
        let text = |key: &str| record.txt.get(key).cloned();
        let model = text("model");

        Some(Self {
            name: record.instance.clone(),
            addr: SocketAddr::new(ip, record.port),
            kind: model
                .as_deref()
                .map_or(DeviceKind::Other, DeviceKind::from_model),
            model,
            airplay_version: text("srcvers"),
            os_version: text("osvers"),
            device_id: text("deviceid"),
            features: text("features")
                .as_deref()
                .and_then(Features::parse_txt)
                .unwrap_or_default(),
            password_required: text("pw").is_some_and(|pw| pw.eq_ignore_ascii_case("true")),
        })
    }

    /// Whether openplay can stream audio to it without user input.
    pub fn can_stream_without_pin(&self) -> bool {
        self.features.audio() && self.features.transient_pairing() && !self.password_required
    }
}

/// Browse the network for AirPlay receivers.
pub async fn scan(bind: Option<Ipv4Addr>, wait: Duration) -> Result<Vec<Device>> {
    let records = discovery::browse(&[SERVICE_AIRPLAY], bind, wait).await?;
    let mut devices: Vec<Device> = records.iter().filter_map(Device::from_record).collect();
    devices.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(devices)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::net::IpAddr;

    use super::*;

    /// Speaker HomePod mini's `features` from its `/info`.
    const HOMEPOD_FEATURES: u64 = 0x3c35_4bd0_4a7f_ca00;

    fn record(txt: &[(&str, &str)]) -> ServiceRecord {
        ServiceRecord {
            instance: "Speaker".into(),
            host: "Speaker.local".into(),
            port: 7000,
            addrs: vec![
                "fe80::1".parse().expect("ipv6"),
                IpAddr::from(Ipv4Addr::new(192, 0, 2, 20)),
            ],
            txt: txt
                .iter()
                .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
                .collect::<BTreeMap<_, _>>(),
        }
    }

    #[test]
    fn txt_features_join_low_and_high_halves() {
        let features = Features::parse_txt("0x4A7FCA00,0x3C354BD0").expect("parse");
        assert_eq!(features.bits(), HOMEPOD_FEATURES);
        assert_eq!(
            Features::parse_txt("0x200").expect("low only").bits(),
            0x200
        );
        assert!(Features::parse_txt("4A7FCA00").is_none());
        assert!(Features::parse_txt("0x1,0x2,0x3").is_none());
    }

    #[test]
    fn homepod_features_report_audio_and_pairing() {
        let features = Features::from_bits(HOMEPOD_FEATURES);

        assert_eq!(
            features.names(),
            [
                "audio",
                "buffered-audio",
                "ptp",
                "homekit-pairing",
                "transient-pairing"
            ]
        );
        assert!(!features.screen_mirroring());
        assert!(!features.has(64));
    }

    #[test]
    fn record_becomes_device_with_ipv4_address() {
        let device = Device::from_record(&record(&[
            ("model", "AudioAccessory5,1"),
            ("srcvers", "980.77.2"),
            ("features", "0x4A7FCA00,0x3C354BD0"),
            ("deviceid", "02:00:00:00:00:01"),
        ]))
        .expect("device");

        assert_eq!(device.addr, "192.0.2.20:7000".parse().expect("addr"));
        assert_eq!(device.kind, DeviceKind::HomePod);
        assert_eq!(device.airplay_version.as_deref(), Some("980.77.2"));
        assert!(device.can_stream_without_pin());
    }

    #[test]
    fn password_or_missing_transient_pairing_needs_user_input() {
        let with_password = Device::from_record(&record(&[
            ("features", "0x4A7FCA00,0x3C354BD0"),
            ("pw", "true"),
        ]))
        .expect("device");
        let without_transient =
            Device::from_record(&record(&[("features", "0x200")])).expect("device");

        assert!(!with_password.can_stream_without_pin());
        assert!(!without_transient.can_stream_without_pin());
        assert_eq!(without_transient.kind, DeviceKind::Other);
    }

    #[test]
    fn model_prefix_picks_kind() {
        assert_eq!(DeviceKind::from_model("AppleTV14,1"), DeviceKind::AppleTv);
        assert_eq!(DeviceKind::from_model("Mac14,2"), DeviceKind::Mac);
        assert_eq!(
            DeviceKind::from_model("AudioAccessory1,1"),
            DeviceKind::HomePod
        );
    }
}
