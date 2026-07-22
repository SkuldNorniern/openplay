//! Ordered, case-insensitive RTSP header collection.

/// Headers preserve insertion order (some receivers are picky about it) while
/// lookups are case-insensitive per the RTSP/HTTP grammar.
#[derive(Default, Debug, Clone)]
pub struct Headers(Vec<(String, String)>);

impl Headers {
    pub fn new() -> Self {
        Headers(Vec::new())
    }

    /// Append a header, keeping order.
    pub fn push(&mut self, name: &str, value: impl Into<String>) {
        self.0.push((name.to_string(), value.into()));
    }

    /// First value for `name`, compared case-insensitively.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.0.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }
}
