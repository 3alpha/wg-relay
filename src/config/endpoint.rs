use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use serde::Deserialize;

use super::error::EndpointError;

/// Longest DNS name, without a trailing dot.
const MAX_HOSTNAME_LEN: usize = 253;
/// Longest label of a DNS name.
const MAX_LABEL_LEN: usize = 63;

/// Where peers reach the relay, `host:port`, as they write it after `Endpoint =`:
/// a hostname, an IPv4 address or a bracketed IPv6 address. Kept verbatim.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub struct PublicEndpoint(String);

impl FromStr for PublicEndpoint {
    type Err = EndpointError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (host, port) = s.rsplit_once(':').ok_or(EndpointError::MissingPort)?;
        match port.parse::<u16>() {
            Ok(p) if p != 0 => {}
            _ => return Err(EndpointError::Port(port.to_owned())),
        }
        if !is_valid_host(host) {
            return Err(EndpointError::Host(host.to_owned()));
        }
        Ok(PublicEndpoint(s.to_owned()))
    }
}

impl TryFrom<String> for PublicEndpoint {
    type Error = EndpointError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl fmt::Display for PublicEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Is `host` a bracketed IPv6 address, an IPv4 address or a DNS name?
fn is_valid_host(host: &str) -> bool {
    if let Some(inner) = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        return inner.parse::<Ipv6Addr>().is_ok();
    }
    host.parse::<Ipv4Addr>().is_ok() || is_hostname(host)
}

/// Is `host` a DNS name: dot-separated labels of letters, digits and inner hyphens?
fn is_hostname(host: &str) -> bool {
    let label_ok = |l: &str| {
        (1..=MAX_LABEL_LEN).contains(&l.len())
            && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && !l.starts_with('-')
            && !l.ends_with('-')
    };
    (1..=MAX_HOSTNAME_LEN).contains(&host.len()) && host.split('.').all(label_ok)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> Result<String, EndpointError> {
        s.parse::<PublicEndpoint>().map(|e| e.to_string())
    }

    #[test]
    fn accepts_hostnames_ipv4_and_bracketed_ipv6_verbatim() {
        for ok in
            ["relay.example.com:51820", "relay-1:1", "203.0.113.7:51820", "[2001:db8::1]:51820"]
        {
            assert_eq!(parse(ok), Ok(ok.to_owned()));
        }
    }

    #[test]
    fn rejects_bad_ports_and_hosts() {
        let host = |h: &str| Err(EndpointError::Host(h.into()));
        assert_eq!(parse("relay.example.com"), Err(EndpointError::MissingPort));
        assert_eq!(parse("relay:0"), Err(EndpointError::Port("0".into())));
        assert_eq!(parse("relay:65536"), Err(EndpointError::Port("65536".into())));
        assert_eq!(parse("relay:"), Err(EndpointError::Port("".into())));
        assert_eq!(parse(":51820"), host(""));
        assert_eq!(parse("2001:db8::1:51820"), host("2001:db8::1"));
        assert_eq!(parse("[relay]:51820"), host("[relay]"));
        assert_eq!(parse("-relay:51820"), host("-relay"));
        assert_eq!(parse("re lay:51820"), host("re lay"));
        assert_eq!(parse("relay..com:51820"), host("relay..com"));
        let long = format!("{}.com", "a".repeat(64));
        assert_eq!(parse(&format!("{long}:1")), host(&long));
    }
}
