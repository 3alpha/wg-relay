use std::fmt;
use std::net::{Ipv4Addr, SocketAddr};

use super::PublicEndpoint;
use crate::key::PublicKey;

/// `PersistentKeepalive` for the relay: keeps NAT mappings open and refreshes
/// the registration well within its 180 s timeout.
pub const RELAY_PEER_KEEPALIVE_SECS: u16 = 25;
/// Width of the longest key, `PersistentKeepalive`, so the values line up.
const KEY_WIDTH: usize = 19;

/// The `[Peer]` section a configured peer adds to its WireGuard config to
/// register with the relay. Holds no secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayPeer {
    public_key: PublicKey,
    endpoint: RelayEndpoint,
    tunnel_ip: Ipv4Addr,
}

/// What goes after `Endpoint =`.
#[derive(Debug, Clone, PartialEq, Eq)]
enum RelayEndpoint {
    /// `public_endpoint` from the config, verbatim.
    Public(PublicEndpoint),
    /// The listen address, when it names one address.
    Listen(SocketAddr),
    /// The listen address is a wildcard, so only the port is known.
    Placeholder { port: u16 },
}

impl RelayPeer {
    /// Build the section for a relay with this key, reached at `public_endpoint`
    /// if set, else at `listen` if that is a specific address.
    pub fn new(
        public_key: PublicKey,
        public_endpoint: Option<&PublicEndpoint>,
        listen: SocketAddr,
        tunnel_ip: Ipv4Addr,
    ) -> Self {
        let endpoint = match public_endpoint {
            Some(e) => RelayEndpoint::Public(e.clone()),
            None if listen.ip().is_unspecified() => {
                RelayEndpoint::Placeholder { port: listen.port() }
            }
            None => RelayEndpoint::Listen(listen),
        };
        RelayPeer { public_key, endpoint, tunnel_ip }
    }

    /// Does `Endpoint` hold a placeholder the operator must fill in?
    pub fn has_placeholder(&self) -> bool {
        match self.endpoint {
            RelayEndpoint::Placeholder { .. } => true,
            RelayEndpoint::Public(_) | RelayEndpoint::Listen(_) => false,
        }
    }
}

impl fmt::Display for RelayEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RelayEndpoint::Public(e) => write!(f, "{e}"),
            RelayEndpoint::Listen(addr) => write!(f, "{addr}"),
            RelayEndpoint::Placeholder { port } => write!(f, "<relay public address>:{port}"),
        }
    }
}

impl fmt::Display for RelayPeer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let w = KEY_WIDTH;
        writeln!(f, "[Peer]")?;
        writeln!(f, "# wg-relay: registration tunnel only")?;
        writeln!(f, "{:<w$} = {}", "PublicKey", self.public_key)?;
        writeln!(f, "{:<w$} = {}", "Endpoint", self.endpoint)?;
        writeln!(f, "{:<w$} = {}/32", "AllowedIPs", self.tunnel_ip)?;
        writeln!(f, "{:<w$} = {}", "PersistentKeepalive", RELAY_PEER_KEEPALIVE_SECS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [7; 32];
    const TUNNEL_IP: Ipv4Addr = Ipv4Addr::new(10, 99, 0, 254);

    fn block(public: Option<&str>, listen: &str) -> String {
        let public = public.map(|p| p.parse::<PublicEndpoint>().unwrap());
        let peer = RelayPeer::new(KEY.into(), public.as_ref(), listen.parse().unwrap(), TUNNEL_IP);
        peer.to_string()
    }

    #[test]
    fn prints_public_endpoint_verbatim() {
        assert_eq!(
            block(Some("relay.example.com:51820"), "0.0.0.0:51820"),
            "[Peer]\n\
             # wg-relay: registration tunnel only\n\
             PublicKey           = BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=\n\
             Endpoint            = relay.example.com:51820\n\
             AllowedIPs          = 10.99.0.254/32\n\
             PersistentKeepalive = 25\n"
        );
    }

    #[test]
    fn falls_back_to_a_specific_listen_address_then_a_placeholder() {
        let endpoint = |public, listen| {
            let text = block(public, listen);
            text.lines().find_map(|l| l.strip_prefix("Endpoint            = ")).unwrap().to_owned()
        };
        assert_eq!(endpoint(None, "203.0.113.7:51820"), "203.0.113.7:51820");
        assert_eq!(endpoint(None, "[2001:db8::1]:51820"), "[2001:db8::1]:51820");
        assert_eq!(endpoint(None, "0.0.0.0:51820"), "<relay public address>:51820");
        assert_eq!(endpoint(None, "[::]:4000"), "<relay public address>:4000");
        assert_eq!(endpoint(Some("[2001:db8::1]:1"), "203.0.113.7:51820"), "[2001:db8::1]:1");
    }

    #[test]
    fn flags_the_placeholder() {
        let peer =
            |listen: &str| RelayPeer::new(KEY.into(), None, listen.parse().unwrap(), TUNNEL_IP);
        assert!(peer("0.0.0.0:51820").has_placeholder());
        assert!(!peer("203.0.113.7:51820").has_placeholder());
    }
}
