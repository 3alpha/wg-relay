use std::fmt;

use super::{Config, Role};
use crate::key::PeerKey;

/// Human-readable overview printed by `--check-config`.
pub struct Summary<'a>(pub(super) &'a Config);

impl fmt::Display for Summary<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let cfg = self.0;
        writeln!(f, "listen       {}", cfg.listen)?;
        writeln!(f, "relay key    {}", cfg.private_key.public_key())?;
        writeln!(f, "tunnel ip    {}", cfg.tunnel_ip)?;
        writeln!(f, "client gate  {:?}", cfg.gate)?;
        writeln!(f, "init rate    {} per source IP", cfg.handshake_rate)?;
        let name = |k: &PeerKey| {
            cfg.peers.iter().find(|p| &p.pubkey == k).map_or("?", |p| p.name.as_str())
        };
        for p in &cfg.peers {
            let (role, reach): (_, Vec<&str>) = match &p.role {
                Role::Server => ("server", Vec::new()),
                Role::Client { servers } => ("client", servers.iter().map(name).collect()),
            };
            writeln!(f, "{role} {:<12} {}  {}", p.name, p.pubkey, reach.join(", "))?;
        }
        Ok(())
    }
}
