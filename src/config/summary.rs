use std::fmt;

use super::Config;

/// Human-readable overview printed by `--check-config`.
pub struct Summary<'a>(pub(super) &'a Config);

impl fmt::Display for Summary<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let cfg = self.0;
        writeln!(f, "listen       {}", cfg.listen)?;
        writeln!(f, "relay key    {}", cfg.private_key.public_key())?;
        writeln!(f, "tunnel ip    {}", cfg.tunnel_ip)?;
        writeln!(f, "init rate    {} per source (IPv4 address or IPv6 /64)", cfg.handshake_rate)?;
        writeln!(f, "workers      {}", cfg.workers)?;
        for p in &cfg.peers {
            writeln!(f, "peer {:<12} {}", p.name, p.pubkey)?;
        }
        Ok(())
    }
}
