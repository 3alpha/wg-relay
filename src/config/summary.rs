use std::fmt;

use super::Config;

/// Human-readable overview printed by `--check-config`.
pub struct Summary<'a>(pub(super) &'a Config);

impl fmt::Display for Summary<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let config = self.0;
        writeln!(f, "listen       {}", config.listen)?;
        writeln!(f, "relay key    {}", config.private_key.public_key())?;
        writeln!(f, "tunnel ip    {}", config.tunnel_ip)?;
        let rate = config.handshake_rate;
        writeln!(f, "init rate    {rate} per source (IPv4 address or IPv6 /64)")?;
        writeln!(f, "workers      {}", config.workers)?;
        for p in &config.peers {
            writeln!(f, "peer {:<12} {}", p.name, p.pubkey)?;
        }
        Ok(())
    }
}
