//! Batched UDP I/O for the socket loop, on top of `quinn-udp`: `recvmmsg`
//! with GRO on receive, GSO on send, and the ECN bits of each datagram.

use std::io::{self, IoSliceMut};
use std::net::SocketAddr;

use quinn_udp::{RecvMeta, Transmit, UdpSocketState};
use tokio::io::Interest;
use tokio::net::UdpSocket;
use wg_relay::error::AppError;

pub mod runs;

/// Receive buffers per `recvmmsg` call.
pub const RECV_BUFS: usize = quinn_udp::BATCH_SIZE;
/// One receive buffer: the largest UDP datagram fits, and so does the largest
/// GRO list, since the kernel only coalesces UDP up to 64 KiB.
pub const RECV_BUF_BYTES: usize = 65_536;
/// Largest UDP payload of one IPv4 packet (65,535 minus the IP and UDP
/// headers); a GSO send carries no more than that in total.
pub const MAX_GSO_BYTES: usize = 65_507;
/// Most datagrams the kernel accepts in one GSO send (`UDP_MAX_SEGMENTS`).
const MAX_GSO_SEGMENTS: usize = 64;

/// The relay's socket, with the offloads the kernel supports turned on.
pub struct Socket {
    io: UdpSocket,
    state: UdpSocketState,
}

impl Socket {
    pub async fn bind(addr: SocketAddr) -> Result<Self, AppError> {
        let io = UdpSocket::bind(addr).await.map_err(|source| AppError::Bind { addr, source })?;
        let offload = |source| AppError::Offload { addr, source };
        #[cfg(target_os = "linux")]
        let kept = kernel_settings::Saved::read(&io);
        let state = UdpSocketState::new((&io).into()).map_err(offload)?;
        #[cfg(target_os = "linux")]
        kept.restore(&io).map_err(offload)?;
        Ok(Socket { io, state })
    }

    /// Datagrams one receive buffer can hold: more than 1 when GRO is on.
    pub fn gro_segments(&self) -> usize {
        self.state.gro_segments()
    }

    /// Datagrams one send may carry: 1 without GSO, or once a GSO send failed.
    pub fn gso_segments(&self) -> usize {
        self.state.max_gso_segments().min(MAX_GSO_SEGMENTS)
    }

    pub async fn readable(&self) -> io::Result<()> {
        self.io.readable().await
    }

    /// Receive what is queued, up to one buffer per entry of `batch`, without waiting.
    pub fn try_recv(&self, batch: &mut RecvBatch) -> io::Result<usize> {
        batch.len = 0;
        let mut bufs = batch.bufs.chunks_mut(RECV_BUF_BYTES);
        let mut iovs: [IoSliceMut<'_>; RECV_BUFS] =
            std::array::from_fn(|_| IoSliceMut::new(bufs.next().unwrap_or_default()));
        let n = self.io.try_io(Interest::READABLE, || {
            self.state.recv((&self.io).into(), &mut iovs, &mut batch.meta)
        })?;
        batch.len = n.min(RECV_BUFS);
        Ok(batch.len)
    }

    /// Send one datagram, or several of equal size as one GSO send, waiting
    /// while the socket's send buffer is full.
    pub async fn send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        loop {
            let sent = self
                .io
                .try_io(Interest::WRITABLE, || self.state.try_send((&self.io).into(), transmit));
            match sent {
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => self.io.writable().await?,
                done => return done,
            }
        }
    }
}

/// Receive buffers and their metadata, allocated once and reused.
pub struct RecvBatch {
    bufs: Box<[u8]>,
    meta: [RecvMeta; RECV_BUFS],
    len: usize,
}

impl Default for RecvBatch {
    fn default() -> Self {
        RecvBatch {
            bufs: vec![0; RECV_BUFS * RECV_BUF_BYTES].into_boxed_slice(),
            meta: [RecvMeta::default(); RECV_BUFS],
            len: 0,
        }
    }
}

impl RecvBatch {
    /// The buffers the last receive filled, each with its metadata.
    pub fn received(&self) -> impl Iterator<Item = (&RecvMeta, &[u8])> {
        (0..self.len).filter_map(|i| Some((self.meta.get(i)?, self.data(i))))
    }

    /// The bytes the last receive put in buffer `i`.
    pub fn data(&self, i: usize) -> &[u8] {
        let len = self.meta.get(i).map_or(0, |m| m.len.min(RECV_BUF_BYTES));
        let start = i * RECV_BUF_BYTES;
        self.bufs.get(start..start + len).unwrap_or_default()
    }
}

/// Settings `UdpSocketState::new` changes that the relay keeps as the kernel
/// set them (Linux only; elsewhere `quinn-udp`'s choices stay):
///
/// * It forbids IP fragmentation, which QUIC wants but a relay must not: it
///   forwards datagrams of any size it receives, and by default the kernel
///   fragments those that exceed a path's MTU.
/// * It turns on receive timestamps, which the relay does not use. Their
///   control message takes so much of `quinn-udp`'s 96-byte control buffer
///   that, next to a GRO segment size and the packet info, the ECN bits no
///   longer fit and are lost.
#[cfg(target_os = "linux")]
mod kernel_settings {
    use std::io;

    use nix::sys::socket::sockopt::{Ipv6DontFrag, ReceiveTimestampns};
    use nix::sys::socket::{getsockopt, setsockopt};
    use rustix::net::sockopt::{self, Ipv4PathMtuDiscovery, Ipv6PathMtuDiscovery};
    use tokio::net::UdpSocket;

    /// The settings before `quinn-udp` changed them; `None` where the
    /// socket's address family has no such option.
    pub struct Saved {
        v4_pmtu: Option<Ipv4PathMtuDiscovery>,
        v6_pmtu: Option<Ipv6PathMtuDiscovery>,
        v6_dontfrag: Option<bool>,
        timestamps: Option<bool>,
    }

    impl Saved {
        pub fn read(sock: &UdpSocket) -> Self {
            Saved {
                v4_pmtu: sockopt::ip_mtu_discover(sock).ok(),
                v6_pmtu: sockopt::ipv6_mtu_discover(sock).ok(),
                v6_dontfrag: getsockopt(sock, Ipv6DontFrag).ok(),
                timestamps: getsockopt(sock, ReceiveTimestampns).ok(),
            }
        }

        pub fn restore(&self, sock: &UdpSocket) -> io::Result<()> {
            if let Some(v) = self.v4_pmtu {
                sockopt::set_ip_mtu_discover(sock, v)?;
            }
            if let Some(v) = self.v6_pmtu {
                sockopt::set_ipv6_mtu_discover(sock, v)?;
            }
            if let Some(v) = self.v6_dontfrag {
                setsockopt(sock, Ipv6DontFrag, &v)?;
            }
            if let Some(v) = self.timestamps {
                setsockopt(sock, ReceiveTimestampns, &v)?;
            }
            Ok(())
        }
    }
}
