//! A minimal HTTP/1.x server for `GET /metrics`: one request per connection,
//! answered with the text the main thread renders when the request arrives.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, mpsc, oneshot};
use tracing::{debug, warn};
use wg_relay::error::AppError;

/// Most connections served at once; more wait in the kernel's accept queue.
const MAX_CONNECTIONS: usize = 16;
/// Longest request head read; a scraper's is a few hundred bytes.
const MAX_REQUEST_BYTES: usize = 8192;
/// How long one connection may take, reading and writing together.
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);
/// Pause after a failed accept, such as running out of file descriptors, so it does not spin.
const ACCEPT_RETRY_DELAY: Duration = Duration::from_millis(100);
/// Content type of the Prometheus text format.
const CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

/// A scrape request: the main thread answers with the rendered text.
pub(in crate::app) type ScrapeRequest = oneshot::Sender<String>;

/// The metrics endpoint's socket, bound but not yet tied to a runtime.
pub(in crate::app) struct Listener {
    /// The address it is bound to, with its port picked if the config had none.
    pub(in crate::app) addr: SocketAddr,
    socket: std::net::TcpListener,
}

impl Listener {
    /// Bind before any thread starts, so a port in use fails startup.
    pub(in crate::app) fn bind(addr: SocketAddr) -> Result<Self, AppError> {
        let bind = |source| AppError::MetricsBind { addr, source };
        let socket = std::net::TcpListener::bind(addr).map_err(bind)?;
        socket.set_nonblocking(true).map_err(bind)?;
        Ok(Listener { addr: socket.local_addr().map_err(bind)?, socket })
    }

    /// Serve on the runtime this is called in, asking `scrapes` for each response's text.
    pub(in crate::app) fn spawn(
        self,
        scrapes: mpsc::Sender<ScrapeRequest>,
    ) -> Result<(), AppError> {
        let addr = self.addr;
        let listener = TcpListener::from_std(self.socket)
            .map_err(|source| AppError::MetricsBind { addr, source })?;
        tokio::spawn(run(listener, scrapes));
        Ok(())
    }
}

/// Accept connections until the runtime stops, serving each on a task of its own.
async fn run(listener: TcpListener, scrapes: mpsc::Sender<ScrapeRequest>) {
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    loop {
        // The semaphore is never closed.
        let Ok(permit) = Arc::clone(&permits).acquire_owned().await else { return };
        match listener.accept().await {
            Ok((stream, peer)) => {
                let scrapes = scrapes.clone();
                tokio::spawn(async move {
                    match tokio::time::timeout(CONNECTION_TIMEOUT, serve(stream, &scrapes)).await {
                        Ok(Ok(())) => {}
                        Ok(Err(e)) => debug!(%peer, error = %e, "metrics connection failed"),
                        Err(_) => debug!(%peer, "metrics connection timed out"),
                    }
                    drop(permit);
                });
            }
            Err(e) => {
                warn!(error = %e, "accepting a metrics connection failed");
                tokio::time::sleep(ACCEPT_RETRY_DELAY).await;
            }
        }
    }
}

/// What a request asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Route {
    /// `GET` or `HEAD` `/metrics`; `HEAD` gets the headers only.
    Metrics {
        head_only: bool,
    },
    NotFound,
    MethodNotAllowed,
    BadRequest,
}

/// Read one request, answer it and close the connection.
async fn serve(mut stream: TcpStream, scrapes: &mpsc::Sender<ScrapeRequest>) -> io::Result<()> {
    let Some(head) = read_head(&mut stream).await? else { return Ok(()) };
    let response = match route(&head) {
        Route::Metrics { head_only } => match scrape(scrapes).await {
            Some(body) => response(Status::Ok, CONTENT_TYPE, &body, head_only),
            None => response(Status::Unavailable, "text/plain", "shutting down\n", head_only),
        },
        Route::NotFound => response(Status::NotFound, "text/plain", "try /metrics\n", false),
        Route::MethodNotAllowed => response(Status::MethodNotAllowed, "text/plain", "", false),
        Route::BadRequest => response(Status::BadRequest, "text/plain", "bad request\n", false),
    };
    stream.write_all(response.as_bytes()).await?;
    stream.shutdown().await
}

/// Ask the main thread for the current exposition; `None` once it has stopped.
async fn scrape(scrapes: &mpsc::Sender<ScrapeRequest>) -> Option<String> {
    let (reply, rendered) = oneshot::channel();
    scrapes.send(reply).await.ok()?;
    rendered.await.ok()
}

/// Read up to the blank line that ends the request head, so no unread request
/// bytes make closing the socket reset it; `None` if the client sent nothing.
async fn read_head(stream: &mut TcpStream) -> io::Result<Option<Vec<u8>>> {
    let mut head = Vec::new();
    let mut buf = [0u8; 1024];
    while !ends_head(&head) && head.len() < MAX_REQUEST_BYTES {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        head.extend_from_slice(buf.get(..n).unwrap_or_default());
    }
    Ok(Some(head).filter(|h| !h.is_empty()))
}

/// Does `head` hold a whole request head?
fn ends_head(head: &[u8]) -> bool {
    head.windows(4).any(|w| w == b"\r\n\r\n") || head.windows(2).any(|w| w == b"\n\n")
}

/// Route a request by its request line.
fn route(head: &[u8]) -> Route {
    let line = head.split(|b| *b == b'\n').next().unwrap_or_default();
    let Ok(line) = std::str::from_utf8(line) else { return Route::BadRequest };
    let mut parts = line.split_whitespace();
    let (Some(method), Some(target), Some(version)) = (parts.next(), parts.next(), parts.next())
    else {
        return Route::BadRequest;
    };
    if !version.starts_with("HTTP/1.") {
        return Route::BadRequest;
    }
    let path = target.split_once('?').map_or(target, |(path, _)| path);
    match (method, path) {
        ("GET", "/metrics") => Route::Metrics { head_only: false },
        ("HEAD", "/metrics") => Route::Metrics { head_only: true },
        ("GET" | "HEAD", _) => Route::NotFound,
        _ => Route::MethodNotAllowed,
    }
}

/// The responses the server gives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Status {
    Ok,
    BadRequest,
    NotFound,
    MethodNotAllowed,
    Unavailable,
}

impl Status {
    /// The status line's code and reason, and any header this status requires.
    fn parts(self) -> (&'static str, &'static str) {
        match self {
            Status::Ok => ("200 OK", ""),
            Status::BadRequest => ("400 Bad Request", ""),
            Status::NotFound => ("404 Not Found", ""),
            Status::MethodNotAllowed => ("405 Method Not Allowed", "Allow: GET, HEAD\r\n"),
            Status::Unavailable => ("503 Service Unavailable", ""),
        }
    }
}

/// A whole response; the connection closes after it. A `HEAD` response gets
/// the headers a `GET` would, without the body.
fn response(status: Status, content_type: &str, body: &str, head_only: bool) -> String {
    let (line, extra) = status.parts();
    let len = body.len();
    let body = if head_only { "" } else { body };
    format!(
        "HTTP/1.1 {line}\r\nContent-Type: {content_type}\r\nContent-Length: {len}\r\n{extra}\
         Connection: close\r\n\r\n{body}"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routes_by_method_and_path() {
        let cases = [
            ("GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n", Route::Metrics { head_only: false }),
            ("GET /metrics?x=1 HTTP/1.0\r\n\r\n", Route::Metrics { head_only: false }),
            ("HEAD /metrics HTTP/1.1\r\n\r\n", Route::Metrics { head_only: true }),
            ("GET / HTTP/1.1\r\n\r\n", Route::NotFound),
            ("POST /metrics HTTP/1.1\r\n\r\n", Route::MethodNotAllowed),
            ("GET /metrics\r\n\r\n", Route::BadRequest),
            ("GET /metrics SPDY/3\r\n\r\n", Route::BadRequest),
            ("\u{0}\u{ff}", Route::BadRequest),
        ];
        for (request, expected) in cases {
            assert_eq!(route(request.as_bytes()), expected, "{request:?}");
        }
    }

    #[test]
    fn writes_a_closing_response_with_its_length() {
        assert_eq!(
            response(Status::Ok, "text/plain", "hi\n", false),
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 3\r\n\
             Connection: close\r\n\r\nhi\n"
        );
        assert_eq!(
            response(Status::Ok, "text/plain", "hi\n", true),
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 3\r\n\
             Connection: close\r\n\r\n",
            "HEAD: the length a GET would get, no body"
        );
        assert_eq!(
            response(Status::MethodNotAllowed, "text/plain", "", false),
            "HTTP/1.1 405 Method Not Allowed\r\nContent-Type: text/plain\r\nContent-Length: 0\r\n\
             Allow: GET, HEAD\r\nConnection: close\r\n\r\n"
        );
    }
}
