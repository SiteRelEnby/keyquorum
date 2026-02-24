pub mod status;
pub mod submit;

use anyhow::Result;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpStream, UnixStream};

/// A connection to the daemon, either Unix socket or TCP.
pub enum Connection {
    Unix(UnixStream),
    Tcp(TcpStream),
}

impl Connection {
    pub fn split(
        self,
    ) -> (
        Box<dyn AsyncRead + Unpin + Send>,
        Box<dyn AsyncWrite + Unpin + Send>,
    ) {
        match self {
            Connection::Unix(s) => {
                let (r, w) = tokio::io::split(s);
                (Box::new(r), Box::new(w))
            }
            Connection::Tcp(s) => {
                let (r, w) = tokio::io::split(s);
                (Box::new(r), Box::new(w))
            }
        }
    }
}

/// Connect to the daemon. If `addr` starts with "tcp://", use TCP.
/// Otherwise treat it as a Unix socket path.
pub async fn connect(addr: &str) -> Result<Connection> {
    if let Some(tcp_addr) = addr.strip_prefix("tcp://") {
        let stream = TcpStream::connect(tcp_addr)
            .await
            .map_err(|e| anyhow::anyhow!("failed to connect to {}: {}", addr, e))?;
        Ok(Connection::Tcp(stream))
    } else {
        let stream = UnixStream::connect(addr)
            .await
            .map_err(|e| anyhow::anyhow!("failed to connect to {}: {}", addr, e))?;
        Ok(Connection::Unix(stream))
    }
}
