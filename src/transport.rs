
/* TODO: implement trasport layer for the committee ( HTTP, TCP or QUIC ) */
use bytes::Bytes;
use std::future::Future;

use tokio::net::TcpStream;
use tokio_util::codec::{Framed, LengthDelimitedCodec};


pub trait TransportModule: Sized {
    fn connect(addr: &str) -> impl Future<Output = Result<Self,Self::Error>> + Send;
    fn send(&mut self, msg: Bytes) -> impl Future<Output = Result<(), Self::Error>> + Send;
    fn recv(&mut self) -> impl Future<Output = Result<Option<Bytes>, Self::Error>> + Send;
}

pub struct TcpTransport {
    framed: Framed<TcpStream, LengthDelimitedCodec>,
}

pub struct HttpTransport {
    addrs: String,
}
