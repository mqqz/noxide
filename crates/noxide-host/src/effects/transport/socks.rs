use super::{
    Error,
    config::{Endpoint, TorProxy, public_ip},
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

async fn connection(proxy: TorProxy) -> Result<TcpStream, Error> {
    // Numeric operator-owned loopback socket only: this cannot invoke a resolver.
    let mut stream = TcpStream::connect(proxy.address())
        .await
        .map_err(|_| Error::ProxyIo)?;
    stream
        .write_all(&[5, 1, 0])
        .await
        .map_err(|_| Error::ProxyIo)?;
    let mut method = [0; 2];
    stream
        .read_exact(&mut method)
        .await
        .map_err(|_| Error::ProxyIo)?;
    if method != [5, 0] {
        return Err(Error::Socks);
    }
    Ok(stream)
}
async fn reply(stream: &mut TcpStream) -> Result<(IpAddr, u16), Error> {
    let mut header = [0; 4];
    stream
        .read_exact(&mut header)
        .await
        .map_err(|_| Error::ProxyIo)?;
    if header[0] != 5 || header[1] != 0 || header[2] != 0 {
        return Err(Error::Socks);
    }
    let address = match header[3] {
        1 => {
            let mut bytes = [0; 4];
            stream
                .read_exact(&mut bytes)
                .await
                .map_err(|_| Error::ProxyIo)?;
            IpAddr::V4(Ipv4Addr::from(bytes))
        }
        4 => {
            let mut bytes = [0; 16];
            stream
                .read_exact(&mut bytes)
                .await
                .map_err(|_| Error::ProxyIo)?;
            IpAddr::V6(Ipv6Addr::from(bytes))
        }
        _ => return Err(Error::Socks), // Never accept another hostname lookup.
    };
    let mut port = [0; 2];
    stream
        .read_exact(&mut port)
        .await
        .map_err(|_| Error::ProxyIo)?;
    Ok((address, u16::from_be_bytes(port)))
}

pub(super) async fn connect(proxy: TorProxy, endpoint: &Endpoint) -> Result<TcpStream, Error> {
    let address = {
        let mut resolving = connection(proxy).await?;
        let host = endpoint.host().as_bytes();
        let mut request = Vec::with_capacity(host.len() + 7);
        request.extend_from_slice(&[5, 0xf0, 0, 3, host.len() as u8]);
        request.extend_from_slice(host);
        request.extend_from_slice(&[0, 0]);
        resolving
            .write_all(&request)
            .await
            .map_err(|_| Error::ProxyIo)?;
        let (address, _port_metadata) = reply(&mut resolving).await?;
        // Tor specifies the resolved IP, not a destination-port grant in this
        // reply. Parse the complete port field, then use only endpoint.port().
        if !public_ip(address) {
            return Err(Error::Address);
        }
        address
    }; // Tor RESOLVE is its own stream; never send application data on it.
    let mut stream = connection(proxy).await?;
    let mut request = vec![5, 1, 0];
    match address {
        IpAddr::V4(ip) => {
            request.push(1);
            request.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            request.push(4);
            request.extend_from_slice(&ip.octets());
        }
    }
    request.extend_from_slice(&endpoint.port().to_be_bytes());
    stream
        .write_all(&request)
        .await
        .map_err(|_| Error::ProxyIo)?;
    reply(&mut stream).await?;
    // CONNECT response's bind address is proxy metadata, not a new destination.
    // All TLS/application traffic stays inside this exact numeric CONNECT stream.
    Ok(stream)
}
