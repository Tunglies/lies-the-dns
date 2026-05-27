use std::net::SocketAddr;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    //! Cannot bind to port 5353 on macOS yet
    // let addr: SocketAddr = "0.0.0.0:5353".parse()?;
    let server_addr: SocketAddr = "0.0.0.0:1024".parse()?;
    let client_addr: SocketAddr = "0.0.0.0:0".parse()?;
    let upstream_dns: SocketAddr = "8.8.8.8:53".parse()?;

    let server_socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    let upstream_socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;

    server_socket.set_reuse_address(true)?;
    server_socket.set_reuse_port(true)?;
    server_socket.set_nonblocking(true)?;
    server_socket.bind(&server_addr.into())?;
    upstream_socket.set_nonblocking(true)?;
    upstream_socket.bind(&client_addr.into())?;

    let server_std_socket: std::net::UdpSocket = server_socket.into();
    let upstream_std_socket: std::net::UdpSocket = upstream_socket.into();
    let server = UdpSocket::from_std(server_std_socket)?;
    let upstream = UdpSocket::from_std(upstream_std_socket)?;

    println!("UDP server listening on {}", server_addr);

    let mut buf = [0u8; 1024];
    loop {
        println!("Waiting for incoming UDP packets...");
        let (len, src) = server.recv_from(&mut buf).await?;
        println!("Received {} bytes from {}", len, src);

        upstream.send_to(&buf[..len], upstream_dns).await?;
        println!(
            "Forwarded packet to upstream DNS server at {}",
            upstream_dns
        );

        let (len, _) = upstream.recv_from(&mut buf).await?;
        println!("Received response from upstream DNS server");

        server.send_to(&buf[..len], src).await?;
        println!("Sent response back to client at {}", src);
    }
}
