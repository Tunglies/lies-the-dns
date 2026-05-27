use std::net::SocketAddr;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    //! Cannot bind to port 5353 on macOS yet
    // let addr: SocketAddr = "0.0.0.0:5353".parse()?;
    let addr: SocketAddr = "0.0.0.0:1024".parse()?;
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;

    socket.set_reuse_address(true)?;
    socket.set_reuse_port(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;

    let std_socket: std::net::UdpSocket = socket.into();

    let tokio_socket = UdpSocket::from_std(std_socket)?;
    println!("UDP server listening on {}", addr);

    let mut buf = [0u8; 1024];
    loop {
        println!("Waiting for incoming UDP packets...");
        let (len, src) = tokio_socket.recv_from(&mut buf).await?;
        println!("Received {} bytes from {}", len, src);
        tokio_socket.send_to(&buf[..len], src).await?;
        println!("Sent {} bytes back to {}", len, src);
        // Here you can process the received data in `buf[..len]`
    }
}
