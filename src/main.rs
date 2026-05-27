mod types;

use std::net::SocketAddr;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;

use crate::types::{parse_dns_answer, parse_dns_header, parse_dns_question};

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

    loop {
        let mut request_buf = [0u8; 1024];
        println!("Waiting for incoming UDP packets...");
        let (len, src) = server.recv_from(&mut request_buf).await?;
        println!("Received {} bytes from {}", len, src);
        let dns_parse = parse_dns_header(&request_buf[..len]).unwrap();
        println!("Parsed DNS header: {:?}", dns_parse);
        let dns_question_parse = parse_dns_question(&request_buf[..len], 12).unwrap();
        println!("Parsed DNS question: {}", dns_question_parse.0);

        upstream.send_to(&request_buf[..len], upstream_dns).await?;
        println!(
            "Forwarded packet to upstream DNS server at {}",
            upstream_dns
        );

        let mut response_buf = [0u8; 1024];
        let (len, _) = upstream.recv_from(&mut response_buf).await?;
        println!("Received response from upstream DNS server");
        let dns_response_parse = parse_dns_header(&response_buf[..len]).unwrap();
        println!("Parsed DNS response header: {:?}", dns_response_parse);

        let mut offset = 12;
        for _ in 0..dns_response_parse.qdcount {
            let (question_parse, next_offset) =
                parse_dns_question(&response_buf[..len], offset).unwrap();
            println!(
                "Parsed DNS question(total: {}) in response: {}",
                dns_response_parse.qdcount, question_parse
            );
            offset = next_offset;
        }
        for _ in 0..dns_response_parse.ancount {
            let (anser_parse, next_offset) =
                parse_dns_answer(&response_buf[..len], offset).unwrap();
            println!(
                "Parsed DNS answer(total: {}) in response: {}",
                dns_response_parse.ancount, anser_parse
            );
            offset = next_offset;
        }

        server.send_to(&response_buf[..len], src).await?;
        println!("Sent response back to client at {}", src);
    }
}
