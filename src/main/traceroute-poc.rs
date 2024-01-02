use socket2::{Domain, SockAddr, Socket};
use std::mem::MaybeUninit;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::net::SocketAddrV4;
use std::net::UdpSocket;
use std::os::fd::AsRawFd;
use std::time::Duration;

fn main() -> std::io::Result<()> {
  let ips: Vec<IpAddr> = dns_lookup::lookup_host("google.com")
    .unwrap()
    .into_iter()
    .filter(IpAddr::is_ipv4)
    .collect::<Vec<_>>();

  let ip = ips.first().unwrap();

  println!("Going to connect to {}", ip);

  let udp_socket_client_port: u16 = 33474;
  let udp_socket_dest_port: u16 = 33475;
  let udp_socket_addr_client: SocketAddr;
  let udp_socket_addr_dest: SocketAddr;

  let icmp_socket: Socket;
  let udp_socket: UdpSocket;
  let hop_limit: u32 = 5;

  // Preparing the IPV4 ICMP socket
  // ----------------------------------------
  icmp_socket = Socket::new(
    Domain::IPV4,
    socket2::Type::RAW,
    Some(socket2::Protocol::ICMPV4),
  )
  .unwrap();

  // Preparing the IPV4 UDP socket
  // ----------------------------------------
  udp_socket_addr_client = format!("0.0.0.0:{}", udp_socket_client_port)
    .parse()
    .unwrap();
  udp_socket_addr_dest = format!("{}:{}", ip.clone(), udp_socket_dest_port)
    .parse()
    .unwrap();

  udp_socket = UdpSocket::bind(udp_socket_addr_client).unwrap();
  udp_socket.set_ttl(hop_limit).unwrap();

  // Start ICMP listener first before sending the probes
  // ----------------------------------------
  icmp_socket
    .set_read_timeout(Some(Duration::from_secs(2)))
    .unwrap();

  let icmp_listener_handle = std::thread::spawn(move || {
    println!("Listening to icmp in the background");

    let mut icmp_resp: [MaybeUninit<u8>; 28] = unsafe { MaybeUninit::uninit().assume_init() };

    loop {
      match icmp_socket.recv_from(&mut icmp_resp) {
        Ok((size, addr)) => {
          let res_bytes = icmp_resp
            .into_iter()
            .map(|byte| unsafe { byte.assume_init() })
            .collect::<Vec<u8>>();

          let ipv4_resp = etherparse::Ipv4Header::from_slice(&res_bytes).unwrap();
          let icmpv4_body = etherparse::Icmpv4Slice::from_slice(&res_bytes[20..]).unwrap();

          println!(
            "Got some response bro size: {}\nipv4 raw resp: {:?}\nip address:{}\nICMP type: {:?}, ICMP code: {}",
            size,
            ipv4_resp,
            if addr.is_ipv4() {
              addr.as_socket_ipv4().unwrap().to_string()
            } else {
              addr.as_socket_ipv6().unwrap().to_string()
            },
            icmpv4_body.icmp_type(),
            icmpv4_body.code_u8()
          );
        }
        Err(err) => {
          println!("Error when waiting for icmp socket {:?}", err);
        }
      }
    }
  });

  // Sending the UDP probes
  // ----------------------------------------
  let mut ip_raw_socket = Socket::new(
    Domain::IPV4,
    socket2::Type::RAW,
    // None, // We will call set_header_included(false);
    Some(socket2::Protocol::UDP),
  )
  .unwrap();

  let udp_payload: [u8; 2] = [0, 0];

  println!("Sending {:?} {:?}", udp_payload, udp_socket_addr_dest);
  let sent_count = udp_socket
    .send_to(&udp_payload, udp_socket_addr_dest)
    .unwrap();

  println!("Sent {} bytes of UDP", sent_count);

  // Block for icmp listener;
  // ----------------------------------------
  icmp_listener_handle.join().unwrap();

  return Ok(());
}
