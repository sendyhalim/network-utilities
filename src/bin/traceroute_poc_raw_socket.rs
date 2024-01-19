use socket2::{Domain, Socket};
use std::net::{Ipv4Addr, SocketAddr, ToSocketAddrs};

fn main() -> std::io::Result<()> {
  let udp_socket_client_port: u16 = 33474;
  let udp_socket_dest_port: u16 = 33475;
  let udp_socket_addr_client: SocketAddr;
  let udp_socket_addr_dest: SocketAddr = ("google.com", udp_socket_dest_port)
    .to_socket_addrs()
    .unwrap()
    .into_iter()
    .filter(|socket_addr: &SocketAddr| {
      return socket_addr.is_ipv4();
    })
    .collect::<Vec<_>>()
    .first()
    .unwrap()
    .to_owned();

  let hop_limit: u32 = 6;

  // Preparing the IPV4 ICMP socket
  // ----------------------------------------

  // Preparing the IPV4 UDP socket address
  // ----------------------------------------
  udp_socket_addr_client = format!("0.0.0.0:{}", udp_socket_client_port)
    .parse()
    .unwrap();

  // Preparing ip raw socket
  // ----------------------------------------
  let ip_raw_socket = Socket::new(
    Domain::IPV4,
    socket2::Type::RAW,
    Some(socket2::Protocol::UDP),
  )
  .unwrap();

  // Prepare the IPv4 payload containing UDP packet
  // ----------------------------------------
  let udp_payload: [u8; 2] = [0, 0];
  let udp_header = etherparse::UdpHeader::without_ipv4_checksum(
    udp_socket_client_port,
    udp_socket_dest_port,
    udp_payload.len(), // Later will be sum-med with udp_header len
  )
  .unwrap();

  let mut udp_packet: Vec<u8> = vec![];
  udp_packet.extend_from_slice(&udp_header.to_bytes());
  udp_packet.extend_from_slice(&udp_payload);

  let ipv4_addr: Ipv4Addr = udp_socket_addr_dest.ip().to_string().parse().unwrap();

  let mut ipv4_header = etherparse::Ipv4Header::new(
    udp_packet.len() as u16,
    hop_limit as u8,
    17,
    udp_socket_addr_client
      .ip()
      .to_string()
      .parse::<Ipv4Addr>()
      .unwrap()
      .octets(),
    ipv4_addr.octets(),
  );

  // The default value is true.
  // The DF bit is not set when observing traceroute
  // through tcpdump, so we're just mimicking the behaviour here.
  ipv4_header.dont_fragment = false;

  // We want to set ip header manually in the payload
  ip_raw_socket.set_header_included(true).unwrap();

  // Construct raw ip payload
  let mut raw_ip_payload: Vec<u8> = vec![];

  ipv4_header.write(&mut raw_ip_payload).unwrap();
  raw_ip_payload.extend_from_slice(&udp_packet);

  println!(
    "Debug IP header {:#?}\n\nIP bytes length: {}\n\nUDP: {:#?}\n\nUDP payload {:?}",
    etherparse::Ipv4Header::from_slice(&raw_ip_payload[..20]).unwrap(),
    ipv4_header.total_len(),
    etherparse::UdpHeader::from_slice(&raw_ip_payload[20..28]).unwrap(),
    &raw_ip_payload[28..30]
  );

  // Start ICMP listener before sending the payload
  // ----------------------------------------
  let icmp_listener_thread_handle = std::thread::spawn(|| {
    lib::icmp_listener::start_icmp_listener();
  });

  // Send the probe
  // ----------------------------------------
  let sent_count = ip_raw_socket
    .send_to(&raw_ip_payload, &udp_socket_addr_dest.into())
    .unwrap();

  println!("Sent {} bytes of payload", sent_count);

  icmp_listener_thread_handle.join().unwrap();

  return Ok(());
}
