use socket2::Domain;
use socket2::Socket;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::net::UdpSocket;

fn main() -> std::io::Result<()> {
  let ips: Vec<IpAddr> = dns_lookup::lookup_host("google.com")
    .unwrap()
    .into_iter()
    .filter(IpAddr::is_ipv4)
    .collect::<Vec<_>>();

  let ip = ips.first().unwrap();
  // let ip: IpAddr = "192.168.1.1".parse().unwrap();

  println!("Going to connect to {}", ip);

  let udp_socket_client_port: u16 = 33474;
  let udp_socket_dest_port: u16 = 33475;
  let udp_socket_addr_client: SocketAddr;
  let udp_socket_addr_dest: SocketAddr;

  let hop_limit: u32 = 5;

  // Preparing the IPV4 UDP socket
  // ----------------------------------------
  udp_socket_addr_client = format!("0.0.0.0:{}", udp_socket_client_port)
    .parse()
    .unwrap();
  udp_socket_addr_dest = format!("{}:{}", ip.clone(), udp_socket_dest_port)
    .parse()
    .unwrap();

  // ----------------------------------------
  let mut ip_raw_socket = Socket::new(
    Domain::IPV4,
    socket2::Type::RAW,
    // None, // We will call set_header_included(false);
    Some(socket2::Protocol::UDP),
  )
  .unwrap();

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
    // "110.138.79.207".parse::<Ipv4Addr>().unwrap().octets(),
    udp_socket_addr_client
      .ip()
      .to_string()
      .parse::<Ipv4Addr>()
      .unwrap()
      .octets(),
    ipv4_addr.octets(),
  );

  ipv4_header.identification = 44332;

  // We want to set ip header manually.
  // ip_raw_socket.set_header_included(true).unwrap();

  // Construct raw ip payload
  let mut raw_ip_payload: Vec<u8> = vec![];

  // ipv4_header.write(&mut raw_ip_payload).unwrap();
  raw_ip_payload.extend_from_slice(&udp_packet);

  // Check here on why we're overriding the checksum and total len
  // https://github.com/rust-lang/socket2/issues/300
  // let checksum: u16 = ipv4_header.calc_header_checksum().unwrap();
  // let checksum_bytes = &checksum.to_le_bytes();
  // raw_ip_payload[10] = checksum_bytes[0];
  // raw_ip_payload[11] = checksum_bytes[1];

  // let total_len: u16 = ipv4_header.total_len();
  // let total_len_bytes = total_len.to_le_bytes();
  // raw_ip_payload[2] = total_len_bytes[0];
  // raw_ip_payload[3] = total_len_bytes[1];

  // println!(
  // "Debug IP header {:#?}\n\nIP bytes length: {}\n\nUDP: {:#?}\n\nUDP payload {:?}",
  // etherparse::Ipv4Header::from_slice(&raw_ip_payload[..20]).unwrap(),
  // ipv4_header.total_len(),
  // etherparse::UdpHeader::from_slice(&raw_ip_payload[20..28]).unwrap(),
  // &raw_ip_payload[28..30]
  // );

  let sent_count = ip_raw_socket
    .send_to(&raw_ip_payload, &udp_socket_addr_dest.into())
    .unwrap();

  println!("Sent {} bytes of UDP", sent_count);

  return Ok(());
}
