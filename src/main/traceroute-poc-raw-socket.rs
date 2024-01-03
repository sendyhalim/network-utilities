use socket2::Domain;
use socket2::Socket;
use std::mem::MaybeUninit;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::time::Duration;

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

  let hop_limit: u32 = 9;

  // Preparing the IPV4 ICMP socket
  // ----------------------------------------
  let icmp_socket = Socket::new(
    Domain::IPV4,
    socket2::Type::RAW,
    Some(socket2::Protocol::ICMPV4),
  )
  .unwrap();

  // Preparing the IPV4 UDP socket address
  // ----------------------------------------
  udp_socket_addr_client = format!("0.0.0.0:{}", udp_socket_client_port)
    .parse()
    .unwrap();
  udp_socket_addr_dest = format!("{}:{}", ip.clone(), udp_socket_dest_port)
    .parse()
    .unwrap();

  // Preparing ip raw socket
  // ----------------------------------------
  let mut ip_raw_socket = Socket::new(
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

  ipv4_header.identification = 28182;

  // We want to set ip header manually.
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
            "Got some response size: {}\nipv4 raw resp: {:?}\nip address:{}\nICMP type: {:?}, ICMP code: {}",
            size,
            ipv4_resp,
            addr.as_socket_ipv4().unwrap().to_string(),
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

  // Send the probe
  // ----------------------------------------
  let sent_count = ip_raw_socket
    .send_to(&raw_ip_payload, &udp_socket_addr_dest.into())
    .unwrap();

  println!("Sent {} bytes of UDP", sent_count);

  // Block the icmp listener
  // ----------------------------------------
  let _ = icmp_listener_handle.join().unwrap();

  return Ok(());
}
