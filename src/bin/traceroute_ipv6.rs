use libc::{setsockopt, IPPROTO_IPV6, IPV6_UNICAST_HOPS};
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
  let hop_limit: u32 = 3;

  if ip.is_ipv6() {
    // Preparing the IPV6 ICMP socket
    // ----------------------------------------
    icmp_socket = Socket::new(
      Domain::IPV6,
      socket2::Type::RAW,
      Some(socket2::Protocol::ICMPV6),
    )
    .unwrap();

    // Preparing the IPV6 UDP socket
    // ----------------------------------------
    udp_socket_addr_client = format!("[::]:{}", udp_socket_client_port).parse().unwrap();
    udp_socket_addr_dest = format!("[{}]:{}", ip.clone(), udp_socket_dest_port)
      .parse()
      .unwrap();

    udp_socket = UdpSocket::bind(udp_socket_addr_client).unwrap();
    let raw_socket_fd: std::os::unix::io::RawFd = udp_socket.as_raw_fd();
    let hop_limit_ptr = &hop_limit as *const libc::c_uint as *const libc::c_void;
    let option_length = std::mem::size_of::<libc::c_uint>() as libc::socklen_t;

    // IPV6_UNICAST_HOPS as defined https://github.com/matthiaskrgr/rust/commit/27bbb53faa97cd13862ff7186b8f83edb6485dcb#diff-96f5abd15201d718909ac0227541d568d9985ac9b075a34ae7eb9f5f66a562f9R220
    let hop_limit_flag: libc::c_int = IPV6_UNICAST_HOPS;

    let res = unsafe {
      setsockopt(
        raw_socket_fd,
        IPPROTO_IPV6,
        hop_limit_flag,
        hop_limit_ptr,
        option_length,
      )
    };

    if res == 0 {
      println!(
        "SUCCESS setting socket option for ipv6 hop limit -- res {}!",
        res
      );
    } else {
      println!(
        "ERROR setting socket option for ipv6 hop limit -- res {}!",
        res
      );
    }
  } else {
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
    udp_socket_addr_client = format!("192.168.1.6:{}", udp_socket_client_port)
      .parse()
      .unwrap();
    udp_socket_addr_dest = format!("{}:{}", ip.clone(), udp_socket_dest_port)
      .parse()
      .unwrap();

    udp_socket = UdpSocket::bind(udp_socket_addr_client).unwrap();
    udp_socket.set_ttl(hop_limit).unwrap();
  }

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

          // NOTE: Because we use raw sockets, the first 20 bytes are the ipv4 header
          // let icmp_res_bytes = &res_bytes[20..];

          // // We are not interested with the checksum at range [2..4);
          // let (icmp_type, icmp_code) = (icmp_res_bytes[0], icmp_res_bytes[1]);

          // let a: u16 = (res_bytes[2] as u16) << 8 | res_bytes[3] as u16;
          // let first_byte: u8 = res_bytes[0] & 0x0F * 4;

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
  let udp_header = etherparse::UdpHeader::without_ipv4_checksum(
    udp_socket_client_port,
    udp_socket_dest_port,
    udp_payload.len(),
  )
  .unwrap();

  let ipv4_addr: Ipv4Addr = udp_socket_addr_dest.ip().to_string().parse().unwrap();

  let mut ipv4_header = etherparse::Ipv4Header::new(
    // (20 + udp_header.length) as u16,
    20_u16,
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

  // ipv4_header.identification = 44332;

  // We want to set ip header manually.
  ip_raw_socket.set_header_included(false).unwrap();

  // Construct raw ip payload
  let mut raw_ip_payload: Vec<u8> = vec![];

  ipv4_header.write(&mut raw_ip_payload).unwrap();
  udp_header.write(&mut raw_ip_payload).unwrap();
  raw_ip_payload.extend_from_slice(&udp_payload);

  // println!(
  // "Debug IP header {:?}\n\nUDP header {:?}\n\nUDP payload {:?}",
  // etherparse::Ipv4Header::from_slice(&raw_ip_payload[..20]).unwrap(),
  // etherparse::UdpHeader::from_slice(&raw_ip_payload[20..28]).unwrap(),
  // &raw_ip_payload[28..30]
  // );

  ip_raw_socket.set_ttl(hop_limit).unwrap();
  let sent_count = ip_raw_socket
    .send_to(&raw_ip_payload, &udp_socket_addr_dest.into())
    .unwrap();

  // println!("Sending {:?} {:?}", udp_payload, udp_socket_addr_dest);
  // let sent_count = udp_socket
  // .send_to(&udp_payload, udp_socket_addr_dest)
  // .unwrap();

  println!("Sent {} bytes of UDP", sent_count);

  // Block for icmp listener;
  // ----------------------------------------
  icmp_listener_handle.join().unwrap();

  return Ok(());
}
