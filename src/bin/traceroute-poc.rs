use std::net::IpAddr;
use std::net::SocketAddr;
use std::net::UdpSocket;

fn main() -> std::io::Result<()> {
  let ips: Vec<IpAddr> = dns_lookup::lookup_host("google.com")
    .unwrap()
    .into_iter()
    .filter(IpAddr::is_ipv4)
    .collect::<Vec<_>>();

  let ip = ips.first().unwrap();

  let udp_socket_client_port: u16 = 33474;
  let udp_socket_dest_port: u16 = 33475;
  let udp_socket_addr_client: SocketAddr;
  let udp_socket_addr_dest: SocketAddr;

  let udp_socket: UdpSocket;
  let hop_limit: u32 = 6;

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

  // Start the icmp listener before sending the UDP probe
  let icmp_listener_handle = std::thread::spawn(|| {
    lib::icmp_listener::start_icmp_listener();
  });

  // Sending the UDP probe
  // ----------------------------------------
  let udp_payload: [u8; 2] = [0, 0];

  println!("Sending {:?} to {:?}", udp_payload, udp_socket_addr_dest);

  let sent_count = udp_socket
    .send_to(&udp_payload, udp_socket_addr_dest)
    .unwrap();

  println!("Sent {} bytes of payload", sent_count);

  // Block for icmp listener;
  // ----------------------------------------
  icmp_listener_handle.join().unwrap();

  return Ok(());
}
