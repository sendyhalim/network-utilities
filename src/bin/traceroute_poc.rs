use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};

fn main() -> std::io::Result<()> {
  // Preparing the IPv4 UDP socket
  // ----------------------------------------
  let udp_socket_client_port: u16 = 33474;
  let udp_socket_dest_port: u16 = 33475;
  let udp_socket_addr_client: SocketAddr = format!("0.0.0.0:{}", udp_socket_client_port)
    .parse()
    .unwrap();

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

  let udp_socket: UdpSocket;
  let hop_limit: u32 = 6;

  // Start the icmp listener before sending the UDP probe
  let icmp_listener_handle = std::thread::spawn(|| {
    println!("Starting icmp listener in the background...");

    lib::icmp_listener::start_icmp_listener(|_| true);
  });

  udp_socket = UdpSocket::bind(udp_socket_addr_client).unwrap();
  udp_socket.set_ttl(hop_limit).unwrap();

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
