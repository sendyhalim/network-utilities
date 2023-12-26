use socket2::{Domain, Socket};
use std::mem::MaybeUninit;
use std::net::IpAddr;
use std::net::SocketAddrV4;
use std::net::UdpSocket;
use std::time::Duration;

fn main() {
  // Receiving ICMP logic
  let icmp_socket: Socket = Socket::new(
    Domain::IPV4,
    socket2::Type::RAW,
    Some(socket2::Protocol::ICMPV4),
  )
  .unwrap();

  icmp_socket
    .set_read_timeout(Some(Duration::from_secs(1)))
    .unwrap();

  let icmp_listener_handle = std::thread::spawn(move || {
    println!("Listening to icmp in the background");

    let mut icmp_resp: [MaybeUninit<u8>; 24] = unsafe { MaybeUninit::uninit().assume_init() };

    loop {
      match icmp_socket.recv_from(&mut icmp_resp) {
        Ok((size, addr)) => {
          println!(
            "Got some response bro {} {}",
            size,
            addr.as_socket_ipv4().unwrap().to_string()
          );
        }
        Err(err) => {
          println!("Error when waiting for icmp socket {:?}", err);
        }
      }
    }
  });

  // Sending logic
  let ips: Vec<IpAddr> = dns_lookup::lookup_host("google.com").unwrap();
  let ip = ips.first().unwrap();

  println!("Going to connect to {}", ip);

  let udp_socket_addr: SocketAddrV4 = format!("0.0.0.0:33474").parse().unwrap();
  let udp_socket_addr_dest: SocketAddrV4 = format!("{}:33474", ip).parse().unwrap();

  let socket = UdpSocket::bind(udp_socket_addr).unwrap();
  socket.set_ttl(4).unwrap();

  let payload = [0];
  println!("Sending payload {:?} to {}", payload, udp_socket_addr_dest);
  let sent_count = socket.send_to(&payload, &udp_socket_addr_dest).unwrap();
  println!("Sent {} bytes", sent_count);

  icmp_listener_handle.join().unwrap();
}
