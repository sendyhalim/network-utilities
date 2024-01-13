use socket2::{Domain, Socket};
use std::mem::MaybeUninit;
use std::time::Duration;

/// Starts an ICMP listener that will listen every incoming ICMP packet.
/// The listener will receive all ICMP packets sent to the network interface,
/// to explicitly test this:
/// 1. Start the icmp listener.
/// 2. Open another shell session and do traceroute to any host.
pub fn start_icmp_listener() {
  let icmp_socket = Socket::new(
    Domain::IPV4,
    socket2::Type::RAW,
    Some(socket2::Protocol::ICMPV4),
  )
  .unwrap();

  icmp_socket
    .set_read_timeout(Some(Duration::from_secs(1)))
    .unwrap();

  let mut icmp_resp: [MaybeUninit<u8>; 28] = unsafe { MaybeUninit::uninit().assume_init() };

  loop {
    match icmp_socket.recv_from(&mut icmp_resp) {
      Ok((size, addr)) => {
        let res_bytes = icmp_resp
          .into_iter()
          .map(|byte| unsafe { byte.assume_init() })
          .collect::<Vec<u8>>();

        let (ipv4_header, icmpv4_payload_bytes) =
          etherparse::Ipv4Header::from_slice(&res_bytes).unwrap();
        let icmpv4_payload = etherparse::Icmpv4Slice::from_slice(icmpv4_payload_bytes).unwrap();

        println!(
            "Got some response size: {}\nIPv4 raw resp: {:#?}\nip address:{}\nICMP type: {:?}, ICMP code: {}",
            size,
            ipv4_header,
            addr.as_socket_ipv4().unwrap().to_string(),
            icmpv4_payload.icmp_type(),
            icmpv4_payload.code_u8()
          );
      }
      Err(err) => {
        println!("Error when waiting for icmp socket {:?}", err);
      }
    }
  }
}
