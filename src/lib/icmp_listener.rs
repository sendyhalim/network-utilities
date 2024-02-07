use anyhow::anyhow;
use etherparse::{Icmpv4Slice, Ipv4Header};
use socket2::{Domain, Socket};
use std::mem::MaybeUninit;
use std::time::Duration;

type IpDatagramId = u16;

/// Starts an ICMP listener that will listen every incoming ICMP packet.
/// The listener will receive all ICMP packets sent to the network interface,
/// to explicitly test this:
/// 1. Start the icmp listener.
/// 2. Open another shell session and do traceroute to any host.
pub fn start_icmp_listener<P>(packet_filter: P) -> anyhow::Result<()>
where
  P: Fn(IpDatagramId) -> bool,
{
  let icmp_socket = Socket::new(
    Domain::IPV4,
    socket2::Type::RAW,
    Some(socket2::Protocol::ICMPV4),
  )
  .map_err(|err| anyhow!("Could not open icmp socket {:?}", err))?;

  icmp_socket.set_read_timeout(Some(Duration::from_secs(1)))?;

  let mut icmp_resp: [MaybeUninit<u8>; 60] = unsafe { MaybeUninit::uninit().assume_init() };

  loop {
    match icmp_socket.recv_from(&mut icmp_resp) {
      Ok((size, addr)) => {
        let res_bytes = icmp_resp
          .into_iter()
          .map(|byte| unsafe { byte.assume_init() })
          .collect::<Vec<u8>>();

        let (ipv4_header, icmpv4_payload_bytes) = Ipv4Header::from_slice(&res_bytes)
          .map_err(|err| anyhow!("Error parsing ipv4 header {:?}", err))?;
        let icmpv4_payload = Icmpv4Slice::from_slice(icmpv4_payload_bytes)?;

        let (maybe_ip_field, _) = Ipv4Header::from_slice(icmpv4_payload.payload())
          .map_err(|err| anyhow!("Error parsing icmp payload as probe ipv4 header {:?}", err))?;

        if !packet_filter(maybe_ip_field.identification) {
          continue;
        }

        println!(
            "Got some response size: {}\nIPv4 raw resp: {:#?}\nip address:{}\nICMP type: {:?}, ICMP code: {}, ICMP DATA: {:?}",
            size,
            ipv4_header,
            addr.as_socket_ipv4().unwrap().to_string(),
            icmpv4_payload.icmp_type(),
            icmpv4_payload.code_u8(),
            maybe_ip_field
          );
      }
      Err(err) => {
        println!("Error when waiting for icmp socket {:?}", err);
      }
    }
  }
}
