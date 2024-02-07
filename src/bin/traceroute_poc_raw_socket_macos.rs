use pnet::{
  packet::{
    ethernet::EtherTypes,
    ip::IpNextHeaderProtocols,
    ipv4::{checksum, Ipv4, Ipv4Flags},
  },
  util::MacAddr,
};

use pnet::datalink::Channel::Ethernet;
use pnet::packet::ethernet::{EthernetPacket, MutableEthernetPacket};
use pnet::packet::{MutablePacket, Packet};

use pnet::packet::ipv4::MutableIpv4Packet;
use socket2::{Domain, Protocol, Socket};
use std::{
  net::{Ipv4Addr, SocketAddr, ToSocketAddrs},
  os::raw::c_int,
};

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

  let hop_limit: u32 = 2;

  let network_interfaces = pnet::datalink::interfaces()
    .into_iter()
    .filter(|i| {
      return i.name == "en0";
    })
    .collect::<Vec<_>>();
  let network_interface = network_interfaces.first().unwrap();

  let (mut sender, receiver) = match pnet::datalink::channel(network_interface, Default::default())
  {
    Ok(pnet::datalink::Channel::Ethernet(sender, receiver)) => (sender, receiver),
    Ok(_) => panic!("undhandled channel type bro"),
    Err(err) => panic!("Error! {}", err),
  };

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
    Some(Protocol::from(0 as c_int)),
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
    (udp_packet.len() as u16).to_be(),
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
  // ipv4_header.dont_fragment = false;

  // We want to set ip header manually in the payload
  ip_raw_socket.set_header_included(true).unwrap();

  // Construct raw ip payload
  let mut raw_ip_payload: Vec<u8> = vec![];

  ipv4_header.write_raw(&mut raw_ip_payload).unwrap();
  raw_ip_payload.extend_from_slice(&udp_packet);

  // Start ICMP listener before sending the payload
  // ----------------------------------------
  let icmp_listener_thread_handle = std::thread::spawn(|| {
    lib::icmp_listener::start_icmp_listener();
  });

  // Send the probe
  // ----------------------------------------
  let mut raw_ip_payload = [0u8; 30];

  let mut ipv4_datagram = MutableIpv4Packet::new(&mut raw_ip_payload[..]).unwrap();
  ipv4_datagram.set_ttl(hop_limit as u8);
  ipv4_datagram.set_version(4);
  ipv4_datagram.set_destination(ipv4_addr);
  ipv4_datagram.set_header_length(5);
  ipv4_datagram.set_total_length(udp_packet.len() as u16 + 20);
  ipv4_datagram.set_next_level_protocol(IpNextHeaderProtocols::Udp);

  ipv4_datagram.set_payload(&udp_packet.clone());
  ipv4_datagram.set_source(udp_socket_addr_client.ip().to_string().parse().unwrap());
  ipv4_datagram.set_version(4);
  ipv4_datagram.set_identification(8);

  let cksm = pnet::packet::ipv4::checksum(&ipv4_datagram.to_immutable());
  ipv4_datagram.set_checksum(cksm);

  let mut ethernet_packet = [0u8; 48];
  let mut ethernet_header = MutableEthernetPacket::new(&mut ethernet_packet[..]).unwrap();
  let dest: MacAddr = "34:da:b7:f0:12:c".parse().unwrap();

  ethernet_header.set_source(network_interface.mac.unwrap());
  ethernet_header.set_destination(dest);
  ethernet_header.set_ethertype(EtherTypes::Ipv4);
  ethernet_header.set_payload(ipv4_datagram.packet());

  let ethernet_frame = ethernet_header.packet();

  sender.send_to(ethernet_frame, None).unwrap().unwrap();

  // println!(
  //   "Sent {:#?} ethernet payload",
  //   etherparse::Ethernet2Header::from_bytes(ethernet_frame[0..14].try_into().unwrap())
  // );

  icmp_listener_thread_handle.join().unwrap();

  return Ok(());
}
