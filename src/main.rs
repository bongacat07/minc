use std::env;
use tun_rs::DeviceBuilder;
use std::net::Ipv4Addr;
use easy_repl::{Repl, CommandStatus, command};
use rand::Rng;

use minc::{
    parser, tcp_parser, ip_checksum, tcp_checksum, create_packet,
    Packet, Ipv4Packet, Ipv6Header, TCPPacket,
    TCPState, Ipv4Header, Ipv4HeaderFields, TCPHeader, TCB, ConnectionKey
};
use std::collections::HashMap;
use std::collections::HashSet;

fn send_rst(dev: &tun_rs::SyncDevice, recv_ip: &Ipv4HeaderFields, recv_tcp: &TCPHeader) {
    let mut tcp_packet = TCPPacket {
        header: TCPHeader {
            src_port: recv_tcp.dst_port,
            dst_port: recv_tcp.src_port,
            seq_num: recv_tcp.ack_num,
            ack_num: recv_tcp.seq_num + 1,
            data_offset: 5,
            flags: 0x04,
            window: 0,
            checksum: 0,
            urgent_ptr: 0,
        },
        payload: vec![],
    };
    let ip_fields = Ipv4HeaderFields {
        version: 4,
        ihl: 5,
        tos: 0,
        total_length: 40,
        identification: 0,
        flags: 0,
        fragment_offset: 0,
        ttl: 64,
        protocol: 6,
        source: recv_ip.destination,
        destination: recv_ip.source,
    };
    let ip_chk = ip_checksum(&ip_fields);
    tcp_packet.header.checksum = tcp_checksum(recv_ip.destination, recv_ip.source, &tcp_packet);
    let ip_header = Ipv4Header { fields: ip_fields, header_checksum: ip_chk };
    dev.send(&create_packet(&tcp_packet, &ip_header));
    println!("RST sent");
}

fn send_fin(dev: &tun_rs::SyncDevice, recv_ip: &Ipv4HeaderFields, recv_tcp: &TCPHeader, seq: u32, ack: u32) {
    let mut tcp_packet = TCPPacket {
        header: TCPHeader {
            src_port: recv_tcp.dst_port,
            dst_port: recv_tcp.src_port,
            seq_num: seq,
            ack_num: ack,
            data_offset: 5,
            flags: 0x11,
            window: 64240,
            checksum: 0,
            urgent_ptr: 0,
        },
        payload: vec![],
    };
    let ip_fields = Ipv4HeaderFields {
        version: 4,
        ihl: 5,
        tos: 0,
        total_length: 40,
        identification: 0,
        flags: 0,
        fragment_offset: 0,
        ttl: 64,
        protocol: 6,
        source: recv_ip.destination,
        destination: recv_ip.source,
    };
    let ip_chk = ip_checksum(&ip_fields);
    tcp_packet.header.checksum = tcp_checksum(recv_ip.destination, recv_ip.source, &tcp_packet);
    let ip_header = Ipv4Header { fields: ip_fields, header_checksum: ip_chk };
    dev.send(&create_packet(&tcp_packet, &ip_header));
    println!("FIN sent");
}

fn send_ack(dev: &tun_rs::SyncDevice, recv_ip: &Ipv4HeaderFields, recv_tcp: &TCPHeader, seq: u32, ack: u32) {
    let mut tcp_packet = TCPPacket {
        header: TCPHeader {
            src_port: recv_tcp.dst_port,
            dst_port: recv_tcp.src_port,
            seq_num: seq,
            ack_num: ack,
            data_offset: 5,
            flags: 0x10,
            window: 64240,
            checksum: 0,
            urgent_ptr: 0,
        },
        payload: vec![],
    };
    let ip_fields = Ipv4HeaderFields {
        version: 4,
        ihl: 5,
        tos: 0,
        total_length: 40,
        identification: 0,
        flags: 0,
        fragment_offset: 0,
        ttl: 64,
        protocol: 6,
        source: recv_ip.destination,
        destination: recv_ip.source,
    };
    let ip_chk = ip_checksum(&ip_fields);
    tcp_packet.header.checksum = tcp_checksum(recv_ip.destination, recv_ip.source, &tcp_packet);
    let ip_header = Ipv4Header { fields: ip_fields, header_checksum: ip_chk };
    dev.send(&create_packet(&tcp_packet, &ip_header));
    println!("ACK sent");
}

fn print_ipv4(h: &Ipv4Packet) {
    println!("--- IPv4 Packet ---");
    println!("Version: {}", h.header.fields.version);
    println!("IHL: {}", h.header.fields.ihl);
    println!("Protocol: {}", h.header.fields.protocol);
    println!("Source: {}.{}.{}.{}",
        h.header.fields.source[0],
        h.header.fields.source[1],
        h.header.fields.source[2],
        h.header.fields.source[3]);
    println!("Destination: {}.{}.{}.{}",
        h.header.fields.destination[0],
        h.header.fields.destination[1],
        h.header.fields.destination[2],
        h.header.fields.destination[3]);
    println!("-------------------");
}

fn print_tcp(tcp: &TCPPacket) {
    let h = &tcp.header;
    let f = h.flags & 0b00111111;
    let flag_str = match f {
        0b000010 => "SYN".to_string(),
        0b010010 => "SYN-ACK".to_string(),
        0b010000 => "ACK".to_string(),
        0b000001 => "FIN".to_string(),
        0b010001 => "FIN-ACK".to_string(),
        0b000100 => "RST".to_string(),
        0b011000 => "PSH-ACK".to_string(),
        _ => {
            let mut s = Vec::new();
            if f & 0b100000 != 0 { s.push("URG") }
            if f & 0b010000 != 0 { s.push("ACK") }
            if f & 0b001000 != 0 { s.push("PSH") }
            if f & 0b000100 != 0 { s.push("RST") }
            if f & 0b000010 != 0 { s.push("SYN") }
            if f & 0b000001 != 0 { s.push("FIN") }
            s.join("-")
        }
    };
    println!("--- TCP ---");
    println!("Src Port: {}", h.src_port);
    println!("Dst Port: {}", h.dst_port);
    println!("Seq:      {}", h.seq_num);
    println!("Ack:      {}", h.ack_num);
    println!("Flags:    {}", flag_str);
    println!("-----------");
}

fn print_ipv6(_: &Ipv6Header) {
    println!("IPv6 packet");
}

fn main() {
    let args: Vec<String> = env::args().collect();
    for (i, arg) in args.iter().enumerate() {
        println!("Arg {}: {}", i, arg);
    }

    let dst_ip: Ipv4Addr = args[1].parse().unwrap();
    let destination: [u8; 4] = dst_ip.octets();
    println!("IP: {:?}", destination);

    let src_ip: Ipv4Addr = "11.0.0.12".parse().expect("Invalid source IP");
    let source: [u8; 4] = src_ip.octets();

    let dst_port: u16 = args[2].parse().expect("Invalid port");

    let dev = DeviceBuilder::new()
        .name("tun1")
        .ipv4("11.0.0.12", 24, None)
        .mtu(1500)
        .build_sync()
        .unwrap();

    let mut buf = [0u8; 65535];
    let mut connections: HashMap<ConnectionKey, TCB> = HashMap::new();

    let key = ConnectionKey {
        src_ip: source,
        src_port: 8080,
        dst_ip: destination,
        dst_port: dst_port,
    };

    let iss: u32 = rand::random();
    let mut tcp_packet = TCPPacket {
        header: TCPHeader {
            src_port: 8080,
            dst_port: dst_port,
            seq_num: iss,
            ack_num: 0,
            data_offset: 5,
            flags: 0x02,
            window: 64240,
            checksum: 0,
            urgent_ptr: 0,
        },
        payload: vec![],
    };

    let ip_fields = Ipv4HeaderFields {
        version: 4,
        ihl: 5,
        tos: 0,
        total_length: 40,
        identification: 0,
        flags: 0,
        fragment_offset: 0,
        ttl: 64,
        protocol: 6,
        source: source,
        destination: destination,
    };

    let ip_chk = ip_checksum(&ip_fields);
    tcp_packet.header.checksum = tcp_checksum(destination, source, &tcp_packet);
    let ip_header = Ipv4Header { fields: ip_fields, header_checksum: ip_chk };

    connections.insert(key, TCB {
        state: TCPState::SynSent,
        iss,
        snd_una: iss,
        snd_nxt: iss + 1,
        irs: tcp_packet.header.seq_num,
        rcv_nxt: tcp_packet.header.seq_num + 1,
    });

    dev.send(&create_packet(&tcp_packet, &ip_header));

    loop {
        match dev.recv(&mut buf) {
            Ok(len) => {
                let packet = parser(&buf[..len]);

                match packet {
                    Packet::IPv4(h) => {
                        print_ipv4(&h);

                        if h.header.fields.protocol != 6 {
                            continue;
                        }

                        let tcp = match tcp_parser(&h.payload) {
                            Some(t) => t,
                            None => continue,
                        };

                        print_tcp(&tcp);

                        let key = ConnectionKey {
                            src_ip: h.header.fields.destination,
                            src_port: tcp.header.dst_port,
                            dst_ip: h.header.fields.source,
                            dst_port: tcp.header.src_port,
                        };

                        if tcp.header.flags & 0x04 != 0 {
                            connections.remove(&key);
                            println!("RST received, connection aborted");
                            continue;
                        }

                        if let Some(tcb) = connections.get_mut(&key) {
                            match tcb.state {
                                TCPState::SynSent     => {

                                    let is_syn_ack = (tcp.header.flags & 0x12) == 0x12;
                                                                      if is_syn_ack {
                                                                          if tcp.header.ack_num == tcb.snd_nxt {
                                                                              tcb.snd_una = tcp.header.ack_num;
                                                                              tcb.irs     = tcp.header.seq_num;
                                                                              tcb.rcv_nxt = tcp.header.seq_num + 1;
                                                                              tcb.state   = TCPState::Established;
                                                                              send_ack(&dev, &h.header.fields, &tcp.header, tcb.snd_nxt, tcb.rcv_nxt);
                                                                              println!("Handshake complete, connection established");
                                                                              break;
                                                                          } else {
                                                                              println!("Bad ACK num in SYN-ACK, expected {}, got {}", tcb.snd_nxt, tcp.header.ack_num);
                                                                              send_rst(&dev, &h.header.fields, &tcp.header);
                                                                              connections.remove(&key);
                                                                              continue;
                                                                          }
                                                                      } else {
                                                                          println!("Unexpected packet in SynSent, sending RST");
                                                                          send_rst(&dev, &h.header.fields, &tcp.header);
                                                                          connections.remove(&key);
                                                                          continue;
                                                                      }
                                     }
                                TCPState::SynReceived => { println!("SynReceived: TODO"); continue; }
                                TCPState::Established => { println!("Established: TODO"); continue; }
                                TCPState::FinWait1    => { println!("FinWait1: TODO");    continue; }
                                TCPState::FinWait2    => { println!("FinWait2: TODO");    continue; }
                                TCPState::CloseWait   => { println!("CloseWait: TODO");   continue; }
                                TCPState::Closing     => { println!("Closing: TODO");     continue; }
                                TCPState::LastAck     => { println!("LastAck: TODO");     continue; }
                                TCPState::TimeWait    => { println!("TimeWait: TODO");    continue; }
                                TCPState::Closed      => { connections.remove(&key);      continue; }
                            }
                        } else {
                            println!("No connection found for packet, sending RST");
                            send_rst(&dev, &h.header.fields, &tcp.header);
                            continue;
                        }
                    }
                    Packet::IPv6(h) => { print_ipv6(&h); }
                    Packet::Unknown => { println!("Unknown packet"); }
                }
            }
            Err(e) => {
                eprintln!("recv error: {}", e);
                continue;
            }
        }
    }

    let mut repl = Repl::builder()
        .add("SYN", command! {
            "Send SYN",
            () => || {
                println!("SYN sent");
                Ok(CommandStatus::Done)
            }
        })
        .add("ACK", command! {
            "Send ACK",
            () => || {
                println!("ACK sent");
                Ok(CommandStatus::Done)
            }
        })
        .add("FIN", command! {
            "Send FIN",
            () => || {
                println!("FIN sent");
                Ok(CommandStatus::Done)
            }
        })
        .add("RST", command! {
            "Send RST",
            () => || {
                println!("RST sent");
                Ok(CommandStatus::Done)
            }
        })
        .add("send", command! {
            "Send payload",
            (payload: String) => |payload| {
                println!("Payload sent: {}", payload);
                Ok(CommandStatus::Done)
            }
        })
        .add("terminate", command! {
            "Terminate connection",
            () => || {
                println!("Connection terminated");
                Ok(CommandStatus::Quit)
            }
        })
        .build()
        .expect("Failed to create repl");

    repl.run().expect("Critical REPL error");
}
