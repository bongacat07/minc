use crate::protocol::*;


pub fn parser(buf: &[u8]) -> Packet {
    if buf.is_empty() {
        return Packet::Unknown;
    }

    match buf[0] >> 4 {
        // ---------------- IPv4 ----------------
        4 => {
            if buf.len() < 20 {
                return Packet::Unknown;
            }

            let ihl = buf[0] & 0x0F;
            if ihl < 5 {
                return Packet::Unknown;
            }

            let total_length = u16::from_be_bytes([buf[2], buf[3]]);
            if total_length as usize > buf.len() {
                return Packet::Unknown;
            }

            let header_end = (ihl * 4) as usize;
            if header_end > total_length as usize {
                return Packet::Unknown;
            }

            let payload = buf[header_end..total_length as usize].to_vec();

            Packet::IPv4(Ipv4Packet {
                header: Ipv4Header {
                    fields: Ipv4HeaderFields {
                        version: 4,
                        ihl,
                        tos: buf[1],
                        total_length,
                        identification: u16::from_be_bytes([buf[4], buf[5]]),
                        flags: buf[6] >> 5,
                        fragment_offset: (((buf[6] as u16) & 0x1F) << 8) | buf[7] as u16,
                        ttl: buf[8],
                        protocol: buf[9],
                        source: [buf[12], buf[13], buf[14], buf[15]],
                        destination: [buf[16], buf[17], buf[18], buf[19]],
                    },
                    header_checksum: u16::from_be_bytes([buf[10], buf[11]]),
                },
                payload,
            })
        }

        // ---------------- IPv6 ----------------
        6 => {
            if buf.len() < 40 {
                return Packet::Unknown;
            }

            let payload_length = u16::from_be_bytes([buf[4], buf[5]]);
            if 40 + payload_length as usize > buf.len() {
                return Packet::Unknown;
            }

            let payload = buf[40..40 + payload_length as usize].to_vec();

            Packet::IPv6(Ipv6Header {
                version: 6,
                traffic_class: ((buf[0] & 0x0F) << 4) | (buf[1] >> 4),
                flow_label: (((buf[1] as u32) & 0x0F) << 16)
                    | ((buf[2] as u32) << 8)
                    | buf[3] as u32,
                payload_length,
                next_header: buf[6],
                hop_limit: buf[7],
                source: buf[8..24].try_into().unwrap(),
                destination: buf[24..40].try_into().unwrap(),
                payload,
            })
        }

        _ => Packet::Unknown,
    }
}

pub fn tcp_parser(buf: &[u8]) -> Option<TCPPacket> {
    if buf.len() < 20 {
        return None;
    }

    let data_offset = (buf[12] >> 4) * 4;

    if buf.len() < data_offset as usize {
        return None;
    }

    let header = TCPHeader {
        src_port: u16::from_be_bytes([buf[0], buf[1]]),
        dst_port: u16::from_be_bytes([buf[2], buf[3]]),
        seq_num: u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]),
        ack_num: u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]),
        data_offset,
        flags: ((buf[12] as u16 & 0x01) << 8) | buf[13] as u16,
        window: u16::from_be_bytes([buf[14], buf[15]]),
        checksum: u16::from_be_bytes([buf[16], buf[17]]),
        urgent_ptr: u16::from_be_bytes([buf[18], buf[19]]),
    };

    let payload = buf[data_offset as usize..].to_vec();

    Some(TCPPacket { header, payload })
}
