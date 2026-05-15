use crate::protocol::*;


pub fn ip_checksum(h: &Ipv4HeaderFields) -> u16 {
    let mut sum: u32 = 0;

    let first_word = ((h.version as u16) << 12)
        | ((h.ihl as u16) << 8)
        | (h.tos as u16);
    sum += first_word as u32;

    sum += h.total_length as u32;

    sum += h.identification as u32;

    let flags_fragment =
        ((h.flags as u16) << 13) | (h.fragment_offset & 0x1FFF);
    sum += flags_fragment as u32;

    let ttl_proto = ((h.ttl as u16) << 8) | (h.protocol as u16);
    sum += ttl_proto as u32;


    sum += u16::from_be_bytes([h.source[0], h.source[1]]) as u32;
    sum += u16::from_be_bytes([h.source[2], h.source[3]]) as u32;

    sum += u16::from_be_bytes([h.destination[0], h.destination[1]]) as u32;
    sum += u16::from_be_bytes([h.destination[2], h.destination[3]]) as u32;

    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !(sum as u16)
}
pub fn tcp_checksum(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    tcp: &TCPPacket,
) -> u16 {
    let mut sum: u32 = 0;

    let h = &tcp.header;


    sum += u16::from_be_bytes([src_ip[0], src_ip[1]]) as u32;
    sum += u16::from_be_bytes([src_ip[2], src_ip[3]]) as u32;

    sum += u16::from_be_bytes([dst_ip[0], dst_ip[1]]) as u32;
    sum += u16::from_be_bytes([dst_ip[2], dst_ip[3]]) as u32;

    sum += 6;

    let tcp_len = (h.data_offset as usize * 4 + tcp.payload.len()) as u16;
    sum += tcp_len as u32;


    sum += h.src_port as u32;
    sum += h.dst_port as u32;

    sum += (h.seq_num >> 16) as u32;
    sum += (h.seq_num & 0xFFFF) as u32;

    sum += (h.ack_num >> 16) as u32;
    sum += (h.ack_num & 0xFFFF) as u32;

    let data_flags =
        ((h.data_offset as u16) << 12) | (h.flags & 0x0FFF);
    sum += data_flags as u32;

    sum += h.window as u32;


    sum += h.urgent_ptr as u32;


    let mut i = 0;
    let payload = &tcp.payload;

    while i < payload.len() {
        let word = if i + 1 < payload.len() {
            u16::from_be_bytes([payload[i], payload[i + 1]])
        } else {
            (payload[i] as u16) << 8
        };

        sum += word as u32;
        i += 2;
    }


    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !(sum as u16)
}
