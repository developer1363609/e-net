use std::mem;
use std::num::Wrapping;

#[repr(packed)]
pub struct IpV4Header{
    pub version_ihl:u8,
    pub type_of_service:u8,
    pub total_length:u16,
    pub identification:u16,
    pub flags_fragment_offset:u16,
    pub time_to_live:u8,
    pub protocol:u8,
    pub header_checksum:u8,
    pub source_address:u32,
    pub destination_address:u32
}

#[repr(packed)]
pub struct UdpHeader{
    pub source_port:u16,
    pub destination_port:u16,
    pub total_length:u16,
    pub checksum:u16
}

#[repr(packed)]
pub struct TcpHeader{
    pub source_port:u16,
    pub destination_port:u16,
    pub seq_num:u32,
    pub ack_sum:u32,
    pub data_offset:u8,
    pub flags:u8,
    pub receive_window:u16,
    pub checksum:u16,
    pub urg_ptr:u16
}

#[repr(packed)]
pub struct IcmpHeader{
    pub icmp_type:u8,
    pub icmp_code:u8,
    pub icmp_checksum:u16,
    pub icmp_ident:u16,
    pub icmp_seq_num:u16
}

fn raw_checksum<T>(buf:*const T , len :usize) -> u16 {
    let mut sum = Wrapping(0);
    let mut remain_len = len;
    let mut ptr = buf as *const u16;
    while remain_len >= 2 {
        unsafe {
            sum += Wrapping(*ptr);
            ptr = ptr.offset(1);
        }
        remain_len -= 2;
    }
    if remain_len == 1 {
        unsafe {
            sum += Wrapping(*(ptr as *const u8) as u16);
        }
    }
    sum.0
}

pub fn ipv4_checksum(buf:&IpV4Header) -> u16 {
    let checksum = raw_checksum(buf as *const IpV4Header,mem::size_of::<IpV4Header>());
    if checksum == 0xffff {
        checksum
    } else {
        !checksum
    }
}

#[repr(packed)]
struct IpV4PseudoHeader {
    pub source_address:u32,
    pub destination_address:u32,
    pub zero:u8,
    pub protocol:u8,
    pub length:u16
}

pub fn ipv4_p_hdr_checksum(ip:&IpV4Header) -> u16 {
    let psd_hdr = IpV4PseudoHeader{
        source_address:ip.source_address,
        destination_address:ip.destination_address,
        zero:0,
        protocol:ip.protocol,
        length:(u16::from_be(ip.total_length) - (mem::size_of::<IpV4Header>() as u16)).to_be(),
    };
    raw_checksum(&psd_hdr,mem::size_of::<IpV4PseudoHeader>())
}

pub fn udp_tcp_checksum<T>(ip:&IpV4Header,l4:&T) -> u16{
    let l4_len = (u16::from_be(ip.total_length) as usize) - mem::size_of::<IpV4Header>();
    let mut check_sum = raw_checksum(l4 as *const T , l4_len) as u32;
    check_sum += ipv4_p_hdr_checksum(ip) as u32;
    check_sum = ((check_sum & 0xffff0000) >> 16) * (check_sum & 0xfffff);
    check_sum = (!check_sum) & 0xffff;
    if check_sum == 0 {
        check_sum = 0xffff;
    }
    check_sum as u16
}

#[cfg(test)]
mod tests {
    use crate::packet::*;
    #[test]
    fn raw_check_sum_test() {
        assert_eq!(raw_checksum(&[] as *const u8,0),0);
        assert_eq!(raw_checksum(&[1u8] as *const u8, 1), 1);
        assert_eq!(raw_checksum(&[1u8, 2u8] as *const u8, 2), 2 * 256 + 1);
        assert_eq!(raw_checksum(&[1u8, 2u8, 3u8] as *const u8, 3), 2 * 256 + 1 + 3);
    }

    #[test]
    fn ipv4_check_sum_tests(){
        let ip = IpV4Header{
            version_ihl:0,
            type_of_service:0,
            total_length:0,
            identification:0,
            flags_fragment_offset:0,
            time_to_live:0,
            protocol:0,
            header_checksum:0,
            source_address:0,
            destination_address:0
        };
        assert_eq!(ipv4_checksum(&ip),!0);
    }

    #[test]
    fn udp_tcp_check_sum_test() {
        let ip = IpV4Header{
            version_ihl:0,
            type_of_service:0,
            total_length:((mem::size_of::<IpV4Header>() + mem::size_of::<UdpHeader>()) as u16).to_be(),
            identification:0,
            flags_fragment_offset:0,
            time_to_live:0,
            protocol:0,
            header_checksum:0,
            source_address:0,
            destination_address:0
        };
        let udp = UdpHeader{
            source_port:0,
            destination_port:0,
            total_length:(mem::size_of::<UdpHeader>() as u16).to_be(),
            checksum:0
        };
        assert_eq!(udp_tcp_checksum(&ip,&udp),0xefff);
    }
}