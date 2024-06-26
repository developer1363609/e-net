use std::fmt::format;
use std::hint::unreachable_unchecked;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::num::NonZeroU32;
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};

use bincode::{deserialize, serialize};
use libc::proc_kmsgbuf;
use log::{info, warn};
use rand::{Rng, thread_rng};
use ring::{aead, pbkdf2};
use serde::__private::de::IdentifierDeserializer;
use serde_derive::{Deserialize, Serialize};
use transient_hashmap::TransientHashMap;

use crate::{device, utils};
use crate::utils::{DefaultGateway, enable_ipv4_forwarding, get_public_ip};

pub static INTERRUPTED:AtomicBool = AtomicBool::new(false);
pub static CONNECTED:AtomicBool = AtomicBool::new(false);
pub static LISTENING:AtomicBool = AtomicBool::new(false);
const KEY_LEN:usize = 32;

type Id = u8;

type Token = u64;

fn generate_add_nonce(_secret: &str) -> (aead::Aad<[u8; 0]>, aead::Nonce) {
    let nonce = aead::Nonce::assume_unique_for_key([0;12]);
    let aad = aead::Aad::empty();
    (aad,nonce)
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
enum Message {
    Request,
    Response {id:Id,token:Token,dns:String},
    Data{id:Id,token:Token,data:Vec<u8>}
}

const TUN:mio::Token = mio::Token(0);
const SOCK:mio::Token = mio::Token(1);

fn resolve(host:&str) -> Result<IpAddr,String> {
    let ip_list = dns_lookup::lookup_host(host).map_err(|_| "dns_lookup::lookup_host")?;
    Ok(ip_list.first().unwrap().clone())
}

fn create_tun_attempt() -> device::Tun{
    fn attempt(id:u8) -> device::Tun{
        match id {
            255 => panic!("unable to create TUN device."),
            _ => match device::Tun::create(id) {
                Ok(tun) => tun,
                Err(_) => attempt(id + 1)
            },
        }
    }
    attempt(0)
}

fn derive_keys(password:&str) -> aead::LessSafeKey{
    let mut key = [0;KEY_LEN];
    let salt = vec![0;64];
    let pbkdf2_iterations : NonZeroU32 = NonZeroU32::new(1024).unwrap();
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        pbkdf2_iterations,
        &salt,
        password.as_bytes(),
        &mut key,
    );
    let less_safe_key = aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_256_GCM, &key).unwrap());
    less_safe_key
}

fn initiate(
    socket:&UdpSocket,
    addr:&SocketAddr,
    secret:&str
) -> Result<(Id,Token,String),String>{
    let key = derive_keys(secret);
    let req_msg = Message::Request;
    let mut encoded_req_msg:Vec<u8> = serialize(&req_msg).map_err(|e|e.to_string())?;
    let mut encrypted_req_msg = encoded_req_msg.clone();
    encoded_req_msg.resize(encoded_req_msg.len() + key.algorithm().tag_len(),0);
    let (aad,nonce) = generate_add_nonce(secret);
    key.seal_in_place_append_tag(nonce,aad,&mut encrypted_req_msg).unwrap();
    let mut remaining_len = encrypted_req_msg.len();
    while remaining_len > 0{
        let send_bytes = socket.send_to(&encrypted_req_msg,addr).map_err(|e|e.to_string())?;
        remaining_len -= send_bytes;
    }
    info!("request sent to {} .",addr);
    let mut buf = [0u8;1600];
    let (len , _recv_addr) = socket.recv_from(&mut buf).map_err(|e|e.to_string())?;
    info!("Response received from {}.", addr);
    let (aad,nonce) = generate_add_nonce(secret);
    let decrypted_buf = key.open_in_place(nonce,aad,&mut buf[0..len]).unwrap();
    let d_len = decrypted_buf.len();
    let resp_msg:Message = deserialize(&decrypted_buf[0..d_len]).map_err(|e|e.to_string())?;
    match resp_msg {
        Message::Response { id,token,dns } => Ok((id,token,dns)),
        _ => Err(format!("invalid message {:?} from {} " , resp_msg,addr))
    }
}

pub fn connect(host:&str,port:u16,default:bool,secret:&str) {
    info!("Working in client mode.");
    let remote_ip = resolve(host).unwrap();
    let remote_addr = SocketAddr::new(remote_ip, port);
    info!("Remote server: {}", remote_addr);
    let local_addr:SocketAddr = "0.0.0.0".parse::<SocketAddr>().unwrap();
    let socket = UdpSocket::bind(&local_addr).unwrap();
    let key = derive_keys(secret);
    let (id,token,dns) = initiate(&socket, &remote_addr, &secret).unwrap();
    info!(
        "Session established with token {}. Assigned IP address: 10.10.10.{}. dns: {}",
        token, id, dns
    );
    info!("Bringing up TUN device.");
    let mut tun = create_tun_attempt();
    let tun_rawfd = tun.as_raw_fd();
    tun.up(id);
    let mut tunfd = &tun_rawfd;
    info!(
        "TUN device {} initialized. Internal IP: 10.10.10.{}/24.",
        tun.name(),
        id
    );
    info!("setting dns to {}", dns);
    utils::set_dns(&dns).unwrap();
    let mut poll = mio::Poll::new().unwrap();
    info!("Setting up TUN device for polling.");
    poll.registry()
        .register(
            &mut tunfd,
            TUN,
            mio::Interest::READABLE | mio::Interest::WRITABLE,
        )
        .unwrap();
    info!("Setting up socket for polling.");
    let mut sockfd = mio::net::UdpSocket::from_std(socket);
    poll.registry()
        .register(&mut sockfd, SOCK, mio::Interest::READABLE)
        .unwrap();
    let mut events = mio::Events::with_capacity(1024);
    let mut buf = [0u8;1600];
    let _gw = DefaultGateway::create("10.10.10.1",&format!("{}",remote_addr.ip()),default);
    let mut encoder = snap::raw::Encoder::new();
    let mut decoder = snap::raw::Decoder::new();
    CONNECTED.store(true,Ordering::Relaxed);
    info!("Ready for transmission.");
    loop {
        if INTERRUPTED.load(Ordering::Relaxed) {
            break;
        }
        poll.poll(&mut events, None).unwrap();
        for event in events.iter() {
            match event.token(){
                SOCK => {
                    let (len , addr) = sockfd.recv_from(&mut buf).unwrap();
                    let (aad,nonce) = generate_add_nonce(secret);
                    let decrypted_buf = key.open_in_place(nonce,aad,&mut buf[0..len]).unwrap();
                    let d_len = decrypted_buf.len();
                    let msg:Message = deserialize(&decrypted_buf[0..d_len]).unwrap();
                    match msg {
                        Message::Request | Message::Response{
                            id:_,
                            token:_,
                            dns:_,
                        } => {
                            warn!("Invalid message {:?} from {}", msg, addr);
                        }
                        Message::Data {
                            id:_,
                            token:server_token,
                            data,
                        } => {
                            if token == server_token {
                                let decompressed_data = decoder.decompress_vec(&data).unwrap();
                                let data_len = decompressed_data.len();
                                let mut sent_len = 0;
                                while sent_len < data_len {
                                    sent_len += tun.write(&decompressed_data[sent_len..data_len]).unwrap();
                                }
                            } else {
                                warn!(
                                    "Token mismatched. Received: {}. Expected: {}",
                                    server_token, token
                                );
                            }
                        }
                    }
                }
                TUN => {
                    let len:usize = tun.read(&mut buf).unwrap();
                    let data = &buf[0..len];
                    let msg = Message::Data {
                        id,
                        token,
                        data:encoder.compress_vec(data).unwrap()
                    };
                    let encode_msg = serialize(&msg).unwrap();
                    let mut encrypted_msg = encode_msg.clone();
                    encrypted_msg.resize(encode_msg.len() + key.algorithm().tag_len(),0);
                    let (aad,nonce) = generate_add_nonce(secret);
                    key.seal_in_place_append_tag(nonce,aad,&mut encrypted_msg).unwrap();
                    let mut sent_len = 0;
                    while sent_len < encrypted_msg.len() {
                        sent_len += sockfd.send_to(&encrypted_msg[sent_len..encrypted_msg.len()],remote_addr).unwrap()
                    }
                }
                _ => unreachable!()
            }
        }
    }
}


pub fn serve(port:u16,secret:&str,dns:IpAddr) {
    if cfg!(not(target_os = "linux")){
        panic!("Server mode is only available in Linux!");
    }
    info!("Working in server mode.");
    let public_ip = get_public_ip().unwrap();
    info!("Public IP: {}", public_ip);
    info!("Enabling kernel's IPv4 forwarding.");
    enable_ipv4_forwarding().unwrap();
    info!("Bringing up TUN device.");
    let mut tun = create_tun_attempt();
    tun.up(1);
    let tun_raw_fd = tun.as_raw_fd();
    let mut tun_fd = mio::unix::SourceFd(&tun_raw_fd);
    info!(
        "TUN device {} initialized. Internal IP: 10.10.10.1/24.",
        tun.name()
    );
    let addr = format!("0.0.0.0:{}",port).parse().unwrap();
    let mut sock_fd = mio::net::UdpSocket::bind(addr).unwrap();
    info!("Listening on: 0.0.0.0:{}.", port);
    let mut poll = mio::Poll::new().unwrap();
    poll.registry()
        .register(&mut sock_fd, SOCK, mio::Interest::READABLE)
        .unwrap();
    poll.registry()
        .register(&mut tun_fd, TUN, mio::Interest::READABLE)
        .unwrap();
    let mut events = mio::Events::with_capacity(1024);
    let mut rng = thread_rng();
    let mut available_ids:Vec<Id> = (2..254).collect();
    let mut client_info:TransientHashMap<Id,(Token,SocketAddr)> = TransientHashMap::new(60);
    let mut buf = [0u8;1600];
    let mut encoder = snap::raw::Encoder::new();
    let mut decoder = snap::raw::Decoder::new();
    let key = derive_keys(secret);
    LISTENING.store(true,Ordering::Relaxed);
    info!("Ready for transmission.");
    loop{
        if INTERRUPTED.load(Ordering::Relaxed) {
            break;
        }
        available_ids.append(&mut client_info.prune());
        poll.poll(&mut events,None).unwrap();
        for event in events.iter(){
            match event.token(){
                SOCK =>{
                    let (len , addr) = sock_fd.recv_from(&mut buf).unwrap();
                    let (aad,nonce) = generate_add_nonce(secret);
                    let decrypted_buf = key.open_in_place(nonce,aad,&mut buf[0..len]).unwrap();
                    let d_len = decrypted_buf.len();
                    let msg:Message = deserialize(&decrypted_buf[0..d_len]).unwrap();
                    match msg {
                        Message::Request => {
                            let client_id:Id = available_ids.pop().unwrap();
                            let client_token:Token = rng.gen::<Token>();
                            client_info.insert(client_id,(client_token,addr));
                            info!(
                                "Got request from {}. Assigning IP address: 10.10.10.{}.",
                                addr, client_id
                            );
                            let reply = Message::Response {
                                id:client_id,
                                token:client_token,
                                dns:dns.to_string()
                            };
                            let mut encoded_reply = serialize(&reply).unwrap();
                            let mut encrypted_reply = encoded_reply.clone();
                            encrypted_reply.resize(encoded_reply.len() + key.algorithm().tag_len(),0);
                            let (aad , nonce) = generate_add_nonce(secret);
                            key.seal_in_place_append_tag(nonce,aad,&mut encoded_reply ).unwrap();
                            let mut sent_len = 0;
                            while sent_len < encoded_reply.len() {
                                sent_len += sock_fd
                                    .send_to(
                                        &encrypted_reply[sent_len..encrypted_reply.len()],
                                        addr
                                    ).unwrap();
                            }
                        }
                        Message::Response {
                            id:_,
                            token:_,
                            dns:_
                        } => warn!("invalid message {:?} from {}",msg,addr),
                        Message::Data {id,token,data} => match client_info.get(&id) {
                            None => warn!("Unknown IP packet from TUN for client {}" , id),
                            Some(&(t,_)) => {
                                if t != token {
                                    warn!(
                                        "Unknown data with mismatched token {} from id {}. \
                                               Expected: {}",
                                        token, id, t
                                    );
                                } else {
                                    let decompressed_data = decoder.decompress_vec(&data).unwrap();
                                    let data_len = decompressed_data.len();
                                    let mut sent_len = 0;
                                    while sent_len < data_len {
                                        sent_len += tun
                                            .write(&decompressed_data[sent_len..data_len])
                                            .unwrap()
                                    }
                                }
                            }
                        },
                    }
                }
                TUN => {
                    let len:usize = tun.read(&mut buf).unwrap();
                    let data = &buf[0..len];
                    let client_id:u8 = data[19];
                    match client_info.get(&client_id) {
                        None => warn!("Unknown IP packet from TUN for client {}.", client_id),
                        Some(&(token,addr)) => {
                            let msg = Message::Data {
                                id:client_id,
                                token,
                                data:encoder.compress_vec(data).unwrap()
                            };
                            let encoded_msg = serialize(&msg).unwrap();
                            let mut encrypted_msg = encoded_msg.clone();
                            encrypted_msg.resize(encoded_msg.len() + key.algorithm().tag_len(),0);
                            let (aad,nonce) = generate_add_nonce(secret);
                            key.seal_in_place_append_tag(nonce,aad,&mut encrypted_msg).unwrap();
                            let mut sent_len = 0;
                            while sent_len < encrypted_msg.len() {
                                sent_len += sock_fd.send_to(&encrypted_msg[sent_len..encrypted_msg.len()],addr).unwrap();

                            }
                        }
                    }
                }
                _ => unreachable!()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    #[cfg(target_os = "linux")]
    use std::thread;

    use crate::network::*;

    #[test]
    fn resolve_test(){
        assert_eq!(
            resolve("127.0.0.1").unwrap(),
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn integration_test() {
        assert!(utils::is_root());
        thread::spawn(move || serve(8964, "password", "8.8.8.8".parse::<IpAddr>().unwrap()));
        thread::sleep(time::Duration::from_secs(1));
        assert!(LISTENING.load(Ordering::Relaxed));
        let remote_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127,0,0,1)),8964);
        let local_addr:SocketAddr = "0.0.0.0:0".parse::<SocketAddr>().unwrap();
        let local_socket = UdpSocket::bind(&local_addr).unwrap();
        let (id,_,_) = initiate(&local_socket,&remote_addr,"password").unwrap();
        assert_eq!(id,253);
        let _client = thread::spawn(move || connect("127.0.0.1",8964,false,"password"));
        thread::sleep(time::Duration::from_secs(1));
        assert!(CONNECTED.load(Ordering::Relaxed));
        INTERRUPTED.store(true,Ordering::Relaxed);
    }
}