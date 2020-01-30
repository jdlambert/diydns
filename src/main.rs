use diydns::{BytePacketBuffer, DnsPacket, DnsQuestion, QueryType};
use std::default::Default;
use std::env;
use std::net::UdpSocket;

fn decode_buffer(buffer: &mut BytePacketBuffer) {
    let packet = buffer.read_packet().unwrap();
    println!("{:#?}", packet.header);

    for q in packet.questions {
        println!("{:#?}", q);
    }
    for rec in packet.answers {
        println!("{:#?}", rec);
    }
    for rec in packet.authorities {
        println!("{:#?}", rec);
    }
    for rec in packet.resources {
        println!("{:#?}", rec);
    }
}

fn decode(args: Vec<String>) {
    let mut buffer = BytePacketBuffer::from_file(args.get(2).unwrap()).unwrap();
    decode_buffer(&mut buffer);
}

fn resolve(args: Vec<String>) {
    let name = args.get(2).unwrap().clone();
    let qtype = QueryType::A;

    let mut packet: DnsPacket = Default::default();

    packet.header.id = 6666;
    packet.header.questions = 1;
    packet.header.recursion_desired = true;
    packet.questions.push(DnsQuestion { name, qtype });

    let mut req_buffer = BytePacketBuffer::new();
    req_buffer.write_packet(packet).unwrap();

    let socket = UdpSocket::bind(("0.0.0.0", 43210)).unwrap();
    socket
        .send_to(&req_buffer.buf[0..req_buffer.pos], ("8.8.8.8", 53))
        .unwrap();

    let mut res_buffer = BytePacketBuffer::new();
    socket.recv_from(&mut res_buffer.buf).unwrap();

    decode_buffer(&mut res_buffer);
}

fn main() {
    let args: Vec<String> = env::args().collect();

    match args[1].as_str() {
        "decode" => decode(args),
        "resolve" => resolve(args),
        _ => {
            println!("Unknown subcommand! Acceptable inputs: decode, resolve");
            return;
        }
    }
}
