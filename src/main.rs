use diydns::{BytePacketBuffer, DnsPacket, DnsQuestion, QueryType, Result, ResultCode};
use std::default::Default;
use std::env;
use std::net::UdpSocket;

fn decode(packet: DnsPacket) {
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

fn lookup(name: &str, qtype: QueryType, server: (&str, u16)) -> Result<DnsPacket> {
    let mut packet: DnsPacket = Default::default();
    packet.header.id = 6666;
    packet.header.questions = 1;
    packet.header.recursion_desired = true;
    packet.questions.push(DnsQuestion {
        name: name.to_owned(),
        qtype,
    });

    let mut req_buffer = BytePacketBuffer::new();
    req_buffer.write_packet(packet).unwrap();

    let socket = UdpSocket::bind(("0.0.0.0", 43210)).unwrap();
    socket
        .send_to(&req_buffer.buf[0..req_buffer.pos], server)
        .unwrap();

    let mut res_buffer = BytePacketBuffer::new();
    socket.recv_from(&mut res_buffer.buf).unwrap();

    Ok(res_buffer.read_packet().unwrap())
}

fn serve() {
    let server = ("8.8.8.8", 53);

    let socket = UdpSocket::bind(("0.0.0.0", 2053)).unwrap();

    println!("DNS running on port 2053...");

    loop {
        let mut req_buffer = BytePacketBuffer::new();
        let (_, src) = match socket.recv_from(&mut req_buffer.buf) {
            Ok(x) => x,
            Err(e) => {
                println!("Failed to read from UDP socket: {:?}", e);
                continue;
            }
        };

        let request = match req_buffer.read_packet() {
            Ok(packet) => packet,
            Err(error) => {
                println!("Failed to parse UDP query packet: {:?}", error);
                continue;
            }
        };

        let mut packet: DnsPacket = Default::default();
        packet.header.id = request.header.id;
        packet.header.recursion_desired = true;
        packet.header.recursion_available = true;
        packet.header.response = true;

        if request.questions.is_empty() {
            packet.header.rescode = ResultCode::FormError;
        } else {
            let question = &request.questions[0];
            println!("Received query: {:?}", question);

            if let Ok(result) = lookup(&question.name, question.qtype, server) {
                packet.questions.push(question.clone());
                packet.header.rescode = result.header.rescode;

                for rec in result.answers {
                    println!("Answer: {:?}", rec);
                    packet.answers.push(rec);
                }
                for rec in result.authorities {
                    println!("Authority: {:?}", rec);
                    packet.authorities.push(rec);
                }
                for rec in result.resources {
                    println!("Resource: {:?}", rec);
                    packet.resources.push(rec);
                }
            } else {
                packet.header.rescode = ResultCode::ServerFail;
            }

            let mut res_buffer = BytePacketBuffer::new();
            if let Err(e) = res_buffer.write_packet(packet) {
                println!("Failed to encode UDP response packet: {:?}", e);
                continue;
            };

            let len = res_buffer.pos;
            let data = match res_buffer.get_range(0, len) {
                Ok(x) => x,
                Err(e) => {
                    println!("Failed to retrieve response buffer: {:?}", e);
                    continue;
                }
            };

            if let Err(e) = socket.send_to(data, src) {
                println!("Failed to send response buffer: {:?}", e);
                continue;
            };
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();

    match args[1].as_str() {
        "decode" => {
            let mut buffer = BytePacketBuffer::from_file(args.get(2).unwrap()).unwrap();
            let packet = buffer.read_packet().unwrap();
            decode(packet);
        }
        "resolve" => {
            let name = args.get(2).unwrap();
            let qtype = QueryType::A;
            let server = ("8.8.8.8", 53);
            let packet = lookup(&name, qtype, server).unwrap();
            decode(packet);
        }
        "serve" => serve(),
        _ => {
            println!("Unknown subcommand! Acceptable inputs: decode, resolve, serve");
            return;
        }
    }
}
