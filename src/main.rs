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

fn recursive_lookup(qname: &str, qtype: QueryType) -> Result<DnsPacket> {
    // For now we're always starting with *a.root-servers.net*.
    let mut ns = "198.41.0.4".to_string();

    loop {
        println!("Attempting lookup of {:?} {} with ns {}", qtype, qname, ns);

        let ns_copy = ns.clone();

        let server = (ns_copy.as_str(), 53);
        let response = lookup(qname, qtype.clone(), server)?;

        // If there are entries in the answer section, and no errors, we are done!
        if !response.answers.is_empty() && response.header.rescode == ResultCode::Success {
            return Ok(response.clone());
        }

        // We might also get a `NXDOMAIN` reply, which is the authoritative name servers
        // way of telling us that the name doesn't exist.
        if response.header.rescode == ResultCode::NonexistantDomain {
            return Ok(response.clone());
        }

        // Otherwise, we'll try to find a new nameserver based on NS and a corresponding A
        // record in the additional section. If this succeeds, we can switch name server
        // and retry the loop.
        if let Some(new_ns) = response.get_resolved_ns(qname) {
            ns = new_ns.clone();

            continue;
        }

        // If not, we'll have to resolve the ip of a NS record. If no NS records exist,
        // we'll go with what the last server told us.
        let new_ns_name = match response.get_unresolved_ns(qname) {
            Some(x) => x,
            None => return Ok(response.clone()),
        };

        // Here we go down the rabbit hole by starting _another_ lookup sequence in the
        // midst of our current one. Hopefully, this will give us the IP of an appropriate
        // name server.
        let recursive_response = recursive_lookup(&new_ns_name, QueryType::A)?;

        // Finally, we pick a random ip from the result, and restart the loop. If no such
        // record is available, we again return the last result we got.
        if let Some(new_ns) = recursive_response.get_random_a() {
            ns = new_ns.clone();
        } else {
            return Ok(response.clone());
        }
    }
}

fn serve() {
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

            if let Ok(result) = recursive_lookup(&question.name, question.qtype) {
                packet.questions.push(question.clone());
                packet.header.questions = 1;
                packet.header.rescode = result.header.rescode;

                packet.answers = result.answers;
                packet.authorities = result.authorities;
                packet.resources = result.resources;

                packet.header.answers = result.header.answers;
                packet.header.authoritative_entries = result.header.authoritative_entries;
                packet.header.resource_entries = result.header.resource_entries;
            } else {
                packet.header.rescode = ResultCode::ServerFail;
            }

            println!("{:#?}", packet);

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
