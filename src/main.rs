use diydns::BytePacketBuffer;
use std::env;

fn decode(args: Vec<String>) {
    let mut buffer = BytePacketBuffer::from_file(args.get(2).unwrap()).unwrap();

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

fn main() {
    let args: Vec<String> = env::args().collect();

    match args[1].as_str() {
        "decode" => decode(args),
        _ => {
            println!("Unknown subcommand! Acceptable inputs: decode, resolve");
            return;
        }
    }
}
