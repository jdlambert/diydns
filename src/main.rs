

use diydns::BytePacketBuffer;
use std::env::args;

fn main() {

    let args: Vec<String> = args().collect();
    let mut buffer = BytePacketBuffer::from_file(args.get(1).unwrap()).unwrap();

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
