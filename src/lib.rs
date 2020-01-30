use std::default::Default;
use std::fs::File;
use std::io::{Error, ErrorKind, Read};
use std::iter;
use std::net::{Ipv4Addr, Ipv6Addr};

const MAX_BUFFER_SIZE: usize = 512;

pub struct BytePacketBuffer {
    pub buf: [u8; MAX_BUFFER_SIZE],
    pub pos: usize,
}

type Result<T> = std::result::Result<T, Error>;

impl BytePacketBuffer {
    pub fn new() -> BytePacketBuffer {
        BytePacketBuffer {
            pos: 0,
            buf: [0; MAX_BUFFER_SIZE],
        }
    }

    pub fn from_file(filename: &str) -> Result<BytePacketBuffer> {
        let mut file = File::open(filename).unwrap();
        let mut buf = [0; MAX_BUFFER_SIZE];
        file.read(&mut buf).unwrap();

        Ok(BytePacketBuffer { buf, pos: 0 })
    }

    fn is_in_range(&self, pos: usize) -> Result<()> {
        if pos < MAX_BUFFER_SIZE {
            Ok(())
        } else {
            Err(Error::new(
                ErrorKind::InvalidInput,
                "Unexpected end of buffer!",
            ))
        }
    }

    fn get(&self, pos: usize) -> Result<u8> {
        self.is_in_range(pos)?;
        Ok(self.buf[pos])
    }

    fn get_range<'a>(&'a self, start: usize, len: usize) -> Result<&'a [u8]> {
        self.is_in_range(start + len)?;
        Ok(&self.buf[start..start + len])
    }

    fn read(&mut self) -> Result<u8> {
        self.is_in_range(self.pos)?;
        self.pos += 1;
        Ok(self.buf[self.pos - 1])
    }

    fn read_u16(&mut self) -> Result<u16> {
        Ok(((self.read()? as u16) << 8) | (self.read()? as u16))
    }

    fn read_u32(&mut self) -> Result<u32> {
        Ok(((self.read_u16()? as u32) << 16) | (self.read_u16()? as u32))
    }

    fn read_qname(&mut self) -> Result<String> {
        let mut qname_pos = self.pos;
        let mut jumped = false;
        let mut first = true;
        let mut out = String::new();

        loop {
            let len = self.get(qname_pos)? as usize;

            if (len & 0xC0) == 0xC0 {
                if !jumped {
                    self.pos = qname_pos + 2;
                }

                let second_byte = self.get(qname_pos + 1)? as usize;
                qname_pos = ((len ^ 0xC0) << 8) | second_byte;
                jumped = true;
            } else {
                qname_pos += 1;

                if len == 0 {
                    break;
                }

                if first {
                    first = false;
                } else {
                    out.push_str(".");
                }

                let str_buffer = self.get_range(qname_pos, len)?;
                out.push_str(&String::from_utf8_lossy(str_buffer).to_lowercase());
                qname_pos += len;
            }
        }

        if !jumped {
            self.pos = qname_pos;
        }

        Ok(out)
    }

    fn write(&mut self, val: u8) -> Result<()> {
        self.is_in_range(self.pos)?;
        self.buf[self.pos] = val;
        self.pos += 1;
        Ok(())
    }

    fn write_u16(&mut self, val: u16) -> Result<()> {
        self.write((val >> 8) as u8)?;
        self.write((val & 0xFF) as u8)?;

        Ok(())
    }

    fn write_u32(&mut self, val: u32) -> Result<()> {
        self.write_u16(((val >> 16) & 0xFFFF) as u16)?;
        self.write_u16((val & 0xFFFF) as u16)?;

        Ok(())
    }

    fn write_qname(&mut self, qname: &str) -> Result<()> {
        for label in qname.split('.') {
            let len = label.len();
            if len > 0x34 {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "Label exceeds 63 characters of length",
                ));
            }

            self.write(len as u8)?;
            for b in label.as_bytes() {
                self.write(*b)?;
            }
        }

        self.write(0)
    }

    fn set(&mut self, pos: usize, val: u8) -> Result<()> {
        self.is_in_range(pos)?;
        self.buf[pos] = val;

        Ok(())
    }

    fn set_u16(&mut self, pos: usize, val: u16) -> Result<()> {
        self.set(pos, (val >> 8) as u8)?;
        self.set(pos + 1, (val & 0xFF) as u8)?;

        Ok(())
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ResultCode {
    Success,
    FormError,
    ServerFail,
    NonexistantDomain,
    NotImplemented,
    Refused,
}

impl Default for ResultCode {
    fn default() -> Self {
        ResultCode::Success
    }
}

impl ResultCode {
    pub fn from_num(num: u8) -> ResultCode {
        match num {
            1 => ResultCode::FormError,
            2 => ResultCode::ServerFail,
            3 => ResultCode::NonexistantDomain,
            4 => ResultCode::NotImplemented,
            5 => ResultCode::Refused,
            0 => ResultCode::Success,
            _ => unreachable!(),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct DnsHeader {
    pub id: u16, // 16 bits

    pub recursion_desired: bool,    // 1 bit
    pub truncated_message: bool,    // 1 bit
    pub authoritative_answer: bool, // 1 bit
    pub opcode: u8,                 // 4 bits
    pub response: bool,             // 1 bit

    pub rescode: ResultCode,       // 4 bits
    pub checking_disabled: bool,   // 1 bit
    pub authed_data: bool,         // 1 bit
    pub z: bool,                   // 1 bit
    pub recursion_available: bool, // 1 bit

    pub questions: u16,             // 16 bits
    pub answers: u16,               // 16 bits
    pub authoritative_entries: u16, // 16 bits
    pub resource_entries: u16,      // 16 bits
}

impl BytePacketBuffer {
    pub fn read_header(&mut self) -> Result<DnsHeader> {
        let id = self.read_u16()?;

        let flags = self.read_u16()?;
        let a = (flags >> 8) as u8;
        let b = (flags & 0xFF) as u8;
        let recursion_desired = (a & (1 << 0)) > 0;
        let truncated_message = (a & (1 << 1)) > 0;
        let authoritative_answer = (a & (1 << 2)) > 0;
        let opcode = (a >> 3) & 0x0F;
        let response = (a & (1 << 7)) > 0;

        let rescode = ResultCode::from_num(b & 0x0F);
        let checking_disabled = (b & (1 << 4)) > 0;
        let authed_data = (b & (1 << 5)) > 0;
        let z = (b & (1 << 6)) > 0;
        let recursion_available = (b & (1 << 7)) > 0;

        let questions = self.read_u16()?;
        let answers = self.read_u16()?;
        let authoritative_entries = self.read_u16()?;
        let resource_entries = self.read_u16()?;

        Ok(DnsHeader {
            id,
            recursion_desired,
            truncated_message,
            authoritative_answer,
            opcode,
            response,
            rescode,
            checking_disabled,
            authed_data,
            z,
            recursion_available,
            questions,
            answers,
            authoritative_entries,
            resource_entries,
        })
    }

    pub fn write_header(&mut self, header: DnsHeader) -> Result<()> {
        self.write_u16(header.id)?;

        self.write(
            (header.recursion_desired as u8)
                | ((header.truncated_message as u8) << 1)
                | ((header.authoritative_answer as u8) << 2)
                | (header.opcode << 3)
                | ((header.response as u8) << 7) as u8,
        )?;

        self.write(
            (header.rescode as u8)
                | ((header.checking_disabled as u8) << 4)
                | ((header.authed_data as u8) << 5)
                | ((header.z as u8) << 6)
                | ((header.recursion_available as u8) << 7),
        )?;

        self.write_u16(header.questions)?;
        self.write_u16(header.answers)?;
        self.write_u16(header.authoritative_entries)?;
        self.write_u16(header.resource_entries)
    }
}

#[derive(PartialEq, Eq, Debug, Clone, Hash, Copy)]
pub enum QueryType {
    Unknown(u16),
    A,
    NS,
    CNAME,
    MX,
    AAAA,
}

impl QueryType {
    pub fn to_num(&self) -> u16 {
        match *self {
            QueryType::Unknown(x) => x,
            QueryType::A => 1,
            QueryType::NS => 2,
            QueryType::CNAME => 5,
            QueryType::MX => 15,
            QueryType::AAAA => 28,
        }
    }

    pub fn from_num(num: u16) -> QueryType {
        match num {
            1 => QueryType::A,
            2 => QueryType::NS,
            5 => QueryType::CNAME,
            15 => QueryType::MX,
            28 => QueryType::AAAA,
            _ => QueryType::Unknown(num),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: QueryType,
}

impl BytePacketBuffer {
    pub fn read_question(&mut self) -> Result<DnsQuestion> {
        let name = self.read_qname()?;
        let qtype = QueryType::from_num(self.read_u16()?);
        self.read_u16()?; // class, which we ignore

        Ok(DnsQuestion { name, qtype })
    }

    pub fn write_question(&mut self, question: DnsQuestion) -> Result<()> {
        self.write_qname(&question.name)?;

        self.write_u16(question.qtype.to_num())?;
        self.write_u16(1)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DnsRecord {
    Unknown {
        domain: String,
        qtype: u16,
        data_len: u16,
        ttl: u32,
    },
    A {
        domain: String,
        addr: Ipv4Addr,
        ttl: u32,
    },
    NS {
        domain: String,
        host: String,
        ttl: u32,
    },
    CNAME {
        domain: String,
        host: String,
        ttl: u32,
    },
    MX {
        domain: String,
        priority: u16,
        host: String,
        ttl: u32,
    },
    AAAA {
        domain: String,
        addr: Ipv6Addr,
        ttl: u32,
    },
}

impl BytePacketBuffer {
    pub fn read_record(&mut self) -> Result<DnsRecord> {
        let domain = self.read_qname()?;

        let qtype = QueryType::from_num(self.read_u16()?);
        self.read_u16()?; // class, which we ignore
        let ttl = self.read_u32()?;
        let data_len = self.read_u16()?;

        Ok(match qtype {
            QueryType::A => DnsRecord::A {
                domain,
                ttl,
                addr: Ipv4Addr::from(self.read_u32()?),
            },
            QueryType::AAAA => DnsRecord::AAAA {
                domain,
                ttl,
                addr: Ipv6Addr::new(
                    self.read_u16()?,
                    self.read_u16()?,
                    self.read_u16()?,
                    self.read_u16()?,
                    self.read_u16()?,
                    self.read_u16()?,
                    self.read_u16()?,
                    self.read_u16()?,
                ),
            },
            QueryType::NS => DnsRecord::NS {
                domain,
                ttl,
                host: self.read_qname()?,
            },
            QueryType::CNAME => DnsRecord::CNAME {
                domain,
                ttl,
                host: self.read_qname()?,
            },
            QueryType::MX => DnsRecord::MX {
                domain: domain,
                priority: self.read_u16()?,
                host: self.read_qname()?,
                ttl: ttl,
            },
            QueryType::Unknown(qtype) => {
                self.pos += data_len as usize;

                DnsRecord::Unknown {
                    domain,
                    qtype,
                    data_len,
                    ttl,
                }
            }
        })
    }

    pub fn write_record(&mut self, record: DnsRecord) -> Result<usize> {
        let start_pos = self.pos;

        match record {
            DnsRecord::A { domain, addr, ttl } => {
                self.write_qname(&domain)?;
                self.write_u16(QueryType::A.to_num())?;
                self.write_u16(1)?;
                self.write_u32(ttl)?;
                self.write_u16(4)?;

                for octet in addr.octets().iter() {
                    self.write(*octet)?;
                }
            }
            DnsRecord::NS {
                ref domain,
                ref host,
                ttl,
            } => {
                self.write_qname(domain)?;
                self.write_u16(QueryType::NS.to_num())?;
                self.write_u16(1)?;
                self.write_u32(ttl)?;

                let pos = self.pos;
                self.write_u16(0)?;

                self.write_qname(host)?;

                let size = self.pos - (pos + 2);
                self.set_u16(pos, size as u16)?;
            }
            DnsRecord::CNAME {
                ref domain,
                ref host,
                ttl,
            } => {
                self.write_qname(domain)?;
                self.write_u16(QueryType::CNAME.to_num())?;
                self.write_u16(1)?;
                self.write_u32(ttl)?;

                let pos = self.pos;
                self.write_u16(0)?;

                self.write_qname(host)?;

                let size = self.pos - (pos + 2);
                self.set_u16(pos, size as u16)?;
            }
            DnsRecord::MX {
                ref domain,
                priority,
                ref host,
                ttl,
            } => {
                self.write_qname(domain)?;
                self.write_u16(QueryType::MX.to_num())?;
                self.write_u16(1)?;
                self.write_u32(ttl)?;

                let pos = self.pos;
                self.write_u16(0)?;

                self.write_u16(priority)?;
                self.write_qname(host)?;

                let size = self.pos - (pos + 2);
                self.set_u16(pos, size as u16)?;
            }
            DnsRecord::AAAA {
                ref domain,
                ref addr,
                ttl,
            } => {
                self.write_qname(domain)?;
                self.write_u16(QueryType::AAAA.to_num())?;
                self.write_u16(1)?;
                self.write_u32(ttl)?;
                self.write_u16(16)?;

                for octet in &addr.segments() {
                    self.write_u16(*octet)?;
                }
            }
            _ => {
                println!("Skipping record: {:#?}", record);
            }
        }

        Ok(self.pos - start_pos)
    }
}

#[derive(Clone, Debug, Default)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub resources: Vec<DnsRecord>,
}

impl BytePacketBuffer {
    pub fn read_packet(&mut self) -> Result<DnsPacket> {
        let header = self.read_header()?;

        let questions = iter::repeat_with(|| self.read_question().unwrap())
            .take(header.questions as usize)
            .collect();
        let answers = iter::repeat_with(|| self.read_record().unwrap())
            .take(header.answers as usize)
            .collect();
        let authorities = iter::repeat_with(|| self.read_record().unwrap())
            .take(header.authoritative_entries as usize)
            .collect();
        let resources = iter::repeat_with(|| self.read_record().unwrap())
            .take(header.resource_entries as usize)
            .collect();

        Ok(DnsPacket {
            header,
            questions,
            answers,
            authorities,
            resources,
        })
    }

    pub fn write_packet(&mut self, packet: DnsPacket) -> Result<()> {
        self.write_header(packet.header)?;

        for question in packet.questions {
            self.write_question(question)?;
        }
        for rec in packet.answers {
            self.write_record(rec)?;
        }
        for rec in packet.authorities {
            self.write_record(rec)?;
        }
        for rec in packet.resources {
            self.write_record(rec)?;
        }

        Ok(())
    }
}
