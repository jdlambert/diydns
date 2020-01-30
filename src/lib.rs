const MAX_BUFFER_SIZE: usize = 512;

pub struct BytePacketBuffer {
    pub buf: [u8; MAX_BUFFER_SIZE],
    pub pos: usize,
}

impl BytePacketBuffer {
    pub fn new() -> BytePacketBuffer {
        BytePacketBuffer {
            buf: [0; MAX_BUFFER_SIZE],
            pos: 0,
        }
    }

    fn is_in_range(&self, pos: usize) -> Option<()> {
        if pos < MAX_BUFFER_SIZE {
            Some(())
        } else {
            None
        }
    }

    fn get(&self, pos: usize) -> Option<u8> {
        self.is_in_range(pos)?;
        Some(self.buf[pos])
    }

    fn get_range<'a>(&'a self, start: usize, len: usize) -> Option<&'a [u8]> {
        self.is_in_range(start + len)?;
        Some(&self.buf[start..start + len])
    }

    fn read(&mut self) -> Option<u8> {
        self.is_in_range(self.pos)?;
        self.pos += 1;
        Some(self.buf[self.pos - 1])
    }

    fn read_u16(&mut self) -> Option<u16> {
        Some(((self.read()? as u16) << 8) | (self.read()? as u16))
    }

    fn read_u32(&mut self) -> Option<u32> {
        Some(((self.read_u16()? as u32) << 16) | (self.read_u16()? as u32))
    }

    fn read_qname(&mut self) -> Option<String> {
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

        Some(out)
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

#[derive(Clone, Debug)]
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
    pub fn read_header(&mut self) -> Option<DnsHeader> {
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

        Some(DnsHeader {
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
}

#[derive(PartialEq, Eq, Debug, Clone, Hash, Copy)]
pub enum QueryType {
    Unknown(u16),
    A,
}

impl QueryType {
    pub fn to_num(&self) -> u16 {
        match *self {
            QueryType::Unknown(x) => x,
            QueryType::A => 1,
        }
    }

    pub fn from_num(num: u16) -> QueryType {
        match num {
            1 => QueryType::A,
            _ => QueryType::Unknown(num),
        }
    }
}
