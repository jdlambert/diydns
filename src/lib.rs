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
