use std::fmt;

pub mod tcp;

pub struct Flags(u8);

pub const FIN: u8 = 0b0000_0001;
pub const SYN: u8 = 0b0000_0010;
pub const RST: u8 = 0b0000_0100;
pub const PSH: u8 = 0b0000_1000;
pub const ACK: u8 = 0b0001_0000;
pub const URG: u8 = 0b0010_0000;

impl fmt::Debug for Flags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut str = String::with_capacity(22);
        if self.0 & URG != 0 {
            str.push_str("URG|");
        }
        if self.0 & ACK != 0 {
            str.push_str("ACK|");
        }
        if self.0 & PSH != 0 {
            str.push_str("PSH|");
        }
        if self.0 & RST != 0 {
            str.push_str("RST|");
        }
        if self.0 & SYN != 0 {
            str.push_str("SYN|");
        }
        if self.0 & FIN != 0 {
            str.push_str("FIN|");
        }
        if str.is_empty() {
            f.debug_struct("NULL").finish()
        } else {
            let len = str.len() - 1;
            f.debug_struct(&str[..len]).finish()
        }
    }
}
