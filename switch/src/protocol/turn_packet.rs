

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum Protocol {
    Punch,
    UnKnow(u8),
}

impl From<u8> for Protocol {
    fn from(value: u8) -> Self {
        match value {
            1 => Protocol::Punch,
            val => Protocol::UnKnow(val),
        }
    }
}

impl Into<u8> for Protocol {
    fn into(self) -> u8 {
        match self {
            Protocol::Punch => 1,
            Protocol::UnKnow(val) => val,
        }
    }
}
