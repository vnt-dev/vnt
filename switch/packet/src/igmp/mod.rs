pub mod igmp_v1;
pub mod igmp_v2;
pub mod igmp_v3;

#[derive(Debug,Copy, Clone,Eq, PartialEq)]
pub enum IgmpType {
    /// 0x11 所有组224.0.0.1或者特定组
    Query,
    /// 0x12
    ReportV1,
    /// 0x16
    ReportV2,
    /// 0x22
    ReportV3,
    /// 0x17 目标组固定是 224.0.0.2
    LeaveV2,
    Unknown(u8),
}

impl From<u8> for IgmpType {
    fn from(value: u8) -> IgmpType {
        use self::IgmpType::*;

        match value {
            0x11 => Query,
            0x12 => ReportV1,
            0x16 => ReportV2,
            0x22 => ReportV3,
            0x17 => LeaveV2,
            v => Unknown(v),
        }
    }
}

impl Into<u8> for IgmpType {
    fn into(self) -> u8 {
        match self {
            IgmpType::Query => 0x11,
            IgmpType::ReportV1 => 0x12,
            IgmpType::ReportV2 => 0x16,
            IgmpType::ReportV3 => 0x22,
            IgmpType::LeaveV2 => 0x17,
            IgmpType::Unknown(v) => v
        }
    }
}