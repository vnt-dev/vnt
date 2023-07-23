pub mod icmp;

#[derive(Eq, PartialEq, Copy, Clone, Debug)]
pub enum Kind {
    /// ping应答，type=0
    /*
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Type      |     Code      |          Checksum             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |           Identifier          |        Sequence Number        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Data ...
    +-+-+-+-+-
      */
    EchoReply,
    /// 目的地不可达，差错报文的一种，路由器收到一个不能转发的数据报，会向源地址返回这个报文，type=3
    /*
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Type      |     Code      |          Checksum             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                             unused                            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |      Internet Header + 64 bits of Original Data Datagram      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      */
    DestinationUnreachable,
    /// 源抑制报文，用于防止接收端缓存溢出，接收设备发送这个来请求源设备降低发送速度，type=4
    /*
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Type      |     Code      |          Checksum             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                             unused                            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |      Internet Header + 64 bits of Original Data Datagram      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      */
    SourceQuench,
    /// 重定向报文，当路由器接收包的接口正好是去往目的地的出口时，会向源地址发送重定向报文，告知源直接将数据发往自己的下一跳，type=5
    /*
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Type      |     Code      |          Checksum             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                 Gateway Internet Address                      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |      Internet Header + 64 bits of Original Data Datagram      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      */
    Redirect,
    /// ping请求，type=8
    EchoRequest,
    /// 路由器通告,type=9,
    RouterAdvertisement,
    /// 路由器请求,type=10
    RouterSolicitation,
    /// 报文ttl为0后，路由器会向源发送此报文，type=11
    /// Tracert工作原理：
    /// 首先向目的地发送ttl=1的包，下一跳路由器收到后ttl-1，此时ttl=0，将向源发送 ICMP time exceeded
    /// 再发送ttl=2的包，以此类推，直到目标主机接收到改包，此时不会回复ICMP time exceeded，代表已经探测到目的地
    /*

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Type      |     Code      |          Checksum             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                             unused                            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |      Internet Header + 64 bits of Original Data Datagram      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      */
    TimeExceeded,
    /// 参数错误，数据有误、校验和不对等，type=12
    /*

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Type      |     Code      |          Checksum             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |    Pointer    |                   unused                      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |      Internet Header + 64 bits of Original Data Datagram      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    注：Pointer指示错误的位置
      */
    ParameterProblem,
    /// 时间戳请求,type=13
    /*
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Type      |      Code     |          Checksum             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |           Identifier          |        Sequence Number        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Originate Timestamp                                       |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Receive Timestamp                                         |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Transmit Timestamp                                        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      */
    TimestampRequest,
    /// 时间戳响应,type=14
    TimestampReply,
    /// 信息请求，type=15
    /*
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Type      |      Code     |          Checksum             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |           Identifier          |        Sequence Number        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      */
    InformationRequest,
    /// 信息响应，type=16
    InformationReply,
    /// 地址掩码请求，type=17
    AddressMaskRequest,
    /// 地址掩码应答，type=18
    AddressMaskReply,
    ///
    TraceRoute,
    ///
    Unknown(u8),
}

impl From<u8> for Kind {
    fn from(value: u8) -> Kind {
        use self::Kind::*;

        match value {
            0 => EchoReply,
            3 => DestinationUnreachable,
            4 => SourceQuench,
            5 => Redirect,
            8 => EchoRequest,
            9 => RouterAdvertisement,
            10 => RouterSolicitation,
            11 => TimeExceeded,
            12 => ParameterProblem,
            13 => TimestampRequest,
            14 => TimestampReply,
            15 => InformationRequest,
            16 => InformationReply,
            17 => AddressMaskRequest,
            18 => AddressMaskReply,
            30 => TraceRoute,
            v => Unknown(v),
        }
    }
}

impl Into<u8> for Kind {
    fn into(self) -> u8 {
        use self::Kind::*;
        match self {
            EchoReply => 0,
            DestinationUnreachable => 3,
            SourceQuench => 4,
            Redirect => 5,
            EchoRequest => 8,
            RouterAdvertisement => 9,
            RouterSolicitation => 10,
            TimeExceeded => 11,
            ParameterProblem => 12,
            TimestampRequest => 13,
            TimestampReply => 14,
            InformationRequest => 15,
            InformationReply => 16,
            AddressMaskRequest => 17,
            AddressMaskReply => 18,
            TraceRoute => 30,
            Unknown(v) => v,
        }
    }
}

#[derive(Eq, PartialEq, Copy, Clone, Debug)]
pub enum Code {
    DestinationUnreachable(DestinationUnreachable),
    Redirect(Redirect),
    ParameterProblem(ParameterProblem),
    Other(u8),
}

impl Code {
    pub fn from(kind: Kind, code: u8) -> Code {
        match kind {
            Kind::DestinationUnreachable => {
                Code::DestinationUnreachable(DestinationUnreachable::from(code))
            }
            Kind::Redirect => Code::Redirect(Redirect::from(code)),
            Kind::ParameterProblem => Code::ParameterProblem(ParameterProblem::from(code)),
            _ => Code::Other(code),
        }
    }
}

#[derive(Eq, PartialEq, Copy, Clone, Debug)]
pub enum DestinationUnreachable {
    /// 网络不可达
    DestinationNetworkUnreachable,
    /// 主机不可达
    DestinationHostUnreachable,
    /// 协议不可达
    DestinationProtocolUnreachable,
    /// 端口不可达
    DestinationPortUnreachable,
    /// 需要进行分片但设置不分片比特
    FragmentationRequired,
    /// 源站选路失败
    SourceRouteFailed,
    /// 目的网络未知
    DestinationNetworkUnknown,
    /// 目的主机未知
    DestinationHostUnknown,
    /// 源主机被隔离（作废不用）
    SourceHostIsolated,
    /// 目的网络被强制禁止
    NetworkAdministrativelyProhibited,
    /// 目的主机被强制禁止
    HostAdministrativelyProhibited,
    /// 由于服务类型TOS，网络不可达
    NetworkUnreachableForTos,
    /// 由于服务类型TOS，主机不可达
    HostUnreachableForTos,
    /// 由于过滤，通信被强制禁止
    CommunicationAdministrativelyProhibited,
    /// 主机越权
    HostPrecedenceViolation,
    /// 优先中止生效
    PrecedentCutoffInEffect,
    ///
    Unknown(u8),
}

/// Codes for Redirect Message packets.
#[derive(Eq, PartialEq, Copy, Clone, Debug)]
pub enum Redirect {
    /// 对网络重定向
    RedirectDatagramForNetwork,
    /// 对主机重定向
    RedirectDatagramForHost,
    /// 对服务类型和网络重定向
    RedirectDatagramForTosAndNetwork,
    /// 对服务类型和主机重定向
    RedirectDatagramForTosAndHost,
    ///
    Unknown(u8),
}

/// Codes for TimeExceeded Message packets.
#[derive(Eq, PartialEq, Copy, Clone, Debug)]
pub enum TimeExceeded {
    /// TTL超时报文
    Transit,
    /// 分片重组超时报文
    Reassembly,
    ///
    Unknown(u8),
}
/// Codes for Parameter Problem packets.
#[derive(Eq, PartialEq, Copy, Clone, Debug)]
pub enum ParameterProblem {
    /// 坏的IP首部（包括各种差错）
    PointerIndicatesError,
    /// 缺少必需的选项
    MissingRequiredData,
    /// 长度错误
    BadLength,
    ///
    Unknown(u8),
}

impl From<u8> for DestinationUnreachable {
    fn from(value: u8) -> Self {
        use self::DestinationUnreachable::*;

        match value {
            0 => DestinationNetworkUnreachable,
            1 => DestinationHostUnreachable,
            2 => DestinationProtocolUnreachable,
            3 => DestinationPortUnreachable,
            4 => FragmentationRequired,
            5 => SourceRouteFailed,
            6 => DestinationNetworkUnknown,
            7 => DestinationHostUnknown,
            8 => SourceHostIsolated,
            9 => NetworkAdministrativelyProhibited,
            10 => HostAdministrativelyProhibited,
            11 => NetworkUnreachableForTos,
            12 => HostUnreachableForTos,
            13 => CommunicationAdministrativelyProhibited,
            14 => HostPrecedenceViolation,
            15 => PrecedentCutoffInEffect,
            v => Unknown(v),
        }
    }
}

impl Into<u8> for DestinationUnreachable {
    fn into(self) -> u8 {
        use self::DestinationUnreachable::*;

        match self {
            DestinationNetworkUnreachable => 0,
            DestinationHostUnreachable => 1,
            DestinationProtocolUnreachable => 2,
            DestinationPortUnreachable => 3,
            FragmentationRequired => 4,
            SourceRouteFailed => 5,
            DestinationNetworkUnknown => 6,
            DestinationHostUnknown => 7,
            SourceHostIsolated => 8,
            NetworkAdministrativelyProhibited => 9,
            HostAdministrativelyProhibited => 10,
            NetworkUnreachableForTos => 11,
            HostUnreachableForTos => 12,
            CommunicationAdministrativelyProhibited => 13,
            HostPrecedenceViolation => 14,
            PrecedentCutoffInEffect => 15,
            Unknown(v) => v,
        }
    }
}

impl From<u8> for Redirect {
    fn from(value: u8) -> Self {
        use self::Redirect::*;

        match value {
            0 => RedirectDatagramForNetwork,
            1 => RedirectDatagramForHost,
            2 => RedirectDatagramForTosAndNetwork,
            3 => RedirectDatagramForTosAndHost,
            v => Unknown(v),
        }
    }
}

impl Into<u8> for Redirect {
    fn into(self) -> u8 {
        use self::Redirect::*;

        match self {
            RedirectDatagramForNetwork => 0,
            RedirectDatagramForHost => 1,
            RedirectDatagramForTosAndNetwork => 2,
            RedirectDatagramForTosAndHost => 3,
            Unknown(v) => v,
        }
    }
}

impl From<u8> for TimeExceeded {
    fn from(value: u8) -> Self {
        use self::TimeExceeded::*;

        match value {
            0 => Transit,
            1 => Reassembly,
            v => Unknown(v),
        }
    }
}

impl Into<u8> for TimeExceeded {
    fn into(self) -> u8 {
        use self::TimeExceeded::*;

        match self {
            Transit => 0,
            Reassembly => 1,
            Unknown(v) => v,
        }
    }
}

impl From<u8> for ParameterProblem {
    fn from(value: u8) -> Self {
        use self::ParameterProblem::*;

        match value {
            0 => PointerIndicatesError,
            1 => MissingRequiredData,
            2 => BadLength,
            v => Unknown(v),
        }
    }
}

impl Into<u8> for ParameterProblem {
    fn into(self) -> u8 {
        use self::ParameterProblem::*;

        match self {
            PointerIndicatesError => 0,
            MissingRequiredData => 1,
            BadLength => 2,
            Unknown(v) => v,
        }
    }
}
