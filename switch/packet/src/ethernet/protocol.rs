/// 以太网帧协议
#[derive(Eq, PartialEq, Copy, Clone, Debug)]
pub enum Protocol {
    ///
    Ipv4,

    ///
    Arp,

    ///
    WakeOnLan,

    ///
    Trill,

    ///
    DecNet,

    ///
    Rarp,

    ///
    AppleTalk,

    ///
    Aarp,

    ///
    Ipx,

    ///
    Qnx,

    ///
    Ipv6,

    ///
    FlowControl,

    ///
    CobraNet,

    ///
    Mpls,

    ///
    MplsMulticast,

    ///
    PppoeDiscovery,

    ///
    PppoeSession,

    ///
    Vlan,

    ///
    PBridge,

    ///
    Lldp,

    ///
    Ptp,

    ///
    Cfm,

    ///
    QinQ,

    ///
    Unknown(u16),
}

impl From<u16> for Protocol {
    fn from(value: u16) -> Protocol {
        use self::Protocol::*;

        match value {
            0x0800 => Ipv4,
            0x0806 => Arp,
            0x0842 => WakeOnLan,
            0x22f3 => Trill,
            0x6003 => DecNet,
            0x8035 => Rarp,
            0x809b => AppleTalk,
            0x80f3 => Aarp,
            0x8137 => Ipx,
            0x8204 => Qnx,
            0x86dd => Ipv6,
            0x8808 => FlowControl,
            0x8819 => CobraNet,
            0x8847 => Mpls,
            0x8848 => MplsMulticast,
            0x8863 => PppoeDiscovery,
            0x8864 => PppoeSession,
            0x8100 => Vlan,
            0x88a8 => PBridge,
            0x88cc => Lldp,
            0x88f7 => Ptp,
            0x8902 => Cfm,
            0x9100 => QinQ,
            n      => Unknown(n),
        }
    }
}

impl Into<u16> for Protocol {
    fn into(self) -> u16 {
        use self::Protocol::*;

        match self {
            Ipv4           => 0x0800,
            Arp            => 0x0806,
            WakeOnLan      => 0x0842,
            Trill          => 0x22f3,
            DecNet         => 0x6003,
            Rarp           => 0x8035,
            AppleTalk      => 0x809b,
            Aarp           => 0x80f3,
            Ipx            => 0x8137,
            Qnx            => 0x8204,
            Ipv6           => 0x86dd,
            FlowControl    => 0x8808,
            CobraNet       => 0x8819,
            Mpls           => 0x8847,
            MplsMulticast  => 0x8848,
            PppoeDiscovery => 0x8863,
            PppoeSession   => 0x8864,
            Vlan           => 0x8100,
            PBridge        => 0x88a8,
            Lldp           => 0x88cc,
            Ptp            => 0x88f7,
            Cfm            => 0x8902,
            QinQ           => 0x9100,
            Unknown(n)     => n,
        }
    }
}
