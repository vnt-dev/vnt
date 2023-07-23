#[derive(Eq, PartialEq,Ord, PartialOrd, Copy, Clone, Debug)]
pub enum Protocol {
    ///
    Hopopt,

    ///
    Icmp,

    ///
    Igmp,

    ///
    Ggp,

    ///
    Ipv4,

    ///
    St,

    ///
    Tcp,

    ///
    Cbt,

    ///
    Egp,

    ///
    Igp,

    ///
    BbnRccMon,

    ///
    NvpII,

    ///
    Pup,

    ///
    Argus,

    ///
    Emcon,

    ///
    Xnet,

    ///
    Chaos,

    ///
    Udp,

    ///
    Mux,

    ///
    DcnMeas,

    ///
    Hmp,

    ///
    Prm,

    ///
    XnsIdp,

    ///
    Trunk1,

    ///
    Trunk2,

    ///
    Leaf1,

    ///
    Leaf2,

    ///
    Rdp,

    ///
    Irtp,

    ///
    IsoTp4,

    ///
    Netblt,

    ///
    MfeNsp,

    ///
    MeritInp,

    ///
    Dccp,

    ///
    ThreePc,

    ///
    Idpr,

    ///
    Xtp,

    ///
    Ddp,

    ///
    IdprCmtp,

    ///
    TpPlusPlus,

    ///
    Il,

    ///
    Ipv6,

    ///
    Sdrp,

    ///
    Ipv6Route,

    ///
    Ipv6Frag,

    ///
    Idrp,

    ///
    Rsvp,

    ///
    Gre,

    ///
    Dsr,

    ///
    Bna,

    ///
    Esp,

    ///
    Ah,

    ///
    INlsp,

    ///
    Swipe,

    ///
    Narp,

    ///
    Mobile,

    ///
    Tlsp,

    ///
    Skip,

    ///
    Ipv6Icmp,

    ///
    Ipv6NoNxt,

    ///
    Ipv6Opts,

    ///
    HostInternal,

    ///
    Cftp,

    ///
    LocalNetwork,

    ///
    SatExpak,

    ///
    Kryptolan,

    ///
    Rvd,

    ///
    Ippc,

    ///
    DistributedFs,

    ///
    SatMon,

    ///
    Visa,

    ///
    Ipcv,

    ///
    Cpnx,

    ///
    Cphb,

    ///
    Wsn,

    ///
    Pvp,

    ///
    BrSatMon,

    ///
    SunNd,

    ///
    WbMon,

    ///
    WbExpak,

    ///
    IsoIp,

    ///
    Vmtp,

    ///
    SecureVmtp,

    ///
    Vines,

    ///
    TtpOrIptm,

    ///
    NsfnetIgp,

    ///
    Dgp,

    ///
    Tcf,

    ///
    Eigrp,

    ///
    OspfigP,

    ///
    SpriteRpc,

    ///
    Larp,

    ///
    Mtp,

    ///
    Ax25,

    ///
    IpIp,

    ///
    Micp,

    ///
    SccSp,

    ///
    Etherip,

    ///
    Encap,

    ///
    PrivEncryption,

    ///
    Gmtp,

    ///
    Ifmp,

    ///
    Pnni,

    ///
    Pim,

    ///
    Aris,

    ///
    Scps,

    ///
    Qnx,

    ///
    AN,

    ///
    IpComp,

    ///
    Snp,

    ///
    CompaqPeer,

    ///
    IpxInIp,

    ///
    Vrrp,

    ///
    Pgm,

    ///
    ZeroHop,

    ///
    L2tp,

    ///
    Ddx,

    ///
    Iatp,

    ///
    Stp,

    ///
    Srp,

    ///
    Uti,

    ///
    Smp,

    ///
    Sm,

    ///
    Ptp,

    ///
    IsisOverIpv4,

    ///
    Fire,

    ///
    Crtp,

    ///
    Crudp,

    ///
    Sscopmce,

    ///
    Iplt,

    ///
    Sps,

    ///
    Pipe,

    ///
    Sctp,

    ///
    Fc,

    ///
    RsvpE2eIgnore,

    ///
    MobilityHeader,

    ///
    UdpLite,

    ///
    MplsInIp,

    ///
    Manet,

    ///
    Hip,

    ///
    Shim6,

    ///
    Wesp,
    Rohc,
    Test1,
    Test2,
    Unknown(u8),
}

impl From<u8> for Protocol {
    fn from(value: u8) -> Protocol {
        use self::Protocol::*;

        match value {
            0 => Hopopt,
            1 => Icmp,
            2 => Igmp,
            3 => Ggp,
            4 => Ipv4,
            5 => St,
            6 => Tcp,
            7 => Cbt,
            8 => Egp,
            9 => Igp,
            10 => BbnRccMon,
            11 => NvpII,
            12 => Pup,
            13 => Argus,
            14 => Emcon,
            15 => Xnet,
            16 => Chaos,
            17 => Udp,
            18 => Mux,
            19 => DcnMeas,
            20 => Hmp,
            21 => Prm,
            22 => XnsIdp,
            23 => Trunk1,
            24 => Trunk2,
            25 => Leaf1,
            26 => Leaf2,
            27 => Rdp,
            28 => Irtp,
            29 => IsoTp4,
            30 => Netblt,
            31 => MfeNsp,
            32 => MeritInp,
            33 => Dccp,
            34 => ThreePc,
            35 => Idpr,
            36 => Xtp,
            37 => Ddp,
            38 => IdprCmtp,
            39 => TpPlusPlus,
            40 => Il,
            41 => Ipv6,
            42 => Sdrp,
            43 => Ipv6Route,
            44 => Ipv6Frag,
            45 => Idrp,
            46 => Rsvp,
            47 => Gre,
            48 => Dsr,
            49 => Bna,
            50 => Esp,
            51 => Ah,
            52 => INlsp,
            53 => Swipe,
            54 => Narp,
            55 => Mobile,
            56 => Tlsp,
            57 => Skip,
            58 => Ipv6Icmp,
            59 => Ipv6NoNxt,
            60 => Ipv6Opts,
            61 => HostInternal,
            62 => Cftp,
            63 => LocalNetwork,
            64 => SatExpak,
            65 => Kryptolan,
            66 => Rvd,
            67 => Ippc,
            68 => DistributedFs,
            69 => SatMon,
            70 => Visa,
            71 => Ipcv,
            72 => Cpnx,
            73 => Cphb,
            74 => Wsn,
            75 => Pvp,
            76 => BrSatMon,
            77 => SunNd,
            78 => WbMon,
            79 => WbExpak,
            80 => IsoIp,
            81 => Vmtp,
            82 => SecureVmtp,
            83 => Vines,
            84 => TtpOrIptm,
            85 => NsfnetIgp,
            86 => Dgp,
            87 => Tcf,
            88 => Eigrp,
            89 => OspfigP,
            90 => SpriteRpc,
            91 => Larp,
            92 => Mtp,
            93 => Ax25,
            94 => IpIp,
            95 => Micp,
            96 => SccSp,
            97 => Etherip,
            98 => Encap,
            99 => PrivEncryption,
            100 => Gmtp,
            101 => Ifmp,
            102 => Pnni,
            103 => Pim,
            104 => Aris,
            105 => Scps,
            106 => Qnx,
            107 => AN,
            108 => IpComp,
            109 => Snp,
            110 => CompaqPeer,
            111 => IpxInIp,
            112 => Vrrp,
            113 => Pgm,
            114 => ZeroHop,
            115 => L2tp,
            116 => Ddx,
            117 => Iatp,
            118 => Stp,
            119 => Srp,
            120 => Uti,
            121 => Smp,
            122 => Sm,
            123 => Ptp,
            124 => IsisOverIpv4,
            125 => Fire,
            126 => Crtp,
            127 => Crudp,
            128 => Sscopmce,
            129 => Iplt,
            130 => Sps,
            131 => Pipe,
            132 => Sctp,
            133 => Fc,
            134 => RsvpE2eIgnore,
            135 => MobilityHeader,
            136 => UdpLite,
            137 => MplsInIp,
            138 => Manet,
            139 => Hip,
            140 => Shim6,
            141 => Wesp,
            142 => Rohc,
            253 => Test1,
            254 => Test2,
            p => Unknown(p),
        }
    }
}

impl Into<u8> for Protocol {
    fn into(self) -> u8 {
        use self::Protocol::*;

        match self {
            Hopopt => 0,
            Icmp => 1,
            Igmp => 2,
            Ggp => 3,
            Ipv4 => 4,
            St => 5,
            Tcp => 6,
            Cbt => 7,
            Egp => 8,
            Igp => 9,
            BbnRccMon => 10,
            NvpII => 11,
            Pup => 12,
            Argus => 13,
            Emcon => 14,
            Xnet => 15,
            Chaos => 16,
            Udp => 17,
            Mux => 18,
            DcnMeas => 19,
            Hmp => 20,
            Prm => 21,
            XnsIdp => 22,
            Trunk1 => 23,
            Trunk2 => 24,
            Leaf1 => 25,
            Leaf2 => 26,
            Rdp => 27,
            Irtp => 28,
            IsoTp4 => 29,
            Netblt => 30,
            MfeNsp => 31,
            MeritInp => 32,
            Dccp => 33,
            ThreePc => 34,
            Idpr => 35,
            Xtp => 36,
            Ddp => 37,
            IdprCmtp => 38,
            TpPlusPlus => 39,
            Il => 40,
            Ipv6 => 41,
            Sdrp => 42,
            Ipv6Route => 43,
            Ipv6Frag => 44,
            Idrp => 45,
            Rsvp => 46,
            Gre => 47,
            Dsr => 48,
            Bna => 49,
            Esp => 50,
            Ah => 51,
            INlsp => 52,
            Swipe => 53,
            Narp => 54,
            Mobile => 55,
            Tlsp => 56,
            Skip => 57,
            Ipv6Icmp => 58,
            Ipv6NoNxt => 59,
            Ipv6Opts => 60,
            HostInternal => 61,
            Cftp => 62,
            LocalNetwork => 63,
            SatExpak => 64,
            Kryptolan => 65,
            Rvd => 66,
            Ippc => 67,
            DistributedFs => 68,
            SatMon => 69,
            Visa => 70,
            Ipcv => 71,
            Cpnx => 72,
            Cphb => 73,
            Wsn => 74,
            Pvp => 75,
            BrSatMon => 76,
            SunNd => 77,
            WbMon => 78,
            WbExpak => 79,
            IsoIp => 80,
            Vmtp => 81,
            SecureVmtp => 82,
            Vines => 83,
            TtpOrIptm => 84,
            NsfnetIgp => 85,
            Dgp => 86,
            Tcf => 87,
            Eigrp => 88,
            OspfigP => 89,
            SpriteRpc => 90,
            Larp => 91,
            Mtp => 92,
            Ax25 => 93,
            IpIp => 94,
            Micp => 95,
            SccSp => 96,
            Etherip => 97,
            Encap => 98,
            PrivEncryption => 99,
            Gmtp => 100,
            Ifmp => 101,
            Pnni => 102,
            Pim => 103,
            Aris => 104,
            Scps => 105,
            Qnx => 106,
            AN => 107,
            IpComp => 108,
            Snp => 109,
            CompaqPeer => 110,
            IpxInIp => 111,
            Vrrp => 112,
            Pgm => 113,
            ZeroHop => 114,
            L2tp => 115,
            Ddx => 116,
            Iatp => 117,
            Stp => 118,
            Srp => 119,
            Uti => 120,
            Smp => 121,
            Sm => 122,
            Ptp => 123,
            IsisOverIpv4 => 124,
            Fire => 125,
            Crtp => 126,
            Crudp => 127,
            Sscopmce => 128,
            Iplt => 129,
            Sps => 130,
            Pipe => 131,
            Sctp => 132,
            Fc => 133,
            RsvpE2eIgnore => 134,
            MobilityHeader => 135,
            UdpLite => 136,
            MplsInIp => 137,
            Manet => 138,
            Hip => 139,
            Shim6 => 140,
            Wesp => 141,
            Rohc => 142,
            Test1 => 253,
            Test2 => 254,
            Unknown(p) => p,
        }
    }
}
