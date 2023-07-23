
use crate::TunDevice;

pub(crate) enum Kind {
    SendPacketPending,
    //Send packet type, but not sent yet
    SendPacketSent,
    //Send packet type - sent
    ReceivePacket,
}

/// Represents a wintun packet
pub struct TunPacket<'a> {
    pub(crate) kind: Kind,
    pub(crate) size:usize,
    pub(crate) bytes_ptr: *const u8,

    //Share ownership of session to prevent the session from being dropped before packets that
    //belong to it
    pub(crate) tun_device: Option<&'a TunDevice>,
}

impl <'a>TunPacket<'a> {
    /// Returns the bytes this packet holds as &mut.
    /// The lifetime of the bytes is tied to the lifetime of this packet.
    pub fn bytes_mut(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.bytes_ptr as *mut u8, self.size) }
    }

    /// Returns an immutable reference to the bytes this packet holds.
    /// The lifetime of the bytes is tied to the lifetime of this packet.
    pub fn bytes(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.bytes_ptr,self.size) }
    }
}

impl <'a>Drop for TunPacket<'a> {
    fn drop(&mut self) {
        match self.kind {
            Kind::ReceivePacket => {
                unsafe {
                    //SAFETY:
                    //
                    //  1. We share ownership of the session therefore it hasn't been dropped yet
                    //  2. Bytes is valid because each packet holds exclusive access to a region of the
                    //     ring buffer that the wintun session owns. We return that region of
                    //     memory back to wintun here
                    let tun_device = self.tun_device.unwrap();
                    tun_device.win_tun
                        .WintunReleaseReceivePacket(tun_device.session, self.bytes_ptr)
                };
            }
            Kind::SendPacketPending => {
                //If someone allocates a packet with session.allocate_send_packet() and then it is
                //dropped without being sent, this will hold up the send queue because wintun expects
                //that every allocated packet is sent
                panic!("Packet was never sent!");
            }
            Kind::SendPacketSent => {
                //Nop
            }
        }
    }
}
