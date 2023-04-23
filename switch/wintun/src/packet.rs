use crate::session;

use std::sync::Arc;

pub(crate) enum Kind {
    SendPacketPending, //Send packet type, but not sent yet
    SendPacketSent,    //Send packet type - sent
    ReceivePacket,
}

/// Represents a wintun packet
pub struct Packet {
    pub(crate) kind: Kind,

    //This lifetime is not actually 'static, however before you get your pitchforks let me explain...
    //The bytes in this slice live for as long at the session that allocated them, or until
    //WintunReleaseReceivePacket, or WintunSendPacket is called on them (whichever happens first).
    //The wrapper functions that call into WintunReleaseReceivePacket, and WintunSendPacket
    //consume the packet, meaning the end of this packet's lifetime coincides with the end of byte's
    //lifetime. Because we never copy out of bytes, this pointer becomes inaccessible when the
    //packet is dropped.
    //
    //This just leaves packets potentially outliving the session that allocated them posing a
    //problem.
    //Fortunately we have an Arc to the session that allocated this packet, meaning that the lifetime
    //of the session that created this packet is at least as long as the packet.
    //Because this is private (to external users) and we only write to this field when allocating
    //new packets, it is impossible for the memory that is pointed to by bytes to outlive the
    //underlying memory allocated by wintun.
    //
    //So what I told you was true, from a certain point of view.
    //From the point of view of this packet, bytes' lifetime is 'static because we are always
    //dropped before the underlying memory is freed
    //
    //Its also important to know that WintunAllocateSendPacket and WintunReceivePacket always
    //return sections of memory that never overlap, so we have exclusive access to the memory,
    //therefore mut is okay here.
    pub(crate) bytes: &'static mut [u8],

    //Share ownership of session to prevent the session from being dropped before packets that
    //belong to it
    pub(crate) session: Arc<session::Session>,
}

impl Packet {
    /// Returns the bytes this packet holds as &mut.
    /// The lifetime of the bytes is tied to the lifetime of this packet.
    pub fn bytes_mut(&mut self) -> &mut [u8] {
        self.bytes
    }

    /// Returns an immutable reference to the bytes this packet holds.
    /// The lifetime of the bytes is tied to the lifetime of this packet.
    pub fn bytes(&self) -> &[u8] {
        self.bytes
    }
}

impl Drop for Packet {
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
                    self.session
                        .wintun
                        .WintunReleaseReceivePacket(self.session.session.0, self.bytes.as_ptr())
                };
            }
            Kind::SendPacketPending => {
                //If someone allocates a packet with session.allocate_send_packet() and then it is
                //dropped without being sent, this will hold up the send queue because wintun expects
                //that every allocated packet is sent

                #[cfg(feature = "panic_on_unsent_packets")]
                panic!("Packet was never sent!");
            }
            Kind::SendPacketSent => {
                //Nop
            }
        }
    }
}
