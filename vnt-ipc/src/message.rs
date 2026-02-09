mod proto {
    include!(concat!(env!("OUT_DIR"), "/protocol.local_ipc.rs"));
}
pub use proto::*;
