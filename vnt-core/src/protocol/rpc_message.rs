mod proto {
    include!(concat!(env!("OUT_DIR"), "/protocol.rpc.rs"));
}
pub use proto::*;
