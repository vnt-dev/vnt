use std::io;

pub trait DeviceWrite: Clone + Send + Sync + 'static {
    fn write(&self, buf: &[u8]) -> io::Result<usize>;
    #[cfg(feature = "integrated_tun")]
    fn into_device_adapter(self) -> crate::tun_tap_device::tun_create_helper::DeviceAdapter;
}
