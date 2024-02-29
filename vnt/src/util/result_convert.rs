use std::fmt::Display;
use std::io;

#[inline]
pub fn io_convert<T, R: Display, F: FnOnce(&io::Error) -> R>(
    rs: io::Result<T>,
    f: F,
) -> io::Result<T> {
    rs.map_err(|e| io::Error::new(e.kind(), format!("{},internal error:{:?}", f(&e), e)))
}
