use std::fmt::Display;

pub type WintunError = Box<dyn std::error::Error>;

/// Error type used to convey that a value is outside of a range that it must fall inside
#[derive(Debug)]
pub struct OutOfRangeData<T> {
    pub range: std::ops::RangeInclusive<T>,
    pub value: T,
}

/// Error type returned when preconditions of this API are broken
#[derive(Debug)]
pub enum ApiError {
    CapacityNotPowerOfTwo(u32),
    CapacityOutOfRange(OutOfRangeData<u32>),
}

impl Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self {
            ApiError::CapacityOutOfRange(data) => write!(
                f,
                "Capacity {} out of range. Must be within {}..={}",
                data.value,
                data.range.start(),
                data.range.end()
            ),
            ApiError::CapacityNotPowerOfTwo(cap) => {
                write!(f, "Capacity {} is not a power of two", cap)
            }
        }
    }
}

impl std::error::Error for ApiError {}
