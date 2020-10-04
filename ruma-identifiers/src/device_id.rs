//! Matrix device identifiers.

#[cfg(feature = "rand")]
use crate::generate_localpart;

/// A Matrix key ID.
///
/// Device identifiers in Matrix are completely opaque character sequences. This type is provided
/// simply for its semantic value.
#[repr(transparent)]
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde1::Serialize), serde(transparent, crate = "serde1"))]
pub struct DeviceId(str);

opaque_identifier!(DeviceId, DeviceIdBox, "device ID");

impl DeviceId {
    /// Generates a random `DeviceId`, suitable for assignment to a new device.
    #[cfg(feature = "rand")]
    #[cfg_attr(docsrs, doc(cfg(feature = "rand")))]
    pub fn new() -> Box<Self> {
        Self::from_owned(generate_localpart(8))
    }
}
/// Generates a random `DeviceId`, suitable for assignment to a new device.
#[cfg(feature = "rand")]
#[cfg_attr(docsrs, doc(cfg(feature = "rand")))]
#[deprecated = "use DeviceId::new instead"]
pub fn generate() -> Box<DeviceId> {
    DeviceId::new()
}

#[cfg(all(test, feature = "rand"))]
mod tests {
    use super::DeviceId;

    #[test]
    fn generate_device_id() {
        assert_eq!(DeviceId::new().as_str().len(), 8);
    }
}
