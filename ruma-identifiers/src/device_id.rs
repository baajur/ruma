//! Matrix device identifiers.

use std::{
    fmt::{self, Display},
    mem,
};

#[cfg(feature = "rand")]
use crate::generate_localpart;

pub use device_id::{DeviceId, DeviceIdBox};
mod device_id {
    //! A Matrix device ID.
    //!
    //! Device identifiers in Matrix are completely opaque character sequences. This type is provided
    //! simply for its semantic value.
    key_identifier!(DeviceId, DeviceIdBox);
}

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
