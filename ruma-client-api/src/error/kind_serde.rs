use std::{
    borrow::Cow,
    collections::btree_map::{BTreeMap, Entry},
    convert::TryFrom,
    fmt,
    time::Duration,
};

use js_int::UInt;
use serde::{
    de::{self, Deserialize, Deserializer, MapAccess, Visitor},
    ser::{self, Serialize, SerializeMap, Serializer},
};
use serde_json::from_value as from_json_value;

use super::ErrorKind;

enum Field<'de> {
    ErrCode,
    SoftLogout,
    RetryAfterMs,
    RoomVersion,
    AdminContact,
    Other(Cow<'de, str>),
}

impl<'de> Field<'de> {
    fn new(s: Cow<'de, str>) -> Field<'de> {
        match s.as_ref() {
            "errcode" => Self::ErrCode,
            "soft_logout" => Self::SoftLogout,
            "retry_after_ms" => Self::RetryAfterMs,
            "room_version" => Self::RoomVersion,
            "admin_contact" => Self::AdminContact,
            _ => Self::Other(s),
        }
    }
}

impl<'de> Deserialize<'de> for Field<'de> {
    fn deserialize<D>(deserializer: D) -> Result<Field<'de>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct FieldVisitor;

        impl<'de> Visitor<'de> for FieldVisitor {
            type Value = Field<'de>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("any struct field")
            }

            fn visit_str<E>(self, value: &str) -> Result<Field<'de>, E>
            where
                E: de::Error,
            {
                Ok(Field::new(Cow::Owned(value.to_owned())))
            }

            fn visit_borrowed_str<E>(self, value: &'de str) -> Result<Field<'de>, E>
            where
                E: de::Error,
            {
                Ok(Field::new(Cow::Borrowed(value)))
            }

            fn visit_string<E>(self, value: String) -> Result<Field<'de>, E>
            where
                E: de::Error,
            {
                Ok(Field::new(Cow::Owned(value)))
            }
        }

        deserializer.deserialize_identifier(FieldVisitor)
    }
}

struct ErrorKindVisitor;

impl<'de> Visitor<'de> for ErrorKindVisitor {
    type Value = ErrorKind;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("enum ErrorKind")
    }

    fn visit_map<V>(self, mut map: V) -> Result<ErrorKind, V::Error>
    where
        V: MapAccess<'de>,
    {
        let mut errcode = None;
        let mut soft_logout = None;
        let mut retry_after_ms = None;
        let mut room_version = None;
        let mut admin_contact = None;
        let mut extra = BTreeMap::new();

        macro_rules! set_field {
            (errcode) => {
                set_field!(@inner errcode);
            };
            ($field:ident) => {
                match errcode {
                    Some(set_field!(@variant_containing $field)) | None => {
                        set_field!(@inner $field);
                    }
                    // if we already know we're deserializing a different variant to the one
                    // containing this field, ignore its value.
                    Some(_) => {
                        let _ = map.next_value::<de::IgnoredAny>()?;
                    },
                }
            };
            (@variant_containing soft_logout) => { ErrCode::UnknownToken };
            (@variant_containing retry_after_ms) => { ErrCode::LimitExceeded };
            (@variant_containing room_version) => { ErrCode::IncompatibleRoomVersion };
            (@variant_containing admin_contact) => { ErrCode::ResourceLimitExceeded };
            (@inner $field:ident) => {
                {
                    if $field.is_some() {
                        return Err(de::Error::duplicate_field(stringify!($field)));
                    }
                    $field = Some(map.next_value()?);
                }
            };
        }

        while let Some(key) = map.next_key()? {
            match key {
                Field::ErrCode => set_field!(errcode),
                Field::SoftLogout => set_field!(soft_logout),
                Field::RetryAfterMs => set_field!(retry_after_ms),
                Field::RoomVersion => set_field!(room_version),
                Field::AdminContact => set_field!(admin_contact),
                Field::Other(other) => match extra.entry(other.into_owned()) {
                    Entry::Vacant(v) => {
                        v.insert(map.next_value()?);
                    }
                    Entry::Occupied(o) => {
                        return Err(de::Error::custom(format!("duplicate field `{}`", o.key())));
                    }
                },
            }
        }

        let errcode = errcode.ok_or_else(|| de::Error::missing_field("errcode"))?;
        Ok(match errcode {
            ErrCode::Forbidden => ErrorKind::Forbidden,
            ErrCode::UnknownToken => ErrorKind::UnknownToken {
                soft_logout: soft_logout
                    .map(from_json_value)
                    .transpose()
                    .map_err(de::Error::custom)?
                    .unwrap_or_default(),
            },
            ErrCode::MissingToken => ErrorKind::MissingToken,
            ErrCode::BadJson => ErrorKind::BadJson,
            ErrCode::NotJson => ErrorKind::NotJson,
            ErrCode::NotFound => ErrorKind::NotFound,
            ErrCode::LimitExceeded => ErrorKind::LimitExceeded {
                retry_after_ms: retry_after_ms
                    .map(from_json_value::<UInt>)
                    .transpose()
                    .map_err(de::Error::custom)?
                    .map(Into::into)
                    .map(Duration::from_millis),
            },
            ErrCode::Unknown => ErrorKind::Unknown,
            ErrCode::Unrecognized => ErrorKind::Unrecognized,
            ErrCode::Unauthorized => ErrorKind::Unauthorized,
            ErrCode::UserDeactivated => ErrorKind::UserDeactivated,
            ErrCode::UserInUse => ErrorKind::UserInUse,
            ErrCode::InvalidUsername => ErrorKind::InvalidUsername,
            ErrCode::RoomInUse => ErrorKind::RoomInUse,
            ErrCode::InvalidRoomState => ErrorKind::InvalidRoomState,
            ErrCode::ThreepidInUse => ErrorKind::ThreepidInUse,
            ErrCode::ThreepidNotFound => ErrorKind::ThreepidNotFound,
            ErrCode::ThreepidAuthFailed => ErrorKind::ThreepidAuthFailed,
            ErrCode::ThreepidDenied => ErrorKind::ThreepidDenied,
            ErrCode::ServerNotTrusted => ErrorKind::ServerNotTrusted,
            ErrCode::UnsupportedRoomVersion => ErrorKind::UnsupportedRoomVersion,
            ErrCode::IncompatibleRoomVersion => ErrorKind::IncompatibleRoomVersion {
                room_version: from_json_value(
                    room_version.ok_or_else(|| de::Error::missing_field("room_version"))?,
                )
                .map_err(de::Error::custom)?,
            },
            ErrCode::BadState => ErrorKind::BadState,
            ErrCode::GuestAccessForbidden => ErrorKind::GuestAccessForbidden,
            ErrCode::CaptchaNeeded => ErrorKind::CaptchaNeeded,
            ErrCode::CaptchaInvalid => ErrorKind::CaptchaInvalid,
            ErrCode::MissingParam => ErrorKind::MissingParam,
            ErrCode::InvalidParam => ErrorKind::InvalidParam,
            ErrCode::TooLarge => ErrorKind::TooLarge,
            ErrCode::Exclusive => ErrorKind::Exclusive,
            ErrCode::ResourceLimitExceeded => ErrorKind::ResourceLimitExceeded {
                admin_contact: from_json_value(
                    admin_contact.ok_or_else(|| de::Error::missing_field("admin_contact"))?,
                )
                .map_err(de::Error::custom)?,
            },
            ErrCode::CannotLeaveServerNoticeRoom => ErrorKind::CannotLeaveServerNoticeRoom,
            ErrCode::_Custom(errcode) => ErrorKind::_Custom { errcode, extra },
        })
    }
}

// FIXME: Derive FromString once available
enum ErrCode {
    Forbidden,
    UnknownToken,
    MissingToken,
    BadJson,
    NotJson,
    NotFound,
    LimitExceeded,
    Unknown,
    Unrecognized,
    Unauthorized,
    UserDeactivated,
    UserInUse,
    InvalidUsername,
    RoomInUse,
    InvalidRoomState,
    ThreepidInUse,
    ThreepidNotFound,
    ThreepidAuthFailed,
    ThreepidDenied,
    ServerNotTrusted,
    UnsupportedRoomVersion,
    IncompatibleRoomVersion,
    BadState,
    GuestAccessForbidden,
    CaptchaNeeded,
    CaptchaInvalid,
    MissingParam,
    InvalidParam,
    TooLarge,
    Exclusive,
    ResourceLimitExceeded,
    CannotLeaveServerNoticeRoom,
    _Custom(String),
}

impl<'de> Deserialize<'de> for ErrCode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = ruma_serde::deserialize_cow_str(deserializer)?;
        Ok(s.into())
    }
}

impl<T> From<T> for ErrCode
where
    T: AsRef<str> + Into<String>,
{
    fn from(s: T) -> Self {
        match s.as_ref() {
            "M_FORBIDDEN" => Self::Forbidden,
            "M_UNKNOWN_TOKEN" => Self::UnknownToken,
            "M_MISSING_TOKEN" => Self::MissingToken,
            "M_BAD_JSON" => Self::BadJson,
            "M_NOT_JSON" => Self::NotJson,
            "M_NOT_FOUND" => Self::NotFound,
            "M_LIMIT_EXCEEDED" => Self::LimitExceeded,
            "M_UNKNOWN" => Self::Unknown,
            "M_UNRECOGNIZED" => Self::Unrecognized,
            "M_UNAUTHORIZED" => Self::Unauthorized,
            "M_USER_DEACTIVATED" => Self::UserDeactivated,
            "M_USER_IN_USE" => Self::UserInUse,
            "M_INVALID_USERNAME" => Self::InvalidUsername,
            "M_ROOM_IN_USE" => Self::RoomInUse,
            "M_INVALID_ROOM_STATE" => Self::InvalidRoomState,
            "M_THREEPID_IN_USE" => Self::ThreepidInUse,
            "M_THREEPID_NOT_FOUND" => Self::ThreepidNotFound,
            "M_THREEPID_AUTH_FAILED" => Self::ThreepidAuthFailed,
            "M_THREEPID_DENIED" => Self::ThreepidDenied,
            "M_SERVER_NOT_TRUSTED" => Self::ServerNotTrusted,
            "M_UNSUPPORTED_ROOM_VERSION" => Self::UnsupportedRoomVersion,
            "M_INCOMPATIBLE_ROOM_VERSION" => Self::IncompatibleRoomVersion,
            "M_BAD_STATE" => Self::BadState,
            "M_GUEST_ACCESS_FORBIDDEN" => Self::GuestAccessForbidden,
            "M_CAPTCHA_NEEDED" => Self::CaptchaNeeded,
            "M_CAPTCHA_INVALID" => Self::CaptchaInvalid,
            "M_MISSING_PARAM" => Self::MissingParam,
            "M_INVALID_PARAM" => Self::InvalidParam,
            "M_TOO_LARGE" => Self::TooLarge,
            "M_EXCLUSIVE" => Self::Exclusive,
            "M_RESOURCE_LIMIT_EXCEEDED" => Self::ResourceLimitExceeded,
            "M_CANNOT_LEAVE_SERVER_NOTICE_ROOM" => Self::CannotLeaveServerNoticeRoom,
            _ => Self::_Custom(s.into()),
        }
    }
}

impl<'de> Deserialize<'de> for ErrorKind {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_map(ErrorKindVisitor)
    }
}

impl Serialize for ErrorKind {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut st = serializer.serialize_map(None)?;
        st.serialize_entry("errcode", self.as_ref())?;
        match self {
            Self::UnknownToken { soft_logout: true } => {
                st.serialize_entry("soft_logout", &true)?;
            }
            Self::LimitExceeded { retry_after_ms: Some(duration) } => {
                st.serialize_entry(
                    "retry_after_ms",
                    &UInt::try_from(duration.as_millis()).map_err(ser::Error::custom)?,
                )?;
            }
            Self::IncompatibleRoomVersion { room_version } => {
                st.serialize_entry("room_version", room_version)?;
            }
            Self::ResourceLimitExceeded { admin_contact } => {
                st.serialize_entry("admin_contact", admin_contact)?;
            }
            Self::_Custom { extra, .. } => {
                for (k, v) in extra {
                    st.serialize_entry(k, v)?;
                }
            }
            _ => {}
        }
        st.end()
    }
}

#[cfg(test)]
mod tests {
    use ruma_identifiers::room_version_id;
    use serde_json::{from_value as from_json_value, json};

    use super::ErrorKind;

    #[test]
    fn deserialize_forbidden() {
        let deserialized: ErrorKind = from_json_value(json!({ "errcode": "M_FORBIDDEN" })).unwrap();
        assert_eq!(deserialized, ErrorKind::Forbidden);
    }

    #[test]
    fn deserialize_forbidden_with_extra_fields() {
        let deserialized: ErrorKind = from_json_value(json!({
            "errcode": "M_FORBIDDEN",
            "error": "…",
        }))
        .unwrap();

        assert_eq!(deserialized, ErrorKind::Forbidden);
    }

    #[test]
    fn deserialize_incompatible_room_version() {
        let deserialized: ErrorKind = from_json_value(json!({
            "errcode": "M_INCOMPATIBLE_ROOM_VERSION",
            "room_version": "7",
        }))
        .unwrap();

        assert_eq!(
            deserialized,
            ErrorKind::IncompatibleRoomVersion { room_version: room_version_id!("7") }
        );
    }
}
