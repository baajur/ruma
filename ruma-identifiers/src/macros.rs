/// Declares an item with a doc attribute computed by some macro expression.
/// This allows documentation to be dynamically generated based on input.
/// Necessary to work around https://github.com/rust-lang/rust/issues/52607.
macro_rules! doc_concat {
    ( $( #[doc = $doc:expr] $( $thing:tt )* )* ) => ( $( #[doc = $doc] $( $thing )* )* );
}

macro_rules! partial_eq_string {
    ($id:ty) => {
        partial_eq_string!(@imp, $id, str);
        partial_eq_string!(@imp, $id, &str);
        partial_eq_string!(@imp, $id, String);
        partial_eq_string!(@imp, str, $id);
        partial_eq_string!(@imp, &str, $id);
        partial_eq_string!(@imp, String, $id);
    };
    (@imp, $l:ty, $r:ty) => {
        impl ::std::cmp::PartialEq<$r> for $l {
            fn eq(&self, other: &$r) -> bool {
                ::std::convert::AsRef::<str>::as_ref(self)
                    == ::std::convert::AsRef::<str>::as_ref(other)
            }
        }
    }
}

macro_rules! common_impls {
    ($id:ty, $try_from:ident, $desc:literal) => {
        impl $id {
            doc_concat! {
                #[doc = concat!("Creates a string slice from this `", stringify!($id), "`")]
                pub fn as_str(&self) -> &str {
                    &self.full_id
                }
            }

            doc_concat! {
                #[doc = concat!("Creates a byte slice from this `", stringify!($id), "`")]
                pub fn as_bytes(&self) -> &[u8] {
                    self.full_id.as_bytes()
                }
            }
        }

        impl ::std::convert::AsRef<str> for $id {
            fn as_ref(&self) -> &str {
                self.as_str()
            }
        }

        impl ::std::convert::From<$id> for ::std::string::String {
            fn from(id: $id) -> Self {
                id.full_id.into()
            }
        }

        impl ::std::str::FromStr for $id {
            type Err = crate::Error;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                $try_from(s)
            }
        }

        impl ::std::convert::TryFrom<&str> for $id {
            type Error = crate::Error;

            fn try_from(s: &str) -> Result<Self, Self::Error> {
                $try_from(s)
            }
        }

        impl ::std::convert::TryFrom<String> for $id {
            type Error = crate::Error;

            fn try_from(s: String) -> Result<Self, Self::Error> {
                $try_from(s)
            }
        }

        impl ::std::fmt::Display for $id {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                write!(f, "{}", self.as_str())
            }
        }

        impl ::std::cmp::PartialEq for $id {
            fn eq(&self, other: &Self) -> bool {
                self.as_str() == other.as_str()
            }
        }

        impl ::std::cmp::Eq for $id {}

        impl ::std::cmp::PartialOrd for $id {
            fn partial_cmp(&self, other: &Self) -> Option<::std::cmp::Ordering> {
                ::std::cmp::PartialOrd::partial_cmp(self.as_str(), other.as_str())
            }
        }

        impl ::std::cmp::Ord for $id {
            fn cmp(&self, other: &Self) -> ::std::cmp::Ordering {
                ::std::cmp::Ord::cmp(self.as_str(), other.as_str())
            }
        }

        impl ::std::hash::Hash for $id {
            fn hash<H: ::std::hash::Hasher>(&self, state: &mut H) {
                self.as_str().hash(state);
            }
        }

        #[cfg(feature = "serde1")]
        impl ::serde1::Serialize for $id {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: ::serde1::Serializer,
            {
                serializer.serialize_str(self.as_str())
            }
        }

        #[cfg(feature = "serde1")]
        impl<'de> ::serde1::Deserialize<'de> for $id {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: ::serde1::Deserializer<'de>,
            {
                crate::deserialize_id(deserializer, $desc)
            }
        }

        partial_eq_string!($id);
    };
}

macro_rules! key_identifier {
    ($id:ident, $boxed:ident) => {
        #[repr(transparent)]
        #[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[cfg_attr(
            feature = "serde",
            derive(serde1::Serialize),
            serde(transparent, crate = "serde1")
        )]
        pub struct $id(str);

        /// An owned device identifier.
        pub type $boxed = Box<$id>;

        impl $id {
            #[allow(clippy::transmute_ptr_to_ptr)]
            fn from_borrowed(s: &str) -> &Self {
                unsafe { ::std::mem::transmute(s) }
            }

            pub(super) fn from_owned(s: Box<str>) -> Box<Self> {
                unsafe { ::std::mem::transmute(s) }
            }

            fn into_owned(self: Box<Self>) -> Box<str> {
                unsafe { ::std::mem::transmute(self) }
            }

            doc_concat! {
                #[doc = concat!("Creates a string slice from this `", stringify!($id), "`.")]
                pub fn as_str(&self) -> &str {
                    &self.0
                }
            }

            doc_concat! {
                #[doc = concat!("Creates a byte slice from this `", stringify!($id), "`.")]
                pub fn as_bytes(&self) -> &[u8] {
                    self.0.as_bytes()
                }
            }
        }

        impl Clone for Box<$id> {
            fn clone(&self) -> Self {
                (**self).to_owned()
            }
        }

        impl ToOwned for $id {
            type Owned = Box<$id>;

            fn to_owned(&self) -> Self::Owned {
                Self::from_owned(self.0.to_owned().into_boxed_str())
            }
        }

        impl From<&$id> for Box<$id> {
            fn from(id: &$id) -> Self {
                id.to_owned()
            }
        }

        impl AsRef<str> for $id {
            fn as_ref(&self) -> &str {
                self.as_str()
            }
        }

        impl AsRef<str> for Box<$id> {
            fn as_ref(&self) -> &str {
                self.as_str()
            }
        }

        impl<'a> From<&'a str> for &'a $id {
            fn from(s: &'a str) -> Self {
                $id::from_borrowed(s)
            }
        }

        impl From<&str> for Box<$id> {
            fn from(s: &str) -> Self {
                $id::from_owned(s.into())
            }
        }

        impl From<String> for Box<$id> {
            fn from(s: String) -> Self {
                $id::from_owned(s.into())
            }
        }

        impl From<Box<$id>> for String {
            fn from(id: Box<$id>) -> Self {
                id.into_owned().into()
            }
        }

        impl ::std::fmt::Display for $id {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                write!(f, "{}", self.as_str())
            }
        }

        #[cfg(feature = "serde")]
        impl<'de> serde1::Deserialize<'de> for Box<$id> {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde1::Deserializer<'de>,
            {
                crate::deserialize_id(deserializer, "An IP address or hostname")
            }
        }

        partial_eq_string!($id);
        partial_eq_string!(Box<$id>);
    };
}
