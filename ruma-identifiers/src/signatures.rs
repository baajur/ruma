use crate::{DeviceId, ServerName, UserId};
use ruma_identifiers_validation::{
    crypto_algorithms::{DeviceKeyAlgorithm, SigningKeyAlgorithm},
    Error,
};
use std::{
    collections::BTreeMap, convert::TryInto, fmt::Debug, marker::PhantomData, num::NonZeroU8,
    str::FromStr,
};

#[derive(Clone, Debug)]
pub struct QualifiedKeyId<A, K>
//where K: Ord,
{
    full_id: Box<str>,
    colon_idx: NonZeroU8,
    algorithm: PhantomData<A>,
    key_identifier: PhantomData<K>,
}

impl<A, K> QualifiedKeyId<A, K>
where
    A: AsRef<str> + FromStr,
    A::Err: Debug,
    K: AsRef<str> + FromStr + Ord,
    K::Err: Debug,
{
    /// Create a `QualifiedKeyId` from an algorithm and key identifier.
    pub fn from_parts(algorithm: A, key_identifier: K) -> Self {
        let algorithm: &str = algorithm.as_ref();
        let key_identifier: &str = key_identifier.as_ref();

        let mut res = String::with_capacity(algorithm.len() + 1 + key_identifier.len());
        res.push_str(algorithm);
        res.push_str(":");
        res.push_str(key_identifier);

        let colon_idx =
            NonZeroU8::new(algorithm.len().try_into().expect("no algorithm name len > 255"))
                .expect("no empty algorithm name");

        QualifiedKeyId {
            full_id: res.into(),
            colon_idx,
            algorithm: PhantomData,
            key_identifier: PhantomData,
        }
    }

    /// Returns key algorithm of the key ID.
    pub fn algorithm(&self) -> A {
        A::from_str(&self.full_id[..self.colon_idx.get() as usize]).unwrap()
    }

    /// Returns the version of the server key ID.
    pub fn identifier(&self) -> K {
        K::from_str(&self.full_id[self.colon_idx.get() as usize + 1..]).unwrap()
    }
}

fn try_from<S, A, K>(key_id: S) -> Result<QualifiedKeyId<A, K>, Error>
where
    S: AsRef<str> + Into<Box<str>>,
    A: FromStr,
    K: FromStr,
{
    let colon_idx =
        ruma_identifiers_validation::qualified_key_id::validate::<A, K>(key_id.as_ref())?;
    Ok(QualifiedKeyId {
        full_id: key_id.into(),
        colon_idx,
        algorithm: PhantomData,
        key_identifier: PhantomData,
    })
}

// common_impls!(QualifiedKeyId<A, K>, try_from, "Key ID with algorithm and key identifier");

// ($id:ty, $try_from:ident, $desc:literal) => {
impl<A, K> QualifiedKeyId<A, K> {
    doc_concat! {
        #[doc = concat!("Creates a string slice from this `", stringify!(QualifiedKeyId<A, K>), "`")]
        pub fn as_str(&self) -> &str {
            &self.full_id
        }
    }

    doc_concat! {
        #[doc = concat!("Creates a byte slice from this `", stringify!(QualifiedKeyId<A, K>), "`")]
        pub fn as_bytes(&self) -> &[u8] {
            self.full_id.as_bytes()
        }
    }
}

impl<A, K> ::std::convert::AsRef<str> for QualifiedKeyId<A, K> {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl<A, K> ::std::convert::From<QualifiedKeyId<A, K>> for ::std::string::String {
    fn from(id: QualifiedKeyId<A, K>) -> Self {
        id.full_id.into()
    }
}

impl<A, K> ::std::str::FromStr for QualifiedKeyId<A, K>
where
    A: FromStr,
    K: FromStr,
{
    type Err = crate::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        try_from(s)
    }
}

impl<A, K> ::std::convert::TryFrom<&str> for QualifiedKeyId<A, K>
where
    A: FromStr,
    K: FromStr,
{
    type Error = crate::Error;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        try_from(s)
    }
}

/*
impl<'a, A, K>  std::convert::TryFrom<&'a str> for &'a QualifiedKeyId<A, K>
where A: FromStr,
      K: FromStr,
{
    type Error = crate::Error;
    fn try_from(s: &'a str) -> Result<Self, Self::Error> {
        try_from(s).map(|k| &k)
    }
}
*/

impl<A, K> ::std::convert::TryFrom<String> for QualifiedKeyId<A, K>
where
    A: FromStr,
    K: FromStr,
{
    type Error = crate::Error;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        try_from(s)
    }
}

impl<A, K> ::std::fmt::Display for QualifiedKeyId<A, K> {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl<A, K> ::std::cmp::PartialEq for QualifiedKeyId<A, K> {
    fn eq(&self, other: &Self) -> bool {
        self.as_str() == other.as_str()
    }
}

impl<A, K> ::std::cmp::Eq for QualifiedKeyId<A, K> {}

impl<A, K: std::cmp::Ord> ::std::cmp::PartialOrd for QualifiedKeyId<A, K> {
    fn partial_cmp(&self, other: &Self) -> Option<::std::cmp::Ordering> {
        ::std::cmp::PartialOrd::partial_cmp(self.as_str(), other.as_str())
    }
}

impl<A, K: std::cmp::Ord> ::std::cmp::Ord for QualifiedKeyId<A, K> {
    fn cmp(&self, other: &Self) -> ::std::cmp::Ordering {
        ::std::cmp::Ord::cmp(self.as_str(), other.as_str())
    }
}

impl<A, K> ::std::hash::Hash for QualifiedKeyId<A, K> {
    fn hash<H: ::std::hash::Hasher>(&self, state: &mut H) {
        self.as_str().hash(state);
    }
}

#[cfg(feature = "serde1")]
impl<A, K> ::serde1::Serialize for QualifiedKeyId<A, K> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ::serde1::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

#[cfg(feature = "serde1")]
impl<'de, A, K> ::serde1::Deserialize<'de> for QualifiedKeyId<A, K>
where
    A: FromStr,
    K: FromStr,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: ::serde1::Deserializer<'de>,
    {
        crate::deserialize_id(deserializer, "Key ID with algorithm and key identifier")
    }
}

impl<A, K> std::cmp::PartialEq<QualifiedKeyId<A, K>> for str {
    fn eq(&self, other: &QualifiedKeyId<A, K>) -> bool {
        ::std::convert::AsRef::<str>::as_ref(self) == ::std::convert::AsRef::<str>::as_ref(other)
    }
}
impl<A, K> std::cmp::PartialEq<QualifiedKeyId<A, K>> for &str {
    fn eq(&self, other: &QualifiedKeyId<A, K>) -> bool {
        ::std::convert::AsRef::<str>::as_ref(self) == ::std::convert::AsRef::<str>::as_ref(other)
    }
}
impl<A, K> std::cmp::PartialEq<QualifiedKeyId<A, K>> for String {
    fn eq(&self, other: &QualifiedKeyId<A, K>) -> bool {
        ::std::convert::AsRef::<str>::as_ref(self) == ::std::convert::AsRef::<str>::as_ref(other)
    }
}
impl<A, K> std::cmp::PartialEq<str> for QualifiedKeyId<A, K> {
    fn eq(&self, other: &str) -> bool {
        ::std::convert::AsRef::<str>::as_ref(self) == ::std::convert::AsRef::<str>::as_ref(other)
    }
}
impl<A, K> std::cmp::PartialEq<&str> for QualifiedKeyId<A, K> {
    fn eq(&self, other: &&str) -> bool {
        ::std::convert::AsRef::<str>::as_ref(self) == ::std::convert::AsRef::<str>::as_ref(other)
    }
}
impl<A, K> std::cmp::PartialEq<String> for QualifiedKeyId<A, K> {
    fn eq(&self, other: &String) -> bool {
        ::std::convert::AsRef::<str>::as_ref(self) == ::std::convert::AsRef::<str>::as_ref(other)
    }
}

key_identifier!(KeyVersion, KeyVersionBox);

/// Algorithm + key identifier for signing keys.
pub type SigningKeyId<K> = QualifiedKeyId<SigningKeyAlgorithm, K>;

/// Algorithm + key identifier for device keys.
pub type DeviceSigningKeyId = SigningKeyId<DeviceId>;

/// Map of key identifier to signature values.
pub type EntitySignatures<K> = BTreeMap<SigningKeyId<K>, String>;

/// Map of all signatures, grouped by entity
///
/// ```
/// let key_id = KeyIdentifier::from_parts(SigningKeyAlgorithm::Ed25519, "1");
/// let mut signatures = Signatures::new();
/// let server_name = server_name!("example.org");
/// let signature = "YbJva03ihSj5mPk+CHMJKUKlCXCPFXjXOK6VqBnN9nA2evksQcTGn6hwQfrgRHIDDXO2le49x7jnWJHMJrJoBQ";
/// add_signature(signatures, server_name, key_id, signature);
/// ```
pub type Signatures<E, K> = BTreeMap<E, EntitySignatures<K>>;

/// Map of server signatures for an event, grouped by server.
pub type ServerSignatures = Signatures<Box<ServerName>, KeyVersion>;

/// Map of device signatures for an event, grouped by user.
pub type DeviceSignatures = Signatures<UserId, DeviceId>;

fn add_signature<E, K>(
    signatures: &mut Signatures<E, K>,
    entity: E,
    key_identifier: QualifiedKeyId<SigningKeyAlgorithm, K>,
    value: String,
) where
    E: Copy + Ord,
    K: Ord,
{
    if !signatures.contains_key(&entity) {
        signatures.insert(entity, EntitySignatures::new());
    }

    let entity_signatures = signatures.get_mut(&entity).unwrap();
    entity_signatures.insert(key_identifier, value);
}
