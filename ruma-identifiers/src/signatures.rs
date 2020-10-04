use crate::{DeviceId, ServerName, UserId};
use ruma_identifiers_validation::{crypto_algorithms::SigningKeyAlgorithm, Error};
use std::{
    cmp::Ordering,
    collections::BTreeMap,
    convert::{TryFrom, TryInto},
    fmt::{self, Debug, Display, Formatter},
    hash::{Hash, Hasher},
    marker::PhantomData,
    num::NonZeroU8,
    str::FromStr,
};

/// A Matrix key identifier.
///
/// Key identifiers in Matrix are opaque character sequences of `[a-zA-Z_]`. This type is provided
/// simply for its semantic value.
#[repr(transparent)]
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde1::Serialize), serde(transparent, crate = "serde1"))]
pub struct KeyName(str);

opaque_identifier!(KeyName, KeyNameBox, "key ID");

impl FromStr for Box<KeyName> {
    type Err = crate::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(KeyName::from_owned(s.into()))
    }
}

/// A key algorithm and key name delimited by a colon
#[derive(Clone, Debug)]
pub struct KeyId<A, K> {
    full_id: Box<str>,
    colon_idx: NonZeroU8,
    algorithm: PhantomData<A>,
    key_name: PhantomData<K>,
}

impl<A, K> KeyId<A, K>
where
    A: AsRef<str> + FromStr,
    A::Err: Debug,
    K: AsRef<str> + FromStr + Ord,
    K::Err: Debug,
{
    /// Creates a `KeyId` from an algorithm and key name.
    pub fn from_parts(algorithm: A, key_name: K) -> Self {
        let algorithm: &str = algorithm.as_ref();
        let key_name: &str = key_name.as_ref();

        let mut res = String::with_capacity(algorithm.len() + 1 + key_name.len());
        res.push_str(algorithm);
        res.push_str(":");
        res.push_str(key_name);

        let colon_idx =
            NonZeroU8::new(algorithm.len().try_into().expect("no algorithm name len > 255"))
                .expect("no empty algorithm name");

        KeyId { full_id: res.into(), colon_idx, algorithm: PhantomData, key_name: PhantomData }
    }

    /// Returns key algorithm of the key ID.
    pub fn algorithm(&self) -> A {
        A::from_str(&self.full_id[..self.colon_idx.get() as usize]).unwrap()
    }

    /// Returns the key name of the key ID.
    pub fn key_name(&self) -> K {
        K::from_str(&self.full_id[self.colon_idx.get() as usize + 1..]).unwrap()
    }

    /// Returns the key name of the key ID.
    #[deprecated = "use key_name() instead"]
    pub fn identifier(&self) -> K {
        self.key_name()
    }
}

fn try_from<S, A, K>(key_identifier: S) -> Result<KeyId<A, K>, Error>
where
    S: AsRef<str> + Into<Box<str>>,
    A: FromStr,
    K: FromStr,
{
    // TODO: Rename qualified_key_id?
    let colon_idx =
        ruma_identifiers_validation::qualified_key_id::validate::<A, K>(key_identifier.as_ref())?;
    Ok(KeyId {
        full_id: key_identifier.into(),
        colon_idx,
        algorithm: PhantomData,
        key_name: PhantomData,
    })
}

impl<A, K> KeyId<A, K> {
    /// Creates a string slice from this `KeyId<A, K>`
    pub fn as_str(&self) -> &str {
        &self.full_id
    }

    /// Creates a byte slice from this `KeyId<A, K>`
    pub fn as_bytes(&self) -> &[u8] {
        self.full_id.as_bytes()
    }
}

impl<A, K> AsRef<str> for KeyId<A, K> {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl<A, K> From<KeyId<A, K>> for String {
    fn from(id: KeyId<A, K>) -> Self {
        id.full_id.into()
    }
}

impl<A, K> FromStr for KeyId<A, K>
where
    A: FromStr,
    K: FromStr,
{
    type Err = crate::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        try_from(s)
    }
}

impl<A, K> TryFrom<&str> for KeyId<A, K>
where
    A: FromStr,
    K: FromStr,
{
    type Error = crate::Error;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        try_from(s)
    }
}

impl<A, K> TryFrom<String> for KeyId<A, K>
where
    A: FromStr,
    K: FromStr,
{
    type Error = crate::Error;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        try_from(s)
    }
}

impl<A, K> Display for KeyId<A, K> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl<A, K> PartialEq for KeyId<A, K> {
    fn eq(&self, other: &Self) -> bool {
        self.as_str() == other.as_str()
    }
}

impl<A, K> Eq for KeyId<A, K> {}

impl<A, K: Ord> PartialOrd for KeyId<A, K> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        PartialOrd::partial_cmp(self.as_str(), other.as_str())
    }
}

impl<A, K: std::cmp::Ord> ::std::cmp::Ord for KeyId<A, K> {
    fn cmp(&self, other: &Self) -> Ordering {
        ::std::cmp::Ord::cmp(self.as_str(), other.as_str())
    }
}

impl<A, K> Hash for KeyId<A, K> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_str().hash(state);
    }
}

#[cfg(feature = "serde1")]
impl<A, K> serde1::Serialize for KeyId<A, K> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde1::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

#[cfg(feature = "serde1")]
impl<'de, A, K> serde1::Deserialize<'de> for KeyId<A, K>
where
    A: FromStr,
    K: FromStr,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde1::Deserializer<'de>,
    {
        crate::deserialize_id(deserializer, "Key name with algorithm and key identifier")
    }
}

impl<A, K> PartialEq<KeyId<A, K>> for str {
    fn eq(&self, other: &KeyId<A, K>) -> bool {
        AsRef::<str>::as_ref(self) == AsRef::<str>::as_ref(other)
    }
}
impl<A, K> PartialEq<KeyId<A, K>> for &str {
    fn eq(&self, other: &KeyId<A, K>) -> bool {
        AsRef::<str>::as_ref(self) == AsRef::<str>::as_ref(other)
    }
}
impl<A, K> PartialEq<KeyId<A, K>> for String {
    fn eq(&self, other: &KeyId<A, K>) -> bool {
        AsRef::<str>::as_ref(self) == AsRef::<str>::as_ref(other)
    }
}
impl<A, K> PartialEq<str> for KeyId<A, K> {
    fn eq(&self, other: &str) -> bool {
        AsRef::<str>::as_ref(self) == AsRef::<str>::as_ref(other)
    }
}
impl<A, K> PartialEq<&str> for KeyId<A, K> {
    fn eq(&self, other: &&str) -> bool {
        AsRef::<str>::as_ref(self) == AsRef::<str>::as_ref(other)
    }
}
impl<A, K> PartialEq<String> for KeyId<A, K> {
    fn eq(&self, other: &String) -> bool {
        AsRef::<str>::as_ref(self) == AsRef::<str>::as_ref(other)
    }
}

/// Algorithm + key name for signing keys.
pub type SigningKeyId<K> = KeyId<SigningKeyAlgorithm, K>;

/// Algorithm + key name for homeserver signing keys.
pub type ServerSigningKeyId = SigningKeyId<KeyNameBox>;

/// Algorithm + key name for device keys.
pub type DeviceSigningKeyId = SigningKeyId<DeviceId>;

/// Map of key identifier to signature values.
pub type EntitySignatures<K> = BTreeMap<SigningKeyId<K>, String>;

/// Map of all signatures, grouped by entity
///
/// ```
/// let key_identifier = KeyId::from_parts(SigningKeyAlgorithm::Ed25519, "1");
/// let mut signatures = Signatures::new();
/// let server_name = server_name!("example.org");
/// let signature = "YbJva03ihSj5mPk+CHMJKUKlCXCPFXjXOK6VqBnN9nA2evksQcTGn6hwQfrgRHIDDXO2le49x7jnWJHMJrJoBQ";
/// add_signature(signatures, server_name, key_identifier, signature);
/// ```
pub type Signatures<E, K> = BTreeMap<E, EntitySignatures<K>>;

/// Map of server signatures for an event, grouped by server.
pub type ServerSignatures = Signatures<Box<ServerName>, KeyName>;

/// Map of device signatures for an event, grouped by user.
pub type DeviceSignatures = Signatures<UserId, DeviceId>;

fn add_signature<E, K>(
    signatures: &mut Signatures<E, K>,
    entity: E,
    key_identifier: KeyId<SigningKeyAlgorithm, K>,
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
