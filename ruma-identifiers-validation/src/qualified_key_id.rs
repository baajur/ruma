use std::{num::NonZeroU8, str::FromStr};

use crate::Error;

pub fn validate<A, K>(s: &str) -> Result<NonZeroU8, Error>
where
    A: FromStr,
    K: FromStr,
{
    let colon_idx = NonZeroU8::new(s.find(':').ok_or(Error::MissingKeyDelimiter)? as u8)
        .ok_or(Error::UnknownKeyAlgorithm)?;

    A::from_str(&s[0..colon_idx.get() as usize]).map_err(|_| Error::UnknownKeyAlgorithm)?;

    K::from_str(&s[colon_idx.get() as usize + 1..]).map_err(|_| Error::InvalidKeyVersion)?;
    Ok(colon_idx)
}
