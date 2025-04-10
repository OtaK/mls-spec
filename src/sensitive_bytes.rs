use crate::macros::ref_forward_tls_impl;

/// Container that ser/deserializes to TLS Variable-Length bytes
/// and implements zeroizing & constant-time equality checks
#[derive(Clone, Default, Ord, PartialOrd, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(transparent)]
pub struct SensitiveBytes(Vec<u8>);

impl SensitiveBytes {
    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }

    pub fn ct_eq_slice(&self, slice: impl AsRef<[u8]>) -> bool {
        use subtle::ConstantTimeEq as _;
        self.0.ct_eq(slice.as_ref()).into()
    }

    pub fn clear(&mut self) {
        use zeroize::Zeroize as _;
        self.0.zeroize();
        self.0.clear();
    }
}

impl std::hash::Hash for SensitiveBytes {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

#[cfg(not(feature = "hazmat"))]
impl std::fmt::Debug for SensitiveBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[REDACTED]")
    }
}

#[cfg(not(feature = "hazmat"))]
impl std::fmt::Display for SensitiveBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[REDACTED]")
    }
}

#[cfg(feature = "hazmat")]
impl std::fmt::Debug for SensitiveBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", &self.0)
    }
}

#[cfg(feature = "hazmat")]
impl std::fmt::Display for SensitiveBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", &hex::encode(self.0.as_slice()))
    }
}

impl tls_codec::Size for SensitiveBytes {
    fn tls_serialized_len(&self) -> usize {
        crate::tlspl::bytes::tls_serialized_len(&self.0)
    }
}

impl tls_codec::Serialize for SensitiveBytes {
    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        crate::tlspl::bytes::tls_serialize(&self.0, writer)
    }
}

impl tls_codec::Deserialize for SensitiveBytes {
    fn tls_deserialize<R: std::io::Read>(bytes: &mut R) -> Result<Self, tls_codec::Error>
    where
        Self: Sized,
    {
        Ok(Self(crate::tlspl::bytes::tls_deserialize(bytes)?))
    }
}

ref_forward_tls_impl!(SensitiveBytes);

impl From<Vec<u8>> for SensitiveBytes {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

impl From<SensitiveBytes> for Vec<u8> {
    fn from(val: SensitiveBytes) -> Self {
        val.0.clone()
    }
}

impl PartialEq for SensitiveBytes {
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq as _;
        self.0.ct_eq(&other.0).into()
    }
}

impl Eq for SensitiveBytes {}

impl std::ops::Deref for SensitiveBytes {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        self.0.as_slice()
    }
}

impl std::ops::DerefMut for SensitiveBytes {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0.as_mut_slice()
    }
}
