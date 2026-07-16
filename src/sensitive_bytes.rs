use std::borrow::Cow;

/// Container that ser/deserializes to TLS Variable-Length bytes
/// and implements zeroizing & constant-time equality checks
#[derive(Clone, Default, Ord, PartialOrd, Hash, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(transparent)]
pub struct SensitiveBytes<'a>(Cow<'a, [u8]>);

impl SensitiveBytes<'_> {
    #[inline]
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn ct_eq_slice(&self, slice: impl AsRef<[u8]>) -> bool {
        use subtle::ConstantTimeEq as _;
        self.0.ct_eq(slice.as_ref()).into()
    }

    pub fn clear(&mut self) {
        use zeroize::Zeroize as _;
        // Upgrade to an owned container first
        let _ = self.0.to_mut();
        // Zeroize memory
        self.zeroize();
        let owned_ref = self.0.to_mut();
        // Clear & shrink the vec
        owned_ref.clear();
        owned_ref.shrink_to_fit();
    }
}

impl zeroize::Zeroize for SensitiveBytes<'_> {
    fn zeroize(&mut self) {
        match &mut self.0 {
            Cow::Borrowed(_) => {} // Borrowed, not up to us to zeroize
            Cow::Owned(vec) => vec.zeroize(),
        }
    }
}

impl Drop for SensitiveBytes<'_> {
    fn drop(&mut self) {
        use zeroize::Zeroize as _;
        self.zeroize();
    }
}

#[cfg(not(feature = "hazmat"))]
impl std::fmt::Debug for SensitiveBytes<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[REDACTED]")
    }
}

#[cfg(not(feature = "hazmat"))]
impl std::fmt::Display for SensitiveBytes<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[REDACTED]")
    }
}

#[cfg(feature = "hazmat")]
impl std::fmt::Debug for SensitiveBytes<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

#[cfg(feature = "hazmat")]
impl std::fmt::Display for SensitiveBytes<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(&*self.0))
    }
}

impl From<Vec<u8>> for SensitiveBytes<'_> {
    #[inline]
    fn from(value: Vec<u8>) -> Self {
        Self(Cow::Owned(value))
    }
}

impl PartialEq for SensitiveBytes<'_> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq as _;
        self.0.ct_eq(&other.0).into()
    }
}

impl Eq for SensitiveBytes<'_> {}

impl<'a> std::ops::Deref for SensitiveBytes<'a> {
    type Target = [u8];
    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for SensitiveBytes<'_> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0.to_mut()
    }
}
