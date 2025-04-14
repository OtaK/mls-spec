#![allow(clippy::unnecessary_cast, non_upper_case_globals, non_camel_case_types)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
mod error;
pub use self::error::*;

pub mod reexports {
    #[cfg(feature = "draft-ietf-mls-extensions-content-advertisement-parse")]
    pub use mediatype;

    pub use tls_codec;
}

pub mod credential;
pub mod crypto;
pub mod defs;
pub mod group;
pub mod key_package;
pub mod key_schedule;
pub mod messages;
pub mod tree;

pub mod drafts;

pub(crate) mod macros;
#[cfg(feature = "test-utils")]
pub mod test_utils;

#[cfg(feature = "tlspl-utils")]
pub mod tlspl;
#[cfg(not(feature = "tlspl-utils"))]
pub(crate) mod tlspl;

mod sensitive_bytes;
pub use sensitive_bytes::*;

/// This trait allows implementers to automatically get a MLS-specific representation
/// that takes in account protocol versions and the label format.
///
/// For example, the MLS 1.0 format is `MLS 1.0 {label}`.
pub trait ToPrefixedLabel: std::fmt::Display {
    fn to_prefixed_string(&self, protocol_version: crate::defs::ProtocolVersion) -> String {
        format!("{protocol_version} {self}")
    }
}

#[async_trait::async_trait]
/// Delegate trait for implementors to implement spec-compliant validation of credentials
/// with their Authentication Service (MLS AS)
pub trait AuthenticationServiceDelegate: Send + Sync {
    async fn validate_credential(&self, credential: &crate::credential::Credential) -> bool;
}

/// Trait that exposes TLS serialization
pub trait Serializable {
    fn to_tls_bytes(&self) -> MlsSpecResult<Vec<u8>>;
}

impl<T> Serializable for T
where
    T: tls_codec::Serialize,
{
    fn to_tls_bytes(&self) -> MlsSpecResult<Vec<u8>> {
        Ok(self.tls_serialize_detached()?)
    }
}

/// Trait that exposes TLS deserialization
pub trait Parsable {
    fn from_tls_bytes(bytes: &[u8]) -> MlsSpecResult<Self>
    where
        Self: Sized;
}

impl<T> Parsable for T
where
    T: tls_codec::Deserialize,
{
    fn from_tls_bytes(mut bytes: &[u8]) -> MlsSpecResult<Self>
    where
        Self: Sized,
    {
        Ok(T::tls_deserialize(&mut bytes)?)
    }
}

#[cfg(feature = "mls-rs-compat")]
pub mod mls_rs_compat {
    use crate::Serializable;

    /// Trait that allows to move from mls-spec data structs to mls-rs
    /// It is inefficient by nature because in order to bypass the Rust type system,
    /// we're using serialization/deserialization as a "boundary break"
    ///
    /// Additionally, none of the trait implementations are done here because we don't want to
    /// depend directly on `mls_rs`. So you'll have to implement it on *your* side like such:
    ///
    /// ```rust,ignore
    /// impl mls_spec::mls_rs_compat::MlsRsTranscode for mls_rs::MlsMessage {
    ///     type Target = mls_spec::messages::MlsMessage;
    /// }
    /// ```
    ///
    pub trait MlsRsTranscode: mls_rs_codec::MlsDecode + mls_rs_codec::MlsEncode {
        type Target: crate::Parsable + crate::Serializable;

        fn transcode_from_mls_spec(item: &Self::Target) -> Result<Self, crate::MlsSpecError>
        where
            Self: Sized,
        {
            let tls_bytes = item.to_tls_bytes()?;
            Ok(Self::mls_decode(&mut &tls_bytes[..])?)
        }

        fn transcode_to_mls_spec(&self) -> Result<Self::Target, crate::MlsSpecError> {
            use crate::Parsable as _;
            let tls_bytes = self.mls_encode_to_vec()?;
            Self::Target::from_tls_bytes(&tls_bytes)
        }
    }
}
