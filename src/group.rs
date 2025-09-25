use crate::{
    SensitiveBytes,
    credential::Credential,
    crypto::SignaturePublicKey,
    defs::{CredentialType, ExtensionType, ProposalType},
};

pub mod commits;
pub mod extensions;
pub mod group_info;
pub mod proposals;
pub mod welcome;

pub type HashReference = SensitiveBytes;
pub type ProposalRef = HashReference;
pub type KeyPackageRef = HashReference;

pub type GroupId = Vec<u8>;
pub type GroupIdRef<'a> = &'a [u8];

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    tls_codec::TlsSerialize,
    tls_codec::TlsDeserialize,
    tls_codec::TlsSize,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct KeyPackageLifetime {
    pub not_before: u64,
    pub not_after: u64,
}

impl KeyPackageLifetime {
    // 14h wiggle room for non-NTP-synced clients
    pub const LIFETIME_WIGGLE_ROOM: u64 = 50_400;
    #[cfg(not(feature = "test-vectors"))]
    // 3 months (93 days)
    pub const MAX_LEAF_NODE_ACCEPTABLE_RANGE: u64 = 8_035_200;
    #[cfg(feature = "test-vectors")]
    pub const MAX_LEAF_NODE_ACCEPTABLE_RANGE: u64 = u64::MAX - Self::LIFETIME_WIGGLE_ROOM;

    /// Validate if the range presented by `not_before` and `not_after` is within an acceptable range
    /// This is currently statically configured to be 3 months as per the spec recommendation
    // TODO: Make it configurable by providing overriding values
    pub fn validate_range(&self) -> bool {
        if self.not_after < self.not_before {
            return false;
        }

        let kp_range = self.not_after.saturating_sub(self.not_before);
        let acceptable_range =
            Self::MAX_LEAF_NODE_ACCEPTABLE_RANGE.saturating_add(Self::LIFETIME_WIGGLE_ROOM);
        kp_range <= acceptable_range
    }

    /// Validate if the [KeyPackageLifetime]'s bounds are around now
    pub fn validate_expiration(&self) -> bool {
        let now = now();
        self.not_before < now && now < self.not_after
    }
}

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
fn now() -> u64 {
    let val = js_sys::Date::now();
    std::time::Duration::from_millis(val as u64).as_secs()
}

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
fn now() -> u64 {
    let now = std::time::SystemTime::now();
    now.duration_since(std::time::SystemTime::UNIX_EPOCH)
        .expect("System clock is before UNIX_EPOCH")
        .as_secs()
}

impl Default for KeyPackageLifetime {
    fn default() -> Self {
        let now = now();
        let not_before = now.saturating_sub(Self::LIFETIME_WIGGLE_ROOM);
        let not_after = now.saturating_add(Self::MAX_LEAF_NODE_ACCEPTABLE_RANGE);
        Self {
            not_before,
            not_after,
        }
    }
}

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    tls_codec::TlsSerialize,
    tls_codec::TlsDeserialize,
    tls_codec::TlsSize,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExternalSender {
    pub signature_key: SignaturePublicKey,
    pub credential: Credential,
}

#[derive(
    Debug,
    Clone,
    Default,
    PartialEq,
    Eq,
    Hash,
    tls_codec::TlsSerialize,
    tls_codec::TlsDeserialize,
    tls_codec::TlsSize,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RequiredCapabilities {
    pub extension_types: Vec<ExtensionType>,
    pub proposal_types: Vec<ProposalType>,
    pub credential_types: Vec<CredentialType>,
}
