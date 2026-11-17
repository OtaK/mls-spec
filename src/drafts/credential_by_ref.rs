use crate::{defs::CredentialType, group::HashReference};

pub const CREDENTIAL_BY_REF: u16 = 0xFB7F; // TODO: Waiting for IANA registration (suggested 0x0007)
static_assertions::const_assert!(
    *CredentialType::RESERVED_PRIVATE_USE_RANGE.start() <= CREDENTIAL_BY_REF
        && CREDENTIAL_BY_REF <= *CredentialType::RESERVED_PRIVATE_USE_RANGE.end()
);

/// <https://www.ietf.org/archive/id/draft-mahy-mls-credential-by-ref-00.html#section-3>
///
/// ### TLS Presentation Language
///
/// ```notrust,ignore
/// struct {
///     CredentialType referenced_credential_type;
///     HashReference referenced_credential_hash<V>;
/// } ByRefCredential;
/// ```
///
/// The spec's trailing `<V>` would make this a list of `HashReference`s, but its prose
/// describes a single hash of the referenced `Credential`; this follows the prose.
#[derive(Debug, Clone, PartialEq, Eq, Hash, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ByRefCredential<'a> {
    pub referenced_credential_type: CredentialType,
    pub referenced_credential_hash: HashReference<'a>,
}

impl ByRefCredential<'_> {
    pub fn to_owned<'out>(&self) -> ByRefCredential<'out> {
        ByRefCredential {
            referenced_credential_type: self.referenced_credential_type,
            referenced_credential_hash: self.referenced_credential_hash.to_vec().into(),
        }
    }
}
