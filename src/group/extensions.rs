use std::borrow::Cow;

use crate::{
    crypto::HpkePublicKey,
    group::{ExtensionType, ExternalSender, RequiredCapabilities},
    tree::RatchetTree,
};

#[derive(Debug, Clone, PartialEq, Eq, Hash, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RatchetTreeExtension<'a> {
    pub ratchet_tree: RatchetTree<'a>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[tlspl(extensible)]
#[repr(u16)]
pub enum Extension<'a> {
    /// Extension to uniquely identify clients
    ///
    /// <https://www.rfc-editor.org/rfc/rfc9420.html#section-5.3.3>
    #[tlspl(discriminant = "ExtensionType::APPLICATION_ID")]
    ApplicationId(Cow<'a, [u8]>),
    /// Sparse vec of TreeNodes, that is right-trimmed
    #[tlspl(discriminant = "ExtensionType::RATCHET_TREE")]
    RatchetTree(RatchetTreeExtension<'a>),
    #[tlspl(discriminant = "ExtensionType::REQUIRED_CAPABILITIES")]
    RequiredCapabilities(RequiredCapabilities),
    /// Extension that enables "External Joins" via external commits
    #[tlspl(discriminant = "ExtensionType::EXTERNAL_PUB")]
    ExternalPub(ExternalPub<'a>),
    /// Extension that allows external proposals to be signed by a third party (i.e. a server or something)
    #[tlspl(discriminant = "ExtensionType::EXTERNAL_SENDERS")]
    ExternalSenders(Vec<ExternalSender<'a>>),
    #[cfg(feature = "draft-ietf-mls-extensions")]
    #[tlspl(discriminant = "ExtensionType::APPLICATION_DATA_DICTIONARY")]
    ApplicationData(crate::drafts::mls_extensions::safe_application::ApplicationDataDictionary<'a>),
    #[cfg(feature = "draft-ietf-mls-extensions")]
    #[tlspl(discriminant = "ExtensionType::SUPPORTED_WIRE_FORMATS")]
    SupportedWireFormats(crate::drafts::mls_extensions::safe_application::WireFormats),
    #[cfg(feature = "draft-ietf-mls-extensions")]
    #[tlspl(discriminant = "ExtensionType::REQUIRED_WIRE_FORMATS")]
    RequiredWireFormats(crate::drafts::mls_extensions::safe_application::WireFormats),
    #[cfg(feature = "draft-ietf-mls-ratchet-tree-options")]
    #[tlspl(discriminant = "ExtensionType::RATCHET_TREE_SOURCE_DOMAINS")]
    RatchetTreeSourceDomains(
        crate::drafts::ratchet_tree_options::RatchetTreeSourceDomainsExtension<'a>,
    ),
    #[tlspl(other)]
    Arbitrary(u16, Cow<'a, [u8]>),
}

impl From<&Extension<'_>> for ExtensionType {
    fn from(value: &Extension) -> Self {
        ExtensionType::new_unchecked(match value {
            Extension::ApplicationId(_) => ExtensionType::APPLICATION_ID,
            Extension::RatchetTree(_) => ExtensionType::RATCHET_TREE,
            Extension::RequiredCapabilities(_) => ExtensionType::REQUIRED_CAPABILITIES,
            Extension::ExternalPub(_) => ExtensionType::EXTERNAL_PUB,
            Extension::ExternalSenders(_) => ExtensionType::EXTERNAL_SENDERS,
            #[cfg(feature = "draft-ietf-mls-extensions")]
            Extension::ApplicationData(_) => ExtensionType::APPLICATION_DATA_DICTIONARY,
            #[cfg(feature = "draft-ietf-mls-extensions")]
            Extension::SupportedWireFormats(_) => ExtensionType::SUPPORTED_WIRE_FORMATS,
            #[cfg(feature = "draft-ietf-mls-extensions")]
            Extension::RequiredWireFormats(_) => ExtensionType::REQUIRED_WIRE_FORMATS,
            #[cfg(feature = "draft-ietf-mls-ratchet-tree-options")]
            Extension::RatchetTreeSourceDomains(_) => ExtensionType::RATCHET_TREE_SOURCE_DOMAINS,
            Extension::Arbitrary(id, _) => *id,
        })
    }
}

impl<'a> Extension<'a> {
    #[deprecated(since = "3.0.0", note = "Use `Extension::try_new` for this API")]
    #[inline]
    pub fn new(extension_id: u16, extension_data: Cow<'a, [u8]>) -> crate::MlsSpecResult<Self> {
        Self::try_new(extension_id, extension_data)
    }

    pub fn try_new(
        extension_id: u16,
        mut extension_data: Cow<'a, [u8]>,
    ) -> crate::MlsSpecResult<Self> {
        use thalassa::TlsplDeserialize as _;

        Ok(match extension_id {
            ExtensionType::APPLICATION_ID => {
                Self::ApplicationId(<_>::tlspl_deserialize_from(&mut extension_data)?)
            }
            ExtensionType::RATCHET_TREE => {
                Self::RatchetTree(<_>::tlspl_deserialize_from(&mut extension_data)?)
            }
            ExtensionType::REQUIRED_CAPABILITIES => {
                Self::RequiredCapabilities(<_>::tlspl_deserialize_from(&mut extension_data)?)
            }
            ExtensionType::EXTERNAL_PUB => {
                Self::ExternalPub(<_>::tlspl_deserialize_from(&mut extension_data)?)
            }
            ExtensionType::EXTERNAL_SENDERS => {
                Self::ExternalSenders(<_>::tlspl_deserialize_from(&mut extension_data)?)
            }
            #[cfg(feature = "draft-ietf-mls-extensions")]
            ExtensionType::APPLICATION_DATA_DICTIONARY => {
                Self::ApplicationData(<_>::tlspl_deserialize_from(&mut extension_data)?)
            }
            #[cfg(feature = "draft-ietf-mls-extensions")]
            ExtensionType::SUPPORTED_WIRE_FORMATS => {
                Self::SupportedWireFormats(<_>::tlspl_deserialize_from(&mut extension_data)?)
            }
            #[cfg(feature = "draft-ietf-mls-extensions")]
            ExtensionType::REQUIRED_WIRE_FORMATS => {
                Self::RequiredWireFormats(<_>::tlspl_deserialize_from(&mut extension_data)?)
            }
            #[cfg(feature = "draft-ietf-mls-ratchet-tree-options")]
            ExtensionType::RATCHET_TREE_SOURCE_DOMAINS => {
                Self::RatchetTreeSourceDomains(<_>::tlspl_deserialize_from(&mut extension_data)?)
            }
            discr => Self::Arbitrary(discr, extension_data),
        })
    }

    pub fn ext_type(&self) -> ExtensionType {
        self.into()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExternalPub<'a> {
    pub external_pub: HpkePublicKey<'a>,
}
