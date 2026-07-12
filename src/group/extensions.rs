use std::borrow::Cow;

use thalassa::{TlsplDeserialize, error::TlsplError};

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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u16)]
pub enum Extension<'a> {
    /// Extension to uniquely identify clients
    ///
    /// <https://www.rfc-editor.org/rfc/rfc9420.html#section-5.3.3>
    ApplicationId(Cow<'a, [u8]>),
    /// Sparse vec of TreeNodes, that is right-trimmed
    RatchetTree(RatchetTreeExtension<'a>),
    RequiredCapabilities(RequiredCapabilities),
    /// Extension that enables "External Joins" via external commits
    ExternalPub(ExternalPub<'a>),
    /// Extension that allows external proposals to be signed by a third party (i.e. a server or something)
    ExternalSenders(Vec<ExternalSender<'a>>),
    #[cfg(feature = "draft-ietf-mls-extensions")]
    ApplicationData(crate::drafts::mls_extensions::safe_application::ApplicationDataDictionary<'a>),
    #[cfg(feature = "draft-ietf-mls-extensions")]
    SupportedWireFormats(crate::drafts::mls_extensions::safe_application::WireFormats),
    #[cfg(feature = "draft-ietf-mls-extensions")]
    RequiredWireFormats(crate::drafts::mls_extensions::safe_application::WireFormats),
    #[cfg(feature = "draft-ietf-mls-ratchet-tree-options")]
    RatchetTreeSourceDomains(
        crate::drafts::ratchet_tree_options::RatchetTreeSourceDomainsExtension<'a>,
    ),
    Arbitrary(ArbitraryExtension<'a>),
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
            Extension::Arbitrary(ArbitraryExtension { extension_id, .. }) => {
                (**extension_id) as u16
            }
        })
    }
}

impl<'a> Extension<'a> {
    pub fn new(extension_id: u16, mut extension_data: Cow<'a, [u8]>) -> crate::MlsSpecResult<Self> {
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
            _ => Self::Arbitrary(ArbitraryExtension {
                extension_id: ExtensionType::new_unchecked(extension_id),
                extension_data,
            }),
        })
    }

    pub fn ext_type(&self) -> ExtensionType {
        self.into()
    }
}

impl thalassa::TlsplSize for Extension<'_> {
    fn tlspl_serialized_len(&self) -> usize {
        let ext_content_cl = match self {
            Extension::ApplicationId(data) => data.tlspl_serialized_len(),
            Extension::RatchetTree(nodes) => nodes.tlspl_serialized_len(),
            Extension::RequiredCapabilities(caps) => caps.tlspl_serialized_len(),
            Extension::ExternalPub(ext_pub) => ext_pub.tlspl_serialized_len(),
            Extension::ExternalSenders(ext_senders) => ext_senders.tlspl_serialized_len(),
            #[cfg(feature = "draft-ietf-mls-extensions")]
            Extension::ApplicationData(app_data_dict) => app_data_dict.tlspl_serialized_len(),
            #[cfg(feature = "draft-ietf-mls-extensions")]
            Extension::SupportedWireFormats(wfs) | Extension::RequiredWireFormats(wfs) => {
                wfs.tlspl_serialized_len()
            }
            #[cfg(feature = "draft-ietf-mls-ratchet-tree-options")]
            Extension::RatchetTreeSourceDomains(rtsd) => rtsd.tlspl_serialized_len(),
            Extension::Arbitrary(ArbitraryExtension { extension_data, .. }) => {
                extension_data.tlspl_serialized_len()
            }
        };

        2 + thalassa::types::content_len_as_vlbytes_overhead(ext_content_cl) + ext_content_cl
    }
}

impl thalassa::TlsplSerialize for Extension<'_> {
    fn tlspl_serialize_to<W: thalassa::io::Write>(
        &self,
        writer: &mut W,
    ) -> thalassa::error::TlsplWriteResult<usize> {
        let arbitrary = match self {
            Extension::ApplicationId(data) => &ArbitraryExtension {
                extension_id: ExtensionType::new_unchecked(ExtensionType::APPLICATION_ID),
                extension_data: data.tlspl_serialize()?.into(),
            },
            Extension::RatchetTree(nodes) => &ArbitraryExtension {
                extension_id: ExtensionType::new_unchecked(ExtensionType::RATCHET_TREE),
                extension_data: nodes.tlspl_serialize()?.into(),
            },
            Extension::RequiredCapabilities(caps) => &ArbitraryExtension {
                extension_id: ExtensionType::new_unchecked(ExtensionType::REQUIRED_CAPABILITIES),
                extension_data: caps.tlspl_serialize()?.into(),
            },
            Extension::ExternalPub(ext_pub) => &ArbitraryExtension {
                extension_id: ExtensionType::new_unchecked(ExtensionType::EXTERNAL_PUB),
                extension_data: ext_pub.tlspl_serialize()?.into(),
            },
            Extension::ExternalSenders(ext_senders) => &ArbitraryExtension {
                extension_id: ExtensionType::new_unchecked(ExtensionType::EXTERNAL_SENDERS),
                extension_data: ext_senders.tlspl_serialize()?.into(),
            },
            #[cfg(feature = "draft-ietf-mls-extensions")]
            Extension::ApplicationData(app_data_dict) => &ArbitraryExtension {
                extension_id: ExtensionType::new_unchecked(
                    ExtensionType::APPLICATION_DATA_DICTIONARY,
                ),
                extension_data: app_data_dict.tlspl_serialize()?.into(),
            },
            #[cfg(feature = "draft-ietf-mls-extensions")]
            Extension::SupportedWireFormats(wfs) => &ArbitraryExtension {
                extension_id: ExtensionType::new_unchecked(ExtensionType::SUPPORTED_WIRE_FORMATS),
                extension_data: wfs.tlspl_serialize()?.into(),
            },
            #[cfg(feature = "draft-ietf-mls-extensions")]
            Extension::RequiredWireFormats(wfs) => &ArbitraryExtension {
                extension_id: ExtensionType::new_unchecked(ExtensionType::REQUIRED_WIRE_FORMATS),
                extension_data: wfs.tlspl_serialize()?.into(),
            },
            #[cfg(feature = "draft-ietf-mls-ratchet-tree-options")]
            Extension::RatchetTreeSourceDomains(rtsd) => &ArbitraryExtension {
                extension_id: ExtensionType::new_unchecked(
                    ExtensionType::RATCHET_TREE_SOURCE_DOMAINS,
                ),
                extension_data: rtsd.tlspl_serialize()?.into(),
            },
            Extension::Arbitrary(arbitrary) => arbitrary,
        };

        arbitrary.tlspl_serialize_to(writer)
    }
}

impl<'a> thalassa::TlsplDeserialize<'a> for Extension<'a> {
    fn tlspl_deserialize_from<R: thalassa::io::Read<'a>>(
        reader: &mut R,
    ) -> thalassa::error::TlsplReadResult<Self>
    where
        Self: Sized + 'a,
    {
        let ArbitraryExtension {
            extension_id,
            extension_data,
        } = ArbitraryExtension::tlspl_deserialize_from(reader)?;

        Self::new(*extension_id, extension_data).map_err(|mls_spec_err| match mls_spec_err {
            crate::MlsSpecError::ThalassaError(TlsplError::Read(tlspl_read_err)) => tlspl_read_err,
            _ => thalassa::error::TlsplReadError::VlBytesLengthOverflow,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExternalPub<'a> {
    pub external_pub: HpkePublicKey<'a>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ArbitraryExtension<'a> {
    pub extension_id: ExtensionType,
    /// This MUST be already serialized as VLBytes
    pub extension_data: Cow<'a, [u8]>,
}
