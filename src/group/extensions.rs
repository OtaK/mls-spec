use crate::{
    crypto::HpkePublicKey,
    group::{ExtensionType, ExternalSender, RequiredCapabilities},
    macros::ref_forward_tls_impl,
    tlspl::{bytes as vlbytes, tls_serialized_len_as_vlvec},
    tree::RatchetTree,
};

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    tls_codec::TlsDeserialize,
    tls_codec::TlsSerialize,
    tls_codec::TlsSize,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RatchetTreeExtension {
    pub ratchet_tree: RatchetTree,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u16)]
pub enum Extension {
    /// Extension to uniquely identify clients
    ///
    /// <https://www.rfc-editor.org/rfc/rfc9420.html#section-5.3.3>
    ApplicationId(Vec<u8>),
    /// Sparse vec of TreeNodes, that is right-trimmed
    RatchetTree(RatchetTreeExtension),
    RequiredCapabilities(RequiredCapabilities),
    /// Extension that enables "External Joins" via external commits
    ExternalPub(ExternalPub),
    /// Extension that allows external proposals to be signed by a third party (i.e. a server or something)
    ExternalSenders(Vec<ExternalSender>),
    #[cfg(feature = "draft-ietf-mls-extensions")]
    ApplicationData(crate::drafts::mls_extensions::safe_application::ApplicationDataDictionary),
    #[cfg(feature = "draft-ietf-mls-extensions")]
    SupportedWireFormats(crate::drafts::mls_extensions::safe_application::WireFormats),
    #[cfg(feature = "draft-ietf-mls-extensions")]
    RequiredWireFormats(crate::drafts::mls_extensions::safe_application::WireFormats),
    #[cfg(feature = "draft-ietf-mls-extensions")]
    TargetedMessagesCapability,
    Arbitrary(ArbitraryExtension),
}

impl From<&Extension> for ExtensionType {
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
            #[cfg(feature = "draft-ietf-mls-extensions")]
            Extension::TargetedMessagesCapability => ExtensionType::TARGETED_MESSAGES_CAPABILITY,
            Extension::Arbitrary(ArbitraryExtension { extension_id, .. }) => {
                (**extension_id) as u16
            }
        })
    }
}

impl Extension {
    pub fn new(extension_id: u16, extension_data: Vec<u8>) -> crate::MlsSpecResult<Self> {
        use tls_codec::Deserialize as _;
        Ok(match extension_id {
            ExtensionType::APPLICATION_ID => {
                Self::ApplicationId(vlbytes::tls_deserialize(&mut &extension_data[..])?)
            }
            ExtensionType::RATCHET_TREE => Self::RatchetTree(
                RatchetTreeExtension::tls_deserialize_exact(&extension_data)?,
            ),
            ExtensionType::REQUIRED_CAPABILITIES => Self::RequiredCapabilities(
                RequiredCapabilities::tls_deserialize_exact(&extension_data)?,
            ),
            ExtensionType::EXTERNAL_PUB => {
                Self::ExternalPub(ExternalPub::tls_deserialize_exact(&extension_data)?)
            }
            ExtensionType::EXTERNAL_SENDERS => Self::ExternalSenders(
                Vec::<ExternalSender>::tls_deserialize_exact(&extension_data)?,
            ),
            #[cfg(feature = "draft-ietf-mls-extensions")]
            ExtensionType::APPLICATION_DATA_DICTIONARY => Self::ApplicationData(
                crate::drafts::mls_extensions::safe_application::ApplicationDataDictionary::tls_deserialize_exact(
                    &extension_data,
                )?,
            ),
            #[cfg(feature = "draft-ietf-mls-extensions")]
            ExtensionType::SUPPORTED_WIRE_FORMATS => Self::SupportedWireFormats(<_>::tls_deserialize_exact(&extension_data)?),
            #[cfg(feature = "draft-ietf-mls-extensions")]
            ExtensionType::REQUIRED_WIRE_FORMATS => Self::RequiredWireFormats(<_>::tls_deserialize_exact(&extension_data)?),
            #[cfg(feature = "draft-ietf-mls-extensions")]
            ExtensionType::TARGETED_MESSAGES_CAPABILITY => Self::TargetedMessagesCapability,
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

impl tls_codec::Size for Extension {
    fn tls_serialized_len(&self) -> usize {
        let ext_type_len = ExtensionType::from(self).tls_serialized_len();
        let ext_value_len = match self {
            Extension::ApplicationId(data) => {
                tls_serialized_len_as_vlvec(data.tls_serialized_len())
            }
            Extension::RatchetTree(nodes) => {
                tls_serialized_len_as_vlvec(nodes.tls_serialized_len())
            }
            Extension::RequiredCapabilities(caps) => {
                tls_serialized_len_as_vlvec(caps.tls_serialized_len())
            }
            Extension::ExternalPub(ext_pub) => {
                tls_serialized_len_as_vlvec(ext_pub.tls_serialized_len())
            }
            Extension::ExternalSenders(ext_senders) => {
                tls_serialized_len_as_vlvec(ext_senders.tls_serialized_len())
            }
            #[cfg(feature = "draft-ietf-mls-extensions")]
            Extension::ApplicationData(app_data_dict) => {
                tls_serialized_len_as_vlvec(app_data_dict.tls_serialized_len())
            }
            #[cfg(feature = "draft-ietf-mls-extensions")]
            Extension::SupportedWireFormats(wfs) | Extension::RequiredWireFormats(wfs) => {
                tls_serialized_len_as_vlvec(wfs.tls_serialized_len())
            }
            #[cfg(feature = "draft-ietf-mls-extensions")]
            Extension::TargetedMessagesCapability => tls_serialized_len_as_vlvec(0),
            Extension::Arbitrary(ArbitraryExtension { extension_data, .. }) => {
                tls_serialized_len_as_vlvec(extension_data.len())
            }
        };

        ext_type_len + ext_value_len
    }
}

impl tls_codec::Serialize for Extension {
    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        use tls_codec::Size as _;

        let extension_id = ExtensionType::from(self);
        let mut written = extension_id.tls_serialize(writer)?;

        // FIXME: Probably can get rid of this copy
        let extdata_len = self.tls_serialized_len() - written;
        let mut extension_data = Vec::with_capacity(extdata_len);

        let _ = match self {
            Extension::ApplicationId(data) => data.tls_serialize(&mut extension_data)?,
            Extension::RatchetTree(nodes) => nodes.tls_serialize(&mut extension_data)?,
            Extension::RequiredCapabilities(caps) => caps.tls_serialize(&mut extension_data)?,
            Extension::ExternalPub(ext_pub) => ext_pub.tls_serialize(&mut extension_data)?,
            Extension::ExternalSenders(ext_senders) => {
                ext_senders.tls_serialize(&mut extension_data)?
            }
            #[cfg(feature = "draft-ietf-mls-extensions")]
            Extension::ApplicationData(app_data_dict) => {
                app_data_dict.tls_serialize(&mut extension_data)?
            }
            #[cfg(feature = "draft-ietf-mls-extensions")]
            Extension::SupportedWireFormats(wfs) | Extension::RequiredWireFormats(wfs) => {
                wfs.tls_serialize(&mut extension_data)?
            }
            #[cfg(feature = "draft-ietf-mls-extensions")]
            Extension::TargetedMessagesCapability => [0u8; 0].tls_serialize(&mut extension_data)?,
            Extension::Arbitrary(ArbitraryExtension {
                extension_data: arbitrary_ext_data,
                ..
            }) => {
                use std::io::Write as _;
                extension_data.write_all(arbitrary_ext_data)?;
                arbitrary_ext_data.len()
            }
        };

        written += extension_data.tls_serialize(writer)?;

        Ok(written)
    }
}

impl tls_codec::Deserialize for Extension {
    fn tls_deserialize<R: std::io::Read>(bytes: &mut R) -> Result<Self, tls_codec::Error>
    where
        Self: Sized,
    {
        Self::new(
            *ExtensionType::tls_deserialize(bytes)?,
            vlbytes::tls_deserialize(bytes)?,
        )
        .map_err(|e| match e {
            crate::MlsSpecError::TlsCodecError(e) => e,
            _ => tls_codec::Error::DecodingError(e.to_string()),
        })
    }
}

ref_forward_tls_impl!(Extension);

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    tls_codec::TlsSerialize,
    tls_codec::TlsDeserialize,
    tls_codec::TlsSize,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExternalPub {
    pub external_pub: HpkePublicKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ArbitraryExtension {
    pub extension_id: ExtensionType,
    pub extension_data: Vec<u8>,
}
