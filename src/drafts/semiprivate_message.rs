use crate::{
    SensitiveBytes,
    credential::Credential,
    crypto::{HpkeCiphertext, HpkePublicKey},
    defs::{Epoch, LeafIndex, WireFormat},
    group::{GroupId, HashReference},
    messages::ReuseGuard,
};

use super::mls_extensions::safe_application::{Component, ComponentId};

pub const EXTERNAL_RECEIVERS_COMPONENT_ID: ComponentId = 0xFEEE; // TODO: Waiting for IANA registration (suggested 0x0008)
static_assertions::const_assert!(
    *super::mls_extensions::COMPONENT_RESERVED_PRIVATE_RANGE.start()
        <= EXTERNAL_RECEIVERS_COMPONENT_ID
        && EXTERNAL_RECEIVERS_COMPONENT_ID
            <= *super::mls_extensions::COMPONENT_RESERVED_PRIVATE_RANGE.end()
);

pub const WIRE_FORMAT_MLS_SEMIPRIVATE_MESSAGE: u16 = 0xFAFE; // TODO: Waiting for IANA registration
static_assertions::const_assert!(
    *WireFormat::RESERVED_PRIVATE_USE_RANGE.start() <= WIRE_FORMAT_MLS_SEMIPRIVATE_MESSAGE
        && WIRE_FORMAT_MLS_SEMIPRIVATE_MESSAGE <= *WireFormat::RESERVED_PRIVATE_USE_RANGE.end()
);

pub type ExternalReceiverRef<'a> = HashReference<'a>;

#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExternalReceiver<'a> {
    pub external_receiver_public_key: HpkePublicKey<'a>,
    pub credential: Credential<'a>,
}

#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExternalReceivers<'a> {
    pub external_receivers: Vec<ExternalReceiver<'a>>,
}

impl<'a> Component<'a> for ExternalReceivers<'a> {
    fn component_id() -> ComponentId {
        EXTERNAL_RECEIVERS_COMPONENT_ID
    }
}

/// <https://rohanmahy.github.io/mls-semiprivatemessage/draft-mahy-mls-semiprivatemessage.html#section-3.1-2>
///
/// ```notrust,ignore
/// struct {
///   opaque key<V>;
///   opaque nonce<V>;
///   opaque reuse_guard[4];
///   uint32 sender_leaf_index;
/// } PerMessageKeyAndNonces;
/// ```
///
#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PerMessageKeyAndNonces<'a> {
    pub key: SensitiveBytes<'a>,
    pub nonce: SensitiveBytes<'a>,
    pub reuse_guard: ReuseGuard,
    pub sender_leaf_index: LeafIndex,
}

#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplSerialize, thalassa::TlsplSize)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct SemiPrivateMessageContext<'a> {
    pub group_id: GroupId<'a>,
    pub epoch: &'a Epoch,
    pub partial_context_hash: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct KeyForExternalReceiver<'a> {
    pub external_receiver_ref: ExternalReceiverRef<'a>,
    pub encrypted_keys_and_nonces: HpkeCiphertext<'a>,
}

pub mod messages {
    use thalassa::{TlsplDeserialize, error::TlsplReadError, io::Read};

    use crate::{
        CRATE_NAME, SensitiveBytes,
        defs::Epoch,
        group::{GroupId, commits::Commit, proposals::Proposal},
        messages::{ContentType, ContentTypeInner, FramedContentAuthData},
    };

    use super::KeyForExternalReceiver;

    #[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplSerialize, thalassa::TlsplSize)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize))]
    pub struct SemiPrivateContentAad<'a> {
        pub group_id: GroupId<'a>,
        pub epoch: &'a Epoch,
        pub content_type: &'a ContentType,
        pub authenticated_data: &'a [u8],
        pub partial_context_hash: &'a [u8],
        pub keys_for_external_receivers: &'a [KeyForExternalReceiver<'a>],
        pub framed_content_tbs_hash: &'a [u8],
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct SemiPrivateMessageContent<'a> {
        pub inner: ContentTypeInner<'a>,
        pub auth: FramedContentAuthData<'a>,
        pub padding_len: usize,
    }

    impl thalassa::TlsplSize for SemiPrivateMessageContent<'_> {
        #[inline]
        fn tlspl_serialized_len(&self) -> usize {
            self.inner.tlspl_serialized_len() + self.auth.tlspl_serialized_len() + self.padding_len
        }
    }

    impl thalassa::TlsplSerialize for SemiPrivateMessageContent<'_> {
        #[inline]
        fn tlspl_serialize_to<W: thalassa::io::Write>(
            &self,
            writer: &mut W,
        ) -> thalassa::error::TlsplWriteResult<usize> {
            let written = self.inner.tlspl_serialize_to(writer)?
                + self.auth.tlspl_serialize_to(writer)?
                + self.padding_len;
            writer.write_all(&vec![0u8; self.padding_len])?;

            Ok(written)
        }
    }

    impl<'a> SemiPrivateMessageContent<'a> {
        pub fn tls_deserialize_with_content_type<R: Read<'a>>(
            reader: &mut R,
            content_type: ContentType,
        ) -> Result<Self, TlsplReadError> {
            let inner = match content_type {
                ContentType::Proposal => ContentTypeInner::Proposal {
                    proposal: Proposal::tlspl_deserialize_from(reader)?,
                },
                ContentType::Commit => ContentTypeInner::Commit {
                    commit: Commit::tlspl_deserialize_from(reader)?,
                },
                _ => {
                    return Err(TlsplReadError::custom(
                        CRATE_NAME,
                        format!(
                            "Tried to deserialize a {content_type}, which is invalid for a SemiPrivateMessage"
                        ),
                    ));
                }
            };
            let auth = FramedContentAuthData::tlspl_deserialize_from_with_content_type(
                reader,
                content_type,
            )?;

            let padding_len = crate::consume_padding(reader)?;

            Ok(Self {
                inner,
                auth,
                padding_len,
            })
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct SemiPrivateMessage<'a> {
        pub group_id: GroupId<'a>,
        pub epoch: Epoch,
        pub content_type: ContentType,
        pub authenticated_data: SensitiveBytes<'a>,
        pub partial_context_hash: SensitiveBytes<'a>,
        pub keys_for_external_receivers: Vec<KeyForExternalReceiver<'a>>,
        pub framed_content_tbs_hash: SensitiveBytes<'a>,
        pub encrypted_sender_data: SensitiveBytes<'a>,
        pub ciphertext: SensitiveBytes<'a>,
    }
}
