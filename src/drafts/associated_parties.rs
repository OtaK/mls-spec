use crate::{
    SensitiveBytes, crypto::HpkePublicKey, defs::SenderIndex, group::ExternalSender,
    key_schedule::GroupContext,
};

use super::mls_extensions::safe_application::{Component, ComponentId};

pub const COMPONENT_ID: ComponentId = 0x0007;

#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplSize, thalassa::TlsplSerialize)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct AssociatedPartyEntryTBS<'a> {
    pub encryption_key: &'a HpkePublicKey<'a>,
    pub external_sender_index: &'a SenderIndex,
}

#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AssociatedPartyEntry<'a> {
    pub encryption_key: HpkePublicKey<'a>,
    pub external_sender_index: SenderIndex,
    pub signature: SensitiveBytes<'a>,
}

impl<'a> AssociatedPartyEntry<'a> {
    pub fn to_tbs(&self) -> AssociatedPartyEntryTBS<'_> {
        AssociatedPartyEntryTBS {
            encryption_key: &self.encryption_key,
            external_sender_index: &self.external_sender_index,
        }
    }

    /// Finds the related `ExternalSender` from the provided `GroupContext`.
    ///
    /// If this returns `None`, then you can safely consider the AssociatedParty to be invalid!
    pub fn related_external_sender_from_group_context(
        &self,
        ctx: &'a GroupContext<'a>,
    ) -> Option<&'a ExternalSender<'a>> {
        ctx.external_senders()
            .get(self.external_sender_index as usize)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AssociatedParties<'a> {
    pub associated_parties: Vec<AssociatedPartyEntry<'a>>,
}

impl<'a> Component<'a> for AssociatedParties<'a> {
    fn component_id() -> ComponentId {
        COMPONENT_ID
    }
}

pub mod proposals {
    use crate::defs::LeafIndex;

    use super::AssociatedPartyEntry;

    #[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct AddAssociatedPartyProposal<'a> {
        pub new_party: AssociatedPartyEntry<'a>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, thalassa::TlsplAll)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct RemoveAssociatedPartyProposal {
        pub removed_party_index: LeafIndex,
    }

    #[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct UpdateAssociatedPartyProposal<'a> {
        pub updated_party: AssociatedPartyEntry<'a>,
    }
}

pub mod key_schedule {
    use crate::{SensitiveBytes, defs::LeafIndex, key_schedule::GroupContext};

    use super::AssociatedPartyEntry;

    #[derive(Debug, Clone, Copy, PartialEq, Eq, thalassa::TlsplSize, thalassa::TlsplSerialize)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize))]
    pub struct AssociatedPartyExportContext<'a> {
        pub ap_index: &'a LeafIndex,
        pub ap_entry: &'a AssociatedPartyEntry<'a>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize))]
    pub struct AssociatedPartyEncryptionContext<'a> {
        pub group_context: &'a GroupContext<'a>,
        pub ap_commit_secret_id: &'a [u8],
    }

    impl AssociatedPartyEncryptionContext<'_> {
        pub const LABEL: &'static [u8] = b"AP Commit Secret";
    }

    // impl tls_codec::Size for AssociatedPartyEncryptionContext<'_> {
    //     fn tls_serialized_len(&self) -> usize {
    //         crate::tlspl::tls_serialized_len_as_vlvec(Self::LABEL.len())
    //             + self.group_context.tls_serialized_len()
    //             + crate::tlspl::tls_serialized_len_as_vlvec(self.ap_commit_secret_id.len())
    //     }
    // }

    // impl tls_codec::Serialize for AssociatedPartyEncryptionContext<'_> {
    //     fn tls_serialize<W: std::io::Write>(
    //         &self,
    //         writer: &mut W,
    //     ) -> Result<usize, tls_codec::Error> {
    //         let mut written = crate::tlspl::bytes::tls_serialize(Self::LABEL, writer)?;
    //         written += self.group_context.tls_serialize(writer)?;
    //         written += crate::tlspl::bytes::tls_serialize(self.ap_commit_secret_id, writer)?;
    //         Ok(written)
    //     }
    // }

    #[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct AssociatedPartySecret<'a> {
        pub associated_party_proposal_secret: SensitiveBytes<'a>,
    }

    #[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct AssociatedPartySecrets<'a> {
        pub associated_party_init_secret: SensitiveBytes<'a>,
    }
}
