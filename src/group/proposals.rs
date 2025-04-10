use crate::{
    defs::{CiphersuiteId, LeafIndex, ProposalType, ProtocolVersion},
    group::{extensions::Extension, GroupId},
    key_package::KeyPackage,
    key_schedule::{GroupContext, PreSharedKeyId},
    tree::leaf_node::LeafNode,
    SensitiveBytes,
};

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
#[repr(u16)]
pub enum Proposal {
    #[tls_codec(discriminant = "ProposalType::ADD")]
    Add(AddProposal),
    #[tls_codec(discriminant = "ProposalType::UPDATE")]
    Update(UpdateProposal),
    #[tls_codec(discriminant = "ProposalType::REMOVE")]
    Remove(RemoveProposal),
    #[tls_codec(discriminant = "ProposalType::PSK")]
    PreSharedKey(PreSharedKeyProposal),
    #[tls_codec(discriminant = "ProposalType::REINIT")]
    ReInit(ReInitProposal),
    #[tls_codec(discriminant = "ProposalType::EXTERNAL_INIT")]
    ExternalInit(ExternalInitProposal),
    #[tls_codec(discriminant = "ProposalType::GROUP_CONTEXT_EXTENSIONS")]
    GroupContextExtensions(GroupContextExtensionsProposal),
    #[cfg(feature = "draft-ietf-mls-extensions")]
    #[tls_codec(discriminant = "ProposalType::APP_DATA_UPDATE")]
    AppDataUpdate(crate::drafts::mls_extensions::safe_application::AppDataUpdate),
    #[cfg(feature = "draft-ietf-mls-extensions")]
    #[tls_codec(discriminant = "ProposalType::APP_EPHEMERAL")]
    AppEphemeral(crate::drafts::mls_extensions::safe_application::AppEphemeral),
    #[cfg(feature = "draft-ietf-mls-extensions")]
    #[tls_codec(discriminant = "ProposalType::SELF_REMOVE")]
    SelfRemove(crate::drafts::mls_extensions::self_remove::SelfRemoveProposal),
}

impl Proposal {
    #[inline(always)]
    pub fn proposal_type(&self) -> ProposalType {
        self.into()
    }
}

impl From<&Proposal> for ProposalType {
    fn from(val: &Proposal) -> Self {
        match val {
            Proposal::Add(_) => ProposalType::new_unchecked(ProposalType::ADD),
            Proposal::Update(_) => ProposalType::new_unchecked(ProposalType::UPDATE),
            Proposal::Remove(_) => ProposalType::new_unchecked(ProposalType::REMOVE),
            Proposal::PreSharedKey(_) => ProposalType::new_unchecked(ProposalType::PSK),
            Proposal::ReInit(_) => ProposalType::new_unchecked(ProposalType::REINIT),
            Proposal::ExternalInit(_) => ProposalType::new_unchecked(ProposalType::EXTERNAL_INIT),
            Proposal::GroupContextExtensions(_) => {
                ProposalType::new_unchecked(ProposalType::GROUP_CONTEXT_EXTENSIONS)
            }
            #[cfg(feature = "draft-ietf-mls-extensions")]
            Proposal::AppDataUpdate(_) => {
                ProposalType::new_unchecked(ProposalType::APP_DATA_UPDATE)
            }
            #[cfg(feature = "draft-ietf-mls-extensions")]
            Proposal::AppEphemeral(_) => ProposalType::new_unchecked(ProposalType::APP_EPHEMERAL),
            #[cfg(feature = "draft-ietf-mls-extensions")]
            Proposal::SelfRemove(_) => ProposalType::new_unchecked(ProposalType::SELF_REMOVE),
        }
    }
}

impl Proposal {
    #[inline]
    pub fn needs_update_path(&self) -> bool {
        self.proposal_type().needs_update_path()
    }
}

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
pub struct AddProposal {
    pub key_package: KeyPackage,
}

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
pub struct UpdateProposal {
    pub leaf_node: LeafNode,
}

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
pub struct RemoveProposal {
    pub removed: LeafIndex,
}

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
pub struct PreSharedKeyProposal {
    pub psk: PreSharedKeyId,
}

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
pub struct ReInitProposal {
    pub group_id: GroupId,
    pub version: ProtocolVersion,
    pub cipher_suite: CiphersuiteId,
    pub extensions: Vec<Extension>,
}

impl ReInitProposal {
    pub fn matches_group_context(&self, ctx: &GroupContext) -> bool {
        self.group_id == ctx.group_id()
            && self.version == ctx.version
            && self.cipher_suite == ctx.cipher_suite
            && self.extensions == ctx.extensions
    }
}

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
pub struct ExternalInitProposal {
    pub kem_output: SensitiveBytes,
}

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
pub struct GroupContextExtensionsProposal {
    pub extensions: Vec<Extension>,
}
