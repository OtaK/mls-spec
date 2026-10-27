use crate::{
    SensitiveBytes,
    defs::{CiphersuiteId, LeafIndex, ProposalType, ProtocolVersion},
    group::{GroupId, extensions::Extension},
    key_package::KeyPackage,
    key_schedule::{GroupContext, PreSharedKeyId},
    tree::leaf_node::LeafNode,
};

/// <https://www.rfc-editor.org/rfc/rfc9420.html#section-12.1>
///
/// ### TLS Presentation Language
///
/// ```notrust,ignore
/// struct {
///     ProposalType proposal_type;
///     select (Proposal.proposal_type) {
///         case add:                      Add;
///         case update:                   Update;
///         case remove:                   Remove;
///         case psk:                      PreSharedKey;
///         case reinit:                   ReInit;
///         case external_init:            ExternalInit;
///         case group_context_extensions: GroupContextExtensions;
///     };
/// } Proposal;
/// ```
#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u16)]
pub enum Proposal<'a> {
    #[tlspl(discriminant = ProposalType::ADD.as_repr())]
    Add(AddProposal<'a>),
    #[tlspl(discriminant = ProposalType::UPDATE.as_repr())]
    Update(UpdateProposal<'a>),
    #[tlspl(discriminant = ProposalType::REMOVE.as_repr())]
    Remove(RemoveProposal),
    #[tlspl(discriminant = ProposalType::PSK.as_repr())]
    PreSharedKey(PreSharedKeyProposal<'a>),
    #[tlspl(discriminant = ProposalType::REINIT.as_repr())]
    ReInit(ReInitProposal<'a>),
    #[tlspl(discriminant = ProposalType::EXTERNAL_INIT.as_repr())]
    ExternalInit(ExternalInitProposal<'a>),
    #[tlspl(discriminant = ProposalType::GROUP_CONTEXT_EXTENSIONS.as_repr())]
    GroupContextExtensions(GroupContextExtensionsProposal<'a>),
    #[cfg(feature = "draft-ietf-mls-extensions")]
    #[tlspl(discriminant = ProposalType::APP_DATA_UPDATE.as_repr())]
    AppDataUpdate(crate::drafts::mls_extensions::safe_application::AppDataUpdate<'a>),
    #[cfg(feature = "draft-ietf-mls-extensions")]
    #[tlspl(discriminant = ProposalType::APP_EPHEMERAL.as_repr())]
    AppEphemeral(crate::drafts::mls_extensions::safe_application::AppEphemeral<'a>),
    #[cfg(feature = "draft-ietf-mls-extensions")]
    #[tlspl(discriminant = ProposalType::SELF_REMOVE.as_repr())]
    SelfRemove(crate::drafts::mls_extensions::self_remove::SelfRemoveProposal),
}

impl Proposal<'_> {
    #[inline(always)]
    pub fn proposal_type(&self) -> ProposalType {
        self.into()
    }

    pub fn to_owned<'out>(&self) -> Proposal<'out> {
        let owned_extensions =
            |exts: &[Extension<'_>]| exts.iter().map(|ext| ext.to_owned()).collect();

        match self {
            Proposal::Add(add) => Proposal::Add(AddProposal {
                key_package: add.key_package.to_owned(),
            }),
            Proposal::Update(update) => Proposal::Update(UpdateProposal {
                leaf_node: update.leaf_node.to_owned(),
            }),
            Proposal::Remove(remove) => Proposal::Remove(remove.clone()),
            Proposal::PreSharedKey(psk) => Proposal::PreSharedKey(PreSharedKeyProposal {
                psk: psk.psk.to_owned(),
            }),
            Proposal::ReInit(reinit) => Proposal::ReInit(ReInitProposal {
                group_id: reinit.group_id.to_vec().into(),
                version: reinit.version,
                cipher_suite: reinit.cipher_suite,
                extensions: owned_extensions(&reinit.extensions),
            }),
            Proposal::ExternalInit(ei) => Proposal::ExternalInit(ExternalInitProposal {
                kem_output: ei.kem_output.to_vec().into(),
            }),
            Proposal::GroupContextExtensions(gce) => {
                Proposal::GroupContextExtensions(GroupContextExtensionsProposal {
                    extensions: owned_extensions(&gce.extensions),
                })
            }
            #[cfg(feature = "draft-ietf-mls-extensions")]
            Proposal::AppDataUpdate(adu) => {
                use crate::drafts::mls_extensions::safe_application::{
                    AppDataUpdate, ApplicationDataUpdateOperation,
                };
                Proposal::AppDataUpdate(AppDataUpdate {
                    component_id: adu.component_id,
                    op: match &adu.op {
                        ApplicationDataUpdateOperation::Update { update } => {
                            ApplicationDataUpdateOperation::Update {
                                update: update.to_vec().into(),
                            }
                        }
                        ApplicationDataUpdateOperation::Remove => {
                            ApplicationDataUpdateOperation::Remove
                        }
                    },
                })
            }
            #[cfg(feature = "draft-ietf-mls-extensions")]
            Proposal::AppEphemeral(ae) => {
                Proposal::AppEphemeral(crate::drafts::mls_extensions::safe_application::AppEphemeral {
                    component_id: ae.component_id,
                    data: ae.data.to_vec().into(),
                })
            }
            #[cfg(feature = "draft-ietf-mls-extensions")]
            Proposal::SelfRemove(sr) => Proposal::SelfRemove(sr.clone()),
        }
    }
}

impl From<&Proposal<'_>> for ProposalType {
    fn from(val: &Proposal) -> Self {
        match val {
            Proposal::Add(_) => ProposalType::ADD,
            Proposal::Update(_) => ProposalType::UPDATE,
            Proposal::Remove(_) => ProposalType::REMOVE,
            Proposal::PreSharedKey(_) => ProposalType::PSK,
            Proposal::ReInit(_) => ProposalType::REINIT,
            Proposal::ExternalInit(_) => ProposalType::EXTERNAL_INIT,
            Proposal::GroupContextExtensions(_) => ProposalType::GROUP_CONTEXT_EXTENSIONS,
            #[cfg(feature = "draft-ietf-mls-extensions")]
            Proposal::AppDataUpdate(_) => ProposalType::APP_DATA_UPDATE,
            #[cfg(feature = "draft-ietf-mls-extensions")]
            Proposal::AppEphemeral(_) => ProposalType::APP_EPHEMERAL,
            #[cfg(feature = "draft-ietf-mls-extensions")]
            Proposal::SelfRemove(_) => ProposalType::SELF_REMOVE,
        }
    }
}

impl Proposal<'_> {
    #[inline]
    pub fn needs_update_path(&self) -> bool {
        self.proposal_type().needs_update_path()
    }
}

/// <https://www.rfc-editor.org/rfc/rfc9420.html#section-12.1.1>
///
/// ### TLS Presentation Language
///
/// ```notrust,ignore
/// struct {
///     KeyPackage key_package;
/// } Add;
/// ```
#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AddProposal<'a> {
    pub key_package: KeyPackage<'a>,
}

/// <https://www.rfc-editor.org/rfc/rfc9420.html#section-12.1.2>
///
/// ### TLS Presentation Language
///
/// ```notrust,ignore
/// struct {
///     LeafNode leaf_node;
/// } Update;
/// ```
#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct UpdateProposal<'a> {
    pub leaf_node: LeafNode<'a>,
}

/// <https://www.rfc-editor.org/rfc/rfc9420.html#section-12.1.3>
///
/// ### TLS Presentation Language
///
/// ```notrust,ignore
/// struct {
///     uint32 removed;
/// } Remove;
/// ```
#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RemoveProposal {
    pub removed: LeafIndex,
}

/// <https://www.rfc-editor.org/rfc/rfc9420.html#section-12.1.4>
///
/// ### TLS Presentation Language
///
/// ```notrust,ignore
/// struct {
///     PreSharedKeyID psk;
/// } PreSharedKey;
/// ```
#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PreSharedKeyProposal<'a> {
    pub psk: PreSharedKeyId<'a>,
}

/// <https://www.rfc-editor.org/rfc/rfc9420.html#section-12.1.5>
///
/// ### TLS Presentation Language
///
/// ```notrust,ignore
/// struct {
///     opaque group_id<V>;
///     ProtocolVersion version;
///     CipherSuite cipher_suite;
///     Extension extensions<V>;
/// } ReInit;
/// ```
#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ReInitProposal<'a> {
    pub group_id: GroupId<'a>,
    pub version: ProtocolVersion,
    pub cipher_suite: CiphersuiteId,
    pub extensions: Vec<Extension<'a>>,
}

impl ReInitProposal<'_> {
    pub fn matches_group_context(&self, ctx: &GroupContext) -> bool {
        self.group_id == ctx.group_id()
            && self.version == ctx.version
            && self.cipher_suite == ctx.cipher_suite
            && self.extensions == ctx.extensions
    }
}

/// <https://www.rfc-editor.org/rfc/rfc9420.html#section-12.1.6>
///
/// ### TLS Presentation Language
///
/// ```notrust,ignore
/// struct {
///   opaque kem_output<V>;
/// } ExternalInit;
/// ```
#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExternalInitProposal<'a> {
    pub kem_output: SensitiveBytes<'a>,
}

/// <https://www.rfc-editor.org/rfc/rfc9420.html#section-12.1.7>
///
/// ### TLS Presentation Language
///
/// ```notrust,ignore
/// struct {
///   Extension extensions<V>;
/// } GroupContextExtensions;
/// ```
#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GroupContextExtensionsProposal<'a> {
    pub extensions: Vec<Extension<'a>>,
}
