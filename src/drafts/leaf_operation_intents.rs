use crate::{
    SensitiveBytes,
    defs::{LeafIndex, WireFormat},
    group::{GroupId, LeafNodeRef},
};

pub const WIRE_FORMAT_MLS_LEAF_OPERATION_INTENT: u16 = 0xFE01;
static_assertions::const_assert!(
    *WireFormat::RESERVED_PRIVATE_USE_RANGE.start() <= WIRE_FORMAT_MLS_LEAF_OPERATION_INTENT
        && WIRE_FORMAT_MLS_LEAF_OPERATION_INTENT <= *WireFormat::RESERVED_PRIVATE_USE_RANGE.end()
);

/// <https://www.ietf.org/archive/id/draft-kohbrok-mls-leaf-operation-intents-01.html#section-2>
///
/// ### TLS Presentation Language
///
/// ```notrust,ignore
/// enum {
///   reserved(0),
///   sender_removal_only(1),
///   remove_associated_members(2),
///   (255)
/// } RemovalMode
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, thalassa::TlsplAll)]
#[cfg_attr(
    feature = "serde",
    derive(serde_repr::Serialize_repr, serde_repr::Deserialize_repr)
)]
#[repr(u8)]
pub enum RemovalMode {
    Reserved = 0x00,
    SenderRemovalOnly = 0x01,
    RemoveAssociatedMembers = 0x02,
}

/// <https://www.ietf.org/archive/id/draft-kohbrok-mls-leaf-operation-intents-01.html#section-2>
///
/// ### TLS Presentation Language
///
/// ```notrust,ignore
/// struct {
///   opaque group_id<V>;
///   uint32 sender_index;
///   LeafNodeRef sender_leaf_ref;
///   RemovalMode removal_mode;
/// } LeafOperationIntentTBS
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, thalassa::TlsplSize, thalassa::TlsplSerialize)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct LeafOperationIntentTBS<'a> {
    pub group_id: &'a GroupId<'a>,
    pub sender_index: &'a LeafIndex,
    pub sender_leaf_ref: &'a LeafNodeRef<'a>,
    pub removal_mode: &'a RemovalMode,
}

/// <https://www.ietf.org/archive/id/draft-kohbrok-mls-leaf-operation-intents-01.html#section-2>
///
/// ### TLS Presentation Language
///
/// ```notrust,ignore
/// struct {
///   opaque group_id<V>;
///   uint32 sender_index;
///   LeafNodeRef sender_leaf_ref;
///   RemovalMode removal_mode;
///   /* SignWithLabel(., "LeafOperationIntentTBS", LeafOperationIntentTBS) */
///   opaque signature<V>;
/// } LeafOperationIntent
/// ```
#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct LeafOperationIntent<'a> {
    pub group_id: GroupId<'a>,
    pub sender_index: LeafIndex,
    pub sender_leaf_ref: LeafNodeRef<'a>,
    pub removal_mode: RemovalMode,
    pub signature: SensitiveBytes<'a>,
}

impl LeafOperationIntent<'_> {
    pub fn to_tbs(&self) -> LeafOperationIntentTBS<'_> {
        LeafOperationIntentTBS {
            group_id: &self.group_id,
            sender_index: &self.sender_index,
            sender_leaf_ref: &self.sender_leaf_ref,
            removal_mode: &self.removal_mode,
        }
    }
}

/// <https://www.ietf.org/archive/id/draft-kohbrok-mls-leaf-operation-intents-01.html#section-2>
///
/// ### TLS Presentation Language
///
/// ```notrust,ignore
/// struct {
///   LeafOperationIntent intent;
/// } LeafOperationProposal
/// ```
#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct LeafOperationProposal<'a> {
    pub intent: LeafOperationIntent<'a>,
}
