use crate::{
    SensitiveBytes,
    defs::{LeafIndex, WireFormat},
    group::GroupId,
    tree::leaf_node::LeafNode,
};

pub const WIRE_FORMAT_MLS_LEAF_OPERATION_INTENT: u16 = 0xFE01;
static_assertions::const_assert!(
    *WireFormat::RESERVED_PRIVATE_USE_RANGE.start() <= WIRE_FORMAT_MLS_LEAF_OPERATION_INTENT
        && WIRE_FORMAT_MLS_LEAF_OPERATION_INTENT <= *WireFormat::RESERVED_PRIVATE_USE_RANGE.end()
);

#[derive(Debug, Clone, Copy, PartialEq, Eq, thalassa::TlsplAll)]
#[cfg_attr(
    feature = "serde",
    derive(serde_repr::Serialize_repr, serde_repr::Deserialize_repr)
)]
#[repr(u8)]
pub enum RemovalMode {
    Reserved = 0x00,
    SenderRemovalOnly = 0x01,
    RemoveAssociatedMember = 0x02,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thalassa::TlsplSize, thalassa::TlsplSerialize)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct LeafOperationIntentTBS<'a> {
    pub group_id: &'a GroupId<'a>,
    pub sender_index: &'a LeafIndex,
    pub sender_leaf_ref: &'a LeafNode<'a>,
    pub removal_mode: &'a RemovalMode,
}

#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct LeafOperationIntent<'a> {
    pub group_id: GroupId<'a>,
    pub sender_index: LeafIndex,
    pub sender_leaf_ref: LeafNode<'a>,
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

#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct LeafOperationProposal<'a> {
    pub intent: LeafOperationIntent<'a>,
}
