use std::collections::BTreeMap;

use crate::{SensitiveBytes, key_schedule::PreSharedKeyId};

pub type ComponentId = u32;

pub const COMPONENT_ID_GREASE_VALUES: [ComponentId; 15] = [
    0x0000_0A0A,
    0x0000_1A1A,
    0x0000_2A2A,
    0x0000_3A3A,
    0x0000_4A4A,
    0x0000_5A5A,
    0x0000_6A6A,
    0x0000_7A7A,
    0x0000_8A8A,
    0x0000_9A9A,
    0x0000_AAAA,
    0x0000_BABA,
    0x0000_CACA,
    0x0000_DADA,
    0x0000_EAEA,
];

pub trait Component: crate::Parsable + crate::Serializable {
    fn component_id() -> ComponentId;

    fn psk(psk_id: Vec<u8>, psk_nonce: SensitiveBytes) -> PreSharedKeyId {
        PreSharedKeyId {
            psktype: crate::key_schedule::PreSharedKeyIdPskType::Application(
                crate::key_schedule::ApplicationPsk {
                    component_id: Self::component_id(),
                    psk_id,
                },
            ),
            psk_nonce,
        }
    }

    fn to_component_data(&self) -> crate::MlsSpecResult<ComponentData> {
        Ok(ComponentData {
            component_id: Self::component_id(),
            data: self.to_tls_bytes()?,
        })
    }
}

#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    strum::IntoStaticStr,
    strum::EnumString,
    strum::Display,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum ComponentOperationBaseLabel {
    #[default]
    Application = 0x00,
}

impl tls_codec::Size for ComponentOperationBaseLabel {
    fn tls_serialized_len(&self) -> usize {
        crate::tlspl::string::tls_serialized_len(self.into())
    }
}

impl tls_codec::Serialize for ComponentOperationBaseLabel {
    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        crate::tlspl::string::tls_serialize(self.into(), writer)
    }
}

impl tls_codec::Deserialize for ComponentOperationBaseLabel {
    fn tls_deserialize<R: std::io::Read>(bytes: &mut R) -> Result<Self, tls_codec::Error>
    where
        Self: Sized,
    {
        <Self as std::str::FromStr>::from_str(&crate::tlspl::string::tls_deserialize(bytes)?)
            .map_err(|_| {
                tls_codec::Error::DecodingError(
                    "Unknown Value in ComponentOperationBaseLabel".into(),
                )
            })
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
pub struct ComponentOperationLabel {
    pub base_label: ComponentOperationBaseLabel,
    pub component_id: ComponentId,
    #[tls_codec(with = "crate::tlspl::bytes")]
    pub label: Vec<u8>,
}

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    tls_codec::TlsSerialize,
    tls_codec::TlsDeserialize,
    tls_codec::TlsSize,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ComponentData {
    pub component_id: ComponentId,
    #[tls_codec(with = "crate::tlspl::bytes")]
    pub data: Vec<u8>,
}

impl ComponentData {
    pub fn as_ref(&self) -> ComponentDataRef<'_> {
        ComponentDataRef {
            component_id: &self.component_id,
            data: &self.data,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, tls_codec::TlsSerialize, tls_codec::TlsSize)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct ComponentDataRef<'a> {
    pub component_id: &'a ComponentId,
    #[tls_codec(with = "crate::tlspl::bytes")]
    pub data: &'a [u8],
}

/// Utilitary struct that contains a `BTreeMap` in order to preserve ordering and unicity
///
/// Also takes extra care to make sure that the `serde` representation when serialized
/// is equivalent to the TLS-PL version of it
#[derive(Debug, Default, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(from = "Vec<ComponentData>", into = "Vec<ComponentData>")
)]
pub struct ComponentDataMap(BTreeMap<ComponentId, Vec<u8>>);

impl ComponentDataMap {
    fn extract_component<C: Component>(&self) -> crate::MlsSpecResult<Option<C>> {
        self.0
            .get(&C::component_id())
            .map(|data| C::from_tls_bytes(data))
            .transpose()
    }

    fn insert_or_update_component<C: Component>(
        &mut self,
        component: &C,
    ) -> crate::MlsSpecResult<bool> {
        // This is put before to make sure we don't error out on serialization before modifying the map
        let component_data = component.to_tls_bytes()?;
        match self.0.entry(C::component_id()) {
            std::collections::btree_map::Entry::Vacant(vacant_entry) => {
                vacant_entry.insert(component_data);
                Ok(true)
            }
            std::collections::btree_map::Entry::Occupied(mut occupied_entry) => {
                *(occupied_entry.get_mut()) = component_data;
                Ok(false)
            }
        }
    }

    fn iter(&self) -> impl Iterator<Item = (&ComponentId, &[u8])> {
        self.0.iter().map(|(cid, data)| (cid, data.as_slice()))
    }
}

impl tls_codec::Size for ComponentDataMap {
    fn tls_serialized_len(&self) -> usize {
        crate::tlspl::tls_serialized_len_as_vlvec(
            self.iter()
                .map(|(component_id, data)| {
                    ComponentDataRef { component_id, data }.tls_serialized_len()
                })
                .sum(),
        )
    }
}

impl tls_codec::Deserialize for ComponentDataMap {
    fn tls_deserialize<R: std::io::Read>(bytes: &mut R) -> Result<Self, tls_codec::Error>
    where
        Self: Sized,
    {
        let tlspl_value: Vec<ComponentData> = <_>::tls_deserialize(bytes)?;

        Ok(Self(BTreeMap::from_iter(
            tlspl_value
                .into_iter()
                .map(|cdata| (cdata.component_id, cdata.data)),
        )))
    }
}

impl tls_codec::Serialize for ComponentDataMap {
    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        // TODO: Improve this by not allocating a vec of refs
        self.iter()
            .map(|(component_id, data)| ComponentDataRef { component_id, data })
            .collect::<Vec<ComponentDataRef>>()
            .tls_serialize(writer)
    }
}

impl std::ops::Deref for ComponentDataMap {
    type Target = BTreeMap<ComponentId, Vec<u8>>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for ComponentDataMap {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<Vec<ComponentData>> for ComponentDataMap {
    fn from(value: Vec<ComponentData>) -> Self {
        Self(BTreeMap::from_iter(
            value
                .into_iter()
                .map(|component| (component.component_id, component.data)),
        ))
    }
}

#[allow(clippy::from_over_into)]
impl Into<Vec<ComponentData>> for ComponentDataMap {
    fn into(self) -> Vec<ComponentData> {
        self.0
            .into_iter()
            .map(|(component_id, data)| ComponentData { component_id, data })
            .collect()
    }
}

/// Please note that this ApplicationDataDictionary is backed by a `BTreeMap` to
/// take care of ordering and deduplication automatically.
///
/// The conversion from/to a `Vec<ComponentData>` is done at serialization/deserialization time
#[derive(
    Debug,
    Default,
    Clone,
    PartialEq,
    Eq,
    Hash,
    tls_codec::TlsSize,
    tls_codec::TlsDeserialize,
    tls_codec::TlsSerialize,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ApplicationDataDictionary {
    pub component_data: ComponentDataMap,
}

impl ApplicationDataDictionary {
    pub fn iter_components(&self) -> impl Iterator<Item = ComponentDataRef<'_>> {
        self.component_data
            .iter()
            .map(|(component_id, data)| ComponentDataRef { component_id, data })
    }

    pub fn extract_component<C: Component>(&self) -> crate::MlsSpecResult<Option<C>> {
        self.component_data.extract_component::<C>()
    }

    /// Returns `true` if newly inserted
    pub fn insert_or_update_component<C: Component>(
        &mut self,
        component: &C,
    ) -> crate::MlsSpecResult<bool> {
        self.component_data.insert_or_update_component(component)
    }

    /// Applies an ApplicationDataUpdate proposal
    ///
    /// Returns `false` in only one case: when an `op` is set to `remove` tries to
    /// remove a non-existing component, which is a soft-error in itself
    pub fn apply_update(&mut self, update: AppDataUpdate) -> bool {
        match update.op {
            ApplicationDataUpdateOperation::Update { update: data } => {
                *self.component_data.entry(update.component_id).or_default() = data;
                true
            }
            ApplicationDataUpdateOperation::Remove => {
                self.component_data.remove(&update.component_id).is_some()
            }
        }
    }
}

impl From<ApplicationDataDictionary> for crate::group::extensions::Extension {
    fn from(val: ApplicationDataDictionary) -> Self {
        crate::group::extensions::Extension::ApplicationData(val)
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
#[repr(u8)]
#[cfg_attr(
    feature = "serde",
    derive(serde_repr::Serialize_repr, serde_repr::Deserialize_repr)
)]
pub enum ApplicationDataUpdateOperationType {
    Invalid = 0x00,
    Update = 0x01,
    Remove = 0x02,
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
#[repr(u8)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ApplicationDataUpdateOperation {
    #[tls_codec(discriminant = "ApplicationDataUpdateOperationType::Update")]
    Update {
        #[tls_codec(with = "crate::tlspl::bytes")]
        update: Vec<u8>,
    },
    #[tls_codec(discriminant = "ApplicationDataUpdateOperationType::Remove")]
    Remove,
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
pub struct AppDataUpdate {
    pub component_id: ComponentId,
    pub op: ApplicationDataUpdateOperation,
}

impl AppDataUpdate {
    /// Allows to extract a concrete `Component` from an update operation
    ///
    /// Returns Ok(None) if the update is a `Remove` operation
    /// Otherwise returns Ok(Some(C)) unless an error occurs
    pub fn extract_component_update<C: Component>(&self) -> crate::MlsSpecResult<Option<C>> {
        let type_component_id = C::component_id();
        if type_component_id != self.component_id {
            return Err(crate::MlsSpecError::SafeAppComponentIdMismatch {
                expected: type_component_id,
                actual: self.component_id,
            });
        }

        let ApplicationDataUpdateOperation::Update { update } = &self.op else {
            return Ok(None);
        };

        Ok(Some(C::from_tls_bytes(update)?))
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
pub struct ApplicationData {
    pub component_id: ComponentId,
    #[tls_codec(with = "crate::tlspl::bytes")]
    pub data: Vec<u8>,
}

pub type AppEphemeral = ApplicationData;

#[derive(Debug, Clone, PartialEq, Eq, tls_codec::TlsSerialize, tls_codec::TlsSize)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct SafeAadItemRef<'a>(ComponentDataRef<'a>);

impl<'a> SafeAadItemRef<'a> {
    pub fn component_id(&self) -> &ComponentId {
        self.0.component_id
    }

    pub fn aad_item_data(&self) -> &[u8] {
        self.0.data
    }

    pub fn from_item_data<C: Component>(
        component_id: &'a ComponentId,
        aad_item_data: &'a [u8],
    ) -> Option<Self> {
        (&C::component_id() == component_id).then_some(SafeAadItemRef(ComponentDataRef {
            component_id,
            data: aad_item_data,
        }))
    }
}

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    tls_codec::TlsSerialize,
    tls_codec::TlsDeserialize,
    tls_codec::TlsSize,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct SafeAadItem(ComponentData);

impl SafeAadItem {
    pub fn as_ref(&self) -> SafeAadItemRef<'_> {
        SafeAadItemRef(self.0.as_ref())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, tls_codec::TlsSerialize, tls_codec::TlsSize)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct SafeAadRef<'a> {
    pub aad_items: &'a [&'a SafeAadItemRef<'a>],
}

impl SafeAadRef<'_> {
    pub fn is_ordered_and_unique(&self) -> bool {
        let mut iter = self.aad_items.iter().peekable();

        while let Some(item) = iter.next() {
            let Some(next) = iter.peek() else {
                continue;
            };

            if item.component_id() >= next.component_id() {
                return false;
            }
        }

        true
    }
}

impl<'a> From<&'a [&'a SafeAadItemRef<'a>]> for SafeAadRef<'a> {
    fn from(aad_items: &'a [&'a SafeAadItemRef<'a>]) -> Self {
        Self { aad_items }
    }
}

#[derive(
    Debug,
    Default,
    Clone,
    PartialEq,
    Eq,
    Hash,
    tls_codec::TlsSerialize,
    tls_codec::TlsDeserialize,
    tls_codec::TlsSize,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SafeAad {
    aad_items: ComponentDataMap,
}

impl SafeAad {
    pub fn iter_components(&self) -> impl Iterator<Item = SafeAadItemRef<'_>> {
        self.aad_items
            .iter()
            .map(|(component_id, data)| SafeAadItemRef(ComponentDataRef { component_id, data }))
    }

    pub fn extract_component<C: Component>(&self) -> crate::MlsSpecResult<Option<C>> {
        self.aad_items.extract_component::<C>()
    }

    /// Returns `true` if newly inserted
    pub fn insert_or_update_component<C: Component>(
        &mut self,
        component: &C,
    ) -> crate::MlsSpecResult<bool> {
        self.aad_items.insert_or_update_component(component)
    }
}

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    tls_codec::TlsSerialize,
    tls_codec::TlsDeserialize,
    tls_codec::TlsSize,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct WireFormats {
    pub wire_formats: Vec<crate::defs::WireFormat>,
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
pub struct ComponentsList {
    pub component_ids: Vec<ComponentId>,
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
pub struct AppComponents(pub ComponentsList);

impl Component for AppComponents {
    fn component_id() -> ComponentId {
        super::APP_COMPONENTS_ID
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
pub struct SafeAadComponent(pub ComponentsList);

impl Component for SafeAadComponent {
    fn component_id() -> ComponentId {
        super::SAFE_AAD_ID
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{ApplicationDataDictionary, Component, SafeAad, SafeAadItemRef, SafeAadRef};
    use crate::{
        drafts::mls_extensions::last_resort_keypackage::LastResortKeyPackage,
        generate_roundtrip_test,
    };

    generate_roundtrip_test!(can_roundtrip_appdatadict, {
        ApplicationDataDictionary {
            component_data: super::ComponentDataMap(BTreeMap::from([
                (1, vec![1]),
                (3, vec![3]),
                (2, vec![2]),
            ])),
        }
    });

    generate_roundtrip_test!(can_roundtrip_safeaad, {
        SafeAad {
            aad_items: super::ComponentDataMap(BTreeMap::from([
                (1, vec![1]),
                (3, vec![3]),
                (2, vec![2]),
            ])),
        }
    });

    #[test]
    fn can_build_safe_aad() {
        let mut safe_aad = SafeAad::default();
        safe_aad
            .insert_or_update_component(&LastResortKeyPackage)
            .unwrap();

        let cid = LastResortKeyPackage::component_id();
        let aad_item_ref =
            SafeAadItemRef::from_item_data::<LastResortKeyPackage>(&cid, &[]).unwrap();

        let items = &[&aad_item_ref];
        let safe_ref = SafeAadRef::from(items.as_slice());
        assert!(safe_ref.is_ordered_and_unique());
    }
}
