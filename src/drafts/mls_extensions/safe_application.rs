use std::{borrow::Cow, collections::BTreeMap};

use crate::{SensitiveBytes, key_schedule::PreSharedKeyId};

pub type ComponentId = u16;

pub const COMPONENT_ID_GREASE_VALUES: [ComponentId; 8] = [
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
];

pub trait Component<'a>: crate::Parsable<'a> + crate::Serializable {
    fn component_id() -> ComponentId;

    fn psk(psk_id: Cow<'a, [u8]>, psk_nonce: SensitiveBytes<'a>) -> PreSharedKeyId<'a> {
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

    fn to_component_data(&self) -> crate::MlsSpecResult<ComponentData<'_>> {
        Ok(ComponentData {
            component_id: Self::component_id(),
            data: self.to_tls_bytes()?.into(),
        })
    }
}

#[derive(
    Debug, Clone, Default, PartialEq, Eq, strum::IntoStaticStr, strum::EnumString, strum::Display,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum ComponentOperationBaseLabel<'a> {
    #[default]
    #[strum(serialize = "MLS Component")]
    MlsComponent,
    /// Other cases. Unlikely to ever happen but whatever!
    Custom(Cow<'a, str>),
}

impl thalassa::TlsplSize for ComponentOperationBaseLabel<'_> {
    #[inline]
    fn tlspl_serialized_len(&self) -> usize {
        let str: &str = self.into();
        str.tlspl_serialized_len()
    }
}

impl thalassa::TlsplSerialize for ComponentOperationBaseLabel<'_> {
    #[inline]
    fn tlspl_serialize_to<W: thalassa::io::Write>(
        &self,
        writer: &mut W,
    ) -> thalassa::error::TlsplWriteResult<usize> {
        let str: &str = self.into();
        str.tlspl_serialize_to(writer)
    }
}

impl<'a> thalassa::TlsplDeserialize<'a> for ComponentOperationBaseLabel<'a> {
    fn tlspl_deserialize_from<R: thalassa::io::Read<'a>>(
        reader: &mut R,
    ) -> thalassa::error::TlsplReadResult<Self>
    where
        Self: Sized + 'a,
    {
        let str = Cow::<str>::tlspl_deserialize_from(reader)?;
        Ok(Self::try_from(&*str).unwrap_or(Self::Custom(str)))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ComponentOperationLabel<'a> {
    pub base_label: ComponentOperationBaseLabel<'a>,
    pub component_id: ComponentId,
    pub label: Cow<'a, [u8]>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ComponentData<'a> {
    pub component_id: ComponentId,
    pub data: Cow<'a, [u8]>,
}

impl<'a> ComponentData<'a> {
    pub fn as_ref(&'a self) -> ComponentDataRef<'a> {
        ComponentDataRef {
            component_id: &self.component_id,
            data: &self.data,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplSerialize, thalassa::TlsplSize)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct ComponentDataRef<'a> {
    pub component_id: &'a ComponentId,
    pub data: &'a [u8],
}

/// Utilitary struct that contains a `BTreeMap` in order to preserve ordering and unicity
///
/// Also takes extra care to make sure that the `serde` representation when serialized
/// is equivalent to the TLS-PL version of it
#[derive(Debug, Default, Clone, PartialEq, Eq, Hash, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(from = "Vec<ComponentData>", into = "Vec<ComponentData>")
)]
pub struct ComponentDataMap<'a>(BTreeMap<ComponentId, Cow<'a, [u8]>>);

impl<'a> ComponentDataMap<'a> {
    fn extract_component<C: Component<'a> + 'a>(&'a self) -> crate::MlsSpecResult<Option<C>> {
        self.0
            .get(&C::component_id())
            .map(|data| C::from_tls_bytes(data))
            .transpose()
    }

    fn insert_or_update_component<C: Component<'a>>(
        &mut self,
        component: &C,
    ) -> crate::MlsSpecResult<bool> {
        // This is put before to make sure we don't error out on serialization before modifying the map
        let component_data = component.to_tls_bytes()?;
        match self.0.entry(C::component_id()) {
            std::collections::btree_map::Entry::Vacant(vacant_entry) => {
                vacant_entry.insert(component_data.into());
                Ok(true)
            }
            std::collections::btree_map::Entry::Occupied(mut occupied_entry) => {
                *(occupied_entry.get_mut()) = component_data.into();
                Ok(false)
            }
        }
    }

    fn iter(&'a self) -> impl Iterator<Item = ComponentData<'a>> {
        self.0.iter().map(|(&component_id, data)| ComponentData {
            component_id,
            data: Cow::Borrowed(data),
        })
    }
}

impl<'a> std::ops::Deref for ComponentDataMap<'a> {
    type Target = BTreeMap<ComponentId, Cow<'a, [u8]>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for ComponentDataMap<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<'a> From<Vec<ComponentData<'a>>> for ComponentDataMap<'a> {
    fn from(value: Vec<ComponentData<'a>>) -> Self {
        Self(BTreeMap::from_iter(
            value
                .into_iter()
                .map(|component| (component.component_id, component.data)),
        ))
    }
}

#[allow(clippy::from_over_into)]
impl<'a> Into<Vec<ComponentData<'a>>> for ComponentDataMap<'a> {
    fn into(self) -> Vec<ComponentData<'a>> {
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
#[derive(Debug, Default, Clone, PartialEq, Eq, Hash, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ApplicationDataDictionary<'a> {
    pub component_data: ComponentDataMap<'a>,
}

impl<'a> ApplicationDataDictionary<'a> {
    pub fn iter_components(&'a self) -> impl Iterator<Item = ComponentData<'a>> {
        self.component_data.iter()
    }

    pub fn extract_component<C: Component<'a> + 'a>(&'a self) -> crate::MlsSpecResult<Option<C>> {
        self.component_data.extract_component::<C>()
    }

    /// Returns `true` if newly inserted
    pub fn insert_or_update_component<C: Component<'a>>(
        &mut self,
        component: &C,
    ) -> crate::MlsSpecResult<bool> {
        self.component_data.insert_or_update_component(component)
    }

    /// Applies an ApplicationDataUpdate proposal
    ///
    /// Returns `false` in only one case: when an `op` is set to `remove` tries to
    /// remove a non-existing component, which is a soft-error in itself
    pub fn apply_update(&mut self, update: AppDataUpdate<'a>) -> bool {
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

impl<'a> From<ApplicationDataDictionary<'a>> for crate::group::extensions::Extension<'a> {
    fn from(val: ApplicationDataDictionary<'a>) -> Self {
        crate::group::extensions::Extension::ApplicationData(val)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
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

#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
#[repr(u8)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ApplicationDataUpdateOperation<'a> {
    #[tlspl(discriminant = "ApplicationDataUpdateOperationType::Update")]
    Update { update: Cow<'a, [u8]> },
    #[tlspl(discriminant = "ApplicationDataUpdateOperationType::Remove")]
    Remove,
}

#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AppDataUpdate<'a> {
    pub component_id: ComponentId,
    pub op: ApplicationDataUpdateOperation<'a>,
}

impl<'a> AppDataUpdate<'a> {
    /// Allows to extract a concrete `Component` from an update operation
    ///
    /// Returns Ok(None) if the update is a `Remove` operation
    /// Otherwise returns Ok(Some(C)) unless an error occurs
    pub fn extract_component_update<C: Component<'a> + 'a>(
        &'a self,
    ) -> crate::MlsSpecResult<Option<C>> {
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

#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ApplicationData<'a> {
    pub component_id: ComponentId,
    pub data: Cow<'a, [u8]>,
}

pub type AppEphemeral<'a> = ApplicationData<'a>;

#[derive(Debug, Clone, PartialEq, Eq, Hash, thalassa::TlsplAll)]
#[repr(transparent)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct SafeAadItem<'a>(ComponentData<'a>);

impl<'a> SafeAadItem<'a> {
    pub fn as_ref(&self) -> SafeAadItemRef<'_> {
        SafeAadItemRef(self.0.as_ref())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplSerialize, thalassa::TlsplSize)]
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

    pub fn from_item_data<C: Component<'a>>(
        component_id: &'a ComponentId,
        aad_item_data: &'a [u8],
    ) -> Option<Self> {
        (&C::component_id() == component_id).then_some(SafeAadItemRef(ComponentDataRef {
            component_id,
            data: aad_item_data,
        }))
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Hash, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SafeAad<'a> {
    aad_items: ComponentDataMap<'a>,
}

impl<'a> SafeAad<'a> {
    pub fn is_ordered_and_unique(&self) -> bool {
        let mut iter = self.aad_items.iter().peekable();

        while let Some(item) = iter.next() {
            let Some(next) = iter.peek() else {
                continue;
            };

            if item.component_id >= next.component_id {
                return false;
            }
        }

        true
    }

    pub fn iter_components(&'a self) -> impl Iterator<Item = SafeAadItem<'a>> {
        self.aad_items.iter().map(SafeAadItem)
    }

    pub fn extract_component<C: Component<'a> + 'a>(&'a self) -> crate::MlsSpecResult<Option<C>> {
        self.aad_items.extract_component::<C>()
    }

    /// Returns `true` if newly inserted
    pub fn insert_or_update_component<C: Component<'a>>(
        &mut self,
        component: &C,
    ) -> crate::MlsSpecResult<bool> {
        self.aad_items.insert_or_update_component(component)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplSerialize, thalassa::TlsplSize)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct SafeAadRef<'a> {
    pub aad_items: &'a [&'a SafeAadItemRef<'a>],
}

impl<'a> SafeAadRef<'a> {
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

#[derive(Debug, Clone, PartialEq, Eq, Hash, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct WireFormats {
    pub wire_formats: Vec<crate::defs::WireFormat>,
}

#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ComponentsList {
    pub component_ids: Vec<ComponentId>,
}

#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
pub struct AppComponents(pub ComponentsList);

impl<'a> Component<'a> for AppComponents {
    fn component_id() -> ComponentId {
        super::APP_COMPONENTS_ID
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
pub struct SafeAadComponent(pub ComponentsList);

impl<'a> Component<'a> for SafeAadComponent {
    fn component_id() -> ComponentId {
        super::SAFE_AAD_ID
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{ApplicationDataDictionary, Component, SafeAad};
    use crate::{
        drafts::mls_extensions::{
            last_resort_keypackage::LastResortKeyPackage,
            safe_application::{SafeAadItemRef, SafeAadRef},
        },
        generate_roundtrip_test,
    };

    generate_roundtrip_test!(can_roundtrip_appdatadict, {
        ApplicationDataDictionary {
            component_data: super::ComponentDataMap(BTreeMap::from([
                (1, vec![1].into()),
                (3, vec![3].into()),
                (2, vec![2].into()),
            ])),
        }
    });

    generate_roundtrip_test!(can_roundtrip_safeaad, {
        SafeAad {
            aad_items: super::ComponentDataMap(BTreeMap::from([
                (1, vec![1].into()),
                (3, vec![3].into()),
                (2, vec![2].into()),
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
