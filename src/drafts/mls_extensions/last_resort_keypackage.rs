use super::safe_application::Component;

#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct LastResortKeyPackage;

impl<'a> Component<'a> for LastResortKeyPackage {
    fn component_id() -> super::safe_application::ComponentId {
        super::LAST_RESORT_KEY_PACKAGE_ID
    }

    fn to_component_data(
        &self,
    ) -> crate::MlsSpecResult<super::safe_application::ComponentData<'_>> {
        Ok(super::safe_application::ComponentData {
            component_id: Self::component_id(),
            data: (&[]).into(),
        })
    }
}
