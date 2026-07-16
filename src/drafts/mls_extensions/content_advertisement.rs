use std::borrow::Cow;

use super::safe_application::{Component, ComponentId, ComponentsList};

#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Parameter<'a> {
    pub parameter_name: Cow<'a, [u8]>,
    pub parameter_value: Cow<'a, [u8]>,
}

#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MediaType<'a> {
    #[cfg_attr(feature = "serde", serde(alias = "type"))]
    pub media_type: Cow<'a, [u8]>,
    pub parameters: Vec<Parameter<'a>>,
}

#[cfg(feature = "draft-ietf-mls-extensions-content-advertisement-parse")]
impl<'a> MediaType<'a> {
    pub fn to_parsed_repr(&self) -> crate::MlsSpecResult<mediatype::MediaType<'_>> {
        let mt = std::str::from_utf8(&self.media_type)
            .map_err(|_| crate::MlsSpecError::ContentAdvertisementUtf8ParameterError)?;

        let mut mt_struct = mediatype::MediaType::parse(mt)?;
        use mediatype::WriteParams as _;
        for p in &self.parameters {
            let name = std::str::from_utf8(&*p.parameter_name)
                .map_err(|_| crate::MlsSpecError::ContentAdvertisementUtf8ParameterError)
                .and_then(|s| {
                    mediatype::Name::new(s)
                        .ok_or(crate::MlsSpecError::ContentAdvertisementUtf8ParameterError)
                })?;

            let value = std::str::from_utf8(&*p.parameter_value)
                .map_err(|_| crate::MlsSpecError::ContentAdvertisementUtf8ParameterError)
                .and_then(|s| {
                    mediatype::Value::new(s)
                        .ok_or(crate::MlsSpecError::ContentAdvertisementUtf8ParameterError)
                })?;

            mt_struct.set_param(name, value);
        }

        Ok(mt_struct)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MediaTypeList<'a> {
    pub media_type_list: Vec<MediaType<'a>>,
}

pub type AcceptedMediaTypes<'a> = MediaTypeList<'a>;
pub type RequiredMediaTypes<'a> = MediaTypeList<'a>;

#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
pub struct ContentMediaTypes(pub ComponentsList);

impl<'a> Component<'a> for ContentMediaTypes {
    fn component_id() -> ComponentId {
        super::CONTENT_MEDIA_TYPES_ID
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ApplicationFraming<'a> {
    pub media_type: MediaType<'a>,
    pub inner_application_content: Cow<'a, [u8]>,
}
