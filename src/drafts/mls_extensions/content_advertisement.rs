use std::borrow::Cow;

use super::safe_application::{Component, ComponentId};

/// <https://www.ietf.org/archive/id/draft-ietf-mls-extensions-10.html#section-6.2.2>
///
/// ### TLS Presentation Language
///
/// ```notrust,ignore
/// struct {
///     opaque parameter_name<V>;
///     /* Note: parameter_value never includes the quotation marks of */
///     /* an RFC 2045 quoted-string or the first "\" of a quoted-pair */
///     opaque parameter_value<V>;
/// } Parameter;
/// ```
#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Parameter<'a> {
    pub parameter_name: Cow<'a, str>,
    pub parameter_value: Cow<'a, str>,
}

/// <https://www.ietf.org/archive/id/draft-ietf-mls-extensions-10.html#section-6.2.2>
///
/// ### TLS Presentation Language
///
/// ```notrust,ignore
/// struct {
///     /* type is an IANA top-level media type, a "/" character,
///      * and the IANA media subtype */
///     opaque type<V>;
///
///     /* a list of zero or more parameters defined for the subtype */
///     Parameter parameters<V>;
/// } MediaType;
/// ```
#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MediaType<'a> {
    #[cfg_attr(feature = "serde", serde(alias = "type"))]
    pub media_type: Cow<'a, str>,
    pub parameters: Vec<Parameter<'a>>,
}

#[cfg(feature = "draft-ietf-mls-extensions-content-advertisement-parse")]
impl<'a> MediaType<'a> {
    pub fn to_parsed_repr(&self) -> crate::MlsSpecResult<mediatype::MediaType<'_>> {
        let mut mt_struct = mediatype::MediaType::parse(&self.media_type)?;
        use mediatype::WriteParams as _;
        for p in &self.parameters {
            let name = mediatype::Name::new(&p.parameter_name)
                .ok_or(crate::MlsSpecError::ContentAdvertisementUtf8ParameterError)?;

            let value = mediatype::Value::new(&p.parameter_value)
                .ok_or(crate::MlsSpecError::ContentAdvertisementUtf8ParameterError)?;

            mt_struct.set_param(name, value);
        }

        Ok(mt_struct)
    }
}

/// <https://www.ietf.org/archive/id/draft-ietf-mls-extensions-10.html#section-6.2.2>
///
/// ### TLS Presentation Language
///
/// ```notrust,ignore
/// struct {
///     /* must contain at least one item */
///     MediaType media_type_list<V>;
/// } MediaTypeList;
/// ```
#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MediaTypeList<'a> {
    pub media_type_list: Vec<MediaType<'a>>,
}

pub type AcceptedMediaTypes<'a> = MediaTypeList<'a>;
pub type RequiredMediaTypes<'a> = MediaTypeList<'a>;

#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
pub struct ContentMediaTypes<'a>(pub MediaTypeList<'a>);

impl<'a> Component<'a> for ContentMediaTypes<'a> {
    fn component_id() -> ComponentId {
        super::CONTENT_MEDIA_TYPES_ID
    }
}

/// <https://www.ietf.org/archive/id/draft-ietf-mls-extensions-10.html#section-6.2.4>
///
/// ### TLS Presentation Language
///
/// ```notrust,ignore
/// struct {
///     MediaType media_type;
///     opaque inner_application_content<V>;
/// } ApplicationFraming;
/// ```
#[derive(Debug, Clone, PartialEq, Eq, thalassa::TlsplAll)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ApplicationFraming<'a> {
    pub media_type: MediaType<'a>,
    pub inner_application_content: Cow<'a, [u8]>,
}
