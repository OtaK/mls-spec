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
pub struct Parameter {
    #[tls_codec(with = "crate::tlspl::bytes")]
    pub parameter_name: Vec<u8>,
    #[tls_codec(with = "crate::tlspl::bytes")]
    pub parameter_value: Vec<u8>,
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
pub struct MediaType {
    #[tls_codec(with = "crate::tlspl::bytes")]
    pub media_type: Vec<u8>,
    pub parameters: Vec<Parameter>,
}

#[cfg(feature = "draft-ietf-mls-extensions-content-advertisement-parse")]
impl MediaType {
    pub fn to_parsed_repr(&self) -> crate::MlsSpecResult<mediatype::MediaType> {
        let mt = std::str::from_utf8(&self.media_type)
            .map_err(|_| crate::MlsSpecError::ContentAdvertisementUtf8ParameterError)?;

        let mut mt_struct = mediatype::MediaType::parse(mt)?;
        use mediatype::WriteParams as _;
        for p in &self.parameters {
            let name = std::str::from_utf8(p.parameter_name.as_slice())
                .map_err(|_| crate::MlsSpecError::ContentAdvertisementUtf8ParameterError)
                .and_then(|s| {
                    mediatype::Name::new(s)
                        .ok_or(crate::MlsSpecError::ContentAdvertisementUtf8ParameterError)
                })?;

            let value = std::str::from_utf8(p.parameter_value.as_slice())
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
pub struct MediaTypeList {
    pub media_types: Vec<MediaType>,
}

pub type AcceptedMediaTypes = MediaTypeList;
pub type RequiredMediaTypes = MediaTypeList;

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
pub struct ApplicationFraming {
    pub media_type: MediaType,
    #[tls_codec(with = "crate::tlspl::bytes")]
    pub application_content: Vec<u8>,
}
