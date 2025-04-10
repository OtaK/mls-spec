#[derive(Debug, thiserror::Error, miette::Diagnostic)]
pub enum MlsSpecError {
    #[error("This wire format identifier is outside the private reserved use range")]
    #[diagnostic(code(mls_spec::invalid_private_range_wireformat))]
    InvalidPrivateRangeWireFormat,
    #[error("This ciphersuite identifier is outside the private reserved use range")]
    #[diagnostic(code(mls_spec::invalid_private_range_ciphersuite))]
    InvalidPrivateRangeCiphersuite,
    #[error("This extension type identifier is outside the private reserved use range")]
    #[diagnostic(code(mls_spec::invalid_private_range_extension_type))]
    InvalidPrivateRangeExtensionType,
    #[error("This proposal type identifier is outside the private reserved use range")]
    #[diagnostic(code(mls_spec::invalid_private_range_proposal_type))]
    InvalidPrivateRangeProposalType,
    #[error("This credential type identifier is outside the private reserved use range")]
    #[diagnostic(code(mls_spec::invalid_private_range_credential_type))]
    InvalidPrivateRangeCredentialType,
    #[error("This content type identifier is outside the specification")]
    #[diagnostic(code(mls_spec::invalid_content_type))]
    InvalidContentType,
    #[error("Trying to build a FramedContentTBS but the GroupContext hasn't been provided")]
    #[diagnostic(code(mls_spec::missing_ctx))]
    FramedContentTBSMissingGroupContext,
    #[error(
        "A reserved value has been used. While we do have definitions for them, they're not supposed to be used in-protocol"
    )]
    #[diagnostic(code(mls_spec::reserved_value_usage))]
    ReservedValueUsage,
    #[error("You have tried to use an invalid value spec-wise")]
    #[diagnostic(code(mls_spec::invalid_spec_value))]
    InvalidSpecValue,
    #[error(transparent)]
    #[diagnostic(code(mls_spec::tls_codec_error))]
    #[diagnostic_source]
    TlsCodecError(#[from] tls_codec::Error),
    #[cfg(feature = "mls-rs-compat")]
    #[error(transparent)]
    #[diagnostic(code(mls_spec::mls_rs_codec_error))]
    #[diagnostic_source]
    MlsRsCodecError(#[from] mls_rs_codec::Error),
    #[cfg(feature = "draft-ietf-mls-extensions")]
    #[error("The Parameter value isn't utf-8")]
    #[diagnostic(code(mls_spec::content_adv_utf8_param_err))]
    ContentAdvertisementUtf8ParameterError,
    #[cfg(feature = "draft-ietf-mls-extensions-content-advertisement-parse")]
    #[error(transparent)]
    #[diagnostic(code(mls_spec::content_adv_invalid_mimetype))]
    ContentAdvertisementInvalidMimeType(#[from] mediatype::MediaTypeError),
    #[cfg(feature = "draft-ietf-mls-extensions")]
    #[error("SafeApp component ID is outside the private reserved use range")]
    #[diagnostic(code(mls_spec::invalid_private_range_component_id))]
    InvalidPrivateRangeComponentId,
    #[cfg(feature = "draft-ietf-mls-extensions")]
    #[error("SafeApp component ID mismatches, expected {expected}, but data contains {actual}")]
    #[diagnostic(code(mls_spec::safe_app_component_id_mismatch))]
    SafeAppComponentIdMismatch {
        expected: crate::drafts::mls_extensions::safe_application::ComponentId,
        actual: crate::drafts::mls_extensions::safe_application::ComponentId,
    },
}

pub type MlsSpecResult<T> = Result<T, MlsSpecError>;
