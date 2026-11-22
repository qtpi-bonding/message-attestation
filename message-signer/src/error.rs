//! Why the message signer refused.

#[derive(Debug, thiserror::Error, coded_error::CodedError)]
#[coded(namespace = "message.signer")]
#[non_exhaustive]
pub enum MessageSignerError {
    #[error("the configuration is invalid: {0}")]
    #[coded(code = "config_invalid", class = Logical)]
    ConfigInvalid(String),
    #[error("the deliverer service principal is missing")]
    #[coded(code = "service_principal_missing", class = Logical)]
    ServicePrincipalMissing,
    #[error("the device keys cannot be used: {0}")]
    #[coded(code = "keys", class = Infrastructure)]
    Keys(String),
}
