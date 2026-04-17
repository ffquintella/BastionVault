use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct CommandError {
    pub message: String,
}

impl std::fmt::Display for CommandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl From<bastion_vault::errors::RvError> for CommandError {
    fn from(e: bastion_vault::errors::RvError) -> Self {
        Self { message: e.to_string() }
    }
}

impl From<String> for CommandError {
    fn from(s: String) -> Self {
        Self { message: s }
    }
}

impl From<&str> for CommandError {
    fn from(s: &str) -> Self {
        Self { message: s.to_string() }
    }
}

impl From<keyring::Error> for CommandError {
    fn from(e: keyring::Error) -> Self {
        Self { message: format!("Keychain error: {e}") }
    }
}

impl From<std::io::Error> for CommandError {
    fn from(e: std::io::Error) -> Self {
        Self { message: format!("IO error: {e}") }
    }
}

impl From<authenticator::errors::AuthenticatorError> for CommandError {
    fn from(e: authenticator::errors::AuthenticatorError) -> Self {
        use authenticator::errors::AuthenticatorError;
        let message = match &e {
            AuthenticatorError::PinError(pin_err) => {
                // Use the Display impl which gives user-friendly messages
                format!("{pin_err}")
            }
            AuthenticatorError::CancelledByUser => {
                "Operation was cancelled".to_string()
            }
            AuthenticatorError::CredentialExcluded => {
                "This security key is already registered".to_string()
            }
            AuthenticatorError::NoConfiguredTransports => {
                "No security key detected. Please insert your key and try again.".to_string()
            }
            _ => format!("Security key error: {e}"),
        };
        Self { message }
    }
}

pub type CmdResult<T> = Result<T, CommandError>;
