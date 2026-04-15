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
        Self { message: format!("Authenticator error: {e:?}") }
    }
}

pub type CmdResult<T> = Result<T, CommandError>;
