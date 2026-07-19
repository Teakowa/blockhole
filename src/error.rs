use thiserror::Error;

#[derive(Debug, Error)]
pub enum BlockholeError {
    #[error("configuration error: {0}")]
    Configuration(String),
    #[error("missing required environment variable: {var}")]
    MissingEnvVar { var: &'static str },
    #[error("unsupported schema version {version}, expected {expected}")]
    UnsupportedSchema { version: u32, expected: u32 },
    #[error("state error: {0}")]
    State(String),
    #[error("policy error: {0}")]
    Policy(String),
    #[error("Cloudflare error: {0}")]
    Cloudflare(String),
    #[error("safety error: {0}")]
    Safety(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Http(#[from] reqwest::Error),
}

pub type Result<T> = std::result::Result<T, BlockholeError>;
