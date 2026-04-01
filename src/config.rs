use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::PathBuf;

const CONFIG_DIR_NAME: &str = "mcp-server-linkedin";

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub client_id: String,
    pub client_secret: String,
    /// Optional override for OAuth scopes (space-separated).
    /// Defaults to "w_member_social openid profile email" if omitted.
    pub scopes: Option<String>,
}

pub fn config_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
    PathBuf::from(home)
        .join(".config")
        .join(CONFIG_DIR_NAME)
        .join("config.toml")
}

pub fn load() -> Result<Config> {
    let path = config_path();
    let content = std::fs::read_to_string(&path).with_context(|| {
        format!(
            "Failed to read config file: {}\n\
             Create it with your LinkedIn app credentials.\n\
             Example:\n\n\
             client_id = \"YOUR_CLIENT_ID\"\n\
             client_secret = \"YOUR_CLIENT_SECRET\"\n\n\
             Register an app at https://developer.linkedin.com/",
            path.display()
        )
    })?;
    let config: Config =
        toml::from_str(&content).with_context(|| format!("Failed to parse {}", path.display()))?;
    Ok(config)
}
