use anyhow::{Context, Result, bail};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const AUTH_URL: &str = "https://www.linkedin.com/oauth/v2/authorization";
const TOKEN_URL: &str = "https://www.linkedin.com/oauth/v2/accessToken";
const USERINFO_URL: &str = "https://api.linkedin.com/v2/userinfo";
const ME_URL: &str = "https://api.linkedin.com/v2/me";

/// Scopes to request. LinkedIn may reject openid/profile/email if those
/// products aren't enabled on the app. We still try them — the error message
/// will tell the user which scope is the problem.
const SCOPES: &str = "w_member_social profile openid email";
const REDIRECT_URI: &str = "http://localhost:8585/callback";

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct StoredTokens {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: u64,
    pub member_id: String,
}

pub fn tokens_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
    PathBuf::from(home)
        .join(".config")
        .join("mcp-server-linkedin")
        .join("tokens.json")
}

pub fn load_tokens() -> Option<StoredTokens> {
    let path = tokens_path();
    let mut file = std::fs::File::open(&path).ok()?;
    let mut content = String::new();
    file.read_to_string(&mut content).ok()?;
    serde_json::from_str(&content).ok()
}

pub fn save_tokens(tokens: &StoredTokens) -> Result<()> {
    let path = tokens_path();
    let json = serde_json::to_string_pretty(tokens)?;
    let mut file = std::fs::File::create(&path)
        .with_context(|| format!("Failed to write {}", path.display()))?;
    file.write_all(json.as_bytes())?;
    #[cfg(unix)]
    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Run the one-time browser authorization flow.
pub async fn authorize(client_id: &str, client_secret: &str, scopes: Option<&str>) -> Result<()> {
    let scopes = scopes.unwrap_or(SCOPES);
    let state = {
        let mut buf = [0u8; 16];
        getrandom::getrandom(&mut buf)
            .map_err(|e| anyhow::anyhow!("Failed to generate random state: {e}"))?;
        buf.iter().map(|b| format!("{b:02x}")).collect::<String>()
    };

    let auth_url = format!(
        "{AUTH_URL}?response_type=code&client_id={}&redirect_uri={}&scope={}&state={state}",
        urlencoding::encode(client_id),
        urlencoding::encode(REDIRECT_URI),
        urlencoding::encode(scopes),
    );

    let listener = TcpListener::bind("127.0.0.1:8585")
        .await
        .context("Failed to bind to port 8585 — is another instance running?")?;

    println!("Opening browser for LinkedIn authorization...\n");
    println!("If the browser doesn't open, visit this URL:\n{auth_url}\n");

    if let Err(e) = open::that(&auth_url) {
        eprintln!("Could not open browser: {e}");
    }

    println!("Waiting for callback on {REDIRECT_URI} ...");

    let (mut stream, _) = listener.accept().await?;

    let mut buf = vec![0u8; 4096];
    let n = stream.read(&mut buf).await?;
    let request = String::from_utf8_lossy(&buf[..n]);

    let first_line = request.lines().next().unwrap_or("");
    let path = first_line.split_whitespace().nth(1).unwrap_or("");

    let code = extract_param(path, "code");
    let returned_state = extract_param(path, "state");
    let error = extract_param(path, "error");
    let error_description = extract_param(path, "error_description");

    // Log the full callback for debugging.
    eprintln!("Callback path: {path}");

    let (status, body) = if code.is_some() {
        (
            "200 OK",
            "<html><body><h2>Authorization successful!</h2><p>You can close this tab.</p></body></html>".to_string(),
        )
    } else {
        let msg = match (&error, &error_description) {
            (Some(e), Some(d)) => format!("{e}: {d}"),
            (Some(e), None) => e.clone(),
            _ => "No code received".to_string(),
        };
        (
            "400 Bad Request",
            format!("<html><body><h2>Authorization failed</h2><p>{msg}</p></body></html>"),
        )
    };

    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.shutdown().await;

    if let Some(err) = error {
        let desc = error_description.unwrap_or_default();
        bail!("LinkedIn authorization failed: {err} — {desc}");
    }

    let code = code.ok_or_else(|| anyhow::anyhow!("No authorization code received"))?;

    if let Some(ref rs) = returned_state {
        if *rs != state {
            bail!("State mismatch — possible CSRF attack");
        }
    }

    println!("Authorization code received. Exchanging for tokens...");

    // LinkedIn expects client credentials in the form body (not Basic auth).
    let http = Client::new();

    let resp = http
        .post(TOKEN_URL)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(format!(
            "grant_type=authorization_code&code={}&redirect_uri={}&client_id={}&client_secret={}",
            urlencoding::encode(&code),
            urlencoding::encode(REDIRECT_URI),
            urlencoding::encode(client_id),
            urlencoding::encode(client_secret),
        ))
        .send()
        .await?;

    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        bail!("Token exchange failed ({status}): {body}");
    }

    let token_resp: TokenResponse = resp.json().await?;

    // Fetch member ID — try OpenID userinfo first, fall back to /v2/me.
    println!("Fetching profile info...");

    let userinfo =
        fetch_member_info(&http, &token_resp.access_token, client_id, client_secret).await?;

    let tokens = StoredTokens {
        access_token: token_resp.access_token,
        refresh_token: token_resp.refresh_token.unwrap_or_default(),
        expires_at: now_secs() + token_resp.expires_in,
        member_id: userinfo.id,
    };

    save_tokens(&tokens)?;

    println!("\nAuthorization complete!");
    println!("  Name:      {}", userinfo.name.unwrap_or_default());
    println!("  Email:     {}", userinfo.email.unwrap_or_default());
    println!("  Member ID: {}", tokens.member_id);
    println!("  Tokens saved to: {}", tokens_path().display());
    println!("\nYou can now run the MCP server normally.");

    Ok(())
}

/// Refresh an access token using the stored refresh token.
pub async fn refresh_tokens(
    http: &Client,
    client_id: &str,
    client_secret: &str,
    stored: &StoredTokens,
) -> Result<StoredTokens> {
    let resp = http
        .post(TOKEN_URL)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(format!(
            "grant_type=refresh_token&refresh_token={}&client_id={}&client_secret={}",
            urlencoding::encode(&stored.refresh_token),
            urlencoding::encode(client_id),
            urlencoding::encode(client_secret),
        ))
        .send()
        .await?;

    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        bail!(
            "Token refresh failed ({status}): {body}. Run `linkedin --auth` to re-authorize."
        );
    }

    let token_resp: TokenResponse = resp.json().await?;

    let updated = StoredTokens {
        access_token: token_resp.access_token,
        refresh_token: token_resp
            .refresh_token
            .unwrap_or_else(|| stored.refresh_token.clone()),
        expires_at: now_secs() + token_resp.expires_in,
        member_id: stored.member_id.clone(),
    };

    save_tokens(&updated)?;
    Ok(updated)
}

fn extract_param(path: &str, key: &str) -> Option<String> {
    let query = path.split('?').nth(1)?;
    for pair in query.split('&') {
        let mut kv = pair.splitn(2, '=');
        if let (Some(k), Some(v)) = (kv.next(), kv.next()) {
            if k == key {
                return Some(urlencoding::decode(v).unwrap_or_default().into_owned());
            }
        }
    }
    None
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    refresh_token: Option<String>,
    expires_in: u64,
}

struct MemberInfo {
    id: String,
    name: Option<String>,
    email: Option<String>,
}

/// Try OpenID userinfo first, fall back to /v2/me, then token introspection.
async fn fetch_member_info(
    http: &Client,
    access_token: &str,
    client_id: &str,
    client_secret: &str,
) -> Result<MemberInfo> {
    // Try OpenID Connect userinfo endpoint.
    let resp = http
        .get(USERINFO_URL)
        .header("Authorization", format!("Bearer {access_token}"))
        .send()
        .await?;

    if resp.status().is_success() {
        #[derive(Deserialize)]
        struct UserInfo {
            sub: String,
            name: Option<String>,
            email: Option<String>,
        }
        let info: UserInfo = resp.json().await?;
        return Ok(MemberInfo {
            id: info.sub,
            name: info.name,
            email: info.email,
        });
    }

    eprintln!(
        "OpenID userinfo not available ({}), trying /v2/me...",
        resp.status()
    );

    // Fall back to /v2/me endpoint (unversioned).
    let resp = http
        .get(ME_URL)
        .header("Authorization", format!("Bearer {access_token}"))
        .send()
        .await?;

    if resp.status().is_success() {
        let value: serde_json::Value = resp.json().await?;
        let id = value["id"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("No 'id' in /v2/me response"))?
            .to_string();
        let first = value["localizedFirstName"].as_str().unwrap_or("");
        let last = value["localizedLastName"].as_str().unwrap_or("");
        let name = if first.is_empty() && last.is_empty() {
            None
        } else {
            Some(format!("{first} {last}").trim().to_string())
        };
        return Ok(MemberInfo {
            id,
            name,
            email: None,
        });
    }

    eprintln!(
        "/v2/me not available ({}), trying versioned /rest/me...",
        resp.status()
    );

    // Fall back to versioned REST endpoint.
    let resp = http
        .get("https://api.linkedin.com/rest/me")
        .header("Authorization", format!("Bearer {access_token}"))
        .header("LinkedIn-Version", "202501")
        .header("X-Restli-Protocol-Version", "2.0.0")
        .send()
        .await?;

    if resp.status().is_success() {
        let value: serde_json::Value = resp.json().await?;
        // REST API may use "id" or "sub"
        let id = value["sub"]
            .as_str()
            .or_else(|| value["id"].as_str())
            .ok_or_else(|| anyhow::anyhow!("No member ID in /rest/me response"))?
            .to_string();
        let first = value["localizedFirstName"].as_str().unwrap_or("");
        let last = value["localizedLastName"].as_str().unwrap_or("");
        let name = if first.is_empty() && last.is_empty() {
            None
        } else {
            Some(format!("{first} {last}").trim().to_string())
        };
        return Ok(MemberInfo {
            id,
            name,
            email: None,
        });
    }

    eprintln!(
        "/rest/me not available ({}), trying token introspection...",
        resp.status()
    );

    // Last resort: LinkedIn token introspection.
    let resp = http
        .post("https://www.linkedin.com/oauth/v2/introspectToken")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(format!(
            "token={}&client_id={}&client_secret={}",
            urlencoding::encode(access_token),
            urlencoding::encode(client_id),
            urlencoding::encode(client_secret),
        ))
        .send()
        .await?;

    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        bail!(
            "Cannot determine member ID. Profile endpoints returned 403 \
             and token introspection failed ({status}): {body}\n\
             Try adding 'openid' and 'profile' scopes, or enable \
             'Sign In with LinkedIn' product on your app."
        );
    }

    let value: serde_json::Value = resp.json().await?;
    eprintln!("Introspection response: {value}");

    if let Some(sub) = value["sub"].as_str() {
        return Ok(MemberInfo {
            id: sub.to_string(),
            name: None,
            email: None,
        });
    }

    // Last resort: try to decode the access token as a JWT.
    if let Some(id) = extract_sub_from_jwt(access_token) {
        eprintln!("Extracted member ID from JWT access token: {id}");
        return Ok(MemberInfo {
            id,
            name: None,
            email: None,
        });
    }

    bail!(
        "Cannot determine member ID. Profile endpoints returned 403 \
         and token does not contain a 'sub' claim.\n\
         Fix: Go to your LinkedIn app at https://developer.linkedin.com/ \
         and enable the 'Sign In with LinkedIn using OpenID Connect' product.\n\
         Then update your config.toml:\n\
         scopes = \"w_member_social openid profile\"\n\
         And run: linkedin --auth"
    )
}

/// Try to extract the 'sub' claim from a JWT access token (no signature verification).
fn extract_sub_from_jwt(token: &str) -> Option<String> {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    let payload = URL_SAFE_NO_PAD.decode(parts[1]).ok()?;
    let value: serde_json::Value = serde_json::from_slice(&payload).ok()?;
    value["sub"].as_str().map(|s| s.to_string())
}
