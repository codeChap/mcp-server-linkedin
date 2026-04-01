use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{debug, warn};

use crate::auth::{self, StoredTokens};

const POSTS_URL: &str = "https://api.linkedin.com/rest/posts";
const IMAGES_URL: &str = "https://api.linkedin.com/rest/images";
const USERINFO_URL: &str = "https://api.linkedin.com/v2/userinfo";

const LINKEDIN_VERSION: &str = "202504";

/// Refresh 5 minutes before expiry.
const TOKEN_EXPIRY_BUFFER_SECS: u64 = 300;

const MAX_RETRIES: u32 = 3;
const RETRY_BASE_DELAY_MS: u64 = 1000;

// --- Public types ---

pub struct LinkedInClient {
    client_id: String,
    client_secret: String,
    http: Client,
    tokens: RwLock<StoredTokens>,
}

pub struct PostResult {
    pub post_urn: String,
    pub url: String,
}

#[derive(Deserialize, Debug)]
pub struct ProfileInfo {
    pub sub: String,
    pub name: Option<String>,
    pub email: Option<String>,
    pub picture: Option<String>,
}

// --- Internal API types ---

#[derive(Serialize)]
struct CreatePostBody {
    author: String,
    commentary: String,
    visibility: String,
    distribution: Distribution,
    #[serde(rename = "lifecycleState")]
    lifecycle_state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    content: Option<PostContent>,
}

#[derive(Serialize)]
struct Distribution {
    #[serde(rename = "feedDistribution")]
    feed_distribution: String,
    #[serde(rename = "targetEntities")]
    target_entities: Vec<String>,
    #[serde(rename = "thirdPartyDistributionChannels")]
    third_party_distribution_channels: Vec<String>,
}

#[derive(Serialize)]
#[serde(untagged)]
enum PostContent {
    Article {
        article: ArticleContent,
    },
    Media {
        media: MediaContent,
    },
}

#[derive(Serialize)]
struct ArticleContent {
    source: String,
}

#[derive(Serialize)]
struct MediaContent {
    id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "altText")]
    alt_text: Option<String>,
}

#[derive(Serialize)]
struct InitializeUploadRequest {
    #[serde(rename = "initializeUploadRequest")]
    inner: InitializeUploadInner,
}

#[derive(Serialize)]
struct InitializeUploadInner {
    owner: String,
}

#[derive(Deserialize)]
struct InitializeUploadResponse {
    value: InitializeUploadValue,
}

#[derive(Deserialize)]
struct InitializeUploadValue {
    #[serde(rename = "uploadUrl")]
    upload_url: String,
    image: String,
}

#[derive(Deserialize)]
struct PostDetailsResponse {
    #[serde(default)]
    pub author: Option<String>,
    #[serde(default)]
    pub commentary: Option<String>,
    #[serde(default)]
    pub visibility: Option<String>,
    #[serde(default, rename = "lifecycleState")]
    pub lifecycle_state: Option<String>,
    #[serde(default, rename = "createdAt")]
    pub created_at: Option<u64>,
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

impl LinkedInClient {
    pub fn new(client_id: String, client_secret: String, tokens: StoredTokens) -> Self {
        Self {
            client_id,
            client_secret,
            http: Client::builder()
                .timeout(Duration::from_secs(60))
                .build()
                .expect("Failed to build reqwest client"),
            tokens: RwLock::new(tokens),
        }
    }

    pub fn member_urn(&self) -> String {
        // We read member_id at startup; it doesn't change.
        // Use try_read to avoid blocking — fall back to blocking read.
        if let Ok(guard) = self.tokens.try_read() {
            return format!("urn:li:person:{}", guard.member_id);
        }
        // Shouldn't happen in practice, but safe fallback.
        format!("urn:li:person:unknown")
    }

    /// Get a valid access token, refreshing if needed.
    async fn ensure_auth(&self) -> Result<String, String> {
        {
            let guard = self.tokens.read().await;
            if now_secs() < guard.expires_at.saturating_sub(TOKEN_EXPIRY_BUFFER_SECS) {
                return Ok(guard.access_token.clone());
            }
        }

        // Need to refresh — acquire write lock.
        let mut guard = self.tokens.write().await;

        // Double-check after acquiring write lock.
        if now_secs() < guard.expires_at.saturating_sub(TOKEN_EXPIRY_BUFFER_SECS) {
            return Ok(guard.access_token.clone());
        }

        debug!("refreshing LinkedIn OAuth2 token");

        let updated = auth::refresh_tokens(
            &self.http,
            &self.client_id,
            &self.client_secret,
            &guard,
        )
        .await
        .map_err(|e| e.to_string())?;

        *guard = updated;
        Ok(guard.access_token.clone())
    }

    /// Build an authenticated request with LinkedIn headers.
    fn authed_request(
        &self,
        builder: reqwest::RequestBuilder,
        token: &str,
    ) -> reqwest::RequestBuilder {
        builder
            .header("Authorization", format!("Bearer {token}"))
            .header("LinkedIn-Version", LINKEDIN_VERSION)
            .header("X-Restli-Protocol-Version", "2.0.0")
    }

    async fn retry_on_error(
        &self,
        build: impl Fn() -> reqwest::RequestBuilder,
    ) -> Result<reqwest::Response, String> {
        for attempt in 0..=MAX_RETRIES {
            if attempt > 0 {
                let delay = RETRY_BASE_DELAY_MS * 2u64.pow(attempt - 1);
                warn!(
                    "LinkedIn API returned error, retrying in {delay}ms (attempt {attempt}/{MAX_RETRIES})"
                );
                tokio::time::sleep(Duration::from_millis(delay)).await;
            }
            let resp = build()
                .send()
                .await
                .map_err(|e| format!("HTTP request failed: {e}"))?;
            let status = resp.status().as_u16();
            if status != 503 || attempt == MAX_RETRIES {
                return Ok(resp);
            }
        }
        unreachable!()
    }

    async fn check_response(&self, resp: reqwest::Response) -> Result<reqwest::Response, String> {
        let status = resp.status();
        if status.as_u16() == 401 {
            warn!("Received 401 from LinkedIn API. Tokens may be expired. Run `linkedin --auth` to re-authorize.");
        }
        if status.as_u16() == 429 {
            return Err("Rate limited (429). Try again later.".into());
        }
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("LinkedIn API error ({status}): {body}"));
        }
        Ok(resp)
    }

    // --- Public API methods ---

    pub async fn get_profile(&self) -> Result<ProfileInfo, String> {
        let token = self.ensure_auth().await?;
        let resp = self
            .retry_on_error(|| {
                self.http
                    .get(USERINFO_URL)
                    .header("Authorization", format!("Bearer {}", token))
            })
            .await?;
        let resp = self.check_response(resp).await?;
        resp.json::<ProfileInfo>()
            .await
            .map_err(|e| format!("Failed to parse profile response: {e}"))
    }

    pub async fn create_post(
        &self,
        author_urn: &str,
        commentary: &str,
        visibility: &str,
    ) -> Result<PostResult, String> {
        let token = self.ensure_auth().await?;
        let body = CreatePostBody {
            author: author_urn.to_string(),
            commentary: commentary.to_string(),
            visibility: visibility.to_string(),
            distribution: Distribution {
                feed_distribution: "MAIN_FEED".to_string(),
                target_entities: vec![],
                third_party_distribution_channels: vec![],
            },
            lifecycle_state: "PUBLISHED".to_string(),
            content: None,
        };

        let resp = self
            .retry_on_error(|| {
                self.authed_request(self.http.post(POSTS_URL), &token)
                    .json(&body)
            })
            .await?;
        let resp = self.check_response(resp).await?;
        self.extract_post_result(&resp)
    }

    pub async fn create_post_with_image(
        &self,
        author_urn: &str,
        commentary: &str,
        image_path: &str,
        alt_text: Option<&str>,
        visibility: &str,
    ) -> Result<PostResult, String> {
        let token = self.ensure_auth().await?;

        // Validate file.
        let path = Path::new(image_path);
        if !path.exists() {
            return Err(format!("File not found: {image_path}"));
        }
        let metadata =
            std::fs::metadata(path).map_err(|e| format!("Cannot read file metadata: {e}"))?;
        if metadata.len() > 10 * 1024 * 1024 {
            return Err(format!(
                "Image too large: {} bytes (max 10MB)",
                metadata.len()
            ));
        }

        // Step 1: Initialize upload.
        let init_body = InitializeUploadRequest {
            inner: InitializeUploadInner {
                owner: author_urn.to_string(),
            },
        };

        let init_resp = self
            .retry_on_error(|| {
                self.authed_request(
                    self.http
                        .post(format!("{IMAGES_URL}?action=initializeUpload")),
                    &token,
                )
                .json(&init_body)
            })
            .await?;
        let init_resp = self.check_response(init_resp).await?;
        let init_data: InitializeUploadResponse = init_resp
            .json()
            .await
            .map_err(|e| format!("Failed to parse initializeUpload response: {e}"))?;

        // Step 2: Upload binary image.
        let file_bytes =
            std::fs::read(path).map_err(|e| format!("Failed to read image file: {e}"))?;

        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();
        let content_type = match ext.as_str() {
            "jpg" | "jpeg" => "image/jpeg",
            "png" => "image/png",
            "gif" => "image/gif",
            _ => "application/octet-stream",
        };

        let upload_resp = self
            .http
            .put(&init_data.value.upload_url)
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", content_type)
            .body(file_bytes)
            .send()
            .await
            .map_err(|e| format!("Image upload failed: {e}"))?;

        let upload_status = upload_resp.status();
        if !upload_status.is_success() {
            let body = upload_resp.text().await.unwrap_or_default();
            return Err(format!("Image upload failed ({upload_status}): {body}"));
        }

        // Step 3: Create post with image.
        let body = CreatePostBody {
            author: author_urn.to_string(),
            commentary: commentary.to_string(),
            visibility: visibility.to_string(),
            distribution: Distribution {
                feed_distribution: "MAIN_FEED".to_string(),
                target_entities: vec![],
                third_party_distribution_channels: vec![],
            },
            lifecycle_state: "PUBLISHED".to_string(),
            content: Some(PostContent::Media {
                media: MediaContent {
                    id: init_data.value.image,
                    alt_text: alt_text.map(|s| s.to_string()),
                },
            }),
        };

        let resp = self
            .retry_on_error(|| {
                self.authed_request(self.http.post(POSTS_URL), &token)
                    .json(&body)
            })
            .await?;
        let resp = self.check_response(resp).await?;
        self.extract_post_result(&resp)
    }

    pub async fn create_post_with_link(
        &self,
        author_urn: &str,
        commentary: &str,
        link_url: &str,
        visibility: &str,
    ) -> Result<PostResult, String> {
        let token = self.ensure_auth().await?;
        let body = CreatePostBody {
            author: author_urn.to_string(),
            commentary: commentary.to_string(),
            visibility: visibility.to_string(),
            distribution: Distribution {
                feed_distribution: "MAIN_FEED".to_string(),
                target_entities: vec![],
                third_party_distribution_channels: vec![],
            },
            lifecycle_state: "PUBLISHED".to_string(),
            content: Some(PostContent::Article {
                article: ArticleContent {
                    source: link_url.to_string(),
                },
            }),
        };

        let resp = self
            .retry_on_error(|| {
                self.authed_request(self.http.post(POSTS_URL), &token)
                    .json(&body)
            })
            .await?;
        let resp = self.check_response(resp).await?;
        self.extract_post_result(&resp)
    }

    pub async fn delete_post(&self, post_urn: &str) -> Result<(), String> {
        let token = self.ensure_auth().await?;
        let encoded_urn = urlencoding::encode(post_urn);
        let url = format!("{POSTS_URL}/{encoded_urn}");

        let resp = self
            .retry_on_error(|| self.authed_request(self.http.delete(&url), &token))
            .await?;
        self.check_response(resp).await?;
        Ok(())
    }

    pub async fn get_post(&self, post_urn: &str) -> Result<String, String> {
        let token = self.ensure_auth().await?;
        let encoded_urn = urlencoding::encode(post_urn);
        let url = format!("{POSTS_URL}/{encoded_urn}");

        let resp = self
            .retry_on_error(|| self.authed_request(self.http.get(&url), &token))
            .await?;
        let resp = self.check_response(resp).await?;
        let details: PostDetailsResponse = resp
            .json()
            .await
            .map_err(|e| format!("Failed to parse post response: {e}"))?;

        let mut output = String::new();
        output.push_str(&format!(
            "Post: {post_urn}\n"
        ));
        if let Some(author) = &details.author {
            output.push_str(&format!("  Author: {author}\n"));
        }
        if let Some(commentary) = &details.commentary {
            output.push_str(&format!("  Text: {commentary}\n"));
        }
        if let Some(visibility) = &details.visibility {
            output.push_str(&format!("  Visibility: {visibility}\n"));
        }
        if let Some(state) = &details.lifecycle_state {
            output.push_str(&format!("  State: {state}\n"));
        }
        if let Some(ts) = details.created_at {
            output.push_str(&format!("  Created: {ts}\n"));
        }

        Ok(output)
    }

    // --- Private helpers ---

    fn extract_post_result(&self, resp: &reqwest::Response) -> Result<PostResult, String> {
        let post_urn = resp
            .headers()
            .get("x-restli-id")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
            .unwrap_or_else(|| "unknown".to_string());

        let url = format!(
            "https://www.linkedin.com/feed/update/{}",
            post_urn
        );

        Ok(PostResult { post_urn, url })
    }
}
