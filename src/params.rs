use schemars::JsonSchema;
use serde::Deserialize;

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PostTextParams {
    #[schemars(
        description = "The text content of the LinkedIn post. Supports mentions, hashtags, and up to 3000 characters."
    )]
    pub text: String,
    #[schemars(
        description = "Post visibility: PUBLIC (default) or CONNECTIONS (connections only)"
    )]
    pub visibility: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PostImageParams {
    #[schemars(description = "The text content of the LinkedIn post")]
    pub text: String,
    #[schemars(description = "Local file path to the image (jpeg, png, gif). Max 10MB.")]
    pub image_path: String,
    #[schemars(description = "Alt text for the image (for accessibility)")]
    pub alt_text: Option<String>,
    #[schemars(
        description = "Post visibility: PUBLIC (default) or CONNECTIONS (connections only)"
    )]
    pub visibility: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PostLinkParams {
    #[schemars(description = "The text content of the LinkedIn post")]
    pub text: String,
    #[schemars(
        description = "The URL to share. LinkedIn will generate a link preview card automatically."
    )]
    pub url: String,
    #[schemars(
        description = "Post visibility: PUBLIC (default) or CONNECTIONS (connections only)"
    )]
    pub visibility: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PostUrnParams {
    #[schemars(
        description = "The LinkedIn post URN (e.g. 'urn:li:share:123456789'). Returned by post_text, post_image, post_link."
    )]
    pub post_urn: String,
}
