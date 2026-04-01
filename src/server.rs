use crate::api::LinkedInClient;
use crate::params::{PostImageParams, PostLinkParams, PostTextParams, PostUrnParams};
use rmcp::{
    ErrorData as McpError, ServerHandler, handler::server::tool::ToolRouter,
    handler::server::wrapper::Parameters, model::*, tool, tool_handler, tool_router,
};
use std::sync::Arc;

#[derive(Clone)]
pub struct LinkedInServer {
    client: Arc<LinkedInClient>,
    tool_router: ToolRouter<Self>,
}

impl LinkedInServer {
    fn ok_or_err(result: Result<String, String>) -> CallToolResult {
        match result {
            Ok(text) => CallToolResult::success(vec![Content::text(text)]),
            Err(e) => CallToolResult::error(vec![Content::text(e)]),
        }
    }
}

#[tool_router]
impl LinkedInServer {
    pub fn new(client: LinkedInClient) -> Self {
        Self {
            client: Arc::new(client),
            tool_router: Self::tool_router(),
        }
    }

    #[tool(
        description = "Get the authenticated LinkedIn user's profile info (name, email, member ID). Useful for verifying credentials."
    )]
    async fn get_profile(&self) -> Result<CallToolResult, McpError> {
        let result = self.client.get_profile().await;

        Ok(Self::ok_or_err(result.map(|p| {
            let mut output = String::from("LinkedIn Profile:\n");
            output.push_str(&format!("  Member ID: {}\n", p.sub));
            if let Some(name) = &p.name {
                output.push_str(&format!("  Name: {name}\n"));
            }
            if let Some(email) = &p.email {
                output.push_str(&format!("  Email: {email}\n"));
            }
            if let Some(picture) = &p.picture {
                output.push_str(&format!("  Picture: {picture}\n"));
            }
            output
        })))
    }

    #[tool(
        description = "Create a text-only post on LinkedIn. Supports up to 3000 characters, hashtags, and mentions."
    )]
    async fn post_text(
        &self,
        Parameters(params): Parameters<PostTextParams>,
    ) -> Result<CallToolResult, McpError> {
        let text = params.text.trim();
        if text.is_empty() {
            return Ok(CallToolResult::error(vec![Content::text(
                "Post text cannot be empty.",
            )]));
        }
        if text.len() > 3000 {
            return Ok(CallToolResult::error(vec![Content::text(
                "Post text exceeds 3000 character limit.",
            )]));
        }

        let visibility = params
            .visibility
            .as_deref()
            .unwrap_or("PUBLIC")
            .to_uppercase();

        let author_urn = self.client.member_urn();
        let result = self
            .client
            .create_post(&author_urn, text, &visibility)
            .await;

        Ok(Self::ok_or_err(result.map(|r| {
            format!(
                "Posted to LinkedIn!\nPost URN: {}\nURL: {}",
                r.post_urn, r.url
            )
        })))
    }

    #[tool(
        description = "Create a LinkedIn post with an image attachment. Supports jpeg, png, gif (max 10MB)."
    )]
    async fn post_image(
        &self,
        Parameters(params): Parameters<PostImageParams>,
    ) -> Result<CallToolResult, McpError> {
        let text = params.text.trim();
        if text.is_empty() {
            return Ok(CallToolResult::error(vec![Content::text(
                "Post text cannot be empty.",
            )]));
        }

        let visibility = params
            .visibility
            .as_deref()
            .unwrap_or("PUBLIC")
            .to_uppercase();

        let author_urn = self.client.member_urn();
        let result = self
            .client
            .create_post_with_image(
                &author_urn,
                text,
                &params.image_path,
                params.alt_text.as_deref(),
                &visibility,
            )
            .await;

        Ok(Self::ok_or_err(result.map(|r| {
            format!(
                "Posted to LinkedIn with image!\nPost URN: {}\nURL: {}",
                r.post_urn, r.url
            )
        })))
    }

    #[tool(
        description = "Create a LinkedIn post with a link/article. LinkedIn auto-generates a preview card for the URL."
    )]
    async fn post_link(
        &self,
        Parameters(params): Parameters<PostLinkParams>,
    ) -> Result<CallToolResult, McpError> {
        let text = params.text.trim();
        if text.is_empty() {
            return Ok(CallToolResult::error(vec![Content::text(
                "Post text cannot be empty.",
            )]));
        }
        let url = params.url.trim();
        if url.is_empty() {
            return Ok(CallToolResult::error(vec![Content::text(
                "URL cannot be empty.",
            )]));
        }

        let visibility = params
            .visibility
            .as_deref()
            .unwrap_or("PUBLIC")
            .to_uppercase();

        let author_urn = self.client.member_urn();
        let result = self
            .client
            .create_post_with_link(&author_urn, text, url, &visibility)
            .await;

        Ok(Self::ok_or_err(result.map(|r| {
            format!(
                "Posted to LinkedIn with link!\nPost URN: {}\nURL: {}",
                r.post_urn, r.url
            )
        })))
    }

    #[tool(
        description = "Delete a LinkedIn post by its URN. You can only delete your own posts."
    )]
    async fn delete_post(
        &self,
        Parameters(params): Parameters<PostUrnParams>,
    ) -> Result<CallToolResult, McpError> {
        let urn = params.post_urn.trim();
        if urn.is_empty() {
            return Ok(CallToolResult::error(vec![Content::text(
                "Post URN cannot be empty.",
            )]));
        }

        let result = self.client.delete_post(urn).await;

        Ok(Self::ok_or_err(
            result.map(|()| format!("Post deleted: {urn}")),
        ))
    }

    #[tool(description = "Get details of a specific LinkedIn post by its URN.")]
    async fn get_post(
        &self,
        Parameters(params): Parameters<PostUrnParams>,
    ) -> Result<CallToolResult, McpError> {
        let urn = params.post_urn.trim();
        if urn.is_empty() {
            return Ok(CallToolResult::error(vec![Content::text(
                "Post URN cannot be empty.",
            )]));
        }

        let result = self.client.get_post(urn).await;
        Ok(Self::ok_or_err(result))
    }
}

#[tool_handler]
impl ServerHandler for LinkedInServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new(
                "mcp-server-linkedin",
                env!("CARGO_PKG_VERSION"),
            ))
            .with_instructions(
                "LinkedIn server. Tools: get_profile, post_text, post_image, \
                 post_link, delete_post, get_post.",
            )
    }
}
