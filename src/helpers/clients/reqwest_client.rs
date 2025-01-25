use async_trait::async_trait;

use http::header::{CONTENT_LENGTH, RETRY_AFTER};
use http::Request;
use reqwest::{Body, Client};

use crate::helpers::clients::{request_builder, WebPushClient};
use crate::helpers::error::{RetryAfter, WebPushError};
use crate::helpers::message::WebPushMessage;

/// An async client for sending the notification payload.
///
/// This client is thread-safe. Clones of this client will share the same underlying resources,
/// so cloning is a cheap and effective method to provide access to the client.
///
/// This client is [`hyper`](https://crates.io/crates/hyper) based, and will only work in Tokio contexts.
#[derive(Clone)]
pub struct ReqwestWebPushClient {
    client: Client,
}

impl Default for ReqwestWebPushClient {
    fn default() -> Self {
        Self::new()
    }
}

impl From<Client> for ReqwestWebPushClient {
    /// Creates a new client from a custom hyper HTTP client.
    fn from(client: Client) -> Self {
        Self { client }
    }
}

impl ReqwestWebPushClient {
    /// Creates a new client.
    pub fn new() -> Self {
        Self {
            client: Client::builder().use_rustls_tls().build().unwrap(),
        }
    }
}

#[async_trait]
impl WebPushClient for ReqwestWebPushClient {
    /// Sends a notification. Never times out.
    async fn send(&self, message: WebPushMessage) -> Result<(), WebPushError> {
        trace!("Message: {:?}", message);

        let request: Request<Body> = request_builder::build_request(message);

        let body = request.body().as_bytes().unwrap().to_vec();
        debug!("Request: {:?}", request);
        let mut builder = self.client.post(request.uri().to_string());
        for (key, value) in request.headers() {
            builder = builder.header(key, value);
        }

        let requesting = builder.body(body).send();

        let mut response = requesting.await?;

        trace!("Response: {:?}", response);

        let retry_after = response
            .headers()
            .get(RETRY_AFTER)
            .and_then(|ra| ra.to_str().ok())
            .and_then(RetryAfter::from_str);

        let response_status = response.status();
        trace!("Response status: {}", response_status);

        let content_length = response
            .headers()
            .get(CONTENT_LENGTH)
            .and_then(|s| s.to_str().ok())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        let mut body: Vec<u8> = Vec::with_capacity(content_length);

        while let Ok(Some(chunk)) = response.chunk().await {
            body.extend(&chunk);
        }
        trace!("Body: {:?}", body);

        trace!("Body text: {:?}", std::str::from_utf8(&body));

        let response = request_builder::parse_response(response_status, body.to_vec());

        debug!("Response: {:?}", response);

        if let Err(WebPushError::ServerError {
            retry_after: None,
            info,
        }) = response
        {
            Err(WebPushError::ServerError { retry_after, info })
        } else {
            Ok(response?)
        }
    }
}
