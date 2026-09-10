//! The HTTP seam the content protocol rides, and its native implementation.
//!
//! The seam exists because the negotiation is shared with R68 and the two
//! platforms cannot share a client: the native side is `reqwest` over rustls,
//! and a browser worker has `fetch`. Everything above this trait, including
//! every status-code decision, lives once above it in the upload negotiation.

use connetto_file_core::MaybeSend;

/// What one content request answered.
pub struct HttpReply {
    /// The HTTP status code.
    pub status: u16,
    /// The response body, empty when the answer carried none.
    pub body: Vec<u8>,
}

/// The three request shapes the content protocol uses.
pub trait ContentHttp {
    /// The transport's own failure type, for a request that never got a status.
    type Error: core::fmt::Display;

    /// `POST` to `url`, with `json` as an `application/json` body when present.
    ///
    /// The absent case is the commit, which carries no body.
    fn post(
        &self,
        url: &str,
        json: Option<Vec<u8>>,
    ) -> impl Future<Output = Result<HttpReply, Self::Error>> + MaybeSend;

    /// `PUT` `body` to `url` as `application/octet-stream`.
    fn put(
        &self,
        url: &str,
        body: Vec<u8>,
    ) -> impl Future<Output = Result<HttpReply, Self::Error>> + MaybeSend;

    /// `GET` `url`, optionally as an inclusive byte range.
    ///
    /// The whole body is collected, which the deployment's read ceiling
    /// already bounds: the file server refuses a response past the ticket's
    /// ceiling, so no answer here is larger than the deployment permits.
    fn get(
        &self,
        url: &str,
        range: Option<(u64, u64)>,
    ) -> impl Future<Output = Result<HttpReply, Self::Error>> + MaybeSend;
}

/// The native content transport.
#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
#[derive(Debug, Clone, Default)]
pub struct ReqwestHttp {
    client: reqwest::Client,
}

#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
impl ReqwestHttp {
    /// Builds a transport over a fresh client.
    pub fn new() -> Self {
        Self::default()
    }

    /// Builds a transport over a client the application already configured,
    /// so a deployment's proxy, timeout and certificate settings carry over.
    pub fn with_client(client: reqwest::Client) -> Self {
        Self { client }
    }

    /// Collects a reqwest response into a reply.
    async fn reply(response: reqwest::Response) -> Result<HttpReply, reqwest::Error> {
        let status = response.status().as_u16();
        let body = response.bytes().await?;
        Ok(HttpReply {
            status,
            body: body.to_vec(),
        })
    }
}

#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
impl ContentHttp for ReqwestHttp {
    type Error = reqwest::Error;

    async fn post(&self, url: &str, json: Option<Vec<u8>>) -> Result<HttpReply, Self::Error> {
        let mut request = self.client.post(url);
        if let Some(body) = json {
            request = request
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(body);
        }
        Self::reply(request.send().await?).await
    }

    async fn put(&self, url: &str, body: Vec<u8>) -> Result<HttpReply, Self::Error> {
        let response = self
            .client
            .put(url)
            .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
            .body(body)
            .send()
            .await?;
        Self::reply(response).await
    }

    async fn get(&self, url: &str, range: Option<(u64, u64)>) -> Result<HttpReply, Self::Error> {
        let mut request = self.client.get(url);
        if let Some((first, last)) = range {
            request = request.header(reqwest::header::RANGE, format!("bytes={first}-{last}"));
        }
        Self::reply(request.send().await?).await
    }
}

#[cfg(all(target_family = "wasm", target_os = "unknown"))]
mod browser {
    use js_sys::Uint8Array;
    use thiserror::Error;
    use wasm_bindgen::{JsCast, JsValue};
    use wasm_bindgen_futures::JsFuture;
    use web_sys::{
        DedicatedWorkerGlobalScope, DomException, Headers, Request, RequestInit, Response,
    };

    use super::{ContentHttp, HttpReply};

    /// A browser content request failure before a status was received.
    #[derive(Debug, Error)]
    #[error("browser HTTP {operation}: {message}")]
    pub struct BrowserHttpError {
        /// The operation that failed.
        operation: &'static str,
        /// The browser exception text.
        message: String,
    }

    /// Content transport through the current worker's `fetch`.
    #[derive(Clone, Copy, Debug, Default)]
    pub struct BrowserHttp;

    impl BrowserHttp {
        /// Creates a browser content transport.
        #[must_use]
        pub fn new() -> Self {
            Self
        }

        async fn request(
            method: &str,
            url: &str,
            body: Option<(Vec<u8>, &'static str)>,
            range: Option<(u64, u64)>,
        ) -> Result<HttpReply, BrowserHttpError> {
            let init = RequestInit::new();
            init.set_method(method);
            let headers = Headers::new().map_err(|value| error("create headers", value))?;
            let body = body.map(|(bytes, content_type)| {
                headers
                    .set("content-type", content_type)
                    .map_err(|value| error("set content type", value))?;
                Ok::<_, BrowserHttpError>(Uint8Array::from(bytes.as_slice()))
            });
            let body = match body {
                Some(body) => Some(body?),
                None => None,
            };
            if let Some(body) = body.as_ref() {
                init.set_body_opt_u8_array(Some(body));
            }
            if let Some((first, last)) = range {
                headers
                    .set("range", &format!("bytes={first}-{last}"))
                    .map_err(|value| error("set byte range", value))?;
            }
            init.set_headers_headers(&headers);
            let request = Request::new_with_str_and_init(url, &init)
                .map_err(|value| error("create request", value))?;
            let scope: DedicatedWorkerGlobalScope = js_sys::global()
                .dyn_into()
                .map_err(|value: js_sys::Object| error("acquire worker scope", value.into()))?;
            let response = JsFuture::from(scope.fetch_with_request(&request))
                .await
                .map_err(|value| error("fetch", value))?
                .dyn_into::<Response>()
                .map_err(|value| error("decode response", value))?;
            let status = response.status();
            let buffer = JsFuture::from(
                response
                    .array_buffer()
                    .map_err(|value| error("begin response read", value))?,
            )
            .await
            .map_err(|value| error("read response", value))?;
            Ok(HttpReply {
                status,
                body: Uint8Array::new(&buffer).to_vec(),
            })
        }
    }

    impl ContentHttp for BrowserHttp {
        type Error = BrowserHttpError;

        async fn post(&self, url: &str, json: Option<Vec<u8>>) -> Result<HttpReply, Self::Error> {
            Self::request(
                "POST",
                url,
                json.map(|body| (body, "application/json")),
                None,
            )
            .await
        }

        async fn put(&self, url: &str, body: Vec<u8>) -> Result<HttpReply, Self::Error> {
            Self::request("PUT", url, Some((body, "application/octet-stream")), None).await
        }

        async fn get(
            &self,
            url: &str,
            range: Option<(u64, u64)>,
        ) -> Result<HttpReply, Self::Error> {
            Self::request("GET", url, None, range).await
        }
    }

    fn error(operation: &'static str, value: JsValue) -> BrowserHttpError {
        let message = value
            .dyn_ref::<DomException>()
            .map(|exception| format!("{}: {}", exception.name(), exception.message()))
            .or_else(|| value.as_string())
            .unwrap_or_else(|| format!("{value:?}"));
        BrowserHttpError { operation, message }
    }
}

#[cfg(all(target_family = "wasm", target_os = "unknown"))]
pub use browser::{BrowserHttp, BrowserHttpError};
