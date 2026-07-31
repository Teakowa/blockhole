use blockhole_core::error::{BlockholeError, Result};
use reqwest::blocking::{Client, Response};
use std::thread::sleep;
use std::time::Duration;

pub fn plugin_error(error: reqwest::Error) -> BlockholeError {
    BlockholeError::Plugin(format!("Cloudflare request failed: {error}"))
}

pub fn request(
    client: &Client,
    method: reqwest::Method,
    url: &str,
    retries: usize,
    body: Option<serde_json::Value>,
) -> Result<Response> {
    for attempt in 0..=retries {
        let mut request = client.request(method.clone(), url);
        if let Some(ref json) = body {
            request = request.json(json);
        }
        match request.send() {
            Ok(response)
                if !matches!(
                    response.status().as_u16(),
                    408 | 429 | 500 | 502 | 503 | 504
                ) || attempt == retries =>
            {
                return Ok(response);
            }
            Ok(response) => {
                let delay = response
                    .headers()
                    .get("Retry-After")
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| value.parse::<f64>().ok())
                    .unwrap_or(2_f64.powi(attempt as i32));
                sleep(Duration::from_secs_f64(delay.max(0.0)));
            }
            Err(error) if attempt == retries => return Err(plugin_error(error)),
            Err(_) => sleep(Duration::from_secs_f64(2_f64.powi(attempt as i32))),
        }
    }
    Err(BlockholeError::Plugin(
        "Cloudflare retry loop ended unexpectedly".into(),
    ))
}
