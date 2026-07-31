use crate::http::{plugin_error, request};
use blockhole_core::{
    error::{BlockholeError, Result},
    models::{BlockTarget, DesiredList, Subject},
    sync::BlockBackend,
};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    thread::sleep,
    time::{Duration, Instant},
};

#[derive(Serialize)]
struct CloudflareItem {
    ip: Subject,
    comment: String,
}
#[derive(Deserialize)]
struct ListResponse {
    result: Vec<ListRaw>,
    result_info: Option<ResultInfo>,
}
#[derive(Deserialize)]
struct ListRaw {
    ip: String,
    #[serde(default)]
    comment: String,
}
#[derive(Deserialize)]
struct ResultInfo {
    cursors: Option<Cursors>,
}
#[derive(Deserialize)]
struct Cursors {
    after: Option<String>,
}
#[derive(Deserialize)]
struct OperationResponse {
    result: Option<Operation>,
}
#[derive(Deserialize)]
struct Operation {
    operation_id: Option<String>,
    status: Option<String>,
}

pub struct ListsClient {
    client: Client,
    base: String,
    account: String,
    list: String,
    retries: usize,
    poll_interval: f64,
    poll_timeout: f64,
}

impl ListsClient {
    pub fn new(
        client: Client,
        base: &str,
        account: &str,
        list: &str,
        retries: usize,
        poll_interval: f64,
        poll_timeout: f64,
    ) -> Self {
        Self {
            client,
            base: base.trim_end_matches('/').into(),
            account: account.into(),
            list: list.into(),
            retries,
            poll_interval,
            poll_timeout,
        }
    }

    fn items_url(&self) -> String {
        format!(
            "{}/accounts/{}/rules/lists/{}/items",
            self.base, self.account, self.list
        )
    }

    fn current_items(&self) -> Result<Vec<BlockTarget>> {
        let mut items = Vec::new();
        let mut cursor = None;
        let mut seen = BTreeSet::new();
        loop {
            let mut url = format!("{}?per_page=500", self.items_url());
            if let Some(ref cursor) = cursor {
                url.push_str(&format!("&cursor={cursor}"));
            }
            let response = request(&self.client, reqwest::Method::GET, &url, self.retries, None)?;
            if !response.status().is_success() {
                return Err(BlockholeError::Plugin(format!(
                    "list read HTTP {}",
                    response.status()
                )));
            }
            let payload: ListResponse = response.json().map_err(plugin_error)?;
            for item in payload.result {
                items.push(BlockTarget {
                    subject: Subject::parse(&item.ip)?,
                    comment: item.comment,
                });
            }
            let next = payload
                .result_info
                .and_then(|info| info.cursors)
                .and_then(|cursors| cursors.after);
            match next {
                None => return Ok(items),
                Some(cursor) if !seen.insert(cursor.clone()) => {
                    return Err(BlockholeError::Plugin(
                        "list response pagination cursor repeated".into(),
                    ));
                }
                Some(next_cursor) => cursor = Some(next_cursor),
            }
        }
    }

    fn replace_remote(&self, desired: &DesiredList) -> Result<()> {
        let body: Vec<CloudflareItem> = desired
            .items
            .iter()
            .map(|item| CloudflareItem {
                ip: item.subject.clone(),
                comment: item.comment.clone(),
            })
            .collect();
        let response = request(
            &self.client,
            reqwest::Method::PUT,
            &self.items_url(),
            self.retries,
            Some(serde_json::to_value(body)?),
        )?;
        if !response.status().is_success() {
            return Err(BlockholeError::Plugin(format!(
                "list write HTTP {}",
                response.status()
            )));
        }
        let operation: OperationResponse = response.json().map_err(plugin_error)?;
        if let Some(id) = operation.result.and_then(|result| result.operation_id) {
            self.wait(&id)?;
        }
        let deadline = Instant::now() + Duration::from_secs_f64(self.poll_timeout);
        loop {
            if blockhole_core::sync::diff(desired, &self.current_items()?).identical() {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(BlockholeError::Plugin(
                    "remote list verification mismatch".into(),
                ));
            }
            sleep(Duration::from_secs_f64(self.poll_interval));
        }
    }

    fn wait(&self, id: &str) -> Result<()> {
        let url = format!(
            "{}/accounts/{}/rules/lists/bulk_operations/{id}",
            self.base, self.account
        );
        let deadline = Instant::now() + Duration::from_secs_f64(self.poll_timeout);
        loop {
            let response = request(&self.client, reqwest::Method::GET, &url, self.retries, None)?;
            if !response.status().is_success() {
                return Err(BlockholeError::Plugin(format!(
                    "operation poll HTTP {}",
                    response.status()
                )));
            }
            let payload: OperationResponse = response.json().map_err(plugin_error)?;
            match payload.result.and_then(|result| result.status) {
                Some(status)
                    if ["completed", "success", "succeeded"].contains(&status.as_str()) =>
                {
                    return Ok(());
                }
                Some(status) if ["failed", "error"].contains(&status.as_str()) => {
                    return Err(BlockholeError::Plugin(format!(
                        "Cloudflare operation failed: {status}"
                    )));
                }
                _ => {}
            }
            if Instant::now() >= deadline {
                return Err(BlockholeError::Plugin(
                    "Cloudflare operation polling timed out".into(),
                ));
            }
            sleep(Duration::from_secs_f64(self.poll_interval));
        }
    }
}

impl BlockBackend for ListsClient {
    fn current(&self) -> Result<Vec<BlockTarget>> {
        self.current_items()
    }

    fn replace(&self, desired: &DesiredList) -> Result<()> {
        self.replace_remote(desired)
    }
}
