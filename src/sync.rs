use crate::{
    error::{BlockholeError, Result},
    http::request,
    models::{CloudflareItem, DesiredList, Subject},
};
use reqwest::blocking::Client;
use serde::Deserialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    thread::sleep,
    time::{Duration, Instant},
};
#[derive(Debug, Eq, PartialEq)]
pub struct ListDiff {
    pub additions: Vec<CloudflareItem>,
    pub removals: Vec<Subject>,
    pub changes: Vec<CloudflareItem>,
}
impl ListDiff {
    pub fn identical(&self) -> bool {
        self.additions.is_empty() && self.removals.is_empty() && self.changes.is_empty()
    }
}
pub fn diff(desired: &DesiredList, actual: &[CloudflareItem]) -> ListDiff {
    let want: BTreeMap<_, _> = desired.items.iter().map(|i| (i.ip.clone(), i)).collect();
    let have: BTreeMap<_, _> = actual.iter().map(|i| (i.ip.clone(), i)).collect();
    ListDiff {
        additions: want
            .iter()
            .filter(|(k, _)| !have.contains_key(*k))
            .map(|(_, v)| (*v).clone())
            .collect(),
        removals: have
            .keys()
            .filter(|k| !want.contains_key(*k))
            .cloned()
            .collect(),
        changes: want
            .iter()
            .filter(|(k, v)| have.get(*k).is_some_and(|x| x.comment != v.comment))
            .map(|(_, v)| (*v).clone())
            .collect(),
    }
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
    pub fn get_items(&self) -> Result<Vec<CloudflareItem>> {
        let mut items = Vec::new();
        let mut cursor = None;
        let mut seen = BTreeSet::new();
        loop {
            let mut url = format!("{}?per_page=500", self.items_url());
            if let Some(ref c) = cursor {
                url.push_str(&format!("&cursor={c}"));
            }
            let response = request(&self.client, reqwest::Method::GET, &url, self.retries, None)?;
            if !response.status().is_success() {
                return Err(BlockholeError::Cloudflare(format!(
                    "list read HTTP {}",
                    response.status()
                )));
            }
            let payload: ListResponse = response.json()?;
            for item in payload.result {
                items.push(CloudflareItem {
                    ip: Subject::parse(&item.ip)?,
                    comment: item.comment,
                });
            }
            let next = payload
                .result_info
                .and_then(|i| i.cursors)
                .and_then(|c| c.after);
            match next {
                None => return Ok(items),
                Some(c) if !seen.insert(c.clone()) => {
                    return Err(BlockholeError::Cloudflare(
                        "list response pagination cursor repeated".into(),
                    ));
                }
                Some(c) => cursor = Some(c),
            }
        }
    }
    pub fn replace(
        &self,
        desired: &DesiredList,
        actual_count: usize,
        allow_empty: bool,
    ) -> Result<()> {
        if actual_count > 0 && desired.items.is_empty() && !allow_empty {
            return Err(BlockholeError::Safety(
                "refusing to replace a non-empty remote list with an empty list".into(),
            ));
        }
        let body = serde_json::to_value(&desired.items)?;
        let response = request(
            &self.client,
            reqwest::Method::PUT,
            &self.items_url(),
            self.retries,
            Some(body),
        )?;
        if !response.status().is_success() {
            return Err(BlockholeError::Cloudflare(format!(
                "list write HTTP {}",
                response.status()
            )));
        }
        let operation: OperationResponse = response.json()?;
        if let Some(id) = operation.result.and_then(|r| r.operation_id) {
            self.wait(&id)?;
        }
        let deadline = Instant::now() + Duration::from_secs_f64(self.poll_timeout);
        loop {
            if diff(desired, &self.get_items()?).identical() {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(BlockholeError::Cloudflare(
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
                return Err(BlockholeError::Cloudflare(format!(
                    "operation poll HTTP {}",
                    response.status()
                )));
            }
            let payload: OperationResponse = response.json()?;
            match payload.result.and_then(|r| r.status) {
                Some(status)
                    if ["completed", "success", "succeeded"].contains(&status.as_str()) =>
                {
                    return Ok(());
                }
                Some(status) if ["failed", "error"].contains(&status.as_str()) => {
                    return Err(BlockholeError::Cloudflare(format!(
                        "Cloudflare operation failed: {status}"
                    )));
                }
                _ => {}
            }
            if Instant::now() >= deadline {
                return Err(BlockholeError::Cloudflare(
                    "Cloudflare operation polling timed out".into(),
                ));
            }
            sleep(Duration::from_secs_f64(self.poll_interval));
        }
    }
}
