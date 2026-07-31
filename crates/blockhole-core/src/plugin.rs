use crate::{
    config::RunMode,
    error::Result,
    models::{DesiredList, Observation},
    sync::ListDiff,
};
use chrono::{DateTime, Utc};
use regex::RegexSet;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CollectionWindow {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyncOptions {
    pub dry_run: bool,
    pub mode: RunMode,
    pub allow_empty: bool,
}

pub trait PlatformPlugin {
    fn collect(
        &self,
        window: CollectionWindow,
        suspicious_path_set: &RegexSet,
    ) -> Result<Vec<Observation>>;

    fn sync(&self, desired: &DesiredList, options: SyncOptions) -> Result<ListDiff>;
}
