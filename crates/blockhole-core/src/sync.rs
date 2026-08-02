use crate::{
    config::RunMode,
    error::{BlockholeError, Result},
    models::{BlockTarget, DesiredList, Subject},
};
use std::collections::BTreeMap;

pub trait BlockBackend {
    fn current(&self) -> Result<Vec<BlockTarget>>;
    fn replace(&self, desired: &DesiredList) -> Result<()>;
}

#[derive(Debug, Eq, PartialEq)]
pub struct ListDiff {
    pub additions: Vec<BlockTarget>,
    pub removals: Vec<Subject>,
    pub changes: Vec<BlockTarget>,
}

impl ListDiff {
    pub fn identical(&self) -> bool {
        self.additions.is_empty() && self.removals.is_empty() && self.changes.is_empty()
    }
}

pub fn diff(desired: &DesiredList, actual: &[BlockTarget]) -> ListDiff {
    let want: BTreeMap<&Subject, &BlockTarget> = desired
        .items
        .iter()
        .map(|item| (&item.subject, item))
        .collect();
    let have: BTreeMap<&Subject, &BlockTarget> =
        actual.iter().map(|item| (&item.subject, item)).collect();
    ListDiff {
        additions: want
            .iter()
            .filter(|(subject, _)| !have.contains_key(*subject))
            .map(|(_, item)| (*item).clone())
            .collect(),
        removals: have
            .keys()
            .filter(|subject| !want.contains_key(*subject))
            .map(|subject| (*subject).clone())
            .collect(),
        changes: want
            .iter()
            .filter(|(subject, item)| {
                have.get(*subject)
                    .is_some_and(|actual| actual.comment != item.comment)
            })
            .map(|(_, item)| (*item).clone())
            .collect(),
    }
}

pub fn reconcile<B: BlockBackend>(
    backend: &B,
    desired: &DesiredList,
    dry_run: bool,
    mode: RunMode,
    allow_empty: bool,
) -> Result<ListDiff> {
    let actual = backend.current()?;
    if !dry_run
        && mode == RunMode::Enforce
        && !allow_empty
        && !actual.is_empty()
        && desired.items.is_empty()
    {
        return Err(BlockholeError::Safety(
            "refusing to replace a non-empty remote list with an empty list".into(),
        ));
    }

    let changes = diff(desired, &actual);
    if !dry_run && mode == RunMode::Enforce && !changes.identical() {
        backend.replace(desired)?;
    }
    Ok(changes)
}
