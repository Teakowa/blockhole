use crate::{
    config::RunMode,
    error::BlockholeError,
    models::{BlockTarget, DesiredList, Subject},
    sync::{self, BlockBackend},
};
use std::cell::Cell;

#[test]
fn policy_parser_accepts_text_without_a_project_path() {
    let settings = crate::config::parse(include_str!("../../../config/policy.toml")).unwrap();

    assert_eq!(
        crate::config::parse_platform(include_str!("../../../config/policy.toml")).unwrap(),
        "cloudflare"
    );
    assert_eq!(settings.lookback_hours, 24);
}

#[test]
fn subject_parser_is_pure_and_deterministic() {
    let subjects = crate::policy::parse_subjects(
        "192.0.2.2 # duplicate\n192.0.2.1\n192.0.2.2\n",
        "allowlist.txt",
    )
    .unwrap();

    assert_eq!(
        subjects,
        vec![
            Subject::parse("192.0.2.1").unwrap(),
            Subject::parse("192.0.2.2").unwrap(),
        ]
    );
}

#[test]
fn state_encoding_round_trips_without_a_path() {
    let state = crate::state::empty();
    let encoded = crate::state::encode(&state).unwrap();
    let decoded = crate::state::decode(&encoded).unwrap();

    assert_eq!(decoded.schema_version, crate::state::CURRENT_SCHEMA);
    assert!(decoded.checkpoints.is_empty());
    assert!(decoded.records.is_empty());
}

struct FakeBackend {
    replace_calls: Cell<usize>,
}

impl BlockBackend for FakeBackend {
    fn current(&self) -> crate::error::Result<Vec<BlockTarget>> {
        Ok(vec![BlockTarget {
            subject: Subject::parse("192.0.2.1").unwrap(),
            comment: "existing".into(),
        }])
    }

    fn replace(&self, _desired: &DesiredList) -> crate::error::Result<()> {
        self.replace_calls.set(self.replace_calls.get() + 1);
        Ok(())
    }
}

#[test]
fn reconcile_keeps_empty_remote_list_safe_without_backend_write() {
    let backend = FakeBackend {
        replace_calls: Cell::new(0),
    };
    let result = sync::reconcile(
        &backend,
        &DesiredList { items: vec![] },
        false,
        RunMode::Enforce,
        false,
    );

    assert!(matches!(result, Err(BlockholeError::Safety(_))));
    assert_eq!(backend.replace_calls.get(), 0);
}

#[test]
fn reconcile_dry_run_reports_changes_without_backend_write() {
    let backend = FakeBackend {
        replace_calls: Cell::new(0),
    };
    let desired = DesiredList {
        items: vec![BlockTarget {
            subject: Subject::parse("192.0.2.2").unwrap(),
            comment: "new".into(),
        }],
    };
    let diff = sync::reconcile(&backend, &desired, true, RunMode::Enforce, false).unwrap();

    assert_eq!(diff.additions, desired.items);
    assert_eq!(diff.removals, vec![Subject::parse("192.0.2.1").unwrap()]);
    assert_eq!(backend.replace_calls.get(), 0);
}

#[test]
fn reconcile_enforce_writes_changed_target() {
    let backend = FakeBackend {
        replace_calls: Cell::new(0),
    };
    let desired = DesiredList {
        items: vec![BlockTarget {
            subject: Subject::parse("192.0.2.2").unwrap(),
            comment: "new".into(),
        }],
    };
    sync::reconcile(&backend, &desired, false, RunMode::Enforce, false).unwrap();

    assert_eq!(backend.replace_calls.get(), 1);
}
