use blockhole_core::{
    config::{RunMode, Settings, Thresholds, Weights},
    models::{Observation, RecordStatus, Subject},
    policy, state, sync,
};
use chrono::{Duration, TimeZone, Utc};
use proptest::prelude::*;
use regex::RegexSet;
use std::path::PathBuf;
fn settings() -> Settings {
    Settings {
        platform: "cloudflare".into(),
        mode: RunMode::DryRun,
        lookback_hours: 24,
        overlap_hours: 2,
        block_ttl_hours: 72,
        cooldown_hours: 24,
        max_ttl_extensions: 3,
        score_decay_per_day: 0.25,
        thresholds: Thresholds {
            min_weighted_requests: 100.0,
            min_distinct_paths: 2,
            min_suspicious_paths: 2,
            max_error_ratio: 0.8,
            block_score: 6.0,
        },
        weights: Weights {
            request_volume: 1.0,
            path_breadth: 0.0,
            suspicious_paths: 4.0,
            high_error_ratio: 1.0,
            repeated_windows: 1.0,
            multiple_sources: 0.0,
        },
        suspicious_path_patterns: vec![r"^/scan/".into()],
        suspicious_path_set: RegexSet::new([r"^/scan/"]).unwrap(),
    }
}

#[test]
fn policy_config_selects_cloudflare_plugin() {
    let settings = blockhole_core::config::load(std::path::Path::new(".")).unwrap();
    assert_eq!(settings.platform, "cloudflare");
}

/// Helper: create a blocking observation (crosses all thresholds).
fn blocking_obs(now: chrono::DateTime<chrono::Utc>) -> Observation {
    Observation {
        ip: Subject::parse("192.0.2.1").unwrap(),
        source_id: "zone".into(),
        observed_at: now,
        observed_requests: 200,
        weighted_requests: 200.0,
        paths: vec!["/scan/a".into(), "/scan/b".into()],
        suspicious_paths: 0,
        error_requests: 180,
        sampled: false,
        sample_interval: None,
        fingerprint: "x".into(),
    }
}

#[test]
fn ip_and_cidr_are_canonical_and_allowlist_is_family_safe() {
    let ip = Subject::parse(" 192.0.2.1 ").unwrap();
    assert_eq!(ip.to_string(), "192.0.2.1/32");
    let network = Subject::parse("192.0.2.0/24").unwrap();
    assert!(network.contains(&ip));
    assert!(!network.contains(&Subject::parse("2001:db8::1").unwrap()));
}
#[test]
fn two_signals_and_scanning_block() {
    let now = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
    let obs = blocking_obs(now);
    let record = crate::lifecycle::transition(None, &[obs], &settings(), now, false).unwrap();
    assert!(matches!(
        record.status,
        RecordStatus::TemporaryBlocked { .. }
    ));
}

#[test]
fn evaluation_result_contains_platform_neutral_block_decision() {
    let now = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
    let subject = Subject::parse("192.0.2.1").unwrap();
    let result = crate::lifecycle::evaluate(
        &subject,
        None,
        &[blocking_obs(now)],
        &settings(),
        now,
        false,
    )
    .unwrap();

    assert_eq!(result.subject, subject);
    assert!(matches!(
        result.decision,
        crate::models::BlockDecision::Temporary { .. }
    ));
}

#[test]
fn policy_computes_suspicious_paths_from_paths() {
    let now = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
    let mut observations = vec![blocking_obs(now)];

    policy::annotate_suspicious_paths(&mut observations, &settings().suspicious_path_set);

    assert_eq!(observations[0].suspicious_paths, 2);
}

#[test]
fn duplicate_fingerprints_count_once() {
    let now = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
    let observation = blocking_obs(now);
    let signals =
        policy::score_signals(&[observation.clone(), observation], None, &settings(), now).unwrap();

    assert_eq!(signals.observed_requests, 200);
    assert_eq!(signals.weighted_requests, 200.0);
    assert_eq!(signals.suspicious_paths, 2);
    assert_eq!(signals.observation_windows, 1);
}

#[test]
fn multiple_source_reason_is_platform_neutral() {
    let now = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
    let first = blocking_obs(now);
    let mut second = blocking_obs(now);
    second.source_id = "source-b".into();
    second.fingerprint = "source-b-observation".into();

    let signals = policy::score_signals(&[first, second], None, &settings(), now).unwrap();

    assert!(signals.reason_codes.contains(&"multiple_sources".into()));
    assert!(!signals.reason_codes.contains(&"multiple_zones".into()));
}

#[test]
fn qualifying_observations_extend_temporary_block_until_cap() {
    let t0 = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
    let t1 = t0 + Duration::hours(1);
    let t2 = t1 + Duration::hours(1);
    let mut s = settings();
    s.block_ttl_hours = 72;
    s.max_ttl_extensions = 1;

    let initial = crate::lifecycle::transition(None, &[blocking_obs(t0)], &s, t0, false).unwrap();
    let extended =
        crate::lifecycle::transition(Some(&initial), &[blocking_obs(t1)], &s, t1, false).unwrap();
    let capped =
        crate::lifecycle::transition(Some(&extended), &[blocking_obs(t2)], &s, t2, false).unwrap();

    let (initial_expires, extended_expires, capped_expires) =
        match (initial.status, extended.status, capped.status) {
            (
                RecordStatus::TemporaryBlocked {
                    expires_at: initial_expires,
                    ..
                },
                RecordStatus::TemporaryBlocked {
                    expires_at: extended_expires,
                    ttl_extensions: 1,
                    ..
                },
                RecordStatus::TemporaryBlocked {
                    expires_at: capped_expires,
                    ttl_extensions: 1,
                    ..
                },
            ) => (initial_expires, extended_expires, capped_expires),
            statuses => panic!("unexpected statuses: {statuses:?}"),
        };

    assert_eq!(extended_expires, initial_expires + Duration::hours(72));
    assert_eq!(capped_expires, extended_expires);
}

#[test]
fn one_scanning_path_stays_candidate() {
    let now = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
    let obs = Observation {
        ip: Subject::parse("192.0.2.1").unwrap(),
        source_id: "zone".into(),
        observed_at: now,
        observed_requests: 300,
        weighted_requests: 300.0,
        paths: vec!["/scan/a".into(), "/normal".into()],
        suspicious_paths: 0,
        error_requests: 270,
        sampled: false,
        sample_interval: None,
        fingerprint: "x".into(),
    };
    let record = crate::lifecycle::transition(None, &[obs], &settings(), now, false).unwrap();
    assert!(matches!(record.status, RecordStatus::Candidate));
}
proptest! { #[test] fn canonicalization_is_idempotent(value in "[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}") { if let Ok(first) = Subject::parse(&value) { let second = Subject::parse(&first.to_string()).unwrap(); prop_assert_eq!(first, second); } } }

#[test]
fn permanent_import_is_not_released_and_allowlist_can_suppress_it() {
    let now = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
    let subject = Subject::parse("192.0.2.1").unwrap();
    let allowlist_net = Subject::parse("192.0.2.0/24").unwrap();
    let mut current = state::empty();
    policy::merge_permanent(&mut current, std::slice::from_ref(&subject), now);

    // Initially not suppressed
    let record = current.records.get(&subject).unwrap();
    let is_allowlisted = policy::is_allowlisted(&subject, std::slice::from_ref(&allowlist_net));
    assert!(is_allowlisted);

    let record =
        crate::lifecycle::transition(Some(record), &[], &settings(), now, is_allowlisted).unwrap();

    // Should remain PermanentBlocked but with suppressed_by_allowlist = true
    if let RecordStatus::PermanentBlocked {
        suppressed_by_allowlist,
        ..
    } = record.status
    {
        assert!(suppressed_by_allowlist);
    } else {
        panic!("expected PermanentBlocked status");
    }

    // Active list should exclude suppressed permanent block
    current.records.insert(subject.clone(), record);
    let active_records = crate::lifecycle::active(&current.records, now);
    assert!(!active_records.contains_key(&subject));

    // When allowlist entry is removed
    let record = current.records.get(&subject).unwrap();
    let record = crate::lifecycle::transition(Some(record), &[], &settings(), now, false).unwrap();
    if let RecordStatus::PermanentBlocked {
        suppressed_by_allowlist,
        ..
    } = record.status
    {
        assert!(!suppressed_by_allowlist);
    } else {
        panic!("expected PermanentBlocked status");
    }

    // Active list should now include restored permanent block
    current.records.insert(subject.clone(), record);
    let active_records = crate::lifecycle::active(&current.records, now);
    assert!(active_records.contains_key(&subject));
}

#[test]
fn allowlist_suppresses_decision_without_erasing_lifecycle_status() {
    let now = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
    let subject = Subject::parse("192.0.2.1").unwrap();
    let record =
        crate::lifecycle::transition(None, &[blocking_obs(now)], &settings(), now, true).unwrap();
    assert!(matches!(
        record.status,
        RecordStatus::TemporaryBlocked { .. }
    ));

    let mut state = state::empty();
    state.records.insert(subject, record);
    let allowlist = vec![Subject::parse("192.0.2.0/24").unwrap()];

    let suppressed =
        crate::render::render_desired_list(&crate::render::evaluate_state(&state, now, &allowlist));
    let active =
        crate::render::render_desired_list(&crate::render::evaluate_state(&state, now, &[]));

    assert!(suppressed.items.is_empty());
    assert_eq!(active.items.len(), 1);
}

#[test]
fn v1_v2_and_v3_state_migrate_to_v4_status() {
    let path_v1 =
        std::env::temp_dir().join(format!("blockhole-state-v1-{}.json", std::process::id()));
    let json_v1 = r#"{"schema_version":1,"checkpoints":{},"records":{"192.0.2.1":{"first_seen":"2026-01-01T00:00:00Z","last_seen":"2026-01-01T00:00:00Z","last_evaluated":"2026-01-01T00:00:00Z","observed_requests":1,"weighted_requests":1.0,"distinct_paths":1,"suspicious_paths":0,"error_requests":0,"observation_windows":1,"source_zones":[],"score":0,"status":"blocked","reason_codes":[],"block_started_at":"2026-01-01T00:00:00Z","expires_at":"2026-01-02T00:00:00Z","ttl_extensions":0}}}"#;
    std::fs::write(&path_v1, json_v1).unwrap();
    let migrated_v1 = state::load(&path_v1).unwrap();
    std::fs::remove_file(path_v1).unwrap();
    assert_eq!(migrated_v1.schema_version, 4);
    assert_eq!(
        migrated_v1.records[&Subject::parse("192.0.2.1").unwrap()].schema_version,
        4
    );
    assert!(matches!(
        migrated_v1.records[&Subject::parse("192.0.2.1").unwrap()].status,
        RecordStatus::TemporaryBlocked { .. }
    ));

    let path_v2 =
        std::env::temp_dir().join(format!("blockhole-state-v2-{}.json", std::process::id()));
    let json_v2 = r#"{"schema_version":2,"checkpoints":{},"records":{"192.0.2.1":{"schema_version":2,"first_seen":"2026-01-01T00:00:00Z","last_seen":"2026-01-01T00:00:00Z","last_evaluated":"2026-01-01T00:00:00Z","observed_requests":0,"weighted_requests":0.0,"distinct_paths":0,"suspicious_paths":0,"error_requests":0,"observation_windows":0,"source_zones":[],"score":0.0,"reason_codes":["manual_import"],"status":{"type":"permanent_blocked","imported_at":"2026-01-01T00:00:00Z","source":"config/permanent-blocklist.txt","reason":null}}}}"#;
    std::fs::write(&path_v2, json_v2).unwrap();
    let migrated_v2 = state::load(&path_v2).unwrap();
    std::fs::remove_file(path_v2).unwrap();
    assert_eq!(migrated_v2.schema_version, 4);
    let record_v2 = &migrated_v2.records[&Subject::parse("192.0.2.1").unwrap()];
    assert_eq!(record_v2.schema_version, 4);
    if let RecordStatus::PermanentBlocked {
        suppressed_by_allowlist,
        ..
    } = record_v2.status
    {
        assert!(!suppressed_by_allowlist);
    } else {
        panic!("expected PermanentBlocked status");
    }

    let path_v3 =
        std::env::temp_dir().join(format!("blockhole-state-v3-{}.json", std::process::id()));
    let json_v3 = r#"{"schema_version":3,"checkpoints":{},"records":{"192.0.2.1":{"schema_version":3,"first_seen":"2026-01-01T00:00:00Z","last_seen":"2026-01-01T00:00:00Z","last_evaluated":"2026-01-01T00:00:00Z","observed_requests":0,"weighted_requests":0.0,"distinct_paths":0,"suspicious_paths":0,"error_requests":0,"observation_windows":0,"source_zones":["legacy-source"],"score":0.0,"reason_codes":[],"status":{"type":"candidate"}}}}"#;
    std::fs::write(&path_v3, json_v3).unwrap();
    let migrated_v3 = state::load(&path_v3).unwrap();
    std::fs::remove_file(path_v3).unwrap();
    assert_eq!(migrated_v3.schema_version, 4);
    assert_eq!(
        migrated_v3.records[&Subject::parse("192.0.2.1").unwrap()].schema_version,
        4
    );
    assert_eq!(
        migrated_v3.records[&Subject::parse("192.0.2.1").unwrap()].sources,
        vec!["legacy-source"]
    );
    let serialized = serde_json::to_value(&migrated_v3).unwrap();
    assert!(
        serialized["records"]["192.0.2.1/32"]
            .get("sources")
            .is_some()
    );
    assert!(
        serialized["records"]["192.0.2.1/32"]
            .get("source_zones")
            .is_none()
    );
}

#[test]
fn list_diff_is_deterministic() {
    let desired = blockhole_core::models::DesiredList {
        items: vec![blockhole_core::models::BlockTarget {
            subject: Subject::parse("192.0.2.1").unwrap(),
            comment: "new".into(),
        }],
    };
    let actual = vec![blockhole_core::models::BlockTarget {
        subject: Subject::parse("192.0.2.2").unwrap(),
        comment: "old".into(),
    }];
    let result = sync::diff(&desired, &actual);
    assert_eq!(
        result.additions[0].subject,
        Subject::parse("192.0.2.1").unwrap()
    );
    assert_eq!(result.removals, vec![Subject::parse("192.0.2.2").unwrap()]);
}

proptest! {
    #[test]
    fn diff_against_self_is_identical(
        comments in prop::collection::vec("[a-z0-9]{1,10}", 0..20)
    ) {
        let items: Vec<blockhole_core::models::BlockTarget> = comments
            .into_iter()
            .enumerate()
            .map(|(idx, comment)| blockhole_core::models::BlockTarget {
                subject: Subject::parse(&format!("192.0.2.{}", (idx % 250) + 1)).unwrap(),
                comment,
            })
            .collect();
        let desired = blockhole_core::models::DesiredList { items: items.clone() };
        let result = sync::diff(&desired, &items);
        prop_assert!(result.identical());
    }
}

#[test]
fn render_writes_report_to_custom_path() {
    let temp = std::env::temp_dir().join(format!("blockhole-render-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&temp);
    std::fs::create_dir_all(&temp).unwrap();
    let state = state::empty();
    let report_path = PathBuf::from("custom/report.md");
    let now = Utc::now();
    let desired =
        crate::render::render_desired_list(&crate::render::evaluate_state(&state, now, &[]));
    let res = crate::output::write_render_outputs(&temp, &desired, now, &report_path);
    assert!(res.is_ok());
    assert!(temp.join("custom/report.md").exists());
    let _ = std::fs::remove_dir_all(&temp);
}

#[test]
fn render_formats_cloudflare_comments_correctly() {
    let temp = std::env::temp_dir().join(format!(
        "blockhole-render-comment-test-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&temp);
    std::fs::create_dir_all(&temp).unwrap();
    let now = Utc.with_ymd_and_hms(2026, 7, 20, 0, 0, 0).unwrap();
    let mut state = state::empty();

    let perm_ip = Subject::parse("192.0.2.10").unwrap();
    state.records.insert(
        perm_ip.clone(),
        crate::models::IpRecord {
            schema_version: crate::state::CURRENT_SCHEMA,
            first_seen: now,
            last_seen: now,
            last_evaluated: now,
            observed_requests: 0,
            weighted_requests: 0.0,
            distinct_paths: 0,
            suspicious_paths: 0,
            error_requests: 0,
            observation_windows: 0,
            sources: vec![],
            score: 0.0,
            reason_codes: vec!["manual_import".into()],
            status: RecordStatus::PermanentBlocked {
                imported_at: now,
                source: "config/permanent-blocklist.txt".into(),
                reason: None,
                suppressed_by_allowlist: false,
            },
        },
    );

    let temp_ip = Subject::parse("192.0.2.20").unwrap();
    let expires = Utc.with_ymd_and_hms(2026, 7, 22, 0, 0, 0).unwrap();
    state.records.insert(
        temp_ip.clone(),
        crate::models::IpRecord {
            schema_version: crate::state::CURRENT_SCHEMA,
            first_seen: now,
            last_seen: now,
            last_evaluated: now,
            observed_requests: 100,
            weighted_requests: 100.0,
            distinct_paths: 2,
            suspicious_paths: 2,
            error_requests: 90,
            observation_windows: 1,
            sources: vec!["zone".into()],
            score: 6.0,
            reason_codes: vec!["high_error_ratio".into(), "suspicious_paths".into()],
            status: RecordStatus::TemporaryBlocked {
                started_at: now,
                expires_at: expires,
                ttl_extensions: 0,
            },
        },
    );

    let desired =
        crate::render::render_desired_list(&crate::render::evaluate_state(&state, now, &[]));
    crate::output::write_render_outputs(
        &temp,
        &desired,
        now,
        PathBuf::from("reports/latest.md").as_path(),
    )
    .unwrap();

    let perm_item = desired.items.iter().find(|i| i.subject == perm_ip).unwrap();
    assert_eq!(perm_item.comment, "blockhole:permanent:manual");

    let temp_item = desired.items.iter().find(|i| i.subject == temp_ip).unwrap();
    assert_eq!(
        temp_item.comment,
        "blockhole:auto:high_error_ratio+suspicious_paths:expires=2026-07-22"
    );

    let _ = std::fs::remove_dir_all(&temp);
}

// ---------------------------------------------------------------------------
// Decay regression tests
// ---------------------------------------------------------------------------

#[test]
fn decay_advances_last_evaluated() {
    let t0 = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
    let t1 = t0 + Duration::days(1);
    let s = settings();
    let record = crate::lifecycle::transition(None, &[blocking_obs(t0)], &s, t0, false).unwrap();
    assert_eq!(record.last_evaluated, t0);

    // Decay without new observations.
    let decayed = crate::lifecycle::transition(Some(&record), &[], &s, t1, false).unwrap();
    assert_eq!(decayed.last_evaluated, t1);

    let expected = (record.score - 1.0 * s.score_decay_per_day).max(0.0);
    let expected = (expected * 10_000.0).round() / 10_000.0;
    assert_eq!(decayed.score, expected);
}

#[test]
fn decay_is_idempotent_at_same_time() {
    let t0 = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
    let t1 = t0 + Duration::days(1);
    let s = settings();
    let record = crate::lifecycle::transition(None, &[blocking_obs(t0)], &s, t0, false).unwrap();

    let first = crate::lifecycle::transition(Some(&record), &[], &s, t1, false).unwrap();
    let second = crate::lifecycle::transition(Some(&first), &[], &s, t1, false).unwrap();

    assert_eq!(first.score, second.score);
    assert_eq!(first.last_evaluated, second.last_evaluated);
}

#[test]
fn decay_is_additive_not_cumulative() {
    let t0 = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
    let t1 = t0 + Duration::days(1);
    let t2 = t0 + Duration::days(2);
    let s = settings();
    let record = crate::lifecycle::transition(None, &[blocking_obs(t0)], &s, t0, false).unwrap();

    let after_1 = crate::lifecycle::transition(Some(&record), &[], &s, t1, false).unwrap();
    let after_2 = crate::lifecycle::transition(Some(&after_1), &[], &s, t2, false).unwrap();

    // Total decay must be exactly 2 days × rate, not 3 (= 1 + 2).
    let expected = (record.score - 2.0 * s.score_decay_per_day).max(0.0);
    let expected = (expected * 10_000.0).round() / 10_000.0;
    assert_eq!(after_2.score, expected);
}

#[test]
fn observations_do_not_suppress_decay() {
    let t0 = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
    let t1 = t0 + Duration::days(1);
    let s = settings();
    let record = crate::lifecycle::transition(None, &[blocking_obs(t0)], &s, t0, false).unwrap();

    // At t1, provide a small new observation (doesn't change which signals fire
    // except repeated_windows kicks in, raising the raw score from 6.0 to 7.0).
    let obs2 = Observation {
        ip: Subject::parse("192.0.2.1").unwrap(),
        source_id: "zone".into(),
        observed_at: t1,
        observed_requests: 1,
        weighted_requests: 1.0,
        paths: vec!["/c".into()],
        suspicious_paths: 0,
        error_requests: 0,
        sampled: false,
        sample_interval: None,
        fingerprint: "y".into(),
    };
    let with_obs = crate::lifecycle::transition(Some(&record), &[obs2], &s, t1, false).unwrap();

    // Raw score with new obs = 7.0 (repeated_windows now satisfied).
    // Decay: 1 day × 0.25 = 0.25 → expected score = 6.75.
    // Without the fix, decay would be zero (old bug) and score would be 7.0.
    assert!(
        with_obs.score < 7.0,
        "decay must apply even with new observations (got {})",
        with_obs.score
    );
    assert_eq!(with_obs.score, 6.75);
}
