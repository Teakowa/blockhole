use crate::{
    analytics,
    config::{RunMode, Settings, Thresholds, Weights},
    models::{Observation, RecordStatus, Subject},
    policy, state, sync,
};
use chrono::{TimeZone, Utc};
use proptest::prelude::*;
use regex::RegexSet;
use std::path::PathBuf;
fn settings() -> Settings {
    Settings {
        root: PathBuf::from("."),
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
            multiple_zones: 0.0,
        },
        suspicious_path_patterns: vec![],
        suspicious_path_set: RegexSet::empty(),
        graphql_url: "".into(),
        api_base_url: "".into(),
        max_retries: 3,
        poll_interval_seconds: 0.0,
        poll_timeout_seconds: 1.0,
        zone_ids: vec!["zone".into()],
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
    let obs = Observation {
        ip: Subject::parse("192.0.2.1").unwrap(),
        zone_id: "zone".into(),
        observed_at: now,
        observed_requests: 200,
        weighted_requests: 200.0,
        paths: vec!["/a".into(), "/b".into()],
        suspicious_paths: 2,
        error_requests: 180,
        sampled: false,
        sample_interval: None,
        fingerprint: "x".into(),
    };
    let record = policy::evaluate(&[obs], None, &settings(), now).unwrap();
    assert!(matches!(
        record.status,
        RecordStatus::TemporaryBlocked { .. }
    ));
}
#[test]
fn one_scanning_path_stays_candidate() {
    let now = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
    let obs = Observation {
        ip: Subject::parse("192.0.2.1").unwrap(),
        zone_id: "zone".into(),
        observed_at: now,
        observed_requests: 300,
        weighted_requests: 300.0,
        paths: vec!["/a".into(), "/b".into()],
        suspicious_paths: 1,
        error_requests: 270,
        sampled: false,
        sample_interval: None,
        fingerprint: "x".into(),
    };
    let record = policy::evaluate(&[obs], None, &settings(), now).unwrap();
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
    let record = current.records.get_mut(&subject).unwrap();
    let is_allowlisted = policy::is_allowlisted(&subject, std::slice::from_ref(&allowlist_net));
    assert!(is_allowlisted);

    crate::lifecycle::apply(record, &settings(), now, is_allowlisted);

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
    let active_records = crate::lifecycle::active(&current.records, now);
    assert!(!active_records.contains_key(&subject));

    // When allowlist entry is removed
    let record = current.records.get_mut(&subject).unwrap();
    crate::lifecycle::apply(record, &settings(), now, false);
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
    let active_records = crate::lifecycle::active(&current.records, now);
    assert!(active_records.contains_key(&subject));
}

#[test]
fn v1_and_v2_state_migrates_to_v3_status() {
    let path_v1 =
        std::env::temp_dir().join(format!("blockhole-state-v1-{}.json", std::process::id()));
    let json_v1 = r#"{"schema_version":1,"checkpoints":{},"records":{"192.0.2.1":{"first_seen":"2026-01-01T00:00:00Z","last_seen":"2026-01-01T00:00:00Z","last_evaluated":"2026-01-01T00:00:00Z","observed_requests":1,"weighted_requests":1.0,"distinct_paths":1,"suspicious_paths":0,"error_requests":0,"observation_windows":1,"source_zones":[],"score":0,"status":"blocked","reason_codes":[],"block_started_at":"2026-01-01T00:00:00Z","expires_at":"2026-01-02T00:00:00Z","ttl_extensions":0}}}"#;
    std::fs::write(&path_v1, json_v1).unwrap();
    let migrated_v1 = state::load(&path_v1).unwrap();
    std::fs::remove_file(path_v1).unwrap();
    assert_eq!(migrated_v1.schema_version, 3);
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
    assert_eq!(migrated_v2.schema_version, 3);
    let record_v2 = &migrated_v2.records[&Subject::parse("192.0.2.1").unwrap()];
    assert_eq!(record_v2.schema_version, 3);
    if let RecordStatus::PermanentBlocked {
        suppressed_by_allowlist,
        ..
    } = record_v2.status
    {
        assert!(!suppressed_by_allowlist);
    } else {
        panic!("expected PermanentBlocked status");
    }
}

#[test]
fn analytics_parser_strips_query_and_preserves_sampling() {
    let payload = r#"{"data":{"viewer":{"zones":[{"series":[{"dimensions":{"clientIP":"192.0.2.1","edgeResponseStatus":404,"clientRequestPath":"/.env?token=redacted"},"avg":{"sampleInterval":1.5},"count":3}]}]}}}"#;
    let now = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
    let pattern_set = RegexSet::new([r"(^|/)\.env($|/)"]).unwrap();
    let observations = analytics::parse(payload, "zone", now, &pattern_set).unwrap();
    assert_eq!(observations[0].paths, vec!["/.env"]);
    assert_eq!(observations[0].weighted_requests, 4.5);
    assert!(observations[0].sampled);
}

#[test]
fn list_diff_is_deterministic() {
    let desired = crate::models::DesiredList {
        items: vec![crate::models::CloudflareItem {
            ip: Subject::parse("192.0.2.1").unwrap(),
            comment: "new".into(),
        }],
    };
    let actual = vec![crate::models::CloudflareItem {
        ip: Subject::parse("192.0.2.2").unwrap(),
        comment: "old".into(),
    }];
    let result = sync::diff(&desired, &actual);
    assert_eq!(result.additions[0].ip, Subject::parse("192.0.2.1").unwrap());
    assert_eq!(result.removals, vec![Subject::parse("192.0.2.2").unwrap()]);
}

#[test]
fn empty_list_fuse_rejects_non_empty_remote_without_request() {
    let client = reqwest::blocking::Client::builder().build().unwrap();
    let lists =
        sync::ListsClient::new(client, "http://127.0.0.1:1", "account", "list", 0, 0.0, 1.0);
    let result = lists.replace(&crate::models::DesiredList { items: vec![] }, 1, false);
    assert!(matches!(
        result,
        Err(crate::error::BlockholeError::Safety(_))
    ));
}

proptest! {
    #[test]
    fn diff_against_self_is_identical(
        comments in prop::collection::vec("[a-z0-9]{1,10}", 0..20)
    ) {
        let items: Vec<crate::models::CloudflareItem> = comments
            .into_iter()
            .enumerate()
            .map(|(idx, comment)| crate::models::CloudflareItem {
                ip: Subject::parse(&format!("192.0.2.{}", (idx % 250) + 1)).unwrap(),
                comment,
            })
            .collect();
        let desired = crate::models::DesiredList { items: items.clone() };
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
    let res = crate::render::render(&temp, &state, Utc::now(), &report_path);
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
            source_zones: vec![],
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
            source_zones: vec!["zone".into()],
            score: 6.0,
            reason_codes: vec!["high_error_ratio".into(), "suspicious_paths".into()],
            status: RecordStatus::TemporaryBlocked {
                started_at: now,
                expires_at: expires,
                ttl_extensions: 0,
            },
        },
    );

    let report_path = PathBuf::from("reports/latest.md");
    let desired = crate::render::render(&temp, &state, now, &report_path).unwrap();

    let perm_item = desired.items.iter().find(|i| i.ip == perm_ip).unwrap();
    assert_eq!(perm_item.comment, "blockhole:permanent:manual");

    let temp_item = desired.items.iter().find(|i| i.ip == temp_ip).unwrap();
    assert_eq!(
        temp_item.comment,
        "blockhole:auto:high_error_ratio+suspicious_paths:expires=2026-07-22"
    );

    let _ = std::fs::remove_dir_all(&temp);
}
