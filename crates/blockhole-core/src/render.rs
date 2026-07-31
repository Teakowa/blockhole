use crate::models::{BlockDecision, BlockTarget, DesiredList, EvaluationResult, State};
use chrono::{DateTime, Utc};

pub fn evaluate_state(state: &State, now: DateTime<Utc>) -> Vec<EvaluationResult> {
    state
        .records
        .iter()
        .map(|(subject, record)| {
            EvaluationResult::from_record(subject.clone(), record.clone(), now)
        })
        .collect()
}

pub fn render_desired_list(results: &[EvaluationResult]) -> DesiredList {
    let mut items = results
        .iter()
        .filter_map(|result| {
            let comment = match &result.decision {
                BlockDecision::Permanent => "blockhole:permanent:manual".to_string(),
                BlockDecision::Temporary { expires_at } => format!(
                    "blockhole:auto:{}:expires={}",
                    result.record.reason_codes.join("+"),
                    expires_at.format("%Y-%m-%d")
                ),
                BlockDecision::Allow => return None,
            };
            Some(BlockTarget {
                subject: result.subject.clone(),
                comment,
            })
        })
        .collect::<Vec<_>>();
    items.sort_by(|a, b| a.subject.cmp(&b.subject));
    DesiredList { items }
}
