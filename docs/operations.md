# Operations

## GitHub configuration

Configure these repository or environment variables:

- `CLOUDFLARE_ACCOUNT_ID`
- `CLOUDFLARE_ZONE_IDS`
- `CLOUDFLARE_LIST_ID`

Store only `CLOUDFLARE_API_TOKEN` as a secret. Do not expose it to pull
request jobs. The synchronization workflow uses a single concurrency group,
does not cancel an active run, and keeps manual dry-run available.

## First rollout

1. Configure zones and the allowlist.
2. Run CI and `cf-ip-blacklist validate`.
3. Run manual collection in dry-run for several days.
4. Review `reports/latest.md`, candidates, and false positives.
5. Confirm the allowlist and policy thresholds.
6. Perform a manual synchronization before enabling scheduled enforcement.

The first analytics collection uses the configured `lookback_hours` window.
After a successful run, the next collection starts at the saved analytics
checkpoint and ends at the current time. This makes hourly runs collect only
the new interval instead of adding the same rolling 24-hour result repeatedly.

## Empty-list protection

A scheduled or ordinary run cannot replace a non-empty Cloudflare list with an
empty desired list. Collection, validation, schema, and state failures do not
modify Cloudflare. An empty replacement requires manual dispatch with
`allow_empty=true` and successful collection for every configured zone.

## Recovery

If collection or synchronization fails, keep the previous committed state and
inspect the redacted workflow report. Re-run after fixing configuration or API
access. If a remote write succeeds but the Git commit fails, the next run
fetches the remote list and reconciles it idempotently; it does not duplicate
items.
