# Operations

## GitHub configuration

The CLI selects a platform implementation through `platform.name` in
`config/policy.toml`. Supported values are `cloudflare` and `nginx`.

For Cloudflare, configure these repository or environment variables:

- `CLOUDFLARE_ACCOUNT_ID`
- `CLOUDFLARE_ZONE_IDS`
- `CLOUDFLARE_LIST_ID`

Store only `CLOUDFLARE_API_TOKEN` as a secret. Do not expose it to pull
request jobs. The synchronization workflow uses a single concurrency group,
does not cancel an active run, and keeps manual dry-run available.

For Nginx, configure a dedicated managed include file:

```toml
[nginx]
access_log = "/var/log/nginx/access.log"
denylist_path = "/etc/nginx/conf.d/blockhole-deny.conf"
source_id = "nginx"
reload = false
```

The Nginx plugin reads standard combined access-log lines and writes only
`deny` directives to `denylist_path`. Include that file from the applicable
Nginx `server` or `location` block. `reload = true` invokes only
`nginx -s reload`; it does not execute a configurable shell command. The process needs
read permission for the access log and write permission for the include file.
Because this is a local-file plugin, the runner must be the Nginx host or have
the required log and configuration paths mounted into it.

## Rollout

1. Configure zones and the allowlist.
2. Run CI and `blockhole validate`.
3. Use manual dry-run to review `reports/latest.md`, candidates, and false
   positives when validating a policy change.
4. Confirm the allowlist and policy thresholds.
5. Scheduled runs enforce the configured policy by default; set the manual
   `dry_run` input to `true` when a manual run must not write Cloudflare.

The CI workflow builds the Linux `blockhole` release binary and writes it to
the GitHub Actions cache keyed by source hash. When a push to `main` bumps the
version in `Cargo.toml`, the CI release job automatically creates a Git tag and
GitHub Release with the binary attached.

The scheduled Sync workflow obtains the CLI in two tiers: it first attempts to
restore the binary from the Actions cache; if the cache misses it downloads
the asset from the latest GitHub Release. If neither source is available the
workflow fails without modifying state or Cloudflare. Scheduled runs do not
install Rust or compile the CLI.

The first analytics collection uses the configured `lookback_hours` window.
After a successful run, the next collection starts at the saved analytics
checkpoint and ends at the current time. This makes hourly runs collect only
the new interval instead of adding the same rolling 24-hour result repeatedly.

## Runtime state branch

Scheduled synchronization runs from `main`, but loads `data/state.json`,
`dist/`, and `reports/latest.md` from the orphan `blacklist-state` branch.
That branch contains only those runtime files; it does not contain the code,
configuration, or workflows from `main`. After a successful run, only those
runtime files are committed back to `blacklist-state`; `main` remains focused
on code, policy, and workflow changes. The state branch must exist before
enabling the scheduled workflow.

The regular CI workflow does not read the state branch: tests generate their
fixtures in temporary directories and validate the source tree independently.

## Empty-list protection

A scheduled or ordinary run cannot replace a non-empty platform block list with
an empty desired list. Collection, validation, schema, and state failures do
not modify the platform. An empty replacement requires manual dispatch with
`allow_empty=true` and successful collection for every configured source.

## Recovery

If collection or synchronization fails, keep the previous committed state on
`blacklist-state` and inspect the redacted workflow report. Re-run after fixing
configuration or API access. If a remote write succeeds but the Git commit
fails, the next run fetches the remote list and reconciles it idempotently; it
does not duplicate items.
