# Blockhole

Blockhole maintains a cautious, auditable IP denylist from suspicious HTTP
scanning activity. Its reusable core applies deterministic policy and lifecycle
rules; platform plugins collect observations and enforce block targets.
Cloudflare is the default plugin and is used by the CLI in this repository.

The policy runs in `enforce` mode by default. Use `--dry-run` when validating a
run without changing the remote list. Scheduled runs execute code from `main`
and read/write runtime state and generated artifacts on the orphan
`blacklist-state` branch.

## Quick start

Requirements: Rust stable and Cargo.

```bash
cargo run -- validate
cargo run -- render
cargo test --workspace
```

Mandatory repository checks:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
```

Before collection, add zone IDs to `config/policy.toml` and provide:

```text
CLOUDFLARE_API_TOKEN
CLOUDFLARE_ACCOUNT_ID
CLOUDFLARE_LIST_ID
```

The token needs analytics read access for the configured zones and Custom List
read/edit access for the configured account. Never commit it or place it in
configuration files.

## Architecture & Workspaces

Blockhole is organized as a Cargo workspace with decoupled core logic and platform plugins:

```text
crates/
  core/                  Policy evaluation, lifecycle state, rendering, and plugin contracts
plugins/
  blockhole-cloudflare   Cloudflare GraphQL analytics collection & Custom List IP denylist sync
  blockhole-nginx        Nginx combined access log collection & managed deny include generation
  blockhole-plugin-aws-waf AWS WAF JSONL log collection & WAFv2 IPSet sync
src/
  main.rs                CLI binary orchestrating plugin selection and subcommand execution
```

The selected plugin is configured by `platform.name`; supported values are
`cloudflare`, `nginx`, and `aws-waf`.

For Nginx, add an `[nginx]` section with `access_log` and a dedicated
`denylist_path`. The access log must use the standard combined format. Set
`reload = true` only when the process can run the fixed `nginx -s reload`
command; the default only updates the include file atomically.

For AWS WAFv2, add an `[aws_waf]` section with a local JSON Lines WAF log,
region, scope, and an existing IPSet name/ID. Set `address_version` to the
IPSet's `IPV4` or `IPV6` family. The plugin uses the AWS SDK default credential
chain and never accepts credentials from `policy.toml`.

## CLI

```text
blockhole validate
blockhole collect
blockhole evaluate
blockhole render
blockhole sync
blockhole run --dry-run --lookback-hours 24
```

`run` supports `--dry-run`, `--lookback-hours`, `--allow-empty`,
and `--report-path`.

## Repository data

- `config/policy.toml`: platform selection, thresholds, lifecycle, API, and rollout settings.
- `config/allowlist.txt`: trusted addresses and networks.
- `config/permanent-blocklist.txt`: manually managed permanent addresses and networks.
- `data/state.json`: canonical versioned lifecycle state (only on the orphan
  `blacklist-state` branch).
- `dist/blacklist.txt`: generated active IP list (only on the orphan
  `blacklist-state` branch).
- `dist/desired-blocks.json`: generated platform-neutral block targets (only on the
  orphan `blacklist-state` branch).
- `reports/latest.md`: redacted run report (only on the orphan
  `blacklist-state` branch).

See [detection policy](docs/detection-policy.md) and
[operations](docs/operations.md) for behavior and GitHub Actions setup.

## Security boundary

Blockhole never treats one request or one sampled record as sufficient for a
block. It strips query strings before analysis, preserves observation fingerprints across window overlaps to prevent duplicate counting, applies the allowlist first, uses expiring blocks, and has an empty-list fuse that protects an existing remote list from failed or partial collection.
