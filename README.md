# Blockhole

Blockhole maintains a cautious, auditable Cloudflare account-level IP
denylist from suspicious HTTP scanning activity observed in Security
Analytics. It is a batch pipeline: GitHub Actions collects analytics, applies
deterministic policy, commits canonical state and generated artifacts, and
reconciles a Cloudflare Custom IP List.

The policy runs in `enforce` mode by default. Use `--dry-run` when validating a
run without changing the remote list. Scheduled runs execute code from `main`
and read/write runtime state and generated artifacts on the `blacklist-state`
branch.

## Quick start

Requirements: Python 3.13 and [uv](https://docs.astral.sh/uv/).

```bash
uv sync --frozen
uv run cf-ip-blacklist validate
uv run cf-ip-blacklist render
uv run pytest
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

## CLI

```text
cf-ip-blacklist validate
cf-ip-blacklist collect
cf-ip-blacklist evaluate
cf-ip-blacklist render
cf-ip-blacklist sync
cf-ip-blacklist run --dry-run --lookback-hours 24
```

`run` supports `--dry-run`, `--lookback-hours`, `--force-rebuild`,
`--allow-empty`, and `--report-path`.

## Repository data

- `config/policy.toml`: thresholds, lifecycle, API, and rollout settings.
- `config/allowlist.txt`: trusted addresses and networks.
- `data/state.json`: canonical versioned lifecycle state (on `blacklist-state`).
- `dist/blacklist.txt`: generated active IP list (on `blacklist-state`).
- `dist/cloudflare-list.json`: generated Custom List payload (on `blacklist-state`).
- `reports/latest.md`: redacted run report (on `blacklist-state`).

See [detection policy](docs/detection-policy.md) and
[operations](docs/operations.md) for behavior and GitHub Actions setup.

## Security boundary

Blockhole never treats one request or one sampled record as sufficient for a
block. It strips query strings before analysis, preserves only bounded
decision evidence, applies the allowlist first, uses expiring blocks, and has
an empty-list fuse that protects an existing remote list from failed or
partial collection.
