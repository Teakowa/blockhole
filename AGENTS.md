# Agent and contributor guide

## Project boundaries

Blockhole is a Python CLI run by GitHub Actions. It reads Cloudflare Security
Analytics, keeps canonical lifecycle state in Git, renders a deterministic IP
denylist, and reconciles one Cloudflare Custom IP List.

- Git is the durable source of truth; Cloudflare is a deployment target.
- Do not add Workers, D1, KV, R2, Queues, Workflows, Durable Objects, Pages,
  databases, servers, web UIs, notifications, or threat-intelligence feeds.
- Keep collection, policy, lifecycle, state, rendering, HTTP, and sync logic
  separate and typed.
- Keep automatic enforcement in `dry-run` until the maintainer explicitly
  enables it.

## Safety requirements

- The allowlist always wins and must accept only valid IPv4, IPv6, or CIDR
  entries.
- A single request, URI, user agent, country, ASN, or sampled event must not
  block an IP. Automatic blocking requires independent and repeated signals.
- Preserve observed and weighted counts separately.
- Strip query strings and never persist bodies, cookies, authorization headers,
  arbitrary headers, secrets, or personal data.
- Collection, validation, schema, or synchronization failure must fail loudly
  and must not clear or modify the remote list.
- Never replace a non-empty remote list with an empty list during an ordinary
  scheduled run. Empty replacement requires explicit manual approval.
- Use UTC-aware timestamps, deterministic ordering, atomic state writes, and
  bounded retries with `Retry-After` support.

## Change rules

- Read `README.md`, `docs/detection-policy.md`, and `docs/operations.md`
  before changing behavior.
- Keep policy in `config/policy.toml`; do not scatter thresholds through code
  or workflow YAML.
- State schema changes require a version increment, migration, and migration
  tests.
- Cloudflare tests must use mocks and redacted fixtures; never call production
  APIs by default.
- Do not commit secrets or raw request data.
- Keep changes narrow and update documentation when public behavior changes.

## Required checks

```bash
uv sync --frozen
uv run ruff check .
uv run ruff format --check .
uv run mypy src
uv run pytest
```
