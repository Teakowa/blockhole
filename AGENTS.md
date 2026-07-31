# Agent and contributor guide

This is the canonical project specification. Agent-specific entry files
(`CLAUDE.md`, `GEMINI.md`) reference this document and add only
agent-specific workflow directives. Update this file first; update an
agent entry file only when the content is specific to that agent's
capabilities or interaction model.

## Project boundaries

Blockhole is a Rust CLI run by GitHub Actions. Its core reads normalized
observations, keeps canonical lifecycle state in Git, renders a deterministic
IP denylist, and delegates collection and enforcement to a platform plugin.
Cloudflare is the default plugin.

- Git is the durable source of truth; Cloudflare is a deployment target.
- Do not add Workers, D1, KV, R2, Queues, Workflows, Durable Objects, Pages,
  databases, servers, web UIs, notifications, or threat-intelligence feeds.
- Keep collection, policy, lifecycle, state, rendering, HTTP, and sync logic
  separate and typed.
- Keep automatic enforcement in `dry-run` until the maintainer explicitly
  enables it.

## Architecture

```text
config/policy.toml ──► blockhole-core
                         config / models / policy / lifecycle
                         state / render / sync / plugin traits
                              ▲                    │
                              │                    ▼
                  platform plugins                generic block target
             Cloudflare / Nginx implementations        │
                              ▲                        ▼
                         blockhole CLI       collect → evaluate → sync
```

### Module responsibilities

| Module/package                    | Responsibility                                      |
|-----------------------------------|-----------------------------------------------------|
| `blockhole-core::config`          | Parse policy and expose typed core configuration    |
| `blockhole-core::models`          | Normalized observations, state, and block targets  |
| `blockhole-core::policy`          | Scoring and threshold evaluation                    |
| `blockhole-core::lifecycle`       | Candidate/block/cooldown/expired transitions       |
| `blockhole-core::state`           | Versioned state I/O, atomic writes, migration      |
| `blockhole-core::render`          | Deterministic generic output and reports           |
| `blockhole-core::sync`            | Generic diff, backend trait, and safety fuse       |
| `blockhole-core::plugin`          | Platform collection and sync contracts              |
| `blockhole-plugin-cloudflare`     | GraphQL, HTTP, authentication, and Custom List API |
| `blockhole-plugin-nginx`          | Access-log collection and managed deny include      |
| `src/main.rs`                     | Plugin selection and CLI orchestration              |

### Runtime data flow

```text
Platform plugin → collect → evaluate (policy + lifecycle) → state.json
state.json → render → dist/blacklist.txt + dist/desired-blocks.json
state.json + desired-blocks.json → core reconcile → platform plugin enforcement
```

### Branch model

- `main` — code, configuration, workflows, documentation.
- `blacklist-state` (orphan) — `data/state.json`, `dist/`, `reports/latest.md`.
  CI does not read this branch; tests use temporary fixtures.

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
- Platform plugin tests must use mocks and redacted fixtures; never call
  production APIs by default.
- Do not commit secrets or raw request data.
- Keep changes narrow and update documentation when public behavior changes.

## Development workflow

1. Understand the task — read the relevant docs and source before editing.
2. Make the smallest correct change — one concern per commit.
3. Run all required checks before marking work as done.
4. Update documentation when public behavior or CLI surface changes.
5. Do not introduce new dependencies without explicit maintainer approval.

## Required checks

All three must pass before a change is considered complete:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
```

## Completion standards

- All required checks pass.
- No new warnings from `clippy`.
- Tests cover the changed behavior; new logic has new tests.
- Documentation updated if public behavior, CLI, or configuration changed.
- Commit messages are concise and describe **why**, not just what.
