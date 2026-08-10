# Blockhole: Agent Working Guide

> This is the canonical project instruction file for Codex, Claude Code, and
> Gemini. `CLAUDE.md` and `GEMINI.md` may add agent-specific workflow details,
> but must not duplicate or override the project rules here.

## Repository boundary

Blockhole is a Rust CLI and Cargo workspace. It reads normalized observations,
keeps canonical lifecycle state in Git, renders a deterministic IP denylist,
and delegates collection and enforcement to a platform plugin. Cloudflare is
the default plugin; Nginx and AWS WAFv2 are also supported.

- `main` contains code, configuration, workflows, and documentation.
- `blacklist-state` is an orphan runtime branch containing generated state,
  denylist outputs, and the latest redacted report. Tests use temporary
  fixtures and do not read that branch.
- Git is the durable source of truth; a platform such as Cloudflare is only a
  deployment target.
- Do not add Workers, D1, KV, R2, Queues, Workflows, Durable Objects, Pages,
  databases, servers, web UIs, notifications, or threat-intelligence feeds.
- Before editing, inspect the current branch, worktree, and `git status`; keep
  user-owned or concurrent changes intact.

## Rules and authority

- Root `AGENTS.md` contains rules that apply to every task. Directory- or
  module-specific rules should live in a nested `AGENTS.md` when such a
  boundary becomes necessary.
- `README.md` is the project-facing overview, CLI reference, workspace map,
  and configuration entry point.
- `docs/detection-policy.md` is authoritative for scoring, evidence,
  lifecycle, allowlist, and observation-retention behavior.
- `docs/operations.md` is authoritative for GitHub Actions, provider setup,
  rollout, runtime state, empty-list recovery, and operational recovery.
- `config/policy.toml` is the source of truth for thresholds, lifecycle
  values, platform selection, and rollout mode. Do not scatter policy values
  through Rust or workflow YAML.
- Source code, tests, and workflows are the final authority when documentation
  is stale; update the affected documentation when public behavior changes.

## Current rule index

Read the smallest applicable set of materials before changing behavior:

- For repository orientation, CLI commands, package boundaries, or output
  paths, read `README.md`, `Cargo.toml`, and the relevant `src/` or workspace
  package.
- For detection, scoring, lifecycle transitions, allowlists, or state schema,
  read `docs/detection-policy.md`, `config/policy.toml`, and the relevant
  `crates/blockhole-core/src/` implementation and tests.
- For scheduled runs, secrets, provider setup, runtime state, or recovery,
  read `docs/operations.md`, the relevant `.github/workflows/` file, and the
  selected plugin.
- For Cloudflare, Nginx, or AWS WAFv2 collection and synchronization, read the
  corresponding directory under `plugins/` and its mock/fixture tests. Tests
  must not call production APIs by default.
- For CLI orchestration or generated files, read `src/main.rs`,
  `src/output.rs`, `src/state_io.rs`, and their tests before editing.
- For a state schema change, read the existing migration and test coverage
  first; a schema version increment, migration, and migration tests are
  required.

## Project map and architecture

Keep collection, policy, lifecycle, state, rendering, HTTP, and synchronization
logic separate and typed:

```text
config/policy.toml ──► blockhole-core
                         config / models / policy / lifecycle
                         state / render / sync / plugin traits
                              ▲                    │
                              │                    ▼
                  platform plugins                generic block target
          Cloudflare / Nginx / AWS WAF implementations   │
                              ▲                        ▼
                         blockhole CLI       collect → evaluate → sync
```

| Module/package | Responsibility |
|---|---|
| `blockhole-core::config` | Parse policy and expose typed core configuration |
| `blockhole-core::models` | Normalized observations, lifecycle state, and block targets |
| `blockhole-core::policy` | Scoring and threshold evaluation |
| `blockhole-core::lifecycle` | Candidate, block, cooldown, and expiry transitions |
| `blockhole-core::state` | Versioned state I/O, atomic writes, and migration |
| `blockhole-core::render` | Deterministic generic output and reports |
| `blockhole-core::sync` | Generic diff, backend reconciliation, and safety fuse |
| `blockhole-core::plugin` | Platform collection and synchronization contracts |
| `plugins/blockhole-cloudflare` | Cloudflare GraphQL collection and Custom List synchronization |
| `plugins/blockhole-nginx` | Combined access-log collection and managed deny include |
| `plugins/blockhole-plugin-aws-waf` | WAF JSONL collection and WAFv2 IPSet synchronization |
| `src/main.rs` | Plugin selection and CLI orchestration |

The runtime path is:

```text
platform plugin → collect → evaluate (policy + lifecycle) → data/state.json
data/state.json → render → dist/blacklist.txt + dist/desired-blocks.json
state + desired blocks → core reconcile → platform plugin enforcement
```

The core owns normalized observations, policy, lifecycle, state, rendering,
generic diff/reconciliation, safety fuses, and plugin traits. Plugins own
collection, authentication, provider HTTP behavior, and remote deployment. The
CLI selects the source and deployer and coordinates the workflow.

## Policy and safety invariants

- The allowlist always wins and accepts only valid IPv4, IPv6, or CIDR entries.
- One request, URI, user agent, country, ASN, or sampled event must never block
  an IP. Automatic blocking requires independent and repeated signals.
- Preserve observed counts and weighted counts separately; weighted values are
  estimates, not exact request totals.
- Strip query strings. Never persist request bodies, cookies, authorization
  headers, arbitrary headers, secrets, request IDs, or other unnecessary
  personal data.
- Collection, validation, schema, or synchronization failures must fail loudly
  and must not clear or modify the remote list.
- Never replace a non-empty remote list with an empty desired list during an
  ordinary run. Empty replacement requires explicit manual `allow-empty`
  approval and successful collection for every configured source.
- Use UTC-aware timestamps, deterministic ordering, atomic state writes, and
  bounded retries with `Retry-After` support where applicable.
- `config/policy.toml` currently uses `mode = "enforce"`. Use `--dry-run` for
  validation or review; do not broaden automatic enforcement, change rollout
  defaults, or enable a new platform without explicit maintainer approval.

## General workflow

1. Confirm the user goal, repository boundary, current branch/worktree, and
   workspace status.
2. Read this file and the applicable documents from the rule index. For a
   behavior change, read `README.md`, `docs/detection-policy.md`, and
   `docs/operations.md` before editing.
3. Inspect the actual producer, consumer, persisted state, and tests before
   deciding on a change; do not rely on documentation alone.
4. Make the smallest task-scoped change. Preserve unrelated work, avoid
   destructive Git commands, and do not add speculative dependencies,
   abstractions, compatibility shims, or validation.
5. Update documentation when public behavior, CLI, configuration, workflow,
   or recovery behavior changes.
6. Run checks proportional to the risk, review the complete diff, and report
   verified, unverified, and externally dependent evidence separately.

## Validation and delivery

All three repository checks are required for a completed change:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
```

For changes to the release binary, packaging, or release workflow, also run:

```bash
cargo build --release --locked
```

Use mocked, redacted fixtures for platform plugin tests. Keep local tests,
GitHub CI, remote GitHub state, and production-provider verification distinct;
one does not prove the others. If a check cannot run, state the exact reason
and the smallest useful follow-up check.

## Git and external delivery

- Inspect `git status`, the final diff, and `git diff --check` before staging.
- Stage only files or hunks owned by the current task. Do not include secrets,
  credentials, raw request data, runtime logs, screenshots, or unrelated work.
- For an implementation change, commit the verified task-owned change with a
  concise message that explains why. Do not push, amend, rewrite history,
  merge, publish, or modify remote state unless the user explicitly requests
  it.
- If a task names a GitHub issue, re-check the repository and issue number
  before staging and committing. Use `Fixes` or `Closes` only when the change
  fully resolves the issue; use `Refs` or `Related to` for partial work. A
  local commit alone does not close a remote issue.
- Do not call Cloudflare, AWS, or another production provider from tests or
  local validation unless the user explicitly requests an operational check.

## Absolute safety baseline

- Never commit or write tokens, credentials, authorization files, or secrets
  to a Git-tracked path.
- Never persist raw request data or broaden the data collected beyond the
  normalized observation contract.
- Never delete data, overwrite user changes, push, publish, merge, or perform
  another difficult-to-recover external action without explicit authorization.
- Keep automatic enforcement in the configured rollout mode and treat any
  change to provider scope, list replacement behavior, state migration, or
  privacy boundaries as a high-risk change requiring focused review.
