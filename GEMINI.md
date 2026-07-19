# Gemini — Blockhole

Read and follow @AGENTS.md — it is the canonical project specification.
This file contains only Gemini-specific workflow directives.

## Interaction model

- Plan before acting: for non-trivial changes, outline the approach and get
  approval before editing code.
- When a task is ambiguous, ask one focused clarifying question rather than
  guessing.
- Keep changes narrow — one concern per edit session.

## Tool usage

- Run the required checks (`cargo fmt --check`, `cargo clippy …`,
  `cargo test`) after making changes and before reporting completion.
- Use file-edit tools for targeted changes; avoid rewriting entire files.
- When modifying `state.json` schemas, always run migration tests after the
  change.

## Output conventions

- Lead with what changed, then explain why.
- Use fenced Rust blocks with the file path when presenting code.
- End each response with a summary of changes and remaining verification
  steps.

## Constraints

- Do not execute network calls to Cloudflare production APIs.
- Do not expand scope beyond what was requested; suggest follow-ups as
  separate tasks.
- Respect all safety requirements and project boundaries from @AGENTS.md.
