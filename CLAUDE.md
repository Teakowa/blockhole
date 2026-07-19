# Claude Code — Blockhole

Read and follow @AGENTS.md — it is the canonical project specification.
This file contains only Claude-specific workflow directives.

## Interaction model

- Think step-by-step before proposing changes; show reasoning in responses.
- When a task is ambiguous, ask one focused clarifying question rather than
  guessing.
- Prefer showing a diff or patch over rewriting entire files.

## Tool usage

- Use `bash` tool to run the required checks (`cargo fmt --check`,
  `cargo clippy …`, `cargo test`) and include the results in your response.
- Use `read` / `write` tools for file operations; avoid `cat` pipelines for
  multi-file edits.
- When modifying `state.json` schemas, always run migration tests after the
  change.

## Output conventions

- Keep responses concise — lead with the change, then explain rationale.
- When presenting code, use fenced Rust blocks with the file path as a comment
  on the first line.
- Summarize what changed and what to verify at the end of each response.

## Constraints

- Do not execute network calls to Cloudflare production APIs.
- Do not expand scope beyond what was requested; suggest follow-ups as
  separate tasks.
- Respect all safety requirements and project boundaries from @AGENTS.md.
