@AGENTS.md

# Claude Code notes for siwx-oidc

The rules above (imported from `AGENTS.md`) apply in full. This file adds only what is
specific to Claude Code; keep project rules in `AGENTS.md` so every agent sees the same set.

## Skills

The task guides in `skills/` are exposed as slash commands through symlinks in
`.claude/commands/`: `/add-did-method`, `/add-cipher-suite`, `/add-auth-ceremony`,
`/authenticate-siwe-matrix`, `/debug-oidc`, `/deploy-check`, `/docker-build`.
`skills/cross-signing-bootstrap-and-debug.md` and `skills/element-x-qr-code-specialist.md`
have no symlink; read them directly, or add a symlink in `.claude/commands/` to invoke them.

## Private notes

Maintainers keep deployment-specific notes (hosts, stack paths, deploy procedure, incident
records) in `CLAUDE.local.md` at the repository root. Claude Code loads it automatically, and
`.gitignore` excludes it. Never copy its content into a tracked file; see "Public-repo
hygiene" in `AGENTS.md`.

## Working in this repo

- Run `git status` and check the current branch before editing: several sessions may share a
  checkout, and a branch switch by another session looks like your work vanishing.
- Background test runs share one mock stack; do not start two e2e suites at once.
