## What this changes and why

<!-- Short description. Link the issue this closes, if any. -->

## Checklist

- [ ] `Invoke-Pester -Path tests` is green (no elevation needed — the backend is mocked).
- [ ] `python -m pytest tests/guest tests/host -q` is green, **if** this PR touches anything
      under `guest/`, `tests/guest`, or `tests/host`.
- [ ] **Fake≠real parity maintained**, if this PR touches `scripts/lib/HyperVBackend.ps1`: the
      manifest, the real factory, and the fake factory were updated together (see
      `CONTRIBUTING.md`'s "the fake must match the real" section, and `AGENTS.md`).
- [ ] `CHANGELOG.md` updated, if this PR changes user-visible behavior.
- [ ] Docs updated (`README.md`, `SECURITY.md`, `docs/*.md`) for any change to what a tier, gate,
      or profile field actually does or guarantees — no doc should overclaim what the code does
      after this PR merges.
- [ ] Commit messages follow the project's conventions (conventional-ish: `feat:`, `fix:`,
      `docs:`, `harden:`; see `CONTRIBUTING.md`).

## Notes for the reviewer

<!-- Anything non-obvious: design tradeoffs, what you deliberately left out, open questions. -->
