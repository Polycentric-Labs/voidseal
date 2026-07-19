# AGENTS.md

Guide for an AI coding agent (Claude, or any other) — or a human — contributing to Voidseal. This
file is a **map**, not a restatement: the substance already lives in the docs below, and this file
points at it rather than duplicating it. If something here and the linked doc ever disagree, the
linked doc is the source of truth.

## Orient

Voidseal provisions a **risk-tiered, host-verified-sealed Hyper-V sandbox VM** for running untrusted
code safely. The whole engine talks to Hyper-V through one mockable seam
(`scripts/lib/HyperVBackend.ps1`, real + fake factories, manifest-enforced parity), so the full test
suite runs with no elevation and no real VM.

Start here, in this order:

- **[`CONTRIBUTING.md`](CONTRIBUTING.md)** — how to run the tests, the project's #1 bug class
  (below), style, commit conventions, scope/safety boundaries.
- **[`SKILL.md`](SKILL.md)** — the Claude-facing entry point: what the tool does, the lifecycle
  state machine, the tier model, the two shipped workload profiles.
- **[`docs/authoring-a-workload-profile.md`](docs/authoring-a-workload-profile.md)** — the profile
  field contract, if your change touches or adds a `profiles/*.psd1`.
- **[`docs/tier-reference.md`](docs/tier-reference.md)** — the full tier model + containment
  rubric.
- **[`docs/threat-model.md`](docs/threat-model.md)** — what's IN SCOPE as a Voidseal bug vs. HOST
  MISCONFIG vs. a KNOWN LIMITATION, per tier. Read this before claiming a change closes a
  containment gap.

## The three load-bearing rules

**1. Fake-must-match-real backend parity.** Voidseal's #1 historical failure mode is *fake≠real
divergence* — the mock backend accepting or shaping something real Hyper-V would reject, so tests
pass but a live run fails. If you add or change a `HyperVBackend.ps1` method or its return shape,
the **manifest, the real factory, and the fake factory move together** — see CONTRIBUTING.md's
"The one rule that matters most" section for the full discipline (parity/drift tests, modeling
settle-lag/null-shape quirks honestly). Do not touch one of the three without the other two.

**2. Both suites green before you propose a change.**

```powershell
Invoke-Pester -Path tests
```

```
python -m pytest tests/guest tests/host -q
```

Run the Python suite too if you touched anything under `guest/` (the in-guest screener/outbox
producer) or `tests/guest`/`tests/host`. CI runs the Pester suite on every push/PR
(`.github/workflows/pester.yml`); the pytest suite is not yet wired into CI, so it's on you to run
it locally when relevant.

**3. Honesty discipline.** Every claim in a doc, comment, or commit message about what Voidseal
*guarantees* must match what the code actually does — no overclaiming a containment property that
isn't host-verified. This project has had repeated drift incidents where a doc said "enforced" or
"boundary" about something that was actually defense-in-depth or scaffold-only; see
`docs/threat-model.md` for the current scoped-claims table and `SECURITY.md`'s "Status / honesty"
section for the pattern. If your change affects what a tier or a gate does or doesn't cover, update
the relevant doc in the same change — don't leave the docs ahead of (or behind) the code.

## AI-contribution norm

Voidseal is itself built via Claude Code, so AI-assisted contributions are welcome and expected —
not a special case to disclose apologetically. The norm, gVisor-style:

- **Review AI-generated output as if you had written it yourself.** You are responsible for
  correctness, for the two load-bearing rules above (parity + both suites green), and for not
  introducing a claim the code doesn't back up. "The model wrote it" is not a defense for a bug or
  an overclaim.
- **Be transparent about substantial AI assistance** in your PR description, at whatever level of
  detail you think is useful to a reviewer (which tool, which parts, how much you verified
  independently) — this project's own README carries an "AI Assistance" section in that spirit.
- This norm is about **transparency and review discipline for contributors**, not about commit
  metadata. It does not say anything about whether *your* commits should or shouldn't carry an AI
  co-author trailer — that's your own call to make for your own commits, not something this project
  mandates one way or the other.

## Anything else

Scope/safety boundaries (what kinds of changes are out of scope for this defensive tool) are in
CONTRIBUTING.md's "Scope / safety" section and `SECURITY.md`. If you're not sure whether a change
fits, open an issue first using the templates under `.github/ISSUE_TEMPLATE/`.
