# Contributing to Voidseal

Thanks for your interest. Voidseal is a PowerShell + Hyper-V skill for provisioning risk-tiered,
sealed sandbox VMs. A few things make it pleasant to work on.

## Running the tests (no admin, no Hyper-V required)

The whole engine is built on a **mockable Hyper-V backend** (`scripts/lib/HyperVBackend.ps1`): every
component touches Hyper-V only through one seam, with a real factory and a fake factory that share a
manifest-enforced method set. So the full suite runs against the fake — **no elevation, no real VM**:

```powershell
# PowerShell 7 + Pester 5
$c = New-PesterConfiguration
$c.Run.Path = 'tests'
$c.Output.Verbosity = 'Detailed'
Invoke-Pester -Configuration $c
```

Every change must keep the suite green. CI runs the same on every push/PR (`.github/workflows/pester.yml`).

## The one rule that matters most: the fake must match the real

The project's #1 historical failure mode is **fake≠real divergence** — the fake backend accepting or
returning something the real Hyper-V/PowerShell-storage cmdlets would reject or shape differently, so the
mock tests pass but a live run fails. When you add or change a backend method:

- update the **manifest**, the **real** factory, and the **fake** factory together (the parity/drift tests
  assert manifest ≡ real ≡ fake);
- if the real cmdlet has settle-lag, ordering, or null-shape quirks, model them honestly (or document the
  gap as live-only-unproven). The mock suite cannot catch what the fake doesn't model.

## Style

- `Set-StrictMode -Version Latest` is on everywhere — no unguarded `$null` property access.
- Match the surrounding code's comment density and naming. The seal/containment invariants are
  load-bearing; if you touch `Sealer.ps1` / `Assert-Sealed`, add a test that proves the invariant still holds.

## Commits

Conventional-ish commit messages (`feat:`, `fix:`, `docs:`, `harden:`). Keep changes focused.

## AI-assisted contributions

You may use AI tools while contributing. Two rules apply, and they mirror the
project's own disclosure in [`docs/ai-assistance.md`](docs/ai-assistance.md):

- **You are the author.** Understand the change and be able to explain it in
  your own words; review questions are answered by you, not by a tool. Pull
  requests opened by autonomous agents are closed.
- **Disclose significant assistance.** Say so in the pull request description,
  or add an `Assisted-by: <tool>` trailer to the commit message. Do not add
  `Co-authored-by` trailers naming AI tools: they create a contributor identity
  in the repository record, and only people are contributors here.

## Scope / safety

Voidseal is a **defensive** containment tool. Contributions that weaken the seal gate, add a live
host↔guest channel at Tier ≥ 2, or enable live malware/untrusted-plugin detonation without verified
isolation are out of scope. See `SECURITY.md`.
