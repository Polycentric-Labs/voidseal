---
name: Bug report
about: Something in Voidseal doesn't behave as documented
title: "[bug] "
labels: bug
assignees: ''
---

<!--
Before filing: if this is a security/containment issue (something that lets a workload escape
isolation, bypass the seal gate, or reach something it shouldn't), please do NOT file it here —
see SECURITY.md for the private reporting channel instead.
-->

## What happened

<!-- A clear description of the bug. -->

## Expected behavior

<!-- What you expected instead, and (if you know it) which doc/claim led you to expect it. -->

## Steps to reproduce

<!-- Minimal repro: the exact `Invoke-Voidseal` call (or script) that triggers it. -->

## Tier and elevation

- Tier: <!-- 0 / 1 / 2 / 3 -->
- Profile: <!-- e.g. firefox, ralph, builder, or your own -->
- Mock or live run: <!-- against the fake backend (`Invoke-Pester`), or a real elevated Hyper-V run -->
- If live: elevated session? Member of `Hyper-V Administrators`?

## `Invoke-Pester` output (if relevant)

<!--
If a test is failing, paste the relevant Invoke-Pester output here (redact anything
host/environment-identifying you don't want to share).
-->

```
<paste here>
```

## Environment

- Windows edition/build: <!-- e.g. Windows 11 Pro 23H2 -->
- PowerShell version (`$PSVersionTable.PSVersion`):
- Pester version (`Get-Module Pester -ListAvailable`):
- Hyper-V host or nested/VM host:

## Additional context

<!-- Anything else — logs, screenshots, related issues. -->
