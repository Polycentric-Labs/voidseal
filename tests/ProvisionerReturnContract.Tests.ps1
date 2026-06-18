#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
.SYNOPSIS
    Pester 5 real-backend-shaped regression test for the New-SandboxVM RETURN-VALUE contract
    (a real-backend bug found during live debugging — PowerShell output-stream pollution).

.DESCRIPTION
    THE LIVE FAILURE (operator elevated session): `Invoke-Voidseal -Tier 0 ... -ParentDiskPath
    <golden.vhdx>` reached PROVISIONED then aborted at STAGED with:
        "Import-SandboxAsset: descriptor has no VM Name."
    and teardown then failed with:
        "The property 'CreatedDisks' cannot be found on this object."

    ROOT CAUSE: New-SandboxVM is meant to return ONLY the New-SandboxDescriptor object. But the
    REAL backend methods emit Hyper-V objects to the OUTPUT STREAM (real New-VM returns a VM object,
    New-VHD a VHD object, Add-VMHardDiskDrive a HardDiskDrive, New-VMSwitch a VMSwitch,
    Add-VMNetworkAdapter a NIC, the Set-VM* calls can emit, ...). Those effect-only calls were NOT
    captured, so PowerShell collected every stray emission as part of New-SandboxVM's return value,
    making it an ARRAY = @(<VM object>, ..., <descriptor>) instead of the lone descriptor. The
    orchestrator's $descriptor became that array; Import-SandboxAsset received element [0] (a raw VM
    object with no .Name) → "descriptor has no VM Name", and teardown saw element [0] with no
    .CreatedDisks. The FAKE backend returns quiet hashtables that do NOT pollute the stream, so the
    mock tests passed and ONLY the live path broke.

    WHY OUT-OF-PROCESS: the real backend's methods are .GetNewClosure() scriptblocks that resolve
    their Hyper-V cmdlets against the SESSION STATE captured when New-RealHyperVBackend ran. A shadow
    stub / Pester Mock installed in a TEST scope is NOT on that closure's command-resolution path. The
    ONLY reliable interception is to define the shadow stubs AND dot-source the libs in the SAME
    top-level script scope — which the harness tests/fixtures/Invoke-RealProvisionCapture.ps1 does.
    EACH shadow stub there EMITS a dummy object to the output stream, mimicking the real cmdlets that
    pollute it, then drives the REAL New-SandboxVM end-to-end and reports (as JSON) how many objects
    landed on its output stream + whether the descriptor is the lone return. We run it in a child
    `pwsh` here and assert on the result. This is the test that WOULD have caught the live bug.
    (PROVEN against the pre-fix Provisioner: count=10, elem0HasName=$false. Post-fix: count=1.)

    The in-process fake-backed Provisioner.Tests.ps1 structurally could NOT catch this —
    the fake's quiet hashtables never pollute the stream — hence this out-of-process companion.

    TDD: written FIRST; RED before the suppression fix, GREEN after.
#>

BeforeAll {
    $script:SkillRoot     = Split-Path -Parent $PSScriptRoot
    $script:HarnessPath   = Join-Path $PSScriptRoot 'fixtures/Invoke-RealProvisionCapture.ps1'
    $script:ProvPath      = Join-Path $script:SkillRoot 'scripts/lib/Provisioner.ps1'
    $script:BackendPath   = Join-Path $script:SkillRoot 'scripts/lib/HyperVBackend.ps1'

    Test-Path $script:HarnessPath | Should -BeTrue -Because 'the out-of-process provision-capture harness must exist'
    Test-Path $script:ProvPath    | Should -BeTrue -Because 'the Provisioner must exist'
    Test-Path $script:BackendPath | Should -BeTrue -Because 'the backend must exist'

    # Run the harness in a fresh child pwsh: top-level emitting shadow stubs + dot-source means the
    # real backend's closures resolve their Hyper-V cmdlets to the (polluting) stubs, so the REAL
    # New-SandboxVM body runs end-to-end with no live Hyper-V + no elevation. Capture the JSON.
    $pwsh = (Get-Process -Id $PID).Path   # the exact pwsh running these tests
    if ([string]::IsNullOrWhiteSpace($pwsh)) { $pwsh = 'pwsh' }
    $raw = & $pwsh -NoProfile -File $script:HarnessPath -ProvisionerPath $script:ProvPath -BackendPath $script:BackendPath 2>&1
    $rawText = ($raw | Out-String).Trim()
    # The harness emits a single JSON line; isolate it (defend against any stray warning text).
    $jsonLine = ($rawText -split "`n" | Where-Object { $_.Trim().StartsWith('{') } | Select-Object -Last 1)
    $jsonLine | Should -Not -BeNullOrEmpty -Because "the harness must emit JSON; got: $rawText"
    $script:Cap = $jsonLine | ConvertFrom-Json
}

Describe 'Real backend — New-SandboxVM returns EXACTLY the descriptor (output-stream pollution; live-debug regression)' {

    It 'New-SandboxVM does not throw when the real backend methods emit stray objects' {
        $script:Cap.err | Should -BeNullOrEmpty -Because 'the emitting backend methods must not break the provision'
    }

    It 'returns EXACTLY ONE object — the descriptor (pre-fix this was an array of 10)' {
        # THE headline assertion. Pre-fix: count=10 (every uncaptured Hyper-V emission leaked in).
        $script:Cap.count | Should -Be 1 -Because 'New-SandboxVM must return ONLY the descriptor; any stray Hyper-V object on its output stream is the live bug'
    }

    It 'the single returned object IS a descriptor (has .Name and .CreatedDisks)' {
        $script:Cap.lastIsDescriptor | Should -BeTrue -Because 'the lone return must be the New-SandboxDescriptor object'
    }

    It 'the descriptor exposes a non-empty .Name (Import-SandboxAsset reads this; the live abort was its absence)' {
        $script:Cap.name | Should -Be 'sbx-pollute' -Because '"Import-SandboxAsset: descriptor has no VM Name" fired because element [0] was a raw VM object with no Name'
    }

    It 'the descriptor exposes .CreatedDisks (teardown reads this; the live teardown crash was its absence)' {
        $script:Cap.createdDisksGiven | Should -BeTrue -Because '"The property CreatedDisks cannot be found on this object" fired because teardown got a raw Hyper-V object, not the descriptor'
        $script:Cap.createdDisksCount | Should -Be 1     -Because 'one system disk was created (the differencing child off the golden parent)'
    }

    It 'element [0] of the return is the descriptor itself (NOT a stray Hyper-V VM/VHD object)' {
        # Pre-fix element [0] was the raw New-VHD/New-VM stub object with no .Name — exactly what
        # Import-SandboxAsset choked on. Post-fix element [0] == the descriptor, which has a Name.
        $script:Cap.elem0HasName | Should -BeTrue -Because 'with a single-object return, element [0] is the descriptor and carries the VM Name'
    }
}
