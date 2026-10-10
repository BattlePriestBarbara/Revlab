<#
    Wrapper for developers who prefer a PowerShell entry point.

    The build itself lives in build_apk.py. PowerShell 5.1 does not pass
    non-ASCII or -Dname=value arguments to native programs intact, and a user
    profile under a non-ASCII path (this machine's is) makes that fatal for
    aapt2 and d8. Python hands Windows the exact command line, so the real work
    happens there.

        powershell -ExecutionPolicy Bypass -File android\build_apk.ps1
        powershell -ExecutionPolicy Bypass -File android\build_apk.ps1 -Api 34 -SkipInstall
#>
param(
    [string]$Sdk = "",
    [string]$JavaHome = "",
    [int]$Api = 34,
    [string]$BuildTools = "34.0.0",
    [switch]$SkipInstall,
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'
$script = Join-Path $PSScriptRoot 'build_apk.py'

function Find-Python {
    $candidates = @()
    if ($env:REVLAB_PYTHON) { $candidates += $env:REVLAB_PYTHON }
    $candidates += @(
        (Join-Path $env:LOCALAPPDATA 'Programs\Python\Python312\python.exe'),
        (Join-Path $env:LOCALAPPDATA 'Programs\Python\Python311\python.exe')
    )
    $onPath = Get-Command python -ErrorAction Ignore
    if ($onPath) { $candidates += $onPath.Source }
    foreach ($candidate in $candidates) {
        if ($candidate -and (Test-Path $candidate)) { return $candidate }
    }
    return "python"
}

$arguments = @($script, '--api', $Api, '--build-tools', $BuildTools)
if ($Sdk) { $arguments += @('--sdk', $Sdk) }
if ($JavaHome) { $arguments += @('--java-home', $JavaHome) }
if ($SkipInstall) { $arguments += '--skip-install' }
if ($DryRun) { $arguments += '--dry-run' }

& (Find-Python) @arguments
exit $LASTEXITCODE
