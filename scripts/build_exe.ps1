<#
    Build the desktop software: RevLab.exe (double-clickable window) and
    RevLabCLI.exe (the same commands in a console), both from packaging\revlab.spec.

        powershell -ExecutionPolicy Bypass -File scripts\build_exe.ps1
        powershell -ExecutionPolicy Bypass -File scripts\build_exe.ps1 -OneFile -Shortcut

    What it does:
      1. finds a *standard* CPython (python.org / nuget -- not MSYS2's mingw
         build, which PyInstaller does not support) and creates
         packaging\.venv-build;
      2. installs PyInstaller there (the app itself has no runtime dependency);
      3. draws packaging\revlab.ico if it is missing;
      4. runs PyInstaller over the spec, producing dist\RevLab\;
      5. verifies the result: runs the frozen CLI, then starts the frozen window
         from a copy in %TEMP% and looks for that window on screen
         (scripts\gui_smoke_frozen.py).

    The verification is the point: a build that merely exits 0 has not been shown
    to start on a machine without the source tree.
#>
param(
    [string]$Python = "",
    [switch]$OneFile,
    [switch]$WithEngines,
    [switch]$NoSmokeTest,
    [switch]$Shortcut
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$venv = Join-Path $root 'packaging\.venv-build'
$venvPython = Join-Path $venv 'Scripts\python.exe'
$distDir = Join-Path $root 'dist\RevLab'
$gui = Join-Path $distDir 'RevLab.exe'
$cli = Join-Path $distDir 'RevLabCLI.exe'

function Step($message) { Write-Host "`n== $message" -ForegroundColor Cyan }
function Fail($message) { Write-Host "!! $message" -ForegroundColor Red; exit 1 }

function Test-BasePython {
    param([string]$Exe)
    if (-not $Exe -or -not (Test-Path $Exe)) { return $false }
    # PyInstaller needs a normal CPython: the MSYS2/mingw build has a different
    # ABI and no working bootloader support.
    $probe = & $Exe -c "import sys, tkinter; print(sys.base_prefix); print('msys' in sys.base_prefix.lower() or 'mingw' in sys.base_prefix.lower())" 2>&1
    if ($LASTEXITCODE -ne 0) { return $false }
    $lines = @($probe) | ForEach-Object { "$_".Trim() }
    return ($lines[-1] -eq 'False')
}

function Find-BasePython {
    param([string]$Explicit)
    $candidates = @()
    if ($Explicit) { $candidates += $Explicit }
    $candidates += @(
        (Join-Path $env:LOCALAPPDATA 'Programs\Python\Python312\python.exe'),
        (Join-Path $env:LOCALAPPDATA 'Programs\Python\Python311\python.exe'),
        (Join-Path $env:LOCALAPPDATA 'Programs\Python\Python313\python.exe')
    )
    foreach ($candidate in $candidates) {
        if (Test-BasePython $candidate) { return $candidate }
    }
    $launcher = Get-Command py -ErrorAction Ignore
    if ($launcher) {
        foreach ($version in @('-3.13', '-3.12', '-3.11')) {
            $found = & $launcher.Source $version -c "import sys; print(sys.executable)" 2>$null
            if ($LASTEXITCODE -eq 0 -and (Test-BasePython "$found".Trim())) {
                return "$found".Trim()
            }
        }
    }
    return ""
}

Step "locating a CPython that PyInstaller supports"
$basePython = Find-BasePython -Explicit $Python
if (-not $basePython) {
    Fail ("no python.org CPython found (a MSYS2/mingw python cannot be frozen).`n" +
          "   install Python 3.12 from python.org, or pass -Python C:\path\python.exe")
}
Write-Host "   $basePython"

if (-not (Test-Path $venvPython)) {
    Step "creating the build environment (packaging\.venv-build)"
    & $basePython -m venv $venv
    if ($LASTEXITCODE -ne 0) { Fail "venv creation failed" }
}

Step "installing PyInstaller into the build environment"
& $venvPython -m pip install --disable-pip-version-check --quiet --upgrade pip pyinstaller
if ($LASTEXITCODE -ne 0) { Fail "pip install pyinstaller failed" }
if ($WithEngines) {
    Write-Host "   also installing the optional engines (frida / ghirdra extras)"
    foreach ($requirements in 'requirements-frida.txt', 'requirements-ghidra.txt') {
        $file = Join-Path $root $requirements
        if (Test-Path $file) {
            & $venvPython -m pip install --disable-pip-version-check --quiet -r $file
            Write-Host "   $requirements -> exit $LASTEXITCODE"
        }
    }
}
Write-Host "   PyInstaller $(& $venvPython -m PyInstaller --version)"

$icon = Join-Path $root 'packaging\revlab.ico'
if (-not (Test-Path $icon)) {
    Step "drawing packaging\revlab.ico"
    & $venvPython (Join-Path $root 'scripts\make_icon.py')
    if ($LASTEXITCODE -ne 0) { Fail "icon generation failed" }
}

Step "running PyInstaller"
# PyInstaller decides *which* Tcl/Tk libraries to collect by asking a real Tcl
# interpreter for `info library`, so an inherited TCL_LIBRARY / TK_LIBRARY points
# the build at whatever that variable names. A debugging session sets exactly
# that, and the next build then harvests its own previous output (hundreds of
# "Ignoring non-existent resource" warnings, a bundle with no init.tcl). The
# build decides what it packages: drop the variables it inherited.
foreach ($leaked in 'TCL_LIBRARY', 'TK_LIBRARY', 'PYTHONHOME', 'PYTHONPATH', 'PYTHONSTARTUP') {
    $value = [Environment]::GetEnvironmentVariable($leaked)
    if ($value) {
        Write-Host "   ignoring inherited $leaked = $value"
        Remove-Item "Env:\$leaked" -ErrorAction Ignore
    }
}
if ($OneFile) { $env:REVLAB_ONEFILE = '1' } else { Remove-Item Env:\REVLAB_ONEFILE -ErrorAction Ignore }
Push-Location $root
try {
    & $venvPython -m PyInstaller --noconfirm --clean 'packaging\revlab.spec'
    if ($LASTEXITCODE -ne 0) { Fail "PyInstaller failed" }
} finally {
    Pop-Location
}

if (-not (Test-Path $gui)) { Fail "expected $gui to exist" }
if (-not (Test-Path $cli)) { Fail "expected $cli to exist" }
$folderSize = [math]::Round((Get-ChildItem $distDir -Recurse -File |
    Measure-Object -Property Length -Sum).Sum / 1MB, 1)

Step "the build produced"
Write-Host "   $gui"
Write-Host "   $cli"
Write-Host "   dist\RevLab\ -- $folderSize MiB"
if ($OneFile) {
    $portable = Join-Path $root 'dist\RevLab-Portable.exe'
    if (Test-Path $portable) {
        Write-Host "   $portable ($([math]::Round((Get-Item $portable).Length / 1MB, 1)) MiB, unpacks to %TEMP% on start)"
    }
}

if (-not $NoSmokeTest) {
    Step "verifying the frozen executables"
    # The window is started for real and then looked for on screen: a visible
    # top-level window owned by that process, titled RevLab. Watching the log file
    # grow is NOT proof -- the log is opened before Tk is created, so a startup
    # traceback grows it too, which is how a build once shipped whose window died
    # with "Can't find a usable init.tcl". The check also runs the copy in %TEMP%
    # with TCL_LIBRARY / TK_LIBRARY stripped from the environment, so neither the
    # build tree nor a leftover variable can make a broken bundle look healthy.
    & $venvPython (Join-Path $root 'scripts\gui_smoke_frozen.py') --exe $gui --timeout 40
    if ($LASTEXITCODE -ne 0) {
        Fail ("the frozen window did not come up -- read $env:LOCALAPPDATA\RevLab\logs\revlab-desktop.log")
    }
}

if ($Shortcut) {
    Step "creating a desktop shortcut"
    $desktop = [Environment]::GetFolderPath('Desktop')
    $link = Join-Path $desktop 'RevLab.lnk'
    $shell = New-Object -ComObject WScript.Shell
    $shortcutObject = $shell.CreateShortcut($link)
    $shortcutObject.TargetPath = $gui
    $shortcutObject.WorkingDirectory = $distDir
    $shortcutObject.IconLocation = $gui
    $shortcutObject.Description = 'RevLab 逆向工程工作台 (Ghidra + Frida)'
    $shortcutObject.Save()
    Write-Host "   $link"
}

Write-Host "`nDone. Double-click $gui (or the shortcut) to use RevLab." -ForegroundColor Green
