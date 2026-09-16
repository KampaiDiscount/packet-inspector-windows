#requires -Version 5.1
[CmdletBinding()]
param(
    [ValidateSet('Setup','Start','Interfaces','Replay')][string]$Mode='Start',
    [string]$PythonExe,
    [string]$Interface,
    [string]$CapturePath,
    [string]$OutputRoot,
    [string]$Bpf='ip or ip6',
    [ValidateRange(1,65535)][int]$Port=8766,
    [switch]$NoBrowser,
    [switch]$NoDashboard
)
$ErrorActionPreference='Stop'
$packageRoot=Split-Path -Parent $PSScriptRoot
$environmentPython=Join-Path $packageRoot '.venv\Scripts\python.exe'
try {
    if ($Mode -eq 'Setup') {
        if (-not $PythonExe) {
            foreach ($name in @('py.exe','python.exe')) {
                $candidate=Get-Command $name -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
                if (-not $candidate -or $candidate.Source -like '*\WindowsApps\*') { continue }
                $probeArguments=@()
                if ($name -eq 'py.exe') { $probeArguments+='-3' }
                $probeArguments+=@('-c','import sys; assert sys.version_info >= (3,11); print(sys.executable)')
                $probe=& $candidate.Source @probeArguments 2>$null
                if ($LASTEXITCODE -eq 0 -and $probe) { $PythonExe=[string](@($probe)[-1]); break }
            }
        }
        if (-not $PythonExe -or -not (Test-Path -LiteralPath $PythonExe -PathType Leaf)) {
            throw 'Install 64-bit Python 3.11+ from python.org, or provide -PythonExe with its full path. No software was downloaded.'
        }
        & $PythonExe -c 'import sys; assert sys.version_info >= (3,11), "Python 3.11+ required"; assert sys.maxsize > 2**32, "64-bit Python required"'
        if ($LASTEXITCODE -ne 0) { throw 'Unsupported Python runtime.' }
        if (-not (Test-Path -LiteralPath $environmentPython)) {
            & $PythonExe -m venv (Join-Path $packageRoot '.venv')
            if ($LASTEXITCODE -ne 0) { throw 'Could not create the package-local Python environment.' }
        }
        & $environmentPython -I -c 'import sys; assert sys.version_info >= (3,11), "Python 3.11+ required"; assert sys.maxsize > 2**32, "64-bit Python required"'
        if ($LASTEXITCODE -ne 0) { throw 'The existing .venv runtime is unsupported. Move it aside and rerun setup with 64-bit Python 3.11+.' }
        $wheels=@(Get-ChildItem -LiteralPath (Join-Path $packageRoot 'dist') -Filter 'packet_inspector_windows-*.whl' -File)
        if ($wheels.Count -ne 1) { throw 'Expected one bundled Windows wheel in dist.' }
        & $environmentPython -m pip install --no-index --no-deps --force-reinstall $wheels[0].FullName
        if ($LASTEXITCODE -ne 0) { throw 'Local wheel installation failed.' }
        & $environmentPython -I -m packet_audit --version
        if ($LASTEXITCODE -ne 0) { throw 'The installed CLI failed its version check; setup is not complete.' }
        Write-Host 'Setup complete. Wireshark capture tools and Npcap must be installed separately. Run LIST-INTERFACES.cmd, then START-PACKET-INSPECTOR.cmd.'
        exit 0
    }
    if (-not (Test-Path -LiteralPath $environmentPython -PathType Leaf)) { throw 'Run SETUP.cmd first.' }
    $runtimeArguments=@('-I','-m','packet_audit.windows_app',$Mode.ToLowerInvariant())
    if ($Mode -eq 'Replay') {
        if (-not $CapturePath) { $CapturePath=Read-Host 'Full path to PCAP/PCAPNG (without surrounding quotes)' }
        $runtimeArguments+=$CapturePath
    }
    if ($Interface) { $runtimeArguments+=@('--interface',$Interface) }
    if ($OutputRoot) { $runtimeArguments+=@('--output-root',$OutputRoot) }
    $runtimeArguments+=@("--filter=$Bpf",'--port',[string]$Port)
    if ($NoBrowser) { $runtimeArguments+='--no-browser' }
    if ($NoDashboard) { $runtimeArguments+='--no-dashboard' }
    & $environmentPython @runtimeArguments
    exit $LASTEXITCODE
}
catch {
    Write-Host ("Packet Inspector: {0}" -f $_.Exception.Message) -ForegroundColor Red
    exit 1
}
