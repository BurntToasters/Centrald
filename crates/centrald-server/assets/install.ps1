# CentralD agent installer for Windows. Run from an elevated PowerShell using
# the command shown in the web app, which pins this server's certificate and
# passes the one-time join code in $env:CENTRALD_JOIN (never as an argument).
# Set $env:CENTRALD_MONITOR_ONLY='1' for a device that refuses commands.

& {
    $ErrorActionPreference = 'Stop'
    $Server = '__CENTRALD_SERVER__'
    $CertSha256 = '__CENTRALD_CERT_SHA256__'

    if (-not $env:CENTRALD_JOIN) {
        throw 'CENTRALD_JOIN is not set. Copy the whole command from the CentralD web app.'
    }
    $principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run PowerShell as Administrator, then paste the command again.'
    }

    [Net.ServicePointManager]::SecurityProtocol = 'Tls12'
    [Net.ServicePointManager]::ServerCertificateValidationCallback = {
        param($s, $certificate)
        $hash = [Security.Cryptography.SHA256]::Create().ComputeHash($certificate.GetRawCertData())
        ([BitConverter]::ToString($hash) -replace '-') -eq $CertSha256
    }.GetNewClosure()

    $arch = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'aarch64' } else { 'x86_64' }
    $dir = Join-Path $env:ProgramFiles 'CentralD'
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $exe = Join-Path $dir 'centrald-agent.exe'
    $download = "$exe.download"

    Write-Host "Downloading the CentralD agent from $Server"
    $client = New-Object Net.WebClient
    $client.DownloadFile("https://$Server/download/agent/windows/$arch", $download)
    $expected = $client.DownloadString("https://$Server/download/agent/windows/$arch.sha256").Trim()
    $actual = (Get-FileHash -Algorithm SHA256 -Path $download).Hash.ToLowerInvariant()
    if ($expected -ne $actual) {
        Remove-Item -Force $download
        throw 'The downloaded agent is corrupt (checksum mismatch).'
    }

    $service = Get-Service -Name 'CentralDAgent' -ErrorAction SilentlyContinue
    if ($service -and $service.Status -ne 'Stopped') {
        Stop-Service -Name 'CentralDAgent' -Force
    }
    Move-Item -Force -Path $download -Destination $exe

    $arguments = @('enroll', '--key-stdin')
    if ($env:CENTRALD_MONITOR_ONLY -eq '1') { $arguments += '--monitor-only' }
    $env:CENTRALD_JOIN | & $exe @arguments
    if ($LASTEXITCODE -ne 0) { throw "Enrollment failed (exit code $LASTEXITCODE)." }
    Remove-Item Env:\CENTRALD_JOIN
}
