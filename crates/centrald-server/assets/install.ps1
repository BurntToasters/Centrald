# CentralD agent installer for Windows. Run from an elevated Windows
# PowerShell (5.1) using the command shown in the web app, which pins this
# server's certificate and passes the one-time join code in
# $env:CENTRALD_JOIN (never as an argument).
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
        throw 'Run Windows PowerShell as Administrator, then paste the command again.'
    }

    $download = $null
    try {
        [Net.ServicePointManager]::SecurityProtocol = 'Tls12'
        [Net.ServicePointManager]::ServerCertificateValidationCallback = {
            param($s, $certificate)
            $hash = [Security.Cryptography.SHA256]::Create().ComputeHash($certificate.GetRawCertData())
            ([BitConverter]::ToString($hash) -replace '-') -eq $CertSha256
        }.GetNewClosure()

        # The machine's architecture, not this PowerShell process's (an x64
        # PowerShell on ARM64 Windows reports AMD64).
        $machine = (Get-ItemProperty -ErrorAction SilentlyContinue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment').PROCESSOR_ARCHITECTURE
        if (-not $machine) {
            $machine = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
        }
        $arch = switch -Regex ($machine) {
            '^ARM64$' { 'aarch64' }
            '^AMD64$' { 'x86_64' }
            default { throw "Unsupported Windows architecture: $machine" }
        }

        # 64-bit Program Files even from a 32-bit PowerShell.
        $programFiles = if ($env:ProgramW6432) { $env:ProgramW6432 } else { $env:ProgramFiles }
        $dir = Join-Path $programFiles 'CentralD'
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
        $exe = Join-Path $dir 'centrald-agent.exe'
        $download = "$exe.download"

        Write-Host "Downloading the CentralD agent ($arch) from $Server"
        $client = New-Object Net.WebClient
        try {
            $client.DownloadFile("https://$Server/download/agent/windows/$arch", $download)
            $expected = $client.DownloadString("https://$Server/download/agent/windows/$arch.sha256").Trim()
        } catch [Net.WebException] {
            $status = $_.Exception.Response.StatusCode
            if ([int]$status -eq 404) {
                throw "The server has no Windows $arch agent build. Install the server from a release package, which includes every agent."
            }
            throw "Could not download the agent from ${Server}: $($_.Exception.Message)"
        }
        $actual = (Get-FileHash -Algorithm SHA256 -Path $download).Hash.ToLowerInvariant()
        if ($expected -ne $actual) {
            throw 'The downloaded agent is corrupt (checksum mismatch).'
        }

        $service = Get-Service -Name 'CentralDAgent' -ErrorAction SilentlyContinue
        if ($service -and $service.Status -ne 'Stopped') {
            Stop-Service -Name 'CentralDAgent' -Force
        }
        # An agent started by hand (`centrald-agent.exe run`) locks the file.
        Get-Process -Name 'centrald-agent' -ErrorAction SilentlyContinue |
            Where-Object { $_.Path -eq $exe } |
            Stop-Process -Force
        Move-Item -Force -Path $download -Destination $exe
        $download = $null

        $arguments = @('enroll', '--key-stdin')
        if ($env:CENTRALD_MONITOR_ONLY -eq '1') { $arguments += '--monitor-only' }
        $env:CENTRALD_JOIN | & $exe @arguments
        if ($LASTEXITCODE -ne 0) { throw "Enrollment failed (exit code $LASTEXITCODE)." }
    } finally {
        if ($download -and (Test-Path $download)) { Remove-Item -Force $download }
        Remove-Item Env:\CENTRALD_JOIN -ErrorAction SilentlyContinue
        # Leave no pin callback or forced TLS version in this session.
        [Net.ServicePointManager]::ServerCertificateValidationCallback = $null
        try { [Net.ServicePointManager]::SecurityProtocol = 'SystemDefault' } catch {}
    }
}
