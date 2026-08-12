CentralD Client for Windows
===========================

1. Open an Administrator PowerShell in this directory.
2. Run: .\install-client.ps1
3. Enroll: "C:\Program Files\CentralD\centrald-client.exe" enroll
4. Enrollment changes CentralDClient to delayed automatic start and attempts to start it.
   Use install-client.ps1 -KeepManualStart only when manual startup is intentional.

Enrollment requires only the one-time CentralD invitation and, when needed, an
IP/FQDN connection override. The invitation contains the trusted public CA and
TLS name. Never paste the invitation into logs or support bundles.
