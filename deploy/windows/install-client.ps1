#Requires -RunAsAdministrator
[CmdletBinding()]
param(
  [switch]$StartAfterInstall,
  [switch]$KeepManualStart
)

$ErrorActionPreference = "Stop"
$serviceName = "CentralDClient"
$brokerServiceName = "CentralDBroker"
$serviceIdentity = "NT SERVICE\$serviceName"
$brokerIdentity = "LocalSystem"
$ProgramFilesDirectory = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
$ProgramDataDirectory = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
$SystemDirectory = [Environment]::SystemDirectory
if ([string]::IsNullOrWhiteSpace($ProgramFilesDirectory) -or
    [string]::IsNullOrWhiteSpace($ProgramDataDirectory) -or
    [string]::IsNullOrWhiteSpace($SystemDirectory)) {
  throw "Windows did not return its trusted Program Files, ProgramData, and System directories."
}
$InstallDirectory = [System.IO.Path]::GetFullPath((Join-Path $ProgramFilesDirectory "CentralD"))
$DataDirectory = [System.IO.Path]::GetFullPath((Join-Path $ProgramDataDirectory "CentralD"))
$ScExe = Join-Path $SystemDirectory "sc.exe"
$source = Join-Path $PSScriptRoot "centrald-client.exe"
$destination = Join-Path $InstallDirectory "centrald-client.exe"
$stagedBinary = Join-Path $InstallDirectory ".centrald-client.exe.next"
$backupBinary = Join-Path $InstallDirectory ".centrald-client.exe.previous"
$configurationDirectory = Join-Path $DataDirectory "configurations"
$currentPointer = Join-Path $configurationDirectory "current.pointer"
$manualStartMarker = Join-Path $InstallDirectory "manual-start.optout"

function Invoke-NativeChecked {
  param(
    [Parameter(Mandatory = $true)][string]$FilePath,
    [Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments
  )

  & $FilePath @Arguments
  if ($LASTEXITCODE -ne 0) {
    throw "$FilePath failed with exit code $LASTEXITCODE"
  }
}

function Assert-NoReparseAncestors {
  param([Parameter(Mandatory = $true)][string]$Path)

  $full = [System.IO.Path]::GetFullPath($Path)
  if ($full.StartsWith("\\", [System.StringComparison]::Ordinal)) {
    throw "CentralD installation paths must not be UNC paths: $full"
  }
  $root = [System.IO.Path]::GetPathRoot($full)
  if ([string]::Equals($full.TrimEnd('\'), $root.TrimEnd('\'), [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Refusing a drive-root CentralD path: $full"
  }
  $current = $full
  while (-not [string]::IsNullOrWhiteSpace($current)) {
    if (Test-Path -LiteralPath $current) {
      $item = Get-Item -LiteralPath $current -Force
      if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Refusing reparse-point CentralD path component: $($item.FullName)"
      }
      if (-not $item.PSIsContainer -and -not [string]::Equals($current, $full, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "CentralD path ancestor is not a directory: $($item.FullName)"
      }
    }
    if ([string]::Equals($current.TrimEnd('\'), $root.TrimEnd('\'), [System.StringComparison]::OrdinalIgnoreCase)) {
      break
    }
    $parent = Split-Path -Parent $current
    if ([string]::IsNullOrWhiteSpace($parent) -or [string]::Equals($parent, $current, [System.StringComparison]::OrdinalIgnoreCase)) {
      break
    }
    $current = $parent
  }
}

function Assert-CentralDLeafPath {
  param(
    [Parameter(Mandatory = $true)][string]$Actual,
    [Parameter(Mandatory = $true)][string]$Expected,
    [Parameter(Mandatory = $true)][string]$Label
  )

  $actualFull = [System.IO.Path]::GetFullPath($Actual).TrimEnd('\')
  $expectedFull = [System.IO.Path]::GetFullPath($Expected).TrimEnd('\')
  if (-not [string]::Equals($actualFull, $expectedFull, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "$Label is package-managed and must be $expectedFull"
  }
  Assert-NoReparseAncestors -Path $actualFull
}

function Assert-RegularNonReparseFile {
  param([Parameter(Mandatory = $true)][string]$Path)
  $item = Get-Item -LiteralPath $Path -Force
  if ($item.PSIsContainer -or (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)) {
    throw "Refusing unsafe CentralD file: $Path"
  }
}

function Get-CentralDAclSnapshot {
  param([Parameter(Mandatory = $true)][string]$Path)

  if (-not (Test-Path -LiteralPath $Path)) {
    return @()
  }
  Assert-NoReparseAncestors -Path $Path
  $root = Get-Item -LiteralPath $Path -Force
  $maximumItems = 4096
  $items = [System.Collections.Generic.List[System.IO.FileSystemInfo]]::new()
  $items.Add($root)
  Get-ChildItem -LiteralPath $Path -Force -Recurse | ForEach-Object {
    if ($items.Count -ge $maximumItems) {
      throw "CentralD path contains more than $maximumItems entries; refusing ACL snapshot"
    }
    if (($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
      throw "Refusing reparse point while snapshotting CentralD ACLs: $($_.FullName)"
    }
    $items.Add($_)
  }
  $snapshot = [System.Collections.Generic.List[object]]::new()
  foreach ($item in $items) {
    if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
      throw "Refusing reparse point while snapshotting CentralD ACLs: $($item.FullName)"
    }
    $acl = Get-Acl -LiteralPath $item.FullName
    $snapshot.Add([PSCustomObject]@{
      Path = $item.FullName
      IsDirectory = [bool]$item.PSIsContainer
      Sddl = $acl.GetSecurityDescriptorSddlForm([System.Security.AccessControl.AccessControlSections]::All)
    })
  }
  return $snapshot
}

function Restore-CentralDAclSnapshot {
  param([Parameter(Mandatory = $true)][object[]]$Snapshot)

  foreach ($entry in $Snapshot) {
    if (-not (Test-Path -LiteralPath $entry.Path)) {
      continue
    }
    $item = Get-Item -LiteralPath $entry.Path -Force
    if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
      throw "Refusing reparse point while restoring CentralD ACLs: $($item.FullName)"
    }
    if ($entry.IsDirectory) {
      $acl = [System.Security.AccessControl.DirectorySecurity]::new()
    } else {
      $acl = [System.Security.AccessControl.FileSecurity]::new()
    }
    $acl.SetSecurityDescriptorSddlForm($entry.Sddl, [System.Security.AccessControl.AccessControlSections]::All)
    Set-Acl -LiteralPath $entry.Path -AclObject $acl
  }
}

function Set-CentralDTreeAcl {
  param(
    [Parameter(Mandatory = $true)][string]$Path,
    [ValidateSet("None", "ReadAndExecute", "Modify")][string]$ServiceRights = "None"
  )

  Assert-CentralDLeafPath -Actual $Path -Expected $Path -Label "CentralD ACL root"
  $root = Get-Item -LiteralPath $Path -Force
  $maximumItems = 4096
  $items = [System.Collections.Generic.List[System.IO.FileSystemInfo]]::new()
  $items.Add($root)
  Get-ChildItem -LiteralPath $Path -Force -Recurse | ForEach-Object {
    if ($items.Count -ge $maximumItems) {
      throw "CentralD path contains more than $maximumItems entries; refusing recursive ACL replacement"
    }
    if (($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
      throw "Refusing reparse point while securing CentralD path: $($_.FullName)"
    }
    $items.Add($_)
  }

  $systemSid = [System.Security.Principal.SecurityIdentifier]::new("S-1-5-18")
  $administratorsSid = [System.Security.Principal.SecurityIdentifier]::new("S-1-5-32-544")
  $serviceSid = $null
  if ($ServiceRights -ne "None") {
    $serviceSid = ([System.Security.Principal.NTAccount]::new($serviceIdentity)).Translate(
      [System.Security.Principal.SecurityIdentifier]
    )
  }
  $allow = [System.Security.AccessControl.AccessControlType]::Allow
  $propagation = [System.Security.AccessControl.PropagationFlags]::None

  foreach ($item in $items) {
    if ($item.PSIsContainer) {
      $acl = [System.Security.AccessControl.DirectorySecurity]::new()
      $inheritance = [System.Security.AccessControl.InheritanceFlags]"ContainerInherit, ObjectInherit"
    } else {
      $acl = [System.Security.AccessControl.FileSecurity]::new()
      $inheritance = [System.Security.AccessControl.InheritanceFlags]::None
    }
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner($administratorsSid)
    $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(
      $systemSid, "FullControl", $inheritance, $propagation, $allow
    ))
    $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(
      $administratorsSid, "FullControl", $inheritance, $propagation, $allow
    ))
    if ($null -ne $serviceSid) {
      $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(
        $serviceSid, $ServiceRights, $inheritance, $propagation, $allow
      ))
    }
    Set-Acl -LiteralPath $item.FullName -AclObject $acl
  }
}

# Complete all destructive/path/start preflight before changing the service or ACLs.
if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
  throw "centrald-client.exe was not found next to this installer script."
}
Assert-RegularNonReparseFile -Path $source
Assert-CentralDLeafPath -Actual $InstallDirectory -Expected (Join-Path $ProgramFilesDirectory "CentralD") -Label "Install directory"
Assert-CentralDLeafPath -Actual $DataDirectory -Expected (Join-Path $ProgramDataDirectory "CentralD") -Label "Data directory"
if ($InstallDirectory.StartsWith($DataDirectory + '\', [System.StringComparison]::OrdinalIgnoreCase) -or
    $DataDirectory.StartsWith($InstallDirectory + '\', [System.StringComparison]::OrdinalIgnoreCase) -or
    [string]::Equals($InstallDirectory, $DataDirectory, [System.StringComparison]::OrdinalIgnoreCase)) {
  throw "CentralD install and data directories must be separate, non-overlapping leaf directories."
}
$enrolled = Test-Path -LiteralPath $currentPointer -PathType Leaf
if ($StartAfterInstall -and -not $enrolled) {
  throw "Cannot start before enrollment publishes configurations\current.pointer. Enroll first, then rerun without changing paths."
}
if ($enrolled) {
  Assert-RegularNonReparseFile -Path $currentPointer
}

$installDirectoryExisted = Test-Path -LiteralPath $InstallDirectory -PathType Container
$dataDirectoryExisted = Test-Path -LiteralPath $DataDirectory -PathType Container
$installAclSnapshot = Get-CentralDAclSnapshot -Path $InstallDirectory
$dataAclSnapshot = Get-CentralDAclSnapshot -Path $DataDirectory
$manualStartMarkerExisted = Test-Path -LiteralPath $manualStartMarker -PathType Leaf
$manualStartMarkerContents = if ($manualStartMarkerExisted) { Get-Content -LiteralPath $manualStartMarker -Raw } else { $null }

$existing = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
$wasRunning = $false
$previousStartValue = $null
$previousDelayedAuto = $false
$serviceRegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName"
if ($null -ne $existing) {
  $wasRunning = $existing.Status -ne "Stopped"
  $serviceCim = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
  if ($null -eq $serviceCim -or -not [string]::Equals($serviceCim.StartName, $serviceIdentity, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "An existing CentralDClient service is not owned by the expected virtual service account; refusing to replace it."
  }
  if (Test-Path -LiteralPath $serviceRegistryPath) {
    $serviceConfig = Get-ItemProperty -LiteralPath $serviceRegistryPath
    $previousStartValue = $serviceConfig.Start
    $previousDelayedAuto = $serviceConfig.DelayedAutoStart -eq 1
  }
}

$existingBroker = Get-Service -Name $brokerServiceName -ErrorAction SilentlyContinue
$brokerWasRunning = $false
$previousBrokerStartValue = $null
$previousBrokerDelayedAuto = $false
$brokerRegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$brokerServiceName"
if ($null -ne $existingBroker) {
  $brokerWasRunning = $existingBroker.Status -ne "Stopped"
  $brokerCim = Get-CimInstance Win32_Service -Filter "Name='$brokerServiceName'"
  if ($null -eq $brokerCim -or -not [string]::Equals($brokerCim.StartName, $brokerIdentity, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "An existing CentralDBroker service is not owned by the expected LocalSystem account; refusing to replace it."
  }
  if (Test-Path -LiteralPath $brokerRegistryPath) {
    $brokerConfig = Get-ItemProperty -LiteralPath $brokerRegistryPath
    $previousBrokerStartValue = $brokerConfig.Start
    $previousBrokerDelayedAuto = $brokerConfig.DelayedAutoStart -eq 1
  }
}

New-Item -ItemType Directory -Path $InstallDirectory -Force | Out-Null
New-Item -ItemType Directory -Path $DataDirectory -Force | Out-Null
Assert-NoReparseAncestors -Path $InstallDirectory
Assert-NoReparseAncestors -Path $DataDirectory
if (Test-Path -LiteralPath $stagedBinary) {
  Assert-RegularNonReparseFile -Path $stagedBinary
  Remove-Item -LiteralPath $stagedBinary -Force
}
Copy-Item -LiteralPath $source -Destination $stagedBinary
Assert-RegularNonReparseFile -Path $stagedBinary

$desiredStart = "demand"
if ($KeepManualStart) {
  $desiredStart = "demand"
} elseif ($null -ne $previousStartValue) {
  switch ($previousStartValue) {
    2 { $desiredStart = $(if ($previousDelayedAuto) { "delayed-auto" } else { "auto" }) }
    4 { $desiredStart = "disabled" }
    default { $desiredStart = "demand" }
  }
} elseif ($enrolled) {
  $desiredStart = "delayed-auto"
}
if ($StartAfterInstall -and -not $KeepManualStart) {
  $desiredStart = "delayed-auto"
}

$createdService = $false
$createdBrokerService = $false
$hadPreviousBinary = Test-Path -LiteralPath $destination -PathType Leaf
try {
  if ($null -ne $existing -and $existing.Status -ne "Stopped") {
    Stop-Service -Name $serviceName -Force
    $existing.WaitForStatus("Stopped", [TimeSpan]::FromSeconds(30))
  }
  if ($null -ne $existingBroker -and $existingBroker.Status -ne "Stopped") {
    Stop-Service -Name $brokerServiceName -Force
    $existingBroker.WaitForStatus("Stopped", [TimeSpan]::FromSeconds(30))
  }

  Set-CentralDTreeAcl -Path $InstallDirectory
  Set-CentralDTreeAcl -Path $DataDirectory

  if ($hadPreviousBinary) {
    Assert-RegularNonReparseFile -Path $destination
    if (Test-Path -LiteralPath $backupBinary) {
      Assert-RegularNonReparseFile -Path $backupBinary
      Remove-Item -LiteralPath $backupBinary -Force
    }
    Move-Item -LiteralPath $destination -Destination $backupBinary
  }
  Move-Item -LiteralPath $stagedBinary -Destination $destination

  $quotedBinary = '"{0}" windows-service' -f $destination
  if ($null -eq $existing) {
    Invoke-NativeChecked $ScExe create $serviceName `
      "binPath= $quotedBinary" `
      "start= $desiredStart" `
      "obj= $serviceIdentity" `
      "DisplayName= CentralD Client"
    $createdService = $true
  } else {
    Invoke-NativeChecked $ScExe config $serviceName `
      "binPath= $quotedBinary" `
      "start= $desiredStart" `
      "obj= $serviceIdentity" `
      "DisplayName= CentralD Client"
  }
  Invoke-NativeChecked $ScExe sidtype $serviceName unrestricted

  $brokerQuotedBinary = '"{0}" windows-service-broker' -f $destination
  $brokerStart = "demand"
  if ($null -eq $existingBroker) {
    Invoke-NativeChecked $ScExe create $brokerServiceName `
      "binPath= $brokerQuotedBinary" `
      "start= $brokerStart" `
      "obj= $brokerIdentity" `
      "DisplayName= CentralD Broker"
    $createdBrokerService = $true
  } else {
    Invoke-NativeChecked $ScExe config $brokerServiceName `
      "binPath= $brokerQuotedBinary" `
      "start= $brokerStart" `
      "obj= $brokerIdentity" `
      "DisplayName= CentralD Broker"
  }
  Invoke-NativeChecked $ScExe description $brokerServiceName "Privileged CentralD operation broker"
  Invoke-NativeChecked $ScExe failure $brokerServiceName `
    "reset= 86400" `
    "actions= restart/5000/restart/15000/restart/60000"

  Set-CentralDTreeAcl -Path $InstallDirectory -ServiceRights ReadAndExecute
  Set-CentralDTreeAcl -Path $DataDirectory -ServiceRights Modify

  $preserveManualOptOut = $KeepManualStart -or (
    -not $StartAfterInstall -and $null -ne $previousStartValue -and $previousStartValue -ne 2
  )
  if ($preserveManualOptOut) {
    Set-Content -LiteralPath $manualStartMarker -Value "CentralD automatic service start is disabled by operator policy." -Encoding ASCII
  } elseif (Test-Path -LiteralPath $manualStartMarker) {
    Remove-Item -LiteralPath $manualStartMarker -Force
  }

  Invoke-NativeChecked $ScExe description $serviceName "Outbound-only CentralD managed client"
  Invoke-NativeChecked $ScExe failure $serviceName `
    "reset= 86400" `
    "actions= restart/5000/restart/15000/restart/60000"

  $shouldStart = $StartAfterInstall -or ($wasRunning -and $enrolled)
  if ($shouldStart) {
    Start-Service -Name $serviceName
  }
  if ($brokerWasRunning) {
    Start-Service -Name $brokerServiceName
  }
  if (Test-Path -LiteralPath $backupBinary) {
    Remove-Item -LiteralPath $backupBinary -Force
  }
} catch {
  $failure = $_
  if ($createdService) {
    try { Invoke-NativeChecked $ScExe delete $serviceName } catch { Write-Warning $_ }
  }
  if ($createdBrokerService) {
    try { Invoke-NativeChecked $ScExe delete $brokerServiceName } catch { Write-Warning $_ }
  }
  if (Test-Path -LiteralPath $destination) {
    try { Remove-Item -LiteralPath $destination -Force } catch { Write-Warning $_ }
  }
  if (Test-Path -LiteralPath $backupBinary) {
    try { Move-Item -LiteralPath $backupBinary -Destination $destination } catch { Write-Warning $_ }
  }
  if ($null -ne $existing) {
    try {
      $restoreStart = "demand"
      switch ($previousStartValue) {
        2 { $restoreStart = $(if ($previousDelayedAuto) { "delayed-auto" } else { "auto" }) }
        4 { $restoreStart = "disabled" }
        default { $restoreStart = "demand" }
      }
      Invoke-NativeChecked $ScExe config $serviceName "start= $restoreStart"
      if ($wasRunning -and $enrolled) { Start-Service -Name $serviceName }
    } catch { Write-Warning "CentralD service rollback was incomplete: $_" }
  }
  if ($null -ne $existingBroker) {
    try {
      $restoreBrokerStart = "demand"
      switch ($previousBrokerStartValue) {
        2 { $restoreBrokerStart = $(if ($previousBrokerDelayedAuto) { "delayed-auto" } else { "auto" }) }
        4 { $restoreBrokerStart = "disabled" }
        default { $restoreBrokerStart = "demand" }
      }
      Invoke-NativeChecked $ScExe config $brokerServiceName "start= $restoreBrokerStart"
      if ($brokerWasRunning -and $enrolled) { Start-Service -Name $brokerServiceName }
    } catch { Write-Warning "CentralD broker service rollback was incomplete: $_" }
  }
  try {
    if ($manualStartMarkerExisted) {
      Set-Content -LiteralPath $manualStartMarker -Value $manualStartMarkerContents -NoNewline -Encoding ASCII
    } elseif (Test-Path -LiteralPath $manualStartMarker) {
      Remove-Item -LiteralPath $manualStartMarker -Force
    }
  } catch { Write-Warning "CentralD manual-start policy rollback was incomplete: $_" }
  try { Restore-CentralDAclSnapshot -Snapshot $installAclSnapshot } catch { Write-Warning "CentralD install ACL rollback was incomplete: $_" }
  try { Restore-CentralDAclSnapshot -Snapshot $dataAclSnapshot } catch { Write-Warning "CentralD data ACL rollback was incomplete: $_" }
  if (-not $installDirectoryExisted -and (Test-Path -LiteralPath $InstallDirectory)) {
    try { Remove-Item -LiteralPath $InstallDirectory -Recurse -Force } catch { Write-Warning "Could not remove newly created CentralD install directory: $_" }
  }
  if (-not $dataDirectoryExisted -and (Test-Path -LiteralPath $DataDirectory)) {
    try { Remove-Item -LiteralPath $DataDirectory -Recurse -Force } catch { Write-Warning "Could not remove newly created CentralD data directory: $_" }
  }
  throw $failure
} finally {
  if (Test-Path -LiteralPath $stagedBinary) {
    Remove-Item -LiteralPath $stagedBinary -Force -ErrorAction SilentlyContinue
  }
}

Write-Host "CentralD Client installed as $serviceIdentity with start mode $desiredStart."
Write-Host "CentralD Broker installed as LocalSystem."
if ($enrolled) {
  Write-Host "This client is already enrolled. Confirm the CentralDClient service is running with: Get-Service CentralDClient"
} else {
  Write-Host "Next step: open an elevated terminal and run: centrald-client enroll"
}
