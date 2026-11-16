<#
.SYNOPSIS
    Enables read auditing (SACL + audit subcategories) on the VPN/SASE client state, certificate
    private-key and DPAPI master-key locations used by the Pass-the-Device endpoint rules (event 4663).

.DESCRIPTION
    Dry run by default: prints what it would change. Pass -Apply to change anything.
    Run elevated, in Windows PowerShell 5.1, on a lab host first.

    - Enables "File System" and "Registry" success auditing by subcategory GUID
      (GUIDs avoid localized subcategory names, e.g. on Japanese Windows).
    - Adds an Everyone / Success audit ACE for read access only:
        files and folders  -> ReadData
        registry keys      -> QueryValues
    - Per-user paths are applied to every existing profile under C:\Users.
      Profiles created later are NOT covered: re-run from a scheduled task or an
      Intune remediation script.

    -SkipDpapi omits the DPAPI master-key folders; -SkipCertKeys omits the CAPI/CNG private-key
    folders (the busiest: every process that uses a legacy CAPI key reads its file).

    -Remove deletes exactly the ACEs this script adds. Pass the same -Skip* switches as when applying.

.NOTES
    Volume: lsass.exe reads master keys during normal DPAPI use and the vendor clients read
    their own state. Filter those at collection (DCR/WEF XPath) or in the query. Measure a
    week of event volume per host before enabling fleet-wide.
#>
[CmdletBinding()]
param(
    [switch]$Apply,
    [switch]$Remove,
    [switch]$SkipDpapi,
    [switch]$SkipCertKeys
)

$ErrorActionPreference = 'Stop'
$Everyone = New-Object System.Security.Principal.SecurityIdentifier('S-1-1-0')

$FileSystemSubcategory = '{0CCE921D-69AE-11D9-BED3-505054503030}'
$RegistrySubcategory   = '{0CCE921E-69AE-11D9-BED3-505054503030}'

# Machine-wide folders (inherit to children)
$MachineFolders = @(
    "$env:ProgramData\Netskope\stagent\data",
    "$env:ProgramData\Cisco\Cisco Secure Client\VPN",
    "$env:ProgramData\Cisco\Cisco AnyConnect Secure Mobility Client"
)
# Zscaler keeps protected state in log_<SID> folders
$MachineFolders += @(Get-ChildItem -Path "$env:ProgramData\Zscaler" -Directory -Filter 'log_*' -ErrorAction SilentlyContinue |
    ForEach-Object { $_.FullName })

if (-not $SkipDpapi) {
    $MachineFolders += "$env:SystemRoot\System32\Microsoft\Protect\S-1-5-18"
}
# Software-backed certificate private keys (CAPI and CNG). Busier than the rest: -SkipCertKeys to omit.
if (-not $SkipCertKeys) {
    $MachineFolders += @(
        "$env:ProgramData\Microsoft\Crypto\RSA\MachineKeys",
        "$env:ProgramData\Microsoft\Crypto\Keys",
        "$env:ProgramData\Microsoft\Crypto\SystemKeys"
    )
}

# Per-user folders, relative to each profile
$UserFolders = @(
    'AppData\Local\Palo Alto Networks\GlobalProtect',
    'AppData\Roaming\Netskope\stagent\data',
    'AppData\Local\Cisco\Cisco AnyConnect Secure Mobility Client',
    'AppData\Local\Cisco\Cisco Secure Client\VPN',
    'AppData\Local\Cisco\Cisco HostScan\log',
    'AppData\Local\Cisco\Cisco Secure Firewall Posture\log',
    'AppData\Local\Cisco Secure Firewall Posture\log'
)
if (-not $SkipDpapi) {
    $UserFolders += 'AppData\Roaming\Microsoft\Protect'
}
if (-not $SkipCertKeys) {
    $UserFolders += 'AppData\Roaming\Microsoft\Crypto'
}

# GlobalProtect HIP state lives in the install folder next to the binaries. Auditing the whole
# folder would log every image load, so audit only these files. GlobalProtect may replace them
# when it refreshes HIP data, and a replaced file loses this ACE: re-run on a schedule, or use the
# Kernel-File ETW rule for these paths.
$MachineFiles = @()
foreach ($gpDir in @("$env:ProgramFiles\Palo Alto Networks\GlobalProtect",
                     "${env:ProgramFiles(x86)}\Palo Alto Networks\GlobalProtect")) {
    foreach ($pattern in @('HipPolicy.dat', 'HIP_*_Report_*.dat', 'pan_gp_hrpt.xml', 'PanGPHip.log')) {
        $MachineFiles += @(Get-ChildItem -Path $gpDir -File -Filter $pattern -ErrorAction SilentlyContinue |
            ForEach-Object { $_.FullName })
    }
}

$RegistryKeys = @(
    'HKLM:\SOFTWARE\Zscaler Inc.\Zscaler',
    'HKLM:\SOFTWARE\WOW6432Node\Zscaler Inc.\Zscaler',
    'HKLM:\SOFTWARE\NetSkope\Provisioning',
    'HKLM:\SOFTWARE\WOW6432Node\NetSkope\Provisioning'
)

function Test-Elevated {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Set-FolderAudit([string]$Path, [switch]$File) {
    if (-not (Test-Path -LiteralPath $Path)) { return }
    # Folders inherit the ACE to everything below them; a single file takes no inheritance flags.
    $inherit = if ($File) { [System.Security.AccessControl.InheritanceFlags]::None }
               else { [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit' }
    $rule = New-Object System.Security.AccessControl.FileSystemAuditRule(
        $Everyone,
        [System.Security.AccessControl.FileSystemRights]::ReadData,
        $inherit,
        [System.Security.AccessControl.PropagationFlags]::None,
        [System.Security.AccessControl.AuditFlags]::Success)
    $verb = if ($Remove) { 'remove' } else { 'add' }
    Write-Host "[$verb] file audit  $Path"
    if (-not $Apply) { return }
    $dir = Get-Item -LiteralPath $Path -Force
    # Read and write only the SACL section, so owner and DACL are left untouched.
    $sec = $dir.GetAccessControl([System.Security.AccessControl.AccessControlSections]::Audit)
    if ($Remove) { [void]$sec.RemoveAuditRuleSpecific($rule) } else { $sec.AddAuditRule($rule) }
    $dir.SetAccessControl($sec)
}

function Set-KeyAudit([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $rule = New-Object System.Security.AccessControl.RegistryAuditRule(
        $Everyone,
        [System.Security.AccessControl.RegistryRights]::QueryValues,
        [System.Security.AccessControl.InheritanceFlags]::None,
        [System.Security.AccessControl.PropagationFlags]::None,
        [System.Security.AccessControl.AuditFlags]::Success)
    $verb = if ($Remove) { 'remove' } else { 'add' }
    Write-Host "[$verb] key audit   $Path"
    if (-not $Apply) { return }
    $acl = Get-Acl -LiteralPath $Path -Audit
    if ($Remove) { [void]$acl.RemoveAuditRuleSpecific($rule) } else { $acl.AddAuditRule($rule) }
    Set-Acl -LiteralPath $Path -AclObject $acl
}

if ($Apply -and -not (Test-Elevated)) { throw 'Run elevated to change audit policy and SACLs.' }
if (-not $Apply) { Write-Host 'Dry run. Re-run with -Apply to make these changes.' -ForegroundColor Yellow }

if (-not $Remove) {
    Write-Host "[policy] File System + Registry success auditing"
    if ($Apply) {
        & auditpol.exe /set /subcategory:$FileSystemSubcategory /success:enable | Out-Null
        & auditpol.exe /set /subcategory:$RegistrySubcategory /success:enable | Out-Null
    }
}

$MachineFolders | ForEach-Object { Set-FolderAudit $_ }
$MachineFiles | ForEach-Object { Set-FolderAudit $_ -File }

Get-ChildItem -Path "$env:SystemDrive\Users" -Directory -Force -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -notin @('Public', 'Default', 'Default User', 'All Users') } |
    ForEach-Object {
        $profileRoot = $_.FullName
        $UserFolders | ForEach-Object { Set-FolderAudit (Join-Path $profileRoot $_) }
    }

$RegistryKeys | ForEach-Object { Set-KeyAudit $_ }

Write-Host 'Done. Audit subcategories are left enabled by -Remove; disable them with auditpol if nothing else needs them.'
