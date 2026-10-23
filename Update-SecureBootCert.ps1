<#
.SYNOPSIS
    Update-SecureBootCert v2.0 - checks the Secure Boot certificates in the firmware and,
    if needed, asks Windows to install the 2023 certificates and the 2023-signed boot manager.

.DESCRIPTION
    Microsoft's 2011 Secure Boot certificates expired in 2026:
      Microsoft Corporation KEK CA 2011      2026-06-24  -> Microsoft Corporation KEK 2K CA 2023
      Microsoft Corporation UEFI CA 2011     2026-06-27  -> Microsoft UEFI CA 2023 + Microsoft Option ROM UEFI CA 2023
      Microsoft Windows Production PCA 2011  2026-10-19  -> Windows UEFI CA 2023
    A PC without the 2023 certificates still starts and still gets normal Windows updates, but
    it no longer gets security fixes for the boot process (boot manager, DB/DBX updates).

    What the script does:
      1. Reads the state (changes nothing): Secure Boot, the certificates in KEK and DB with
         their real expiry dates, Windows' own update status, the Secure-Boot-Update task,
         BitLocker and recent Secure Boot events.
      2. Only after you confirm:
         - Windows 10 21H2/22H2 older than build .6809: installs KB5073724 (optional)
         - installs all pending Windows software updates (optional, off by default)
         - suspends BitLocker for 2 restarts (optional)
         - sets AvailableUpdates = 0x5944 (Microsoft's full update) and starts the
           Secure-Boot-Update task. An update Windows already queued is never overwritten.
      3. Shows the result and asks to restart. After the restart, run it again: it starts
         the next step and confirms the result.

    Log files: %ProgramData%\Update-SecureBootCert

.PARAMETER CheckOnly
    Only show the state; change nothing. Exit code 0 = up to date, 2 = update needed, 3010 = restart needed.
.PARAMETER Unattended
    No questions. Uses the defaults plus the switches you pass.
.PARAMETER InstallWindowsUpdates
    Also install all pending Windows software updates.
.PARAMETER SkipKB
    Do not install KB5073724 on older Windows 10.
.PARAMETER DbOnly
    Old method (v1.x): only add Windows UEFI CA 2023 to the DB (AvailableUpdates = 0x40).
.PARAMETER SuspendBitLocker
    Suspend BitLocker on the system drive for the next 2 restarts.
.PARAMETER Restart
    Restart automatically (after 30 seconds) when a restart is needed.
.PARAMETER NoPause
    Do not wait for Enter at the end (used by RunMe.bat).
.PARAMETER LogPath
    Log file path. Default: %ProgramData%\Update-SecureBootCert\Update-SecureBootCert_<date>.log

.EXAMPLE
    .\Update-SecureBootCert.ps1
    Interactive: shows the state and asks before changing anything.
.EXAMPLE
    .\Update-SecureBootCert.ps1 -CheckOnly
    Report only.
.EXAMPLE
    .\Update-SecureBootCert.ps1 -Unattended -SuspendBitLocker -Restart
    Silent update, for scripts and deployment tools.

.NOTES
    Version 2.0. Original tool by anomixer; GUI (1.2) and 2.0 by j0p3s.
    Exit codes: 0 up to date / nothing to do, 1 error, 2 update needed or not finished,
                3 cancelled, 3010 restart needed (run again after restarting).
#>

[CmdletBinding()]
param(
    [switch]$CheckOnly,
    [switch]$Unattended,
    [switch]$InstallWindowsUpdates,
    [switch]$SkipKB,
    [switch]$DbOnly,
    [switch]$SuspendBitLocker,
    [switch]$Restart,
    [switch]$NoPause,
    [string]$LogPath
)

$SbBoundParams = $PSBoundParameters
$ProgressPreference = 'SilentlyContinue'

# >>> SB-ENGINE BEGIN - keep this block identical in Update-SecureBootCert.ps1 and Update-SecureBootCert-GUI.cmd <<<
# Shared by the script and the GUI. Functions that report progress call Write-SbLog,
# which the script and the GUI each define for themselves.

$SbVersion   = '2.0'
$SbKey       = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot'
$SbTaskPath  = '\Microsoft\Windows\PI\'
$SbTaskName  = 'Secure-Boot-Update'
$SbFullValue = 0x5944   # Microsoft's value for the full update: 2023 KEK, 2023 DB certificates, 2023-signed boot manager
$SbDbValue   = 0x40     # Old method (v1.x): only adds Windows UEFI CA 2023 to the DB
$SbKbId      = 'KB5073724'
$SbKbUbr     = 6809     # Windows 10 build 1904x.6809 = KB5073724

# ----- Reference data -----

function Get-SbKnownCerts {
    @(
        [pscustomobject]@{ Store = 'KEK'; Name = 'Microsoft Corporation KEK CA 2011';     Year = 2011; Expires = [datetime]'2026-06-24'; Use = 'Signs updates to DB and DBX' }
        [pscustomobject]@{ Store = 'KEK'; Name = 'Microsoft Corporation KEK 2K CA 2023';  Year = 2023; Expires = [datetime]'2038-03-02'; Use = 'Signs updates to DB and DBX' }
        [pscustomobject]@{ Store = 'db';  Name = 'Microsoft Windows Production PCA 2011'; Year = 2011; Expires = [datetime]'2026-10-19'; Use = 'Windows boot manager' }
        [pscustomobject]@{ Store = 'db';  Name = 'Windows UEFI CA 2023';                  Year = 2023; Expires = [datetime]'2035-06-13'; Use = 'Windows boot manager' }
        [pscustomobject]@{ Store = 'db';  Name = 'Microsoft Corporation UEFI CA 2011';    Year = 2011; Expires = [datetime]'2026-06-27'; Use = 'Third-party boot loaders and option ROMs' }
        [pscustomobject]@{ Store = 'db';  Name = 'Microsoft UEFI CA 2023';                Year = 2023; Expires = [datetime]'2038-06-13'; Use = 'Third-party boot loaders (Linux shim, tools)' }
        [pscustomobject]@{ Store = 'db';  Name = 'Microsoft Option ROM UEFI CA 2023';     Year = 2023; Expires = [datetime]'2038-10-26'; Use = 'Third-party option ROMs (graphics, network)' }
    )
}

function Get-SbEventMeaning([int]$Id) {
    switch ($Id) {
        1032 { 'Not applied: BitLocker would have asked for the recovery key' }
        1033 { 'DBX update postponed: an old, possibly revoked boot manager is on the EFI partition' }
        1034 { 'DBX updated' }
        1036 { 'DB updated' }
        1037 { 'DBX updated: Windows Production PCA 2011 revoked' }
        1042 { 'DBX updated: old boot manager versions blocked' }
        1043 { 'KEK updated with Microsoft Corporation KEK 2K CA 2023' }
        1044 { 'DB updated with Microsoft Option ROM UEFI CA 2023' }
        1045 { 'DB updated with Microsoft UEFI CA 2023' }
        1795 { 'The firmware returned an error; Windows tries again at the next restart' }
        1796 { 'Unexpected error; Windows tries again at the next restart' }
        1797 { 'DBX update blocked: Windows UEFI CA 2023 is not in the DB' }
        1798 { 'DBX update blocked: the boot manager is not signed with Windows UEFI CA 2023' }
        1799 { 'Boot manager signed with Windows UEFI CA 2023 installed' }
        1800 { 'A restart is needed before the update can continue' }
        1801 { 'The 2023 certificates/boot manager are not fully applied to the firmware yet' }
        1802 { 'Blocked by Microsoft: known firmware issue on this device' }
        1803 { 'KEK update not possible: no KEK signed by this PC maker''s platform key (PK)' }
        1808 { 'Finished: this PC has the 2023 Secure Boot certificates and boot manager' }
        default { 'Secure Boot servicing event' }
    }
}

# ----- Reading the state (nothing is changed here) -----

function Get-SbOsInfo {
    $v = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $build = [int]$v.CurrentBuildNumber
    $ubr = 0
    if ($null -ne $v.UBR) { $ubr = [int]$v.UBR }
    $type = [string]$v.InstallationType
    $isClient = ($type -eq 'Client')
    $name = [string]$v.ProductName
    if ($isClient -and $build -ge 22000) { $name = $name -replace 'Windows 10', 'Windows 11' }
    $display = [string]$v.DisplayVersion
    if (-not $display) { $display = [string]$v.ReleaseId }
    $arch = $env:PROCESSOR_ARCHITEW6432
    if (-not $arch) { $arch = $env:PROCESSOR_ARCHITECTURE }
    $archTag = switch ($arch) { 'AMD64' { 'x64' } 'ARM64' { 'ARM64' } 'x86' { 'x86' } default { '' } }
    [pscustomobject]@{
        Name          = $name
        Display       = $display
        Build         = $build
        Ubr           = $ubr
        Type          = $type
        IsClient      = $isClient
        IsServer      = (-not $isClient)
        IsWin10Client = ($isClient -and ($build -eq 19044 -or $build -eq 19045))
        IsWin11       = ($isClient -and $build -ge 22000)
        Arch          = $archTag
    }
}

# $true / $false, or $null when Secure Boot is not available (legacy BIOS/CSM)
function Get-SbSecureBoot {
    try { [bool](Confirm-SecureBootUEFI -ErrorAction Stop) } catch { $null }
}

# Raw bytes of a Secure Boot variable (KEK or db), or $null
function Get-SbUefiVariable([string]$Name) {
    try {
        $v = Get-SecureBootUEFI -Name $Name -ErrorAction Stop
        if ($null -eq $v -or $null -eq $v.Bytes) { return $null }
        return , ([byte[]]$v.Bytes)
    } catch { return $null }
}

# X.509 certificates in an EFI_SIGNATURE_LIST buffer
function Get-SbEslCerts([byte[]]$Bytes, [string]$Store) {
    if ($null -eq $Bytes) { return }
    $x509 = [guid]'a5c059a1-94e4-4aa7-87b5-ab155c2bf072'   # EFI_CERT_X509_GUID
    $o = 0
    while ($o + 28 -le $Bytes.Length) {
        $type     = [guid]::new([byte[]]$Bytes[$o..($o + 15)])
        $listSize = [int][BitConverter]::ToUInt32($Bytes, $o + 16)
        $hdrSize  = [int][BitConverter]::ToUInt32($Bytes, $o + 20)
        $sigSize  = [int][BitConverter]::ToUInt32($Bytes, $o + 24)
        if ($listSize -lt 28 -or ($o + $listSize) -gt $Bytes.Length) { break }
        if ($type -eq $x509 -and $sigSize -gt 16) {
            $s = $o + 28 + $hdrSize
            while ($s + $sigSize -le $o + $listSize) {
                try {
                    $der = [byte[]]$Bytes[($s + 16)..($s + $sigSize - 1)]
                    $c = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($der)
                    [pscustomobject]@{
                        Store      = $Store
                        Name       = $c.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
                        NotAfter   = $c.NotAfter
                        Thumbprint = $c.Thumbprint
                    }
                } catch { }
                $s += $sigSize
            }
        }
        $o += $listSize
    }
}

function Get-SbCertStatus([datetime]$NotAfter) {
    $now = Get-Date
    if ($NotAfter -lt $now) { 'Expired' }
    elseif ($NotAfter -lt $now.AddDays(180)) { 'Expires soon' }
    else { 'Valid' }
}

# All certificates in KEK and db, with status. Readable = $false when the variables can't be read.
function Get-SbFirmwareCerts {
    $known = Get-SbKnownCerts
    $found = @()
    $readable = $false
    foreach ($store in 'KEK', 'db') {
        $bytes = Get-SbUefiVariable $store
        if ($null -eq $bytes) { continue }
        $readable = $true
        $parsed = @(Get-SbEslCerts -Bytes $bytes -Store $store)
        if ($parsed.Count -eq 0 -and $bytes.Length -gt 0) {
            # Fallback: look for the known names in the raw bytes
            $text = [Text.Encoding]::ASCII.GetString($bytes)
            foreach ($k in $known) {
                if ($k.Store -eq $store -and $text.Contains($k.Name)) {
                    $parsed += [pscustomobject]@{ Store = $store; Name = $k.Name; NotAfter = $k.Expires; Thumbprint = '' }
                }
            }
        }
        $found += $parsed
    }
    $certs = foreach ($c in $found) {
        $k = $known | Where-Object { $_.Name -eq $c.Name } | Select-Object -First 1
        $year = 0; $use = 'Added by the PC maker or another vendor'
        if ($k) { $year = $k.Year; $use = $k.Use }
        [pscustomobject]@{
            Store    = $(if ($c.Store -eq 'db') { 'DB' } else { 'KEK' })
            Name     = $c.Name
            NotAfter = $c.NotAfter
            Status   = Get-SbCertStatus $c.NotAfter
            Year     = $year
            Use      = $use
        }
    }
    [pscustomobject]@{ Readable = $readable; Certs = @($certs) }
}

function Get-SbServicing {
    $p = $null
    try { $p = Get-ItemProperty -Path ($SbKey + '\Servicing') -ErrorAction Stop } catch { }
    [pscustomobject]@{
        Status     = $(if ($p) { $p.UEFICA2023Status })
        Error      = $(if ($p) { $p.UEFICA2023Error })
        ErrorEvent = $(if ($p) { $p.UEFICA2023ErrorEvent })
        Capable    = $(if ($p) { $p.WindowsUEFICA2023Capable })
    }
}

function Get-SbAvailableUpdates {
    try {
        $v = (Get-ItemProperty -Path $SbKey -Name 'AvailableUpdates' -ErrorAction Stop).AvailableUpdates
        if ($null -ne $v) { return [int]$v }
    } catch { }
    return $null
}

function Get-SbTask {
    $r = [pscustomobject]@{ Exists = $false; State = ''; LastRun = $null; LastResult = $null }
    try {
        $t = Get-ScheduledTask -TaskPath $SbTaskPath -TaskName $SbTaskName -ErrorAction Stop
        $r.Exists = $true
        $r.State = [string]$t.State
        $i = $t | Get-ScheduledTaskInfo -ErrorAction Stop
        if ($i.LastRunTime -and $i.LastRunTime.Year -gt 2000) {
            $r.LastRun = $i.LastRunTime
            $r.LastResult = [int64]$i.LastTaskResult
        }
    } catch { }
    $r
}

function Get-SbBitLocker {
    $r = [pscustomobject]@{ Available = $false; On = $false; RecoveryPassword = $false; Drive = $env:SystemDrive }
    try {
        $vol = Get-CimInstance -Namespace 'root\cimv2\Security\MicrosoftVolumeEncryption' -ClassName 'Win32_EncryptableVolume' -Filter ("DriveLetter='{0}'" -f $env:SystemDrive) -ErrorAction Stop
        if ($vol) {
            $r.Available = $true
            $r.On = ($vol.ProtectionStatus -eq 1)
            try {
                $kp = Invoke-CimMethod -InputObject $vol -MethodName 'GetKeyProtectors' -Arguments @{ KeyProtectorType = [uint32]3 } -ErrorAction Stop
                $r.RecoveryPassword = (@($kp.VolumeKeyProtectorID | Where-Object { $_ }).Count -gt 0)
            } catch { }
        }
    } catch { }
    $r
}

function Get-SbPendingReboot {
    (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or
    (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')
}

function Get-SbLastBoot {
    try { (Get-CimInstance -ClassName 'Win32_OperatingSystem' -ErrorAction Stop).LastBootUpTime } catch { $null }
}

# Newest Secure Boot servicing events first (System log, source TPM-WMI)
function Get-SbEvents([int]$Max = 10) {
    $ids = 1032, 1033, 1034, 1036, 1037, 1042, 1043, 1044, 1045, 1795, 1796, 1797, 1798, 1799, 1800, 1801, 1802, 1803, 1808
    try {
        @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = $ids } -MaxEvents 200 -ErrorAction Stop |
            Where-Object { $_.ProviderName -like '*TPM-WMI*' } |
            Select-Object -First $Max |
            ForEach-Object { [pscustomobject]@{ Time = $_.TimeCreated; Id = $_.Id; Meaning = (Get-SbEventMeaning $_.Id) } })
    } catch { @() }
}

# Decides the overall result from a state object (no system calls, so it can be tested)
function Resolve-SbVerdict($S) {
    $missing = @()
    if (-not $S.HasKek2023)   { $missing += 'Microsoft Corporation KEK 2K CA 2023 (KEK)' }
    if (-not $S.HasWinCa2023) { $missing += 'Windows UEFI CA 2023 (DB)' }
    if ($S.HasUefi2011 -and -not $S.HasMsUefi2023)     { $missing += 'Microsoft UEFI CA 2023 (DB)' }
    if ($S.HasUefi2011 -and -not $S.HasOptionRom2023)  { $missing += 'Microsoft Option ROM UEFI CA 2023 (DB)' }
    if ($null -ne $S.Servicing.Capable -and $S.Servicing.Capable -ne 2) { $missing += 'boot manager signed with Windows UEFI CA 2023' }

    $queued = 0
    if ($null -ne $S.AvailableUpdates) { $queued = $S.AvailableUpdates -band (-bnot 0x4000) }

    if ($null -eq $S.SecureBoot -or -not $S.FirmwareReadable) { $v = 'NoUefi' }
    elseif ($S.Servicing.Status -eq 'Updated') { $v = 'Complete' }
    elseif ($missing.Count -eq 0 -and $queued -eq 0) {
        if ($null -eq $S.Servicing.Capable) { $v = 'CertsPresent' } else { $v = 'Complete' }
    }
    elseif ($queued -eq 0x100) {
        # Only the boot manager step is left. Restarted since the task last ran? Then the task must run again.
        if ($S.Task.LastRun -and $S.LastBoot -and $S.LastBoot -gt $S.Task.LastRun) { $v = 'InProgress' } else { $v = 'RestartNeeded' }
    }
    elseif ($queued -ne 0 -or $S.Servicing.Status -eq 'InProgress') { $v = 'InProgress' }
    elseif ($S.HasWinCa2023 -or $S.HasKek2023) { $v = 'Partial' }
    else { $v = 'NotStarted' }

    $S.Verdict = $v
    $S.Missing = $missing
}

function Get-SbState {
    $os = Get-SbOsInfo
    $fw = Get-SbFirmwareCerts
    $names = @($fw.Certs | ForEach-Object { $_.Name })
    $s = [pscustomobject]@{
        Time             = Get-Date
        Os               = $os
        SecureBoot       = Get-SbSecureBoot
        FirmwareReadable = $fw.Readable
        Certs            = $fw.Certs
        HasKek2023       = ($names -contains 'Microsoft Corporation KEK 2K CA 2023')
        HasWinCa2023     = ($names -contains 'Windows UEFI CA 2023')
        HasMsUefi2023    = ($names -contains 'Microsoft UEFI CA 2023')
        HasOptionRom2023 = ($names -contains 'Microsoft Option ROM UEFI CA 2023')
        HasUefi2011      = ($names -contains 'Microsoft Corporation UEFI CA 2011')
        Servicing        = Get-SbServicing
        AvailableUpdates = Get-SbAvailableUpdates
        Task             = Get-SbTask
        BitLocker        = Get-SbBitLocker
        PendingReboot    = Get-SbPendingReboot
        LastBoot         = Get-SbLastBoot
        Events           = @(Get-SbEvents 10)
        Verdict          = ''
        Missing          = @()
    }
    Resolve-SbVerdict $s
    $s
}

# ----- Text for the script and the GUI -----

# Error codes as 0x80070490 (registry DWORDs and HRESULTs come back as negative Int32)
function Format-SbHex($Value) {
    if ($null -eq $Value) { return '' }
    try { return ('0x{0:X8}' -f [int]$Value) } catch { return ('0x{0:X}' -f $Value) }
}

function Format-SbFlag($Value) {
    if ($null -eq $Value) { return 'not set' }
    if ($Value -eq 0) { return '0 (nothing queued)' }
    $q = $Value -band (-bnot 0x4000)
    $hex = '0x{0:X}' -f $Value
    if ($q -eq 0) { return "$hex (finished)" }
    if ($q -eq 0x100) { return "$hex (restart, then run again)" }
    return "$hex (update queued)"
}

function Format-SbServicing($Svc) {
    $t = 'not reported by this Windows'
    if ($Svc.Status) { $t = [string]$Svc.Status }
    if ($Svc.Error) { $t += ' (error ' + (Format-SbHex $Svc.Error) + ')' }
    $t
}

function Format-SbBootManager($Capable) {
    if ($null -eq $Capable) { return 'unknown (not reported)' }
    switch ([int]$Capable) {
        2 { 'Yes (PC starts with it)' }
        1 { 'Not yet (old boot manager)' }
        0 { 'No (2023 CA not in the DB)' }
        default { 'unknown (' + $Capable + ')' }
    }
}

function Format-SbTask($Task) {
    if (-not $Task.Exists) { return 'NOT FOUND' }
    if (-not $Task.LastRun) { return 'present, never run' }
    'last run {0:yyyy-MM-dd HH:mm}, result {1}' -f $Task.LastRun, (Format-SbHex $Task.LastResult)
}

function Format-SbBitLocker($Bl) {
    if (-not $Bl.Available) { return 'not available' }
    if (-not $Bl.On) { return 'off' }
    if ($Bl.RecoveryPassword) { return 'ON (recovery key exists)' }
    'ON (no recovery key protector!)'
}

function Format-SbOs($Os) {
    $t = $Os.Name
    if ($Os.Display) { $t += ' ' + $Os.Display }
    $t + (' (build {0}.{1})' -f $Os.Build, $Os.Ubr)
}

# Caption / Value / Level rows (Level: Ok, Warn, Error, Muted, Info)
function Get-SbStateRows($S) {
    $noUefi = ($S.Verdict -eq 'NoUefi')
    $rows = New-Object System.Collections.Generic.List[object]
    $add = { param($c, $v, $l) $rows.Add([pscustomobject]@{ Caption = $c; Value = [string]$v; Level = $l }) }

    if ($S.SecureBoot -eq $true) { & $add 'Secure Boot' 'Enabled' 'Ok' }
    elseif ($S.SecureBoot -eq $false) { & $add 'Secure Boot' 'DISABLED' 'Warn' }
    else { & $add 'Secure Boot' 'not available (legacy BIOS/CSM)' 'Muted' }

    & $add 'Windows' (Format-SbOs $S.Os) 'Info'

    $miss = 'Error'; if ($noUefi) { $miss = 'Muted' }
    if ($S.HasKek2023) { & $add 'KEK 2K CA 2023 (KEK)' 'Yes' 'Ok' } else { & $add 'KEK 2K CA 2023 (KEK)' 'No' $miss }
    if ($S.HasWinCa2023) { & $add 'Windows UEFI CA 2023 (DB)' 'Yes' 'Ok' } else { & $add 'Windows UEFI CA 2023 (DB)' 'No' $miss }

    $c = $S.Servicing.Capable
    $l = 'Muted'
    if ($null -ne $c) { if ($c -eq 2) { $l = 'Ok' } elseif ($c -eq 1) { $l = 'Warn' } else { $l = 'Error' } }
    & $add '2023 boot manager' (Format-SbBootManager $c) $l

    $l = 'Muted'
    if ($S.Servicing.Error) { $l = 'Error' }
    elseif ($S.Servicing.Status -eq 'Updated') { $l = 'Ok' }
    elseif ($S.Servicing.Status) { $l = 'Warn' }
    & $add 'Windows update status' (Format-SbServicing $S.Servicing) $l

    $l = 'Muted'
    if ($null -ne $S.AvailableUpdates -and ($S.AvailableUpdates -band (-bnot 0x4000)) -ne 0) { $l = 'Warn' }
    & $add 'AvailableUpdates' (Format-SbFlag $S.AvailableUpdates) $l

    $l = 'Ok'
    if (-not $S.Task.Exists) { if ($noUefi) { $l = 'Muted' } else { $l = 'Error' } }
    elseif (-not $S.Task.LastRun) { $l = 'Muted' }
    elseif ($S.Task.LastResult -ne 0) { $l = 'Warn' }
    & $add 'Secure-Boot-Update task' (Format-SbTask $S.Task) $l

    $l = 'Muted'; if ($S.BitLocker.On) { $l = 'Warn' }
    & $add ('BitLocker (' + $S.BitLocker.Drive + ')') (Format-SbBitLocker $S.BitLocker) $l

    if ($S.PendingReboot) { & $add 'Restart pending' 'Yes' 'Warn' } else { & $add 'Restart pending' 'No' 'Muted' }

    $rows.ToArray()
}

# One-line summary: Text and Level
function Get-SbVerdictText($S) {
    $t = ''; $l = 'Info'
    switch ($S.Verdict) {
        'NoUefi'        { $t = 'This PC does not use UEFI Secure Boot (legacy BIOS/CSM), or its Secure Boot variables cannot be read. There is nothing to update in the firmware.'; $l = 'Muted' }
        'Complete'      { $t = 'Up to date: the 2023 Secure Boot certificates and boot manager are in place.'; $l = 'Ok' }
        'CertsPresent'  { $t = 'The 2023 certificates are in the firmware (KEK and DB). This Windows build does not report the boot manager status.'; $l = 'Ok' }
        'RestartNeeded' { $t = 'Restart needed: the certificates are applied and the 2023 boot manager is installed at the next restart. After restarting, run this tool again.'; $l = 'Warn' }
        'InProgress'    { $t = 'Update in progress (AvailableUpdates = ' + (Format-SbFlag $S.AvailableUpdates) + '). Run the update again to start the next step.'; $l = 'Warn' }
        'Partial'       { $t = 'Partly updated. Missing: ' + ($S.Missing -join ', ') + '.'; $l = 'Warn' }
        default         { $t = 'Not updated: the 2023 Secure Boot certificates are not in the firmware yet.'; $l = 'Error' }
    }
    if ($S.SecureBoot -eq $false) { $t += ' Secure Boot is OFF.' }
    [pscustomobject]@{ Text = $t; Level = $l }
}

# Advice for known problems
function Get-SbHints($S) {
    $h = @()
    if ($S.Verdict -eq 'NoUefi') { return $h }
    if (-not $S.Task.Exists -and $S.Verdict -notin 'Complete', 'CertsPresent') {
        $h += 'The Secure-Boot-Update scheduled task is missing. Install the latest cumulative update for this Windows, then run this tool again.'
    }
    if ($S.SecureBoot -eq $false) {
        $h += 'Secure Boot is off. Windows can still install the certificates; turn Secure Boot on in the BIOS/UEFI setup afterwards and run this tool again to check.'
    }
    if ($S.Servicing.Error) {
        $e = 'Windows reported error ' + (Format-SbHex $S.Servicing.Error)
        if ($S.Servicing.ErrorEvent) { $e += (' (event {0}: {1})' -f $S.Servicing.ErrorEvent, (Get-SbEventMeaning ([int]$S.Servicing.ErrorEvent))) }
        $h += $e + '.'
    }
    if ($S.Verdict -notin 'Complete', 'CertsPresent' -and @($S.Events).Count -gt 0) {
        switch ($S.Events[0].Id) {
            1032 { $h += 'Windows held the update because BitLocker would ask for the recovery key. Suspend BitLocker for 2 restarts and run the update again.' }
            1795 { $h += 'The firmware refused the change. Look for a BIOS/UEFI update from the PC maker; Windows tries again at each restart.' }
            1796 { $h += 'The last attempt failed; Windows tries again at the next restart. If it keeps failing, look for a BIOS/UEFI update.' }
            1802 { $h += 'Microsoft blocks this update on this device because of a known firmware issue. Install the latest BIOS/UEFI update from the PC maker, then try again.' }
            1803 { $h += 'The firmware has no KEK update signed by the PC maker, so the KEK cannot be updated by Windows. Look for a BIOS/UEFI update from the PC maker.' }
        }
    }
    if ($S.BitLocker.On -and $S.Verdict -notin 'Complete', 'CertsPresent') {
        $h += 'BitLocker is on: have the 48-digit recovery key ready (https://aka.ms/myrecoverykey) or suspend BitLocker for 2 restarts.'
    }
    $h
}

# ----- Actions -----

# Windows 10 21H2/22H2 only: downloads KB5073724 from the Microsoft Update Catalog and installs it.
function Install-SbWin10Update($State) {
    $res = [pscustomobject]@{ Ok = $true; RebootRequired = $false }
    $os = $State.Os
    if (-not $os.IsWin10Client) { Write-SbLog ("Skipped: $SbKbId is only for Windows 10 21H2/22H2.") 'Muted'; return $res }
    if ($os.Ubr -ge $SbKbUbr) {
        Write-SbLog ('Skipped: this PC is at build {0}.{1}, so {2} or a later cumulative update is installed.' -f $os.Build, $os.Ubr, $SbKbId) 'Ok'
        return $res
    }
    if (-not $os.Arch) { Write-SbLog 'WARNING: unknown processor architecture; skipped.' 'Warn'; $res.Ok = $false; return $res }
    $ver = '21H2'; if ($os.Build -eq 19045) { $ver = '22H2' }
    $dir = Join-Path $env:TEMP 'Update-SecureBootCert'
    $file = $null
    try {
        $ProgressPreference = 'SilentlyContinue'
        try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch { }

        Write-SbLog ("Looking up $SbKbId for Windows 10 Version $ver ($($os.Arch)) in the Microsoft Update Catalog...") 'Step'
        $page = Invoke-WebRequest -Uri ('https://www.catalog.update.microsoft.com/Search.aspx?q=' + $SbKbId) -UseBasicParsing -ErrorAction Stop
        $id = $null; $title = $null
        $rx = '(?s)id=["'']([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})_link["''][^>]*>(.*?)</a>'
        foreach ($m in [regex]::Matches($page.Content, $rx)) {
            $t = ($m.Groups[2].Value -replace '<[^>]+>', '' -replace '\s+', ' ').Trim()
            if ($t -match ('Windows 10 Version ' + $ver) -and $t -match ([regex]::Escape($os.Arch) + '-based') -and $t -notmatch 'Dynamic|Server') {
                $id = $m.Groups[1].Value; $title = $t; break
            }
        }
        if (-not $id) {
            Write-SbLog ('WARNING: {0} for Windows 10 Version {1} ({2}) was not found in the Catalog.' -f $SbKbId, $ver, $os.Arch) 'Warn'
            Write-SbLog ('         Manual download: https://www.catalog.update.microsoft.com/Search.aspx?q=' + $SbKbId) 'Muted'
            $res.Ok = $false; return $res
        }
        Write-SbLog ('Found: ' + $title)

        $json = '[{"size":0,"languages":"","uidInfo":"' + $id + '","updateID":"' + $id + '"}]'
        $dlg = Invoke-WebRequest -Uri 'https://www.catalog.update.microsoft.com/DownloadDialog.aspx' -Method Post -Body @{ updateIDs = $json } -UseBasicParsing -ErrorAction Stop
        $urls = @([regex]::Matches($dlg.Content, 'https?://[^''"\s<>]+?\.(?:msu|cab)\b') | ForEach-Object { $_.Value } | Select-Object -Unique)
        $url = $urls | Where-Object { $_ -match '\.msu$' } | Select-Object -First 1
        if (-not $url) { $url = $urls | Select-Object -First 1 }
        if (-not $url) { Write-SbLog 'ERROR: the Catalog did not return a download link.' 'Error'; $res.Ok = $false; return $res }
        $urlHost = ([uri]$url).Host
        if ($urlHost -notmatch '(^|\.)(windowsupdate\.com|microsoft\.com)$') {
            Write-SbLog ('ERROR: unexpected download host ' + $urlHost + '; not downloading.') 'Error'; $res.Ok = $false; return $res
        }

        if (-not (Test-Path $dir)) { [void](New-Item -ItemType Directory -Path $dir -Force) }
        $file = Join-Path $dir ([IO.Path]::GetFileName(([uri]$url).AbsolutePath))
        Write-SbLog ('Downloading ' + [IO.Path]::GetFileName($file) + ' (several hundred MB, please wait)...') 'Step'
        $wc = New-Object System.Net.WebClient
        try {
            try { $wc.DownloadFile(($url -replace '^http://', 'https://'), $file) } catch { $wc.DownloadFile($url, $file) }
        } finally { $wc.Dispose() }

        $sig = Get-AuthenticodeSignature -FilePath $file
        if ($sig.Status -eq 'HashMismatch' -or ($sig.Status -eq 'Valid' -and $sig.SignerCertificate.Subject -notmatch 'Microsoft')) {
            Write-SbLog ('ERROR: the downloaded file failed the signature check (' + $sig.Status + '); not installing.') 'Error'
            $res.Ok = $false; return $res
        }

        Write-SbLog 'Installing (10-30 minutes; do not turn the PC off)...' 'Step'
        if ($file -match '\.msu$') {
            $p = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\wusa.exe') -ArgumentList ('"' + $file + '" /quiet /norestart') -Wait -PassThru -WindowStyle Hidden
        } else {
            $p = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\dism.exe') -ArgumentList ('/Online /Add-Package /PackagePath:"' + $file + '" /Quiet /NoRestart') -Wait -PassThru -WindowStyle Hidden
        }
        $code = [int64]$p.ExitCode
        switch ($code) {
            0           { Write-SbLog ('OK: ' + $SbKbId + ' installed.') 'Ok' }
            3010        { Write-SbLog ('OK: ' + $SbKbId + ' installed; restart required.') 'Ok'; $res.RebootRequired = $true }
            2359302     { Write-SbLog ('OK: ' + $SbKbId + ' is already installed.') 'Ok' }
            -2145124329 {
                Write-SbLog ('WARNING: ' + $SbKbId + ' is not applicable to this PC (0x80240017).') 'Warn'
                Write-SbLog '         Usually a newer cumulative update is installed, or the PC has no ESU license. The certificate step does not need it.' 'Muted'
                $res.Ok = $false
            }
            default     { Write-SbLog ('WARNING: the installer returned ' + (Format-SbHex $code) + '.') 'Warn'; $res.Ok = $false }
        }
        if ($res.Ok) {
            Write-SbLog 'NOTE: without an ESU license, Windows can remove this update again after the restart. The certificate step does not depend on it.' 'Muted'
        }
    } catch {
        Write-SbLog ('WARNING: ' + $SbKbId + ' failed: ' + $_.Exception.Message) 'Warn'
        Write-SbLog '         Continuing; the certificate step does not depend on it.' 'Muted'
        $res.Ok = $false
    } finally {
        if ($file -and (Test-Path -LiteralPath $file)) { Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue }
    }
    $res
}

# Installs pending Windows software updates (not drivers, not hidden ones).
function Install-SbWindowsUpdates {
    $res = [pscustomobject]@{ Ok = $false; RebootRequired = $false }
    try {
        $session = New-Object -ComObject 'Microsoft.Update.Session'
        $searcher = $session.CreateUpdateSearcher()
        Write-SbLog 'Searching for pending Windows updates (software only; this can take several minutes)...' 'Step'
        $found = $searcher.Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
        $coll = New-Object -ComObject 'Microsoft.Update.UpdateColl'
        foreach ($u in $found.Updates) {
            if ($u.InstallationBehavior.CanRequestUserInput) { Write-SbLog ('  skipped (needs user input): ' + $u.Title) 'Muted'; continue }
            if (-not $u.EulaAccepted) { try { $u.AcceptEula() } catch { } }
            [void]$coll.Add($u)
            Write-SbLog ('  * ' + $u.Title)
        }
        if ($coll.Count -eq 0) { Write-SbLog 'OK: no pending updates.' 'Ok'; $res.Ok = $true; return $res }

        Write-SbLog ('Downloading {0} update(s)...' -f $coll.Count) 'Step'
        $dl = $session.CreateUpdateDownloader()
        $dl.Updates = $coll
        $dr = $dl.Download()
        if ($dr.ResultCode -ne 2 -and $dr.ResultCode -ne 3) { Write-SbLog ('WARNING: download result code {0}.' -f $dr.ResultCode) 'Warn' }

        Write-SbLog 'Installing (please wait)...' 'Step'
        $inst = $session.CreateUpdateInstaller()
        $inst.Updates = $coll
        $ir = $inst.Install()
        $res.RebootRequired = [bool]$ir.RebootRequired
        # OperationResultCode: 2 succeeded, 3 succeeded with errors, 4 failed, 5 aborted
        for ($i = 0; $i -lt $coll.Count; $i++) {
            $ur = $ir.GetUpdateResult($i)
            if ($ur.ResultCode -ne 2) { Write-SbLog ('  not installed (code {0}, {1}): {2}' -f $ur.ResultCode, (Format-SbHex $ur.HResult), $coll.Item($i).Title) 'Warn' }
        }
        switch ($ir.ResultCode) {
            2       { Write-SbLog 'OK: updates installed.' 'Ok'; $res.Ok = $true }
            3       { Write-SbLog 'OK: updates installed, some with errors (see above).' 'Warn'; $res.Ok = $true }
            4       { Write-SbLog 'ERROR: installation failed.' 'Error' }
            5       { Write-SbLog 'ERROR: installation aborted.' 'Error' }
            default { Write-SbLog ('WARNING: result code {0}.' -f $ir.ResultCode) 'Warn' }
        }
        if ($res.RebootRequired) { Write-SbLog 'A restart is required to finish installing the updates.' 'Warn' }
    } catch {
        Write-SbLog ('WARNING: Windows Update failed: ' + $_.Exception.Message) 'Warn'
    }
    $res
}

# Suspends BitLocker on the system drive for N restarts (it resumes by itself).
function Suspend-SbBitLocker([int]$RebootCount = 2) {
    try {
        $vol = Get-CimInstance -Namespace 'root\cimv2\Security\MicrosoftVolumeEncryption' -ClassName 'Win32_EncryptableVolume' -Filter ("DriveLetter='{0}'" -f $env:SystemDrive) -ErrorAction Stop
        if (-not $vol) { Write-SbLog 'BitLocker is not available; nothing to suspend.' 'Muted'; return $true }
        if ($vol.ProtectionStatus -ne 1) { Write-SbLog ('BitLocker protection is already off on ' + $env:SystemDrive + '.') 'Muted'; return $true }
        $r = Invoke-CimMethod -InputObject $vol -MethodName 'DisableKeyProtectors' -Arguments @{ DisableCount = [uint32]$RebootCount } -ErrorAction Stop
        if ($r.ReturnValue -eq 0) {
            Write-SbLog ('OK: BitLocker suspended on {0} for the next {1} restarts; it turns back on by itself.' -f $env:SystemDrive, $RebootCount) 'Ok'
            return $true
        }
        Write-SbLog ('WARNING: BitLocker could not be suspended (code ' + (Format-SbHex $r.ReturnValue) + ').') 'Warn'
    } catch {
        Write-SbLog ('WARNING: BitLocker could not be suspended: ' + $_.Exception.Message) 'Warn'
    }
    $false
}

# Asks Windows to install the 2023 certificates (and boot manager) and starts the Secure-Boot-Update task.
# Never overwrites an update that Windows has already queued.
function Start-SbDeployment($State, [switch]$DbOnly) {
    $res = [pscustomobject]@{ Ok = $false; RebootRequired = $false }
    if ($null -eq $State.SecureBoot -or -not $State.FirmwareReadable) {
        Write-SbLog 'Skipped: UEFI Secure Boot is not available on this PC.' 'Muted'
        return $res
    }
    if (-not $State.Task.Exists) {
        Write-SbLog 'ERROR: the Secure-Boot-Update scheduled task was not found. Install the latest cumulative update for this Windows, then run this tool again.' 'Error'
        return $res
    }
    try {
        $au = $State.AvailableUpdates
        $queued = 0
        if ($null -ne $au) { $queued = $au -band (-bnot 0x4000) }
        if ($queued -ne 0) {
            Write-SbLog ('Windows already has an update queued (AvailableUpdates = 0x{0:X}); leaving it as is.' -f $au)
        } else {
            $value = $SbFullValue; $what = 'full update: KEK, DB certificates and boot manager'
            if ($DbOnly) { $value = $SbDbValue; $what = 'old method: Windows UEFI CA 2023 in the DB only' }
            Write-SbLog ('Setting AvailableUpdates = 0x{0:X} ({1})...' -f $value, $what) 'Step'
            Set-ItemProperty -Path $SbKey -Name 'AvailableUpdates' -Value $value -Type DWord -ErrorAction Stop
            Write-SbLog 'OK: value set.' 'Ok'
        }

        Write-SbLog 'Starting the Secure-Boot-Update task...' 'Step'
        Start-ScheduledTask -TaskPath $SbTaskPath -TaskName $SbTaskName -ErrorAction Stop
        Start-Sleep -Seconds 3
        $deadline = (Get-Date).AddSeconds(180)
        while ((Get-Date) -lt $deadline) {
            $t = Get-ScheduledTask -TaskPath $SbTaskPath -TaskName $SbTaskName -ErrorAction SilentlyContinue
            if (-not $t -or [string]$t.State -ne 'Running') { break }
            Start-Sleep -Seconds 2
        }
        $task = Get-SbTask
        $svc = Get-SbServicing
        Write-SbLog ('Task: ' + (Format-SbTask $task) + '.')
        Write-SbLog ('AvailableUpdates is now ' + (Format-SbFlag (Get-SbAvailableUpdates)) + '.')
        Write-SbLog ('Windows update status: ' + (Format-SbServicing $svc) + '.')
        if ($svc.Error) {
            $m = ''
            if ($svc.ErrorEvent) { $m = ' - event ' + $svc.ErrorEvent + ': ' + (Get-SbEventMeaning ([int]$svc.ErrorEvent)) }
            Write-SbLog ('WARNING: Windows reported error ' + (Format-SbHex $svc.Error) + $m) 'Warn'
        }
        $res.Ok = $true
        $res.RebootRequired = $true
    } catch {
        Write-SbLog ('ERROR: ' + $_.Exception.Message) 'Error'
    }
    $res
}

# <<< SB-ENGINE END >>>

# =============================================================================
#  Console front-end
# =============================================================================

function Get-SbColor([string]$Level) {
    switch ($Level) {
        'Ok'    { 'Green' }
        'Warn'  { 'Yellow' }
        'Error' { 'Red' }
        'Step'  { 'Cyan' }
        'Muted' { 'Gray' }
        default { 'White' }
    }
}

function Write-SbLog([string]$Text, [string]$Level = 'Info') {
    Write-Host $Text -ForegroundColor (Get-SbColor $Level)
}

function Test-SbAdmin {
    try {
        $p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { $false }
}

function Read-SbYesNo([string]$Question) {
    while ($true) {
        $a = [string](Read-Host ($Question + ' (Y/N)'))
        $a = $a.Trim().ToLowerInvariant()
        if ($a -in 'y', 'yes', 's', 'sim') { return $true }
        if ($a -in 'n', 'no', 'nao') { return $false }
    }
}

function Wait-SbExit {
    if (-not $NoPause -and -not $Unattended) {
        Write-Host ''
        [void](Read-Host 'Press Enter to exit')
    }
}

function Show-SbHeader {
    Write-Host ''
    Write-Host '================================================================' -ForegroundColor Cyan
    Write-Host ('  Update-SecureBootCert v' + $SbVersion + ' - Secure Boot certificate updater') -ForegroundColor Cyan
    Write-Host '================================================================' -ForegroundColor Cyan
    Write-Host '  Nothing is changed until you confirm.' -ForegroundColor Gray
    Write-Host ''
}

function Show-SbState($S) {
    Write-Host ''
    foreach ($r in (Get-SbStateRows $S)) {
        Write-Host ('  {0,-26} ' -f $r.Caption) -NoNewline -ForegroundColor Gray
        Write-Host $r.Value -ForegroundColor (Get-SbColor $r.Level)
    }

    Write-Host ''
    Write-Host '  Certificates in the firmware:' -ForegroundColor Cyan
    if (@($S.Certs).Count -eq 0) {
        Write-Host '    (none could be read)' -ForegroundColor Gray
    }
    foreach ($c in $S.Certs) {
        $color = 'Gray'
        if ($c.Year -eq 2023) { if ($c.Status -eq 'Valid') { $color = 'Green' } else { $color = 'Red' } }
        elseif ($c.Year -eq 2011) { $color = 'Yellow' }
        Write-Host ('    [{0,-3}] {1,-38} {2:yyyy-MM-dd}  {3}' -f $c.Store, $c.Name, $c.NotAfter, $c.Status) -ForegroundColor $color
    }
    if ((@($S.Certs) | Where-Object { $_.Year -eq 2011 -and $_.Status -eq 'Expired' })) {
        Write-Host '    (Expired 2011 certificates stay in the firmware so older boot media keeps working. That is normal.)' -ForegroundColor Gray
    }

    if (@($S.Events).Count -gt 0) {
        Write-Host ''
        Write-Host '  Recent Secure Boot events (System log, TPM-WMI):' -ForegroundColor Cyan
        foreach ($e in (@($S.Events) | Select-Object -First 5)) {
            Write-Host ('    {0:yyyy-MM-dd HH:mm}  {1}  {2}' -f $e.Time, $e.Id, $e.Meaning) -ForegroundColor Gray
        }
    }

    $v = Get-SbVerdictText $S
    Write-Host ''
    Write-Host ('  ' + $v.Text) -ForegroundColor (Get-SbColor $v.Level)
    foreach ($h in (Get-SbHints $S)) { Write-Host ('  - ' + $h) -ForegroundColor Yellow }
    Write-Host ''
}

function Get-SbExitCode($S) {
    switch ($S.Verdict) {
        'Complete'      { 0 }
        'CertsPresent'  { 0 }
        'NoUefi'        { 0 }
        'RestartNeeded' { 3010 }
        default         { 2 }
    }
}

function Invoke-SbRestartPrompt {
    Write-SbLog ''
    Write-SbLog 'A restart is needed. After the restart, run this tool again: it starts the next step and confirms the result.' 'Warn'
    Write-SbLog '(If you do not, Windows runs the Secure-Boot-Update task by itself within about 12 hours.)' 'Muted'
    $go = [bool]$Restart
    if (-not $go -and -not $Unattended) { $go = Read-SbYesNo 'Restart the PC now?' }
    if ($go) {
        Write-SbLog 'Restarting in 30 seconds. To cancel, run: shutdown /a' 'Warn'
        & shutdown.exe /r /t 30 /c 'Secure Boot certificate update (Update-SecureBootCert)' | Out-Null
    } else {
        Write-SbLog 'Restart the PC yourself when you are ready.'
    }
    3010
}

function Invoke-SbMain {
    Show-SbHeader
    Write-SbLog 'Reading the Secure Boot state...' 'Step'
    $st = Get-SbState
    Show-SbState $st

    if ($CheckOnly) { return (Get-SbExitCode $st) }

    switch ($st.Verdict) {
        'NoUefi'        { Write-SbLog 'Nothing to do on this PC.' 'Muted'; return 0 }
        'Complete'      { Write-SbLog 'Nothing to do.' 'Ok'; return 0 }
        'CertsPresent'  { Write-SbLog 'Nothing to do.' 'Ok'; return 0 }
        'RestartNeeded' { return (Invoke-SbRestartPrompt) }
    }

    # ----- Plan -----
    $doKb = (-not $SkipKB) -and $st.Os.IsWin10Client -and ($st.Os.Ubr -lt $SbKbUbr)
    $doWu = [bool]$InstallWindowsUpdates
    if (-not $doWu -and -not $Unattended) {
        $doWu = Read-SbYesNo 'Also install ALL pending Windows updates first? (optional, can take a long time)'
    }
    $doBl = $false
    if ($st.BitLocker.On) {
        if ($SuspendBitLocker) { $doBl = $true }
        elseif (-not $Unattended) {
            Write-SbLog ''
            Write-SbLog ('BitLocker is ON for ' + $st.BitLocker.Drive + '. Changing Secure Boot can make it ask for the 48-digit recovery key at the next start.') 'Warn'
            Write-SbLog '  Find the key at https://aka.ms/myrecoverykey or with:  manage-bde -protectors -get C:' 'Muted'
            $doBl = Read-SbYesNo 'Suspend BitLocker for the next 2 restarts? (it turns back on by itself)'
        }
    }

    Write-SbLog ''
    Write-SbLog 'Planned steps:' 'Step'
    if ($doKb) { Write-SbLog ('  - Install ' + $SbKbId + ' (Windows 10 cumulative update with the new certificates)') }
    if ($doWu) { Write-SbLog '  - Install all pending Windows software updates' }
    if ($doBl) { Write-SbLog '  - Suspend BitLocker for 2 restarts' }
    if ($DbOnly) { Write-SbLog '  - Add Windows UEFI CA 2023 to the Secure Boot DB (old method, 0x40)' }
    else { Write-SbLog '  - Install the 2023 Secure Boot certificates and boot manager (0x5944)' }
    Write-SbLog ''
    if (-not $Unattended) {
        if (-not (Read-SbYesNo 'Start now? Do not turn the PC off while it runs.')) {
            Write-SbLog 'Cancelled. Nothing was changed.' 'Warn'
            return 3
        }
    }

    # ----- Run -----
    $needRestart = $false
    $failed = $false
    $n = 0
    $total = 1 + [int]$doKb + [int]$doWu + [int]$doBl

    if ($doKb) {
        $n++; Write-SbLog ''; Write-SbLog ('Step {0}/{1}: {2}' -f $n, $total, $SbKbId) 'Step'
        $r = Install-SbWin10Update -State $st
        if ($r.RebootRequired) { $needRestart = $true }
        if (-not $r.Ok) { $failed = $true }
    }
    if ($doWu) {
        $n++; Write-SbLog ''; Write-SbLog ('Step {0}/{1}: Windows Update' -f $n, $total) 'Step'
        $r = Install-SbWindowsUpdates
        if ($r.RebootRequired) { $needRestart = $true }
        if (-not $r.Ok) { $failed = $true }
    }
    if ($doBl) {
        $n++; Write-SbLog ''; Write-SbLog ('Step {0}/{1}: BitLocker' -f $n, $total) 'Step'
        if (-not (Suspend-SbBitLocker -RebootCount 2)) { $failed = $true }
    }
    $n++; Write-SbLog ''; Write-SbLog ('Step {0}/{1}: Secure Boot certificates' -f $n, $total) 'Step'
    $st = Get-SbState
    $r = Start-SbDeployment -State $st -DbOnly:$DbOnly
    if ($r.RebootRequired) { $needRestart = $true }
    if (-not $r.Ok) { $failed = $true }

    # ----- Result -----
    Write-SbLog ''
    Write-SbLog 'Checking the result...' 'Step'
    $after = Get-SbState
    $v = Get-SbVerdictText $after
    Write-SbLog ('  ' + $v.Text) $v.Level
    foreach ($h in (Get-SbHints $after)) { Write-SbLog ('  - ' + $h) 'Warn' }

    if ($after.Verdict -in 'Complete', 'CertsPresent' -and -not $needRestart -and -not $after.PendingReboot) { return 0 }
    if ($needRestart -or $after.PendingReboot -or $after.Verdict -in 'RestartNeeded', 'InProgress') { return (Invoke-SbRestartPrompt) }
    if ($failed) { return 1 }
    2
}

# =============================================================================
#  Start
# =============================================================================

# Administrator rights first, before any question
if (-not (Test-SbAdmin)) {
    Write-Host 'Administrator rights are needed. Asking for them...' -ForegroundColor Yellow
    $argList = '-NoProfile -ExecutionPolicy Bypass -File "' + $PSCommandPath + '"'
    foreach ($k in $SbBoundParams.Keys) {
        $val = $SbBoundParams[$k]
        if ($val -is [System.Management.Automation.SwitchParameter]) { if ($val.IsPresent) { $argList += ' -' + $k } }
        else { $argList += ' -' + $k + ' "' + $val + '"' }
    }
    try {
        $exe = (Get-Process -Id $PID).Path
        $p = Start-Process -FilePath $exe -ArgumentList $argList -Verb RunAs -Wait -PassThru -ErrorAction Stop
        exit $p.ExitCode
    } catch {
        Write-Host ('Could not get administrator rights: ' + $_.Exception.Message) -ForegroundColor Red
        Write-Host 'Right-click RunMe.bat and choose "Run as administrator".' -ForegroundColor Yellow
        Wait-SbExit
        exit 1
    }
}

if (-not $LogPath) {
    $LogPath = Join-Path (Join-Path $env:ProgramData 'Update-SecureBootCert') ('Update-SecureBootCert_{0:yyyyMMdd_HHmmss}.log' -f (Get-Date))
}
$transcript = $false
try {
    $logDir = Split-Path -Parent $LogPath
    if ($logDir -and -not (Test-Path $logDir)) { [void](New-Item -ItemType Directory -Path $logDir -Force) }
    Start-Transcript -Path $LogPath -Append | Out-Null
    $transcript = $true
} catch { }

$exitCode = 1
try {
    $exitCode = Invoke-SbMain
} catch {
    Write-SbLog ('ERROR: ' + $_.Exception.Message + ' (line ' + $_.InvocationInfo.ScriptLineNumber + ')') 'Error'
    $exitCode = 1
}

Write-SbLog ''
if ($transcript) {
    Write-SbLog ('Log file: ' + $LogPath) 'Muted'
    try { Stop-Transcript | Out-Null } catch { }
}
Wait-SbExit
exit $exitCode
