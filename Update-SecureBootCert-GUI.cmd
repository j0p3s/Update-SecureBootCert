<# : batch
@echo off
REM ---------------------------------------------------------------------------
REM  Secure Boot Certificate Updater (GUI) - batch/PowerShell hybrid launcher.
REM  cmd.exe runs only these few lines; to PowerShell, this whole header is a
REM  block comment. The batch part passes this file's own path to
REM  Windows PowerShell, which reads the rest of the file and opens the window.
REM  Administrator rights are asked for once (UAC).
REM ---------------------------------------------------------------------------
setlocal
set "SBGUI_SCRIPT=%~f0"
set "SBGUI_PS=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if exist "%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe" set "SBGUI_PS=%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe"
if not exist "%SBGUI_PS%" set "SBGUI_PS=powershell"
"%SBGUI_PS%" -NoProfile -ExecutionPolicy Bypass -STA -Command "iex ([IO.File]::ReadAllText($env:SBGUI_SCRIPT, [Text.Encoding]::UTF8))"
if errorlevel 1 pause
exit /b
#>

# =============================================================================
#  Secure Boot Certificate Updater - GUI
#
#  A window for the steps of Update-SecureBootCert.ps1 (same actions, same
#  order), so you can see the state of the certificates and choose what to do:
#    - shows Secure Boot, the Windows version and the certificates found in
#      the firmware (KEK and DB)
#    - optional: install KB5073724 (Windows 10 only)
#    - optional: install ALL pending Windows updates
#    - optional: deploy "Windows UEFI CA 2023" to the Secure Boot DB (registry
#      value AvailableUpdates = 0x40 and the Secure-Boot-Update scheduled task)
#    - restart button (two restarts are needed)
#
#  Nothing is changed until you click "Start update" and confirm.
# =============================================================================

# Known certificates: where they are stored, the text found in the firmware, and how to show them
$CertDefs = @(
    @{ Store = 'KEK'; Pattern = 'Microsoft Corporation KEK 2K CA 2023'; Name = 'Microsoft Corporation KEK 2K CA 2023'; State = 'new'; Expiry = '~2033' }
    @{ Store = 'KEK'; Pattern = 'Microsoft Corporation KEK CA 2011';    Name = 'Microsoft Corporation KEK CA 2011';    State = 'expired'; Expiry = '2026-06' }
    @{ Store = 'db';  Pattern = 'Windows UEFI CA 2023';                 Name = 'Windows UEFI CA 2023';                 State = 'new'; Expiry = '~2033' }
    @{ Store = 'db';  Pattern = 'Microsoft UEFI CA 2023';               Name = 'Microsoft UEFI CA 2023';               State = 'new'; Expiry = '-' }
    @{ Store = 'db';  Pattern = 'Microsoft Option ROM UEFI CA 2023';    Name = 'Microsoft Option ROM UEFI CA 2023';    State = 'new'; Expiry = '-' }
    @{ Store = 'db';  Pattern = 'Microsoft UEFI CA 2011';               Name = 'Microsoft UEFI CA 2011';               State = 'expired'; Expiry = '2026-06' }
    @{ Store = 'db';  Pattern = 'Windows Production PCA 2011';          Name = 'Windows Production PCA 2011';          State = 'soon'; Expiry = '2026-10' }
)

function Test-Admin {
    try { ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }
    catch { $false }
}

function ConvertTo-PsLiteral([string]$s) { $s -replace "'", "''" }

# ----- Reading the state (nothing is changed here) -----

function Get-OsInfo {
    $v = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $build = [int]$v.CurrentBuildNumber
    $name = [string]$v.ProductName
    $win10 = ($build -lt 22000)
    if (-not $win10) { $name = $name -replace 'Windows 10', 'Windows 11' }
    [pscustomobject]@{ Name = $name; Build = $build; IsWin10 = $win10 }
}

# $true / $false, or $null when it can't be read (for example legacy BIOS)
function Get-SecureBootState {
    try { [bool](Confirm-SecureBootUEFI -ErrorAction Stop) } catch { $null }
}

# The firmware variable as text (KEK or db), or $null
function Get-DbText([string]$name) {
    try {
        $v = Get-SecureBootUEFI -Name $name -ErrorAction Stop
        [Text.Encoding]::ASCII.GetString($v.Bytes)
    } catch { $null }
}

function Get-CertRows {
    $rows = @()
    foreach ($store in 'KEK', 'db') {
        $t = Get-DbText $store
        if ($null -eq $t) { continue }
        foreach ($d in $CertDefs) {
            if ($d.Store -eq $store -and $t -match [regex]::Escape($d.Pattern)) { $rows += $d }
        }
    }
    $rows
}

function Get-Status {
    $os = Get-OsInfo
    $dbText = Get-DbText 'db'
    $kb = $false
    if ($os.IsWin10) {
        try { $kb = [bool](Get-HotFix -Id 'KB5073724' -ErrorAction SilentlyContinue) } catch { $kb = $false }
    }
    $reg = $null
    try { $reg = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot' -Name AvailableUpdates -ErrorAction Stop).AvailableUpdates } catch { $reg = $null }
    [pscustomobject]@{
        Os         = $os
        SecureBoot = Get-SecureBootState
        Certs      = @(Get-CertRows)
        Uefi2023   = (($null -ne $dbText) -and ($dbText -match 'Windows UEFI CA 2023'))
        Kb         = $kb
        Reg        = $reg
    }
}

# ----- Actions (same as Update-SecureBootCert.ps1) -----

# Windows 10: downloads KB5073724 from the Microsoft Update Catalog and installs it with DISM. Returns $true if installed.
function Install-Kb5073724 {
    try {
        try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch { }
        $downloadDir = Join-Path $env:TEMP 'WindowsUpdates'
        if (-not (Test-Path $downloadDir)) { [void](New-Item -ItemType Directory -Path $downloadDir -Force) }

        $archName = ''
        switch ($env:PROCESSOR_ARCHITECTURE) {
            'AMD64' { $archName = 'x64' }
            'x86'   { $archName = 'x86' }
            'ARM64' { $archName = 'arm64' }
        }
        if (-not $archName) { Write-Log 'WARNING: unknown processor architecture, KB5073724 skipped.'; return $false }
        Write-Log ('Detected system: ' + $archName)
        Write-Log 'Fetching update information...'

        $catalogUrl = 'https://www.catalog.update.microsoft.com/Search.aspx?q=KB5073724'
        $response = Invoke-WebRequest -Uri $catalogUrl -UseBasicParsing -ErrorAction Stop
        $updatePattern = "updateIDs\.push\(\{\'size\'\:\'.*?\'\'languages\'\:\'.*?\'\'uidInfo\'\:\'(.*?)\'\'updateID\'\:\'(.*?)\'\}\)"
        $regexMatches = [regex]::Matches($response.Content, $updatePattern)

        $targetId = $null
        foreach ($m in $regexMatches) {
            if ($m.Groups[1].Value -match $archName) { $targetId = $m.Groups[2].Value; break }
        }
        if (-not $targetId) {
            Write-Log ('WARNING: could not find the update for ' + $archName + '.')
            Write-Log '         This is expected if the update is not public or was superseded. The registry step does not need it.'
            return $false
        }
        Write-Log 'Found the update. Retrieving the download link...'

        $postData = "updateIDs=[$targetId]"
        $downloadPage = Invoke-WebRequest -Uri 'https://www.catalog.update.microsoft.com/DownloadDialog.aspx' -Method Post -Body $postData -ContentType 'application/x-www-form-urlencoded' -UseBasicParsing -ErrorAction Stop
        $cabMatch = [regex]::Match($downloadPage.Content, "http[s]?://[^'`"<>]+\.cab")
        if (-not $cabMatch.Success) {
            Write-Log 'ERROR: could not extract the download URL.'
            return $false
        }
        $cabUrl = $cabMatch.Value
        $fileName = Split-Path $cabUrl -Leaf
        $downloadPath = Join-Path $downloadDir $fileName
        Write-Log ('Downloading ' + $fileName + ' (please wait, the window can look frozen)...')
        Invoke-WebRequest -Uri $cabUrl -OutFile $downloadPath -UseBasicParsing -ErrorAction Stop
        Write-Log ('Saved to: ' + $downloadPath)

        Write-Log 'Installing with DISM (please wait)...'
        $out = & dism.exe /Online /Add-Package "/PackagePath:$downloadPath" /NoRestart 2>&1
        $code = $LASTEXITCODE
        foreach ($line in @($out)) { $t = ([string]$line).Trim(); if ($t) { Write-Log ('  ' + $t) } }
        if ($code -eq 0 -or $code -eq 3010) {
            Write-Log 'OK: KB5073724 installed.'
            Write-Log 'NOTE: without an ESU license this update may be removed after the restart.'
            Write-Log '      The Secure Boot DB step is scheduled independently.'
            return $true
        }
        Write-Log ('WARNING: DISM exit code ' + $code)
        return $false
    } catch {
        Write-Log ('WARNING: KB5073724 failed: ' + $_.Exception.Message)
        Write-Log '         Continuing; the registry step does not depend on it.'
        return $false
    }
}

# Searches, downloads and installs ALL pending Windows updates. Returns $true if a restart is needed.
function Install-WindowsUpdates {
    try {
        $session = New-Object -ComObject Microsoft.Update.Session
        $searcher = $session.CreateUpdateSearcher()
        Write-Log 'Searching for available updates (this can take several minutes)...'
        $found = $searcher.Search('IsInstalled=0')
        $count = $found.Updates.Count
        Write-Log ('Found {0} available update(s).' -f $count)
        if ($count -eq 0) { Write-Log 'System is already up to date.'; return $false }
        foreach ($u in $found.Updates) { Write-Log ('  * ' + $u.Title) }

        Write-Log 'Downloading updates (please wait)...'
        $downloader = $session.CreateUpdateDownloader()
        $downloader.Updates = $found.Updates
        $dr = $downloader.Download()
        if ($dr.ResultCode -eq 2) { Write-Log 'OK: download successful.' } else { Write-Log ('WARNING: download result code ' + $dr.ResultCode) }

        Write-Log 'Installing updates (please wait)...'
        $installer = $session.CreateUpdateInstaller()
        $installer.Updates = $found.Updates
        $ir = $installer.Install()
        switch ($ir.ResultCode) {
            0 { Write-Log 'No restart required.'; return $false }
            1 { Write-Log 'OK: installed, restart required.'; return $true }
            2 { Write-Log 'OK: installed.'; return $false }
            3 { Write-Log 'ERROR: installation failed.'; return $false }
            default { Write-Log ('WARNING: unknown result code ' + $ir.ResultCode); return $false }
        }
    } catch {
        Write-Log ('WARNING: Windows Update failed: ' + $_.Exception.Message)
        return $false
    }
}

# Asks Windows to put "Windows UEFI CA 2023" in the Secure Boot DB. Returns $true if the task was started.
function Install-UefiCa2023 {
    try {
        Write-Log 'Setting the registry value AvailableUpdates = 0x40...'
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot' -Name 'AvailableUpdates' -Value 0x40 -ErrorAction Stop
        Write-Log 'OK: registry value set.'
        Write-Log 'Starting the Secure-Boot-Update scheduled task...'
        Start-ScheduledTask -TaskName '\Microsoft\Windows\PI\Secure-Boot-Update' -ErrorAction Stop
        Write-Log 'OK: task started.'
        return $true
    } catch {
        Write-Log ('ERROR: could not deploy UEFI CA 2023: ' + $_.Exception.Message)
        return $false
    }
}

# ===== GUI =====
try {
    # --- Administrator: reopens elevated, without a console, and this copy ends ---
    if (-not (Test-Admin)) {
        $exe = Join-Path $PSHOME 'powershell.exe'
        if (-not (Test-Path -LiteralPath $exe)) { $exe = 'powershell' }
        $cmd = "`$env:SBGUI_SCRIPT = '{0}'; iex ([IO.File]::ReadAllText(`$env:SBGUI_SCRIPT, [Text.Encoding]::UTF8))" -f (ConvertTo-PsLiteral $env:SBGUI_SCRIPT)
        $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
        try {
            Start-Process -FilePath $exe -Verb RunAs -WindowStyle Hidden -ErrorAction Stop -ArgumentList "-NoProfile -ExecutionPolicy Bypass -STA -EncodedCommand $enc"
            exit 0
        } catch {
            Write-Host 'Administrator rights are needed. Open the file again and accept the prompt.' -ForegroundColor Yellow
            exit 1
        }
    }

    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    [System.Windows.Forms.Application]::EnableVisualStyles()

    # Hides the console behind the window (when already opened as administrator)
    try {
        Add-Type -Namespace SbGui -Name Con -MemberDefinition '[DllImport("kernel32.dll")] public static extern IntPtr GetConsoleWindow(); [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int n);'
        [void][SbGui.Con]::ShowWindow([SbGui.Con]::GetConsoleWindow(), 0)
    } catch { }

    function Rgb($a) { [System.Drawing.Color]::FromArgb($a[0], $a[1], $a[2]) }
    $cBg    = Rgb @(28, 30, 36);   $cBox = Rgb @(20, 22, 27)
    $cText  = Rgb @(235, 236, 240); $cMuted = Rgb @(130, 136, 150)
    $cGreen = Rgb @(72, 199, 116);  $cRed = Rgb @(239, 83, 80)
    $cYellow = Rgb @(250, 204, 21); $cOrange = Rgb @(249, 115, 22); $cBlue = Rgb @(59, 130, 246); $cGrey = Rgb @(75, 80, 94)
    $fText  = New-Object System.Drawing.Font('Segoe UI', 9)
    $fBold  = New-Object System.Drawing.Font('Segoe UI', 10, [System.Drawing.FontStyle]::Bold)
    $fTitle = New-Object System.Drawing.Font('Segoe UI', 13, [System.Drawing.FontStyle]::Bold)
    $fMono  = New-Object System.Drawing.Font('Consolas', 9)

    function New-Ctl($type, $x, $y, $w, $h) {
        $c = New-Object ("System.Windows.Forms.$type")
        $c.Location = New-Object System.Drawing.Point($x, $y)
        $c.Size = New-Object System.Drawing.Size($w, $h)
        $c
    }
    function New-Btn($text, $x, $y, $w, $h, $color) {
        $b = New-Ctl 'Button' $x $y $w $h
        $b.Text = $text; $b.FlatStyle = 'Flat'; $b.BackColor = $color; $b.ForeColor = [System.Drawing.Color]::White
        $b.Font = $fBold; $b.FlatAppearance.BorderSize = 0; $b.Cursor = [System.Windows.Forms.Cursors]::Hand
        $b
    }
    function New-Label($text, $x, $y, $w, $h) {
        $l = New-Ctl 'Label' $x $y $w $h
        $l.Text = $text; $l.ForeColor = $cText
        $l
    }
    function New-Check($text, $x, $y, $w, $checked) {
        $c = New-Ctl 'CheckBox' $x $y $w 22
        $c.Text = $text; $c.Checked = $checked; $c.ForeColor = $cText
        $c
    }

    # --- Window ---
    $form = New-Object System.Windows.Forms.Form
    $form.Text = 'Secure Boot Certificate Updater'
    $form.ClientSize = New-Object System.Drawing.Size(900, 720)
    $form.StartPosition = 'CenterScreen'; $form.FormBorderStyle = 'FixedSingle'; $form.MaximizeBox = $false
    $form.BackColor = $cBg; $form.ForeColor = $cText; $form.Font = $fText

    $lblTitle = New-Label 'Secure Boot Certificate Updater' 16 10 868 28
    $lblTitle.Font = $fTitle
    $form.Controls.Add($lblTitle)

    # --- State ---
    $lblSbCap = New-Label 'Secure Boot' 16 48 284 20;                                 $lblSbCap.ForeColor = $cMuted
    $lblSb    = New-Label '' 304 48 580 20
    $lblOsCap = New-Label 'Windows' 16 70 284 20;                                     $lblOsCap.ForeColor = $cMuted
    $lblOs    = New-Label '' 304 70 580 20
    $lblDbCap = New-Label 'Windows UEFI CA 2023 in the Secure Boot DB' 16 92 284 20;  $lblDbCap.ForeColor = $cMuted
    $lblDb    = New-Label '' 304 92 580 20
    $lblKbCap = New-Label 'KB5073724 (Windows 10 only)' 16 114 284 20;               $lblKbCap.ForeColor = $cMuted
    $lblKb    = New-Label '' 304 114 580 20
    $lblRgCap = New-Label 'Pending update flag (AvailableUpdates)' 16 136 284 20;    $lblRgCap.ForeColor = $cMuted
    $lblRg    = New-Label '' 304 136 580 20
    foreach ($c in $lblSbCap, $lblSb, $lblOsCap, $lblOs, $lblDbCap, $lblDb, $lblKbCap, $lblKb, $lblRgCap, $lblRg) { $form.Controls.Add($c) }

    $lblSummary = New-Label '' 16 162 868 24
    $lblSummary.Font = $fBold
    $form.Controls.Add($lblSummary)

    # --- Certificates found in the firmware ---
    $lvCerts = New-Ctl 'ListView' 16 192 868 150
    $lvCerts.View = 'Details'; $lvCerts.FullRowSelect = $true; $lvCerts.HideSelection = $true
    $lvCerts.BackColor = $cBox; $lvCerts.ForeColor = $cText; $lvCerts.Font = $fText; $lvCerts.HeaderStyle = 'Nonclickable'
    [void]$lvCerts.Columns.Add('Store', 70)
    [void]$lvCerts.Columns.Add('Certificate', 430)
    [void]$lvCerts.Columns.Add('Status', 200)
    [void]$lvCerts.Columns.Add('Expires', 140)
    $form.Controls.Add($lvCerts)

    # --- What to do ---
    $lblWhat = New-Label 'What to do (same steps as Update-SecureBootCert.ps1):' 16 352 868 20
    $lblWhat.Font = $fBold
    $form.Controls.Add($lblWhat)
    $chkKb     = New-Check 'Install KB5073724 (Windows 10 only; skipped when UEFI CA 2023 is already in the DB)' 24 376 860 $true
    $chkWu     = New-Check 'Also install ALL pending Windows updates (can take a long time)' 24 400 860 $false
    $chkDeploy = New-Check 'Deploy Windows UEFI CA 2023 to the Secure Boot DB (registry value + scheduled task)' 24 424 860 $true
    foreach ($c in $chkKb, $chkWu, $chkDeploy) { $form.Controls.Add($c) }

    $btnRefresh = New-Btn 'Refresh' 16 456 140 40 $cGrey
    $btnStart   = New-Btn 'Start update' 168 456 520 40 $cOrange
    $btnRestart = New-Btn 'Restart now' 700 456 184 40 $cBlue
    $btnRestart.Enabled = $false
    foreach ($c in $btnRefresh, $btnStart, $btnRestart) { $form.Controls.Add($c) }

    $txtLog = New-Ctl 'TextBox' 16 506 868 170
    $txtLog.Multiline = $true; $txtLog.ReadOnly = $true; $txtLog.ScrollBars = 'Vertical'
    $txtLog.BackColor = $cBox; $txtLog.ForeColor = Rgb @(210, 210, 210); $txtLog.Font = $fMono
    $form.Controls.Add($txtLog)

    $lblFoot = New-Label 'Two restarts are needed for the Secure Boot DB change. Back up your BitLocker recovery key before you start. Use at your own risk.' 16 684 868 28
    $lblFoot.ForeColor = $cMuted
    $form.Controls.Add($lblFoot)

    function Write-Log([string]$t) {
        $txtLog.AppendText($t + "`r`n")
        [System.Windows.Forms.Application]::DoEvents()
    }

    function Set-Busy([bool]$busy) {
        $form.UseWaitCursor = $busy
        foreach ($c in $btnRefresh, $btnStart, $chkKb, $chkWu, $chkDeploy) { $c.Enabled = (-not $busy) }
        if ($busy) { $btnRestart.Enabled = $false } elseif ($script:NeedsRestart) { $btnRestart.Enabled = $true }
        [System.Windows.Forms.Application]::DoEvents()
    }

    function Set-Value($label, [string]$text, $color) { $label.Text = $text; $label.ForeColor = $color }

    # Reads the state and fills the window
    function Update-View {
        $lblSummary.Text = 'Reading the state...'; $lblSummary.ForeColor = $cMuted
        [System.Windows.Forms.Application]::DoEvents()
        $st = Get-Status
        $script:State = $st

        if ($st.SecureBoot -eq $true) { Set-Value $lblSb 'Enabled' $cGreen }
        elseif ($st.SecureBoot -eq $false) { Set-Value $lblSb 'DISABLED (updates install, but only apply when it is turned on)' $cYellow }
        else { Set-Value $lblSb 'Unknown (legacy BIOS, or not supported)' $cMuted }
        Set-Value $lblOs ('{0} (build {1})' -f $st.Os.Name, $st.Os.Build) $cText
        if ($st.Uefi2023) { Set-Value $lblDb 'Yes' $cGreen } else { Set-Value $lblDb 'No' $cOrange }
        if ($st.Os.IsWin10) {
            if ($st.Kb) { Set-Value $lblKb 'Installed' $cGreen } else { Set-Value $lblKb 'Not installed' $cMuted }
        } else { Set-Value $lblKb 'Not needed on this Windows' $cMuted }
        if ($null -eq $st.Reg) { Set-Value $lblRg 'not set' $cMuted } else { Set-Value $lblRg ('0x{0:X}' -f [int]$st.Reg) $cText }

        $lvCerts.Items.Clear()
        foreach ($d in $st.Certs) {
            $store = if ($d.Store -eq 'db') { 'DB' } else { 'KEK' }
            $it = New-Object System.Windows.Forms.ListViewItem($store)
            switch ($d.State) {
                'new'     { $status = 'Valid';        $col = $cGreen }
                'expired' { $status = 'EXPIRED';      $col = $cRed }
                default   { $status = 'Expires soon'; $col = $cYellow }
            }
            [void]$it.SubItems.Add($d.Name); [void]$it.SubItems.Add($status); [void]$it.SubItems.Add($d.Expiry)
            $it.ForeColor = $col
            [void]$lvCerts.Items.Add($it)
        }
        if ($st.Certs.Count -eq 0) {
            $it = New-Object System.Windows.Forms.ListViewItem('-')
            [void]$it.SubItems.Add('Could not read the certificates from the firmware (Secure Boot not available?)')
            $it.ForeColor = $cMuted
            [void]$lvCerts.Items.Add($it)
        }

        $chkKb.Enabled = $st.Os.IsWin10
        if (-not $st.Os.IsWin10) { $chkKb.Checked = $false }

        if ($st.Uefi2023) { Set-Value $lblSummary 'Windows UEFI CA 2023 is already in the Secure Boot DB. Nothing to do.' $cGreen }
        elseif ($st.SecureBoot -eq $false) { Set-Value $lblSummary 'Secure Boot is off. You can still run the update; it applies once Secure Boot is turned on.' $cYellow }
        else { Set-Value $lblSummary 'The 2023 certificate is NOT in the Secure Boot DB yet. Choose what to do and click Start update.' $cOrange }
    }

    function Start-Update {
        $st = $script:State
        if (-not ($chkKb.Checked -or $chkWu.Checked -or $chkDeploy.Checked)) {
            [void][System.Windows.Forms.MessageBox]::Show('Tick at least one action.', 'Secure Boot', 'OK', 'Information'); return
        }
        $q = "This changes how this PC starts (Secure Boot certificates).`r`n`r`n" +
             "- If you use BitLocker, make sure you have the recovery key.`r`n" +
             "- Do not turn the PC off while it runs.`r`n" +
             "- Two restarts are needed afterwards.`r`n`r`nContinue?"
        if ([System.Windows.Forms.MessageBox]::Show($q, 'Secure Boot', 'YesNo', 'Warning') -ne 'Yes') { Write-Log 'Cancelled.'; return }

        Set-Busy $true
        $script:NeedsRestart = $false
        $uefi = $st.Uefi2023
        Write-Log ''
        Write-Log ('=== ' + (Get-Date -Format 'yyyy-MM-dd HH:mm') + ' ===')

        if ($chkKb.Checked) {
            Write-Log 'Step: KB5073724'
            if (-not $st.Os.IsWin10) { Write-Log 'Skipped (Windows 10 only).' }
            elseif ($uefi)           { Write-Log 'Skipped (UEFI CA 2023 is already in the DB).' }
            elseif ($st.Kb)          { Write-Log 'Skipped (already installed).' }
            elseif (Install-Kb5073724) { $script:NeedsRestart = $true }
        }
        if ($chkWu.Checked) {
            Write-Log 'Step: Windows Update'
            if ($uefi) { Write-Log 'Skipped (UEFI CA 2023 is already in the DB).' }
            elseif (Install-WindowsUpdates) { $script:NeedsRestart = $true }
        }
        if ($chkDeploy.Checked) {
            Write-Log 'Step: deploy Windows UEFI CA 2023'
            if ($uefi) { Write-Log 'Skipped (already in the DB).' }
            elseif (Install-UefiCa2023) { $script:NeedsRestart = $true }
        }

        Write-Log ''
        Write-Log 'Done.'
        if ($script:NeedsRestart) { Write-Log 'IMPORTANT: restart the PC TWICE to finish the Secure Boot DB update.' }
        Set-Busy $false
        Update-View
    }

    $btnRefresh.Add_Click({ try { Set-Busy $true; Update-View } catch { Write-Log ('ERROR: ' + $_.Exception.Message) } finally { Set-Busy $false } })
    $btnStart.Add_Click({ try { Start-Update } catch { Write-Log ('ERROR: ' + $_.Exception.Message); Set-Busy $false } })
    $btnRestart.Add_Click({
        try {
            $q = "The PC will restart in 30 seconds.`r`n`r`nSave your work first. You can cancel by running:  shutdown /a`r`n`r`nRestart now?"
            if ([System.Windows.Forms.MessageBox]::Show($q, 'Restart', 'YesNo', 'Warning') -eq 'Yes') {
                Write-Log 'Restarting in 30 seconds (cancel with: shutdown /a)...'
                & shutdown.exe /r /t 30 /c 'Secure Boot certificate update'
            }
        } catch { Write-Log ('ERROR: ' + $_.Exception.Message) }
    })

    $script:NeedsRestart = $false
    $script:State = $null
    Write-Log 'Secure Boot Certificate Updater'
    Write-Log 'Nothing is changed until you click Start update and confirm.'

    $form.Add_Shown({
        try { $form.Activate(); Set-Busy $true; Update-View } catch { Write-Log ('ERROR: ' + $_.Exception.Message) } finally { Set-Busy $false }
    })
    [void]$form.ShowDialog()
    exit 0
} catch {
    $msg = 'Unexpected error: ' + $_.Exception.Message + "`r`nLine " + $_.InvocationInfo.ScriptLineNumber
    try { Add-Type -AssemblyName System.Windows.Forms; [void][System.Windows.Forms.MessageBox]::Show($msg, 'Secure Boot Certificate Updater', 'OK', 'Error') } catch { Write-Host $msg -ForegroundColor Red }
    exit 1
}
