<# 
    Enhanced Web Server Installer Script with GUI Settings
    ---------------------------------------------------------
    This script installs Apache web server and PHP on Windows with robust
    error handling, logging (console & file), progress indicators, configuration
    persistence via a JSON file, service management, and a module to display network
    connections (incoming/outgoing with host names).

    A GUI for settings is available (accessed via option 3) to allow you to browse
    for install directories and adjust settings easily. Default values have been chosen
    as best practices: Apache is installed to C:\Apache24, PHP to C:\Apache24\php, with
    recommended download URLs and settings.

    To launch this script remotely, use:
    iwr -useb 'https://raw.githubusercontent.com/AsheshDev/site/refs/heads/main/apache.ps1' | iex

    Ensure you run this script as Administrator.
#>

# Ensure $PSScriptRoot is set; if not, fallback to the current directory.
if (-not $PSScriptRoot) {
    $PSScriptRoot = (Get-Location).Path
}

# Load necessary assemblies for GUI.
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Check for Administrator privileges.
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "This script must be run as Administrator." -ForegroundColor Red
    exit
}

# Global config file path (in the same directory as the script)
$global:ConfigPath = Join-Path -Path $PSScriptRoot -ChildPath "config.json"
$global:Config = @{}

# Function: Load configuration from JSON file or create default configuration.
function Load-Config {
    if (Test-Path $global:ConfigPath) {
        try {
            $global:Config = Get-Content $global:ConfigPath | ConvertFrom-Json
        }
        catch {
            Write-Host "Error loading configuration. Using default settings." -ForegroundColor Yellow
            $global:Config = $null
        }
    }
    if (-not $global:Config) {
        # Best default configuration settings.
        $global:Config = @{
            ApacheInstallPath   = "C:\Apache24"
            ApacheDownloadUrl   = "https://www.apachelounge.com/download/VC15/binaries/httpd-2.4.54-win64-VS16.zip"
            PHPInstallPath      = "C:\Apache24\php"
            PHPDownloadUrl      = "https://windows.php.net/downloads/releases/php-8.0.13-Win32-vs16-x64.zip"
            DebugMode           = $true
            LogFilePath         = (Join-Path -Path $PSScriptRoot -ChildPath "installer.log")
            ApacheServiceName   = "Apache2.4"
        }
        Save-Config
    }
}

# Function: Save configuration to JSON file.
function Save-Config {
    try {
        $global:Config | ConvertTo-Json -Depth 4 | Out-File -FilePath $global:ConfigPath -Encoding UTF8
    }
    catch {
        Write-Host "Error saving configuration: $_" -ForegroundColor Red
    }
}

# Load configuration at start.
Load-Config

# Function: Write log message to console (if DebugMode) and to log file.
function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "$timestamp [$Level] $Message"
    if ($global:Config.DebugMode -or $Level -eq "ERROR") {
        Write-Host $logEntry -ForegroundColor Yellow
    }
    try {
        Add-Content -Path $global:Config.LogFilePath -Value $logEntry
    }
    catch {
        Write-Host "Failed to write to log file: $_" -ForegroundColor Red
    }
}

# Function: Download file with progress indicator.
function Download-FileWithProgress {
    param(
        [Parameter(Mandatory=$true)][string]$Uri,
        [Parameter(Mandatory=$true)][string]$Destination
    )
    Write-Log "Starting download from $Uri to $Destination"
    $wc = New-Object System.Net.WebClient
    $wc.DownloadProgressChanged += {
        Write-Progress -Activity "Downloading File" -Status "$($_.ProgressPercentage)% complete" -PercentComplete $_.ProgressPercentage
    }
    $wc.DownloadFileCompleted += {
        Write-Progress -Activity "Downloading File" -Completed -Status "Download complete!"
        Write-Log "Download completed for $Uri"
    }
    try {
        $wc.DownloadFileAsync([uri]$Uri, $Destination)
        while ($wc.IsBusy) { Start-Sleep -Milliseconds 100 }
    }
    catch {
        Write-Log "Error downloading file: $_" "ERROR"
        throw $_
    }
}

# Function: Install Apache Web Server.
function Install-Apache {
    Write-Log "Starting Apache installation..."
    try {
        if (-not (Test-Path $global:Config.ApacheInstallPath)) {
            Write-Log "Creating Apache directory at $($global:Config.ApacheInstallPath)"
            New-Item -ItemType Directory -Path $global:Config.ApacheInstallPath -Force | Out-Null
        }
        $tempZip = "$env:TEMP\apache.zip"
        Write-Log "Downloading Apache from $($global:Config.ApacheDownloadUrl)"
        Download-FileWithProgress -Uri $global:Config.ApacheDownloadUrl -Destination $tempZip
        Write-Log "Extracting Apache zip file to $($global:Config.ApacheInstallPath)"
        Expand-Archive -Path $tempZip -DestinationPath $global:Config.ApacheInstallPath -Force
        Remove-Item $tempZip -Force
        Write-Log "Apache installed successfully at $($global:Config.ApacheInstallPath)"
        Write-Host "Apache installed successfully." -ForegroundColor Green
    }
    catch {
        Write-Log "Error installing Apache: $_" "ERROR"
        Write-Host "Error installing Apache. Check log for details." -ForegroundColor Red
    }
    Pause-AndReturn
}

# Function: Install PHP.
function Install-PHP {
    Write-Log "Starting PHP installation..."
    try {
        if (-not (Test-Path $global:Config.PHPInstallPath)) {
            Write-Log "Creating PHP directory at $($global:Config.PHPInstallPath)"
            New-Item -ItemType Directory -Path $global:Config.PHPInstallPath -Force | Out-Null
        }
        $tempZip = "$env:TEMP\php.zip"
        Write-Log "Downloading PHP from $($global:Config.PHPDownloadUrl)"
        Download-FileWithProgress -Uri $global:Config.PHPDownloadUrl -Destination $tempZip
        Write-Log "Extracting PHP zip file to $($global:Config.PHPInstallPath)"
        Expand-Archive -Path $tempZip -DestinationPath $global:Config.PHPInstallPath -Force
        Remove-Item $tempZip -Force
        Write-Log "PHP installed successfully at $($global:Config.PHPInstallPath)"
        Write-Host "PHP installed successfully." -ForegroundColor Green
    }
    catch {
        Write-Log "Error installing PHP: $_" "ERROR"
        Write-Host "Error installing PHP. Check log for details." -ForegroundColor Red
    }
    Pause-AndReturn
}

# Function: Uninstall Apache and PHP.
function Uninstall-Applications {
    Write-Host "WARNING: This will remove the Apache and PHP installation directories." -ForegroundColor Red
    $confirm = Read-Host "Are you sure you want to proceed? (Y/N)"
    if ($confirm -match '^(y|Y)$') {
        try {
            if (Test-Path $global:Config.ApacheInstallPath) {
                Write-Log "Removing Apache installation at $($global:Config.ApacheInstallPath)"
                Remove-Item $global:Config.ApacheInstallPath -Recurse -Force
            }
            if (Test-Path $global:Config.PHPInstallPath) {
                Write-Log "Removing PHP installation at $($global:Config.PHPInstallPath)"
                Remove-Item $global:Config.PHPInstallPath -Recurse -Force
            }
            Write-Host "Uninstallation completed." -ForegroundColor Green
            Write-Log "Uninstallation of Apache and PHP completed."
        }
        catch {
            Write-Log "Error during uninstallation: $_" "ERROR"
            Write-Host "Error during uninstallation. Check log for details." -ForegroundColor Red
        }
    }
    Pause-AndReturn
}

# Function: Install Apache as a Windows Service.
function Install-ApacheService {
    Write-Log "Installing Apache as a Windows service..."
    $httpdPath = Join-Path -Path $global:Config.ApacheInstallPath -ChildPath "bin\httpd.exe"
    if (-not (Test-Path $httpdPath)) {
        Write-Host "Apache executable not found at $httpdPath" -ForegroundColor Red
        Pause-AndReturn
        return
    }
    try {
        & $httpdPath -k install
        Write-Log "Apache service installed successfully."
        Write-Host "Apache service installed successfully." -ForegroundColor Green
    }
    catch {
        Write-Log "Error installing Apache service: $_" "ERROR"
        Write-Host "Error installing Apache service." -ForegroundColor Red
    }
    Pause-AndReturn
}

# Function: Start Apache Service.
function Start-ApacheService {
    Write-Log "Starting Apache service..."
    try {
        Start-Service -Name $global:Config.ApacheServiceName
        Write-Log "Apache service started."
        Write-Host "Apache service started." -ForegroundColor Green
    }
    catch {
        Write-Log "Error starting Apache service: $_" "ERROR"
        Write-Host "Error starting Apache service." -ForegroundColor Red
    }
    Pause-AndReturn
}

# Function: Stop Apache Service.
function Stop-ApacheService {
    Write-Log "Stopping Apache service..."
    try {
        Stop-Service -Name $global:Config.ApacheServiceName
        Write-Log "Apache service stopped."
        Write-Host "Apache service stopped." -ForegroundColor Green
    }
    catch {
        Write-Log "Error stopping Apache service: $_" "ERROR"
        Write-Host "Error stopping Apache service." -ForegroundColor Red
    }
    Pause-AndReturn
}

# Function: Restart Apache Service.
function Restart-ApacheService {
    Write-Log "Restarting Apache service..."
    try {
        Restart-Service -Name $global:Config.ApacheServiceName
        Write-Log "Apache service restarted."
        Write-Host "Apache service restarted." -ForegroundColor Green
    }
    catch {
        Write-Log "Error restarting Apache service: $_" "ERROR"
        Write-Host "Error restarting Apache service." -ForegroundColor Red
    }
    Pause-AndReturn
}

# Function: Display network connections (incoming/outgoing) with host names and IPs.
function Show-NetworkConnections {
    Write-Log "Displaying current network connections..."
    try {
        $connections = Get-NetTCPConnection
        $results = @()
        foreach ($conn in $connections) {
            $remoteHost = ""
            if ($conn.RemoteAddress -and $conn.RemoteAddress -ne "0.0.0.0" -and $conn.RemoteAddress -ne "::") {
                try {
                    $entry = [System.Net.Dns]::GetHostEntry($conn.RemoteAddress)
                    $remoteHost = $entry.HostName
                }
                catch {
                    $remoteHost = "N/A"
                }
            }
            else {
                $remoteHost = "Local/None"
            }
            $results += [PSCustomObject]@{
                "LocalAddress"  = $conn.LocalAddress
                "LocalPort"     = $conn.LocalPort
                "RemoteAddress" = $conn.RemoteAddress
                "RemotePort"    = $conn.RemotePort
                "State"         = $conn.State
                "RemoteHost"    = $remoteHost
            }
        }
        $results | Format-Table -AutoSize
    }
    catch {
        Write-Log "Error displaying network connections: $_" "ERROR"
        Write-Host "Error retrieving network connections." -ForegroundColor Red
    }
    Pause-AndReturn
}

# Function: Show Settings GUI to browse and change installation paths and URLs.
function Show-SettingsGUI {
    # Create the form.
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "Installer Settings"
    $form.Size = New-Object System.Drawing.Size(600, 400)
    $form.StartPosition = "CenterScreen"

    # Apache Install Path
    $labelApachePath = New-Object System.Windows.Forms.Label
    $labelApachePath.Text = "Apache Install Path:"
    $labelApachePath.Location = New-Object System.Drawing.Point(10, 20)
    $labelApachePath.AutoSize = $true
    $form.Controls.Add($labelApachePath)

    $textApachePath = New-Object System.Windows.Forms.TextBox
    $textApachePath.Location = New-Object System.Drawing.Point(150, 20)
    $textApachePath.Size = New-Object System.Drawing.Size(300, 20)
    $textApachePath.Text = $global:Config.ApacheInstallPath
    $form.Controls.Add($textApachePath)

    $btnBrowseApache = New-Object System.Windows.Forms.Button
    $btnBrowseApache.Text = "Browse..."
    $btnBrowseApache.Location = New-Object System.Drawing.Point(460, 20)
    $btnBrowseApache.Size = New-Object System.Drawing.Size(75, 23)
    $btnBrowseApache.Add_Click({
        $folderDlg = New-Object System.Windows.Forms.FolderBrowserDialog
        $folderDlg.SelectedPath = $textApachePath.Text
        if ($folderDlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            $textApachePath.Text = $folderDlg.SelectedPath
        }
    })
    $form.Controls.Add($btnBrowseApache)

    # PHP Install Path
    $labelPHPPath = New-Object System.Windows.Forms.Label
    $labelPHPPath.Text = "PHP Install Path:"
    $labelPHPPath.Location = New-Object System.Drawing.Point(10, 60)
    $labelPHPPath.AutoSize = $true
    $form.Controls.Add($labelPHPPath)

    $textPHPPath = New-Object System.Windows.Forms.TextBox
    $textPHPPath.Location = New-Object System.Drawing.Point(150, 60)
    $textPHPPath.Size = New-Object System.Drawing.Size(300, 20)
    $textPHPPath.Text = $global:Config.PHPInstallPath
    $form.Controls.Add($textPHPPath)

    $btnBrowsePHP = New-Object System.Windows.Forms.Button
    $btnBrowsePHP.Text = "Browse..."
    $btnBrowsePHP.Location = New-Object System.Drawing.Point(460, 60)
    $btnBrowsePHP.Size = New-Object System.Drawing.Size(75, 23)
    $btnBrowsePHP.Add_Click({
        $folderDlg = New-Object System.Windows.Forms.FolderBrowserDialog
        $folderDlg.SelectedPath = $textPHPPath.Text
        if ($folderDlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            $textPHPPath.Text = $folderDlg.SelectedPath
        }
    })
    $form.Controls.Add($btnBrowsePHP)

    # Apache Download URL
    $labelApacheUrl = New-Object System.Windows.Forms.Label
    $labelApacheUrl.Text = "Apache Download URL:"
    $labelApacheUrl.Location = New-Object System.Drawing.Point(10, 100)
    $labelApacheUrl.AutoSize = $true
    $form.Controls.Add($labelApacheUrl)

    $textApacheUrl = New-Object System.Windows.Forms.TextBox
    $textApacheUrl.Location = New-Object System.Drawing.Point(150, 100)
    $textApacheUrl.Size = New-Object System.Drawing.Size(385, 20)
    $textApacheUrl.Text = $global:Config.ApacheDownloadUrl
    $form.Controls.Add($textApacheUrl)

    # PHP Download URL
    $labelPHPUrl = New-Object System.Windows.Forms.Label
    $labelPHPUrl.Text = "PHP Download URL:"
    $labelPHPUrl.Location = New-Object System.Drawing.Point(10, 140)
    $labelPHPUrl.AutoSize = $true
    $form.Controls.Add($labelPHPUrl)

    $textPHPUrl = New-Object System.Windows.Forms.TextBox
    $textPHPUrl.Location = New-Object System.Drawing.Point(150, 140)
    $textPHPUrl.Size = New-Object System.Drawing.Size(385, 20)
    $textPHPUrl.Text = $global:Config.PHPDownloadUrl
    $form.Controls.Add($textPHPUrl)

    # Debug Mode Checkbox
    $checkDebug = New-Object System.Windows.Forms.CheckBox
    $checkDebug.Text = "Enable Debug Mode"
    $checkDebug.Location = New-Object System.Drawing.Point(150, 180)
    $checkDebug.Checked = $global:Config.DebugMode
    $form.Controls.Add($checkDebug)

    # Apache Service Name
    $labelServiceName = New-Object System.Windows.Forms.Label
    $labelServiceName.Text = "Apache Service Name:"
    $labelServiceName.Location = New-Object System.Drawing.Point(10, 220)
    $labelServiceName.AutoSize = $true
    $form.Controls.Add($labelServiceName)

    $textServiceName = New-Object System.Windows.Forms.TextBox
    $textServiceName.Location = New-Object System.Drawing.Point(150, 220)
    $textServiceName.Size = New-Object System.Drawing.Size(300, 20)
    $textServiceName.Text = $global:Config.ApacheServiceName
    $form.Controls.Add($textServiceName)

    # Save button
    $btnSave = New-Object System.Windows.Forms.Button
    $btnSave.Text = "Save"
    $btnSave.Location = New-Object System.Drawing.Point(150, 260)
    $btnSave.Size = New-Object System.Drawing.Size(75, 23)
    $btnSave.Add_Click({
        $global:Config.ApacheInstallPath = $textApachePath.Text
        $global:Config.PHPInstallPath = $textPHPPath.Text
        $global:Config.ApacheDownloadUrl = $textApacheUrl.Text
        $global:Config.PHPDownloadUrl = $textPHPUrl.Text
        $global:Config.DebugMode = $checkDebug.Checked
        $global:Config.ApacheServiceName = $textServiceName.Text
        Save-Config
        [System.Windows.Forms.MessageBox]::Show("Settings saved.", "Information", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
        $form.Close()
    })
    $form.Controls.Add($btnSave)

    # Cancel button
    $btnCancel = New-Object System.Windows.Forms.Button
    $btnCancel.Text = "Cancel"
    $btnCancel.Location = New-Object System.Drawing.Point(250, 260)
    $btnCancel.Size = New-Object System.Drawing.Size(75, 23)
    $btnCancel.Add_Click({ $form.Close() })
    $form.Controls.Add($btnCancel)

    $form.Add_Shown({ $form.Activate() })
    [void]$form.ShowDialog()
}

# Function: Toggle Debug Mode.
function Toggle-DebugMode {
    $global:Config.DebugMode = -not $global:Config.DebugMode
    Write-Log "Debug Mode toggled to $($global:Config.DebugMode)"
    Write-Host "Debug Mode is now set to: $($global:Config.DebugMode)" -ForegroundColor Green
    Save-Config
    Start-Sleep -Seconds 2
}

# Helper function: Pause until key is pressed then clear the screen.
function Pause-AndReturn {
    Write-Host ""
    Write-Host "Press any key to return to the main menu..."
    [void][System.Console]::ReadKey($true)
    Clear-Host
}

# Function: Display Apache Service Management Menu.
function Manage-ApacheService {
    while ($true) {
        Clear-Host
        Write-Host "---- Apache Service Management ----" -ForegroundColor Cyan
        Write-Host "1. Install Apache as a Service"
        Write-Host "2. Start Apache Service"
        Write-Host "3. Stop Apache Service"
        Write-Host "4. Restart Apache Service"
        Write-Host "5. Return to Main Menu"
        $svcChoice = Read-Host "Enter your choice (1-5)"
        switch ($svcChoice) {
            "1" { Install-ApacheService }
            "2" { Start-ApacheService }
            "3" { Stop-ApacheService }
            "4" { Restart-ApacheService }
            "5" { break }
            default { Write-Host "Invalid selection. Please try again." -ForegroundColor Red; Start-Sleep -Seconds 2 }
        }
    }
}

# Function: Display the main CLI menu.
function Show-Menu {
    Clear-Host
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "         Enhanced Web Server Installer         " -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "1. Install Apache Web Server"
    Write-Host "2. Install PHP"
    Write-Host "3. Show/Change Settings (GUI)"
    Write-Host "4. Toggle Debug Mode"
    Write-Host "5. Manage Apache Service"
    Write-Host "6. Show Network Connections"
    Write-Host "7. Uninstall Apache/PHP"
    Write-Host "8. Exit"
    Write-Host "========================================" -ForegroundColor Cyan
}

# Main loop for the CLI menu.
while ($true) {
    Show-Menu
    $choice = Read-Host "Enter your choice (1-8)"
    switch ($choice) {
        "1" { Install-Apache }
        "2" { Install-PHP }
        "3" { Show-SettingsGUI }
        "4" { Toggle-DebugMode }
        "5" { Manage-ApacheService }
        "6" { Show-NetworkConnections }
        "7" { Uninstall-Applications }
        "8" { Write-Host "Exiting the installer. Goodbye!" -ForegroundColor Magenta; break }
        default { Write-Host "Invalid selection. Please try again." -ForegroundColor Red; Start-Sleep -Seconds 2 }
    }
}
