#
# PowerShell script to install and configure OpenSSH Server on Windows 10 and Windows 11.
#
# This script performs the following actions:
#
#   - Installs OpenSSH Server if not already installed.
#
#   - Starts the SSH service and configures it to start on boot.
#
#   - Adds a firewall rule to allow SSH connections on port 22.
#
#   - Ensures the .ssh directory exists with correct permissions.
#
#   - Allows the user to add an SSH public key to the authorized_keys file.
#
#   - Displays the local IP addresses for SSH connection.
#
#
# How to Run PowerShell Scripts in Windows:
#
#   By default, PowerShell script execution is restricted. To allow this
#   script to run, follow these steps:
#
#     1. Open PowerShell as Administrator.
#
#     2. Check the current execution policy:
#          Get-ExecutionPolicy
#
#     3. If it is set to 'Restricted', allow script execution with:
#          Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
#
#     4. Run this script:
#          ./win-sshd-setup.ps1
#
#     5. After execution, you may revert the policy using:
#          Set-ExecutionPolicy Restricted -Scope CurrentUser
#



Write-Host "Checking OpenSSH installation..." -ForegroundColor Cyan
$sshServer = Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH.Server*'

if ($sshServer.State -eq 'NotPresent') {
    Write-Host "Installing OpenSSH Server..." -ForegroundColor Yellow
    Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
    Write-Host "Installation complete. Please restart your computer and re-run this script." -ForegroundColor Red
    exit 1
} else {
    Write-Host "OpenSSH Server is already installed." -ForegroundColor Green
}

# Determine the correct SSH service name
$sshService = Get-Service | Where-Object { $_.Name -like "*ssh*" -and $_.Name -ne "ssh-agent" } | Select-Object -ExpandProperty Name -ErrorAction SilentlyContinue

if (-not $sshService) {
    Write-Host "No SSH service found. Attempting to create the sshd service..." -ForegroundColor Yellow
    sc.exe create sshd binPath= "C:\Windows\System32\OpenSSH\sshd.exe" start= auto
    Start-Sleep -Seconds 3
    $sshService = "sshd"
}

# Start the SSH service
Write-Host "Starting SSH service ($sshService)..." -ForegroundColor Cyan
Start-Service $sshService

# Set SSH service to start automatically
Write-Host "Configuring SSH service to start on boot..." -ForegroundColor Cyan
Set-Service -Name $sshService -StartupType Automatic

# Allow SSH through Windows Firewall
Write-Host "Configuring Windows Firewall to allow SSH connections..." -ForegroundColor Cyan
New-NetFirewallRule -Name sshd -DisplayName "OpenSSH Server (sshd)" -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22 -ErrorAction SilentlyContinue

# Verify SSH service status
Write-Host "Checking SSH service status..." -ForegroundColor Cyan
$serviceStatus = Get-Service -Name $sshService
if ($serviceStatus.Status -eq "Running") {
    Write-Host "SSH is running successfully!" -ForegroundColor Green
} else {
    Write-Host "SSH service is NOT running. Try starting it manually: Start-Service $sshService" -ForegroundColor Red
}

# Verify SSH is listening on port 22
Write-Host "Checking if SSH is listening on port 22..." -ForegroundColor Cyan
$portCheck = netstat -an | Select-String ":22"
if ($portCheck) {
    Write-Host "SSH is listening on port 22!" -ForegroundColor Green
} else {
    Write-Host "SSH is NOT listening on port 22. Check your firewall and service status." -ForegroundColor Red
}

# Ensure proper permissions for .ssh directory
$sshDir = "$env:USERPROFILE\.ssh"
if (!(Test-Path $sshDir)) {
    try {
        New-Item -ItemType Directory -Path $sshDir -Force | Out-Null
    } catch {
        Write-Host "Warning: Failed to create .ssh directory, but continuing." -ForegroundColor Yellow
    }
}

# Ask user for SSH key
$sshKey = Read-Host "Paste your SSH public key (leave blank to skip)"
if ($sshKey -ne "") {
    $keyFile = "$sshDir\authorized_keys"

    # Ensure the authorized_keys file exists before setting permissions
    if (!(Test-Path $keyFile)) {
        New-Item -ItemType File -Path $keyFile -Force | Out-Null
    }

    # Append the SSH key to the file before modifying permissions
    Add-Content -Path $keyFile -Value $sshKey
    Write-Host "SSH key saved successfully! Applying correct permissions..." -ForegroundColor Green

    # Set correct permissions after saving the key
    icacls $sshDir /setowner "$env:USERNAME" /T

    # Restart SSH service
    Restart-Service $sshService
}

# Display local IP address for SSH connection
Write-Host "`nYour local IP addresses (use one of these to connect via SSH):" -ForegroundColor Cyan
Get-NetIPAddress | Where-Object { $_.AddressFamily -eq "IPv4" -and $_.InterfaceAlias -notlike "*Loopback*" } | Select-Object -ExpandProperty IPAddress

Write-Host "`nTo connect from another computer, use: ssh <your-username>@<your-ip-address>`n" -ForegroundColor Yellow
