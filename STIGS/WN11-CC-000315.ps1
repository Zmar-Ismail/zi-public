<#
.SYNOPSIS
    This PowerShell script disables the Windows Installer “AlwaysInstallElevated” policy by setting the registry value to 0, preventing privilege escalation by standard users.

.NOTES
    Author          : Zmar Ismail
    LinkedIn        : linkedin.com/in/zmarismail/
    GitHub          : github.com/Zmar-Ismail
    Date Created    : 2026-02-11
    Last Modified   : 2026-02-11
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000315

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
Run this script with administrative privileges.

    Verify the setting:
    PS C:\> Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated
#>

# Define registry path
$RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"

# Create the key if it does not exist
if (-not (Test-Path $RegPath)) {
    New-Item -Path $RegPath -Force | Out-Null
}

# Set AlwaysInstallElevated to 0 (Disabled)
New-ItemProperty -Path $RegPath `
    -Name "AlwaysInstallElevated" `
    -Value 0 `
    -PropertyType DWord `
    -Force
