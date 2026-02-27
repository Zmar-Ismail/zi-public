<#
.SYNOPSIS
    This PowerShell script ensures that the maximum size of the Windows Application event log is at least 32768 KB (32 MB).

.NOTES
    Author          : Zmar Ismail
    LinkedIn        : linkedin.com/in/zmarismail/
    GitHub          : github.com/zmar-i
    Date Created    : 2026-02-11
    Last Modified   : 2026-02-11
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-AU-000500

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Run this script in an elevated PowerShell session (Run as Administrator).

    After execution, verify the setting in:
    HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application
    Value Name: MaxSize (DWORD) = 32768
#>

# Define the registry path
$RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application"

# Create the key if it does not exist
If (-Not (Test-Path $RegPath)) {
    New-Item -Path $RegPath -Force | Out-Null
}

# Set MaxSize to 0x8000 (32768 in decimal)
New-ItemProperty -Path $RegPath `
    -Name "MaxSize" `
    -Value 0x8000 `
    -PropertyType DWord `
    -Force
