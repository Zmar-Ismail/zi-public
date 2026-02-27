<#
.SYNOPSIS
    Creates the HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers registry path if it does not exist and sets the DisableHTTPPrinting REG_DWORD value to 1, effectively enabling the “Turn off printing over HTTP” policy and disabling HTTP-based printing on the system.

.NOTES
    Author          : Zmar Ismail
    LinkedIn        : linkedin.com/in/zmarismail/
    GitHub          : github.com/zmar-i
    Date Created    : 2026-02-12
    Last Modified   : 2026-02-12
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000110

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Run this script in an elevated PowerShell session (Run as Administrator).
    This will create the required registry path (if missing) and enforce
    the “Turn off printing over HTTP” policy.
#>

$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers"
$valueName = "DisableHTTPPrinting"

# Create the registry path if it does not exist
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

# Set the policy value
New-ItemProperty -Path $regPath `
                 -Name $valueName `
                 -PropertyType DWord `
                 -Value 1 `
                 -Force | Out-Null

Write-Output "Remediation complete: HTTP printing has been disabled."
