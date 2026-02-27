<#
.SYNOPSIS
    Configures the local machine to always reprocess registry-based Group Policy settings by ensuring the NoGPOListChanges registry value is set to 0 under the appropriate Group Policy processing key.

    The script creates the required registry path if it does not exist, sets the value as a REG_DWORD, and verifies compliance to ensure registry policies are reapplied even when Group Policy Objects have not changed.

.NOTES
    Author          : Zmar Ismail
    LinkedIn        : linkedin.com/in/zmarismail/
    GitHub          : github.com/zmar-i
    Date Created    : 2026-02-12
    Last Modified   : 2026-02-12
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000090

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Run PowerShell as Administrator.

    No parameters are required. The script will create the registry path if missing,
    configure the required value, and display a success or failure message.
#>

# Define registry path and value
$RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}"
$ValueName = "NoGPOListChanges"
$DesiredValue = 0

# Ensure the registry path exists
if (-not (Test-Path $RegPath)) {
    New-Item -Path $RegPath -Force | Out-Null
    Write-Output "Created registry path: $RegPath"
}

# Set the registry value
New-ItemProperty -Path $RegPath `
                 -Name $ValueName `
                 -PropertyType DWord `
                 -Value $DesiredValue `
                 -Force | Out-Null

Write-Output "Registry value '$ValueName' set to $DesiredValue"

# Verification
$CurrentValue = Get-ItemProperty -Path $RegPath -Name $ValueName -ErrorAction SilentlyContinue

if ($CurrentValue.$ValueName -eq $DesiredValue) {
    Write-Output "SUCCESS: Registry is configured correctly."
} else {
    Write-Output "FAILURE: Registry is not configured correctly."
}
