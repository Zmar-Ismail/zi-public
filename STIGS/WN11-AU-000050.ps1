<#
.SYNOPSIS
    Enables advanced audit policy override and configures Success auditing for Process Creation, ensuring detailed process activity (Event ID 4688) is logged in the Security log for compliance and monitoring.

.NOTES
    Author          : Zmar Ismail
    LinkedIn        : linkedin.com/in/zmarismail/
    GitHub          : github.com/Zmar-Ismail
    Date Created    : 2026-02-12
    Last Modified   : 2026-02-12
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-AU-000050

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
  - Sets HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\SCENoApplyLegacyAuditPolicy = 1
  - Enables Success auditing for "Process Creation" (Event ID 4688)
#>

# Ensure script is running as Administrator
If (-NOT ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
    [Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "This script must be run as Administrator."
    Exit 1
}

# 1. Enable: Audit - Force audit policy subcategory settings to override category settings
$LsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"

If (-Not (Test-Path $LsaPath)) {
    Write-Error "LSA registry path not found."
    Exit 1
}

New-ItemProperty -Path $LsaPath `
    -Name "SCENoApplyLegacyAuditPolicy" `
    -Value 1 `
    -PropertyType DWord `
    -Force | Out-Null

# 2. Enable Success auditing for Process Creation
auditpol /set /subcategory:"Process Creation" /success:enable /failure:disable

# 3. Verification Output
Write-Host "`nVerification:`n" -ForegroundColor Cyan

Write-Host "SCENoApplyLegacyAuditPolicy value:"
Get-ItemProperty -Path $LsaPath -Name "SCENoApplyLegacyAuditPolicy" |
    Select-Object SCENoApplyLegacyAuditPolicy

Write-Host "`nProcess Creation audit setting:"
auditpol /get /subcategory:"Process Creation"
