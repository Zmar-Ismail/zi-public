<#
.SYNOPSIS
    Checks and automatically remediates the Windows Hello for Business policy:
    "Use a hardware security device" (RequireSecurityDevice=1).

.NOTES
    Author          : Zmar Ismail
    LinkedIn        : linkedin.com/in/zmarismail/
    GitHub          : github.com/zmar-i
    Date Created    : 2026-02-13
    Last Modified   : 2026-02-13
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000255

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Run in an elevated PowerShell session).

    The script automatically:
    - Checks if RequireSecurityDevice is set to 1
    - Creates the registry path if missing
    - Sets the value to compliant if not configured

    Exit Codes:
    0 = Compliant or successfully remediated
    1 = Not remediated (not running as Administrator)
    2 = Unexpected error
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param()

$ErrorActionPreference = 'Stop'

$RegPath      = 'HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork'
$ValueName    = 'RequireSecurityDevice'
$DesiredValue = 1

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-PolicyValue {
    if (-not (Test-Path -LiteralPath $RegPath)) { return $null }
    try {
        (Get-ItemProperty -LiteralPath $RegPath -Name $ValueName -ErrorAction Stop).$ValueName
    } catch {
        $null
    }
}

function Ensure-Policy {
    if (-not (Test-Path -LiteralPath $RegPath)) {
        New-Item -Path $RegPath -Force | Out-Null
    }

    # Create or update as DWORD
    New-ItemProperty -Path $RegPath -Name $ValueName -PropertyType DWord -Value $DesiredValue -Force | Out-Null
}

try {
    $current = Get-PolicyValue

    if ($current -eq $DesiredValue) {
        Write-Host "COMPLIANT: $ValueName is set to $DesiredValue at $RegPath."
        exit 0
    }

    # Not compliant -> attempt remediation automatically
    if (-not (Test-IsAdmin)) {
        Write-Host "FINDING: $ValueName is not set to $DesiredValue at $RegPath (Current: $current)."
        Write-Host "NOT REMEDIATED: Run PowerShell as Administrator to set HKLM policy values."
        exit 1
    }

    if ($PSCmdlet.ShouldProcess("$RegPath\$ValueName", "Set DWORD to $DesiredValue")) {
        Ensure-Policy
    }

    $after = Get-PolicyValue
    if ($after -eq $DesiredValue) {
        Write-Host "REMEDIATED: $ValueName is now set to $DesiredValue at $RegPath."
        exit 0
    } else {
        Write-Host "FAILED: Unable to set $ValueName to $DesiredValue at $RegPath (Current: $after)."
        exit 1
    }
}
catch {
    Write-Host "ERROR: $($_.Exception.Message)"
    exit 2
}
