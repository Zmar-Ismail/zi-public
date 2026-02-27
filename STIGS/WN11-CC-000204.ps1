<#
.SYNOPSIS
    Configures the policy "Limit optional diagnostic data for Windows Analytics" by setting the
    LimitEnhancedDiagnosticDataWindowsAnalytics registry value to 1.

.NOTES
    Author          : Zmar Ismail
    LinkedIn        : linkedin.com/in/zmarismail/
    GitHub          : github.com/Zmar-Ismail
    Date Created    : 2026-02-13
    Last Modified   : 2026-02-13
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000204

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    1. Run PowerShell as Administrator.
    2. Execute the script:
    3. A compliance message will display.
       Exit code 0 = Compliant
       Exit code 1 = Not Compliant
       Exit code 2 = Error
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param()

$RegPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
$ValueName = 'LimitEnhancedDiagnosticDataWindowsAnalytics'
$DesiredValue = 1

function Test-IsAdmin {
    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdmin)) {
    throw "This script must be run as Administrator."
}

try {
    if (-not (Test-Path -Path $RegPath)) {
        if ($PSCmdlet.ShouldProcess($RegPath, "Create registry key")) {
            New-Item -Path $RegPath -Force | Out-Null
        }
    }

    if ($PSCmdlet.ShouldProcess("$RegPath\$ValueName", "Set DWORD to $DesiredValue")) {
        New-ItemProperty -Path $RegPath -Name $ValueName -PropertyType DWord -Value $DesiredValue -Force | Out-Null
    }

    $current = Get-ItemProperty -Path $RegPath -Name $ValueName -ErrorAction Stop
    $currentValue = [int]$current.$ValueName

    if ($currentValue -eq $DesiredValue) {
        Write-Host "Compliant: $ValueName is set to $currentValue at $RegPath"
        exit 0
    } else {
        Write-Warning "Not compliant: $ValueName is $currentValue (expected $DesiredValue) at $RegPath"
        exit 1
    }
}
catch {
    Write-Error $_
    exit 2
}
