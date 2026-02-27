<#
.SYNOPSIS
    Ensures "Turn off Microsoft consumer experiences" is enabled by setting:
    HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent\DisableWindowsConsumerFeatures = 1 (REG_DWORD)

.NOTES
    Author          : Zmar Ismail
    LinkedIn        : linkedin.com/in/zmarismail/
    GitHub          : github.com/Zmar-Ismail
    Date Created    : 2026-02-13
    Last Modified   : 2026-02-13
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000197

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Run in an elevated PowerShell session:

        .\WN11-CloudContent-DisableConsumerFeatures.ps1 
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param()

$RegPath  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent'
$ValueName = 'DisableWindowsConsumerFeatures'
$Desired   = 1

function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "This script must be run as Administrator."
    }
}

function Get-CurrentValue {
    try {
        $item = Get-ItemProperty -Path $RegPath -Name $ValueName -ErrorAction Stop
        return [int]$item.$ValueName
    } catch {
        return $null
    }
}

try {
    Assert-Admin

    # Ensure key exists
    if (-not (Test-Path -Path $RegPath)) {
        if ($PSCmdlet.ShouldProcess($RegPath, "Create registry key")) {
            New-Item -Path $RegPath -Force | Out-Null
        }
    }

    $current = Get-CurrentValue

    # Set value if missing or incorrect
    if ($current -ne $Desired) {
        if ($PSCmdlet.ShouldProcess("$RegPath\$ValueName", "Set DWORD to $Desired")) {
            New-ItemProperty -Path $RegPath -Name $ValueName -PropertyType DWord -Value $Desired -Force | Out-Null
        }
    }

    # Verify
    $after = Get-CurrentValue
    if ($after -eq $Desired) {
        Write-Host "Compliant: $RegPath\$ValueName is set to $Desired (DWORD)."
        exit 0
    } else {
        Write-Error "Non-compliant: expected $Desired but found '$after' for $RegPath\$ValueName."
        exit 1
    }
}
catch {
    Write-Error $_
    exit 1
}
