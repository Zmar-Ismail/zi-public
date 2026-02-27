<#
.SYNOPSIS
    Enables the Windows Connection Manager policy to prohibit connecting to non-domain networks
    while connected to a domain-authenticated network by setting the required registry value.

.NOTES
    Author          : Zmar Ismail
    LinkedIn        : linkedin.com/in/zmarismail/
    GitHub          : github.com/zmar-i
    Date Created    : 2026-02-13
    Last Modified   : 2026-02-13
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000060

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    1. Run PowerShell as Administrator.
    2. Execute the script:
    3. (Optional) Run 'gpupdate /force' or reboot to ensure the policy applies.
    4. Verify:
       Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" -Name fBlockNonDomain
#>

# Requires admin
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "This script must be run as Administrator."
}

$regPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy'
$valueName = 'fBlockNonDomain'
$desiredValue = 1

try {
    # Ensure key exists
    if (-not (Test-Path -Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }

    # Set value
    New-ItemProperty -Path $regPath -Name $valueName -PropertyType DWord -Value $desiredValue -Force | Out-Null

    # Verify
    $current = (Get-ItemProperty -Path $regPath -Name $valueName -ErrorAction Stop).$valueName
    if ($current -ne $desiredValue) {
        throw "Verification failed: $valueName is $current, expected $desiredValue."
    }

    Write-Host "Configured successfully: $regPath\$valueName = $desiredValue"
    Write-Host "Note: You may need to run 'gpupdate /force' or reboot for policy to fully apply."
}
catch {
    Write-Error "Failed to configure policy. $($_.Exception.Message)"
    exit 1
}
