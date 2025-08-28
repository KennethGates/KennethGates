 <#
.SYNOPSIS
    This PowerShell script ensures the registry path exists and sets the MaxSize value to 32768 KB (32 MB) or greater, allowing more events to be retained in the System Event Log.

.NOTES
    Author          : Kenneth Gates
    LinkedIn        : www.linkedin.com/in/kenneth-gates-224745365
    GitHub          : https://github.com/KennethGates
    Date Created    : 2025-08-28
    Last Modified   : 2025-08-28
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-AU-000510

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\WN10-AU-000510.ps1 
#>

# 
$RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System"

# Ensure the key exists (creates it if missing)
If (-not (Test-Path $RegPath)) {
    New-Item -Path $RegPath -Force | Out-Null
}

# Set the MaxSize value (DWORD) to 32768 KB (32 MB) or greater
New-ItemProperty -Path $RegPath -Name "MaxSize" -Value 32768 -PropertyType DWord -Force
 
