 <#
.SYNOPSIS
    This PowerShell script configures Remote Desktop/ Remote Assistance and USB redirection policies by creating and updating registry keys   

.NOTES
    Author          : Kenneth Gates
    LinkedIn        : www.linkedin.com/in/kenneth-gates-224745365
    GitHub          : https://github.com/KennethGates
    Date Created    : 2025-08-27
    Last Modified   : 2025-08-27
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000155 

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\STIG-ID-WN10-CC-000155.ps1 
#>

 
  Apply RDP/Remote Assistance + USB redirection policy registry values
  Paths:
    HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services
    HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\Client
    HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\Client\UsbBlockDeviceBySetupClasses
    HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\Client\UsbSelectDeviceByInterfaces
#>

# --- Safety checks ---
$IsAdmin = ([Security.Principal.WindowsPrincipal] `
  [Security.Principal.WindowsIdentity]::GetCurrent() `
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $IsAdmin) {
  Write-Error "Run this PowerShell window as Administrator."
  exit 1
}

# --- Helper to set a registry value idempotently ---
function Set-RegValue {
  param(
    [Parameter(Mandatory)] [string] $Path,
    [Parameter(Mandatory)] [string] $Name,
    [Parameter(Mandatory)] $Value,
    [ValidateSet('String','ExpandString','DWord','QWord','Binary','MultiString')]
    [string] $Type = 'DWord'
  )
  # Ensure key exists
  if (-not (Test-Path -LiteralPath $Path)) {
    New-Item -Path $Path -Force | Out-Null
  }
  # Create or update value
  if (Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction SilentlyContinue) {
    Set-ItemProperty -LiteralPath $Path -Name $Name -Value $Value
  } else {
    New-ItemProperty -LiteralPath $Path -Name $Name -Value $Value -PropertyType $Type | Out-Null
  }
}

# --- Paths ---
$tsBase   = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
$client   = Join-Path $tsBase 'Client'
$usbBlock = Join-Path $client 'UsbBlockDeviceBySetupClasses'
$usbSel   = Join-Path $client 'UsbSelectDeviceByInterfaces'

# --- Set values (exactly as you specified) ---
# Terminal Services (server-side policy)
Set-RegValue -Path $tsBase -Name 'KeepAliveEnable'   -Value 1    -Type DWord
Set-RegValue -Path $tsBase -Name 'KeepAliveInterval' -Value 1    -Type DWord   # 1 ms per your spec
Set-RegValue -Path $tsBase -Name 'fAllowToGetHelp'   -Value 0    -Type DWord   # Remote Assistance disabled

# Client subkey (USB behavior)
Set-RegValue -Path $client  -Name 'fEnableUsbBlockDeviceBySetupClass'      -Value 1   -Type DWord
Set-RegValue -Path $client  -Name 'fEnableUsbNoAckIsochWriteToDevice'      -Value 0x50 -Type DWord  # 0x50 = 80
Set-RegValue -Path $client  -Name 'fEnableUsbSelectDeviceByInterface'      -Value 1   -Type DWord

# Nested GUID lists (REG_SZ values)
Set-RegValue -Path $usbBlock -Name '1000' -Value '{3376f4ce-ff8d-40a2-a80f-bb4359d1415c}' -Type String
Set-RegValue -Path $usbSel   -Name '1000' -Value '{6bdd1fc6-810f-11d0-bec7-08002be2092f}' -Type String

# --- Show what got set ---
$pathsToShow = @($tsBase, $client, $usbBlock, $usbSel)
"`n== Current Policy Values =="
foreach ($p in $pathsToShow) {
  if (Test-Path $p) {
    Write-Host "`n[$p]"
    Get-ItemProperty -Path $p | Select-Object * -ExcludeProperty PS*, Provider, Properties
  } else {
    Write-Host "`n[$p] (not found)"
  }
}

# Optional: refresh policies (gpedit-managed environments)
try {
  gpupdate /target:computer /force | Out-Null
  Write-Host "`nGroup Policy refreshed."
} catch {
  Write-Host "`nCould not run gpupdate (non-fatal)."
}

Write-Host "`nDone. Reboot is recommended for full effect."
 
