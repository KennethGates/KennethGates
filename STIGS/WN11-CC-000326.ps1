# ==============================================================================
# STIG ID:          WN11-CC-000326
# Vulnerability ID: V-253414
# Rule ID:          SV-253414r958478_rule
# Severity:         Medium (CAT II)
# CCI:              CCI-000135
# SRG:              SRG-OS-000062-GPOS-00031
#
# Title:
#   Create WN11-CC-000326.ps1
#
# Summary:
#   Enabling PowerShell script block logging records detailed information from
#   the processing of PowerShell commands and scripts. This data is essential
#   for analyzing the security of information assets, detecting signs of
#   suspicious behavior, and providing additional forensic detail when malware
#   has executed on a system.
#
# Fix:
#   Configure: Computer Configuration >> Administrative Templates >>
#   Windows Components >> Windows PowerShell >>
#   "Turn on PowerShell Script Block Logging" to "Enabled"
#
# Registry:
#   Hive:       HKEY_LOCAL_MACHINE
#   Path:       SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
#   Value Name: EnableScriptBlockLogging
#   Value Type: REG_DWORD
#   Value:      1
#
# Author: Kenneth Gates | Gates Cyber Consulting
# Date:   2026-05-04
# ==============================================================================

# --- REMEDIATION ---

Write-Output "[*] Applying WN11-CC-000326: Enabling PowerShell Script Block Logging..."

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f | Out-Null

gpupdate /force | Out-Null

Write-Output "[+] Registry key set and Group Policy updated."

# --- VERIFICATION ---

$result = reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" 2>$null

if ($result -match "EnableScriptBlockLogging.*0x1") {
    Write-Output "[✓] COMPLIANT: EnableScriptBlockLogging is set to 1."
} else {
    Write-Output "[✗] NON-COMPLIANT: Registry key not set correctly. Manual review required."
}

Write-Output ""
Write-Output "[*] Logs will appear in Event Viewer:"
Write-Output "    Applications and Services Logs > Microsoft > Windows > PowerShell > Operational"
Write-Output "    Event ID: 4104"
