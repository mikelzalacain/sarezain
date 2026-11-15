"""Auditoría del propio equipo (Windows). No necesita permisos de administrador."""

from __future__ import annotations

import json
import platform
import subprocess

from .netinfo import NO_WINDOW

PS_SCRIPT = r"""
$ErrorActionPreference = 'SilentlyContinue'
$r = [ordered]@{}
$os = Get-CimInstance Win32_OperatingSystem
$r.os = @{ caption = $os.Caption; version = $os.Version; build = [int]$os.BuildNumber }
$r.firewall = @(Get-NetFirewallProfile | ForEach-Object { @{ name = "$($_.Name)"; enabled = [bool]($_.Enabled -eq 'True' -or $_.Enabled -eq 1) } })
$mp = Get-MpComputerStatus
if ($mp) { $r.defender = @{ av = [bool]$mp.AntivirusEnabled; realtime = [bool]$mp.RealTimeProtectionEnabled; sig_age = [int]$mp.AntivirusSignatureAge; tamper = [bool]$mp.IsTamperProtected } }
$r.antivirus = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | ForEach-Object { @{ name = $_.displayName; state = [int]$_.productState } })
$smb = Get-SmbServerConfiguration
if ($smb) { $r.smb = @{ smb1 = [bool]$smb.EnableSMB1Protocol; signing = [bool]$smb.RequireSecuritySignature } }
$ts = Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server'
$r.rdp_enabled = ($ts.fDenyTSConnections -eq 0)
$uac = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$r.uac = @{ enabled = ($uac.EnableLUA -ne 0); prompt = [int]$uac.ConsentPromptBehaviorAdmin }
$hf = Get-HotFix | Where-Object InstalledOn | Sort-Object InstalledOn -Descending | Select-Object -First 1
if ($hf) { $r.last_update = $hf.InstalledOn.ToString('yyyy-MM-dd'); $r.last_update_id = $hf.HotFixID }
$guest = Get-LocalUser | Where-Object { $_.SID -like '*-501' }
if ($guest) { $r.guest_enabled = [bool]$guest.Enabled }
try { $bl = (New-Object -ComObject Shell.Application).NameSpace('C:').Self.ExtendedProperty('System.Volume.BitLockerProtection'); $r.bitlocker = [int]$bl } catch {}
$r.network_category = "$((Get-NetConnectionProfile | Select-Object -First 1).NetworkCategory)"
$procs = @{}; Get-Process | ForEach-Object { $procs[$_.Id] = $_.ProcessName }
$r.listening = @(Get-NetTCPConnection -State Listen | Where-Object { $_.LocalAddress -in @('0.0.0.0','::') } |
  Sort-Object LocalPort -Unique | ForEach-Object { @{ port = [int]$_.LocalPort; process = $procs[[int]$_.OwningProcess] } })
$r | ConvertTo-Json -Depth 4 -Compress
"""


def audit() -> dict | None:
    if platform.system() != "Windows":
        return None
    try:
        out = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", PS_SCRIPT],
                             capture_output=True, timeout=60, creationflags=NO_WINDOW)
        text = out.stdout.decode("utf-8", errors="replace").strip()
        return json.loads(text[text.find("{"):]) if "{" in text else None
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
        return None


def av_active(state: int) -> bool:
    """productState de SecurityCenter2: el segundo byte 0x10/0x11 indica protección activa."""
    return ((state >> 8) & 0xFF) in (0x10, 0x11)
