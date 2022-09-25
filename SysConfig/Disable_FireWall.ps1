# Disable Windows Firewall
$LogPath = "C:\Temp"
$TestPath = Test-Path $LogPath
If(!$TestPath)
{
	New-Item -ItemType Directory -Force "C:\Temp"
}
Start-Transcript -Path $LogPath\Disable_Firewall.log -Append -Force -NoClobber
Get-NetFirewallProfile
Set-NetFirewallProfile -All -Enabled False
Get-NetFirewallProfile
Stop-Transcript