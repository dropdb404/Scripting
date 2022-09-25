# Disable net share
$LogPath = "C:\Temp"
$TestPath = Test-Path $LogPath
If(!$TestPath)
{
	New-Item -ItemType Directory -Force "C:\Temp"
}
Start-Transcript -Path $LogPath\NetShare.log -Append -Force -NoClobber
"Disable Default Net Share" | Out-Host
Net Share c$ /d | Out-Host
Net Share d$ /d | Out-Host
Net Share admin$ /d | Out-Host
Net Share share /d | Out-Host
Net Share Temp /d | Out-Host
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\lanmanserver\parameters"
New-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\lanmanserver\parameters" -Name AutoShareServer -Value 0 -PropertyType DWord
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\lanmanserver\parameters"
Stop-Transcript