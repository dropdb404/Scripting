# AutoShareServer1
$LogPath = "C:\Temp"
$TestPath = Test-Path $LogPath
If(!$TestPath)
{
	New-Item -ItemType Directory -Force "C:\Temp"
}
Start-Transcript -Path $LogPath\AutoShareServer1.log -Append -Force -NoClobber
"Set AutoShareServer 1" | Out-Host
New-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\lanmanserver\parameters" -Name AutoShareServer -Value 1 -PropertyType DWord
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\lanmanserver\parameters"
Stop-Transcript