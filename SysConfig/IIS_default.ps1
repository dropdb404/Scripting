# IIS default
$LogPath = "C:\Temp"
$TestPath = Test-Path $LogPath
If(!$TestPath)
{
	New-Item -ItemType Directory -Force "C:\Temp"
}
Start-Transcript -Path $LogPath\IIS_Default.log -Append -Force -NoClobber
Install-WindowsFeature Web-Server -IncludeManagementTools
Install-WindowsFeature Web-Request-Monitor
Install-WindowsFeature WAS
Get-WindowsFeature | Where-Object {$_.installed -match "True"} | Where-Object {$_.Name -match "Web"}
Stop-Transcript