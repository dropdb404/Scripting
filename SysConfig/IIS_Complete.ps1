# IIS Complete
$LogPath = "C:\Temp"
$TestPath = Test-Path $LogPath
If(!$TestPath)
{
	New-Item -ItemType Directory -Force "C:\Temp"
}
Start-Transcript -Path $LogPath\IIS_Complete.log -Append -Force -NoClobber
$CDDrive=GWMI Win32_CDROMDrive
Install-WindowsFeature Web-Server -IncludeAllSubFeature -IncludeManagementTools -Source "$CDDrive.Drive\Sources\SXS"
Install-WindowsFeature WAS
Get-WindowsFeature | Where-Object {$_.installed -match "True"} | Where-Object {$_.Name -match "Web"}
Stop-Transcript