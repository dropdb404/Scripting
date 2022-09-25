# Install Windows Failvoer cluster services
$LogPath = "C:\Temp"
$TestPath = Test-Path $LogPath
If(!$TestPath)
{
	New-Item -ItemType Directory -Force "C:\Temp"
}
Start-Transcript -Path $LogPath\Install_WFCS.log -Append -Force -NoClobber
Install-WindowsFeature -Name Failover-Clustering -includeManagementTools
Stop-Transcript