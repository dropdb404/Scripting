# Install Windows Server Backup Feature
$LogPath = "C:\Temp"
$TestPath = Test-Path $LogPath
If(!$TestPath)
{
	New-Item -ItemType Directory -Force "C:\Temp"
}
Start-Transcript -Path $LogPath\Install_WBackup.log -Append -Force -NoClobber
Install-WindowsFeature Windows-Server-Backup
Get-WindowsFeature | Where-Object {$_.Installed -match "True"} | Where-Object {$_.Name -match "Windows-Server-Backup"}
Stop-Transcript