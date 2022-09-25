# Windows configuration
$LogPath = "C:\Temp"
$TestPath = Test-Path $LogPath
If(!$TestPath)
{
	New-Item -ItemType Directory -Force "C:\Temp"
}
.\Set_TimeZone.ps1
.\Disable_SNP_x64.ps1
.\Disable_FireWall.ps1
.\Install_NetFramewrok35.ps1
.\Install_WBackup.ps1
.\Disable_AutoUpdate.ps1
.\Disable_LSO.ps1