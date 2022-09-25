# Security Config
$LogPath = "C:\Temp"
$TestPath = Test-Path $LogPath
If(!$TestPath)
{
	New-Item -ItemType Directory -Force "C:\Temp"
}
Start-Transcript -Path $LogPath\SystemStartupTimeout.log -Append -Force -NoClobber
bcdedit /v | Out-Host
bcdedit /timeout 0 | Out-Host
bcdedit /v | Out-Host
Stop-Transcript
.\NetShare.ps1
#.\Crashdump.ps1
#.\Disable_autorun.ps1
.\Disable_TS.ps1