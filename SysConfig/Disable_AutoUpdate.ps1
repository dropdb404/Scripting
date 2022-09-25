# Disable Windows AutoUpdate
# NotificationLevel:
# 0 = not Configured
# 1 = Disabled (Never check for update)
# 2 = Notify before download
# 3 = Notify before installation
# 4 = Scheduled installation
$LogPath = "C:\Temp"
$TestPath = Test-Path $LogPath
If(!$TestPath)
{
	New-Item -ItemType Directory -Force "C:\Temp"
}
Start-Transcript -Path $LogPath\DisableAutoUpdate.log -Append -Force -NoClobber
"Change Auto update to Never check for update" | Out-Host
$WU=(New-Object -com "Microsoft.Update.AutoUpdate").Settings
$WU
$WU.NotificationLevel=1
$WU.Save()
$WU
Stop-Transcript