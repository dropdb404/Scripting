# Set time zone to UTC +8
$LogPath = "C:\Temp"
$TestPath = Test-Path $LogPath
If(!$TestPath)
{
	New-Item -ItemType Directory -Force "C:\Temp"
}
$TZ = tzutil /g
If($TZ -ne "China Standard Time")
{
	tzutil /s "China Standard Time" >> $LogPath\Set_TZ.log
	tzutil /g >> $LogPath\Set_TZ.log
}
else
{
	tzutil /g >> $LogPath\Set_TZ.log
}
