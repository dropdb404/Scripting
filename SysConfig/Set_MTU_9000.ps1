# Disable Terminal Services
$LogPath = "C:\Temp"
$TestPath = Test-Path $LogPath
If(!$TestPath)
{
	New-Item -ItemType Directory -Force "C:\Temp"
}
Start-Transcript -Path $LogPath\Set_MTU_9000.log -Append -Force -NoClobber
get-netlbfoteammember -Team "replication" | set-NetAdapterAdvancedProperty -RegistryKeyword "*JumboPacket" -RegistryValue "9000"
Stop-Transcript