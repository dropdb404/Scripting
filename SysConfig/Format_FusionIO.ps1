# Disable Terminal Services
$LogPath = "C:\Temp"
$TestPath = Test-Path $LogPath
If(!$TestPath)
{
	New-Item -ItemType Directory -Force "C:\Temp"
}
Start-Transcript -Path $LogPath\Format_FusionIO.log -Append -Force -NoClobber
fio-detach /dev/fct0
fio-detach /dev/fct1

fio-format -b 4K -y /dev/fct0
fio-format -b 4K -y /dev/fct1

fio-attach -c /dev/fct0
fio-attach -c /dev/fct1

#*force detach
#fio-detach -f /dev/fct0
#fio-detach -f /dev/fct1

Stop-Transcript