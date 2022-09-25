# Disable Terminal Services
$LogPath = "C:\Temp"
$TestPath = Test-Path $LogPath
If(!$TestPath)
{
	New-Item -ItemType Directory -Force "C:\Temp"
}
Start-Transcript -Path $LogPath\Disable_IPv6.log -Append -Force -NoClobber

Get-NetAdapterBinding -ComponentID ms_tcpip6
Disable-NetAdapterBinding -Name * -componentiD ms_tcpip6
Get-NetAdapterBinding -ComponentID ms_tcpip6

Stop-Transcript