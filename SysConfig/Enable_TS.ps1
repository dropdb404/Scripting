# Disable Terminal Services
$LogPath = "C:\Temp"
$TestPath = Test-Path $LogPath
If(!$TestPath)
{
	New-Item -ItemType Directory -Force "C:\Temp"
}
Start-Transcript -Path $LogPath\Enable_TS.log -Append -Force -NoClobber
$ts=GWMI Win32_TerminalServiceSetting -NameSpace "root\cimv2\TerminalServices"
$ts
$ts.SetAllowTSConnections(1)
$ts
Stop-Transcript