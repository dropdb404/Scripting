#Enable Force Crash Dump
$LogPath = "C:\Temp"
$TestPath = Test-Path $LogPath
If(!$TestPath)
{
	New-Item -ItemType Directory -Force "C:\Temp"
}
Start-Transcript -Path $LogPath\CrashDump.log -Append -Force -NoClobber
$DmpPath = "D:\MemDmp"
$TestDmpPath = Test-Path $DmpPath
If(!$TestDmpPath)
{
	New-Item -ItemType Directory -Force "D:\MemDmp"
}
$MemDmp = $DmpPath+"\Memory.dmp"
$Dmpsys = "D:\dedicatedumpfile.sys"
"Enable force crash dump" | Out-Host
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\i8042prt\Parameters"
New-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\i8042prt\Parameters" -Name CrashOnCtrlScroll -Value 1 -PropertyType DWord
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\i8042prt\Parameters"
Write-host "Change crash dump parameters"
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl"
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" -Name AutoReboot -Value 1
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" -Name CrashDumpEnabled -Value 1
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" -Name Overwrite -Value 1
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" -Name LogEvent -Value 1
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" -Name DumpFile -Value $MemDmp
New-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" -Name DedicateDumpFile -Value $DmpSys
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl"

Stop-Transcript
