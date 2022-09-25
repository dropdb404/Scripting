@echo off
REM set Screen Buffer Size
mode 250

REM check_Current_Date_Ttime YYYYMMDDSSSS+Timezone
for /f %%a in ('wmic os get LocalDateTime ^| findstr ^[0-9]') do (set cdt=%%a)

REM report headrt and configuration standard 
SET Report="FO 1.1 environmental configuration"
SET LogFile=%~dp0%computername%_EnvConfigRpt_%cdt:~0,12%.log

echo ---------%computername% %report% summary report at %cdt:~0,12%----------- > %LogFile%
echo.

REM check existing of FusionIO Utils
If NOT exist "C:\Program files\Common Files\VSL Utils" goto skipfusionio

powershell %~dp0CheckFusionIO.ps1 >> %LogFile%
echo. >> %LogFile%

REM check storage pool
powershell "Get-StoragePool | Select FriendlyName,ProvisioningtypeDefault,ResiliencySettingNameDefault,HealthStatus,PhysicalSectorSize,{$_.AllocatedSize/1GB} | FT -AutoSize" >> %LogFile%

:skipfusionio

REM Check network configuration
powershell "Get-NetAdapter | Select Name,MacAddress | Sort-object Name | FT -AutoSize" >> %LogFile%

powershell "Get-NetIPAddress -AddressFamily IPv4 | select InterfaceAlias,IPaddress,PrefixLength,ifIndex | FT -AutoSize" >> %LogFile%

powershell "Get-NetRoute -AddressFamily IPv4 -PolicyStore PersistentStore | FT -AutoSize" >> %LogFile%

powershell "Get-NetLbfoTeam | FT -AutoSize" >> %LogFile%

powershell "Get-NetAdapterHardwareInfo | Sort-Object Slot,Function | FT -AutoSize" >> %LogFile%

powershell "Get-NetAdapterAdvancedProperty -RegistryKeyword *JumboPacket | FT -AutoSize" >> %LogFile%

powershell "Get-WmiObject Win32_NetworkAdapterConfiguration -Filter IPEnabled=TRUE | Select IPAddress,DefaultIPGateway,TcpipNetbiosOptions,DNSDomainSuffixSearchOrder,DNSServerSearchOrder| FT -autosize" >> %LogFile%


REM check harddisk, partitions, volumes

powershell "Get-PhysicalDisk | Select FriendlyName,FirmwareVersion,HealthStatus,{$_AllocatedSize/1GB},PhysicalSectorSize | sort-object FriendlyName | FT -AutoSize" >> %LogFile%

powershell "Get-WmiObject Win32_volume | select Name,Label,FileSystem,BlockSize,{$_.Capacity/1GB},{$_.FreeSpace/1GB} | FT -AutoSize" >> %LogFile%


REM check disable NIC powersaving
powershell %~dp0\CheckNetworkAdapterPnPCapabilities.ps1 >> %LogFile%

REM check disable IPV6
powershell "Get-NetAdapterBinding -componentiD ms_tcpip6" >> %LogFile%

REM check Disable Firewall
powershell "Get-NetFirewallProfile | select Profile,Enabled | FT -AutoSize" >> %LogFile%

REM check Enable Remote Desktop
powershell "GWMI Win32_TerminalServiceSetting -NameSpace "root\cimv2\TerminalServices" | select AllowTSConnections | FT -AutoSize" >> %LogFile%

REM check RDP agent installation
If NOT exist "C:\Program files\Altiris\Dagent\dagent.exe" echo "RDP is NOT installed." >> %LogFile%
If exist "C:\Program files\Altiris\Dagent\dagent.exe" echo "RDP is installed." >> %LogFile%

REM check setNICBIND
nvspbind.exe /o ms_tcpip >> %LogFile%

REM check SetPSUnrestricted
reg query HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell /v ExecutionPolicy >> %LogFile%
reg query HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\ScriptedDiagnostics /v ExecutionPolicy >> %LogFile%
reg query HKLM\SOFTWARE\Wow6432Node\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell /v ExecutionPolicy >> %LogFile%
reg query HKLM\SOFTWARE\Wow6432Node\Microsoft\PowerShell\1\ShellIds\ScriptedDiagnostics /v ExecutionPolicy >> %LogFile%

REM check EnableRemotePS (NT AUTHORITY\NETWORK AccessDenied )
powershell "Get-PSSessionConfiguration | select permission | ft -AutoSize" >> %LogFile%

REM check admin share and auto admin share (those c$, D$, admin$,)
reg query HKLM\SYSTEM\CurrentControlSet\Services\lanmanserver\parameters /v AutoShareServer 2>&1 >> %LogFile%
net share >> %LogFile%

REM check crash dump setting
REM reg query HKLM\SYSTEM\CurrentControlSet\Control\CrashControl /v CrashOnCtrlScroll 2>&1 >> %LogFile%
REM reg query HKLM\SYSTEM\CurrentControlSet\Control\CrashControl /v AutoReboot 2>&1 >> %LogFile%
REM reg query HKLM\SYSTEM\CurrentControlSet\Control\CrashControl /v CrashDumpEnabled 2>&1 >> %LogFile%
REM reg query HKLM\SYSTEM\CurrentControlSet\Control\CrashControl /v Overwrite 2>&1 >> %LogFile%
REM reg query HKLM\SYSTEM\CurrentControlSet\Control\CrashControl /v LogEvent 2>&1 >> %LogFile%
REM reg query HKLM\SYSTEM\CurrentControlSet\Control\CrashControl /v DumpFile 2>&1 >> %LogFile%
REM reg query HKLM\SYSTEM\CurrentControlSet\Control\CrashControl /v DedicateDumpFile 2>&1 >> %LogFile%
reg query HKLM\SYSTEM\CurrentControlSet\Control\CrashControl 2>&1 >> %LogFile%

REM check pagefile location and size
wmic pagefile list /format:table >> %LogFile%

REM check Timezone (China Standard Time)
tzutil /g >> %LogFile%

REM check SNP setting (NetDMA, RSS,chimney,EnableTCPA disabled, dynamic port 57535,8000 ports)
Netsh int tcp show global >> %LogFile%
reg query HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\parameters /v EnableTCPA >> %LogFile%
Netsh int ipv4 show dynamicport tcp >> %LogFile%
Netsh int ipv4 show dynamicport udp >> %LogFile%
Netsh int ipv6 show dynamicport tcp >> %LogFile%
Netsh int ipv6 show dynamicport udp >> %LogFile%

REM check .NET 3.5 installed
powershell Get-WindowsFeature -name NET-Framework-Features >> %LogFile%

REM Check windows server backup installed
powershell Get-WindowsFeature -name Windows-Server-Backup >> %LogFile%

REM Check Windows Update (1 = Disabled (Never check for update))
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v AUOptions 2>&1 >> %LogFile%

REM Check LSO is disabled
powershell Get-NetAdapterLSO >> %LogFile%

REM check existing of windows 2012 R2 configuration Tools
If NOT exist "C:\Program files\Tools" echo C:\Program files\Tools NOT found >> %LogFile%
If exist "C:\Program files\Tools" echo C:\Program files\Tools found >> %LogFile%

exit

REM	powershell "Get-Volume | Select DriveLetter,BlockSize,FileSystemLabel,FileSystem,DriveType,HealthStatus,{$_.SizeRemaining/1GB},{$_.Size/1GB} | FT -Autosize" >> %LogFile%
REM	echo. >> %LogFile%

REM	check windows patch installation
REM	#wmic qfe list >%Log_path%\%host%_wmic_qfe_installed_hotfixes_%currentdate%.log#
REM	#powershell.exe "Get-Hotfix" >%Log_path%\%host%_Hotfix_%currentdate%.log#
REM	start /wait C:\Hotfix\checking\list_missing_hotfixes_all.bat
REM	type C:\Hotfix\checking\missing_hotfix_info_all_%host%@%host%*.* >> %LogFile%

REM	powershell "Get-DnsClientServerAddress | select ElementName,Address | FT -AutoSize" >> %LogFile%
REM	echo. >> %LogFile%

REM	powershell "Get-NetIPConfiguration | Select InterfaceAlias,IPv4Address,IPv4DefaultGateway,DNSSserver | FT -AutoSize" >> %LogFile%
REM	echo. >> %LogFile%

REM	ipconfig /allcompartments /all >> %LogFile%
REM	echo. >> %LogFile%

REM	powershell "Get-PSDrive -PSProvider "FileSystem" | FT -AutoSize" >> %LogFile%
REM	echo. >> %LogFile%
REM 	wmic volume get blocksize,Driveletter /format:list

REM	test DNS resolve and DC connection
REM	powershell "Test-NetConnection WINDC01.WIN.LOCAL" >> %LogFile%
REM	powershell "Test-NetConnection WINDC02.WIN.LOCAL" >> %LogFile%
REM	powershell "Test-NetConnection WINDC03.WIN.LOCAL" >> %LogFile%
REM	powershell "Test-NetConnection WINDC04.WIN.LOCAL" >> %LogFile%


REM	echo ---------** Current FusionIO configuration Standard (20170805) ** ----------- >> %LogFile%
REM	echo ---------FusionIO VSL driver 4.3.0 build 769 ----------- >> %LogFile%
REM	echo ---------FusionIO driver 4.3.0 ----------- >> %LogFile%
REM	echo ---------FusionIO firmware v8.9.5 ----------- >> %LogFile%
REM	echo ---------FusionIO PCIe Power limit threshold 74.9W (75W) ----------- >> %LogFile%
REM	echo ---------** Current FusionIO configuration Standard (20170805) ** ----------- >> %LogFile%
REM	echo.

REM	echo ---------FusionIO fct0 ----------- >> %LogFile%
REM	fio-status /dev/fct0 -a | find /i "driver" >> %LogFile%
REM	fio-status /dev/fct0 -a | find /i "firmware" >> %LogFile%
REM	fio-status /dev/fct0 -a | find /i "PCIe Power Limit threshold" >> %LogFile%
REM	fio-status /dev/fct0 -a | find /i "ioMemory Adapter Controller, Product Number:831739-B21, SN:" >> %LogFile%

REM	echo ---------FusionIO fct1 ----------- >> %LogFile%
REM	fio-status /dev/fct1 -a | find /i "driver" >> %LogFile%
REM	fio-status /dev/fct1 -a | find /i "firmware" >> %LogFile%
REM	fio-status /dev/fct1 -a | find /i "PCIe Power Limit threshold" >> %LogFile%
REM	fio-status /dev/fct1 -a | find /i "ioMemory Adapter Controller, Product Number:831739-B21, SN:" >> %LogFile%
