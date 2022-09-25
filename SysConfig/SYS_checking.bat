@echo off
REM set Screen Buffer Size
mode 250

REM check_Current_Date_Ttime YYYYMMDDSSSS+Timezone
for /f %%a in ('wmic os get LocalDateTime ^| findstr ^[0-9]') do (set cdt=%%a)

SET Log_path=%~dp0%computername%

REM check current path
If NOT exist "C:\Program files\Common Files\VSL Utils" goto skipfusionio
fio-status -a >%Log_path%_fiostatus_%cdt:~0,12%.log

:skipfusionio

REM check windows patch installation
wmic qfe list >%Log_path%_wmic_qfe_installed_hotfixes_%cdt:~0,12%.log
powershell.exe "Get-Hotfix" >%Log_path%_Hotfix_%cdt:~0,12%.log

REM Check network configuration
netsh interface ipv4 show subinterface >%Log_path%_network_%cdt:~0,12%.log
route print >>%Log_path%_network_%cdt:~0,12%.log
ipconfig /all >>%Log_path%_network_%cdt:~0,12%.log
wmic nic >>%Log_path%_wmic_NIC_%cdt:~0,12%.log
powershell.exe "Get-NetLbfoTeam" >>%Log_path%_NetLbfoTeam_%cdt:~0,12%.log
powershell.exe "Get-NetAdapter | Sort-Object MacAddress | Sort-Object Name" >>%Log_path%_NetAdapter_%cdt:~0,12%.log

REM check harddisk, partitions, volumes
fsutil fsinfo drives >%Log_path%_harddisk_%cdt:~0,12%.log
FOR %%I in (C D E F G H I J K L M N O P Q R S T U V W X Y Z) DO If exist %%I: (
fsutil fsinfo drivetype %%I: >>%Log_path%_harddisk_%cdt:~0,12%.log
fsutil fsinfo ntfsinfo %%I: >>%Log_path%_harddisk_%cdt:~0,12%.log
fsutil fsinfo sectorInfo %%I: >>%Log_path%_harddisk_%cdt:~0,12%.log
fsutil fsinfo volumeInfo %%I: >>%Log_path%_harddisk_%cdt:~0,12%.log
)
wmic diskdrive >%Log_path%_wmic_diskdrive_%cdt:~0,12%.log
wmic logicaldisk >%Log_path%_wmic_logicaldisk_%cdt:~0,12%.log
wmic partition >%Log_path%_wmic_partition_%cdt:~0,12%.log
wmic volume >%Log_path%_wmic_volume_%cdt:~0,12%.log

REM check CPU
wmic cpu >>%Log_path%_wmic_CPU_%cdt:~0,12%.log

REM check RAM
wmic memorychip >>%Log_path%_wmic_RAM_%cdt:~0,12%.log

call .\sp3d_checking_summary.bat
call C:\Hotfix\checking\list_missing_hotfixes_all.bat

exit