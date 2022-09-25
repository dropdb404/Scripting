@echo off


REM check exist or create C:\Temp folder, if both failed then exit
If NOT exist C:\Temp md C:\Temp || exit

REM check_Current_Date_Ttime YYYYMMDDSSSS+Timezone
for /f %%a in ('wmic os get LocalDateTime ^| findstr ^[0-9]') do (set cdt=%%a)

REM set logfile
SET logfile=C:\Temp\SYS_%COMPUTERNAME%_%cdt:~0,12%.log

REM Check OS Version and Architecture
REM	Windows Server 2012 R2		6.3.9600
wmic os get osarchitecture | find /i "64-bit" > NUL && set OS=64bit || exit
for /f "tokens=4-5 delims=. " %%i in ('ver') do set VERSION=%%i.%%j
if not %version%==6.3 echo unsupported OS >>%logfile% & ver >>%logfile% & exit

REM install DotNET 3.5
%windir%\system32\DISM.exe /Online /Enable-Feature /FeatureName:NetFx3 /All /LimitAccess /Source:%~dp0sources\sxs /LogPath:%logfile%

REM copy files
set skiplist=%~dp0SYS\Hotfix\6.3.64BIT.skip.txt
xcopy /c /i /e /y %~dp0SYS\Temp C:\Temp 2>&1>>%logfile%
xcopy /c /i /e /y /exclude:%skiplist% %~dp0SYS\Hotfix C:\Hotfix 2>&1>>%logfile%
xcopy /c /i /e /y C:\Hotfix\MRT.exe C:\Windows\System32 2>&1>>%logfile%

REM install Visual Studio library 
"C:\Hotfix\wsusoffline\client\cpp\vcredist2008_x64.exe" /q /norestart
"C:\Hotfix\wsusoffline\client\cpp\vcredist2008_x86.exe" /q /norestart

REM WSUSOFFLINE auto installation
cd /D "C:\Hotfix\wsusoffline\client\cmd"
start DoUpdate.cmd /updatecpp /verify /autoreboot /seconly

                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           