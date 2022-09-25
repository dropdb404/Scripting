@echo off

REM check exist or create C:\Hotfix\checking folder, if both failed then exit
If NOT exist C:\Hotfix md C:\Hotfix\checking || exit

REM Share folder path and access credential
set SMBPATH=%~1
set SMBUSR=%~2
set SMBPWD=%~3

REM check_Current_Date_Ttime YYYYMMDDSSSS+Timezone
for /f %%a in ('wmic os get LocalDateTime ^| findstr ^[0-9]') do (set cdt=%%a)

REM set logfile
SET logfile=C:\hotfix\checking\WSUSCOPY_%COMPUTERNAME%_%cdt:~0,12%.log

REM connect share drive
if exist %SMBPATH% (net use %SMBPATH% /delete)
net use %SMBPATH% /user:%SMBUSR% %SMBPWD%
if errorlevel 1 echo Unable to mount share drive >>%logfile% & exit

REM copy files
echo copy checking files >>%logfile%
echo.>>%logfile%
xcopy /c /i /e /y %SMBPATH%\checking C:\Hotfix\checking 2>&1>>%logfile%

:uploadlog
REM upload logs
xcopy /c /i /e /y %logfile% %SMBPATH%\COPYLOGS
net use %SMBPATH% /delete
