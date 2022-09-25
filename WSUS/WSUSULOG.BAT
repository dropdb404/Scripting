@echo off

REM Share folder path and access credential
set SMBPATH=%~1
set SMBUSR=%~2
set SMBPWD=%~3

REM check_Current_Date_Ttime YYYYMMDDSSSS+Timezone
for /f %%a in ('wmic os get LocalDateTime ^| findstr ^[0-9]') do (set cdt=%%a)

REM set logfile
SET logfile=%~dp0WSUSULOG_%COMPUTERNAME%_%cdt:~0,12%.log
echo %date% %time% >>%logfile%
hostname >>%logfile%
ipconfig /all >>%logfile%

REM connect share drive
if exist %SMBPATH% (net use %SMBPATH% /delete)
net use %SMBPATH% /user:%SMBUSR% %SMBPWD%
if errorlevel 1 echo Unable to mount share drive >>%logfile% & exit
if NOT exist %SMBPATH%\%computername%_%cdt:~0,12% md %SMBPATH%\%computername%_%cdt:~0,12% || goto unmount

REM copy logs
SET uploadpath=%SMBPATH%\%computername%_%cdt:~0,12%
copy /y %logfile% %uploadpath%
if exist c:\hotfix\checking\missing_hotfix_info* (copy /y c:\hotfix\checking\missing_hotfix_info*.* %uploadpath%)
if exist c:\hotfix\checking\winupdate.log.* (copy /y c:\hotfix\checking\winupdate.log.* %uploadpath%)
if exist c:\Windows\temp\winupdate.log.* (copy /y c:\Windows\temp\winupdate.log.* %uploadpath%)
if exist C:\Windows\Logs\CBS\CBS*.* (copy /y C:\Windows\Logs\CBS\CBS*.* %uploadpath%)

:unmount
REM Unmount network drive
net use %SMBPATH% /delete
