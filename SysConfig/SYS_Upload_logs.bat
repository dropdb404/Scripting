@echo off

REM Share folder path and access credential
if "%~1"=="DEV" set SMBPATH=\\10.194.119.160\NewPhysicalServer
if "%~1"=="Dev" set SMBPATH=\\10.194.119.160\NewPhysicalServer
if "%~1"=="dev" set SMBPATH=\\10.194.119.160\NewPhysicalServer
if "%~1"=="" set SMBPATH=\\10.8.40.13\NewPhysicalServer
set SMBUSR=wsuscopy
set SMBPWD=WSUS@ffline

REM check_Current_Date_Ttime YYYYMMDDSSSS+Timezone
for /f %%a in ('wmic os get LocalDateTime ^| findstr ^[0-9]') do (set cdt=%%a)

REM set logfile
SET logfile=%~dp0SP3D_upload_logs_%COMPUTERNAME%_%cdt:~0,12%.log

REM connect share drive
net use | find /i "%SMBPATH%" && net use %SMBPATH% /delete
net use %SMBPATH% /user:%SMBUSR% %SMBPWD%
if errorlevel 1 echo Unable to mount share drive >>%logfile% & exit
if NOT exist %SMBPATH%\%computername%_%cdt:~0,12% md %SMBPATH%\%computername%_%cdt:~0,12% || goto unmount

REM copy logs
SET uploadpath=%SMBPATH%\%computername%_%cdt:~0,12%
copy /y c:\hotfix\checking\missing_hotfix_info*.* %uploadpath%
copy /y c:\temp\SP3D\*.log %uploadpath%
copy /y c:\temp\*.log %uploadpath%

:unmount
REM Unmount network drive
net use %SMBPATH% /delete
