@echo off
REM if exist %SystemRoot%\system32\WindowsPowerShell\ (%SystemRoot%\system32\WindowsPowerShell\v1.0\powershell.exe set-executionpolicy restricted -force)
REM if exist %SystemRoot%\syswow64\WindowsPowerShell\ (%SystemRoot%\syswow64\WindowsPowerShell\v1.0\powershell.exe set-executionpolicy restricted -force)
reg add HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell /v ExecutionPolicy /t REG_SZ /d Unrestricted /f
reg add HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\ScriptedDiagnostics /v ExecutionPolicy /t REG_SZ /d Unrestricted /f
reg add HKLM\SOFTWARE\Wow6432Node\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell /v ExecutionPolicy /t REG_SZ /d Unrestricted /f
reg add HKLM\SOFTWARE\Wow6432Node\Microsoft\PowerShell\1\ShellIds\ScriptedDiagnostics /v ExecutionPolicy /t REG_SZ /d Unrestricted /f
