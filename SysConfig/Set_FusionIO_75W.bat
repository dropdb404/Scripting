@echo off

fio-status /dev/fct0 | find "ioMemory Adapter Controller, Product Number" >%~dp0\fct0.txt
fio-status /dev/fct1 | find "ioMemory Adapter Controller, Product Number" >%~dp0\fct1.txt

for /f "tokens=2* delims=:" %%a in ('type %~dp0\fct0.txt') do set fct0sn=%%b
for /f "tokens=2* delims=:" %%a in ('type %~dp0\fct1.txt') do set fct1sn=%%b

set fct0sn=%fct0sn: =%
set fct1sn=%fct1sn: =%

REM echo %fct0sn%CheckNoSpaceChar
REM echo %fct1sn%CheckNoSpaceChar

REM fio-config -p FIO_EXTERNAL_POWER_OVERRIDE %fct0sn: =%:75000,%fct1sn: =%:75000
fio-config -p FIO_EXTERNAL_POWER_OVERRIDE %fct0sn%:75000,%fct1sn%:75000

del %~dp0\fct0.txt /f /q
del %~dp0\fct1.txt /f /q
