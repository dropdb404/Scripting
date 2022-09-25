@echo off

set SSA_path="C:\Program Files\Smart Storage Administrator\ssacli\bin"
cd /d %SSA_path%
ssacli.exe controller slot=0 logicaldrive 1 modify size=max forced


