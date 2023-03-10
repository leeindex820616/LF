@echo off
set "RAR=C:\Program Files (x86)\WinRAR\winrar.exe"
set "PATH_TO_ARCHIVE=E:\backup_temp\old"

for /D %%f in ("%PATH_TO_ARCHIVE%\*") do (
  "%RAR%" a -r "%%~f.rar" "%%~f\*"
)
