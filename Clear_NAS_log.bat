@echo on
net use x: "\\172.20.101.161\Logs"
for %%G in (.rar, .zip, .json) do forfiles /s /m *%%G /p x:\ /d -35 /c "cmd /c del /s/q @path"
pause