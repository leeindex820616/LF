[@echo](https://my.oschina.net/echolee1987) off&color 17
if exist "%SystemRoot%\SysWOW64" path %path%;%windir%\SysNative;%SystemRoot%\SysWOW64;%~dp0
bcdedit >nul
if '%errorlevel%' NEQ '0' (goto UACPrompt) else (goto UACAdmin)
:UACPrompt
%1 start "" mshta vbscript:createobject("shell.application").shellexecute("""%~0""","::",,"runas",1)(window.close)&exit
exit /B
:UACAdmin
cd /d "%~dp0"
echo ???????:%CD%
echo ?????????
echo.>> C:\Zabbix_Agentd\conf\zabbix_agentd.conf
TYPE C:\zabbix_socket_monitor.txt>> C:\Zabbix_Agentd\conf\zabbix_agentd.conf
NET STOP "Zabbix Agent"&&NET START "Zabbix Agent"