@echo off
call %CD%\scripts\th06vars.bat
nmake %*
if %errorlevel% neq 0 exit /b %errorlevel%
