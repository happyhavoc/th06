@echo off
call %~dp0\..\scripts\th06vars.bat
%*
if %errorlevel% neq 0 exit /b %errorlevel%
