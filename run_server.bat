@echo off
cd /d "%~dp0"
echo Starting UDH MCP Server on port 12021...
call .venv\Scripts\python.exe src\server.py
pause
