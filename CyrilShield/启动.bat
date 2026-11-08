@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion
set "APP=%~dp0"
set "PY="

if exist "%APP%dist\CyrilShield.exe" (
  start "" "%APP%dist\CyrilShield.exe"
  exit /b 0
)

for %%P in (
  "%LOCALAPPDATA%\Programs\Python\Python313\pythonw.exe"
  "%LOCALAPPDATA%\Programs\Python\Python312\pythonw.exe"
  "%LOCALAPPDATA%\Programs\Python\Python311\pythonw.exe"
  "C:\Python313\pythonw.exe"
  "C:\Python312\pythonw.exe"
) do (
  if not defined PY if exist %%P set "PY=%%~P"
)

if not defined PY (
  for /f "delims=" %%i in ('where pythonw.exe 2^>nul') do (
    if not defined PY set "PY=%%i"
  )
)

if not defined PY (
  echo [错误] 未找到 pythonw.exe，请先安装 Python 3.10+。
  echo        也可以直接运行: python "%APP%main.py"
  pause
  exit /b 1
)

start "" "%PY%" "%APP%main.py"
endlocal
