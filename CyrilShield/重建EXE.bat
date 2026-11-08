@echo off
chcp 65001 >nul
setlocal
set "APP=%~dp0"
set "PY="

for %%P in (
  "%LOCALAPPDATA%\Programs\Python\Python313\python.exe"
  "%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
  "%LOCALAPPDATA%\Programs\Python\Python311\python.exe"
) do (
  if not defined PY if exist %%P set "PY=%%~P"
)
if not defined PY set "PY=python"

echo 正在重新打包独立 EXE ...
"%PY%" -m PyInstaller --noconfirm --clean --onefile --windowed --noupx ^
  --log-level=WARN --name CyrilShield --icon "assets/app.ico" ^
  --add-binary "tools/upx.exe;tools" ^
  --add-data "cyrilshield/web;cyrilshield/web" ^
  --add-data "assets/app.ico;assets" ^
  --hidden-import=PIL.Image --hidden-import=PIL.ImageTk ^
  --distpath dist --workpath .build --specpath . main.py
if errorlevel 1 (
  echo 打包失败，请确认已安装 PyInstaller ^(pip install pyinstaller^)。
) else (
  echo 完成：%APP%dist\CyrilShield.exe
)
pause
endlocal
