@echo off
setlocal
cd /d "%~dp0"
title 学习通签到助手 - 启动器

netstat -ano | findstr ":8787" | findstr LISTENING >nul 2>&1
if %errorlevel%==0 (
  echo [i] 服务已在运行,直接显示地址...
  goto show
)

echo [1/2] 后台启动服务(HTTPS + 局域网)...
powershell -NoProfile -Command "Start-Process -FilePath cmd -ArgumentList '/c','set PYTHONIOENCODING=utf-8&& python server.py --lan --https > server-lan.log 2>&1' -WorkingDirectory '%CD%' -WindowStyle Hidden"

echo [2/2] 等待就绪...
for /l %%i in (1,1,25) do (
  netstat -ano | findstr ":8787" | findstr LISTENING >nul 2>&1
  if not errorlevel 1 goto show
  ping -n 2 127.0.0.1 >nul
)
echo [!] 启动超时,请查看 server-lan.log
pause
exit /b 1

:show
set TOKEN=
if exist "data\.token" set /p TOKEN=<data\.token
echo.
echo ============================================================
echo    学习通签到助手 - 浏览器版(学生端)  已启动
echo ============================================================
echo    电脑本机:  https://127.0.0.1:8787
for /f "tokens=2 delims=:" %%a in ('ipconfig ^| findstr /c:"IPv4"') do (
  for /f "tokens=1" %%b in ("%%a") do (
    if not "%%b"=="127.0.0.1" echo    手机访问:  https://%%b:8787/?k=%TOKEN%
  )
)
echo.
echo    手机首次使用需装证书: certs\ca.crt
echo      (设置 - 安全 - 加密与凭据 - 安装证书 - CA 证书)
echo    本窗口可直接关闭,服务在后台运行;停止请用 stop.bat
echo ============================================================
echo.
pause
