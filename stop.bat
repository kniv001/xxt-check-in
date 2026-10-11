@echo off
setlocal enabledelayedexpansion
title 学习通签到助手 - 停止器
set FOUND=0
for /f "tokens=5" %%p in ('netstat -ano ^| findstr ":8787" ^| findstr LISTENING') do (
  taskkill /F /PID %%p >nul 2>&1
  if not errorlevel 1 (
    echo [OK] 已停止服务进程 PID %%p
    set FOUND=1
  )
)
if "!FOUND!"=="0" echo [i] 服务未在运行
echo.
pause
