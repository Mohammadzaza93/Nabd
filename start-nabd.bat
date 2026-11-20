@echo off
chcp 65001 >nul
title نبض - مراقبة الشبكة
cd /d "%~dp0"

where python >nul 2>nul
if errorlevel 1 (
  echo.
  echo خطأ: Python غير مثبت أو غير مضاف إلى PATH.
  echo حمّل Python من https://www.python.org/downloads/ أثناء تحديد "Add to PATH".
  echo.
  pause
  exit /b 1
)

python -c "import flask, requests, yaml, waitress" >nul 2>nul
if errorlevel 1 (
  echo تثبيت المتطلبات لأول مرة...
  python -m pip install -r requirements.txt
  if errorlevel 1 (
    echo فشل تثبيت المتطلبات. تحقق من اتصال الإنترنت ثم أعد المحاولة.
    pause
    exit /b 1
  )
)

rem تشغيل PostgreSQL المحمول تلقائياً إذا كان مضبوطاً في الإعدادات
if "%NABD_PG_BIN%"=="" if exist "%LOCALAPPDATA%\nabd-pg\pgsql\bin\pg_ctl.exe" set "NABD_PG_BIN=%LOCALAPPDATA%\nabd-pg\pgsql\bin"
if "%NABD_PG_DATA%"=="" if exist "%LOCALAPPDATA%\nabd-pg\data\PG_VERSION" set "NABD_PG_DATA=%LOCALAPPDATA%\nabd-pg\data"
if defined NABD_PG_BIN if defined NABD_PG_DATA (
  netstat -an | findstr ":5432 " >nul
  if errorlevel 1 (
    echo تشغيل خادم PostgreSQL المحلي...
    "%NABD_PG_BIN%\pg_ctl.exe" -D "%NABD_PG_DATA%" -o "-p 5432 -h 127.0.0.1" -l "%LOCALAPPDATA%\nabd-pg\pg.log" start >nul
  )
)

if not exist config.yaml (
  echo.
  echo لا يوجد ملف إعدادات بعد. سأشغّل الإعداد التفاعلي لإدخال عناوينك...
  python -u nabd.py --setup
  if errorlevel 1 (
    echo تعذر إكمال الإعداد.
    pause
    exit /b 1
  )
)

:loop
echo.
echo [+] تشغيل نبض...
python -u nabd.py
echo.
echo نبض توقف، إعادة التشغيل بعد 5 ثوان...
timeout /t 5 >nul
goto loop
