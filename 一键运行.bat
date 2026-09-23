@echo off
set ADB=D:\leidian\LDPlayer9\adb.exe
set VENV=D:\逆向\逆向学习\tools\venv\Scripts
cd /d "%~dp0"

echo [1/2] connecting emulator and starting frida-server ...
"%ADB%" connect 127.0.0.1:5555 >nul
"%ADB%" -s emulator-5554 shell "su -c 'chmod 755 /data/local/tmp/frida-server; nohup /data/local/tmp/frida-server >/dev/null 2>&1 &'"
timeout /t 3 >nul

echo [2/2] running Frida hooks on UnCrackable L1 ...
echo.
"%VENV%\python.exe" "%~dp0run_verify.py"

echo.
pause