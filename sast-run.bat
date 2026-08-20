@echo off
REM 실행형 SAST 러너 (Windows 더블클릭용). WSL Kali 안에서 sast-run.sh 실행.
setlocal
set "TARGET=%~1"
if "%TARGET%"=="" set /p TARGET=스캔 대상 (경로/gitURL/owner-repo/폴더명):
if "%TARGET%"=="" (echo 대상이 없습니다. & pause & exit /b 1)

REM 이 .bat 이 있는 폴더의 WSL 경로로 변환
set "HEREWIN=%~dp0"
for /f "usebackq delims=" %%i in (`wsl -d kali-linux wslpath "%HEREWIN%"`) do set "HERE=%%i"

wsl -d kali-linux -- bash "%HERE%/sast-run.sh" "%TARGET%"
echo.
pause
