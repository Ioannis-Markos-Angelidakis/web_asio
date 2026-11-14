@echo off
setlocal EnableDelayedExpansion

:: Locate openssl.exe in PATH or common installation folders
set "OPENSSL_BIN="
where openssl >nul 2>&1
if not errorlevel 1 (
    set "OPENSSL_BIN=openssl"
) else (
    for %%P in (
        "%ProgramFiles%\Git\usr\bin\openssl.exe"
        "%ProgramFiles%\Git\mingw64\bin\openssl.exe"
        "%ProgramFiles(x86)%\Git\usr\bin\openssl.exe"
        "%LocalAppData%\Programs\Git\usr\bin\openssl.exe"
        "%ProgramFiles%\OpenSSL-Win64\bin\openssl.exe"
        "%ProgramFiles%\OpenSSL\bin\openssl.exe"
        "C:\OpenSSL-Win64\bin\openssl.exe"
    ) do (
        if not defined OPENSSL_BIN if exist "%%~P" set "OPENSSL_BIN=%%~P"
    )
)

if not defined OPENSSL_BIN (
    echo [ERROR] Could not find openssl.exe.
    echo Install it via: winget install ShiningLight.OpenSSL.Light
    exit /b 1
)

if defined FW_CERT_DAYS (
    set "DAYS=%FW_CERT_DAYS%"
) else (
    set "DAYS=825"
)

set "SANs=DNS:localhost,IP:127.0.0.1,IP:::1"

:: Auto-include every non-link-local IPv4 address of this machine
for /f "tokens=2 delims=:" %%A in ('ipconfig ^| findstr /i "IPv4"') do (
    for /f "tokens=1" %%B in ("%%A") do (
        set "ADDR=%%B"
        if not "!ADDR!"=="127.0.0.1" if not "!ADDR:~0,8!"=="169.254." (
            set "SANs=!SANs!,IP:!ADDR!"
        )
    )
)

:: Extra names / IPs from the command line
for %%E in (%*) do (
    echo "%%~E" | findstr /r "^\"[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\"" >nul
    if not errorlevel 1 (
        set "SANs=!SANs!,IP:%%~E"
    ) else (
        set "SANs=!SANs!,DNS:%%~E"
    )
)

"%OPENSSL_BIN%" req -x509 -newkey rsa:2048 -sha256 -days "%DAYS%" -nodes ^
  -keyout key.pem -out cert.pem ^
  -subj "/CN=localhost" ^
  -addext "subjectAltName=%SANs%" ^
  -addext "basicConstraints=critical,CA:FALSE" ^
  -addext "keyUsage=critical,digitalSignature,keyEncipherment" ^
  -addext "extendedKeyUsage=serverAuth"

if errorlevel 1 exit /b %errorlevel%

echo wrote cert.pem / key.pem
echo   SANs: %SANs%
echo run with:
echo   webfw --port 8443 --tls-cert cert.pem --tls-key key.pem
echo test with:
echo   curl.exe -k --http2 https://localhost:8443/api/info
echo   curl.exe --http2-prior-knowledge http://localhost:8443/api/info