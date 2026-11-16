@echo off
:: DESBLOQUEO - Requiere ejecución como Administrador

NET SESSION >nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
    echo Por favor, ejecuta este script como Administrador.
    pause
    exit
)

:: Restaurar hosts
IF EXIST %SystemRoot%\System32\drivers\etc\hosts.backup (
    copy /Y %SystemRoot%\System32\drivers\etc\hosts.backup %SystemRoot%\System32\drivers\etc\hosts
    echo Archivo HOSTS restaurado.
)

:: Restaurar DNS automático
netsh interface ip set dns name="Wi-Fi" dhcp
netsh interface ip set dns name="Ethernet" dhcp

echo DNS restaurado a automático.

pause
