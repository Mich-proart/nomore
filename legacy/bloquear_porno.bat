@echo off
:: BLOQUEO DE CONTENIDO EXPLÍCITO VIA HOSTS Y DNS
:: Requiere ejecución como Administrador

:: Verifica permisos
NET SESSION >nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
    echo Por favor, ejecuta este script como Administrador.
    pause
    exit
)

echo Bloqueando sitios porno en archivo HOSTS...

:: Backup del archivo hosts
copy %SystemRoot%\System32\drivers\etc\hosts %SystemRoot%\System32\drivers\etc\hosts.backup

:: Lista de sitios porno bloqueados
set HOSTS_PATH=%SystemRoot%\System32\drivers\etc\hosts
echo. >> %HOSTS_PATH%
echo ### BLOQUEADOR PORNO ### >> %HOSTS_PATH%
echo 127.0.0.1 pornhub.com >> %HOSTS_PATH%
echo 127.0.0.1 www.pornhub.com >> %HOSTS_PATH%
echo 127.0.0.1 xvideos.com >> %HOSTS_PATH%
echo 127.0.0.1 www.xvideos.com >> %HOSTS_PATH%
echo 127.0.0.1 xnxx.com >> %HOSTS_PATH%
echo 127.0.0.1 www.xnxx.com >> %HOSTS_PATH%
echo 127.0.0.1 onlyfans.com >> %HOSTS_PATH%
echo 127.0.0.1 redtube.com >> %HOSTS_PATH%
echo 127.0.0.1 youporn.com >> %HOSTS_PATH%
echo 127.0.0.1 xhamster.com >> %HOSTS_PATH%

echo Sitios añadidos al archivo HOSTS.

:: Configurar DNS CleanBrowsing Family Filter
echo Configurando DNS...
netsh interface ip set dns name="Wi-Fi" static 185.228.168.168
netsh interface ip add dns name="Wi-Fi" 185.228.169.168 index=2
netsh interface ip set dns name="Ethernet" static 185.228.168.168
netsh interface ip add dns name="Ethernet" 185.228.169.168 index=2

echo DNS configurado para CleanBrowsing Family Filter.

pause
