@echo off
title OPERACAO VIGIA - Arsenal de Regras
cd /d "%~dp0"
echo Iniciando servidor local em http://localhost:8787 ...
where python >nul 2>&1 && (start "" http://localhost:8787 & python -m http.server 8787) && goto :eof
where py >nul 2>&1 && (start "" http://localhost:8787 & py -m http.server 8787) && goto :eof
echo Python nao encontrado. Instale em https://www.python.org/downloads/ (marque "Add to PATH") e tente de novo.
pause
