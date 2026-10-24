#!/bin/bash
cd "$(dirname "$0")"
echo "Iniciando servidor local em http://localhost:8787 ..."
(sleep 1; xdg-open http://localhost:8787 2>/dev/null || sensible-browser http://localhost:8787 2>/dev/null) &
python3 -m http.server 8787
