#!/bin/bash
cd "$(dirname "$0")"
echo "Iniciando servidor local em http://localhost:8787 ..."
(sleep 1; open http://localhost:8787) &
python3 -m http.server 8787
