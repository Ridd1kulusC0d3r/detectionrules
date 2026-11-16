#!/usr/bin/env bash
# artex_exposure_check.sh: verifica, em ativos AUTORIZADOS, se há console ARTEX exposto e imagens Docker
# com backdoor. Use só em ativos do seu escopo (seus ou de clientes com autorização por escrito).
#
# O que checa (fonte: pack MalwareMustDie ARTEX v1.1.3, osquery mmd_artex_t4_console_ports e Suricata 4260122):
#   - portas do ARTEX: 8787 (console padrão), 8788 (recorder), 8790 e 8890 (console customizado), 5435 (banco)
#   - resposta HTTP com  WWW-Authenticate: Basic realm="ARTEX"  ou "ARTEX" no <title> (T2)
#   - com --docker: imagens/containers locais tomicdd/artex e congdonglinux/artex (T1, backdoor)
#     e outras imagens */artex (T4, conferir procedência)
#
# Uso:
#   ./scripts/artex_exposure_check.sh hosts.txt             # um host/IP por linha (# comenta)
#   ./scripts/artex_exposure_check.sh -p 8787,8788 10.0.0.5 app.cliente.com.br
#   ./scripts/artex_exposure_check.sh --docker              # só a checagem local de imagens
# Saída: CSV em stdout (host,porta,estado,evidência,tier). Código 2 se achar T1/T2.
set -u
PORTS="8787,8788,8790,8890,5435"
TIMEOUT=4
DOCKER=0
TARGETS=()

while [ $# -gt 0 ]; do
  case "$1" in
    -p|--ports) PORTS="$2"; shift 2 ;;
    -t|--timeout) TIMEOUT="$2"; shift 2 ;;
    --docker) DOCKER=1; shift ;;
    -h|--help) sed -n '2,16p' "$0"; exit 0 ;;
    *) if [ -f "$1" ]; then
         while IFS= read -r l; do l="${l%%#*}"; l="$(echo "$l" | tr -d '[:space:]')"; [ -n "$l" ] && TARGETS+=("$l"); done < "$1"
       else TARGETS+=("$1"); fi
       shift ;;
  esac
done

FOUND=0
echo "host,porta,estado,evidencia,tier"

port_open() {  # host porta -> 0 se aberta (bash /dev/tcp, sem nmap)
  timeout "$TIMEOUT" bash -c "exec 3<>/dev/tcp/$1/$2" 2>/dev/null
}

probe_http() {  # host porta -> imprime evidência ARTEX se houver
  local h="$1" p="$2" out=""
  for scheme in http https; do
    out=$(curl -sk -m "$TIMEOUT" -D - -o - --max-filesize 65536 "$scheme://$h:$p/" 2>/dev/null | head -c 65536 | tr -d '\r')
    [ -n "$out" ] || continue
    if echo "$out" | grep -qi 'www-authenticate:.*realm="\?ARTEX'; then echo "realm=\"ARTEX\" ($scheme)"; return; fi
    if echo "$out" | grep -qiE '<title>[^<]*ARTEX'; then echo "title ARTEX ($scheme)"; return; fi
    echo "http-sem-marcador ($scheme)"; return
  done
}

for h in "${TARGETS[@]}"; do
  IFS=',' read -ra PL <<< "$PORTS"
  for p in "${PL[@]}"; do
    if port_open "$h" "$p"; then
      ev=$(probe_http "$h" "$p")
      case "$ev" in
        realm*|title*) echo "$h,$p,ABERTA,$ev,T2"; FOUND=1 ;;
        *)             echo "$h,$p,ABERTA,${ev:-tcp},T4" ;;
      esac
    fi
  done
done

if [ "$DOCKER" = 1 ]; then
  if command -v docker >/dev/null 2>&1; then
    docker images --format '{{.Repository}}:{{.Tag}} {{.ID}}' 2>/dev/null | while read -r img id; do
      case "$img" in
        tomicdd/artex*|congdonglinux/artex*|artex-local:perf2-20261003*) echo "local,-,IMAGEM,$img ($id) backdoor conhecido: remover e reconstruir de fonte auditada,T1" ;;
        */artex*|artex*) echo "local,-,IMAGEM,$img ($id) conferir procedência,T4" ;;
      esac
    done
    docker ps -a --format '{{.Image}} {{.Names}} {{.Ports}}' 2>/dev/null | while read -r img name ports; do
      case "$img" in
        tomicdd/artex*|congdonglinux/artex*) echo "local,-,CONTAINER,$name usa $img $ports,T1" ;;
      esac
    done
    docker images --format '{{.Repository}}' 2>/dev/null | grep -qE '^(tomicdd|congdonglinux)/artex' && FOUND=1
  else
    echo "local,-,SEM-DOCKER,docker não encontrado neste host,-"
  fi
fi

exit $([ "$FOUND" = 1 ] && echo 2 || echo 0)
