#!/usr/bin/env python3
"""artex_retrohunt.py: retro-hunt dos IOCs do ARTEX (pack MalwareMustDie) em logs exportados.

Somente biblioteca padrão. Lê o CSV de IOCs do pack (iocs/mmd-artex-iocs.csv, DRL 1.1,
atribuição "MalwareMustDie.org - @unixfreaxjp") e varre arquivos de log exportados do Entra ID,
CloudTrail, firewall, proxy, WAF, servidor web, Sysmon etc. Aceita JSON, JSON Lines, CSV,
texto puro e .gz, arquivo a arquivo ou diretórios inteiros.

Regras do pack respeitadas aqui:
  - Tiers: T1 confirmado, T2 comportamento, T3 IOC de incidente passado, T4 genérico.
    T4 é só enriquecimento: nunca abra incidente só com T4.
  - Janela: por padrão, só eventos a partir de --since (2026-08-01).
  - Validade: modo "alert" usa alert_until (IPs alertam até 2027-02-11); modo "hunt"
    usa hunt_until/valid_until (até 2027-11-13). IOC vencido no modo escolhido é ignorado.
  - User-agents genéricos (T4, p.ex. "Mozilla/5.0", "curl/7.88.1") só casam por igualdade
    exata num campo de user-agent; em texto puro só casam UAs T1/T2.
  - Qualquer hit de 38.244.50.120 é marcado para escalar (campanha coreana + lista JPCERT/CC).
  - App IDs do ConnectWise (T1): o pack manda caçar desde 2026-10-13 e alertar pelo que a
    identidade FAZ (role, credencial), não só pelo login.

Exemplos:
  python3 scripts/artex_retrohunt.py --iocs ext/mmd_artex/.../iocs/mmd-artex-iocs.csv logs/
  python3 scripts/artex_retrohunt.py --download --since 2026-08-01 --mode hunt \
      --out hits.csv entra_signins.json cloudtrail/ proxy.log.gz
  python3 scripts/artex_retrohunt.py --download --list-iocs --mode alert   # só mostra os IOCs válidos

Saída: CSV (ou JSON Lines com --jsonl) com tier, indicador, tipo, campanha, arquivo, linha,
timestamp e aviso do pack. Código de saída: 0 sem hits, 1 só T3/T4, 2 com T1/T2.
"""
import argparse, csv, datetime as dt, gzip, io, ipaddress, json, os, re, sys, urllib.request

PACK_DIR = "etc/artex-stix-osquery-sigma-kql-snort-suricata-yara"
RAW_URL = f"https://raw.githubusercontent.com/unixfreaxjp/malwaremustdie/master/{PACK_DIR}/iocs/mmd-artex-iocs.csv"
DEFAULT_LOCAL = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "ext", "mmd_artex", PACK_DIR, "iocs", "mmd-artex-iocs.csv")
ESCALATE_IP = "38.244.50.120"
CONNECTWISE_HUNT_FROM = "2026-10-13"
TIER_ORDER = {"T1": 1, "T2": 2, "T3": 3, "T4": 4}

UA_KEYS = re.compile(r"(?i)^(user[-_ ]?agent|useragent|cs-user-agent|http\.user_agent|http_user_agent|ua|client\.user_agent|useragent_original|user_agent\.original)$")
TS_KEYS = ("eventTime", "createdDateTime", "TimeGenerated", "@timestamp", "timestamp", "time", "Timestamp",
           "date", "datetime", "EventTime", "UtcTime", "ts", "event_time", "_time", "receivedTime")
ISO_RX = re.compile(r"(20\d\d)-(\d\d)-(\d\d)[T ](\d\d):(\d\d)")
CLF_RX = re.compile(r"\b(\d{1,2})/([A-Z][a-z]{2})/(20\d\d):\d\d:\d\d")          # Apache/Nginx: 16/Nov/2026:10:00:00
SYSLOG_RX = re.compile(r"^(?:<\d+>)?([A-Z][a-z]{2})\s+(\d{1,2})\s+\d\d:\d\d:\d\d")  # syslog BSD: Nov 16 10:00:00 (sem ano)
MONTHS = {m: i for i, m in enumerate("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split(), 1)}
EPOCH_RX = re.compile(r"^\d{10}(\.\d+)?$|^\d{13}$")
IPV4_RX = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
GUID_RX = re.compile(r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b")


# ---------------------------------------------------------------- IOCs
def load_iocs(path=None, download=False):
    if download:
        req = urllib.request.Request(RAW_URL, headers={"User-Agent": "detectionrules-retrohunt"})
        with urllib.request.urlopen(req, timeout=60) as r:
            text = r.read().decode("utf-8", "replace")
    else:
        path = path or DEFAULT_LOCAL
        if not os.path.exists(path):
            sys.exit(f"CSV de IOCs não encontrado: {path}\nUse --iocs <arquivo> ou --download.")
        text = open(path, encoding="utf-8", errors="replace").read()
    return list(csv.DictReader(io.StringIO(text)))


def _date(s):
    try: return dt.date.fromisoformat((s or "").strip()[:10])
    except ValueError: return None


def still_valid(row, mode, today):
    """IOC ainda vale no modo escolhido? Datas não ISO ('until vendor confirms retirement') = vale."""
    key = "alert_until" if mode == "alert" else "hunt_until"
    until = _date(row.get(key)) or _date(row.get("valid_until"))
    if until is None: return True
    return today <= until


def marker_regex(ind):
    """Converte marcadores do CSV ('artx_* / artx-* / zzartx<n>.php', 'sink-* (GitHub runner)') em regex."""
    ind = re.sub(r"\s*\([^)]*\)\s*$", "", ind).strip()
    alts = [a.strip() for a in ind.split(" / ") if a.strip()]
    out = []
    for a in alts:
        rx = re.escape(a).replace(r"\*", r"[\w.\-]*").replace(re.escape("<n>"), r"\d+").replace(re.escape("<intentID>"), r"\d+")
        out.append(rx)
    return re.compile("|".join(out), re.I) if out else None


class Matcher:
    def __init__(self, rows, mode, today):
        self.ip, self.cidr, self.dom, self.suffix = {}, [], {}, {}
        self.ua_exact, self.ua_text, self.ua_sub, self.guid, self.rx = {}, [], [], {}, []
        self.skipped = 0
        for r in rows:
            ind, typ = (r.get("indicator") or "").strip(), (r.get("type") or "").strip()
            if not ind or typ == "type": continue
            if not still_valid(r, mode, today):
                self.skipped += 1; continue
            tier = r.get("tier", "T4")
            if typ == "ipv4": self.ip[ind] = r
            elif typ == "ipv4-cidr":
                try: self.cidr.append((ipaddress.ip_network(ind, strict=False), r))
                except ValueError: pass
            elif typ == "domain": self.dom[ind.lower()] = r
            elif typ == "domain-suffix": self.suffix[ind.lower().lstrip(".")] = r
            elif typ == "user-agent":
                self.ua_exact[ind] = r
                if tier in ("T1", "T2"): self.ua_text.append((ind, r))
            elif typ == "user-agent-substring": self.ua_sub.append((ind, r))
            elif typ == "azure-app-id": self.guid[ind.lower()] = r
            elif typ in ("string-marker", "container-image", "tool-name", "tool-fork", "malware"):
                rx = marker_regex(ind) if typ == "string-marker" else re.compile(r"(?<![\w/])" + re.escape(ind) + r"(?![\w])", re.I)
                if rx: self.rx.append((rx, r))
        self.dom_rx = re.compile(r"(?i)(?<![\w-])((?:[a-z0-9-]+\.)+[a-z]{2,})(?![\w-])")

    def size(self):
        return sum(map(len, (self.ip, self.cidr, self.dom, self.suffix, self.ua_exact, self.ua_sub, self.guid, self.rx)))

    def scan(self, text, ua_values=()):
        hits = []
        for ip in set(IPV4_RX.findall(text)):
            if ip in self.ip: hits.append((ip, self.ip[ip]))
            else:
                try: a = ipaddress.ip_address(ip)
                except ValueError: continue
                for net, r in self.cidr:
                    if a in net: hits.append((ip, r))
        for d in set(m.lower() for m in self.dom_rx.findall(text)):
            if d in self.dom: hits.append((d, self.dom[d]))
            for suf, r in self.suffix.items():
                if d == suf or d.endswith("." + suf): hits.append((d, r))
        for g in set(m.lower() for m in GUID_RX.findall(text)):
            if g in self.guid: hits.append((g, self.guid[g]))
        for ua in ua_values:
            ua = (ua or "").strip()
            if ua in self.ua_exact: hits.append((ua, self.ua_exact[ua]))
        for ua, r in self.ua_text + self.ua_sub:
            if ua in text: hits.append((ua, r))
        for rx, r in self.rx:
            m = rx.search(text)
            if m: hits.append((m.group(0), r))
        seen, out = set(), []
        for v, r in hits:
            k = (v, r.get("indicator"))
            if k not in seen: seen.add(k); out.append((v, r))
        return out


# ---------------------------------------------------------------- eventos
def iter_files(paths):
    for p in paths:
        if os.path.isdir(p):
            for root, _, files in os.walk(p):
                for f in sorted(files): yield os.path.join(root, f)
        elif os.path.exists(p): yield p
        else: print(f"aviso: não encontrado: {p}", file=sys.stderr)


def open_text(path):
    raw = open(path, "rb")
    if raw.read(2) == b"\x1f\x8b":
        raw.seek(0); return io.TextIOWrapper(gzip.GzipFile(fileobj=raw), encoding="utf-8", errors="replace")
    raw.seek(0); return io.TextIOWrapper(raw, encoding="utf-8", errors="replace")


def walk_json(o, uas, ts):
    if isinstance(o, dict):
        for k, v in o.items():
            if isinstance(v, str):
                if UA_KEYS.match(k): uas.append(v)
                if k in TS_KEYS and not ts: ts.append(v)
            elif isinstance(v, (int, float)) and k in TS_KEYS and not ts: ts.append(str(v))
            else: walk_json(v, uas, ts)
    elif isinstance(o, list):
        for x in o: walk_json(x, uas, ts)


def parse_ts(s):
    if not s: return None
    s = str(s).strip()
    if EPOCH_RX.match(s):
        v = float(s); v = v / 1000 if v > 1e11 else v
        return dt.datetime.fromtimestamp(v, dt.timezone.utc).date()
    try:
        m = ISO_RX.search(s)
        if m: return dt.date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
        m = CLF_RX.search(s)
        if m and m.group(2) in MONTHS: return dt.date(int(m.group(3)), MONTHS[m.group(2)], int(m.group(1)))
        m = SYSLOG_RX.search(s)
        if m and m.group(1) in MONTHS:
            today = dt.date.today(); d = dt.date(today.year, MONTHS[m.group(1)], int(m.group(2)))
            return d if d <= today else d.replace(year=today.year - 1)
    except ValueError:
        return None
    return None


def events(path):
    """Gera (nº da linha, texto do evento, [user-agents], data|None)."""
    with open_text(path) as fh:
        head = fh.read(4096); fh.seek(0)
        stripped = head.lstrip()
        if stripped.startswith(("[", "{")):
            try: doc = json.load(fh)          # documento JSON único (export do Graph, CloudTrail, array)
            except ValueError: doc = None     # não é um documento só: trata como JSON Lines abaixo
            if doc is not None:
                if isinstance(doc, dict):
                    recs = next((doc[k] for k in ("Records", "value", "records", "events", "hits", "data")
                                 if isinstance(doc.get(k), list)), [doc])
                else:
                    recs = doc
                for i, rec in enumerate(recs, 1):
                    uas, ts = [], []; walk_json(rec, uas, ts)
                    yield i, json.dumps(rec, ensure_ascii=False), uas, parse_ts(ts[0] if ts else None)
                return
            fh.seek(0)
        is_csv = path.lower().endswith((".csv", ".tsv"))
        if is_csv:
            rdr = csv.DictReader(fh, delimiter="\t" if path.lower().endswith(".tsv") else ",")
            for i, row in enumerate(rdr, 2):
                uas = [v for k, v in row.items() if k and UA_KEYS.match(k.strip())]
                ts = next((row[k] for k in row if k and k.strip() in TS_KEYS and row[k]), None)
                yield i, " | ".join(f"{k}={v}" for k, v in row.items() if v), uas, parse_ts(ts)
            return
        for i, line in enumerate(fh, 1):
            line = line.rstrip("\n")
            if not line.strip(): continue
            uas, ts = [], []
            if line.lstrip().startswith("{"):
                try: walk_json(json.loads(line), uas, ts)
                except ValueError: pass
            if not uas:  # log combinado do Apache/Nginx: último campo entre aspas
                q = re.findall(r'"([^"]*)"', line)
                if len(q) >= 3: uas.append(q[-1])
            yield i, line, uas, parse_ts(ts[0] if ts else line[:120])


# ---------------------------------------------------------------- principal
def main():
    ap = argparse.ArgumentParser(description="Retro-hunt dos IOCs ARTEX (pack MalwareMustDie) em logs exportados.")
    ap.add_argument("paths", nargs="*", help="arquivos ou diretórios de log (JSON, JSONL, CSV, texto, .gz)")
    ap.add_argument("--iocs", help="CSV de IOCs do pack (padrão: ext/mmd_artex/.../iocs/mmd-artex-iocs.csv)")
    ap.add_argument("--download", action="store_true", help="baixa o CSV mais recente do GitHub do pack")
    ap.add_argument("--since", default="2026-08-01", help="ignora eventos com data anterior (AAAA-MM-DD; padrão 2026-08-01)")
    ap.add_argument("--mode", choices=("alert", "hunt"), default="hunt", help="janela de validade do IOC (padrão hunt)")
    ap.add_argument("--today", help="data de referência para a validade (padrão: hoje)")
    ap.add_argument("--min-tier", default="T4", choices=list(TIER_ORDER), help="menor tier reportado (padrão T4)")
    ap.add_argument("--drop-undated", action="store_true", help="descarta eventos sem data reconhecível (padrão: reporta, com event_date vazio)")
    ap.add_argument("--out", help="grava os hits neste arquivo (padrão: stdout)")
    ap.add_argument("--jsonl", action="store_true", help="saída em JSON Lines em vez de CSV")
    ap.add_argument("--list-iocs", action="store_true", help="lista os IOCs válidos no modo escolhido e sai")
    a = ap.parse_args()

    today = _date(a.today) or dt.date.today(); since = _date(a.since)
    rows = load_iocs(a.iocs, a.download)
    m = Matcher(rows, a.mode, today)
    print(f"[i] {m.size()} IOCs ativos (modo {a.mode}, referência {today}); {m.skipped} vencidos ignorados", file=sys.stderr)
    if a.list_iocs:
        w = csv.writer(sys.stdout); w.writerow(["indicator", "type", "tier", "campaign", "alert_until", "hunt_until"])
        for r in rows:
            if r.get("indicator") and still_valid(r, a.mode, today):
                w.writerow([r["indicator"], r["type"], r["tier"], r.get("campaign", ""), r.get("alert_until", ""), r.get("hunt_until", "")])
        return 0
    if not a.paths: ap.error("informe ao menos um arquivo ou diretório de log (ou use --list-iocs)")

    fields = ["tier", "indicator", "matched", "type", "campaign", "source", "file", "line", "event_date", "escalate", "note", "warning", "excerpt"]
    out = open(a.out, "w", newline="", encoding="utf-8") if a.out else sys.stdout
    w = None if a.jsonl else csv.DictWriter(out, fieldnames=fields)
    if w: w.writeheader()
    counts, worst, nfiles, nev = {}, 9, 0, 0
    for path in iter_files(a.paths):
        nfiles += 1
        try:
            for ln, text, uas, day in events(path):
                nev += 1
                if day is None and a.drop_undated: continue
                if day is not None and since and day < since: continue
                for val, r in m.scan(text, uas):
                    tier = r.get("tier", "T4")
                    if TIER_ORDER.get(tier, 4) > TIER_ORDER[a.min_tier]: continue
                    esc = ""
                    if ESCALATE_IP in text: esc = "escalar para T1 se houver hit comportamental (38.244.50.120: Coreia + JPCERT/CC)"
                    note = ""
                    if r.get("type") == "azure-app-id":
                        note = f"ConnectWise: revisar role/credencial deste app desde {CONNECTWISE_HUNT_FROM}; desabilitar, não apagar"
                        if day and day < _date(CONNECTWISE_HUNT_FROM): note += " (evento anterior à janela do incidente)"
                    if tier == "T4": note = (note + "; " if note else "") + "T4: só enriquecimento, correlacione com T1/T2"
                    rec = {"tier": tier, "indicator": r.get("indicator"), "matched": val, "type": r.get("type"),
                           "campaign": r.get("campaign", ""), "source": r.get("source", ""), "file": path, "line": ln,
                           "event_date": day.isoformat() if day else "", "escalate": esc, "note": note,
                           "warning": r.get("warning", ""), "excerpt": text[:300]}
                    if w: w.writerow(rec)
                    else: out.write(json.dumps(rec, ensure_ascii=False) + "\n")
                    counts[tier] = counts.get(tier, 0) + 1; worst = min(worst, TIER_ORDER.get(tier, 4))
        except (OSError, UnicodeError) as e:
            print(f"aviso: {path}: {e}", file=sys.stderr)
    if a.out: out.close()
    resumo = ", ".join(f"{t}={counts[t]}" for t in sorted(counts)) or "nenhum hit"
    print(f"[i] {nfiles} arquivos, {nev} eventos; hits: {resumo}", file=sys.stderr)
    return 2 if worst <= 2 else 1 if counts else 0


if __name__ == "__main__":
    sys.exit(main())
