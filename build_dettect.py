#!/usr/bin/env python3
"""Catálogo → arquivos do DeTT&CT + mapa OSSEM de eventos. stdlib-only.

Ideia trazida do Dettectinator (siriussecurity/dettectinator): em vez de mapear a mão o que você
detecta, gere os YAML do DeTT&CT (rabobank-cdc/DeTTECT) a partir das regras. Aqui a origem é o
catálogo público, então o resultado é uma LINHA DE BASE ("o que as regras públicas cobririam"),
não a cobertura do seu ambiente.

Uso:  python3 build_dettect.py [OSSEM_CSV]
  OSSEM_CSV  attack_events_mapping.csv do OTRF/OSSEM-DM
             (padrão: ossem/use-cases/mitre_attack/attack_events_mapping.csv, clonado por scripts/fetch_sources.sh)

Lê:   data/index.json, data/manifest.json, data/graph/attack.json
Gera:
  data/dettect/techniques-all.yaml       technique-administration: todas as regras, uma linha por fonte
  data/dettect/techniques-<formato>.yaml technique-administration por linguagem (sigma, elastic, splunk…)
  data/dettect/data-sources-<x>.yaml     data-source-administration (modelo): Sysmon, Windows Security
                                         Auditing e Defender for Endpoint, a partir do OSSEM
  data/dettect/index.json                lista dos arquivos gerados, com contagens
  data/graph/ossem.json                  componente de dados ATT&CK → eventos, canal e como habilitar

Sem o CSV do OSSEM, os arquivos de técnica são gerados e os que dependem do OSSEM ficam como estão.
"""
import collections, csv, datetime, json, os, re, sys

OSSEM = sys.argv[1] if len(sys.argv) > 1 else "ossem/use-cases/mitre_attack/attack_events_mapping.csv"
OUT = "data/dettect"
MAX_LOC = 20          # nomes de regra listados por técnica nos arquivos por formato
os.makedirs(OUT, exist_ok=True)

IDX = json.load(open("data/index.json", encoding="utf-8"))
MAN = json.load(open("data/manifest.json", encoding="utf-8"))
ATT = json.load(open("data/graph/attack.json", encoding="utf-8"))
TECH, REV = ATT["techniques"], ATT.get("rev", {})
COL = {c: i for i, c in enumerate(IDX["cols"])}
DATE = MAN.get("generated") or datetime.date.today().isoformat()
STAMP = f"{DATE}T00:00:00.000Z"

# formatos de detecção (playbooks SOAR respondem, não detectam: ficam de fora)
FAMILY = {"sigma": "Sigma", "elastic": "Elastic", "splunk": "Splunk", "sentinel": "Microsoft Sentinel",
          "kql-md": "KQL (Defender/Sentinel)", "yaral": "Google SecOps (YARA-L)", "wazuh": "Wazuh",
          "suricata": "Suricata/Snort/Sagan", "yara": "YARA", "panther": "Panther", "falco": "Falco",
          "aql": "QRadar AQL", "gcp": "GCP security-analytics"}


def q(s):
    """Escalar YAML entre aspas simples (uma linha, sem caracteres de controle)."""
    s = re.sub(r"[\x00-\x1f\x7f  ]+", " ", str(s)).strip()
    return "'" + s.replace("'", "''") + "'"


def norm_tid(t):
    t = str(t).upper()
    t = REV.get(t, t)
    return t if t in TECH else None


def tech_yaml(name, per_tech, note):
    """per_tech: {tid: [linhas de location]} → texto technique-administration v1.2."""
    L = ["# Gerado por build_dettect.py (Detection Rules). " + note,
         "# Linha de base de regras PÚBLICAS: reavalie cada nota depois de implantar e testar no seu ambiente.",
         "version: 1.2", "file_type: technique-administration", f"name: {q(name)}",
         "domain: enterprise-attack", "platform:", "  - all", "techniques:"]
    for tid in sorted(per_tech):
        L += [f"  - technique_id: {tid}", f"    technique_name: {q(TECH[tid]['n'])}",
              "    detection:", "      - applicable_to:", "          - all", "        location:"]
        L += [f"          - {q(x)}" for x in per_tech[tid]]
        L += ["        comment: ''", "        score_logbook:", f"          - date: {STAMP}", "            score: 1",
              "            comment: 'Regra pública disponível; ainda não validada neste ambiente.'",
              "    visibility:", "      - applicable_to:", "          - all", "        comment: ''",
              "        score_logbook:", "          - date: null", "            score: 0",
              "            comment: ''", "            auto_generated: true"]
    return "\n".join(L) + "\n"


files = []
def write(fn, text, **meta):
    open(f"{OUT}/{fn}", "w", encoding="utf-8").write(text)
    files.append({"file": fn, "bytes": len(text.encode("utf-8")), **meta})
    print(f"  {OUT}/{fn}  {len(text)/1e3:.0f} KB  {meta}")


# ---------------------------------------------------------------- técnicas
by_fmt = collections.defaultdict(lambda: collections.defaultdict(list))      # fmt → tid → [(fonte, título)]
by_src = collections.defaultdict(collections.Counter)                        # tid → fonte → n
nrules = collections.Counter()
for r in IDX["rows"]:
    fmt = IDX["fmt"][r[COL["fmt"]]]
    if fmt not in FAMILY or r[COL["ctype"]] == "playbook": continue
    tids = {t for t in (norm_tid(x) for x in r[COL["techniques"]]) if t}
    if not tids: continue
    src = IDX["src"][r[COL["src"]]]; nrules[fmt] += 1
    for t in tids:
        by_fmt[fmt][t].append((src, r[COL["title"]])); by_src[t][src] += 1

write("techniques-all.yaml",
      tech_yaml("Detection Rules: catálogo público (todas as linguagens)",
                {t: [f"{s}: {n} regra{'s' if n > 1 else ''}" for s, n in c.most_common()] for t, c in by_src.items()},
                f"ATT&CK v{ATT.get('version')}, catálogo de {DATE}."),
      kind="techniques", label="Todas as linguagens", techniques=len(by_src), rules=sum(nrules.values()))
for fmt in sorted(by_fmt, key=lambda f: -nrules[f]):
    per = {}
    for t, items in by_fmt[fmt].items():
        items = sorted(set(items)); loc = [f"{s}: {ti}" for s, ti in items[:MAX_LOC]]
        if len(items) > MAX_LOC: loc.append(f"(+{len(items) - MAX_LOC} outras regras no catálogo)")
        per[t] = loc
    write(f"techniques-{fmt}.yaml",
          tech_yaml(f"Detection Rules: {FAMILY[fmt]}", per, f"Só regras {FAMILY[fmt]}. ATT&CK v{ATT.get('version')}, catálogo de {DATE}."),
          kind="techniques", label=FAMILY[fmt], techniques=len(per), rules=nrules[fmt])

# ---------------------------------------------------------------- OSSEM
if not os.path.exists(OSSEM):
    print(f"  (sem {OSSEM}: mantive data/graph/ossem.json e os data-sources-*.yaml existentes)")
    old = {}
    try: old = {f["file"]: f for f in json.load(open(f"{OUT}/index.json", encoding="utf-8"))["files"]}
    except Exception: pass
    files += [f for fn, f in old.items() if fn.startswith("data-sources-") and os.path.exists(f"{OUT}/{fn}")]
else:
    rows = list(csv.DictReader(open(OSSEM, encoding="utf-8-sig")))
    title = lambda s: " ".join(w if w.isupper() else w.capitalize() for w in s.split())
    def actions(r):
        try: return [a.get("ActionType") for a in json.loads(r["Filter in Log"].replace("'", '"')) if a.get("ActionType")]
        except Exception: return []

    # componente de dados → eventos (para a aba "Prepare os dados")
    comp = collections.defaultdict(dict)
    for r in rows:
        ls = {"sysmon": "Sysmon for Linux", "cloudtrail": "AWS CloudTrail"}.get(r["Log Source"].lower(), r["Log Source"])
        k = (ls, r["EventID"])
        e = comp[r["Component"].strip().lower()].setdefault(k, {"e": r["EventID"], "n": r["Event Name"].strip(), "ls": ls, "pl": r["Event Platform"]})
        if r["Channel"]: e["ch"] = r["Channel"]
        if r["Enable Commands"]: e["on"] = r["Enable Commands"]
        if r["GPO Audit Policy"]: e["gpo"] = r["GPO Audit Policy"]
        acts = actions(r)
        if acts: e["at"] = sorted(set(e.get("at", [])) | set(acts))
    json.dump({"source": "OTRF/OSSEM-DM · use-cases/mitre_attack/attack_events_mapping.csv (MIT)", "generated": DATE,
               "components": {c: list(v.values()) for c, v in sorted(comp.items())}},
              open("data/graph/ossem.json", "w", encoding="utf-8"), ensure_ascii=False, separators=(",", ":"))
    print(f"  data/graph/ossem.json  {os.path.getsize('data/graph/ossem.json')/1e3:.0f} KB  {len(comp)} componentes")

    # modelos de data-source-administration (mesma lógica dos plugins OSSEM do Dettectinator)
    def ds_yaml(name, log_source, product):
        per = collections.defaultdict(list)
        for r in rows:
            if r["Log Source"] != log_source: continue
            for p in product(r):
                if p not in per[title(r["Component"])]: per[title(r["Component"])].append(p)
        L = ["# Gerado por build_dettect.py (Detection Rules) a partir do OTRF/OSSEM-DM (MIT).",
             "# MODELO: lista o que a fonte é capaz de registrar. Preencha datas e data_quality com o que você realmente coleta.",
             "version: 1.1", "file_type: data-source-administration", f"name: {q(name)}", "domain: enterprise-attack",
             "systems:", "  - applicable_to: default", "    platform:", "      - Windows", "data_sources:"]
        for c in sorted(per):
            L += [f"  - data_source_name: {q(c)}", "    data_source:", "      - applicable_to:", "          - default",
                  "        date_registered: null", "        date_connected: null", "        products:"]
            L += [f"          - {q(p)}" for p in per[c]]
            L += ["        available_for_data_analytics: false", "        comment: ''", "        data_quality:",
                  "          device_completeness: 0", "          data_field_completeness: 0", "          timeliness: 0",
                  "          consistency: 0", "          retention: 0"]
        return "\n".join(L) + "\n", len(per)
    ev = lambda r: [f"{r['EventID']}: {r['Event Name'].strip()}"]
    mde = lambda r: [f"{r['Event Name']}: {a}" for a in actions(r)] or [r["Event Name"]]
    for fn, name, ls, prod in (("data-sources-sysmon.yaml", "Windows + Sysmon", "Microsoft-Windows-Sysmon", ev),
                               ("data-sources-windows-security.yaml", "Windows Security Auditing", "Microsoft-Windows-Security-Auditing", ev),
                               ("data-sources-defender-endpoint.yaml", "Microsoft Defender for Endpoint", "Microsoft Defender for Endpoint", mde)):
        text, n = ds_yaml(name, ls, prod)
        write(fn, text, kind="data-sources", label=name, data_sources=n)

json.dump({"generated": DATE, "attack": ATT.get("version"), "files": files},
          open(f"{OUT}/index.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1)
print(f"  {OUT}/index.json  {len(files)} arquivos")
