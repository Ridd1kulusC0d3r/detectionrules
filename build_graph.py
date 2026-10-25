#!/usr/bin/env python3
"""build_graph.py — grafo de conhecimento do Detection Rules (stdlib-only).

Cruza:
  - catálogo de regras (catalog.json)            → cobertura por técnica e formato
  - MITRE ATT&CK v20 STIX (attack-stix-data)     → táticas, técnicas, grupos, software,
                                                    campanhas, mitigações, estratégias de
                                                    detecção, analíticas e fontes de log
  - Atomic Red Team (só metadados)                → testes para validar cada técnica
  - EVTX-to-MITRE-Attack (índice)                 → amostras de log mapeadas por técnica (explícito)
  - EVTX-ATTACK-SAMPLES (índice)                  → amostras mapeadas por palavra-chave (inferido)
  - CyberMonitor APT collections (índice)         → relatórios públicos ligados a grupos (inferido)
  - planilha "Malware IR - Tools & Resources"     → ferramentas e materiais ligados a fases e formatos

Saída em data/graph/:
  attack.json      técnicas/táticas/grupos/... + cobertura de regras (carregado pelo app)
  resources.json   recursos da planilha estruturados e relacionados
  graph.json       nós e arestas (para outras ferramentas)
  graph.graphml    o mesmo grafo em GraphML (Gephi, yEd, Neo4j)
  navigator-layer.json  camada do ATT&CK Navigator com a cobertura de regras

Uso: python3 build_graph.py [DIR_FONTES] [CATALOGO]
"""
import json, os, re, sys, csv, io, subprocess, collections, datetime
from xml.sax.saxutils import escape as xesc

SRC = sys.argv[1] if len(sys.argv) > 1 else "."
CAT = sys.argv[2] if len(sys.argv) > 2 else os.path.join(SRC, "catalog.json")
OUT = "data/graph"
os.makedirs(OUT, exist_ok=True)
P = lambda *a: os.path.join(SRC, *a)
slug = lambda s: re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")

def ls_tree(repo):
    """Lista arquivos de um clone sem checkout (--filter=blob:none)."""
    try:
        out = subprocess.run(["git", "-C", P(repo), "ls-tree", "-r", "--name-only", "HEAD"],
                             capture_output=True, text=True, check=True).stdout
        return out.splitlines()
    except Exception:
        return []

def ext_id(o):
    for r in o.get("external_references", []):
        if r.get("source_name") == "mitre-attack":
            return r.get("external_id"), r.get("url")
    return None, None

def clip(s, n):
    s = re.sub(r"\(Citation:[^)]*\)", "", s or "")
    s = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", s)
    s = re.sub(r"<[^>]+>", "", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s if len(s) <= n else s[:n].rsplit(" ", 1)[0] + "…"

# ------------------------------------------------------------------ ATT&CK
B = json.load(open(P("attack_stix", "enterprise-attack", "enterprise-attack.json"), encoding="utf-8"))
objs = B["objects"]
live = lambda o: not o.get("revoked") and not o.get("x_mitre_deprecated")
byid = {o["id"]: o for o in objs}
version = next((o.get("x_mitre_version") for o in objs if o["type"] == "x-mitre-collection"), "?")

TACTIC_ORDER = ["reconnaissance", "resource-development", "initial-access", "execution", "persistence",
                "privilege-escalation", "stealth", "defense-impairment", "credential-access", "discovery",
                "lateral-movement", "collection", "command-and-control", "exfiltration", "impact"]
tactics = {}
for o in objs:
    if o["type"] == "x-mitre-tactic":
        tid, url = ext_id(o)
        tactics[o["x_mitre_shortname"]] = {"id": tid, "n": o["name"], "d": clip(o.get("description"), 240)}
tac_list = [dict(short=s, **tactics[s]) for s in TACTIC_ORDER if s in tactics] + \
           [dict(short=s, **v) for s, v in tactics.items() if s not in TACTIC_ORDER]

tech, stix2tid = {}, {}
for o in objs:
    if o["type"] == "attack-pattern" and live(o):
        tid, url = ext_id(o)
        if not tid: continue
        stix2tid[o["id"]] = tid
        tech[tid] = {"n": o["name"], "ta": [k["phase_name"] for k in o.get("kill_chain_phases", []) if k.get("kill_chain_name") == "mitre-attack"],
                     "pl": o.get("x_mitre_platforms", []), "d": clip(o.get("description"), 320),
                     "sub": bool(o.get("x_mitre_is_subtechnique")), "g": [], "s": [], "c": [], "m": [],
                     "det": [], "at": [], "ev": [], "rc": {}, "rt": 0, "ex": []}
# IDs revogados → substitutos (regras antigas citam técnicas que mudaram de número)
revoked = {}
for o in objs:
    if o["type"] == "relationship" and o["relationship_type"] == "revoked-by":
        s, t = byid.get(o["source_ref"]), byid.get(o["target_ref"])
        if s and t and s["type"] == "attack-pattern":
            a, b = ext_id(s)[0], ext_id(t)[0]
            if a and b: revoked[a] = b

# técnicas DESCONTINUADAS sem "revoked-by": a descrição oficial indica a substituta ("Please use [X](.../techniques/T1571)")
for o in objs:
    if o["type"] == "attack-pattern" and o.get("x_mitre_deprecated"):
        a = ext_id(o)[0]
        m = re.search(r"deprecated.*?techniques/(T\d{4})(?:/(\d{3}))?", o.get("description") or "", re.S | re.I)
        if a and m and a not in revoked:
            revoked[a] = m.group(1) + ("." + m.group(2) if m.group(2) else "")

def norm_tid(t):
    t = t.upper()
    seen = 0
    while t in revoked and seen < 5: t = revoked[t]; seen += 1
    return t

groups, gix = [], {}
software, six = [], {}
campaigns, cix = [], {}
mitig, mix = [], {}
for o in objs:
    if not live(o): continue
    xid, url = ext_id(o)
    if o["type"] == "intrusion-set":
        gix[o["id"]] = len(groups)
        groups.append({"id": xid, "n": o["name"], "al": [a for a in o.get("aliases", []) if a != o["name"]][:12], "d": clip(o.get("description"), 260), "t": [], "rep": []})
    elif o["type"] in ("malware", "tool"):
        six[o["id"]] = len(software)
        software.append({"id": xid, "n": o["name"], "k": o["type"], "t": []})
    elif o["type"] == "campaign":
        cix[o["id"]] = len(campaigns)
        campaigns.append({"id": xid, "n": o["name"], "al": o.get("aliases", [])[:6], "t": []})
    elif o["type"] == "course-of-action":
        mix[o["id"]] = len(mitig)
        mitig.append({"id": xid, "n": o["name"]})

# estratégias de detecção → analíticas → fontes de log
dc_name = {o["id"]: o["name"] for o in objs if o["type"] == "x-mitre-data-component"}
analytic = {o["id"]: o for o in objs if o["type"] == "x-mitre-analytic"}
strategy = {o["id"]: o for o in objs if o["type"] == "x-mitre-detection-strategy" and live(o)}

for o in objs:
    if o["type"] != "relationship" or not live(o): continue
    rt, s, t = o["relationship_type"], o["source_ref"], o["target_ref"]
    tid = stix2tid.get(t)
    if rt == "uses" and tid:
        if s in gix: tech[tid]["g"].append(gix[s]); groups[gix[s]]["t"].append(tid)
        elif s in six: tech[tid]["s"].append(six[s]); software[six[s]]["t"].append(tid)
        elif s in cix: tech[tid]["c"].append(cix[s]); campaigns[cix[s]]["t"].append(tid)
    elif rt == "mitigates" and tid and s in mix:
        tech[tid]["m"].append(mix[s])
    elif rt == "detects" and tid and s in strategy:
        st = strategy[s]; sid, surl = ext_id(st)
        ans = []
        for aref in st.get("x_mitre_analytic_refs", []):
            a = analytic.get(aref)
            if not a: continue
            logs = []
            for lr in a.get("x_mitre_log_source_references", []):
                logs.append({"dc": dc_name.get(lr.get("x_mitre_data_component_ref"), ""), "src": lr.get("name", ""), "ch": lr.get("channel", "")})
            ans.append({"pl": a.get("x_mitre_platforms", []), "d": clip(a.get("description"), 260), "logs": logs[:6]})
        tech[tid]["det"].append({"id": sid, "n": st.get("name", ""), "an": ans[:6]})
for t in tech.values():
    for k in ("g", "s", "c", "m"): t[k] = sorted(set(t[k]))
for g in groups: g["t"] = sorted(set(g["t"]))
for s in software: s["t"] = sorted(set(s["t"]))
for c in campaigns: c["t"] = sorted(set(c["t"]))

# ------------------------------------------------------------------ regras do catálogo
R = json.load(open(CAT, encoding="utf-8"))
unmapped = collections.Counter()
fmt_tac_edges = collections.Counter()
for r in R:
    seen = set()
    for raw_t in r.get("techniques") or []:
        t = norm_tid(raw_t)
        if t not in tech:
            unmapped[raw_t] += 1; continue
        if t in seen: continue
        seen.add(t)
        x = tech[t]
        x["rc"][r["format"]] = x["rc"].get(r["format"], 0) + 1
        x["rt"] += 1
        if len(x["ex"]) < 12:
            x["ex"].append({"u": slug(r["source"]) + "::" + r["id"], "t": r["title"][:110], "f": r["format"], "s": r["source"], "v": r.get("severity") or "", "k": r.get("ctype", "detection")})
        for ta in x["ta"]: fmt_tac_edges[(r["format"], ta)] += 1

# ------------------------------------------------------------------ Atomic Red Team (só metadados, sem comandos)
atomic_total = 0
adir = P("atomic", "atomics")
if os.path.isdir(adir):
    for d in sorted(os.listdir(adir)):
        f = os.path.join(adir, d, d + ".yaml")
        if not os.path.isfile(f): continue
        t = norm_tid(d)
        if t not in tech: continue
        txt = open(f, encoding="utf-8", errors="replace").read()
        for blk in re.split(r"^- name:", txt, flags=re.M)[1:]:
            name = blk.splitlines()[0].strip().strip('"\'')
            guid = (re.search(r"auto_generated_guid:\s*(\S+)", blk) or [None, ""])[1]
            plats = re.findall(r"^\s+-\s+(windows|linux|macos|office-365|azure-ad|google-workspace|saas|iaas[:\w-]*|containers|esxi)\s*$", blk.split("input_arguments:")[0].split("executor:")[0], re.M)
            ex = (re.search(r"executor:\s*\n\s+name:\s*(\S+)", blk) or [None, ""])[1]
            tech[t]["at"].append({"n": name[:120], "g": guid, "p": sorted(set(plats)), "e": ex})
            atomic_total += 1

# ------------------------------------------------------------------ amostras EVTX
EVTX_KEYWORDS = [  # palavra-chave no nome do arquivo → técnica (relação INFERIDA)
 (r"lsass|minidump|procdump|mimikatz_sekurlsa|sekurlsa", "T1003.001"), (r"dcsync", "T1003.006"), (r"ntds", "T1003.003"),
 (r"\bsam\b|sam_dump|hive", "T1003.002"), (r"kerberoast", "T1558.003"), (r"asrep", "T1558.004"), (r"golden", "T1558.001"),
 (r"silver", "T1558.002"), (r"pass.?the.?hash|\bpth\b", "T1550.002"), (r"pass.?the.?ticket|\bptt\b", "T1550.003"),
 (r"psexec", "T1569.002"), (r"wmi(?!c)|wmiexec", "T1047"), (r"wmic", "T1047"), (r"dcom|mmc20|shellwindows|shbrwnd", "T1021.003"),
 (r"winrm|wsmprovhost", "T1021.006"), (r"\brdp\b|tsclient|sharprdp", "T1021.001"), (r"smb|5145|admin\$", "T1021.002"),
 (r"schtask|scheduled.?task", "T1053.005"), (r"runkey|run_key|\brun\b.?persist", "T1547.001"), (r"service.?creat|7045|sc_create", "T1543.003"),
 (r"uac.?bypass|uacbypass|fodhelper|eventvwr|sdclt", "T1548.002"), (r"timestomp", "T1070.006"), (r"clear.?log|1102|wevtutil", "T1070.001"),
 (r"sideload", "T1574.001"), (r"hollow", "T1055.012"), (r"inject", "T1055"), (r"masquerad", "T1036"), (r"rundll32", "T1218.011"),
 (r"regsvr32|squiblydoo", "T1218.010"), (r"mshta", "T1218.005"), (r"certutil", "T1105"), (r"bitsadmin|bits", "T1197"),
 (r"powershell|psh|\bps1\b", "T1059.001"), (r"\bcmd\b", "T1059.003"), (r"vssadmin|shadow", "T1490"), (r"\bdpapi", "T1555.004"),
 (r"credman|vaultcmd", "T1555.004"), (r"browser|chrome|firefox", "T1555.003"), (r"kerberos.?deleg|unconstrained|rbcd", "T1558"),
 (r"spray", "T1110.003"), (r"brute", "T1110.001"), (r"\bdns\b.?exfil|exfil", "T1048"), (r"lateral", "T1021"),
 (r"token|impersonat|runas", "T1134"), (r"sysmon.?(stop|unload)|evasion.?sysmon", "T1562.001"), (r"defender.?(disabl|tamper)", "T1562.001"),
 (r"printspool|spoolss|printnightmare", "T1068"), (r"zerologon|netlogon", "T1210"), (r"petitpotam|efsrpc", "T1187"),
 (r"bloodhound|sharphound|ldap.?recon|adfind", "T1087.002"), (r"net.?user|net1", "T1087.001"), (r"keylog", "T1056.001"),
 (r"etw", "T1562.006"), (r"amsi", "T1562.001"), (r"skeleton", "T1556.001"), (r"sid.?history", "T1134.005"), (r"dcshadow", "T1207"),
]
ev_explicit = ev_inferred = 0
for path in ls_tree("evtx_mitre"):
    if not path.lower().endswith(".evtx"): continue
    m = re.search(r"/(T\d{4}(?:\.\d{3})?)", "/" + path)
    if not m: continue
    t = norm_tid(m.group(1))
    if t in tech:
        tech[t]["ev"].append({"n": os.path.basename(path)[:-5][:120], "r": "mdecrevoisier/EVTX-to-MITRE-Attack", "p": path, "c": "explícito"})
        ev_explicit += 1
for path in ls_tree("evtx_samples"):
    if not path.lower().endswith(".evtx"): continue
    name = os.path.basename(path)[:-5]; low = (path.lower()).replace("-", "_")
    hits = set()
    for rx, t in EVTX_KEYWORDS:
        if re.search(rx, low): hits.add(norm_tid(t))
    for t in hits:
        if t in tech:
            tech[t]["ev"].append({"n": name[:120], "r": "sbousseaden/EVTX-ATTACK-SAMPLES", "p": path, "c": "inferido"})
            ev_inferred += 1

# ------------------------------------------------------------------ relatórios APT ↔ grupos (nome da pasta)
def norm(s): return re.sub(r"[^a-z0-9]+", " ", s.lower()).strip()
STOP = {"apt", "group", "team", "the", "operation", "campaign", "spider", "panda", "bear", "kitten", "chollima", "tiger"}
alias_rx = []
for i, g in enumerate(groups):
    for a in [g["n"]] + g["al"]:
        na = norm(a)
        if len(na) < 4 or na in STOP: continue
        alias_rx.append((re.compile(r"(?:^| )" + re.escape(na) + r"(?: |$)"), i, a))
rep_total = rep_linked = 0
for path in ls_tree("apt_collections"):
    if not path.lower().endswith(".pdf"): continue
    rep_total += 1
    parts = path.split("/")
    if len(parts) < 3: continue
    folder = parts[1]; year = parts[0]
    nf = norm(folder.replace(".", " ") + " " + parts[-1][:-4])
    linked = set()
    for rx, i, a in alias_rx:
        if i in linked: continue
        if rx.search(nf):
            linked.add(i)
            if len(groups[i]["rep"]) < 25:
                groups[i]["rep"].append({"y": year, "t": parts[-1][:-4][:120], "f": folder[:90], "p": path, "via": a})
    if linked: rep_linked += 1

# ------------------------------------------------------------------ recursos da planilha
def parse_sheet(path):
    txt = open(path, encoding="utf-8", errors="replace").read()
    secs = re.split(r"^## Sheet name:\s*", txt, flags=re.M)[1:]
    out = {}
    for s in secs:
        title, _, body = s.partition("\n")
        rows = list(csv.reader(io.StringIO(body)))
        out[title.strip()] = [r for r in rows if any(c.strip() for c in r)]
    return out
CAT_MAP = {  # aba da planilha → (fase do trabalho, formatos de regra relacionados, táticas relacionadas)
 "APT Reference": ("Inteligência", ["yara", "sigma"], ["reconnaissance", "resource-development"]),
 "Books": ("Formação", [], []), "Classes": ("Formação", [], []), "CTF": ("Formação", [], []),
 "Malware Analysis Course": ("Formação", [], []), "YouTube Channel": ("Formação", [], []), "Twitter Handle": ("Formação", [], []),
 "Deobfuscation": ("Análise estática", ["yara"], ["stealth", "defense-impairment"]),
 "Disassembler": ("Análise estática", ["yara"], []), "Reverse Engineering": ("Análise estática", ["yara"], []),
 "PE Analysis": ("Análise estática", ["yara"], ["stealth"]), "Document Analysis": ("Análise estática", ["yara", "sigma"], ["initial-access", "execution"]),
 "Yara": ("Análise estática", ["yara"], []), "Scripts": ("Automação", ["yara", "playbook"], []),
 "Dymanic Analysis": ("Análise dinâmica", ["sigma", "elastic", "wazuh"], ["execution", "persistence", "privilege-escalation"]),
 "Offline SandBox": ("Análise dinâmica", ["yara", "sigma"], ["execution"]), "Online SandBox": ("Análise dinâmica", ["yara", "playbook"], ["execution", "command-and-control"]),
 "Network Monitor": ("Análise de rede", ["suricata"], ["command-and-control", "exfiltration"]),
 "Honey Pot": ("Engano (deception)", ["suricata", "wazuh"], ["reconnaissance", "initial-access"]),
 "Memory Acquisition": ("Forense", ["yara"], ["credential-access", "stealth"]), "Memroy Analysis": ("Forense", ["yara"], ["credential-access", "stealth"]),
 "File Carving": ("Forense", ["yara"], ["collection"]),
 "Threat Hunting": ("Hunting", ["sigma", "kql-md", "elastic", "splunk", "sentinel"], ["execution", "lateral-movement", "credential-access"]),
 "Threat Intelligence": ("Inteligência", ["suricata", "playbook"], ["command-and-control"]),
 "Malware Samples": ("Laboratório", ["yara"], []), "VMs": ("Laboratório", [], []), "Others": ("Apoio", [], []),
}
KNOWN_DEAD = ["badips.com", "hosts-file.net", "malwaredomainlist", "urlvir.com", "nothink.org", "sndbox.com", "panwdbl.appspot.com",
              "security-research.dyndns.org", "threatsourcing.com", "torstatus.blutmagie.de", "report.cs.rutgers.edu", "peerlyst.com",
              "code.google.com", "cybercrime-tracker.net", "tracker.h3x.eu", "vxvault.net", "virusbay.io", "tracker.virusshare.com"]
resources = []
sheet_path = os.path.join("sources", "malware-ir-tools-resources.txt")
if os.path.exists(sheet_path):
    for sec, rows in parse_sheet(sheet_path).items():
        if sec in ("Skill Set", "Contribution") or not rows: continue
        phase, fmts, tacs = CAT_MAP.get(sec, ("Apoio", [], []))
        header = [h.strip().lower() for h in rows[0]]
        for r in rows[1:]:
            link = next((c.strip() for c in r if c.strip().startswith("http")), "")
            name = r[0].strip()
            if not name or name.lower() in ("reference", "reference:", "name", "practical acticity", "videos", "tools", "courses", "blog post", "note") or (not link and len(r) < 2):
                continue
            desc = ""
            for key in ("description", "decription", "note", "comment", "dependency"):
                if key in header:
                    i = header.index(key)
                    if i < len(r) and r[i].strip() and not r[i].strip().startswith("http"): desc = r[i].strip(); break
            plat = ""
            for key in ("platform", "platfrom", "paltform"):
                if key in header:
                    i = header.index(key)
                    if i < len(r): plat = re.sub(r"\s+", ", ", r[i].strip()); break
            dead = any(d in link for d in KNOWN_DEAD)
            resources.append({"n": name[:90], "cat": sec.replace("Dymanic", "Dynamic").replace("Memroy", "Memory"), "ph": phase,
                              "l": link, "d": clip(desc, 260), "pl": plat[:60], "f": fmts, "ta": tacs, "dead": dead})

# Ferramentas citadas na planilha que também são SOFTWARE no ATT&CK (ex.: PsExec, Mimikatz) → ligação explícita
sw_by_name = {s["n"].lower(): i for i, s in enumerate(software)}
for res in resources:
    k = res["n"].lower().strip()
    if k in sw_by_name: res["sw"] = software[sw_by_name[k]]["id"]

# ------------------------------------------------------------------ saída
tech_out = {}
for t, x in tech.items():
    tech_out[t] = x
# agregados por técnica-pai (inclui subtécnicas)
for t, x in tech.items():
    if x["sub"]:
        p = t.split(".")[0]
        if p in tech_out:
            tech_out[p].setdefault("rsub", 0); tech_out[p]["rsub"] += x["rt"]

attack = {"version": version, "generated": datetime.date.today().isoformat(), "tactics": tac_list, "techniques": tech_out,
          "groups": groups, "software": software, "campaigns": campaigns, "mitigations": mitig,
          "stats": {"techniques": len(tech), "groups": len(groups), "software": len(software), "campaigns": len(campaigns),
                    "mitigations": len(mitig), "atomic_tests": atomic_total, "evtx_explicit": ev_explicit, "evtx_inferred": ev_inferred,
                    "apt_reports": rep_total, "apt_reports_linked": rep_linked, "rules_mapped": sum(1 for r in R if r.get("techniques")),
                    "unmapped_tech_ids": len(unmapped), "techniques_with_rules": sum(1 for x in tech.values() if x["rt"] > 0),
                    "fmt_tactic": [[f, t, n] for (f, t), n in fmt_tac_edges.items()]}}
json.dump(attack, open(f"{OUT}/attack.json", "w", encoding="utf-8"), ensure_ascii=False, separators=(",", ":"))
json.dump({"source": "Malware IR - Tools & Resources (Cyb3rUltron @ShilpeshTrivedi, Harsh Shah @harshsshah)", "items": resources},
          open(f"{OUT}/resources.json", "w", encoding="utf-8"), ensure_ascii=False, separators=(",", ":"))

# ---- graph.json / GraphML (técnica, tática, grupo, software, formato de regra, fase, recurso)
nodes, edges = {}, []
def N(i, label, kind, **kw): nodes[i] = dict(id=i, label=label, kind=kind, **kw)
for t in tac_list: N("tactic:" + t["short"], t["n"], "tactic", attack_id=t["id"])
for t, x in tech.items():
    N("tech:" + t, f"{t} {x['n']}", "technique", rules=x["rt"], atomic=len(x["at"]), evtx=len(x["ev"]), groups=len(x["g"]))
    for ta in x["ta"]: edges.append(("tech:" + t, "tactic:" + ta, "in_tactic"))
    if x["sub"]: edges.append(("tech:" + t, "tech:" + t.split(".")[0], "subtechnique_of"))
    for f, n in x["rc"].items(): edges.append(("format:" + f, "tech:" + t, "detects", n))
for g in groups:
    N("group:" + g["id"], g["n"], "group", reports=len(g["rep"]))
    for t in g["t"]: edges.append(("group:" + g["id"], "tech:" + t, "uses"))
for s in software:
    if len(s["t"]) >= 1: N("software:" + s["id"], s["n"], "software:" + s["k"])
    for t in s["t"]: edges.append(("software:" + s["id"], "tech:" + t, "uses"))
for f in sorted({r["format"] for r in R}): N("format:" + f, f, "rule_format", rules=sum(1 for r in R if r["format"] == f))
for i, res in enumerate(resources):
    rid = "resource:" + str(i); N(rid, res["n"], "resource", phase=res["ph"], url=res["l"])
    edges.append((rid, "phase:" + res["ph"], "in_phase"))
    for f in res["f"]: edges.append((rid, "format:" + f, "supports"))
    if res.get("sw"): edges.append((rid, "software:" + res["sw"], "same_as"))
for ph in sorted({r["ph"] for r in resources}): N("phase:" + ph, ph, "phase")
edges = [e for e in edges if e[0] in nodes and e[1] in nodes]
json.dump({"nodes": list(nodes.values()), "edges": [{"s": e[0], "t": e[1], "rel": e[2], **({"w": e[3]} if len(e) > 3 else {})} for e in edges]},
          open(f"{OUT}/graph.json", "w", encoding="utf-8"), ensure_ascii=False, separators=(",", ":"))
with open(f"{OUT}/graph.graphml", "w", encoding="utf-8") as g:
    g.write('<?xml version="1.0" encoding="UTF-8"?>\n<graphml xmlns="http://graphml.graphdrawing.org/xmlns">\n')
    g.write('<key id="label" for="node" attr.name="label" attr.type="string"/><key id="kind" for="node" attr.name="kind" attr.type="string"/>')
    g.write('<key id="rules" for="node" attr.name="rules" attr.type="int"/><key id="rel" for="edge" attr.name="rel" attr.type="string"/><key id="w" for="edge" attr.name="weight" attr.type="int"/>\n')
    g.write('<graph id="detectionrules" edgedefault="directed">\n')
    for n in nodes.values():
        g.write(f'<node id="{xesc(n["id"])}"><data key="label">{xesc(n["label"])}</data><data key="kind">{xesc(n["kind"])}</data>'
                + (f'<data key="rules">{n["rules"]}</data>' if "rules" in n else "") + "</node>\n")
    for i, e in enumerate(edges):
        g.write(f'<edge id="e{i}" source="{xesc(e[0])}" target="{xesc(e[1])}"><data key="rel">{e[2]}</data>' + (f'<data key="w">{e[3]}</data>' if len(e) > 3 else "") + "</edge>\n")
    g.write("</graph>\n</graphml>\n")

# ---- camada do ATT&CK Navigator
mx = max([x["rt"] for x in tech.values()] + [1])
layer = {"name": "Detection Rules — cobertura de regras públicas", "versions": {"attack": str(version).split(".")[0], "navigator": "5.1.0", "layer": "4.5"},
         "domain": "enterprise-attack", "description": f"Número de regras públicas (de {len(R):,} no catálogo) que citam cada técnica. Gerado em {datetime.date.today()}.",
         "gradient": {"colors": ["#f5ddcf", "#d4804f", "#7c2406"], "minValue": 0, "maxValue": min(mx, 200)},
         "techniques": [{"techniqueID": t, "score": x["rt"], "comment": ", ".join(f"{k}:{v}" for k, v in sorted(x["rc"].items(), key=lambda z: -z[1])) or "sem regra pública no catálogo",
                         "enabled": True, "showSubtechniques": False} for t, x in tech.items()],
         "legendItems": [{"label": "sem regra", "color": "#ffffff"}, {"label": "muitas regras", "color": "#7c2406"}]}
json.dump(layer, open(f"{OUT}/navigator-layer.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1)

s = attack["stats"]
print(f"ATT&CK v{version}: {s['techniques']} técnicas · {s['groups']} grupos · {s['software']} softwares · {s['campaigns']} campanhas · {s['mitigations']} mitigações")
print(f"técnicas com regra: {s['techniques_with_rules']} · regras mapeadas: {s['rules_mapped']:,} · IDs não reconhecidos: {s['unmapped_tech_ids']}")
print(f"Atomic: {atomic_total} testes · EVTX: {ev_explicit} explícitas + {ev_inferred} inferidas · relatórios APT: {rep_linked}/{rep_total} ligados a grupos")
print(f"recursos da planilha: {len(resources)} ({sum(r['dead'] for r in resources)} com domínio sabidamente desativado)")
print(f"grafo: {len(nodes)} nós · {len(edges)} arestas")
for f in os.listdir(OUT): print(f"  {f}: {os.path.getsize(os.path.join(OUT, f))/1e6:.2f} MB")
