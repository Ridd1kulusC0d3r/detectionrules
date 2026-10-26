#!/usr/bin/env python3
"""Contexto externo das bases do autor → data/graph/*.json. stdlib-only.

Uso:  python3 build_context.py [SRC] [CATALOG]
  SRC      pasta com ext/apt4all, ext/llminjection e ext/tcem (clonados por scripts/fetch_sources.sh)
  CATALOG  catalog.json completo (padrão: SRC/catalog.json); usado para casar ferramentas × regras

Gera:
  data/graph/actors.json      APT4ALL → por grupo ATT&CK: país, motivação, setores, vítimas, nomes por
                              fornecedor, operações, ferramentas, relatórios públicos (APTnotes)
  data/graph/ransomware.json  Ransomware Tool Matrix (via APT4ALL) × regras do catálogo que citam a ferramenta
  data/graph/tcem.json        TCEM: lentes de contexto, padrões de correlação, ponte de esquemas
                              (OCSF/ECS/ASIM/CIM) e cenários de referência com cobertura do catálogo
  data/graph/ai.json          LLmInjection: técnicas de IA (ATLAS/OWASP), especificações de detecção,
                              casos de teste, controles, atores, campanhas e incidentes

Atribuição é hipótese de quem a publicou: cada bloco guarda a fonte; nada aqui é confirmado por nós.
"""
import json, os, re, sys, glob, collections, datetime
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mini_yaml

SRC = sys.argv[1] if len(sys.argv) > 1 else "."
CAT = sys.argv[2] if len(sys.argv) > 2 else os.path.join(SRC, "catalog.json")
EXT = os.path.join(SRC, "ext")
OUT = "data/graph"
os.makedirs(OUT, exist_ok=True)
today = datetime.date.today().isoformat()
slug = lambda s: re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")
def jload(p, default=None):
    try: return json.load(open(p, encoding="utf-8"))
    except Exception as e:
        print("  (ausente)", p, type(e).__name__); return default
def dump(name, obj):
    p = f"{OUT}/{name}"; json.dump(obj, open(p, "w", encoding="utf-8"), ensure_ascii=False, separators=(",", ":"))
    print(f"  {p}  {os.path.getsize(p)/1e3:.0f} KB")

ATT = jload(f"{OUT}/attack.json", {})
GROUPS = ATT.get("groups", [])
GID = {g["id"]: i for i, g in enumerate(GROUPS)}
TECH = ATT.get("techniques", {})
REV = ATT.get("rev", {})
IDX = jload("data/index.json", {})

# ======================================================== APT4ALL — atores
A4 = os.path.join(EXT, "apt4all")
atl = jload(os.path.join(A4, "docs/atlas/atores.json"), {}) or {}
pais = jload(os.path.join(A4, "docs/atlas/paises.json"), {}) or {}
COUNTRY = {k: v.get("nome_pt") or k for k, v in (pais.get("paises") or {}).items()}
COUNTRY.update({"??": "Sem país atribuído", "NATO": "OTAN / Five Eyes"})
SECT = {k: v.get("pt", k) for k, v in (pais.get("setores") or {}).items()}
by_gid = {}; a4_by_id = {}
for a in atl.get("atores", []):
    a4_by_id[a["id"]] = a
    m = a.get("mitre") or {}
    g = m.get("id") if isinstance(m, dict) else None
    if not g or g in by_gid: continue
    rel = sorted(a.get("relatorios") or [], key=lambda r: (r.get("data") or "")[-4:] + (r.get("data") or ""), reverse=True)
    by_gid[g] = {
        "a4": a["id"], "pais": a.get("pais") or "??", "pais_n": COUNTRY.get(a.get("pais") or "??", a.get("pais")),
        "mot": a.get("motivos") or [], "set": [SECT.get(s, s) for s in (a.get("setores") or [])],
        "vit": (a.get("vitimas") or [])[:30], "vit_iso": a.get("vitimas_iso") or [],
        "alvos": (a.get("alvos") or "")[:400], "ops": (a.get("operacoes") or [])[:20],
        "ferr": (a.get("ferramentas") or [])[:40], "forn": a.get("fornecedores") or {},
        "al": (a.get("aliases") or [])[:60], "conf": a.get("confianca") or "",
        "fontes": a.get("fontes") or [], "rel": [{"t": r.get("titulo", "")[:160], "f": r.get("fonte", ""), "d": r.get("data", ""), "u": r.get("link", "")} for r in rel[:12]],
        "nrel": len(rel), "desc": (a.get("descricao") or "")[:600],
    }
countries = {}
for k, v in (pais.get("paises") or {}).items():
    countries[k] = {"n": v.get("nome_pt") or k, "atores": v.get("atores", 0), "attack": v.get("com_mitre", 0),
                    "rel": v.get("relatorios", 0), "mot": v.get("motivos", [])[:5], "tt": v.get("top_tecnicas", [])[:10],
                    "ts": v.get("top_setores", [])[:6]}
dump("actors.json", {"meta": {"gerado": today, "fonte": "APT4ALL (Ridd1kulusC0d3r/apt4all) — MISP Galaxy, APT Groups & Operations (F. Roth), EternalLiberty, APTnotes, ATT&CK",
                              "atlas": atl.get("meta", {}), "n_ligados": len(by_gid), "aviso": "Atribuição é afirmação de quem publicou, com confiança variável. Confira a fonte original antes de citar."},
                     "g": by_gid, "paises": countries})
print(f"apt4all: {len(by_gid)} grupos ATT&CK enriquecidos · {len(countries)} países")

# ======================================================== Ransomware Tool Matrix × catálogo
rw = jload(os.path.join(A4, "docs/atlas/ransomware.json"), {}) or {}
tools = rw.get("ferramentas", [])
SKIP = {"logger"}
variants = {}
for t in tools:
    n = t["nome"]; low = n.lower()
    if low in SKIP or len(low) < 3: continue
    low = low.replace("[.]", ".")
    vs = {low, low.replace(" ", ""), low.replace(" ", "-"), low.replace(" ", "_")}
    # "Windows Event Utility (wevtutil)" → wevtutil; "NirSoft Netpass" → netpass; "A/B driver (BYOVD)" → a, b
    for par in re.findall(r"\(([^)]+)\)", low):
        if par not in ("byovd",) and len(par) >= 4: vs.add(par.strip())
    core = re.sub(r"\s*\([^)]*\)", "", low).strip()
    core = re.sub(r"^nirsoft\s+", "", core); vs.add(core)
    for part in core.split("/"):
        part = re.sub(r"\s+driver$", "", part.strip())
        if len(part) >= 4: vs.add(part)
    if low == "cobalt strike": vs |= {"cobaltstrike", "beacon.dll"}
    if low == "psexec": vs |= {"psexesvc"}
    if low == "rclone": vs |= {"rclone.exe"}
    if low == "anydesk": vs |= {"anydesk.exe"}
    for v in vs: variants[v] = n
rx_tools = re.compile(r"(?<![a-z0-9])(" + "|".join(sorted((re.escape(v) for v in variants), key=len, reverse=True)) + r")(?![a-z0-9])") if variants else None
hits = collections.defaultdict(list); RANK = {"sigma": 5, "elastic": 4, "splunk": 4, "sentinel": 4, "yaral": 3, "wazuh": 3, "panther": 3, "falco": 3}
cat_rows = None
if rx_tools and os.path.exists(CAT):
    print("  casando", len(tools), "ferramentas com", CAT)
    for r in json.load(open(CAT, encoding="utf-8")):
        if r.get("ctype") == "playbook" or r.get("format") == "yara": continue
        txt = (r.get("title", "") + "\n" + (r.get("description") or "")[:600] + "\n" + (r.get("query") or r.get("raw") or "")[:6000]).lower()
        found = {variants[m] for m in rx_tools.findall(txt)}
        for n in found:
            sc = RANK.get(r["format"], 1) + (2 if (r.get("status") or "").lower() in ("stable", "production") else 0) + (1 if n.lower() in r.get("title", "").lower() else 0)
            hits[n].append((sc, {"u": slug(r["source"]) + "::" + r["id"], "t": r["title"][:110], "f": r["format"], "s": r["source"], "v": r.get("severity") or ""}))
elif rx_tools:
    print("  (sem catalog.json: usando títulos do índice)")
    cols = IDX.get("cols", []); ci = {c: i for i, c in enumerate(cols)}
    for row in IDX.get("rows", []):
        txt = (row[ci["title"]] + " " + row[ci["desc"]]).lower()
        for n in {variants[m] for m in rx_tools.findall(txt)}:
            hits[n].append((1, {"u": IDX["src_slug"][row[ci["src"]]] + "::" + row[ci["id"]], "t": row[ci["title"]][:110], "f": IDX["fmt"][row[ci["fmt"]]], "s": IDX["src"][row[ci["src"]]], "v": row[ci["sev"]]}))
tool_out = []
for t in tools:
    h = sorted(hits.get(t["nome"], []), key=lambda z: -z[0])
    tool_out.append({"n": t["nome"], "cat": t.get("cat"), "g": t.get("grupos", []), "r": len(h), "ex": [x[1] for x in h[:10]]})
gangs = []
for g in rw.get("grupos", []):
    a = a4_by_id.get(g.get("ator") or "")
    gid = ((a or {}).get("mitre") or {}).get("id") if a else None
    gangs.append({"n": g["nome"], "tipo": g.get("tipo"), "a4": g.get("ator"), "gid": gid, "t": g.get("ferramentas", [])})
dump("ransomware.json", {"meta": {**rw.get("meta", {}), "via": "APT4ALL", "gerado": today,
                                  "n_ferramentas_com_regra": sum(1 for t in tool_out if t["r"]),
                                  "metodo": "A ferramenta 'tem regra' quando o nome (ou variante) aparece no título, descrição ou lógica de uma regra do catálogo. É indício de cobertura, não prova: confira a regra."},
                         "cats": rw.get("categorias", []), "gangs": gangs, "tools": tool_out})
print(f"ransomware: {len(tool_out)} ferramentas, {sum(1 for t in tool_out if t['r'])} citadas por regras")

# ======================================================== TCEM
TC = os.path.join(EXT, "tcem")
def yl(p):
    try: return mini_yaml.load(p)
    except Exception as e:
        print("  (falha YAML)", p, e); return None
lenses = (yl(os.path.join(TC, "src/tce/data/threat-context-lenses.yaml")) or {}).get("lenses", [])
pats = (yl(os.path.join(TC, "src/tce/data/detection-correlation-patterns.yaml")) or {}).get("patterns", [])
schema = (yl(os.path.join(TC, "src/tce/data/telemetry-schema-map.yaml")) or {}).get("concepts", {})

# cobertura: nº de regras por técnica (inclui subtécnicas quando o cenário cita a técnica-mãe)
rt_count = collections.Counter()
if IDX:
    ci = {c: i for i, c in enumerate(IDX["cols"])}
    for row in IDX["rows"]:
        for t in set(row[ci["techniques"]] or []):
            t = REV.get(t, t); rt_count[t] += 1
            if "." in t: rt_count["~" + t.split(".")[0]] += 1
def cov(t):
    t = REV.get(t, t); return rt_count.get(t, 0) + (rt_count.get("~" + t, 0) if "." not in t else 0)

def case_from(d, name_hint):
    """Normaliza um caso TCEM (arquivo único case.yaml OU pasta com vários yaml)."""
    case = d.get("case") or {}
    scen = d.get("scenarios") or []
    tcs = {x["id"]: x for x in (d.get("telemetry_contracts") or [])}
    dsps = {x["id"]: x for x in (d.get("detection_specifications") or [])}
    cjs = d.get("crown_jewels") or []
    ctxs = d.get("threat_contexts") or []
    out = {"id": case.get("id") or name_hint, "n": case.get("name") or name_hint, "mission": case.get("mission", ""),
           "scope": case.get("scope", []), "cj": [{"n": c.get("name"), "r": c.get("rationale", ""), "crit": c.get("criticality", "")} for c in cjs],
           "lens": [c.get("lens_id") for c in ctxs if c.get("lens_id")], "scen": []}
    for s in scen:
        ap = s.get("attack_path") or {}
        steps = []
        for st in ap.get("steps") or []:
            techs = st.get("attack_techniques") or []
            steps.append({"o": st.get("order"), "b": st.get("behavior", ""), "t": techs,
                          "tn": [TECH.get(REV.get(t, t), {}).get("n", "") for t in techs],
                          "obs": st.get("expected_observable", ""), "rules": {t: cov(t) for t in techs}})
        tcl = [tcs[i] for i in (s.get("telemetry_requirements") or []) if i in tcs]
        dsl = [dsps[i] for i in (s.get("detection_specification_ids") or []) if i in dsps]
        pr = s.get("priority") or {}
        out["scen"].append({
            "id": s.get("id"), "t": s.get("title", ""), "obj": s.get("objective", ""), "entry": ap.get("entry_vector", ""),
            "steps": steps, "impact": s.get("impact") or {}, "conf": s.get("confidence", ""),
            "prio": {k: v for k, v in pr.items() if isinstance(v, (int, float)) and k != "calculated_score"},
            "design": s.get("defensive_design") or {},
            "tc": [{"t": c.get("title"), "src": c.get("source"), "req": c.get("required_fields", []), "av": c.get("available_fields", []),
                    "status": c.get("status"), "fm": c.get("failure_modes", []), "lat": c.get("latency_target"), "ret": c.get("retention")} for c in tcl],
            "dsp": [{"t": x.get("title"), "sev": x.get("severity"), "status": x.get("status"), "pat": (x.get("correlation") or {}).get("pattern_id"),
                     "win": (x.get("correlation") or {}).get("window"), "by": (x.get("correlation") or {}).get("group_by", []),
                     "benign": ((x.get("analytic_concept") or {}).get("benign_alternatives") or []),
                     "effect": (x.get("analytic_concept") or {}).get("observable_effect", "")} for x in dsl]})
    return out
cases = []
for p in sorted(glob.glob(os.path.join(TC, "examples/reference-cases/*/case.yaml"))):
    d = yl(p)
    if d: cases.append(case_from(d, os.path.basename(os.path.dirname(p))))
for dpath in sorted(glob.glob(os.path.join(TC, "examples/cases/*/"))):
    merged = {}
    for p in glob.glob(dpath + "*.yaml"):
        d = yl(p) or {}
        for k, v in d.items():
            if k == "version": continue
            if k == "case": merged["case"] = v
            elif isinstance(v, list): merged.setdefault(k, []).extend(v)
    if "crown_jewels" not in merged:
        cj = yl(dpath + "crown-jewels.yaml") or {}
        merged["crown_jewels"] = cj.get("crown_jewels", [])
    if merged: cases.insert(0, case_from(merged, os.path.basename(dpath.rstrip("/"))))
dump("tcem.json", {"meta": {"gerado": today, "fonte": "TCEM — Threat Context Engineering Method (Ridd1kulusC0d3r/Cyber-Threat-Context-Modeling)",
                            "principio": "Modele a ameaça antes do primeiro log: decida o que precisa ser observável e só então escreva a detecção.",
                            "limites": "prioridade ≠ confiança; pressão de previsão ≠ probabilidade de ataque."},
                   "lenses": [{"id": l["id"], "n": l.get("name"), "cls": l.get("class"), "d": l.get("description", ""), "arch": l.get("architecture_focus", []),
                               "tel": l.get("telemetry_focus", []), "sig": l.get("signals", [])} for l in lenses],
                   "patterns": [{"id": p["id"], "n": p.get("name"), "d": p.get("description"), "use": p.get("use_when")} for p in pats],
                   "schema": schema, "cases": cases})
print(f"tcem: {len(lenses)} lentes, {len(pats)} padrões, {len(schema)} conceitos de esquema, {len(cases)} casos")

# ======================================================== LLmInjection
LI = os.path.join(EXT, "llminjection", "data")
L = {k: jload(os.path.join(LI, f"{k}.json"), []) or [] for k in ("techniques", "detections", "test-cases", "controls", "actors", "campaigns", "incidents", "relationships")}
tl = jload(os.path.join(LI, "threat-landscape-2026.json"), {}) or {}
rel = collections.defaultdict(lambda: collections.defaultdict(list))
for r in L["relationships"]:
    rel[r.get("target")][r.get("relationship")].append(r.get("source"))
    rel[r.get("source")]["_" + (r.get("relationship") or "")].append(r.get("target"))
tech_ai = []
for t in L["techniques"]:
    tid = t["id"]
    tech_ai.append({"id": tid, "n": t.get("name"), "cat": t.get("category"), "d": t.get("summary", ""),
                    "map": [{"fw": m.get("framework"), "id": m.get("id"), "n": m.get("name"), "rel": m.get("relation"), "u": m.get("url")} for m in t.get("external_mappings", [])],
                    "det": rel[tid].get("detects", []), "inc": rel[tid].get("demonstrates", []), "camp": rel[tid].get("uses", []),
                    "tc": rel[tid].get("validates", []), "ctrl": rel[tid].get("_mitigated-by", [])})
dump("ai.json", {"meta": {"gerado": today, "fonte": "LLmInjection (Ridd1kulusC0d3r/LLmInjection) — Apache-2.0", "landscape": tl.get("meta", {})},
                 "tech": tech_ai,
                 "det": [{k: d.get(k) for k in ("id", "name", "category", "severity", "status", "hypothesis", "telemetry", "test_ids")} for d in L["detections"]],
                 "tc": [{k: d.get(k) for k in ("id", "name", "category", "risk", "mode", "goal", "expected", "telemetry")} for d in L["test-cases"]],
                 "ctrl": [{k: d.get(k) for k in ("id", "name", "category", "description")} for d in L["controls"]],
                 "actors": [{k: d.get(k) for k in ("id", "name", "aliases", "nexus", "ai_role", "confidence", "summary", "last_verified")} | {"src": [s.get("url") for s in d.get("sources", [])][:3]} for d in L["actors"]],
                 "camp": [{k: d.get(k) for k in ("id", "name", "confidence", "first_seen", "last_seen", "summary")} for d in L["campaigns"]],
                 "inc": [{k: d.get(k) for k in ("id", "name", "kind", "status", "confidence", "date", "summary")} for d in L["incidents"]],
                 "metrics": [{k: m.get(k) for k in ("name", "value", "unit", "timeframe", "confidence")} | {"src": (m.get("source") or {}).get("publisher")} for m in tl.get("key_metrics", [])],
                 "domains": [{k: d.get(k) for k in ("name", "trend", "confidence", "summary", "signals", "defensive_focus")} for d in tl.get("domains", [])]})
print(f"llminjection: {len(tech_ai)} técnicas, {len(L['detections'])} especificações, {len(L['test-cases'])} testes")
