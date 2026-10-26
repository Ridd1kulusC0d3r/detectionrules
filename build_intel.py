#!/usr/bin/env python3
"""build_intel.py — dossiês de inteligência e OSINT por grupo (stdlib-only).

Lê:  attack-stix (procedimentos, campanhas, bibliografia) + data/graph/attack.json (cobertura, Atomic, EVTX, relatórios)
Gera:
  data/graph/groups.json        perfil completo de cada grupo (carregado sob demanda pelo app)
  reports/groups/<ID>-<nome>.md dossiê por grupo, em pt-BR, pronto para compartilhar (TLP:CLEAR)
  reports/README.md             índice dos dossiês
  reports/groups.csv            planilha-resumo

Uso: python3 build_intel.py [DIR_FONTES]
"""
import json, os, re, sys, math, csv, datetime, collections, html as H
from intel_html import md_to_html, page
from urllib.parse import quote_plus

SRC = sys.argv[1] if len(sys.argv) > 1 else "."
SITE = "https://ridd1kulusc0d3r.github.io/detectionrules/"
REPO = "https://github.com/Ridd1kulusC0d3r/detectionrules"
TODAY = datetime.date.today().isoformat()
A = json.load(open("data/graph/attack.json", encoding="utf-8"))
B = json.load(open(os.path.join(SRC, "attack_stix", "enterprise-attack", "enterprise-attack.json"), encoding="utf-8"))
objs = B["objects"]; byid = {o["id"]: o for o in objs}
live = lambda o: not o.get("revoked") and not o.get("x_mitre_deprecated")
TECH = A["techniques"]; TAC = {t["short"]: t for t in A["tactics"]}; TAC_ORDER = [t["short"] for t in A["tactics"]]
NG = len(A["groups"])
def _j(p, d):
    try: return json.load(open(p, encoding="utf-8"))
    except Exception: return d
AX = _j("data/graph/actors.json", {"g": {}, "paises": {}})      # APT4ALL (build_context.py)
RW = _j("data/graph/ransomware.json", {"tools": [], "gangs": []})
IX = _j("data/index.json", {})
# regras por (tecnologia, técnica) — para "onde procurar" no dossiê
TT = collections.Counter(); TECHN = {}
if IX:
    ci = {c: i for i, c in enumerate(IX["cols"])}
    TECHN = {i: t["n"] for i, t in enumerate(IX.get("tech", []))}
    for row in IX["rows"]:
        for tid in set(A["rev"].get(x, x) for x in (row[ci["techniques"]] or [])):
            for k in row[ci["tech"]]: TT[(k, tid)] += 1
RW_TOOL = {t["n"]: t for t in RW.get("tools", [])}
RW_BY_GID = collections.defaultdict(list)
for g in RW.get("gangs", []):
    if g.get("gid"): RW_BY_GID[g["gid"]].append(g)

def ext(o):
    for r in o.get("external_references", []):
        if r.get("source_name") in ("mitre-attack",): return r.get("external_id")
def clean(s):
    s = re.sub(r"\(Citation:[^)]*\)", "", s or "")
    s = re.sub(r"\[([^\]]+)\]\(https?://attack\.mitre\.org[^)]*\)", r"\1", s)
    s = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r"\1 (\2)", s)
    s = re.sub(r"<[^>]+>", "", s)
    return re.sub(r"[ \t]+", " ", s).strip()
def cites(s): return re.findall(r"\(Citation: ([^)]+)\)", s or "")
def slug(s): return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")
def idf(t): return math.log((NG + 1) / (len(TECH[t]["g"]) + 1)) if t in TECH else 0

# ---------------------------------------------------------------- perfis
gstix = {ext(o): o for o in objs if o["type"] == "intrusion-set" and live(o)}
camp_by_group = collections.defaultdict(list)
for o in objs:
    if o["type"] == "relationship" and live(o) and o["relationship_type"] == "attributed-to":
        c, g = byid.get(o["source_ref"]), byid.get(o["target_ref"])
        if c and g and c["type"] == "campaign": camp_by_group[g["id"]].append(c)

rels_by_src = collections.defaultdict(list)
for o in objs:
    if o["type"] == "relationship" and live(o) and o["relationship_type"] == "uses":
        rels_by_src[o["source_ref"]].append(o)
norm = lambda t: A["rev"].get(t, t)

profiles = {}
for g in A["groups"]:
    so = gstix.get(g["id"])
    if not so: continue
    refs = {}
    def addref(r):
        if r.get("source_name") in ("mitre-attack",) or not r.get("url"): return
        refs.setdefault(r["source_name"], {"n": r["source_name"], "d": clean(r.get("description", ""))[:220], "u": r["url"]})
    for r in so.get("external_references", []): addref(r)
    procs = collections.defaultdict(list); swp = collections.defaultdict(list)
    for rel in rels_by_src[so["id"]]:
        tgt = byid.get(rel["target_ref"])
        if not tgt or not live(tgt): continue
        for r in rel.get("external_references", []): addref(r)
        if tgt["type"] == "attack-pattern":
            t = norm(ext(tgt) or "")
            if t in TECH: procs[t].append({"p": clean(rel.get("description", ""))[:600], "c": cites(rel.get("description", ""))[:3]})
        elif tgt["type"] in ("malware", "tool"):
            swp[ext(tgt)].append(clean(rel.get("description", ""))[:300])
    sw = []
    for i in g.get("sw", []):
        s = A["software"][i]
        sw.append({"id": s["id"], "n": s["n"], "k": s["k"], "t": len(s["t"]), "p": (swp.get(s["id"]) or [""])[0]})
    camps = []
    for c in camp_by_group.get(so["id"], []):
        if not live(c): continue
        camps.append({"id": ext(c), "n": c["name"], "f": (c.get("first_seen") or "")[:7], "l": (c.get("last_seen") or "")[:7], "d": clean(c.get("description"))[:300]})
    camps.sort(key=lambda c: c["f"] or "")
    tech = []
    for t in sorted(set(g["t"]) | set(procs)):
        if t not in TECH: continue
        x = TECH[t]
        tech.append({"id": t, "n": x["n"], "ta": x["ta"], "pr": procs.get(t, [])[:3], "rt": x["rt"], "at": len(x["at"]), "ev": len(x["ev"]), "idf": round(idf(t), 3)})
    years = sorted({m.group(1) for r in refs.values() for m in [re.search(r"\b(19[89]\d|20[0-3]\d)\b", r["d"])] if m})
    profiles[g["id"]] = {"id": g["id"], "n": g["n"], "al": [a for a in so.get("aliases", []) if a != g["n"]],
        "d": clean(so.get("description")), "cr": so.get("created", "")[:10], "md": so.get("modified", "")[:10],
        "contrib": so.get("x_mitre_contributors", []), "dom": so.get("x_mitre_domains", []),
        "tech": tech, "sw": sorted(sw, key=lambda s: -s["t"]), "camp": camps, "refs": sorted(refs.values(), key=lambda r: r["n"].lower()),
        "rep": g["rep"], "yrs": [years[0], years[-1]] if years else [], "ctx": AX["g"].get(g["id"], {}),
        "rw": sorted([{"n": t, "cat": RW_TOOL.get(t, {}).get("cat", ""), "r": RW_TOOL.get(t, {}).get("r", 0)} for t in {t for g_ in RW_BY_GID.get(g["id"], []) for t in g_["t"]}], key=lambda z: -z["r"]),
        "rwg": [g_["n"] for g_ in RW_BY_GID.get(g["id"], [])]}
json.dump(profiles, open("data/graph/groups.json", "w", encoding="utf-8"), ensure_ascii=False, separators=(",", ":"))
story = {}
users = collections.defaultdict(list)
for gid_, p_ in profiles.items():
    for t in p_["tech"]:
        if t["pr"]: users[t["id"]].append((len(p_["tech"]), gid_, p_["n"], t["pr"][0]["p"]))
TIDX = {s_: i for i, s_ in enumerate(TAC_ORDER)}
for tid, us in users.items():
    us.sort(key=lambda z: -z[0])
    first = min((TIDX.get(s_, 99) for s_ in TECH[tid]["ta"]), default=99)
    nxt = collections.Counter()
    for _, gid_, _, _ in us:
        for t in profiles[gid_]["tech"]:
            if t["id"] != tid and min((TIDX.get(s_, 99) for s_ in t["ta"]), default=99) == first + 1: nxt[t["id"]] += 1
    story[tid] = {"u": [{"g": g_, "n": n_, "c": AX["g"].get(g_, {}).get("pais", ""), "cn": AX["g"].get(g_, {}).get("pais_n", ""), "p": pr_[:280]} for _, g_, n_, pr_ in us[:4]],
                  "nu": len(TECH[tid]["g"]), "nx": [[t, TECH[t]["n"], c] for t, c in nxt.most_common(3)]}
json.dump(story, open("data/graph/story.json", "w", encoding="utf-8"), ensure_ascii=False, separators=(",", ":"))

# ---------------------------------------------------------------- dossiês Markdown
os.makedirs("reports/groups", exist_ok=True)
for f in os.listdir("reports/groups"):
    if f.endswith((".md", ".html")): os.remove(os.path.join("reports/groups", f))
FMT = {"sigma": "Sigma", "elastic": "Elastic", "splunk": "Splunk", "sentinel": "Sentinel KQL", "yaral": "YARA-L", "wazuh": "Wazuh", "falco": "Falco",
       "yara": "YARA", "panther": "Panther", "kql-md": "KQL hunting", "suricata": "Suricata/Snort", "aql": "QRadar AQL", "gcp": "GCP", "playbook": "Playbook"}
md_cell = lambda s: (s or "").replace("|", "\\|").replace("\n", " ")
def fname(p): return f"{p['id']}-{slug(p['n'])}.md"

index = []
for gid, p in sorted(profiles.items(), key=lambda kv: -len(kv[1]["tech"])):
    tech = p["tech"]; n = len(tech)
    cov = [t for t in tech if t["rt"] > 0]; gaps = [t for t in tech if t["rt"] == 0]
    pct = round(len(cov) / n * 100) if n else 0
    tac_count = collections.Counter(ta for t in tech for ta in t["ta"])
    top_tac = [TAC[s]["n"] for s, _ in tac_count.most_common(3) if s in TAC]
    sig = sorted(tech, key=lambda t: -t["idf"])[:10]
    malware = [s for s in p["sw"] if s["k"] == "malware"]; tools = [s for s in p["sw"] if s["k"] == "tool"]
    names = [p["n"]] + p["al"]
    cx = p.get("ctx") or {}
    gangs = RW_BY_GID.get(gid, [])
    ttools = sorted({t for g_ in gangs for t in g_["t"]})
    where = collections.Counter()
    for t in tech:
        for k in TECHN:
            if TT.get((k, t["id"])): where[k] += 1
    L = []
    L += [f"# {p['n']} ({gid}) — Dossiê de inteligência", "",
          f"> **TLP:CLEAR** · gerado em {TODAY} a partir de fontes abertas · MITRE ATT&CK v{A['version']} · [abrir no site]({SITE}#group={gid}) · [ATT&CK](https://attack.mitre.org/groups/{gid}/)", "",
          f"**Também conhecido como:** {', '.join(p['al']) or '—'}  ",
          *( [f"**Origem atribuída:** {cx.get('pais_n') or '—'} · **Motivação:** {', '.join(cx.get('mot') or []) or '—'} · **Setores-alvo:** {', '.join(cx.get('set') or []) or '—'}  "] if cx else [] ),
          f"**Registro no ATT&CK:** criado em {p['cr']}, atualizado em {p['md']}" + (f" · referências de {p['yrs'][0]} a {p['yrs'][1]}" if p['yrs'] else ""), ""]
    L += ["## 1. Sumário executivo", "",
          f"- **{n} técnicas** atribuídas publicamente, concentradas em **{', '.join(top_tac) or '—'}**.",
          f"- **Arsenal:** {len(malware)} malware e {len(tools)} ferramentas" + (f" (ex.: {', '.join(s['n'] for s in p['sw'][:5])})." if p['sw'] else "."),
          f"- **Campanhas atribuídas:** {len(p['camp'])}" + (f" ({', '.join(c['n'] for c in p['camp'][:3])})." if p['camp'] else "."),
          f"- **Cobertura de detecção pública:** {pct}% das técnicas têm ao menos uma regra no catálogo; **{len(gaps)} técnicas sem nenhuma regra pública**.",
          *( [f"- **Origem e alvos (APT4ALL):** atribuído a **{cx.get('pais_n')}**" + (f", motivação {', '.join(cx['mot'])}" if cx.get('mot') else "") + (f"; setores {', '.join(cx['set'][:5])}" if cx.get('set') else "") + (f"; {len(cx.get('vit_iso') or [])} países vítimas citados" if cx.get('vit_iso') else "") + "."] if cx.get("pais_n") else [] ),
          *( [f"- **Onde a cobertura está:** " + ", ".join(f"{TECHN[k]} ({v} técnicas com regra)" for k, v in where.most_common(4)) + "."] if where else [] ),
          f"- **Assinatura comportamental** (técnicas raras entre os {NG} grupos, as mais úteis para atribuição): " + ", ".join(f"{t['id']} {t['n']}" for t in sig[:5]) + ".", ""]
    L += ["## 2. Quem é", "", "> " + p["d"].replace("\n", "\n> "), "", "_Texto original do MITRE ATT&CK, em inglês._", ""]
    L += ["## 3. Contexto, nomes e alvos", ""]
    if cx:
        L += [f"Consolidado pelo [APT4ALL](https://github.com/Ridd1kulusC0d3r/apt4all) a partir de MISP Galaxy, planilha APT Groups & Operations, EternalLiberty e APTnotes. Atribuição é afirmação de quem publicou; confira a fonte.", "",
              "| Campo | Valor |", "|---|---|",
              f"| Origem atribuída | {md_cell(cx.get('pais_n') or '—')} |",
              f"| Motivação | {md_cell(', '.join(cx.get('mot') or []) or '—')} |",
              f"| Setores-alvo | {md_cell(', '.join(cx.get('set') or []) or '—')} |",
              f"| Vítimas citadas | {md_cell(', '.join(cx.get('vit') or [])[:600] or '—')} |",
              f"| Alvos (planilha) | {md_cell(cx.get('alvos') or '—')} |",
              f"| Operações conhecidas | {md_cell(', '.join(cx.get('ops') or []) or '—')} |",
              f"| Confiança de atribuição (MISP) | {md_cell(str(cx.get('conf') or '—'))} |", ""]
        if cx.get("forn"):
            L += ["**Como cada fornecedor chama este grupo** (útil para cruzar relatórios):", "", "| Fornecedor | Nome(s) |", "|---|---|"]
            for v, ns in sorted(cx["forn"].items()): L.append(f"| {md_cell(v)} | {md_cell(', '.join(ns))} |")
            L.append("")
        if len(cx.get("al") or []) > len(p["al"]):
            extra_al = [a for a in cx["al"] if a not in p["al"] and a != p["n"]]
            if extra_al: L += [f"**Outros nomes no APT4ALL (não listados pelo ATT&CK):** {', '.join(extra_al[:40])}", ""]
    else:
        L += ["Este grupo ainda não tem registro consolidado no APT4ALL (país, setores e nomes por fornecedor).", ""]
    L += ["## 4. Perfil TTP por tática (kill chain)", "", "Cada linha: técnica, como o grupo a usou segundo relatos públicos, e o que existe para detectar e testar.", ""]
    for s in TAC_ORDER:
        rows = [t for t in tech if s in t["ta"]]
        if not rows: continue
        L += [f"### {TAC[s]['n']} ({TAC[s]['id']}) — {len(rows)}", "", "| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |", "|---|---|---:|---:|---:|"]
        for t in sorted(rows, key=lambda t: t["id"]):
            pr = t["pr"][0]["p"] if t["pr"] else "—"
            L.append(f"| [{t['id']}]({SITE}#tech={t['id']}) {md_cell(t['n'])} | {md_cell(pr[:260] + ('…' if len(pr) > 260 else ''))} | {t['rt'] or '**0**'} | {t['at'] or '—'} | {t['ev'] or '—'} |")
        L.append("")
    L += ["## 5. Assinatura comportamental", "", f"Técnicas que este grupo usa e que poucos dos {NG} grupos do ATT&CK usam. Pesam mais numa atribuição por TTP: ver várias delas juntas é mais informativo do que ver técnicas comuns como PowerShell.", "",
          "| Técnica | Outros grupos que usam | Peso (raridade) |", "|---|---:|---:|"]
    for t in sig: L.append(f"| {t['id']} {md_cell(t['n'])} | {len(TECH[t['id']]['g']) - 1} | {t['idf']:.2f} |")
    L.append("")
    L += ["## 6. Arsenal", ""]
    if p["sw"]:
        L += ["| Software | Tipo | Técnicas no ATT&CK | Uso relatado (EN) |", "|---|---|---:|---|"]
        for s in p["sw"]: L.append(f"| [{md_cell(s['n'])}](https://attack.mitre.org/software/{s['id']}/) | {'malware' if s['k']=='malware' else 'ferramenta'} | {s['t']} | {md_cell(s['p'][:180])} |")
    else: L.append("Nenhum software atribuído no ATT&CK.")
    L.append("")
    if cx.get("ferr"):
        extra_f = [f_ for f_ in cx["ferr"] if f_.lower() not in {s_["n"].lower() for s_ in p["sw"]}]
        if extra_f: L += [f"**Outras ferramentas e malware relatados (planilha APT Groups & Operations / MISP):** {', '.join(extra_f[:40])}", ""]
    if ttools:
        L += [f"### Ferramentas observadas em intrusões ({', '.join(g_['n'] for g_ in gangs)}) — Ransomware Tool Matrix", "",
              "Ferramentas legítimas e ofensivas que afiliados usam dentro da rede. Cada uma é um ponto de detecção: veja quantas regras do catálogo a citam.", "",
              "| Ferramenta | Categoria | Regras que citam |", "|---|---|---:|"]
        for t_ in sorted(ttools, key=lambda t_: -(RW_TOOL.get(t_, {}).get("r", 0))):
            rt_ = RW_TOOL.get(t_, {}); L.append(f"| {md_cell(t_)} | {rt_.get('cat', '')} | {rt_.get('r', 0) or '**0**'} |")
        L.append("")
    L += ["## 7. Campanhas", ""]
    if p["camp"]:
        L += ["| Campanha | Período | Resumo (EN) |", "|---|---|---|"]
        for c in p["camp"]: L.append(f"| [{md_cell(c['n'])}](https://attack.mitre.org/campaigns/{c['id']}/) | {c['f'] or '?'} → {c['l'] or '?'} | {md_cell(c['d'][:220])} |")
    else: L.append("Nenhuma campanha atribuída no ATT&CK.")
    L.append("")
    L += ["## 8. Cobertura defensiva", "", f"**{len(cov)} de {n} técnicas ({pct}%)** têm ao menos uma regra pública no catálogo Detection Rules.", ""]
    if gaps:
        L += ["### Técnicas sem regra pública (prioridade para engenharia de detecção)", ""]
        for t in sorted(gaps, key=lambda t: -t["idf"]):
            src = "; ".join(f"`{l['src']}` {l['ch']}".strip() for d in TECH[t["id"]]["det"] for a in d["an"] for l in a["logs"][:1])[:200]
            L.append(f"- **{t['id']} {t['n']}** — {TAC[t['ta'][0]]['n'] if t['ta'] and t['ta'][0] in TAC else ''}" + (f". Fonte de log sugerida pelo MITRE: {src}" if src else ""))
        L.append("")
    if where:
        L += ["### Onde procurar — cobertura por tecnologia", "", "Quantas técnicas deste grupo têm ao menos uma regra em cada tecnologia. Comece a caça pelas tecnologias que você tem e que aparecem aqui.", "",
              "| Tecnologia | Técnicas do grupo com regra |", "|---|---:|"]
        for k, v in where.most_common(12): L.append(f"| {md_cell(TECHN[k])} | {v} |")
        L.append("")
    L += ["### Regras recomendadas por técnica", "", "Melhor regra disponível por técnica (formato portável e maduro primeiro).", "", "| Técnica | Regra | Formato | Fonte |", "|---|---|---|---|"]
    for t in sorted(cov, key=lambda t: t["id"]):
        for e in TECH[t["id"]]["ex"][:2]:
            L.append(f"| {t['id']} | [{md_cell(e['t'])}]({SITE}#rule={quote_plus(e['u'])}) | {FMT.get(e['f'], e['f'])} | {md_cell(e['s'])} |")
    L.append("")
    L += ["## 9. Plano de emulação e validação", "", "Use num laboratório isolado e autorizado para confirmar que as regras disparam. Os comandos estão nos repositórios oficiais.", ""]
    emu = [(t, TECH[t["id"]]["at"]) for t in tech if TECH[t["id"]]["at"]]
    if emu:
        L += ["| Tática | Técnica | Teste Atomic Red Team | Plataformas |", "|---|---|---|---|"]
        for t, ats in sorted(emu, key=lambda z: TAC_ORDER.index(z[0]["ta"][0]) if z[0]["ta"] and z[0]["ta"][0] in TAC_ORDER else 99):
            for a in ats[:2]:
                L.append(f"| {TAC[t['ta'][0]]['n'] if t['ta'] and t['ta'][0] in TAC else ''} | [{t['id']}](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/{t['id']}/{t['id']}.md) | {md_cell(a['n'])} | {', '.join(a['p'])} |")
    ev = [(t, e) for t in tech for e in TECH[t["id"]]["ev"][:2]]
    if ev:
        L += ["", "**Logs reais de ataque (EVTX) para testar sem executar nada:**", ""]
        for t, e in ev[:25]:
            base = "https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/" if "mdecrevoisier" in e["r"] else "https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/"
            L.append(f"- {t['id']} — [{e['n']}]({base}{quote_plus(e['p']).replace('+','%20').replace('%2F','/')}) _({e['c']})_")
    L.append("")
    L += ["## 10. Hipóteses de hunting", "", f"Se {p['n']} estiver no seu ambiente, estas são as perguntas a fazer aos seus dados (fontes de log segundo as estratégias de detecção do MITRE ATT&CK).", ""]
    k = 0
    for t in sorted(tech, key=lambda t: -t["idf"]):
        det = TECH[t["id"]]["det"]
        if not det: continue
        an = next((a for d in det for a in d["an"] if a["logs"]), None)
        if not an: continue
        logs = ", ".join(f"`{l['src']}`" + (f" ({l['ch']})" if l["ch"] else "") for l in an["logs"][:3])
        L.append(f"{k+1}. **{t['id']} {t['n']}** — {an['d']} Dados: {logs}.")
        k += 1
        if k >= 12: break
    L.append("")
    q = " OR ".join(f'"{a}"' for a in names[:6])
    L += ["## 11. OSINT — onde pesquisar", "", "Consultas prontas com todos os nomes conhecidos do grupo:", "",
          f"- Relatórios técnicos: [busca web]({'https://duckduckgo.com/?q=' + quote_plus('(' + q + ') threat report')}) · [PDFs]({'https://duckduckgo.com/?q=' + quote_plus('(' + q + ') filetype:pdf')})",
          f"- Regras e IOCs publicados: [GitHub]({'https://github.com/search?type=code&q=' + quote_plus(q)})",
          f"- Pulsos de ameaça: [AlienVault OTX](https://otx.alienvault.com/browse/global/pulses?q={quote_plus(p['n'])})",
          f"- Família de malware e atores: [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/actors) (busque por {', '.join(names[:3])})",
          f"- Cartões de grupo: [ThaiCERT Threat Group Cards](https://apt.etda.or.th/cgi-bin/listgroups.cgi)",
          f"- Página oficial: [MITRE ATT&CK {gid}](https://attack.mitre.org/groups/{gid}/)", ""]
    if p["rep"]:
        L += ["**Relatórios na coleção CyberMonitor** (ligados pelo nome do grupo, conferir antes de citar):", ""]
        for r in p["rep"]:
            L.append(f"- {r['y']} — [{r['t']}](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/{quote_plus(r['p']).replace('+','%20').replace('%2F','/')}) _(via “{r['via']}”)_")
        L.append("")
    if cx.get("rel"):
        L += [f"**Relatórios públicos ligados pelo APT4ALL** ({cx.get('nrel', len(cx['rel']))} no total, mais recentes primeiro):", ""]
        for r in cx["rel"]: L.append(f"- {r['d'][-4:] if r['d'] else '?'} — [{md_cell(r['t'])}]({r['u']}) _({md_cell(r['f'])})_")
        L.append("")
    L += [f"## 12. Bibliografia ({len(p['refs'])} fontes citadas pelo ATT&CK)", ""]
    for r in p["refs"]: L.append(f"- [{r['n']}]({r['u']}) — {r['d']}")
    L += ["", "## 13. Limites e confiança", "",
          "- O ATT&CK registra o que foi **relatado publicamente**, não tudo o que o grupo faz. Ausência de uma técnica não prova que o grupo não a usa.",
          "- **Sobreposição de TTP não é atribuição.** Muitas técnicas são compartilhadas entre grupos e com red teams. Use a assinatura comportamental como hipótese, junto com infraestrutura, malware e contexto.",
          "- Cobertura de detecção refere-se ao catálogo público Detection Rules, não ao seu ambiente: confira se a telemetria necessária chega ao seu SIEM.",
          "- Ligações marcadas como _inferidas_ (EVTX por palavra-chave, relatórios por nome) devem ser verificadas.",
          "", "---", f"Fontes: MITRE ATT&CK® (uso livre com atribuição, © The MITRE Corporation), APT4ALL (MISP Galaxy CC0/BSD-2, APT Groups & Operations CC BY 4.0, EternalLiberty, APTnotes, Ransomware Tool Matrix CC BY 4.0), Atomic Red Team (Red Canary, MIT), EVTX-to-MITRE-Attack, EVTX-ATTACK-SAMPLES, APT & CyberCriminal Campaign Collections. Gerado por [Detection Rules]({REPO})."]
    open(os.path.join("reports/groups", fname(p)), "w", encoding="utf-8").write("\n".join(L) + "\n")
    # ---- versão HTML do dossiê
    body, toc = md_to_html("\n".join(L))
    tc = collections.OrderedDict((s_, [0, 0]) for s_ in TAC_ORDER)
    for t in tech:
        for s_ in t["ta"]:
            if s_ in tc: tc[s_][0 if t["rt"] else 1] += 1
    mx = max([a + b for a, b in tc.values()] + [1])
    bars = "".join(f'<div class="br"><span>{H.escape(TAC[s_]["n"])}</span><span class="t"><i style="width:{a/mx*100:.1f}%"></i><i style="width:{b/mx*100:.1f}%"></i></span><b>{a}/{a+b}</b></div>' for s_, (a, b) in tc.items() if a + b)
    strip = (f'<div class="strip"><div><b>{n}</b><span>técnicas</span></div><div><b>{pct}%</b><span>com regra pública</span></div><div><b>{len(gaps)}</b><span>sem regra</span></div>'
             f'<div><b>{len(p["sw"])}</b><span>softwares</span></div><div><b>{len(p["camp"])}</b><span>campanhas</span></div><div><b>{len(p["refs"]) + len(p["rep"])}</b><span>fontes</span></div></div>')
    extra = (strip + '<h3>Cobertura de detecção pública por tática</h3><div class="bars">' + bars + '</div><p style="font-size:13px;color:var(--ink-3)">Barra escura = técnicas com regra pública · clara = sem regra.</p>'
             + '<nav class="toc" aria-label="Sumário">' + "".join(f'<a href="#{k}">{H.escape(t)}</a>' for k, t in toc) + '</nav>')
    body = body.replace("<h2", extra + "<h2", 1)
    tools = f'<a class="btn" href="{fname(p)}" download>Markdown</a><a class="btn" href="{SITE}#group={gid}">Abrir no site</a>'
    open(os.path.join("reports/groups", fname(p)[:-3] + ".html"), "w", encoding="utf-8").write(
        page(f"{p['n']} ({gid}) · Dossiê de inteligência", body, desc=f"Dossiê de inteligência de fontes abertas sobre {p['n']}: TTP, arsenal, cobertura de detecção, emulação, hunting e OSINT.", nav_back="../index.html", site=SITE, extra_tools=tools))
    index.append({"id": gid, "n": p["n"], "al": ", ".join(p["al"][:4]), "t": n, "pct": pct, "gaps": len(gaps), "sw": len(p["sw"]), "camp": len(p["camp"]), "rep": len(p["rep"]), "refs": len(p["refs"]), "f": fname(p)})

R = ["# Dossiês de inteligência — grupos de ameaça", "",
     f"{len(index)} dossiês gerados em {TODAY} a partir do MITRE ATT&CK v{A['version']} e do catálogo [Detection Rules]({REPO}). Cada dossiê traz perfil TTP com procedimentos, arsenal, campanhas, cobertura de detecção pública, plano de emulação, hipóteses de hunting, OSINT e bibliografia.", "",
     "**TLP:CLEAR** — material de fontes abertas, livre para compartilhar com atribuição.", "",
     "| Grupo | Também conhecido como | Técnicas | Cobertura pública | Sem regra | Software | Campanhas | Relatórios | Fontes |", "|---|---|---:|---:|---:|---:|---:|---:|---:|"]
for i in index:
    R.append(f"| [{i['n']}](groups/{i['f']}) `{i['id']}` | {md_cell(i['al'])} | {i['t']} | {i['pct']}% | {i['gaps']} | {i['sw']} | {i['camp']} | {i['rep']} | {i['refs']} |")
R.insert(4, f"**Versão HTML:** [índice navegável](index.html) — no site: {SITE}reports/index.html")
R.insert(5, "")
open("reports/README.md", "w", encoding="utf-8").write("\n".join(R) + "\n")
# ---- índice HTML pesquisável
tot_t = sum(i["t"] for i in index); avg = round(sum(i["pct"] for i in index) / max(1, len(index)))
rows = "".join(
    f'<tr data-q="{H.escape((i["n"] + " " + i["id"] + " " + " ".join(profiles[i["id"]]["al"])).lower())}">'
    f'<td><a href="groups/{i["f"][:-3]}.html"><strong>{H.escape(i["n"])}</strong></a> <code>{i["id"]}</code><span class="al">{H.escape(i["al"])}</span></td>'
    f'<td class="num">{i["t"]}</td><td class="num"><span class="pbar"><i style="width:{i["pct"]}%"></i></span>{i["pct"]}%</td><td class="num">{i["gaps"]}</td>'
    f'<td class="num">{i["sw"]}</td><td class="num">{i["camp"]}</td><td class="num">{i["rep"]}</td><td class="num">{i["refs"]}</td></tr>' for i in index)
ibody = f"""<p style="font:600 11px var(--mono);letter-spacing:.14em;text-transform:uppercase;color:var(--signal);margin:0">Detection Rules · inteligência de fontes abertas</p>
<h1>Dossiês de inteligência sobre grupos de ameaça</h1>
<p class="meta"><span class="tlp">TLP:CLEAR</span>{len(index)} dossiês gerados em {TODAY} a partir do MITRE ATT&amp;CK v{A['version']} e do catálogo Detection Rules. Cada um traz perfil TTP com procedimentos, assinatura comportamental, arsenal, campanhas, cobertura de detecção pública, plano de emulação, hipóteses de hunting, OSINT e bibliografia.</p>
<div class="strip"><div><b>{len(index)}</b><span>grupos</span></div><div><b>{tot_t:,}</b><span>vínculos grupo-técnica</span></div><div><b>{avg}%</b><span>cobertura média</span></div><div><b>{sum(i['refs'] for i in index):,}</b><span>referências</span></div><div><b>{sum(i['rep'] for i in index)}</b><span>relatórios ligados</span></div></div>
<input class="q" id="q" type="search" placeholder="Filtrar por grupo ou nome alternativo: APT28, Fancy Bear, Lazarus, Turla…" aria-label="Filtrar grupos">
<p id="cnt" style="font:12px var(--mono);color:var(--ink-3)"></p>
<div class="tw"><table><thead><tr><th>Grupo</th><th class="num">Técnicas</th><th class="num">Cobertura</th><th class="num">Sem regra</th><th class="num">Software</th><th class="num">Campanhas</th><th class="num">Relatórios</th><th class="num">Fontes</th></tr></thead><tbody id="tb">{rows}</tbody></table></div>
<p style="font-size:13px;color:var(--ink-3)">Sobreposição de TTP não é atribuição. O ATT&amp;CK registra apenas o que foi relatado publicamente. Planilha-resumo: <a href="groups.csv">groups.csv</a>.</p>
<script>const q=document.getElementById('q'),rs=[...document.querySelectorAll('#tb tr')],c=document.getElementById('cnt');function f(){{const v=q.value.trim().toLowerCase();let n=0;rs.forEach(r=>{{const ok=!v||r.dataset.q.includes(v);r.style.display=ok?'':'none';if(ok)n++;}});c.textContent=n+' de '+rs.length+' grupos';}}q.addEventListener('input',f);f();</script>"""
open("reports/index.html", "w", encoding="utf-8").write(page("Dossiês de inteligência · Detection Rules", ibody, desc="Dossiês de inteligência de fontes abertas sobre grupos de ameaça.", site=SITE))
with open("reports/groups.csv", "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f); w.writerow(["id", "grupo", "aliases", "tecnicas", "cobertura_pct", "sem_regra", "software", "campanhas", "relatorios", "fontes", "dossie"])
    for i in index: w.writerow([i["id"], i["n"], i["al"], i["t"], i["pct"], i["gaps"], i["sw"], i["camp"], i["rep"], i["refs"], "reports/groups/" + i["f"]])
print(f"HTML: {len([f for f in os.listdir('reports/groups') if f.endswith('.html')])} dossiês + reports/index.html")
print(f"{len(profiles)} perfis · {len(index)} dossiês · groups.json {os.path.getsize('data/graph/groups.json')/1e6:.2f} MB · procedimentos {sum(len(t['pr']) for p in profiles.values() for t in p['tech'])} · referências {sum(len(p['refs']) for p in profiles.values())}")
