#!/usr/bin/env python3
"""Relatórios e painéis por TECNOLOGIA (stdlib-only).

Lê data/index.json (coluna tech/pat de techmap.py), data/graph/attack.json, actors.json, ransomware.json,
tcem.json e ai.json. Gera:
  data/graph/tech.json             agregados para a aba Tecnologias do app
  reports/tech/<id>-<nome>.md|html relatório por tecnologia (cobertura, lacunas, grupos, padrões, telemetria)
  reports/tech/index.html          painel estático com todas as tecnologias
"""
import json, os, re, collections, datetime, html as H
from urllib.parse import quote_plus
import techmap
from intel_html import md_to_html, page

SITE = "https://ridd1kulusc0d3r.github.io/detectionrules/"
REPO = "https://github.com/Ridd1kulusC0d3r/detectionrules"
TODAY = datetime.date.today().isoformat()
def J(p, d):
    try: return json.load(open(p, encoding="utf-8"))
    except Exception: return d
IX = J("data/index.json", None); A = J("data/graph/attack.json", None)
AX = J("data/graph/actors.json", {"g": {}}); RW = J("data/graph/ransomware.json", {"tools": [], "cats": []})
TC = J("data/graph/tcem.json", {"lenses": [], "cases": [], "schema": {}, "patterns": []}); AI = J("data/graph/ai.json", {})
assert IX and A, "rode make_data.py e build_graph.py antes"
ci = {c: i for i, c in enumerate(IX["cols"])}
TECHS = IX["tech"]; PATS = IX["pat"]; TID = [t["id"] for t in TECHS]
TECH = A["techniques"]; REV = A["rev"]; TAC = [t["short"] for t in A["tactics"]]; TACN = {t["short"]: t["n"] for t in A["tactics"]}
TAC_PT = {"reconnaissance": "Reconhecimento", "resource-development": "Desenv. de recursos", "initial-access": "Acesso inicial", "execution": "Execução",
          "persistence": "Persistência", "privilege-escalation": "Escalação de privilégio", "stealth": "Furtividade", "defense-impairment": "Enfraquecimento de defesas",
          "credential-access": "Acesso a credenciais", "discovery": "Descoberta", "lateral-movement": "Movimento lateral", "collection": "Coleta",
          "command-and-control": "Comando e controle", "exfiltration": "Exfiltração", "impact": "Impacto"}
EN2SHORT = {t["n"]: t["short"] for t in A["tactics"]}; EN2SHORT["Defense Evasion"] = "stealth"
FMT_PT = {"sigma": "Sigma", "elastic": "Elastic", "splunk": "Splunk", "sentinel": "Sentinel KQL", "yaral": "YARA-L", "wazuh": "Wazuh", "falco": "Falco", "yara": "YARA",
          "panther": "Panther", "kql-md": "KQL hunting", "suricata": "Suricata/Snort/Sagan", "aql": "QRadar AQL", "gcp": "GCP", "playbook": "Playbook"}
CT_PT = {"detection": "detecção", "hunting": "hunting", "signature": "assinatura", "playbook": "playbook"}
RANK_FMT = {"sigma": 5, "elastic": 4, "splunk": 4, "sentinel": 4, "yaral": 3, "wazuh": 3, "falco": 3, "panther": 3, "kql-md": 2, "suricata": 2}
RANK_ST = {"stable": 2, "production": 2, "test": 1, "experimental": 0, "deprecated": -4}
TECH_RW = {"windows": ["lolbas", "evasao", "credenciais", "descoberta"], "ad": ["descoberta", "credenciais"], "edr": ["evasao", "offsec"],
           "vpn": ["rmm", "rede"], "firewall": ["rede"], "nsm": ["rede", "offsec"], "proxy": ["exfiltracao", "rede"], "saas": ["exfiltracao"],
           "backup": ["evasao"], "linux": ["rede", "offsec"], "aws": ["credenciais", "exfiltracao"], "entra": ["credenciais"], "virt": ["evasao", "rmm"]}
slug = lambda s: re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")
src_names = IX["src"]; fmt_names = IX["fmt"]

# ------------------------------------------------------------------ agregação
S = {k: {"n": 0, "ct": collections.Counter(), "fmt": collections.Counter(), "src": collections.Counter(), "pat": collections.Counter(),
         "sev": collections.Counter(), "tac": collections.Counter(), "tt": collections.Counter(), "cand": []} for k in TID}
flows = collections.Counter()
for row in IX["rows"]:
    ks = [TID[i] for i in row[ci["tech"]]]
    techs = {REV.get(t, t) for t in (row[ci["techniques"]] or [])}
    tacs = {s for t in techs if t in TECH for s in TECH[t]["ta"]} or {EN2SHORT.get(x) for x in (row[ci["tactics"]] or []) if EN2SHORT.get(x)}
    fmt = fmt_names[row[ci["fmt"]]]; src = src_names[row[ci["src"]]]; ct = row[ci["ctype"]]; pat = PATS[row[ci["pat"]]]["id"]
    sev = row[ci["sev"]] or "none"; st = (row[ci["status"]] or "").lower()
    for k in ks:
        x = S[k]; x["n"] += 1; x["ct"][ct] += 1; x["fmt"][fmt] += 1; x["src"][src] += 1; x["pat"][pat] += 1; x["sev"][sev] += 1
        for s in tacs: x["tac"][s] += 1
        for t in techs:
            if t in TECH: x["tt"][t] += 1
        flows[(src, k)] += 1
        if ct in ("detection", "hunting") and techs:
            sc = RANK_FMT.get(fmt, 1) + RANK_ST.get(st, 0) + (1 if sev in ("high", "critical") else 0) + (1 if ct == "detection" else 0)
            x["cand"].append((sc, -len(x["cand"]), {"u": IX["src_slug"][row[ci["src"]]] + "::" + row[ci["id"]], "t": row[ci["title"]][:110], "f": fmt, "s": src, "v": row[ci["sev"]], "k": ct, "tc": sorted(techs)[:3]}))
            if len(x["cand"]) > 400: x["cand"].sort(key=lambda z: (-z[0], -z[1])); del x["cand"][150:]

def covered(tt, t):
    """técnica coberta nesta tecnologia: regra na própria técnica, ou (para técnica-mãe) em qualquer subtécnica"""
    if tt.get(t): return True
    return "." not in t and any(tt.get(s) for s in tt if s.startswith(t + "."))

GRP = A["groups"]
out = {"meta": {"gerado": TODAY, "total": len(IX["rows"]), "metodo": "Tecnologia inferida por techmap.py a partir de logsource, caminho, título e descrição de cada regra (heurística auditável). Uma regra pode tocar várias tecnologias."},
       "tac": [{"id": s, "n": TAC_PT.get(s, TACN[s])} for s in TAC], "pats": PATS, "tech": [], "flows": [], "dom": []}
for t in TECHS:
    k = t["id"]; x = S[k]
    if not x["n"]: continue
    pl = t.get("pl") or ""
    plat = [tid for tid, v in TECH.items() if pl and pl in v["pl"]] if pl else []
    cov = [tid for tid in plat if covered(x["tt"], tid)]
    gaps = sorted([tid for tid in plat if not covered(x["tt"], tid)], key=lambda tid: (-len(TECH[tid]["g"]), tid))
    grp = []
    if plat:
        ps = set(plat)
        for g in GRP:
            gt = [REV.get(tt, tt) for tt in g["t"]]; on = [tt for tt in gt if tt in ps]
            if len(on) >= 2:
                c = [tt for tt in on if covered(x["tt"], tt)]
                cx = AX["g"].get(g["id"], {})
                grp.append({"g": g["id"], "n": g["n"], "on": len(on), "cov": len(c), "c": cx.get("pais", ""), "cn": cx.get("pais_n", ""), "miss": [tt for tt in on if tt not in c][:6]})
        grp.sort(key=lambda z: (-z["on"], z["n"]))
    x["cand"].sort(key=lambda z: (-z[0], -z[1]))
    seen = set(); rec = []
    for sc, _, e in x["cand"]:
        key = e["t"].lower()
        if key in seen: continue
        seen.add(key); rec.append(e)
        if len(rec) >= 15: break
    lens = next((l for l in TC.get("lenses", []) if l["id"] == t.get("lens")), None)
    cases = [c for c in TC.get("cases", []) if t.get("lens") and t["lens"] in (c.get("lens") or [])]
    rw = []
    for cat in TECH_RW.get(k, []):
        for tl in RW.get("tools", []):
            if tl.get("cat") == cat: rw.append({"n": tl["n"], "cat": cat, "g": len(tl["g"]), "r": tl["r"]})
    rw.sort(key=lambda z: -z["g"])
    out["tech"].append({
        "id": k, "n": t["n"], "dom": t["dom"], "pl": pl, "lens": t.get("lens"), "st": t.get("st", ""),
        "n_rules": x["n"], "ct": dict(x["ct"]), "fmt": dict(x["fmt"].most_common()), "src": x["src"].most_common(10), "pat": dict(x["pat"]),
        "sev": dict(x["sev"]), "tac": {s: x["tac"].get(s, 0) for s in TAC}, "ntech": len(x["tt"]),
        "top": [[tid, TECH[tid]["n"], c] for tid, c in x["tt"].most_common(12)],
        "plat_n": len(plat), "plat_cov": len(cov), "pct": round(len(cov) / len(plat) * 100) if plat else None,
        "gaps": [[tid, TECH[tid]["n"], len(TECH[tid]["g"]), TECH[tid]["rt"] + TECH[tid].get("rsub", 0)] for tid in gaps[:20]], "n_gaps": len(gaps),
        "grp": grp[:14], "rec": rec,
        "lensd": ({"n": lens["n"], "d": lens["d"], "tel": lens.get("tel", []), "arch": lens.get("arch", [])} if lens else None),
        "cases": [c["id"] for c in cases], "rw": rw[:18]})
out["tech"].sort(key=lambda z: (techmap.DOMAINS.index(z["dom"]) if z["dom"] in techmap.DOMAINS else 99, -z["n_rules"]))
for d in techmap.DOMAINS + ["Outros"]:
    ts = [z for z in out["tech"] if z["dom"] == d]
    if ts: out["dom"].append({"n": d, "t": [z["id"] for z in ts], "n_rules": sum(z["n_rules"] for z in ts)})
# fluxos fonte → tecnologia (12 maiores fontes, resto agrupado)
srcTot = collections.Counter()
for (s, k), v in flows.items(): srcTot[s] += v
topS = {s for s, _ in srcTot.most_common(12)}
fl = collections.Counter()
for (s, k), v in flows.items(): fl[(s if s in topS else "Outras fontes", k)] += v
out["flows"] = [[s, k, v] for (s, k), v in fl.most_common() if v >= 15]
out["cases"] = TC.get("cases", []); out["schema"] = TC.get("schema", {}); out["lenses"] = [{"id": l["id"], "n": l["n"]} for l in TC.get("lenses", [])]
out["rw_cats"] = RW.get("cats", [])
os.makedirs("data/graph", exist_ok=True)
json.dump(out, open("data/graph/tech.json", "w", encoding="utf-8"), ensure_ascii=False, separators=(",", ":"))
print(f"tech.json: {len(out['tech'])} tecnologias · {os.path.getsize('data/graph/tech.json')/1e3:.0f} KB")

# ------------------------------------------------------------------ relatórios
os.makedirs("reports/tech", exist_ok=True)
for f in os.listdir("reports/tech"):
    if f.endswith((".md", ".html")): os.remove(os.path.join("reports/tech", f))
md_cell = lambda s: (str(s) if s is not None else "").replace("|", "\\|").replace("\n", " ")
PATN = {p["id"]: p["n"] for p in PATS}; PATD = {p["id"]: p["d"] for p in PATS}
fname = lambda z: f"{z['id']}-{slug(z['n'])}"
CASES = {c["id"]: c for c in TC.get("cases", [])}
AI_SUM = AI.get("tech", [])

def report(z):
    n = z["n_rules"]; ct = z["ct"]; top_tac = sorted(z["tac"].items(), key=lambda kv: -kv[1])
    L = [f"# {z['n']} — relatório de regras de detecção", "",
         f"> **TLP:CLEAR** · {TODAY} · domínio **{z['dom']}**" + (f" · plataforma ATT&CK **{z['pl']}**" if z["pl"] else "") + (f" · lente TCEM **{z['lensd']['n']}**" if z.get("lensd") else "") + f" · [abrir no site]({SITE}#techno={z['id']})", ""]
    # a história
    tac_txt = ", ".join(TAC_PT[s] for s, v in top_tac[:3] if v)
    L += ["## 1. A história em um parágrafo", "",
          f"O palco é **{z['st'] or z['n']}**. O catálogo reúne **{n:,} regras** que olham para cá — "
          f"{ct.get('detection', 0):,} de detecção, {ct.get('hunting', 0):,} de hunting, {ct.get('signature', 0):,} assinaturas e {ct.get('playbook', 0):,} playbooks de resposta. "
          + (f"Elas se concentram em **{tac_txt}**. " if tac_txt else "")
          + (f"Das {z['plat_n']} técnicas do ATT&CK para a plataforma {z['pl']}, **{z['plat_cov']} ({z['pct']}%)** têm ao menos uma regra aqui e **{z['n_gaps']} não têm nenhuma** — é onde um atacante passa sem ser visto. " if z["pl"] else "")
          + (f"Entre os grupos com mais técnicas nesta plataforma estão {', '.join(g['n'] for g in z['grp'][:3])}." if z["grp"] else ""), ""]
    if z.get("lensd"):
        L += [f"**Lente TCEM — {z['lensd']['n']}.** {z['lensd']['d']} Para observar: {', '.join(z['lensd']['tel'])}. Arquitetura a mapear: {', '.join(z['lensd']['arch'])}.", ""]
    L += ["## 2. Números", "", "| Indicador | Valor |", "|---|---:|", f"| Regras | {n:,} |"]
    for k_, v_ in sorted(ct.items(), key=lambda kv: -kv[1]): L.append(f"| {CT_PT.get(k_, k_)} | {v_:,} |")
    L += [f"| Técnicas ATT&CK distintas | {z['ntech']} |"]
    if z["pl"]: L += [f"| Cobertura da plataforma {z['pl']} | {z['plat_cov']}/{z['plat_n']} ({z['pct']}%) |"]
    L += ["", "### Por tática", "", "| Tática | Regras |", "|---|---:|"]
    for s in TAC:
        if z["tac"][s]: L.append(f"| {TAC_PT[s]} | {z['tac'][s]:,} |")
    L += ["", "### Linguagens disponíveis", "", "Em que formato você encontra regra pronta para esta tecnologia.", "", "| Formato | Regras |", "|---|---:|"]
    for f_, v_ in z["fmt"].items(): L.append(f"| {FMT_PT.get(f_, f_)} | {v_:,} |")
    L += ["", "### Padrões de correlação (TCEM)", "", "Como as regras decidem. Muitas de evento único = cobertura ampla mas ruidosa; sequências e novidade = mais contexto, mais exigência de dados.", "", "| Padrão | Regras | O que significa |", "|---|---:|---|"]
    for p_, v_ in sorted(z["pat"].items(), key=lambda kv: -kv[1]): L.append(f"| {PATN.get(p_, p_)} | {v_:,} | {md_cell(PATD.get(p_, ''))} |")
    L += ["", "### Fontes que mais contribuem", "", "| Fonte | Regras |", "|---|---:|"]
    for s_, v_ in z["src"]: L.append(f"| {md_cell(s_)} | {v_:,} |")
    L += ["", "## 3. Técnicas mais cobertas", "", "| Técnica | Regras nesta tecnologia |", "|---|---:|"]
    for tid, nm, c in z["top"]: L.append(f"| [{tid}]({SITE}#tech={tid}) {md_cell(nm)} | {c:,} |")
    L.append("")
    if z["pl"]:
        L += [f"## 4. Detecção pela ausência — o que ninguém está olhando ({z['n_gaps']} técnicas)", "",
              f"Técnicas do ATT&CK para {z['pl']} **sem nenhuma regra nesta tecnologia**, ordenadas pelo número de grupos que as usam. A coluna \"regras no catálogo\" mostra se existe cobertura em outra tecnologia (ex.: EDR ou rede) que você pode adaptar.", "",
              "| Técnica | Grupos que usam | Regras no catálogo (todas as tecnologias) |", "|---|---:|---:|"]
        for tid, nm, ng, rt in z["gaps"]: L.append(f"| [{tid}]({SITE}#tech={tid}) {md_cell(nm)} | {ng} | {rt or '**0**'} |")
        L.append("")
    if z["grp"]:
        L += ["## 5. Quem mira esta plataforma", "", "Grupos com mais técnicas registradas nesta plataforma e quantas delas você enxerga com as regras desta tecnologia. País atribuído pelo APT4ALL (afirmação de quem publicou).", "",
              "| Grupo | Origem atribuída | Técnicas na plataforma | Com regra aqui | Exemplos sem regra |", "|---|---|---:|---:|---|"]
        for g in z["grp"]: L.append(f"| [{md_cell(g['n'])}]({SITE}#group={g['g']}) `{g['g']}` | {md_cell(g['cn'] or '—')} | {g['on']} | {g['cov']} | {', '.join(g['miss'][:4]) or '—'} |")
        L.append("")
    if z["rw"]:
        L += ["## 6. Ferramentas de afiliados de ransomware que passam por aqui", "", "Do Ransomware Tool Matrix (via APT4ALL): ferramentas usadas por gangues dentro da rede, nas categorias que esta tecnologia enxerga.", "",
              "| Ferramenta | Categoria | Gangues que usam | Regras que citam |", "|---|---|---:|---:|"]
        catn = {c["id"]: c["pt"] for c in RW.get("cats", [])}
        for r_ in z["rw"]: L.append(f"| {md_cell(r_['n'])} | {catn.get(r_['cat'], r_['cat'])} | {r_['g']} | {r_['r'] or '**0**'} |")
        L.append("")
    if z["cases"]:
        L += ["## 7. Cenário de referência TCEM", ""]
        for cid in z["cases"]:
            c = CASES[cid]
            L += [f"### {c['n']}", "", f"**Missão:** {c['mission']}", ""]
            for s in c["scen"]:
                L += [f"**{s['t']}** — {s['obj']}", ""]
                for st in s["steps"]:
                    L.append(f"{st['o']}. {st['b']} — " + ", ".join(f"{t} ({st['rules'].get(t, 0)} regras no catálogo)" for t in st["t"]))
                for tc in s["tc"]:
                    miss = [f for f in tc["req"] if f not in tc["av"]]
                    L += ["", f"Contrato de telemetria: fonte **{tc['src']}**, campos exigidos {', '.join(tc['req'])}" + (f"; **faltam {', '.join(miss)}**" if miss else "") + f" (status {tc['status']})."]
                for d in s["dsp"]:
                    L += [f"Especificação de detecção: padrão **{d['pat']}**, janela {d['win']}, agrupado por {', '.join(d['by'] or [])}. Alternativas benignas: {', '.join(d['benign'])}."]
                L.append("")
    if z["id"] == "ai" and AI_SUM:
        L += ["## 8. Ameaças de IA mapeadas (LLmInjection)", "", "| Técnica | Categoria | ATLAS / OWASP | Especificações de detecção | Testes |", "|---|---|---|---:|---:|"]
        for t in AI_SUM:
            mp = ", ".join(f"{m['id']}" for m in t["map"] if m["rel"] == "exact")[:80]
            L.append(f"| {t['id']} {md_cell(t['n'])} | {md_cell(t['cat'])} | {md_cell(mp)} | {len(t['det'])} | {len(t['tc'])} |")
        L.append("")
    L += ["## 9. Regras recomendadas para começar", "", "Ranqueadas por portabilidade do formato, maturidade, severidade e por mapearem técnica ATT&CK.", "", "| Regra | Formato | Fonte | Técnicas |", "|---|---|---|---|"]
    for e in z["rec"]: L.append(f"| [{md_cell(e['t'])}]({SITE}#rule={quote_plus(e['u'])}) | {FMT_PT.get(e['f'], e['f'])} | {md_cell(e['s'])} | {', '.join(e['tc'])} |")
    L += ["", "## 10. Limites", "",
          "- A tecnologia de cada regra é inferida por heurística sobre metadados e texto (techmap.py). Regras genéricas podem aparecer em várias tecnologias.",
          "- \"Sem regra\" quer dizer sem regra pública neste catálogo, não sem detecção possível. Telemetria e contexto do seu ambiente decidem.",
          "- Atribuição de país é afirmação das fontes reunidas pelo APT4ALL, não nossa.", "", "---",
          f"Fontes: catálogo [Detection Rules]({REPO}), MITRE ATT&CK®, APT4ALL, Ransomware Tool Matrix (CC BY 4.0), TCEM, LLmInjection. Gerado em {TODAY}."]
    return "\n".join(L) + "\n"

rows = []
for z in out["tech"]:
    md = report(z); fn = fname(z)
    open(f"reports/tech/{fn}.md", "w", encoding="utf-8").write(md)
    body, toc = md_to_html(md)
    ctot = sum(z["ct"].values()) or 1
    mx = max(z["tac"].values()) or 1
    bars = "".join(f'<div class="br"><span>{H.escape(TAC_PT[s])}</span><span class="t"><i style="width:{z["tac"][s]/mx*100:.1f}%"></i></span><b>{z["tac"][s]:,}</b></div>' for s in TAC)
    strip = (f'<div class="strip"><div><b>{z["n_rules"]:,}</b><span>regras</span></div><div><b>{z["ntech"]}</b><span>técnicas ATT&amp;CK</span></div>'
             + (f'<div><b>{z["pct"]}%</b><span>da plataforma coberta</span></div><div><b>{z["n_gaps"]}</b><span>técnicas sem regra</span></div>' if z["pl"] else "")
             + f'<div><b>{len(z["fmt"])}</b><span>formatos</span></div><div><b>{len(z["grp"])}</b><span>grupos na mira</span></div></div>')
    extra = strip + '<h3>Regras por tática</h3><div class="bars">' + bars + '</div><nav class="toc" aria-label="Sumário">' + "".join(f'<a href="#{k}">{H.escape(t)}</a>' for k, t in toc) + "</nav>"
    body = body.replace("<h2", extra + "<h2", 1)
    tools = f'<a class="btn" href="{fn}.md" download>Markdown</a><a class="btn" href="{SITE}#techno={z["id"]}">Abrir no site</a>'
    open(f"reports/tech/{fn}.html", "w", encoding="utf-8").write(page(f"{z['n']} · Relatório de regras", body, desc=f"Regras de detecção para {z['n']}: cobertura ATT&CK, lacunas, grupos, padrões e telemetria.", nav_back="index.html", site=SITE, extra_tools=tools, back_label="← relatórios por tecnologia"))
    rows.append((z, fn))

# painel estático
dom_html = []
for d in out["dom"]:
    ts = [z for z, _ in rows if z["dom"] == d["n"]]
    trs = "".join(
        f'<tr data-q="{H.escape((z["n"]+" "+z["dom"]).lower())}"><td><a href="{fn}.html"><strong>{H.escape(z["n"])}</strong></a><span class="al">{H.escape(z["pl"] or "—")}</span></td>'
        f'<td class="num">{z["n_rules"]:,}</td><td class="num">{z["ct"].get("detection",0):,}</td><td class="num">{z["ct"].get("hunting",0):,}</td><td class="num">{z["ct"].get("playbook",0):,}</td>'
        f'<td class="num">{"<span class=pbar><i style=width:%d%%></i></span>%d%%" % (z["pct"], z["pct"]) if z["pct"] is not None else "—"}</td><td class="num">{z["n_gaps"] if z["pl"] else "—"}</td></tr>' for z in ts)
    dom_html.append(f'<h2>{H.escape(d["n"])} <span style="font:12px var(--mono);color:var(--ink-3)">{d["n_rules"]:,} vínculos regra-tecnologia</span></h2><div class="tw"><table><thead><tr><th>Tecnologia</th><th class="num">Regras</th><th class="num">Detecção</th><th class="num">Hunting</th><th class="num">Playbooks</th><th class="num">Plataforma coberta</th><th class="num">Técnicas sem regra</th></tr></thead><tbody>{trs}</tbody></table></div>')
ibody = f"""<p style="font:600 11px var(--mono);letter-spacing:.14em;text-transform:uppercase;color:var(--signal);margin:0">Detection Rules · relatórios por tecnologia</p>
<h1>O catálogo pelo que ele observa</h1>
<p class="meta"><span class="tlp">TLP:CLEAR</span>{len(rows)} tecnologias em {len(out['dom'])} domínios, geradas em {TODAY} a partir de {out['meta']['total']:,} regras. Cada relatório conta a história da tecnologia, mostra cobertura por tática e por formato, os padrões de correlação, as técnicas que ninguém está olhando (detecção pela ausência), os grupos que miram a plataforma, ferramentas de ransomware e o cenário TCEM correspondente.</p>
<input class="q" id="q" type="search" placeholder="Filtrar: Okta, AWS, Kubernetes, ESXi…" aria-label="Filtrar tecnologias">
{''.join(dom_html)}
<p style="font-size:13px;color:var(--ink-3)">A tecnologia de cada regra é inferida por heurística (techmap.py). Cobertura de plataforma = técnicas do ATT&amp;CK daquela plataforma com ao menos uma regra nesta tecnologia.</p>
<script>const q=document.getElementById('q'),rs=[...document.querySelectorAll('tr[data-q]')];q.addEventListener('input',()=>{{const v=q.value.trim().toLowerCase();rs.forEach(r=>r.style.display=!v||r.dataset.q.includes(v)?'':'none');}});</script>"""
open("reports/tech/index.html", "w", encoding="utf-8").write(page("Relatórios por tecnologia · Detection Rules", ibody, desc="Regras de detecção organizadas por tecnologia: cobertura, lacunas, grupos e padrões.", nav_back=SITE, site=SITE, back_label="← Detection Rules"))
print(f"relatórios: {len(rows)} tecnologias em reports/tech/")
