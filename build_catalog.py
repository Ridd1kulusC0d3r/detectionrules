TQ="'"*3
#!/usr/bin/env python3
"""Normaliza todos os catálogos de regras de detecção em um único JSON.
stdlib-only. Saída: catalog.json (lista de dicts com schema unificado).
"""
import os, re, json, glob, sys, hashlib
import xml.etree.ElementTree as ET
from collections import Counter

ROOT = os.path.dirname(os.path.abspath(__file__))
OUT  = os.path.join(ROOT, "catalog.json")

TACTIC_MAP = {
 "reconnaissance":"Reconnaissance","resource_development":"Resource Development",
 "initial_access":"Initial Access","execution":"Execution","persistence":"Persistence",
 "privilege_escalation":"Privilege Escalation","defense_evasion":"Defense Evasion",
 "credential_access":"Credential Access","discovery":"Discovery","lateral_movement":"Lateral Movement",
 "collection":"Collection","command_and_control":"Command and Control","exfiltration":"Exfiltration",
 "impact":"Impact",
}
TECH_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.I)


def clean_sev(v):
    if not v: return None
    v = v.split("#")[0].strip().strip("'\"").lower()
    return {"info":"informational","test":None,"informational":"informational"}.get(v, v) or None

def norm_tactic(s):
    if not s: return None
    k = s.strip().lower().replace("-", "_").replace(" ", "_").replace("attack.", "")
    if k in TACTIC_MAP: return TACTIC_MAP[k]
    for key, val in TACTIC_MAP.items():
        if key.replace("_","") == k.replace("_",""): return val
    return None

def techs_from(*texts):
    out = set()
    for t in texts:
        if not t: continue
        if isinstance(t, (list, tuple, set)):
            for x in t: out.update(techs_from(x))
        else:
            for m in TECH_RE.findall(str(t)): out.add(m.upper())
    return sorted(out)

def read(p):
    try:
        with open(p, encoding="utf-8", errors="replace") as f: return f.read()
    except Exception: return ""

def stable_id(*parts):
    return hashlib.sha1("|".join(str(p) for p in parts).encode()).hexdigest()[:12]

# ---------------- mini YAML (suficiente p/ frontmatter simples) ----------------
# Para YAML real usamos uma heurística: extraímos campos de topo por regex,
# porque não temos PyYAML garantido. Mantemos o texto bruto como fonte de verdade.
def yaml_top(text, key):
    """Valor de um campo escalar de topo (sem indentação)."""
    m = re.search(rf"^{re.escape(key)}:\s*(.*)$", text, re.M)
    if not m: return None
    v = m.group(1).strip()
    if v in ("|", "|-", ">", ">-", ""):
        # bloco multilinha indentado
        lines = []
        for ln in text[m.end():].splitlines()[1:]:
            if ln.strip()=="" or ln.startswith((" ","\t")): lines.append(ln.strip())
            else: break
        return "\n".join(lines).strip()
    return v.strip().strip("'\"")

def yaml_list(text, key):
    """Lista de topo em formato '- item' logo abaixo da chave."""
    m = re.search(rf"^{re.escape(key)}:\s*(.*)$", text, re.M)
    if not m: return []
    inline = m.group(1).strip()
    if inline.startswith("["):
        return [x.strip().strip("'\"") for x in inline.strip("[]").split(",") if x.strip()]
    items = []
    for ln in text[m.end():].splitlines()[1:]:
        if re.match(r"^\s+-\s+", ln): items.append(re.sub(r"^\s+-\s+","",ln).strip().strip("'\""))
        elif ln.strip()=="" : continue
        elif ln.startswith((" ","\t")): continue
        else: break
    return items

def yaml_block(text, key):
    """Bloco inteiro (chave + conteúdo indentado) como texto."""
    m = re.search(rf"^{re.escape(key)}:.*$", text, re.M)
    if not m: return None
    lines=[m.group(0)]
    for ln in text[m.end():].splitlines()[1:]:
        if ln.strip()=="" or ln.startswith((" ","\t")): lines.append(ln)
        else: break
    return "\n".join(lines).rstrip()

# ---------------- SIGMA-family (SigmaHQ, Hayabusa-sigma, OpenSearch) ----------------
def parse_sigma_file(path, source, license_):
    t = read(path)
    if not t.strip() or "detection:" not in t: return None
    tags = yaml_list(t, "tags")
    tactics = sorted({x for x in (norm_tactic(tg) for tg in tags) if x})
    techs = techs_from(tags)
    logsrc = yaml_block(t, "logsource") or ""
    prod = re.search(r"^\s+product:\s*(.+)$", logsrc, re.M)
    cat  = re.search(r"^\s+category:\s*(.+)$", logsrc, re.M)
    svc  = re.search(r"^\s+service:\s*(.+)$", logsrc, re.M)
    return {
        "id": yaml_top(t,"id") or stable_id(path),
        "title": yaml_top(t,"title") or os.path.basename(path),
        "description": yaml_top(t,"description") or "",
        "source": source, "format": "sigma", "lang": "Sigma (YAML)",
        "severity": clean_sev(yaml_top(t,"level")),
        "status": yaml_top(t,"status"),
        "author": yaml_top(t,"author"),
        "date": yaml_top(t,"date"),
        "tactics": tactics, "techniques": techs,
        "logsource": {"product": prod.group(1).strip() if prod else None,
                      "category": cat.group(1).strip() if cat else None,
                      "service": svc.group(1).strip() if svc else None},
        "false_positives": yaml_list(t,"falsepositives"),
        "references": yaml_list(t,"references"),
        "query": yaml_block(t,"detection") or "",
        "raw": t, "path": os.path.relpath(path, ROOT), "license": license_,
    }

# ---------------- ELASTIC (TOML) ----------------
def toml_str(t, key):
    m = re.search(rf'^{key}\s*=\s*"""(.*?)"""', t, re.M|re.S)
    if m: return m.group(1).strip()
    m = re.search(rf'^{key}\s*=\s*"((?:[^"\\]|\\.)*)"', t, re.M)
    return m.group(1).strip() if m else None
def toml_list(t, key):
    m = re.search(rf'^{key}\s*=\s*\[(.*?)\]', t, re.M|re.S)
    if not m: return []
    return [x.strip().strip('"').strip("'") for x in re.split(r",\s*", m.group(1).strip()) if x.strip()]

def parse_elastic(path):
    t = read(path)
    if "[rule]" not in t: return None
    name = toml_str(t,"name");
    if not name: return None
    # threat blocks: [[rule.threat]] with tactic.name and technique.id
    tactics = sorted({x for x in (norm_tactic(m) for m in re.findall(r'^\s*name\s*=\s*"([^"]+)"', t, re.M)) if x})
    techs = techs_from(t)
    sev = (toml_str(t,"severity") or "").lower() or None
    lang = toml_str(t,"language") or toml_str(t,"type") or "kql"
    q = toml_str(t,"query") or ""
    return {
        "id": toml_str(t,"rule_id") or stable_id(path),
        "title": name, "description": toml_str(t,"description") or "",
        "source": "Elastic detection-rules", "format": "elastic", "lang": f"Elastic ({lang})",
        "severity": sev, "status": toml_str(t,"maturity") or None,
        "author": ", ".join(toml_list(t,"author")) or None,
        "date": toml_str(t,"creation_date"),
        "tactics": tactics, "techniques": techs,
        "logsource": {"product": ", ".join(toml_list(t,"integration")) or None,
                      "category": toml_str(t,"type"), "service": ", ".join(toml_list(t,"index"))[:200] or None},
        "false_positives": toml_list(t,"false_positives"),
        "references": toml_list(t,"references"),
        "query": q, "raw": t, "path": os.path.relpath(path, ROOT), "license": "Elastic License v2",
    }

# ---------------- SPLUNK ----------------
def parse_splunk(path):
    t = read(path)
    if "search:" not in t or "name:" not in t: return None
    tech = yaml_list(t,"mitre_attack_id")
    return {
        "id": yaml_top(t,"id") or stable_id(path),
        "title": yaml_top(t,"name") or os.path.basename(path),
        "description": yaml_top(t,"description") or "",
        "source": "Splunk security_content", "format": "splunk", "lang": "Splunk SPL",
        "severity": None, "status": yaml_top(t,"status"), "author": yaml_top(t,"author"),
        "date": yaml_top(t,"creation_date") or yaml_top(t,"date"),
        "tactics": [], "techniques": techs_from(tech),
        "logsource": {"product": ", ".join(yaml_list(t,"data_source"))[:200] or None,
                      "category": yaml_top(t,"type"), "service": None},
        "false_positives": [yaml_top(t,"known_false_positives")] if yaml_top(t,"known_false_positives") else [],
        "references": yaml_list(t,"references"),
        "query": yaml_top(t,"search") or "", "raw": t, "path": os.path.relpath(path, ROOT), "license": "Apache-2.0",
    }

# ---------------- SENTINEL (KQL YAML) ----------------
def parse_sentinel(path):
    t = read(path)
    if "query:" not in t: return None
    desc = yaml_top(t,"description") or ""
    if "content migration" in desc and "moved to new location" in desc: return None  # stub
    tactics = sorted({x for x in (norm_tactic(m) for m in yaml_list(t,"tactics")) if x})
    kind = "Hunting Queries" if "Hunting" in path else "Analytic Rules"
    return {
        "id": yaml_top(t,"id") or stable_id(path),
        "title": yaml_top(t,"name") or os.path.basename(path), "description": desc,
        "source": f"Microsoft Sentinel ({kind})", "format": "sentinel", "lang": "KQL",
        "severity": clean_sev(yaml_top(t,"severity")), "status": yaml_top(t,"status"),
        "author": None, "date": None,
        "tactics": tactics, "techniques": techs_from(yaml_list(t,"relevantTechniques")),
        "logsource": {"product": ", ".join(re.findall(r"connectorId:\s*(\S+)", t))[:200] or None,
                      "category": yaml_top(t,"kind"), "service": None},
        "false_positives": [], "references": [],
        "query": yaml_top(t,"query") or "", "raw": t, "path": os.path.relpath(path, ROOT), "license": "MIT",
    }

# ---------------- CHRONICLE YARA-L ----------------
def parse_yaral(path):
    t = read(path)
    m = re.search(r"^\s*rule\s+(\w+)\s*\{", t, re.M)
    if not m: return None
    def meta(k):
        mm = re.search(rf'^\s*{k}\s*=\s*"([^"]*)"', t, re.M); return mm.group(1) if mm else None
    sev = clean_sev(meta("severity"))
    mitre = meta("mitre") or ""
    tactics = sorted({x for x in (norm_tactic(p) for p in re.split(r"[,\s]+", mitre)) if x})
    return {
        "id": stable_id(path), "title": m.group(1), "description": meta("description") or "",
        "source": "Google SecOps / Chronicle", "format": "yaral", "lang": "YARA-L 2.0",
        "severity": sev, "status": None, "author": meta("author"), "date": meta("created"),
        "tactics": tactics, "techniques": techs_from(t[:4000]),
        "logsource": {"product": meta("product"), "category": None, "service": meta("service")},
        "false_positives": [], "references": [meta("reference")] if meta("reference") else [],
        "query": t, "raw": t, "path": os.path.relpath(path, ROOT), "license": "Apache-2.0",
    }

# ---------------- WAZUH XML ----------------
WZ_LEVEL = lambda l: "critical" if l>=13 else "high" if l>=10 else "medium" if l>=7 else "low" if l>=4 else "informational"
def parse_wazuh_xml(path, source):
    t = read(path)
    out = []
    # arquivos Wazuh têm vários <group> roots → embrulhar
    try:
        root = ET.fromstring("<root>"+re.sub(r"<\?xml[^>]*\?>","",t)+"</root>")
    except ET.ParseError:
        # fallback regex por <rule ...>...</rule>
        for m in re.finditer(r"<rule\b[^>]*\bid=\"(\d+)\"[^>]*\blevel=\"(\d+)\"[^>]*>(.*?)</rule>", t, re.S):
            rid, lvl, body = m.group(1), int(m.group(2)), m.group(3)
            d = re.search(r"<description>(.*?)</description>", body, re.S)
            out.append(_wz(rid,lvl,d.group(1) if d else "", m.group(0), body, path, source))
        return out
    for grp in root.iter("group"):
        gname = grp.get("name","")
        for r in grp.findall("rule"):
            rid = r.get("id"); lvl = int(r.get("level","0") or 0)
            d = r.findtext("description") or ""
            raw = ET.tostring(r, encoding="unicode")
            out.append(_wz(rid,lvl,d,raw,raw,path,source,gname))
    return out
def _wz(rid,lvl,desc,raw,body,path,source,gname=""):
    g = re.search(r"<group>(.*?)</group>", body, re.S)
    groups = (gname + "," + (g.group(1) if g else "")).strip(",")
    return {
        "id": f"wazuh-{rid}", "title": desc.strip()[:160] or f"Wazuh rule {rid}",
        "description": desc.strip(),
        "source": source, "format": "wazuh", "lang": "Wazuh XML",
        "severity": WZ_LEVEL(lvl), "status": None, "author": None, "date": None,
        "tactics": [], "techniques": techs_from(body),
        "logsource": {"product": None, "category": groups[:200] or None, "service": None},
        "false_positives": [], "references": [],
        "query": raw.strip(), "raw": raw.strip(), "path": os.path.relpath(path, ROOT),
        "license": "GPLv2", "wazuh_level": lvl,
    }

# ---------------- FALCO ----------------
def parse_falco(path):
    t = read(path); out=[]
    blocks = re.split(r"^(?=- (?:rule|macro|list):)", t, flags=re.M)
    for b in blocks:
        m = re.match(r"- rule:\s*(.+)", b)
        if not m: continue
        dm = re.search(r"^\s+desc:\s*(?:>-?|\|-?)?\s*\n((?:[ \t]+.*\n?)+)", b, re.M)
        desc = re.sub(r"\s+"," ", dm.group(1)).strip() if dm else (re.search(r"^\s+desc:\s*(.+)$", b, re.M) or [None,""])[1].strip()
        pr = (re.search(r"^\s*priority:\s*(\w+)", b, re.M) or [None,None])[1]
        sev = {"EMERGENCY":"critical","ALERT":"critical","CRITICAL":"critical","ERROR":"high","WARNING":"medium","NOTICE":"low","INFO":"informational","INFORMATIONAL":"informational","DEBUG":"informational"}.get((pr or "").upper())
        tags = re.search(r"^\s*tags:\s*\[(.*?)\]", b, re.M|re.S)
        tagl = [x.strip() for x in tags.group(1).split(",")] if tags else []
        tactics = sorted({x for x in (norm_tactic(tg.replace("mitre_","")) for tg in tagl) if x})
        out.append({
            "id": stable_id(path, m.group(1)), "title": m.group(1).strip(), "description": desc,
            "source": "Falco rules", "format": "falco", "lang": "Falco (syscall)",
            "severity": sev, "status": None, "author": None, "date": None,
            "tactics": tactics, "techniques": techs_from(tagl),
            "logsource": {"product": "linux/containers", "category": "syscall", "service": None},
            "false_positives": [], "references": [],
            "query": b.strip(), "raw": b.strip(), "path": os.path.relpath(path, ROOT), "license": "Apache-2.0",
        })
    return out

# ---------------- YARA ----------------
def parse_yara(path, source, license_):
    t = read(path); out=[]
    for m in re.finditer(r"^\s*(?:private\s+|global\s+)*rule\s+([A-Za-z0-9_]+)[^{]*\{", t, re.M):
        start = m.start()
        # encontra fechamento balanceado
        depth=0; i=m.end()-1; end=None
        while i < len(t):
            c=t[i]
            if c=="{": depth+=1
            elif c=="}":
                depth-=1
                if depth==0: end=i+1; break
            i+=1
        if end is None: continue
        body = t[start:end]
        def meta(k):
            keys = [k] + ({"description":["Description","desc","info","descr"],"author":["Author","autor"],"date":["Date","created"],"reference":["ref","Reference","source"]}.get(k, []))
            for kk in keys:
                mm = re.search(rf'^\s*{kk}\s*=\s*"([^"]*)"', body, re.M)
                if mm: return mm.group(1)
            return None
        score = meta("score")
        sev = None
        try:
            s=int(score or 0); sev = "critical" if s>=80 else "high" if s>=65 else "medium" if s>=50 else "low"
        except: pass
        cat = os.path.basename(os.path.dirname(path))
        tags_m = re.match(r"^\s*(?:private\s+|global\s+)*rule\s+[A-Za-z0-9_]+\s*:\s*([^{]+)", body)
        ytags = tags_m.group(1).strip() if tags_m else ""
        desc = meta("description") or ""
        if not desc:
            pretty = m.group(1).replace("_"," ")
            if cat == "packers": desc = f"Assinatura de packer/compilador/protetor: {pretty}. Identifica o empacotador usado no binário (útil para triagem: binários empacotados com protetores incomuns merecem análise)."
            elif cat == "antidebug_antivm": desc = f"Detecta técnica anti-debug/anti-VM: {pretty}. Malware usa isso para perceber que está sendo analisado e se comportar diferente."
            elif cat == "capabilities": desc = f"Detecta capacidade/comportamento no binário: {pretty}."
            else: desc = f"Regra YARA '{pretty}' (categoria {cat}){(' — tags: '+ytags) if ytags else ''}."
        out.append({
            "id": stable_id(path, m.group(1)), "title": m.group(1), "description": desc, "yara_tags": ytags,
            "source": source, "format": "yara", "lang": "YARA",
            "severity": sev, "status": None, "author": meta("author"), "date": meta("date"),
            "tactics": [], "techniques": techs_from(body[:3000]),
            "logsource": {"product": "arquivo/memória", "category": os.path.basename(os.path.dirname(path)), "service": None},
            "false_positives": [], "references": [meta("reference")] if meta("reference") else [],
            "query": body.strip(), "raw": body.strip(), "path": os.path.relpath(path, ROOT), "license": license_,
        })
    return out

# ---------------- PANTHER (yml + py) ----------------
def parse_panther(path):
    t = read(path)
    if "AnalysisType:" not in t: return None
    atype = yaml_top(t,"AnalysisType")
    if atype not in ("rule","scheduled_rule","policy","correlation_rule","scheduled_query"): return None
    pyf = yaml_top(t,"Filename")
    code = ""
    if pyf:
        pp = os.path.join(os.path.dirname(path), pyf)
        if os.path.exists(pp): code = read(pp)
    reports = yaml_block(t,"Reports") or ""
    techs = techs_from(reports)
    tactics = sorted({x for x in (norm_tactic(x) for x in re.findall(r"TA\d{4}|([A-Za-z ]+)", "")) if x})
    return {
        "id": yaml_top(t,"RuleID") or yaml_top(t,"PolicyID") or yaml_top(t,"QueryName") or stable_id(path),
        "title": yaml_top(t,"DisplayName") or yaml_top(t,"RuleID") or os.path.basename(path),
        "description": yaml_top(t,"Description") or "",
        "source": "Panther panther-analysis", "format": "panther", "lang": "Python (Panther)",
        "severity": clean_sev(yaml_top(t,"Severity")), "status": "enabled" if (yaml_top(t,"Enabled") or "").lower()=="true" else yaml_top(t,"Enabled"),
        "author": None, "date": None,
        "tactics": tactics, "techniques": techs,
        "logsource": {"product": ", ".join(yaml_list(t,"LogTypes"))[:200] or None, "category": atype, "service": None},
        "false_positives": [], "references": yaml_list(t,"Reference") or ([yaml_top(t,"Reference")] if yaml_top(t,"Reference") else []),
        "query": code or (yaml_top(t,"Query") or ""), "raw": t + ("\n\n# ---- " + pyf + " ----\n" + code if code else ""),
        "path": os.path.relpath(path, ROOT), "license": "Apache-2.0",
    }

# ---------------- MARKDOWN KQL (FalconFriday / Bert-JanP) ----------------
def parse_md_kql(path, source, license_):
    t = read(path)
    blocks = re.findall(r"```(?:kql|kusto|KQL|Kusto)?\s*\n(.*?)```", t, re.S)
    blocks = [b for b in blocks if re.search(r"\|\s*(where|summarize|project|extend|join)\b", b)]
    if not blocks: return None
    title = (re.search(r"^#\s+(.+)$", t, re.M) or [None, os.path.splitext(os.path.basename(path))[0].replace("_"," ").replace("-"," ")])[1].strip()
    desc_m = re.search(r"^#[^\n]*\n+(.*?)(?=\n#|\n```)", t, re.S)
    desc = re.sub(r"\s+"," ", desc_m.group(1)).strip()[:600] if desc_m else ""
    tactics = sorted({x for x in (norm_tactic(x) for x in TACTIC_MAP) if x and re.search(x.replace(" ",r"[ _-]?"), t, re.I)})
    return {
        "id": stable_id(path), "title": title, "description": desc,
        "source": source, "format": "kql-md", "lang": "KQL (Defender/Sentinel)",
        "severity": None, "status": None, "author": None, "date": None,
        "tactics": tactics, "techniques": techs_from(t),
        "logsource": {"product": "Microsoft Defender / Sentinel", "category": None, "service": None},
        "false_positives": [], "references": re.findall(r"https?://\S+", t)[:6],
        "query": "\n\n".join(b.strip() for b in blocks), "raw": t, "path": os.path.relpath(path, ROOT), "license": license_,
    }

# ---------------- GCP security-analytics (SQL / YARA-L) ----------------
def parse_gcp(path):
    t = read(path)
    if not t.strip(): return None
    ext = path.rsplit(".",1)[-1]
    title = os.path.splitext(os.path.basename(path))[0].replace("_"," ").replace("-"," ")
    lang = {"sql":"BigQuery SQL","sqlx":"Dataform SQLX","yaral":"YARA-L 2.0","yaml":"Log Analytics YAML"}.get(ext,ext)
    desc_m = re.search(r"(?:^|\n)\s*(?:--|#|//)\s*(.{20,300})", t)
    return {
        "id": stable_id(path), "title": title, "description": desc_m.group(1).strip() if desc_m else "",
        "source": "GCP security-analytics", "format": "gcp", "lang": lang,
        "severity": None, "status": None, "author": "Google Cloud", "date": None,
        "tactics": [], "techniques": techs_from(t),
        "logsource": {"product": "Google Cloud (Cloud Logging / BigQuery)", "category": os.path.basename(os.path.dirname(path)), "service": None},
        "false_positives": [], "references": [], "query": t, "raw": t, "path": os.path.relpath(path, ROOT), "license": "Apache-2.0",
    }


# ---------------- SURICATA / SNORT / SAGAN (.rules) ----------------
def parse_rules_file(path, source, lang, license_):
    out=[]
    for ln in read(path).splitlines():
        ln=ln.strip()
        if not ln: continue
        if ln.startswith("#"):
            if re.match(r"^#\s*alert", ln): ln=ln.lstrip("# ").strip()
            else: continue
        m=re.match(r"^(alert|drop|reject|pass)\s+(\S+)\s+(\S+)\s+(\S+)\s+(->|<>)\s+(\S+)\s+(\S+)\s*\((.*)\)\s*$", ln)
        if not m: continue
        opts=m.group(8)
        g=lambda k: (re.search(rf"\b{k}\s*:\s*\"?([^;\"]*)", opts) or [None,None])[1]
        msg=g("msg") or ""; sid=g("sid") or stable_id(path,ln[:80]); ct=g("classtype") or ""
        refs=[r.strip() for r in re.findall(r"reference\s*:\s*([^;]+)", opts)]
        meta=g("metadata") or ""
        sev={"trojan-activity":"high","command-and-control":"high","exploit-kit":"high","attempted-admin":"high","attempted-user":"medium","web-application-attack":"medium","policy-violation":"low","bad-unknown":"medium","brute-force":"high","successful-admin":"critical","successful-user":"high","unsuccessful-user":"low","network-scan":"low","attempted-recon":"low","misc-activity":"informational","not-suspicious":"informational"}.get(ct)
        out.append({"id":f"sid-{sid}","title":msg[:160] or f"{lang} sid {sid}","description":f"Assinatura {lang}: {msg}. classtype={ct or '—'}; protocolo={m.group(2)}; {m.group(3)}:{m.group(4)} {m.group(5)} {m.group(6)}:{m.group(7)}.",
            "source":source,"format":"suricata","lang":lang,"severity":sev,"status":None,"author":None,"date":None,"tactics":[],"techniques":techs_from(meta,msg),
            "logsource":{"product":"rede" if lang.startswith("Suricata") else "logs (syslog)","category":ct or None,"service":m.group(2)},
            "false_positives":[],"references":refs[:8],"query":ln,"raw":ln,"path":os.path.relpath(path,ROOT),"license":license_,"ctype":"signature"})
    return out

# ---------------- QRADAR AQL (markdown com blocos sql) ----------------
def parse_md_sql(path, source, license_):
    t=read(path); blocks=[b for b in re.findall(r"```[a-zA-Z]*\s*\n(.*?)```", t, re.S) if re.search(r"\bFROM\s+(events|flows)\b", b, re.I)]
    if not blocks: return None
    out=[]
    heads=re.findall(r"^#{1,4}\s+(.+)$", t, re.M)
    title0=(heads[0] if heads else os.path.splitext(os.path.basename(path))[0]).strip()
    for i,b in enumerate(blocks):
        pos=t.find(b); prev=[h for h in re.finditer(r"^#{1,4}\s+(.+)$", t[:pos], re.M)]
        title=(prev[-1].group(1).strip() if prev else title0)
        out.append({"id":stable_id(path,i),"title":title[:160],"description":f"Consulta AQL (QRadar) — {title0}. Hunting/investigação; para virar regra CRE, revise propriedades, janela e resposta.",
            "source":source,"format":"aql","lang":"QRadar AQL","severity":None,"status":None,"author":(re.search(r"\*\*Author\*\*\s*:\s*\*?([^*<\n]+)",t) or [None,None])[1],"date":None,
            "tactics":[],"techniques":techs_from(t[:3000]),"logsource":{"product":"QRadar","category":"hunting","service":None},
            "false_positives":[],"references":re.findall(r"https?://\S+",t)[:6],"query":b.strip(),"raw":t if len(blocks)==1 else b.strip(),"path":os.path.relpath(path,ROOT),"license":license_,"ctype":"hunting"})
    return out

# ---------------- ELASTIC protections-artifacts (behavior) e hunting ----------------
def parse_elastic_behavior(path):
    t=read(path); name=toml_str(t,"name")
    if not name or "query" not in t: return None
    return {"id":toml_str(t,"id") or stable_id(path),"title":name,"description":toml_str(t,"description") or "","source":"Elastic protections-artifacts (behavior)","format":"elastic","lang":"Elastic Endpoint (EQL)",
        "severity":None,"status":None,"author":"Elastic","date":None,"tactics":sorted({x for x in (norm_tactic(m) for m in re.findall(r'^\s*name\s*=\s*"([^"]+)"',t,re.M)) if x}),"techniques":techs_from(t),
        "logsource":{"product":", ".join(toml_list(t,"os_list")) or None,"category":"endpoint behavior","service":None},"false_positives":[],"references":toml_list(t,"reference"),
        "query":toml_str(t,"query") or "","raw":t,"path":os.path.relpath(path,ROOT),"license":"Elastic License v2","ctype":"detection"}
def parse_elastic_hunt(path):
    t=read(path); name=toml_str(t,"name")
    if not name: return None
    q=re.findall(r"query\s*=\s*\[(.*?)\]", t, re.S); qq=re.findall(TQ+r"(.*?)"+TQ, q[0], re.S) if q else []
    return {"id":toml_str(t,"uuid") or stable_id(path),"title":name,"description":toml_str(t,"description") or "","source":"Elastic hunting queries","format":"elastic","lang":"Elastic hunting (ES|QL/EQL)",
        "severity":None,"status":None,"author":toml_str(t,"author") or "Elastic","date":None,"tactics":[],"techniques":techs_from(t),
        "logsource":{"product":", ".join(toml_list(t,"integration")) or None,"category":"hunting","service":None},"false_positives":[],"references":toml_list(t,"references"),
        "query":"\n\n".join(x.strip() for x in qq) or t,"raw":t,"path":os.path.relpath(path,ROOT),"license":"Elastic License v2","ctype":"hunting"}

# ---------------- SPLUNK stories ----------------
def parse_splunk_story(path):
    t=read(path); n=yaml_top(t,"name")
    if not n or "narrative:" not in t: return None
    return {"id":yaml_top(t,"id") or stable_id(path),"title":n,"description":yaml_top(t,"description") or "","source":"Splunk analytic stories","format":"splunk","lang":"Splunk Analytic Story",
        "severity":None,"status":yaml_top(t,"status"),"author":yaml_top(t,"author"),"date":yaml_top(t,"date"),"tactics":[],"techniques":techs_from(t),
        "logsource":{"product":"Splunk ES","category":"story","service":None},"false_positives":[],"references":yaml_list(t,"references"),"query":yaml_top(t,"narrative") or "","raw":t,"path":os.path.relpath(path,ROOT),"license":"Apache-2.0","ctype":"hunting"}

# ---------------- PLAYBOOKS (SOAR) ----------------
def pb(path, source, lang, title, desc, raw, license_):
    return {"id":stable_id(path),"title":(title or os.path.splitext(os.path.basename(path))[0].replace("_"," ").replace("-"," "))[:160],"description":(desc or "")[:600],"source":source,"format":"playbook","lang":lang,
        "severity":None,"status":None,"author":None,"date":None,"tactics":[],"techniques":techs_from(raw[:6000]),"logsource":{"product":lang,"category":"playbook","service":None},
        "false_positives":[],"references":re.findall(r"https?://[^\s\"'<>)]+",raw)[:5],"query":raw[:20000],"raw":raw[:60000],"path":os.path.relpath(path,ROOT),"license":license_,"ctype":"playbook"}
def parse_xsoar(path):
    t=read(path)
    if "tasks:" not in t: return None
    n=yaml_top(t,"name"); ntasks=len(re.findall(r'^\s{2}"\d+":',t,re.M))
    return pb(path,"Cortex XSOAR (demisto/content)","XSOAR playbook YAML",n,(yaml_top(t,"description") or "")+f" [{ntasks} tarefas]",t,"MIT")
def parse_phantom(path):
    try: d=json.loads(read(path))
    except Exception: return None
    coa=d.get("coa",{}); data=coa.get("data",{}) if isinstance(coa,dict) else {}
    desc=data.get("description") or d.get("description") or ""
    py=os.path.splitext(path)[0]+".py"; code=read(py) if os.path.exists(py) else ""
    return pb(path,"Splunk SOAR / Phantom playbooks","Splunk SOAR (JSON+Python)",os.path.splitext(os.path.basename(path))[0].replace("_"," "),desc,code or json.dumps(d,indent=1)[:60000],"Apache-2.0")
def parse_shuffle(path):
    try: d=json.loads(read(path))
    except Exception: return None
    if not isinstance(d,dict) or "actions" not in d: return None
    return pb(path,"Shuffle workflows","Shuffle workflow JSON",d.get("name"),(d.get("description") or "")+f" [{len(d.get('actions',[]))} ações]",json.dumps(d,indent=1)[:60000],"AGPL-3.0")
def parse_splunk_playbook(path):
    t=read(path); n=yaml_top(t,"name")
    if not n: return None
    return pb(path,"Splunk security_content playbooks","Splunk SOAR playbook (metadata YAML)",n,yaml_top(t,"description"),t,"Apache-2.0")
def parse_awesome(path):
    vendor=path.split("/playbooks/")[1].split("/")[0] if "/playbooks/" in path else "?"
    ext=path.rsplit(".",1)[-1].lower()
    if ext not in ("yml","yaml","json","md","xml"): return None
    t=read(path)
    if not t.strip() or len(t)<80: return None
    title=None; desc=""
    if ext in ("yml","yaml"): title=yaml_top(t,"name") or yaml_top(t,"title") or yaml_top(t,"id"); desc=yaml_top(t,"description") or ""
    elif ext=="json":
        try: d=json.loads(t); d=d if isinstance(d,dict) else {}
        except Exception: d={}
        title=d.get("name") or d.get("title") or d.get("displayName"); desc=d.get("description") or (d.get("coa",{}).get("data",{}).get("description") if isinstance(d.get("coa"),dict) else "") or ""
    elif ext=="md": title=(re.search(r"^#\s+(.+)$",t,re.M) or [None,None])[1]; desc=re.sub(r"\s+"," ",t[:400])
    elif ext=="xml": title=(re.search(r"<(?:name|title|displayName)>([^<]+)<",t) or [None,None])[1]; desc=(re.search(r"<description>([^<]+)<",t) or [None,""])[1]
    if isinstance(desc,dict): desc=json.dumps(desc)[:400]
    return pb(path,f"awesome-playbooks · {vendor}",f"Playbook {vendor} ({ext})",title,str(desc),t,"CC-BY-4.0 (agregador; cada playbook mantém sua licença)")

# ======================= RUN =======================
def main():
    rules = []
    def add(x):
        if x is None: return
        if isinstance(x, list): rules.extend([r for r in x if r])
        else: rules.append(x)

    for p in glob.glob("sigma/rules*/**/*.yml", recursive=True):
        add(parse_sigma_file(p, "SigmaHQ", "DRL 1.1"))
    for p in glob.glob("Yamato-Security_hayabusa-rules/hayabusa/**/*.yml", recursive=True):
        add(parse_sigma_file(p, "Hayabusa (native)", "DRL 1.1"))
    for p in glob.glob("os_secanalytics/src/main/config/rules/**/*.yml", recursive=True):
        add(parse_sigma_file(p, "OpenSearch Security Analytics", "Apache-2.0"))
    for p in glob.glob("elastic_detection-rules/rules/**/*.toml", recursive=True) + glob.glob("elastic_detection-rules/rules_building_block/**/*.toml", recursive=True):
        add(parse_elastic(p))
    for p in glob.glob("splunk_security_content/detections/**/*.yml", recursive=True):
        add(parse_splunk(p))
    for p in glob.glob("azure_sentinel/Solutions/*/Analytic Rules/*.yaml") + glob.glob("azure_sentinel/Solutions/*/Hunting Queries/*.yaml") + glob.glob("azure_sentinel/Detections/**/*.yaml", recursive=True) + glob.glob("azure_sentinel/Hunting Queries/**/*.yaml", recursive=True):
        add(parse_sentinel(p))
    for p in glob.glob("chronicle_detection-rules/rules/**/*.yaral", recursive=True):
        add(parse_yaral(p))
    for p in glob.glob("wazuh_wazuh/ruleset/rules/*.xml"):
        add(parse_wazuh_xml(p, "Wazuh ruleset (oficial)"))
    for p in glob.glob("socfortress_Wazuh-Rules/**/*.xml", recursive=True):
        add(parse_wazuh_xml(p, "SOCFortress Wazuh-Rules"))
    for p in glob.glob("falcosecurity_rules/rules/*.yaml"):
        add(parse_falco(p))
    for p in glob.glob("Neo23x0_signature-base/yara/**/*.yar", recursive=True):
        add(parse_yara(p, "Neo23x0 signature-base", "DRL 1.1"))
    for p in glob.glob("Yara-Rules_rules/**/*.yar", recursive=True):
        if "/deprecated/" in p or p.endswith("index.yar") or "_index.yar" in p: continue
        add(parse_yara(p, "Yara-Rules community", "GPLv2"))
    for p in glob.glob("reversinglabs_reversinglabs-yara-rules/yara/**/*.yar*", recursive=True):
        add(parse_yara(p, "ReversingLabs YARA", "MIT"))
    for p in glob.glob("panther-labs_panther-analysis/rules/**/*.yml", recursive=True) + glob.glob("panther-labs_panther-analysis/policies/**/*.yml", recursive=True) + glob.glob("panther-labs_panther-analysis/correlation_rules/**/*.yml", recursive=True):
        add(parse_panther(p))
    for p in glob.glob("FalconForceTeam_FalconFriday/*.md"):
        add(parse_md_kql(p, "FalconFriday (FalconForce)", "BSD-3"))
    for p in glob.glob("Bert-JanP_Hunting-Queries-Detection-Rules/**/*.md", recursive=True):
        if os.path.basename(p).lower() in ("readme.md","detectiontemplate.md","community repositories.md"): continue
        add(parse_md_kql(p, "Bert-JanP Hunting Queries", "BSD-3"))
    for p in glob.glob("gcp_secanalytics/**/*.sql", recursive=True) + glob.glob("gcp_secanalytics/**/*.sqlx", recursive=True) + glob.glob("gcp_secanalytics/**/*.yaral", recursive=True):
        add(parse_gcp(p))

    for p in glob.glob("mir_hunting-rules/*.rules"): add(parse_rules_file(p,"Suricata hunting-rules (travisbgreen)","Suricata/Snort","MIT"))
    for p in glob.glob("mir_opnsense-suricata-nmaps/**/*.rules",recursive=True): add(parse_rules_file(p,"Suricata nmap/OPNsense rules","Suricata/Snort","MIT"))
    for p in glob.glob("mir_sagan-rules/*.rules"): add(parse_rules_file(p,"Sagan rules (Quadrant)","Sagan (log IDS, sintaxe Snort)","GPLv2"))
    for p in glob.glob("System-CTL_QRadar-AQL-Queries/**/*.md",recursive=True)+glob.glob("Cyb3rSn0rlax_QRadar-AQLQueries/**/*.md",recursive=True):
        add(parse_md_sql(p,"QRadar AQL (comunidade)","MIT"))
    for p in glob.glob("saifbelaarbi_evtx-wazuh-rules/**/*.xml",recursive=True): add(parse_wazuh_xml(p,"EVTX-Wazuh-Rules (saifbelaarbi)"))
    for p in glob.glob("saifbelaarbi_evtx-wazuh-rules/database/exports/sigma/*.yml"): add(parse_sigma_file(p,"EVTX-Wazuh-Rules (Sigma export)","MIT"))
    for p in glob.glob("Jeremy-Burgos_wazuh-detection-engineering/**/*.xml",recursive=True): add(parse_wazuh_xml(p,"wazuh-detection-engineering (Jeremy-Burgos)"))
    for p in glob.glob("rowham_chronicle-detection-rules/**/*.yaral",recursive=True):
        r=parse_yaral(p)
        if r: r["source"]="Chronicle rules (rowham)"; add(r)
    for p in glob.glob("elastic_protections-artifacts/behavior/**/*.toml",recursive=True): add(parse_elastic_behavior(p))
    for p in glob.glob("elastic_protections-artifacts/yara/**/*.yar",recursive=True): add(parse_yara(p,"Elastic protections-artifacts (YARA)","Elastic License v2"))
    for p in glob.glob("elastic_detection-rules/hunting/**/*.toml",recursive=True): add(parse_elastic_hunt(p))
    for p in glob.glob("splunk_security_content/stories/*.yml"): add(parse_splunk_story(p))
    for p in glob.glob("splunk_security_content/playbooks/*.yml"): add(parse_splunk_playbook(p))
    for p in glob.glob("panther-labs_panther-analysis/queries/**/*.yml",recursive=True): add(parse_panther(p))
    for p in glob.glob("gcp_secanalytics/**/*.yaml",recursive=True): add(parse_gcp(p))
    for p in glob.glob("demisto_content/Packs/*/Playbooks/*.yml"): add(parse_xsoar(p))
    for p in glob.glob("phantomcyber_playbooks/*.json"): add(parse_phantom(p))
    for p in glob.glob("Shuffle_workflows/**/*.json",recursive=True): add(parse_shuffle(p))
    for p in glob.glob("luduslibrum_awesome-playbooks/playbooks/**/*",recursive=True):
        if os.path.isfile(p): add(parse_awesome(p))

    # dedupe por (source,id)
    for r in rules:
        if r is None: continue
        r.setdefault("ctype", "hunting" if (r["format"]=="kql-md" or "Hunting" in r["source"] or r["format"]=="gcp") else "signature" if r["format"]=="yara" else "detection")
    seen=set(); final=[]
    for r in rules:
        k=(r["source"], r["id"]);
        if k in seen: r["id"] = r["id"]+"-"+stable_id(r["path"], r["title"])
        seen.add((r["source"], r["id"])); final.append(r)

    with open(OUT,"w",encoding="utf-8") as f: json.dump(final, f, ensure_ascii=False)
    c = Counter(r["source"] for r in final)
    print(f"TOTAL {len(final)} regras → {OUT} ({os.path.getsize(OUT)/1e6:.1f} MB)")
    for s,n in c.most_common(): print(f"  {n:6d}  {s}")
    print("formatos:", Counter(r["format"] for r in final).most_common())
    print("com técnica ATT&CK:", sum(1 for r in final if r["techniques"]))
    print("com tática:", sum(1 for r in final if r["tactics"]))

if __name__=="__main__":
    os.chdir(ROOT); main()
