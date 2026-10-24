#!/usr/bin/env python3
"""catalog.json -> data/ otimizado para GitHub Pages. stdlib-only.
- data/index.json   índice colunar (busca/filtros)
- data/chunks/<fonte>/<n>.json  texto original fatiado em blocos de ~3 MB (nenhum arquivo perto do limite de 50 MB do GitHub)
- data/manifest.json fontes, contagens e nº de blocos por fonte
O bloco de cada regra = FNV-1a(id) % nblocos (mesma função no JS).
A query só é guardada quando NÃO está contida no arquivo original (dedup).
"""
import json,os,re,collections,datetime,math,shutil,sys
# ---- mascaramento de credenciais embutidas em conteúdo de terceiros ----
# Mantém padrões de DETECÇÃO intactos (ex.: a string "BEGIN PRIVATE KEY" de uma regra YARA)
# e chaves de exemplo da documentação AWS (…EXAMPLE) usadas em logs de teste.
MASK="REDIGIDO-PELO-DETECTIONRULES"
ALWAYS=[
 re.compile(r'https://hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9/_\-]+'),
 re.compile(r'https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]+'),
 re.compile(r'https://[a-z0-9]+\.webhook\.office\.com/webhookb2/[^\s"\'<>]+'),
 re.compile(r'\bxox[abposr]-[A-Za-z0-9-]{10,}'),
 re.compile(r'\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{60,}'),
 re.compile(r'\bAIza[0-9A-Za-z_\-]{35}\b'),
 re.compile(r'\b(?:sk|rk)_live_[0-9A-Za-z]{20,}'),
 re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----[A-Za-z0-9+/=\s\\n]{100,}?-----END (?:RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----'),
]
AWS_KEY=re.compile(r'\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA)[A-Z0-9]{16}\b')
AWS_SECRET=re.compile(r'(?<![A-Za-z0-9/+=])[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+=])')
CRED_ATTR=re.compile(r'(?i)((?:pass|passwd|password|poppass|secret|secretkey|secret_key|apikey|api_key|access_token|auth_token|token)["\']?\s*[=:]\s*["\'])([^"\'{}$<>\s]{16,})(["\'])')
def redact(text, ctype):
    if not text: return text, 0
    n=0
    for rx in ALWAYS:
        text,k=rx.subn(MASK,text); n+=k
    if ctype=="playbook":
        text,k=CRED_ATTR.subn(lambda m:m.group(1)+MASK+m.group(3),text); n+=k
        text,k=AWS_KEY.subn(lambda m:m.group(0) if "EXAMPLE" in m.group(0) else MASK,text); n+=k
        if AWS_KEY.search(text) or "aws" in text.lower():
            text,k=AWS_SECRET.subn(lambda m:m.group(0) if (m.group(0).isalpha() or "/" not in m.group(0) and "+" not in m.group(0) and m.group(0).islower()) else MASK,text); n+=k
    return text, n

CHUNK=3_000_000
def fnv(s):
    h=0x811c9dc5
    for b in s.encode("utf-8"): h^=b; h=(h*0x01000193)&0xffffffff
    return h
CAT=sys.argv[1] if len(sys.argv)>1 else "catalog.json"
R=json.load(open(CAT,encoding="utf-8")); OUT="data"
shutil.rmtree(f"{OUT}/chunks",ignore_errors=True); shutil.rmtree(f"{OUT}/shards",ignore_errors=True)
os.makedirs(f"{OUT}/chunks",exist_ok=True)
slug=lambda s: re.sub(r"[^a-z0-9]+","-",s.lower()).strip("-")
enc=lambda key: sorted({r[key] for r in R if r[key] is not None})
S=enc("source");F=enc("format");L=enc("lang");LIC=enc("license")
ix=lambda lst:{v:i for i,v in enumerate(lst)}; si,fi,li,lici=ix(S),ix(F),ix(L),ix(LIC)
rows=[[r["id"],redact(r["title"][:140],r.get("ctype",""))[0],redact((r["description"] or "")[:140],r.get("ctype",""))[0],si[r["source"]],fi[r["format"]],li[r["lang"]],r["severity"] or "",r["tactics"],r["techniques"],(r["logsource"].get("product") or "")[:60],(r["logsource"].get("category") or "")[:60],r.get("status") or "",lici[r["license"]],r.get("ctype","detection")] for r in R]
json.dump({"cols":["id","title","desc","src","fmt","lang","sev","tactics","techniques","product","category","status","lic","ctype"],"src":S,"src_slug":[slug(s) for s in S],"fmt":F,"lang":L,"lic":LIC,"rows":rows},open(f"{OUT}/index.json","w",encoding="utf-8"),ensure_ascii=False,separators=(",",":"))
groups=collections.defaultdict(list); REDACTED=collections.Counter()
for r in R:
    ct=r.get("ctype","detection")
    raw,n1=redact(r["raw"] or "",ct); q,n2=redact(r["query"] or "",ct)
    e={"raw":raw,"fp":r["false_positives"],"ref":r["references"],"desc":r["description"],"path":r["path"],"a":r.get("author"),"dt":r.get("date"),"sv":r["logsource"].get("service")}
    if q and q not in raw: e["q"]=q
    refs=[]; n3=0
    for x in (r["references"] or []):
        y,k=redact(x,ct); refs.append(y); n3+=k
    e["ref"]=refs
    d0,n4=redact(r["description"] or "",ct); e["desc"]=d0
    fps=[]
    for x in (r["false_positives"] or []):
        y,k=redact(x if isinstance(x,str) else str(x),ct); fps.append(y); n4+=k
    e["fp"]=fps
    if n1+n2+n3+n4: e["red"]=n1+n2+n3+n4; REDACTED[r["source"]]+=n1+n2+n3+n4
    groups[slug(r["source"])].append((r["id"],e))
man={"total":len(R),"generated":datetime.date.today().isoformat(),"chunked":True,"sources":[]}
for k,items in sorted(groups.items(),key=lambda x:-len(x[1])):
    size=sum(len(json.dumps(e,ensure_ascii=False)) for _,e in items)
    n=max(1,math.ceil(size/CHUNK)); buckets=[{} for _ in range(n)]
    for i,e in items: buckets[fnv(i)%n][i]=e
    os.makedirs(f"{OUT}/chunks/{k}",exist_ok=True)
    tb=0
    for j,b in enumerate(buckets):
        p=f"{OUT}/chunks/{k}/{j}.json"; json.dump(b,open(p,"w",encoding="utf-8"),ensure_ascii=False,separators=(",",":")); tb+=os.path.getsize(p)
    name=next(r["source"] for r in R if slug(r["source"])==k)
    man["sources"].append({"slug":k,"name":name,"n":len(items),"chunks":n,"bytes":tb})
json.dump(man,open(f"{OUT}/manifest.json","w",encoding="utf-8"),ensure_ascii=False,indent=1)
print("ok",len(R),"regras ·",sum(s["chunks"] for s in man["sources"]),"blocos")
print("credenciais mascaradas:",sum(REDACTED.values()),dict(REDACTED))
