"""Leitor de um subconjunto de YAML, stdlib-only.

Suficiente para os arquivos do TCEM (mapas, listas em bloco, listas/mapas em linha,
strings com aspas, números, booleanos, null e comentários). Não suporta âncoras,
blocos literais (| >) nem documentos múltiplos — e falha alto se encontrar um deles.
"""
import re

def _strip_comment(s):
    out=[]; q=None
    for i,ch in enumerate(s):
        if q:
            out.append(ch)
            if ch==q and (q=="'" or s[i-1]!="\\"): q=None
        elif ch in "\"'" and (i==0 or s[i-1] in " [,{:"):
            q=ch; out.append(ch)
        elif ch=="#" and (i==0 or s[i-1] in " \t"):
            break
        else: out.append(ch)
    return "".join(out).rstrip()

def _split_flow(s):
    parts=[]; depth=0; q=None; cur=""
    for i,ch in enumerate(s):
        if q:
            cur+=ch
            if ch==q: q=None
            continue
        if ch in "\"'" and cur.strip()=="" : q=ch; cur+=ch; continue
        if ch in "[{": depth+=1
        elif ch in "]}": depth-=1
        if ch=="," and depth==0: parts.append(cur); cur=""
        else: cur+=ch
    if cur.strip(): parts.append(cur)
    return [p.strip() for p in parts]

def scalar(s):
    s=s.strip()
    if s=="" : return None
    if s[0]=='"' and s.endswith('"') and len(s)>=2:
        return bytes(s[1:-1],"utf-8").decode("unicode_escape").encode("latin-1").decode("utf-8") if "\\" in s else s[1:-1]
    if s[0]=="'" and s.endswith("'") and len(s)>=2: return s[1:-1].replace("''","'")
    if s[0]=="[" and s.endswith("]"): return [scalar(x) for x in _split_flow(s[1:-1])]
    if s[0]=="{" and s.endswith("}"):
        d={}
        for x in _split_flow(s[1:-1]):
            k,_,v=x.partition(":"); d[scalar(k)]=scalar(v)
        return d
    if s in ("null","~","Null","NULL"): return None
    if s in ("true","True","TRUE"): return True
    if s in ("false","False","FALSE"): return False
    if re.fullmatch(r"[-+]?\d+",s): return int(s)
    if re.fullmatch(r"[-+]?(\d+\.\d*|\.\d+)([eE][-+]?\d+)?",s): return float(s)
    if s[0] in "|>&*": raise ValueError("mini_yaml: recurso YAML não suportado: "+s[:30])
    return s

_KEY=re.compile(r"""^((?:"[^"]*"|'[^']*'|[^:#'"\[\]{}][^:#]*?)):(?:\s+(.*)|$)""")

def loads(text):
    lines=[]
    for raw in text.splitlines():
        if raw.strip().startswith("---") and not lines: continue
        s=_strip_comment(raw)
        if not s.strip(): continue
        lines.append((len(s)-len(s.lstrip(" ")), s.strip()))
    pos=[0]
    def block(ind):
        if pos[0]>=len(lines): return None
        i,s=lines[pos[0]]
        if s.startswith("- ") or s=="-": return seq(i)
        return mapping(i)
    def mapping(ind, first=None):
        d={}
        if first is not None:
            k,v=first; d[k]=v
        while pos[0]<len(lines):
            i,s=lines[pos[0]]
            if i<ind or (i==ind and s.startswith("- ")): break
            if i>ind: raise ValueError(f"mini_yaml: indentação inesperada: {s[:40]}")
            m=_KEY.match(s)
            if not m: raise ValueError(f"mini_yaml: linha não reconhecida: {s[:60]}")
            k=scalar(m.group(1)); v=m.group(2)
            pos[0]+=1
            if v is None or v=="":
                if pos[0]<len(lines) and (lines[pos[0]][0]>ind or (lines[pos[0]][0]==ind and lines[pos[0]][1].startswith("- "))):
                    d[k]=block(lines[pos[0]][0])
                else: d[k]=None
            else: d[k]=scalar(v)
        return d
    def seq(ind):
        out=[]
        while pos[0]<len(lines):
            i,s=lines[pos[0]]
            if i!=ind or not (s.startswith("- ") or s=="-"): break
            body=s[1:].strip()
            if body=="":
                pos[0]+=1; out.append(block(lines[pos[0]][0]) if pos[0]<len(lines) and lines[pos[0]][0]>ind else None); continue
            m=_KEY.match(body)
            if m and not body.startswith(("[","{",'"',"'")) or (m and body.startswith(('"',"'")) and _KEY.match(body)):
                # item é um mapa: "- chave: valor" + chaves seguintes alinhadas em ind+2
                child=ind+2+(len(body)-len(body.lstrip()))
                lines[pos[0]]=(child, body)
                out.append(mapping(child))
            else:
                pos[0]+=1; out.append(scalar(body))
        return out
    return block(0) if lines else None

def load(path):
    with open(path,encoding="utf-8") as f: return loads(f.read())
