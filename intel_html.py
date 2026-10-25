"""intel_html.py — converte os dossiês (Markdown controlado) em páginas HTML autocontidas.

Sem dependências: um conversor para o subconjunto de Markdown que o build_intel.py gera
(títulos, parágrafos, listas, citações, tabelas, links, negrito, itálico, código, regra horizontal).
Cada página leva o CSS inline no visual "mesa de analista" do site (claro/escuro, impressão).
"""
import html, re

CSS = """
:root{--paper:#f3f0e8;--paper-2:#ebe7dc;--ink:#17150f;--ink-2:#4a463c;--ink-3:#68635a;--rule:#cfc9ba;--rule-2:#e0dacb;--signal:#b43c0e;--signal-ink:#fff;--seq-0:#f5ddcf;--seq-3:#b43c0e;
--serif:Georgia,"Iowan Old Style","Times New Roman",serif;--mono:ui-monospace,"SF Mono",Menlo,Consolas,"Liberation Mono",monospace;--sans:system-ui,-apple-system,"Segoe UI",Helvetica,Arial,sans-serif;color-scheme:light}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--paper:#131210;--paper-2:#1b1915;--ink:#ece8dd;--ink-2:#b9b4a6;--ink-3:#908b7d;--rule:#37332b;--rule-2:#27241e;--signal:#f0885a;--signal-ink:#131210;--seq-0:#3a2a21;--seq-3:#e07f4e;color-scheme:dark}}
:root[data-theme="dark"]{--paper:#131210;--paper-2:#1b1915;--ink:#ece8dd;--ink-2:#b9b4a6;--ink-3:#908b7d;--rule:#37332b;--rule-2:#27241e;--signal:#f0885a;--signal-ink:#131210;--seq-0:#3a2a21;--seq-3:#e07f4e;color-scheme:dark}
*{box-sizing:border-box}
body{margin:0;background:var(--paper);color:var(--ink);font:16px/1.65 var(--sans);-webkit-font-smoothing:antialiased}
a{color:var(--ink);text-decoration:underline;text-decoration-color:var(--signal);text-underline-offset:3px;overflow-wrap:anywhere}
a:hover{color:var(--signal)}
.wrap{max-width:1040px;margin:0 auto;padding:0 28px}
.bar{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap;padding:12px 0;border-bottom:1px solid var(--rule);font:600 11px/1 var(--mono);letter-spacing:.14em;text-transform:uppercase;color:var(--ink-2)}
.bar a{text-decoration:none;color:var(--ink-2)}.bar a:hover{color:var(--signal)}
.tools{display:inline-flex;gap:8px;flex-wrap:wrap}.tools button,.tools a.btn{white-space:nowrap}
.tools button,.tools a.btn{font:inherit;letter-spacing:inherit;text-transform:inherit;color:var(--ink-2);background:none;border:1px solid var(--rule);padding:6px 10px;cursor:pointer;text-decoration:none}
.tools button:hover,.tools a.btn:hover{border-color:var(--ink);color:var(--ink)}
main{padding:34px 0 60px}
h1{font:700 clamp(30px,5vw,50px)/1.05 var(--serif);letter-spacing:-.02em;margin:10px 0 18px;text-wrap:balance}
h2{font:700 24px/1.2 var(--serif);margin:42px 0 10px;padding-top:14px;border-top:1px solid var(--ink);text-wrap:balance}
h3{font:600 12px var(--mono);letter-spacing:.12em;text-transform:uppercase;color:var(--ink-2);margin:26px 0 8px}
p{margin:10px 0}
ul,ol{padding-left:22px;margin:10px 0}li{margin:5px 0}
blockquote{margin:14px 0;padding:12px 18px;border-left:3px solid var(--signal);background:var(--paper-2);font:17px/1.6 var(--serif)}
blockquote p{margin:6px 0}
code{font:12.5px var(--mono);background:var(--paper-2);padding:1px 5px;border:1px solid var(--rule-2)}
strong{color:var(--ink)}
em{color:var(--ink-2)}
hr{border:0;border-top:1px solid var(--rule);margin:30px 0}
.tw{overflow-x:auto;margin:12px 0}
table{width:100%;border-collapse:collapse;font-size:14px}
th{font:600 10.5px var(--mono);letter-spacing:.1em;text-transform:uppercase;color:var(--ink-3);text-align:left;padding:8px 12px 8px 0;border-bottom:1px solid var(--ink);vertical-align:bottom}
td{padding:9px 12px 9px 0;border-bottom:1px solid var(--rule);vertical-align:top;color:var(--ink-2)}
td.num,th.num{text-align:right;font-family:var(--mono);white-space:nowrap}
tr:hover td{background:var(--paper-2)}
.meta{border-left:3px solid var(--signal);background:var(--paper-2);padding:10px 14px;font-size:14px;color:var(--ink-2)}
.tlp{display:inline-block;font:700 11px var(--mono);letter-spacing:.1em;background:var(--ink);color:var(--paper);padding:2px 8px;margin-right:8px}
.strip{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));border-top:1px solid var(--ink);border-bottom:1px solid var(--rule);margin:22px 0}
.strip div{padding:14px 14px 12px;border-left:1px solid var(--rule)}.strip div:first-child{border-left:0;padding-left:0}
.strip b{display:block;font:600 30px/1 var(--mono);letter-spacing:-.03em}.strip span{display:block;margin-top:6px;font:600 10.5px var(--mono);letter-spacing:.1em;text-transform:uppercase;color:var(--ink-3)}
.bars{display:grid;gap:7px;margin:12px 0}
.br{display:grid;grid-template-columns:minmax(120px,190px) 1fr 64px;gap:12px;align-items:center;font-size:13.5px}
.br .t{height:10px;background:var(--rule-2);display:flex}.br .t i{display:block;height:100%;background:var(--seq-3)}.br .t i+i{background:var(--rule)}
.br b{font:600 12px var(--mono);text-align:right}
.toc{columns:2;column-gap:40px;font-size:14px;margin:16px 0;padding:12px 0;border-top:1px solid var(--rule);border-bottom:1px solid var(--rule)}
.toc a{display:block;padding:2px 0;text-decoration:none}.toc a:hover{color:var(--signal)}
footer{border-top:1px solid var(--ink);padding:18px 0 40px;font:12px var(--mono);color:var(--ink-3)}
input.q{width:100%;font:15px var(--sans);color:var(--ink);background:transparent;border:0;border-bottom:1px solid var(--ink);padding:8px 2px;outline:none;margin:8px 0 4px}
input.q:focus{border-bottom-color:var(--signal)}
.pbar{display:inline-block;width:60px;height:6px;background:var(--seq-0);vertical-align:middle;margin-right:6px}.pbar i{display:block;height:100%;background:var(--signal)}
.al{display:block;font:12px var(--mono);color:var(--ink-3)}
:focus-visible{outline:2px solid var(--signal);outline-offset:2px}
main p,main li,main blockquote,main h1,main h2,main h3,.br span{overflow-wrap:anywhere}code{overflow-wrap:anywhere}
@media(max-width:760px){.wrap{padding:0 18px}.strip b{font-size:clamp(20px,6.5vw,30px)}.strip{grid-template-columns:1fr 1fr}.strip div{min-width:0;padding:12px 10px}.strip div:nth-child(odd){border-left:0;padding-left:0}.bar{letter-spacing:.08em}h1{font-size:clamp(28px,8vw,46px)}.toc{columns:1}.br{grid-template-columns:100px 1fr 50px}h2{font-size:21px}}
@media print{.tools,.toc,footer .nav{display:none!important}body{background:#fff;color:#000;font-size:11pt}a{color:#000}h2{break-after:avoid}tr,li,blockquote{break-inside:avoid}.wrap{max-width:none;padding:0}}
"""
THEME_JS = """<script>try{const t=localStorage.getItem('dr_theme');if(t)document.documentElement.dataset.theme=t;}catch(e){}
function toggleTheme(){const r=document.documentElement;const d=r.dataset.theme?r.dataset.theme==='dark':matchMedia('(prefers-color-scheme: dark)').matches;r.dataset.theme=d?'light':'dark';try{localStorage.setItem('dr_theme',r.dataset.theme)}catch(e){}}</script>"""
FAVICON = "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect width='32' height='32' fill='%2317150f'/%3E%3Crect x='6' y='13' width='20' height='6' fill='%23b43c0e'/%3E%3C/svg%3E"

def _inline(s):
    s = html.escape(s, quote=False)
    s = re.sub(r"`([^`]+)`", r"<code>\1</code>", s)
    s = re.sub(r"\[([^\]]+)\]\(([^)\s]+)\)", lambda m: f'<a href="{m.group(2).replace(chr(34), "%22")}"' + (' target="_blank" rel="noopener"' if m.group(2).startswith("http") else "") + f">{m.group(1)}</a>", s)
    s = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", s)
    s = re.sub(r"(?<![\w/])_([^_\n]+?)_(?![\w])", r"<em>\1</em>", s)
    return s.replace("\\|", "|")

def _cells(line):
    parts = re.split(r"(?<!\\)\|", line.strip().strip("|")) if line.strip().startswith("|") else []
    return [p.strip() for p in parts]

def md_to_html(md, slugger=None):
    out, lines, i = [], md.split("\n"), 0
    toc = []
    def sid(t): return re.sub(r"[^a-z0-9]+", "-", re.sub(r"<[^>]+>", "", t).lower()).strip("-")[:60]
    while i < len(lines):
        ln = lines[i]
        if not ln.strip(): i += 1; continue
        if ln.startswith("# "): out.append(f"<h1>{_inline(ln[2:])}</h1>"); i += 1; continue
        if ln.startswith("## "):
            t = _inline(ln[3:]); k = sid(ln[3:]); toc.append((k, re.sub(r"<[^>]+>", "", t))); out.append(f'<h2 id="{k}">{t}</h2>'); i += 1; continue
        if ln.startswith("### "): out.append(f"<h3>{_inline(ln[4:])}</h3>"); i += 1; continue
        if ln.strip() == "---": out.append("<hr>"); i += 1; continue
        if ln.startswith(">"):
            paras, cur = [], []
            while i < len(lines) and lines[i].startswith(">"):
                t = lines[i][1:].strip(); i += 1
                if t: cur.append(t)
                elif cur: paras.append(" ".join(cur)); cur = []
            if cur: paras.append(" ".join(cur))
            out.append("<blockquote>" + "".join(f"<p>{_inline(p)}</p>" for p in paras) + "</blockquote>"); continue
        if ln.startswith("|") and i + 1 < len(lines) and re.match(r"^\|[\s:|-]+\|$", lines[i + 1].strip()):
            head = _cells(ln); align = _cells(lines[i + 1]); i += 2; rows = []
            while i < len(lines) and lines[i].startswith("|"):
                rows.append(_cells(lines[i])); i += 1
            num = [a.endswith(":") for a in align]
            th = "".join(f'<th{" class=num" if num[j] else ""}>{_inline(h)}</th>' for j, h in enumerate(head))
            tb = "".join("<tr>" + "".join(f'<td{" class=num" if j < len(num) and num[j] else ""}>{_inline(c)}</td>' for j, c in enumerate(r)) + "</tr>" for r in rows)
            out.append(f'<div class="tw"><table><thead><tr>{th}</tr></thead><tbody>{tb}</tbody></table></div>'); continue
        if re.match(r"^- ", ln):
            items = []
            while i < len(lines) and re.match(r"^- ", lines[i]):
                items.append(lines[i][2:]); i += 1
            out.append("<ul>" + "".join(f"<li>{_inline(x)}</li>" for x in items) + "</ul>"); continue
        if re.match(r"^\d+\. ", ln):
            items = []
            while i < len(lines) and re.match(r"^\d+\. ", lines[i]):
                items.append(re.sub(r"^\d+\. ", "", lines[i])); i += 1
            out.append("<ol>" + "".join(f"<li>{_inline(x)}</li>" for x in items) + "</ol>"); continue
        buf = []
        while i < len(lines) and lines[i].strip() and not re.match(r"^(#|>|\||- |\d+\. |---)", lines[i]):
            buf.append(lines[i].rstrip()); i += 1
        if buf: out.append("<p>" + "<br>".join(_inline(b.rstrip(" ")) for b in buf) + "</p>")
        else: i += 1
    return "\n".join(out), toc

def page(title, body, desc="", nav_back="", site="", extra_tools=""):
    back = f'<a href="{nav_back}">← índice dos dossiês</a>' if nav_back else '<span>Detection Rules / dossiês de inteligência</span>'
    return f"""<!doctype html>
<html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html.escape(title)}</title><meta name="description" content="{html.escape(desc)}"><link rel="icon" href="{FAVICON}">
{THEME_JS}<style>{CSS}</style></head>
<body><div class="wrap">
<div class="bar">{back}<span class="tools">{extra_tools}<button type="button" onclick="window.print()">Imprimir / PDF</button><button type="button" onclick="toggleTheme()">Tema</button></span></div>
<main>{body}</main>
<footer><span class="nav"><a href="{site}">Detection Rules</a> · </span>Fontes abertas: MITRE ATT&amp;CK® (© The MITRE Corporation, uso com atribuição), Atomic Red Team, EVTX-to-MITRE-Attack, EVTX-ATTACK-SAMPLES, APT &amp; CyberCriminal Campaign Collections. TLP:CLEAR.</footer>
</div></body></html>"""
