/* ============================================================
   graph.js — grafo de conhecimento: ATT&CK v20 × regras × Atomic Red Team × EVTX × grupos APT × recursos
   Dados: data/graph/attack.json e data/graph/resources.json (gerados por build_graph.py)
   ============================================================ */
const G = { A:null, RES:null, loading:null, sel:null, mode:'matrix' };
const GH = {
  evtx_mitre:'https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/',
  evtx_samples:'https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/',
  apt:'https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/',
  atomic:t=>`https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/${t}/${t}.md`,
};
const encPath = p => p.split('/').map(encodeURIComponent).join('/');

async function loadGraph(){
  if(G.A) return G;
  if(!G.loading) G.loading=Promise.all([
    fetch('data/graph/attack.json').then(r=>{ if(!r.ok) throw new Error('attack.json HTTP '+r.status); return r.json(); }),
    fetch('data/graph/resources.json').then(r=>r.ok?r.json():{items:[]}),
  ]).then(([a,res])=>{ G.A=a; G.RES=res; return G; });
  return G.loading;
}
const T = id => G.A?.techniques[id];
const tacName = s => (G.A.tactics.find(t=>t.short===s)||{}).n || s;
const heatClass = n => n<=0?'h0': n<5?'h1': n<20?'h2': n<80?'h3':'h4';
const parentsOf = () => Object.entries(G.A.techniques).filter(([id,x])=>!x.sub);
const subsOf = id => Object.entries(G.A.techniques).filter(([k,x])=>x.sub && k.startsWith(id+'.'));
const totalRules = (id,x) => x.rt + (x.rsub||0);

/* ---------------- view principal ---------------- */
async function renderGraph(){
  const v=$('#v-graph');
  v.innerHTML='<div class="loading">Carregando o grafo ATT&CK (≈3 MB)…<div class="bar"><i style="width:55%"></i></div></div>';
  try{ await loadGraph(); }catch(e){ v.innerHTML=`<div class="note warn"><span class="ni">▸</span><div>Não consegui carregar o grafo: ${esc(e.message)}. Rode <code>python3 build_graph.py</code> para gerar <code>data/graph/</code>.</div></div>`; return; }
  const s=G.A.stats;
  v.innerHTML=`
  <div class="eyebrow">Grafo de conhecimento · ATT&CK v${esc(G.A.version)}</div>
  <h1 class="sec">Quem ataca, como ataca e <span class="g">o que detecta</span></h1>
  <p class="sub">Dos alertas aos grupos de ameaça: cada técnica do ATT&CK ligada às regras do catálogo, aos grupos que a usam, aos testes do Atomic Red Team que a reproduzem, a logs reais de ataque (EVTX) e às ferramentas para investigá-la. Clique numa técnica para ver seus relacionamentos.</p>
  <div class="grid g4" style="grid-template-columns:repeat(auto-fit,minmax(150px,1fr))">
    <div class="stat"><div class="v">${s.techniques_with_rules}<span style="font-size:18px;color:var(--ink-3)">/${s.techniques}</span></div><div class="l">técnicas com regra</div></div>
    <div class="stat"><div class="v">${s.groups}</div><div class="l">grupos APT</div></div>
    <div class="stat"><div class="v">${s.atomic_tests.toLocaleString('pt-BR')}</div><div class="l">testes Atomic</div></div>
    <div class="stat"><div class="v">${(s.evtx_explicit+s.evtx_inferred).toLocaleString('pt-BR')}</div><div class="l">amostras EVTX</div></div>
    <div class="stat"><div class="v">${s.apt_reports_linked.toLocaleString('pt-BR')}</div><div class="l">relatórios APT ligados</div></div>
    <div class="stat"><div class="v">${(G.RES.items||[]).length}</div><div class="l">ferramentas e materiais</div></div>
  </div>
  <div class="toolbar" style="margin-top:18px">
    <button class="btn ${G.mode==='attrib'?'p':''}" data-gm="attrib">Atribuição por TTP${(V.state.case?.items?.length)?' · '+V.state.case.items.length:''}</button>
    <button class="btn ${G.mode==='flows'?'p':''}" data-gm="flows">Fluxos (Sankey)</button>
    <button class="btn ${G.mode==='matrix'?'p':''}" data-gm="matrix">Matriz de cobertura</button>
    <button class="btn ${G.mode==='gaps'?'p':''}" data-gm="gaps">Lacunas prioritárias</button>
    <button class="btn ${G.mode==='groups'?'p':''}" data-gm="groups">Grupos APT</button>
    <button class="btn ${G.mode==='resources'?'p':''}" data-gm="resources">Ferramentas e materiais</button>
    <span style="margin-left:auto;display:flex;gap:6px;flex-wrap:wrap">
      <a class="btn sm" href="data/graph/graph.graphml" download>⬇ GraphML</a>
      <a class="btn sm" href="data/graph/graph.json" download>⬇ grafo JSON</a>
      <a class="btn sm" href="data/graph/navigator-layer.json" download title="Abra em mitre-attack.github.io/attack-navigator">⬇ camada Navigator</a>
    </span>
  </div>
  <div class="field" style="margin:10px 0 0"><input class="search" id="gq" placeholder="Buscar técnica, grupo ou ferramenta: T1003, lsass, APT28, Turla, Volatility…"></div>
  <div id="gsearch"></div>
  <div id="gbody" style="margin-top:18px"></div>`;
  $$('[data-gm]',v).forEach(b=>b.onclick=()=>{ G.mode=b.dataset.gm; renderGraph(); });
  $('#gq').oninput=e=>graphSearch(e.target.value);
  ({matrix:renderMatrix,gaps:renderGaps,groups:renderGroups,resources:renderResources,flows:()=>renderFlows(),attrib:()=>renderAttrib()})[G.mode]();
}

/* ---------------- busca unificada ---------------- */
function graphSearch(q){
  q=q.trim().toLowerCase(); const box=$('#gsearch'); if(q.length<2){ box.innerHTML=''; return; }
  const tech=Object.entries(G.A.techniques).filter(([id,x])=>id.toLowerCase().startsWith(q)||x.n.toLowerCase().includes(q)).slice(0,8);
  const grp=G.A.groups.filter(g=>g.n.toLowerCase().includes(q)||g.al.some(a=>a.toLowerCase().includes(q))||(g.id||'').toLowerCase()===q).slice(0,6);
  const res=(G.RES.items||[]).filter(r=>r.n.toLowerCase().includes(q)).slice(0,6);
  box.innerHTML=`<div class="rlist" style="margin-top:8px">${
    tech.map(([id,x])=>`<div class="row" onclick="openTech('${id}')"><div class="t">${id} · ${esc(x.n)}</div><span class="tag">técnica</span><div class="m"><span>${totalRules(id,x)} regras</span><span>${x.g.length} grupos</span><span>${x.at.length} testes Atomic</span></div></div>`).join('')+
    grp.map(g=>`<div class="row" onclick="openGroup('${g.id}')"><div class="t">${esc(g.n)} <span class="id">${g.id}</span></div><span class="tag">grupo</span><div class="m"><span>${g.t.length} técnicas</span><span>${esc(g.al.slice(0,4).join(', '))}</span></div></div>`).join('')+
    res.map(r=>`<div class="row" onclick="window.open('${esc(r.l)}','_blank','noopener')"><div class="t">${esc(r.n)}</div><span class="tag">${esc(r.ph)}</span><div class="m"><span>${esc(r.cat)}</span></div></div>`).join('')
  || '<div class="empty">Nada encontrado.</div>'}</div>`;
}

/* ---------------- matriz de cobertura ---------------- */
function renderMatrix(){
  const cols=G.A.tactics.map(t=>({t, items:parentsOf().filter(([id,x])=>x.ta.includes(t.short)).sort((a,b)=>totalRules(b[0],b[1])-totalRules(a[0],a[1]))}));
  $('#gbody').innerHTML=`
  <div class="legend-row"><span class="note" style="margin:0;padding:6px 10px">Cor = nº de regras públicas que citam a técnica (incluindo subtécnicas). <b>A</b> = há testes Atomic · <b>E</b> = há log real EVTX · <b>!</b> = usada por grupos e sem nenhuma regra.</span>
   <span class="heatkey"><i class="heat h0">0</i><i class="heat h1">1–4</i><i class="heat h2">5–19</i><i class="heat h3">20–79</i><i class="heat h4">80+</i></span></div>
  <div class="gwrap"><div class="matrix">${cols.map(c=>`<div class="mcol"><div class="mxtitle" title="${esc(c.t.d)}">${esc(c.t.n)}<small>${c.t.id} · ${c.items.length}</small></div>
    ${c.items.map(([id,x])=>{ const n=totalRules(id,x); const subA=subsOf(id).some(([k,s])=>s.at.length)||x.at.length; const subE=subsOf(id).some(([k,s])=>s.ev.length)||x.ev.length;
      return `<button class="mcell ${heatClass(n)}" onclick="openTech('${id}')" title="${id} ${esc(x.n)} — ${n} regras, ${x.g.length} grupos"><b>${id}</b><span>${esc(x.n)}</span><em>${n}${subA?' · A':''}${subE?' · E':''}${(n===0&&x.g.length)?' · !':''}</em></button>`; }).join('')}
  </div>`).join('')}</div></div>
  <p class="note">Mapeamento: ${G.A.stats.rules_mapped.toLocaleString('pt-BR')} regras citam técnicas. IDs antigos são convertidos pelas revogações oficiais do ATT&CK (ex.: T1562 → T1685, T1086 → T1059.001). Citações de técnicas ICS (T0xxx) ficam fora desta matriz Enterprise.</p>`;
}

/* ---------------- lacunas: técnicas mais usadas por adversários com pouca detecção ---------------- */
function renderGaps(){
  const rows=Object.entries(G.A.techniques).map(([id,x])=>({id,x,n:totalRules(id,x),g:x.g.length}))
    .filter(r=>r.g>0).map(r=>({...r,score:r.g/(1+r.n)})).sort((a,b)=>b.score-a.score).slice(0,40);
  $('#gbody').innerHTML=`
  <div class="feynman"><div class="lbl">COMO LER ESTA LISTA</div><p>Se muitos grupos usam uma técnica e quase nenhuma regra pública a detecta, ali está um <span class="em">ponto cego da comunidade</span>. É o melhor lugar para escrever sua próxima regra — e, se você publicar, o melhor lugar para contribuir com o SigmaHQ ou com o ATT&CK.</p></div>
  <table class="tbl"><tr><th>Técnica</th><th>Táticas</th><th class="num">Grupos que usam</th><th class="num">Regras</th><th class="num">Atomic</th><th class="num">EVTX</th><th></th></tr>
  ${rows.map(r=>`<tr style="cursor:pointer" onclick="openTech('${r.id}')"><td><b>${r.id}</b> ${esc(r.x.n)}</td><td>${r.x.ta.map(tacName).join(', ')}</td><td class="num">${r.g}</td><td class="num">${r.n===0?'<span class="gap">0</span>':r.n}</td><td class="num">${r.x.at.length||'—'}</td><td class="num">${r.x.ev.length||'—'}</td><td><button class="btn sm" onclick="event.stopPropagation();forgeFromTech('${r.id}')">criar regra</button></td></tr>`).join('')}</table>
  <p class="note">Ordenação: grupos ÷ (1 + regras). Considera só as regras deste catálogo público, não as do seu ambiente.</p>`;
}

/* ---------------- grupos ---------------- */
function groupCoverage(g){ const ts=g.t.filter(id=>T(id)); const cov=ts.filter(id=>T(id).rt>0); return {total:ts.length,cov:cov.length,pct:ts.length?Math.round(cov.length/ts.length*100):0}; }
function renderGroups(){
  const gs=G.A.groups.map(g=>({g,c:groupCoverage(g)})).sort((a,b)=>b.g.t.length-a.g.t.length);
  $('#gbody').innerHTML=`
  <p class="sub" style="margin-top:0">Defesa orientada a ameaça: para cada grupo, quanto do que ele faz o catálogo público consegue ver. Clique para ver as técnicas descobertas e os relatórios.</p>
  <table class="tbl"><tr><th>Grupo</th><th>Também conhecido como</th><th class="num">Técnicas</th><th>Cobertura pública</th><th class="num">Relatórios</th></tr>
  ${gs.map(({g,c})=>`<tr style="cursor:pointer" onclick="openGroup('${g.id}')"><td><b>${esc(g.n)}</b> <span class="id">${g.id}</span></td><td style="font-size:13px">${esc(g.al.slice(0,4).join(', '))}</td><td class="num">${c.total}</td><td><span class="pbar"><i style="width:${c.pct}%"></i></span><span class="pnum">${c.pct}%</span></td><td class="num">${g.rep.length||'—'}</td></tr>`).join('')}</table>`;
}
window.openGroup=async function(gid){
  await loadGraph(); const g=G.A.groups.find(x=>x.id===gid); if(!g) return; const c=groupCoverage(g);
  const unc=g.t.filter(id=>T(id)&&T(id).rt===0); const cov=g.t.filter(id=>T(id)&&T(id).rt>0).sort((a,b)=>T(b).rt-T(a).rt);
  openModal(`<div class="mhead"><div style="flex:1"><div class="eyebrow">Grupo · ${g.id}</div><h2>${esc(g.n)}</h2><div class="pill-row">${g.al.map(a=>`<span class="tag">${esc(a)}</span>`).join('')}</div></div><button class="x" onclick="closeModal()">✕</button></div>
  <div class="mbody"><p style="color:var(--ink-2)">${esc(g.d)}</p>
   <div class="grid" style="margin-top:10px;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:0 24px"><div class="stat"><div class="v">${c.total}</div><div class="l">técnicas atribuídas</div></div><div class="stat"><div class="v">${c.pct}%</div><div class="l">com regra pública</div></div><div class="stat"><div class="v">${unc.length}</div><div class="l">sem nenhuma regra</div></div></div>
   ${egoGroupSVG(g)}
   <h3 class="h">Técnicas deste grupo sem regra pública (${unc.length})</h3>
   ${unc.length?`<div class="rlist">${unc.map(id=>`<div class="row" onclick="openTech('${id}')"><div class="t">${id} · ${esc(T(id).n)}</div><span class="tag r">sem regra</span><div class="m"><span>${T(id).ta.map(tacName).join(', ')}</span><span>${T(id).at.length} testes Atomic</span></div></div>`).join('')}</div>`:'<p class="empty">Todas as técnicas atribuídas têm ao menos uma regra pública.</p>'}
   <h3 class="h">Técnicas cobertas (${cov.length})</h3><div class="pill-row">${cov.map(id=>`<a class="tag" href="#" onclick="openTech('${id}');return false" title="${esc(T(id).n)}">${id} · ${T(id).rt}</a>`).join('')}</div>
   <h3 class="h">Relatórios públicos (${g.rep.length})</h3>
   ${g.rep.length?`<div class="rlist">${g.rep.map(r=>`<div class="row" onclick="window.open('${GH.apt+encPath(r.p)}','_blank','noopener')"><div class="t">${esc(r.t)}</div><span class="tag">${esc(r.y)}</span><div class="m"><span>${esc(r.f)}</span><span>ligado pelo nome “${esc(r.via)}” (inferido)</span></div></div>`).join('')}</div>`:'<p class="empty">Nenhum relatório da coleção CyberMonitor ligado a este grupo pelo nome.</p>'}
   <div class="toolbar"><a class="btn" href="https://attack.mitre.org/groups/${g.id}/" target="_blank" rel="noopener">Página no ATT&CK ↗</a></div>
  </div>`);
};

/* ---------------- técnica: ego-grafo ---------------- */
window.openTech=async function(tid){
  await loadGraph(); const x=T(tid); if(!x) return;
  const subs=subsOf(tid); const parent=x.sub?tid.split('.')[0]:null; const n=totalRules(tid,x);
  const groups=x.g.map(i=>G.A.groups[i]); const sw=x.s.map(i=>G.A.software[i]); const mit=x.m.map(i=>G.A.mitigations[i]);
  const res=(G.RES.items||[]).filter(r=>r.ta.some(t=>x.ta.includes(t)) || r.f.some(f=>x.rc[f]));
  openModal(`<div class="mhead"><div style="flex:1"><div class="eyebrow">Técnica · ${x.ta.map(tacName).join(' · ')}</div><h2>${tid} ${esc(x.n)}</h2>
    <div class="pill-row">${x.pl.map(p=>`<span class="tag">${esc(p)}</span>`).join('')}${parent?`<a class="tag a" href="#" onclick="openTech('${parent}');return false">↑ ${parent} ${esc(T(parent)?.n||'')}</a>`:''}</div></div><button class="x" onclick="closeModal()">✕</button></div>
  <div class="mbody">
   <p style="color:var(--ink-2)">${esc(x.d)}</p>
   <div class="grid" style="margin-top:10px;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:0 24px"><div class="stat"><div class="v">${n}</div><div class="l">regras públicas</div></div><div class="stat"><div class="v">${x.g.length}</div><div class="l">grupos usam</div></div><div class="stat"><div class="v">${x.at.length}</div><div class="l">testes Atomic</div></div><div class="stat"><div class="v">${x.ev.length}</div><div class="l">logs EVTX</div></div></div>
   <h3 class="h">Relacionamentos</h3>${egoTechSVG(tid,x,groups,subs)}
   <div class="mtabs"><button class="mtab on" data-tp="rules">Regras</button><button class="mtab" data-tp="det">Como o ATT&CK detecta</button><button class="mtab" data-tp="test">Provar que funciona</button><button class="mtab" data-tp="adv">Adversários</button><button class="mtab" data-tp="tools">Ferramentas</button></div>
   <div class="mpane on" id="tp-rules">${techRulesPane(tid,x,subs)}</div>
   <div class="mpane" id="tp-det">${techDetPane(x)}</div>
   <div class="mpane" id="tp-test">${techTestPane(tid,x)}</div>
   <div class="mpane" id="tp-adv">${techAdvPane(groups,sw,mit,x)}</div>
   <div class="mpane" id="tp-tools">${resourcesList(res.slice(0,30), 'Ferramentas e materiais da planilha relacionados às táticas e formatos desta técnica.')}</div>
   <div class="toolbar"><button class="btn a" onclick="caseAddTech('${tid}')">+ caso</button><button class="btn p" onclick="closeModal();A.q='';A.tech='${tid}';A.page=0;go('arsenal')">Ver as ${n} regras no Arsenal</button><button class="btn" onclick="closeModal();forgeFromTech('${tid}')">Criar regra para esta técnica</button><a class="btn" href="https://attack.mitre.org/techniques/${tid.replace('.','/')}/" target="_blank" rel="noopener">ATT&CK ↗</a></div>
  </div>`);
  $$('[data-tp]','#mbox').forEach(b=>b.onclick=()=>{ $$('[data-tp]','#mbox').forEach(z=>z.classList.remove('on')); b.classList.add('on'); $$('#mbox .mpane').forEach(p=>p.classList.remove('on')); $('#tp-'+b.dataset.tp).classList.add('on'); });
};
function techRulesPane(tid,x,subs){
  const fm=Object.entries(x.rc).sort((a,b)=>b[1]-a[1]);
  return `${fm.length?`<div class="bars">${fm.map(([f,c])=>`<div class="barrow" style="cursor:pointer" onclick="closeModal();A.q='';A.tech='${tid}';A.fmt.clear();A.fmt.add('${f}');A.page=0;go('arsenal')"><span class="lb">${FMT_PT[f]||f}</span><div class="bb"><i style="width:${c/fm[0][1]*100}%"></i></div><span class="nn">${c}</span></div>`).join('')}</div>`:'<div class="note warn"><span class="ni">!</span><div><b>Nenhuma regra pública cita esta técnica diretamente.</b> Veja a aba <i>Como o ATT&CK detecta</i> para as fontes de log e crie a regra na Forja.</div></div>'}
  ${x.ex.length?`<h3 class="h">Exemplos</h3><div class="rlist">${x.ex.map(e=>`<div class="row" onclick="openRuleByUid('${e.u}')"><div class="t">${esc(e.t)}</div><span class="sev ${sevClass(e.v)}">${SEV_PT[e.v]||'—'}</span><div class="m"><span class="src">${esc(e.s)}</span><span class="tag">${FMT_PT[e.f]||e.f}</span></div></div>`).join('')}</div>`:''}
  ${subs.length?`<h3 class="h">Subtécnicas (${subs.length})</h3><div class="pill-row">${subs.map(([k,s])=>`<a class="tag ${s.rt?'':'r'}" href="#" onclick="openTech('${k}');return false" title="${esc(s.n)}">${k} · ${s.rt}</a>`).join('')}</div>`:''}`;
}
function techDetPane(x){
  if(!x.det.length) return '<p class="empty">O ATT&CK v20 não publica estratégia de detecção para esta técnica.</p>';
  return x.det.map(d=>`<div class="card"><div class="eyebrow">${esc(d.id||'')}</div><h3 class="h">${esc(d.n)}</h3>
   ${d.an.map(a=>`<div style="margin:10px 0 14px"><div class="pill-row">${a.pl.map(p=>`<span class="tag">${esc(p)}</span>`).join('')}</div><p style="font-size:14px">${esc(a.d)}</p>
   ${a.logs.length?`<table class="tbl"><tr><th>Componente de dados</th><th>Fonte</th><th>Canal / evento</th></tr>${a.logs.map(l=>`<tr><td>${esc(l.dc)}</td><td><code>${esc(l.src)}</code></td><td><code>${esc(l.ch)}</code></td></tr>`).join('')}</table>`:''}</div>`).join('')}</div>`).join('')
   +'<p class="note">Fonte: estratégias de detecção e analíticas oficiais do MITRE ATT&CK v20. Use a coluna "Canal / evento" para conferir se a sua coleta cobre a técnica.</p>';
}
function techTestPane(tid,x){
  return `<div class="feynman"><div class="lbl">COMO PROVAR QUE A REGRA FUNCIONA</div><p>Rode um <span class="em">teste Atomic</span> num laboratório isolado e confira se a regra dispara. Sem laboratório, carregue um <span class="em">log EVTX real</span> do ataque no seu SIEM (ou no Hayabusa/Chainsaw) e veja se a regra pega.</p></div>
  <h3 class="h">Testes Atomic Red Team (${x.at.length})</h3>
  ${x.at.length?`<table class="tbl"><tr><th>Teste</th><th>Plataformas</th><th>Executor</th></tr>${x.at.map(a=>`<tr><td>${esc(a.n)}</td><td>${esc(a.p.join(', '))}</td><td><code>${esc(a.e)}</code></td></tr>`).join('')}</table><div class="toolbar"><a class="btn" href="${GH.atomic(tid)}" target="_blank" rel="noopener">Ver os testes no Atomic Red Team ↗</a></div>`:'<p class="empty">Sem teste Atomic para esta técnica exata.</p>'}
  <p class="note">Só os nomes e metadados dos testes ficam aqui; os comandos estão no repositório oficial. Execute apenas em laboratório isolado e autorizado.</p>
  <h3 class="h">Logs reais de ataque — EVTX (${x.ev.length})</h3>
  ${x.ev.length?`<div class="rlist">${x.ev.map(e=>`<div class="row" onclick="window.open('${(e.r.includes('mdecrevoisier')?GH.evtx_mitre:GH.evtx_samples)+encPath(e.p)}','_blank','noopener')"><div class="t">${esc(e.n)}</div><span class="tag ${e.c==='explícito'?'a':''}">${esc(e.c)}</span><div class="m"><span class="src">${esc(e.r)}</span></div></div>`).join('')}</div><p class="note"><b>explícito</b> = o repositório organiza a amostra por esta técnica. <b>inferido</b> = ligado por palavra-chave no nome do arquivo; confira antes de usar.</p>`:'<p class="empty">Sem amostra EVTX ligada a esta técnica.</p>'}`;
}
function techAdvPane(groups,sw,mit,x){
  return `<h3 class="h">Grupos que usam (${groups.length})</h3>${groups.length?`<div class="pill-row">${groups.sort((a,b)=>b.rep.length-a.rep.length).map(g=>`<a class="tag" href="#" onclick="openGroup('${g.id}');return false">${esc(g.n)}${g.rep.length?' · '+g.rep.length+' rel.':''}</a>`).join('')}</div>`:'<p class="empty">Nenhum grupo atribuído no ATT&CK.</p>'}
  <h3 class="h">Malware e ferramentas (${sw.length})</h3>${sw.length?`<div class="pill-row">${sw.slice(0,80).map(s=>`<a class="tag" href="https://attack.mitre.org/software/${s.id}/" target="_blank" rel="noopener">${esc(s.n)}</a>`).join('')}${sw.length>80?`<span class="tag">+${sw.length-80}</span>`:''}</div>`:'<p class="empty">—</p>'}
  <h3 class="h">Campanhas (${x.c.length})</h3>${x.c.length?`<div class="pill-row">${x.c.map(i=>G.A.campaigns[i]).map(c=>`<a class="tag" href="https://attack.mitre.org/campaigns/${c.id}/" target="_blank" rel="noopener">${esc(c.n)}</a>`).join('')}</div>`:'<p class="empty">—</p>'}
  <h3 class="h">Mitigações (${mit.length})</h3>${mit.length?`<div class="pill-row">${mit.map(m=>`<a class="tag" href="https://attack.mitre.org/mitigations/${m.id}/" target="_blank" rel="noopener">${m.id} · ${esc(m.n)}</a>`).join('')}</div>`:'<p class="empty">—</p>'}`;
}

/* ---------------- SVG: ego-grafo da técnica ---------------- */
function egoTechSVG(tid,x,groups,subs){
  const W=1060, colX=[130,330,510,690,860];
  const left=groups.slice().sort((a,b)=>b.rep.length-a.rep.length).slice(0,10).map(g=>({k:'g',id:g.id,l:g.n}));
  if(groups.length>10) left.push({k:'more',l:`+${groups.length-10} grupos`});
  const tacs=x.ta.map(s=>({k:'ta',id:s,l:tacName(s)}));
  const fmts=Object.entries(x.rc).sort((a,b)=>b[1]-a[1]).slice(0,9).map(([f,c])=>({k:'f',id:f,l:`${FMT_PT[f]||f} · ${c}`}));
  const right2=[ {k:'at',l:`${x.at.length} testes Atomic`,on:x.at.length}, {k:'ev',l:`${x.ev.length} logs EVTX`,on:x.ev.length}, {k:'m',l:`${x.m.length} mitigações`,on:x.m.length}, {k:'s',l:`${x.s.length} softwares`,on:x.s.length} ];
  const subN=subs.slice(0,8).map(([k,s])=>({k:'sub',id:k,l:`${k} · ${s.rt}`}));
  const colsData=[left,tacs.concat(subN.length?[]:[]),[{k:'c',l:`${tid}`,sub:x.n}],fmts.length?fmts:[{k:'none',l:'sem regras'}],right2];
  const rows=Math.max(...colsData.map(c=>c.length),subN.length+tacs.length,4);
  const H=Math.max(220, rows*30+60);
  const y=(i,n)=>H/2+(i-(n-1)/2)*30;
  const pos=[]; let edges='';
  const nodeSvg=(c,i,n,d)=>{ const yy=y(i,n), xx=colX[c]; pos.push({c,yy,xx});
    const click=d.k==='g'?`openGroup('${d.id}')`: d.k==='sub'?`openTech('${d.id}')`: d.k==='f'?`closeModal();A.q='';A.tech='${tid}';A.fmt.clear();A.fmt.add('${d.id}');A.page=0;go('arsenal')`: d.k==='at'||d.k==='ev'?`document.querySelector('[data-tp=test]').click()`: d.k==='m'||d.k==='s'?`document.querySelector('[data-tp=adv]').click()`:'';
    const cls=`node ${d.k==='c'?'center':''} ${(d.on===0||d.k==='none')?'dim':''}`;
    const anchor=c<2?'end':c===2?'middle':'start'; const tx=c<2?-10:c===2?0:10;
    return `<g class="${cls}" ${click?`onclick="${click}" tabindex="0" role="button"`:''}><circle class="mk" cx="${xx}" cy="${yy}" r="${d.k==='c'?9:5}"/><text x="${xx+tx}" y="${yy+(d.k==='c'?-16:4)}" text-anchor="${anchor}">${esc(d.l.length>34?d.l.slice(0,33)+'…':d.l)}</text>${d.sub?`<text x="${xx}" y="${yy+26}" text-anchor="middle" class="subt">${esc(d.sub.length>40?d.sub.slice(0,39)+'…':d.sub)}</text>`:''}</g>`; };
  const cy=H/2, cx=colX[2];
  const curve=(x1,y1,x2,y2,on=true)=>`<path class="edge ${on?'on2':''}" d="M${x1},${y1} C${(x1+x2)/2},${y1} ${(x1+x2)/2},${y2} ${x2},${y2}"/>`;
  left.forEach((d,i)=>edges+=curve(colX[0],y(i,left.length),cx,cy));
  const mid=tacs.concat(subN);
  mid.forEach((d,i)=>edges+=curve(colX[1],y(i,mid.length),cx,cy));
  const r1=fmts.length?fmts:[{k:'none',l:'sem regras'}]; r1.forEach((d,i)=>edges+=curve(cx,cy,colX[3],y(i,r1.length),d.k!=='none'));
  right2.forEach((d,i)=>edges+=curve(cx,cy,colX[4],y(i,right2.length),!!d.on));
  let nodes='';
  left.forEach((d,i)=>nodes+=nodeSvg(0,i,left.length,d));
  mid.forEach((d,i)=>nodes+=nodeSvg(1,i,mid.length,d));
  nodes+=nodeSvg(2,0,1,{k:'c',l:tid,sub:x.n});
  r1.forEach((d,i)=>nodes+=nodeSvg(3,i,r1.length,d));
  right2.forEach((d,i)=>nodes+=nodeSvg(4,i,right2.length,d));
  const heads=['GRUPOS','TÁTICA · SUBTÉCNICAS','TÉCNICA','REGRAS POR FORMATO','VALIDAÇÃO E DEFESA'];
  return `<div class="gwrap"><svg class="ego" viewBox="0 0 ${W} ${H}" role="img" aria-label="Relacionamentos da técnica ${tid}">${heads.map((h,i)=>`<text class="gcol" x="${colX[i]}" y="18" text-anchor="${i<2?'end':i===2?'middle':'start'}">${h}</text>`).join('')}${edges}${nodes}</svg></div>`;
}
function egoGroupSVG(g){
  const byTac={}; G.A.tactics.forEach(t=>byTac[t.short]={t,cov:0,unc:0});
  g.t.forEach(id=>{ const x=T(id); if(!x) return; x.ta.forEach(s=>{ if(byTac[s]) (x.rt>0?byTac[s].cov++:byTac[s].unc++); }); });
  const rows=Object.values(byTac).filter(r=>r.cov+r.unc>0); const mx=Math.max(1,...rows.map(r=>r.cov+r.unc));
  return `<h3 class="h">Onde este grupo atua e quanto você vê</h3><div class="bars">${rows.map(r=>`<div class="barrow"><span class="lb">${esc(r.t.n)}</span><div class="bb" style="display:flex"><i style="width:${r.cov/mx*100}%"></i><i style="width:${r.unc/mx*100}%;background:var(--rule)"></i></div><span class="nn">${r.cov}/${r.cov+r.unc}</span></div>`).join('')}</div><p class="note">Barra escura = técnicas com regra pública · clara = técnicas sem regra.</p>`;
}

/* ---------------- recursos da planilha ---------------- */
const PHASE_ORDER=['Inteligência','Hunting','Análise estática','Análise dinâmica','Análise de rede','Forense','Engano (deception)','Laboratório','Automação','Formação','Apoio'];
function resourcesList(items, intro){
  if(!items.length) return '<p class="empty">Nenhum material relacionado.</p>';
  return `${intro?`<p class="sub" style="margin-top:0">${esc(intro)}</p>`:''}<div class="rlist">${items.map(r=>`<div class="row" onclick="window.open('${esc(r.l)}','_blank','noopener')"><div class="t">${esc(r.n)}</div><span class="tag ${r.dead?'r':''}">${r.dead?'domínio desativado':esc(r.ph)}</span>${r.d?`<div class="d">${esc(r.d)}</div>`:''}<div class="m"><span class="src">${esc(r.cat)}</span>${r.pl?`<span>${esc(r.pl)}</span>`:''}${r.f.map(f=>`<span class="tag">${FMT_PT[f]||f}</span>`).join('')}</div></div>`).join('')}</div>`;
}
function renderResources(){
  const items=G.RES.items||[]; const byPh={}; items.forEach(r=>(byPh[r.ph]=byPh[r.ph]||[]).push(r));
  const phases=PHASE_ORDER.filter(p=>byPh[p]).concat(Object.keys(byPh).filter(p=>!PHASE_ORDER.includes(p)));
  const fmts=[...new Set(items.flatMap(r=>r.f))];
  // diagrama bipartido fase → formato de regra
  const W=900, H=Math.max(phases.length,fmts.length)*30+50, y1=i=>40+i*30;
  const ph_y={}; phases.forEach((p,i)=>ph_y[p]=y1(i)); const f_y={}; fmts.forEach((f,i)=>f_y[f]=40+i*(H-60)/Math.max(1,fmts.length-1));
  const links={}; items.forEach(r=>r.f.forEach(f=>{ const k=r.ph+'|'+f; links[k]=(links[k]||0)+1; }));
  const svg=`<div class="gwrap"><svg class="ego" viewBox="0 0 ${W} ${H}" role="img" aria-label="Fases de trabalho ligadas a formatos de regra"><text class="gcol" x="250" y="18" text-anchor="end">FASE DO TRABALHO</text><text class="gcol" x="650" y="18">FORMATO DE REGRA QUE ELA ALIMENTA</text>
   ${Object.entries(links).map(([k,n])=>{const [p,f]=k.split('|'); return `<path class="edge on2" style="stroke-width:${Math.min(6,0.6+n/4)}" d="M260,${ph_y[p]} C450,${ph_y[p]} 450,${f_y[f]} 640,${f_y[f]}"/>`;}).join('')}
   ${phases.map(p=>`<g class="node" onclick="document.getElementById('ph-${slugify(p)}')?.scrollIntoView({behavior:'smooth'})"><circle class="mk" cx="260" cy="${ph_y[p]}" r="5"/><text x="250" y="${ph_y[p]+4}" text-anchor="end">${esc(p)} · ${byPh[p].length}</text></g>`).join('')}
   ${fmts.map(f=>`<g class="node" onclick="A.q='';A.fmt.clear();A.fmt.add('${f}');A.page=0;go('arsenal')"><circle class="mk" cx="640" cy="${f_y[f]}" r="5"/><text x="650" y="${f_y[f]+4}">${esc(FMT_PT[f]||f)}</text></g>`).join('')}</svg></div>`;
  const dead=items.filter(r=>r.dead).length;
  $('#gbody').innerHTML=`<p class="sub" style="margin-top:0">${items.length} ferramentas e materiais da planilha <i>Malware IR – Tools & Resources</i> (Cyb3rUltron e Harsh Shah), organizados pela fase do trabalho e ligados aos formatos de regra que cada fase produz ou valida.</p>
  ${svg}
  <p class="note">${dead} links apontam para domínios que já foram desativados (ex.: badips.com, hosts-file.net, malwaredomainlist). Ficam listados por referência histórica e marcados.</p>
  ${phases.map(p=>`<h2 class="h" id="ph-${slugify(p)}">${esc(p)} <span class="id">${byPh[p].length}</span></h2>${resourcesList(byPh[p])}`).join('')}`;
}
const slugify=s=>s.toLowerCase().normalize('NFD').replace(/[̀-ͯ]/g,'').replace(/[^a-z0-9]+/g,'-');

/* ---------------- ligações com o resto do app ---------------- */
window.openRuleByUid=function(uid){
  const [slug,...rest]=uid.split('::'); const id=rest.join('::');
  const r=IDX.find(x=>x.slug===slug&&x.id===id); if(r){ closeModal(); setTimeout(()=>openRule(r),60); }
};
window.forgeFromTech=async function(tid){
  await loadGraph(); const x=T(tid); if(!x) return;
  const tacMap={'stealth':'defense_evasion','defense-impairment':'defense_evasion'};
  F.sel=[{f:'',m:'',v:''}]; F.flt=[]; F.id=null;
  F.meta={title:`Detect ${x.n}`,description:x.d.slice(0,240),level:'medium',status:'experimental',author:'',product:(x.pl[0]||'windows').toLowerCase().split(' ')[0],category:'process_creation',service:'',
    tactic:(tacMap[x.ta[0]]||x.ta[0]||'execution').replace(/-/g,'_'),technique:tid,fp:'',refs:['https://attack.mitre.org/techniques/'+tid.replace('.','/')+'/'],corr:null};
  go('forge'); setTimeout(()=>{ fillForm(); drawRows(); toast('⚒',`Forja preparada para ${tid}. Veja em "Como o ATT&CK detecta" quais campos usar.`); },80);
};
/* contexto ATT&CK para a ficha da regra (usado pelo arsenal.js) */
window.attackContextHTML=async function(r){
  try{ await loadGraph(); }catch{ return ''; }
  const ids=[...new Set(r.tech.map(t=>t.toUpperCase()))].filter(id=>T(id)); if(!ids.length) return '';
  return `<h3 class="h">Contexto ATT&CK</h3><div class="rlist">${ids.slice(0,4).map(id=>{const x=T(id); return `<div class="row" onclick="openTech('${id}')"><div class="t">${id} · ${esc(x.n)}</div><span class="tag">${totalRules(id,x)} regras</span><div class="d">${esc(x.d)}</div><div class="m"><span>${x.g.length} grupos usam</span><span>${x.at.length} testes Atomic</span><span>${x.ev.length} logs EVTX</span><span>${x.m.length} mitigações</span></div></div>`;}).join('')}</div>`;
};
window.attackValidationHTML=async function(r){
  try{ await loadGraph(); }catch{ return ''; }
  const ids=[...new Set(r.tech.map(t=>t.toUpperCase()))].filter(id=>T(id)); if(!ids.length) return '';
  const at=ids.flatMap(id=>T(id).at.map(a=>({...a,id}))); const ev=ids.flatMap(id=>T(id).ev.map(e=>({...e,id})));
  if(!at.length&&!ev.length) return '';
  return `<h3 class="h">Validar no mundo real</h3><p class="sub" style="margin-top:0">Para provar que esta regra pega o ataque de verdade: ${at.length} teste(s) Atomic e ${ev.length} log(s) EVTX das técnicas ${ids.join(', ')}.</p>
   ${at.slice(0,6).map(a=>`<div class="fx"><code>${a.id}</code><span class="w">${esc(a.n)} <span class="id">${esc(a.p.join(', '))}</span></span></div>`).join('')}
   ${ev.slice(0,6).map(e=>`<div class="fx"><code>EVTX</code><span class="w"><a href="${(e.r.includes('mdecrevoisier')?GH.evtx_mitre:GH.evtx_samples)+encPath(e.p)}" target="_blank" rel="noopener">${esc(e.n)}</a> <span class="id">${esc(e.c)}</span></span></div>`).join('')}
   <div class="toolbar"><button class="btn" onclick="openTech('${ids[0]}');setTimeout(()=>document.querySelector('[data-tp=test]')?.click(),300)">Ver todos na técnica ${ids[0]}</button></div>`;
};
window.attackLogsHTML=async function(r){
  try{ await loadGraph(); }catch{ return ''; }
  const ids=[...new Set(r.tech.map(t=>t.toUpperCase()))].filter(id=>T(id)&&T(id).det.length); if(!ids.length) return '';
  const rows=[]; ids.forEach(id=>T(id).det.forEach(d=>d.an.forEach(a=>a.logs.forEach(l=>rows.push({id,pl:a.pl.join(', '),...l})))));
  const uniq=[]; const seen=new Set(); rows.forEach(x=>{const k=x.src+x.ch+x.pl; if(!seen.has(k)){seen.add(k); uniq.push(x);}});
  return `<h3 class="h">O que o MITRE ATT&CK recomenda coletar</h3><table class="tbl"><tr><th>Técnica</th><th>Plataforma</th><th>Componente</th><th>Fonte</th><th>Canal / evento</th></tr>${uniq.slice(0,14).map(x=>`<tr><td>${x.id}</td><td>${esc(x.pl)}</td><td>${esc(x.dc)}</td><td><code>${esc(x.src)}</code></td><td><code>${esc(x.ch)}</code></td></tr>`).join('')}</table>`;
};
Object.assign(window,{renderGraph,loadGraph,G});
