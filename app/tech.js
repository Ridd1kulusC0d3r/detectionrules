/* ============================================================
   tech.js — aba TECNOLOGIAS: o catálogo pelo que ele observa (não por quem escreveu)
   Dados: data/graph/tech.json (build_tech.py) + ransomware.json, ai.json, tcem.json (build_context.py)
   ============================================================ */
const TX={d:null,p:null,mode:'map',rwq:'',rwcat:'',rwgap:false};
function loadTech(){
  if(TX.d) return Promise.resolve(TX);
  if(!TX.p){ const j=(u,d)=>fetch(u).then(r=>r.ok?r.json():d).catch(()=>d);
    TX.p=Promise.all([j('data/graph/tech.json',null),j('data/graph/ransomware.json',{tools:[],cats:[],gangs:[]}),j('data/graph/ai.json',{tech:[]})])
      .then(([d,rw,ai])=>{ if(!d) throw new Error('tech.json ausente — rode build_tech.py'); TX.d=d; TX.rw=rw; TX.ai=ai; TX.by={}; d.tech.forEach(z=>TX.by[z.id]=z); return TX; }); }
  return TX.p;
}
const nf=n=>Number(n||0).toLocaleString('pt-BR');
const CTL={detection:'detecção',hunting:'hunting',signature:'assinatura',playbook:'playbook'};
const CTC={detection:'var(--seq-4)',hunting:'var(--seq-2)',signature:'var(--seq-1)',playbook:'var(--ink-3)'};
const PATC=['var(--ink-3)','var(--seq-4)','var(--seq-3)','var(--seq-2)','var(--seq-1)','var(--ink-2)','var(--rule)'];
const patColor=id=>PATC[Math.max(0,(window.PATS||[]).findIndex(p=>p.id===id))]||'var(--rule)';
const lvl=(v,mx)=>!v?'h0':v/mx<.04?'h1':v/mx<.15?'h2':v/mx<.45?'h3':'h4';
function stackBar(obj,colors,labels,total){
  total=total||Object.values(obj).reduce((a,b)=>a+b,0)||1;
  return `<span class="stk">${Object.entries(obj).filter(([,v])=>v).map(([k,v])=>`<i style="width:${v/total*100}%;background:${colors(k)}" title="${esc(labels(k))}: ${nf(v)}"></i>`).join('')}</span>`;
}

async function renderTechno(){
  const v=$('#v-techno');
  v.innerHTML='<div class="loading">Carregando painéis por tecnologia…<div class="bar"><i style="width:60%"></i></div></div>';
  try{ await loadTech(); }catch(e){ v.innerHTML=`<div class="note warn"><span class="ni">▸</span><div>${esc(e.message)}</div></div>`; return; }
  const d=TX.d; const T=d.tech.filter(z=>z.id!=='other');
  const withPl=T.filter(z=>z.pct!=null); const worst=withPl.slice().sort((a,b)=>a.pct-b.pct)[0]; const best=withPl.slice().sort((a,b)=>b.pct-a.pct)[0];
  const specific=d.meta.total-(TX.by.other?.n_rules||0);
  const modes=[['map','Mapa por domínio'],['heat','Tecnologia × tática'],['flows','De onde vem (Sankey)'],['pat','Como decidem'],['fmt','Em que linguagem'],['gaps','Detecção pela ausência'],['rw','Ransomware: ferramentas'],['ai','IA e agentes'],['tcem','Cenários TCEM']];
  v.innerHTML=`
  <div class="eyebrow">Tecnologias · ${T.length} em ${d.dom.length} domínios</div>
  <h1 class="sec">O catálogo pelo que ele <span class="g">observa</span>, não por quem escreveu</h1>
  <p class="sub">Quem defende pensa em tecnologia: "o que eu tenho para Okta? e para ESXi?". Cada regra foi reclassificada pelo que ela enxerga — logsource, caminho, título e descrição — e cruzada com o ATT&CK, os grupos que miram cada plataforma, as ferramentas de ransomware, os cenários do TCEM e o mapa de ameaças de IA do LLmInjection.</p>
  <div class="grid g4" style="grid-template-columns:repeat(auto-fit,minmax(160px,1fr))">
    <div class="stat"><div class="v">${T.length}</div><div class="l">tecnologias</div></div>
    <div class="stat"><div class="v">${Math.round(specific/d.meta.total*100)}%</div><div class="l">regras com tecnologia identificada</div></div>
    <div class="stat"><div class="v">${best?best.pct+'%':'—'}</div><div class="l">maior cobertura · ${esc(best?.n||'')}</div></div>
    <div class="stat"><div class="v">${worst?worst.pct+'%':'—'}</div><div class="l">menor cobertura · ${esc(worst?.n||'')}</div></div>
  </div>
  <div class="toolbar" style="margin-top:18px" role="tablist">${modes.map(([k,l])=>`<button class="btn ${TX.mode===k?'p':''}" data-tm="${k}">${l}</button>`).join('')}
    <a class="btn sm" style="margin-left:auto" href="reports/tech/index.html">Relatórios em HTML ↗</a><a class="btn sm" href="data/graph/tech.json" download>⬇ tech.json</a></div>
  <div id="tbody"></div>
  <p class="id" style="margin-top:18px">${esc(d.meta.metodo)}</p>`;
  $$('[data-tm]',v).forEach(b=>b.onclick=()=>{TX.mode=b.dataset.tm; renderTechno();});
  ({map:txMap,heat:txHeat,flows:txFlows,pat:txPat,fmt:txFmt,gaps:txGaps,rw:txRw,ai:txAi,tcem:txTcem})[TX.mode]();
}

/* 1 — mapa por domínio */
function txMap(){
  const d=TX.d;
  $('#tbody').innerHTML=`<p class="sub" style="margin-top:0">Clique numa tecnologia para abrir o relatório: história, cobertura, lacunas, grupos, padrões e regras recomendadas. A barra mostra a composição: <span class="lgd" style="--c:${CTC.detection}">detecção</span> <span class="lgd" style="--c:${CTC.hunting}">hunting</span> <span class="lgd" style="--c:${CTC.signature}">assinatura</span> <span class="lgd" style="--c:${CTC.playbook}">playbook</span>.</p>`+
  d.dom.map(dm=>`<h2 class="h">${esc(dm.n)} <span class="id">${nf(dm.n_rules)} vínculos</span></h2><div class="tiles">${dm.t.map(id=>{const z=TX.by[id]; return `<button class="tile" onclick="openTechno('${id}')">
     <span class="tn">${esc(z.n)}</span><span class="tv">${nf(z.n_rules)}</span>
     ${stackBar(z.ct,k=>CTC[k]||'var(--rule)',k=>CTL[k]||k)}
     <span class="tm">${z.pct!=null?`<b>${z.pct}%</b> de ${esc(z.pl)} · ${z.n_gaps} sem regra`:`${z.ntech} técnicas ATT&CK`}</span></button>`;}).join('')}</div>`).join('');
}
/* 2 — heatmap tecnologia × tática */
function txHeat(){
  const d=TX.d; const T=d.tech.filter(z=>z.id!=='other'); const mx=Math.max(...T.flatMap(z=>Object.values(z.tac)));
  $('#tbody').innerHTML=`<p class="sub" style="margin-top:0">Regras por tecnologia e tática (tática vinda das técnicas ATT&CK de cada regra). Linhas vazias numa coluna = aquela fase do ataque não é vista naquela tecnologia. Clique numa linha para o relatório.</p>
  <div class="gwrap"><table class="hmx"><thead><tr><th></th>${d.tac.map(t=>`<th><span>${esc(t.n)}</span></th>`).join('')}</tr></thead><tbody>
  ${T.map(z=>`<tr onclick="openTechno('${z.id}')"><th>${esc(z.n)}</th>${d.tac.map(t=>{const v=z.tac[t.id]||0; return `<td class="heat ${lvl(v,mx)}" title="${esc(z.n)} · ${esc(t.n)}: ${nf(v)}">${v?nf(v):''}</td>`;}).join('')}</tr>`).join('')}</tbody></table></div>`;
}
/* 3 — Sankey fonte → domínio → tecnologia */
function txFlows(){
  const d=TX.d; const nodes=[]; const seen=new Set(); const links={};
  const add=(id,label,col,extra={})=>{ if(!seen.has(id)){seen.add(id); nodes.push({id,label,col,...extra});} };
  const topT=new Set(d.tech.filter(z=>z.id!=='other').sort((a,b)=>b.n_rules-a.n_rules).slice(0,22).map(z=>z.id));
  d.flows.forEach(([s,k,v])=>{ if(!topT.has(k)) return; const z=TX.by[k]; add('s:'+s,s,0); add('d:'+z.dom,z.dom,1); add('t:'+k,z.n,2,{click:`openTechno('${k}')`});
    links['s:'+s+'|d:'+z.dom]=(links['s:'+s+'|d:'+z.dom]||0)+v; links['d:'+z.dom+'|t:'+k]=(links['d:'+z.dom+'|t:'+k]||0)+v; });
  const L=Object.entries(links).map(([k,v])=>{const [s,t]=k.split('|'); return {s,t,v};});
  $('#tbody').innerHTML=`<p class="sub" style="margin-top:0">Cada fonte pública contribui para tecnologias diferentes. Passe o mouse num nó para isolar seus fluxos; clique numa tecnologia para o relatório. (22 maiores tecnologias; fontes menores agrupadas.)</p>`+
    sankeySVG({cols:['FONTE','DOMÍNIO','TECNOLOGIA'],nodes,links:L},{w:1320,padX:320,minH:4,rowH:24,maxLabel:34,unit:'regras',label:'Fluxo de regras: fonte para domínio para tecnologia'});
}
/* 4 — padrões de correlação */
function txPat(){
  const d=TX.d; const P=window.PATS||[]; const tot={}; d.tech.forEach(z=>Object.entries(z.pat).forEach(([k,v])=>tot[k]=(tot[k]||0)+v));
  const T=d.tech.filter(z=>z.id!=='other'&&z.n_rules>=80);
  $('#tbody').innerHTML=`<p class="sub" style="margin-top:0">Como cada regra decide, segundo o catálogo de padrões do <b>TCEM</b>. Evento único dá cobertura ampla e barata; sequência, limiar, novidade e mudança de estado exigem mais dados e contam uma história mais completa. Tecnologias dominadas por evento único são as que mais ganham com correlação.</p>
  <div class="grid g2">${P.map(p=>`<div class="card"><div class="pill-row" style="justify-content:space-between"><b><span class="sw" style="background:${patColor(p.id)}"></span>${esc(p.n)}</b><span class="tag">${nf(tot[p.id]||0)} vínculos</span></div><p style="font-size:13.5px;margin-top:6px">${esc(p.d)}</p><button class="btn sm" onclick="A.pat.clear();A.pat.add('${p.id}');A.page=0;go('arsenal')">ver regras</button></div>`).join('')}</div>
  <h2 class="h">Mistura de padrões por tecnologia</h2>
  <div class="bars">${T.map(z=>`<div class="barrow" style="cursor:pointer;grid-template-columns:minmax(120px,230px) 1fr 70px" onclick="openTechno('${z.id}')"><span class="lb">${esc(z.n)}</span>${stackBar(z.pat,patColor,k=>(window.PAT_BY||{})[k]?.n||k)}<span class="nn">${nf(z.n_rules)}</span></div>`).join('')}</div>
  <p class="id">${P.map(p=>`<span class="lgd" style="--c:${patColor(p.id)}">${esc(p.n)}</span>`).join(' ')}</p>`;
}
/* 5 — formatos */
function txFmt(){
  const d=TX.d; const T=d.tech.filter(z=>z.id!=='other'); const F=[...new Set(T.flatMap(z=>Object.keys(z.fmt)))]; const mx=Math.max(...T.flatMap(z=>Object.values(z.fmt)));
  $('#tbody').innerHTML=`<p class="sub" style="margin-top:0">Em que linguagem existe regra pronta para cada tecnologia. Útil para decidir: se o seu SIEM fala KQL e só há Sigma para Okta, você converte; se só há YARA-L, você reescreve.</p>
  <div class="gwrap"><table class="hmx"><thead><tr><th></th>${F.map(f=>`<th><span>${esc(FMT_PT[f]||f)}</span></th>`).join('')}</tr></thead><tbody>
  ${T.map(z=>`<tr><th onclick="openTechno('${z.id}')">${esc(z.n)}</th>${F.map(f=>{const v=z.fmt[f]||0; return `<td class="heat ${lvl(v,mx)}" ${v?`onclick="A.techno.clear();A.techno.add('${z.id}');A.fmt.clear();A.fmt.add('${f}');A.page=0;go('arsenal')"`:''} title="${esc(z.n)} · ${esc(FMT_PT[f]||f)}: ${nf(v)}">${v?nf(v):''}</td>`;}).join('')}</tr>`).join('')}</tbody></table></div>`;
}
/* 6 — detecção pela ausência */
function txGaps(){
  const T=TX.d.tech.filter(z=>z.pct!=null).sort((a,b)=>a.pct-b.pct);
  $('#tbody').innerHTML=`<p class="sub" style="margin-top:0"><b>Detecção pela ausência</b> (princípio do TCEM): antes de escrever a regra, pergunte que evidência precisa existir se o ataque acontecer — e qual está faltando. Aqui: quantas técnicas do ATT&CK de cada plataforma têm ao menos uma regra pública na tecnologia correspondente. Barra curta = onde um atacante passa sem ser visto.</p>
  <div class="bars">${T.map(z=>`<div class="barrow" style="cursor:pointer;grid-template-columns:minmax(120px,230px) 1fr 120px" onclick="openTechno('${z.id}')"><span class="lb">${esc(z.n)} <span class="id">${esc(z.pl)}</span></span><div class="bb"><i style="width:${z.pct}%"></i></div><span class="nn">${z.pct}% · ${z.n_gaps} lacunas</span></div>`).join('')}</div>
  <h2 class="h">As lacunas que mais importam</h2><p class="sub" style="margin-top:0">Técnicas sem regra na tecnologia, usadas por mais grupos. A última coluna mostra se existe regra em <i>outra</i> tecnologia que dá para adaptar.</p>
  <table class="tbl"><tr><th>Tecnologia</th><th>Técnica</th><th class="num">Grupos</th><th class="num">Regras em outras tecnologias</th></tr>
  ${T.flatMap(z=>z.gaps.slice(0,3).map(g=>({z,g}))).sort((a,b)=>b.g[2]-a.g[2]).slice(0,30).map(({z,g})=>`<tr><td><a href="#" onclick="event.preventDefault();openTechno('${z.id}')">${esc(z.n)}</a></td><td><a href="#" onclick="event.preventDefault();openTech('${g[0]}')">${g[0]}</a> ${esc(g[1])}</td><td class="num">${g[2]}</td><td class="num">${g[3]?nf(g[3]):'<span class="gap">nenhuma</span>'}</td></tr>`).join('')}</table>`;
}
/* 7 — ransomware tool matrix */
function txRw(){
  const rw=TX.rw; const cats=rw.cats||[]; const catN={}; cats.forEach(c=>catN[c.id]=c.pt);
  const tools=(rw.tools||[]).filter(t=>(!TX.rwcat||t.cat===TX.rwcat)&&(!TX.rwq||t.n.toLowerCase().includes(TX.rwq))&&(!TX.rwgap||!t.r)).sort((a,b)=>b.g.length-a.g.length);
  const mxg=Math.max(1,...(rw.tools||[]).map(t=>t.g.length));
  const noRule=(rw.tools||[]).filter(t=>!t.r).length;
  $('#tbody').innerHTML=`<p class="sub" style="margin-top:0">O <b>Ransomware Tool Matrix</b> (Will Thomas, CC BY 4.0, consolidado pelo <b>APT4ALL</b>) lista as ferramentas que afiliados de ransomware usam dentro da rede — muitas legítimas (AnyDesk, Rclone, PsExec). Cada uma é um ponto de detecção. Ao lado: quantas regras do catálogo citam a ferramenta no título, descrição ou lógica (indício de cobertura, confira a regra).</p>
  <div class="grid g4" style="grid-template-columns:repeat(auto-fit,minmax(150px,1fr))"><div class="stat"><div class="v">${nf((rw.tools||[]).length)}</div><div class="l">ferramentas</div></div><div class="stat"><div class="v">${nf((rw.gangs||[]).length)}</div><div class="l">gangues e afiliados</div></div><div class="stat"><div class="v">${nf((rw.tools||[]).length-noRule)}</div><div class="l">citadas por regras</div></div><div class="stat"><div class="v">${nf(noRule)}</div><div class="l">sem nenhuma regra</div></div></div>
  <div class="toolbar"><input class="search" id="rwq" style="max-width:260px" placeholder="ferramenta: rclone, anydesk…" value="${esc(TX.rwq)}"><select id="rwcat" class="btn sm"><option value="">todas as categorias</option>${cats.map(c=>`<option value="${c.id}" ${TX.rwcat===c.id?'selected':''}>${esc(c.pt)}</option>`).join('')}</select><button class="btn sm ${TX.rwgap?'p':''}" id="rwgap">só sem regra</button></div>
  <table class="tbl"><tr><th>Ferramenta</th><th>Categoria</th><th>Gangues que usam</th><th class="num">Regras</th></tr>
  ${tools.slice(0,150).map(t=>`<tr><td><b>${esc(t.n)}</b></td><td>${esc(catN[t.cat]||t.cat)}</td><td><span class="pbar"><i style="width:${t.g.length/mxg*100}%"></i></span>${t.g.length} <span class="id">${esc(t.g.slice(0,4).join(', '))}${t.g.length>4?'…':''}</span></td><td class="num">${t.r?`<a href="#" onclick="event.preventDefault();rwRules('${esc(t.n).replace(/'/g,"\\'")}')">${nf(t.r)}</a>`:'<span class="gap">0</span>'}</td></tr>`).join('')}</table>
  ${tools.length>150?`<p class="id">${tools.length-150} a mais — refine a busca.</p>`:''}`;
  $('#rwq').oninput=e=>{TX.rwq=e.target.value.trim().toLowerCase(); clearTimeout(TX._t); TX._t=setTimeout(()=>{txRw(); const i=$('#rwq'); i.focus(); i.setSelectionRange(i.value.length,i.value.length);},250);};
  $('#rwcat').onchange=e=>{TX.rwcat=e.target.value; txRw();};
  $('#rwgap').onclick=()=>{TX.rwgap=!TX.rwgap; txRw();};
}
window.rwRules=function(n){
  const t=(TX.rw.tools||[]).find(x=>x.n===n); if(!t) return;
  openModal(`<div class="mhead"><div style="flex:1"><div class="eyebrow">Ransomware Tool Matrix · ${esc(t.cat)}</div><h2>${esc(t.n)}</h2></div><button class="x" onclick="closeModal()">✕</button></div>
  <div class="mbody"><p>Usada por <b>${t.g.length}</b> gangue(s)/afiliado(s): ${esc(t.g.join(', '))}.</p>
  <h3 class="h">Regras que citam a ferramenta (${nf(t.r)})</h3><div class="rlist">${t.ex.map(e=>`<div class="row" onclick="openRuleByUid('${e.u}')"><div class="t">${esc(e.t)}</div><span class="sev ${sevClass(e.v)}">${SEV_PT[e.v]||'—'}</span><div class="m"><span class="src">${esc(e.s)}</span><span class="tag">${FMT_PT[e.f]||e.f}</span></div></div>`).join('')}</div>
  <div class="toolbar"><button class="btn" onclick="closeModal();A.q='${esc(t.n.toLowerCase()).replace(/'/g,"\\'")}';A.page=0;go('arsenal')">buscar no Arsenal</button></div></div>`);
};
/* 8 — IA (LLmInjection) */
function txAi(){
  const ai=TX.ai||{}; const z=TX.by.ai;
  $('#tbody').innerHTML=`<p class="sub" style="margin-top:0">Ameaças a IA, LLMs e agentes do <b>LLmInjection</b> (Apache-2.0), mapeadas para MITRE ATLAS e OWASP, ligadas às ${nf(z?.n_rules||0)} regras do catálogo que observam IA. ${esc(ai.meta?.landscape?.methodology||'')}</p>
  <div class="toolbar"><button class="btn p" onclick="openTechno('ai')">relatório IA, LLMs & agentes</button><button class="btn" onclick="A.techno.clear();A.techno.add('ai');A.page=0;go('arsenal')">ver as regras no Arsenal</button></div>
  ${(ai.metrics||[]).length?`<h2 class="h">O cenário em números</h2><div class="grid g4" style="grid-template-columns:repeat(auto-fit,minmax(220px,1fr))">${ai.metrics.slice(0,8).map(m=>`<div class="stat"><div class="v">${esc(String(m.value))}${/percent/.test(m.unit||'')?'%':''}</div><div class="l" style="text-transform:none;letter-spacing:0;font-family:var(--sans);font-size:12.5px">${esc(m.name)} <span class="id">${esc(m.src||'')}</span></div></div>`).join('')}</div>`:''}
  ${(ai.domains||[]).length?`<h2 class="h">Tendências</h2><div class="grid g2">${ai.domains.map(dm=>`<div class="card"><div class="pill-row"><b>${esc(dm.name)}</b><span class="tag ${dm.trend==='rising'?'a':''}">${esc(dm.trend||'')}</span><span class="tag">confiança ${esc(dm.confidence||'')}</span></div><p style="font-size:13.5px;margin-top:6px">${esc(dm.summary||'')}</p>${(dm.defensive_focus||[]).length?`<p class="id">foco defensivo: ${esc(dm.defensive_focus.join(' · '))}</p>`:''}</div>`).join('')}</div>`:''}
  <h2 class="h">Técnicas de ataque a IA (${(ai.tech||[]).length})</h2>
  <table class="tbl"><tr><th>Técnica</th><th>Mapeamento</th><th class="num">Detecções</th><th class="num">Testes</th><th class="num">Incidentes</th></tr>
  ${(ai.tech||[]).map(t=>`<tr><td><b>${esc(t.id)}</b> ${esc(t.n)}<div class="id">${esc(t.d)}</div></td><td>${t.map.filter(m=>m.rel==='exact').slice(0,3).map(m=>`<a class="tag" href="${esc(m.u||'#')}" target="_blank" rel="noopener">${esc(m.id)}</a>`).join(' ')}</td><td class="num">${t.det.length}</td><td class="num">${t.tc.length}</td><td class="num">${t.inc.length}</td></tr>`).join('')}</table>
  ${(ai.actors||[]).length?`<h2 class="h">Atores que usam IA</h2><div class="rlist">${ai.actors.map(a=>`<div class="row" style="cursor:default"><div class="t">${esc(a.name)}</div><span class="tag">${esc(a.confidence||'')}</span><div class="d">${esc(a.summary||'')}</div><div class="m"><span>${esc(a.nexus||'')}</span><span>${esc((a.ai_role||[]).join(', '))}</span><span class="id">verificado ${esc(a.last_verified||'')}</span></div></div>`).join('')}</div>`:''}
  <h2 class="h">Especificações de detecção (${(ai.det||[]).length}) e testes seguros (${(ai.tc||[]).length})</h2>
  <p class="sub" style="margin-top:0">Hipóteses prontas para virar regra — cada uma diz que telemetria precisa existir. Os testes são de laboratório seguro (marcadores benignos), para provar que a detecção funciona.</p>
  <table class="tbl"><tr><th>ID</th><th>Hipótese</th><th>Telemetria</th><th>Sev.</th></tr>${(ai.det||[]).map(x=>`<tr><td><code>${esc(x.id)}</code></td><td><b>${esc(x.name)}</b><div class="id">${esc(x.hypothesis||'')}</div></td><td class="id">${esc((x.telemetry||[]).join(', '))}</td><td>${esc(x.severity||'')}</td></tr>`).join('')}</table>`;
}
/* 9 — cenários TCEM */
function caseHTML(c){
  return `<div class="card"><div class="eyebrow">${esc(c.id)} · ${esc((c.lens||[]).join(', '))}</div><h3 class="h">${esc(c.n)}</h3><p style="font-size:14px"><b>Missão:</b> ${esc(c.mission)}</p>
   ${(c.cj||[]).map(j=>`<p class="id">Joia da coroa: <b>${esc(j.n)}</b>${j.crit?` (${esc(j.crit)})`:''} — ${esc(j.r)}</p>`).join('')}
   ${c.scen.map(s=>`<h4 style="margin:12px 0 6px;font:600 15px var(--serif)">${esc(s.t)}</h4><p style="font-size:13.5px">${esc(s.obj)}${s.entry?` <span class="id">entrada: ${esc(s.entry)}</span>`:''}</p>
     <div class="path2">${s.steps.map((st,i)=>`${i?'<span class="arr">→</span>':''}<div class="stp"><span class="n">PASSO ${st.o}</span><b>${esc(st.b.replace(/_/g,' '))}</b>${st.t.map((t,k)=>`<a href="#" onclick="event.preventDefault();openTech('${t}')" class="tag ${st.rules[t]?'':'r'}">${t} · ${nf(st.rules[t]||0)} regras</a>`).join('')}${st.obs?`<span class="id">${esc(st.obs)}</span>`:''}</div>`).join('')}</div>
     ${s.tc.map(tc=>`<p style="font-size:13px;margin-top:8px"><b>Contrato de telemetria</b> — ${esc(tc.src||'')} <span class="tag">${esc(tc.status||'')}</span><br>${(tc.req||[]).map(f=>`<code class="${(tc.av||[]).includes(f)?'ok':'miss'}">${(tc.av||[]).includes(f)?'✓':'✗'} ${esc(f)}</code>`).join(' ')}${tc.lat?` <span class="id">latência ${esc(tc.lat)} · retenção ${esc(tc.ret||'')}</span>`:''}</p>`).join('')}
     ${s.dsp.map(dd=>`<p style="font-size:13px"><b>Especificação de detecção</b> — padrão <span class="tag a">${esc(dd.pat||'')}</span> janela ${esc(dd.win||'—')}, agrupado por ${esc((dd.by||[]).join(', ')||'—')}. ${esc(dd.effect||'')}${(dd.benign||[]).length?` <span class="id">Benignos: ${esc(dd.benign.join('; '))}</span>`:''}</p>`).join('')}
     ${Object.keys(s.prio||{}).length?`<div class="bars" style="margin-top:6px;max-width:560px">${Object.entries(s.prio).map(([k,v])=>`<div class="barrow" style="grid-template-columns:200px 1fr 30px"><span class="lb">${esc(k.replace(/_/g,' '))}</span><div class="bb"><i style="width:${v/5*100}%"></i></div><span class="nn">${v}</span></div>`).join('')}</div>`:''}`).join('')}</div>`;
}
function txTcem(){
  const cs=TX.d.cases||[]; const sc=TX.d.schema||{};
  $('#tbody').innerHTML=`<p class="sub" style="margin-top:0"><b>TCEM — Threat Context Engineering Method</b>: modele a ameaça antes do primeiro log, decida o que precisa ser observável e só então escreva a detecção. Cada cenário de referência abaixo liga missão → joia da coroa → caminho de ataque → contrato de telemetria → especificação de detecção, com a cobertura do catálogo em cada passo. <span class="id">✗ = campo exigido pelo contrato que ainda não chega.</span></p>
  ${cs.map(caseHTML).join('')}
  <h2 class="h">Ponte de esquemas (um campo, quatro nomes)</h2><p class="sub" style="margin-top:0">O mesmo conceito tem nomes diferentes em cada SIEM. Ao portar uma regra, é aqui que ela quebra.</p>
  <table class="tbl"><tr><th>Conceito</th><th>OCSF</th><th>Elastic ECS</th><th>Sentinel ASIM</th><th>Splunk CIM</th></tr>${Object.entries(sc).map(([k,v])=>`<tr><td><b>${esc(k)}</b></td><td><code>${esc(v.ocsf||'')}</code></td><td><code>${esc(v.ecs||'')}</code></td><td><code>${esc(v.asim||'')}</code></td><td><code>${esc(v.cim||'')}</code></td></tr>`).join('')}</table>`;
}

/* ---------------- relatório de uma tecnologia (modal) ---------------- */
async function openTechno(id){
  openModal('<div class="mbody"><div class="loading">Montando o relatório…</div></div>');
  try{ await loadTech(); }catch(e){ $('#mbox .mbody').innerHTML=`<div class="loading">${esc(e.message)}</div>`; return; }
  const z=TX.by[id]; if(!z){ closeModal(); return; }
  const d=TX.d; const mxT=Math.max(1,...Object.values(z.tac)); const ct=z.ct;
  const topTac=Object.entries(z.tac).sort((a,b)=>b[1]-a[1]).filter(([,v])=>v).slice(0,3).map(([k])=>d.tac.find(t=>t.id===k)?.n).join(', ');
  const catN={}; (TX.rw.cats||[]).forEach(c=>catN[c.id]=c.pt);
  const fileName=`${z.id}-${z.n.toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g,'').replace(/[^a-z0-9]+/g,'-').replace(/^-|-$/g,'')}`;
  const cases=(d.cases||[]).filter(c=>z.cases.includes(c.id));
  if(!V.state['techno_'+id]){ V.state['techno_'+id]=1; save(); addXP(10,'Relatório de tecnologia: '+z.n); }
  $('#mbox').innerHTML=`<div class="mhead"><div style="flex:1"><div class="eyebrow">${esc(z.dom)}${z.pl?` · plataforma ATT&CK ${esc(z.pl)}`:''}${z.lensd?` · lente TCEM ${esc(z.lensd.n)}`:''}</div><h2>${esc(z.n)}</h2></div>
   <a class="btn sm" href="reports/tech/${fileName}.html" target="_blank" rel="noopener">relatório HTML ↗</a><button class="btn sm p" onclick="closeModal();A.techno.clear();A.techno.add('${z.id}');A.page=0;go('arsenal')">ver ${nf(z.n_rules)} regras</button><button class="x" onclick="closeModal()">✕</button></div>
  <div class="mbody">
   <div class="feynman"><div class="lbl">A HISTÓRIA DESTA TECNOLOGIA</div>
    <p>O palco é <span class="em">${esc(z.st||z.n)}</span>. O catálogo reúne <b>${nf(z.n_rules)}</b> regras que olham para cá — ${nf(ct.detection)} de detecção, ${nf(ct.hunting)} de hunting, ${nf(ct.signature)} assinaturas e ${nf(ct.playbook)} playbooks de resposta${topTac?`, concentradas em <b>${esc(topTac)}</b>`:''}.</p>
    ${z.pl?`<p>Das ${z.plat_n} técnicas do ATT&CK para ${esc(z.pl)}, <b>${z.plat_cov} (${z.pct}%)</b> têm regra aqui; <b>${z.n_gaps}</b> não têm nenhuma — é por onde um atacante passa sem ser visto.${z.grp.length?` Quem mais mira esta plataforma: ${z.grp.slice(0,3).map(g=>esc(g.n)).join(', ')}.`:''}</p>`:''}
    ${z.lensd?`<p><b>Lente TCEM:</b> ${esc(z.lensd.d)} Para enxergar, colete: <i>${esc((z.lensd.tel||[]).join(', '))}</i>.</p>`:''}</div>
   <div class="grid g4" style="grid-template-columns:repeat(auto-fit,minmax(130px,1fr))">
    <div class="stat"><div class="v">${nf(z.n_rules)}</div><div class="l">regras</div></div><div class="stat"><div class="v">${z.ntech}</div><div class="l">técnicas ATT&CK</div></div>
    ${z.pl?`<div class="stat"><div class="v">${z.pct}%</div><div class="l">plataforma coberta</div></div><div class="stat"><div class="v">${z.n_gaps}</div><div class="l">técnicas sem regra</div></div>`:''}
    <div class="stat"><div class="v">${Object.keys(z.fmt).length}</div><div class="l">linguagens</div></div></div>
   <div class="grid g2">
    <div class="card"><h3 class="h" style="margin-top:0">Por tática</h3><div class="bars">${d.tac.map(t=>`<div class="barrow"><span class="lb">${esc(t.n)}</span><div class="bb"><i style="width:${(z.tac[t.id]||0)/mxT*100}%"></i></div><span class="nn">${nf(z.tac[t.id]||0)}</span></div>`).join('')}</div></div>
    <div class="card"><h3 class="h" style="margin-top:0">Como as regras decidem (TCEM)</h3><div class="bars">${Object.entries(z.pat).sort((a,b)=>b[1]-a[1]).map(([k,v])=>`<div class="barrow" title="${esc((window.PAT_BY||{})[k]?.d||'')}"><span class="lb"><span class="sw" style="background:${patColor(k)}"></span>${esc((window.PAT_BY||{})[k]?.n||k)}</span><div class="bb"><i style="width:${v/z.n_rules*100}%"></i></div><span class="nn">${nf(v)}</span></div>`).join('')}</div>
     <h3 class="h">Linguagens</h3><div class="pill-row">${Object.entries(z.fmt).map(([f,v])=>`<span class="tag">${esc(FMT_PT[f]||f)} · ${nf(v)}</span>`).join('')}</div>
     <h3 class="h">Fontes</h3><div class="pill-row">${z.src.map(([s,v])=>`<span class="tag b">${esc(s)} · ${nf(v)}</span>`).join('')}</div></div></div>
   <h3 class="h">Técnicas mais cobertas</h3><div class="pill-row">${z.top.map(([t,n,c])=>`<a class="tag a" href="#" onclick="event.preventDefault();openTech('${t}')">${t} ${esc(n)} · ${nf(c)}</a>`).join('')}</div>
   ${z.gaps.length?`<h3 class="h">Detecção pela ausência — ${z.n_gaps} técnicas sem regra aqui</h3><p class="sub" style="margin-top:0">Ordenadas por quantos grupos as usam. "Em outras tecnologias" mostra se dá para adaptar uma regra existente.</p>
    <table class="tbl"><tr><th>Técnica</th><th class="num">Grupos</th><th class="num">Em outras tecnologias</th></tr>${z.gaps.slice(0,12).map(g=>`<tr><td><a href="#" onclick="event.preventDefault();openTech('${g[0]}')">${g[0]}</a> ${esc(g[1])}</td><td class="num">${g[2]}</td><td class="num">${g[3]?nf(g[3]):'<span class="gap">nenhuma</span>'}</td></tr>`).join('')}</table>`:''}
   ${z.grp.length?`<h3 class="h">Quem mira esta plataforma</h3><table class="tbl"><tr><th>Grupo</th><th>Origem atribuída</th><th class="num">Técnicas na plataforma</th><th class="num">Você vê</th></tr>${z.grp.slice(0,10).map(g=>`<tr><td><a href="#" onclick="event.preventDefault();openGroup('${g.g}')">${esc(g.n)}</a> <span class="id">${g.g}</span></td><td>${esc(g.cn||'—')}</td><td class="num">${g.on}</td><td class="num"><span class="pbar"><i style="width:${g.cov/g.on*100}%"></i></span>${g.cov}/${g.on}</td></tr>`).join('')}</table><p class="id">País atribuído pelo APT4ALL — afirmação das fontes, não nossa.</p>`:''}
   ${z.rw.length?`<h3 class="h">Ferramentas de afiliados de ransomware que passam por aqui</h3><div class="pill-row">${z.rw.map(t=>`<a class="tag ${t.r?'':'r'}" href="#" onclick="event.preventDefault();${t.r?`rwRules('${esc(t.n).replace(/'/g,"\\'")}')`:''}" title="${esc(catN[t.cat]||t.cat)} · ${t.g} gangues">${esc(t.n)} · ${t.g} gangues · ${t.r} regras</a>`).join('')}</div>`:''}
   ${cases.length?`<h3 class="h">Cenário de referência TCEM</h3>${cases.map(caseHTML).join('')}`:''}
   ${z.id==='ai'?`<div class="note osint"><span class="ni">✶</span><div>Veja também a visão <b>IA e agentes</b> na aba Tecnologias: técnicas do LLmInjection mapeadas para ATLAS/OWASP, especificações de detecção e testes seguros. <button class="btn sm" onclick="closeModal();TX.mode='ai';go('techno')">abrir</button></div></div>`:''}
   <h3 class="h">Regras recomendadas para começar</h3><div class="rlist">${z.rec.map(e=>`<div class="row" onclick="openRuleByUid('${e.u}')"><div class="t">${esc(e.t)}</div><span class="sev ${sevClass(e.v)}">${SEV_PT[e.v]||'—'}</span><div class="m"><span class="src">${esc(e.s)}</span><span class="tag">${FMT_PT[e.f]||e.f}</span>${(e.tc||[]).map(t=>`<span class="tech">${t}</span>`).join('')}</div></div>`).join('')}</div>
  </div>`;
}
window.openTechno=openTechno; window.renderTechno=renderTechno; window.TX=TX;
