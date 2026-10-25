/* ============================================================
   intel.js — inteligência de ameaças sobre o grafo
   1) CASO: conjunto de alertas (regras que dispararam) e técnicas observadas
   2) ATRIBUIÇÃO POR TTP: ranking de grupos por sobreposição ponderada pela raridade da técnica
   3) DOSSIÊ por grupo: perfil, TTP com procedimentos, arsenal, cobertura, emulação, hunting, OSINT
   4) FLUXOS (Sankey): oferta de detecção × demanda adversária
   ============================================================ */
const I = { P:null, loading:null };
async function loadIntel(){
  await loadGraph();
  if(I.P) return I;
  if(!I.loading) I.loading=fetch('data/graph/groups.json').then(r=>{ if(!r.ok) throw new Error('groups.json HTTP '+r.status); return r.json(); }).then(p=>{ I.P=p; return I; });
  return I.loading;
}
const NG = () => G.A.groups.length;
const normT = t => { t=String(t).toUpperCase(); let n=0; while(G.A.rev[t]&&n<5){ t=G.A.rev[t]; n++; } return t; };
const idfT = t => { const x=G.A.techniques[t]; return x? Math.log((NG()+1)/(x.g.length+1)) : 0; };
const gslug = s => s.toLowerCase().replace(/[^a-z0-9]+/g,'-').replace(/^-|-$/g,'');
const dossierFile = (id,n) => `reports/groups/${id}-${gslug(n)}.md`;
const REPO='https://github.com/Ridd1kulusC0d3r/detectionrules';

/* ---------------- 1) CASO ---------------- */
V.state.case ??= {items:[]};
const caseItems = () => V.state.case.items;
function caseTechniques(){
  const s=new Map();
  for(const it of caseItems()){
    const ts = it.k==='tech'? [it.id] : it.tech;
    for(const raw of ts){ const t=normT(raw); if(G.A.techniques[t]){ if(!s.has(t)) s.set(t,[]); s.get(t).push(it); } }
  }
  return s;
}
window.caseAddRule=function(r){
  const u=r.slug+'::'+r.id; if(caseItems().some(i=>i.u===u)) return toast('•','Este alerta já está no caso');
  caseItems().push({k:'rule',u,title:r.title,tech:r.tech,src:r.src,fmt:r.fmt}); save();
  toast('+','Alerta adicionado ao caso ('+caseItems().length+'). Veja em Grafo → Atribuição por TTP');
};
window.caseAddTech=function(t){ t=normT(t); if(caseItems().some(i=>i.k==='tech'&&i.id===t)) return; caseItems().push({k:'tech',id:t,title:t+' '+(G.A.techniques[t]?.n||'')}); save(); toast('+',t+' adicionada ao caso'); };
window.caseRemove=function(i){ caseItems().splice(i,1); save(); renderAttrib(); };
window.caseClear=function(){ V.state.case.items=[]; save(); renderAttrib(); };

/* ---------------- 2) ATRIBUIÇÃO ---------------- */
function attribute(){
  const S=caseTechniques(); const ts=[...S.keys()]; const tot=ts.reduce((s,t)=>s+idfT(t),0)||1;
  const res=G.A.groups.map((g,gi)=>{
    const Tg=new Set(g.t); const m=[];
    for(const t of ts){
      let w=0, how='';
      if(Tg.has(t)){ w=1; how='exata'; }
      else { const p=t.split('.')[0]; if(t.includes('.')&&Tg.has(p)){ w=.5; how='técnica-pai'; } else if(!t.includes('.')&&[...Tg].some(x=>x.startsWith(t+'.'))){ w=.5; how='subtécnica'; } }
      if(w) m.push({t,w,how,idf:idfT(t)});
    }
    const score=m.reduce((s,x)=>s+x.w*x.idf,0)/tot;
    return {g,gi,score,m,cov:m.length/Math.max(1,ts.length),frac:m.filter(x=>x.w===1).length/Math.max(1,g.t.length)};
  }).filter(r=>r.m.length).sort((a,b)=>b.score-a.score||b.m.length-a.m.length);
  return {ts,res,S};
}
const confLabel=(score,n)=> n<3? ['insuficiente','Menos de 3 técnicas: qualquer ranking aqui é ruído.'] : score>=.6? ['sobreposição forte','Boa hipótese para investigar; ainda não é atribuição.'] : score>=.35? ['sobreposição moderada','Várias técnicas em comum; procure as técnicas distintivas do grupo.'] : ['sobreposição fraca','Técnicas comuns a muitos grupos; não sustenta hipótese.'];

async function renderAttrib(){
  const body=$('#gbody'); if(!body) return;
  await loadGraph();
  const {ts,res,S}=attribute(); const top=res.slice(0,12);
  const items=caseItems();
  body.innerHTML=`
  <div class="feynman"><div class="lbl">COMO FUNCIONA</div><p>Monte um <span class="em">caso</span> com os alertas que dispararam (ou técnicas observadas). Cada alerta aponta técnicas ATT&CK; cada grupo tem as técnicas que usa. O ranking soma as técnicas em comum, dando <span class="em">mais peso às técnicas raras</span> — ver Office Test é muito mais informativo do que ver PowerShell, que quase todo grupo usa.</p><p>Isso gera <span class="em">hipóteses</span> para a investigação, não atribuição. Atribuir exige também infraestrutura, malware, vitimologia e contexto.</p></div>
  <div class="forge" style="gap:40px">
   <div>
    <div class="fset"><b>Caso atual · ${items.length} item(ns) · ${ts.length} técnica(s)</b>
     ${items.length? `<div class="rlist">${items.map((it,i)=>`<div class="row" style="cursor:default"><div class="t">${esc(it.title)}</div><button class="btn sm" onclick="caseRemove(${i})">remover</button><div class="m">${it.k==='rule'?`<span class="src">${esc(it.src||'')}</span><span class="tag">${FMT_PT[it.fmt]||it.fmt||''}</span>${(it.tech||[]).map(t=>`<span class="tech">${esc(normT(t))}</span>`).join('')}`:'<span class="tag">técnica informada</span>'}</div></div>`).join('')}</div>`
       : '<p class="empty">Caso vazio. Adicione alertas pelo Arsenal (botão “+ caso” na ficha da regra), cole abaixo ou carregue o exemplo.</p>'}
     <div class="toolbar"><button class="btn" onclick="caseDemo()">carregar exemplo</button><button class="btn" onclick="caseClear()">limpar caso</button><button class="btn" onclick="caseExport()">⬇ caso (.json)</button><button class="btn a" onclick="caseReport()" ${ts.length?'':'disabled'}>⬇ relatório do caso (.md)</button></div></div>
    <div class="fset"><b>Colar alertas do SIEM</b>
     <p>Uma linha por alerta: nome da regra (como aparece no catálogo) ou códigos de técnica. Ex.: <code>T1003.001</code>, <code>Potential LSASS Process Dump Via Procdump</code>.</p>
     <textarea id="casepaste" placeholder="Cole aqui os nomes dos alertas ou códigos Txxxx…"></textarea>
     <div class="toolbar"><button class="btn p" onclick="casePaste()">adicionar ao caso</button></div><div id="pastemsg" class="note" style="display:none"></div></div>
   </div>
   <div>
    ${ts.length? (()=>{ const [lab,txt]=confLabel(top[0]?.score||0,ts.length); return `
     <div class="fset"><b>Grupos mais compatíveis</b><p><span class="gap">${esc(lab)}</span> ${esc(txt)}</p>
      <table class="tbl"><tr><th>#</th><th>Grupo</th><th class="num">Compatibilidade</th><th class="num">Técnicas em comum</th></tr>
      ${top.map((r,i)=>`<tr style="cursor:pointer" onclick="openGroup('${r.g.id}')"><td>${i+1}</td><td><b>${esc(r.g.n)}</b> <span class="id">${r.g.id}</span><div class="id">${esc(r.g.al.slice(0,3).join(', '))}</div></td><td class="num"><span class="pbar"><i style="width:${Math.round(r.score*100)}%"></i></span>${Math.round(r.score*100)}%</td><td class="num">${r.m.length}/${ts.length}</td></tr>`).join('')}</table>
      <p class="note">Compatibilidade = soma da raridade das técnicas do caso que o grupo usa ÷ raridade total do caso. Correspondência pela técnica-pai ou subtécnica conta metade.</p></div>`; })() : ''}
   </div>
  </div>
  ${ts.length? `<h2 class="h">Do alerta ao grupo</h2><p class="sub" style="margin-top:0">Espessura = peso da técnica (raridade). Passe o mouse num nó para isolar os fluxos dele.</p>${attribSankey(ts,S,top.slice(0,8))}
   ${nextHunts(top[0],ts)}`:''}`;
}
function attribSankey(ts,S,top){
  const nodes=[], links=[]; const seen=new Set(); const add=n=>{ if(!seen.has(n.id)){ seen.add(n.id); nodes.push(n); } };
  for(const [t,its] of S){ const w=idfT(t)||.05;
    add({id:'t:'+t,label:`${t} ${G.A.techniques[t].n}`,col:1,click:`openTech('${t}')`});
    its.forEach((it,k)=>{ const aid='a:'+(it.u||it.id); add({id:aid,label:it.title,col:0,click:it.u?`openRuleByUid('${it.u}')`:`openTech('${it.id}')`}); links.push({s:aid,t:'t:'+t,v:w/its.length}); });
  }
  top.forEach(r=>{ add({id:'g:'+r.g.id,label:`${r.g.n} · ${Math.round(r.score*100)}%`,col:2,click:`openGroup('${r.g.id}')`,cls:'grp'});
    r.m.forEach(x=>links.push({s:'t:'+x.t,t:'g:'+r.g.id,v:x.idf*x.w})); });
  return sankeySVG({cols:['ALERTAS DO CASO','TÉCNICAS ATT&CK','GRUPOS COMPATÍVEIS'],nodes,links},{w:1240,padX:300,minH:16,gap:6,maxLabel:36,unit:'de peso',label:'Alertas ligados a técnicas e a grupos'});
}
function nextHunts(best,ts){
  if(!best) return '';
  const have=new Set(ts); const g=best.g;
  const cand=g.t.filter(t=>!have.has(t)&&G.A.techniques[t]).sort((a,b)=>idfT(b)-idfT(a)).slice(0,8);
  if(!cand.length) return '';
  return `<h2 class="h">Próximas caças se a hipótese for ${esc(g.n)}</h2><p class="sub" style="margin-top:0">Técnicas distintivas de ${esc(g.n)} que ainda não aparecem no caso. Encontrá-las fortalece a hipótese; não encontrá-las enfraquece.</p>
  <div class="rlist">${cand.map(t=>{const x=G.A.techniques[t]; return `<div class="row" onclick="openTech('${t}')"><div class="t">${t} · ${esc(x.n)}</div><span class="tag">${x.rt} regras</span><div class="m"><span>raridade ${idfT(t).toFixed(2)}</span><span>${x.g.length} grupos usam</span><span>${x.at.length} testes Atomic</span><button class="btn sm" onclick="event.stopPropagation();caseAddTech('${t}');renderAttrib()">observei</button></div></div>`;}).join('')}</div>`;
}
window.casePaste=function(){
  const lines=($('#casepaste').value||'').split(/\n+/).map(s=>s.trim()).filter(Boolean); let ok=0; const miss=[];
  for(const ln of lines){
    const tc=ln.match(/\bT\d{4}(?:\.\d{3})?\b/gi);
    if(tc&&tc.length&&ln.replace(/\bT\d{4}(?:\.\d{3})?\b/gi,'').replace(/[\s,;|]+/g,'').length<3){ tc.forEach(t=>{ caseAddTech(t); ok++; }); continue; }
    const low=ln.toLowerCase(); let r=IDX.find(x=>x.title.toLowerCase()===low && x.tech.length);
    if(!r){ const c=IDX.filter(x=>x.tech.length && x.title.toLowerCase().includes(low)); if(c.length===1) r=c[0]; else if(c.length>1) r=c.sort((a,b)=>(b.fmt==='sigma')-(a.fmt==='sigma'))[0]; }
    if(r){ const u=r.slug+'::'+r.id; if(!caseItems().some(i=>i.u===u)) caseItems().push({k:'rule',u,title:r.title,tech:r.tech,src:r.src,fmt:r.fmt}); ok++; }
    else if(tc){ tc.forEach(t=>caseAddTech(t)); ok++; } else miss.push(ln);
  }
  save(); renderAttrib(); setTimeout(()=>{ const m=$('#pastemsg'); if(m){ m.style.display='flex'; m.innerHTML=`<span class="ni">▸</span><div>${ok} linha(s) reconhecida(s).${miss.length?` Sem correspondência: ${miss.slice(0,5).map(esc).join('; ')}${miss.length>5?'…':''}. Use o nome exato da regra ou o código da técnica.`:''}</div>`; } },30);
};
window.caseDemo=function(){
  const want=['T1566.001','T1204.002','T1059.001','T1547.001','T1003.001','T1021.002','T1071.001','T1560.001'];
  V.state.case.items=[];
  for(const t of want){ const x=G.A.techniques[t]; const e=x?.ex?.find(e=>e.k==='detection'&&!caseItems().some(i=>i.u===e.u))||x?.ex?.[0]; if(!e) continue;
    const [slug,...rest]=e.u.split('::'); const r=IDX.find(z=>z.slug===slug&&z.id===rest.join('::'));
    if(r && !caseItems().some(i=>i.u===e.u)) caseItems().push({k:'rule',u:e.u,title:r.title,tech:r.tech,src:r.src,fmt:r.fmt}); }
  save(); renderAttrib(); toast('▸','Exemplo: 8 alertas típicos de intrusão por phishing. Note como técnicas comuns geram atribuição fraca.');
};
window.caseExport=function(){ download('caso-detectionrules.json', JSON.stringify({gerado:new Date().toISOString(),itens:caseItems(),tecnicas:[...caseTechniques().keys()]},null,1),'application/json'); };
window.caseReport=function(){
  const {ts,res}=attribute(); const top=res.slice(0,10); const [lab,txt]=confLabel(top[0]?.score||0,ts.length);
  const L=[`# Relatório de caso — atribuição por TTP`,``,`> TLP:CLEAR (ajuste antes de compartilhar) · gerado em ${new Date().toLocaleString('pt-BR')} · Detection Rules + MITRE ATT&CK v${G.A.version}`,``,
   `## Alertas (${caseItems().length})`,``,...caseItems().map(i=>`- ${i.title}${i.k==='rule'?` — ${i.src} (${FMT_PT[i.fmt]||i.fmt}) — ${(i.tech||[]).map(normT).join(', ')}`:' — técnica informada'}`),``,
   `## Técnicas observadas (${ts.length})`,``,`| Técnica | Táticas | Grupos que usam | Raridade |`,`|---|---|---:|---:|`,
   ...ts.sort((a,b)=>idfT(b)-idfT(a)).map(t=>`| ${t} ${G.A.techniques[t].n} | ${G.A.techniques[t].ta.map(tacName).join(', ')} | ${G.A.techniques[t].g.length} | ${idfT(t).toFixed(2)} |`),``,
   `## Hipóteses de grupo`,``,`**Avaliação:** ${lab}. ${txt}`,``,`| # | Grupo | Compatibilidade | Técnicas em comum | Dossiê |`,`|---|---|---:|---:|---|`,
   ...top.map((r,i)=>`| ${i+1} | ${r.g.n} (${r.g.id}) | ${Math.round(r.score*100)}% | ${r.m.map(x=>x.t+(x.w<1?'*':'')).join(', ')} | [${r.g.id}](${REPO}/blob/main/${dossierFile(r.g.id,r.g.n)}) |`),``,`\\* correspondência pela técnica-pai ou subtécnica (meio peso).`,``];
  if(top[0]){ const have=new Set(ts); const cand=top[0].g.t.filter(t=>!have.has(t)&&G.A.techniques[t]).sort((a,b)=>idfT(b)-idfT(a)).slice(0,8);
    L.push(`## Próximas caças (hipótese: ${top[0].g.n})`,``,...cand.map(t=>`- ${t} ${G.A.techniques[t].n} — ${G.A.techniques[t].rt} regras públicas, ${G.A.techniques[t].at.length} testes Atomic`),``); }
  L.push(`## Limites`,``,`- Sobreposição de TTP não é atribuição: combine com infraestrutura, malware, vitimologia e contexto geopolítico.`,`- O ATT&CK registra apenas o que foi relatado publicamente.`,`- Técnicas comuns (PowerShell, phishing) pesam pouco de propósito.`);
  download('relatorio-caso-ttp.md', L.join('\n'),'text/markdown');
};

/* ---------------- 3) DOSSIÊ ---------------- */
window.openGroup=async function(gid){
  openModal(`<div class="mhead"><h2>Carregando dossiê…</h2><button class="x" onclick="closeModal()">✕</button></div><div class="mbody"><div class="loading">Carregando perfil do grupo…<div class="bar"><i style="width:60%"></i></div></div></div>`);
  try{ await loadIntel(); }catch(e){ $('#mbox .mbody').innerHTML=`<div class="note warn"><span class="ni">!</span><div>${esc(e.message)}</div></div>`; return; }
  const p=I.P[gid]; const g=G.A.groups.find(x=>x.id===gid); if(!p||!g) return;
  const tech=p.tech, cov=tech.filter(t=>t.rt>0), gaps=tech.filter(t=>t.rt===0); const pct=tech.length?Math.round(cov.length/tech.length*100):0;
  const sig=[...tech].sort((a,b)=>b.idf-a.idf).slice(0,10);
  const tacOrder=G.A.tactics.map(t=>t.short);
  const file=dossierFile(gid,p.n);
  openModal(`<div class="mhead"><div style="flex:1"><div class="eyebrow">Dossiê de inteligência · ${gid} · TLP:CLEAR</div><h2>${esc(p.n)}</h2><div class="pill-row">${p.al.map(a=>`<span class="tag">${esc(a)}</span>`).join('')}</div></div><button class="x" onclick="closeModal()">✕</button></div>
  <div class="mbody">
   <div class="toolbar" style="margin-top:0"><a class="btn p" href="${file.replace(/\.md$/,'.html')}" target="_blank" rel="noopener">dossiê (HTML) ↗</a><a class="btn" href="${file}" download>⬇ .md</a><a class="btn" href="${REPO}/blob/main/${file}" target="_blank" rel="noopener">ver no GitHub ↗</a><a class="btn" href="https://attack.mitre.org/groups/${gid}/" target="_blank" rel="noopener">ATT&CK ↗</a><button class="btn" onclick="copy(location.origin+location.pathname+'#group=${gid}')">copiar link</button><button class="btn a" onclick="groupAsCase('${gid}')">comparar com o caso</button></div>
   <div class="grid" style="grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:0 24px"><div class="stat"><div class="v">${tech.length}</div><div class="l">técnicas</div></div><div class="stat"><div class="v">${pct}%</div><div class="l">cobertas por regra</div></div><div class="stat"><div class="v">${p.sw.length}</div><div class="l">softwares</div></div><div class="stat"><div class="v">${p.camp.length}</div><div class="l">campanhas</div></div><div class="stat"><div class="v">${p.refs.length+p.rep.length}</div><div class="l">fontes</div></div></div>
   <div class="mtabs"><button class="mtab on" data-dp="sum">Resumo</button><button class="mtab" data-dp="ttp">TTP e procedimentos</button><button class="mtab" data-dp="ars">Arsenal</button><button class="mtab" data-dp="det">Detecção</button><button class="mtab" data-dp="emu">Emulação e hunting</button><button class="mtab" data-dp="osint">OSINT e fontes</button></div>
   <div class="mpane on" id="dp-sum">
     <p style="font:16px/1.6 var(--serif)">${esc(p.d)}</p><p class="note">Texto original do MITRE ATT&CK (inglês). Registro criado em ${p.cr}, atualizado em ${p.md}${p.yrs.length?` · referências de ${p.yrs[0]} a ${p.yrs[1]}`:''}.</p>
     <h3 class="h">Da tática à detecção</h3><p class="sub" style="margin-top:0">Cada técnica do grupo, agrupada por tática, e se existe regra pública para ela. Clique para abrir.</p>
     ${groupSankey(p,tacOrder)}
     <h3 class="h">Assinatura comportamental</h3><p class="sub" style="margin-top:0">Técnicas raras entre os ${NG()} grupos: as mais úteis para reconhecer este grupo pelo comportamento.</p>
     <table class="tbl"><tr><th>Técnica</th><th class="num">Outros grupos</th><th class="num">Raridade</th><th class="num">Regras</th></tr>${sig.map(t=>`<tr style="cursor:pointer" onclick="openTech('${t.id}')"><td><b>${t.id}</b> ${esc(t.n)}</td><td class="num">${G.A.techniques[t.id].g.length-1}</td><td class="num">${t.idf.toFixed(2)}</td><td class="num">${t.rt||'<span class="gap">0</span>'}</td></tr>`).join('')}</table>
     ${egoGroupSVG(g)}
   </div>
   <div class="mpane" id="dp-ttp">${tacOrder.map(s=>{ const rows=tech.filter(t=>t.ta.includes(s)); if(!rows.length) return ''; return `<h3 class="h">${esc(tacName(s))} · ${rows.length}</h3><div class="rlist">${rows.map(t=>`<div class="row" onclick="openTech('${t.id}')"><div class="t">${t.id} · ${esc(t.n)}</div><span class="tag ${t.rt?'':'r'}">${t.rt?t.rt+' regras':'sem regra'}</span>${t.pr.length?`<div class="d" style="-webkit-line-clamp:4">${esc(t.pr[0].p)}</div>`:''}<div class="m">${t.pr[0]?.c?.length?`<span>fonte: ${esc(t.pr[0].c.join('; '))}</span>`:''}<span>${t.at} Atomic</span><span>${t.ev} EVTX</span></div></div>`).join('')}</div>`; }).join('')}<p class="note">Procedimentos: texto original do ATT&CK (inglês), com a fonte citada.</p></div>
   <div class="mpane" id="dp-ars">
     <h3 class="h">Softwares (${p.sw.length})</h3>${p.sw.length?`<table class="tbl"><tr><th>Software</th><th>Tipo</th><th class="num">Técnicas</th><th>Uso relatado (EN)</th></tr>${p.sw.map(s=>`<tr><td><a href="https://attack.mitre.org/software/${s.id}/" target="_blank" rel="noopener">${esc(s.n)}</a> <span class="id">${s.id}</span></td><td>${s.k==='malware'?'malware':'ferramenta'}</td><td class="num">${s.t}</td><td style="font-size:13px">${esc(s.p.slice(0,200))}</td></tr>`).join('')}</table>`:'<p class="empty">Nenhum software atribuído.</p>'}
     <h3 class="h">Campanhas (${p.camp.length})</h3>${p.camp.length?`<table class="tbl"><tr><th>Campanha</th><th>Período</th><th>Resumo (EN)</th></tr>${p.camp.map(c=>`<tr><td><a href="https://attack.mitre.org/campaigns/${c.id}/" target="_blank" rel="noopener">${esc(c.n)}</a></td><td class="num">${esc(c.f||'?')} → ${esc(c.l||'?')}</td><td style="font-size:13px">${esc(c.d.slice(0,220))}</td></tr>`).join('')}</table>`:'<p class="empty">Nenhuma campanha atribuída.</p>'}
   </div>
   <div class="mpane" id="dp-det">
     <p class="sub" style="margin-top:0"><b>${cov.length} de ${tech.length} técnicas (${pct}%)</b> têm ao menos uma regra pública no catálogo.</p>
     <h3 class="h">Sem regra pública (${gaps.length})</h3>${gaps.length?`<div class="rlist">${gaps.sort((a,b)=>b.idf-a.idf).map(t=>`<div class="row" onclick="openTech('${t.id}')"><div class="t">${t.id} · ${esc(t.n)}</div><button class="btn sm" onclick="event.stopPropagation();closeModal();forgeFromTech('${t.id}')">criar regra</button><div class="m"><span>${t.ta.map(tacName).join(', ')}</span><span>${t.at} testes Atomic</span></div></div>`).join('')}</div>`:'<p class="empty">Todas as técnicas têm regra pública.</p>'}
     <h3 class="h">Regras recomendadas por técnica</h3><p class="note">Melhor regra disponível: formato portável e maduro primeiro.</p>
     <div class="rlist">${cov.slice().sort((a,b)=>b.idf-a.idf).slice(0,40).map(t=>{ const e=G.A.techniques[t.id].ex[0]; return e?`<div class="row" onclick="openRuleByUid('${e.u}')"><div class="t">${esc(e.t)}</div><span class="sev ${sevClass(e.v)}">${SEV_PT[e.v]||'—'}</span><div class="m"><span class="tech">${t.id}</span><span class="src">${esc(e.s)}</span><span class="tag">${FMT_PT[e.f]||e.f}</span><span>+${t.rt-1} outras</span></div></div>`:''; }).join('')}</div>
   </div>
   <div class="mpane" id="dp-emu">${groupEmulation(p)}</div>
   <div class="mpane" id="dp-osint">${groupOsint(p)}</div>
  </div>`);
  $$('[data-dp]','#mbox').forEach(b=>b.onclick=()=>{ $$('[data-dp]','#mbox').forEach(z=>z.classList.remove('on')); b.classList.add('on'); $$('#mbox .mpane').forEach(x=>x.classList.remove('on')); $('#dp-'+b.dataset.dp).classList.add('on'); });
};
function groupSankey(p,tacOrder){
  const nodes=[],links=[]; const add=new Set();
  const top=new Set([...p.tech].sort((a,b)=>b.idf-a.idf).slice(0,28).map(t=>t.id));
  nodes.push({id:'c:yes',label:'Com regra pública',col:2,cls:'grp'},{id:'c:no',label:'Sem regra pública',col:2,cls:'gapn'});
  for(const t of p.tech){
    const s=t.ta.find(x=>tacOrder.includes(x)); if(!s) continue;
    if(!add.has('ta:'+s)){ add.add('ta:'+s); nodes.push({id:'ta:'+s,label:tacName(s),col:0}); }
    const nid= top.has(t.id)? 't:'+t.id : 'o:'+s;
    if(!add.has(nid)){ add.add(nid); nodes.push(top.has(t.id)? {id:nid,label:`${t.id} ${t.n}`,col:1,click:`openTech('${t.id}')`} : {id:nid,label:`outras de ${tacName(s)}`,col:1}); }
    links.push({s:'ta:'+s,t:nid,v:1}); links.push({s:nid,t:t.rt?'c:yes':'c:no',v:1,cls:t.rt?'':'gapl'});
  }
  // agrega fluxos repetidos
  const agg={}; links.forEach(l=>{ const k=l.s+'|'+l.t; agg[k]=agg[k]? {...agg[k],v:agg[k].v+l.v} : {...l}; });
  return sankeySVG({cols:['TÁTICA','TÉCNICA (MAIS DISTINTIVAS)','DETECÇÃO'],nodes,links:Object.values(agg)},{w:1050,rowH:19,minH:12,gap:5,maxLabel:40,showV:false,unit:'técnica(s)',label:'Técnicas do grupo por tática e cobertura de detecção'});
}
function groupEmulation(p){
  const rows=p.tech.filter(t=>t.at>0); const ev=p.tech.flatMap(t=>G.A.techniques[t.id].ev.slice(0,2).map(e=>({...e,t:t.id})));
  const hyp=[...p.tech].sort((a,b)=>b.idf-a.idf).map(t=>{ const an=G.A.techniques[t.id].det.flatMap(d=>d.an).find(a=>a.logs.length); return an?{t,an}:null; }).filter(Boolean).slice(0,12);
  return `<div class="feynman"><div class="lbl">EMULAR PARA VALIDAR</div><p>Reproduza as técnicas do grupo num <span class="em">laboratório isolado e autorizado</span> com os testes Atomic, ou carregue os <span class="em">logs reais</span> no SIEM, e confira quais regras disparam. O que não disparar é lacuna concreta do seu ambiente.</p></div>
   <h3 class="h">Testes Atomic Red Team (${rows.length} técnicas)</h3>${rows.length?`<table class="tbl"><tr><th>Técnica</th><th>Teste</th><th>Plataformas</th></tr>${rows.flatMap(t=>G.A.techniques[t.id].at.slice(0,2).map(a=>`<tr><td><a href="https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/${t.id}/${t.id}.md" target="_blank" rel="noopener">${t.id}</a></td><td>${esc(a.n)}</td><td>${esc(a.p.join(', '))}</td></tr>`)).join('')}</table>`:'<p class="empty">Sem testes Atomic para as técnicas deste grupo.</p>'}
   <h3 class="h">Logs reais (EVTX) — ${ev.length}</h3>${ev.length?`<div class="rlist">${ev.slice(0,30).map(e=>`<div class="row" onclick="window.open('${(e.r.includes('mdecrevoisier')?GH.evtx_mitre:GH.evtx_samples)+encPath(e.p)}','_blank','noopener')"><div class="t">${esc(e.n)}</div><span class="tag">${esc(e.c)}</span><div class="m"><span class="tech">${e.t}</span><span class="src">${esc(e.r)}</span></div></div>`).join('')}</div>`:'<p class="empty">—</p>'}
   <h3 class="h">Hipóteses de hunting</h3><p class="sub" style="margin-top:0">Ordenadas pelas técnicas mais distintivas, com as fontes de log das estratégias de detecção do MITRE ATT&CK.</p>
   <ol style="padding-left:20px">${hyp.map(({t,an})=>`<li style="margin:8px 0"><b><a href="#" onclick="openTech('${t.id}');return false">${t.id} ${esc(t.n)}</a></b> — ${esc(an.d)} <br><span class="id">${an.logs.slice(0,3).map(l=>esc(l.src)+(l.ch?' ('+esc(l.ch)+')':'')).join(' · ')}</span></li>`).join('')}</ol>`;
}
function groupOsint(p){
  const names=[p.n,...p.al]; const q=names.slice(0,6).map(a=>`"${a}"`).join(' OR ');
  const enc=encodeURIComponent;
  return `<div class="feynman"><div class="lbl">OSINT SOBRE O GRUPO</div><p>Consultas prontas com <span class="em">todos os nomes</span> do grupo — cada fornecedor batiza o mesmo ator de um jeito, e pesquisar só um nome perde metade dos relatórios.</p></div>
   <div class="rlist">
    <div class="row" onclick="window.open('https://duckduckgo.com/?q=${enc('('+q+') threat report')}','_blank','noopener')"><div class="t">Relatórios técnicos (busca web)</div><span class="tag">web</span><div class="m"><span>${esc(q)}</span></div></div>
    <div class="row" onclick="window.open('https://duckduckgo.com/?q=${enc('('+q+') filetype:pdf')}','_blank','noopener')"><div class="t">Relatórios em PDF</div><span class="tag">web</span></div>
    <div class="row" onclick="window.open('https://github.com/search?type=code&q=${enc(q)}','_blank','noopener')"><div class="t">Regras, IOCs e ferramentas no GitHub</div><span class="tag">código</span></div>
    <div class="row" onclick="window.open('https://otx.alienvault.com/browse/global/pulses?q=${enc(p.n)}','_blank','noopener')"><div class="t">Pulsos de ameaça no AlienVault OTX</div><span class="tag">IOCs</span></div>
    <div class="row" onclick="window.open('https://malpedia.caad.fkie.fraunhofer.de/actors','_blank','noopener')"><div class="t">Malpedia — atores e famílias de malware</div><span class="tag">malware</span><div class="m"><span>busque por ${esc(names.slice(0,3).join(', '))}</span></div></div>
    <div class="row" onclick="window.open('https://apt.etda.or.th/cgi-bin/listgroups.cgi','_blank','noopener')"><div class="t">ThaiCERT Threat Group Cards</div><span class="tag">perfis</span></div>
   </div>
   <h3 class="h">Relatórios na coleção CyberMonitor (${p.rep.length})</h3>${p.rep.length?`<div class="rlist">${p.rep.map(r=>`<div class="row" onclick="window.open('${GH.apt+encPath(r.p)}','_blank','noopener')"><div class="t">${esc(r.t)}</div><span class="tag">${esc(r.y)}</span><div class="m"><span>${esc(r.f)}</span><span>via “${esc(r.via)}” (inferido)</span></div></div>`).join('')}</div>`:'<p class="empty">Nenhum relatório ligado pelo nome.</p>'}
   <h3 class="h">Bibliografia citada pelo ATT&CK (${p.refs.length})</h3>${p.refs.length?`<ul style="padding-left:18px">${p.refs.map(r=>`<li style="margin:6px 0;font-size:14px"><a href="${esc(r.u)}" target="_blank" rel="noopener">${esc(r.n)}</a> <span style="color:var(--ink-3)">— ${esc(r.d)}</span></li>`).join('')}</ul>`:'<p class="empty">—</p>'}
   ${p.contrib.length?`<p class="note">Contribuidores do registro no ATT&CK: ${esc(p.contrib.join('; '))}.</p>`:''}`;
}
window.groupAsCase=async function(gid){ closeModal(); G.mode='attrib'; go('graph'); setTimeout(()=>toast('▸','Compare: o grupo aparece no ranking se o seu caso tiver técnicas dele'),400); };

/* ---------------- 4) FLUXOS (Sankey global) ---------------- */
function renderFlows(){
  const A=G.A; const tacOrder=A.tactics.map(t=>t.short);
  // (a) oferta: formato de regra → tática
  const fa=A.stats.fmt_tactic.filter(([f,t,n])=>tacOrder.includes(t));
  const fmts=[...new Set(fa.map(x=>x[0]))];
  const sA=sankeySVG({cols:['FORMATO DE REGRA','TÁTICA'],nodes:[...fmts.map(f=>({id:'f:'+f,label:FMT_PT[f]||f,col:0,click:`A.q='';A.fmt.clear();A.fmt.add('${f}');A.page=0;go('arsenal')`})),...tacOrder.filter(t=>fa.some(x=>x[1]===t)).map(t=>({id:'t:'+t,label:tacName(t),col:1}))],
    links:fa.map(([f,t,n])=>({s:'f:'+f,t:'t:'+t,v:n}))},{w:1050,unit:'regras×técnica',label:'Formatos de regra por tática'});
  // (b) demanda: grupo (top 15) → tática → cobertura
  const top=[...A.groups].sort((a,b)=>b.t.length-a.t.length).slice(0,15);
  const nodes=[], links=[], agg={}; const L=(s,t,v,cls)=>{ const k=s+'|'+t; agg[k]=agg[k]||{s,t,v:0,cls}; agg[k].v+=v; };
  top.forEach(g=>{ nodes.push({id:'g:'+g.id,label:g.n,col:0,click:`openGroup('${g.id}')`});
    g.t.forEach(id=>{ const x=A.techniques[id]; if(!x) return; const s=x.ta.find(z=>tacOrder.includes(z)); if(!s) return; L('g:'+g.id,'t:'+s,1); L('t:'+s, x.rt?'c:yes':'c:no',1, x.rt?'':'gapl'); }); });
  tacOrder.forEach(t=>{ if(Object.values(agg).some(l=>l.t==='t:'+t)) nodes.push({id:'t:'+t,label:tacName(t),col:1}); });
  nodes.push({id:'c:yes',label:'Com regra pública',col:2,cls:'grp'},{id:'c:no',label:'Sem regra pública',col:2,cls:'gapn'});
  const sB=sankeySVG({cols:['GRUPO (15 MAIS DOCUMENTADOS)','TÁTICA','DETECÇÃO PÚBLICA'],nodes,links:Object.values(agg)},{w:1050,unit:'técnica(s)',label:'Grupos, táticas e cobertura'});
  $('#gbody').innerHTML=`
   <h2 class="h" style="margin-top:0">Oferta de detecção</h2><p class="sub" style="margin-top:0">De onde vem a detecção pública: quantas vezes cada formato de regra cita técnicas de cada tática.</p>${sA}
   <h2 class="h">Demanda adversária</h2><p class="sub" style="margin-top:0">O que os 15 grupos mais documentados fazem, por tática, e quanto disso tem regra pública. A faixa “sem regra” é onde vale escrever a próxima detecção.</p>${sB}
   <p class="note">Passe o mouse num nó para isolar os fluxos dele; clique num grupo para abrir o dossiê.</p>`;
}

/* ---------------- ligação regra → grupos (ficha da regra) ---------------- */
window.groupsForRuleHTML=async function(r){
  try{ await loadGraph(); }catch{ return ''; }
  const ts=[...new Set(r.tech.map(normT))].filter(t=>G.A.techniques[t]); if(!ts.length) return '';
  const score=G.A.groups.map(g=>{ const m=ts.filter(t=>g.t.includes(t)); return {g,m}; }).filter(x=>x.m.length).sort((a,b)=>b.m.length-a.m.length||b.g.rep.length-a.g.rep.length);
  if(!score.length) return `<h3 class="h">Quem costuma fazer isso</h3><p class="empty">Nenhum grupo do ATT&CK tem as técnicas ${ts.join(', ')} atribuídas.</p>`;
  return `<h3 class="h">Quem costuma fazer isso (${score.length} grupos)</h3><p class="sub" style="margin-top:0">Grupos que usam ${ts.join(', ')} segundo o ATT&CK. Um alerta sozinho não aponta um grupo; junte vários alertas num caso para ranquear hipóteses.</p>
   <div class="pill-row">${score.slice(0,24).map(x=>`<a class="tag" href="#" onclick="openGroup('${x.g.id}');return false">${esc(x.g.n)}</a>`).join('')}${score.length>24?`<span class="tag">+${score.length-24}</span>`:''}</div>`;
};
Object.assign(window,{loadIntel,renderAttrib,renderFlows,attribute,I});
