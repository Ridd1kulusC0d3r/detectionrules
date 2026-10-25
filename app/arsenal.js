/* ============================================================
   arsenal.js — navegador das 44.595 regras: busca, filtros, mapa ATT&CK, modal campo-a-campo
   ============================================================ */
const A = { q:'', src:new Set(), fmt:new Set(), sev:new Set(), tac:new Set(), ctype:new Set(), tech:'', prod:'', page:0, per:40, sort:'rel', rows:[], fav:false };
let IDX=null; // linhas normalizadas em objetos

function buildIndex(){
  const I=V.idx; IDX=I.rows.map((r,i)=>({
    i, id:r[0], title:r[1], desc:r[2], src:I.src[r[3]], slug:I.src_slug[r[3]], fmt:I.fmt[r[4]], lang:I.lang[r[5]], sev:r[6]||'',
    tac:r[7], tech:r[8], prod:r[9], cat:r[10], status:r[11], lic:I.lic[r[12]], ctype:r[13]||"detection",
    hay:(r[1]+' '+r[2]+' '+r[8].join(' ')+' '+(r[9]||'')+' '+(r[10]||'')).toLowerCase(),
  }));
}

function renderArsenal(){
  if(!IDX) buildIndex();
  const v=$('#v-arsenal');
  v.innerHTML=`
  <div class="eyebrow"><span class="num">ARSENAL /</span> ${V.man.total.toLocaleString('pt-BR')} REGRAS · ${V.man.sources.length} FONTES</div>
  <h1 class="sec">Todas as regras, <span class="g">explicadas e editáveis</span></h1>
  <p class="sub">Busque por técnica (T1059), ferramenta (certutil), comportamento (lsass), fonte ou produto. Clique numa regra: você vê o arquivo original, cada campo explicado, contexto ATT&CK, e pode editar e baixar para ajustar ao seu ambiente.</p>
  <div class="arsenal">
    <aside class="filters" id="filters"></aside>
    <div>
      <input class="search" id="q" placeholder="buscar… ex.: lsass, T1003, certutil urlcache, password spray, vssadmin   (atalho: /)" value="${esc(A.q)}">
      <div class="rhead"><span class="cnt" id="cnt"></span>
        <select id="sort" class="btn sm" style="margin-left:auto"><option value="rel">relevância</option><option value="sev">severidade ↓</option><option value="title">título A→Z</option><option value="src">fonte</option></select>
        <button class="btn sm ${A.fav?'p':''}" id="favbtn">★ favoritas (${Object.keys(V.state.fav).length})</button>
        <button class="btn sm" id="heatbtn">⊞ mapa ATT&CK</button>
        <button class="btn sm" id="exportbtn">⬇ exportar lista (CSV)</button>
        <button class="btn sm" id="clearbtn">limpar filtros</button></div>
      <div id="heat" style="display:none" class="card"></div>
      <div class="rlist" id="rlist"></div>
      <div class="pager" id="pager"></div>
    </div>
  </div>`;
  $('#q').oninput=e=>{A.q=e.target.value; A.page=0; applyFilters();};
  $('#sort').value=A.sort; $('#sort').onchange=e=>{A.sort=e.target.value; applyFilters();};
  $('#favbtn').onclick=()=>{A.fav=!A.fav; A.page=0; renderArsenal();};
  $('#heatbtn').onclick=()=>{const h=$('#heat'); h.style.display=h.style.display==='none'?'block':'none'; if(h.style.display==='block') renderHeat();};
  $('#clearbtn').onclick=()=>{A.q='';A.src.clear();A.fmt.clear();A.sev.clear();A.tac.clear();A.ctype.clear();A.tech='';A.prod='';A.page=0;A.fav=false;renderArsenal();};
  $('#exportbtn').onclick=exportCSV;
  applyFilters();
}

function applyFilters(){
  const q=A.q.trim().toLowerCase(); const terms=q.split(/\s+/).filter(Boolean);
  let rows=IDX.filter(r=>{
    if(A.fav && !V.state.fav[r.slug+'::'+r.id]) return false;
    if(A.src.size && !A.src.has(r.src)) return false;
    if(A.fmt.size && !A.fmt.has(r.fmt)) return false;
    if(A.sev.size && !A.sev.has(r.sev||'none')) return false;
    if(A.ctype.size && !A.ctype.has(r.ctype)) return false;
    if(A.tac.size && !r.tac.some(t=>A.tac.has(t))) return false;
    if(A.tech && !r.tech.some(t=>t.startsWith(A.tech))) return false;
    if(A.prod && (r.prod||'').toLowerCase()!==A.prod) return false;
    if(terms.length){ for(const t of terms){ if(!r.hay.includes(t)) return false; } }
    return true;
  });
  if(terms.length && A.sort==='rel'){
    rows.forEach(r=>{let s=0; for(const t of terms){ if(r.title.toLowerCase().includes(t)) s+=3; if(r.tech.some(x=>x.toLowerCase()===t)) s+=4; } r._s=s;});
    rows.sort((a,b)=>b._s-a._s);
  } else if(A.sort==='sev'){ const o={critical:0,high:1,medium:2,low:3,informational:4,'':5}; rows.sort((a,b)=>(o[a.sev]??5)-(o[b.sev]??5)); }
  else if(A.sort==='title') rows.sort((a,b)=>a.title.localeCompare(b.title));
  else if(A.sort==='src') rows.sort((a,b)=>a.src.localeCompare(b.src)||a.title.localeCompare(b.title));
  A.rows=rows; renderFilters(rows); renderList();
}

function facet(rows, key, all){ const c={}; for(const r of rows){ const vals = key==='tac'? r.tac : [key==='sev'?(r.sev||'none'):(key==='ctype'?r.ctype:r[key])]; for(const v of vals){ if(v==null) continue; c[v]=(c[v]||0)+1; } } return c; }
function renderFilters(rows){
  const base = IDX; // contagens totais sempre do índice inteiro para orientação
  const fs=facet(rows,'src'), ff=facet(rows,'fmt'), fv=facet(rows,'sev'), ft=facet(rows,'tac');
  const group=(title,set,counts,order,label)=>`<div class="fgroup"><b>${title}</b>${order.filter(k=>counts[k]||set.has(k)).map(k=>`<div class="fopt ${set.has(k)?'on':''}" data-g="${title}" data-k="${esc(k)}"><span>${label(k)}</span><span class="n">${(counts[k]||0).toLocaleString('pt-BR')}</span></div>`).join('')}</div>`;
  const srcOrder=V.man.sources.map(s=>s.name);
  const fmtOrder=Object.keys(FMT_PT);
  const sevOrder=['critical','high','medium','low','informational','none'];
  const CT={detection:'Detecção',hunting:'Hunting',signature:'Assinatura (arquivo/rede)',playbook:'Playbook (resposta)'};
  const fct=facet(rows,'ctype');
  $('#filters').innerHTML=
    group('Tipo de conteúdo',A.ctype,fct,['detection','hunting','signature','playbook'],k=>CT[k]||k)+
    group('Fonte',A.src,fs,srcOrder,k=>k)+
    group('Formato',A.fmt,ff,fmtOrder,k=>FMT_PT[k]||k)+
    group('Severidade',A.sev,fv,sevOrder,k=>`<span class="sev ${k}">${SEV_PT[k==='none'?'':k]||k}</span>`)+
    group('Tática ATT&CK',A.tac,ft,TACTICS,k=>TACTIC_PT[k])+
    `<div class="fgroup"><b>Técnica (prefixo)</b><input class="search" style="padding:7px 10px;font-size:12px" id="techf" placeholder="T1059" value="${esc(A.tech)}"></div>
     <div class="fgroup"><b>Produto / logsource</b><input class="search" style="padding:7px 10px;font-size:12px" id="prodf" placeholder="windows, aws, linux…" value="${esc(A.prod)}"></div>`;
  $$('.fopt','#filters').forEach(o=>o.onclick=()=>{
    const set={'Tipo de conteúdo':A.ctype,Fonte:A.src,Formato:A.fmt,Severidade:A.sev,'Tática ATT&CK':A.tac}[o.dataset.g];
    set.has(o.dataset.k)? set.delete(o.dataset.k): set.add(o.dataset.k); A.page=0; applyFilters();
  });
  $('#techf').oninput=e=>{A.tech=e.target.value.trim().toUpperCase(); A.page=0; applyFilters();};
  $('#prodf').oninput=e=>{A.prod=e.target.value.trim().toLowerCase(); A.page=0; applyFilters();};
}

function renderList(){
  const rows=A.rows; const start=A.page*A.per; const slice=rows.slice(start,start+A.per);
  $('#cnt').innerHTML=`<b>${rows.length.toLocaleString('pt-BR')}</b> regra(s) · página ${A.page+1}/${Math.max(1,Math.ceil(rows.length/A.per))}`;
  $('#rlist').innerHTML= slice.length? slice.map(r=>`<div class="row" data-i="${r.i}">
      <div class="t">${esc(r.title)}</div><span class="sev ${sevClass(r.sev)}">${SEV_PT[r.sev]||'—'}</span>
      <div class="d">${esc(r.desc)||'<i style="color:var(--ink-faint)">sem descrição no arquivo original</i>'}</div>
      <div class="m"><span class="src">${esc(r.src)}</span><span class="tag ${r.ctype==='playbook'?'a':r.ctype==='hunting'?'b':r.ctype==='signature'?'':'s'}">${({detection:'detecção',hunting:'hunting',signature:'assinatura',playbook:'playbook'})[r.ctype]||r.ctype}</span><span class="tag">${FMT_PT[r.fmt]||r.fmt}</span>${r.prod?`<span class="tag b">${esc(r.prod)}</span>`:''}${r.tac.slice(0,2).map(t=>`<span class="tag v">${TACTIC_PT[t]||t}</span>`).join('')}${r.tech.slice(0,4).map(t=>`<span class="tech">${t}</span>`).join('')}${V.state.fav[r.slug+'::'+r.id]?'<span style="color:var(--amber)">★</span>':''}</div>
    </div>`).join('') : `<div class="loading">Nenhuma regra com esses filtros. Tente ampliar a busca.</div>`;
  $$('.row','#rlist').forEach(x=>x.onclick=()=>openRule(IDX[+x.dataset.i]));
  const pages=Math.ceil(rows.length/A.per);
  $('#pager').innerHTML= pages>1? `<button class="btn sm" ${A.page===0?'disabled':''} onclick="A.page--;renderList();window.scrollTo({top:0,behavior:'smooth'})">← anterior</button><span>${A.page+1} / ${pages}</span><button class="btn sm" ${A.page>=pages-1?'disabled':''} onclick="A.page++;renderList();window.scrollTo({top:0,behavior:'smooth'})">próxima →</button>`:'';
}

/* ---- mapa de cobertura ATT&CK (táticas × contagem) ---- */
function renderHeat(){
  const rows=A.rows; const c={}; TACTICS.forEach(t=>c[t]=0);
  rows.forEach(r=>r.tac.forEach(t=>{ if(c[t]!=null) c[t]++; }));
  const max=Math.max(1,...Object.values(c));
  $('#heat').innerHTML=`<h3 class="h" style="margin-top:0">Cobertura por tática ATT&CK (no conjunto filtrado)</h3>
  <p style="font-size:12.5px;color:var(--ink-dim);margin-bottom:10px">Clique numa tática para filtrar. Barras curtas = pontos cegos. Note: ${rows.filter(r=>!r.tac.length).length.toLocaleString('pt-BR')} regras não trazem tática mapeada (ex.: a maioria das YARA/Wazuh) — a cobertura real é maior que a visível.</p>
  <div class="bars">${TACTICS.map(t=>`<div class="barrow" style="cursor:pointer" onclick="A.tac.clear();A.tac.add('${t}');A.page=0;applyFilters();window.heatSeen=(window.heatSeen||new Set()).add('${t}');if(window.heatSeen.size>=8)badge('mitre_mapper')"><span class="lb">${TACTIC_PT[t]}</span><div class="bb"><i style="width:${c[t]/max*100}%"></i></div><span class="nn">${c[t].toLocaleString('pt-BR')}</span></div>`).join('')}</div>`;
}

function exportCSV(){
  const h=['id','title','source','format','severity','tactics','techniques','product','category','status','license'];
  const lines=[h.join(',')].concat(A.rows.map(r=>[r.id,r.title,r.src,r.fmt,r.sev,r.tac.join('|'),r.tech.join('|'),r.prod||'',r.cat||'',r.status||'',r.lic].map(x=>'"'+String(x).replace(/"/g,'""')+'"').join(',')));
  download(`vigia_regras_${A.rows.length}.csv`, lines.join('\n'), 'text/csv');
}

/* ---- carregar dados sob demanda ----
   Formato novo (GitHub Pages): data/chunks/<fonte>/<n>.json, bloco = FNV-1a(id) % nblocos.
   Formato antigo (data/shards/<fonte>.json) continua aceito como fallback. */
function fnv1a(s){ let h=0x811c9dc5; for(const b of new TextEncoder().encode(s)){ h^=b; h=Math.imul(h,0x01000193)>>>0; } return h>>>0; }
async function getShard(slug, id){
  const src=V.man.sources.find(s=>s.slug===slug);
  if(V.man.chunked && src && src.chunks){
    const n=fnv1a(String(id))%src.chunks; const key=slug+'/'+n;
    if(!V.shards[key]){ const r=await fetch(`data/chunks/${slug}/${n}.json`); if(!r.ok) throw new Error('bloco '+key+' HTTP '+r.status); V.shards[key]=await r.json(); }
    return V.shards[key];
  }
  if(V.shards[slug]) return V.shards[slug];
  toast('⏳','Carregando fonte '+slug+'…');
  const r=await fetch(`data/shards/${slug}.json`); V.shards[slug]=await r.json(); return V.shards[slug];
}

/* ---- modal da regra ---- */
async function openRule(r){
  openModal(`<div class="mhead"><h2>${esc(r.title)}</h2><button class="x" onclick="closeModal()">✕</button></div><div class="mbody"><div class="loading">Carregando arquivo original…<div class="bar"><i style="width:60%"></i></div></div></div>`);
  let sh; try{ sh=await getShard(r.slug, r.id); }catch(e){ $('#mbox .mbody').innerHTML=`<div class="loading">Falha ao carregar o arquivo original: ${esc(e.message)}</div>`; return; }
  const d=sh[r.id]; if(!d){ $('#mbox .mbody').innerHTML='<div class="loading">Regra não encontrada no bloco de dados.</div>'; return; }
  const key=r.slug+'::'+r.id;
  // XP / badges
  if(!V.state.seen[key]){ V.state.seen[key]=1; save(); const n=Object.keys(V.state.seen).length; if(n===1) badge('first_rule'); addXP(n<=50?8:3,'Regra estudada: '+r.title.slice(0,40));
    const fmts=new Set(Object.keys(V.state.seen).map(k=>IDX.find(x=>x.slug+'::'+x.id===k)?.fmt).filter(Boolean)); if(fmts.size>=5) badge('polyglot');
    const bySig=Object.keys(V.state.seen).filter(k=>IDX.find(x=>x.slug+'::'+x.id===k)?.fmt==='sigma').length; if(bySig>=10) badge('sigma_reader');
    const byYara=Object.keys(V.state.seen).filter(k=>IDX.find(x=>x.slug+'::'+x.id===k)?.fmt==='yara').length; if(byYara>=10) badge('yara_reader'); }
  const fname=d.path.split('/').pop();
  const fav=!!V.state.fav[key];
  $('#mbox').innerHTML=`
  <div class="mhead"><div style="flex:1"><h2>${esc(r.title)}</h2>
    <div class="pill-row"><span class="sev ${sevClass(r.sev)}">${SEV_PT[r.sev]||'sem severidade'}</span><span class="tag v">${esc(r.src)}</span><span class="tag">${esc(r.lang)}</span>${r.status?`<span class="tag">${esc(r.status)}</span>`:''}<span class="tag">${esc(r.lic)}</span>${r.tac.map(t=>`<span class="tag v">${TACTIC_PT[t]||t}</span>`).join('')}${r.tech.map(t=>`<a class="tag a" href="https://attack.mitre.org/techniques/${t.replace('.','/')}/" target="_blank" rel="noopener">${t} ↗</a>`).join('')}</div></div>
    ${r.tech.length?`<button class="btn sm a" id="addcase" title="Adicionar este alerta ao caso de atribuição por TTP">+ caso</button>`:''}<button class="btn sm ${fav?'a':''}" id="favtog">★ ${fav?'favorita':'favoritar'}</button><button class="x" onclick="closeModal()">✕</button></div>
  <div class="mbody">
    <p style="font-size:14px;color:var(--ink-dim);margin-bottom:12px">${esc(d.desc||r.desc)||'<i>sem descrição no arquivo</i>'}</p>
    <div id="curation" style="margin-bottom:10px">${curationBar(r,key)}</div>
    <div class="mtabs">
      <button class="mtab on" data-p="understand">① Entenda</button>
      <button class="mtab" data-p="logic">② Veja a lógica</button>
      <button class="mtab" data-p="data">③ Prepare os dados</button>
      <button class="mtab" data-p="experiment">④ Experimente</button>
      <button class="mtab" data-p="edit">⑤ Adapte</button>
      <button class="mtab" data-p="investigate">⑥ Investigue</button>
      <button class="mtab" data-p="origin">⑦ Origem & versões</button></div>
    <div class="mpane on" id="p-understand">${understandPane(r,d)}<div id="ctx-attack"></div></div>
    <div class="mpane" id="p-logic">${term(fname, d.raw, r.fmt, `<button class="btn sm" id="cp">copiar</button><button class="btn sm p" id="dl">⬇ baixar .${FMT_EXT[r.fmt]||'txt'}</button>`)}
      ${fieldsPane(r,d)}</div>
    <div class="mpane" id="p-data">${dataPane(r,d)}<div id="ctx-logs"></div></div>
    <div class="mpane" id="p-experiment">${experimentPane(r,d,key)}<div id="ctx-valid"></div></div>
    <div class="mpane" id="p-edit">
      <div class="note tip"><span class="ni">▸</span><div><b>Adapte ao seu ambiente e baixe.</b> Ajuste caminhos, nomes de conta, limiares e filtros. O validador checa a estrutura do formato. Sua versão fica salva neste navegador e marca a regra como "adaptada por você".</div></div>
      <textarea class="editor" id="ed">${esc(V.state['edit_'+key]||d.raw)}</textarea>
      <div class="toolbar"><button class="btn p" id="eddl">⬇ baixar minha versão</button><button class="btn" id="edsave">💾 salvar rascunho</button><button class="btn" id="edreset">↺ restaurar original</button><button class="btn v" id="edlint">✓ validar estrutura</button>${r.fmt==='sigma'?'<button class="btn" id="edsim">▶ simular com evento</button>':''}<button class="btn" id="edforge">⚒ abrir na Forja</button><button class="btn a" id="edpkg">📦 baixar pacote de detecção</button></div>
      <div id="lint"></div></div>
    <div class="mpane" id="p-investigate"><div id="ctx-groups"></div>${investigatePane(r,d)}</div>
    <div class="mpane" id="p-origin">${originPane(r,d)}</div>
  </div>`;
  $$('.mtab','#mbox').forEach(t=>t.onclick=()=>{$$('.mtab','#mbox').forEach(x=>x.classList.remove('on'));t.classList.add('on');$$('.mpane','#mbox').forEach(p=>p.classList.remove('on'));$('#p-'+t.dataset.p).classList.add('on'); if(t.dataset.p==='understand'&&!V.state['explained_'+key]){V.state['explained_'+key]=1;save();}});
  $('#cp').onclick=()=>copy(d.raw); $('#dl').onclick=()=>download(fname, d.raw);
  if($('#edsim')) $('#edsim').onclick=()=>{$$('.mtab','#mbox').forEach(x=>x.classList.remove('on'));$('.mtab[data-p="experiment"]').classList.add('on');$$('.mpane','#mbox').forEach(p=>p.classList.remove('on'));$('#p-experiment').classList.add('on');$('#ed')&&runSim(r,$('#ed').value,key);};
  $('#edpkg').onclick=()=>downloadPackage(r,d,key);
  if($('#addcase')) $('#addcase').onclick=()=>caseAddRule(r);
  if(r.tech.length && window.groupsForRuleHTML){ groupsForRuleHTML(r).then(h=>{ const z=$('#ctx-groups'); if(z) z.innerHTML=h; }); }
  if(r.tech.length && window.attackContextHTML){ (async()=>{ const [c,l,v]=await Promise.all([attackContextHTML(r),attackLogsHTML(r),attackValidationHTML(r)]); const a=$('#ctx-attack'),b=$('#ctx-logs'),z=$('#ctx-valid'); if(a) a.innerHTML=c; if(b) b.innerHTML=l; if(z) z.innerHTML=v; })(); }
  if(r.fmt==='sigma'){ setTimeout(()=>{ const sr=$('#simrun'); if(sr) sr.onclick=()=>runSim(r, (V.state['edit_'+key]||d.raw), key); const se=$('#simedit'); if(se) se.onclick=()=>{ const t=prompt('Cole um evento JSON para testar contra a regra:','{"ParentImage":"C:\\\\...\\\\WINWORD.EXE","Image":"C:\\\\Windows\\\\System32\\\\cmd.exe","CommandLine":"cmd /c x"}'); if(!t) return; try{ const ev=JSON.parse(t); const rule=Sigma.parseSigma(V.state['edit_'+key]||d.raw); const res=Sigma.evaluate(rule,ev); $('#simout').innerHTML=`<div class="lint ${res.matched?'bad':'ok'}">${res.matched?'A regra DISPARARIA para este evento.':'A regra NÃO dispararia.'}</div>`+term('evento',JSON.stringify(ev,null,2),'kql-md')+`<div style="font-size:12.5px;color:var(--ink-dim);margin-top:8px">${Object.entries(res.blocks).map(([n,b])=>`<code style="color:${b.hit?'var(--signal)':'var(--ink-3)'}">${esc(n)} ${b.hit?'✓':'✗'}</code>: ${b.fields.map(f=>`<span style="color:${f.hit?'var(--ink)':'var(--ink-3)'}">${esc(f.field)} ${f.hit?'✓':'✗'}</span>`).join(', ')}`).join('<br>')}</div>`; }catch(e){ toast('✗','JSON inválido'); } }; },0); }
  $('#favtog').onclick=()=>{ if(V.state.fav[key]) delete V.state.fav[key]; else V.state.fav[key]=1; save(); openRule(r); };
  $('#eddl').onclick=()=>download(fname.replace(/(\.[^.]+)$/, '_custom$1'), $('#ed').value);
  $('#edsave').onclick=()=>{V.state['edit_'+key]=$('#ed').value; save(); toast('💾','Rascunho salvo neste navegador');};
  $('#edreset').onclick=()=>{$('#ed').value=d.raw; delete V.state['edit_'+key]; save();};
  $('#edlint').onclick=()=>{$('#lint').innerHTML=lintRule($('#ed').value, r.fmt);};
  $('#edforge').onclick=()=>{ closeModal(); window.forgeImport?.($('#ed').value, r.fmt, r.title); };
}

/* Campos explicados: percorre o texto bruto e anota cada campo de topo encontrado */
function fieldsPane(r,d){
  const dict=FIELDS[r.fmt]||{}; const raw=d.raw; const found=[];
  const tryKey=(k,label)=>{ if(dict[k] && !found.some(f=>f.k===k)) found.push({k,label:label||k,v:dict[k]}); };
  if(r.fmt==='sigma'||r.fmt==='splunk'||r.fmt==='sentinel'||r.fmt==='panther'){
    for(const m of raw.matchAll(/^([A-Za-z_][\w]*):/gm)) tryKey(m[1]);
    if(r.fmt==='sigma'){ if(/^\s+condition:/m.test(raw)) tryKey('detection.condition','condition'); if(/^\s+filter/m.test(raw)) tryKey('detection.filter','filter_*'); if(/^\s+selection/m.test(raw)) tryKey('detection.selection','selection'); }
    if(r.fmt==='panther'){ if(/def rule\(/.test(raw)) tryKey('rule(event)'); if(/def title\(/.test(raw)) tryKey('title(event)'); if(/def severity\(/.test(raw)) tryKey('severity(event)'); }
  } else if(r.fmt==='elastic'){
    for(const m of raw.matchAll(/^\[(\[?rule\.threat\]?\]|metadata|rule)\]/gm)) tryKey(m[0].includes('threat')?'[[rule.threat]]':'['+m[1]+']');
    for(const m of raw.matchAll(/^([a-z_]+)\s*=/gm)) tryKey(m[1]);
    if(/\[rule\.threshold\]/.test(raw)) tryKey('threshold'); if(/\[rule\.new_terms\]/.test(raw)) tryKey('new_terms');
  } else if(r.fmt==='wazuh'){
    tryKey('<rule id level>'); if(/<group name/.test(raw)) tryKey('<group name>');
    for(const m of raw.matchAll(/<([a-z_]+)[\s>\/]/g)) tryKey(m[1]);
    if(/frequency=/.test(raw)) tryKey('frequency');
  } else if(r.fmt==='yara'){
    tryKey('rule <nome> : tags'); for(const k of ['meta','strings','condition']) if(new RegExp('^\\s*'+k+':','m').test(raw)) tryKey(k);
    if(/\b(ascii|wide|nocase|fullword|xor|base64)\b/.test(raw)) tryKey('modificadores'); if(/^import /m.test(raw)) tryKey('imports');
  } else if(r.fmt==='yaral'){
    tryKey('rule <nome>'); for(const k of ['meta','events','match','outcome','condition','options']) if(new RegExp('^\\s*'+k+':','m').test(raw)) tryKey(k);
  } else if(r.fmt==='falco'){
    for(const k of ['- rule','- macro','- list']) if(raw.includes(k+':')) tryKey(k);
    for(const k of ['desc','condition','output','priority','tags','enabled']) if(new RegExp('^\\s+'+k+':','m').test(raw)) tryKey(k);
  } else if(r.fmt==='kql-md'){
    const q=d.q||raw; tryKey('Tabela'); for(const k of ['| where','| summarize','| extend','| project','| join']) if(q.includes(k)) tryKey(k); if(/\blet\b/.test(q)) tryKey('let'); if(/\bago\(|\bbin\(/.test(q)) tryKey('ago()/bin()');
  } else if(r.fmt==='gcp'){ Object.keys(dict).forEach(k=>tryKey(k)); }
  if(!found.length) return `<div class="note warn"><span class="ni">▸</span><div>Não identifiquei campos conhecidos neste arquivo. Veja a Academia → Lição 07 para o dicionário completo do formato <b>${FMT_PT[r.fmt]}</b>.</div></div>`;
  return `<p style="font-size:13px;color:var(--ink-dim);margin-bottom:10px">Campos presentes <b>neste arquivo</b>, na ordem em que aparecem. Cada um: o que é, por que existe, exemplo.</p>
  <div class="fieldexp">${found.map(f=>`<div class="fx"><code>${esc(f.label)}</code><span class="w"><b style="color:var(--ink)">${esc(f.v[0])}</b> ${f.v[1]?'— '+esc(f.v[1]):''}</span>${f.v[2]?`<div class="v">${esc(f.v[2])}</div>`:''}</div>`).join('')}</div>
  <div class="note tip" style="margin-top:12px"><span class="ni">▸</span><div>Ver o dicionário completo deste formato (incluindo campos que esta regra não usa): <button class="btn sm" onclick="closeModal();go('academy');setTimeout(()=>showLesson('formats'),200)">Academia → Lição 07</button></div></div>`;
}

function ctxPane(r,d){
  const info=FORMAT_INFO[r.fmt];
  return `<div class="grid g2">
   <div class="card"><h3 class="h" style="margin-top:0">MITRE ATT&CK</h3>${r.tac.length||r.tech.length? `<div class="pill-row">${r.tac.map(t=>`<span class="tag v">${TACTIC_PT[t]||t}</span>`).join('')}</div><div class="pill-row">${r.tech.map(t=>`<a class="tag a" href="https://attack.mitre.org/techniques/${t.replace('.','/')}/" target="_blank" rel="noopener">${t} ↗</a>`).join('')}</div>`:'<p style="font-size:13px;color:var(--ink-faint)">Sem mapeamento no arquivo. Exercício: qual tática/técnica você atribuiria? Anote na Forja.</p>'}</div>
   <div class="card"><h3 class="h" style="margin-top:0">Falsos positivos declarados</h3>${d.fp&&d.fp.length? `<ul style="font-size:13px;color:var(--ink-dim);margin-left:16px">${d.fp.map(x=>`<li>${esc(x)}</li>`).join('')}</ul>`:'<p style="font-size:13px;color:var(--ink-faint)">O autor não documentou FPs. Antes de produzir, rode contra 7 dias de dados e anote o que aparece.</p>'}</div>
   <div class="card"><h3 class="h" style="margin-top:0">Referências</h3>${d.ref&&d.ref.length? `<ul style="font-size:12.5px;margin-left:16px">${d.ref.slice(0,10).map(x=>`<li><a href="${esc(x)}" target="_blank" rel="noopener" style="word-break:break-all">${esc(x)}</a></li>`).join('')}</ul>`:'<p style="font-size:13px;color:var(--ink-faint)">Sem referências.</p>'}</div>
   <div class="card"><h3 class="h" style="margin-top:0">Sobre o formato ${info?.name||r.fmt}</h3><p style="font-size:13px;color:var(--ink-dim)">${info?.what||''}</p><p style="font-size:12px;color:var(--ink-faint);margin-top:6px;font-family:var(--mono)">motor: ${info?.engine||'—'}</p><p style="font-size:12px;color:var(--ink-faint);margin-top:6px">Licença: <b>${esc(r.lic)}</b> — ${LIC_NOTE[r.lic]||'verifique antes de redistribuir.'}</p></div>
  </div>`;
}
const LIC_NOTE={'DRL 1.1':'Detection Rule License — uso, cópia e modificação livres; mantenha atribuição e a nota de licença.','Apache-2.0':'uso comercial permitido; mantenha NOTICE/atribuição.','MIT':'uso livre com atribuição.','GPLv2':'copyleft: derivados devem ser GPLv2 se redistribuídos.','Elastic License v2':'uso livre; não pode fornecer como serviço gerenciado concorrente; leia o texto.','BSD-3':'uso livre com atribuição; sem endosso.'};

function studyPane(r,d){
  const q=(d.q||d.raw);
  const hints=[];
  if(/\|contains|\|endswith|has |contains/.test(q)) hints.push('Localize os <b>modificadores/operadores</b> de comparação e pergunte: por que o autor escolheu "contém" em vez de "igual"? (dica: caminhos variam).');
  if(/filter|and not|not\(|<if_sid>.*level="0"/.test(q)) hints.push('Encontre a <b>exclusão</b> (filtro). Ela é específica o bastante para o atacante não conseguir se disfarçar como o caso legítimo?');
  if(/frequency|threshold|summarize|match:|sequence|tstats.*by/.test(q)) hints.push('Esta regra tem <b>correlação/contagem</b>. Identifique: agrupa por qual entidade? em que janela? qual limiar? O limiar pegaria um atacante lento?');
  if(r.fmt==='yara') hints.push('Conte quantas <b>strings</b> a condição exige. Com muitas strings e "all of them", a regra é precisa mas frágil; com "2 of them", mais abrangente. Qual o trade-off aqui?');
  if(!r.tac.length) hints.push('Não há tática ATT&CK mapeada. <b>Atribua uma</b>: qual objetivo do adversário esse comportamento serve?');
  hints.push('Imagine o <b>log real</b> que faria esta regra disparar. Escreva uma linha dele mentalmente. Se não consegue, você ainda não entendeu a regra.');
  hints.push('<b>Evasão:</b> como um atacante escaparia desta regra com a menor mudança possível? Essa resposta é a próxima regra que você escreve.');
  return `<div class="feynman"><div class="lbl">COMO ESTUDAR ESTA REGRA (uma ação por vez)</div>${hints.map((h,i)=>`<p><span class="em">${i+1}.</span> ${h}</p>`).join('')}</div>
  <div class="note osint"><span class="ni">✶</span><div><b>Caminho recomendado:</b> leia a aba <b>Regra</b> achando as 5 peças da Lição 01 → confira na aba <b>Campos</b> o que não entendeu → vá em <b>Editar</b> e adapte um valor ao seu ambiente → baixe. Fez isso com 20 regras? Você já pensa como engenheiro de detecção.</div></div>`;
}

/* ---- validador estrutural (leve, por formato) ---- */
function lintRule(text, fmt){
  const errs=[], warns=[];
  const has=(re)=>re.test(text);
  if(fmt==='sigma'){
    for(const k of ['title','logsource','detection']) if(!has(new RegExp('^'+k+':','m'))) errs.push(`campo obrigatório ausente: <code>${k}</code>`);
    if(!has(/^\s+condition:/m)) errs.push('<code>detection.condition</code> ausente');
    if(!has(/^id:\s*[0-9a-f-]{36}/m)) warns.push('<code>id</code> deveria ser um UUID v4');
    if(!has(/^level:\s*(informational|low|medium|high|critical)/m)) warns.push('<code>level</code> ausente ou inválido');
    if(!has(/^tags:/m)) warns.push('sem <code>tags</code> ATT&CK — você perde o mapa de cobertura');
    if(!has(/^falsepositives:/m)) warns.push('sem <code>falsepositives</code> — documente o ruído esperado');
    if(/^\s+Image:\s*'?[A-Za-z]+\.exe/m.test(text)) warns.push('<code>Image: nome.exe</code> com igualdade exata raramente casa; use <code>|endswith: \'\\\\nome.exe\'</code>');
    const tabs=/\t/.test(text); if(tabs) errs.push('YAML não aceita TAB para indentação — use espaços');
  } else if(fmt==='elastic'){
    for(const k of ['name','rule_id','query','type','severity','risk_score','language']) if(!has(new RegExp('^'+k+'\\s*=','m'))) errs.push(`<code>${k}</code> ausente no [rule]`);
    if(!has(/^\[rule\]/m)) errs.push('bloco <code>[rule]</code> ausente');
  } else if(fmt==='splunk'){
    for(const k of ['name','id','search','description','type','data_source']) if(!has(new RegExp('^'+k+':','m'))) errs.push(`<code>${k}</code> ausente`);
    if(!has(/_filter`?\s*$/m)) warns.push('a busca não termina com a macro <code>&lt;nome&gt;_filter</code> — padrão Splunk para exclusões locais');
  } else if(fmt==='sentinel'){
    for(const k of ['id','name','query','severity']) if(!has(new RegExp('^'+k+':','m'))) errs.push(`<code>${k}</code> ausente`);
    if(has(/^kind:\s*Scheduled/m)||!has(/^kind:/m)){ for(const k of ['queryFrequency','queryPeriod','triggerOperator','triggerThreshold']) if(!has(new RegExp('^'+k+':','m'))) warns.push(`<code>${k}</code> ausente (necessário para regra agendada)`); }
    if(!has(/^entityMappings:/m)) warns.push('sem <code>entityMappings</code> — o grafo de investigação do Sentinel não saberá quem é conta/host/IP');
  } else if(fmt==='wazuh'){
    if(!has(/<rule\s+id="\d+"\s+level="\d+"/)) errs.push('<code>&lt;rule id=".." level=".."&gt;</code> ausente ou malformado');
    if(!has(/<description>/)) errs.push('<code>&lt;description&gt;</code> ausente');
    const id=text.match(/<rule\s+id="(\d+)"/); if(id && +id[1]<100000) warns.push('regras customizadas devem usar id ≥ 100000 (ids menores são reservados ao ruleset oficial)');
    if(!has(/<if_sid>|<if_group>|<decoded_as>|<if_matched_sid>/)) warns.push('sem <code>if_sid/if_group/decoded_as</code> — a regra pode ficar fora da árvore e nunca ser avaliada');
    if(!has(/<group>/)) warns.push('sem <code>&lt;group&gt;</code> de tags');
    const open=(text.match(/<rule\b/g)||[]).length, close=(text.match(/<\/rule>/g)||[]).length; if(open!==close) errs.push(`tags &lt;rule&gt; abertas (${open}) ≠ fechadas (${close})`);
  } else if(fmt==='yara'){
    if(!has(/^\s*rule\s+\w+/m)) errs.push('declaração <code>rule nome</code> ausente');
    if(!has(/^\s*condition:/m)) errs.push('<code>condition:</code> ausente');
    const o=(text.match(/\{/g)||[]).length, c=(text.match(/\}/g)||[]).length; if(o!==c) errs.push(`chaves desbalanceadas: { ${o} vs } ${c}`);
    if(has(/^\s*strings:/m)){ const names=[...text.matchAll(/^\s*(\$\w*)\s*=/gm)].map(m=>m[1]); const cond=text.split(/condition:/)[1]||''; for(const n of names){ if(n!=='$' && !cond.includes(n) && !/\bthem\b|\$\w*\*/.test(cond)) warns.push(`string <code>${n}</code> definida mas não usada na condition`); } }
    if(!has(/filesize|uint16\(0\)|uint32\(0\)/)) warns.push('considere <code>uint16(0) == 0x5a4d</code> e/ou <code>filesize &lt;</code> para performance e precisão');
  } else if(fmt==='yaral'){
    if(!has(/^\s*rule\s+\w+\s*\{/m)) errs.push('declaração <code>rule nome {</code> ausente');
    for(const k of ['events','condition']) if(!has(new RegExp('^\\s*'+k+':','m'))) errs.push(`seção <code>${k}:</code> ausente`);
    if(!has(/^\s*meta:/m)) warns.push('sem <code>meta:</code> (author, description, severity)');
  } else if(fmt==='falco'){
    if(!has(/^- rule:/m)) errs.push('<code>- rule:</code> ausente');
    for(const k of ['condition','output','priority']) if(!has(new RegExp('^\\s+'+k+':','m'))) errs.push(`<code>${k}</code> ausente`);
  } else if(fmt==='panther'){
    for(const k of ['AnalysisType','RuleID','Enabled','Severity','LogTypes']) if(!has(new RegExp('^'+k+':','m'))) errs.push(`<code>${k}</code> ausente`);
    if(!has(/def rule\(event\)/)) warns.push('função <code>def rule(event)</code> não encontrada no texto (pode estar em arquivo .py separado)');
    if(!has(/^Tests:/m)) warns.push('sem <code>Tests:</code> — Panther espera testes unitários');
  } else { warns.push('validação estrutural não disponível para este formato; verifique na ferramenta nativa.'); }
  if(!errs.length && !warns.length) return `<div class="lint ok">✓ estrutura válida para ${FMT_PT[fmt]||fmt}. Próximo passo: testar na ferramenta real com um evento de ataque e um dia de dados normais.</div>`;
  return (errs.length?`<div class="lint bad"><b>✗ ${errs.length} erro(s) estrutural(is)</b><ul>${errs.map(e=>`<li>${e}</li>`).join('')}</ul></div>`:'')+(warns.length?`<div class="lint warn"><b>⚠ ${warns.length} aviso(s) de qualidade</b><ul>${warns.map(e=>`<li>${e}</li>`).join('')}</ul></div>`:'');
}
/* ===== estados de curadoria ===== */
function curationBar(r,key){
  const states=[]; states.push('imported');
  if(V.state['explained_'+key]) states.push('explained');
  if(V.state['sim_'+key]) states.push('simulated');
  if(V.state['edit_'+key]) states.push('adapted');
  return `<div class="pill-row" style="align-items:center"><span style="font-family:var(--mono);font-size:10px;color:var(--ink-faint);letter-spacing:.1em">ESTADO:</span>${Object.entries(CURATION).map(([k,c])=>`<span class="tag" title="${esc(c[1])}" style="${states.includes(k)?`color:${c[2]};border-color:${c[2]}`:'opacity:.4'}">${states.includes(k)?'●':'○'} ${c[0]}</span>`).join('')}<span class="tag" style="opacity:.6" title="A explicação é apoio de estudo gerado pelo guia, não validação. 'Simulada' = lógica checada no navegador, não teste no mecanismo real.">ⓘ o que significam</span></div>`;
}
/* ===== ① ENTENDA ===== */
function understandPane(r,d){
  const info=FORMAT_INFO[r.fmt]; const inv=investigateFor(r.tac);
  const scenario = r.desc||d.desc||'';
  return `<div class="feynman"><div class="lbl">O QUE ESTA REGRA DETECTA — EM LINGUAGEM SIMPLES</div>
    <p>${esc(scenario)||'Esta regra não traz descrição no arquivo original. Veja a lógica na aba ② para inferir o comportamento.'}</p>
    ${r.tac.length?`<p style="margin-top:8px"><span class="em">Objetivo do adversário:</span> ${r.tac.map(t=>TACTIC_PT[t]||t).join(', ')}${r.tech.length?` (${r.tech.join(', ')})`:''}. ${TACTIC_HINT[r.tac[0]]||''}</p>`:''}</div>
  <div class="grid g2">
    <div class="card"><h3 class="h" style="margin-top:0">Cenário</h3><p style="font-size:13px;color:var(--ink-dim)">${CENARIO(r)}</p></div>
    <div class="card"><h3 class="h" style="margin-top:0">O que ela <b>não</b> vê (ponto cego)</h3><p style="font-size:13px;color:var(--ink-dim)">${BLINDSPOTS[r.fmt]||'Toda regra tem limites: campos ausentes, evasão por variação mínima, e atividade legítima parecida. Veja a aba ④ para testar o limite.'}</p></div>
  </div>
  <div class="note tip"><span class="ni">▸</span><div><b>Pergunta-guia (o diferencial):</b> ao sair deste modal você deve saber responder — <i>o que ela detecta, de quais dados depende (aba ③), por que dispararia (aba ④) e como provar que funciona (aba ④/⑤)</i>.</div></div>`;
}
const TACTIC_HINT={'Credential Access':'Roubar credenciais é o que permite o atacante "virar" usuário legítimo e se mover.','Execution':'Rodar código é o passo que transforma o acesso em ação.','Persistence':'Garantir que volta mesmo após reboot.','Privilege Escalation':'Sair de usuário comum para admin/root.','Defense Evasion':'Apagar rastros e cegar defesas.','Lateral Movement':'Pular de máquina em máquina rumo ao alvo.','Command and Control':'Telefonar para casa e receber ordens.','Exfiltration':'Levar os dados para fora.','Impact':'O dano final (ex.: ransomware).','Discovery':'Mapear o ambiente invadido.','Initial Access':'A porta de entrada.','Collection':'Reunir os dados antes de levar.'};
function CENARIO(r){
  const c=r.cat||''; const map={process_creation:'Um processo é criado no endpoint. A regra inspeciona quem o criou (pai), o que ele é (imagem) e o que ele faz (linha de comando).',process_access:'Um processo tenta ler a memória de outro — padrão de roubo de credenciais quando o alvo é o lsass.',network_connection:'Um processo abre uma conexão de rede. A regra olha destino, porta e quem iniciou.',registry_set:'Uma chave de registro é escrita — frequentemente autostart (persistência).',security:'Um evento de autenticação/segurança do Windows. Logon, falha, criação de conta.',ps_script:'Um script PowerShell é executado — a regra lê o conteúdo real, mesmo ofuscado.',webserver:'Uma requisição chega ao servidor web — a regra procura payloads de ataque.',};
  if(map[c]) return map[c];
  if(r.fmt==='yara') return 'Um arquivo (ou região de memória) é varrido. A regra procura strings e padrões de bytes característicos; se achar o suficiente, classifica.';
  if(r.fmt==='suricata') return 'Um pacote/fluxo de rede passa pelo sensor. A regra casa protocolo, conteúdo e contexto para sinalizar atividade maliciosa.';
  if(r.fmt==='playbook') return 'Este não é uma regra de detecção, e sim um PLAYBOOK de resposta: um fluxo de ações automatizadas disparado após um alerta. Veja a aba ⑥ para o procedimento.';
  return 'Um evento da fonte indicada é avaliado contra a lógica da regra.';
}
/* ===== ③ PREPARE OS DADOS ===== */
function dataPane(r,d){
  const tel=telemetryFor(r);
  if(!tel) return `<div class="note warn"><span class="ni">▸</span><div>Telemetria específica não catalogada para <b>${esc([r.prod,r.cat].filter(Boolean).join('/')||r.fmt)}</b>. Regra geral: identifique a fonte do log que contém os campos usados na aba ②, garanta a coleta e o encaminhamento ao seu SIEM, e confirme que os campos chegam com os nomes esperados.</div></div>`;
  const t=tel.t;
  return `<div class="note tip"><span class="ni">▸</span><div><b>Uma regra correta não dispara se os dados não chegam.</b> Confira origem, coleta e campos antes de confiar na cobertura.</div></div>
  <div class="kv"><dt>Origem do log</dt><dd><b>${esc(t.src)}</b></dd><dt>Como coletar</dt><dd>${esc(t.collect)}</dd></div>
  <h3 class="h">Campos obrigatórios/úteis</h3><div class="pill-row">${t.fields.map(f=>`<span class="tag b">${esc(f)}</span>`).join('')}</div>
  ${t.sample?`<h3 class="h">Exemplo de evento (como chega ao SIEM)</h3>${term('evento.json', JSON.stringify(t.sample,null,2),'kql-md')}`:''}
  <div class="note warn"><span class="ni">▸</span><div><b>Teste de sanidade:</b> antes de ativar a regra, rode uma busca pela fonte acima e confirme que há eventos recentes e que os campos da aba ② existem com esses nomes. Sem isso, a regra fica silenciosa — a pior falha de detecção, porque passa despercebida.</div></div>`;
}
/* ===== ④ EXPERIMENTE ===== */
function experimentPane(r,d,key){
  if(r.fmt!=='sigma') return `<div class="note warn"><span class="ni">▸</span><div>A simulação interativa de eventos está disponível para regras <b>Sigma</b> (a lógica é estruturada e portável). Para <b>${FMT_PT[r.fmt]||r.fmt}</b>, use a aba ② para ler a lógica e teste no mecanismo nativo:<br>${(PLATFORM_COMPAT[r.fmt]||[]).slice(0,1).map(x=>`<b>${x[0]}</b>`).join('')} — ${FORMAT_INFO[r.fmt]?.engine||''}.<br><br><b>Dica:</b> importe a intenção para Sigma na Forja (quando aplicável) para poder simular, ou escreva 2 eventos à mão: um que deveria disparar e um que não.</div></div>`;
  return `<div class="note tip"><span class="ni">▸</span><div><b>Simulação didática no navegador.</b> Geramos um evento que <span style="color:var(--sig)">deveria disparar</span> e variações que <span style="color:var(--red)">não deveriam</span>, e mostramos <b>por quê</b>, campo a campo. Isso verifica a <b>lógica</b> — não é teste no mecanismo real.</div></div>
  <div class="toolbar"><button class="btn p" id="simrun">▶ rodar simulação</button><button class="btn" id="simedit">✎ editar evento manualmente</button></div>
  <div id="simout"></div>`;
}
function runSim(r, yamlText, key){
  const host=$('#simout')||(()=>{const t=$('.mtab[data-p="experiment"]'); t&&t.click(); return $('#simout');})();
  try{
    const rule=Sigma.parseSigma(yamlText);
    if(!Object.keys(rule.blocks).length){ host.innerHTML='<div class="lint bad">Não consegui extrair a lógica (detection) desta regra.</div>'; return; }
    const {positive,negatives}=Sigma.genEvents(rule);
    const cases=[{label:'deveria DISPARAR (evento de ataque sintético)',ev:positive,expect:true},...negatives.map(n=>({label:n.label,ev:n.ev,expect:false}))];
    let pass=0;
    const html=cases.map(c=>{
      const res=Sigma.evaluate(rule,c.ev); const ok=res.matched===c.expect; if(ok)pass++;
      return `<div class="card" style="border-color:${res.matched?'var(--signal)':'var(--rule)'}">
        <div class="pill-row" style="justify-content:space-between"><b style="font-size:13px">${esc(c.label)}</b><span class="sev ${res.matched?'high':'low'}">${res.matched?'DISPAROU':'não disparou'} ${ok?'✓ esperado':'✗ inesperado'}</span></div>
        ${term('evento', JSON.stringify(c.ev,null,2),'kql-md')}
        <div style="font-size:12.5px;color:var(--ink-dim)">${Object.entries(res.blocks).map(([n,b])=>`<div style="margin:5px 0"><code style="color:${b.hit?'var(--signal)':'var(--ink-3)'}">${esc(n)}</code> ${b.hit?'casou':'não casou'}: ${b.fields.map(f=>`<span title="valores: ${esc((f.values||[]).join(' | '))}" style="color:${f.hit?'var(--ink)':'var(--ink-3)'}">${esc(f.field)}${f.mods&&f.mods.length?'|'+f.mods.join('|'):''} ${f.hit?'✓':'✗'}</span>`).join(', ')}</div>`).join('')}
        <div style="font-family:var(--mono);font-size:11px;color:var(--ink-faint);margin-top:4px">condição: <code>${esc(res.condition||'(implícita)')}</code>${res.steps.length?' · '+res.steps.map(esc).join(' · '):''}</div></div></div>`;
    }).join('');
    host.innerHTML=`<div class="lint ${pass===cases.length?'ok':'warn'}">${pass}/${cases.length} casos com resultado esperado. ${pass===cases.length?'A lógica se comporta como o esperado nos casos sintéticos.':'Divergências são ótimas para aprender: veja qual campo decidiu.'}</div>${html}
    <div class="note osint"><span class="ni">✶</span><div><b>Leitura do caçador:</b> repare como <b>um único campo ausente</b> (caso de telemetria incompleta) já impede a regra de disparar. É por isso que a aba ③ (dados) importa tanto quanto a lógica.</div></div>`;
    if(!V.state['sim_'+key]){ V.state['sim_'+key]=1; save(); addXP(15,'Regra simulada'); $('#curation')&&($('#curation').innerHTML=curationBar(r,key)); }
  }catch(e){ host.innerHTML=`<div class="lint bad">Erro na simulação: ${esc(e.message)}. Esta regra pode usar recursos fora do subconjunto simulado (correlação, keywords complexas).</div>`; }
}
/* ===== ⑥ INVESTIGUE ===== */
function investigatePane(r,d){
  if(r.fmt==='playbook'){ return `<div class="note tip"><span class="ni">▸</span><div>Esta entrada <b>é</b> um playbook de resposta. Abaixo, o fluxo original e, ao lado, nossos modelos de triagem reutilizáveis.</div></div>
    ${term('playbook', (d.raw||'').slice(0,4000)+((d.raw||'').length>4000?'\n...':''),'kql-md')}`; }
  const inv=investigateFor(r.tac);
  return `<div class="note tip"><span class="ni">▸</span><div><b>O alerta disparou. E agora?</b> Guia de triagem ${inv.tactic?`para <b>${TACTIC_PT[inv.tactic]||inv.tactic}</b>`:'genérico'} — liga a regra ao trabalho do analista.</div></div>
  <div class="path" style="flex-direction:column;gap:0">${inv.steps.map((s,i)=>`<div class="step" style="cursor:default;min-width:auto;border-radius:${i===0?'12px 12px 0 0':i===inv.steps.length-1?'0 0 12px 12px':'0'}"><div class="n">PASSO ${i+1}</div><div class="d" style="font-size:13px;color:var(--ink-dim)">${esc(s)}</div></div>`).join('')}</div>
  <div class="note osint"><span class="ni">✶</span><div><b>Regra de ouro:</b> nunca investigue o evento isolado. Pergunte sempre "o que veio <b>antes</b> e <b>depois</b>?". O incidente é uma história; sua tarefa é remontá-la do clique inicial ao impacto.</div></div>
  <div class="toolbar"><button class="btn" onclick="closeModal();go('playbooks')">▣ ver modelos de playbook</button></div>`;
}
/* ===== ⑦ ORIGEM & VERSÕES ===== */
function originPane(r,d){
  const edited=!!V.state['edit_'+(r.slug+'::'+r.id)];
  return `<div class="kv">
    <dt>Fonte</dt><dd><b>${esc(r.src)}</b></dd>
    <dt>Formato / linguagem</dt><dd>${FMT_PT[r.fmt]||r.fmt} · ${esc(r.lang)}</dd>
    <dt>Arquivo original</dt><dd><code style="color:var(--ink-dim)">${esc(d.path)}</code></dd>
    <dt>Autor</dt><dd>${esc(d.a||r.a||'—')}</dd>
    <dt>Data</dt><dd>${esc(d.dt||r.dt||'—')}</dd>
    <dt>Status/maturidade</dt><dd>${esc(r.status||'—')}</dd>
    <dt>Licença</dt><dd><b>${esc(r.lic)}</b> — ${LIC_NOTE[r.lic]||'verifique antes de redistribuir.'}</dd>
    <dt>ID</dt><dd><code>${esc(r.id)}</code></dd>
    <dt>Suas modificações</dt><dd>${edited?'<span style="color:var(--amber)">● Você adaptou esta regra neste navegador.</span>':'<span style="color:var(--ink-faint)">nenhuma (original intacto)</span>'}</dd>
    ${d.red?`<dt>Credenciais</dt><dd><b>${d.red} valor(es) mascarado(s)</b> como <code>REDIGIDO-PELO-DETECTIONRULES</code>. O arquivo original continha o que parecem credenciais reais (chaves de API, senhas, webhooks); elas não são republicadas aqui. A lógica do playbook não muda; reconfigure com as suas credenciais.</dd>`:''}</div>
  ${edited?`<h3 class="h">Diferença (original → sua versão)</h3>${term('diff', simpleDiff(d.raw, V.state['edit_'+(r.slug+'::'+r.id)]),'kql-md')}`:''}
  <div class="note warn"><span class="ni">▸</span><div><b>Proveniência preservada:</b> autor, fonte, licença e versão permitem atribuição, atualização e reuso corretos. Ao redistribuir sua adaptação, mantenha o crédito da origem e respeite a licença acima.</div></div>
  <div class="toolbar"><button class="btn" onclick="copy(V.show?${JSON.stringify(r.src)}:'')">copiar fonte</button><a class="btn" href="${esc((d.ref&&d.ref[0])||'')}" target="_blank" rel="noopener" style="${(d.ref&&d.ref[0])?'':'display:none'}">referência ↗</a></div>`;
}
function simpleDiff(a,b){ const la=a.split('\n'),lb=b.split('\n'); const out=[]; const n=Math.max(la.length,lb.length); for(let i=0;i<n;i++){ if(la[i]===lb[i]){ if(la[i]!==undefined) out.push('  '+la[i]); } else { if(la[i]!==undefined) out.push('- '+la[i]); if(lb[i]!==undefined) out.push('+ '+lb[i]); } } return out.join('\n').replace(/^- /gm,'- ').replace(/^\+ /gm,'+ '); }
/* ===== pacote de detecção ===== */
function downloadPackage(r,d,key){
  const edited=V.state['edit_'+key]||d.raw; const slug=(r.title||'regra').toLowerCase().replace(/[^a-z0-9]+/g,'_').replace(/^_|_$/g,'').slice(0,50);
  const tel=telemetryFor(r); const inv=investigateFor(r.tac);
  const readme=`# Pacote de Detecção — ${r.title}

## 1. Objetivo
${d.desc||r.desc||'(sem descrição)'}

Tática ATT&CK: ${r.tac.join(', ')||'—'}  |  Técnica: ${r.tech.join(', ')||'—'}
Severidade: ${SEV_PT[r.sev]||'—'}  |  Formato: ${FMT_PT[r.fmt]||r.fmt} (${r.lang})

## 2. Telemetria necessária
${tel?`Origem: ${tel.t.src}
Coleta: ${tel.t.collect}
Campos: ${tel.t.fields.join(', ')}`:'Identifique a fonte que contém os campos usados na regra.'}

## 3. Investigação (o que fazer após o alerta)
${inv.steps.map((s,i)=>`${i+1}. ${s}`).join('\n')}

## 4. Pontos cegos / limitações
${BLINDSPOTS[r.fmt]||'Campos ausentes silenciam a regra; variação mínima pode evadir; atividade legítima parecida gera FP.'}

## 5. Compatibilidade por plataforma
${(PLATFORM_COMPAT[r.fmt]||[]).map(x=>`- ${x[0]}: ${x[1]} — ${x[2]}`).join('\n')}

## 6. Proveniência
Fonte: ${r.src}
Arquivo: ${d.path}
Autor: ${d.a||'—'}  |  Data: ${d.dt||'—'}  |  Licença: ${r.lic}
Estado de curadoria: importada${V.state['explained_'+key]?', explicada':''}${V.state['sim_'+key]?', simulada':''}${V.state['edit_'+key]?', adaptada localmente':''}

> Explicação e simulação são apoio de estudo gerado pelo guia, não validação em mecanismo real.
`;
  // monta um "zip" simples concatenado? Não: baixa arquivos separados em sequência.
  download(`${slug}.${FMT_EXT[r.fmt]||'txt'}`, edited);
  setTimeout(()=>download(`${slug}_GUIA.md`, readme),250);
  setTimeout(()=>{ if(r.fmt==='sigma'){ try{ const rule=Sigma.parseSigma(edited); const {positive,negatives}=Sigma.genEvents(rule); const tests={rule:r.title,should_match:[positive],should_not_match:negatives.map(n=>n.ev)}; download(`${slug}_testes.json`, JSON.stringify(tests,null,2)); }catch{} } },500);
  toast('📦','Pacote de detecção: regra + guia'+(r.fmt==='sigma'?' + testes':''));
}
Object.assign(window,{renderArsenal,applyFilters,renderList,openRule,lintRule,getShard,A,buildIndex,runSim,curationBar,downloadPackage});
