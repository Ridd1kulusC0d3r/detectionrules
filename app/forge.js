/* ============================================================
   forge.js — FORJA: motor de criação/tradução de regras.
   Sigma é a fonte da verdade; o motor traduz para KQL / SPL / EQL / Elastic TOML / Wazuh XML.
   Ponto de partida: formulário em branco OU importar uma regra Sigma real do Arsenal.
   A tradução é didática (process_creation, network, logon); revise na ferramenta nativa.
   ============================================================ */
const F = { sel:[], flt:[], meta:{}, outTab:'sigma' };
const MODS=['','contains','endswith','startswith','all','contains|all','re','windash','contains|windash','cidr','exists'];

function renderForge(){
  const v=$('#v-forge');
  v.innerHTML=`
  <div class="eyebrow"><span class="num">FORJA /</span> MOTOR DE CRIAÇÃO</div>
  <h1 class="sec">Escreva uma regra. <span class="g">Receba em seis formatos.</span></h1>
  <p class="sub">Monte a lógica em Sigma pelo formulário, ou abra qualquer regra Sigma no Arsenal e clique em <b>"abrir na Forja"</b> para importá-la. O motor valida a estrutura e traduz para KQL (Sentinel/Defender), SPL (Splunk), EQL (Elastic), TOML Elastic e Wazuh XML — e explica cada decisão na aba Explicação.</p>
  <div class="forge">
   <div>
    <div class="fset" style="border-color:var(--sig-dim)"><b style="color:var(--sig)">★ Construtor orientado ao comportamento</b>
      <p style="font-size:12px;color:var(--ink-dim);margin-bottom:8px">Comece pela pergunta certa: <b>o que você quer detectar</b> e <b>quais dados você tem</b>. O assistente pré-preenche a lógica.</p>
      <label>1 · O que você quer detectar? (comportamento)</label>
      <select id="beh_what"><option value="">— escolha —</option>
        <option value="office_shell">Aplicativo do Office gerando um shell (phishing com macro)</option>
        <option value="enc_ps">PowerShell codificado/oculto (cradle de download)</option>
        <option value="lolbin">LOLBin baixando payload (certutil/bitsadmin/mshta)</option>
        <option value="webshell">Servidor web gerando shell (web shell / RCE)</option>
        <option value="persist_run">Persistência via chave Run do registro</option>
        <option value="vss">Exclusão de shadow copies (precursor de ransomware)</option>
        <option value="spray">Password spraying (muitas contas, 1 origem)</option>
        <option value="brute">Brute force (muitas senhas, 1 conta)</option>
        <option value="newconn">Processo incomum abrindo conexão de rede externa</option>
        <option value="absence">Telemetria parou (detecção pela ausência)</option></select>
      <label>2 · Quais dados você tem? (ambiente/telemetria)</label>
      <select id="beh_env"><option value="windows_sysmon">Windows + Sysmon</option><option value="windows_sec">Windows Security (4625/4688)</option><option value="linux">Linux (auditd/Sysmon)</option><option value="identity">Identidade/Cloud (Entra/Okta/AWS)</option><option value="network">Rede (Zeek/proxy/DNS)</option></select>
      <div class="toolbar" style="margin-top:8px"><button class="btn p" id="beh_go">→ gerar ponto de partida</button></div>
      <div id="beh_tip" style="font-size:12px;color:var(--ink-faint)"></div></div>
    <div class="fset"><b>0 · Outras formas de começar</b>
      <div class="toolbar"><button class="btn" id="blank">▢ começar em branco</button><button class="btn" id="fromars">⛨ escolher regra Sigma no Arsenal</button><button class="btn" id="imp">⤓ colar Sigma (YAML)</button></div>
      <p style="font-size:12px;color:var(--ink-dim)">Dica: importe uma regra real, mude UM valor para o seu ambiente, forje e compare as traduções.</p></div>
    <div class="fset"><b>1 · Identidade <span class="help" title="Peça 5 da gramática: POR QUÊ. É o que o analista lê no alerta.">?</span></b>
      <label>title <span class="help" title="Uma frase: o QUE foi detectado.">?</span></label><input id="m_title" placeholder="O que esta regra detecta, em uma frase">
      <label>description</label><textarea id="m_desc" placeholder="Comportamento detectado e por que importa"></textarea>
      <label>level (severidade)</label><select id="m_level"><option>informational</option><option>low</option><option selected>medium</option><option>high</option><option>critical</option></select>
      <label>status (maturidade)</label><select id="m_status"><option selected>experimental</option><option>test</option><option>stable</option></select>
      <label>author</label><input id="m_author" placeholder="seu nome / time"></div>
    <div class="fset"><b>2 · Logsource — ONDE olhar <span class="help" title="Peça 1 da gramática. Define a tabela/índice no SIEM.">?</span></b>
      <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:8px">
      <div><label>product</label><input id="ls_product" list="dl_prod" value="windows"><datalist id="dl_prod"><option>windows<option>linux<option>macos<option>aws<option>azure<option>gcp<option>m365<option>okta<option>zeek<option>proxy<option>dns</datalist></div>
      <div><label>category</label><input id="ls_category" list="dl_cat" value="process_creation"><datalist id="dl_cat"><option>process_creation<option>process_access<option>network_connection<option>file_event<option>registry_set<option>image_load<option>ps_script<option>dns_query<option>webserver<option>firewall</datalist></div>
      <div><label>service</label><input id="ls_service" list="dl_svc" placeholder="—"><datalist id="dl_svc"><option>security<option>sysmon<option>system<option>powershell<option>cloudtrail<option>signinlogs<option>auditd<option>sshd</datalist></div></div></div>
    <div class="fset"><b>3 · Selection — O QUE procurar <span class="help" title="Peça 2. Linhas = AND. Valores separados por | = OR.">?</span></b>
      <p style="font-size:12px;color:var(--ink-dim);margin-bottom:8px">Cada linha é <code>campo | modificador | valores</code>. Separe múltiplos valores com <code>|</code> (vira OR). Linhas diferentes = AND.</p>
      <div id="sel"></div><button class="btn sm" id="addsel">+ adicionar campo</button></div>
    <div class="fset"><b>4 · Filter — O QUE ignorar <span class="help" title="Peça 3. Exclusões de falso positivo. Combinadas com 'and not'.">?</span></b>
      <div id="flt"></div><button class="btn sm" id="addflt">+ adicionar exclusão</button></div>
    <div class="fset"><b>5 · Correlação (opcional) <span class="help" title="Contagem por entidade numa janela de tempo.">?</span></b>
      <label><input type="checkbox" id="c_on" style="width:auto;margin-right:6px">ativar contagem em janela</label>
      <div id="corrbox" style="display:none;grid-template-columns:1fr 1fr;gap:8px">
        <div><label>agrupar por (entidade)</label><input id="c_by" placeholder="campo da entidade"></div>
        <div><label>janela</label><input id="c_win" placeholder="5m"></div>
        <div><label>operação</label><select id="c_op"><option value="count">count (eventos)</option><option value="dcount">dcount (distintos)</option></select></div>
        <div><label>campo contado (dcount)</label><input id="c_field" placeholder="campo"></div>
        <div><label>limiar (≥)</label><input id="c_n" type="number" value="10"></div></div></div>
    <div class="fset"><b>6 · ATT&CK e falsos positivos</b>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px">
      <div><label>tática</label><select id="m_tactic">${TACTICS.map(t=>`<option value="${t.toLowerCase().replace(/ /g,'_')}">${TACTIC_PT[t]}</option>`).join('')}</select></div>
      <div><label>técnica (T-code)</label><input id="m_tech" placeholder="Txxxx.xxx"></div></div>
      <label>falsepositives</label><textarea id="m_fp" placeholder="Onde a regra pode errar e como filtrar"></textarea>
      <label>references (uma por linha)</label><textarea id="m_ref"></textarea></div>
    <button class="btn p" id="forgebtn" style="width:100%;justify-content:center;padding:12px">⚒ FORJAR REGRA</button>
   </div>
   <div class="sticky">
    <div class="mtabs" id="otabs">${['sigma','kql','spl','eql','toml','wazuh','explain'].map(o=>`<button class="mtab ${o===F.outTab?'on':''}" data-o="${o}">${{sigma:'Sigma',kql:'KQL',spl:'SPL',eql:'EQL',toml:'Elastic TOML',wazuh:'Wazuh',explain:'Explicação'}[o]}</button>`).join('')}</div>
    <div id="out"><div class="loading">Preencha o formulário e clique em FORJAR — ou importe uma regra do Arsenal.</div></div>
    <div id="olint"></div>
   </div>
  </div>`;
  $('#beh_go').onclick=behaviorBuild;
  $('#blank').onclick=()=>{F.sel=[{f:'',m:'',v:''}];F.flt=[];F.meta={};F.id=null;fillForm();drawRows();$('#out').innerHTML='<div class="loading">Formulário limpo.</div>';};
  $('#fromars').onclick=()=>{ A.fmt.clear(); A.fmt.add('sigma'); A.page=0; go('arsenal'); toast('⛨','Abra uma regra Sigma e clique em "abrir na Forja"'); };
  $('#imp').onclick=()=>{ const t=prompt('Cole uma regra Sigma (YAML):'); if(t) forgeImport(t,'sigma'); };
  $('#addsel').onclick=()=>{F.sel.push({f:'',m:'',v:''}); drawRows();};
  $('#addflt').onclick=()=>{F.flt.push({f:'',m:'',v:''}); drawRows();};
  $('#c_on').onchange=e=>{$('#corrbox').style.display=e.target.checked?'grid':'none';};
  $('#forgebtn').onclick=forge;
  $$('.mtab','#otabs').forEach(t=>t.onclick=()=>{$$('.mtab','#otabs').forEach(x=>x.classList.remove('on'));t.classList.add('on');F.outTab=t.dataset.o;showOut();});
  fillForm(); drawRows(); if(F.sel.some(r=>r.f)) forge();
}

function rowHTML(list, i, r){
  return `<div class="selrow"><input placeholder="campo" value="${esc(r.f)}" data-l="${list}" data-i="${i}" data-k="f">
  <select data-l="${list}" data-i="${i}" data-k="m">${MODS.map(m=>`<option value="${m}" ${r.m===m?'selected':''}>${m||'(igual)'}</option>`).join('')}${MODS.includes(r.m)?'':`<option value="${esc(r.m)}" selected>${esc(r.m)}</option>`}</select>
  <input placeholder="valor1|valor2" value="${esc(r.v)}" data-l="${list}" data-i="${i}" data-k="v"><button class="rm" data-l="${list}" data-i="${i}">✕</button></div>`;
}
function drawRows(){
  $('#sel').innerHTML=F.sel.map((r,i)=>rowHTML('sel',i,r)).join('')||'<p style="font-size:12px;color:var(--ink-faint)">nenhum campo ainda</p>';
  $('#flt').innerHTML=F.flt.map((r,i)=>rowHTML('flt',i,r)).join('')||'<p style="font-size:12px;color:var(--ink-faint)">sem exclusões (ok para começar)</p>';
  $$('#sel input,#sel select,#flt input,#flt select').forEach(x=>x.oninput=x.onchange=e=>{F[e.target.dataset.l][+e.target.dataset.i][e.target.dataset.k]=e.target.value;});
  $$('#sel .rm,#flt .rm').forEach(b=>b.onclick=()=>{F[b.dataset.l].splice(+b.dataset.i,1); drawRows();});
}
function fillForm(){
  const m=F.meta||{};
  $('#m_title').value=m.title||''; $('#m_desc').value=m.description||''; $('#m_level').value=m.level||'medium'; $('#m_status').value=m.status||'experimental'; $('#m_author').value=m.author||'';
  $('#ls_product').value=m.product||'windows'; $('#ls_category').value=m.category??'process_creation'; $('#ls_service').value=m.service||'';
  $('#m_tactic').value=m.tactic||'execution'; $('#m_tech').value=m.technique||''; $('#m_fp').value=m.fp||''; $('#m_ref').value=(m.refs||[]).join('\n');
  const c=m.corr; $('#c_on').checked=!!c; $('#corrbox').style.display=c?'grid':'none';
  if(c){ $('#c_by').value=c.by||''; $('#c_win').value=c.window||'5m'; $('#c_op').value=c.op||'count'; $('#c_field').value=c.field||''; $('#c_n').value=c.n||10; }
}
function readForm(){
  F.meta={title:$('#m_title').value.trim(),description:$('#m_desc').value.trim(),level:$('#m_level').value,status:$('#m_status').value,author:$('#m_author').value.trim(),
    product:$('#ls_product').value.trim(),category:$('#ls_category').value.trim(),service:$('#ls_service').value.trim(),tactic:$('#m_tactic').value,technique:$('#m_tech').value.trim().toUpperCase(),
    fp:$('#m_fp').value.trim(),refs:$('#m_ref').value.split('\n').map(s=>s.trim()).filter(Boolean),
    corr:$('#c_on').checked?{by:$('#c_by').value.trim(),window:$('#c_win').value.trim()||'5m',op:$('#c_op').value,field:$('#c_field').value.trim(),n:+$('#c_n').value||10}:null};
}
function uuid(){ return ([1e7]+-1e3+-4e3+-8e3+-1e11).replace(/[018]/g,c=>(c^crypto.getRandomValues(new Uint8Array(1))[0]&15>>c/4).toString(16)); }
const vals = r => r.v.split('|').map(s=>s.trim()).filter(Boolean);
const yq = s => `'${s.replace(/'/g,"''")}'`;
const mods = r => (r.m||'').split('|').filter(Boolean);

/* ---------- importar Sigma existente para o formulário ---------- */
function forgeImport(text, fmt, title){
  if(fmt!=='sigma'){ toast('⚠','A Forja importa Sigma. Para outros formatos, use a aba Editar da regra.'); go('forge'); return; }
  const top=k=>{const m=text.match(new RegExp('^'+k+':\\s*(.*)$','m')); return m?m[1].trim().replace(/^['"]|['"]$/g,''):'';};
  const ls=s=>{const m=text.match(new RegExp('^\\s+'+s+':\\s*(.+)$','m')); return m?m[1].trim():'';};
  const tags=[...text.matchAll(/^\s+-\s+attack\.([a-z_0-9.]+)/gm)].map(m=>m[1]);
  const tech=tags.find(t=>/^t\d{4}/.test(t)); const tac=tags.find(t=>!/^t\d{4}/.test(t));
  const fps=[...(text.split(/^falsepositives:/m)[1]||'').split(/^\w/m)[0].matchAll(/^\s+-\s+(.+)$/gm)].map(m=>m[1]);
  const refs=[...(text.split(/^references:/m)[1]||'').split(/^\w/m)[0].matchAll(/^\s+-\s+(.+)$/gm)].map(m=>m[1]);
  // blocos de detection
  const det=(text.split(/^detection:/m)[1]||'').split(/^\w/m)[0];
  const blocks={}; let cur=null;
  for(const ln of det.split('\n')){
    const b=ln.match(/^    ([A-Za-z_][\w]*):\s*$/); if(b){cur=b[1]; blocks[cur]=[]; continue;}
    if(cur==null) continue;
    const kv=ln.match(/^        ([A-Za-z_][\w|.]*):\s*(.*)$/);
    if(kv){ const [f,...m]=kv[1].split('|'); blocks[cur].push({f,m:m.join('|'),v:kv[2].replace(/^['"]|['"]$/g,'')}); continue; }
    const li=ln.match(/^            -\s+(.*)$/); if(li&&blocks[cur].length){ const last=blocks[cur][blocks[cur].length-1]; last.v=(last.v?last.v+'|':'')+li[1].replace(/^['"]|['"]$/g,''); }
  }
  const selKeys=Object.keys(blocks).filter(k=>!/^filter/.test(k)&&k!=='condition'); const fltKeys=Object.keys(blocks).filter(k=>/^filter/.test(k));
  F.sel=selKeys.flatMap(k=>blocks[k]); F.flt=fltKeys.flatMap(k=>blocks[k]); F.id=top('id')||null;
  if(selKeys.length>1) toast('⚠',`${selKeys.length} blocos de seleção foram unidos em um (AND). Revise a condition original.`);
  F.meta={title:top('title')||title||'',description:top('description'),level:top('level')||'medium',status:top('status')||'experimental',author:top('author'),
    product:ls('product'),category:ls('category'),service:ls('service'),tactic:(tac||'execution').replace(/-/g,'_'),technique:(tech||'').toUpperCase(),fp:fps.join('; '),refs,corr:null};
  go('forge'); setTimeout(()=>{fillForm();drawRows();forge();},50);
}

/* ---------- geradores ---------- */
function genSigma(){
  const m=F.meta; const id=F.id||(F.id=uuid());
  const block=rows=>rows.filter(r=>r.f).map(r=>{const vs=vals(r); const key=r.f+(r.m?'|'+r.m:''); return vs.length>1? `        ${key}:\n`+vs.map(v=>`            - ${yq(v)}`).join('\n') : `        ${key}: ${yq(vs[0]||'')}`;}).join('\n');
  const ls=[`    product: ${m.product||'windows'}`, m.category?`    category: ${m.category}`:null, m.service?`    service: ${m.service}`:null].filter(Boolean).join('\n');
  const hasF=F.flt.some(r=>r.f);
  let det=`    selection:\n${block(F.sel)}`; if(hasF) det+=`\n    filter_main_known_fp:\n${block(F.flt)}`;
  det+=`\n    condition: selection${hasF?' and not 1 of filter_main_*':''}`;
  if(m.corr&&m.corr.by) det+=`\n    # correlação (Sigma v2 meta-regra): ${m.corr.op}(${m.corr.field||'*'}) by ${m.corr.by} over ${m.corr.window} >= ${m.corr.n}`;
  const tags=[`    - attack.${m.tactic}`, m.technique?`    - attack.${m.technique.toLowerCase()}`:null].filter(Boolean).join('\n');
  return `title: ${m.title||'Untitled Rule'}
id: ${id}
status: ${m.status}
description: ${m.description||'TODO: descreva o comportamento detectado'}
references:
${(m.refs.length?m.refs:['https://attack.mitre.org/techniques/'+(m.technique||'T1059').replace('.','/')+'/']).map(r=>'    - '+r).join('\n')}
author: ${m.author||'Operação Vigia'}
date: ${new Date().toISOString().slice(0,10)}
tags:
${tags}
logsource:
${ls}
detection:
${det}
falsepositives:
    - ${m.fp||'Unknown'}
level: ${m.level}`;
}
/* mapeamento de campos Sigma (Sysmon/Windows) → plataformas */
const MAP = {
  kql:{Image:'FolderPath',ParentImage:'InitiatingProcessFolderPath',CommandLine:'ProcessCommandLine',ParentCommandLine:'InitiatingProcessCommandLine',User:'AccountName',TargetImage:'FileName',SourceImage:'InitiatingProcessFolderPath',DestinationIp:'RemoteIP',DestinationPort:'RemotePort',DestinationHostname:'RemoteUrl',TargetFilename:'FolderPath',OriginalFileName:'ProcessVersionInfoOriginalFileName'},
  spl:{Image:'Processes.process_path',ParentImage:'Processes.parent_process_path',CommandLine:'Processes.process',ParentCommandLine:'Processes.parent_process',User:'Processes.user',OriginalFileName:'Processes.original_file_name',DestinationIp:'All_Traffic.dest_ip',DestinationPort:'All_Traffic.dest_port'},
  eql:{Image:'process.executable',ParentImage:'process.parent.executable',CommandLine:'process.command_line',ParentCommandLine:'process.parent.command_line',User:'user.name',OriginalFileName:'process.pe.original_file_name',DestinationIp:'destination.ip',DestinationPort:'destination.port',TargetFilename:'file.path',TargetImage:'Target.process.executable'},
  wazuh:{Image:'win.eventdata.image',ParentImage:'win.eventdata.parentImage',CommandLine:'win.eventdata.commandLine',ParentCommandLine:'win.eventdata.parentCommandLine',User:'win.eventdata.user',TargetImage:'win.eventdata.targetImage',SourceImage:'win.eventdata.sourceImage',GrantedAccess:'win.eventdata.grantedAccess',DestinationIp:'win.eventdata.destinationIp',DestinationPort:'win.eventdata.destinationPort',EventID:'win.system.eventID',TargetFilename:'win.eventdata.targetFilename'},
};
const TABLE_KQL={process_creation:'DeviceProcessEvents',process_access:'DeviceEvents',network_connection:'DeviceNetworkEvents',file_event:'DeviceFileEvents',registry_set:'DeviceRegistryEvents',image_load:'DeviceImageLoadEvents',ps_script:'DeviceEvents',dns_query:'DeviceNetworkEvents',security:'SecurityEvent',signinlogs:'SigninLogs',cloudtrail:'AWSCloudTrail'};
const DM_SPL={process_creation:'Endpoint.Processes',network_connection:'Network_Traffic.All_Traffic',file_event:'Endpoint.Filesystem',registry_set:'Endpoint.Registry',security:'Authentication'};
const EQL_CAT={process_creation:'process',network_connection:'network',file_event:'file',registry_set:'registry',image_load:'library',process_access:'process'};
const esq = s => s.replace(/\\/g,'\\\\').replace(/"/g,'\\"');
const kq = s => `"${s.replace(/\\/g,'\\\\').replace(/"/g,'\\"')}"`;
const unknownFields=[];
function fieldFor(plat,f){ const m=MAP[plat][f]; if(!m){ if(!unknownFields.includes(f)) unknownFields.push(f); return f; } return m; }

function kqlCond(r){
  const f=fieldFor('kql',r.f), vs=vals(r), ms=mods(r); const win=ms.includes('windash');
  const expand=v=> win? [v, v.replace(/^-/,'/'), v.replace(/^-/,'–')] : [v];
  if(ms.includes('all')) return vs.map(v=>`${f} has_any (${expand(v).map(kq).join(', ')})`).join(' and ');
  if(ms.includes('re')) return vs.map(v=>`${f} matches regex ${kq(v)}`).join(' or ');
  if(ms.includes('cidr')) return vs.map(v=>`ipv4_is_in_range(${f}, ${kq(v)})`).join(' or ');
  if(ms.includes('exists')) return `isnotempty(${f})`;
  const all=vs.flatMap(expand);
  if(ms.includes('contains')) return `${f} has_any (${all.map(kq).join(', ')})`;
  if(ms.includes('endswith')) return '('+all.map(v=>`${f} endswith ${kq(v)}`).join(' or ')+')';
  if(ms.includes('startswith')) return '('+all.map(v=>`${f} startswith ${kq(v)}`).join(' or ')+')';
  return `${f} in~ (${all.map(kq).join(', ')})`;
}
function genKQL(){
  unknownFields.length=0; const m=F.meta;
  const table=TABLE_KQL[m.category]||TABLE_KQL[m.service]||'DeviceEvents';
  const sel=F.sel.filter(r=>r.f).map(kqlCond); const flt=F.flt.filter(r=>r.f).map(kqlCond);
  let q=`// ${m.title}\n// ${m.description}\n${table}\n| where Timestamp > ago(1h)\n`+sel.map(c=>`| where ${c}`).join('\n');
  if(flt.length) q+=`\n| where not(${flt.join(' and ')})   // exclusões (filter_*)`;
  if(m.corr&&m.corr.by){ const agg=m.corr.op==='dcount'?`dcount(${fieldFor('kql',m.corr.field||'AccountName')})`:'count()'; q+=`\n| summarize N = ${agg}, Primeiro = min(Timestamp), Ultimo = max(Timestamp) by ${fieldFor('kql',m.corr.by)}, bin(Timestamp, ${m.corr.window})\n| where N >= ${m.corr.n}`; }
  else q+=`\n| project Timestamp, DeviceName, AccountName, ${[...new Set(F.sel.filter(r=>r.f).map(r=>fieldFor('kql',r.f)))].join(', ')}`;
  return q+(unknownFields.length?`\n// ⚠ campos sem mapeamento conhecido (mantidos literais): ${unknownFields.join(', ')}`:'');
}
function splCond(r){
  const f=fieldFor('spl',r.f), vs=vals(r), ms=mods(r);
  const wrap=v=> ms.includes('contains')?`*${v}*`: ms.includes('endswith')?`*${v}`: ms.includes('startswith')?`${v}*`: v;
  if(ms.includes('all')) return vs.map(v=>`${f}="${esq(wrap(v))}"`).join(' AND ');
  if(ms.includes('re')) return `match(${f}, "${esq(vs[0])}")`;
  return `${f} IN (${vs.map(v=>`"${esq(wrap(v))}"`).join(', ')})`;
}
function genSPL(){
  unknownFields.length=0; const m=F.meta; const dm=DM_SPL[m.category]||DM_SPL[m.service]||'Endpoint.Processes'; const obj=dm.split('.')[1];
  const sel=F.sel.filter(r=>r.f).map(splCond); const flt=F.flt.filter(r=>r.f).map(splCond);
  const slug=(m.title||'rule').toLowerCase().replace(/[^a-z0-9]+/g,'_').replace(/^_|_$/g,'');
  const by=m.corr&&m.corr.by? `${fieldFor('spl',m.corr.by)} _time span=${m.corr.window}` : `${obj}.dest ${obj}.user ${[...new Set(F.sel.filter(r=>r.f).map(r=>fieldFor('spl',r.f)))].join(' ')}`;
  let q=`| tstats \`security_content_summariesonly\` count ${m.corr&&m.corr.op==='dcount'?`dc(${fieldFor('spl',m.corr.field)}) as distintos `:''}min(_time) as firstTime max(_time) as lastTime\n    from datamodel=${dm}\n    where ${sel.join('\n      AND ')}${flt.length?'\n      AND NOT ('+flt.join(' OR ')+')':''}\n    by ${by}\n| \`drop_dm_object_name(${obj})\`\n| \`security_content_ctime(firstTime)\`\n| \`security_content_ctime(lastTime)\``;
  if(m.corr&&m.corr.by) q+=`\n| where ${m.corr.op==='dcount'?'distintos':'count'} >= ${m.corr.n}`;
  q+=`\n| \`${slug}_filter\``;
  return `\`\`\` ${m.title} — ${m.description} \`\`\`\n`+q+(unknownFields.length?`\n\`\`\` ⚠ campos sem mapeamento CIM conhecido: ${unknownFields.join(', ')} \`\`\``:'');
}
function eqlCond(r){
  const f=fieldFor('eql',r.f), vs=vals(r), ms=mods(r);
  const wrap=v=> ms.includes('contains')?`*${v}*`: ms.includes('endswith')?`*${v}`: ms.includes('startswith')?`${v}*`: v;
  if(ms.includes('all')) return vs.map(v=>`${f} : "${esq(wrap(v))}"`).join(' and ');
  if(ms.includes('re')) return `${f} regex~ "${esq(vs[0])}"`;
  if(ms.includes('cidr')) return `cidrMatch(${f}, ${vs.map(v=>`"${v}"`).join(', ')})`;
  return `${f} : (${vs.map(v=>`"${esq(wrap(v))}"`).join(', ')})`;
}
function genEQL(){
  unknownFields.length=0; const m=F.meta; const cat=EQL_CAT[m.category]||'any';
  const sel=F.sel.filter(r=>r.f).map(eqlCond); const flt=F.flt.filter(r=>r.f).map(eqlCond);
  let q=`${cat} where ${cat==='process'?'event.type == "start" and ':''}\n  ${sel.join(' and\n  ')}`;
  if(flt.length) q+=` and\n  not (${flt.join(' or ')})`;
  if(m.corr&&m.corr.by) q=`// correlação: em Elastic use type = "threshold" (veja aba TOML)\n`+q;
  return q+(unknownFields.length?`\n// ⚠ campos sem mapeamento ECS conhecido: ${unknownFields.join(', ')}`:'');
}
function genTOML(){
  const m=F.meta; const eql=genEQL().split('\n').filter(l=>!l.startsWith('//')).join('\n');
  const risk={informational:21,low:21,medium:47,high:73,critical:99}[m.level]||47;
  const tac=TACTICS.find(t=>t.toLowerCase().replace(/ /g,'_')===m.tactic)||'Execution';
  const taid={'Reconnaissance':'TA0043','Resource Development':'TA0042','Initial Access':'TA0001','Execution':'TA0002','Persistence':'TA0003','Privilege Escalation':'TA0004','Defense Evasion':'TA0005','Credential Access':'TA0006','Discovery':'TA0007','Lateral Movement':'TA0008','Collection':'TA0009','Command and Control':'TA0011','Exfiltration':'TA0010','Impact':'TA0040'}[tac];
  let thr=''; if(m.corr&&m.corr.by) thr=`\n[rule.threshold]\nfield = ["${fieldFor('eql',m.corr.by)}"]\nvalue = ${m.corr.n}${m.corr.op==='dcount'?`\n[[rule.threshold.cardinality]]\nfield = "${fieldFor('eql',m.corr.field)}"\nvalue = ${m.corr.n}`:''}`;
  return `[metadata]
creation_date = "${new Date().toISOString().slice(0,10).replace(/-/g,'/')}"
integration = ["endpoint"]
maturity = "development"

[rule]
author = ["${m.author||'Operação Vigia'}"]
description = """
${m.description||'TODO'}
"""
false_positives = ["${(m.fp||'Unknown').replace(/"/g,'\\"')}"]
from = "now-9m"
index = ["logs-endpoint.events.*", "winlogbeat-*", "logs-windows.*"]
language = "${m.corr&&m.corr.by?'kuery':'eql'}"
license = "Elastic License v2"
name = "${(m.title||'Untitled').replace(/"/g,'\\"')}"
risk_score = ${risk}
rule_id = "${F.id||uuid()}"
severity = "${m.level==='informational'?'low':m.level}"
tags = ["Domain: Endpoint", "OS: ${m.product==='linux'?'Linux':m.product==='macos'?'macOS':'Windows'}", "Tactic: ${tac}", "Data Source: Elastic Defend"]
timestamp_override = "event.ingested"
type = "${m.corr&&m.corr.by?'threshold':'eql'}"
query = '''
${eql}
'''
${thr}
[[rule.threat]]
framework = "MITRE ATT&CK"
${m.technique?`[[rule.threat.technique]]\nid = "${m.technique.split('.')[0]}"\nname = "TODO: nome da técnica"\nreference = "https://attack.mitre.org/techniques/${m.technique.split('.')[0]}/"\n${m.technique.includes('.')?`[[rule.threat.technique.subtechnique]]\nid = "${m.technique}"\nname = "TODO"\nreference = "https://attack.mitre.org/techniques/${m.technique.replace('.','/')}/"\n`:''}`:''}
[rule.threat.tactic]
id = "${taid}"
name = "${tac}"
reference = "https://attack.mitre.org/tactics/${taid}/"`;
}
function wzField(r){
  const f=fieldFor('wazuh',r.f), vs=vals(r), ms=mods(r);
  const rx=v=>v.replace(/\\/g,'\\\\').replace(/[.+?^${}()[\]|]/g,'\\$&');
  let pat; if(ms.includes('re')) pat=vs[0]; else if(ms.includes('endswith')) pat=vs.map(v=>rx(v)+'$').join('|'); else if(ms.includes('startswith')) pat=vs.map(v=>'^'+rx(v)).join('|'); else if(ms.includes('contains')) pat=vs.map(rx).join('|'); else pat=vs.map(v=>'^'+rx(v)+'$').join('|');
  if(ms.includes('all')) return vs.map(v=>`    <field name="${f}" type="pcre2">(?i)${ms.includes('endswith')?rx(v)+'$':ms.includes('startswith')?'^'+rx(v):rx(v)}</field>`).join('\n');
  return `    <field name="${f}" type="pcre2">(?i)${pat}</field>`;
}
function genWazuh(){
  unknownFields.length=0; const m=F.meta; const lvl={informational:3,low:5,medium:8,high:11,critical:13}[m.level]||8;
  const parent={process_creation:'61603',network_connection:'61605',file_event:'61613',registry_set:'61615',process_access:'61612',image_load:'61609'}[m.category]||'60000';
  const sel=F.sel.filter(r=>r.f).map(wzField).join('\n'); const flt=F.flt.filter(r=>r.f);
  const id=100000+Math.floor(Math.random()*899);
  let x=`<!-- ${m.title} — ${m.description}\n     Gerado pela Forja (Operação Vigia). Pai ${parent} = regra Sysmon do ruleset oficial. Ajuste if_sid ao seu decoder. -->
<group name="vigia,sysmon,${m.tactic},">
  <rule id="${id}" level="${lvl}"${m.corr&&m.corr.by?` frequency="${m.corr.n}" timeframe="${parseInt(m.corr.window)*(/m/.test(m.corr.window)?60:/h/.test(m.corr.window)?3600:1)}"`:''}>
    <if_sid>${parent}</if_sid>
${sel}
${m.corr&&m.corr.by?`    <same_field>${fieldFor('wazuh',m.corr.by)}</same_field>\n`:''}    <description>${m.title}</description>
${m.technique?`    <mitre><id>${m.technique.split('.')[0]}</id></mitre>\n`:''}    <group>${m.tactic},</group>
  </rule>`;
  if(flt.length) x+=`\n\n  <!-- exclusão: regra filha nível 0 "engole" o alerta nos casos legítimos -->\n  <rule id="${id+1}" level="0">\n    <if_sid>${id}</if_sid>\n${flt.map(wzField).join('\n')}\n    <description>${m.title} — falso positivo conhecido (ignorado)</description>\n  </rule>`;
  x+=`\n</group>`;
  return x+(unknownFields.length?`\n<!-- ⚠ campos sem mapeamento conhecido para win.eventdata: ${unknownFields.join(', ')} -->`:'');
}
function genExplain(){
  const m=F.meta; const hasF=F.flt.some(r=>r.f);
  const rows=F.sel.filter(r=>r.f);
  return `<div class="feynman"><div class="lbl">O QUE VOCÊ ACABOU DE CONSTRUIR</div>
  <p><span class="em">ONDE:</span> a regra lê <b>${m.product}${m.category?' / '+m.category:''}${m.service?' / '+m.service:''}</b>. Em KQL isso virou a tabela <code>${TABLE_KQL[m.category]||TABLE_KQL[m.service]||'DeviceEvents'}</code>; no Splunk, o data model <code>${DM_SPL[m.category]||DM_SPL[m.service]||'Endpoint.Processes'}</code>; no Wazuh, a regra-pai Sysmon correspondente.</p>
  <p><span class="em">O QUÊ:</span> ${rows.length} condição(ões) combinadas com <b>AND</b>: ${rows.map(r=>`<code>${esc(r.f)}</code> ${r.m?'<i>'+esc(r.m)+'</i>':'igual a'} ${vals(r).length>1?vals(r).length+' valores (OR)':'1 valor'}`).join('; ')}.</p>
  <p><span class="em">IGNORAR:</span> ${hasF?`${F.flt.filter(r=>r.f).length} exclusão(ões) via <code>and not</code>. No Wazuh isso virou uma <b>regra filha nível 0</b> — jeito Wazuh de dizer "nesse caso, cala".`:'nenhuma exclusão. Rode 7 dias em modo teste e volte aqui para adicionar o que apareceu de legítimo.'}</p>
  <p><span class="em">GRAVIDADE:</span> level <b>${m.level}</b> → Elastic risk_score ${ {informational:21,low:21,medium:47,high:73,critical:99}[m.level]}, Wazuh level ${ {informational:3,low:5,medium:8,high:11,critical:13}[m.level]}.</p>
  ${m.corr&&m.corr.by?`<p><span class="em">CORRELAÇÃO:</span> conta <b>${m.corr.op==='dcount'?'valores distintos de '+m.corr.field:'eventos'}</b> por <b>${m.corr.by}</b> em janelas de <b>${m.corr.window}</b> e alerta com ≥ <b>${m.corr.n}</b>. Em KQL é o <code>summarize ... by bin()</code>; no Elastic virou <code>type = threshold</code>; no Wazuh, <code>frequency + timeframe + same_field</code>.</p>`:''}
  <p><span class="em">POR QUÊ:</span> tática <b>${TACTIC_PT[TACTICS.find(t=>t.toLowerCase().replace(/ /g,'_')===m.tactic)]||m.tactic}</b>${m.technique?', técnica <b>'+m.technique+'</b>':''}. ${m.fp?'FP documentado: <i>'+esc(m.fp)+'</i>.':'<b style="color:var(--amber)">Sem FP documentado</b> — preencha antes de produzir.'}</p></div>
  <div class="note warn"><span class="ni">▸</span><div><b>Limites honestos da tradução:</b> o mapeamento de campos cobre Sysmon/Windows (process, network, file, registry). Campos fora disso ficam literais e são sinalizados com ⚠ no output. Modificadores como <code>base64offset</code> e regex complexa precisam de revisão manual. Sempre valide na ferramenta nativa com um evento real.</div></div>
  <div class="note tip"><span class="ni">▸</span><div><b>Próxima ação (uma só):</b> baixe a versão para a SUA plataforma, cole no modo de teste, gere o evento (ex.: Atomic Red Team para a técnica ${m.technique||'escolhida'}) e confirme que dispara. Depois rode 24h de dados normais e veja o ruído.</div></div>`;
}

function forge(){
  readForm();
  if(!F.sel.some(r=>r.f&&r.v)){ $('#out').innerHTML='<div class="lint bad">✗ adicione pelo menos um campo com valor na Selection.</div>'; return; }
  F.out={sigma:genSigma(),kql:genKQL(),spl:genSPL(),eql:genEQL(),toml:genTOML(),wazuh:genWazuh()};
  const lint=lintRule(F.out.sigma,'sigma'); $('#olint').innerHTML=lint;
  if(!/lint bad/.test(lint)){ V.state.forged++; save(); if(V.state.forged===1) badge('forger'); if(V.state.forged>=5) badge('master_forger'); addXP(25,'Regra forjada'); }
  showOut();
}
function showOut(){
  if(!F.out) return;
  const o=F.outTab; const ext={sigma:'yml',kql:'kql',spl:'spl',eql:'eql',toml:'toml',wazuh:'xml'}[o]; const fmt={sigma:'sigma',kql:'kql-md',spl:'splunk',eql:'elastic',toml:'elastic',wazuh:'wazuh'}[o];
  const slug=(F.meta.title||'regra').toLowerCase().replace(/[^a-z0-9]+/g,'_').replace(/^_|_$/g,'');
  if(o==='explain'){ $('#out').innerHTML=genExplain(); return; }
  $('#out').innerHTML=term(`${slug}.${ext}`, F.out[o], fmt, `<button class="btn sm" onclick="copy(F.out['${o}'])">copiar</button><button class="btn sm p" onclick="download('${slug}.${ext}', F.out['${o}'])">⬇ baixar</button><button class="btn sm" onclick="downloadAll()">⬇ todos (6)</button>`);
}
function downloadAll(){ const slug=(F.meta.title||'regra').toLowerCase().replace(/[^a-z0-9]+/g,'_'); const ext={sigma:'yml',kql:'kql',spl:'spl',eql:'eql',toml:'toml',wazuh:'xml'}; Object.entries(F.out).forEach(([k,v],i)=>setTimeout(()=>download(`${slug}.${ext[k]}`,v),i*250)); }
/* ---------- construtor orientado ao comportamento ---------- */
const BEHAVIORS={
 office_shell:{meta:{title:'Microsoft Office Product Spawning Shell',description:'Aplicativo do Office gerando interpretador de comando/script — padrão de macro maliciosa (phishing).',level:'high',product:'windows',category:'process_creation',tactic:'execution',technique:'T1204.002',fp:'Macros corporativas legítimas (raras; filtre pelo caminho assinado)'},sel:[{f:'ParentImage',m:'endswith',v:'\\WINWORD.EXE|\\EXCEL.EXE|\\POWERPNT.EXE|\\OUTLOOK.EXE'},{f:'Image',m:'endswith',v:'\\cmd.exe|\\powershell.exe|\\pwsh.exe|\\wscript.exe|\\cscript.exe|\\mshta.exe|\\rundll32.exe'}],flt:[{f:'CommandLine',m:'contains',v:'OfficeClickToRun'}]},
 enc_ps:{meta:{title:'Suspicious Encoded Hidden PowerShell',description:'PowerShell com comando codificado e janela oculta — ofuscação típica de cradle de download.',level:'high',product:'windows',category:'process_creation',tactic:'execution',technique:'T1059.001',fp:'Scripts de gestão que usam -enc (identifique o pai legítimo)'},sel:[{f:'Image',m:'endswith',v:'\\powershell.exe|\\pwsh.exe'},{f:'CommandLine',m:'contains|windash',v:'-enc |-ec |-e '},{f:'CommandLine',m:'contains|windash',v:'-w hidden|-nop'}],flt:[]},
 lolbin:{meta:{title:'LOLBin Downloading Payload',description:'certutil/bitsadmin/mshta usados para baixar arquivos da internet — abuso de binário legítimo.',level:'high',product:'windows',category:'process_creation',tactic:'command_and_control',technique:'T1105',fp:'Admins baixando certificados (raro com flags de download)'},sel:[{f:'Image',m:'endswith',v:'\\certutil.exe|\\bitsadmin.exe|\\mshta.exe'},{f:'CommandLine',m:'contains',v:'http|-urlcache|/transfer'}],flt:[]},
 webshell:{meta:{title:'Webserver Process Spawning Shell',description:'Processo de servidor web gerando interpretador — web shell ou RCE.',level:'critical',product:'windows',category:'process_creation',tactic:'persistence',technique:'T1505.003',fp:'Scripts de deploy no contexto do webserver'},sel:[{f:'ParentImage',m:'endswith',v:'\\w3wp.exe|\\httpd.exe|\\nginx.exe|\\tomcat.exe|\\php-cgi.exe'},{f:'Image',m:'endswith',v:'\\cmd.exe|\\powershell.exe|\\whoami.exe|\\net.exe'}],flt:[]},
 persist_run:{meta:{title:'Registry Run Key Persistence to User Path',description:'Escrita em chave Run apontando para executável em pasta de usuário — persistência mascarada.',level:'high',product:'windows',category:'registry_set',tactic:'persistence',technique:'T1547.001',fp:'Instaladores legítimos (valide o executável)'},sel:[{f:'TargetObject',m:'contains',v:'\\CurrentVersion\\Run'},{f:'Details',m:'contains',v:'\\AppData\\|\\Temp\\|\\ProgramData\\'}],flt:[]},
 vss:{meta:{title:'Shadow Copies Deletion',description:'vssadmin/wmic/wbadmin apagando cópias de sombra — precursor de ransomware.',level:'critical',product:'windows',category:'process_creation',tactic:'impact',technique:'T1490',fp:'Rotinas de backup muito específicas (valide com infra)'},sel:[{f:'Image',m:'endswith',v:'\\vssadmin.exe|\\wmic.exe|\\wbadmin.exe'},{f:'CommandLine',m:'contains|all',v:'delete|shadow'}],flt:[]},
 spray:{meta:{title:'Password Spraying - Many Accounts One Source',description:'Muitas contas distintas com falha de autenticação a partir da mesma origem em janela curta.',level:'high',product:'windows',category:'',service:'security',tactic:'credential_access',technique:'T1110.003',fp:'Servidores de app com contas expiradas; NAT concentrando IPs',corr:{by:'IpAddress',window:'5m',op:'dcount',field:'TargetUserName',n:10}},sel:[{f:'EventID',m:'',v:'4625'},{f:'LogonType',m:'',v:'3'}],flt:[]},
 brute:{meta:{title:'Brute Force - Many Failures One Account',description:'Muitas falhas de autenticação contra a mesma conta a partir da mesma origem.',level:'high',product:'windows',category:'',service:'security',tactic:'credential_access',technique:'T1110.001',fp:'Usuário que esqueceu a senha; serviço com credencial antiga',corr:{by:'TargetUserName',window:'5m',op:'count',field:'',n:10}},sel:[{f:'EventID',m:'',v:'4625'}],flt:[]},
 newconn:{meta:{title:'Unusual Process External Network Connection',description:'Processo em pasta temporária/usuário abrindo conexão externa — possível C2.',level:'medium',product:'windows',category:'network_connection',tactic:'command_and_control',technique:'T1071',fp:'Apps portáteis legítimos; navegadores em caminho não padrão'},sel:[{f:'Image',m:'contains',v:'\\AppData\\|\\Temp\\|\\ProgramData\\'},{f:'Initiated',m:'',v:'true'}],flt:[{f:'DestinationIp',m:'cidr',v:'10.0.0.0/8|192.168.0.0/16|172.16.0.0/12'}]},
 absence:{meta:{title:'Host Telemetry Heartbeat Missing',description:'Host que enviava eventos regularmente parou — possível desativação de agente/Sysmon.',level:'high',product:'windows',category:'process_creation',tactic:'defense_evasion',technique:'T1562.001',fp:'Manutenção/desligamento planejado (use allowlist de janelas)',absence:true},sel:[{f:'Image',m:'endswith',v:'\\fltMC.exe'},{f:'CommandLine',m:'contains|all',v:'unload|SysmonDrv'}],flt:[]},
};
const ENV_NOTE={windows_sysmon:'Sysmon dá os campos ricos (ParentImage, CommandLine). Ideal para regras de processo.',windows_sec:'Windows Security (4625/4688): bom para logon e criação de processo; linha de comando exige auditoria habilitada.',linux:'Ajuste os caminhos para Linux (/bin/sh, exe) — a lógica de "pai proibido gera shell" é a mesma.',identity:'Para spraying/brute em nuvem, troque EventID/LogonType pelos campos de SigninLogs (ResultType, IPAddress, UserPrincipalName).',network:'Para rede, considere expressar como regra Suricata/Zeek; esta Forja produz Sigma/SIEM.'};
function behaviorBuild(){
  const what=$('#beh_what').value, env=$('#beh_env').value;
  if(!what){ toast('▸','Escolha o comportamento primeiro'); return; }
  const b=BEHAVIORS[what]; F.sel=JSON.parse(JSON.stringify(b.sel)); F.flt=JSON.parse(JSON.stringify(b.flt)); F.meta=JSON.parse(JSON.stringify(b.meta)); F.id=null;
  // adapta ao ambiente
  if(env==='linux'){ F.meta.product='linux'; F.sel.forEach(s=>{ if(s.f==='Image') s.v=s.v.replace(/\\[A-Za-z]+\.exe/g,m=>'/'+m.slice(1,-4).toLowerCase()); if(s.f==='ParentImage') s.v=s.v.replace(/\\[A-Za-z]+\.EXE/gi,m=>'/'+m.slice(1).toLowerCase().replace('.exe','')); }); }
  if(env==='identity' && (what==='spray'||what==='brute')){ F.meta.product='azure'; F.meta.service='signinlogs'; F.meta.category=''; F.sel=[{f:'ResultType',m:'',v:'50126'}]; if(F.meta.corr){ F.meta.corr.by='IPAddress'; F.meta.corr.field='UserPrincipalName'; } }
  if(env==='windows_sec' && F.meta.category==='process_creation'){ F.meta.service=''; }
  fillForm(); drawRows(); forge();
  $('#beh_tip').innerHTML='✓ Ponto de partida gerado. '+esc(ENV_NOTE[env]||'')+' Ajuste os campos abaixo e forje.';
  toast('★','Regra montada a partir do comportamento — revise e adapte');
}
Object.assign(window,{renderForge,forgeImport,forge,showOut,downloadAll,F,behaviorBuild});
