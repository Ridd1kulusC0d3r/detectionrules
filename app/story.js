/* ============================================================
   story.js — a regra contada como história (aba ① Entenda)
   Cinco atos + epílogo, montados a partir de:
     · metadados da regra e do texto original (indicadores, filtros, IDs de evento)
     · ATT&CK v20 (técnica, fontes de log) e procedimentos reais de grupos (story.json)
     · APT4ALL (país atribuído), Ransomware Tool Matrix (ferramentas citadas na regra)
     · TCEM (lente de contexto da tecnologia e padrão de correlação)
     · LLmInjection (quando a regra é de IA/LLM/agentes)
   Tudo é apoio de estudo gerado automaticamente — não é validação da regra.
   ============================================================ */
const ST={p:null};
function loadStoryData(){
  if(ST.p) return ST.p;
  const j=(u,d)=>fetch(u).then(r=>r.ok?r.json():d).catch(()=>d);
  ST.p=Promise.all([j('data/graph/story.json',{}),j('data/graph/tcem.json',{lenses:[],patterns:[],schema:{}}),j('data/graph/ransomware.json',{tools:[]}),j('data/graph/ai.json',{tech:[]}),(window.loadGraph?loadGraph().catch(()=>null):null)])
    .then(([story,tcem,rw,ai])=>{ Object.assign(ST,{story,tcem,rw,ai}); ST.lens={}; (tcem.lenses||[]).forEach(l=>ST.lens[l.id]=l);
      ST.toolRx=null; const names=(rw.tools||[]).filter(t=>t.n.length>3).map(t=>t.n);
      if(names.length) ST.toolRx=new RegExp('(?<![a-z0-9])('+names.map(n=>n.toLowerCase().replace(/[.*+?^${}()|[\]\\]/g,'\\$&')).sort((a,b)=>b.length-a.length).join('|')+')(?![a-z0-9])','gi');
      ST.toolBy={}; (rw.tools||[]).forEach(t=>ST.toolBy[t.n.toLowerCase()]=t); return ST; });
  return ST.p;
}

/* ---- Feynman: o ataque como uma casa ---- */
const ACT_TACTIC={
 'Reconnaissance':['observa a casa da calçada','Antes de entrar, o ladrão anota quem mora ali, a que horas sai e quais janelas ficam abertas. Quase nada disso acontece dentro da sua rede.'],
 'Resource Development':['compra ferramentas e aluga um esconderijo','Ele registra domínios parecidos com o seu, compra acessos e prepara o servidor de onde vai dar ordens.'],
 'Initial Access':['encontra a porta','Uma senha válida, um e-mail com anexo, um serviço exposto sem correção: é o primeiro passo para dentro.'],
 'Execution':['aperta o botão','Já dentro, ele faz o computador rodar algo dele — um script, um comando, um programa.'],
 'Persistence':['faz cópia da chave','Garante que, mesmo se alguém desligar tudo, ele consegue voltar amanhã.'],
 'Privilege Escalation':['pega o crachá do gerente','Sai de usuário comum para administrador: agora as portas internas abrem.'],
 'Defense Evasion':['cobre as câmeras e apaga as pegadas','Desliga o antivírus, limpa logs, se disfarça de programa legítimo.'],
 'Stealth':['se disfarça de morador','Mistura-se ao que é normal para não ser notado.'],
 'Defense Impairment':['desliga o alarme','Enfraquece as próprias defesas: sensor parado, log desligado, política afrouxada.'],
 'Credential Access':['abre a gaveta das senhas','Senhas e tokens guardados na memória, em arquivos ou no navegador viram chaves para outras portas.'],
 'Discovery':['acende a lanterna e desenha o mapa','Descobre quem é quem, onde estão os servidores e o que vale a pena levar.'],
 'Lateral Movement':['passa de quarto em quarto','Usa as chaves roubadas para pular de máquina em máquina rumo ao cofre.'],
 'Collection':['enche a mochila','Junta documentos, e-mails e bancos de dados num lugar só, pronto para levar.'],
 'Command and Control':['liga para o chefe lá fora','O programa plantado telefona para casa pedindo ordens — às vezes disfarçado de tráfego comum.'],
 'Exfiltration':['sai pelos fundos com a mochila','Os dados deixam a empresa: para a nuvem, por DNS, pelo próprio canal de controle.'],
 'Impact':['quebra ou tranca tudo','Criptografa, apaga, para serviços. É aqui que o prejuízo fica visível para todos.'],
};
const PAT_STORY={
 'single-event':['Um alarme de porta','Abriu, tocou. Um único evento já basta porque ele é raro e perigoso o suficiente sozinho.','O preço: qualquer coisa legítima que abra a mesma porta também toca o alarme. O ajuste fino está nos filtros.'],
 'ordered-sequence':['Dois sensores em ordem','O alarme só toca se a porta abrir e, logo depois, o cofre for mexido — pela mesma pessoa, dentro da janela de tempo.','Cada passo sozinho é comum; a sequência é que conta a história. Um atacante paciente que espaça os passos além da janela escapa.'],
 'threshold':['O porteiro que conta','Uma tentativa é distração; cinquenta em cinco minutos é ataque. O sinal está na repetição por uma mesma chave (usuário, IP, host).','Quem ataca devagar ("low and slow") fica abaixo do limiar. Limiar baixo demais vira ruído.'],
 'new-entity':['O cachorro que late para estranho','Ele conhece quem é da casa. A regra compara com o histórico: país novo, processo raro, relação nunca vista.','Precisa de histórico limpo. Se o atacante já estava lá quando o "normal" foi aprendido, ele vira morador.'],
 'state-transition':['O sensor da câmera desligada','O perigo não é um valor, é a mudança: estava ligado e foi desligado; era restrito e ficou aberto.','Mudanças legítimas (janela de manutenção, ticket aprovado) parecem iguais — o contexto de autorização decide.'],
 'content-signature':['O farejador','Reconhece o "cheiro" de algo específico dentro da caixa: bytes, strings, padrões de um arquivo, da memória ou de um pacote.','Mudou o cheiro (recompilou, empacotou, cifrou), o farejador não reconhece. Ótimo para confirmar, fraco para o desconhecido.'],
 'response-flow':['O roteiro do que fazer','Não é alarme: é o procedimento automático para quando o alarme toca — coletar, enriquecer, conter, avisar.','Só funciona se alguma detecção disparar antes e se as integrações estiverem testadas.'],
};
/* o que está em jogo em cada tecnologia (Ato 1) */
const STAGE=new Proxy({},{get:(_,k)=>(window.TECH_BY||{})[k]?.st||''});
const EVT={4688:'criação de processo',4624:'logon com sucesso',4625:'falha de logon',4648:'logon com credencial explícita',4672:'privilégios especiais no logon',4697:'serviço instalado',4698:'tarefa agendada criada',4699:'tarefa agendada apagada',4702:'tarefa agendada alterada',4719:'política de auditoria alterada',4720:'conta criada',4722:'conta habilitada',4724:'reset de senha',4728:'membro adicionado a grupo global',4732:'membro adicionado a grupo local',4738:'conta alterada',4740:'conta bloqueada',4756:'membro adicionado a grupo universal',4768:'TGT Kerberos solicitado',4769:'ticket de serviço Kerberos',4771:'falha de pré-autenticação Kerberos',4776:'validação NTLM',4662:'operação em objeto do AD',5136:'objeto do AD modificado',5140:'acesso a compartilhamento',5145:'acesso a arquivo em compartilhamento',7045:'serviço instalado (System)',7036:'serviço mudou de estado',1102:'log de segurança apagado',104:'log apagado (System)',4104:'bloco de script PowerShell',4103:'módulo PowerShell',400:'motor PowerShell iniciado',800:'pipeline PowerShell'};
const SYSMON={1:'criação de processo',3:'conexão de rede',7:'imagem/DLL carregada',8:'thread remota criada',10:'acesso a processo',11:'arquivo criado',12:'chave de registro criada/apagada',13:'valor de registro gravado',15:'fluxo alternativo de arquivo',17:'pipe criado',18:'pipe conectado',22:'consulta DNS',23:'arquivo apagado',25:'adulteração de processo'};

/* ---- leitura do texto original: o que a regra procura e o que ela ignora ---- */
function storyIndicators(r,d){
  const raw=d.raw||''; const q=d.q||raw; const out={look:[],skip:[],ids:[],win:null,thr:null,by:null};
  const uniq=a=>[...new Set(a)];
  try{
    if(r.fmt==='sigma' && typeof Sigma!=='undefined'){
      const rule=Sigma.parseSigma(raw);
      Object.entries(rule.blocks||{}).forEach(([n,b])=>{
        const flds=Array.isArray(b)?b:(b.fields||[]);
        const txt=(Array.isArray(flds)?flds:[]).filter(f=>(f.values||[]).some(v=>String(v).trim())).slice(0,4).map(f=>{ const vs=(f.values||[]).map(v=>String(v)).filter(v=>v.trim()); return `${f.field||'(palavra-chave)'}${f.mods&&f.mods.length?' ('+f.mods.join(', ')+')':''} → ${vs.slice(0,3).join(' | ')}${vs.length>3?` … (+${vs.length-3})`:''}`; });
        (/filter|exclu|fp|legit/i.test(n)?out.skip:out.look).push(...txt);
      });
      const tf=raw.match(/timeframe:\s*(\S+)/); if(tf) out.win=tf[1];
    }
  }catch(e){}
  if(r.fmt==='wazuh'){
    for(const m of raw.matchAll(/<field name="([^"]+)"[^>]*>([^<]{1,80})<\/field>/g)) out.look.push(`${m[1]} casa ${m[2]}`);
    for(const m of raw.matchAll(/<(match|regex)[^>]*>([^<]{1,80})<\/\1>/g)) out.look.push(`${m[1]==='match'?'texto contém':'regex'} ${m[2]}`);
    const f=raw.match(/frequency="(\d+)"/), t=raw.match(/timeframe="(\d+)"/); if(f) out.thr=f[1]; if(t) out.win=t[1]+'s';
    const sid=raw.match(/<if_(matched_)?sid>([^<]+)</); if(sid) out.look.unshift(`depende da regra-mãe ${sid[2]}`);
    for(const [tag,lab] of [['decoded_as','decodificador'],['if_group','grupo-mãe'],['program_name','programa'],['category','categoria'],['url','URL'],['srcip','IP de origem'],['user','usuário']]){
      const m=raw.match(new RegExp(`<${tag}[^>]*>([^<]{1,80})</${tag}>`)); if(m) out.look.push(`${lab}: ${m[1]}`); }
    const lv=raw.match(/level="(\d+)"/); if(lv&&+lv[1]===0) out.look.push('nível 0: só agrupa/organiza, não gera alerta sozinho');
  }
  if(r.fmt==='yara'){
    const ns=(raw.match(/^\s*\$\w*\s*=/gm)||[]).length; const cond=(raw.split(/condition:/)[1]||'').split('\n').map(s=>s.trim()).filter(Boolean)[0]||'';
    if(ns) out.look.push(`${ns} assinatura(s) de bytes/strings`); if(cond) out.look.push(`condição: ${cond.slice(0,90)}`);
    for(const m of raw.matchAll(/^\s*\$\w+\s*=\s*"([^"]{4,40})"/gm)){ out.look.push(`"${m[1]}"`); if(out.look.length>5) break; }
  }
  if(r.fmt==='suricata'){
    const msg=raw.match(/msg:\s*"([^"]+)"/); if(msg) out.look.push(`mensagem: ${msg[1]}`);
    for(const m of raw.matchAll(/content:\s*"([^"]{2,40})"/g)){ out.look.push(`conteúdo "${m[1]}"`); if(out.look.length>4) break; }
    const th=raw.match(/(threshold|detection_filter):\s*([^;]+)/); if(th) out.thr=th[2];
  }
  if(!out.look.length && r.fmt!=='wazuh'){
    // só o corpo da consulta — metadados (datas, autor, status) não contam a história
    let body=d.q||'';
    if(!body){ const m=raw.match(/\n\s*(?:query|search)\s*[:=]\s*(?:'''|\"\"\"|\|[-+]?)([\s\S]*?)(?:'''|\"\"\"|\n[A-Za-z_]+\s*[:=]|$)/); body=m?m[1]:raw; }
    const strs=uniq([...body.matchAll(/["']([^"'\n]{3,60})["']/g)].map(m=>m[1]).filter(s=>!/^(true|false|null|high|medium|low|critical|informational|\s+)$/i.test(s)&&!/^https?:/.test(s)&&!/^\d{4}[/-]\d{2}[/-]\d{2}$/.test(s)&&!/^now-/.test(s)));
    out.look.push(...strs.slice(0,6).map(s=>`"${s}"`));
    if(!out.look.length){ for(const m of body.matchAll(/\b([A-Za-z_][\w.]*)\s*(?:=|==|!=|IN)\s*\(?\s*([A-Za-z0-9_.*\\-]{3,40})/g)){ if(!/^(true|false|null|index|sourcetype|source)$/i.test(m[1])) out.look.push(`${m[1]} = ${m[2]}`); if(out.look.length>=5) break; } }
  }
  for(const m of q.matchAll(/(?:EventCode|EventID|event\.code|event_id|winlog\.event_id|EventId)\s*(?:=|==|:|\bin\b|IN)\s*\(?\s*["']?(\d{1,5})/gi)) out.ids.push(+m[1]);
  for(const m of raw.matchAll(/^\s*EventID:\s*(\d+)/gm)) out.ids.push(+m[1]);
  out.ids=uniq(out.ids).slice(0,6);
  const by=q.match(/(?:\bstats\b|\bsummarize\b|\bsequence\b|\bcount\(|\bdcount\(|\bdc\()[^|\n]*?\bby\s+([A-Za-z_][\w.]*(?:\s*,\s*[A-Za-z_][\w.]*)?)|group_by:\s*\[?\s*([\w.]+)|<same_(\w+)/i);
  if(by && /threshold|sequence|ordered|new-entity/.test(r.pat)) out.by=by[1]||by[2]||by[3];
  const span=q.match(/maxspan\s*=\s*(\w+)|\bwindow\s*[:=]\s*"?(\w+)|timeframe\s*[:=]\s*"?(\w+)/i); if(span&&!out.win) out.win=span[1]||span[2]||span[3];
  out.look=uniq(out.look).slice(0,6); out.skip=uniq(out.skip).slice(0,4);
  return out;
}

const tacOf=r=>{ const t=(r.tac||[])[0]; if(t) return t; return null; };
function killStrip(tac){
  if(!tac) return '';
  const i=TACTICS.indexOf(tac);
  return `<div class="kc" aria-label="Posição na cadeia do ataque">${TACTICS.map((t,k)=>`<span class="${k===i?'on':k<i?'past':''}" title="${esc(TACTIC_PT[t])}"><i></i><em>${esc(TACTIC_PT[t])}</em></span>`).join('')}</div>`;
}

async function renderStory(r,d){
  const host=document.getElementById('story-host'); if(!host) return;
  await loadStoryData();
  if(document.getElementById('story-host')!==host) return;
  const A_=window.G?.A; const techIds=[...new Set((r.tech||[]).map(t=>t.toUpperCase()))].map(t=>A_?.rev?.[t]||t).filter(t=>A_?.techniques?.[t]);
  const main=techIds[0]; const X=main?A_.techniques[main]:null; const SS=main?ST.story[main]:null;
  const tac=tacOf(r) || (X? ({'stealth':'Defense Evasion','defense-impairment':'Defense Evasion'}[X.ta[0]] || (A_.tactics.find(t=>t.short===X.ta[0])||{}).n) : null);
  const tk=ACT_TACTIC[tac]||null;
  const techs=(r.techs||[]).filter(t=>t!=='other'); const tmain=techs[0]||'other'; const TB=window.TECH_BY||{};
  const lens=ST.lens[TB[tmain]?.lens]||null;
  const pat=PAT_STORY[r.pat]||PAT_STORY['single-event']; const patMeta=(window.PAT_BY||{})[r.pat];
  const ind=storyIndicators(r,d);
  const sevTxt={critical:'crítica — acorde alguém',high:'alta — investigar no mesmo turno',medium:'média — investigar hoje, com contexto',low:'baixa — sinal para correlacionar, não para acordar ninguém',informational:'informativa — contexto, não alerta'}[r.sev]||'sem severidade declarada — decida pelo impacto do ativo';
  // ferramentas de ransomware citadas no título/descrição/lógica
  // ferramenta conta só se aparece no título ou na descrição (na lógica pode ser só um caminho citado, ex.: pasta do Dropbox)
  const hay=((r.title||'')+' '+(d.desc||r.desc||'')).toLowerCase();
  const tools=ST.toolRx?[...new Set([...hay.matchAll(ST.toolRx)].map(m=>m[1].toLowerCase()))].map(n=>ST.toolBy[n]).filter(Boolean).slice(0,3):[];
  const aiT=techs.includes('ai')?(ST.ai.tech||[]).filter(t=>{const w=(t.n||'').toLowerCase().split(/\W+/).filter(x=>x.length>4); return w.some(x=>hay.includes(x));}).slice(0,2):[];
  const flag=c=>c&&c.length===2&&c!=='??'?String.fromCodePoint(...[...c.toUpperCase()].map(x=>0x1F1E6+x.charCodeAt(0)-65))+' ':'';

  /* PRÓLOGO */
  const one = (r.desc||d.desc||'').split(/(?<=[.!?])\s/)[0] || r.title;
  let h=`<div class="story">
  <div class="st-pro"><div class="lbl">EM UMA FRASE</div><p>${esc(one)}</p>
   ${tk?`<p class="st-feyn">Pense numa casa. Nesta parte da história, o invasor <b>${esc(tk[0])}</b>. ${esc(tk[1])}</p>`:''}
   ${killStrip(tac)}</div>`;

  /* ATO 1 — O PALCO */
  h+=`<section class="act"><div class="an">ATO 1</div><div class="ab"><h3>O palco</h3>
   <p>A cena se passa ${techs.length?`em <b>${esc(STAGE[tmain]||TB[tmain]?.n)}</b>`:'no ambiente descrito pelo log'}${techs.length>1?`, com reflexos em ${techs.slice(1,4).map(t=>esc(TB[t]?.n||t)).join(', ')}`:''}.</p>
   ${lens?`<p class="st-lens"><span class="tag">lente TCEM · ${esc(lens.n)}</span> ${esc(lens.d)} Para ver esta cena, o TCEM pede: <i>${esc((lens.tel||[]).join(', '))}</i>.</p>`:''}
   <div class="pill-row">${techs.map(t=>`<a class="tag b" href="#" onclick="event.preventDefault();closeModal();openTechno('${t}')">${esc(TB[t]?.n||t)} ↗</a>`).join('')}</div></div></section>`;

  /* ATO 2 — O ADVERSÁRIO */
  h+=`<section class="act"><div class="an">ATO 2</div><div class="ab"><h3>Quem faz isso de verdade</h3>`;
  if(X){
    h+=`<p><b>${main} · ${esc(X.n)}</b>${techIds.length>1?` <span class="id">(+${techIds.length-1} técnica${techIds.length>2?'s':''})</span>`:''}. ${esc((X.d||'').split(/(?<=\.)\s/).slice(0,2).join(' '))}</p>`;
    if(SS&&SS.u.length){
      h+=`<p>${SS.nu} grupo${SS.nu===1?'':'s'} do ATT&CK ${SS.nu===1?'tem':'têm'} esta técnica registrada. ${SS.u.length>1?'Alguns relatos reais':'Um relato real'}:</p>`+
        SS.u.slice(0,3).map(u=>`<blockquote class="st-q"><p>“${esc(u.p)}”</p><footer><a href="#" onclick="event.preventDefault();closeModal();openGroup('${u.g}')">${flag(u.c)}${esc(u.n)}</a>${u.cn?` · atribuído a ${esc(u.cn)}`:''} · <span class="id">MITRE ATT&CK, procedimento ${main}</span></footer></blockquote>`).join('');
    } else h+=`<p>Nenhum grupo do ATT&CK tem procedimento publicado para esta técnica — ela aparece mais em pesquisa e red team do que em relatórios de intrusão. Isso não quer dizer que não aconteça.</p>`;
  } else {
    h+=`<p>A regra não declara técnica ATT&CK, então o adversário fica sem rosto. <b>Exercício:</b> leia o Ato 4 e decida qual objetivo esse comportamento serve; depois procure a técnica no Grafo.</p>`;
  }
  if(tools.length) h+=`<p class="st-rw"><b>Ferramenta${tools.length>1?'s':''} citada${tools.length>1?'s':''} na regra:</b> ${tools.map(t=>`<b>${esc(t.n)}</b> — usada por ${t.g.length} gangue${t.g.length===1?'':'s'} de ransomware/afiliados (${esc(t.g.slice(0,5).join(', '))}${t.g.length>5?'…':''})`).join('; ')}. <span class="id">Ransomware Tool Matrix via APT4ALL</span></p>`;
  if(aiT.length) h+=`<p class="st-rw"><b>No mapa de ameaças de IA (LLmInjection):</b> ${aiT.map(t=>`<b>${esc(t.id)} ${esc(t.n)}</b> — ${esc(t.d)} ${t.map.filter(m=>m.rel==='exact').slice(0,2).map(m=>`<span class="tag">${esc(m.fw)} ${esc(m.id)}</span>`).join('')}`).join(' ')}</p>`;
  h+=`</div></section>`;

  /* ATO 3 — O RASTRO */
  const det=X?.det?.flatMap(dd=>dd.an.flatMap(a=>a.logs.map(l=>({...l,pl:a.pl})))) || [];
  const logsU=[]; const seen=new Set(); det.forEach(l=>{const k=l.src+l.ch; if(!seen.has(k)){seen.add(k); logsU.push(l);} });
  const src=[r.prod,r.cat,d.sv].filter(Boolean).join(' · ');
  h+=`<section class="act"><div class="an">ATO 3</div><div class="ab"><h3>O rastro que fica</h3>
   ${r.fmt==='yara'?`<p>Aqui o rastro é <b>o próprio objeto</b>: o arquivo que chegou por e-mail, o binário largado no disco, a região de memória do processo. A regra não lê logs — ela varre conteúdo. Onde ela roda importa: varredura de disco, de memória, de anexos no gateway ou de amostras na sua sandbox.</p>`:
   `<p>Nenhum ataque é invisível: cada passo escreve alguma coisa em algum lugar. Esta regra lê <b>${esc(src||FORMAT_INFO[r.fmt]?.name||r.fmt)}</b>.</p>`}
   ${ind.ids.length?`<p>Os eventos que ela usa:</p><ul class="st-ul">${ind.ids.map(i=>`<li><code>${i}</code> ${esc((/sysmon/i.test(src)&&SYSMON[i])?'Sysmon — '+SYSMON[i]:(EVT[i]||SYSMON[i]||'evento da fonte'))}</li>`).join('')}</ul>`:''}
   ${logsU.length?`<p>O MITRE ATT&CK recomenda, para ${main}: ${logsU.slice(0,4).map(l=>`<code>${esc(l.src)}</code>${l.ch?` (${esc(l.ch)})`:''}`).join(', ')}.</p>`:''}
   <p class="st-warn">${r.fmt==='yara'?'Se ninguém varre o lugar onde o arquivo está, a regra existe e nunca é avaliada.':'Se esse log não chega ao seu SIEM, a história acontece e ninguém lê. Confira na aba ③ antes de confiar.'}</p></div></section>`;

  /* ATO 4 — A ARMADILHA */
  h+=`<section class="act"><div class="an">ATO 4</div><div class="ab"><h3>A armadilha: ${esc(pat[0])}</h3>
   <p><span class="tag a">${esc(patMeta?.n||r.pat)}</span> ${esc(pat[1])}</p>
   ${ind.look.length?`<p>O que ela procura:</p><ul class="st-ul">${ind.look.map(x=>`<li><code>${esc(x)}</code></li>`).join('')}</ul>`:''}
   ${ind.skip.length?`<p>O que ela ignora de propósito (para não acusar inocentes):</p><ul class="st-ul">${ind.skip.map(x=>`<li><code>${esc(x)}</code></li>`).join('')}</ul>`:''}
   ${(ind.thr||ind.win||ind.by)?`<p>Regra de contagem/tempo: ${ind.thr?`limiar <b>${esc(ind.thr)}</b> `:''}${ind.win?`janela <b>${esc(ind.win)}</b> `:''}${ind.by?`agrupado por <b>${esc(ind.by)}</b>`:''}.</p>`:''}
   <p>Quando dispara, a severidade declarada é <b>${esc(sevTxt)}</b>.</p></div></section>`;

  /* ATO 5 — ONDE ELA TROPEÇA */
  const fps=(d.fp||[]).filter(Boolean);
  const evade=[];
  if(ind.look.some(x=>/\.exe|Image|process\.name|FileName|filename/i.test(x))) evade.push('renomear ou copiar o binário para outro caminho');
  if(ind.look.some(x=>/CommandLine|command_line|cmdline|contains/i.test(x))) evade.push('trocar a ordem dos argumentos, usar aliases ou ofuscar a linha de comando');
  if(r.pat==='threshold') evade.push('ir devagar, abaixo do limiar');
  if(r.pat==='ordered-sequence') evade.push('espaçar os passos além da janela');
  if(r.pat==='new-entity') evade.push('agir a partir de algo que já é "conhecido" (conta, host ou país habituais)');
  if(r.pat==='content-signature') evade.push('recompilar, empacotar ou cifrar o artefato');
  if(!evade.length) evade.push('usar uma ferramenta diferente que alcance o mesmo objetivo');
  h+=`<section class="act"><div class="an">ATO 5</div><div class="ab"><h3>Onde ela tropeça</h3>
   <p>${esc(pat[2])}</p>
   ${fps.length?`<p>O autor avisa sobre estes inocentes:</p><ul class="st-ul">${fps.slice(0,5).map(x=>`<li>${esc(x)}</li>`).join('')}</ul>`:`<p>O autor não documentou falsos positivos. Antes de produção, rode 7 dias em modo silencioso e anote quem aparece.</p>`}
   <p>Como um atacante tentaria passar: <b>${esc(evade.join('; '))}</b>. Cada resposta é a próxima regra que você escreve.</p>
   <p class="id">${esc(BLINDSPOTS[r.fmt]||'')}</p></div></section>`;

  /* EPÍLOGO */
  const inv=investigateFor(r.tac);
  h+=`<section class="act ep"><div class="an">EPÍLOGO</div><div class="ab"><h3>O alerta tocou. E agora?</h3>
   <ol class="st-ol">${inv.steps.slice(0,3).map(s=>`<li>${esc(s)}</li>`).join('')}</ol>
   ${SS&&SS.nx.length?`<p>Se a história continuar, o próximo capítulo costuma ser: ${SS.nx.map(([t,n,c])=>`<a href="#" onclick="event.preventDefault();closeModal();openTech('${t}')"><b>${t}</b> ${esc(n)}</a> <span class="id">(${c} grupo${c===1?'':'s'})</span>`).join(' · ')}. Vale caçar isso logo em seguida.</p>`:''}
   <p class="id">Narrativa montada automaticamente a partir dos metadados e do texto da regra, do MITRE ATT&CK (procedimentos), do APT4ALL (país atribuído), do Ransomware Tool Matrix, do TCEM (lente e padrão) e do LLmInjection. Serve para estudar — não valida a regra. Atribuição é de quem publicou.</p></div></section></div>`;
  host.innerHTML=h;
}
window.renderStory=renderStory;
window.loadStoryData=loadStoryData;
