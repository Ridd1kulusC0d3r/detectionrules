/* boot.js — carga de dados, navegação e página Base */
function go(view){
  V.view=view; $$('.tab').forEach(t=>t.classList.toggle('on',t.dataset.v===view)); $$('.view').forEach(s=>s.classList.toggle('on',s.id==='v-'+view));
  ({home:renderHome,academy:renderAcademy,arsenal:renderArsenal,techno:renderTechno,graph:renderGraph,forge:renderForge,playbooks:renderPlaybooks,progress:renderProgress})[view]?.();
  window.scrollTo({top:0});
  location.hash=view;
}
$$('.tab').forEach(t=>t.onclick=()=>go(t.dataset.v));
addEventListener('keydown',e=>{ if(e.key==='/'&&!/INPUT|TEXTAREA/.test(document.activeElement.tagName)){ e.preventDefault(); if(V.view!=='arsenal') go('arsenal'); setTimeout(()=>$('#q')?.focus(),50);} });

function renderHome(){
  const m=V.man; const bySrc=m.sources; const total=m.total;
  const fmtCount={}; if(window.IDX||V.idx){ if(!window.IDX) buildIndex(); for(const r of IDX) fmtCount[r.fmt]=(fmtCount[r.fmt]||0)+1; }
  const tac={}; TACTICS.forEach(t=>tac[t]=0); for(const r of IDX) r.tac.forEach(t=>{ if(tac[t]!=null) tac[t]++; });
  const withTech=IDX.filter(r=>r.tech.length).length; const maxT=Math.max(...Object.values(tac));
  const ct={}; IDX.forEach(r=>ct[r.ctype]=(ct[r.ctype]||0)+1);
  $('#v-home').innerHTML=`
  <div class="eyebrow">Visão geral</div>
  <h1 class="sec">O estado do catálogo</h1>
  <p class="sub">${bySrc.length} fontes públicas de engenharia de detecção normalizadas num só esquema, gerado em ${m.generated}. Clique em qualquer barra ou número para abrir as regras correspondentes no Arsenal.</p>
  <div class="grid g4" style="margin-bottom:8px">
    <div class="stat"><div class="v">${Object.keys(fmtCount).length}</div><div class="l">formatos de regra</div></div>
    <div class="stat"><div class="v">${withTech.toLocaleString('pt-BR')}</div><div class="l">com técnica ATT&CK</div></div>
    <div class="stat"><div class="v">${(ct.hunting||0).toLocaleString('pt-BR')}</div><div class="l">consultas de hunting</div></div>
    <div class="stat"><div class="v">${(ct.playbook||0).toLocaleString('pt-BR')}</div><div class="l">playbooks SOAR</div></div>
  </div>
  <div id="ctstats" hidden></div>
  <h2 class="h">Por onde começar</h2>
  <div class="grid g4">
    <div class="card click" onclick="go('academy')"><div class="eyebrow">8 lições</div><h3 class="h">Academia</h3><p style="font-size:14px">A gramática que todos os formatos compartilham, explicada como para uma criança e levada até o nível de quem escreve regra.</p></div>
    <div class="card click" onclick="go('arsenal')"><div class="eyebrow">${total.toLocaleString('pt-BR')} regras</div><h3 class="h">Arsenal</h3><p style="font-size:14px">Busque e filtre por tática, fonte e severidade. Cada regra abre com campos explicados, dados necessários, simulação e guia de investigação.</p></div>
    <div class="card click" onclick="go('techno')"><div class="eyebrow">${(V.idx.tech||[]).length-1} tecnologias</div><h3 class="h">Tecnologias</h3><p style="font-size:14px">O catálogo pelo que ele observa: Okta, AWS, ESXi, Kubernetes… cobertura por tática, lacunas, grupos na mira, ferramentas de ransomware e cenários TCEM.</p></div>
    <div class="card click" onclick="go('forge')"><div class="eyebrow">6 formatos</div><h3 class="h">Forja</h3><p style="font-size:14px">Diga o comportamento e os dados que você tem; receba Sigma, KQL, SPL, EQL, TOML Elastic e Wazuh, com validação e explicação.</p></div>
    <div class="card click" onclick="go('progress')"><div class="eyebrow">XP e ranks</div><h3 class="h">Progressão</h3><p style="font-size:14px">XP por regra lida, lição concluída, quiz e regra forjada. Sete ranks e doze conquistas, salvos no seu navegador.</p></div>
  </div>
  <div class="note osint"><span class="ni">✶</span><div><b>Mais que um catálogo — um ambiente de engenharia de detecção.</b> Cada regra abre em 7 abas (Entenda · Lógica · Prepare os dados · Experimente · Adapte · Investigue · Origem): você responde <i>o que ela detecta, de quais dados depende, por que dispararia e como provar que funciona</i>. Regras Sigma têm <b>simulação de eventos</b> no navegador. A Forja tem <b>construtor orientado ao comportamento</b> e gera <b>pacote de detecção</b> (regra + guia + testes). Playbooks de resposta estão separados das detecções.</div></div>
  <h2 class="h">O que tem dentro</h2>
  <div class="grid g2">
   <div class="card"><h3 class="h" style="margin-top:0">Regras por fonte</h3><div class="bars">${bySrc.map(s=>`<div class="barrow" style="cursor:pointer" onclick="A.src.clear();A.src.add('${s.name.replace(/'/g,"\\'")}');go('arsenal')"><span class="lb" title="${esc(s.name)}">${esc(s.name)}</span><div class="bb"><i style="width:${s.n/bySrc[0].n*100}%"></i></div><span class="nn">${s.n.toLocaleString('pt-BR')}</span></div>`).join('')}</div></div>
   <div class="card"><h3 class="h" style="margin-top:0">Cobertura ATT&CK (regras com tática mapeada)</h3><div class="bars">${TACTICS.map(t=>`<div class="barrow" style="cursor:pointer" onclick="A.tac.clear();A.tac.add('${t}');go('arsenal')"><span class="lb">${TACTIC_PT[t]}</span><div class="bb"><i style="width:${tac[t]/maxT*100}%"></i></div><span class="nn">${tac[t].toLocaleString('pt-BR')}</span></div>`).join('')}</div>
   <p style="font-size:12px;color:var(--ink-faint);margin-top:8px">Barras curtas (Reconhecimento, Desenvolvimento de Recursos) são pontos cegos reais da indústria: acontecem fora da sua rede. É onde OSINT entra como sensor.</p></div>
  </div>
  <div class="feynman"><div class="lbl">COMO USAR ESTE MATERIAL (PARA UMA CRIANÇA)</div>
  <p>Imagine uma <span class="em">biblioteca com 84 mil receitas de "como pegar ladrão"</span>, escritas por cozinheiros do mundo inteiro, em 11 línguas diferentes. Sozinhas, elas assustam. Este app faz três coisas: <span class="em">ensina as línguas</span> (Academia), <span class="em">deixa você ler qualquer receita com um dicionário do lado</span> (Arsenal) e <span class="em">te dá uma cozinha para escrever a sua</span> (Forja).</p>
  <p>Regra de ouro: <span class="em">não leia 84 mil. Leia 20 com atenção.</span> Cada regra bem entendida vale mais que mil copiadas.</p></div>
  <h2 class="h">Fontes e licenças</h2>
  <table class="tbl"><tr><th>Fonte</th><th>Regras</th><th>Formato</th><th>Licença</th></tr>
  ${bySrc.map(s=>{const x=IDX.find(r=>r.src===s.name); return `<tr><td><strong>${esc(s.name)}</strong></td><td>${s.n.toLocaleString('pt-BR')}</td><td><code>${FMT_PT[x?.fmt]||x?.fmt||''}</code></td><td>${esc(x?.lic||'')}</td></tr>`;}).join('')}</table>
  <p style="font-size:12px;color:var(--ink-faint)">Os arquivos originais foram clonados dos repositórios públicos em ${m.generated} e são exibidos sem alteração; cada regra mantém sua licença. Observe as condições (especialmente GPLv2 e Elastic License v2) antes de redistribuir. Emerging Threats Open e Snort Community oficiais não puderam ser baixados (fora do GitHub, bloqueados pela rede do ambiente de geração); incluímos mirrors de regras Suricata/Snort e Sagan no lugar.</p>`;
  const cts=document.getElementById('ctstats'); if(cts) cts.innerHTML=[['detection','Detecção','s'],['signature','Assinaturas','a'],['hunting','Hunting','b'],['playbook','Playbooks SOAR','v']].map(([k,l,c])=>`<div class="stat ${c}" style="cursor:pointer" onclick="A.ctype.clear();A.ctype.add('${k}');go('arsenal')"><div class="v">${(ct[k]||0).toLocaleString('pt-BR')}</div><div class="l">${l}</div></div>`).join('');
}

/* faixa de números do cabeçalho */
function renderMast(){
  const ct={}; IDX.forEach(r=>ct[r.ctype]=(ct[r.ctype]||0)+1);
  const items=[[V.man.total,'regras',()=>{A.ctype.clear();}],[V.man.sources.length,'fontes',null],[ct.detection||0,'detecção','detection'],[ct.signature||0,'assinaturas','signature'],[ct.hunting||0,'hunting','hunting'],[ct.playbook||0,'playbooks','playbook']];
  $('#metrics').innerHTML=items.map(([n,l,k])=>`<div class="st" data-k="${typeof k==='string'?k:''}"><b>${Number(n).toLocaleString('pt-BR')}</b><span>${l}</span></div>`).join('');
  $$('#metrics .st').forEach((el,i)=>el.onclick=()=>{ A.ctype.clear(); const k=el.dataset.k; if(k) A.ctype.add(k); A.page=0; go(i===1?'home':'arsenal'); });
  $('#asof').textContent='Catálogo de '+V.man.generated.split('-').reverse().join('/');
}
/* ticker */
(function(){ const items=['<b class="g">ARSENAL</b> · 84.566 regras de 47 fontes','<b class="a">DICA</b> · pressione / para buscar','<b class="v">ACADEMIA</b> · 8 lições · técnica de Feynman','<b class="r">LEMBRE</b> · regra sem FP documentado não vai para produção','<b class="g">FORJA</b> · construtor por comportamento · 6 formatos','<b class="a">PIRÂMIDE</b> · mire no comportamento, não na assinatura','<b class="v">AUSÊNCIA</b> · o silêncio também é sinal']; $('#ticker').innerHTML=(items.concat(items)).map(i=>`<span>${i}</span>`).join(''); })();

/* carga */
(async function boot(){
  renderXP();
  $('#v-home').innerHTML='<div class="loading">Carregando índice de regras…<div class="bar"><i id="lb" style="width:15%"></i></div><p style="margin-top:8px;font-size:11px">~10 MB na primeira vez; depois fica em cache do navegador</p></div>';
  try{
    const [man,show]=await Promise.all([fetch('data/manifest.json').then(r=>r.json()),fetch('data/showcase.json').then(r=>r.json())]);
    V.man=man; V.show=show; $('#lb').style.width='40%';
    V.idx=await fetch('data/index.json').then(r=>r.json()); $('#lb').style.width='90%';
    buildIndex(); renderMast();
    const h=location.hash.replace('#','');
    const dl=h.match(/^(group|tech|rule|techno)=(.+)$/);
    if(dl){ const [,k,v]=dl; const val=decodeURIComponent(v);
      if(k==='rule'){ go('arsenal'); setTimeout(()=>openRuleByUid(val),300); }
      else if(k==='techno'){ go('techno'); setTimeout(()=>openTechno(val),400); }
      else { go('graph'); setTimeout(()=>(k==='group'?openGroup(val):openTech(val.toUpperCase())),600); }
    } else go(['home','academy','arsenal','techno','graph','forge','playbooks','progress'].includes(h)?h:'home');
  }catch(e){
    $('#v-home').innerHTML=`<div class="note warn"><span class="ni">▸</span><div><b>Não consegui carregar os dados.</b> Este app precisa ser aberto por um servidor local (os navegadores bloqueiam fetch de arquivos locais). Use o lançador <code>ABRIR.bat</code> / <code>ABRIR.command</code> / <code>abrir.sh</code> na pasta, ou rode <code>python3 -m http.server 8787</code> e abra <code>http://localhost:8787</code>.<br><br>Erro: <code>${esc(e.message)}</code></div></div>`;
  }
})();
window.go=go;
