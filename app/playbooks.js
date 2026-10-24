/* playbooks.js — modelos de resposta (SOAR) + navegador dos playbooks reais do catálogo */
function renderPlaybooks(){
  if(!window.IDX) buildIndex();
  const pbs=IDX.filter(r=>r.fmt==='playbook');
  const bySrc={}; pbs.forEach(p=>bySrc[p.src]=(bySrc[p.src]||0)+1);
  const v=$('#v-playbooks');
  v.innerHTML=`
  <div class="eyebrow"><span class="num">PLAYBOOKS /</span> RESPOSTA & INVESTIGAÇÃO (SOAR)</div>
  <h1 class="sec">Detecção aponta o problema. <span class="g">Playbook conduz a resposta.</span></h1>
  <p class="sub">Separe os três: <b>Detecção</b> identifica uma condição suspeita; <b>Hunting</b> explora uma hipótese; <b>Resposta (SOAR)</b> conduz investigação e contenção. Abaixo, 5 modelos de triagem reutilizáveis e ${pbs.length.toLocaleString('pt-BR')} playbooks reais do catálogo (Cortex XSOAR, Splunk SOAR/Phantom, Shuffle, awesome-playbooks).</p>
  <h2 class="h">Modelos de triagem (prontos para adaptar)</h2>
  <div class="grid g2">${PLAYBOOK_TEMPLATES.map(p=>`<div class="card click" onclick="openPlaybookTemplate('${p.id}')"><div class="tag v">MODELO</div><h3 class="h">${esc(p.name)}</h3><p style="font-size:12.5px;color:var(--ink-dim)"><b>Gatilho:</b> ${esc(p.trigger)}</p><p style="font-size:12px;color:var(--ink-faint);margin-top:6px">${p.steps.length} passos · entrada: ${esc(p.entrada)} → saída: ${esc(p.saida)}</p></div>`).join('')}</div>
  <h2 class="h">Playbooks reais do catálogo</h2>
  <div class="pill-row">${Object.entries(bySrc).sort((a,b)=>b[1]-a[1]).map(([s,n])=>`<span class="tag" style="cursor:pointer" onclick="A.fmt.clear();A.fmt.add('playbook');A.src.clear();A.src.add('${s.replace(/'/g,"\\'")}');go('arsenal')">${esc(s)} (${n})</span>`).join('')}</div>
  <div class="note tip" style="margin-top:14px"><span class="ni">▸</span><div>Clique numa fonte para abrir esses playbooks no Arsenal (eles entram no mesmo navegador de regras, com proveniência e licença). <b>Lembre:</b> um playbook só é útil se disparado por uma detecção e se as integrações/credenciais estiverem configuradas — por isso ele precisa de editor, entradas e testes próprios, distintos da regra.</div></div>
  <div class="note osint"><span class="ni">✶</span><div><b>O cuidado que o projeto adota:</b> não tratamos SOAR como "conversor universal". Cada plataforma (XSOAR, Splunk SOAR, Shuffle) tem seu modelo; mostramos o original e ligamos a regra ao playbook por <b>intenção</b>, não por conversão automática silenciosa.</div></div>`;
}
window.openPlaybookTemplate=function(id){
  const p=PLAYBOOK_TEMPLATES.find(x=>x.id===id); if(!p) return;
  openModal(`<div class="mhead"><div style="flex:1"><h2>${esc(p.name)}</h2><div class="pill-row"><span class="tag v">modelo de triagem</span><span class="tag">${p.steps.length} passos</span></div></div><button class="x" onclick="closeModal()">✕</button></div>
  <div class="mbody">
    <div class="kv"><dt>Gatilho</dt><dd>${esc(p.trigger)}</dd><dt>Entrada</dt><dd>${esc(p.entrada)}</dd><dt>Saída esperada</dt><dd>${esc(p.saida)}</dd></div>
    <h3 class="h">Fluxo</h3>
    <div class="path" style="flex-direction:column;gap:0">${p.steps.map((s,i)=>`<div class="step" style="cursor:default;min-width:auto;border-radius:${i===0?'12px 12px 0 0':i===p.steps.length-1?'0 0 12px 12px':'0'}"><div class="n">PASSO ${i+1}</div><div class="d" style="font-size:13px;color:var(--ink-dim)">${esc(s)}</div></div>`).join('')}</div>
    <div class="toolbar"><button class="btn p" onclick='download("playbook_${p.id}.md", ${JSON.stringify("# "+p.name+"\n\n**Gatilho:** "+p.trigger+"\n\n**Entrada:** "+p.entrada+"  \n**Saída:** "+p.saida+"\n\n## Fluxo\n"+p.steps.map((s,i)=>(i+1)+". "+s).join("\n"))})'>⬇ baixar modelo (.md)</button></div>
    <div class="note warn"><span class="ni">▸</span><div>Modelo <b>agnóstico de plataforma</b>. Para implementar em XSOAR/Splunk SOAR/Shuffle, mapeie cada passo para as integrações disponíveis e defina entradas, dependências e testes próprios do playbook.</div></div>
  </div>`);
};
window.renderPlaybooks=renderPlaybooks;
