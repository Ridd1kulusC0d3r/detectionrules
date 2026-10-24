/* progress.js — Progressão: ranks, conquistas, estatísticas de estudo */
function renderProgress(){
  const v=$('#v-progress'); const r=rank(V.state.xp); const n=nextRank(V.state.xp);
  const seen=Object.keys(V.state.seen).length; const fmts={}; const srcs={};
  if(window.IDX) for(const k of Object.keys(V.state.seen)){ const x=IDX.find(z=>z.slug+'::'+z.id===k); if(x){fmts[x.fmt]=(fmts[x.fmt]||0)+1; srcs[x.src]=(srcs[x.src]||0)+1;} }
  const lessons=LESSONS.filter(l=>V.state.steps[l.id]).length; const quizOk=Object.values(V.state.quiz).filter(x=>x===1).length;
  v.innerHTML=`
  <div class="eyebrow"><span class="num">PROGRESSÃO /</span> SEU TRILHO</div>
  <h1 class="sec">${r[1]} Você é <span class="g">${r[0]}</span></h1>
  <p class="sub">${n?`Faltam <b style="color:var(--sig)">${n[2]-V.state.xp} XP</b> para ${n[1]} ${n[0]}.`:'Rank máximo. Agora ensine alguém.'} XP vem de: ler regras (+8, depois +3), concluir lições (+50 a +120), acertar quizzes (+40), forjar regras (+25), conquistas (+60).</p>
  <div class="grid g4" style="margin-bottom:22px">
    <div class="stat s"><div class="v">${V.state.xp}</div><div class="l">XP total</div></div>
    <div class="stat b"><div class="v">${seen}</div><div class="l">regras estudadas</div></div>
    <div class="stat v"><div class="v">${lessons}/${LESSONS.length}</div><div class="l">lições</div></div>
    <div class="stat a"><div class="v">${quizOk}/${TOTAL_QUIZ}</div><div class="l">quizzes certos</div></div>
    <div class="stat s"><div class="v">${V.state.forged}</div><div class="l">regras forjadas</div></div>
    <div class="stat b"><div class="v">${V.state.downloads}</div><div class="l">downloads</div></div>
    <div class="stat v"><div class="v">${Object.keys(fmts).length}/11</div><div class="l">formatos lidos</div></div>
    <div class="stat a"><div class="v">${Object.keys(V.state.badges).length}/${Object.keys(BADGES).length}</div><div class="l">conquistas</div></div>
  </div>
  <h2 class="h">Ranks</h2>
  <div class="rankbox">${RANKS.map(k=>`<div class="rank ${V.state.xp>=k[2]?'got':''} ${k[0]===r[0]?'cur':''}"><div class="e">${k[1]}</div><div class="n">${k[0]}</div><div class="x">${k[2]} XP</div></div>`).join('')}</div>
  <h2 class="h">Conquistas</h2>
  <div class="grid g3">${Object.entries(BADGES).map(([k,b])=>`<div class="badge ${V.state.badges[k]?'got':''}"><span class="e">${b[0]}</span><div><b>${b[1]}</b><small>${b[2]}</small></div></div>`).join('')}</div>
  <h2 class="h">Formatos que você já leu</h2>
  <div class="bars">${Object.keys(FMT_PT).map(f=>`<div class="barrow"><span class="lb">${FMT_PT[f]}</span><div class="bb"><i style="width:${Math.min(100,(fmts[f]||0)*10)}%"></i></div><span class="nn">${fmts[f]||0}</span></div>`).join('')}</div>
  <div class="note tip" style="margin-top:18px"><span class="ni">▸</span><div><b>Uma ação por vez.</b> Sugestão agora: ${suggestNext(lessons,seen,fmts)}</div></div>
  <div class="toolbar" style="margin-top:18px"><button class="btn" onclick="download('vigia_progresso.json', JSON.stringify(V.state,null,1))">⬇ exportar progresso</button><button class="btn" onclick="importProgress()">⤓ importar progresso</button><button class="btn" style="color:var(--red)" onclick="if(confirm('Zerar todo o progresso?')){localStorage.removeItem('vigia_state');location.reload()}">zerar</button></div>`;
}
function suggestNext(lessons,seen,fmts){
  if(lessons<LESSONS.length) return `conclua a <b>Lição ${LESSONS.find(l=>!V.state.steps[l.id]).n}</b> na Academia (10 min).`;
  if(seen<10) return `abra <b>3 regras Sigma</b> de process_creation no Arsenal e ache as 5 peças em cada.`;
  const missing=Object.keys(FMT_PT).filter(f=>!fmts[f]); if(missing.length) return `leia uma regra em <b>${FMT_PT[missing[0]]}</b> — formato que você ainda não tocou.`;
  if(V.state.forged<1) return `importe uma regra Sigma na <b>Forja</b>, mude um valor e veja as 6 traduções.`;
  return `escolha uma tática com barra curta no <b>mapa ATT&CK</b> e estude 3 regras dela.`;
}
function importProgress(){ const i=document.createElement('input'); i.type='file'; i.accept='.json'; i.onchange=()=>{const fr=new FileReader(); fr.onload=()=>{try{Object.assign(V.state,JSON.parse(fr.result)); save(); renderXP(); renderProgress(); toast('✓','Progresso importado');}catch{toast('✗','Arquivo inválido')}}; fr.readAsText(i.files[0]);}; i.click(); }
Object.assign(window,{renderProgress,importProgress});
