/* ============================================================
   sigma_engine.js — simulação didática de regras Sigma no navegador.
   parseSigma(yaml) → {blocks:{name:[{field,mods,values}]}, condition, logsource, meta}
   evaluate(rule, event) → {matched, blocks:{name:{hit, fields:[{field,mods,values,actual,hit}]}}, condition, steps}
   genEvents(rule) → {positive, negative[]}
   É uma SIMULAÇÃO DIDÁTICA: cobre o subconjunto comum da spec Sigma (v1/v2 básica).
   Não substitui o teste no mecanismo real.
   ============================================================ */
(function(){
function unq(v){ v=v.trim(); if((v.startsWith("'")&&v.endsWith("'"))||(v.startsWith('"')&&v.endsWith('"'))) v=v.slice(1,-1).replace(/''/g,"'"); if(v==='null'||v==='') return null; if(/^-?\d+$/.test(v)) return Number(v); if(v==='true') return true; if(v==='false') return false; return v; }
function parseSigma(text){
  const lines=text.replace(/\t/g,'    ').split('\n');
  // detection block
  let i=lines.findIndex(l=>/^detection:\s*$/.test(l)); const blocks={}; let condition=''; const notes=[];
  if(i>=0){
    let cur=null, curField=null;
    for(i=i+1;i<lines.length;i++){
      const l=lines[i]; if(/^\S/.test(l)) break; if(!l.trim()||l.trim().startsWith('#')) continue;
      const ind=l.match(/^ */)[0].length; const s=l.trim();
      if(ind===4){
        const m=s.match(/^([A-Za-z_][\w]*):\s*(.*)$/); if(!m) continue;
        if(m[1]==='condition'){ condition=m[2].replace(/#.*$/,'').trim(); cur=null; continue; }
        cur=m[1]; blocks[cur]=[]; curField=null;
        if(m[2].trim()){ notes.push(`bloco ${cur} com valor inline (lista de mapas/keywords) — suportado parcialmente`); if(m[2].trim().startsWith('[')) { // keywords inline list
            blocks[cur].push({field:null,mods:[],values:m[2].trim().slice(1,-1).split(',').map(unq).filter(x=>x!=null),kw:true}); } }
      } else if(ind===8 && cur){
        const m=s.match(/^([A-Za-z_][\w.|]*):\s*(.*)$/);
        if(m){ const parts=m[1].split('|'); curField={field:parts[0],mods:parts.slice(1),values:[]}; blocks[cur].push(curField);
          const v=m[2].replace(/\s+#.*$/,'').trim();
          if(v.startsWith('[')&&v.endsWith(']')) curField.values=v.slice(1,-1).split(',').map(unq).filter(x=>x!=null); else if(v!=='') { const u=unq(v); if(u!=null) curField.values=[u]; }
        } else if(s.startsWith('- ')){ // keyword list (no field)
          const kw=blocks[cur].find(b=>b.kw)||(blocks[cur].push({field:null,mods:[],values:[],kw:true}),blocks[cur][blocks[cur].length-1]); const u=unq(s.slice(2)); if(u!=null) kw.values.push(u);
        }
      } else if(ind>=12 && curField && s.startsWith('- ')){ const u=unq(s.slice(2).replace(/\s+#.*$/,'')); if(u!=null) curField.values.push(u); }
      else if(ind===8 && !cur){ }
    }
  }
  const top=k=>{const m=text.match(new RegExp('^'+k+':\\s*(.*)$','m')); return m?m[1].trim():'';};
  const ls=k=>{const m=text.match(new RegExp('^    '+k+':\\s*(.+)$','m')); return m?m[1].trim():'';};
  return {blocks,condition,notes,meta:{title:top('title'),level:top('level'),id:top('id')},logsource:{product:ls('product'),category:ls('category'),service:ls('service')}};
}
/* ---------- comparação de valor com modificadores ---------- */
function globToRe(s){ return new RegExp('^'+String(s).replace(/[.+^${}()|[\]\\]/g,'\\$&').replace(/\*/g,'.*').replace(/\?/g,'.')+'$','i'); }
function cmp(actual, value, mods){
  if(actual===undefined||actual===null) return mods.includes('exists')? value===false : false;
  const a=String(actual), v=String(value); const al=a.toLowerCase(), vl=v.toLowerCase();
  if(mods.includes('exists')) return value!==false;
  if(mods.includes('re')) { try{ return new RegExp(v, mods.includes('i')?'i':'').test(a);}catch{return false;} }
  if(mods.includes('cidr')) return cidr(a,v);
  if(mods.includes('gt')) return Number(a)>Number(v); if(mods.includes('gte')) return Number(a)>=Number(v); if(mods.includes('lt')) return Number(a)<Number(v); if(mods.includes('lte')) return Number(a)<=Number(v);
  let cands=[vl];
  if(mods.includes('windash')) cands=cands.flatMap(x=>[x, x.replace(/(^|\s)-/g,'$1/'), x.replace(/(^|\s)-/g,'$1–'), x.replace(/(^|\s)\//g,'$1-')]);
  if(mods.includes('base64offset')||mods.includes('base64')){ const b=s=>btoa(unescape(encodeURIComponent(s))); cands=cands.flatMap(x=>{ if(mods.includes('base64offset')) return [0,1,2].map(o=>b(' '.repeat(o)+x).slice(o?2:0,-2)); return [b(x)]; }).map(x=>x.toLowerCase()); }
  for(const c of cands){
    if(mods.includes('contains')&&al.includes(c)) return true;
    if(mods.includes('endswith')&&al.endsWith(c)) return true;
    if(mods.includes('startswith')&&al.startsWith(c)) return true;
    if(!mods.some(m=>['contains','endswith','startswith'].includes(m))){ if(/[*?]/.test(c)){ if(globToRe(c).test(a)) return true; } else if(al===c) return true; }
  }
  return false;
}
function cidr(ip,range){ const [r,bits]=range.split('/'); const toN=s=>s.split('.').reduce((n,o)=>(n<<8)+(+o),0)>>>0; if(!/^\d+\.\d+\.\d+\.\d+$/.test(ip)) return false; const mask=bits==='0'?0:(~0<<(32-+bits))>>>0; return (toN(ip)&mask)===(toN(r)&mask); }
function getField(ev, f){ if(f in ev) return ev[f]; const k=Object.keys(ev).find(k=>k.toLowerCase()===f.toLowerCase()); if(k) return ev[k]; if(f.includes('.')) return f.split('.').reduce((o,p)=>o&&o[p],ev); return undefined; }
function evalBlock(items, ev){
  const fields=[]; let hit=true;
  for(const it of items){
    if(it.kw){ const hay=JSON.stringify(ev).toLowerCase(); const h=it.values.some(v=>hay.includes(String(v).toLowerCase())); fields.push({field:'(keywords)',mods:[],values:it.values,actual:'(evento inteiro)',hit:h}); hit=hit&&h; continue; }
    const actual=getField(ev,it.field); const mods=it.mods; const all=mods.includes('all');
    const results=it.values.map(v=>cmp(actual,v,mods)); const h= it.values.length? (all? results.every(Boolean) : results.some(Boolean)) : (actual!==undefined);
    fields.push({field:it.field,mods,values:it.values,actual,hit:h,per:results}); hit=hit&&h;
  }
  return {hit,fields};
}
/* ---------- condition ---------- */
function evalCondition(cond, blockHits){
  const names=Object.keys(blockHits);
  let toks=cond.replace(/\(/g,' ( ').replace(/\)/g,' ) ').split(/\s+/).filter(Boolean); let p=0; const steps=[];
  const matchNames=pat=>{ if(pat==='them') return names; if(pat.endsWith('*')) return names.filter(n=>n.startsWith(pat.slice(0,-1))); return names.includes(pat)?[pat]:[]; };
  function primary(){
    const t=toks[p];
    if(t==='('){ p++; const v=orExpr(); if(toks[p]===')') p++; return v; }
    if(t==='not'){ p++; const v=primary(); steps.push(`not → ${!v}`); return !v; }
    if(t==='1'||t==='all'||/^\d+$/.test(t)){ const n=t; p++; if(toks[p]==='of') p++; const pat=toks[p++]; const ns=matchNames(pat); const hits=ns.filter(x=>blockHits[x]).length; const v= n==='all'? ns.length>0&&hits===ns.length : hits>=+n; steps.push(`${n} of ${pat} → ${hits}/${ns.length} casaram → ${v}`); return v; }
    p++; const v=!!blockHits[t]; if(!(t in blockHits)) steps.push(`⚠ bloco "${t}" não existe`); return v;
  }
  function andExpr(){ let v=primary(); while(toks[p]==='and'){ p++; const r=primary(); v=v&&r; } return v; }
  function orExpr(){ let v=andExpr(); while(toks[p]==='or'){ p++; const r=andExpr(); v=v||r; } return v; }
  if(/\|\s*(count|near)/.test(cond)) steps.push('⚠ agregação (| count/near) ignorada na simulação de evento único');
  const c=cond.split('|')[0].trim(); toks=c.replace(/\(/g,' ( ').replace(/\)/g,' ) ').split(/\s+/).filter(Boolean); p=0;
  const result=orExpr(); return {result,steps};
}
function evaluate(rule, ev){
  const blocks={}; const hits={};
  for(const [n,items] of Object.entries(rule.blocks)){ blocks[n]=evalBlock(items,ev); hits[n]=blocks[n].hit; }
  const c=evalCondition(rule.condition||Object.keys(rule.blocks)[0]||'', hits);
  return {matched:c.result, blocks, condition:rule.condition, steps:c.steps};
}
/* ---------- geração de eventos de teste ---------- */
const PREFIX={Image:'C:\\Windows\\System32',ParentImage:'C:\\Program Files\\App',TargetImage:'C:\\Windows\\System32',SourceImage:'C:\\Users\\user\\AppData\\Local\\Temp',TargetFilename:'C:\\Users\\user\\AppData\\Roaming',ImageLoaded:'C:\\Windows\\System32',TargetObject:'HKCU\\Software'};
function synth(field,values,mods){
  const v=values[0]; if(v==null) return 'x';
  const s=String(v).replace(/[*?]/g,'');
  if(mods.includes('re')) return s.replace(/[\\^$.*+?()[\]{}|]/g,'').slice(0,40)||'match';
  if(mods.includes('cidr')) return s.split('/')[0].replace(/\.0$/,'.10');
  if(mods.includes('all')) return values.map(x=>String(x).replace(/[*?]/g,'')).join(' ');
  if(mods.includes('endswith')) return (PREFIX[field]||'C:\\path')+(s.startsWith('\\')?'':'\\')+s;
  if(mods.includes('startswith')) return s+'\\rest';
  if(mods.includes('contains')) return 'prefix '+s+' suffix';
  return v;
}
function genEvents(rule){
  const sel=Object.entries(rule.blocks).filter(([n])=>!/^filter/.test(n)); const flt=Object.entries(rule.blocks).filter(([n])=>/^filter/.test(n));
  const pos={};
  for(const [n,items] of sel) for(const it of items){ if(it.kw){ pos._keywords=it.values[0]; continue;} if(pos[it.field]===undefined) pos[it.field]=synth(it.field,it.values,it.mods); }
  // campos base plausíveis
  if(rule.logsource.category==='process_creation'){ pos.EventID??=1; pos.User??='CORP\\usuario'; pos.Computer??='WS-042'; pos.ProcessId??=4812; }
  if(rule.logsource.service==='security'){ pos.Computer??='DC-01'; }
  const negs=[];
  // negativo 1: muda o primeiro campo da selection
  const first=sel[0]?.[1]?.find(x=>!x.kw); if(first){ const n1={...pos}; n1[first.field]= first.mods.includes('endswith')? 'C:\\Windows\\System32\\notepad.exe' : 'valor_benigno'; negs.push({label:`mudou ${first.field} para valor benigno`, ev:n1}); }
  // negativo 2: remove um campo (evento incompleto)
  const second=sel[0]?.[1]?.filter(x=>!x.kw)[1]; if(second){ const n2={...pos}; delete n2[second.field]; negs.push({label:`campo ${second.field} ausente (telemetria incompleta)`, ev:n2}); }
  // negativo 3: ativa o filtro (caso legítimo)
  if(flt.length){ const n3={...pos}; for(const it of flt[0][1]){ if(!it.kw) n3[it.field]=synth(it.field,it.values,it.mods); } negs.push({label:`caso legítimo do ${flt[0][0]} (deve ser ignorado)`, ev:n3}); }
  return {positive:pos, negatives:negs};
}
window.Sigma={parseSigma,evaluate,genEvents,cmp};
})();
