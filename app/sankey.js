/* ============================================================
   sankey.js — diagrama Sankey em SVG puro (sem bibliotecas).
   sankeySVG({cols:[título...], nodes:[{id,label,col,click?,cls?}], links:[{s,t,v}]}, {w,h,unit})
   - altura do nó = máx(entrada, saída); largura da faixa = valor do fluxo
   - faixas ordenadas pela posição do nó do outro lado (menos cruzamentos)
   - passar o mouse num nó destaca só os fluxos dele
   ============================================================ */
(function(){
let SK_ID=0;
function sankeySVG(data, opt={}){
  const W=opt.w||1100, padX=opt.padX||170, nodeW=10, gap=opt.gap||8, top=34, unit=opt.unit||'', minH=opt.minH||2;
  const ncol=Math.max(...data.nodes.map(n=>n.col))+1;
  const nodes=data.nodes.map(n=>({...n,in:0,out:0,ins:[],outs:[]})); const by={}; nodes.forEach(n=>by[n.id]=n);
  const links=data.links.filter(l=>by[l.s]&&by[l.t]&&l.v>0).map(l=>({...l,src:by[l.s],dst:by[l.t]}));
  links.forEach(l=>{ l.src.out+=l.v; l.dst.in+=l.v; l.src.outs.push(l); l.dst.ins.push(l); });
  nodes.forEach(n=>n.v=Math.max(n.in,n.out,1e-9));
  const cols=[...Array(ncol)].map((_,c)=>nodes.filter(n=>n.col===c));
  // ordenação: coluna 0 por valor; demais pelo baricentro das origens (reduz cruzamentos)
  cols[0].sort((a,b)=>b.v-a.v);
  const H=opt.h||Math.max(260, Math.max(...cols.map(c=>c.length))*(opt.rowH||26)+top+20);
  const avail=H-top-14;
  const ky=Math.min(...cols.map(c=>(avail-gap*(c.length-1))/Math.max(1e-9,c.reduce((s,n)=>s+n.v,0))));
  let maxY=0; const place=c=>{ let y=top; cols[c].forEach(n=>{ n.y=y; n.h=Math.max(minH,n.v*ky); y+=n.h+gap; }); const extra=(H-14)-y+gap; if(extra>0) cols[c].forEach(n=>n.y+=extra/2); maxY=Math.max(maxY,y); };
  place(0);
  for(let c=1;c<ncol;c++){
    cols[c].forEach(n=>{ const w=n.ins.reduce((s,l)=>s+l.v,0); n.bc= w? n.ins.reduce((s,l)=>s+(l.src.y+l.src.h/2)*l.v,0)/w : 1e9; });
    cols[c].sort((a,b)=>a.bc-b.bc||b.v-a.v); place(c);
  }
  const HH=Math.max(H,maxY+14);
  const x=c=> ncol===1?padX: padX+(W-2*padX-nodeW)*c/(ncol-1);
  nodes.forEach(n=>{ n.x=x(n.col); n.outs.sort((a,b)=>a.dst.y-b.dst.y); n.ins.sort((a,b)=>a.src.y-b.src.y); let o=n.y; n.outs.forEach(l=>{l.sy=o; l.w=l.v*ky; o+=l.w;}); let i=n.y; n.ins.forEach(l=>{l.ty=i; i+=l.v*ky;}); });
  const id='sk'+(++SK_ID);
  const fmtV=v=> (Math.round(v*10)/10).toLocaleString('pt-BR');
  const band=l=>{ const x0=l.src.x+nodeW, x1=l.dst.x, xm=(x0+x1)/2, w=Math.max(1,l.w);
    return `M${x0},${l.sy} C${xm},${l.sy} ${xm},${l.ty} ${x1},${l.ty} L${x1},${l.ty+w} C${xm},${l.ty+w} ${xm},${l.sy+w} ${x0},${l.sy+w} Z`; };
  const linkSvg=links.map((l,i)=>`<path class="sk-link ${l.cls||''}" data-s="${esc(l.s)}" data-t="${esc(l.t)}" d="${band(l)}"><title>${esc(l.src.label)} → ${esc(l.dst.label)}: ${fmtV(l.v)}${unit?' '+unit:''}</title></path>`).join('');
  const nodeSvg=nodes.map(n=>{ const left=n.col===ncol-1? false : n.col===0? true : n.col<ncol/2;
    const tx= n.col===0? n.x-6 : n.col===ncol-1? n.x+nodeW+6 : (left? n.x-6 : n.x+nodeW+6); const anchor= (n.col===0||(n.col<ncol-1&&left))?'end':'start';
    const lab=n.label.length>(opt.maxLabel||34)? n.label.slice(0,(opt.maxLabel||34)-1)+'…' : n.label;
    return `<g class="sk-node ${n.cls||''}" data-id="${esc(n.id)}" ${n.click?`onclick="${n.click}" tabindex="0" role="button"`:''}><rect x="${n.x}" y="${n.y}" width="${nodeW}" height="${n.h}"/><text x="${tx}" y="${n.y+n.h/2+4}" text-anchor="${anchor}">${esc(lab)}${opt.showV!==false?` <tspan class="sk-v">${fmtV(n.v)}</tspan>`:''}</text><title>${esc(n.label)} — ${fmtV(n.v)}${unit?' '+unit:''}</title></g>`; }).join('');
  const heads=(data.cols||[]).map((h,c)=>`<text class="gcol" x="${x(c)+(c===0?nodeW:0)}" y="16" text-anchor="${c===0?'end':c===ncol-1?'start':'middle'}">${esc(h)}</text>`).join('');
  setTimeout(()=>wireSankey(id),0);
  return `<div class="gwrap"><svg id="${id}" class="sankey" viewBox="0 0 ${W} ${HH}" role="img" aria-label="${esc(opt.label||'Diagrama Sankey')}">${heads}<g>${linkSvg}</g><g>${nodeSvg}</g></svg></div>`;
}
function wireSankey(id){
  const svg=document.getElementById(id); if(!svg) return;
  svg.querySelectorAll('.sk-node').forEach(g=>{
    const nid=g.dataset.id;
    const on=()=>{ svg.classList.add('focus'); svg.querySelectorAll('.sk-link').forEach(p=>p.classList.toggle('hot',p.dataset.s===nid||p.dataset.t===nid)); g.classList.add('hot'); };
    const off=()=>{ svg.classList.remove('focus'); svg.querySelectorAll('.hot').forEach(p=>p.classList.remove('hot')); };
    g.addEventListener('mouseenter',on); g.addEventListener('mouseleave',off); g.addEventListener('focus',on); g.addEventListener('blur',off);
  });
}
window.sankeySVG=sankeySVG;
})();
