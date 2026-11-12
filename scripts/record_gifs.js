#!/usr/bin/env node
/* Grava os GIFs do README a partir do site rodando localmente.
   Uso:  python3 -m http.server 8765 &   (na raiz do repo)
         node scripts/record_gifs.js [cena ...]      cenas: regra simulacao grafo tecnologias forja
   Requer Playwright (chromium) e ffmpeg. Saída: .github/assets/<cena>.gif */
const { chromium } = require('playwright');
const { execFileSync } = require('child_process');
const fs = require('fs'), path = require('path'), os = require('os');

const URL = process.env.SITE_URL || 'http://localhost:8765/';
const OUT = path.join(__dirname, '..', '.github', 'assets');
const W = 1200, H = 720, GIF_W = 820, FPS = 6;
const sleep = ms => new Promise(r => setTimeout(r, ms));

async function cursor(p) {              // ponteiro visível no vídeo
  await p.addStyleTag({ content: `#__cur{position:fixed;z-index:99999;width:18px;height:18px;border-radius:50%;background:rgba(168,58,20,.35);border:2px solid #a83a14;pointer-events:none;transform:translate(-50%,-50%);transition:width .12s,height .12s}#__cur.dn{width:30px;height:30px}` });
  await p.evaluate(() => { const c = document.createElement('div'); c.id = '__cur'; c.style.left = '600px'; c.style.top = '360px'; document.body.appendChild(c);
    addEventListener('mousemove', e => { c.style.left = e.clientX + 'px'; c.style.top = e.clientY + 'px'; }, true);
    addEventListener('mousedown', () => c.classList.add('dn'), true); addEventListener('mouseup', () => c.classList.remove('dn'), true); });
}
async function click(p, sel, wait = 900) {
  const el = typeof sel === 'string' ? p.locator(sel).first() : sel;
  await el.scrollIntoViewIfNeeded(); const b = await el.boundingBox();
  await p.mouse.move(b.x + b.width / 2, b.y + b.height / 2, { steps: 14 }); await sleep(220);
  await p.mouse.down(); await sleep(90); await p.mouse.up(); await sleep(wait);
}
const top = (p, sel, off = 16) => p.evaluate(([s, o]) => { const e = document.querySelector(s); scrollTo({ top: e.getBoundingClientRect().top + scrollY - o, behavior: 'instant' }); }, [sel, off]).then(() => sleep(900));
const scrollIn = (p, box, sel, off = 60) => p.evaluate(([b, s, o]) => { const m = document.querySelector(b), e = document.querySelector(s); if (m && e) m.scrollTo({ top: e.getBoundingClientRect().top - m.getBoundingClientRect().top + m.scrollTop - o, behavior: 'instant' }); }, [box, sel, off]).then(() => sleep(1100));
const by = (p, dy) => p.evaluate(d => scrollBy({ top: d, behavior: 'instant' }), dy).then(() => sleep(1000));
const tab = async (p, v) => { await click(p, `.tab[data-v=${v}]`, 1600); await top(p, '.tabs', 8); };

const START = {'regra': 'arsenal', 'simulacao': 'arsenal', 'grafo': 'graph', 'tecnologias': 'techno', 'forja': 'forge'};   // aba em que cada cena começa (fora do GIF)
const SCENES = {
  async regra(p) {                       // busca → ficha → história em 5 atos → lógica
    await top(p, '#q', 90);
    await click(p, '#q', 300); await p.keyboard.type('lsass', { delay: 170 }); await sleep(1500);
    await click(p, '.rlist .row', 2200);
    for (const a of [1, 3]) { await p.evaluate(n => { const m = document.querySelector('#mbox'), e = document.querySelectorAll('#p-understand .act')[n]; if (e) m.scrollTo({ top: e.getBoundingClientRect().top - m.getBoundingClientRect().top + m.scrollTop - 70, behavior: 'instant' }); }, a); await sleep(1500); }
    await p.evaluate(() => document.querySelector('#mbox').scrollTo({ top: 0, behavior: 'instant' })); await sleep(700);
    await click(p, '.mtab[data-p=logic]', 2200);
    await p.evaluate(() => document.querySelector('#mbox').scrollBy({ top: 360, behavior: 'instant' })); await sleep(1800);
  },
  async simulacao(p) {                   // prepare os dados (ATT&CK + OSSEM) → simulação no navegador
    await p.fill('#q', 'lsass'); await sleep(1200);
    await p.locator('.rlist .row').first().click(); await sleep(1800);
    await click(p, '.mtab[data-p=data]', 2000); await scrollIn(p, '#mbox', '#ctx-logs', 60); await sleep(1200);
    await p.evaluate(() => document.querySelector('#mbox').scrollBy({ top: 330, behavior: 'instant' })); await sleep(2000);
    await p.evaluate(() => document.querySelector('#mbox').scrollTo({ top: 0, behavior: 'instant' })); await sleep(700);
    await click(p, '.mtab[data-p=experiment]', 1600);
    await click(p, '#simrun', 1800);
    await p.evaluate(() => document.querySelector('#mbox').scrollBy({ top: 300, behavior: 'instant' })); await sleep(2400);
  },
  async grafo(p) {                       // matriz de cobertura → técnica → atribuição por TTP → Sankey
    await sleep(1200); await click(p, '[data-gm=matrix]', 1200); await by(p, 260); await sleep(900);
    await click(p, '.mcell[onclick*="T1059"]', 2600); await p.keyboard.press('Escape'); await sleep(700);
    await top(p, '.tabs', 8); await click(p, '[data-gm=attrib]', 1200);
    await click(p, 'button[onclick="caseDemo()"]', 2200); await by(p, 430); await sleep(1700); await by(p, 430); await sleep(2200);
  },
  async tecnologias(p) {                 // mapa por domínio → heatmap → Sankey → relatório da tecnologia
    await sleep(1200); await by(p, 200); await sleep(900);
    await click(p, '[data-tm=heat]', 2200); await by(p, 160); await sleep(1300);
    await click(p, '[data-tm=flows]', 2400); await by(p, 120); await sleep(1500);
    await click(p, '[data-tm=map]', 1200); await click(p, '.tile[onclick*="okta"]', 2600); await by(p, 420); await sleep(2000);
  },
  async forja(p) {                       // comportamento + dados → regra → 6 traduções
    await sleep(800);
    await top(p, '#beh_what', 120); const b = await p.locator('#beh_what').boundingBox();
    await p.mouse.move(b.x + b.width / 2, b.y + b.height / 2, { steps: 14 }); await sleep(500);
    await p.selectOption('#beh_what', { index: 1 }); await sleep(1300);
    await click(p, '#beh_go', 2200);
    await top(p, '.mtab[data-o=sigma]', 60); await sleep(1600);
    for (const o of ['kql', 'spl', 'eql', 'wazuh']) await click(p, `.mtab[data-o=${o}]`, 1400);
  },
};

(async () => {
  const want = process.argv.slice(2).length ? process.argv.slice(2) : Object.keys(SCENES);
  fs.mkdirSync(OUT, { recursive: true });
  const browser = await chromium.launch();
  for (const name of want) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rec-'));
    const ctx = await browser.newContext({ viewport: { width: W, height: H }, recordVideo: { dir, size: { width: W, height: H } }, locale: 'pt-BR' });
    const p = await ctx.newPage(); const t0 = Date.now();
    await p.goto(URL); await p.waitForSelector('.tab[data-v=arsenal]'); await sleep(3000); await cursor(p);
    await tab(p, START[name]); await sleep(600);
    const skip = (Date.now() - t0) / 1000;                        // corta o carregamento inicial
    await SCENES[name](p); await sleep(1200);
    await ctx.close(); const webm = path.join(dir, fs.readdirSync(dir).find(f => f.endsWith('.webm')));
    const gif = path.join(OUT, `${name}.gif`);
    execFileSync('ffmpeg', ['-y', '-loglevel', 'error', '-ss', skip.toFixed(2), '-i', webm, '-vf',
      `fps=${FPS},scale=${GIF_W}:-1:flags=lanczos,split[a][b];[a]palettegen=max_colors=40:stats_mode=diff[p];[b][p]paletteuse=dither=none:diff_mode=rectangle`, gif]);
    console.log(name, (fs.statSync(gif).size / 1e6).toFixed(2) + ' MB', ((Date.now() - t0) / 1000 - skip).toFixed(0) + 's');
    fs.rmSync(dir, { recursive: true, force: true });
  }
  await browser.close();
})();
