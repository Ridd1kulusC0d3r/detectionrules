/* ============================================================
   academy.js — Academia: lições Feynman + dissecação de regras reais campo a campo
   ============================================================ */
const LESSONS = [
 {id:'logic', n:'01', t:'A gramática de toda regra', d:'5 peças que existem em qualquer formato', xp:60},
 {id:'pyramid', n:'02', t:'O que vale detectar', d:'Pirâmide da Dor aplicada a regras', xp:50},
 {id:'anatomy', n:'03', t:'Anatomia: selection + condition', d:'AND, OR, NOT e modificadores', xp:70},
 {id:'correlation', n:'04', t:'Correlação e janelas de tempo', d:'frequency, threshold, match, sequence', xp:80},
 {id:'fp', n:'05', t:'Falsos positivos e tuning', d:'filtros, allowlists e o custo do ruído', xp:60},
 {id:'absence', n:'06', t:'Detecção pela Ausência', d:'quando o silêncio é o sinal', xp:90},
 {id:'formats', n:'07', t:'Os 11 formatos, dissecados', d:'uma regra real de cada, campo a campo', xp:120},
 {id:'lifecycle', n:'08', t:'Ciclo de vida de uma regra', d:'ideia → teste → produção → tuning → aposentadoria', xp:60},
];

function renderAcademy(){
  const v=$('#v-academy');
  const done=LESSONS.filter(l=>V.state.steps[l.id]).length;
  v.innerHTML=`
  <div class="eyebrow"><span class="num">ACADEMIA /</span> ENTENDER ANTES DE COPIAR</div>
  <h1 class="sec">Como uma regra <span class="g">pensa</span></h1>
  <p class="sub">Oito lições curtas, do zero. Cada uma termina com algo que você faz — não só lê. Conclua as oito e todo arquivo do Arsenal vira texto legível. Progresso: <b style="color:var(--sig)">${done}/${LESSONS.length}</b>.</p>
  <div class="path" id="lesson-path">${LESSONS.map(l=>`<div class="step ${V.state.steps[l.id]?'done':''}" data-l="${l.id}"><div class="n">LIÇÃO ${l.n}</div><div class="t">${l.t}</div><div class="d">${l.d}</div><span class="chk">✓</span></div>`).join('')}</div>
  <div id="lesson-body" style="margin-top:22px"></div>`;
  $$('.step',v).forEach(s=>s.onclick=()=>showLesson(s.dataset.l));
  const first=LESSONS.find(l=>!V.state.steps[l.id])||LESSONS[0];
  showLesson(first.id);
}

function completeBtn(id){
  const l=LESSONS.find(x=>x.id===id);
  if(V.state.steps[id]) return `<div class="note tip"><span class="ni">✓</span><div>Lição concluída. Avance para a próxima no trilho acima.</div></div>`;
  return `<button class="btn p" onclick="completeLesson('${id}')">✓ Entendi — concluir lição (+${l.xp} XP)</button>`;
}
window.completeLesson=function(id){
  if(V.state.steps[id]) return;
  V.state.steps[id]=1; save();
  const l=LESSONS.find(x=>x.id===id); addXP(l.xp,'Lição concluída: '+l.t);
  if(id==='absence') badge('absence');
  if(LESSONS.every(x=>V.state.steps[x.id])) badge('academy_done');
  renderAcademy();
  const nxt=LESSONS.find(x=>!V.state.steps[x.id]); if(nxt) showLesson(nxt.id);
};

function showLesson(id){
  $$('.step').forEach(s=>s.style.outline= s.dataset.l===id?'1px solid var(--violet)':'');
  const b=$('#lesson-body'); b.innerHTML=LESSON_HTML[id](); b.scrollIntoView({behavior:'smooth',block:'start'});
}

const LESSON_HTML = {
/* ---------------- 01 ---------------- */
logic(){ return `
<div class="eyebrow"><span class="num">LIÇÃO 01 /</span> A GRAMÁTICA DE TODA REGRA</div>
<h2 class="h">Não importa o formato: toda regra tem as mesmas 5 peças</h2>
<div class="feynman"><div class="lbl">EXPLICANDO PARA UMA CRIANÇA</div>
<p>Uma regra de detecção é um <span class="em">bilhete para o vigia</span>. Todo bilhete bom diz 5 coisas: <span class="em">(1) ONDE olhar</span> (a porta da frente, não a casa inteira), <span class="em">(2) O QUE procurar</span> (alguém com luva e lanterna), <span class="em">(3) O QUE IGNORAR</span> (o carteiro usa luva, deixa ele passar), <span class="em">(4) QUÃO GRAVE é</span> (grite ou só anote?) e <span class="em">(5) POR QUÊ</span> (para o vigia entender e confiar).</p>
<p>Sigma, Splunk, Elastic, Wazuh, YARA... <span class="em">são só jeitos diferentes de escrever o mesmo bilhete.</span> Quando você acha as 5 peças, qualquer formato fica fácil.</p></div>
<table class="tbl"><tr><th>Peça</th><th>Pergunta</th><th>Sigma</th><th>Elastic</th><th>Splunk</th><th>Sentinel</th><th>Wazuh</th><th>YARA</th></tr>
<tr><td><strong>1. Onde</strong></td><td>Em que log/dado?</td><td><code>logsource</code></td><td><code>index</code> + <code>integration</code></td><td><code>data_source</code> + datamodel</td><td>tabela + <code>requiredDataConnectors</code></td><td><code>decoded_as</code> / <code>if_sid</code></td><td>arquivo/memória (<code>filesize</code>, <code>uint16(0)</code>)</td></tr>
<tr><td><strong>2. O quê</strong></td><td>Que padrão?</td><td><code>detection.selection</code></td><td><code>query</code></td><td><code>search</code></td><td><code>query</code> (| where)</td><td><code>match</code> / <code>regex</code> / <code>field</code></td><td><code>strings</code></td></tr>
<tr><td><strong>3. Ignorar</strong></td><td>Que ruído conhecido?</td><td><code>filter_*</code> + <code>and not</code></td><td><code>and not</code> na query</td><td>macro <code>_filter</code></td><td><code>| where not(...)</code></td><td>regra filha com <code>level="0"</code></td><td><code>and not $fp</code></td></tr>
<tr><td><strong>4. Gravidade</strong></td><td>Grite ou anote?</td><td><code>level</code></td><td><code>severity</code> + <code>risk_score</code></td><td>RBA <code>score</code></td><td><code>severity</code></td><td><code>level</code> 0-15</td><td><code>score</code> (meta)</td></tr>
<tr><td><strong>5. Por quê</strong></td><td>Contexto</td><td><code>description</code>, <code>references</code>, <code>tags</code></td><td><code>note</code>, <code>threat</code></td><td><code>analytic_story</code>, <code>how_to_implement</code></td><td><code>description</code>, <code>tactics</code></td><td><code>description</code>, <code>mitre</code></td><td><code>meta</code></td></tr></table>
<div class="note tip"><span class="ni">▸</span><div><b>Exercício mental:</b> abra qualquer regra no Arsenal e, antes de ler a lógica, localize as 5 peças. Em 30 segundos você sabe o que ela faz. Esse hábito é o que separa quem "copia regra" de quem "entende regra".</div></div>
${quizHTML('l1','Em uma regra Sigma, qual campo responde à pergunta "ONDE olhar"?',['<code>detection</code>','<code>logsource</code>','<code>level</code>','<code>tags</code>'],1,'<b>logsource</b> (product/category/service) diz de qual fonte de log a regra lê. O conversor usa isso para escolher índice/tabela no SIEM. <code>detection</code> é "o quê", <code>level</code> é "quão grave", <code>tags</code> é "por quê/ATT&CK".')}
${completeBtn('logic')}`; },

/* ---------------- 02 ---------------- */
pyramid(){ return `
<div class="eyebrow"><span class="num">LIÇÃO 02 /</span> O QUE VALE DETECTAR</div>
<h2 class="h">Regra boa dói no atacante, não só no analista</h2>
<div class="feynman"><div class="lbl">EXPLICANDO PARA UMA CRIANÇA</div>
<p>Se você reconhece o ladrão pela <span class="em">camiseta vermelha</span>, amanhã ele troca de camiseta. Se reconhece pelo <span class="em">jeito de andar</span>, ele está perdido — não dá pra trocar o jeito de andar.</p>
<p>Regra de <span class="em">hash/IP/domínio</span> = camiseta (ele troca em segundos). Regra de <span class="em">comportamento</span> ("Word abrindo PowerShell", "processo lendo a memória do LSASS") = jeito de andar. <b>Olhe o catálogo com esse olho:</b> as 19 mil regras YARA são camisetas úteis para triagem; as regras Sigma de process_creation são jeitos de andar.</p></div>
<div class="grid g3">
 <div class="card"><div class="tag r">BASE · artefatos</div><h3 class="h">YARA, IOCs, assinaturas de rede</h3><p style="font-size:13px;color:var(--ink-dim)">Precisas e rápidas, mas envelhecem. Ótimas para <b>triagem e forense</b> ("isso é o Cobalt Strike?"). Fracas para pegar o adversário de amanhã.</p></div>
 <div class="card"><div class="tag a">MEIO · ferramentas</div><h3 class="h">Nomes de processo, argumentos típicos</h3><p style="font-size:13px;color:var(--ink-dim)">"mimikatz.exe", "sekurlsa::". Pegam o preguiçoso. Quem renomeia o binário escapa — por isso combine com <b>comportamento</b> (ex.: acesso ao LSASS).</p></div>
 <div class="card"><div class="tag s">TOPO · comportamento (TTP)</div><h3 class="h">Relações e sequências</h3><p style="font-size:13px;color:var(--ink-dim)">Pai→filho proibido, N falhas → 1 sucesso, serviço web gerando shell, vssadmin delete. <b>Pega mil variantes com uma regra.</b> É onde você quer viver.</p></div>
</div>
<div class="note osint"><span class="ni">✶</span><div><b>Como ler o catálogo com isso:</b> no Arsenal, filtre por <b>category = process_creation</b> (Sigma) ou tipo <b>TTP</b> (Splunk) para ver detecções comportamentais. Filtre <b>YARA</b> quando precisar de triagem de artefato. Saber qual camada da pirâmide você está olhando evita a ilusão de "temos 44 mil regras, estamos protegidos".</div></div>
${quizHTML('l2','Qual destas regras dói mais no atacante (é mais difícil de evadir)?',['Bloquear o hash SHA256 do malware','Alertar quando o domínio evil.xyz for consultado','Alertar quando qualquer processo filho de WINWORD.EXE for um interpretador de script','Alertar quando mimikatz.exe for executado'],2,'A relação <b>Office → interpretador</b> é comportamento (TTP): não depende de hash, domínio ou nome de arquivo. O atacante teria que mudar <em>como</em> ataca. Hash e domínio são trocados em segundos; o nome mimikatz.exe é renomeado em um segundo.')}
${completeBtn('pyramid')}`; },

/* ---------------- 03 ---------------- */
anatomy(){ return `
<div class="eyebrow"><span class="num">LIÇÃO 03 /</span> ANATOMIA DA LÓGICA</div>
<h2 class="h">selection + condition: o motor por dentro</h2>
<div class="feynman"><div class="lbl">EXPLICANDO PARA UMA CRIANÇA</div>
<p>Uma <span class="em">selection</span> é uma lista de pistas: "casaco preto E lanterna". Dentro da mesma lista, as pistas precisam aparecer <span class="em">todas</span> (E). Se uma pista tem várias opções ("lanterna OU vela OU celular"), basta <span class="em">uma</span> (OU).</p>
<p>A <span class="em">condition</span> é a frase final: "<em>pistas_do_ladrão</em> E NÃO <em>pistas_do_carteiro</em>". Simples assim. Todo o resto são detalhes de como comparar cada pista (começa com? contém? é exatamente igual?).</p></div>
<h3 class="h">Dissecando um bloco Sigma real</h3>
${term('office_spawning_shell.yml (trecho)', `detection:
    selection:
        ParentImage|endswith:          # modificador: termina com
            - '\\WINWORD.EXE'           # lista = OR
            - '\\EXCEL.EXE'
            - '\\POWERPNT.EXE'
        Image|endswith:                # campo 2 = AND com o campo 1
            - '\\cmd.exe'
            - '\\powershell.exe'
            - '\\wscript.exe'
            - '\\mshta.exe'
    filter_main_legit_update:          # convenção: filter_* = exclusão
        CommandLine|contains: 'OfficeClickToRun'
    condition: selection and not 1 of filter_main_*`, 'sigma')}
<table class="tbl"><tr><th>Trecho</th><th>Lê-se como</th></tr>
<tr><td><code>ParentImage|endswith: [A, B, C]</code></td><td>pai termina com A <strong>ou</strong> B <strong>ou</strong> C</td></tr>
<tr><td>dois campos no mesmo bloco</td><td>campo1 <strong>e</strong> campo2</td></tr>
<tr><td><code>condition: selection and not 1 of filter_main_*</code></td><td>casou a seleção <strong>e não</strong> casou nenhum filtro</td></tr>
<tr><td><code>1 of selection_*</code> / <code>all of selection_*</code></td><td>pelo menos um / todos os blocos com esse prefixo</td></tr></table>
<h3 class="h">Modificadores — como comparar cada pista</h3>
<table class="tbl"><tr><th>Modificador</th><th>Significa</th><th>Uso no catálogo</th></tr>
<tr><td><code>|contains</code></td><td>contém em qualquer posição</td><td>6.917 vezes — o campeão. Use em CommandLine.</td></tr>
<tr><td><code>|endswith</code></td><td>termina com</td><td>5.304 — ideal para caminhos (<code>\\cmd.exe</code>) sem depender do diretório.</td></tr>
<tr><td><code>|startswith</code></td><td>começa com</td><td>874</td></tr>
<tr><td><code>|all</code></td><td>lista vira AND (todos os valores)</td><td>1.851 — "CommandLine contém -enc E -nop E hidden".</td></tr>
<tr><td><code>|re</code></td><td>regex</td><td>332 — poder máximo, custo máximo. Use com parcimônia.</td></tr>
<tr><td><code>|windash</code></td><td>aceita - e / e – como prefixo de flag</td><td>114 — pega <code>-enc</code>, <code>/enc</code>, <code>–enc</code> de uma vez (evasão comum!).</td></tr>
<tr><td><code>|cidr</code></td><td>IP dentro de bloco</td><td>42</td></tr>
<tr><td><code>|base64offset|contains</code></td><td>procura o texto nas 3 posições Base64 possíveis</td><td>pega payload codificado sem decodificar</td></tr></table>
<div class="note warn"><span class="ni">▸</span><div><b>Erro de iniciante nº 1:</b> usar <code>Image: 'cmd.exe'</code> (igualdade exata) — nunca casa, porque o campo traz o caminho completo <code>C:\\Windows\\System32\\cmd.exe</code>. Use <code>|endswith: '\\cmd.exe'</code> (com a barra, para não casar "notcmd.exe").</div></div>
${quizHTML('l3','Em Sigma, dois campos dentro do MESMO bloco selection são combinados com...',['OR','AND','NOT','XOR'],1,'Campos no mesmo bloco = <b>AND</b> (todos devem casar). Valores em lista dentro de um campo = OR. Para OR entre campos diferentes, você cria blocos separados (selection_a, selection_b) e usa <code>1 of selection_*</code> na condition.')}
${completeBtn('anatomy')}`; },

/* ---------------- 04 ---------------- */
correlation(){ return `
<div class="eyebrow"><span class="num">LIÇÃO 04 /</span> CORRELAÇÃO E TEMPO</div>
<h2 class="h">Um evento mente; uma sequência conta a verdade</h2>
<div class="feynman"><div class="lbl">EXPLICANDO PARA UMA CRIANÇA</div>
<p>Uma pessoa errando a senha uma vez é normal. <span class="em">Cem pessoas diferentes errando uma vez cada, do mesmo lugar, em 3 minutos</span> — isso é um ataque. O evento sozinho não diz nada; a <span class="em">contagem numa janela de tempo</span> diz tudo.</p>
<p>Cada formato tem um jeito de dizer "conte isso durante X minutos". Aprenda os 5 jeitos abaixo e você consegue escrever spraying, brute force, beaconing e lateral movement em qualquer ferramenta.</p></div>
<div class="grid g2">
<div class="card"><div class="tag">WAZUH</div><h3 class="h">frequency + timeframe + same_*</h3>${term('sshd brute force (regra 5712 real)',`<rule id="5712" level="10" frequency="8" timeframe="120" ignore="60">
  <if_matched_sid>5710</if_matched_sid>
  <same_source_ip />
  <description>sshd: brute force trying to get access to the system. Non existent user.</description>
  <mitre><id>T1110</id></mitre>
</rule>`,'wazuh')}<p style="font-size:13px;color:var(--ink-dim)">"Se a regra 5710 (falha SSH) casar <b>8 vezes em 120s</b> do <b>mesmo IP</b>, dispare nível 10 e ignore repetições por 60s."</p></div>
<div class="card"><div class="tag">ELASTIC</div><h3 class="h">type = threshold / EQL sequence</h3>${term('threshold + eql',`[rule.threshold]
field = ["source.ip"]
value = 10                 # ≥10 eventos agrupados por IP
[[rule.threshold.cardinality]]
field = "user.name"
value = 5                  # ...com ≥5 usuários DISTINTOS = spraying

# ou, em EQL, ENCADEAMENTO:
sequence by host.id with maxspan=1m
  [process where process.name == "vssadmin.exe"]
  [file where event.action == "rename" and file.extension == "locked"]`,'elastic')}</div>
<div class="card"><div class="tag">KQL (Sentinel/Defender)</div><h3 class="h">summarize ... by bin(time)</h3>${term('spraying em KQL',`SigninLogs
| where ResultType == "50126"            // senha inválida
| summarize Contas = dcount(UserPrincipalName),
            Tentativas = count()
          by IPAddress, bin(TimeGenerated, 5m)
| where Contas >= 10                      // 10 contas distintas / 5 min`,'kql-md')}</div>
<div class="card"><div class="tag">YARA-L</div><h3 class="h">match: $var over Xm</h3>${term('match window',`events:
  $e.metadata.event_type = "USER_LOGIN"
  $e.security_result.action = "BLOCK"
  $e.principal.ip = $ip
  $e.target.user.userid = $user
match:
  $ip over 10m                 // agrupa por IP em 10 min
outcome:
  $usuarios = count_distinct($user)
condition:
  $e and $usuarios > 10`,'yaral')}</div>
</div>
<div class="card" style="margin-top:14px"><div class="tag">SPLUNK</div><h3 class="h">tstats ... by _time span + where count</h3>${term('SPL',`| tstats count dc(Authentication.user) as usuarios
    from datamodel=Authentication
    where Authentication.action=failure
    by Authentication.src _time span=5m
| where usuarios >= 10`,'splunk')}</div>
<div class="note tip"><span class="ni">▸</span><div><b>Padrão universal:</b> <em>filtro → agrupa por entidade + janela → conta (ou conta distintos) → limiar</em>. Grave isso. Spraying = conta <b>distintos</b> de usuário por IP. Brute force = conta <b>eventos</b> por usuário. Beaconing = desvio padrão baixo dos intervalos. Lateral = conta hosts distintos por conta.</div></div>
${quizHTML('l4','Para detectar password SPRAYING (não brute force), o que você precisa contar?',['Falhas por usuário','Usuários DISTINTOS que falharam, por IP de origem','Sucessos por IP','Pacotes por segundo'],1,'Spraying = 1 senha × muitas contas × 1 origem. Quem conta "falhas por usuário" vê 1 falha por conta e não alerta. A contagem certa é <b>dcount(usuário) by IP</b> numa janela curta.')}
${completeBtn('correlation')}`; },

/* ---------------- 05 ---------------- */
fp(){ return `
<div class="eyebrow"><span class="num">LIÇÃO 05 /</span> FALSOS POSITIVOS</div>
<h2 class="h">Toda regra nasce barulhenta. Tuning é o trabalho de verdade</h2>
<div class="feynman"><div class="lbl">EXPLICANDO PARA UMA CRIANÇA</div>
<p>Se o alarme da casa toca toda vez que o gato passa, em uma semana você <span class="em">desliga o alarme</span> — e aí o ladrão entra de graça. Alarme que grita demais é pior que alarme nenhum, porque ensina todo mundo a ignorar.</p>
<p>Então, depois de escrever a regra, você <span class="em">ensina ela a conhecer o gato</span>: "se for o processo de atualização do Office, deixa passar". Isso é o filtro. E você anota no campo <span class="em">falsepositives</span> para o próximo analista não ter que descobrir o gato de novo.</p></div>
<table class="tbl"><tr><th>Técnica de tuning</th><th>Como fazer</th><th>Cuidado</th></tr>
<tr><td><strong>Filtro na regra</strong></td><td>bloco <code>filter_*</code> (Sigma), <code>and not</code> (KQL/EQL), regra filha level 0 (Wazuh)</td><td>Filtre pelo <em>comportamento legítimo específico</em> (caminho assinado + argumento), nunca por "contém update" genérico — o atacante usa a mesma palavra.</td></tr>
<tr><td><strong>Allowlist externa</strong></td><td>lookup/macro (<code>_filter</code> Splunk, watchlist Sentinel, lista Wazuh/Falco)</td><td>Mantenha fora da regra: muda com frequência, e a regra fica limpa.</td></tr>
<tr><td><strong>Subir o limiar</strong></td><td>ajustar frequency/threshold/value</td><td>Sobe demais e o atacante lento passa. Prefira olhar distribuição (contas distintas) a volume.</td></tr>
<tr><td><strong>Baixar o level</strong></td><td>high → medium enquanto tuna</td><td>Vários Sigma têm comentário: <code>level: low # too many false positives</code>. É honesto — e temporário.</td></tr>
<tr><td><strong>Enriquecer antes de alertar</strong></td><td>idade de domínio, reputação, assinatura do binário</td><td>Melhor FP-killer: "powershell para domínio raro criado há 2 dias" quase não erra.</td></tr></table>
<div class="note warn"><span class="ni">▸</span><div><b>Regra de ouro:</b> cada filtro que você adiciona é um <em>buraco</em> que o atacante pode usar. Documente o motivo de cada um. Filtro sem justificativa escrita é dívida técnica de segurança.</div></div>
${quizHTML('l5','Qual filtro é mais seguro para excluir o atualizador legítimo do Office de uma regra "Office → shell"?',['<code>CommandLine|contains: update</code>','<code>Image|endswith: \'\\OfficeClickToRun.exe\'</code> com <code>Image|startswith: \'C:\\Program Files\\Common Files\\Microsoft Shared\\ClickToRun\\\'</code>','<code>User: SYSTEM</code>','Desligar a regra fora do horário comercial'],1,'Filtrar pelo <b>binário específico no caminho legítimo</b> fecha o buraco. "contains update" é trivial de abusar (o atacante nomeia o payload update.exe). SYSTEM exclui ataques com privilégio. Desligar fora do horário é exatamente quando o atacante age.')}
${completeBtn('fp')}`; },

/* ---------------- 06 ---------------- */
absence(){ return `
<div class="eyebrow"><span class="num">LIÇÃO 06 /</span> DETECÇÃO PELA AUSÊNCIA</div>
<h2 class="h">Quase todo o catálogo procura o que apareceu. Aprenda a ouvir o que sumiu</h2>
<div class="feynman"><div class="lbl">EXPLICANDO PARA UMA CRIANÇA</div>
<p>Todo dia às 18h o cachorro do vizinho late quando o carteiro passa. Um dia, <span class="em">ele não late</span>. Você não ouviu nada de errado — mas a <span class="em">falta</span> do latido te conta que algo aconteceu.</p>
<p>Das 44 mil regras do Arsenal, <span class="em">quase todas</span> são "se X aparecer, grite". Mas o adversário sofisticado trabalha para <span class="em">nada aparecer</span>: desliga o Sysmon, para o agente, limpa o log. Nesses casos, <b>o silêncio é a única evidência</b>. Esta é a técnica que o catálogo quase não ensina — e que separa o analista do caçador.</p></div>
<h3 class="h">Como escrever regras de ausência</h3>
<div class="grid g2">
<div class="card"><div class="tag v">KQL</div>${term('host parou de enviar logs',`let esperado = 15m;
DeviceInfo
| summarize UltimoVisto = max(Timestamp) by DeviceName
| where UltimoVisto < ago(esperado)
| extend SilencioMin = datetime_diff('minute', now(), UltimoVisto)
| where SilencioMin < 1440   // ignora decomissionados há >1 dia`,'kql-md')}</div>
<div class="card"><div class="tag v">SPL</div>${term('fonte que calou',`| tstats latest(_time) as ultimo where index=* by host
| eval silencio_min = (now()-ultimo)/60
| where silencio_min > 30 AND silencio_min < 1440`,'splunk')}</div>
<div class="card"><div class="tag v">SIGMA (o que SEMPRE antecede o silêncio)</div>${term('desligando a telemetria — T1562.001',`title: Sysmon Driver Unload or Service Stop
logsource:
    product: windows
    category: process_creation
detection:
    selection_unload:
        Image|endswith: '\\fltmc.exe'
        CommandLine|contains|all: ['unload', 'SysmonDrv']
    selection_stop:
        CommandLine|contains|all: ['stop', 'Sysmon']
    condition: 1 of selection_*
level: high`,'sigma')}</div>
<div class="card"><div class="tag v">WAZUH</div>${term('agente desconectado',`<!-- regra nativa 506/507: agent disconnected / started -->
<rule id="100300" level="12" frequency="1" timeframe="300">
  <if_sid>506</if_sid>
  <description>Agente $(agent.name) desconectado sem evento de shutdown</description>
  <mitre><id>T1562.001</id></mitre>
</rule>`,'wazuh')}</div>
</div>
<div class="note osint"><span class="ni">✶</span><div><b>Camadas da ausência:</b> (1) <b>telemetria</b> — host/fonte calou; (2) <b>comportamento</b> — conta de serviço que agia 24/7 mudou de padrão ou parou; (3) <b>processo</b> — backup não rodou, job agendado não executou; (4) <b>rede</b> — volume de DNS/proxy caiu abruptamente. Para cada fonte que você monitora, pergunte: <em>"qual é o batimento normal dela, e quem me avisa quando o batimento para?"</em></div></div>
${quizHTML('l6','O host PREMIUM-17 enviava logs a cada 2 min há meses. Há 40 minutos, silêncio; o resto da rede está normal. A leitura de caçador é:',['Nenhum alerta disparou, então está tudo bem','Possível desativação de telemetria (T1562.001) — investigar o host agora','O host só está ocioso hoje','Problema do SIEM, abrir ticket para a infra'],1,'Ausência de batimento <b>isolada</b> (só um host, rede normal) é o padrão de quem desligou o agente antes de agir. "Nenhum alerta" é exatamente o resultado que o atacante queria produzir. Investigue — e tenha uma regra de ausência para que isso vire alerta, não sorte.')}
${completeBtn('absence')}`; },

/* ---------------- 07 ---------------- */
formats(){
  const order=['sigma','elastic','splunk','sentinel','yaral','wazuh','falco','yara','panther','kql-md'];
  return `
<div class="eyebrow"><span class="num">LIÇÃO 07 /</span> OS FORMATOS, DISSECADOS</div>
<h2 class="h">Uma regra real de cada formato, campo a campo</h2>
<p class="sub">Abra cada formato. Você vê a regra de verdade (retirada do catálogo), com <b>cada campo clicável</b> — clique num nome de campo para ler o que ele faz e por que existe. Depois, no Arsenal, qualquer regra desse formato terá o mesmo botão "Campos".</p>
${order.map(f=>formatLesson(f)).join('')}
${quizHTML('l7','Qual formato usa uma ÁRVORE de regras (if_sid) onde regras específicas só são avaliadas se a regra-pai casou?',['Sigma','Wazuh','YARA','Falco'],1,'<b>Wazuh</b>: <code>&lt;if_sid&gt;5700&lt;/if_sid&gt;</code> liga a regra ao pai. Regras genéricas (ex.: "é log do sshd") ficam no topo, e as específicas ("8 falhas do mesmo IP") embaixo. Entender a árvore é entender o Wazuh.')}
${completeBtn('formats')}`; },

/* ---------------- 08 ---------------- */
lifecycle(){ return `
<div class="eyebrow"><span class="num">LIÇÃO 08 /</span> CICLO DE VIDA</div>
<h2 class="h">Regra não é arquivo. É um produto com versão, teste e aposentadoria</h2>
<div class="feynman"><div class="lbl">EXPLICANDO PARA UMA CRIANÇA</div>
<p>Uma regra é como uma <span class="em">planta</span>: nasce de uma semente (uma ideia ou um incidente), precisa ser <span class="em">testada</span> (regou? cresceu?), vai para o jardim (<span class="em">produção</span>), precisa de <span class="em">poda</span> (tuning) e um dia <span class="em">morre</span> (a técnica saiu de uso, ou outra regra a substituiu). Regra plantada e esquecida vira mato — gera ruído e esconde as outras.</p></div>
<div class="path">
<div class="step" style="cursor:default"><div class="n">1</div><div class="t">Ideia</div><div class="d">relatório de TI, incidente, ATT&CK, purple team</div></div>
<div class="step" style="cursor:default"><div class="n">2</div><div class="t">Escrever</div><div class="d">Sigma primeiro; mapear tática/técnica; documentar FP</div></div>
<div class="step" style="cursor:default"><div class="n">3</div><div class="t">Testar</div><div class="d">Atomic Red Team / dataset de ataque; verificar que dispara E que não dispara no normal</div></div>
<div class="step" style="cursor:default"><div class="n">4</div><div class="t">Produção</div><div class="d">status: stable; versionar no Git; dono nomeado</div></div>
<div class="step" style="cursor:default"><div class="n">5</div><div class="t">Tuning</div><div class="d">medir FP/TP semanalmente; filtros justificados</div></div>
<div class="step" style="cursor:default"><div class="n">6</div><div class="t">Aposentar</div><div class="d">status: deprecated; related: obsoletes → nova regra</div></div>
</div>
<h3 class="h">Como os repositórios do catálogo fazem isso</h3>
<table class="tbl"><tr><th>Repositório</th><th>Maturidade</th><th>Teste</th><th>Versão</th></tr>
<tr><td>SigmaHQ</td><td><code>status: experimental/test/stable/deprecated</code></td><td>pasta <code>tests/</code> + regression_data</td><td><code>date</code> + <code>modified</code>, <code>related</code></td></tr>
<tr><td>Elastic</td><td><code>maturity: development/production/deprecated</code></td><td>CLI valida schema; regra deprecated fica no repo com <code>deprecation_date</code></td><td><code>updated_date</code>, pasta <code>_deprecated</code></td></tr>
<tr><td>Splunk</td><td><code>status: production/experimental/deprecated</code></td><td><code>tests:</code> com dataset de ataque real por detecção</td><td><code>version: N</code> incremental</td></tr>
<tr><td>Panther</td><td><code>Enabled</code> + <code>Status</code></td><td><code>Tests:</code> unitários com log de exemplo</td><td>Git</td></tr>
<tr><td>Wazuh</td><td>implícito pelo level</td><td><code>wazuh-logtest</code> manual</td><td>Git</td></tr></table>
<div class="note tip"><span class="ni">▸</span><div><b>Métrica que importa:</b> para cada regra em produção, você consegue dizer <em>quantas vezes disparou no último mês, quantas foram verdadeiro positivo, e quem é o dono</em>? Se não, você tem arquivos, não detecção. O Arsenal te dá o ponto de partida; o ciclo de vida é o que transforma em programa.</div></div>
${quizHTML('l8','Uma regra Sigma está marcada <code>status: experimental</code>. Isso significa:',['Está quebrada','Pode gerar ruído e ainda não foi validada em ambientes diversos — use com tuning e monitore','Detecta técnicas experimentais de ataque','Só funciona no Splunk'],1,'<b>experimental</b> é a maturidade inicial: a lógica faz sentido mas não foi batida contra ambientes variados. Aplique, meça FPs, ajuste. Depois de validar, ela vira <code>test</code> e então <code>stable</code>.')}
${completeBtn('lifecycle')}`; },
};

/* Dissecação de um formato: regra real do showcase + campos explicados */
function formatLesson(f){
  const info=FORMAT_INFO[f]; const r=V.show?.[f];
  const fields=FIELDS[f]||{};
  return `<details class="collapse"><summary><span style="font-size:18px">${info.emoji}</span> ${info.name} <span class="tag" style="margin-left:auto">${info.sources.length} fonte(s) no Arsenal</span></summary>
  <div class="in">
    <div class="grid g2" style="margin-bottom:12px">
      <div><h3 class="h" style="margin-top:0">O que é</h3><p style="font-size:13.5px;color:var(--ink-dim)">${info.what}</p>
      <h3 class="h">Quando usar</h3><p style="font-size:13.5px;color:var(--ink-dim)">${info.when}</p><p style="font-size:12px;color:var(--ink-faint);margin-top:6px;font-family:var(--mono)">motor: ${info.engine}</p></div>
      <div class="feynman" style="margin:0"><div class="lbl">PARA UMA CRIANÇA</div><p>${info.child}</p></div>
    </div>
    ${r? `<h3 class="h">Regra real: <span style="color:var(--sig)">${esc(r.title)}</span> <span class="tag v">${esc(r.source)}</span></h3>
    ${term(r.path.split('/').pop(), r.raw, f, `<button class="btn sm" onclick="copy(V.show['${f}'].raw)">copiar</button><button class="btn sm" onclick="download('${esc(r.path.split('/').pop())}', V.show['${f}'].raw)">⬇ baixar</button>`)}`:''}
    <h3 class="h">Dicionário de campos — clique para expandir</h3>
    <div class="fieldexp">${Object.entries(fields).map(([k,v])=>`<details class="fx-d"><summary class="fx" style="cursor:pointer"><code>${esc(k)}</code><span class="w"><b style="color:var(--ink)">${esc(v[0])}</b> ${v[1]?'— '+esc(v[1]):''}</span>${v[2]?`<div class="v">${esc(v[2])}</div>`:''}</summary></details>`).join('')}</div>
  </div></details>`;
}
window.renderAcademy=renderAcademy; window.LESSONS=LESSONS; window.formatLesson=formatLesson;
