/* ============================================================
   OPERAÇÃO VIGIA · core.js — dados, XP, modal, utilitários, dicionários de campos
   stdlib-only no backend; aqui JS puro, sem dependências.
   ============================================================ */
const V = window.V = {
  idx:null, man:null, show:null, shards:{}, view:'home',
  state: JSON.parse(localStorage.getItem('vigia_state')||'{}'),
};
V.state.xp ??= 0; V.state.badges ??= {}; V.state.seen ??= {}; V.state.quiz ??= {}; V.state.steps ??= {}; V.state.forged ??= 0; V.state.downloads ??= 0; V.state.fav ??= {};
const save = () => localStorage.setItem('vigia_state', JSON.stringify(V.state));

/* ---------- gamificação ---------- */
const RANKS = [
  ['RECRUTA','🪖',0],['ANALISTA N1','🔍',150],['ANALISTA N2','🧭',400],['HUNTER','🏹',800],
  ['ENGENHEIRO DE DETECÇÃO','⚙️',1400],['ARQUITETO','🏛️',2200],['VIGIA SUPREMO','👁️',3200],
];
const BADGES = {
  first_rule:['🔓','Primeira Regra','Abriu a primeira regra do Arsenal'],
  polyglot:['🗣️','Poliglota','Leu regras em 5 formatos diferentes'],
  sigma_reader:['Σ','Leitor Sigma','Leu 10 regras Sigma'],
  yara_reader:['🧬','Caçador de Bytes','Leu 10 regras YARA'],
  downloader:['⬇️','Colecionador','Baixou 5 regras para ajustar'],
  forger:['⚒️','Ferreiro','Forjou sua primeira regra'],
  master_forger:['🔥','Mestre Ferreiro','Forjou 5 regras válidas'],
  academy_done:['🎓','Formado','Concluiu todas as lições da Academia'],
  quiz_perfect:['🏅','Prova de Fogo','Acertou todos os quizzes'],
  mitre_mapper:['🗺️','Cartógrafo ATT&CK','Explorou 8 táticas no mapa de cobertura'],
  night_owl:['🦉','Coruja','Estudou depois das 23h'],
  absence:['○','Detecção pela Ausência','Leu a lição sobre o silêncio como sinal'],
};
function rank(xp){ let r=RANKS[0]; for(const k of RANKS) if(xp>=k[2]) r=k; return r; }
function nextRank(xp){ for(const k of RANKS) if(xp<k[2]) return k; return null; }
function addXP(n,msg){
  const before=rank(V.state.xp)[0]; V.state.xp+=n; save(); renderXP();
  toast(`+${n} XP`, msg||'');
  const after=rank(V.state.xp)[0];
  if(after!==before) setTimeout(()=>toast('⬆ PROMOÇÃO', `Você agora é ${after}`),1400);
}
function badge(k){
  if(V.state.badges[k]) return; V.state.badges[k]=Date.now(); save();
  const b=BADGES[k]; setTimeout(()=>toast(b[0]+' CONQUISTA', b[1]+' — '+b[2]),700);
  V.state.xp+=60; save(); renderXP();
}
function renderXP(){
  const r=rank(V.state.xp), n=nextRank(V.state.xp);
  document.getElementById('xp-rank').textContent=r[1]+' '+r[0];
  document.getElementById('xp-val').textContent=V.state.xp+' XP';
  const pct = n? Math.min(100, (V.state.xp-r[2])/(n[2]-r[2])*100) : 100;
  document.getElementById('xp-fill').style.width=pct+'%';
}
let toastT; function toast(xp,msg){
  const t=document.getElementById('toast'); document.getElementById('toast-xp').textContent=xp; document.getElementById('toast-msg').textContent=msg;
  t.classList.add('on'); clearTimeout(toastT); toastT=setTimeout(()=>t.classList.remove('on'),2600);
}
if(new Date().getHours()>=23) setTimeout(()=>badge('night_owl'),4000);

/* ---------- utilitários ---------- */
const esc = s => String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const _r = r => typeof r==='string'? (document.querySelector(r)||document) : r;
const $ = (q,root=document)=>_r(root).querySelector(q);
const $$ = (q,root=document)=>[..._r(root).querySelectorAll(q)];
const el = (html)=>{const d=document.createElement('div'); d.innerHTML=html.trim(); return d.firstElementChild;};
function download(name, text, mime='text/plain'){
  const a=document.createElement('a'); a.href=URL.createObjectURL(new Blob([text],{type:mime})); a.download=name; a.click();
  setTimeout(()=>URL.revokeObjectURL(a.href),2000);
  V.state.downloads++; save(); if(V.state.downloads>=5) badge('downloader');
}
function copy(text){ navigator.clipboard?.writeText(text).then(()=>toast('✓','Copiado para a área de transferência')); }
const sevClass = s => (s||'none').toLowerCase();
const SEV_PT = {critical:'crítico',high:'alto',medium:'médio',low:'baixo',informational:'informativo','':'—'};
const FMT_PT = {sigma:'Sigma',elastic:'Elastic',splunk:'Splunk SPL',sentinel:'Sentinel KQL',yaral:'YARA-L',wazuh:'Wazuh',falco:'Falco',yara:'YARA',panther:'Panther',gcp:'GCP','kql-md':'KQL (hunting)',suricata:'Suricata/Snort',aql:'QRadar AQL',playbook:'Playbook SOAR'};
const FMT_EXT = {sigma:'yml',elastic:'toml',splunk:'yml',sentinel:'yaml',yaral:'yaral',wazuh:'xml',falco:'yaml',yara:'yar',panther:'yml',gcp:'sql','kql-md':'kql',suricata:'rules',aql:'sql',playbook:'txt'};
const TACTICS = ['Reconnaissance','Resource Development','Initial Access','Execution','Persistence','Privilege Escalation','Defense Evasion','Credential Access','Discovery','Lateral Movement','Collection','Command and Control','Exfiltration','Impact'];
const TACTIC_PT = {'Reconnaissance':'Reconhecimento','Resource Development':'Desenv. de Recursos','Initial Access':'Acesso Inicial','Execution':'Execução','Persistence':'Persistência','Privilege Escalation':'Escalação de Privilégio','Defense Evasion':'Evasão de Defesa','Credential Access':'Acesso a Credenciais','Discovery':'Descoberta','Lateral Movement':'Movimento Lateral','Collection':'Coleta','Command and Control':'Comando e Controle','Exfiltration':'Exfiltração','Impact':'Impacto'};

/* realce de sintaxe leve (genérico p/ YAML/TOML/KQL/YARA/XML) */
function hl(text, fmt){
  let s=esc(text);
  if(fmt==='wazuh'){ // xml
    s=s.replace(/(&lt;\/?)([a-z_]+)/g,'$1<span class="k">$2</span>').replace(/([a-z_]+)=(&quot;[^&]*&quot;)/g,'<span class="b">$1</span>=<span class="s">$2</span>');
    return s;
  }
  // comentários
  s=s.replace(/(^|\n)(\s*)(#[^\n]*|\/\/[^\n]*|--[^\n]*)/g,(m,a,b,c)=>a+b+'<span class="c">'+c+'</span>');
  // strings
  s=s.replace(/(&quot;(?:[^&]|&(?!quot;))*?&quot;|&#39;[^&]*?&#39;)/g,'<span class="s">$1</span>');
  // chaves yaml/toml no início da linha
  s=s.replace(/(^|\n)(\s*)([A-Za-z_][\w.\-]*)(\s*)(:|=)(?!=)/g,(m,a,b,k,sp,sep)=>a+b+'<span class="b">'+k+'</span>'+sp+sep);
  // palavras-chave
  s=s.replace(/\b(and|or|not|where|summarize|project|extend|join|let|count|by|condition|selection|filter|rule|meta|strings|events|match|outcome|from|index|search|stats|tstats|eval|table|rex|where|all of them|any of them|of|them|contains|startswith|endswith|re|windash|cidr|has|has_any|in|matches regex|ago|now|datetime|bin|dcount|make_set|arg_max|union|stats|rename|fields|lookup)\b/g,'<span class="k">$1</span>');
  // modificadores sigma
  s=s.replace(/\|(contains|endswith|startswith|all|re|windash|cidr|base64offset|base64|utf16|wide|expand|fieldref|exists|gt|lt|gte|lte|i|m|s)\b/g,'|<span class="n">$1</span>');
  // T-codes
  s=s.replace(/\b(T\d{4}(?:\.\d{3})?)\b/g,'<span class="a">$1</span>');
  return s;
}
function term(title, text, fmt, acts=''){
  return `<div class="term"><div class="term-bar"><i></i><i></i><i></i><span>${esc(title)}</span><div class="acts">${acts}</div></div><pre>${hl(text,fmt)}</pre></div>`;
}

/* ---------- modal ---------- */
function openModal(html){ $('#mbox').innerHTML=html; $('#modal').classList.add('on'); document.body.style.overflow='hidden'; }
function closeModal(){ $('#modal').classList.remove('on'); document.body.style.overflow=''; }
document.addEventListener('click',e=>{ if(e.target.id==='modal') closeModal(); });
document.addEventListener('keydown',e=>{ if(e.key==='Escape') closeModal(); });

/* ---------- quiz genérico ---------- */
function quizHTML(id, q, opts, correct, exp){
  return `<div class="quiz" data-q="${id}" ${V.state.quiz[id]?'data-done="1"':''}><div class="q"><span class="qi">QUIZ</span>${q}</div>
  ${opts.map((o,i)=>`<button class="opt" data-c="${i===correct?1:0}">${o}<span class="res"></span></button>`).join('')}
  <div class="exp">${exp}</div></div>`;
}
document.addEventListener('click',e=>{
  const o=e.target.closest('.opt'); if(!o) return;
  const qz=o.closest('.quiz'); if(qz.classList.contains('answered')) return;
  qz.classList.add('answered'); const ok=o.dataset.c==='1';
  $$('.opt',qz).forEach(x=>{ if(x.dataset.c==='1') x.classList.add('correct'); else if(x===o) x.classList.add('wrong'); });
  const id=qz.dataset.q; if(!V.state.quiz[id]){ V.state.quiz[id]=ok?1:-1; save(); if(ok) addXP(40,'Quiz correto'); else toast('✗','Veja a explicação — o conceito importa mais que o acerto'); }
  checkQuizBadge();
});
function checkQuizBadge(){ const ids=Object.keys(V.state.quiz); if(ids.length>=TOTAL_QUIZ && ids.every(k=>V.state.quiz[k]===1)) badge('quiz_perfect'); }
const TOTAL_QUIZ = 9;

/* ============================================================
   DICIONÁRIOS DE CAMPOS — o coração do "explicativo de cada campo".
   Cada formato: campo → [explicação curta (Feynman), por que importa, exemplo]
   ============================================================ */
const FIELDS = {
sigma:{
  title:['O nome da regra, em uma frase.','Aparece no alerta. Deve dizer O QUE foi detectado, não como. Ex.: "Office spawning shell".','Suspicious Microsoft Office Child Process'],
  id:['Identificador único (UUID v4).','Permite referenciar, atualizar e rastrear a regra em qualquer SIEM sem ambiguidade. Nunca reuse.','438025f9-5856-4663-83f7-52f878a70a50'],
  status:['Maturidade da regra.','experimental → test → stable (ou deprecated/unsupported). Diz quanto confiar: experimental pode gerar ruído.','test'],
  description:['O que a regra detecta e por quê.','Contexto para o analista que recebe o alerta às 3h. Explique o comportamento adversário.','Detects a suspicious process spawned by Office'],
  references:['Links que embasam a regra.','Blog de pesquisa, relatório de incidente, página ATT&CK. É a "bibliografia" da detecção.','- https://attack.mitre.org/techniques/T1566/001'],
  author:['Quem escreveu.','Crédito e ponto de contato para dúvidas sobre a lógica.','Florian Roth (Nextron Systems)'],
  date:['Data de criação (YYYY-MM-DD).','Regras velhas podem estar desatualizadas frente a técnicas novas.','2018-04-06'],
  modified:['Última modificação.','Indica manutenção ativa.','2023-02-04'],
  tags:['Rótulos padronizados.','attack.<tática> e attack.tXXXX mapeiam para MITRE ATT&CK — alimentam o mapa de cobertura. cve.XXXX e detection.<tipo> também.','- attack.execution\n- attack.t1204.002'],
  logsource:['De ONDE vem o log.','product (windows/linux/aws), category (process_creation/network_connection) e service (security/sysmon). O conversor usa isso para escolher o índice/tabela certo no seu SIEM.','product: windows\ncategory: process_creation'],
  detection:['A LÓGICA. Coração da regra.','Contém uma ou mais "seleções" (padrões a casar) e a "condition" que as combina. É o que vira a query do SIEM.','selection:\n  ParentImage|endswith: \'\\WINWORD.EXE\'\ncondition: selection'],
  'detection.selection':['Um conjunto de campo: valor.','Dentro de um bloco, campos são AND. Lista de valores em um campo é OR. Modificadores (|contains, |endswith) mudam a comparação.','Image|endswith:\n  - \'\\cmd.exe\'\n  - \'\\powershell.exe\''],
  'detection.filter':['Exclusões (falsos positivos conhecidos).','Por convenção, blocos chamados filter_* são combinados com "and not" na condition.','filter_main_known:\n  CommandLine|contains: \'update\''],
  'detection.condition':['Como combinar os blocos.','Expressão booleana: and, or, not, 1 of selection_*, all of filter_*. Ordem de leitura: selection and not filter.','selection and not 1 of filter_*'],
  fields:['Campos a mostrar no alerta.','Dica para a UI do SIEM: o que o analista precisa ver primeiro.','- CommandLine\n- ParentCommandLine'],
  falsepositives:['Onde a regra pode errar.','Documenta o ruído esperado — poupa o próximo analista de reinvestigar. "Unknown" é aceitável mas pobre.','- Legitimate macros in corporate templates'],
  level:['Severidade.','informational, low, medium, high, critical. Define a prioridade na fila do SOC. Não confunda com confiança.','high'],
  related:['Regras relacionadas.','Vínculos (derived, obsoletes, similar) para rastrear famílias de regras.','- id: 4e...\n  type: derived'],
},
elastic:{
  '[metadata]':['Bloco de metadados do repositório.','Datas, integração (que pacote Elastic Agent alimenta), maturidade (development/production/deprecated).','creation_date = "2020/02/18"\nintegration = ["endpoint"]'],
  '[rule]':['Bloco principal da regra.','Tudo que o Kibana Security precisa para criar a regra via API.',''],
  author:['Autores.','Lista; Elastic assina as oficiais.','author = ["Elastic"]'],
  description:['O que detecta.','Igual ao Sigma: comportamento adversário, não a sintaxe.',''],
  from:['Janela de lookback.','"now-9m" = olhe 9 min para trás a cada execução. Deve ser maior que interval para não perder eventos atrasados.','from = "now-9m"'],
  interval:['Frequência de execução.','A cada quanto tempo a regra roda. 5m é comum.','interval = "5m"'],
  index:['Índices consultados.','Padrões de índice (logs-endpoint.events.*). Define onde a query roda.','index = ["logs-endpoint.events.process-*"]'],
  language:['Linguagem da query.','kuery (KQL), eql (sequências de eventos!), lucene, esql. EQL permite "sequence by host.id [...] [...]" — detectar ENCADEAMENTO.','language = "eql"'],
  license:['Licença.','Elastic License v2 — leia antes de redistribuir.',''],
  name:['Nome da regra.','O que o analista vê.',''],
  note:['Guia de triagem (Markdown).','Elastic inclui investigação, FP analysis e resposta. Ouro para N1.','note = """## Triage and analysis..."""'],
  references:['Links.','',''],
  risk_score:['Pontuação 0-100.','Alimenta o risk engine (score de entidades). Severidade é categórica; risk_score é numérica.','risk_score = 73'],
  rule_id:['UUID estável.','Mesmo papel do id Sigma.',''],
  severity:['low/medium/high/critical.','',''],
  tags:['Rótulos.','Domain: Endpoint, OS: Windows, Use Case, Tactic — usados para filtrar no Kibana.','tags = ["Domain: Endpoint", "Tactic: Credential Access"]'],
  'timestamp_override':['Campo de tempo a usar.','event.ingested evita perder eventos que chegaram atrasados.','timestamp_override = "event.ingested"'],
  type:['Tipo de regra.','query, eql, threshold (contagem), machine_learning, new_terms (valor nunca visto — ótimo p/ detecção de novidade), esql.','type = "new_terms"'],
  query:['A query em si.','KQL/EQL/ES|QL.','process where event.type == "start" and process.parent.name : "WINWORD.EXE"'],
  '[[rule.threat]]':['Mapeamento ATT&CK estruturado.','framework, tactic{id,name,reference}, technique[{id,name,subtechnique}]. É daqui que vem a cobertura no Kibana.','[[rule.threat]]\nframework = "MITRE ATT&CK"\n[rule.threat.tactic]\nid = "TA0006"'],
  'threshold':['Config de regra threshold.','field + value: alerta quando N eventos agrupados por campo. Ex.: 10 falhas por user.name.','[rule.threshold]\nfield = ["user.name"]\nvalue = 10'],
  'new_terms':['Config de regra new_terms.','history_window_start define "nunca visto nos últimos X dias".','[rule.new_terms]\nfield = "new_terms_fields"\nvalue = ["host.id","process.name"]'],
  setup:['Pré-requisitos.','Que integração/auditoria precisa estar habilitada para a regra ter dados.',''],
},
splunk:{
  name:['Nome.','',''],
  id:['UUID.','',''],
  version:['Versão incremental.','Splunk versiona cada mudança de lógica.','version: 3'],
  status:['production / experimental / deprecated.','',''],
  type:['Tipo de analítica.','TTP (comportamento confirmado), Anomaly (desvio), Hunting (investigação), Correlation (junta findings), Baseline.','type: TTP'],
  description:['O que detecta.','',''],
  data_source:['Fontes de dados.','Sysmon EventID 1, Windows Security 4688... Diz o que você precisa coletar.','data_source:\n  - Sysmon EventID 1'],
  search:['A busca SPL.','Geralmente via tstats sobre um Data Model (Endpoint.Processes) — rápido e normalizado (CIM). Termina com uma macro _filter para exclusões locais.','| tstats count from datamodel=Endpoint.Processes where Processes.parent_process_name=winword.exe ...'],
  how_to_implement:['Como colocar para funcionar.','Que add-on, que data model, que campos precisam existir.',''],
  known_false_positives:['FPs conhecidos.','',''],
  references:['Links.','',''],
  drilldown_searches:['Buscas de aprofundamento.','Cliques pré-prontos para o analista pivotar do alerta aos eventos brutos.',''],
  'finding / rba':['Config de Risk-Based Alerting.','message, risk_objects (quem/onde), threat_objects (o quê), score. O RBA soma scores por entidade em vez de alertar evento a evento.','risk_objects:\n  - field: user\n    type: user\n    score: 49'],
  analytic_story:['História analítica.','Agrupa detecções por campanha/técnica (ex.: "Ransomware"). Contexto narrativo.',''],
  mitre_attack_id:['Técnicas ATT&CK.','Lista de T-codes.','mitre_attack_id:\n  - T1059.001'],
  tests:['Testes automatizados.','Dataset de ataque + resultado esperado. Detection-as-Code de verdade: se a regra quebrar, o CI avisa.',''],
  cve:['CVEs relacionadas.','',''],
},
sentinel:{
  id:['GUID.','',''],
  name:['Nome.','',''],
  description:['O que detecta.','',''],
  severity:['Informational/Low/Medium/High.','',''],
  requiredDataConnectors:['Conectores necessários.','connectorId + dataTypes: diz qual tabela (SecurityEvent, SigninLogs) precisa existir.','- connectorId: AzureActiveDirectory\n  dataTypes: [SigninLogs]'],
  queryFrequency:['A cada quanto roda.','5m, 1h, 1d. Formato ISO-ish.','queryFrequency: 1h'],
  queryPeriod:['Janela de dados.','Quanto olha para trás. Deve ser ≥ queryFrequency.','queryPeriod: 1h'],
  triggerOperator:['Operador do gatilho.','gt / lt / eq sobre a contagem de resultados.','triggerOperator: gt'],
  triggerThreshold:['Limiar.','gt 0 = qualquer resultado alerta.','triggerThreshold: 0'],
  tactics:['Táticas ATT&CK.','Nomes sem espaço: CredentialAccess, LateralMovement.',''],
  relevantTechniques:['T-codes.','',''],
  query:['A query KQL.','A lógica. Tabela | where | summarize | extend. Resultado vira o alerta.','SigninLogs\n| where ResultType != 0\n| summarize count() by IPAddress'],
  entityMappings:['Mapeamento de entidades.','Diz ao Sentinel que coluna é Account, Host, IP — habilita o grafo de investigação e UEBA.','- entityType: Account\n  fieldMappings:\n    - identifier: Name\n      columnName: UserName'],
  kind:['Tipo.','Scheduled (query agendada) ou NRT (near-real-time).',''],
  eventGroupingSettings:['Agrupamento.','SingleAlert (um alerta por execução) ou AlertPerResult.',''],
  incidentConfiguration:['Config do incidente.','Se cria incidente e como agrupa alertas semelhantes (reduz fatiga).',''],
  customDetails:['Campos extras no alerta.','Pares nome: coluna exibidos ao analista.',''],
  version:['Versão.','',''],
},
yaral:{
  'rule <nome>':['Declaração.','YARA-L 2.0 usa sintaxe parecida com YARA, mas para EVENTOS (UDM), não arquivos.','rule suspicious_powershell_download {'],
  meta:['Metadados.','author, description, severity, mitre... livres, mas severity e priority são lidos pela plataforma.',''],
  events:['Os padrões de evento.','Variáveis $e vinculam a eventos UDM. $e.metadata.event_type, $e.principal.process.command_line. Múltiplas variáveis + match = correlação.','$e.metadata.event_type = "PROCESS_LAUNCH"\n$e.target.process.file.full_path = /powershell/ nocase'],
  match:['Janela de correlação.','"$user over 10m" = agrupa eventos por usuário em 10 minutos. É o que permite "5 falhas + 1 sucesso".','match:\n  $user over 10m'],
  outcome:['Variáveis de saída.','Calcula risk_score, listas de IPs etc. para enriquecer a detecção.','outcome:\n  $risk_score = max(70)'],
  condition:['Condição final.','#e > 5 (contagem), $e1 and $e2 (coexistência).','condition:\n  $e'],
  options:['Opções.','allow_zero_values etc.',''],
},
wazuh:{
  '<group name>':['Grupo de regras.','Arquivo é organizado em <group>. O name vira tag em todos os alertas filhos (ex.: sshd, authentication_failed).','<group name="syslog,sshd,">'],
  '<rule id level>':['Declaração.','id único (100000+ para custom). level 0-15: 0 = ignora, 3 = baixo, 7+ = alerta, 12+ = alto. O level é a severidade Wazuh.','<rule id="100001" level="10">'],
  if_sid:['Pai da regra.','Esta regra só é avaliada se a regra com esse id casou antes. É a ÁRVORE do Wazuh: regras genéricas em cima, específicas embaixo.','<if_sid>5700</if_sid>'],
  if_group:['Pai por grupo.','Avalia se alguma regra do grupo casou.','<if_group>authentication_failed</if_group>'],
  if_matched_sid:['Correlação por frequência.','Combinado com frequency e timeframe: "se a regra X casou N vezes em T segundos".','<if_matched_sid>5716</if_matched_sid>'],
  frequency:['Quantas ocorrências.','Atributo da rule. frequency="8" timeframe="120" = 8 em 2 min.','<rule id="5720" level="10" frequency="8" timeframe="120">'],
  same_source_ip:['Agrupar por IP.','Para frequency: conta só eventos do MESMO IP. Também same_user, same_field.','<same_source_ip />'],
  decoded_as:['Decoder que parseou o log.','Liga a regra ao formato de log (sshd, json, windows_eventchannel).','<decoded_as>sshd</decoded_as>'],
  match:['Texto a casar (simples).','Casa substring no log (OSRegex simplificado). ^ = início.','<match>^Failed password</match>'],
  regex:['Regex completa.','OSRegex/PCRE2 (regex type="pcre2"). Mais poderosa que match.','<regex type="pcre2">Failed password for (\\S+)</regex>'],
  field:['Campo decodificado.','Compara um campo extraído pelo decoder (ex.: win.eventdata.image). Essencial para JSON/Windows.','<field name="win.system.eventID">^4625$</field>'],
  description:['Texto do alerta.','Pode usar variáveis $(srcip), $(dstuser).','<description>sshd: brute force trying to get access.</description>'],
  mitre:['Mapeamento ATT&CK.','<mitre><id>T1110</id></mitre>',''],
  group:['Tags adicionais.','authentication_failed, pci_dss_10.2.4, gdpr_IV_35.7.d — compliance embutido.',''],
  options:['Opções.','no_full_log, alert_by_email, no_email_alert.',''],
  info:['Link/explicação.','Documentação extra.',''],
},
falco:{
  '- rule':['Nome da regra.','Falco lê regras, macros e lists de YAML.','- rule: Terminal shell in container'],
  desc:['Descrição.','',''],
  condition:['Filtro de syscall.','Expressão sobre campos do evento: evt.type, proc.name, fd.name, container.id. Macros (spawned_process) e lists (shell_binaries) tornam legível.','spawned_process and container and shell_procs and proc.tty != 0'],
  output:['Mensagem do alerta.','Template com %campo. É o que chega ao SIEM.','A shell was spawned in a container (user=%user.name container=%container.id)'],
  priority:['Severidade Falco.','EMERGENCY, ALERT, CRITICAL, ERROR, WARNING, NOTICE, INFORMATIONAL, DEBUG.','priority: NOTICE'],
  tags:['Tags.','maturity_stable, container, mitre_execution, T1059 — alimentam filtros e ATT&CK.','tags: [container, shell, mitre_execution, T1059]'],
  enabled:['Liga/desliga.','',''],
  '- macro':['Macro reutilizável.','Nomeia uma condição (ex.: container = container.id != host). Regras compõem macros.','- macro: container\n  condition: (container.id != host)'],
  '- list':['Lista de valores.','shell_binaries: [bash, sh, zsh...]. Usada com "in".',''],
},
yara:{
  'rule <nome> : tags':['Declaração + tags.','Tags livres após ":" (Trojan RAT APT). Nome descreve família/comportamento. Prefixos de convenção: MAL_, APT_, SUSP_, HKTL_, VULN_.','rule MAL_CobaltStrike_Beacon : Beacon'],
  meta:['Metadados.','description, author, date, reference, hash (amostra que motivou), score (Nextron: 0-100, confiança×severidade).','score = 75\nhash1 = "a3f..."'],
  strings:['Os padrões a procurar.','$a = "texto" (ascii/wide/nocase/fullword), $b = { 4D 5A ?? ?? } (hex com wildcards), $c = /regex/. Cada string é uma "pista".','$s1 = "mimikatz" ascii wide\n$op1 = { 48 8B 05 ?? ?? ?? ?? 48 85 C0 }'],
  condition:['Lógica final.','uint16(0) == 0x5A4D (é PE?) and filesize < 2MB and 3 of ($s*). Combine cabeçalho + tamanho + N strings para precisão.','uint16(0) == 0x5a4d and filesize < 3000KB and 2 of them'],
  'modificadores':['ascii / wide / nocase / fullword / xor / base64.','wide = UTF-16 (Windows!). xor = procura versões XOR-cifradas. base64 = procura codificado.',''],
  'imports':['import "pe" / "math" / "hash".','pe.imphash(), pe.exports(), math.entropy() — condições avançadas.','import "pe"\n... pe.imphash() == "..."'],
},
panther:{
  AnalysisType:['Tipo.','rule (streaming), scheduled_rule (sobre query), policy (config de cloud), correlation_rule.',''],
  RuleID:['Identificador.','Namespace.Nome.',''],
  DisplayName:['Nome exibido.','',''],
  Enabled:['Ativa?','',''],
  Severity:['Info/Low/Medium/High/Critical.','',''],
  LogTypes:['Fontes.','AWS.CloudTrail, Okta.SystemLog, GitHub.Audit... define que eventos chegam na função.','LogTypes:\n  - AWS.CloudTrail'],
  Filename:['Arquivo Python.','A lógica vive em Python: def rule(event) -> bool. Detection-as-Code literal.','Filename: aws_console_login_without_mfa.py'],
  'rule(event)':['Função principal.','Retorna True = alerta. event.get("field") lê o log normalizado. Pode usar helpers globais.','def rule(event):\n    return event.get("eventName") == "ConsoleLogin" and not event.deep_get("additionalEventData","MFAUsed")'],
  'title(event)':['Título dinâmico.','Função que monta o título do alerta com dados do evento.',''],
  'severity(event)':['Severidade dinâmica.','Pode escalar conforme contexto (ex.: root → CRITICAL).',''],
  DedupPeriodMinutes:['Janela de deduplicação.','Alertas iguais nessa janela se agrupam.',''],
  Threshold:['Limiar.','N eventos antes de alertar.',''],
  Tests:['Testes unitários.','Log de exemplo + ExpectedResult. Roda em CI.','Tests:\n  - Name: Login sem MFA\n    ExpectedResult: true\n    Log: {...}'],
  Runbook:['O que fazer.','Passos de resposta embutidos.',''],
  Reports:['ATT&CK.','MITRE ATT&CK: [TA0001:T1078].',''],
},
'kql-md':{
  'Tabela':['Fonte de dados.','DeviceProcessEvents, DeviceNetworkEvents, SigninLogs, SecurityEvent... Cada tabela = um tipo de telemetria.','DeviceProcessEvents'],
  '| where':['Filtro.','Reduz linhas. Operadores: ==, =~ (case-insens), has, contains, startswith, matches regex, in.','| where FileName =~ "certutil.exe" and ProcessCommandLine has "urlcache"'],
  '| summarize':['Agregação.','count(), dcount(), make_set() by campos. É como você conta "contas distintas por IP" (spraying!).','| summarize Alvos=dcount(AccountName) by IPAddress, bin(TimeGenerated, 5m)'],
  '| extend':['Nova coluna.','Calcula campos derivados (parse, extract, tolower).',''],
  '| project':['Seleciona colunas.','Deixa só o que o analista precisa.',''],
  '| join':['Junta tabelas.','kind=inner/leftouter on chave. Correlaciona processo com rede, login com dispositivo.',''],
  'let':['Variável.','let timeframe = 1h; reutiliza valores e sub-queries.',''],
  'ago()/bin()':['Tempo.','ago(1h) = última hora. bin(T, 5m) agrupa em janelas.',''],
},
gcp:{
  'SQL/SQLX':['Consulta sobre logs exportados.','Cloud Logging → BigQuery; a query procura padrões de auditoria (IAM, Storage, VPC).',''],
  'YARA-L':['Regras Chronicle para GCP.','Mesma sintaxe YARA-L sobre eventos UDM do Google Cloud.',''],
  'config.yaml':['Config Log Analytics.','Query + metadados para o Cloud Logging Log Analytics.',''],
},
};
/* Resumo Feynman de cada formato */
const FORMAT_INFO = {
sigma:{name:'Sigma',emoji:'Σ',what:'O "idioma universal" das regras de log. YAML genérico que um conversor traduz para Splunk, Elastic, Sentinel, QRadar...',
 child:'Imagine uma receita de bolo escrita numa língua que um tradutor mágico converte para a língua de qualquer cozinheiro. Você escreve a receita UMA vez; todo mundo consegue fazer o bolo.',
 when:'Quando você quer compartilhar lógica de detecção independente de ferramenta. É o ponto de partida de 80% da engenharia de detecção moderna.',
 engine:'Conversor: sigma-cli (pySigma) + backend do seu SIEM.', sources:['SigmaHQ','Hayabusa (native)','OpenSearch Security Analytics']},
elastic:{name:'Elastic detection-rules',emoji:'🔶',what:'TOML com query KQL/EQL/ES|QL + metadados ricos (triagem, ATT&CK estruturado, risk score). EQL permite sequências de eventos.',
 child:'É a receita Sigma, mas já traduzida para a cozinha Elastic — e com um manual de "o que fazer se o bolo queimar" (o campo note) grudado atrás.',
 when:'Elastic Security / Kibana. Melhor referência pública de como documentar triagem junto com a regra.',engine:'Kibana Detection Engine; repo tem CLI de validação.',sources:['Elastic detection-rules']},
splunk:{name:'Splunk Security Content',emoji:'🟢',what:'YAML com busca SPL (normalmente tstats em Data Models CIM), testes com dataset de ataque, e config de Risk-Based Alerting.',
 child:'Receita Splunk que vem com um "degustador automático": toda regra traz um log de ataque real para provar que ela dispara.',
 when:'Splunk ES. Estude as analytic stories e o RBA — ideia de somar risco por entidade em vez de alertar por evento.',engine:'Splunk + contentctl (build/test).',sources:['Splunk security_content']},
sentinel:{name:'Microsoft Sentinel',emoji:'🟦',what:'YAML com query KQL, agenda (frequency/period), gatilho (operator/threshold), entidades mapeadas e conectores necessários.',
 child:'Receita Microsoft: além do que procurar, diz DE QUANTO EM QUANTO TEMPO olhar e QUEM é quem no resultado (esse campo é a pessoa, esse é o computador).',
 when:'Sentinel / Defender XDR. KQL é a linguagem de hunting mais usada em ambientes Microsoft.',engine:'Sentinel Analytics; Hunting Queries são KQL sem agenda.',sources:['Microsoft Sentinel (Analytic Rules)','Microsoft Sentinel (Hunting Queries)','Bert-JanP Hunting Queries','FalconFriday (FalconForce)']},
yaral:{name:'YARA-L 2.0 (Google SecOps)',emoji:'🔷',what:'Sintaxe estilo YARA aplicada a EVENTOS normalizados (UDM). Seções events / match / outcome / condition permitem correlação em janela de tempo.',
 child:'Parece YARA (que caça arquivos), mas caça ACONTECIMENTOS: "se o mesmo usuário fizer X e depois Y em 10 minutos".',
 when:'Google SecOps / Chronicle. Ótimo para aprender correlação multi-evento.',engine:'Chronicle Detection Engine.',sources:['Google SecOps / Chronicle','GCP security-analytics']},
wazuh:{name:'Wazuh',emoji:'🛡️',what:'XML em ÁRVORE: regras genéricas (if_sid) alimentam regras específicas; frequency+timeframe fazem correlação simples; level 0-15 é a severidade.',
 child:'Uma árvore de perguntas: "é log do SSH?" → "é falha de senha?" → "foram 8 falhas do mesmo IP em 2 min?" Cada galho é uma regra que só é olhada se o galho de cima casou.',
 when:'Wazuh / OSSEC. Comum em MSSPs e ambientes com orçamento limitado. Entenda a árvore e você entende tudo.',engine:'wazuh-analysisd; teste com wazuh-logtest.',sources:['Wazuh ruleset (oficial)','SOCFortress Wazuh-Rules']},
falco:{name:'Falco',emoji:'🦅',what:'Regras sobre SYSCALLS em Linux/containers/Kubernetes. Macros e lists compõem condições legíveis; output é o template do alerta.',
 child:'Um vigia dentro do motor do carro, não na rua: vê cada peça se mexendo (cada chamada ao kernel) e grita quando uma peça faz algo que não deveria.',
 when:'Runtime security de containers/K8s/cloud-native.',engine:'Falco (eBPF/kernel module).',sources:['Falco rules']},
yara:{name:'YARA',emoji:'🧬',what:'Padrões em ARQUIVOS e MEMÓRIA: strings, bytes hex com wildcards, regex, + condição (cabeçalho PE, tamanho, N de M strings).',
 child:'Um "procura-palavras" para arquivos: você diz quais frases e quais sequências de bytes aparecem no malware; se achar 3 delas num arquivo pequeno que começa com MZ, achou.',
 when:'Triagem de malware, DFIR, hunting em disco/memória (Thor, Loki, Velociraptor). Base da pirâmide (artefatos), mas indispensável.',engine:'yara / yara-x; THOR, Loki, VirusTotal Hunting.',sources:['Neo23x0 signature-base','Yara-Rules community','ReversingLabs YARA']},
panther:{name:'Panther (Detection-as-Code)',emoji:'🐍',what:'YAML de metadados + função Python rule(event). Testes unitários embutidos. Logs normalizados de SaaS/cloud.',
 child:'A regra é um programinha de verdade: "se o evento for login no console E não usou MFA, grite". E já vem com a prova (teste) de que funciona.',
 when:'Quando sua equipe programa. Modelo mental de Detection-as-Code mais puro do catálogo.',engine:'Panther; panther_analysis_tool para testar localmente.',sources:['Panther panther-analysis']},
'kql-md':{name:'KQL de Hunting (Markdown)',emoji:'🔎',what:'Queries KQL soltas, documentadas em Markdown, sem agenda — para threat hunting manual no Defender/Sentinel.',
 child:'Perguntas prontas para fazer ao banco de dados quando você está caçando ativamente, em vez de esperar o alarme tocar.',
 when:'Hunting proativo; base para criar regras agendadas depois.',engine:'Advanced Hunting (Defender XDR) / Log Analytics.',sources:['Bert-JanP Hunting Queries','FalconFriday (FalconForce)']},
gcp:{name:'GCP Security Analytics',emoji:'☁️',what:'Consultas SQL (BigQuery/Dataform), YAML (Log Analytics) e YARA-L para auditoria e ameaças no Google Cloud.',
 child:'Perguntas prontas para os registros de auditoria da nuvem: "alguém abriu um bucket para o mundo?", "criaram uma chave de serviço nova?".',
 when:'Postura e detecção em GCP.',engine:'BigQuery / Cloud Logging / Chronicle.',sources:['GCP security-analytics']},
};
window.FIELDS=FIELDS; window.FORMAT_INFO=FORMAT_INFO; window.RANKS=RANKS; window.BADGES=BADGES;
Object.assign(window,{esc,$,$$,el,download,copy,sevClass,SEV_PT,FMT_PT,FMT_EXT,TACTICS,TACTIC_PT,hl,term,openModal,closeModal,quizHTML,addXP,badge,rank,nextRank,renderXP,toast,save});
