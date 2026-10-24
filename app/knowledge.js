/* knowledge.js — telemetria, investigacao, pontos cegos, compatibilidade, playbooks, curadoria */
const TELEMETRY = {
 'windows/process_creation':{src:'Sysmon Event ID 1 (ProcessCreate) ou Windows Security 4688 (com auditoria de linha de comando habilitada)',
  collect:'Sysmon: instale com uma config de referencia (SwiftOnSecurity / Olaf Hartong) e colete o canal Microsoft-Windows-Sysmon/Operational. Para 4688: GPO Audit Process Creation + "Include command line in process creation events". Encaminhe por Winlogbeat / Elastic Agent / agente Wazuh / Splunk UF.',
  fields:['Image','ParentImage','CommandLine','ParentCommandLine','User','OriginalFileName','Hashes','IntegrityLevel','CurrentDirectory'],
  sample:{EventID:1,Image:'C\\Windows\\System32\\cmd.exe',ParentImage:'C\\Program Files\\Microsoft Office\\WINWORD.EXE',CommandLine:'cmd /c payload',User:'CORP\\ana',IntegrityLevel:'Medium'}},
 'windows/process_access':{src:'Sysmon Event ID 10 (ProcessAccess)',
  collect:'Sysmon com ProcessAccess habilitado (cuidado com volume; filtre por TargetImage lsass). Canal Microsoft-Windows-Sysmon/Operational.',
  fields:['SourceImage','TargetImage','GrantedAccess','CallTrace','SourceProcessId'],
  sample:{EventID:10,SourceImage:'C\\Temp\\x.exe',TargetImage:'C\\Windows\\System32\\lsass.exe',GrantedAccess:'0x1410'}},
 'windows/network_connection':{src:'Sysmon Event ID 3 (NetworkConnect)',
  collect:'Sysmon NetworkConnect (volumoso; filtre portas/processos de interesse). Alternativa: Zeek conn.log, firewall, proxy.',
  fields:['Image','DestinationIp','DestinationPort','DestinationHostname','Initiated','SourceIp'],
  sample:{EventID:3,Image:'C\\Users\\u\\AppData\\Local\\Temp\\a.exe',DestinationIp:'185.100.1.1',DestinationPort:443}},
 'windows/registry_set':{src:'Sysmon Event ID 12/13/14 (Registry)',
  collect:'Sysmon RegistryEvent. Foque chaves de autostart (Run, Services, IFEO).',
  fields:['TargetObject','Details','Image','EventType'],
  sample:{EventID:13,TargetObject:'HKCU\\...\\Run\\Updater',Details:'C\\Users\\u\\AppData\\Roaming\\svchost.exe'}},
 'windows/security':{src:'Windows Security Event Log (4624/4625/4672/4688/4698/4720...)',
  collect:'Advanced Audit Policy via GPO. Encaminhe o canal Security por WEF ou agente. Para logon, habilite Logon/Logoff e Account Logon.',
  fields:['EventID','TargetUserName','SubjectUserName','LogonType','IpAddress','WorkstationName','Status','SubStatus'],
  sample:{EventID:4625,TargetUserName:'admin',LogonType:3,IpAddress:'45.61.0.2',SubStatus:'0xC000006A'}},
 'windows/ps_script':{src:'PowerShell Operational 4104 (ScriptBlockLogging) e 4103 (ModuleLogging)',
  collect:'GPO Administrative Templates > Windows PowerShell > Turn on Script Block Logging. Colete Microsoft-Windows-PowerShell/Operational.',
  fields:['ScriptBlockText','Path','User'],
  sample:{EventID:4104,ScriptBlockText:'IEX (New-Object Net.WebClient).DownloadString(...)'}},
 'linux/process_creation':{src:'auditd (execve) ou Sysmon for Linux (Event 1)',
  collect:'auditd: regra -a exit,always -F arch=b64 -S execve. Ou Sysmon for Linux. Colete via agente (Wazuh/Elastic/Splunk).',
  fields:['exe','comm','cmdline','auid','uid','ppid','pcomm'],
  sample:{exe:'/bin/sh',pcomm:'nginx',cmdline:'/bin/sh -c whoami',euid:33}},
 'linux/network_connection':{src:'Sysmon for Linux Event 3, auditd connect, ou Zeek',
  collect:'Zeek conn.log para rede; Sysmon for Linux/auditd no host.',
  fields:['exe','DestinationIp','DestinationPort'],
  sample:{exe:'/tmp/.x',DestinationIp:'185.1.1.1',DestinationPort:4444}},
 'linux/auditd':{src:'auditd (syscalls, sudo, acesso a arquivo)',
  collect:'Configure /etc/audit/rules.d. Regras para execve, acesso a /etc/shadow, chamadas de sudo. Encaminhe audit.log.',
  fields:['type','exe','syscall','key','auid','euid'],
  sample:{type:'EXECVE',exe:'/usr/bin/find',euid:0,key:'privesc'}},
 'aws/cloudtrail':{src:'AWS CloudTrail (management + data events)',
  collect:'Habilite CloudTrail em todas as regioes, entregue no S3/CloudWatch, ingira no SIEM. Data events para S3/Lambda sob demanda.',
  fields:['eventName','eventSource','userIdentity.arn','sourceIPAddress','awsRegion','requestParameters'],
  sample:{eventName:'ConsoleLogin',eventSource:'signin.amazonaws.com',additionalEventData:{MFAUsed:'No'}}},
 'azure/signinlogs':{src:'Entra ID (Azure AD) SigninLogs / AuditLogs',
  collect:'Diagnostic settings do Entra ID exportando para Log Analytics / Event Hub. Tabela SigninLogs no Sentinel.',
  fields:['UserPrincipalName','IPAddress','ResultType','AppDisplayName','Location','ClientAppUsed'],
  sample:{UserPrincipalName:'ana@corp.com',ResultType:'50126',IPAddress:'45.61.0.2'}},
 'network':{src:'Suricata/Snort (IDS), Zeek, NetFlow',
  collect:'Sensor IDS em span/tap na borda e segmentos internos. Zeek para metadados ricos. Carregue rulesets ET Open/Talos.',
  fields:['src_ip','dest_ip','dest_port','proto','http.hostname','dns.query','tls.sni','classtype'],
  sample:{src_ip:'10.0.0.5',dest_ip:'185.1.1.1',dest_port:443,proto:'TCP'}},
 'proxy':{src:'Proxy web / Secure Web Gateway / DNS logs',
  collect:'Logs do proxy (Squid, Zscaler, etc.) e do servidor DNS. Essenciais para beaconing, C2 e tunelamento.',
  fields:['url','host','user_agent','bytes_out','bytes_in','method','status'],
  sample:{host:'cdn-update-asia.xyz',user_agent:'python-requests/2.31',bytes_out:120}},
};
function telemetryFor(r){
  const key=[r.prod,r.cat].filter(Boolean).join('/').toLowerCase();
  if(TELEMETRY[key]) return {k:key,t:TELEMETRY[key]};
  const byCat=Object.keys(TELEMETRY).find(k=>r.cat&&k.endsWith('/'+r.cat));
  if(byCat) return {k:byCat,t:TELEMETRY[byCat]};
  const byProd=Object.keys(TELEMETRY).find(k=>r.prod&&k.startsWith(r.prod+'/'))||Object.keys(TELEMETRY).find(k=>k===(r.prod||'').toLowerCase());
  if(byProd) return {k:byProd,t:TELEMETRY[byProd]};
  if(r.fmt==='suricata') return {k:'network',t:TELEMETRY['network']};
  if(r.fmt==='yara') return {k:'yara',t:{src:'Arquivos e memoria (varredura sob demanda ou continua)',collect:'Scanner YARA (yara/yara-x), ou integrado em THOR, Loki, Velociraptor, osquery, ClamAV, VirusTotal. Varra disco, dumps de memoria e artefatos coletados.',fields:['conteudo do arquivo','cabecalho PE','tamanho','entropia','imphash'],sample:null}};
  return null;
}

const INVESTIGATE = {
 'Credential Access':['Confirme o processo de origem: caminho, assinatura, hash no VirusTotal. E um binario legitimo ou mascarado?','Liste o que o processo tocou depois: conexoes de rede, arquivos .dmp criados, filhos gerados.','Verifique quais contas estavam na memoria do host no momento (quais credenciais podem ter vazado).','Isole o host se o acesso ao LSASS/credenciais for confirmado. Force reset das contas potencialmente expostas.','Cace movimento lateral subsequente: logons NTLM/Kerberos a partir deste host nas horas seguintes.'],
 'Execution':['Reconstrua a arvore de processos: quem e o pai? A relacao pai-filho e esperada?','Decodifique a linha de comando (Base64/ofuscacao) para ver o comando real.','Verifique conexoes de rede do processo e arquivos criados em %TEMP%/%APPDATA%.','Cheque persistencia criada logo apos (Run keys, tarefas, servicos).','Determine o vetor inicial: email com anexo? download? exploracao?'],
 'Persistence':['Identifique o artefato de persistencia exato (chave, tarefa, servico, cron) e o binario/comando que ele executa.','O binario e assinado e esta em caminho legitimo? Nome de sistema em pasta de usuario = mascaramento.','Quando foi criado? Correlacione com outros eventos daquele horario (o paciente zero).','Remova a persistencia e o payload. Verifique se ha outras ancoras (atacantes plantam varias).'],
 'Privilege Escalation':['Confirme a transicao de privilegio: a mesma conta passou a fazer acoes de admin/root sem o caminho normal?','Identifique a tecnica (bypass UAC, GTFOBin via sudo, token, exploit de kernel) pelos artefatos.','Verifique o que foi feito com o privilegio elevado.','Avalie se credenciais privilegiadas foram expostas no processo.'],
 'Defense Evasion':['Confirme o que foi desabilitado/limpo (AV, Sysmon, log de evento) e por qual processo/conta.','A ausencia de telemetria apos este evento e esperada? Procure o silencio subsequente.','Trate como forte indicio de atividade em andamento: evasao raramente e legitima.','Preserve a evidencia que ainda existe (RAM, outros hosts) antes que mais seja apagado.'],
 'Lateral Movement':['Mapeie origem e destino: qual conta, de qual host para qual host, por qual protocolo (SMB/WMI/RDP/SSH).','Conte hosts distintos tocados pela conta na janela: muitos em pouco tempo = anomalo.','Verifique se ha NTLM onde so deveria existir Kerberos, e acesso a shares administrativos (ADMIN$, C$).','Identifique a credencial usada e force reset. Cace a origem (onde ela foi roubada).'],
 'Command and Control':['Caracterize o canal: destino, periodicidade (beacon?), tamanho das requisicoes, user-agent.','Enriqueca o destino: idade do dominio, reputacao, presenca em feeds de C2. Dominio novo = suspeito.','Identifique o processo local que fala com o C2 e como ele foi iniciado.','Bloqueie o destino, isole o host, e procure outros hosts falando com a mesma infraestrutura.'],
 'Exfiltration':['Meca o volume de saida vs. o baseline do host/usuario. Pico contra vale de atividade = gritante.','Identifique o canal (C2, DNS tunneling, upload para nuvem) e o destino.','Determine que dados foram acessados antes da saida (o que pode ter vazado).','Acione resposta a incidente/juridico se dados sensiveis sairam. Preserve evidencias.'],
 'Impact':['Para ransomware: isole o host IMEDIATAMENTE (o precursor vssadmin/bcdedit ja indica criptografia iminente).','Identifique o processo que cria/renomeia arquivos em massa e o encerre.','Determine o escopo: quantos hosts, quais shares, ha backup limpo?','Acione o plano de resposta a ransomware. Nao reinicie (pode perder chaves em memoria).'],
 'Discovery':['Identifique o que foi enumerado (contas, grupos, shares, processos, dominio).','Correlacione com o acesso inicial: discovery costuma seguir uma invasao recente.','Verifique se a enumeracao precede movimento lateral (o atacante esta mapeando alvos).'],
 'Initial Access':['Identifique o vetor: email (anexo/link), exploracao de servico exposto, credencial valida.','Para phishing: encontre a mensagem, o remetente, outros destinatarios, e quem mais clicou.','Reconstrua o que aconteceu no host apos o acesso (execucao, persistencia).','Bloqueie o vetor (remetente/dominio/CVE) e avise os usuarios afetados.'],
 'Collection':['Identifique que dados estavam sendo reunidos e por qual processo.','Verifique se ha staging (arquivos compactados em uma pasta) preparando exfiltracao.','Correlacione com credential access anterior e exfiltration posterior.'],
 'Reconnaissance':['Normalmente externo e pre-invasao. Caracterize origem e alvos do scan.','Correlacione com tentativas de acesso subsequentes aos servicos descobertos.','Avalie exposicao: o que o atacante conseguiu enumerar da sua superficie?'],
 'Resource Development':['Geralmente fora da sua rede (o atacante monta infraestrutura). Use OSINT/TI.','Monitore dominios lookalike (Certificate Transparency) e vazamentos que mencionam voce.'],
};
function investigateFor(tactics){
  const t=(tactics&&tactics[0])||null;
  return (t&&INVESTIGATE[t]) ? {tactic:t,steps:INVESTIGATE[t]} : {tactic:null,steps:['Confirme o verdadeiro positivo cruzando com outra fonte de dados.','Reconstrua a linha do tempo: o que veio antes e depois deste evento?','Identifique as entidades envolvidas (usuario, host, IP, processo) e seu contexto.','Decida contencao proporcional ao risco e preserve evidencias.','Registre o aprendizado: vire-o em ajuste de regra ou nova deteccao.']};
}

const BLINDSPOTS = {
 sigma:'Sigma descreve a logica, mas depende da telemetria chegar normalizada. Campos ausentes = regra silenciosa. Modificadores como base64offset e correlacao (Sigma v2) nem todo backend suporta.',
 yara:'YARA ve o artefato, nao o comportamento. Packer/cripto/ofuscacao mudam os bytes e evadem. Malware fileless (so memoria) escapa de varredura em disco. Assinaturas envelhecem.',
 suricata:'IDS de rede nao ve dentro de TLS sem inspecao (JA3/SNI ajudam, mas limitado). Trafego cifrado, dominios novos e dominios legitimos abusados reduzem a eficacia. Alto volume = tuning obrigatorio.',
 wazuh:'A arvore if_sid: se a regra-pai nao casar (decoder ausente/errado), a filha nunca e avaliada. Correlacao e simples (frequency/timeframe), sem sequencias complexas.',
 elastic:'EQL/ES|QL poderosos, mas presos ao ECS: campos fora do schema quebram a regra. New_terms depende de historico suficiente.',
 splunk:'Depende de Data Models CIM populados. tstats so ve o que foi normalizado. RBA precisa de tuning de scores.',
 sentinel:'KQL depende das tabelas certas (conectores). Janela de ingestao e custo influenciam a frequencia. entityMappings ausente quebra o grafo.',
 yaral:'YARA-L ve eventos UDM: parsing incorreto esconde campos. Janelas de correlacao tem limites de performance.',
 falco:'Ve syscalls no host/container: nao ve o que acontece so em user-space sem syscall, nem trafego de rede em detalhe.',
 panther:'Python flexivel, mas so ve logs que chegam normalizados ao data lake. Latencia de ingestao afeta deteccao em tempo real.',
 'kql-md':'Hunting manual, nao e alerta: depende de alguem rodar. Boa para investigar hipotese, nao para cobertura continua.',
 aql:'Consulta de investigacao, nao regra CRE pronta. Precisa virar regra de correlacao com janela e resposta no QRadar.',
 gcp:'Depende dos logs de auditoria estarem habilitados e exportados. Cobre postura/nuvem, nao endpoint.',
 playbook:'Playbook nao detecta: responde. So e util se disparado por uma deteccao e se as integracoes/credenciais estiverem configuradas e testadas.',
};

const PLATFORM_COMPAT = {
 sigma:[['Sentinel (KQL)','adaptado','Conversivel via pySigma; campos mapeados para a tabela certa. Correlacao v2 parcial.'],['Splunk (SPL)','adaptado','Conversivel; depende de Data Model/CIM ou busca crua.'],['Elastic (EQL/KQL)','adaptado','Conversivel; EQL cobre sequencias.'],['Wazuh','parcial','Logica simples converte; modificadores avancados e correlacao exigem reescrita manual.'],['QRadar (AQL)','adaptado','pySigma-backend-QRadar-AQL gera consulta AQL; vira regra CRE com trabalho adicional.'],['Chronicle (YARA-L)','parcial','Conceito portavel; sintaxe e campos UDM diferentes.']],
 yara:[['Scanner YARA/yara-x','nativo','Formato nativo.'],['THOR/Loki','nativo','Consomem YARA diretamente.'],['Velociraptor/osquery','adaptado','Via artefatos/integracao.'],['SIEM de log','impossivel','YARA e para arquivos/memoria, nao para eventos de log.']],
 suricata:[['Suricata','nativo','Formato nativo.'],['Snort','parcial','Sintaxe proxima; nem toda keyword e compativel entre versoes.'],['Zeek','adaptado','Conceito portavel; implementacao diferente.'],['SIEM','adaptado','Via alertas IDS ingeridos como eventos.']],
 wazuh:[['Wazuh/OSSEC','nativo','Formato nativo.'],['OpenSearch Security Analytics','adaptado','Preferir Sigma como fonte.'],['Outros SIEM','parcial','Logica portavel, sintaxe XML especifica.']],
 elastic:[['Elastic Security','nativo','Formato nativo.'],['Sigma','adaptado','Pode-se converter a intencao para Sigma e dai para outros.'],['Outros','parcial','EQL/ES|QL sao especificos da Elastic.']],
 splunk:[['Splunk ES','nativo','Formato nativo.'],['Sigma','adaptado','Intencao portavel via Sigma.'],['Outros SIEM','parcial','SPL e especifico.']],
 sentinel:[['Microsoft Sentinel','nativo','Formato nativo.'],['Defender XDR','adaptado','KQL de hunting avancado compativel.'],['Outros','parcial','KQL e especifico da Microsoft.']],
 yaral:[['Google SecOps/Chronicle','nativo','Formato nativo.'],['Sigma','adaptado','Intencao portavel.'],['Outros','parcial','UDM e YARA-L sao especificos.']],
 falco:[['Falco','nativo','Formato nativo (runtime Linux/containers/K8s).'],['Outros','impossivel','Baseado em syscalls; nao portavel para SIEM de log.']],
 panther:[['Panther','nativo','Formato nativo (Python).'],['Outros','parcial','Logica Python portavel conceitualmente; API especifica.']],
 'kql-md':[['Defender XDR / Sentinel','nativo','KQL de Advanced Hunting.'],['Outros','parcial','KQL especifico.']],
 aql:[['IBM QRadar','nativo','AQL e a linguagem do QRadar.'],['Outros','impossivel','AQL e especifico do QRadar.']],
 gcp:[['Google Cloud / Chronicle','nativo','SQL/YARA-L/Log Analytics do ecossistema Google.'],['Outros','parcial','Depende de BigQuery/Cloud Logging.']],
 playbook:[['Plataforma de origem','nativo','Roda na plataforma SOAR para a qual foi escrito.'],['Outras SOAR','parcial','Logica do fluxo portavel; integracoes e sintaxe diferem.']],
};

const PLAYBOOK_TEMPLATES = [
 {id:'phishing',name:'Phishing reportado',trigger:'Usuario reporta email suspeito OU regra de deteccao de phishing dispara',
  steps:['Coletar o email (cabecalhos, remetente, URLs, anexos) e preservar.','Analisar remetente (SPF/DKIM/DMARC), reputacao do dominio, idade.','Detonar URLs/anexos em sandbox; extrair IOCs.','Buscar mensagens relacionadas na organizacao (quem mais recebeu).','Verificar quem clicou/abriu (logs de proxy/email).','Conter: remover mensagens, bloquear remetente/dominio/URL.','Para quem clicou: isolar/escanear host, resetar credenciais se houve entrada de dados.','Registrar IOCs e licoes; atualizar regras.'],
  entrada:'Email ou alerta', saida:'Veredito, lista de afetados, IOCs, mensagens removidas'},
 {id:'ioc',name:'Triagem de IOC',trigger:'Alerta com indicador (hash/IP/dominio) ou feed de TI',
  steps:['Extrair e normalizar os indicadores.','Enriquecer (VirusTotal, TI, passive DNS, idade de dominio).','Buscar ocorrencias internas (EDR, proxy, DNS, SIEM).','Priorizar por confianca e presenca interna.','Se presente internamente: escalar para investigacao de host/conta.','Bloquear onde aplicavel; registrar no caso com contexto.'],
  entrada:'Indicadores', saida:'Caso com evidencias, contexto e classificacao'},
 {id:'endpoint',name:'Endpoint suspeito',trigger:'Deteccao de EDR (ex.: Office gerando shell, acesso ao LSASS)',
  steps:['Reconstruir arvore de processos e linha de comando.','Consultar conexoes de rede, arquivos criados, persistencia.','Coletar evidencias volateis (RAM/processos) antes de qualquer acao destrutiva.','Decidir contencao: isolar host da rede.','Erradicar: remover payload e persistencia; resetar credenciais expostas.','Verificar movimento lateral a partir do host.','Documentar linha do tempo e paciente zero.'],
  entrada:'Alerta de EDR', saida:'Linha do tempo, contencao registrada, escopo'},
 {id:'account',name:'Conta comprometida',trigger:'Viagem impossivel, spraying bem-sucedido, MFA anomalo',
  steps:['Correlacionar autenticacoes (origem, dispositivo, horario).','Verificar mudancas de privilegio, registro de novo MFA, regras de inbox.','Investigar sessoes ativas e tokens emitidos.','Conter: revogar sessoes/tokens, forcar reset de senha e re-MFA.','Avaliar o que a conta acessou durante o comprometimento.','Registrar escopo e resposta auditavel.'],
  entrada:'Alerta de identidade', saida:'Escopo do comprometimento, sessoes revogadas'},
 {id:'ransomware',name:'Precursor de ransomware',trigger:'vssadmin delete / bcdedit recoveryenabled no / criptografia em massa',
  steps:['ISOLAR o host imediatamente da rede (prioridade sobre investigacao).','Identificar e encerrar o processo que apaga backups/criptografa.','Determinar escopo: hosts afetados, shares montados, backups intactos.','Preservar evidencias (nao reiniciar: chaves podem estar em memoria).','Acionar plano de resposta a ransomware e comunicacao.','Restaurar de backup limpo apos erradicacao; monitorar reincidencia.'],
  entrada:'Alerta de impacto', saida:'Contencao imediata, escopo, acionamento do plano'},
];

const CURATION = {
 imported:['Importada','Regra original da fonte, exibida sem alteracao. Metadados extraidos automaticamente.','var(--ink-faint)'],
 explained:['Explicada','Tem explicacao por campo e contexto gerados pelo guia. NAO significa validada — a explicacao e um apoio de estudo, nao uma verificacao.','var(--blue)'],
 simulated:['Simulada','Passou pela simulacao didatica no navegador (eventos positivos/negativos). Verifica a LOGICA, nao equivale a teste no mecanismo real.','var(--violet)'],
 adapted:['Adaptada por voce','Voce editou/ajustou esta regra neste navegador. Comparavel com o original.','var(--amber)'],
};
Object.assign(window,{TELEMETRY,telemetryFor,INVESTIGATE,investigateFor,BLINDSPOTS,PLATFORM_COMPAT,PLAYBOOK_TEMPLATES,CURATION});
