# Rancor (G0075) — Dossiê de inteligência

> **TLP:CLEAR** · gerado em 2026-10-26 a partir de fontes abertas · MITRE ATT&CK v20.0 · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0075) · [ATT&CK](https://attack.mitre.org/groups/G0075/)

**Também conhecido como:** —  
**Origem atribuída:** China · **Motivação:** espionagem · **Setores-alvo:** Sociedade civil e mídia, Governo  
**Registro no ATT&CK:** criado em 2018-10-17, atualizado em 2026-07-31 · referências de 2018 a 2019

## 1. Sumário executivo

- **9 técnicas** atribuídas publicamente, concentradas em **Execution, Persistence, Privilege Escalation**.
- **Arsenal:** 2 malware e 2 ferramentas (ex.: PLAINTEE, DDKONG, certutil, Reg).
- **Campanhas atribuídas:** 0.
- **Cobertura de detecção pública:** 100% das técnicas têm ao menos uma regra no catálogo; **0 técnicas sem nenhuma regra pública**.
- **Origem e alvos (APT4ALL):** atribuído a **China**, motivação espionagem; setores Sociedade civil e mídia, Governo; 2 países vítimas citados.
- **Onde a cobertura está:** Windows (9 técnicas com regra), EDR / XDR (9 técnicas com regra), Servidores web & aplicações (9 técnicas com regra), Linux (8 técnicas com regra).
- **Assinatura comportamental** (técnicas raras entre os 178 grupos, as mais úteis para atribuição): T1218.007 Msiexec, T1546.003 Windows Management Instrumentation Event Subscription, T1059.005 Visual Basic, T1053.005 Scheduled Task, T1071.001 Web Protocols.

## 2. Quem é

> Rancor is a threat group that has led targeted campaigns against the South East Asia region. Rancor uses politically-motivated lures to entice victims to open malicious documents.

_Texto original do MITRE ATT&CK, em inglês._

## 3. Contexto, nomes e alvos

Consolidado pelo [APT4ALL](https://github.com/Ridd1kulusC0d3r/apt4all) a partir de MISP Galaxy, planilha APT Groups & Operations, EternalLiberty e APTnotes. Atribuição é afirmação de quem publicou; confira a fonte.

| Campo | Valor |
|---|---|
| Origem atribuída | China |
| Motivação | espionagem |
| Setores-alvo | Sociedade civil e mídia, Governo |
| Vítimas citadas | Cambodia, Singapore |
| Alvos (planilha) | South-East Asia |
| Operações conhecidas | — |
| Confiança de atribuição (MISP) | 50 |

**Como cada fornecedor chama este grupo** (útil para cruzar relatórios):

| Fornecedor | Nome(s) |
|---|---|
| MITRE ATT&CK | G0075 |

**Outros nomes no APT4ALL (não listados pelo ATT&CK):** Rancor group, Rancor Taurus

## 4. Perfil TTP por tática (kill chain)

Cada linha: técnica, como o grupo a usou segundo relatos públicos, e o que existe para detectar e testar.

### Initial Access (TA0001) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1566.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1566.001) Spearphishing Attachment | Rancor has attached a malicious document to an email to gain initial access. | 230 | 2 | — |

### Execution (TA0002) — 4

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1053.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1053.005) Scheduled Task | Rancor launched a scheduled task to gain persistence using the schtasks /create /sc command. | 248 | 14 | 11 |
| [T1059.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.003) Windows Command Shell | Rancor has used cmd.exe to execute commmands. | 269 | 6 | 1 |
| [T1059.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.005) Visual Basic | Rancor has used VBS scripts as well as embedded macros for execution. | 192 | 3 | — |
| [T1204.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1204.002) Malicious File | Rancor attempted to get users to click on an embedded macro within a Microsoft Office Excel document to launch their malware. | 259 | 13 | — |

### Persistence (TA0003) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1053.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1053.005) Scheduled Task | Rancor launched a scheduled task to gain persistence using the schtasks /create /sc command. | 248 | 14 | 11 |
| [T1546.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1546.003) Windows Management Instrumentation Event Subscription | Rancor has complied VBScript-generated MOF files into WMI event subscriptions for persistence. | 99 | 4 | — |

### Privilege Escalation (TA0004) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1053.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1053.005) Scheduled Task | Rancor launched a scheduled task to gain persistence using the schtasks /create /sc command. | 248 | 14 | 11 |
| [T1546.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1546.003) Windows Management Instrumentation Event Subscription | Rancor has complied VBScript-generated MOF files into WMI event subscriptions for persistence. | 99 | 4 | — |

### Stealth (TA0005) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1218.007](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1218.007) Msiexec | Rancor has used msiexec to download and execute malicious installer files over HTTP. | 85 | 11 | — |

### Command and Control (TA0011) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1071.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1071.001) Web Protocols | Rancor has used HTTP for C2. | 228 | 3 | — |
| [T1105](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1105) Ingress Tool Transfer | Rancor has downloaded additional malware, including by using certutil. | 644 | 39 | — |

## 5. Assinatura comportamental

Técnicas que este grupo usa e que poucos dos 178 grupos do ATT&CK usam. Pesam mais numa atribuição por TTP: ver várias delas juntas é mais informativo do que ver técnicas comuns como PowerShell.

| Técnica | Outros grupos que usam | Peso (raridade) |
|---|---:|---:|
| T1218.007 Msiexec | 5 | 3.24 |
| T1546.003 Windows Management Instrumentation Event Subscription | 9 | 2.79 |
| T1059.005 Visual Basic | 45 | 1.34 |
| T1053.005 Scheduled Task | 54 | 1.16 |
| T1071.001 Web Protocols | 57 | 1.11 |
| T1059.003 Windows Command Shell | 72 | 0.88 |
| T1566.001 Spearphishing Attachment | 78 | 0.81 |
| T1204.002 Malicious File | 86 | 0.71 |
| T1105 Ingress Tool Transfer | 89 | 0.68 |

## 6. Arsenal

| Software | Tipo | Técnicas no ATT&CK | Uso relatado (EN) |
|---|---|---:|---|
| [PLAINTEE](https://attack.mitre.org/software/S0254/) | malware | 9 |  |
| [DDKONG](https://attack.mitre.org/software/S0255/) | malware | 4 |  |
| [certutil](https://attack.mitre.org/software/S0160/) | ferramenta | 4 |  |
| [Reg](https://attack.mitre.org/software/S0075/) | ferramenta | 3 |  |

**Outras ferramentas e malware relatados (planilha APT Groups & Operations / MISP):** KHRAT Trojan, Derusbi, Dudell, DDKONG Plugin

## 7. Campanhas

Nenhuma campanha atribuída no ATT&CK.

## 8. Cobertura defensiva

**9 de 9 técnicas (100%)** têm ao menos uma regra pública no catálogo Detection Rules.

### Onde procurar — cobertura por tecnologia

Quantas técnicas deste grupo têm ao menos uma regra em cada tecnologia. Comece a caça pelas tecnologias que você tem e que aparecem aqui.

| Tecnologia | Técnicas do grupo com regra |
|---|---:|
| Windows | 9 |
| EDR / XDR | 9 |
| Servidores web & aplicações | 9 |
| Linux | 8 |
| Proxy / SWG | 8 |
| macOS | 7 |
| VPN & acesso remoto | 7 |
| E-mail | 7 |
| Microsoft 365 | 7 |
| Outros / genérico | 6 |
| IoT & embarcados | 6 |
| IA, LLMs & agentes | 6 |

### Regras recomendadas por técnica

Melhor regra disponível por técnica (formato portável e maduro primeiro).

| Técnica | Regra | Formato | Fonte |
|---|---|---|---|
| T1053.005 | [Operation Wocao Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1cfac73c-be78-4f9a-9b08-5bde0c3953ab) | Sigma | SigmaHQ |
| T1053.005 | [Operation Wocao Activity - Security](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A74ad4314-482e-4c3e-b237-3f7ed3b9ca8d) | Sigma | SigmaHQ |
| T1059.003 | [HackTool - CrackMapExec Execution Patterns](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A058f4380-962d-40a5-afce-50207d36d7e2) | Sigma | SigmaHQ |
| T1059.003 | [CrackMapExec Command Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A058f4380-962d-40a5-afce-50207d36d7e2) | Sigma | OpenSearch Security Analytics |
| T1059.005 | [Potential QBot Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4fcac6eb-0287-4090-8eea-2602e4c20040) | Sigma | SigmaHQ |
| T1059.005 | [QBot Process Creation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A4fcac6eb-0287-4090-8eea-2602e4c20040) | Sigma | OpenSearch Security Analytics |
| T1071.001 | [Ursnif Malware Download URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aa36ce77e-30db-4ea0-8795-644d7af5dfb4) | Sigma | SigmaHQ |
| T1071.001 | [Ursnif Malware C2 URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A932ac737-33ca-4afd-9869-0d48b391fcc9) | Sigma | SigmaHQ |
| T1105 | [Greenbug Espionage Group Indicators](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A3711eee4-a808-4849-8a14-faf733da3612) | Sigma | SigmaHQ |
| T1105 | [Pandemic Registry Key](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A47e0852a-cf81-4494-a8e6-31864f8c86ed) | Sigma | SigmaHQ |
| T1204.002 | [Ursnif Malware C2 URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A932ac737-33ca-4afd-9869-0d48b391fcc9) | Sigma | SigmaHQ |
| T1204.002 | [Droppers Exploiting CVE-2017-11882](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A678eb5f4-8597-4be6-8be7-905e4234b53a) | Sigma | SigmaHQ |
| T1218.007 | [Potential Remote Install via MsiExec](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ac9847fe9-3bed-4e6b-b319-f9956d6dd02a) | Elastic | Elastic detection-rules |
| T1218.007 | [Potential Escalation via Vulnerable MSI Repair](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A043d80a3-c49e-43ef-9c72-1088f0c7b278) | Elastic | Elastic detection-rules |
| T1546.003 | [WMI Persistence - Script Event Consumer File Write](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A33f41cdd-35ac-4ba8-814b-c6a4244a1ad4) | Sigma | SigmaHQ |
| T1546.003 | [NewActiveScriptEventConsumer Creation Attempt via Wmic.EXE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aebef4391-1a81-4761-a40a-1db446c0e625) | Sigma | SigmaHQ |
| T1566.001 | [Ursnif Malware C2 URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A932ac737-33ca-4afd-9869-0d48b391fcc9) | Sigma | SigmaHQ |
| T1566.001 | [Droppers Exploiting CVE-2017-11882](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A678eb5f4-8597-4be6-8be7-905e4234b53a) | Sigma | SigmaHQ |

## 9. Plano de emulação e validação

Use num laboratório isolado e autorizado para confirmar que as regras disparam. Os comandos estão nos repositórios oficiais.

| Tática | Técnica | Teste Atomic Red Team | Plataformas |
|---|---|---|---|
| Initial Access | [T1566.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1566.001/T1566.001.md) | Download Macro-Enabled Phishing Attachment | windows |
| Initial Access | [T1566.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1566.001/T1566.001.md) | Word spawned a command shell and used an IP address in the command line | windows |
| Execution | [T1053.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1053.005/T1053.005.md) | Scheduled Task Startup Script | windows |
| Execution | [T1053.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1053.005/T1053.005.md) | Scheduled task Local | windows |
| Execution | [T1059.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.003/T1059.003.md) | Create and Execute Batch Script | windows |
| Execution | [T1059.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.003/T1059.003.md) | Writes text to a file and displays it. | windows |
| Execution | [T1059.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.005/T1059.005.md) | Visual Basic script execution to gather local computer information | windows |
| Execution | [T1059.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.005/T1059.005.md) | Encoded VBS code execution | windows |
| Execution | [T1204.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1204.002/T1204.002.md) | OSTap Style Macro Execution | windows |
| Execution | [T1204.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1204.002/T1204.002.md) | OSTap Payload Download | windows |
| Privilege Escalation | [T1546.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1546.003/T1546.003.md) | Persistence via WMI Event Subscription - CommandLineEventConsumer | windows |
| Privilege Escalation | [T1546.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1546.003/T1546.003.md) | Persistence via WMI Event Subscription - ActiveScriptEventConsumer | windows |
| Stealth | [T1218.007](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.007/T1218.007.md) | Msiexec.exe - Execute Local MSI file with embedded JScript | windows |
| Stealth | [T1218.007](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.007/T1218.007.md) | Msiexec.exe - Execute Local MSI file with embedded VBScript | windows |
| Command and Control | [T1071.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1071.001/T1071.001.md) | Malicious User Agents - Powershell | windows |
| Command and Control | [T1071.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1071.001/T1071.001.md) | Malicious User Agents - CMD | windows |
| Command and Control | [T1105](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1105/T1105.md) | rsync remote file copy (push) | linux, macos |
| Command and Control | [T1105](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1105/T1105.md) | rsync remote file copy (pull) | linux, macos |

**Logs reais de ataque (EVTX) para testar sem executar nada:**

- T1053.005 — [ID4688-4698 Persistent scheduled task with SYSTEM privileges creation](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1053.005-Scheduled%20Task/ID4688-4698%20Persistent%20scheduled%20task%20with%20SYSTEM%20privileges%20creation.evtx) _(explícito)_
- T1053.005 — [ID4688-Interactive shell using AT schedule task](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1053.005-Scheduled%20Task/ID4688-Interactive%20shell%20using%20AT%20schedule%20task.evtx) _(explícito)_
- T1059.003 — [ID4688-SQL Server payload injectection for reverse shell (MSF)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1059.003-Windows%20Command%20Shell/ID4688-SQL%20Server%20payload%20injectection%20for%20reverse%20shell%20%28MSF%29.evtx) _(explícito)_

## 10. Hipóteses de hunting

Se Rancor estiver no seu ambiente, estas são as perguntas a fazer aos seus dados (fontes de log segundo as estratégias de detecção do MITRE ATT&CK).

1. **T1218.007 Msiexec** — Detection of msiexec.exe execution where command-line arguments reference remote MSI packages, UNC paths, HTTP/HTTPS URLs, or DLLs, correlated with subsequent module loads and/or network connections to previously unseen destinations. The behavioral chain… Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=7), `WinEventLog:Sysmon` (EventCode=3, 22).
2. **T1546.003 Windows Management Instrumentation Event Subscription** — Monitor for creation of WMI EventFilter, EventConsumer, and FilterToConsumerBinding objects through WMI or MOF file execution. Detect command-line execution of `mofcomp.exe`, usage of `Register-WmiEvent` via PowerShell, and anomalous child processes of… Dados: `WinEventLog:WMI` (EventCode=5857, 5858, 5860, 5861), `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=7).
3. **T1059.005 Visual Basic** — Detects execution of VB-based scripts or macros (VBS/VBA/VBScript) through cscript.exe/wscript.exe, Office-based process chains, or HTA usage. Focuses on chained behavior: Office or HTML container spawns script host > script host spawns PowerShell, network… Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=7).
4. **T1053.005 Scheduled Task** — Detects the creation, modification, or deletion of scheduled tasks through Task Scheduler, WMI, PowerShell, or API-based methods followed by execution from svchost.exe or taskeng.exe. Includes detection of hidden or anomalous scheduled tasks, especially those… Dados: `WinEventLog:Security` (EventCode=4698), `WinEventLog:Security` (EventCode=4702), `WinEventLog:Sysmon` (EventCode=1).
5. **T1071.001 Web Protocols** — Detects unexpected or high-volume HTTP/S/WebSocket communication from suspicious processes (e.g., PowerShell, rundll32) using uncommon user agents or mimicking browser traffic to unusual domains or IPs. Dados: `NSM:Flow` (http.log, ssl.log), `WinEventLog:Sysmon` (EventCode=3, 22).
6. **T1059.003 Windows Command Shell** — Detects interactive or scripted abuse of cmd.exe, batch files, or shell invocation chains. Focuses on parent-child relationships (e.g., cmd.exe launched from unusual parents), anomalous command-line parameters, and chaining with discovery, credential access,… Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=7), `EDR:scriptblock` (Process Tree + Script Block Logging).
7. **T1566.001 Spearphishing Attachment** — Detection of spearphishing attachments by correlating suspicious email delivery with subsequent file creation and abnormal process execution (e.g., Office spawning PowerShell or CMD). Behavior chain includes inbound email metadata → attachment stored on disk… Dados: `m365:unified` (Send/Receive: Inbound emails with attachments from suspicious or spoofed senders), `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Sysmon` (EventCode=1).
8. **T1204.002 Malicious File** — User opens a file delivered by email, web, chat, or share. The handler application (Word/PDF reader/archiver) creates a file in user-controlled paths (Downloads, Temp, Desktop) and then spawns a new or unusual child process (e.g., powershell.exe, wscript.exe,… Dados: `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=15).
9. **T1105 Ingress Tool Transfer** — Unusual or uncommon processes initiate network connections to external destinations followed by file creation (tools downloaded). Dados: `WinEventLog:Sysmon` (EventCode=3, 22), `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Sysmon` (EventCode=1).

## 11. OSINT — onde pesquisar

Consultas prontas com todos os nomes conhecidos do grupo:

- Relatórios técnicos: [busca web](https://duckduckgo.com/?q=%28%22Rancor%22%29+threat+report) · [PDFs](https://duckduckgo.com/?q=%28%22Rancor%22%29+filetype%3Apdf)
- Regras e IOCs publicados: [GitHub](https://github.com/search?type=code&q=%22Rancor%22)
- Pulsos de ameaça: [AlienVault OTX](https://otx.alienvault.com/browse/global/pulses?q=Rancor)
- Família de malware e atores: [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/actors) (busque por Rancor)
- Cartões de grupo: [ThaiCERT Threat Group Cards](https://apt.etda.or.th/cgi-bin/listgroups.cgi)
- Página oficial: [MITRE ATT&CK G0075](https://attack.mitre.org/groups/G0075/)

**Relatórios na coleção CyberMonitor** (ligados pelo nome do grupo, conferir antes de citar):

- 2018 — [rancor-targeted-attacks-south-east-asia-using-plaintee-ddkong-malware-families_](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2018/2018.06.26.RANCOR/rancor-targeted-attacks-south-east-asia-using-plaintee-ddkong-malware-families_.pdf) _(via “Rancor”)_
- 2019 — [RANCOR APT_ Suspected targeted attacks against South East Asia](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2019/2019.09.11.RANCOR_APT/RANCOR%20APT_%20Suspected%20targeted%20attacks%20against%20South%20East%20Asia.pdf) _(via “Rancor”)_
- 2019 — [Rancor_ Cyber Espionage Group Uses New Custom Malware to Attack Southeast Asia](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2019/2019.12.17.Rancor/Rancor_%20Cyber%20Espionage%20Group%20Uses%20New%20Custom%20Malware%20to%20Attack%20Southeast%20Asia.pdf) _(via “Rancor”)_

## 12. Bibliografia (2 fontes citadas pelo ATT&CK)

- [Rancor Unit42 June 2018](https://researchcenter.paloaltonetworks.com/2018/06/unit42-rancor-targeted-attacks-south-east-asia-using-plaintee-ddkong-malware-families/) — Ash, B., et al. (2018, June 26). RANCOR: Targeted Attacks in South East Asia Using PLAINTEE and DDKONG Malware Families. Retrieved July 2, 2018.
- [Rancor WMI](https://unit42.paloaltonetworks.com/rancor-cyber-espionage-group-uses-new-custom-malware-to-attack-southeast-asia/) — Jen Miller-Osborn and Mike Harbison. (2019, December 17). Rancor: Cyber Espionage Group Uses New Custom Malware to Attack Southeast Asia. Retrieved February 9, 2024.

## 13. Limites e confiança

- O ATT&CK registra o que foi **relatado publicamente**, não tudo o que o grupo faz. Ausência de uma técnica não prova que o grupo não a usa.
- **Sobreposição de TTP não é atribuição.** Muitas técnicas são compartilhadas entre grupos e com red teams. Use a assinatura comportamental como hipótese, junto com infraestrutura, malware e contexto.
- Cobertura de detecção refere-se ao catálogo público Detection Rules, não ao seu ambiente: confira se a telemetria necessária chega ao seu SIEM.
- Ligações marcadas como _inferidas_ (EVTX por palavra-chave, relatórios por nome) devem ser verificadas.

---
Fontes: MITRE ATT&CK® (uso livre com atribuição, © The MITRE Corporation), APT4ALL (MISP Galaxy CC0/BSD-2, APT Groups & Operations CC BY 4.0, EternalLiberty, APTnotes, Ransomware Tool Matrix CC BY 4.0), Atomic Red Team (Red Canary, MIT), EVTX-to-MITRE-Attack, EVTX-ATTACK-SAMPLES, APT & CyberCriminal Campaign Collections. Gerado por [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules).
