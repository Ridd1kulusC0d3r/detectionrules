# Andariel (G0138) — Dossiê de inteligência

> **TLP:CLEAR** · gerado em 2026-10-25 a partir de fontes abertas · MITRE ATT&CK v20.0 · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0138) · [ATT&CK](https://attack.mitre.org/groups/G0138/)

**Também conhecido como:** Silent Chollima, PLUTONIUM, Onyx Sleet  
**Registro no ATT&CK:** criado em 2021-09-29, atualizado em 2026-07-31 · referências de 2017 a 2023

## 1. Sumário executivo

- **12 técnicas** atribuídas publicamente, concentradas em **Discovery, Initial Access, Execution**.
- **Arsenal:** 2 malware e 0 ferramentas (ex.: gh0st RAT, Rifdoor).
- **Campanhas atribuídas:** 0.
- **Cobertura de detecção pública:** 100% das técnicas têm ao menos uma regra no catálogo; **0 técnicas sem nenhuma regra pública**.
- **Assinatura comportamental** (técnicas raras entre os 178 grupos, as mais úteis para atribuição): T1590.005 IP Addresses, T1592.002 Software, T1027.003 Steganography, T1588.001 Malware, T1189 Drive-by Compromise.

## 2. Quem é

> Andariel is a North Korean state-sponsored threat group that has been active since at least 2009. Andariel has primarily focused its operations--which have included destructive attacks--against South Korean government agencies, military organizations, and a variety of domestic companies; they have also conducted cyber financial operations against ATMs, banks, and cryptocurrency exchanges. Andariel's notable activity includes Operation Black Mine, Operation GoldenAxe, and Campaign Rifle.
> 
> Andariel is considered a sub-set of Lazarus Group, and has been attributed to North Korea's Reconnaissance General Bureau.
> 
> North Korean group definitions are known to have significant overlap, and some security researchers report all North Korean state-sponsored cyber activity under the name Lazarus Group instead of tracking clusters or subgroups.

_Texto original do MITRE ATT&CK, em inglês._

## 3. Perfil TTP por tática (kill chain)

Cada linha: técnica, como o grupo a usou segundo relatos públicos, e o que existe para detectar e testar.

### Reconnaissance (TA0043) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1590.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1590.005) IP Addresses | Andariel has limited its watering hole attacks to specific IP address ranges. | 1 | — | — |
| [T1592.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1592.002) Software | Andariel has inserted a malicious script within compromised websites to collect potential victim information such as browser type, system language, Flash Player version, and other data. | 2 | — | — |

### Resource Development (TA0042) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1588.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1588.001) Malware | Andariel has used a variety of publicly-available remote access Trojans (RATs) for its operations. | 7 | — | — |

### Initial Access (TA0001) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1189](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1189) Drive-by Compromise | Andariel has used watering hole attacks, often with zero-day exploits, to gain initial access to victims within a specific IP range. | 57 | — | — |
| [T1566.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1566.001) Spearphishing Attachment | Andariel has conducted spearphishing campaigns that included malicious Word or Excel attachments. | 230 | 2 | — |

### Execution (TA0002) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1203](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1203) Exploitation for Client Execution | Andariel has exploited numerous ActiveX vulnerabilities, including zero-days. | 202 | — | — |
| [T1204.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1204.002) Malicious File | Andariel has attempted to lure victims into enabling malicious macros within email attachments. | 259 | 13 | — |

### Stealth (TA0005) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1027.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1027.003) Steganography | Andariel has hidden malicious executables within PNG files. | 13 | — | — |

### Discovery (TA0007) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1049](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1049) System Network Connections Discovery | Andariel has used the netstat -naop tcp command to display TCP connections on a victim's machine. | 47 | 7 | — |
| [T1057](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1057) Process Discovery | Andariel has used tasklist to enumerate processes and find a specific string. | 82 | 10 | — |

### Collection (TA0009) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1005) Data from Local System | Andariel has collected large numbers of files from compromised network systems for later extraction. | 170 | 3 | — |

### Command and Control (TA0011) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1105](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1105) Ingress Tool Transfer | Andariel has downloaded additional tools and malware onto compromised hosts. | 644 | 39 | — |

## 4. Assinatura comportamental

Técnicas que este grupo usa e que poucos dos 178 grupos do ATT&CK usam. Pesam mais numa atribuição por TTP: ver várias delas juntas é mais informativo do que ver técnicas comuns como PowerShell.

| Técnica | Outros grupos que usam | Peso (raridade) |
|---|---:|---:|
| T1590.005 IP Addresses | 2 | 3.80 |
| T1592.002 Software | 2 | 3.80 |
| T1027.003 Steganography | 9 | 2.79 |
| T1588.001 Malware | 17 | 2.24 |
| T1189 Drive-by Compromise | 30 | 1.72 |
| T1049 System Network Connections Discovery | 32 | 1.66 |
| T1057 Process Discovery | 41 | 1.43 |
| T1203 Exploitation for Client Execution | 41 | 1.43 |
| T1005 Data from Local System | 46 | 1.32 |
| T1566.001 Spearphishing Attachment | 78 | 0.81 |

## 5. Arsenal

| Software | Tipo | Técnicas no ATT&CK | Uso relatado (EN) |
|---|---|---:|---|
| [gh0st RAT](https://attack.mitre.org/software/S0032/) | malware | 24 |  |
| [Rifdoor](https://attack.mitre.org/software/S0433/) | malware | 9 |  |

## 6. Campanhas

Nenhuma campanha atribuída no ATT&CK.

## 7. Cobertura defensiva

**12 de 12 técnicas (100%)** têm ao menos uma regra pública no catálogo Detection Rules.

### Regras recomendadas por técnica

Melhor regra disponível por técnica (formato portável e maduro primeiro).

| Técnica | Regra | Formato | Fonte |
|---|---|---|---|
| T1005 | [Potential Conti Ransomware Database Dumping Activity Via SQLCmd](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A2f47f1fd-0901-466e-a770-3b7092834a1b) | Sigma | SigmaHQ |
| T1005 | [OpenCanary - SMB File Open Request](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A22777c9e-873a-4b49-855f-6072ab861a52) | Sigma | SigmaHQ |
| T1027.003 | [Steganography Hide Files with Steghide](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ace446a9e-30b9-4483-8e38-d2c9ad0a2280) | Sigma | SigmaHQ |
| T1027.003 | [Steganography Unzip Hidden Information From Picture File](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aedd595d7-7895-4fa7-acb3-85a18a8772ca) | Sigma | SigmaHQ |
| T1049 | [Potential Pikabot Discovery Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A698d4431-514f-4c82-af4d-cf573872a9f5) | Sigma | SigmaHQ |
| T1049 | [HackTool - SharpView Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab2317cfa-4a47-4ead-b3ff-297438c0bc2d) | Sigma | SigmaHQ |
| T1057 | [Process Discovery](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4e2f5868-08d4-413d-899f-dc2f1508627b) | Sigma | SigmaHQ |
| T1057 | [HackTool - PCHunter Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Afca949cc-79ca-446e-8064-01aa7e52ece5) | Sigma | SigmaHQ |
| T1105 | [Greenbug Espionage Group Indicators](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A3711eee4-a808-4849-8a14-faf733da3612) | Sigma | SigmaHQ |
| T1105 | [Pandemic Registry Key](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A47e0852a-cf81-4494-a8e6-31864f8c86ed) | Sigma | SigmaHQ |
| T1189 | [Flash Player Update from Suspicious Location](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4922a5dd-6743-4fc2-8e81-144374280997) | Sigma | SigmaHQ |
| T1189 | [Cross Site Scripting Strings](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A65354b83-a2ea-4ea6-8414-3ab38be0d409) | Sigma | SigmaHQ |
| T1203 | [Droppers Exploiting CVE-2017-11882](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A678eb5f4-8597-4be6-8be7-905e4234b53a) | Sigma | SigmaHQ |
| T1203 | [OMIGOD HTTP No Authentication RCE - CVE-2021-38647](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aab6b1a39-a9ee-4ab4-b075-e83acf6e346b) | Sigma | SigmaHQ |
| T1204.002 | [Ursnif Malware C2 URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A932ac737-33ca-4afd-9869-0d48b391fcc9) | Sigma | SigmaHQ |
| T1204.002 | [Droppers Exploiting CVE-2017-11882](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A678eb5f4-8597-4be6-8be7-905e4234b53a) | Sigma | SigmaHQ |
| T1566.001 | [Ursnif Malware C2 URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A932ac737-33ca-4afd-9869-0d48b391fcc9) | Sigma | SigmaHQ |
| T1566.001 | [Droppers Exploiting CVE-2017-11882](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A678eb5f4-8597-4be6-8be7-905e4234b53a) | Sigma | SigmaHQ |
| T1588.001 | [Relevant ClamAV Message](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A36aa86ca-fd9d-4456-814e-d3b1b8e1e0bb) | Sigma | SigmaHQ |
| T1588.001 | [Relevant ClamAV Message](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A36aa86ca-fd9d-4456-814e-d3b1b8e1e0bb) | Sigma | OpenSearch Security Analytics |
| T1590.005 | [Cisco ASA - Reconnaissance Command Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=splunk-security-content%3A%3A6e9d4f7a-3c8b-4a9e-8d2f-7b5c9e1a6f3d) | Splunk | Splunk security_content |
| T1592.002 | [Windows WinPEAS PowerShell Script Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=splunk-security-content%3A%3A5cb208df-e1aa-478d-ab2f-8270ff9999b9) | Splunk | Splunk security_content |
| T1592.002 | [Possible IP geolocation lookup with curl (T1592.002)](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=socfortress-wazuh-rules%3A%3Awazuh-700182) | Wazuh | SOCFortress Wazuh-Rules |

## 8. Plano de emulação e validação

Use num laboratório isolado e autorizado para confirmar que as regras disparam. Os comandos estão nos repositórios oficiais.

| Tática | Técnica | Teste Atomic Red Team | Plataformas |
|---|---|---|---|
| Initial Access | [T1566.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1566.001/T1566.001.md) | Download Macro-Enabled Phishing Attachment | windows |
| Initial Access | [T1566.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1566.001/T1566.001.md) | Word spawned a command shell and used an IP address in the command line | windows |
| Execution | [T1204.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1204.002/T1204.002.md) | OSTap Style Macro Execution | windows |
| Execution | [T1204.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1204.002/T1204.002.md) | OSTap Payload Download | windows |
| Discovery | [T1049](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1049/T1049.md) | System Network Connections Discovery | windows |
| Discovery | [T1049](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1049/T1049.md) | System Network Connections Discovery with PowerShell | windows |
| Discovery | [T1057](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1057/T1057.md) | Process Discovery - ps | linux, macos |
| Discovery | [T1057](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1057/T1057.md) | Process Discovery - tasklist | windows |
| Collection | [T1005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1005/T1005.md) | Search files of interest and save them to a single zip file (Windows) | windows |
| Collection | [T1005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1005/T1005.md) | Find and dump sqlite databases (Linux) | linux |
| Command and Control | [T1105](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1105/T1105.md) | rsync remote file copy (push) | linux, macos |
| Command and Control | [T1105](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1105/T1105.md) | rsync remote file copy (pull) | linux, macos |

## 9. Hipóteses de hunting

Se Andariel estiver no seu ambiente, estas são as perguntas a fazer aos seus dados (fontes de log segundo as estratégias de detecção do MITRE ATT&CK).

1. **T1592.002 Software** — Internet scanners may be used to look for patterns associated with malicious content designed to collect host software information from visitors. Much of this activity may have a very high occurrence and associated false positive rate, as well as potentially… Dados: `Internet Scan` (None).
2. **T1027.003 Steganography** — Detects execution of image viewers or PowerShell scripts accessing or decoding files with mismatched MIME headers or embedded script-like byte patterns; often correlated with suspicious parent-child process lineage and outbound connections. Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=3, 22), `WinEventLog:Security` (EventCode=4663, 4670, 4656).
3. **T1588.001 Malware** — Monitor for contextual data about a malicious payload, such as compilation times, file hashes, as well as watermarks or other identifiable configuration information. Much of this activity will take place outside the visibility of the target organization,… Dados: `Malware Repository` (None), `Malware Repository` (None).
4. **T1189 Drive-by Compromise** — Correlated evidence of anomalous browser/network behavior (suspicious external resource fetches and script injection patterns) followed by atypical child processes, ephemeral execution contexts, memory modification or process injection, and unexpected file… Dados: `WinEventLog:Security` (EventCode=4624, 4648), `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=3, 22).
5. **T1049 System Network Connections Discovery** — Detects usage of commands or binaries (e.g., netstat, PowerShell Get-NetTCPConnection) and WMI or API calls to enumerate local or remote network connections. Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:PowerShell` (EventCode=4103, 4104, 4105, 4106).
6. **T1057 Process Discovery** — Identifies adversary behavior that launches commands or invokes APIs to enumerate active processes (e.g., tasklist.exe, Get-Process, or CreateToolhelp32Snapshot). Detects execution combined with parent process lineage, network session context, or remote… Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=10).
7. **T1203 Exploitation for Client Execution** — Cause→effect chain: (1) A client app (browser, Office, PDF/Flash/reader) experiences a crash/abnormal exit or loads from an unusual location, then (2) drops or modifies a file in user-writable paths, and/or (3) spawns an unexpected child (e.g.,… Dados: `WinEventLog:Application` (EventCode=1000), `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Sysmon` (EventCode=1).
8. **T1005 Data from Local System** — Adversaries collecting local files via PowerShell, WMI, or direct file API calls often include recursive file listings, targeted file reads, and temporary file staging. Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=11).
9. **T1566.001 Spearphishing Attachment** — Detection of spearphishing attachments by correlating suspicious email delivery with subsequent file creation and abnormal process execution (e.g., Office spawning PowerShell or CMD). Behavior chain includes inbound email metadata → attachment stored on disk… Dados: `m365:unified` (Send/Receive: Inbound emails with attachments from suspicious or spoofed senders), `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Sysmon` (EventCode=1).
10. **T1204.002 Malicious File** — User opens a file delivered by email, web, chat, or share. The handler application (Word/PDF reader/archiver) creates a file in user-controlled paths (Downloads, Temp, Desktop) and then spawns a new or unusual child process (e.g., powershell.exe, wscript.exe,… Dados: `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=15).
11. **T1105 Ingress Tool Transfer** — Unusual or uncommon processes initiate network connections to external destinations followed by file creation (tools downloaded). Dados: `WinEventLog:Sysmon` (EventCode=3, 22), `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Sysmon` (EventCode=1).

## 10. OSINT — onde pesquisar

Consultas prontas com todos os nomes conhecidos do grupo:

- Relatórios técnicos: [busca web](https://duckduckgo.com/?q=%28%22Andariel%22+OR+%22Silent+Chollima%22+OR+%22PLUTONIUM%22+OR+%22Onyx+Sleet%22%29+threat+report) · [PDFs](https://duckduckgo.com/?q=%28%22Andariel%22+OR+%22Silent+Chollima%22+OR+%22PLUTONIUM%22+OR+%22Onyx+Sleet%22%29+filetype%3Apdf)
- Regras e IOCs publicados: [GitHub](https://github.com/search?type=code&q=%22Andariel%22+OR+%22Silent+Chollima%22+OR+%22PLUTONIUM%22+OR+%22Onyx+Sleet%22)
- Pulsos de ameaça: [AlienVault OTX](https://otx.alienvault.com/browse/global/pulses?q=Andariel)
- Família de malware e atores: [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/actors) (busque por Andariel, Silent Chollima, PLUTONIUM)
- Cartões de grupo: [ThaiCERT Threat Group Cards](https://apt.etda.or.th/cgi-bin/listgroups.cgi)
- Página oficial: [MITRE ATT&CK G0138](https://attack.mitre.org/groups/G0138/)

**Relatórios na coleção CyberMonitor** (ligados pelo nome do grupo, conferir antes de citar):

- 2018 — [[AhnLab]Andariel_a_Subgroup_of_Lazarus (3)](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2018/2018.06.23.Andariel_Group/%5BAhnLab%5DAndariel_a_Subgroup_of_Lazarus%20%283%29.pdf) _(via “Andariel”)_
- 2018 — [new-andariel-reconnaissance-tactics-hint-at-next-targets](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2018/2018.07.16.new-andariel/new-andariel-reconnaissance-tactics-hint-at-next-targets.pdf) _(via “Andariel”)_

## 11. Bibliografia (9 fontes citadas pelo ATT&CK)

- [AhnLab Andariel Subgroup of Lazarus June 2018](https://web.archive.org/web/20230213154832/http://download.ahnlab.com/global/brochure/%5BAnalysis%5DAndariel_Group.pdf) — AhnLab. (2018, June 23). Targeted attacks by Andariel Threat Group, a subgroup of the Lazarus. Retrieved September 29, 2021.
- [CrowdStrike Silent Chollima Adversary September 2021](https://adversary.crowdstrike.com/en-US/adversary/silent-chollima/) — CrowdStrike. (2021, September 29). Silent Chollima Adversary Profile. Retrieved September 29, 2021.
- [FSI Andariel Campaign Rifle July 2017](https://fsiceat.tistory.com/2) — FSI. (2017, July 27). Campaign Rifle - Andariel, the Maiden of Anguish. Retrieved September 12, 2024.
- [IssueMakersLab Andariel GoldenAxe May 2017](http://www.issuemakerslab.com/research3/) — IssueMakersLab. (2017, May 1). Operation GoldenAxe. Retrieved September 12, 2024.
- [Kaspersky Andariel Ransomware June 2021](https://securelist.com/andariel-evolves-to-target-south-korea-with-ransomware/102811/) — Park, S. (2021, June 15). Andariel evolves to target South Korea with ransomware. Retrieved September 29, 2021.
- [MalwareBytes Lazarus-Andariel Conceals Code April 2021](https://blog.malwarebytes.com/threat-intelligence/2021/04/lazarus-apt-conceals-malicious-code-within-bmp-file-to-drop-its-rat/) — Jazi, H. (2021, April 19). Lazarus APT conceals malicious code within BMP image to drop its RAT . Retrieved September 29, 2021.
- [Microsoft Threat Actor Naming July 2023](https://learn.microsoft.com/en-us/microsoft-365/security/intelligence/microsoft-threat-actor-naming?view=o365-worldwide) — Microsoft . (2023, July 12). How Microsoft names threat actors. Retrieved November 17, 2023.
- [Treasury North Korean Cyber Groups September 2019](https://home.treasury.gov/news/press-releases/sm774) — US Treasury . (2019, September 13). Treasury Sanctions North Korean State-Sponsored Malicious Cyber Groups. Retrieved September 29, 2021.
- [TrendMicro New Andariel Tactics July 2018](https://www.trendmicro.com/en_us/research/18/g/new-andariel-reconnaissance-tactics-hint-at-next-targets.html) — Chen, Joseph. (2018, July 16). New Andariel Reconnaissance Tactics Uncovered. Retrieved September 29, 2021.

## 12. Limites e confiança

- O ATT&CK registra o que foi **relatado publicamente**, não tudo o que o grupo faz. Ausência de uma técnica não prova que o grupo não a usa.
- **Sobreposição de TTP não é atribuição.** Muitas técnicas são compartilhadas entre grupos e com red teams. Use a assinatura comportamental como hipótese, junto com infraestrutura, malware e contexto.
- Cobertura de detecção refere-se ao catálogo público Detection Rules, não ao seu ambiente: confira se a telemetria necessária chega ao seu SIEM.
- Ligações marcadas como _inferidas_ (EVTX por palavra-chave, relatórios por nome) devem ser verificadas.

---
Fontes: MITRE ATT&CK® (uso livre com atribuição, © The MITRE Corporation), Atomic Red Team (Red Canary, MIT), EVTX-to-MITRE-Attack, EVTX-ATTACK-SAMPLES, APT & CyberCriminal Campaign Collections. Gerado por [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules).
