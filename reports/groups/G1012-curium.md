# CURIUM (G1012) — Dossiê de inteligência

> **TLP:CLEAR** · gerado em 2026-10-26 a partir de fontes abertas · MITRE ATT&CK v20.0 · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1012) · [ATT&CK](https://attack.mitre.org/groups/G1012/)

**Também conhecido como:** Crimson Sandstorm, TA456, Tortoise Shell, Yellow Liderc  
**Origem atribuída:** Irã · **Motivação:** espionagem, sabotagem · **Setores-alvo:** Sociedade civil e mídia, Energia, Financeiro, Governo, Saúde, Defesa e militar, Tecnologia, Telecomunicações, Transporte e logística  
**Registro no ATT&CK:** criado em 2023-01-13, atualizado em 2026-07-31 · referências de 2019 a 2023

## 1. Sumário executivo

- **19 técnicas** atribuídas publicamente, concentradas em **Resource Development, Initial Access, Exfiltration**.
- **Arsenal:** 1 malware e 0 ferramentas (ex.: IMAPLoader).
- **Campanhas atribuídas:** 0.
- **Cobertura de detecção pública:** 74% das técnicas têm ao menos uma regra no catálogo; **5 técnicas sem nenhuma regra pública**.
- **Origem e alvos (APT4ALL):** atribuído a **Irã**, motivação espionagem, sabotagem; setores Sociedade civil e mídia, Energia, Financeiro, Governo, Saúde; 2 países vítimas citados.
- **Onde a cobertura está:** Outros / genérico (13 técnicas com regra), Windows (12 técnicas com regra), Microsoft 365 (11 técnicas com regra), E-mail (10 técnicas com regra).
- **Assinatura comportamental** (técnicas raras entre os 178 grupos, as mais úteis para atribuição): T1584.006 Web Services, T1048.002 Exfiltration Over Asymmetric Encrypted Non-C2 Protocol, T1608.004 Drive-by Target, T1583.004 Server, T1124 System Time Discovery.

## 2. Quem é

> CURIUM is an Iranian threat group, first reported in September 2019 and active since at least July 2018, targeting IT service providers in the Middle East. CURIUM has since invested in building relationships with potential targets via social media over a period of months to establish trust and confidence before sending malware. Security researchers note CURIUM has demonstrated great patience and persistence by chatting with potential targets daily and sending benign files to help lower their security consciousness.

_Texto original do MITRE ATT&CK, em inglês._

## 3. Contexto, nomes e alvos

Consolidado pelo [APT4ALL](https://github.com/Ridd1kulusC0d3r/apt4all) a partir de MISP Galaxy, planilha APT Groups & Operations, EternalLiberty e APTnotes. Atribuição é afirmação de quem publicou; confira a fonte.

| Campo | Valor |
|---|---|
| Origem atribuída | Irã |
| Motivação | espionagem, sabotagem |
| Setores-alvo | Sociedade civil e mídia, Energia, Financeiro, Governo, Saúde, Defesa e militar, Tecnologia, Telecomunicações, Transporte e logística |
| Vítimas citadas | Europe, Israel, Middle East, United States |
| Alvos (planilha) | IT providers in Saudi Arabia, Aerospace & Defense (Israel, UAE) |
| Operações conhecidas | — |
| Confiança de atribuição (MISP) | 50 |

**Como cada fornecedor chama este grupo** (útil para cruzar relatórios):

| Fornecedor | Nome(s) |
|---|---|
| CrowdStrike | ImperialKitten, Imperial Kitten |
| FireEye | APT35 |
| MITRE ATT&CK | G1012 |
| Microsoft | Crimson Sandstorm, CURIUM (antigo · old) |

**Outros nomes no APT4ALL (não listados pelo ATT&CK):** FunRun RAT, Liderc, DEV-0228, UNC1549, Smoke Sandstorm, Cuboid Sandstorm, APT35, ImperialKitten, Bohrium, DEV-0056, DUSTYCAVE, Nimbus Manticore, Curium/Crimson Sandstorm, Hive0095, Cobalt Fireside, Devious Serpens, TA455, Bohrium/Smoke Sandstorm, Yellow Dev 13

## 4. Perfil TTP por tática (kill chain)

Cada linha: técnica, como o grupo a usou segundo relatos públicos, e o que existe para detectar e testar.

### Reconnaissance (TA0043) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1598.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1598.003) Spearphishing Link | CURIUM used malicious links to adversary-controlled resources for credential harvesting. | **0** | — | — |

### Resource Development (TA0042) — 7

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1583.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1583.001) Domains | CURIUM created domains to facilitate strategic website compromise and credential capture activities. | 7 | — | — |
| [T1583.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1583.003) Virtual Private Server | CURIUM created virtual private server instances to facilitate use of malicious domains and other items. | **0** | — | — |
| [T1583.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1583.004) Server | CURIUM has created dedicated servers for command and control and exfiltration purposes. | **0** | — | — |
| [T1584.006](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1584.006) Web Services | CURIUM has compromised legitimate websites to enable strategic website compromise attacks. | 1 | — | — |
| [T1585.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1585.001) Social Media Accounts | CURIUM has established a network of fictitious social media accounts, including on Facebook and LinkedIn, to establish relationships with victims, often posing as an attractive woman. | 4 | — | — |
| [T1585.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1585.002) Email Accounts | CURIUM has created dedicated email accounts for use with tools such as IMAPLoader. | **0** | — | — |
| [T1608.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1608.004) Drive-by Target | CURIUM used strategic website compromise to fingerprint then target victims. | **0** | — | — |

### Initial Access (TA0001) — 3

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1189](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1189) Drive-by Compromise | CURIUM has used strategic website compromise to infect victims with malware such as IMAPLoader. | 57 | — | — |
| [T1566.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1566.001) Spearphishing Attachment | CURIUM has used phishing with malicious attachments for initial access to victim environments. | 230 | 2 | — |
| [T1566.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1566.003) Spearphishing via Service | CURIUM has used social media to deliver malicious files to victims. | 8 | — | — |

### Execution (TA0002) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1059.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.001) PowerShell | CURIUM has leveraged PowerShell scripts for initial process execution and data gathering in victim environments. | 1340 | 22 | 15 |
| [T1204.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1204.002) Malicious File | CURIUM has lured users into opening malicious files delivered via social media. | 259 | 13 | — |

### Persistence (TA0003) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1505.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1505.003) Web Shell | CURIUM has been linked to web shells following likely server compromise as an initial access vector into victim networks. | 210 | 1 | — |

### Discovery (TA0007) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1082](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1082) System Information Discovery | CURIUM deploys information gathering tools focused on capturing IP configuration, running application, system information, and network connectivity information. | 264 | 41 | — |
| [T1124](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1124) System Time Discovery | CURIUM deployed mechanisms to check system time information following strategic website compromise attacks. | 18 | 6 | — |

### Collection (TA0009) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1005) Data from Local System | CURIUM has exfiltrated data from a compromised machine. | 170 | 3 | — |

### Exfiltration (TA0010) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1041](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1041) Exfiltration Over C2 Channel | CURIUM has used IMAP and SMTPS for exfiltration via tools such as IMAPLoader. | 135 | 2 | — |
| [T1048.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1048.002) Exfiltration Over Asymmetric Encrypted Non-C2 Protocol | CURIUM has used SMTPS to exfiltrate collected data from victims. | 15 | 4 | — |

## 5. Assinatura comportamental

Técnicas que este grupo usa e que poucos dos 178 grupos do ATT&CK usam. Pesam mais numa atribuição por TTP: ver várias delas juntas é mais informativo do que ver técnicas comuns como PowerShell.

| Técnica | Outros grupos que usam | Peso (raridade) |
|---|---:|---:|
| T1584.006 Web Services | 3 | 3.58 |
| T1048.002 Exfiltration Over Asymmetric Encrypted Non-C2 Protocol | 4 | 3.40 |
| T1608.004 Drive-by Target | 7 | 2.99 |
| T1583.004 Server | 8 | 2.88 |
| T1124 System Time Discovery | 14 | 2.42 |
| T1566.003 Spearphishing via Service | 14 | 2.42 |
| T1598.003 Spearphishing Link | 15 | 2.35 |
| T1583.003 Virtual Private Server | 18 | 2.19 |
| T1585.002 Email Accounts | 20 | 2.10 |
| T1585.001 Social Media Accounts | 22 | 2.01 |

## 6. Arsenal

| Software | Tipo | Técnicas no ATT&CK | Uso relatado (EN) |
|---|---|---:|---|
| [IMAPLoader](https://attack.mitre.org/software/S1152/) | malware | 9 | IMAPLoader was deployed by CURIUM as a post-exploitation payload from strategic website compromise. |

**Outras ferramentas e malware relatados (planilha APT Groups & Operations / MISP):** Backdoor.Syskit, Poison Frog, Infostealer/Sha.exe/Sha432.exe, Infostealer/stereoversioncontrol.exe, get-logon-history.ps1, FunRun RAT, Liderc, MINIBUS, MINIBIKE

## 7. Campanhas

Nenhuma campanha atribuída no ATT&CK.

## 8. Cobertura defensiva

**14 de 19 técnicas (74%)** têm ao menos uma regra pública no catálogo Detection Rules.

### Técnicas sem regra pública (prioridade para engenharia de detecção)

- **T1608.004 Drive-by Target** — Resource Development. Fonte de log sugerida pelo MITRE: `Internet Scan` None
- **T1583.004 Server** — Resource Development. Fonte de log sugerida pelo MITRE: `Internet Scan` None
- **T1598.003 Spearphishing Link** — Reconnaissance. Fonte de log sugerida pelo MITRE: `Application Log` None
- **T1583.003 Virtual Private Server** — Resource Development. Fonte de log sugerida pelo MITRE: `Internet Scan` None
- **T1585.002 Email Accounts** — Resource Development

### Onde procurar — cobertura por tecnologia

Quantas técnicas deste grupo têm ao menos uma regra em cada tecnologia. Comece a caça pelas tecnologias que você tem e que aparecem aqui.

| Tecnologia | Técnicas do grupo com regra |
|---|---:|
| Outros / genérico | 13 |
| Windows | 12 |
| Microsoft 365 | 11 |
| E-mail | 10 |
| AWS | 9 |
| IDS / NSM / NDR | 9 |
| Servidores web & aplicações | 9 |
| EDR / XDR | 8 |
| DNS | 8 |
| Linux | 7 |
| Firewall & perímetro | 7 |
| Proxy / SWG | 7 |

### Regras recomendadas por técnica

Melhor regra disponível por técnica (formato portável e maduro primeiro).

| Técnica | Regra | Formato | Fonte |
|---|---|---|---|
| T1005 | [Potential Conti Ransomware Database Dumping Activity Via SQLCmd](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A2f47f1fd-0901-466e-a770-3b7092834a1b) | Sigma | SigmaHQ |
| T1005 | [OpenCanary - SMB File Open Request](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A22777c9e-873a-4b49-855f-6072ab861a52) | Sigma | SigmaHQ |
| T1041 | [Equation Group C2 Communication](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A881834a4-6659-4773-821e-1c151789d873) | Sigma | SigmaHQ |
| T1041 | [OpenCanary - TFTP Request](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab4e6b016-a2ac-4759-ad85-8000b300d61e) | Sigma | SigmaHQ |
| T1048.002 | [CYFIRMA - High severity TOR Node Network Indicators - Monitor Recommended Rule](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A6f107cf8-02f9-4440-b5d8-1235293e5ad7) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1048.002 | [CYFIRMA - High severity TOR Node Network Indicators - Block Recommended Rule](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3Afa53ac37-a646-4106-91b6-ce478a1b5323) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1059.001 | [Potential Emotet Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad02e8cf5-6099-48cf-9bfc-1eec2d0c7b18) | Sigma | SigmaHQ |
| T1059.001 | [TropicTrooper Campaign November 2018](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A8c7090c3-e0a0-4944-bd08-08c3a0cecf79) | Sigma | SigmaHQ |
| T1082 | [Potential GobRAT File Discovery Via Grep](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae34cfa0c-0a50-4210-9cb3-5632d08eb041) | Sigma | SigmaHQ |
| T1082 | [System Information Discovery](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A42df45e7-e6e9-43b5-8f26-bec5b39cc239) | Sigma | SigmaHQ |
| T1124 | [Use of W32tm as Timer](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A6da2c9f5-7c53-401b-aacb-92c040ce1215) | Sigma | SigmaHQ |
| T1124 | [Cisco Discovery](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A9705a6a1-6db6-4a16-a987-15b7151e299b) | Sigma | SigmaHQ |
| T1189 | [Flash Player Update from Suspicious Location](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4922a5dd-6743-4fc2-8e81-144374280997) | Sigma | SigmaHQ |
| T1189 | [Cross Site Scripting Strings](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A65354b83-a2ea-4ea6-8414-3ab38be0d409) | Sigma | SigmaHQ |
| T1204.002 | [Ursnif Malware C2 URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A932ac737-33ca-4afd-9869-0d48b391fcc9) | Sigma | SigmaHQ |
| T1204.002 | [Droppers Exploiting CVE-2017-11882](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A678eb5f4-8597-4be6-8be7-905e4234b53a) | Sigma | SigmaHQ |
| T1505.003 | [MOVEit CVE-2023-34362 Exploitation Attempt - Potential Web Shell Request](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A435e41f2-48eb-4c95-8a2b-ed24b50ec30b) | Sigma | SigmaHQ |
| T1505.003 | [Solarwinds SUPERNOVA Webshell Access](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aa2cee20b-eacc-459f-861d-c02e5d12f1db) | Sigma | SigmaHQ |
| T1566.001 | [Ursnif Malware C2 URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A932ac737-33ca-4afd-9869-0d48b391fcc9) | Sigma | SigmaHQ |
| T1566.001 | [Droppers Exploiting CVE-2017-11882](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A678eb5f4-8597-4be6-8be7-905e4234b53a) | Sigma | SigmaHQ |
| T1566.003 | [M365 Teams Rogue Help Desk Chat Created](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ae8e7b6b6-78b0-4015-97fe-c2f28468e0d4) | Elastic | Elastic detection-rules |
| T1566.003 | [M365 Azure Monitor Alert Email with Financial or Billing Theme](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Aa6129187-c47b-48ab-a412-67a44836d918) | Elastic | Elastic detection-rules |
| T1583.001 | [AWS Route 53 Private Hosted Zone Associated With a VPC](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ae3c27562-709a-42bd-82f2-3ed926cced19) | Elastic | Elastic detection-rules |
| T1583.001 | [AWS SES Email Identity Verified Then Deleted](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A8e4bde35-125d-4eb3-9a2e-d7e77a053a08) | Elastic | Elastic detection-rules |
| T1584.006 | [Suspicious PowerShell Mailbox Export to Share](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A889719ef-dd62-43df-86c3-768fb08dc7c0) | Sigma | OpenSearch Security Analytics |
| T1585.001 | [CYFIRMA - Brand Intelligence - Social Media Handle Impersonation Detected High Rule](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A22f49d67-7da7-4809-8d07-89e4478aa6b0) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1585.001 | [CYFIRMA - Brand Intelligence - Executive/People Impersonation High Rule](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A159d26a1-591c-4f70-b1ca-2843c881aaec) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |

## 9. Plano de emulação e validação

Use num laboratório isolado e autorizado para confirmar que as regras disparam. Os comandos estão nos repositórios oficiais.

| Tática | Técnica | Teste Atomic Red Team | Plataformas |
|---|---|---|---|
| Initial Access | [T1566.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1566.001/T1566.001.md) | Download Macro-Enabled Phishing Attachment | windows |
| Initial Access | [T1566.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1566.001/T1566.001.md) | Word spawned a command shell and used an IP address in the command line | windows |
| Execution | [T1059.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md) | Mimikatz | windows |
| Execution | [T1059.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md) | Run BloodHound from local disk | windows |
| Execution | [T1204.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1204.002/T1204.002.md) | OSTap Style Macro Execution | windows |
| Execution | [T1204.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1204.002/T1204.002.md) | OSTap Payload Download | windows |
| Persistence | [T1505.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1505.003/T1505.003.md) | Web Shell Written to Disk | windows |
| Discovery | [T1082](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1082/T1082.md) | System Information Discovery | windows |
| Discovery | [T1082](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1082/T1082.md) | System Information Discovery | macos |
| Discovery | [T1124](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1124/T1124.md) | System Time Discovery | windows |
| Discovery | [T1124](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1124/T1124.md) | System Time Discovery - PowerShell | windows |
| Collection | [T1005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1005/T1005.md) | Search files of interest and save them to a single zip file (Windows) | windows |
| Collection | [T1005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1005/T1005.md) | Find and dump sqlite databases (Linux) | linux |
| Exfiltration | [T1041](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1041/T1041.md) | C2 Data Exfiltration | windows |
| Exfiltration | [T1041](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1041/T1041.md) | Text Based Data Exfiltration using DNS subdomains | windows |
| Exfiltration | [T1048.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1048.002/T1048.002.md) | Exfiltrate data HTTPS using curl windows | windows |
| Exfiltration | [T1048.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1048.002/T1048.002.md) | Exfiltrate data HTTPS using curl freebsd,linux or macos | linux, macos |

**Logs reais de ataque (EVTX) para testar sem executar nada:**

- T1059.001 — [ID4103-4104-Payload download via PowerShell](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1059.001-PowerShell/ID4103-4104-Payload%20download%20via%20PowerShell.evtx) _(explícito)_
- T1059.001 — [ID4688-Encoded PowerShell MSF payload via process execution](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1059.001-PowerShell/ID4688-Encoded%20PowerShell%20MSF%20payload%20via%20process%20execution.evtx) _(explícito)_

## 10. Hipóteses de hunting

Se CURIUM estiver no seu ambiente, estas são as perguntas a fazer aos seus dados (fontes de log segundo as estratégias de detecção do MITRE ATT&CK).

1. **T1584.006 Web Services** — Once adversaries leverage the abused web service as infrastructure (ex: for command and control), it may be possible to look for unique characteristics associated with adversary software, if known. Much of this activity will take place outside the visibility… Dados: `Internet Scan` (None).
2. **T1048.002 Exfiltration Over Asymmetric Encrypted Non-C2 Protocol** — Detects non-browser processes that establish encrypted outbound connections (e.g., TLS/SSL) to unfamiliar or atypical destinations for the host/user, following a data staging or compression event. Dados: `WinEventLog:Sysmon` (EventCode=3, 22), `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Security` (EventCode=4663, 4670, 4656).
3. **T1608.004 Drive-by Target** — If infrastructure or patterns in the malicious web content utilized to deliver a Drive-by Compromise have been previously identified, internet scanning may uncover when an adversary has staged web content for use in a strategic web compromise. Much of this… Dados: `Internet Scan` (None).
4. **T1583.004 Server** — Much of this activity will take place outside the visibility of the target organization, making detection of this behavior difficult. Detection efforts may be focused on related stages of the adversary lifecycle, such as during Command and Control. Once… Dados: `Internet Scan` (None), `Internet Scan` (None).
5. **T1124 System Time Discovery** — Untrusted or unusual process/script (cmd.exe, powershell.exe, w32tm.exe, net.exe, custom binaries) queries system time/timezone (e.g., w32tm /tz, net time \\host, Get-TimeZone, GetTickCount API) and (optionally) is followed within a short window by time-based… Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=7), `WinEventLog:Sysmon` (EventCode=10).
6. **T1566.003 Spearphishing via Service** — Inbound spearphishing attempts delivered via third-party services (e.g., Gmail, LinkedIn messages) leading to malicious file downloads or browser-initiated script execution. Defender view includes correlation of external service logins, unexpected file write… Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Sysmon` (EventCode=3, 22).
7. **T1598.003 Spearphishing Link** — Monitor for suspicious email activity, such as numerous accounts receiving messages from a single unusual/unknown sender. Filtering based on DKIM+SPF or header analysis can help detect when the email sender is spoofed. Monitor for references to uncategorized… Dados: `Application Log` (None), `Network Traffic` (None), `Network Traffic` (None).
8. **T1583.003 Virtual Private Server** — Once adversaries have provisioned a VPS (ex: for use as a command and control server), internet scans may reveal servers that adversaries have acquired. Consider looking for identifiable patterns such as services listening, certificates in use, SSL/TLS… Dados: `Internet Scan` (None), `Internet Scan` (None).
9. **T1585.001 Social Media Accounts** — Monitor and analyze traffic patterns and packet inspection associated to protocol(s) that do not follow the expected protocol standards and traffic flows (e.g extraneous packets that do not belong to established flows, gratuitous or anomalous traffic… Dados: `Network Traffic` (None), `Persona` (None).
10. **T1041 Exfiltration Over C2 Channel** — Identifies suspicious outbound traffic volume mismatches from processes that typically do not generate network activity, particularly over C2 protocols like HTTPS, DNS, or custom TCP/UDP ports, following file or data access. Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=3, 22), `NSM:Flow` (Flow/PCAP analysis for outbound payloads).
11. **T1189 Drive-by Compromise** — Correlated evidence of anomalous browser/network behavior (suspicious external resource fetches and script injection patterns) followed by atypical child processes, ephemeral execution contexts, memory modification or process injection, and unexpected file… Dados: `WinEventLog:Security` (EventCode=4624, 4648), `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=3, 22).
12. **T1505.003 Web Shell** — Unexpected file creation in web directories followed by web server processes (e.g., w3wp.exe) spawning command shells or script interpreters (e.g., cmd.exe, powershell.exe) Dados: `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Security` (EventCode=4624, 4648).

## 11. OSINT — onde pesquisar

Consultas prontas com todos os nomes conhecidos do grupo:

- Relatórios técnicos: [busca web](https://duckduckgo.com/?q=%28%22CURIUM%22+OR+%22Crimson+Sandstorm%22+OR+%22TA456%22+OR+%22Tortoise+Shell%22+OR+%22Yellow+Liderc%22%29+threat+report) · [PDFs](https://duckduckgo.com/?q=%28%22CURIUM%22+OR+%22Crimson+Sandstorm%22+OR+%22TA456%22+OR+%22Tortoise+Shell%22+OR+%22Yellow+Liderc%22%29+filetype%3Apdf)
- Regras e IOCs publicados: [GitHub](https://github.com/search?type=code&q=%22CURIUM%22+OR+%22Crimson+Sandstorm%22+OR+%22TA456%22+OR+%22Tortoise+Shell%22+OR+%22Yellow+Liderc%22)
- Pulsos de ameaça: [AlienVault OTX](https://otx.alienvault.com/browse/global/pulses?q=CURIUM)
- Família de malware e atores: [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/actors) (busque por CURIUM, Crimson Sandstorm, TA456)
- Cartões de grupo: [ThaiCERT Threat Group Cards](https://apt.etda.or.th/cgi-bin/listgroups.cgi)
- Página oficial: [MITRE ATT&CK G1012](https://attack.mitre.org/groups/G1012/)

**Relatórios na coleção CyberMonitor** (ligados pelo nome do grupo, conferir antes de citar):

- 2021 — [I Knew You Were Trouble_ TA456 Targets Defense Contractor with Alluring Social Media Persona _ Proofpoint US](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2021/2021.07.28.TA456/I%20Knew%20You%20Were%20Trouble_%20TA456%20Targets%20Defense%20Contractor%20with%20Alluring%20Social%20Media%20Persona%20_%20Proofpoint%20US.pdf) _(via “TA456”)_

**Relatórios públicos ligados pelo APT4ALL** (1 no total, mais recentes primeiro):

- 2022 — [APT35 Automates Initial Access Using ProxyShell](https://app.box.com/s/effdjg8nuddhq3e9ooywuesizw5b0e3w) _(TheDFIRreport)_

## 12. Bibliografia (5 fontes citadas pelo ATT&CK)

- [Microsoft Iranian Threat Actor Trends November 2021](https://www.microsoft.com/en-us/security/blog/2021/11/16/evolving-trends-in-iranian-threat-actor-activity-mstic-presentation-at-cyberwarcon-2021) — MSTIC. (2021, November 16). Evolving trends in Iranian threat actor activity – MSTIC presentation at CyberWarCon 2021. Retrieved January 12, 2023.
- [Microsoft Threat Actor Naming July 2023](https://learn.microsoft.com/en-us/microsoft-365/security/intelligence/microsoft-threat-actor-naming?view=o365-worldwide) — Microsoft . (2023, July 12). How Microsoft names threat actors. Retrieved November 17, 2023.
- [Proofpoint TA456 Defense Contractor July 2021](https://www.proofpoint.com/us/blog/threat-insight/i-knew-you-were-trouble-ta456-targets-defense-contractor-alluring-social-media) — Miller, J. et. al. (2021, July 28). I Knew You Were Trouble: TA456 Targets Defense Contractor with Alluring Social Media Persona. Retrieved March 11, 2024.
- [PWC Yellow Liderc 2023](https://www.pwc.com/gx/en/issues/cybersecurity/cyber-threat-intelligence/yellow-liderc-ships-its-scripts-delivers-imaploader-malware.html) — PwC Threat Intelligence. (2023, October 25). Yellow Liderc ships its scripts and delivers IMAPLoader malware. Retrieved August 14, 2024.
- [Symantec Tortoiseshell 2019](https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/tortoiseshell-apt-supply-chain) — Symantec Threat Hunter Team. (2019, September 18). Tortoiseshell Group Targets IT Providers in Saudi Arabia in Probable Supply Chain Attacks. Retrieved May 20, 2024.

## 13. Limites e confiança

- O ATT&CK registra o que foi **relatado publicamente**, não tudo o que o grupo faz. Ausência de uma técnica não prova que o grupo não a usa.
- **Sobreposição de TTP não é atribuição.** Muitas técnicas são compartilhadas entre grupos e com red teams. Use a assinatura comportamental como hipótese, junto com infraestrutura, malware e contexto.
- Cobertura de detecção refere-se ao catálogo público Detection Rules, não ao seu ambiente: confira se a telemetria necessária chega ao seu SIEM.
- Ligações marcadas como _inferidas_ (EVTX por palavra-chave, relatórios por nome) devem ser verificadas.

---
Fontes: MITRE ATT&CK® (uso livre com atribuição, © The MITRE Corporation), APT4ALL (MISP Galaxy CC0/BSD-2, APT Groups & Operations CC BY 4.0, EternalLiberty, APTnotes, Ransomware Tool Matrix CC BY 4.0), Atomic Red Team (Red Canary, MIT), EVTX-to-MITRE-Attack, EVTX-ATTACK-SAMPLES, APT & CyberCriminal Campaign Collections. Gerado por [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules).
