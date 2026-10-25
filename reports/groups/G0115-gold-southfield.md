# GOLD SOUTHFIELD (G0115) — Dossiê de inteligência

> **TLP:CLEAR** · gerado em 2026-10-25 a partir de fontes abertas · MITRE ATT&CK v20.0 · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0115) · [ATT&CK](https://attack.mitre.org/groups/G0115/)

**Também conhecido como:** Pinchy Spider  
**Registro no ATT&CK:** criado em 2020-09-22, atualizado em 2026-07-31 · referências de 2019 a 2021

## 1. Sumário executivo

- **9 técnicas** atribuídas publicamente, concentradas em **Initial Access, Stealth, Execution**.
- **Arsenal:** 1 malware e 1 ferramentas (ex.: REvil, ConnectWise).
- **Campanhas atribuídas:** 0.
- **Cobertura de detecção pública:** 100% das técnicas têm ao menos uma regra no catálogo; **0 técnicas sem nenhuma regra pública**.
- **Assinatura comportamental** (técnicas raras entre os 178 grupos, as mais úteis para atribuição): T1566 Phishing, T1195.002 Compromise Software Supply Chain, T1219 Remote Access Tools, T1199 Trusted Relationship, T1113 Screen Capture.

## 2. Quem é

> GOLD SOUTHFIELD is a financially motivated threat group active since at least 2018 that operates the REvil Ransomware-as-a Service (RaaS). GOLD SOUTHFIELD provides backend infrastructure for affiliates recruited on underground forums to perpetrate high value deployments. By early 2020, GOLD SOUTHFIELD started capitalizing on the new trend of stealing data and further extorting the victim to pay for their data to not get publicly leaked.

_Texto original do MITRE ATT&CK, em inglês._

## 3. Perfil TTP por tática (kill chain)

Cada linha: técnica, como o grupo a usou segundo relatos públicos, e o que existe para detectar e testar.

### Initial Access (TA0001) — 5

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1133](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1133) External Remote Services | GOLD SOUTHFIELD has used publicly-accessible RDP and remote management and monitoring (RMM) servers to gain access to victim machines. | 361 | 1 | — |
| [T1190](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1190) Exploit Public-Facing Application | GOLD SOUTHFIELD has exploited Oracle WebLogic vulnerabilities for initial compromise. | 580 | — | — |
| [T1195.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1195.002) Compromise Software Supply Chain | GOLD SOUTHFIELD has distributed ransomware by backdooring software installers via a strategic web compromise of the site hosting Italian WinRAR. | 74 | 1 | — |
| [T1199](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1199) Trusted Relationship | GOLD SOUTHFIELD has breached Managed Service Providers (MSP's) to deliver malware to MSP customers. | 18 | — | — |
| [T1566](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1566) Phishing | GOLD SOUTHFIELD has conducted malicious spam (malspam) campaigns to gain access to victim's machines. | 286 | — | — |

### Execution (TA0002) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1059.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.001) PowerShell | GOLD SOUTHFIELD has staged and executed PowerShell scripts on compromised hosts. | 1340 | 22 | 15 |

### Persistence (TA0003) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1133](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1133) External Remote Services | GOLD SOUTHFIELD has used publicly-accessible RDP and remote management and monitoring (RMM) servers to gain access to victim machines. | 361 | 1 | — |

### Stealth (TA0005) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1027.010](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1027.010) Command Obfuscation | GOLD SOUTHFIELD has executed base64 encoded PowerShell scripts on compromised hosts. | 78 | — | — |

### Collection (TA0009) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1113](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1113) Screen Capture | GOLD SOUTHFIELD has used the remote monitoring and management tool ConnectWise to obtain screen captures from victim's machines. | 60 | 10 | — |

### Command and Control (TA0011) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1219](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1219) Remote Access Tools | GOLD SOUTHFIELD has used the cloud-based remote management and monitoring tool "ConnectWise Control" to deploy REvil. | 119 | 15 | — |

## 4. Assinatura comportamental

Técnicas que este grupo usa e que poucos dos 178 grupos do ATT&CK usam. Pesam mais numa atribuição por TTP: ver várias delas juntas é mais informativo do que ver técnicas comuns como PowerShell.

| Técnica | Outros grupos que usam | Peso (raridade) |
|---|---:|---:|
| T1566 Phishing | 7 | 2.99 |
| T1195.002 Compromise Software Supply Chain | 8 | 2.88 |
| T1219 Remote Access Tools | 12 | 2.55 |
| T1199 Trusted Relationship | 13 | 2.48 |
| T1113 Screen Capture | 18 | 2.19 |
| T1133 External Remote Services | 27 | 1.82 |
| T1027.010 Command Obfuscation | 30 | 1.72 |
| T1190 Exploit Public-Facing Application | 46 | 1.32 |
| T1059.001 PowerShell | 85 | 0.72 |

## 5. Arsenal

| Software | Tipo | Técnicas no ATT&CK | Uso relatado (EN) |
|---|---|---:|---|
| [REvil](https://attack.mitre.org/software/S0496/) | malware | 35 |  |
| [ConnectWise](https://attack.mitre.org/software/S0591/) | ferramenta | 3 |  |

## 6. Campanhas

Nenhuma campanha atribuída no ATT&CK.

## 7. Cobertura defensiva

**9 de 9 técnicas (100%)** têm ao menos uma regra pública no catálogo Detection Rules.

### Regras recomendadas por técnica

Melhor regra disponível por técnica (formato portável e maduro primeiro).

| Técnica | Regra | Formato | Fonte |
|---|---|---|---|
| T1027.010 | [Decoded Payload Piped to Interpreter Detected via Defend for Containers](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A0fb83aa0-3d17-41e9-b09c-56397bf7a7d9) | Elastic | Elastic detection-rules |
| T1027.010 | [Potential PowerShell Obfuscation via String Concatenation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Af6d8c743-0916-4483-8333-3c6f107e0caa) | Elastic | Elastic detection-rules |
| T1059.001 | [Potential Emotet Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad02e8cf5-6099-48cf-9bfc-1eec2d0c7b18) | Sigma | SigmaHQ |
| T1059.001 | [TropicTrooper Campaign November 2018](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A8c7090c3-e0a0-4944-bd08-08c3a0cecf79) | Sigma | SigmaHQ |
| T1113 | [PowerShell Suspicious Script with Screenshot Capabilities](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A959a7353-1129-4aa7-9084-30746b256a70) | Elastic | Elastic detection-rules |
| T1113 | [Potential Remote Desktop Shadowing Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ac57f8579-e2a5-4804-847f-f2732edc5156) | Elastic | Elastic detection-rules |
| T1133 | [OpenCanary - SSH Login Attempt](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aff7139bc-fdb1-4437-92f2-6afefe8884cb) | Sigma | SigmaHQ |
| T1133 | [OpenCanary - SSH New Connection Attempt](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acd55f721-5623-4663-bd9b-5229cab5237d) | Sigma | SigmaHQ |
| T1190 | [OMIGOD HTTP No Authentication RCE - CVE-2021-38647](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aab6b1a39-a9ee-4ab4-b075-e83acf6e346b) | Sigma | SigmaHQ |
| T1190 | [Exploited CVE-2020-10189 Zoho ManageEngine](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A846b866e-2a57-46ee-8e16-85fa92759be7) | Sigma | OpenSearch Security Analytics |
| T1195.002 | [Elastic Defend Alert from Package Manager Install Ancestry](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A344e6c7d-ceb0-4f20-ba04-7c75569a7e38) | Elastic | Elastic detection-rules |
| T1195.002 | [Elastic Defend Alert from GenAI Utility or Descendant](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ad4e5f6a7-b8c9-7d0e-1f2a-3b4c5d6e7f8a) | Elastic | Elastic detection-rules |
| T1199 | [Microsoft 365 - User Restricted from Sending Email](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aff246f56-7f24-402a-baca-b86540e3925c) | Sigma | SigmaHQ |
| T1199 | [Microsoft 365 - User Restricted from Sending Email](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Aff246f56-7f24-402a-baca-b86540e3925c) | Sigma | OpenSearch Security Analytics |
| T1219 | [Renamed Visual Studio Code Tunnel Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A2cf29f11-e356-4f61-98c0-1bdb9393d6da) | Sigma | SigmaHQ |
| T1219 | [Hijack Legit RDP Session to Move Laterally](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A52753ea4-b3a0-4365-910d-36cff487b789) | Sigma | OpenSearch Security Analytics |
| T1566 | [CVE-2021-31979 CVE-2021-33771 Exploits by Sourgum](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aad7085ac-92e4-4b76-8ce2-276d2c0e68ef) | Sigma | SigmaHQ |
| T1566 | [CVE-2021-31979 CVE-2021-33771 Exploits](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A32b5db62-cb5f-4266-9639-0fa48376ac00) | Sigma | SigmaHQ |

## 8. Plano de emulação e validação

Use num laboratório isolado e autorizado para confirmar que as regras disparam. Os comandos estão nos repositórios oficiais.

| Tática | Técnica | Teste Atomic Red Team | Plataformas |
|---|---|---|---|
| Initial Access | [T1195.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1195.002/T1195.002.md) | Simulate npm package installation on a Linux system | containers, linux |
| Execution | [T1059.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md) | Mimikatz | windows |
| Execution | [T1059.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md) | Run BloodHound from local disk | windows |
| Persistence | [T1133](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1133/T1133.md) | Running Chrome VPN Extensions via the Registry 2 vpn extension | windows |
| Collection | [T1113](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1113/T1113.md) | Screencapture | macos |
| Collection | [T1113](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1113/T1113.md) | Screencapture (silent) | macos |
| Command and Control | [T1219](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1219/T1219.md) | TeamViewer Files Detected Test on Windows | windows |
| Command and Control | [T1219](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1219/T1219.md) | AnyDesk Files Detected Test on Windows | windows |

**Logs reais de ataque (EVTX) para testar sem executar nada:**

- T1059.001 — [ID4103-4104-Payload download via PowerShell](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1059.001-PowerShell/ID4103-4104-Payload%20download%20via%20PowerShell.evtx) _(explícito)_
- T1059.001 — [ID4688-Encoded PowerShell MSF payload via process execution](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1059.001-PowerShell/ID4688-Encoded%20PowerShell%20MSF%20payload%20via%20process%20execution.evtx) _(explícito)_

## 9. Hipóteses de hunting

Se GOLD SOUTHFIELD estiver no seu ambiente, estas são as perguntas a fazer aos seus dados (fontes de log segundo as estratégias de detecção do MITRE ATT&CK).

1. **T1566 Phishing** — Unusual inbound email activity where attachments or embedded URLs are delivered to users followed by execution of new processes or suspicious document behavior. Detection involves correlating email metadata, file creation, and network activity after a… Dados: `m365:unified` (Send/Receive: Emails with suspicious sender domains, spoofed headers, or anomalous attachment types), `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Sysmon` (EventCode=1).
2. **T1195.002 Compromise Software Supply Chain** — Adversary ships a tampered application or update: an updater/installer (msiexec/setup/update.exe/vendor service) writes or replaces binaries; on first run it spawns scripts/shells or unsigned DLLs and beacons to non-approved update CDNs/hosts. Detection… Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=6), `WinEventLog:Sysmon` (EventCode=7).
3. **T1219 Remote Access Tools** — Chain of remote access tool behavior: (1) initial execution of remote-control/assist agent or GUI under user context; (2) persistence via service or autorun; (3) long-lived outbound connection/tunnel to external infrastructure; (4) interactive control signals… Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:System` (EventCode=7045), `WinEventLog:Sysmon` (EventCode=12).
4. **T1199 Trusted Relationship** — Behavioral chain: (1) a login from a third-party account or untrusted source network establishes an interactive/remote session; (2) the session acquires elevated privileges or accesses sensitive resources atypical for that account; (3) subsequent lateral… Dados: `WinEventLog:Security` (EventCode=4624, 4648), `WinEventLog:Security` (EventCode=4776, 4771, 4770), `WinEventLog:Sysmon` (EventCode=3, 22).
5. **T1113 Screen Capture** — Unusual use of screen capture APIs (e.g., CopyFromScreen) or command-line tools to write image files to disk. Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=7).
6. **T1133 External Remote Services** — Unusual or unauthorized external remote access attempts (e.g., RDP, VPN, Citrix) → repeated failed logins followed by a successful session from uncommon geolocations or outside business hours → subsequent internal lateral movement or data exfiltration… Dados: `WinEventLog:Security` (EventCode=4776, 4625), `WinEventLog:Application` (VPN, Citrix, or remote access gateway logs showing external IP addresses), `WinEventLog:Sysmon` (EventCode=3, 22).
7. **T1027.010 Command Obfuscation** — Detection of command-line activity exhibiting syntactic obfuscation patterns, such as excessive escape characters, base64 encoding, command concatenation, or outlier command length and entropy. Dados: `WinEventLog:Security` (EventCode=4688).
8. **T1190 Exploit Public-Facing Application** — Adversary sends crafted HTTP/S (or other service) input to an Internet-facing app (IIS/ASP.NET, API, device portal). Chain: (1) abnormal request patterns to public endpoint → (2) elevated 4xx/5xx or unusual methods/paths → (3) server process (w3wp.exe/other… Dados: `ApplicationLog:IIS` (IIS W3C logs in C:\inetpub\logs\LogFiles\W3SVC* (spikes in 5xx, RCE/SQLi/path traversal/JNDI patterns)), `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=7).
9. **T1059.001 PowerShell** — Detects behavioral chains where PowerShell is launched with encoded commands, unusual parent processes, or suspicious modules loaded, potentially followed by network connections or child process spawning. Supports detection of both direct (powershell.exe) and… Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:PowerShell` (EventCode=4103, 4104, 4105, 4106), `WinEventLog:PowerShell` (EventCode=400, 403).

## 10. OSINT — onde pesquisar

Consultas prontas com todos os nomes conhecidos do grupo:

- Relatórios técnicos: [busca web](https://duckduckgo.com/?q=%28%22GOLD+SOUTHFIELD%22+OR+%22Pinchy+Spider%22%29+threat+report) · [PDFs](https://duckduckgo.com/?q=%28%22GOLD+SOUTHFIELD%22+OR+%22Pinchy+Spider%22%29+filetype%3Apdf)
- Regras e IOCs publicados: [GitHub](https://github.com/search?type=code&q=%22GOLD+SOUTHFIELD%22+OR+%22Pinchy+Spider%22)
- Pulsos de ameaça: [AlienVault OTX](https://otx.alienvault.com/browse/global/pulses?q=GOLD+SOUTHFIELD)
- Família de malware e atores: [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/actors) (busque por GOLD SOUTHFIELD, Pinchy Spider)
- Cartões de grupo: [ThaiCERT Threat Group Cards](https://apt.etda.or.th/cgi-bin/listgroups.cgi)
- Página oficial: [MITRE ATT&CK G0115](https://attack.mitre.org/groups/G0115/)

## 11. Bibliografia (6 fontes citadas pelo ATT&CK)

- [Anomali Static Kitten February 2021](https://www.anomali.com/blog/probable-iranian-cyber-actors-static-kitten-conducting-cyberespionage-campaign-targeting-uae-and-kuwait-government-agencies) — Mele, G. et al. (2021, February 10). Probable Iranian Cyber Actors, Static Kitten, Conducting Cyberespionage Campaign Targeting UAE and Kuwait Government Agencies. Retrieved March 17, 2021.
- [CrowdStrike Evolution of Pinchy Spider July 2021](https://www.crowdstrike.com/blog/the-evolution-of-revil-ransomware-and-pinchy-spider/) — Meyers, Adam. (2021, July 6). The Evolution of PINCHY SPIDER from GandCrab to REvil. Retrieved March 28, 2023.
- [Secureworks GandCrab and REvil September 2019](https://www.secureworks.com/blog/revil-the-gandcrab-connection) — Secureworks . (2019, September 24). REvil: The GandCrab Connection. Retrieved August 4, 2020.
- [Secureworks GOLD SOUTHFIELD](https://www.secureworks.com/research/threat-profiles/gold-southfield) — Secureworks. (n.d.). GOLD SOUTHFIELD. Retrieved October 6, 2020.
- [Secureworks REvil September 2019](https://www.secureworks.com/research/revil-sodinokibi-ransomware) — Counter Threat Unit Research Team. (2019, September 24). REvil/Sodinokibi Ransomware. Retrieved August 4, 2020.
- [Tetra Defense Sodinokibi March 2020](https://web.archive.org/web/20210414101816/https://tetradefense.com/incident-response-services/cause-and-effect-sodinokibi-ransomware-analysis/) — Tetra Defense. (2020, March). CAUSE AND EFFECT: SODINOKIBI RANSOMWARE ANALYSIS. Retrieved November 17, 2024.

## 12. Limites e confiança

- O ATT&CK registra o que foi **relatado publicamente**, não tudo o que o grupo faz. Ausência de uma técnica não prova que o grupo não a usa.
- **Sobreposição de TTP não é atribuição.** Muitas técnicas são compartilhadas entre grupos e com red teams. Use a assinatura comportamental como hipótese, junto com infraestrutura, malware e contexto.
- Cobertura de detecção refere-se ao catálogo público Detection Rules, não ao seu ambiente: confira se a telemetria necessária chega ao seu SIEM.
- Ligações marcadas como _inferidas_ (EVTX por palavra-chave, relatórios por nome) devem ser verificadas.

---
Fontes: MITRE ATT&CK® (uso livre com atribuição, © The MITRE Corporation), Atomic Red Team (Red Canary, MIT), EVTX-to-MITRE-Attack, EVTX-ATTACK-SAMPLES, APT & CyberCriminal Campaign Collections. Gerado por [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules).
