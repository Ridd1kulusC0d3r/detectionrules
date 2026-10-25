# VOID MANTICORE (G1055) — Dossiê de inteligência

> **TLP:CLEAR** · gerado em 2026-10-25 a partir de fontes abertas · MITRE ATT&CK v20.0 · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1055) · [ATT&CK](https://attack.mitre.org/groups/G1055/)

**Também conhecido como:** COBALT MYSTIQUE, Handala Hack, Homeland Justice, Karma, Karmabelow80, BANISHED KITTEN, Red Sandstorm  
**Registro no ATT&CK:** criado em 2026-04-20, atualizado em 2026-07-31 · referências de 2026 a 2026

## 1. Sumário executivo

- **63 técnicas** atribuídas publicamente, concentradas em **Collection, Stealth, Resource Development**.
- **Arsenal:** 0 malware e 0 ferramentas.
- **Campanhas atribuídas:** 1 (HomeLand Justice).
- **Cobertura de detecção pública:** 94% das técnicas têm ao menos uma regra no catálogo; **4 técnicas sem nenhuma regra pública**.
- **Assinatura comportamental** (técnicas raras entre os 178 grupos, as mais úteis para atribuição): T1679 Selective Exclusion, T1110.004 Credential Stuffing, T1123 Audio Capture, T1651 Cloud Administration Command, T1552.002 Credentials in Registry.

## 2. Quem é

> VOID MANTICORE is a threat group assessed to operate on behalf of Iran’s Ministry of Intelligence and Security (MOIS). Active since at least mid-2022, VOID MANTICORE has targeted government entities, critical infrastructure, and private sector organizations across Albania, Israel, and the United States. VOID MANTICORE conducts destructive cyber operations, combining wiper attacks with hack-and-leak campaigns. The group has operated under multiple public-facing personas, including HomeLand Justice in operations against Albania, Karma and Karma Below in campaigns targeting Israeli organizations, and Handala Hack, its current primary persona, which has claimed activity against Israeli and U.S. entities, including a March 2026 attack against Stryker Corporation. VOID MANTICORE has been observed collaborating with Scarred Manticore, which has been linked to initial access operations preceding VOID MANTICORE’s activity.

_Texto original do MITRE ATT&CK, em inglês._

## 3. Perfil TTP por tática (kill chain)

Cada linha: técnica, como o grupo a usou segundo relatos públicos, e o que existe para detectar e testar.

### Reconnaissance (TA0043) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1589](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1589) Gather Victim Identity Information | VOID MANTICORE has gathered details on their intended victims to aid in social engineering efforts for leveraging tailored themes of attacks. | 11 | — | — |
| [T1595.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1595.002) Vulnerability Scanning | VOID MANTICORE has scanned victim environments for susceptibility to vulnerability exploitation. | 27 | — | — |

### Resource Development (TA0042) — 9

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1583.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1583.001) Domains | VOID MANTICORE has registered domains for messaging purposes. VOID MANTICORE has created typosquatted domains and sub-domains in attempts to avoid detection or draw suspicion. VOID MANTICORE has also purchased domains leveraging cryptocurrency platforms to inc… | 7 | — | — |
| [T1583.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1583.003) Virtual Private Server | VOID MANTICORE has utilized VPS solutions for C2. | **0** | — | — |
| [T1583.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1583.004) Server | VOID MANTICORE has leveraged backend servers within Iran. | **0** | — | — |
| [T1583.006](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1583.006) Web Services | VOID MANTICORE has obtained access to commercial VPN services to launch malicious activity. VOID MANTICORE has also leveraged Starlink internet services. VOID MANTICORE has used operator-controlled Telegram bots and channels as C2 infrastructure. | 2 | — | — |
| [T1585.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1585.001) Social Media Accounts | VOID MANTICORE has created Telegram Accounts. VOID MANTICORE has also leveraged online personas such as Handala Hack, Karma, and Homeland Justice on social media to include Telegram. VOID MANTICORE has established and maintained social media accounts on Twitte… | 4 | — | — |
| [T1585.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1585.002) Email Accounts | VOID MANTICORE has created email accounts to send threatening messages to victims to include ‘Handala_Team[@]outlook[.]com’. | **0** | — | — |
| [T1587.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1587.001) Malware | VOID MANTICORE has utilized custom-malware and wipers to include BiBi Wiper. | 43 | — | — |
| [T1588.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1588.001) Malware | VOID MANTICORE has developed or obtained trojanized applications used for persistent surveillance of targeted individuals. | 7 | — | — |
| [T1588.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1588.002) Tool | VOID MANTICORE has obtained and utilized commercial VPN services, open-source software and publicly available offensive security tools to facilitate malicious activities. | 35 | — | — |

### Initial Access (TA0001) — 7

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | VOID MANTICORE has leveraged valid accounts to log into VPN infrastructure. VOID MANTICORE has used compromised valid credentials to gain access to management infrastructure and enterprise control systems. VOID MANTICORE has also validated and tested authentic… | 825 | — | 3 |
| [T1078.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.002) Domain Accounts | VOID MANTICORE has used previously compromised Domain Administrator credentials to maintain persistent access. | 36 | — | 1 |
| [T1078.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.004) Cloud Accounts | VOID MANTICORE has leveraged privileged cloud accounts to access cloud-based management consoles to include Microsoft Intune. VOID MANTICORE has also compromised existing accounts within the Microsoft Entra ID environment. | 356 | 3 | — |
| [T1133](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1133) External Remote Services | VOID MANTICORE has leveraged public facing VPN infrastructure to gain initial access to victim environments. | 361 | 1 | — |
| [T1190](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1190) Exploit Public-Facing Application | VOID MANTICORE has exploited public facing vulnerabilities within victim environments to include SharePoint CVE-2019-0604. | 580 | — | — |
| [T1199](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1199) Trusted Relationship | VOID MANTICORE has targeted IT and service providers in an effort to obtain credentials, relying largely on compromised VPN accounts for initial access. | 18 | — | — |
| [T1566](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1566) Phishing | VOID MANTICORE has emailed victims threatening messages. VOID MANTICORE has used phishing as an initial access vector. | 286 | — | — |

### Execution (TA0002) — 6

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1047](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1047) Windows Management Instrumentation | VOID MANTICORE has utilized WMIC to log into the victim host and create a process `process call create “cmd.exe /c copy \\?\\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\windows\system32\config\system c:\users\public”`. | 370 | 12 | 11 |
| [T1059.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.001) PowerShell | VOID MANTICORE has utilized PowerShell to execute malware in victim environments. | 1340 | 22 | 15 |
| [T1059.006](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.006) Python | VOID MANTICORE has utilized Python scripts to execute its malicious payloads. | 122 | — | — |
| [T1072](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1072) Software Deployment Tools | VOID MANTICORE has leveraged legitimate built-in features of cloud-based management platforms to include mobile device management (MDM) and Remote Monitoring and Management (RMM) solutions. VOID MANTICORE has also initiated built-in remote wipe instructions us… | 59 | 3 | — |
| [T1204.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1204.002) Malicious File | VOID MANTICORE has delivered malicious payloads that initiate through user execution to include interaction with a masqueraded file. VOID MANTICORE has used trojanized application lures to induce targets into executing malware enabling persistent surveillance. | 259 | 13 | — |
| [T1651](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1651) Cloud Administration Command | VOID MANTICORE has abused built-in remote wipe or factory reset commands to wipe devices managed within an organization’s Cloud management solution impacting laptops, servers, and mobile devices. | 20 | 1 | — |

### Persistence (TA0003) — 6

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | VOID MANTICORE has leveraged valid accounts to log into VPN infrastructure. VOID MANTICORE has used compromised valid credentials to gain access to management infrastructure and enterprise control systems. VOID MANTICORE has also validated and tested authentic… | 825 | — | 3 |
| [T1078.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.002) Domain Accounts | VOID MANTICORE has used previously compromised Domain Administrator credentials to maintain persistent access. | 36 | — | 1 |
| [T1078.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.004) Cloud Accounts | VOID MANTICORE has leveraged privileged cloud accounts to access cloud-based management consoles to include Microsoft Intune. VOID MANTICORE has also compromised existing accounts within the Microsoft Entra ID environment. | 356 | 3 | — |
| [T1098](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1098) Account Manipulation | VOID MANTICORE has leveraged access to administrative control systems to achieve disruptive effects, consistent with administrative account abuse or privilege escalation within existing access. | 535 | 17 | 30 |
| [T1133](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1133) External Remote Services | VOID MANTICORE has leveraged public facing VPN infrastructure to gain initial access to victim environments. | 361 | 1 | — |
| [T1547.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1547.001) Registry Run Keys / Startup Folder | VOID MANTICORE has created Windows Registry entries to autorun stage two malware payloads to maintain persistence. | 299 | 21 | 2 |

### Privilege Escalation (TA0004) — 6

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | VOID MANTICORE has leveraged valid accounts to log into VPN infrastructure. VOID MANTICORE has used compromised valid credentials to gain access to management infrastructure and enterprise control systems. VOID MANTICORE has also validated and tested authentic… | 825 | — | 3 |
| [T1078.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.002) Domain Accounts | VOID MANTICORE has used previously compromised Domain Administrator credentials to maintain persistent access. | 36 | — | 1 |
| [T1078.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.004) Cloud Accounts | VOID MANTICORE has leveraged privileged cloud accounts to access cloud-based management consoles to include Microsoft Intune. VOID MANTICORE has also compromised existing accounts within the Microsoft Entra ID environment. | 356 | 3 | — |
| [T1098](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1098) Account Manipulation | VOID MANTICORE has leveraged access to administrative control systems to achieve disruptive effects, consistent with administrative account abuse or privilege escalation within existing access. | 535 | 17 | 30 |
| [T1484.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1484.001) Group Policy Modification | VOID MANTICORE had utilized Group Policy logon scripts to distribute the malicious payloads to victim devices through the execution of a batch file. | 47 | 2 | 1 |
| [T1547.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1547.001) Registry Run Keys / Startup Folder | VOID MANTICORE has created Windows Registry entries to autorun stage two malware payloads to maintain persistence. | 299 | 21 | 2 |

### Stealth (TA0005) — 9

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1027.015](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1027.015) Compression | VOID MANTICORE has compressed their payloads by leveraging zip files. | 3 | — | — |
| [T1036.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1036.004) Masquerade Task or Service | VOID MANTICORE has masqueraded as commonly used programs and services on Windows hosts. | 31 | 4 | — |
| [T1036.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1036.005) Match Legitimate Resource Name or Location | VOID MANTICORE has masqueraded malicious payloads to resemble legitimate applications. VOID MANTICORE has leveraged malicious payloads that use nomenclature associated with common applications that include Pictory, KeePass, WhatsApp, and Telegram. | 116 | 4 | — |
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | VOID MANTICORE has leveraged valid accounts to log into VPN infrastructure. VOID MANTICORE has used compromised valid credentials to gain access to management infrastructure and enterprise control systems. VOID MANTICORE has also validated and tested authentic… | 825 | — | 3 |
| [T1078.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.002) Domain Accounts | VOID MANTICORE has used previously compromised Domain Administrator credentials to maintain persistent access. | 36 | — | 1 |
| [T1078.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.004) Cloud Accounts | VOID MANTICORE has leveraged privileged cloud accounts to access cloud-based management consoles to include Microsoft Intune. VOID MANTICORE has also compromised existing accounts within the Microsoft Entra ID environment. | 356 | 3 | — |
| [T1564.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1564.003) Hidden Window | VOID MANTICORE has utilized PowerShell scripts that run without notifying the user of its execution to include `-nop -w hidden- ep bypass -enc`. | 51 | 3 | — |
| [T1679](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1679) Selective Exclusion | VOID MANTICORE has avoided interacting with specific directories in order to reduce the likelihood of detection. | **0** | — | — |
| [T1684.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1684.001) Impersonation | VOID MANTICORE has impersonated individuals familiar to the victim and technical support associated with social messaging services. | 1 | — | — |

### Defense Impairment (TA0112) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1484.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1484.001) Group Policy Modification | VOID MANTICORE had utilized Group Policy logon scripts to distribute the malicious payloads to victim devices through the execution of a batch file. | 47 | 2 | 1 |
| [T1686.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1686.003) Windows Host Firewall | VOID MANTICORE has disabled Windows Defender protections to allow for follow-on activities within the compromised host. | 64 | 2 | — |

### Credential Access (TA0006) — 5

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1003.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1003.001) LSASS Memory | VOID MANTICORE has dumped LSASS credentials using `comsvcs.dll` via `rundll32.exe`. | 580 | 14 | 10 |
| [T1110](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1110) Brute Force | VOID MANTICORE has conducted brute-force attempts against organizational VPN infrastructure. | 381 | — | 12 |
| [T1110.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1110.001) Password Guessing | VOID MANTICORE has conducted password guessing to gain initial access. | 63 | 8 | — |
| [T1110.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1110.004) Credential Stuffing | VOID MANTICORE has utilized credential stuffing attacks to obtain initial access to victim environments. | 35 | 4 | — |
| [T1552.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1552.002) Credentials in Registry | VOID MANTICORE had exported credentials from registry hives to include those stored in HKLM. | 28 | 2 | — |

### Discovery (TA0007) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1082](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1082) System Information Discovery | VOID MANTICORE has gathered system information and disseminated it back to C2. | 264 | 41 | — |
| [T1087.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1087.002) Domain Account | VOID MANTICORE has utilized ADRecon to enumerate the active directory environment. | 180 | 25 | 1 |

### Lateral Movement (TA0008) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1021.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1021.001) Remote Desktop Protocol | VOID MANTICORE has used RDP to move laterally within the victim environment. | 139 | 4 | 7 |
| [T1072](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1072) Software Deployment Tools | VOID MANTICORE has leveraged legitimate built-in features of cloud-based management platforms to include mobile device management (MDM) and Remote Monitoring and Management (RMM) solutions. VOID MANTICORE has also initiated built-in remote wipe instructions us… | 59 | 3 | — |

### Collection (TA0009) — 9

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1005) Data from Local System | VOID MANTICORE has collected cached data and files from within the victim environment. | 170 | 3 | — |
| [T1074](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1074) Data Staged | VOID MANTICORE has staged compressed files in specified locations prior to exfiltration over C2. | 40 | — | — |
| [T1113](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1113) Screen Capture | VOID MANTICORE has captured screen content during an active Zoom session. | 60 | 10 | — |
| [T1114.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1114.002) Remote Email Collection | VOID MANTICORE has gathered victim email-content from victim servers. | 11 | 1 | — |
| [T1119](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1119) Automated Collection | VOID MANTICORE conducted large-scale data exfiltration in the Stryker operation, consistent with automated or scripted collection against enterprise systems. | 72 | 4 | — |
| [T1123](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1123) Audio Capture | VOID MANTICORE has gathered audio during a Zoom session. | 34 | 3 | — |
| [T1125](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1125) Video Capture | VOID MANTICORE has collected video from compromised victim devices. | 13 | 1 | 1 |
| [T1213.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1213.002) Sharepoint | VOID MANTICORE has accessed victim’s public facing SharePoint servers and exfiltrated data. | 7 | — | — |
| [T1560.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1560.001) Archive via Utility | VOID MANTICORE has stored collected data in a password protected compressed file prior to exfiltration. | 76 | 13 | — |

### Command and Control (TA0011) — 5

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1071.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1071.001) Web Protocols | VOID MANTICORE has utilized HTTPS for communication to C2 domains. | 228 | 3 | — |
| [T1102](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1102) Web Service | VOID MANTICORE has utilized Telegram API for C2. | 98 | — | — |
| [T1105](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1105) Ingress Tool Transfer | VOID MANTICORE has deployed additional payloads from dedicated C2 servers. VOID MANTICORE has also downloaded legitimate tools and software from publicly available services. VOID MANTICORE had utilized VeraCrypt a legitimate disk encrypting utility that was do… | 644 | 39 | — |
| [T1219.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1219.002) Remote Desktop Software | VOID MANTICORE has installed NetBird on victim devices to create a mesh network that facilitated control of several victim devices at once. | 221 | — | — |
| [T1572](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1572) Protocol Tunneling | VOID MANTICORE has used tunneling tools to facilitate destructive attacks on compromised devices. | 173 | 9 | 1 |

### Exfiltration (TA0010) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1041](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1041) Exfiltration Over C2 Channel | VOID MANTICORE malware has exfiltrated collected data via Telegram bot C2 channels using encrypted communications. | 135 | 2 | — |

### Impact (TA0040) — 6

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1485](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1485) Data Destruction | VOID MANTICORE has conducted data wiping attacks on compromised systems. VOID MANTICORE has also manually deleted files from compromised hosts, to include selecting all files and then deleting them. | 215 | 5 | — |
| [T1486](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1486) Data Encrypted for Impact | VOID MANTICORE has utilized legitimate disk encryption utilities to increase likelihood of encrypting system drives and reduce system recovery efforts. | 160 | 10 | 1 |
| [T1490](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1490) Inhibit System Recovery | VOID MANTICORE has deleted virtual machines directly from the virtualization platform. | 188 | 13 | 5 |
| [T1561.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1561.001) Disk Content Wipe | VOID MANTICORE has utilized a disk wiping utility to facilitate destructive actions on victim servers. VOID MANTICORE has also utilized legitimate remote disk wiping commands. | 6 | — | — |
| [T1561.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1561.002) Disk Structure Wipe | VOID MANTICORE has deployed custom wipers that overwrite system files and the host devices master boot records (MBR) to corrupt or destroy files. | 2 | — | — |
| [T1657](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1657) Financial Theft | VOID MANTICORE has conducted data exfiltration and posted stolen information on data leak sites for the purposes of financial and political extortion. VOID MANTICORE has also sold stolen data to prospective buyers for cryptocurrency. | 2 | — | — |

## 4. Assinatura comportamental

Técnicas que este grupo usa e que poucos dos 178 grupos do ATT&CK usam. Pesam mais numa atribuição por TTP: ver várias delas juntas é mais informativo do que ver técnicas comuns como PowerShell.

| Técnica | Outros grupos que usam | Peso (raridade) |
|---|---:|---:|
| T1679 Selective Exclusion | 0 | 4.49 |
| T1110.004 Credential Stuffing | 1 | 4.09 |
| T1123 Audio Capture | 1 | 4.09 |
| T1651 Cloud Administration Command | 1 | 4.09 |
| T1552.002 Credentials in Registry | 2 | 3.80 |
| T1561.001 Disk Content Wipe | 2 | 3.80 |
| T1110.001 Password Guessing | 3 | 3.58 |
| T1125 Video Capture | 3 | 3.58 |
| T1074 Data Staged | 4 | 3.40 |
| T1484.001 Group Policy Modification | 4 | 3.40 |

## 5. Arsenal

Nenhum software atribuído no ATT&CK.

## 6. Campanhas

| Campanha | Período | Resumo (EN) |
|---|---|---|
| [HomeLand Justice](https://attack.mitre.org/campaigns/C0038/) | 2021-05 → 2022-09 | HomeLand Justice was a disruptive cyber campaign conducted by Iranian state-affiliated actors against Albanian government networks in July and September 2022. The activity combined ransomware, wiper malware, and data lea |

## 7. Cobertura defensiva

**59 de 63 técnicas (94%)** têm ao menos uma regra pública no catálogo Detection Rules.

### Técnicas sem regra pública (prioridade para engenharia de detecção)

- **T1679 Selective Exclusion** — Stealth. Fonte de log sugerida pelo MITRE: `WinEventLog:PowerShell` EventCode=4103, 4104, 4105, 4106
- **T1583.004 Server** — Resource Development. Fonte de log sugerida pelo MITRE: `Internet Scan` None
- **T1583.003 Virtual Private Server** — Resource Development. Fonte de log sugerida pelo MITRE: `Internet Scan` None
- **T1585.002 Email Accounts** — Resource Development

### Regras recomendadas por técnica

Melhor regra disponível por técnica (formato portável e maduro primeiro).

| Técnica | Regra | Formato | Fonte |
|---|---|---|---|
| T1003.001 | [Antivirus - Password Dumper Signature](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A78cc2dd2-7d20-4d32-93ff-057084c38b93) | Sigma | SigmaHQ |
| T1003.001 | [Mimikatz through Windows Remote Management](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Aaa35a627-33fb-4d04-a165-d33b4afca3e8) | Sigma | OpenSearch Security Analytics |
| T1005 | [Potential Conti Ransomware Database Dumping Activity Via SQLCmd](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A2f47f1fd-0901-466e-a770-3b7092834a1b) | Sigma | SigmaHQ |
| T1005 | [OpenCanary - SMB File Open Request](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A22777c9e-873a-4b49-855f-6072ab861a52) | Sigma | SigmaHQ |
| T1021.001 | [Hermetic Wiper TG Process Patterns](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A2f974656-6d83-4059-bbdf-68ac5403422f) | Sigma | SigmaHQ |
| T1021.001 | [Publicly Accessible RDP Service](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1fc0809e-06bf-4de3-ad52-25e5263b7623) | Sigma | SigmaHQ |
| T1027.015 | [PowerShell Suspicious Payload Encoded and Compressed](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A81fe9dc6-a2d7-4192-a2d8-eed98afc766a) | Elastic | Elastic detection-rules |
| T1027.015 | [Suspicious Content Extracted or Decompressed via Funzip](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Adc0b7782-0df0-47ff-8337-db0d678bdb66) | Elastic | Elastic detection-rules |
| T1036.004 | [Operation Wocao Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1cfac73c-be78-4f9a-9b08-5bde0c3953ab) | Sigma | SigmaHQ |
| T1036.004 | [Operation Wocao Activity - Security](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A74ad4314-482e-4c3e-b237-3f7ed3b9ca8d) | Sigma | SigmaHQ |
| T1036.005 | [Exploit for CVE-2015-1641](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A7993792c-5ce2-4475-a3db-a3a5539827ef) | Sigma | SigmaHQ |
| T1036.005 | [Exploit for CVE-2015-1641](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A7993792c-5ce2-4475-a3db-a3a5539827ef) | Sigma | OpenSearch Security Analytics |
| T1041 | [Equation Group C2 Communication](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A881834a4-6659-4773-821e-1c151789d873) | Sigma | SigmaHQ |
| T1041 | [OpenCanary - TFTP Request](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab4e6b016-a2ac-4759-ad85-8000b300d61e) | Sigma | SigmaHQ |
| T1047 | [HackTool - Potential Impacket Lateral Movement Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A10c14723-61c7-4c75-92ca-9af245723ad2) | Sigma | SigmaHQ |
| T1047 | [CrackMapExec Command Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A058f4380-962d-40a5-afce-50207d36d7e2) | Sigma | OpenSearch Security Analytics |
| T1059.001 | [Potential Emotet Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad02e8cf5-6099-48cf-9bfc-1eec2d0c7b18) | Sigma | SigmaHQ |
| T1059.001 | [TropicTrooper Campaign November 2018](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A8c7090c3-e0a0-4944-bd08-08c3a0cecf79) | Sigma | SigmaHQ |
| T1059.006 | [Emotet Loader Execution Via .LNK File](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1f32d820-1d5c-43fe-8fe2-feef0c952eb7) | Sigma | SigmaHQ |
| T1059.006 | [Serpent Backdoor Payload Execution Via Scheduled Task](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad5eb7432-fda4-4bba-a37f-ffa74d9ed639) | Sigma | SigmaHQ |
| T1071.001 | [Ursnif Malware Download URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aa36ce77e-30db-4ea0-8795-644d7af5dfb4) | Sigma | SigmaHQ |
| T1071.001 | [Ursnif Malware C2 URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A932ac737-33ca-4afd-9869-0d48b391fcc9) | Sigma | SigmaHQ |
| T1072 | [Restricted Software Access By SRP](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab4c8da4a-1c12-46b0-8a2b-0a8521d03442) | Sigma | SigmaHQ |
| T1072 | [Suspicious Curl to Jamf Endpoint](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Aa8256685-9736-465b-b159-f25a172d08e8) | Elastic | Elastic detection-rules |
| T1074 | [Sensitive File Access followed by Compression](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Aa0fbd7a9-1923-4e05-92df-b484168f17bc) | Elastic | Elastic detection-rules |
| T1074 | [Cisco Stage Data](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A5e51acb2-bcbe-435b-99c6-0e3cd5e2aa59) | Sigma | SigmaHQ |
| T1078 | [Privilege Role Sign-In Outside Expected Controls](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acf1e5687-84e1-41af-97a9-158094efef53) | Sigma | SigmaHQ |
| T1078 | [OpenCanary - SSH Login Attempt](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aff7139bc-fdb1-4437-92f2-6afefe8884cb) | Sigma | SigmaHQ |
| T1078.002 | [Malicious Usage Of IMDS Credentials Outside Of AWS Infrastructure](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A352a918a-34d8-4882-8470-44830c507aa3) | Sigma | SigmaHQ |
| T1078.002 | [AdminSDHolder SDProp Exclusion Added](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A61d29caf-6c15-4d1e-9ccb-7ad12ccc0bc7) | Elastic | Elastic detection-rules |
| T1078.004 | [Okta New Admin Console Behaviours](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aa0b38b70-3cb5-484b-a4eb-c4d8e7bcc0a9) | Sigma | SigmaHQ |
| T1078.004 | [AWS IAM S3Browser User or AccessKey Creation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Adb014773-d9d9-4792-91e5-133337c0ffee) | Sigma | SigmaHQ |
| T1082 | [Potential GobRAT File Discovery Via Grep](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae34cfa0c-0a50-4210-9cb3-5632d08eb041) | Sigma | SigmaHQ |
| T1082 | [System Information Discovery](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A42df45e7-e6e9-43b5-8f26-bec5b39cc239) | Sigma | SigmaHQ |
| T1087.002 | [BloodHound Collection Files](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A02773bed-83bf-469f-b7ff-e676e7d78bab) | Sigma | SigmaHQ |
| T1087.002 | [Suspicious Active Directory Database Snapshot Via ADExplorer](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aef61af62-bc74-4f58-b49b-626448227652) | Sigma | SigmaHQ |
| T1098 | [Password Change on Directory Service Restore Mode (DSRM) Account](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A53ad8e36-f573-46bf-97e4-15ba5bf4bb51) | Sigma | SigmaHQ |
| T1098 | [User Added To Global Domain Admins Grp](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=hayabusa-native%3A%3A4bb89c86-a138-42a0-baaf-fc2f777a4506) | Sigma | Hayabusa (native) |
| T1102 | [Communication To LocaltoNet Tunneling Service Initiated - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac4568f5d-131f-4e78-83d4-45b2da0ec4f1) | Sigma | SigmaHQ |
| T1102 | [Communication To Ngrok Tunneling Service - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A19bf6fdb-7721-4f3d-867f-53467f6a5db6) | Sigma | SigmaHQ |
| T1105 | [Greenbug Espionage Group Indicators](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A3711eee4-a808-4849-8a14-faf733da3612) | Sigma | SigmaHQ |
| T1105 | [Pandemic Registry Key](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A47e0852a-cf81-4494-a8e6-31864f8c86ed) | Sigma | SigmaHQ |
| T1110 | [Hack Tool User Agent](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac42a3073-30fb-48ae-8c99-c23ada84b103) | Sigma | SigmaHQ |
| T1110 | [HackTool - CrackMapExec Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A42a993dd-bb3e-48c8-b372-4d6684c4106c) | Sigma | SigmaHQ |
| T1110.001 | [HackTool - Hydra Password Bruteforce Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aaaafa146-074c-11eb-adc1-0242ac120002) | Sigma | SigmaHQ |
| T1110.001 | [Hydra Password Guessing Hack Tool](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Aaaafa146-074c-11eb-adc1-0242ac120002) | Sigma | OpenSearch Security Analytics |
| T1110.004 | [Multiple SonicWall Login Failures Followed by Successful Login](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Aefe7ac71-3b13-41cf-8263-30af68ce3f19) | Elastic | Elastic detection-rules |
| T1110.004 | [Okta Successful Login After Credential Attack](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A50742e15-c5ef-49c8-9a2d-31221d45af58) | Elastic | Elastic detection-rules |
| T1113 | [PowerShell Suspicious Script with Screenshot Capabilities](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A959a7353-1129-4aa7-9084-30746b256a70) | Elastic | Elastic detection-rules |
| T1113 | [Potential Remote Desktop Shadowing Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ac57f8579-e2a5-4804-847f-f2732edc5156) | Elastic | Elastic detection-rules |
| T1114.002 | [Microsoft Graph Email Access by Unusual User and Client](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ae882e934-2aaa-11f0-8272-f661ea17fbcc) | Elastic | Elastic detection-rules |
| T1114.002 | [M365 Exchange Mailbox Accessed by Unusual Client](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A48819484-9826-4083-9eba-1da74cd0eaf2) | Elastic | Elastic detection-rules |
| T1119 | [iOS Implant URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Ae06ac91d-b9e6-443d-8e5b-af749e7aa6b6) | Sigma | OpenSearch Security Analytics |
| T1119 | [Shai-Hulud Malicious GitHub Workflow Creation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A0aba5685-6db6-486f-88ef-29a99c545cfd) | Sigma | SigmaHQ |
| T1123 | [OpenCanary - SIP Request](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae30de276-68ec-435c-ab99-ef3befec6c61) | Sigma | SigmaHQ |
| T1123 | [Suspicious Camera and Microphone Access](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A62120148-6b7a-42be-8b91-271c04e281a3) | Sigma | SigmaHQ |
| T1125 | [Suspicious Camera and Microphone Access](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A62120148-6b7a-42be-8b91-271c04e281a3) | Sigma | SigmaHQ |
| T1125 | [Suspicious Camera and Microphone Access](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A62120148-6b7a-42be-8b91-271c04e281a3) | Sigma | OpenSearch Security Analytics |
| T1133 | [OpenCanary - SSH Login Attempt](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aff7139bc-fdb1-4437-92f2-6afefe8884cb) | Sigma | SigmaHQ |
| T1133 | [OpenCanary - SSH New Connection Attempt](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acd55f721-5623-4663-bd9b-5229cab5237d) | Sigma | SigmaHQ |
| T1190 | [OMIGOD HTTP No Authentication RCE - CVE-2021-38647](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aab6b1a39-a9ee-4ab4-b075-e83acf6e346b) | Sigma | SigmaHQ |
| T1190 | [Exploited CVE-2020-10189 Zoho ManageEngine](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A846b866e-2a57-46ee-8e16-85fa92759be7) | Sigma | OpenSearch Security Analytics |
| T1199 | [Microsoft 365 - User Restricted from Sending Email](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aff246f56-7f24-402a-baca-b86540e3925c) | Sigma | SigmaHQ |
| T1199 | [Microsoft 365 - User Restricted from Sending Email](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Aff246f56-7f24-402a-baca-b86540e3925c) | Sigma | OpenSearch Security Analytics |
| T1204.002 | [Ursnif Malware C2 URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A932ac737-33ca-4afd-9869-0d48b391fcc9) | Sigma | SigmaHQ |
| T1204.002 | [Droppers Exploiting CVE-2017-11882](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A678eb5f4-8597-4be6-8be7-905e4234b53a) | Sigma | SigmaHQ |
| T1213.002 | [M365 SharePoint/OneDrive File Access via PowerShell](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A491651da-125b-11f1-af7d-f661ea17fbce) | Elastic | Elastic detection-rules |
| T1213.002 | [Entra ID Sharepoint or OneDrive Accessed by Unusual Client](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Aa3cc60d8-2701-11f0-accf-f661ea17fbcd) | Elastic | Elastic detection-rules |
| T1219.002 | [Antivirus - Exploitation Framework Signature](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A238527ad-3c2c-4e4f-a1f6-92fd63adb864) | Sigma | SigmaHQ |
| T1219.002 | [Potential SocGholish Second Stage C2 DNS Query](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A70761fe8-6aa2-4f80-98c1-a57049c08e66) | Sigma | SigmaHQ |
| T1484.001 | [Group Policy Abuse for Privilege Addition](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ab9554892-5e0e-424b-83a0-5aef95aa43bf) | Elastic | Elastic detection-rules |
| T1484.001 | [Modify Group Policy Settings](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aada4b0c4-758b-46ac-9033-9004613a150d) | Sigma | SigmaHQ |
| T1485 | [Fsutil Suspicious Invocation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aadd64136-62e5-48ea-807e-88638d02df1e) | Sigma | SigmaHQ |
| T1485 | [Potential BlackByte Ransomware Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A999e8307-a775-4d5f-addc-4855632335be) | Sigma | SigmaHQ |
| T1486 | [LockerGoga Ransomware Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A74db3488-fd28-480a-95aa-b7af626de068) | Sigma | SigmaHQ |
| T1486 | [LockerGoga Ransomware](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A74db3488-fd28-480a-95aa-b7af626de068) | Sigma | OpenSearch Security Analytics |
| T1490 | [Potential Dtrack RAT Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Af1531fa4-5b84-4342-8f68-9cf3fdbd83d4) | Sigma | SigmaHQ |
| T1490 | [Boot Configuration Tampering Via Bcdedit.EXE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1444443e-6757-43e4-9ea4-c8fc705f79a2) | Sigma | SigmaHQ |
| T1547.001 | [Potential Ryuk Ransomware Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac37510b8-2107-4b78-aa32-72f251e7a844) | Sigma | SigmaHQ |
| T1547.001 | [Ryuk Ransomware](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Ac37510b8-2107-4b78-aa32-72f251e7a844) | Sigma | OpenSearch Security Analytics |
| T1552.002 | [SAM Registry Hive Handle Request](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Af8748f2c-89dc-4d95-afb0-5a2dfdbad332) | Sigma | SigmaHQ |
| T1552.002 | [SAM Registry Hive Handle Request](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Af8748f2c-89dc-4d95-afb0-5a2dfdbad332) | Sigma | OpenSearch Security Analytics |
| T1560.001 | [APT31 Judgement Panda Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A03e2746e-2b31-42f1-ab7a-eb39365b2422) | Sigma | SigmaHQ |
| T1560.001 | [Suspicious Manipulation Of Default Accounts Via Net.EXE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A5b768e71-86f2-4879-b448-81061cbae951) | Sigma | SigmaHQ |
| T1561.001 | [Cisco File Deletion](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A71d65515-c436-43c0-841b-236b1f32c21e) | Sigma | SigmaHQ |
| T1561.001 | [Cisco File Deletion](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A71d65515-c436-43c0-841b-236b1f32c21e) | Sigma | OpenSearch Security Analytics |
| T1561.002 | [Cisco File Deletion](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A71d65515-c436-43c0-841b-236b1f32c21e) | Sigma | SigmaHQ |
| T1561.002 | [Cisco File Deletion](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A71d65515-c436-43c0-841b-236b1f32c21e) | Sigma | OpenSearch Security Analytics |
| T1564.003 | [Potential Data Stealing Via Chromium Headless Debugging](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A3e8207c5-fcd2-4ea6-9418-15d45b4890e4) | Sigma | SigmaHQ |
| T1564.003 | [HackTool - Covenant PowerShell Launcher](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac260b6db-48ba-4b4a-a76f-2f67644e99d2) | Sigma | SigmaHQ |
| T1566 | [CVE-2021-31979 CVE-2021-33771 Exploits by Sourgum](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aad7085ac-92e4-4b76-8ce2-276d2c0e68ef) | Sigma | SigmaHQ |
| T1566 | [CVE-2021-31979 CVE-2021-33771 Exploits](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A32b5db62-cb5f-4266-9639-0fa48376ac00) | Sigma | SigmaHQ |
| T1572 | [Communication To LocaltoNet Tunneling Service Initiated - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac4568f5d-131f-4e78-83d4-45b2da0ec4f1) | Sigma | SigmaHQ |
| T1572 | [Communication To Ngrok Tunneling Service - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A19bf6fdb-7721-4f3d-867f-53467f6a5db6) | Sigma | SigmaHQ |
| T1583.001 | [AWS Route 53 Private Hosted Zone Associated With a VPC](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ae3c27562-709a-42bd-82f2-3ed926cced19) | Elastic | Elastic detection-rules |
| T1583.001 | [AWS SES Email Identity Verified Then Deleted](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A8e4bde35-125d-4eb3-9a2e-d7e77a053a08) | Elastic | Elastic detection-rules |
| T1583.006 | [GitHub Repo Created](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A6cea88e4-6ce2-4238-9981-a54c140d6336) | Elastic | Elastic detection-rules |
| T1583.006 | [Cisco Secure Firewall - Rare Snort Rule Triggered](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=splunk-security-content%3A%3Ae20313d2-7d63-4fcf-b2d9-d6e12c6c7bd7) | Splunk | Splunk security_content |
| T1585.001 | [CYFIRMA - Brand Intelligence - Social Media Handle Impersonation Detected High Rule](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A22f49d67-7da7-4809-8d07-89e4478aa6b0) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1585.001 | [CYFIRMA - Brand Intelligence - Executive/People Impersonation High Rule](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A159d26a1-591c-4f70-b1ca-2843c881aaec) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1587.001 | [Formbook Process Creation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A032f5fb3-d959-41a5-9263-4173c802dc2b) | Sigma | SigmaHQ |
| T1587.001 | [Uncommon File Created In Office Startup Folder](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aa10a2c40-2c4d-49f8-b557-1a946bc55d9d) | Sigma | SigmaHQ |
| T1588.001 | [Relevant ClamAV Message](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A36aa86ca-fd9d-4456-814e-d3b1b8e1e0bb) | Sigma | SigmaHQ |
| T1588.001 | [Relevant ClamAV Message](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A36aa86ca-fd9d-4456-814e-d3b1b8e1e0bb) | Sigma | OpenSearch Security Analytics |
| T1588.002 | [Hacktool Execution - Imphash](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A24e3e58a-646b-4b50-adef-02ef935b9fc8) | Sigma | SigmaHQ |
| T1588.002 | [Renamed SysInternals DebugView Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acd764533-2e07-40d6-a718-cfeec7f2da7f) | Sigma | SigmaHQ |
| T1589 | [SSHD Error Message CVE-2018-15473](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4c9d903d-4939-4094-ade0-3cb748f4d7da) | Sigma | SigmaHQ |
| T1589 | [SSHD Error Message CVE-2018-15473](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A4c9d903d-4939-4094-ade0-3cb748f4d7da) | Sigma | OpenSearch Security Analytics |
| T1595.002 | [DNS Query to External Service Interaction Domains](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aaff715fa-4dd5-497a-8db3-910bea555566) | Sigma | SigmaHQ |
| T1595.002 | [Web Server Potential SQL Injection Request](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A7f7a0ee1-7b6f-466a-85b4-110fb105f5e2) | Elastic | Elastic detection-rules |
| T1651 | [AWS SSM Command Document Created by Rare User](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A50a2bdea-9876-11ef-89db-f661ea17fbcd) | Elastic | Elastic detection-rules |
| T1651 | [AWS EC2 LOLBin Execution via SSM SendCommand](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Aa8b3e2f0-8c7d-11ef-b4c6-f661ea17fbcd) | Elastic | Elastic detection-rules |
| T1657 | [AWS S3 Bucket Enumeration or Brute Force](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A5f0234fd-7f21-42af-8391-511d5fd11d5c) | Elastic | Elastic detection-rules |
| T1657 | [Monitor ransomwarelive for companies of interest on ransowmare data leak sites (DLS)](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=bert-janp-hunting-queries%3A%3A8b9af12a820a) | KQL hunting | Bert-JanP Hunting Queries |
| T1684.001 | [Entra ID OAuth user_impersonation Scope for Unusual User and Client](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A9563dace-5822-11f0-b1d3-f661ea17fbcd) | Elastic | Elastic detection-rules |
| T1686.003 | [Suspicious Program Location Whitelisted In Firewall Via Netsh.EXE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aa35f5a72-f347-4e36-8895-9869b0d5fc6d) | Sigma | SigmaHQ |
| T1686.003 | [RDP Connection Allowed Via Netsh.EXE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A01aeb693-138d-49d2-9403-c4f52d7d3d62) | Sigma | SigmaHQ |

## 8. Plano de emulação e validação

Use num laboratório isolado e autorizado para confirmar que as regras disparam. Os comandos estão nos repositórios oficiais.

| Tática | Técnica | Teste Atomic Red Team | Plataformas |
|---|---|---|---|
| Execution | [T1047](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1047/T1047.md) | WMI Reconnaissance Users | windows |
| Execution | [T1047](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1047/T1047.md) | WMI Reconnaissance Processes | windows |
| Execution | [T1059.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md) | Mimikatz | windows |
| Execution | [T1059.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md) | Run BloodHound from local disk | windows |
| Execution | [T1072](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1072/T1072.md) | Radmin Viewer Utility | windows |
| Execution | [T1072](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1072/T1072.md) | PDQ Deploy RAT | windows |
| Execution | [T1204.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1204.002/T1204.002.md) | OSTap Style Macro Execution | windows |
| Execution | [T1204.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1204.002/T1204.002.md) | OSTap Payload Download | windows |
| Execution | [T1651](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1651/T1651.md) | AWS Run Command (and Control) | iaas:aws |
| Persistence | [T1098](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1098/T1098.md) | Admin Account Manipulate | windows |
| Persistence | [T1098](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1098/T1098.md) | Domain Account and Group Manipulate | windows |
| Persistence | [T1133](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1133/T1133.md) | Running Chrome VPN Extensions via the Registry 2 vpn extension | windows |
| Persistence | [T1547.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1547.001/T1547.001.md) | Reg Key Run | windows |
| Persistence | [T1547.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1547.001/T1547.001.md) | Reg Key RunOnce | windows |
| Stealth | [T1036.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.004/T1036.004.md) | Creating W32Time similar named service using schtasks | windows |
| Stealth | [T1036.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.004/T1036.004.md) | Creating W32Time similar named service using sc | windows |
| Stealth | [T1036.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.005/T1036.005.md) | Execute a process from a directory masquerading as the current parent directory | linux, macos |
| Stealth | [T1036.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.005/T1036.005.md) | Masquerade as a built-in system executable | windows |
| Stealth | [T1078.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1078.004/T1078.004.md) | Creating GCP Service Account and Service Account Key | google-workspace, iaas:gcp |
| Stealth | [T1078.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1078.004/T1078.004.md) | Azure Persistence Automation Runbook Created or Modified | iaas:azure |
| Stealth | [T1564.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1564.003/T1564.003.md) | Hidden Window | windows |
| Stealth | [T1564.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1564.003/T1564.003.md) | Headless Browser Accessing Mockbin | windows |
| Defense Impairment | [T1484.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1484.001/T1484.001.md) | LockBit Black - Modify Group policy settings -cmd | windows |
| Defense Impairment | [T1484.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1484.001/T1484.001.md) | LockBit Black - Modify Group policy settings -Powershell | windows |
| Defense Impairment | [T1686.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1686.003/T1686.003.md) | Enable Firewall Rule Group via COM Object (HNetCfg.FwPolicy2) | windows |
| Defense Impairment | [T1686.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1686.003/T1686.003.md) | Set All Network Profiles to Private via Registry | windows |
| Credential Access | [T1003.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/T1003.001.md) | Dump LSASS.exe Memory using ProcDump | windows |
| Credential Access | [T1003.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/T1003.001.md) | Dump LSASS.exe Memory using comsvcs.dll | windows |
| Credential Access | [T1110.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1110.001/T1110.001.md) | Brute Force Credentials of single Active Directory domain users via SMB | windows |
| Credential Access | [T1110.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1110.001/T1110.001.md) | Brute Force Credentials of single Active Directory domain user via LDAP against domain controller (NTLM or Kerberos) | windows |
| Credential Access | [T1110.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1110.004/T1110.004.md) | SSH Credential Stuffing From Linux | linux |
| Credential Access | [T1110.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1110.004/T1110.004.md) | SSH Credential Stuffing From MacOS | macos |
| Credential Access | [T1552.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1552.002/T1552.002.md) | Enumeration for Credentials in Registry | windows |
| Credential Access | [T1552.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1552.002/T1552.002.md) | Enumeration for PuTTY Credentials in Registry | windows |
| Discovery | [T1082](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1082/T1082.md) | System Information Discovery | windows |
| Discovery | [T1082](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1082/T1082.md) | System Information Discovery | macos |
| Discovery | [T1087.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1087.002/T1087.002.md) | Enumerate all accounts (Domain) | windows |
| Discovery | [T1087.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1087.002/T1087.002.md) | Enumerate all accounts via PowerShell (Domain) | windows |
| Lateral Movement | [T1021.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.001/T1021.001.md) | RDP to Remote Host | windows |
| Lateral Movement | [T1021.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.001/T1021.001.md) | Changing RDP Port to Non Standard Port via Powershell | windows |
| Collection | [T1005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1005/T1005.md) | Search files of interest and save them to a single zip file (Windows) | windows |
| Collection | [T1005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1005/T1005.md) | Find and dump sqlite databases (Linux) | linux |
| Collection | [T1113](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1113/T1113.md) | Screencapture | macos |
| Collection | [T1113](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1113/T1113.md) | Screencapture (silent) | macos |
| Collection | [T1114.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1114.002/T1114.002.md) | Office365 - Remote Mail Collected | office-365 |
| Collection | [T1119](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1119/T1119.md) | Automated Collection Command Prompt | windows |
| Collection | [T1119](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1119/T1119.md) | Automated Collection PowerShell | windows |
| Collection | [T1123](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1123/T1123.md) | using device audio capture commandlet | windows |
| Collection | [T1123](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1123/T1123.md) | Registry artefact when application use microphone | windows |
| Collection | [T1125](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1125/T1125.md) | Registry artefact when application use webcam | windows |
| Collection | [T1560.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1560.001/T1560.001.md) | Compress Data for Exfiltration With Rar | windows |
| Collection | [T1560.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1560.001/T1560.001.md) | Compress Data and lock with password for Exfiltration with winrar | windows |
| Command and Control | [T1071.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1071.001/T1071.001.md) | Malicious User Agents - Powershell | windows |
| Command and Control | [T1071.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1071.001/T1071.001.md) | Malicious User Agents - CMD | windows |
| Command and Control | [T1105](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1105/T1105.md) | rsync remote file copy (push) | linux, macos |
| Command and Control | [T1105](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1105/T1105.md) | rsync remote file copy (pull) | linux, macos |
| Command and Control | [T1572](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1572/T1572.md) | DNS over HTTPS Large Query Volume | windows |
| Command and Control | [T1572](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1572/T1572.md) | DNS over HTTPS Regular Beaconing | windows |
| Exfiltration | [T1041](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1041/T1041.md) | C2 Data Exfiltration | windows |
| Exfiltration | [T1041](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1041/T1041.md) | Text Based Data Exfiltration using DNS subdomains | windows |
| Impact | [T1485](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1485/T1485.md) | Windows - Overwrite file with SysInternals SDelete | windows |
| Impact | [T1485](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1485/T1485.md) | FreeBSD/macOS/Linux - Overwrite file with DD | linux, macos |
| Impact | [T1486](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1486/T1486.md) | Encrypt files using gpg (FreeBSD/Linux) | linux |
| Impact | [T1486](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1486/T1486.md) | Encrypt files using 7z (FreeBSD/Linux) | linux |
| Impact | [T1490](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1490/T1490.md) | Windows - Delete Volume Shadow Copies | windows |
| Impact | [T1490](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1490/T1490.md) | Windows - Delete Volume Shadow Copies via WMI | windows |

**Logs reais de ataque (EVTX) para testar sem executar nada:**

- T1003.001 — [CA_hashdump_4663_4656_lsass_access](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Credential%20Access/CA_hashdump_4663_4656_lsass_access.evtx) _(inferido)_
- T1003.001 — [LsassSilentProcessExit_process_exit_monitor_3001_lsass](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Credential%20Access/LsassSilentProcessExit_process_exit_monitor_3001_lsass.evtx) _(inferido)_
- T1021.001 — [ID4688,4778,4779 RDP hijack direct](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0008-Lateral%20Movement/T1021.001-Remote%20Desktop%20Protocol/ID4688%2C4778%2C4779%20RDP%20hijack%20direct.evtx) _(explícito)_
- T1021.001 — [ID4688-4778 RDP hijack command execution](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0008-Lateral%20Movement/T1021.001-Remote%20Desktop%20Protocol/ID4688-4778%20RDP%20hijack%20command%20execution.evtx) _(explícito)_
- T1047 — [ID1-WMI spwaning PowerShell process - WMImplant](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1047-Windows%20Management%20Instrumentation/ID1-WMI%20spwaning%20PowerShell%20process%20-%20WMImplant.evtx) _(explícito)_
- T1047 — [ID1-WMIexec process execution](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1047-Windows%20Management%20Instrumentation/ID1-WMIexec%20process%20execution.evtx) _(explícito)_
- T1059.001 — [ID4103-4104-Payload download via PowerShell](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1059.001-PowerShell/ID4103-4104-Payload%20download%20via%20PowerShell.evtx) _(explícito)_
- T1059.001 — [ID4688-Encoded PowerShell MSF payload via process execution](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1059.001-PowerShell/ID4688-Encoded%20PowerShell%20MSF%20payload%20via%20process%20execution.evtx) _(explícito)_
- T1078 — [ID1149-RDP success logins to multiple hosts](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0001-Initial%20access/T1078-Valid%20accounts/ID1149-RDP%20success%20logins%20to%20multiple%20hosts.evtx) _(explícito)_
- T1078 — [ID33205-SQL Server failed login with disabled SA account](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0001-Initial%20access/T1078-Valid%20accounts/ID33205-SQL%20Server%20failed%20login%20with%20disabled%20SA%20account.evtx) _(explícito)_
- T1078.002 — [ID4964-Login of a member of a special group](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0005-Defense%20Evasion/T1078.002-Valid%20accounts-Domain%20accounts/ID4964-Login%20of%20a%20member%20of%20a%20special%20group.evtx) _(explícito)_
- T1087.002 — [discovery_bloodhound](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Discovery/discovery_bloodhound.evtx) _(inferido)_
- T1098 — [ID33205-SQL Server member added to database role](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0003-Persistence/T1098.xxx-Account%20manipulation/ID33205-SQL%20Server%20member%20added%20to%20database%20role.evtx) _(explícito)_
- T1098 — [ID33205-SQL Server member added to server role](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0003-Persistence/T1098.xxx-Account%20manipulation/ID33205-SQL%20Server%20member%20added%20to%20server%20role.evtx) _(explícito)_
- T1110 — [ID 4776,4625-AccountRestore local bruteforce](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0006-Credential%20Access/T1110.xxx-Brut%20force/ID%204776%2C4625-AccountRestore%20local%20bruteforce.evtx) _(explícito)_
- T1110 — [ID18456-SQL Server failed login because only Windows auth](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0006-Credential%20Access/T1110.xxx-Brut%20force/ID18456-SQL%20Server%20failed%20login%20because%20only%20Windows%20auth.evtx) _(explícito)_
- T1125 — [ID13-RDP shadow session configuration enabled (registry)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0009-Collection/T1125-Video%20capture/ID13-RDP%20shadow%20session%20configuration%20enabled%20%28registry%29.evtx) _(explícito)_
- T1484.001 — [ID5136-4662 sensitive GPO edited](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0004-Privilege%20Escalation/T1484.001-Domain%20Policy%20Modification-Group%20Policy%20Modification/ID5136-4662%20sensitive%20GPO%20edited.evtx) _(explícito)_
- T1486 — [ID 768,775,793,796,817,840-BitLocker encryption activated](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0040-Impact/T1486-Data%20Encrypted%20for%20Impact/ID%20768%2C775%2C793%2C796%2C817%2C840-BitLocker%20encryption%20activated.evtx) _(explícito)_
- T1490 — [ID4688-Delete VSS backup (WMI)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0040-Impact/T1490-Inhibit%20System%20Recovery/ID4688-Delete%20VSS%20backup%20%28WMI%29.evtx) _(explícito)_
- T1490 — [ID4688-Delete Window backup (webadmin)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0040-Impact/T1490-Inhibit%20System%20Recovery/ID4688-Delete%20Window%20backup%20%28webadmin%29.evtx) _(explícito)_
- T1547.001 — [sideloading_injection_persistence_run_key](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/AutomatedTestingTools/Malware/sideloading_injection_persistence_run_key.evtx) _(inferido)_
- T1547.001 — [evasion_persis_hidden_run_keyvalue_sysmon_13](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Persistence/evasion_persis_hidden_run_keyvalue_sysmon_13.evtx) _(inferido)_
- T1572 — [ID4688-netsh RDP port forwarding abuse](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0011-Command%20and%20Control/T1572-Protocol%20tunneling/ID4688-netsh%20RDP%20port%20forwarding%20abuse.evtx) _(explícito)_

## 9. Hipóteses de hunting

Se VOID MANTICORE estiver no seu ambiente, estas são as perguntas a fazer aos seus dados (fontes de log segundo as estratégias de detecção do MITRE ATT&CK).

1. **T1679 Selective Exclusion** — A process with no prior history or outside of known whitelisted tools initiates file or registry modifications to configure exclusion rules for antivirus, backup, or file-handling systems. Or a file system enumeration for specific file names andcritical… Dados: `WinEventLog:PowerShell` (EventCode=4103, 4104, 4105, 4106), `WinEventLog:Security` (EventCode=4688), `WinEventLog:Security` (EventCode=4663, 4670, 4656).
2. **T1110.004 Credential Stuffing** — Multiple failed authentication attempts using distinct username/password pairs from a single IP address or session within a short time window, targeting common services like RDP or SMB Dados: `WinEventLog:Security` (EventCode=4625).
3. **T1123 Audio Capture** — Unusual or unauthorized processes accessing microphone APIs (e.g., winmm.dll, avrt.dll) followed by audio file writes to user-accessible or temp directories. Dados: `WinEventLog:Sysmon` (EventCode=10), `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Security` (EventCode=4688).
4. **T1651 Cloud Administration Command** — Monitor for suspicious use of cloud-native administrative command services (e.g., AWS Systems Manager Run Command, Azure RunCommand, GCP OS Config) to execute code inside VMs. Detect anomalies such as commands/scripts executed by unexpected users, execution… Dados: `AWS:CloudTrail` (SendCommand, StartSession, ExecuteCommand: Unexpected AWS Systems Manager command execution targeting EC2 instances), `azure:activity` (Microsoft.Compute/virtualMachines/runCommand/action: Abnormal initiation of Azure RunCommand jobs or PowerShell/Bash payloads), `azure:vmguest` (Unexpected execution of cloud agent processes (e.g., WindowsAzureGuestAgent.exe, ssm-agent) followed by arbitrary script or binary execution).
5. **T1552.002 Credentials in Registry** — Defenders observe command-line executions or API-based registry reads targeting sensitive paths like HKLM or HKCU with keyword filters such as 'password', 'cred', or 'logon'. Typically performed by Reg.exe, PowerShell, custom binaries, or offensive tools such… Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=13, 14), `EDR:hunting` (Behavioral rule for registry enumeration under credential-related paths).
6. **T1561.001 Disk Content Wipe** — Processes attempting raw disk access via \\.\PhysicalDrive paths, abnormal file I/O to MBR/boot sectors, or loading of third-party drivers (e.g., RawDisk) that enable disk overwrite. Correlate process creation, privilege usage, and disk modification events… Dados: `WinEventLog:Security` (EventCode=4673), `WinEventLog:Sysmon` (Raw disk writes targeting \\.\PhysicalDrive* or MBR locations), `WinEventLog:Sysmon` (EventCode=6).
7. **T1110.001 Password Guessing** — Series of authentication failures (Event ID 4625) targeting the same or similar user accounts over time from one or more remote IPs Dados: `WinEventLog:Security` (EventCode=4625).
8. **T1125 Video Capture** — A non-standard process (or script-hosted process) loads camera/video-capture libraries (e.g., avicap32.dll, mf.dll, ksproxy.ax), opens the Camera Frame Server/device, writes video/image artifacts (e.g., .mp4/.avi/.yuv) to unusual locations, and optionally… Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=3, 22), `WinEventLog:Sysmon` (EventCode=7).
9. **T1074 Data Staged** — Detects staging of sensitive files into temporary or public directories, compression with 7zip/WinRAR, or batch copy prior to exfiltration. Dados: `WinEventLog:Security` (EventCode=4663, 4670, 4656), `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Sysmon` (EventCode=1).
10. **T1484.001 Group Policy Modification** — Adversary modifies GPO containers or files under SYSVOL using LDAP, ADSI, PowerShell (e.g., New-GPOImmediateTask) or GUI tools. This includes directory object changes (e.g., gPCFileSysPath), delegation assignments (SeEnableDelegationPrivilege), and SYSVOL… Dados: `WinEventLog:Security` (EventCode=5136), `WinEventLog:Security` (EventCode=4663, 4670, 4656), `WinEventLog:Security` (EventCode=4704).
11. **T1098 Account Manipulation** — Account attribute changes (e.g., password set, group membership, servicePrincipalName, logon hours) correlated with unusual process lineage or timing, indicating privilege escalation or persistence via valid accounts. Dados: `WinEventLog:Security` (EventCode=4738, 4728, 4670), `WinEventLog:Sysmon` (EventCode=1).
12. **T1561.002 Disk Structure Wipe** — Processes attempting raw disk access to overwrite sensitive structures such as the MBR or partition table using \\.\PhysicalDrive notation. Detection relies on correlating process creation, privilege escalation, and raw sector writes in Sysmon and Security… Dados: `WinEventLog:Security` (EventCode=4673), `WinEventLog:Sysmon` (Raw write attempts targeting \\.\PhysicalDrive0 or sector 0 (MBR/partition table)), `WinEventLog:Sysmon` (EventCode=6).

## 10. OSINT — onde pesquisar

Consultas prontas com todos os nomes conhecidos do grupo:

- Relatórios técnicos: [busca web](https://duckduckgo.com/?q=%28%22VOID+MANTICORE%22+OR+%22COBALT+MYSTIQUE%22+OR+%22Handala+Hack%22+OR+%22Homeland+Justice%22+OR+%22Karma%22+OR+%22Karmabelow80%22%29+threat+report) · [PDFs](https://duckduckgo.com/?q=%28%22VOID+MANTICORE%22+OR+%22COBALT+MYSTIQUE%22+OR+%22Handala+Hack%22+OR+%22Homeland+Justice%22+OR+%22Karma%22+OR+%22Karmabelow80%22%29+filetype%3Apdf)
- Regras e IOCs publicados: [GitHub](https://github.com/search?type=code&q=%22VOID+MANTICORE%22+OR+%22COBALT+MYSTIQUE%22+OR+%22Handala+Hack%22+OR+%22Homeland+Justice%22+OR+%22Karma%22+OR+%22Karmabelow80%22)
- Pulsos de ameaça: [AlienVault OTX](https://otx.alienvault.com/browse/global/pulses?q=VOID+MANTICORE)
- Família de malware e atores: [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/actors) (busque por VOID MANTICORE, COBALT MYSTIQUE, Handala Hack)
- Cartões de grupo: [ThaiCERT Threat Group Cards](https://apt.etda.or.th/cgi-bin/listgroups.cgi)
- Página oficial: [MITRE ATT&CK G1055](https://attack.mitre.org/groups/G1055/)

## 11. Bibliografia (9 fontes citadas pelo ATT&CK)

- [Check Point VOID MANTICORE Handala Hack March 2026](https://research.checkpoint.com/2026/handala-hack-unveiling-groups-modus-operandi/) — Check Point Research. (2026, March 12). “Handala Hack” – Unveiling Group’s Modus Operandi. Retrieved April 20, 2026.
- [DOJ FBI Handala Hack March 2026](https://www.justice.gov/opa/media/1431956/dl?inline) — DOJ/FBI. (2026, March 19). Case 1:26-mj-00683-CDA: Affidavit in Support of Seizure Warrant: In the Matter of the Seizure of Domain Names Justicehomeland[.]org; karmabelow80[.]org; handala-hack[.]to; and handala-redwatned
- [Domain Tools Handala Hack Karma Homeland Justice MOIS April 2026](https://dti.domaintools.com/research/handala-mois-linked-cyber-influence-ecosystem-threat-intelligence-assessment) — DomainTools Investigations. (2026, April 6). Handala: MOIS Linked Cyber Influence Ecosystem Threat Intelligence Assessment. Retrieved April 20, 2026.
- [FBI IC3 Flash VOID MANTICORE Handala Hack March 2026](https://www.ic3.gov/CSA/2026/260320.pdf) — FBI. (2026, March 20). FBI Flash: FLASH-20260320-001:Government of Iran Cyber Actors Deploy Telegram C2 to Push Malware to Identified Targets. Retrieved April 20, 2026.
- [Palo Alto VOID MANTICORE Iran Cyber Threats March 2026](https://unit42.paloaltonetworks.com/evolution-of-iran-cyber-threats/) — Justin Moore. (2026, March 16). Iranian Cyber Threat Evolution: From MBR Wipers to Identity Weaponization. Retrieved April 20, 2026.
- [SEC 8-K Stryker Corporation Filing Handala Hack March 2026](https://www.sec.gov/ix?doc=/Archives/edgar/data/0000310764/000119312526118634/d94012d8k.htm) — Stryker Corporation. (2026, March 23). SEC 8-K Stryker Corporation. Retrieved April 20, 2026.
- [SEC 8K Palo Alto Statement Stryker Corp Handala March 2026](https://www.sec.gov/Archives/edgar/data/310764/000119312526118634/d94012dex991.htm) — Troy Bettencourt. (2026, March 20). SEC 8k: Stryker Corporation Partner and Customer Connections to the Stryker Environment. Retrieved April 20, 2026.
- [Sophos VOID MANTICORE COBALT MYSTIQUE other Names April 2026](https://www.sophos.com/en-us/threat-profiles/cobalt-mystique) — Sophos. (2026, April 20). Iran COBALT MYSTIQUE. Retrieved April 20, 2026.
- [SPECOPS Outpost24 Handala Hack Stryker March 2026](https://specopssoft.com/blog/stryker-cyber-attack-what-we-know-remote-wipe/) — David Ketler. (2026, March 30). Stryker Cyber-Attack: What we Know so Far About the Remote Wipe Attack. Retrieved April 20, 2026.

## 12. Limites e confiança

- O ATT&CK registra o que foi **relatado publicamente**, não tudo o que o grupo faz. Ausência de uma técnica não prova que o grupo não a usa.
- **Sobreposição de TTP não é atribuição.** Muitas técnicas são compartilhadas entre grupos e com red teams. Use a assinatura comportamental como hipótese, junto com infraestrutura, malware e contexto.
- Cobertura de detecção refere-se ao catálogo público Detection Rules, não ao seu ambiente: confira se a telemetria necessária chega ao seu SIEM.
- Ligações marcadas como _inferidas_ (EVTX por palavra-chave, relatórios por nome) devem ser verificadas.

---
Fontes: MITRE ATT&CK® (uso livre com atribuição, © The MITRE Corporation), Atomic Red Team (Red Canary, MIT), EVTX-to-MITRE-Attack, EVTX-ATTACK-SAMPLES, APT & CyberCriminal Campaign Collections. Gerado por [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules).
