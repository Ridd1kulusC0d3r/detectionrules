# Contagious Interview (G1052) — Dossiê de inteligência

> **TLP:CLEAR** · gerado em 2026-10-25 a partir de fontes abertas · MITRE ATT&CK v20.0 · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1052) · [ATT&CK](https://attack.mitre.org/groups/G1052/)

**Também conhecido como:** DeceptiveDevelopment, Gwisin Gang, Tenacious Pungsan, DEV#POPPER, PurpleBravo, TAG-121  
**Registro no ATT&CK:** criado em 2025-10-19, atualizado em 2026-07-31 · referências de 2023 a 2025

## 1. Sumário executivo

- **54 técnicas** atribuídas publicamente, concentradas em **Resource Development, Execution, Stealth**.
- **Arsenal:** 4 malware e 0 ferramentas (ex.: InvisibleFerret, BeaverTail, HexEval Loader, XORIndex Loader).
- **Campanhas atribuídas:** 0.
- **Cobertura de detecção pública:** 87% das técnicas têm ao menos uma regra no catálogo; **7 técnicas sem nenhuma regra pública**.
- **Assinatura comportamental** (técnicas raras entre os 178 grupos, as mais úteis para atribuição): T1204.005 Malicious Library, T1546.004 Unix Shell Configuration Modification, T1547.013 XDG Autostart Entries, T1543.001 Launch Agent, T1555.001 Keychain.

## 2. Quem é

> Contagious Interview is a North Korea–aligned threat group active since 2023. The group conducts both cyberespionage and financially motivated operations, including the theft of cryptocurrency and user credentials. Contagious Interview targets Windows, Linux, and macOS systems, with a particular focus on individuals engaged in software development and cryptocurrency-related activities.

_Texto original do MITRE ATT&CK, em inglês._

## 3. Perfil TTP por tática (kill chain)

Cada linha: técnica, como o grupo a usou segundo relatos públicos, e o que existe para detectar e testar.

### Reconnaissance (TA0043) — 5

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1589](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1589) Gather Victim Identity Information | Contagious Interview has researched specific professional groups such as software developers for targeting. Contagious Interview has also researched individuals who work in roles related to cryptocurrency and blockchain technologies. | 11 | — | — |
| [T1593](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1593) Search Open Websites/Domains | Contagious Interview has utilized open-source indicator of compromise repositories to determine their exposure to include VirusTotal, and MalTrail. | 8 | — | — |
| [T1593.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1593.001) Social Media | Contagious Interview had identified and solicited victims through social media such as LinkedIn, X, and Telegram. | **0** | — | — |
| [T1593.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1593.003) Code Repositories | Contagious Interview had identified and solicited victims through code repositories such as GitHub. | 6 | — | — |
| [T1681](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1681) Search Threat Vendor Data | Contagious Interview has registered accounts with Threat Intelligence vendor services to check for reporting associated with their infrastructure and to evaluate new potential infrastructure. | **0** | — | — |

### Resource Development (TA0042) — 14

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1583](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1583) Acquire Infrastructure | Contagious Interview has used services such as Astrill VPN. | 9 | — | — |
| [T1583.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1583.001) Domains | Contagious Interview has registered domains to leverage in their social engineering campaigns. Contagious Interview has also registered domains to utilize for C2. | 7 | — | — |
| [T1583.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1583.003) Virtual Private Server | Contagious Interview has acquired virtual private servers from services such as Stark Industries Solutions and RouterHosting. Contagious Interview has also utilized hosting providers to include Tier[.]Net, Majestic Hosting, Leaseweb Singapore, and Kaopu Cloud. | **0** | — | — |
| [T1583.006](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1583.006) Web Services | Contagious Interview has used web services such as Dropbox to receive stolen data and Google Drive, Firebase, GitHub, and Telegram to disseminate files. Contagious Interview has also used a cloud platform such as Vercel for C2 operations leveraging malicious w… | 2 | — | — |
| [T1585](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1585) Establish Accounts | Contagious Interview has created and maintained personas on code repositories to distribute malicious payloads. | 1 | — | — |
| [T1585.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1585.001) Social Media Accounts | Contagious Interview has created fake social media accounts such as LinkedIn and Telegram accounts for their targeting efforts. | 4 | — | — |
| [T1585.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1585.002) Email Accounts | Contagious Interview has created fake email accounts to correspond with social media accounts, fake LinkedIn personas, code repository accounts, and job announcements on development job board services. Contagious Interview has also utilized fake email accounts… | **0** | — | — |
| [T1587](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1587) Develop Capabilities | Contagious Interview developed malicious NPM packages for delivery to or retrieval by victims. | 22 | — | — |
| [T1587.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1587.001) Malware | Contagious Interview has developed malware that utilizes Qt cross-platform framework to include BeaverTail. | 43 | — | — |
| [T1588.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1588.002) Tool | Contagious Interview has used remote management and monitoring software such as “AnyDesk”. | 35 | — | — |
| [T1588.007](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1588.007) Artificial Intelligence | Contagious Interview has appeared to have used AI to generate images and content to facilitate their campaigns. | **0** | — | — |
| [T1608.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1608.001) Upload Malware | Contagious Interview has hosted malicious payloads on code repositories used as lures for victims to download. | 3 | — | — |
| [T1683.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1683.001) Written Content | Contagious Interview has created fake social media accounts such as LinkedIn and Telegram accounts for their targeting efforts. | **0** | — | — |
| [T1683.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1683.002) Audio-Visual Content | Contagious Interview has used AI to clone video-conferencing applications to distribute their BeaverTail malware. They have also used AI to create deepfake videos. | **0** | — | — |

### Initial Access (TA0001) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1566.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1566.003) Spearphishing via Service | Contagious Interview has used fake job advertisements and messages sent via social media to spearphish targets. Contagious Interview has also leveraged hiring websites to solicit victims. | 8 | — | — |

### Execution (TA0002) — 9

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1059.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.003) Windows Command Shell | Contagious Interview has utilized VBS scripts to open cmd.exe and run commands to include the go_batch.bat batch file. | 269 | 6 | 1 |
| [T1059.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.004) Unix Shell | Contagious Interview has targeted macOS victim hosts using a bash downloader coremedia.sh and a bash script cloud.sh. | 395 | 17 | — |
| [T1059.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.005) Visual Basic | Contagious Interview has utilized Visual Basic scripts in the execution of their downloader malware targeting Windows devices including as script called update.vbs. | 192 | 3 | — |
| [T1059.006](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.006) Python | Contagious Interview has used the Python-based malware such as InvisibleFerret to install and execute Python Packages and Python modules. | 122 | — | — |
| [T1059.007](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.007) JavaScript | Contagious Interview has leveraged JavaScript in the execution of their downloader malware targeting Windows devices using a NodeJS script titled nvidia.js. | 205 | 5 | — |
| [T1204.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1204.001) Malicious Link | Contagious Interview has lured victims to click on a malicious link that led to download of a malicious payload. Contagious Interview has also leveraged links to malicious payloads on social media and code repositories. | 52 | — | — |
| [T1204.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1204.002) Malicious File | Contagious Interview has distributed malicious files requiring direct victim interaction to execute through the guise of a code test. | 259 | 13 | — |
| [T1204.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1204.004) Malicious Copy and Paste | Contagious Interview has leveraged ClickFix type tactics enticing victims to copy and paste malicious code. | 32 | — | — |
| [T1204.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1204.005) Malicious Library | Contagious Interview has relied on users to install a malicious library from a code repository to infect the victim's device and has led to additional payload distribution and theft of sensitive data. | 1 | — | — |

### Persistence (TA0003) — 4

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1543.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1543.001) Launch Agent | Contagious Interview has established persistence using InvisibleFerret malware to create file to run the script on Startup via LaunchAgents. Contagious Interview has also utilized a plist file located in `/Library/LaunchAgents` to enable a malicious bash scrip… | 18 | 3 | — |
| [T1546.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1546.004) Unix Shell Configuration Modification | Contagious Interview has targeted macOS victim hosts using a bash downloader `coremedia.sh` and a bash script `cloud.sh`. | 22 | 7 | — |
| [T1547.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1547.001) Registry Run Keys / Startup Folder | Contagious Interview has established persistence using InvisibleFerret malware to place a .bat file in the Startup Folder. | 299 | 21 | 2 |
| [T1547.013](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1547.013) XDG Autostart Entries | Contagious Interview has established persistence using InvisibleFerret malware to create a .desktop entry to run on startup on GNOME-based Linux devices. | 5 | — | — |

### Privilege Escalation (TA0004) — 4

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1543.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1543.001) Launch Agent | Contagious Interview has established persistence using InvisibleFerret malware to create file to run the script on Startup via LaunchAgents. Contagious Interview has also utilized a plist file located in `/Library/LaunchAgents` to enable a malicious bash scrip… | 18 | 3 | — |
| [T1546.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1546.004) Unix Shell Configuration Modification | Contagious Interview has targeted macOS victim hosts using a bash downloader `coremedia.sh` and a bash script `cloud.sh`. | 22 | 7 | — |
| [T1547.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1547.001) Registry Run Keys / Startup Folder | Contagious Interview has established persistence using InvisibleFerret malware to place a .bat file in the Startup Folder. | 299 | 21 | 2 |
| [T1547.013](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1547.013) XDG Autostart Entries | Contagious Interview has established persistence using InvisibleFerret malware to create a .desktop entry to run on startup on GNOME-based Linux devices. | 5 | — | — |

### Stealth (TA0005) — 7

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1027.010](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1027.010) Command Obfuscation | Contagious Interview has obfuscated JavaScript code using Base64 and variable substitutions. | 78 | — | — |
| [T1027.013](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1027.013) Encrypted/Encoded File | Contagious Interview has used hexadecimal string encoding to hide critical JavaScript module names, function names, and C2 URLs, which are decoded dynamically at runtime. | 8 | 4 | — |
| [T1036](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1036) Masquerading | Contagious Interview has delivered BeaverTail malware masquerading as legitimate software or applications. Contagious Interview has also delivered malicious payloads masquerading as legitimate software drivers. | 453 | 2 | 1 |
| [T1070.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1070.004) File Deletion | Contagious Interview has configured malware to remove archives used in collection activities following successful exfiltration. | 132 | 11 | — |
| [T1480](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1480) Execution Guardrails | Contagious Interview has configured C2 endpoints to review IP geolocation, request headers, victim environment details and runtime conditions prior to delivering payloads. | 2 | — | — |
| [T1497](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1497) Virtualization/Sandbox Evasion | Contagious Interview has requested victims to disable Docker and other container environments in attempts to thwart container isolation and ensure device infection. | 18 | — | — |
| [T1684.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1684.001) Impersonation | Contagious Interview had impersonated HR hiring personnel through social media, job board notifications, and conducted interviews with victims in order to entice them to download malware disguised as legitimate applications or malicious scripts from code repos… | 1 | — | — |

### Defense Impairment (TA0112) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1685](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1685) Disable or Modify Tools | Contagious Interview has convinced victims to disable Docker and other container environments and run code on their machine natively in attempts to bypass container isolation and ensure device infection. | 1275 | 78 | 19 |

### Credential Access (TA0006) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1555.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1555.001) Keychain | Contagious Interview has leveraged malware variants configured to dump credentials from the macOS keychain. | 19 | 4 | — |

### Discovery (TA0007) — 3

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1082](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1082) System Information Discovery | Contagious Interview has configured malicious webpages to identify the victim’s operating system by reviewing the details of the victims User-Agent of their browser. | 264 | 41 | — |
| [T1083](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1083) File and Directory Discovery | Contagious Interview has conducted key word searches within files and directories on a compromised hosts to identify files for exfiltration. | 137 | 9 | — |
| [T1497](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1497) Virtualization/Sandbox Evasion | Contagious Interview has requested victims to disable Docker and other container environments in attempts to thwart container isolation and ensure device infection. | 18 | — | — |

### Command and Control (TA0011) — 5

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1071.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1071.003) Mail Protocols | Contagious Interview has utilized email notifications from malware distribution servers to track victim engagement. | 6 | — | — |
| [T1090](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1090) Proxy | Contagious Interview has leveraged Astrill VPN for C2. | 162 | — | 1 |
| [T1219.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1219.002) Remote Desktop Software | Contagious Interview has downloaded remote management and monitoring software such as “AnyDesk” for post compromise activities. | 221 | — | — |
| [T1571](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1571) Non-Standard Port | Contagious Interview has used TCP port 1224 for C2. | 163 | 2 | — |
| [T1573.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1573.001) Symmetric Cryptography | Contagious Interview has encrypted C2 traffic using RC4. | 5 | — | — |

### Exfiltration (TA0010) — 4

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1041](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1041) Exfiltration Over C2 Channel | Contagious Interview has exfiltrated data from a compromised host to actor-controlled C2 servers. | 135 | 2 | — |
| [T1048.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1048.003) Exfiltration Over Unencrypted Non-C2 Protocol | Contagious Interview has exfiltrated victim information using FTP. | 51 | 8 | — |
| [T1567](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1567) Exfiltration Over Web Service | Contagious Interview has leveraged Telegram API to exfiltrate stolen data. | 162 | — | — |
| [T1567.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1567.002) Exfiltration to Cloud Storage | Contagious Interview has exfiltrated stolen passwords to Dropbox. | 85 | 2 | — |

### Impact (TA0040) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1657](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1657) Financial Theft | Contagious Interview has stolen cryptocurrency wallet credentials and credit card information utilizing BeaverTail and InvisibleFerret malware. | 2 | — | — |

## 4. Assinatura comportamental

Técnicas que este grupo usa e que poucos dos 178 grupos do ATT&CK usam. Pesam mais numa atribuição por TTP: ver várias delas juntas é mais informativo do que ver técnicas comuns como PowerShell.

| Técnica | Outros grupos que usam | Peso (raridade) |
|---|---:|---:|
| T1204.005 Malicious Library | 0 | 4.49 |
| T1546.004 Unix Shell Configuration Modification | 0 | 4.49 |
| T1547.013 XDG Autostart Entries | 0 | 4.49 |
| T1543.001 Launch Agent | 1 | 4.09 |
| T1555.001 Keychain | 1 | 4.09 |
| T1681 Search Threat Vendor Data | 1 | 4.09 |
| T1204.004 Malicious Copy and Paste | 2 | 3.80 |
| T1497 Virtualization/Sandbox Evasion | 2 | 3.80 |
| T1593.001 Social Media | 2 | 3.80 |
| T1587 Develop Capabilities | 3 | 3.58 |

## 5. Arsenal

| Software | Tipo | Técnicas no ATT&CK | Uso relatado (EN) |
|---|---|---:|---|
| [InvisibleFerret](https://attack.mitre.org/software/S1245/) | malware | 35 |  |
| [BeaverTail](https://attack.mitre.org/software/S1246/) | malware | 23 |  |
| [HexEval Loader](https://attack.mitre.org/software/S1249/) | malware | 12 |  |
| [XORIndex Loader](https://attack.mitre.org/software/S1248/) | malware | 12 |  |

## 6. Campanhas

Nenhuma campanha atribuída no ATT&CK.

## 7. Cobertura defensiva

**47 de 54 técnicas (87%)** têm ao menos uma regra pública no catálogo Detection Rules.

### Técnicas sem regra pública (prioridade para engenharia de detecção)

- **T1681 Search Threat Vendor Data** — Reconnaissance
- **T1593.001 Social Media** — Reconnaissance
- **T1588.007 Artificial Intelligence** — Resource Development
- **T1683.002 Audio-Visual Content** — Resource Development
- **T1683.001 Written Content** — Resource Development
- **T1583.003 Virtual Private Server** — Resource Development. Fonte de log sugerida pelo MITRE: `Internet Scan` None
- **T1585.002 Email Accounts** — Resource Development

### Regras recomendadas por técnica

Melhor regra disponível por técnica (formato portável e maduro primeiro).

| Técnica | Regra | Formato | Fonte |
|---|---|---|---|
| T1027.010 | [Decoded Payload Piped to Interpreter Detected via Defend for Containers](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A0fb83aa0-3d17-41e9-b09c-56397bf7a7d9) | Elastic | Elastic detection-rules |
| T1027.010 | [Potential PowerShell Obfuscation via String Concatenation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Af6d8c743-0916-4483-8333-3c6f107e0caa) | Elastic | Elastic detection-rules |
| T1027.013 | [ROT Encoded Python Script Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A5ab49127-b1b3-46e6-8a38-9e8512a2a363) | Elastic | Elastic detection-rules |
| T1027.013 | [Data Encrypted via OpenSSL Utility](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Afeba48f6-40ca-4d04-b41f-5dfa327de865) | Elastic | Elastic detection-rules |
| T1036 | [Potential LSASS Process Dump Via Procdump](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A5afee48e-67dd-4e03-a783-f74259dcf998) | Sigma | SigmaHQ |
| T1036 | [Suspicious Use of Procdump on LSASS](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A5afee48e-67dd-4e03-a783-f74259dcf998) | Sigma | OpenSearch Security Analytics |
| T1041 | [Equation Group C2 Communication](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A881834a4-6659-4773-821e-1c151789d873) | Sigma | SigmaHQ |
| T1041 | [OpenCanary - TFTP Request](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab4e6b016-a2ac-4759-ad85-8000b300d61e) | Sigma | SigmaHQ |
| T1048.003 | [Suspicious WebDav Client Execution Via Rundll32.EXE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A982e9f2d-1a85-4d5b-aea4-31f5e97c6555) | Sigma | SigmaHQ |
| T1048.003 | [Possible DNS Tunneling](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A1ec4b281-aa65-46a2-bdae-5fd830ed914e) | Sigma | OpenSearch Security Analytics |
| T1059.003 | [HackTool - CrackMapExec Execution Patterns](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A058f4380-962d-40a5-afce-50207d36d7e2) | Sigma | SigmaHQ |
| T1059.003 | [CrackMapExec Command Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A058f4380-962d-40a5-afce-50207d36d7e2) | Sigma | OpenSearch Security Analytics |
| T1059.004 | [Shell Invocation via Env Command - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Abed978f8-7f3a-432b-82c5-9286a9b3031a) | Sigma | SigmaHQ |
| T1059.004 | [Suspicious Reverse Shell Command Line](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A738d9bcf-6999-4fdb-b4ac-3033037db8ab) | Sigma | SigmaHQ |
| T1059.005 | [Potential QBot Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4fcac6eb-0287-4090-8eea-2602e4c20040) | Sigma | SigmaHQ |
| T1059.005 | [QBot Process Creation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A4fcac6eb-0287-4090-8eea-2602e4c20040) | Sigma | OpenSearch Security Analytics |
| T1059.006 | [Emotet Loader Execution Via .LNK File](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1f32d820-1d5c-43fe-8fe2-feef0c952eb7) | Sigma | SigmaHQ |
| T1059.006 | [Serpent Backdoor Payload Execution Via Scheduled Task](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad5eb7432-fda4-4bba-a37f-ffa74d9ed639) | Sigma | SigmaHQ |
| T1059.007 | [Adwind RAT / JRAT](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1fac1481-2dbc-48b2-9096-753c49b4ec71) | Sigma | SigmaHQ |
| T1059.007 | [WScript or CScript Dropper - File](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A002bdb95-0cf1-46a6-9e08-d38c128a6127) | Sigma | SigmaHQ |
| T1070.004 | [File Deletion](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A30aed7b6-d2c1-4eaf-9382-b6bc43e50c57) | Sigma | SigmaHQ |
| T1070.004 | [Prefetch File Deleted](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A0a1f9d29-6465-4776-b091-7f43b26e4c89) | Sigma | SigmaHQ |
| T1071.003 | [SMTP to the Internet on Port 26/TCP](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ad7e62693-aab9-4f66-a21a-3d79ecdd603d) | Elastic | Elastic detection-rules |
| T1071.003 | [CYFIRMA - Brand Intelligence - Domain Impersonation High Rule](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A10bdf525-5b89-4a25-933a-e63e73b915f1) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1082 | [Potential GobRAT File Discovery Via Grep](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae34cfa0c-0a50-4210-9cb3-5632d08eb041) | Sigma | SigmaHQ |
| T1082 | [System Information Discovery](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A42df45e7-e6e9-43b5-8f26-bec5b39cc239) | Sigma | SigmaHQ |
| T1083 | [Turla Group Lateral Movement](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac601f20d-570a-4cde-a7d6-e17f99cb8e7f) | Sigma | SigmaHQ |
| T1083 | [WannaCry Ransomware Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A41d40bff-377a-43e2-8e1b-2e543069e079) | Sigma | SigmaHQ |
| T1090 | [Communication To LocaltoNet Tunneling Service Initiated - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac4568f5d-131f-4e78-83d4-45b2da0ec4f1) | Sigma | SigmaHQ |
| T1090 | [Communication To Ngrok Tunneling Service - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A19bf6fdb-7721-4f3d-867f-53467f6a5db6) | Sigma | SigmaHQ |
| T1204.001 | [Google Workspace Object Copied from External Drive with App Consent](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Af33e68a4-bd19-11ed-b02f-f661ea17fbcc) | Elastic | Elastic detection-rules |
| T1204.001 | [Suspicious ClickFix/FileFix Execution Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad487ed4a-fd24-436d-a0b2-f4e95f7b2635) | Sigma | SigmaHQ |
| T1204.002 | [Ursnif Malware C2 URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A932ac737-33ca-4afd-9869-0d48b391fcc9) | Sigma | SigmaHQ |
| T1204.002 | [Droppers Exploiting CVE-2017-11882](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A678eb5f4-8597-4be6-8be7-905e4234b53a) | Sigma | SigmaHQ |
| T1204.004 | [Potential TerminalFix Cloudflare Lure in PowerShell](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Aa4071476-76c8-4dc4-a3e2-956148d22aa2) | Elastic | Elastic detection-rules |
| T1204.004 | [Potential Fake CAPTCHA Phishing Attack](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Afbad57ec-4442-48db-a34f-5ee907b44a22) | Elastic | Elastic detection-rules |
| T1204.005 | [Node.js Pre or Post-Install Script Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A0871a5d8-6b5f-4a12-a568-fd7bc05bd8db) | Elastic | Elastic detection-rules |
| T1219.002 | [Antivirus - Exploitation Framework Signature](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A238527ad-3c2c-4e4f-a1f6-92fd63adb864) | Sigma | SigmaHQ |
| T1219.002 | [Potential SocGholish Second Stage C2 DNS Query](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A70761fe8-6aa2-4f80-98c1-a57049c08e66) | Sigma | SigmaHQ |
| T1480 | [[ZINGBOX] Risk level increased to Medium](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sagan-rules-quadrant%3A%3Asid-5004309) | Suricata/Snort | Sagan rules (Quadrant) |
| T1480 | [[ZINGBOX] Risk level increased to High](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sagan-rules-quadrant%3A%3Asid-5004310) | Suricata/Snort | Sagan rules (Quadrant) |
| T1497 | [Virtual Machine Fingerprinting](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A5b03c9fb-9945-4d2f-9568-fd690fee3fba) | Elastic | Elastic detection-rules |
| T1497 | [Potential Microsoft Office Sandbox Evasion](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ad22a85c6-d2ad-4cc4-bf7b-54787473669a) | Elastic | Elastic detection-rules |
| T1543.001 | [Potential Persistence Via PlistBuddy](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A65d506d3-fcfe-4071-b4b2-bcefe721bbbb) | Sigma | SigmaHQ |
| T1543.001 | [SSFileCopyReceiver Writing to Common Persistence Locations](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A5773cef4-11a5-4d51-a40b-0e0a79d68432) | Elastic | Elastic detection-rules |
| T1546.004 | [Suspicious Echo or Printf Execution Detected via Defend for Containers](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ad9bfa475-270d-4b07-93cb-b1f49abe13da) | Elastic | Elastic detection-rules |
| T1546.004 | [Curl Execution via Shell Profile](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Aafdca1e0-0f8a-4fcf-9e1e-95e09791e3cd) | Elastic | Elastic detection-rules |
| T1547.001 | [Potential Ryuk Ransomware Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac37510b8-2107-4b78-aa32-72f251e7a844) | Sigma | SigmaHQ |
| T1547.001 | [Ryuk Ransomware](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Ac37510b8-2107-4b78-aa32-72f251e7a844) | Sigma | OpenSearch Security Analytics |
| T1547.013 | [KDE AutoStart Script or Desktop File Creation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ae3e904b3-0a8e-4e68-86a8-977a163e21d3) | Elastic | Elastic detection-rules |
| T1547.013 | [Pod or Container Creation with Suspicious Command-Line](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ac595363f-52a6-49e1-9257-0e08ae043dbd) | Elastic | Elastic detection-rules |
| T1555.001 | [Keychain Password Retrieval via Command Line](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A9092cd6c-650f-4fa3-8a8a-28256c7489c9) | Elastic | Elastic detection-rules |
| T1555.001 | [Keychain CommandLine Interaction via Unsigned or Untrusted Process](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A96e90768-c3b7-4df6-b5d9-6237f8bc36a8) | Elastic | Elastic detection-rules |
| T1566.003 | [M365 Teams Rogue Help Desk Chat Created](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ae8e7b6b6-78b0-4015-97fe-c2f28468e0d4) | Elastic | Elastic detection-rules |
| T1566.003 | [M365 Azure Monitor Alert Email with Financial or Billing Theme](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Aa6129187-c47b-48ab-a412-67a44836d918) | Elastic | Elastic detection-rules |
| T1567 | [Monero Crypto Coin Mining Pool Lookup](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab593fd50-7335-4682-a36c-4edcb68e4641) | Sigma | SigmaHQ |
| T1567 | [Monero Crypto Coin Mining Pool Lookup](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Ab593fd50-7335-4682-a36c-4edcb68e4641) | Sigma | OpenSearch Security Analytics |
| T1567.002 | [APT40 Dropbox Tool User Agent](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A5ba715b6-71b7-44fd-8245-f66893e81b3d) | Sigma | SigmaHQ |
| T1567.002 | [PUA - Rclone Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae37db05d-d1f9-49c8-b464-cee1a4b11638) | Sigma | SigmaHQ |
| T1571 | [Potentially Suspicious Malware Callback Communication - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Adbfc7c98-04ab-4ab7-aa94-c74d22aa7376) | Sigma | SigmaHQ |
| T1571 | [Potentially Suspicious Malware Callback Communication](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4b89abaa-99fe-4232-afdd-8f9aa4d20382) | Sigma | SigmaHQ |
| T1573.001 | [CYFIRMA - High severity Command & Control Network Indicators with Monitor Recommendation Rule](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A6d8fb3fe-2501-4103-8137-34261fa3a596) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1573.001 | [CYFIRMA - High severity Command & Control Network Indicators with Block Recommendation Rule](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A6b61b716-afd9-4f6c-ad00-965d5987cafd) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1583 | [AWS Route 53 Private Hosted Zone Associated With a VPC](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ae3c27562-709a-42bd-82f2-3ed926cced19) | Elastic | Elastic detection-rules |
| T1583 | [AWS Service Quota Increase Requested by Rare Identity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A7e1b0654-b6c0-4b1b-ab47-75588533083c) | Elastic | Elastic detection-rules |
| T1583.001 | [AWS Route 53 Private Hosted Zone Associated With a VPC](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ae3c27562-709a-42bd-82f2-3ed926cced19) | Elastic | Elastic detection-rules |
| T1583.001 | [AWS SES Email Identity Verified Then Deleted](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A8e4bde35-125d-4eb3-9a2e-d7e77a053a08) | Elastic | Elastic detection-rules |
| T1583.006 | [GitHub Repo Created](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A6cea88e4-6ce2-4238-9981-a54c140d6336) | Elastic | Elastic detection-rules |
| T1583.006 | [Cisco Secure Firewall - Rare Snort Rule Triggered](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=splunk-security-content%3A%3Ae20313d2-7d63-4fcf-b2d9-d6e12c6c7bd7) | Splunk | Splunk security_content |
| T1585 | [A SAML Connector was created or modified](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=panther-panther-analysis%3A%3ATeleport.SAMLCreated) | Panther | Panther panther-analysis |
| T1585.001 | [CYFIRMA - Brand Intelligence - Social Media Handle Impersonation Detected High Rule](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A22f49d67-7da7-4809-8d07-89e4478aa6b0) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1585.001 | [CYFIRMA - Brand Intelligence - Executive/People Impersonation High Rule](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A159d26a1-591c-4f70-b1ca-2843c881aaec) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1587 | [FoggyWeb Backdoor DLL Loading](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A640dc51c-7713-4faa-8a0e-e7c0d9d4654c) | Sigma | SigmaHQ |
| T1587 | [CVE-2021-1675 Print Spooler Exploitation Filename Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A2131cfb3-8c12-45e8-8fa0-31f5924e9f07) | Sigma | SigmaHQ |
| T1587.001 | [Formbook Process Creation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A032f5fb3-d959-41a5-9263-4173c802dc2b) | Sigma | SigmaHQ |
| T1587.001 | [Uncommon File Created In Office Startup Folder](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aa10a2c40-2c4d-49f8-b557-1a946bc55d9d) | Sigma | SigmaHQ |
| T1588.002 | [Hacktool Execution - Imphash](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A24e3e58a-646b-4b50-adef-02ef935b9fc8) | Sigma | SigmaHQ |
| T1588.002 | [Renamed SysInternals DebugView Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acd764533-2e07-40d6-a718-cfeec7f2da7f) | Sigma | SigmaHQ |
| T1589 | [SSHD Error Message CVE-2018-15473](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4c9d903d-4939-4094-ade0-3cb748f4d7da) | Sigma | SigmaHQ |
| T1589 | [SSHD Error Message CVE-2018-15473](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A4c9d903d-4939-4094-ade0-3cb748f4d7da) | Sigma | OpenSearch Security Analytics |
| T1593 | [CYFIRMA - Social and Public Exposure -  Social Media Threats  Activity Detected Rule](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A4fe04459-13f1-4ff7-9b7c-f9be0c2aad6d) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1593 | [CYFIRMA - Social and Public Exposure - Confidential Files Information Exposure Rule](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A67e9c4aa-a2fa-4e4e-9272-1a8da41475c6) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1593.003 | [Suspicious Git Clone - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acfec9d29-64ec-4a0f-9ffe-0fdb856d5446) | Sigma | SigmaHQ |
| T1593.003 | [Suspicious Git Clone](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aaef9d1f1-7396-4e92-a927-4567c7a495c1) | Sigma | SigmaHQ |
| T1608.001 | [M365 OneDrive Malware File Upload](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Abba1b212-b85c-41c6-9b28-be0e5cdfc9b1) | Elastic | Elastic detection-rules |
| T1608.001 | [M365 SharePoint Malware File Detected](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A0e52157a-8e96-4a95-a6e3-5faae5081a74) | Elastic | Elastic detection-rules |
| T1657 | [AWS S3 Bucket Enumeration or Brute Force](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A5f0234fd-7f21-42af-8391-511d5fd11d5c) | Elastic | Elastic detection-rules |
| T1657 | [Monitor ransomwarelive for companies of interest on ransowmare data leak sites (DLS)](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=bert-janp-hunting-queries%3A%3A8b9af12a820a) | KQL hunting | Bert-JanP Hunting Queries |
| T1684.001 | [Entra ID OAuth user_impersonation Scope for Unusual User and Client](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A9563dace-5822-11f0-b1d3-f661ea17fbcd) | Elastic | Elastic detection-rules |
| T1685 | [Windows Defender Configuration Changes](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A801bd44f-ceed-4eb6-887c-11544633c0aa) | Sigma | SigmaHQ |
| T1685 | [Windows Defender Virus Scanning Feature Disabled](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A686c0b4b-9dd3-4847-9077-d6c1bbe36fcb) | Sigma | SigmaHQ |

## 8. Plano de emulação e validação

Use num laboratório isolado e autorizado para confirmar que as regras disparam. Os comandos estão nos repositórios oficiais.

| Tática | Técnica | Teste Atomic Red Team | Plataformas |
|---|---|---|---|
| Execution | [T1059.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.003/T1059.003.md) | Create and Execute Batch Script | windows |
| Execution | [T1059.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.003/T1059.003.md) | Writes text to a file and displays it. | windows |
| Execution | [T1059.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.004/T1059.004.md) | Create and Execute Bash Shell Script | linux, macos |
| Execution | [T1059.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.004/T1059.004.md) | Command-Line Interface | linux, macos |
| Execution | [T1059.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.005/T1059.005.md) | Visual Basic script execution to gather local computer information | windows |
| Execution | [T1059.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.005/T1059.005.md) | Encoded VBS code execution | windows |
| Execution | [T1059.007](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.007/T1059.007.md) | JScript execution to gather local computer information via cscript | windows |
| Execution | [T1059.007](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.007/T1059.007.md) | JScript execution to gather local computer information via wscript | windows |
| Execution | [T1204.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1204.002/T1204.002.md) | OSTap Style Macro Execution | windows |
| Execution | [T1204.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1204.002/T1204.002.md) | OSTap Payload Download | windows |
| Persistence | [T1543.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1543.001/T1543.001.md) | Launch Agent | macos |
| Persistence | [T1543.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1543.001/T1543.001.md) | Event Monitor Daemon Persistence | macos |
| Persistence | [T1547.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1547.001/T1547.001.md) | Reg Key Run | windows |
| Persistence | [T1547.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1547.001/T1547.001.md) | Reg Key RunOnce | windows |
| Privilege Escalation | [T1546.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1546.004/T1546.004.md) | Add command to .bash_profile | linux, macos |
| Privilege Escalation | [T1546.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1546.004/T1546.004.md) | Add command to .bashrc | linux, macos |
| Stealth | [T1027.013](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027.013/T1027.013.md) | Decode Eicar File and Write to File | linux, macos, windows |
| Stealth | [T1027.013](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027.013/T1027.013.md) | Decrypt Eicar File and Write to File | linux, macos, windows |
| Stealth | [T1036](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036/T1036.md) | System File Copied to Unusual Location | windows |
| Stealth | [T1036](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036/T1036.md) | Malware Masquerading and Execution from Zip File | windows |
| Stealth | [T1070.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.004/T1070.004.md) | Delete a single file - FreeBSD/Linux/macOS | linux, macos |
| Stealth | [T1070.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.004/T1070.004.md) | Delete an entire folder - FreeBSD/Linux/macOS | linux, macos |
| Defense Impairment | [T1685](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1685/T1685.md) | Windows Disable LSA Protection | windows |
| Defense Impairment | [T1685](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1685/T1685.md) | Disable journal logging via systemctl utility | linux |
| Credential Access | [T1555.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1555.001/T1555.001.md) | Keychain Dump | macos |
| Credential Access | [T1555.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1555.001/T1555.001.md) | Export Certificate Item(s) | macos |
| Discovery | [T1082](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1082/T1082.md) | System Information Discovery | windows |
| Discovery | [T1082](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1082/T1082.md) | System Information Discovery | macos |
| Discovery | [T1083](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1083/T1083.md) | File and Directory Discovery (cmd.exe) | windows |
| Discovery | [T1083](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1083/T1083.md) | File and Directory Discovery (PowerShell) | windows |
| Command and Control | [T1571](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1571/T1571.md) | Testing usage of uncommonly used port with PowerShell | windows |
| Command and Control | [T1571](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1571/T1571.md) | Testing usage of uncommonly used port | linux, macos |
| Exfiltration | [T1041](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1041/T1041.md) | C2 Data Exfiltration | windows |
| Exfiltration | [T1041](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1041/T1041.md) | Text Based Data Exfiltration using DNS subdomains | windows |
| Exfiltration | [T1048.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1048.003/T1048.003.md) | Exfiltration Over Alternative Protocol - HTTP | linux, macos |
| Exfiltration | [T1048.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1048.003/T1048.003.md) | Exfiltration Over Alternative Protocol - ICMP | windows |
| Exfiltration | [T1567.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1567.002/T1567.002.md) | Exfiltrate data with rclone to cloud Storage - Mega (Windows) | windows |
| Exfiltration | [T1567.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1567.002/T1567.002.md) | Exfiltrate data with rclone to cloud Storage - AWS S3 | linux, macos |

**Logs reais de ataque (EVTX) para testar sem executar nada:**

- T1036 — [rundll32_hollowing_wermgr_masquerading](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/AutomatedTestingTools/Malware/rundll32_hollowing_wermgr_masquerading.evtx) _(inferido)_
- T1059.003 — [ID4688-SQL Server payload injectection for reverse shell (MSF)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1059.003-Windows%20Command%20Shell/ID4688-SQL%20Server%20payload%20injectection%20for%20reverse%20shell%20%28MSF%29.evtx) _(explícito)_
- T1090 — [ID5600-proxy configuration changed](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0011-Command%20and%20Control/T1090-Proxy/ID5600-proxy%20configuration%20changed.evtx) _(explícito)_
- T1547.001 — [sideloading_injection_persistence_run_key](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/AutomatedTestingTools/Malware/sideloading_injection_persistence_run_key.evtx) _(inferido)_
- T1547.001 — [evasion_persis_hidden_run_keyvalue_sysmon_13](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Persistence/evasion_persis_hidden_run_keyvalue_sysmon_13.evtx) _(inferido)_
- T1685 — [ID1-SYSMON driver unload (FilterManager)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0005-Defense%20Evasion/T1562.001-Impair%20Defenses-Disable%20or%20Modify%20tool/ID1-SYSMON%20driver%20unload%20%28FilterManager%29.evtx) _(explícito)_
- T1685 — [ID13-Defender service configuration disabled](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0005-Defense%20Evasion/T1562.001-Impair%20Defenses-Disable%20or%20Modify%20tool/ID13-Defender%20service%20configuration%20disabled.evtx) _(explícito)_

## 9. Hipóteses de hunting

Se Contagious Interview estiver no seu ambiente, estas são as perguntas a fazer aos seus dados (fontes de log segundo as estratégias de detecção do MITRE ATT&CK).

1. **T1204.005 Malicious Library** — User-initiated installation of Python (pip), NodeJS (npm), or other language libraries, followed by unexpected network connections, credential access, or startup file modifications. Defender sees `pip install` or `npm install` commands run by a non-root user,… Dados: `auditd:SYSCALL` (execve: Execution of pip, npm, gem, or similar package managers), `auditd:PATH` (New .py/.js/.sh files written to ~/.local/, ~/.cache/, or /tmp/ within 5 min of package install), `NSM:Flow` (http::request: Network connection to package registry or C2 from interpreter shortly after install).
2. **T1546.004 Unix Shell Configuration Modification** — Detects modification of shell startup/logout scripts such as ~/.bashrc, ~/.bash_profile, or /etc/profile, followed by anomalous process execution or network connections upon interactive or remote shell login. Dados: `auditd:SYSCALL` (AUDIT_SYSCALL (open, write, rename, unlink)), `auditd:EXECVE` (execution of unexpected binaries during user shell startup), `NSM:Flow` (unexpected network activity initiated shortly after shell session starts).
3. **T1547.013 XDG Autostart Entries** — Correlation of file creation/modification of `.desktop` files within XDG autostart directories, followed by execution of processes at user login initiated by the desktop environment. Malicious entries typically include suspicious Exec paths or anomalous names… Dados: `auditd:SYSCALL` (creat), `auditd:SYSCALL` (open), `auditd:EXECVE` (Process execution via .desktop Exec path from /etc/xdg/autostart or ~/.config/autostart).
4. **T1543.001 Launch Agent** — Detects creation or modification of user-level Launch Agents in monitored directories using `.plist` files with suspicious `ProgramArguments` or `RunAtLoad` keys. Correlates file write activity with execution of `launchctl` or unsigned binaries invoked at… Dados: `macos:unifiedlog` (launchctl load or boot-time plist registration), `fs:fsusage` (write or chmod to ~/Library/LaunchAgents/*.plist), `fs:fsusage` (modification of existing LaunchAgents plist).
5. **T1555.001 Keychain** — Detects suspicious access to macOS Keychain files and APIs. Observes processes invoking the 'security' utility or accessing Keychain databases directly, correlates these with abnormal parent process lineage or unexpected user context. Monitors attempts to… Dados: `macos:unifiedlog` (execution of security or osascript), `macos:unifiedlog` (access or unlock attempt to keychain database), `macos:unifiedlog` (read access to ~/Library/Keychains/login.keychain-db).
6. **T1204.004 Malicious Copy and Paste** — A user is socially engineered (web page, email, document) to open Run/PowerShell/CMD and paste an obfuscated one-liner. The chain is: (1) user context active in a browser/email/office app → (2) process creation of a command interpreter with suspicious… Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:PowerShell` (EventCode=4103, 4104, 4105, 4106), `WinEventLog:Sysmon` (EventCode=11).
7. **T1497 Virtualization/Sandbox Evasion** — Execution of discovery commands or API calls for virtualization artifacts (e.g., registry keys, device drivers, services), sleep/skipped execution behavior, or sandbox evasion DLLs before payload deployment. Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=7).
8. **T1587 Develop Capabilities** — Consider analyzing malware for features that may be associated with the adversary and/or their developers, such as compiler used, debugging artifacts, or code similarities. Malware repositories can also be used to identify additional samples associated with… Dados: `Malware Repository` (None), `Malware Repository` (None), `Internet Scan` (None).
9. **T1480 Execution Guardrails** — Windows environmental validation behavioral chain: (1) Rapid system discovery reconnaissance through WMI queries, registry enumeration, and network share discovery, (2) Environment-specific artifact collection (hostname, domain, IP addresses, installed… Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:Security` (EventCode=4648), `WinEventLog:Security` (EventCode=4624, 4648).
10. **T1071.003 Mail Protocols** — Detects unauthorized use of SMTP/IMAP/POP3 by suspicious binaries (e.g., PowerShell, rundll32) to exfiltrate data or beacon via email, often bypassing proxy or content filters. Dados: `WinEventLog:Sysmon` (EventCode=3, 22), `WinEventLog:Sysmon` (EventCode=1), `NSM:Flow` (smtp.log).
11. **T1567 Exfiltration Over Web Service** — Processes that normally do not initiate network communications suddenly making outbound HTTPS connections with high outbound-to-inbound data ratios. Defender view: correlation between process creation logs (e.g., Word, Excel, PowerShell) and subsequent… Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=3, 22), `WinEventLog:Sysmon` (EventCode=11).
12. **T1585 Establish Accounts** — Monitor and analyze traffic patterns and packet inspection associated to protocol(s) that do not follow the expected protocol standards and traffic flows (e.g extraneous packets that do not belong to established flows, gratuitous or anomalous traffic… Dados: `Network Traffic` (None), `Persona` (None).

## 10. OSINT — onde pesquisar

Consultas prontas com todos os nomes conhecidos do grupo:

- Relatórios técnicos: [busca web](https://duckduckgo.com/?q=%28%22Contagious+Interview%22+OR+%22DeceptiveDevelopment%22+OR+%22Gwisin+Gang%22+OR+%22Tenacious+Pungsan%22+OR+%22DEV%23POPPER%22+OR+%22PurpleBravo%22%29+threat+report) · [PDFs](https://duckduckgo.com/?q=%28%22Contagious+Interview%22+OR+%22DeceptiveDevelopment%22+OR+%22Gwisin+Gang%22+OR+%22Tenacious+Pungsan%22+OR+%22DEV%23POPPER%22+OR+%22PurpleBravo%22%29+filetype%3Apdf)
- Regras e IOCs publicados: [GitHub](https://github.com/search?type=code&q=%22Contagious+Interview%22+OR+%22DeceptiveDevelopment%22+OR+%22Gwisin+Gang%22+OR+%22Tenacious+Pungsan%22+OR+%22DEV%23POPPER%22+OR+%22PurpleBravo%22)
- Pulsos de ameaça: [AlienVault OTX](https://otx.alienvault.com/browse/global/pulses?q=Contagious+Interview)
- Família de malware e atores: [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/actors) (busque por Contagious Interview, DeceptiveDevelopment, Gwisin Gang)
- Cartões de grupo: [ThaiCERT Threat Group Cards](https://apt.etda.or.th/cgi-bin/listgroups.cgi)
- Página oficial: [MITRE ATT&CK G1052](https://attack.mitre.org/groups/G1052/)

## 11. Bibliografia (17 fontes citadas pelo ATT&CK)

- [Datadog Contagious Interview Tenacious Pungsan October 2024](https://securitylabs.datadoghq.com/articles/tenacious-pungsan-dprk-threat-actor-contagious-interview/) — Ian Kretz, Sebastian Obregoso, Datadog Security Research Team. (2024, October 24). Tenacious Pungsan: A DPRK threat actor linked to Contagious Interview. Retrieved October 20, 2025.
- [dtex DPRK 2025 structure ITworkers](https://reports.dtexsystems.com/DTEX-Exposing+DPRK+Cyber+Syndicate+and+Hidden+IT+Workforce.pdf) — Michael “Barni” Barnhart, DTEX, and Anonymous SMEs. (2025, May 14). Exposing DPRK's Cyber Syndicate and Hidden IT Workforce. Retrieved September 3, 2025.
- [Esentire ContagiousInterview BeaverTail InvisibleFerret November 2024](https://www.esentire.com/blog/bored-beavertail-invisibleferret-yacht-club-a-lazarus-lure-pt-2) — eSentire Threat Response Unit (TRU). (2024, November 14). Bored BeaverTail & InvisibleFerret Yacht Club – A Lazarus Lure Pt.2. Retrieved October 17, 2025.
- [ESET Contagious Interview BeaverTail InvisibleFerret February 2025](https://www.welivesecurity.com/en/eset-research/deceptivedevelopment-targets-freelance-developers/) — Matej Havranek. (2025, February 20). DeceptiveDevelopment targets freelance developers. Retrieved October 17, 2025.
- [PaloAlto ContagiousInterview BeaverTail InvisibleFerret November 2023](https://unit42.paloaltonetworks.com/two-campaigns-by-north-korea-bad-actors-target-job-hunters/) — Unit 42. (2023, November 21). Hacking Employers and Seeking Employment: Two Job-Related Campaigns Bear Hallmarks of North Korean Threat Actors. Retrieved October 17, 2025.
- [PaloAlto Unit42 ContagiousInterview BeaverTail InvisibileFerret October 2024](https://unit42.paloaltonetworks.com/north-korean-threat-actors-lure-tech-job-seekers-as-fake-recruiters/) — Unit42. (2024, October 9). Contagious Interview: DPRK Threat Actors Lure Tech Industry Job Seekers to Install New Variants of BeaverTail and InvisibleFerret Malware. Retrieved October 17, 2025.
- [Recorded Future Contagious Inteview BeaverTail InvisibleFerret OtterCookie February 2025](https://www.recordedfuture.com/research/inside-the-scam-north-koreas-it-worker-threat) — Insikt Group. (2025, February 13). Inside the Scam: North Korea’s IT Worker Threat. Retrieved October 17, 2025.
- [SecurityScorecard Contagious Interview FamousChollima October 2024](https://securityscorecard.com/blog/the-job-offer-that-wasnt-how-we-stopped-an-espionage-plot/) — Steve Cobb. (2024, October 29). The Job Offer That Wasn’t: How We Stopped an Espionage Plot. Retrieved October 20, 2025.
- [SecurityScorecard Contagious Interview October 2024](https://securityscorecard.com/blog/inside-a-north-korean-phishing-operation-targeting-devops-employees/) — Ryan Sherstobitoff. (2024, October 29). Inside a North Korean Phishing Operation Targeting DevOps Employees. Retrieved October 20, 2025.
- [Securonix Contagious Interview DEVPOPPER April 2024](https://www.securonix.com/blog/analysis-of-devpopper-new-attack-campaign-targeting-software-developers-likely-associated-with-north-korean-threat-actors/) — Securonix Threat Research, D.Iuzvyk, T. Peck, O.Kolesnikov. (2024, April 24). Analysis of DEV#POPPER: New Attack Campaign Targeting Software Developers Likely Associated With North Korean Threat Actors. Retrieved October
- [Sekoia ClickFake 2025](https://blog.sekoia.io/clickfake-interview-campaign-by-lazarus/) — Amaury G., Coline Chavane, Felix Aimé and Sekoia TDR. (2025, March 31). From Contagious to ClickFake Interview: Lazarus leveraging the ClickFix tactic. Retrieved April 1, 2025.
- [Sentinel One Contagious Interview ClickFix September 2025](https://www.sentinelone.com/labs/contagious-interview-threat-actors-scout-cyber-intel-platforms-reveal-plans-and-ops/) — Aleksandar Milenkoski, Sreekar Madabushi, Kenneth Kinion. (2025, September 4). Contagious Interview | North Korean Threat Actors Reveal Plans and Ops by Abusing Cyber Intel Platforms. Retrieved October 20, 2025.
- [Socket BeaverTail XORIndex HexEval Contagious Interview July 2025](https://socket.dev/blog/contagious-interview-campaign-escalates-67-malicious-npm-packages) — Kirill Boychenko. (2025, July 14). Contagious Interview Campaign Escalates With 67 Malicious npm Packages and New Malware Loader. Retrieved October 19, 2025.
- [Socket Contagious Interview NPM April 2025](https://socket.dev/blog/lazarus-expands-malicious-npm-campaign-11-new-packages-add-malware-loaders-and-bitbucket) — Kirill Boychenko. (2025, April 4). Lazarus Expands Malicious npm Campaign: 11 New Packages Add Malware Loaders and Bitbucket Payloads. Retrieved October 20, 2025.
- [Socket HexEval BeaverTail Contagious Interview June 2025](https://socket.dev/blog/north-korean-contagious-interview-campaign-drops-35-new-malicious-npm-packages) — Kirill Boychenko. (2025, June 25). Another Wave: North Korean Contagious Interview Campaign Drops 35 New Malicious npm Packages. Retrieved October 19, 2025.
- [Validin Contagious Interview North Korea ClickFix January 2025](https://www.validin.com/blog/inoculating_contagious_interview_with_validin/) — Efstratios Lontzetidis. (2025, January 16). Lazarus APT: Techniques for Hunting Contagious Interview. Retrieved October 20, 2025.
- [Zscaler ContagiousInterview BeaverTail InvisibleFerret November 2024](https://www.zscaler.com/blogs/security-research/pyongyang-your-payroll-rise-north-korean-remote-workers-west) — Seongsu Park. (2024, November 4). From Pyongyang to Your Payroll: The Rise of North Korean Remote Workers in the West. Retrieved October 17, 2025.

## 12. Limites e confiança

- O ATT&CK registra o que foi **relatado publicamente**, não tudo o que o grupo faz. Ausência de uma técnica não prova que o grupo não a usa.
- **Sobreposição de TTP não é atribuição.** Muitas técnicas são compartilhadas entre grupos e com red teams. Use a assinatura comportamental como hipótese, junto com infraestrutura, malware e contexto.
- Cobertura de detecção refere-se ao catálogo público Detection Rules, não ao seu ambiente: confira se a telemetria necessária chega ao seu SIEM.
- Ligações marcadas como _inferidas_ (EVTX por palavra-chave, relatórios por nome) devem ser verificadas.

---
Fontes: MITRE ATT&CK® (uso livre com atribuição, © The MITRE Corporation), Atomic Red Team (Red Canary, MIT), EVTX-to-MITRE-Attack, EVTX-ATTACK-SAMPLES, APT & CyberCriminal Campaign Collections. Gerado por [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules).
