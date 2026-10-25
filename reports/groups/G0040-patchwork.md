# Patchwork (G0040) — Dossiê de inteligência

> **TLP:CLEAR** · gerado em 2026-10-25 a partir de fontes abertas · MITRE ATT&CK v20.0 · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0040) · [ATT&CK](https://attack.mitre.org/groups/G0040/)

**Também conhecido como:** Hangover Group, Dropping Elephant, Chinastrats, MONSOON, Operation Hangover  
**Registro no ATT&CK:** criado em 2017-05-31, atualizado em 2026-07-31 · referências de 2013 a 2020

## 1. Sumário executivo

- **41 técnicas** atribuídas publicamente, concentradas em **Execution, Stealth, Discovery**.
- **Arsenal:** 6 malware e 2 ferramentas (ex.: PowerSploit, QuasarRAT, BADNEWS, BackConfig, Unknown Logger).
- **Campanhas atribuídas:** 0.
- **Cobertura de detecção pública:** 93% das técnicas têm ao menos uma regra no catálogo; **3 técnicas sem nenhuma regra pública**.
- **Assinatura comportamental** (técnicas raras entre os 178 grupos, as mais úteis para atribuição): T1587.002 Code Signing Certificates, T1197 BITS Jobs, T1102.001 Dead Drop Resolver, T1027.005 Indicator Removal from Tools, T1027.001 Binary Padding.

## 2. Quem é

> Patchwork is a cyber espionage group that was first observed in December 2015. While the group has not been definitively attributed, circumstantial evidence suggests the group may be a pro-Indian or Indian entity. Patchwork has been seen targeting industries related to diplomatic and government agencies. Much of the code used by this group was copied and pasted from online forums. Patchwork was also seen operating spearphishing campaigns targeting U.S. think tank groups in March and April of 2018.

_Texto original do MITRE ATT&CK, em inglês._

## 3. Perfil TTP por tática (kill chain)

Cada linha: técnica, como o grupo a usou segundo relatos públicos, e o que existe para detectar e testar.

### Reconnaissance (TA0043) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1598.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1598.003) Spearphishing Link | Patchwork has used embedded image tags (known as web bugs) with unique, per-recipient tracking links in their emails for the purpose of identifying which recipients opened messages. | **0** | — | — |

### Resource Development (TA0042) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1587.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1587.002) Code Signing Certificates | Patchwork has created self-signed certificates from fictitious and spoofed legitimate software companies that were later used to sign malware. | **0** | — | — |
| [T1588.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1588.002) Tool | Patchwork has obtained and used open-source tools such as QuasarRAT. | 35 | — | — |

### Initial Access (TA0001) — 3

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1189](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1189) Drive-by Compromise | Patchwork has used watering holes to deliver files with exploits to initial victims. | 57 | — | — |
| [T1566.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1566.001) Spearphishing Attachment | Patchwork has used spearphishing with an attachment to deliver files with exploits to initial victims. | 230 | 2 | — |
| [T1566.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1566.002) Spearphishing Link | Patchwork has used spearphishing with links to deliver files with exploits to initial victims. | 138 | 1 | — |

### Execution (TA0002) — 10

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1053.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1053.005) Scheduled Task | A Patchwork file stealer can run a TaskScheduler DLL to add persistence. | 248 | 14 | 11 |
| [T1059.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.001) PowerShell | Patchwork used PowerSploit to download payloads, run a reverse shell, and execute malware on the victim's machine. | 1340 | 22 | 15 |
| [T1059.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.003) Windows Command Shell | Patchwork ran a reverse shell with Meterpreter. Patchwork used JavaScript code and .SCT files on victim machines. | 269 | 6 | 1 |
| [T1059.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.005) Visual Basic | Patchwork used Visual Basic Scripts (VBS) on victim machines. | 192 | 3 | — |
| [T1197](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1197) BITS Jobs | Patchwork has used BITS jobs to download malicious payloads. | 94 | 4 | 8 |
| [T1203](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1203) Exploitation for Client Execution | Patchwork uses malicious documents to deliver remote execution exploits as part of. The group has previously exploited CVE-2017-8570, CVE-2012-1856, CVE-2014-4114, CVE-2017-0199, CVE-2017-11882, and CVE-2015-1641. | 202 | — | — |
| [T1204.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1204.001) Malicious Link | Patchwork has used spearphishing with links to try to get users to click, download and open malicious files. | 52 | — | — |
| [T1204.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1204.002) Malicious File | Patchwork embedded a malicious macro in a Word document and lured the victim to click on an icon to execute the malware. | 259 | 13 | — |
| [T1559.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1559.002) Dynamic Data Exchange | Patchwork leveraged the DDE protocol to deliver their malware. | 10 | 3 | — |
| [T1574.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1574.001) DLL | A Patchwork .dll that contains BADNEWS is loaded and executed using DLL side-loading. | 455 | 7 | 5 |

### Persistence (TA0003) — 4

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1053.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1053.005) Scheduled Task | A Patchwork file stealer can run a TaskScheduler DLL to add persistence. | 248 | 14 | 11 |
| [T1112](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1112) Modify Registry | A Patchwork payload deletes Resiliency Registry keys created by Microsoft Office applications in an apparent effort to trick users into thinking there were no issues during application runs. | 601 | 92 | 3 |
| [T1197](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1197) BITS Jobs | Patchwork has used BITS jobs to download malicious payloads. | 94 | 4 | 8 |
| [T1547.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1547.001) Registry Run Keys / Startup Folder | Patchwork has added the path of its second-stage malware to the startup folder to achieve persistence. One of its file stealers has also persisted by adding a Registry Run key. | 299 | 21 | 2 |

### Privilege Escalation (TA0004) — 4

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1053.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1053.005) Scheduled Task | A Patchwork file stealer can run a TaskScheduler DLL to add persistence. | 248 | 14 | 11 |
| [T1055.012](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1055.012) Process Hollowing | A Patchwork payload uses process hollowing to hide the UAC bypass vulnerability exploitation inside svchost.exe. | 29 | 4 | 2 |
| [T1547.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1547.001) Registry Run Keys / Startup Folder | Patchwork has added the path of its second-stage malware to the startup folder to achieve persistence. One of its file stealers has also persisted by adding a Registry Run key. | 299 | 21 | 2 |
| [T1548.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1548.002) Bypass User Account Control | Patchwork bypassed User Access Control (UAC). | 379 | 28 | 14 |

### Stealth (TA0005) — 9

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1027.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1027.001) Binary Padding | Patchwork apparently altered NDiskMonitor samples by adding four bytes of random letters in a likely attempt to change the file hashes. | 13 | 3 | — |
| [T1027.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1027.002) Software Packing | A Patchwork payload was packed with UPX. | 12 | 4 | — |
| [T1027.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1027.005) Indicator Removal from Tools | Patchwork apparently altered NDiskMonitor samples by adding four bytes of random letters in a likely attempt to change the file hashes. | 24 | — | — |
| [T1027.010](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1027.010) Command Obfuscation | Patchwork has obfuscated a script with Crypto Obfuscator. | 78 | — | — |
| [T1036.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1036.005) Match Legitimate Resource Name or Location | Patchwork installed its payload in the startup programs folder as "Baidu Software Update." The group also adds its second stage payload to the startup programs as “Net Monitor." They have also dropped QuasarRAT binaries as files named microsoft_network.exe and… | 116 | 4 | — |
| [T1055.012](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1055.012) Process Hollowing | A Patchwork payload uses process hollowing to hide the UAC bypass vulnerability exploitation inside svchost.exe. | 29 | 4 | 2 |
| [T1070.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1070.004) File Deletion | Patchwork removed certain files and replaced them so they could not be retrieved. | 132 | 11 | — |
| [T1197](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1197) BITS Jobs | Patchwork has used BITS jobs to download malicious payloads. | 94 | 4 | 8 |
| [T1574.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1574.001) DLL | A Patchwork .dll that contains BADNEWS is loaded and executed using DLL side-loading. | 455 | 7 | 5 |

### Defense Impairment (TA0112) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1112](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1112) Modify Registry | A Patchwork payload deletes Resiliency Registry keys created by Microsoft Office applications in an apparent effort to trick users into thinking there were no issues during application runs. | 601 | 92 | 3 |
| [T1553.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1553.002) Code Signing | Patchwork has signed malware with self-signed certificates from fictitious and spoofed legitimate software companies. | 11 | — | — |

### Credential Access (TA0006) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1555.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1555.003) Credentials from Web Browsers | Patchwork dumped the login data database from \AppData\Local\Google\Chrome\User Data\Default\Login Data. | 59 | 18 | 5 |

### Discovery (TA0007) — 5

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1033](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1033) System Owner/User Discovery | Patchwork collected the victim username and whether it was running as admin, then sent the information to its C2 server. | 181 | 8 | — |
| [T1082](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1082) System Information Discovery | Patchwork collected the victim computer name, OS version, and architecture type and sent the information to its C2 server. | 264 | 41 | — |
| [T1083](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1083) File and Directory Discovery | A Patchwork payload has searched all fixed drives on the victim for files matching a specified list of extensions. | 137 | 9 | — |
| [T1518.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1518.001) Security Software Discovery | Patchwork scanned the “Program Files” directories for a directory with the string “Total Security” (the installation path of the “360 Total Security” antivirus tool). | 54 | 12 | — |
| [T1680](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1680) Local Storage Discovery | Patchwork enumerated all available drives on the victim's machine. | **0** | — | — |

### Lateral Movement (TA0008) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1021.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1021.001) Remote Desktop Protocol | Patchwork attempted to use RDP to move laterally. | 139 | 4 | 7 |

### Collection (TA0009) — 4

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1005) Data from Local System | Patchwork collected and exfiltrated files from the infected system. | 170 | 3 | — |
| [T1074.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1074.001) Local Data Staging | Patchwork copied all targeted files to a directory called index that was eventually uploaded to the C&C server. | 37 | 3 | — |
| [T1119](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1119) Automated Collection | Patchwork developed a file stealer to search C:\ and collect files with certain extensions. Patchwork also executed a script to enumerate all drives, store them as a list, and upload generated files to the C2 server. | 72 | 4 | — |
| [T1560](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1560) Archive Collected Data | Patchwork encrypted the collected files' path with AES and then encoded them with base64. | 53 | 1 | — |

### Command and Control (TA0011) — 3

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1102.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1102.001) Dead Drop Resolver | Patchwork hides base64-encoded and encrypted C2 server locations in comments on legitimate websites. | 18 | — | — |
| [T1105](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1105) Ingress Tool Transfer | Patchwork payloads download additional files from the C2 server. | 644 | 39 | — |
| [T1132.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1132.001) Standard Encoding | Patchwork used Base64 to encode C2 traffic. | 26 | 3 | — |

## 4. Assinatura comportamental

Técnicas que este grupo usa e que poucos dos 178 grupos do ATT&CK usam. Pesam mais numa atribuição por TTP: ver várias delas juntas é mais informativo do que ver técnicas comuns como PowerShell.

| Técnica | Outros grupos que usam | Peso (raridade) |
|---|---:|---:|
| T1587.002 Code Signing Certificates | 2 | 3.80 |
| T1197 BITS Jobs | 4 | 3.40 |
| T1102.001 Dead Drop Resolver | 5 | 3.24 |
| T1027.005 Indicator Removal from Tools | 6 | 3.11 |
| T1027.001 Binary Padding | 7 | 2.99 |
| T1055.012 Process Hollowing | 7 | 2.99 |
| T1680 Local Storage Discovery | 9 | 2.79 |
| T1548.002 Bypass User Account Control | 10 | 2.70 |
| T1559.002 Dynamic Data Exchange | 10 | 2.70 |
| T1132.001 Standard Encoding | 12 | 2.55 |

## 5. Arsenal

| Software | Tipo | Técnicas no ATT&CK | Uso relatado (EN) |
|---|---|---:|---|
| [PowerSploit](https://attack.mitre.org/software/S0194/) | ferramenta | 28 |  |
| [QuasarRAT](https://attack.mitre.org/software/S0262/) | ferramenta | 25 |  |
| [BADNEWS](https://attack.mitre.org/software/S0128/) | malware | 24 |  |
| [BackConfig](https://attack.mitre.org/software/S0475/) | malware | 16 |  |
| [Unknown Logger](https://attack.mitre.org/software/S0130/) | malware | 8 |  |
| [NDiskMonitor](https://attack.mitre.org/software/S0272/) | malware | 5 |  |
| [TINYTYPHON](https://attack.mitre.org/software/S0131/) | malware | 4 |  |
| [AutoIt backdoor](https://attack.mitre.org/software/S0129/) | malware | 4 |  |

## 6. Campanhas

Nenhuma campanha atribuída no ATT&CK.

## 7. Cobertura defensiva

**38 de 41 técnicas (93%)** têm ao menos uma regra pública no catálogo Detection Rules.

### Técnicas sem regra pública (prioridade para engenharia de detecção)

- **T1587.002 Code Signing Certificates** — Resource Development. Fonte de log sugerida pelo MITRE: `Malware Repository` None
- **T1680 Local Storage Discovery** — Discovery. Fonte de log sugerida pelo MITRE: `WinEventLog:Sysmon` EventCode=1; `auditd:SYSCALL` execve call with argv matching known disk enumeration commands (lsblk, parted, fdisk); `macos:unifiedlog` process launch of diskutil or system_profil
- **T1598.003 Spearphishing Link** — Reconnaissance. Fonte de log sugerida pelo MITRE: `Application Log` None

### Regras recomendadas por técnica

Melhor regra disponível por técnica (formato portável e maduro primeiro).

| Técnica | Regra | Formato | Fonte |
|---|---|---|---|
| T1005 | [Potential Conti Ransomware Database Dumping Activity Via SQLCmd](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A2f47f1fd-0901-466e-a770-3b7092834a1b) | Sigma | SigmaHQ |
| T1005 | [OpenCanary - SMB File Open Request](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A22777c9e-873a-4b49-855f-6072ab861a52) | Sigma | SigmaHQ |
| T1021.001 | [Hermetic Wiper TG Process Patterns](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A2f974656-6d83-4059-bbdf-68ac5403422f) | Sigma | SigmaHQ |
| T1021.001 | [Publicly Accessible RDP Service](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1fc0809e-06bf-4de3-ad52-25e5263b7623) | Sigma | SigmaHQ |
| T1027.001 | [Binary Padding - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac52a914f-3d8b-4b2a-bb75-b3991e75f8ba) | Sigma | SigmaHQ |
| T1027.001 | [Failed Code Integrity Checks](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A470ec5fa-7b4e-4071-b200-4c753100f49b) | Sigma | SigmaHQ |
| T1027.002 | [Python Image Load By Non-Python Process](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acbb56d62-4060-40f7-9466-d8aaf3123f83) | Sigma | SigmaHQ |
| T1027.002 | [Python Py2Exe Image Load](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Acbb56d62-4060-40f7-9466-d8aaf3123f83) | Sigma | OpenSearch Security Analytics |
| T1027.005 | [PUA - DefenderCheck Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Af0ca6c24-3225-47d5-b1f5-352bf07ecfa7) | Sigma | SigmaHQ |
| T1027.005 | [HackTool - CrackMapExec PowerShell Obfuscation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A6f8b3439-a203-45dc-a88b-abf57ea15ccf) | Sigma | SigmaHQ |
| T1027.010 | [Decoded Payload Piped to Interpreter Detected via Defend for Containers](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A0fb83aa0-3d17-41e9-b09c-56397bf7a7d9) | Elastic | Elastic detection-rules |
| T1027.010 | [Potential PowerShell Obfuscation via String Concatenation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Af6d8c743-0916-4483-8333-3c6f107e0caa) | Elastic | Elastic detection-rules |
| T1033 | [Potential Dridex Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae6eb5a96-9e6f-4a18-9cdd-642cfda21c8e) | Sigma | SigmaHQ |
| T1033 | [Dridex Process Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Ae6eb5a96-9e6f-4a18-9cdd-642cfda21c8e) | Sigma | OpenSearch Security Analytics |
| T1036.005 | [Exploit for CVE-2015-1641](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A7993792c-5ce2-4475-a3db-a3a5539827ef) | Sigma | SigmaHQ |
| T1036.005 | [Exploit for CVE-2015-1641](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A7993792c-5ce2-4475-a3db-a3a5539827ef) | Sigma | OpenSearch Security Analytics |
| T1053.005 | [Operation Wocao Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1cfac73c-be78-4f9a-9b08-5bde0c3953ab) | Sigma | SigmaHQ |
| T1053.005 | [Operation Wocao Activity - Security](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A74ad4314-482e-4c3e-b237-3f7ed3b9ca8d) | Sigma | SigmaHQ |
| T1055.012 | [Potential Pikabot Hollowing Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad8937fe7-42d5-4b4d-8178-e089c908f63f) | Sigma | SigmaHQ |
| T1055.012 | [HackTool - CACTUSTORCH Remote Thread Creation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A2e4e488a-6164-4811-9ea1-f960c7359c40) | Sigma | SigmaHQ |
| T1059.001 | [Potential Emotet Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad02e8cf5-6099-48cf-9bfc-1eec2d0c7b18) | Sigma | SigmaHQ |
| T1059.001 | [TropicTrooper Campaign November 2018](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A8c7090c3-e0a0-4944-bd08-08c3a0cecf79) | Sigma | SigmaHQ |
| T1059.003 | [HackTool - CrackMapExec Execution Patterns](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A058f4380-962d-40a5-afce-50207d36d7e2) | Sigma | SigmaHQ |
| T1059.003 | [CrackMapExec Command Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A058f4380-962d-40a5-afce-50207d36d7e2) | Sigma | OpenSearch Security Analytics |
| T1059.005 | [Potential QBot Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4fcac6eb-0287-4090-8eea-2602e4c20040) | Sigma | SigmaHQ |
| T1059.005 | [QBot Process Creation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A4fcac6eb-0287-4090-8eea-2602e4c20040) | Sigma | OpenSearch Security Analytics |
| T1070.004 | [File Deletion](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A30aed7b6-d2c1-4eaf-9382-b6bc43e50c57) | Sigma | SigmaHQ |
| T1070.004 | [Prefetch File Deleted](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A0a1f9d29-6465-4776-b091-7f43b26e4c89) | Sigma | SigmaHQ |
| T1074.001 | [Sensitive File Access followed by Compression](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Aa0fbd7a9-1923-4e05-92df-b484168f17bc) | Elastic | Elastic detection-rules |
| T1074.001 | [Folder Compress To Potentially Suspicious Output Via Compress-Archive Cmdlet](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A85a8e5ba-bd03-4bfb-bbfa-a4409a8f8b98+%23+Process+Creation) | Sigma | SigmaHQ |
| T1082 | [Potential GobRAT File Discovery Via Grep](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae34cfa0c-0a50-4210-9cb3-5632d08eb041) | Sigma | SigmaHQ |
| T1082 | [System Information Discovery](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A42df45e7-e6e9-43b5-8f26-bec5b39cc239) | Sigma | SigmaHQ |
| T1083 | [Turla Group Lateral Movement](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac601f20d-570a-4cde-a7d6-e17f99cb8e7f) | Sigma | SigmaHQ |
| T1083 | [WannaCry Ransomware Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A41d40bff-377a-43e2-8e1b-2e543069e079) | Sigma | SigmaHQ |
| T1102.001 | [Raw Paste Service Access](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A5468045b-4fcc-4d1a-973c-c9c9578edacb) | Sigma | SigmaHQ |
| T1102.001 | [PwnDrp Access](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A2b1ee7e4-89b6-4739-b7bb-b811b6607e5e) | Sigma | SigmaHQ |
| T1105 | [Greenbug Espionage Group Indicators](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A3711eee4-a808-4849-8a14-faf733da3612) | Sigma | SigmaHQ |
| T1105 | [Pandemic Registry Key](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A47e0852a-cf81-4494-a8e6-31864f8c86ed) | Sigma | SigmaHQ |
| T1112 | [ShimCache Flush](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab0524451-19af-4efa-a46f-562a977f792e) | Sigma | SigmaHQ |
| T1112 | [ShimCache Flush](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Ab0524451-19af-4efa-a46f-562a977f792e) | Sigma | OpenSearch Security Analytics |
| T1119 | [iOS Implant URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Ae06ac91d-b9e6-443d-8e5b-af749e7aa6b6) | Sigma | OpenSearch Security Analytics |
| T1119 | [Shai-Hulud Malicious GitHub Workflow Creation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A0aba5685-6db6-486f-88ef-29a99c545cfd) | Sigma | SigmaHQ |
| T1132.001 | [DNS Exfiltration and Tunneling Tools Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A98a96a5a-64a0-4c42-92c5-489da3866cb0) | Sigma | SigmaHQ |
| T1132.001 | [DNS Exfiltration and Tunneling Tools Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A98a96a5a-64a0-4c42-92c5-489da3866cb0) | Sigma | OpenSearch Security Analytics |
| T1189 | [Flash Player Update from Suspicious Location](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4922a5dd-6743-4fc2-8e81-144374280997) | Sigma | SigmaHQ |
| T1189 | [Cross Site Scripting Strings](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A65354b83-a2ea-4ea6-8414-3ab38be0d409) | Sigma | SigmaHQ |
| T1197 | [Bitsadmin to Uncommon TLD](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A9eb68894-7476-4cd6-8752-23b51f5883a7) | Sigma | SigmaHQ |
| T1197 | [Bitsadmin to Uncommon IP Server Address](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A8ccd35a2-1c7c-468b-b568-ac6cdf80eec3) | Sigma | SigmaHQ |
| T1203 | [Droppers Exploiting CVE-2017-11882](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A678eb5f4-8597-4be6-8be7-905e4234b53a) | Sigma | SigmaHQ |
| T1203 | [OMIGOD HTTP No Authentication RCE - CVE-2021-38647](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aab6b1a39-a9ee-4ab4-b075-e83acf6e346b) | Sigma | SigmaHQ |
| T1204.001 | [Google Workspace Object Copied from External Drive with App Consent](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Af33e68a4-bd19-11ed-b02f-f661ea17fbcc) | Elastic | Elastic detection-rules |
| T1204.001 | [Suspicious ClickFix/FileFix Execution Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad487ed4a-fd24-436d-a0b2-f4e95f7b2635) | Sigma | SigmaHQ |
| T1204.002 | [Ursnif Malware C2 URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A932ac737-33ca-4afd-9869-0d48b391fcc9) | Sigma | SigmaHQ |
| T1204.002 | [Droppers Exploiting CVE-2017-11882](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A678eb5f4-8597-4be6-8be7-905e4234b53a) | Sigma | SigmaHQ |
| T1518.001 | [Sysmon Discovery Via Default Driver Altitude Using Findstr.EXE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A37db85d1-b089-490a-a59a-c7b6f984f480) | Sigma | SigmaHQ |
| T1518.001 | [Local Firewall Rules Enumeration Via NetFirewallRule Cmdlet](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aea207a23-b441-4a17-9f76-ad5be47d51d3) | Sigma | SigmaHQ |
| T1547.001 | [Potential Ryuk Ransomware Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac37510b8-2107-4b78-aa32-72f251e7a844) | Sigma | SigmaHQ |
| T1547.001 | [Ryuk Ransomware](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Ac37510b8-2107-4b78-aa32-72f251e7a844) | Sigma | OpenSearch Security Analytics |
| T1548.002 | [CMSTP UAC Bypass via COM Object Access](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4b60e6f2-bf39-47b4-b4ea-398e33cfe253) | Sigma | SigmaHQ |
| T1548.002 | [HackTool - Empire PowerShell UAC Bypass](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A3268b746-88d8-4cd3-bffc-30077d02c787) | Sigma | SigmaHQ |
| T1553.002 | [Driver Loaded (Invalid Signature)](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=hayabusa-native%3A%3A1f666722-3948-40a2-9d78-d9d374477a90) | Sigma | Hayabusa (native) |
| T1553.002 | [Driver Loaded (Expired/Revoked Cert)](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=hayabusa-native%3A%3Ac837dd6d-0c91-4593-aeab-f6a1f3ca1961) | Sigma | Hayabusa (native) |
| T1555.003 | [SQLite Chromium Profile Data DB Access](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A24c77512-782b-448a-8950-eddb0785fc71) | Sigma | SigmaHQ |
| T1555.003 | [HackTool - WinPwn Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad557dc06-62e8-4468-a8e8-7984124908ce) | Sigma | SigmaHQ |
| T1559.002 | [Enable Microsoft Dynamic Data Exchange](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A63647769-326d-4dde-a419-b925cc0caf42) | Sigma | SigmaHQ |
| T1559.002 | [Enable Microsoft Dynamic Data Exchange](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A63647769-326d-4dde-a419-b925cc0caf42) | Sigma | OpenSearch Security Analytics |
| T1560 | [Conti NTDS Exfiltration Command](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aaa92fd02-09f2-48b0-8a93-864813fb8f41) | Sigma | SigmaHQ |
| T1560 | [Sensitive Files Compression Inside A Container](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ad9faf1ba-a216-4c29-b8e0-a05a9d14b027) | Elastic | Elastic detection-rules |
| T1566.001 | [Ursnif Malware C2 URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A932ac737-33ca-4afd-9869-0d48b391fcc9) | Sigma | SigmaHQ |
| T1566.001 | [Droppers Exploiting CVE-2017-11882](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A678eb5f4-8597-4be6-8be7-905e4234b53a) | Sigma | SigmaHQ |
| T1566.002 | [Potential Malicious Usage of CloudTrail System Manager](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A38e7f511-3f74-41d4-836e-f57dfa18eead) | Sigma | SigmaHQ |
| T1566.002 | [Google Workspace Device Registration After OAuth from Suspicious ASN](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A012bfca7-45cb-4507-a3ba-3777167f8b81) | Elastic | Elastic detection-rules |
| T1574.001 | [Winnti Pipemon Characteristics](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A73d70463-75c9-4258-92c6-17500fe972f2) | Sigma | SigmaHQ |
| T1574.001 | [Winnti Pipemon Characteristics](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A73d70463-75c9-4258-92c6-17500fe972f2) | Sigma | OpenSearch Security Analytics |
| T1588.002 | [Hacktool Execution - Imphash](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A24e3e58a-646b-4b50-adef-02ef935b9fc8) | Sigma | SigmaHQ |
| T1588.002 | [Renamed SysInternals DebugView Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acd764533-2e07-40d6-a718-cfeec7f2da7f) | Sigma | SigmaHQ |

## 8. Plano de emulação e validação

Use num laboratório isolado e autorizado para confirmar que as regras disparam. Os comandos estão nos repositórios oficiais.

| Tática | Técnica | Teste Atomic Red Team | Plataformas |
|---|---|---|---|
| Initial Access | [T1566.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1566.001/T1566.001.md) | Download Macro-Enabled Phishing Attachment | windows |
| Initial Access | [T1566.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1566.001/T1566.001.md) | Word spawned a command shell and used an IP address in the command line | windows |
| Initial Access | [T1566.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1566.002/T1566.002.md) | Paste and run technique | windows |
| Execution | [T1053.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1053.005/T1053.005.md) | Scheduled Task Startup Script | windows |
| Execution | [T1053.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1053.005/T1053.005.md) | Scheduled task Local | windows |
| Execution | [T1059.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md) | Mimikatz | windows |
| Execution | [T1059.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md) | Run BloodHound from local disk | windows |
| Execution | [T1059.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.003/T1059.003.md) | Create and Execute Batch Script | windows |
| Execution | [T1059.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.003/T1059.003.md) | Writes text to a file and displays it. | windows |
| Execution | [T1059.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.005/T1059.005.md) | Visual Basic script execution to gather local computer information | windows |
| Execution | [T1059.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.005/T1059.005.md) | Encoded VBS code execution | windows |
| Execution | [T1204.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1204.002/T1204.002.md) | OSTap Style Macro Execution | windows |
| Execution | [T1204.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1204.002/T1204.002.md) | OSTap Payload Download | windows |
| Execution | [T1559.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1559.002/T1559.002.md) | Execute Commands | windows |
| Execution | [T1559.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1559.002/T1559.002.md) | Execute PowerShell script via Word DDE | windows |
| Persistence | [T1547.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1547.001/T1547.001.md) | Reg Key Run | windows |
| Persistence | [T1547.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1547.001/T1547.001.md) | Reg Key RunOnce | windows |
| Privilege Escalation | [T1548.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1548.002/T1548.002.md) | Bypass UAC using Event Viewer (cmd) | windows |
| Privilege Escalation | [T1548.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1548.002/T1548.002.md) | Bypass UAC using Event Viewer (PowerShell) | windows |
| Stealth | [T1027.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027.001/T1027.001.md) | Pad Binary to Change Hash - Linux/macOS dd | linux, macos |
| Stealth | [T1027.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027.001/T1027.001.md) | Pad Binary to Change Hash using truncate command - Linux/macOS | linux, macos |
| Stealth | [T1027.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027.002/T1027.002.md) | Binary simply packed by UPX (linux) | linux |
| Stealth | [T1027.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027.002/T1027.002.md) | Binary packed by UPX, with modified headers (linux) | linux |
| Stealth | [T1036.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.005/T1036.005.md) | Execute a process from a directory masquerading as the current parent directory | linux, macos |
| Stealth | [T1036.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.005/T1036.005.md) | Masquerade as a built-in system executable | windows |
| Stealth | [T1055.012](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1055.012/T1055.012.md) | Process Hollowing using PowerShell | windows |
| Stealth | [T1055.012](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1055.012/T1055.012.md) | RunPE via VBA | windows |
| Stealth | [T1070.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.004/T1070.004.md) | Delete a single file - FreeBSD/Linux/macOS | linux, macos |
| Stealth | [T1070.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.004/T1070.004.md) | Delete an entire folder - FreeBSD/Linux/macOS | linux, macos |
| Stealth | [T1197](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1197/T1197.md) | Bitsadmin Download (cmd) | windows |
| Stealth | [T1197](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1197/T1197.md) | Bitsadmin Download (PowerShell) | windows |
| Stealth | [T1574.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1574.001/T1574.001.md) | DLL Search Order Hijacking - amsi.dll | windows |
| Stealth | [T1574.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1574.001/T1574.001.md) | Phantom Dll Hijacking - WinAppXRT.dll | windows |
| Defense Impairment | [T1112](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1112/T1112.md) | Modify Registry of Current User Profile - cmd | windows |
| Defense Impairment | [T1112](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1112/T1112.md) | Modify Registry of Local Machine - cmd | windows |
| Credential Access | [T1555.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1555.003/T1555.003.md) | Run Chrome-password Collector | windows |
| Credential Access | [T1555.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1555.003/T1555.003.md) | Search macOS Safari Cookies | macos |
| Discovery | [T1033](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1033/T1033.md) | System Owner/User Discovery | windows |
| Discovery | [T1033](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1033/T1033.md) | System Owner/User Discovery | linux, macos |
| Discovery | [T1082](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1082/T1082.md) | System Information Discovery | windows |
| Discovery | [T1082](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1082/T1082.md) | System Information Discovery | macos |
| Discovery | [T1083](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1083/T1083.md) | File and Directory Discovery (cmd.exe) | windows |
| Discovery | [T1083](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1083/T1083.md) | File and Directory Discovery (PowerShell) | windows |
| Discovery | [T1518.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1518.001/T1518.001.md) | Security Software Discovery | windows |
| Discovery | [T1518.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1518.001/T1518.001.md) | Security Software Discovery - powershell | windows |
| Lateral Movement | [T1021.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.001/T1021.001.md) | RDP to Remote Host | windows |
| Lateral Movement | [T1021.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.001/T1021.001.md) | Changing RDP Port to Non Standard Port via Powershell | windows |
| Collection | [T1005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1005/T1005.md) | Search files of interest and save them to a single zip file (Windows) | windows |
| Collection | [T1005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1005/T1005.md) | Find and dump sqlite databases (Linux) | linux |
| Collection | [T1074.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1074.001/T1074.001.md) | Stage data from Discovery.bat | windows |
| Collection | [T1074.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1074.001/T1074.001.md) | Stage data from Discovery.sh | linux, macos |
| Collection | [T1119](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1119/T1119.md) | Automated Collection Command Prompt | windows |
| Collection | [T1119](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1119/T1119.md) | Automated Collection PowerShell | windows |
| Collection | [T1560](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1560/T1560.md) | Compress Data for Exfiltration With PowerShell | windows |
| Command and Control | [T1105](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1105/T1105.md) | rsync remote file copy (push) | linux, macos |
| Command and Control | [T1105](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1105/T1105.md) | rsync remote file copy (pull) | linux, macos |
| Command and Control | [T1132.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1132.001/T1132.001.md) | Base64 Encoded data. | linux, macos |
| Command and Control | [T1132.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1132.001/T1132.001.md) | Base64 Encoded data (freebsd) | linux |

**Logs reais de ataque (EVTX) para testar sem executar nada:**

- T1021.001 — [ID4688,4778,4779 RDP hijack direct](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0008-Lateral%20Movement/T1021.001-Remote%20Desktop%20Protocol/ID4688%2C4778%2C4779%20RDP%20hijack%20direct.evtx) _(explícito)_
- T1021.001 — [ID4688-4778 RDP hijack command execution](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0008-Lateral%20Movement/T1021.001-Remote%20Desktop%20Protocol/ID4688-4778%20RDP%20hijack%20command%20execution.evtx) _(explícito)_
- T1053.005 — [ID4688-4698 Persistent scheduled task with SYSTEM privileges creation](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1053.005-Scheduled%20Task/ID4688-4698%20Persistent%20scheduled%20task%20with%20SYSTEM%20privileges%20creation.evtx) _(explícito)_
- T1053.005 — [ID4688-Interactive shell using AT schedule task](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1053.005-Scheduled%20Task/ID4688-Interactive%20shell%20using%20AT%20schedule%20task.evtx) _(explícito)_
- T1055.012 — [rundll32_hollowing_wermgr_masquerading](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/AutomatedTestingTools/Malware/rundll32_hollowing_wermgr_masquerading.evtx) _(inferido)_
- T1055.012 — [apt10_jjs_sideloading_prochollowing_persist_as_service_sysmon_1_7_8_13](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Defense%20Evasion/apt10_jjs_sideloading_prochollowing_persist_as_service_sysmon_1_7_8_13.evtx) _(inferido)_
- T1059.001 — [ID4103-4104-Payload download via PowerShell](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1059.001-PowerShell/ID4103-4104-Payload%20download%20via%20PowerShell.evtx) _(explícito)_
- T1059.001 — [ID4688-Encoded PowerShell MSF payload via process execution](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1059.001-PowerShell/ID4688-Encoded%20PowerShell%20MSF%20payload%20via%20process%20execution.evtx) _(explícito)_
- T1059.003 — [ID4688-SQL Server payload injectection for reverse shell (MSF)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1059.003-Windows%20Command%20Shell/ID4688-SQL%20Server%20payload%20injectection%20for%20reverse%20shell%20%28MSF%29.evtx) _(explícito)_
- T1112 — [ID11,13-SMBexec service registration](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0005-Defense%20Evasion/T1112-Modify%20registry/ID11%2C13-SMBexec%20service%20registration.evtx) _(explícito)_
- T1112 — [ID4624,4670,4688,4674-Registry permission change via WMI (DAMP)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0005-Defense%20Evasion/T1112-Modify%20registry/ID4624%2C4670%2C4688%2C4674-Registry%20permission%20change%20via%20WMI%20%28DAMP%29.evtx) _(explícito)_
- T1197 — [ID3-59-60-BITS job created](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0003-Persistence/T1197-BITS%20jobs/ID3-59-60-BITS%20job%20created.evtx) _(explícito)_
- T1197 — [ID4688-BITS transfer initiated](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0003-Persistence/T1197-BITS%20jobs/ID4688-BITS%20transfer%20initiated.evtx) _(explícito)_
- T1547.001 — [sideloading_injection_persistence_run_key](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/AutomatedTestingTools/Malware/sideloading_injection_persistence_run_key.evtx) _(inferido)_
- T1547.001 — [evasion_persis_hidden_run_keyvalue_sysmon_13](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Persistence/evasion_persis_hidden_run_keyvalue_sysmon_13.evtx) _(inferido)_
- T1548.002 — [sideloading_uacbypass_rundll32_injection_c2](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/AutomatedTestingTools/Malware/sideloading_uacbypass_rundll32_injection_c2.evtx) _(inferido)_
- T1548.002 — [Invoke_TokenDuplication_UAC_Bypass4624](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Privilege%20Escalation/Invoke_TokenDuplication_UAC_Bypass4624.evtx) _(inferido)_
- T1555.003 — [CA_4624_4625_LogonType2_LogonProc_chrome](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Credential%20Access/CA_4624_4625_LogonType2_LogonProc_chrome.evtx) _(inferido)_
- T1555.003 — [CA_chrome_firefox_opera_4663](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Credential%20Access/CA_chrome_firefox_opera_4663.evtx) _(inferido)_
- T1574.001 — [DE_timestomp_and_dll_sideloading_and_RunPersist](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/AutomatedTestingTools/Malware/DE_timestomp_and_dll_sideloading_and_RunPersist.evtx) _(inferido)_
- T1574.001 — [sideloading_injection_persistence_run_key](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/AutomatedTestingTools/Malware/sideloading_injection_persistence_run_key.evtx) _(inferido)_

## 9. Hipóteses de hunting

Se Patchwork estiver no seu ambiente, estas são as perguntas a fazer aos seus dados (fontes de log segundo as estratégias de detecção do MITRE ATT&CK).

1. **T1587.002 Code Signing Certificates** — Consider analyzing self-signed code signing certificates for features that may be associated with the adversary and/or their developers, such as the thumbprint, algorithm used, validity period, and common name. Malware repositories can also be used to… Dados: `Malware Repository` (None).
2. **T1197 BITS Jobs** — Behavioral chain: (1) An actor creates or modifies a BITS job via bitsadmin.exe, PowerShell BITS cmdlets, or COM; (2) the job performs HTTP(S)/SMB network transfers while the owning user is logged on; (3) upon job completion/error, BITS launches a notify… Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=3, 22), `WinEventLog:PowerShell` (EventCode=4103, 4104, 4105, 4106).
3. **T1102.001 Dead Drop Resolver** — Detection of a process or script that accesses a common web service to retrieve content containing obfuscated indicators of a secondary C2 server (dead drop resolver behavior). Dados: `WinEventLog:Sysmon` (EventCode=3, 22), `etw:Microsoft-Windows-NDIS-PacketCapture` (TLS Handshake/Network Flow).
4. **T1027.005 Indicator Removal from Tools** — Detection of known tools or malware flagged by antivirus, followed by a near-term drop of a similar binary with modified signature and resumed activity (execution, C2, or persistence). Dados: `WinEventLog:Application` (EventCode=1000), `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=11).
5. **T1027.001 Binary Padding** — Detects the creation or execution of padded binary files (e.g., large size but minimal legitimate content) followed by process execution or lateral movement from the host. Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:Security` (EventCode=4663, 4670, 4656), `WinEventLog:Sysmon` (EventCode=11).
6. **T1055.012 Process Hollowing** — Detects adversary use of suspended process creation, using the CREATE_SUSPENDED flag via CreateProcess, followed by unmapping the memory of the child process (NtUnmapViewOfSection) and replacing it with malicious code via VirtualAllocEx/WriteProcessMemory,… Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=10), `WinEventLog:Sysmon` (EventCode=8).
7. **T1680 Local Storage Discovery** — Drive enumeration using PowerShell (`Get-PSDrive`), `wmic logicaldisk`, or Win32 API indicative of local volume enumeration by non-admin users or executed outside of baseline system inventory scripts. Dados: `WinEventLog:Sysmon` (EventCode=1).
8. **T1548.002 Bypass User Account Control** — Detects a multi-event behavior chain involving UAC bypass attempts via known auto-elevated binaries (e.g., eventvwr.exe, sdclt.exe), unauthorized Registry changes to UAC-related keys, and anomalous process execution with elevated privileges but lacking… Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:Security` (EventCode=4672), `WinEventLog:Sysmon` (EventCode=13, 14).
9. **T1559.002 Dynamic Data Exchange** — Detects anomalous use of Dynamic Data Exchange (DDE) for code execution, such as Office applications (WINWORD.EXE, EXCEL.EXE) spawning command interpreters, or loading unusual modules through DDEAUTO/DDE formulas. Correlates suspicious parent-child process… Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=7), `WinEventLog:Security` (EventCode=4663, 4670, 4656).
10. **T1132.001 Standard Encoding** — Process invokes a standard encoder (e.g., PowerShell -enc, certutil -encode, base64 via .NET/Invoke-Expression) or emits long Base64/hex literals → shortly followed by outbound network egress with high bytes_out:bytes_in ratio or HTTP headers/payloads… Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=3, 22), `WinEventLog:PowerShell` (EventCode=4103, 4104, 4105, 4106).
11. **T1560 Archive Collected Data** — Detects adversarial archiving of files prior to exfiltration by correlating execution of compression/encryption utilities (e.g., makecab.exe, rar.exe, 7z.exe, powershell Compress-Archive) with subsequent creation of large compressed or encrypted files.… Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Sysmon` (EventCode=7).
12. **T1598.003 Spearphishing Link** — Monitor for suspicious email activity, such as numerous accounts receiving messages from a single unusual/unknown sender. Filtering based on DKIM+SPF or header analysis can help detect when the email sender is spoofed. Monitor for references to uncategorized… Dados: `Application Log` (None), `Network Traffic` (None), `Network Traffic` (None).

## 10. OSINT — onde pesquisar

Consultas prontas com todos os nomes conhecidos do grupo:

- Relatórios técnicos: [busca web](https://duckduckgo.com/?q=%28%22Patchwork%22+OR+%22Hangover+Group%22+OR+%22Dropping+Elephant%22+OR+%22Chinastrats%22+OR+%22MONSOON%22+OR+%22Operation+Hangover%22%29+threat+report) · [PDFs](https://duckduckgo.com/?q=%28%22Patchwork%22+OR+%22Hangover+Group%22+OR+%22Dropping+Elephant%22+OR+%22Chinastrats%22+OR+%22MONSOON%22+OR+%22Operation+Hangover%22%29+filetype%3Apdf)
- Regras e IOCs publicados: [GitHub](https://github.com/search?type=code&q=%22Patchwork%22+OR+%22Hangover+Group%22+OR+%22Dropping+Elephant%22+OR+%22Chinastrats%22+OR+%22MONSOON%22+OR+%22Operation+Hangover%22)
- Pulsos de ameaça: [AlienVault OTX](https://otx.alienvault.com/browse/global/pulses?q=Patchwork)
- Família de malware e atores: [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/actors) (busque por Patchwork, Hangover Group, Dropping Elephant)
- Cartões de grupo: [ThaiCERT Threat Group Cards](https://apt.etda.or.th/cgi-bin/listgroups.cgi)
- Página oficial: [MITRE ATT&CK G0040](https://attack.mitre.org/groups/G0040/)

**Relatórios na coleção CyberMonitor** (ligados pelo nome do grupo, conferir antes de citar):

- 2013 — [NS-Unveiling-an-Indian-Cyberattack-Infrastructure_FINAL_Web](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2013/2013.05.20.Operation_Hangover/NS-Unveiling-an-Indian-Cyberattack-Infrastructure_FINAL_Web.pdf) _(via “Operation Hangover”)_
- 2013 — [Norman_HangOver report_Executive Summary_042513](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2013/2013.05.20.Operation_Hangover/Norman_HangOver%20report_Executive%20Summary_042513.pdf) _(via “Operation Hangover”)_
- 2013 — [Unveiling an Indian Cyberattack Infrastructure - appendixes](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2013/2013.05.20.Operation_Hangover/Unveiling%20an%20Indian%20Cyberattack%20Infrastructure%20-%20appendixes.pdf) _(via “Operation Hangover”)_
- 2013 — [Unveiling_an_Indian_Cyberattack_Infrastructure](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2013/2013.05.20.Operation_Hangover/Unveiling_an_Indian_Cyberattack_Infrastructure.pdf) _(via “Operation Hangover”)_
- 2016 — [Unveiling-Patchwork](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2016/2016.07.07.UNVEILING_PATCHWORK/Unveiling-Patchwork.pdf) _(via “Patchwork”)_
- 2016 — [The Dropping Elephant actor - Securelist](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2016/2016.07.08.The_Dropping_Elephant/The%20Dropping%20Elephant%20actor%20-%20Securelist.pdf) _(via “Dropping Elephant”)_
- 2016 — [forcepoint-security-labs-monsoon-analysis-report](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2016/2016.08.08.monsoon-analysis-apt-campaign/forcepoint-security-labs-monsoon-analysis-report.pdf) _(via “MONSOON”)_
- 2017 — [appendix-untangling-the-patchwork-cyberespionage-group](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2017/2017.12.11.Patchwork_APT/appendix-untangling-the-patchwork-cyberespionage-group.pdf) _(via “Patchwork”)_
- 2017 — [tech-brief-untangling-the-patchwork-cyberespionage-group](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2017/2017.12.11.Patchwork_APT/tech-brief-untangling-the-patchwork-cyberespionage-group.pdf) _(via “Patchwork”)_
- 2018 — [patchwork-continues-deliver-badnews](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2018/2018.03.07.patchwork-continues-deliver-badnews-indian-subcontinent/patchwork-continues-deliver-badnews.pdf) _(via “Patchwork”)_
- 2018 — [patchwork-apt-group-targets-us-think-tanks](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2018/2018.06.07.patchwork-apt-group-targets-us-think-tanks/patchwork-apt-group-targets-us-think-tanks.pdf) _(via “Patchwork”)_
- 2018 — [Appendix-TheUrpageConnectiontoBahamutConfuciusandPatchwork](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2018/2018.08.29.Bahamut_Confucius_Patchwork/Appendix-TheUrpageConnectiontoBahamutConfuciusandPatchwork.pdf) _(via “Patchwork”)_
- 2018 — [The Urpage Connection to Bahamut Confucius and Patchwork](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2018/2018.08.29.Bahamut_Confucius_Patchwork/The%20Urpage%20Connection%20to%20Bahamut%20Confucius%20and%20Patchwork.pdf) _(via “Patchwork”)_
- 2019 — [Malware analysis about sample of APT Patchwork](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2019/2019.08.27.Patchwork_Malware_Analysis/Malware%20analysis%20about%20sample%20of%20APT%20Patchwork.pdf) _(via “Patchwork”)_
- 2021 — [A Deep Dive Into Patchwork APT Group _ Cyble](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2021/2021.01.20.Deep_Dive_Patchwork/A%20Deep%20Dive%20Into%20Patchwork%20APT%20Group%20_%20Cyble.pdf) _(via “Patchwork”)_
- 2022 — [Patchwork_Patchwork-APT-caught-in-its-own-web_MalwarebytesLabs](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2022/2022.01.07.Patchwork_APT_India/Patchwork_Patchwork-APT-caught-in-its-own-web_MalwarebytesLabs.pdf) _(via “Patchwork”)_

## 11. Bibliografia (9 fontes citadas pelo ATT&CK)

- [Cymmetria Patchwork](https://web.archive.org/web/20180825085952/https:/s3-us-west-2.amazonaws.com/cymmetria-blog/public/Unveiling_Patchwork.pdf) — Cymmetria. (2016). Unveiling Patchwork - The Copy-Paste APT. Retrieved November 17, 2024.
- [Forcepoint Monsoon](https://www.forcepoint.com/sites/default/files/resources/files/forcepoint-security-labs-monsoon-analysis-report.pdf) — Settle, A., et al. (2016, August 8). MONSOON - Analysis Of An APT Campaign. Retrieved September 22, 2016.
- [Operation Hangover May 2013](https://web.archive.org/web/20140424084220/http://enterprise-manage.norman.c.bitbit.net/resources/files/Unveiling_an_Indian_Cyberattack_Infrastructure.pdf) — Fagerland, S., et al. (2013, May). Operation Hangover: Unveiling an Indian Cyberattack Infrastructure. Retrieved November 17, 2024.
- [PaloAlto Patchwork Mar 2018](https://researchcenter.paloaltonetworks.com/2018/03/unit42-patchwork-continues-deliver-badnews-indian-subcontinent/) — Levene, B. et al.. (2018, March 7). Patchwork Continues to Deliver BADNEWS to the Indian Subcontinent. Retrieved March 31, 2018.
- [Securelist Dropping Elephant](https://securelist.com/the-dropping-elephant-actor/75328/) — Kaspersky Lab's Global Research & Analysis Team. (2016, July 8). The Dropping Elephant – aggressive cyber-espionage in the Asian region. Retrieved August 3, 2016.
- [Symantec Patchwork](http://www.symantec.com/connect/blogs/patchwork-cyberespionage-group-expands-targets-governments-wide-range-industries) — Hamada, J.. (2016, July 25). Patchwork cyberespionage group expands targets from governments to wide range of industries. Retrieved August 17, 2016.
- [TrendMicro Patchwork Dec 2017](https://documents.trendmicro.com/assets/tech-brief-untangling-the-patchwork-cyberespionage-group.pdf) — Lunghi, D., et al. (2017, December). Untangling the Patchwork Cyberespionage Group. Retrieved July 10, 2018.
- [Unit 42 BackConfig May 2020](https://unit42.paloaltonetworks.com/updated-backconfig-malware-targeting-government-and-military-organizations/) — Hinchliffe, A. and Falcone, R. (2020, May 11). Updated BackConfig Malware Targeting Government and Military Organizations in South Asia. Retrieved June 17, 2020.
- [Volexity Patchwork June 2018](https://www.volexity.com/blog/2018/06/07/patchwork-apt-group-targets-us-think-tanks/) — Meltzer, M, et al. (2018, June 07). Patchwork APT Group Targets US Think Tanks. Retrieved July 16, 2018.

## 12. Limites e confiança

- O ATT&CK registra o que foi **relatado publicamente**, não tudo o que o grupo faz. Ausência de uma técnica não prova que o grupo não a usa.
- **Sobreposição de TTP não é atribuição.** Muitas técnicas são compartilhadas entre grupos e com red teams. Use a assinatura comportamental como hipótese, junto com infraestrutura, malware e contexto.
- Cobertura de detecção refere-se ao catálogo público Detection Rules, não ao seu ambiente: confira se a telemetria necessária chega ao seu SIEM.
- Ligações marcadas como _inferidas_ (EVTX por palavra-chave, relatórios por nome) devem ser verificadas.

---
Fontes: MITRE ATT&CK® (uso livre com atribuição, © The MITRE Corporation), Atomic Red Team (Red Canary, MIT), EVTX-to-MITRE-Attack, EVTX-ATTACK-SAMPLES, APT & CyberCriminal Campaign Collections. Gerado por [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules).
