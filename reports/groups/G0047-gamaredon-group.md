# Gamaredon Group (G0047) — Dossiê de inteligência

> **TLP:CLEAR** · gerado em 2026-10-26 a partir de fontes abertas · MITRE ATT&CK v20.0 · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0047) · [ATT&CK](https://attack.mitre.org/groups/G0047/)

**Também conhecido como:** IRON TILDEN, Primitive Bear, ACTINIUM, Armageddon, Shuckworm, DEV-0157, Aqua Blizzard, NastyShrew  
**Origem atribuída:** Rússia · **Motivação:** espionagem · **Setores-alvo:** Governo  
**Registro no ATT&CK:** criado em 2017-05-31, atualizado em 2026-10-01 · referências de 2017 a 2026

## 1. Sumário executivo

- **70 técnicas** atribuídas publicamente, concentradas em **Stealth, Command and Control, Discovery**.
- **Arsenal:** 3 malware e 3 ferramentas (ex.: Remcos, Pteranodon, QuietSieve, PowerPunch, Reg).
- **Campanhas atribuídas:** 0.
- **Cobertura de detecção pública:** 96% das técnicas têm ao menos uma regra no catálogo; **3 técnicas sem nenhuma regra pública**.
- **Origem e alvos (APT4ALL):** atribuído a **Rússia**, motivação espionagem; setores Governo; 2 países vítimas citados.
- **Onde a cobertura está:** Windows (60 técnicas com regra), EDR / XDR (54 técnicas com regra), Linux (44 técnicas com regra), Outros / genérico (39 técnicas com regra).
- **Assinatura comportamental** (técnicas raras entre os 178 grupos, as mais úteis para atribuição): T1001 Data Obfuscation, T1102.003 One-Way Communication, T1137 Office Application Startup, T1027.012 LNK Icon Smuggling, T1561.001 Disk Content Wipe.

## 2. Quem é

> Gamaredon Group is a suspected Russian cyber espionage group that has targeted military, law enforcement, judiciary, non-profit, and non-governmental organizations in Ukraine since at least 2013. The name Gamaredon Group derives from a misspelling of the word "Armageddon," found in early campaigns.
> 
> In November 2021, the Ukrainian government publicly attributed Gamaredon Group to Russia’s Federal Security Service (FSB) Center 18, an assessment later supported by multiple independent cybersecurity researchers.

_Texto original do MITRE ATT&CK, em inglês._

## 3. Contexto, nomes e alvos

Consolidado pelo [APT4ALL](https://github.com/Ridd1kulusC0d3r/apt4all) a partir de MISP Galaxy, planilha APT Groups & Operations, EternalLiberty e APTnotes. Atribuição é afirmação de quem publicou; confira a fonte.

| Campo | Valor |
|---|---|
| Origem atribuída | Rússia |
| Motivação | espionagem |
| Setores-alvo | Governo |
| Vítimas citadas | Germany, Ukraine |
| Alvos (planilha) | — |
| Operações conhecidas | OP Armageddon, Op Gamework |
| Confiança de atribuição (MISP) | High |

**Como cada fornecedor chama este grupo** (útil para cruzar relatórios):

| Fornecedor | Nome(s) |
|---|---|
| MITRE ATT&CK | G0047 |
| Microsoft | Aqua Blizzard, ACTINIUM (antigo · old) |

**Outros nomes no APT4ALL (não listados pelo ATT&CK):** FSB 16th & 18th Centers, BlueAlpha, Trident Ursa, Hive0051, (IBM), Blue Otso, UAC-0010, Winterflounder, Temp.Armageddon/UNC530, Dancing Salome, DEV-0157/Actinum/Aqua Blizzard, APT-C-53, SectorC08, UNC530

## 4. Perfil TTP por tática (kill chain)

Cada linha: técnica, como o grupo a usou segundo relatos públicos, e o que existe para detectar e testar.

### Resource Development (TA0042) — 6

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1583.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1583.001) Domains | Gamaredon Group has registered multiple domains to facilitate payload staging and C2. | 7 | — | — |
| [T1583.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1583.003) Virtual Private Server | Gamaredon Group has used VPS hosting providers for infrastructure outside of Russia. | **0** | — | — |
| [T1583.006](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1583.006) Web Services | Gamaredon Group has used Cloudflare’s TryClouldflare service to obtain C2 nodes. | 2 | — | — |
| [T1587.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1587.003) Digital Certificates | Gamaredon Group has used the same TLS certificate across its infrastructure. | **0** | — | — |
| [T1588.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1588.002) Tool | Gamaredon Group has used various legitimate tools, such as `mshta.exe` and Reg, and services during operations. | 35 | — | — |
| [T1608.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1608.001) Upload Malware | Gamaredon Group has registered domains to stage payloads. | 3 | — | — |

### Initial Access (TA0001) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1091](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1091) Replication Through Removable Media | Gamaredon Group has replicated to removable media by leveraging the User Assist Reg Key and creating LNKs on all network and removable drives available on the infected host. | 10 | 1 | — |
| [T1566.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1566.001) Spearphishing Attachment | Gamaredon Group has delivered spearphishing emails with malicious attachments to targets. Additionally, Gamaredon Group has distributed malicious LNK files compressed in ZIP archives. | 230 | 2 | — |

### Execution (TA0002) — 9

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1047](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1047) Windows Management Instrumentation | Gamaredon Group has used WMI to execute scripts used for discovery and for determining the C2 IP address. Gamaredon Group has used the following WMI query to search for a ping record: `Select * From Win32_PingStatus where Address = 'mil.gov.ua'`. | 370 | 12 | 11 |
| [T1053.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1053.005) Scheduled Task | Gamaredon Group has created scheduled tasks to launch executables after a designated number of minutes have passed. | 248 | 14 | 11 |
| [T1059.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.001) PowerShell | Gamaredon Group has used obfuscated PowerShell scripts for staging. Additionally, (LinkById : G0047) has used PowerShell based tools later in its attack chain. Additionally, Gamaredon Group has used the PowerShell cmdlet `Get-Command` to download and execute t… | 1340 | 22 | 15 |
| [T1059.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.003) Windows Command Shell | Gamaredon Group has used various batch scripts to establish C2 and download additional files. Gamaredon Group's backdoor malware has also been written to a batch file. | 269 | 6 | 1 |
| [T1059.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.005) Visual Basic | Gamaredon Group has embedded malicious macros in document templates, which executed VBScript. Gamaredon Group has also delivered Microsoft Outlook VBA projects with embedded macros. Additionally, Gamaredon Group has executed VBScript files using wscript.exe. | 192 | 3 | — |
| [T1106](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1106) Native API | Gamaredon Group malware has used CreateProcess to launch additional malicious components. | 118 | 5 | — |
| [T1204.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1204.001) Malicious Link | Gamaredon Group has attempted to get users to click on a link pointing to a malicious HTML file leading to follow-on malicious content. | 52 | — | — |
| [T1204.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1204.002) Malicious File | Gamaredon Group has attempted to get users to click on Office attachments with malicious macros embedded. Gamaredon Group has also attempted to get users to click on thematically named files. | 259 | 13 | — |
| [T1559.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1559.001) Component Object Model | Gamaredon Group malware can insert malicious macros into documents using a Microsoft.Office.Interop object. | 35 | — | — |

### Persistence (TA0003) — 4

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1053.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1053.005) Scheduled Task | Gamaredon Group has created scheduled tasks to launch executables after a designated number of minutes have passed. | 248 | 14 | 11 |
| [T1112](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1112) Modify Registry | Gamaredon Group has removed security settings for VBA macro execution by changing registry values HKCU\Software\Microsoft\Office\&lt;version&gt;\&lt;product&gt;\Security\VBAWarnings and HKCU\Software\Microsoft\Office\&lt;version&gt;\&lt;product&gt;\Security\Ac… | 601 | 92 | 3 |
| [T1137](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1137) Office Application Startup | Gamaredon Group has inserted malicious macros into existing documents, providing persistence when they are reopened. Gamaredon Group has loaded the group's previously delivered VBA project by relaunching Microsoft Outlook with the /altvba option, once the Appl… | 85 | 1 | — |
| [T1547.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1547.001) Registry Run Keys / Startup Folder | Gamaredon Group tools have registered Run keys in the registry to give malicious VBS files persistence. | 299 | 21 | 2 |

### Privilege Escalation (TA0004) — 3

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1053.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1053.005) Scheduled Task | Gamaredon Group has created scheduled tasks to launch executables after a designated number of minutes have passed. | 248 | 14 | 11 |
| [T1055](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1055) Process Injection | Gamaredon Group has injected Remcos into explorer.exe. | 481 | 13 | 4 |
| [T1547.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1547.001) Registry Run Keys / Startup Folder | Gamaredon Group tools have registered Run keys in the registry to give malicious VBS files persistence. | 299 | 21 | 2 |

### Stealth (TA0005) — 17

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1027](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1027) Obfuscated Files or Information | Gamaredon Group has delivered self-extracting 7z archive files within malicious document attachments. Additionally, Gamaredon Group has used an obfuscated .drv file. | 520 | 11 | 5 |
| [T1027.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1027.004) Compile After Delivery | Gamaredon Group has compiled the source code for a downloader directly on the infected system using the built-in Microsoft.CSharp.CSharpCodeProvider class. | 32 | 5 | — |
| [T1027.010](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1027.010) Command Obfuscation | Gamaredon Group has used obfuscated or encrypted scripts. | 78 | — | — |
| [T1027.012](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1027.012) LNK Icon Smuggling | Gamaredon Group has used LNK files to hide malicious scripts for execution. | 1 | — | — |
| [T1027.015](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1027.015) Compression | Gamaredon Group has delivered malicious payloads within compressed archives and zip files. | 3 | — | — |
| [T1027.016](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1027.016) Junk Code Insertion | Gamaredon Group has obfuscated .NET executables by inserting junk code. | **0** | — | — |
| [T1036.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1036.005) Match Legitimate Resource Name or Location | Gamaredon Group has used legitimate process names to hide malware including svchosst. Additionally, Gamaredon Group disguised malicious ZIP archives as Office documents that are related to the invasion. | 116 | 4 | — |
| [T1055](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1055) Process Injection | Gamaredon Group has injected Remcos into explorer.exe. | 481 | 13 | 4 |
| [T1070.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1070.004) File Deletion | Gamaredon Group tools can delete files used during an operation. | 132 | 11 | — |
| [T1140](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1140) Deobfuscate/Decode Files or Information | Gamaredon Group tools decrypted additional payloads from the C2. Gamaredon Group has also decoded Base64-encoded source code of a downloader. Additionally, Gamaredon Group has decoded Telegram content to reveal the IP address for C2 communications. | 173 | 11 | 1 |
| [T1218.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1218.005) Mshta | Gamaredon Group has used `mshta.exe` to execute malicious files. | 130 | 10 | 4 |
| [T1218.011](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1218.011) Rundll32 | Gamaredon Group malware has used rundll32 to launch additional malicious components. | 274 | 16 | 12 |
| [T1221](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1221) Template Injection | Gamaredon Group has used DOCX files to download malicious DOT document templates and has used RTF template injection to download malicious payloads. Gamaredon Group can also inject malicious macros or remote templates into documents already present on compromi… | 4 | 1 | — |
| [T1480](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1480) Execution Guardrails | Gamaredon Group has used geoblocking to limit downloads of the malicious file to specific geographic locations. | 2 | — | — |
| [T1497.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1497.001) System Checks | Gamaredon Group has checked existing conditions, such as geographic location, device type, or system specification, before the victim is sent a malicious Word document. | 16 | 9 | — |
| [T1564.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1564.003) Hidden Window | Gamaredon Group has used hidcon to run batch files in a hidden console window. Gamaredon Group has also executed PowerShell in a hidden window. | 51 | 3 | — |
| [T1620](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1620) Reflective Code Loading | Gamaredon Group has used an obfuscated PowerShell script that used `System.Reflection.Assembly` to gather and send victim information to the C2. | 54 | 3 | — |

### Defense Impairment (TA0112) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1112](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1112) Modify Registry | Gamaredon Group has removed security settings for VBA macro execution by changing registry values HKCU\Software\Microsoft\Office\&lt;version&gt;\&lt;product&gt;\Security\VBAWarnings and HKCU\Software\Microsoft\Office\&lt;version&gt;\&lt;product&gt;\Security\Ac… | 601 | 92 | 3 |
| [T1685](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1685) Disable or Modify Tools | Gamaredon Group has delivered macros which can tamper with Microsoft Office security settings. | 1275 | 78 | 19 |

### Discovery (TA0007) — 9

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1012](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1012) Query Registry | Gamaredon Group has queried ` HKEY_CURRENT_USER\\Console\\WindowsUpdates` to obtain the C2 addresses. | 92 | 6 | — |
| [T1016.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1016.001) Internet Connection Discovery | Gamaredon Group has tested connectivity between a compromised machine and a C2 server using Ping with commands such as `CSIDL_SYSTEM\cmd.exe /c ping -n 1`. Gamaredon Group has searched the ping records to obtain the C2 address and has used ping to search for t… | 14 | 5 | — |
| [T1033](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1033) System Owner/User Discovery | A Gamaredon Group file stealer can gather the victim's username to send to a C2 server. | 181 | 8 | — |
| [T1057](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1057) Process Discovery | Gamaredon Group has used tools to enumerate processes on target hosts including Process Explorer. | 82 | 10 | — |
| [T1082](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1082) System Information Discovery | A Gamaredon Group file stealer can gather the victim's computer name and drive serial numbers to send to a C2 server. | 264 | 41 | — |
| [T1083](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1083) File and Directory Discovery | Gamaredon Group macros can scan for Microsoft Word and Excel files to inject with additional malicious macros. Gamaredon Group has also used its backdoors to automatically list interesting files (such as Office documents) found on a system. Gamaredon Group has… | 137 | 9 | — |
| [T1120](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1120) Peripheral Device Discovery | Gamaredon Group tools have contained an application to check performance of USB flash drives. Gamaredon Group has also used malware to scan for removable drives. | 11 | 4 | — |
| [T1497.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1497.001) System Checks | Gamaredon Group has checked existing conditions, such as geographic location, device type, or system specification, before the victim is sent a malicious Word document. | 16 | 9 | — |
| [T1518.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1518.001) Security Software Discovery | Gamaredon Group has used PowerShell scripts to identify security software on the victim machine. | 54 | 12 | — |

### Lateral Movement (TA0008) — 4

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1021.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1021.005) VNC | Gamaredon Group has used VNC tools, including UltraVNC, to remotely interact with compromised hosts. | 7 | 1 | — |
| [T1080](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1080) Taint Shared Content | Gamaredon Group has injected malicious macros into all Word and Excel documents on mapped network drives. | 12 | — | — |
| [T1091](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1091) Replication Through Removable Media | Gamaredon Group has replicated to removable media by leveraging the User Assist Reg Key and creating LNKs on all network and removable drives available on the infected host. | 10 | 1 | — |
| [T1534](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1534) Internal Spearphishing | Gamaredon Group has used an Outlook VBA module on infected systems to send phishing emails with malicious attachments to other employees within the organization. | 5 | — | — |

### Collection (TA0009) — 5

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1005) Data from Local System | Gamaredon Group has collected files from infected systems and uploaded them to a C2 server. | 170 | 3 | — |
| [T1025](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1025) Data from Removable Media | A Gamaredon Group file stealer has the capability to steal data from newly connected logical volumes on a system, including USB drives. | 4 | 1 | — |
| [T1039](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1039) Data from Network Shared Drive | Gamaredon Group malware has collected Microsoft Office documents from mapped network drives. | 24 | 2 | — |
| [T1113](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1113) Screen Capture | Gamaredon Group's malware can take screenshots of the compromised computer every minute. | 60 | 10 | — |
| [T1119](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1119) Automated Collection | Gamaredon Group has deployed scripts on compromised systems that automatically scan for interesting documents. | 72 | 4 | — |

### Command and Control (TA0011) — 12

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1001) Data Obfuscation | Gamaredon Group has used obfuscated VBScripts with randomly generated variable names and concatenated strings. | 17 | — | — |
| [T1071.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1071.001) Web Protocols | Gamaredon Group has used HTTP and HTTPS for C2 communications. | 228 | 3 | — |
| [T1090](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1090) Proxy | Gamaredon Group has used the Cloudflare Tunnel client to proxy C2 traffic. | 162 | — | 1 |
| [T1090.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1090.003) Multi-hop Proxy | Gamaredon Group has used Tor for C2 traffic. | 44 | 4 | — |
| [T1095](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1095) Non-Application Layer Protocol | Gamaredon Group has used SOCKS5 over port 9050 for C2 communication. | 72 | 5 | — |
| [T1102](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1102) Web Service | Gamaredon Group has used GitHub repositories for downloaders which will be obtained by the group's .NET executable on the compromised system. | 98 | — | — |
| [T1102.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1102.002) Bidirectional Communication | Gamaredon Group has used several ways to try to resolve the C2 server, including: public third-party websites, an adversary-operated Telegraph channel, the ngrok utility and the TXT record of a hardcoded C2 domain. | 27 | — | — |
| [T1102.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1102.003) One-Way Communication | Gamaredon Group has used Telegram Messenger content to discover the IP address for C2 communications. | 6 | — | — |
| [T1105](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1105) Ingress Tool Transfer | Gamaredon Group has downloaded additional malware and tools onto a compromised host. For example, Gamaredon Group uses a backdoor script to retrieve and decode additional payloads once in victim environments. | 644 | 39 | — |
| [T1568](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1568) Dynamic Resolution | Gamaredon Group has incorporated dynamic DNS domains in its infrastructure. | 32 | — | — |
| [T1568.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1568.001) Fast Flux DNS | Gamaredon Group has used fast flux DNS to mask their command and control channel behind rotating IP addresses. Additionally, Gamaredon Group has used a low-frequency variant of the single-flux method. | 1 | — | — |
| [T1571](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1571) Non-Standard Port | Gamaredon Group has used port 6856 for C2 communications. | 163 | 2 | — |

### Exfiltration (TA0010) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1020](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1020) Automated Exfiltration | Gamaredon Group has used modules that automatically upload gathered documents to the C2 server. | 69 | 2 | — |
| [T1041](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1041) Exfiltration Over C2 Channel | A Gamaredon Group file stealer can transfer collected files to a hardcoded C2 server. | 135 | 2 | — |

### Impact (TA0040) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1491.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1491.001) Internal Defacement | Gamaredon Group has left taunting images and messages on the victims' desktops as proof of system access. | 18 | 4 | — |
| [T1561.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1561.001) Disk Content Wipe | Gamaredon Group has used tools to delete files and folders from victims' desktops and profiles. | 6 | — | — |

## 5. Assinatura comportamental

Técnicas que este grupo usa e que poucos dos 178 grupos do ATT&CK usam. Pesam mais numa atribuição por TTP: ver várias delas juntas é mais informativo do que ver técnicas comuns como PowerShell.

| Técnica | Outros grupos que usam | Peso (raridade) |
|---|---:|---:|
| T1001 Data Obfuscation | 0 | 4.49 |
| T1102.003 One-Way Communication | 1 | 4.09 |
| T1137 Office Application Startup | 1 | 4.09 |
| T1027.012 LNK Icon Smuggling | 2 | 3.80 |
| T1561.001 Disk Content Wipe | 2 | 3.80 |
| T1568.001 Fast Flux DNS | 2 | 3.80 |
| T1021.005 VNC | 3 | 3.58 |
| T1025 Data from Removable Media | 3 | 3.58 |
| T1027.004 Compile After Delivery | 3 | 3.58 |
| T1491.001 Internal Defacement | 3 | 3.58 |

## 6. Arsenal

| Software | Tipo | Técnicas no ATT&CK | Uso relatado (EN) |
|---|---|---:|---|
| [Remcos](https://attack.mitre.org/software/S0332/) | ferramenta | 38 | Gamaredon Group used Remcos during operations. |
| [Pteranodon](https://attack.mitre.org/software/S0147/) | malware | 17 |  |
| [QuietSieve](https://attack.mitre.org/software/S0686/) | malware | 9 |  |
| [PowerPunch](https://attack.mitre.org/software/S0685/) | malware | 4 |  |
| [Reg](https://attack.mitre.org/software/S0075/) | ferramenta | 3 | Gamaredon Group has used Reg to add Run keys to the Registry. |
| [Ping](https://attack.mitre.org/software/S0097/) | ferramenta | 1 |  |

**Outras ferramentas e malware relatados (planilha APT Groups & Operations / MISP):** Pterodo, DessertDown, DinoTrain

## 7. Campanhas

Nenhuma campanha atribuída no ATT&CK.

## 8. Cobertura defensiva

**67 de 70 técnicas (96%)** têm ao menos uma regra pública no catálogo Detection Rules.

### Técnicas sem regra pública (prioridade para engenharia de detecção)

- **T1587.003 Digital Certificates** — Resource Development. Fonte de log sugerida pelo MITRE: `Internet Scan` None
- **T1027.016 Junk Code Insertion** — Stealth. Fonte de log sugerida pelo MITRE: `WinEventLog:Sysmon` EventCode=11; `auditd:SYSCALL` write; `macos:endpointsecurity` ES_EVENT_TYPE_NOTIFY_EXEC
- **T1583.003 Virtual Private Server** — Resource Development. Fonte de log sugerida pelo MITRE: `Internet Scan` None

### Onde procurar — cobertura por tecnologia

Quantas técnicas deste grupo têm ao menos uma regra em cada tecnologia. Comece a caça pelas tecnologias que você tem e que aparecem aqui.

| Tecnologia | Técnicas do grupo com regra |
|---|---:|
| Windows | 60 |
| EDR / XDR | 54 |
| Linux | 44 |
| Outros / genérico | 39 |
| Servidores web & aplicações | 38 |
| Proxy / SWG | 35 |
| Firewall & perímetro | 33 |
| macOS | 32 |
| IA, LLMs & agentes | 31 |
| Microsoft 365 | 30 |
| E-mail | 30 |
| IDS / NSM / NDR | 29 |

### Regras recomendadas por técnica

Melhor regra disponível por técnica (formato portável e maduro primeiro).

| Técnica | Regra | Formato | Fonte |
|---|---|---|---|
| T1001 | [Windows PowGoop Beacon Decoding](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=splunk-security-content%3A%3A4d0480d8-80c4-4f74-84fe-2ab7fb514c85) | Splunk | Splunk security_content |
| T1001 | [Windows Suspicious QEMU Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=splunk-security-content%3A%3Ac4c0a2d4-0675-4fde-97b7-115145ba257c) | Splunk | Splunk security_content |
| T1005 | [Potential Conti Ransomware Database Dumping Activity Via SQLCmd](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A2f47f1fd-0901-466e-a770-3b7092834a1b) | Sigma | SigmaHQ |
| T1005 | [OpenCanary - SMB File Open Request](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A22777c9e-873a-4b49-855f-6072ab861a52) | Sigma | SigmaHQ |
| T1012 | [Potential Baby Shark Malware Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A2b30fa36-3a18-402f-a22d-bf4ce2189f35) | Sigma | SigmaHQ |
| T1012 | [Operation Wocao Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1cfac73c-be78-4f9a-9b08-5bde0c3953ab) | Sigma | SigmaHQ |
| T1016.001 | [System Public IP Discovery via DNS Query](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A642ce354-4252-4d43-80c9-6603f16571c1) | Elastic | Elastic detection-rules |
| T1016.001 | [Suspicious PDF Reader Child Process](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A53a26770-9cbd-40c5-8b57-61d01a325e14) | Elastic | Elastic detection-rules |
| T1020 | [Restore Public AWS RDS Instance](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac3f265c7-ff03-4056-8ab2-d486227b4599) | Sigma | SigmaHQ |
| T1020 | [Restore Public AWS RDS Instance](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Ac3f265c7-ff03-4056-8ab2-d486227b4599) | Sigma | OpenSearch Security Analytics |
| T1021.005 | [Suspicious UltraVNC Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A871b9555-69ca-4993-99d3-35a59f9f3599) | Sigma | SigmaHQ |
| T1021.005 | [Suspicious UltraVNC Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A871b9555-69ca-4993-99d3-35a59f9f3599) | Sigma | OpenSearch Security Analytics |
| T1025 | [Windows Process Executed From Removable Media](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=splunk-security-content%3A%3Ab483804a-4cc0-49a4-9f00-ac29ba844d08) | Splunk | Splunk security_content |
| T1025 | [Windows WPDBusEnum Registry Key Modification](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=splunk-security-content%3A%3A52b48e8b-eb6e-48b0-b8f1-73273f6b134e) | Splunk | Splunk security_content |
| T1027 | [Potential Emotet Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad02e8cf5-6099-48cf-9bfc-1eec2d0c7b18) | Sigma | SigmaHQ |
| T1027 | [Emotet Process Creation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Ad02e8cf5-6099-48cf-9bfc-1eec2d0c7b18) | Sigma | OpenSearch Security Analytics |
| T1027.004 | [Visual Basic Command Line Compiler Usage](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A7b10f171-7f04-47c7-9fa2-5be43c76e535) | Sigma | SigmaHQ |
| T1027.004 | [Csc.EXE Execution Form Potentially Suspicious Parent](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab730a276-6b63-41b8-bcf8-55930c8fc6ee) | Sigma | SigmaHQ |
| T1027.010 | [Decoded Payload Piped to Interpreter Detected via Defend for Containers](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A0fb83aa0-3d17-41e9-b09c-56397bf7a7d9) | Elastic | Elastic detection-rules |
| T1027.010 | [Potential PowerShell Obfuscation via String Concatenation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Af6d8c743-0916-4483-8333-3c6f107e0caa) | Elastic | Elastic detection-rules |
| T1027.012 | [Rare .lnk File Created on Desktop](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=bert-janp-hunting-queries%3A%3A64f8f89949bb) | KQL hunting | Bert-JanP Hunting Queries |
| T1027.015 | [PowerShell Suspicious Payload Encoded and Compressed](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A81fe9dc6-a2d7-4192-a2d8-eed98afc766a) | Elastic | Elastic detection-rules |
| T1027.015 | [Suspicious Content Extracted or Decompressed via Funzip](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Adc0b7782-0df0-47ff-8337-db0d678bdb66) | Elastic | Elastic detection-rules |
| T1033 | [Potential Dridex Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae6eb5a96-9e6f-4a18-9cdd-642cfda21c8e) | Sigma | SigmaHQ |
| T1033 | [Dridex Process Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Ae6eb5a96-9e6f-4a18-9cdd-642cfda21c8e) | Sigma | OpenSearch Security Analytics |
| T1036.005 | [Exploit for CVE-2015-1641](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A7993792c-5ce2-4475-a3db-a3a5539827ef) | Sigma | SigmaHQ |
| T1036.005 | [Exploit for CVE-2015-1641](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A7993792c-5ce2-4475-a3db-a3a5539827ef) | Sigma | OpenSearch Security Analytics |
| T1039 | [Copy from Admin Share](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A855bc8b5-2ae8-402e-a9ed-b889e6df1900) | Sigma | OpenSearch Security Analytics |
| T1039 | [PowerShell Share Enumeration Script](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A4c59cff1-b78a-41b8-a9f1-4231984d1fb6) | Elastic | Elastic detection-rules |
| T1041 | [Equation Group C2 Communication](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A881834a4-6659-4773-821e-1c151789d873) | Sigma | SigmaHQ |
| T1041 | [OpenCanary - TFTP Request](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab4e6b016-a2ac-4759-ad85-8000b300d61e) | Sigma | SigmaHQ |
| T1047 | [HackTool - Potential Impacket Lateral Movement Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A10c14723-61c7-4c75-92ca-9af245723ad2) | Sigma | SigmaHQ |
| T1047 | [CrackMapExec Command Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A058f4380-962d-40a5-afce-50207d36d7e2) | Sigma | OpenSearch Security Analytics |
| T1053.005 | [Operation Wocao Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1cfac73c-be78-4f9a-9b08-5bde0c3953ab) | Sigma | SigmaHQ |
| T1053.005 | [Operation Wocao Activity - Security](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A74ad4314-482e-4c3e-b237-3f7ed3b9ca8d) | Sigma | SigmaHQ |
| T1055 | [Potential Dridex Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae6eb5a96-9e6f-4a18-9cdd-642cfda21c8e) | Sigma | SigmaHQ |
| T1055 | [Antivirus PrinterNightmare CVE-2021-34527 Exploit Detection](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A6fe1719e-ecdf-4caf-bffe-4f501cb0a561) | Sigma | SigmaHQ |
| T1057 | [Process Discovery](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4e2f5868-08d4-413d-899f-dc2f1508627b) | Sigma | SigmaHQ |
| T1057 | [HackTool - PCHunter Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Afca949cc-79ca-446e-8064-01aa7e52ece5) | Sigma | SigmaHQ |
| T1059.001 | [Potential Emotet Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad02e8cf5-6099-48cf-9bfc-1eec2d0c7b18) | Sigma | SigmaHQ |
| T1059.001 | [TropicTrooper Campaign November 2018](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A8c7090c3-e0a0-4944-bd08-08c3a0cecf79) | Sigma | SigmaHQ |
| T1059.003 | [HackTool - CrackMapExec Execution Patterns](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A058f4380-962d-40a5-afce-50207d36d7e2) | Sigma | SigmaHQ |
| T1059.003 | [CrackMapExec Command Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A058f4380-962d-40a5-afce-50207d36d7e2) | Sigma | OpenSearch Security Analytics |
| T1059.005 | [Potential QBot Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4fcac6eb-0287-4090-8eea-2602e4c20040) | Sigma | SigmaHQ |
| T1059.005 | [QBot Process Creation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A4fcac6eb-0287-4090-8eea-2602e4c20040) | Sigma | OpenSearch Security Analytics |
| T1070.004 | [File Deletion](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A30aed7b6-d2c1-4eaf-9382-b6bc43e50c57) | Sigma | SigmaHQ |
| T1070.004 | [Prefetch File Deleted](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A0a1f9d29-6465-4776-b091-7f43b26e4c89) | Sigma | SigmaHQ |
| T1071.001 | [Ursnif Malware Download URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aa36ce77e-30db-4ea0-8795-644d7af5dfb4) | Sigma | SigmaHQ |
| T1071.001 | [Ursnif Malware C2 URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A932ac737-33ca-4afd-9869-0d48b391fcc9) | Sigma | SigmaHQ |
| T1080 | [M365 OneDrive Malware File Upload](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Abba1b212-b85c-41c6-9b28-be0e5cdfc9b1) | Elastic | Elastic detection-rules |
| T1080 | [M365 SharePoint Malware File Detected](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A0e52157a-8e96-4a95-a6e3-5faae5081a74) | Elastic | Elastic detection-rules |
| T1082 | [Potential GobRAT File Discovery Via Grep](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae34cfa0c-0a50-4210-9cb3-5632d08eb041) | Sigma | SigmaHQ |
| T1082 | [System Information Discovery](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A42df45e7-e6e9-43b5-8f26-bec5b39cc239) | Sigma | SigmaHQ |
| T1083 | [Turla Group Lateral Movement](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac601f20d-570a-4cde-a7d6-e17f99cb8e7f) | Sigma | SigmaHQ |
| T1083 | [WannaCry Ransomware Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A41d40bff-377a-43e2-8e1b-2e543069e079) | Sigma | SigmaHQ |
| T1090 | [Communication To LocaltoNet Tunneling Service Initiated - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac4568f5d-131f-4e78-83d4-45b2da0ec4f1) | Sigma | SigmaHQ |
| T1090 | [Communication To Ngrok Tunneling Service - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A19bf6fdb-7721-4f3d-867f-53467f6a5db6) | Sigma | SigmaHQ |
| T1090.003 | [Tor Client/Browser Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A62f7c9bf-9135-49b2-8aeb-1e54a6ecc13c) | Sigma | SigmaHQ |
| T1090.003 | [Query Tor Onion Address - DNS Client](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A8384bd26-bde6-4da9-8e5d-4174a7a47ca2) | Sigma | SigmaHQ |
| T1091 | [New USB Storage Device Mounted](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A483832a8-ffdd-4e11-8e96-e0224f7bda9b) | Elastic | Elastic detection-rules |
| T1091 | [Execution from a Removable Media with Network Connection](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A1542fa53-955e-4330-8e4d-b2d812adeb5f) | Elastic | Elastic detection-rules |
| T1095 | [PUA - Netcat Suspicious Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae31033fc-33f0-4020-9a16-faf9b31cbf08) | Sigma | SigmaHQ |
| T1095 | [Suspicious React Server Child Process](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Aae3e9625-89ad-4fc3-a7bf-fced5e64f01b) | Elastic | Elastic detection-rules |
| T1102 | [Communication To LocaltoNet Tunneling Service Initiated - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac4568f5d-131f-4e78-83d4-45b2da0ec4f1) | Sigma | SigmaHQ |
| T1102 | [Communication To Ngrok Tunneling Service - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A19bf6fdb-7721-4f3d-867f-53467f6a5db6) | Sigma | SigmaHQ |
| T1102.002 | [Potential Etherhiding C2 via Blockchain Connection](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Abba8c7d1-172b-435d-9034-02ed9289c628) | Elastic | Elastic detection-rules |
| T1102.002 | [Google Calendar C2 via Script Interpreter](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Aabc7a2be-479e-428b-b0b3-1d22bda46dd9) | Elastic | Elastic detection-rules |
| T1102.003 | [Raw Paste Service Access](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A5468045b-4fcc-4d1a-973c-c9c9578edacb) | Sigma | SigmaHQ |
| T1102.003 | [PwnDrp Access](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A2b1ee7e4-89b6-4739-b7bb-b811b6607e5e) | Sigma | SigmaHQ |
| T1105 | [Greenbug Espionage Group Indicators](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A3711eee4-a808-4849-8a14-faf733da3612) | Sigma | SigmaHQ |
| T1105 | [Pandemic Registry Key](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A47e0852a-cf81-4494-a8e6-31864f8c86ed) | Sigma | SigmaHQ |
| T1106 | [Turla Group Named Pipes](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A739915e4-1e70-4778-8b8a-17db02f66db1) | Sigma | SigmaHQ |
| T1106 | [BPFDoor Abnormal Process ID or Lock File Accessed](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A808146b2-9332-4d78-9416-d7e47012d83d) | Sigma | SigmaHQ |
| T1112 | [ShimCache Flush](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab0524451-19af-4efa-a46f-562a977f792e) | Sigma | SigmaHQ |
| T1112 | [ShimCache Flush](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Ab0524451-19af-4efa-a46f-562a977f792e) | Sigma | OpenSearch Security Analytics |
| T1113 | [PowerShell Suspicious Script with Screenshot Capabilities](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A959a7353-1129-4aa7-9084-30746b256a70) | Elastic | Elastic detection-rules |
| T1113 | [Potential Remote Desktop Shadowing Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ac57f8579-e2a5-4804-847f-f2732edc5156) | Elastic | Elastic detection-rules |
| T1119 | [iOS Implant URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Ae06ac91d-b9e6-443d-8e5b-af749e7aa6b6) | Sigma | OpenSearch Security Analytics |
| T1119 | [Shai-Hulud Malicious GitHub Workflow Creation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A0aba5685-6db6-486f-88ef-29a99c545cfd) | Sigma | SigmaHQ |
| T1120 | [PowerShell Suspicious Script with Audio Capture Capabilities](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A2f2f4939-0b34-40c2-a0a3-844eb7889f43) | Elastic | Elastic detection-rules |
| T1120 | [Fsutil Drive Enumeration](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A63de06b9-a385-40b5-8b32-73f2b9ef84b6) | Sigma | SigmaHQ |
| T1137 | [Potential Persistence Via Microsoft Office Startup Folder](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A0e20c89d-2264-44ae-8238-aeeaba609ece) | Sigma | SigmaHQ |
| T1137 | [Suspicious Outlook Macro Created](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A117d3d3a-755c-4a61-b23e-9171146d094c) | Sigma | SigmaHQ |
| T1140 | [UNC4841 - SSL Certificate Exfiltration Via Openssl](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A60911c07-f989-4362-84af-c609828ef829) | Sigma | SigmaHQ |
| T1140 | [UNC4841 - Download Compressed Files From Temp.sh Using Wget](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A60d050c4-e253-4d9a-b673-5ac100cfddfb) | Sigma | SigmaHQ |
| T1204.001 | [Google Workspace Object Copied from External Drive with App Consent](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Af33e68a4-bd19-11ed-b02f-f661ea17fbcc) | Elastic | Elastic detection-rules |
| T1204.001 | [Suspicious ClickFix/FileFix Execution Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad487ed4a-fd24-436d-a0b2-f4e95f7b2635) | Sigma | SigmaHQ |
| T1204.002 | [Ursnif Malware C2 URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A932ac737-33ca-4afd-9869-0d48b391fcc9) | Sigma | SigmaHQ |
| T1204.002 | [Droppers Exploiting CVE-2017-11882](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A678eb5f4-8597-4be6-8be7-905e4234b53a) | Sigma | SigmaHQ |
| T1218.005 | [Potential Baby Shark Malware Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A2b30fa36-3a18-402f-a22d-bf4ce2189f35) | Sigma | SigmaHQ |
| T1218.005 | [Remotely Hosted HTA File Executed Via Mshta.EXE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab98d0db6-511d-45de-ad02-e82a98729620) | Sigma | SigmaHQ |
| T1218.011 | [Equation Group DLL_U Export Function Load](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad465d1d8-27a2-4cca-9621-a800f37cf72e) | Sigma | SigmaHQ |
| T1218.011 | [APT29 2018 Phishing Campaign File Indicators](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A3a3f81ca-652c-482b-adeb-b1c804727f74) | Sigma | SigmaHQ |
| T1221 | [Server Side Template Injection Strings](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aada3bc4f-f0fd-42b9-ba91-e105e8af7342) | Sigma | SigmaHQ |
| T1221 | [Suspicious Set Value of MSDT in Registry (CVE-2022-30190)](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A2d9403d5-7927-46b7-8216-37ab7c9ec5e3) | Sigma | SigmaHQ |
| T1480 | [[ZINGBOX] Risk level increased to Medium](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sagan-rules-quadrant%3A%3Asid-5004309) | Suricata/Snort | Sagan rules (Quadrant) |
| T1480 | [[ZINGBOX] Risk level increased to High](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sagan-rules-quadrant%3A%3Asid-5004310) | Suricata/Snort | Sagan rules (Quadrant) |
| T1491.001 | [Potential Ransomware Activity Using LegalNotice Message](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A8b9606c9-28be-4a38-b146-0e313cc232c1) | Sigma | SigmaHQ |
| T1491.001 | [Potentially Suspicious Desktop Background Change Using Reg.EXE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A8cbc9475-8d05-4e27-9c32-df960716c701) | Sigma | SigmaHQ |
| T1497.001 | [Virtual Machine Fingerprinting](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A5b03c9fb-9945-4d2f-9568-fd690fee3fba) | Elastic | Elastic detection-rules |
| T1497.001 | [Powershell Detect Virtualization Environment](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad93129cd-1ee0-479f-bc03-ca6f129882e3) | Sigma | SigmaHQ |
| T1518.001 | [Sysmon Discovery Via Default Driver Altitude Using Findstr.EXE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A37db85d1-b089-490a-a59a-c7b6f984f480) | Sigma | SigmaHQ |
| T1518.001 | [Local Firewall Rules Enumeration Via NetFirewallRule Cmdlet](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aea207a23-b441-4a17-9f76-ad5be47d51d3) | Sigma | SigmaHQ |
| T1534 | [AWS SNS Topic Message Publish by Rare User](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A2112ecce-cd34-11ef-873f-f661ea17fbcd) | Elastic | Elastic detection-rules |
| T1534 | [OpenAI ChatGPT Enterprise Gmail Message Sent via Connector](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A7184e35d-5605-4283-badf-435e1974e488) | Elastic | Elastic detection-rules |
| T1547.001 | [Potential Ryuk Ransomware Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac37510b8-2107-4b78-aa32-72f251e7a844) | Sigma | SigmaHQ |
| T1547.001 | [Ryuk Ransomware](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Ac37510b8-2107-4b78-aa32-72f251e7a844) | Sigma | OpenSearch Security Analytics |
| T1559.001 | [CMSTP Execution Process Access](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A3b4b232a-af90-427c-a22f-30b0c0837b95) | Sigma | SigmaHQ |
| T1559.001 | [CMSTP Execution Process Access](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A3b4b232a-af90-427c-a22f-30b0c0837b95) | Sigma | OpenSearch Security Analytics |
| T1561.001 | [Cisco File Deletion](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A71d65515-c436-43c0-841b-236b1f32c21e) | Sigma | SigmaHQ |
| T1561.001 | [Cisco File Deletion](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A71d65515-c436-43c0-841b-236b1f32c21e) | Sigma | OpenSearch Security Analytics |
| T1564.003 | [Potential Data Stealing Via Chromium Headless Debugging](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A3e8207c5-fcd2-4ea6-9418-15d45b4890e4) | Sigma | SigmaHQ |
| T1564.003 | [HackTool - Covenant PowerShell Launcher](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac260b6db-48ba-4b4a-a76f-2f67644e99d2) | Sigma | SigmaHQ |
| T1566.001 | [Ursnif Malware C2 URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A932ac737-33ca-4afd-9869-0d48b391fcc9) | Sigma | SigmaHQ |
| T1566.001 | [Droppers Exploiting CVE-2017-11882](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A678eb5f4-8597-4be6-8be7-905e4234b53a) | Sigma | SigmaHQ |
| T1568 | [Possible FIN7 DGA Command and Control Behavior](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A4a4e23cf-78a2-449c-bac3-701924c269d3) | Elastic | Elastic detection-rules |
| T1568 | [Cobalt Strike Command and Control Beacon](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Acf53f532-9cc9-445a-9ae7-fced307ec53c) | Elastic | Elastic detection-rules |
| T1568.001 | [Abnormal Deny Rate for Source IP](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3Ad36bb1e3-5abc-4037-ad9a-24ba3469819e) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1571 | [Potentially Suspicious Malware Callback Communication - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Adbfc7c98-04ab-4ab7-aa94-c74d22aa7376) | Sigma | SigmaHQ |
| T1571 | [Potentially Suspicious Malware Callback Communication](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4b89abaa-99fe-4232-afdd-8f9aa4d20382) | Sigma | SigmaHQ |
| T1583.001 | [AWS Route 53 Private Hosted Zone Associated With a VPC](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ae3c27562-709a-42bd-82f2-3ed926cced19) | Elastic | Elastic detection-rules |
| T1583.001 | [AWS SES Email Identity Verified Then Deleted](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A8e4bde35-125d-4eb3-9a2e-d7e77a053a08) | Elastic | Elastic detection-rules |
| T1583.006 | [GitHub Repo Created](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A6cea88e4-6ce2-4238-9981-a54c140d6336) | Elastic | Elastic detection-rules |
| T1583.006 | [Cisco Secure Firewall - Rare Snort Rule Triggered](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=splunk-security-content%3A%3Ae20313d2-7d63-4fcf-b2d9-d6e12c6c7bd7) | Splunk | Splunk security_content |
| T1588.002 | [Hacktool Execution - Imphash](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A24e3e58a-646b-4b50-adef-02ef935b9fc8) | Sigma | SigmaHQ |
| T1588.002 | [Renamed SysInternals DebugView Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acd764533-2e07-40d6-a718-cfeec7f2da7f) | Sigma | SigmaHQ |
| T1608.001 | [M365 OneDrive Malware File Upload](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Abba1b212-b85c-41c6-9b28-be0e5cdfc9b1) | Elastic | Elastic detection-rules |
| T1608.001 | [M365 SharePoint Malware File Detected](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A0e52157a-8e96-4a95-a6e3-5faae5081a74) | Elastic | Elastic detection-rules |
| T1620 | [PowerShell Base64 Encoded Reflective Assembly Load](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A62b7ccc9-23b4-471e-aa15-6da3663c4d59) | Sigma | SigmaHQ |
| T1620 | [Potential WinAPI Calls Via PowerShell Scripts](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A03d83090-8cba-44a0-b02f-0b756a050306) | Sigma | SigmaHQ |
| T1685 | [Windows Defender Configuration Changes](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A801bd44f-ceed-4eb6-887c-11544633c0aa) | Sigma | SigmaHQ |
| T1685 | [Windows Defender Virus Scanning Feature Disabled](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A686c0b4b-9dd3-4847-9077-d6c1bbe36fcb) | Sigma | SigmaHQ |

## 9. Plano de emulação e validação

Use num laboratório isolado e autorizado para confirmar que as regras disparam. Os comandos estão nos repositórios oficiais.

| Tática | Técnica | Teste Atomic Red Team | Plataformas |
|---|---|---|---|
| Initial Access | [T1566.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1566.001/T1566.001.md) | Download Macro-Enabled Phishing Attachment | windows |
| Initial Access | [T1566.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1566.001/T1566.001.md) | Word spawned a command shell and used an IP address in the command line | windows |
| Execution | [T1047](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1047/T1047.md) | WMI Reconnaissance Users | windows |
| Execution | [T1047](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1047/T1047.md) | WMI Reconnaissance Processes | windows |
| Execution | [T1053.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1053.005/T1053.005.md) | Scheduled Task Startup Script | windows |
| Execution | [T1053.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1053.005/T1053.005.md) | Scheduled task Local | windows |
| Execution | [T1059.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md) | Mimikatz | windows |
| Execution | [T1059.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md) | Run BloodHound from local disk | windows |
| Execution | [T1059.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.003/T1059.003.md) | Create and Execute Batch Script | windows |
| Execution | [T1059.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.003/T1059.003.md) | Writes text to a file and displays it. | windows |
| Execution | [T1059.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.005/T1059.005.md) | Visual Basic script execution to gather local computer information | windows |
| Execution | [T1059.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.005/T1059.005.md) | Encoded VBS code execution | windows |
| Execution | [T1106](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1106/T1106.md) | Execution through API - CreateProcess | windows |
| Execution | [T1106](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1106/T1106.md) | WinPwn - Get SYSTEM shell - Pop System Shell using CreateProcess technique | windows |
| Execution | [T1204.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1204.002/T1204.002.md) | OSTap Style Macro Execution | windows |
| Execution | [T1204.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1204.002/T1204.002.md) | OSTap Payload Download | windows |
| Persistence | [T1137](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1137/T1137.md) | Office Application Startup - Outlook as a C2 | windows |
| Persistence | [T1547.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1547.001/T1547.001.md) | Reg Key Run | windows |
| Persistence | [T1547.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1547.001/T1547.001.md) | Reg Key RunOnce | windows |
| Stealth | [T1027](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027/T1027.md) | Decode base64 Data into Script | linux, macos |
| Stealth | [T1027](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027/T1027.md) | Execute base64-encoded PowerShell | windows |
| Stealth | [T1027.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027.004/T1027.004.md) | Compile After Delivery using csc.exe | windows |
| Stealth | [T1027.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027.004/T1027.004.md) | Dynamic C# Compile | windows |
| Stealth | [T1036.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.005/T1036.005.md) | Execute a process from a directory masquerading as the current parent directory | linux, macos |
| Stealth | [T1036.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.005/T1036.005.md) | Masquerade as a built-in system executable | windows |
| Stealth | [T1055](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1055/T1055.md) | Shellcode execution via VBA | windows |
| Stealth | [T1055](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1055/T1055.md) | Remote Process Injection in LSASS via mimikatz | windows |
| Stealth | [T1070.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.004/T1070.004.md) | Delete a single file - FreeBSD/Linux/macOS | linux, macos |
| Stealth | [T1070.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.004/T1070.004.md) | Delete an entire folder - FreeBSD/Linux/macOS | linux, macos |
| Stealth | [T1140](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1140/T1140.md) | Deobfuscate/Decode Files Or Information | windows |
| Stealth | [T1140](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1140/T1140.md) | Certutil Rename and Decode | windows |
| Stealth | [T1218.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.005/T1218.005.md) | Mshta executes JavaScript Scheme Fetch Remote Payload With GetObject | windows |
| Stealth | [T1218.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.005/T1218.005.md) | Mshta executes VBScript to execute malicious command | windows |
| Stealth | [T1218.011](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.011/T1218.011.md) | Rundll32 execute JavaScript Remote Payload With GetObject | windows |
| Stealth | [T1218.011](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.011/T1218.011.md) | Rundll32 execute VBscript command | windows |
| Stealth | [T1221](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1221/T1221.md) | WINWORD Remote Template Injection | windows |
| Stealth | [T1497.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1497.001/T1497.001.md) | Detect Virtualization Environment (Linux) | linux |
| Stealth | [T1497.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1497.001/T1497.001.md) | Detect Virtualization Environment (FreeBSD) | linux |
| Stealth | [T1564.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1564.003/T1564.003.md) | Hidden Window | windows |
| Stealth | [T1564.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1564.003/T1564.003.md) | Headless Browser Accessing Mockbin | windows |
| Stealth | [T1620](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1620/T1620.md) | WinPwn - Reflectively load Mimik@tz into memory | windows |
| Stealth | [T1620](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1620/T1620.md) | Reflective PE Injection via PowerSploit | windows |
| Defense Impairment | [T1112](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1112/T1112.md) | Modify Registry of Current User Profile - cmd | windows |
| Defense Impairment | [T1112](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1112/T1112.md) | Modify Registry of Local Machine - cmd | windows |
| Defense Impairment | [T1685](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1685/T1685.md) | Windows Disable LSA Protection | windows |
| Defense Impairment | [T1685](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1685/T1685.md) | Disable journal logging via systemctl utility | linux |
| Discovery | [T1012](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1012/T1012.md) | Query Registry | windows |
| Discovery | [T1012](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1012/T1012.md) | Query Registry with Powershell cmdlets | windows |
| Discovery | [T1016.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1016.001/T1016.001.md) | Check internet connection using ping Windows | windows |
| Discovery | [T1016.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1016.001/T1016.001.md) | Check internet connection using ping freebsd, linux or macos | linux, macos |
| Discovery | [T1033](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1033/T1033.md) | System Owner/User Discovery | windows |
| Discovery | [T1033](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1033/T1033.md) | System Owner/User Discovery | linux, macos |
| Discovery | [T1057](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1057/T1057.md) | Process Discovery - ps | linux, macos |
| Discovery | [T1057](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1057/T1057.md) | Process Discovery - tasklist | windows |
| Discovery | [T1082](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1082/T1082.md) | System Information Discovery | windows |
| Discovery | [T1082](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1082/T1082.md) | System Information Discovery | macos |
| Discovery | [T1083](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1083/T1083.md) | File and Directory Discovery (cmd.exe) | windows |
| Discovery | [T1083](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1083/T1083.md) | File and Directory Discovery (PowerShell) | windows |
| Discovery | [T1120](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1120/T1120.md) | Win32_PnPEntity Hardware Inventory | windows |
| Discovery | [T1120](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1120/T1120.md) | WinPwn - printercheck | windows |
| Discovery | [T1518.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1518.001/T1518.001.md) | Security Software Discovery | windows |
| Discovery | [T1518.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1518.001/T1518.001.md) | Security Software Discovery - powershell | windows |
| Lateral Movement | [T1021.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.005/T1021.005.md) | Enable Apple Remote Desktop Agent | macos |
| Lateral Movement | [T1091](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1091/T1091.md) | USB Malware Spread Simulation | windows |
| Collection | [T1005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1005/T1005.md) | Search files of interest and save them to a single zip file (Windows) | windows |
| Collection | [T1005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1005/T1005.md) | Find and dump sqlite databases (Linux) | linux |
| Collection | [T1025](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1025/T1025.md) | Identify Documents on USB and Removable Media via PowerShell | windows |
| Collection | [T1039](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1039/T1039.md) | Copy a sensitive File over Administrative share with copy | windows |
| Collection | [T1039](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1039/T1039.md) | Copy a sensitive File over Administrative share with Powershell | windows |
| Collection | [T1113](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1113/T1113.md) | Screencapture | macos |
| Collection | [T1113](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1113/T1113.md) | Screencapture (silent) | macos |
| Collection | [T1119](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1119/T1119.md) | Automated Collection Command Prompt | windows |
| Collection | [T1119](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1119/T1119.md) | Automated Collection PowerShell | windows |
| Command and Control | [T1071.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1071.001/T1071.001.md) | Malicious User Agents - Powershell | windows |
| Command and Control | [T1071.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1071.001/T1071.001.md) | Malicious User Agents - CMD | windows |
| Command and Control | [T1090.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1090.003/T1090.003.md) | Psiphon | windows |
| Command and Control | [T1090.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1090.003/T1090.003.md) | Tor Proxy Usage - Windows | windows |
| Command and Control | [T1095](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1095/T1095.md) | ICMP C2 | windows |
| Command and Control | [T1095](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1095/T1095.md) | Netcat C2 | windows |
| Command and Control | [T1105](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1105/T1105.md) | rsync remote file copy (push) | linux, macos |
| Command and Control | [T1105](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1105/T1105.md) | rsync remote file copy (pull) | linux, macos |
| Command and Control | [T1571](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1571/T1571.md) | Testing usage of uncommonly used port with PowerShell | windows |
| Command and Control | [T1571](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1571/T1571.md) | Testing usage of uncommonly used port | linux, macos |
| Exfiltration | [T1020](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1020/T1020.md) | IcedID Botnet HTTP PUT | windows |
| Exfiltration | [T1020](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1020/T1020.md) | Exfiltration via Encrypted FTP | windows |
| Exfiltration | [T1041](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1041/T1041.md) | C2 Data Exfiltration | windows |
| Exfiltration | [T1041](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1041/T1041.md) | Text Based Data Exfiltration using DNS subdomains | windows |
| Impact | [T1491.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1491.001/T1491.001.md) | Replace Desktop Wallpaper | windows |
| Impact | [T1491.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1491.001/T1491.001.md) | Configure LegalNoticeCaption and LegalNoticeText registry keys to display ransom message | windows |

**Logs reais de ataque (EVTX) para testar sem executar nada:**

- T1027 — [4624,4674,4688- CrackMap Exec SMB mimikatz](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0005-Defense%20Evasion/T1027-Obfuscated%20Files%20or%20Information/4624%2C4674%2C4688-%20CrackMap%20Exec%20SMB%20mimikatz.evtx) _(explícito)_
- T1027 — [ID1-CrackMapExec payload execution](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0005-Defense%20Evasion/T1027-Obfuscated%20Files%20or%20Information/ID1-CrackMapExec%20payload%20execution.evtx) _(explícito)_
- T1047 — [ID1-WMI spwaning PowerShell process - WMImplant](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1047-Windows%20Management%20Instrumentation/ID1-WMI%20spwaning%20PowerShell%20process%20-%20WMImplant.evtx) _(explícito)_
- T1047 — [ID1-WMIexec process execution](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1047-Windows%20Management%20Instrumentation/ID1-WMIexec%20process%20execution.evtx) _(explícito)_
- T1053.005 — [ID4688-4698 Persistent scheduled task with SYSTEM privileges creation](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1053.005-Scheduled%20Task/ID4688-4698%20Persistent%20scheduled%20task%20with%20SYSTEM%20privileges%20creation.evtx) _(explícito)_
- T1053.005 — [ID4688-Interactive shell using AT schedule task](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1053.005-Scheduled%20Task/ID4688-Interactive%20shell%20using%20AT%20schedule%20task.evtx) _(explícito)_
- T1055 — [sideloading_injection_persistence_run_key](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/AutomatedTestingTools/Malware/sideloading_injection_persistence_run_key.evtx) _(inferido)_
- T1055 — [sideloading_uacbypass_rundll32_injection_c2](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/AutomatedTestingTools/Malware/sideloading_uacbypass_rundll32_injection_c2.evtx) _(inferido)_
- T1059.001 — [ID4103-4104-Payload download via PowerShell](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1059.001-PowerShell/ID4103-4104-Payload%20download%20via%20PowerShell.evtx) _(explícito)_
- T1059.001 — [ID4688-Encoded PowerShell MSF payload via process execution](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1059.001-PowerShell/ID4688-Encoded%20PowerShell%20MSF%20payload%20via%20process%20execution.evtx) _(explícito)_
- T1059.003 — [ID4688-SQL Server payload injectection for reverse shell (MSF)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1059.003-Windows%20Command%20Shell/ID4688-SQL%20Server%20payload%20injectection%20for%20reverse%20shell%20%28MSF%29.evtx) _(explícito)_
- T1090 — [ID5600-proxy configuration changed](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0011-Command%20and%20Control/T1090-Proxy/ID5600-proxy%20configuration%20changed.evtx) _(explícito)_
- T1112 — [ID11,13-SMBexec service registration](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0005-Defense%20Evasion/T1112-Modify%20registry/ID11%2C13-SMBexec%20service%20registration.evtx) _(explícito)_
- T1112 — [ID4624,4670,4688,4674-Registry permission change via WMI (DAMP)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0005-Defense%20Evasion/T1112-Modify%20registry/ID4624%2C4670%2C4688%2C4674-Registry%20permission%20change%20via%20WMI%20%28DAMP%29.evtx) _(explícito)_
- T1140 — [ID4688-Certutil download](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0005-Defense%20Evasion/T1140-Deobfuscate-Decode%20Files%20or%20Information/ID4688-Certutil%20download.evtx) _(explícito)_
- T1218.005 — [exec_persist_rundll32_mshta_scheduledtask_sysmon_1_3_11](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Execution/exec_persist_rundll32_mshta_scheduledtask_sysmon_1_3_11.evtx) _(inferido)_
- T1218.005 — [sysmon_mshta_sharpshooter_stageless_meterpreter](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Execution/sysmon_mshta_sharpshooter_stageless_meterpreter.evtx) _(inferido)_
- T1218.011 — [rundll32_cmd_schtask](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/AutomatedTestingTools/Malware/rundll32_cmd_schtask.evtx) _(inferido)_
- T1218.011 — [rundll32_hollowing_wermgr_masquerading](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/AutomatedTestingTools/Malware/rundll32_hollowing_wermgr_masquerading.evtx) _(inferido)_
- T1547.001 — [sideloading_injection_persistence_run_key](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/AutomatedTestingTools/Malware/sideloading_injection_persistence_run_key.evtx) _(inferido)_
- T1547.001 — [evasion_persis_hidden_run_keyvalue_sysmon_13](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Persistence/evasion_persis_hidden_run_keyvalue_sysmon_13.evtx) _(inferido)_
- T1685 — [ID1-SYSMON driver unload (FilterManager)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0005-Defense%20Evasion/T1562.001-Impair%20Defenses-Disable%20or%20Modify%20tool/ID1-SYSMON%20driver%20unload%20%28FilterManager%29.evtx) _(explícito)_
- T1685 — [ID13-Defender service configuration disabled](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0005-Defense%20Evasion/T1562.001-Impair%20Defenses-Disable%20or%20Modify%20tool/ID13-Defender%20service%20configuration%20disabled.evtx) _(explícito)_

## 10. Hipóteses de hunting

Se Gamaredon Group estiver no seu ambiente, estas são as perguntas a fazer aos seus dados (fontes de log segundo as estratégias de detecção do MITRE ATT&CK).

1. **T1001 Data Obfuscation** — Detects excessive outbound traffic to remote host over HTTP(S) from uncommon or previously unseen processes. Dados: `NSM:Flow` (HTTP ).
2. **T1102.003 One-Way Communication** — Suspicious process initiating outbound connections to web services without corresponding response or return traffic, indicative of one-way command channels. Dados: `WinEventLog:Sysmon` (EventCode=3, 22), `etw:Microsoft-Windows-WinINet` (WinINet API telemetry).
3. **T1137 Office Application Startup** — Office-based persistence via Office template macros, Outlook forms/rules/homepage, or registry-persistent scripts. Adversary modifies registry keys or Office application directories to load malicious scripts at startup. Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Sysmon` (EventCode=13, 14).
4. **T1027.012 LNK Icon Smuggling** — Correlates LNK file execution with embedded resource extraction or suspicious network activity following initial launch, often leading to payload delivery via disguised icons. Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=15), `WinEventLog:Sysmon` (EventCode=3, 22).
5. **T1561.001 Disk Content Wipe** — Processes attempting raw disk access via \\.\PhysicalDrive paths, abnormal file I/O to MBR/boot sectors, or loading of third-party drivers (e.g., RawDisk) that enable disk overwrite. Correlate process creation, privilege usage, and disk modification events… Dados: `WinEventLog:Security` (EventCode=4673), `WinEventLog:Sysmon` (Raw disk writes targeting \\.\PhysicalDrive* or MBR locations), `WinEventLog:Sysmon` (EventCode=6).
6. **T1568.001 Fast Flux DNS** — Identify repeated DNS resolutions where the same domain name returns multiple IPs in short succession, combined with low TTL values and high query volume from unusual processes. Correlate with process lineage (e.g., Office apps spawning abnormal DNS lookups). Dados: `WinEventLog:Sysmon` (EventCode=3, 22), `WinEventLog:Security` (EventCode=1).
7. **T1021.005 VNC** — Detection of VNC service or executable starting unexpectedly, followed by user session creation and interactive desktop activity (mouse/keyboard simulation). Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Security` (EventCode=4624, 4648), `NSM:Flow` (port 5900 inbound).
8. **T1025 Data from Removable Media** — Adversary mounts a USB device and begins enumerating, copying, or compressing files using scripting engines, cmd, or remote access tools. Dados: `WinEventLog:Security` (EventCode=4663, 4670, 4656), `WinEventLog:System` (EventCode=2003), `WinEventLog:Sysmon` (EventCode=1).
9. **T1027.004 Compile After Delivery** — Detects compilation activity using csc.exe, ilasm.exe, or msbuild.exe initiated by user-space processes outside typical development environments, followed by execution or network activity from newly written binaries. Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Sysmon` (EventCode=3, 22).
10. **T1491.001 Internal Defacement** — Adversary modifies internal UI messages (e.g., login banners, desktop wallpapers) or hosted intranet web pages by creating or altering content files using scripts or unauthorized access. Often preceded by privilege escalation or web shell deployment. Dados: `WinEventLog:Security` (EventCode=4663, 4670, 4656), `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Sysmon` (EventCode=2).
11. **T1559.001 Component Object Model** — Detects anomalous use of COM objects for execution, such as Office applications spawning scripting engines, enumeration of COM interfaces via registry queries, or processes loading atypical DLLs through COM activation. Correlates process creation, module… Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=7), `WinEventLog:Security` (EventCode=4663, 4670, 4656).
12. **T1587.003 Digital Certificates** — Consider use of services that may aid in the tracking of certificates in use on sites across the Internet. In some cases it may be possible to pivot on known pieces of certificate information to uncover other adversary infrastructure. Detection efforts may be… Dados: `Internet Scan` (None).

## 11. OSINT — onde pesquisar

Consultas prontas com todos os nomes conhecidos do grupo:

- Relatórios técnicos: [busca web](https://duckduckgo.com/?q=%28%22Gamaredon+Group%22+OR+%22IRON+TILDEN%22+OR+%22Primitive+Bear%22+OR+%22ACTINIUM%22+OR+%22Armageddon%22+OR+%22Shuckworm%22%29+threat+report) · [PDFs](https://duckduckgo.com/?q=%28%22Gamaredon+Group%22+OR+%22IRON+TILDEN%22+OR+%22Primitive+Bear%22+OR+%22ACTINIUM%22+OR+%22Armageddon%22+OR+%22Shuckworm%22%29+filetype%3Apdf)
- Regras e IOCs publicados: [GitHub](https://github.com/search?type=code&q=%22Gamaredon+Group%22+OR+%22IRON+TILDEN%22+OR+%22Primitive+Bear%22+OR+%22ACTINIUM%22+OR+%22Armageddon%22+OR+%22Shuckworm%22)
- Pulsos de ameaça: [AlienVault OTX](https://otx.alienvault.com/browse/global/pulses?q=Gamaredon+Group)
- Família de malware e atores: [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/actors) (busque por Gamaredon Group, IRON TILDEN, Primitive Bear)
- Cartões de grupo: [ThaiCERT Threat Group Cards](https://apt.etda.or.th/cgi-bin/listgroups.cgi)
- Página oficial: [MITRE ATT&CK G0047](https://attack.mitre.org/groups/G0047/)

**Relatórios na coleção CyberMonitor** (ligados pelo nome do grupo, conferir antes de citar):

- 2017 — [The Gamaredon Group Toolset Evolution - Palo Alto Networks Blog](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2017/2017.02.27.gamaredon-group-toolset-evolution/The%20Gamaredon%20Group%20Toolset%20Evolution%20-%20Palo%20Alto%20Networks%20Blog.pdf) _(via “Gamaredon Group”)_
- 2019 — [The Gamaredon Group_ A TTP Profile Analysis](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2019/2019.08.21.Gamaredon_Group/The%20Gamaredon%20Group_%20A%20TTP%20Profile%20Analysis.pdf) _(via “Gamaredon Group”)_
- 2020 — [Gamaredon group grows its game _ WeLiveSecurity](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2020/2020.06.11.Gamaredon_group/Gamaredon%20group%20grows%20its%20game%20_%20WeLiveSecurity.pdf) _(via “Gamaredon Group”)_
- 2021 — [Technical report Armagedon](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2021/2021.11.04.Gamaredon_Armageddon_Group/Technical%20report%20Armagedon.pdf) _(via “Armageddon”)_
- 2022 — [Shuckworm_APT](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2022/2022.01.31.Shuckworm_APT/Shuckworm_APT.pdf) _(via “Shuckworm”)_

**Relatórios públicos ligados pelo APT4ALL** (6 no total, mais recentes primeiro):

- 2022 — [Russia's Trident Ursa (aka Gamaredon APT) Cyber Conflict Operations Unwavering Since Invasion of Ukraine](https://app.box.com/s/2xgd6r6ttw57hlg1gx0k2g72earqc9oy) _(Palo Alto)_
- 2022 — [Shuckworm: Espionage Group Continues Intense Campaign Against Ukraine](https://app.box.com/s/0kwypesas8xwv9a43cu3l5x9d632gyy6) _(Symantec)_
- 2022 — [ACTINIUM targets Ukrainian organizations](https://app.box.com/s/0qxv3fc5yx2j8lbv1ftlvmaakuy0nrsk) _(microsoft)_
- 2022 — [Gamaredon (Primitive Bear) Russian APT Group Actively Targeting Ukraine](https://app.box.com/s/bhitsulabbr6y4d8jz56ljweejy7htqf) _(palo alto networks)_
- 2022 — [Shuckworm Continues Cyber-Espionage Attacks Against Ukraine](https://app.box.com/s/px3ro986hh3mvw0hqxr9n9n45tilygy2) _(Symantec)_
- 2017 — [The Gamaredon Group Toolset Evolution](https://app.box.com/s/9wb59m0q2nw315jshwr3launllnnqtht) _(Palo Alto Networks)_

## 12. Bibliografia (18 fontes citadas pelo ATT&CK)

- [Bleepingcomputer Gamardeon FSB November 2021](https://www.bleepingcomputer.com/news/security/ukraine-links-members-of-gamaredon-hacker-group-to-russian-fsb/) — Toulas, B. (2018, November 4). Ukraine links members of Gamaredon hacker group to Russian FSB. Retrieved April 15, 2022.
- [CERT-EE Gamaredon January 2021](https://www.ria.ee/sites/default/files/content-editors/kuberturve/tale_of_gamaredon_infection.pdf) — CERT-EE. (2021, January 27). Gamaredon Infection: From Dropper to Entry. Retrieved February 17, 2022.
- [Cloudflare 2026 Threat Report New Threat Actors March 2026](https://blog.cloudflare.com/2026-threat-report/) — Cloudflare. (2026, March 3). Introducing the 2026 Cloudflare Threat Report. Retrieved April 18, 2026.
- [ESET Gamaredon June 2020](https://www.welivesecurity.com/2020/06/11/gamaredon-group-grows-its-game/) — Boutin, J. (2020, June 11). Gamaredon group grows its game. Retrieved June 16, 2020.
- [ESET Gamaredon Sept2024](https://web-assets.esetstatic.com/wls/en/papers/white-papers/cyberespionage-gamaredon-way.pdf) — Rusnák, Z. (2024, September 26). Cyberespionage the Gamaredon way: Analysis of toolset used to spy on Ukraine in 2022 and 2023. Retrieved October 30, 2024.
- [Huntio_GamaredonFlux_Apr2025](https://hunt.io/blog/state-sponsored-activity-gamaredon-shadowpad) — Hunt.io. (2025, April 8). State-Sponsored Tactics: How Gamaredon and ShadowPad Operate and Rotate Their Infrastructure. Retrieved July 23, 2025.
- [Microsoft Actinium February 2022](https://www.microsoft.com/security/blog/2022/02/04/actinium-targets-ukrainian-organizations/) — Microsoft Threat Intelligence Center. (2022, February 4). ACTINIUM targets Ukrainian organizations. Retrieved February 18, 2022.
- [Microsoft Threat Actor Naming July 2023](https://learn.microsoft.com/en-us/microsoft-365/security/intelligence/microsoft-threat-actor-naming?view=o365-worldwide) — Microsoft . (2023, July 12). How Microsoft names threat actors. Retrieved November 17, 2023.
- [Palo Alto Gamaredon Feb 2017](https://researchcenter.paloaltonetworks.com/2017/02/unit-42-title-gamaredon-group-toolset-evolution/) — Kasza, A. and Reichel, D. (2017, February 27). The Gamaredon Group Toolset Evolution. Retrieved March 1, 2017.
- [Proofpoint RTF Injection](https://www.proofpoint.com/us/blog/threat-insight/injection-new-black-novel-rtf-template-inject-technique-poised-widespread) — Raggi, M. (2021, December 1). Injection is the New Black: Novel RTF Template Inject Technique Poised for Widespread Adoption Beyond APT Actors . Retrieved December 9, 2021.
- [Secureworks IRON TILDEN Profile](https://www.secureworks.com/research/threat-profiles/iron-tilden) — Secureworks CTU. (n.d.). IRON TILDEN. Retrieved February 24, 2022.
- [SilentPush_GamaredonFastFlux_Sept2023](https://www.silentpush.com/blog/from-russia-with-a-71/) — Silent Push. (2023, September 7). From Russia with a 71: Uncovering Gamaredon's fast flux infrastructure. New Apex domains and ASN/IP diversity patterns discovered. Retrieved July 28, 2025.
- [Symantec Shuckworm January 2022](https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/shuckworm-gamaredon-espionage-ukraine) — Symantec. (2022, January 31). Shuckworm Continues Cyber-Espionage Attacks Against Ukraine. Retrieved February 17, 2022.
- [SymantecCarbonBlack_ShuckwormUSB_Apr2025](https://www.security.com/threat-intelligence/shuckworm-ukraine-gammasteel) — Threat Hunter Team, Symantec and Carbon Black. (2025, April 10). Shuckworm Targets Foreign Military Mission Based in Ukraine. Retrieved July 23, 2025.
- [TrendMicro Gamaredon April 2020](https://blog.trendmicro.com/trendlabs-security-intelligence/gamaredon-apt-group-use-covid-19-lure-in-campaigns/) — Kakara, H., Maruyama, E. (2020, April 17). Gamaredon APT Group Use Covid-19 Lure in Campaigns. Retrieved May 19, 2020.
- [Unit 42 Gamaredon February 2022](https://unit42.paloaltonetworks.com/gamaredon-primitive-bear-ukraine-update-2021/) — Unit 42. (2022, February 3). Russia’s Gamaredon aka Primitive Bear APT Group Actively Targeting Ukraine. Retrieved February 21, 2022.
- [unit42_gamaredon_dec2022](https://unit42.paloaltonetworks.com/trident-ursa/) — Unit 42. (2022, December 20). Russia’s Trident Ursa (aka Gamaredon APT) Cyber Conflict Operations Unwavering Since Invasion of Ukraine. Retrieved September 12, 2024.
- [VenereCiscoTalos_Gamaredon_Mar2025](https://blog.talosintelligence.com/gamaredon-campaign-distribute-remcos/) — Venere, G. (2025, March 28). Gamaredon campaign abuses LNK files to distribute Remcos backdoor. Retrieved July 23, 2025.

## 13. Limites e confiança

- O ATT&CK registra o que foi **relatado publicamente**, não tudo o que o grupo faz. Ausência de uma técnica não prova que o grupo não a usa.
- **Sobreposição de TTP não é atribuição.** Muitas técnicas são compartilhadas entre grupos e com red teams. Use a assinatura comportamental como hipótese, junto com infraestrutura, malware e contexto.
- Cobertura de detecção refere-se ao catálogo público Detection Rules, não ao seu ambiente: confira se a telemetria necessária chega ao seu SIEM.
- Ligações marcadas como _inferidas_ (EVTX por palavra-chave, relatórios por nome) devem ser verificadas.

---
Fontes: MITRE ATT&CK® (uso livre com atribuição, © The MITRE Corporation), APT4ALL (MISP Galaxy CC0/BSD-2, APT Groups & Operations CC BY 4.0, EternalLiberty, APTnotes, Ransomware Tool Matrix CC BY 4.0), Atomic Red Team (Red Canary, MIT), EVTX-to-MITRE-Attack, EVTX-ATTACK-SAMPLES, APT & CyberCriminal Campaign Collections. Gerado por [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules).
