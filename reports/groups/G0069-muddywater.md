# MuddyWater (G0069) — Dossiê de inteligência

> **TLP:CLEAR** · gerado em 2026-10-25 a partir de fontes abertas · MITRE ATT&CK v20.0 · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0069) · [ATT&CK](https://attack.mitre.org/groups/G0069/)

**Também conhecido como:** Earth Vetala, MERCURY, Static Kitten, Seedworm, TEMP.Zagros, Mango Sandstorm, TA450, MuddyKrill  
**Registro no ATT&CK:** criado em 2018-04-18, atualizado em 2026-07-31 · referências de 2017 a 2026

## 1. Sumário executivo

- **68 técnicas** atribuídas publicamente, concentradas em **Execution, Stealth, Command and Control**.
- **Arsenal:** 11 malware e 10 ferramentas (ex.: Empire, PowerSploit, POWERSTATS, Koadic, RustyWater).
- **Campanhas atribuídas:** 0.
- **Cobertura de detecção pública:** 99% das técnicas têm ao menos uma regra no catálogo; **1 técnicas sem nenhuma regra pública**.
- **Assinatura comportamental** (técnicas raras entre os 178 grupos, as mais úteis para atribuição): T1137.001 Office Template Macros, T1218.003 CMSTP, T1204.004 Malicious Copy and Paste, T1003.005 Cached Domain Credentials, T1027.004 Compile After Delivery.

## 2. Quem é

> MuddyWater is a cyber espionage group assessed to be a subordinate element within Iran's Ministry of Intelligence and Security (MOIS). Since at least 2017, MuddyWater has targeted a range of government and private organizations across sectors, including telecommunications, local government, finance, defense, and oil and natural gas organizations, in the Middle East (specifically the UAE and Saudi Arabia), Asia, Africa, Europe, and North America. MuddyWater has reused domains dating back to October 2025, and has a preference for NameCheap and Hosterdaddy Private Limited (AS136557). In late 2025 and early 2026, MuddyWater used commercial satellite internet (i.e., Starlink) for command and control (C2) communication.

_Texto original do MITRE ATT&CK, em inglês._

## 3. Perfil TTP por tática (kill chain)

Cada linha: técnica, como o grupo a usou segundo relatos públicos, e o que existe para detectar e testar.

### Reconnaissance (TA0043) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1590.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1590.004) Network Topology | MuddyWater has mapped target networks; access to this information and more is then shared/sold to other Iran threat actors. | **0** | — | — |

### Resource Development (TA0042) — 4

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1583.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1583.001) Domains | MuddyWater has established domains, some of which appeared to spoof legitimate domains for use in operations. | 7 | — | — |
| [T1583.006](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1583.006) Web Services | MuddyWater has used file sharing services including OneHub, Sync, and TeraBox to distribute tools. | 2 | — | — |
| [T1588.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1588.001) Malware | MuddyWater has used publicly available malware for operations, likely to blend in with other cybercriminals. | 7 | — | — |
| [T1588.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1588.002) Tool | MuddyWater has used legitimate tools ConnectWise, RemoteUtilities, and SimpleHelp to gain access to the target environment. | 35 | — | — |

### Initial Access (TA0001) — 4

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1190](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1190) Exploit Public-Facing Application | MuddyWater has exploited the Microsoft Exchange memory corruption vulnerability (CVE-2020-0688). | 580 | — | — |
| [T1566](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1566) Phishing | MuddyWater has sent phishing emails to targets from the email address support@microsoftonlines[.]com. | 286 | — | — |
| [T1566.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1566.001) Spearphishing Attachment | MuddyWater has compromised third parties and used compromised accounts to send spearphishing emails with targeted attachments to recipients. MuddyWater has also sent spearphishing emails with the attachment Cybersecurity.doc, which served as the primarily payl… | 230 | 2 | — |
| [T1566.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1566.002) Spearphishing Link | MuddyWater has sent targeted spearphishing e-mails with malicious links. | 138 | 1 | — |

### Execution (TA0002) — 14

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1047](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1047) Windows Management Instrumentation | MuddyWater has used malware that leveraged WMI for execution and querying host information. | 370 | 12 | 11 |
| [T1053.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1053.005) Scheduled Task | MuddyWater has used scheduled tasks to establish persistence. | 248 | 14 | 11 |
| [T1059.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.001) PowerShell | MuddyWater has used PowerShell for execution. | 1340 | 22 | 15 |
| [T1059.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.003) Windows Command Shell | MuddyWater has used a custom tool for creating reverse shells. | 269 | 6 | 1 |
| [T1059.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.005) Visual Basic | MuddyWater has used VBScript files to execute its POWERSTATS payload, as well as macros. | 192 | 3 | — |
| [T1059.006](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.006) Python | MuddyWater has developed tools in Python including Out1. | 122 | — | — |
| [T1059.007](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.007) JavaScript | MuddyWater has used JavaScript files to execute its POWERSTATS payload. | 205 | 5 | — |
| [T1203](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1203) Exploitation for Client Execution | MuddyWater has exploited the Office vulnerability CVE-2017-0199 for execution. | 202 | — | — |
| [T1204.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1204.001) Malicious Link | MuddyWater has distributed URLs in phishing e-mails that link to lure documents. | 52 | — | — |
| [T1204.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1204.002) Malicious File | MuddyWater has attempted to get users to open malicious PDF attachment and to enable macros and launch malicious Microsoft Word documents delivered via spearphishing emails. Additionally, MuddyWater has used a Word document with a malicious Visual Basic for Ap… | 259 | 13 | — |
| [T1204.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1204.004) Malicious Copy and Paste | MuddyWater has leveraged ClickFix type tactics enticing victims to copy and paste malicious PowerShell code. | 32 | — | — |
| [T1559.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1559.001) Component Object Model | MuddyWater has used malware that has the capability to execute malicious code via COM, DCOM, and Outlook. | 35 | — | — |
| [T1559.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1559.002) Dynamic Data Exchange | MuddyWater has used malware that can execute PowerShell scripts via DDE. | 10 | 3 | — |
| [T1574.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1574.001) DLL | MuddyWater maintains persistence on victim networks through side-loading dlls to trick legitimate programs into running malware. | 455 | 7 | 5 |

### Persistence (TA0003) — 3

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1053.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1053.005) Scheduled Task | MuddyWater has used scheduled tasks to establish persistence. | 248 | 14 | 11 |
| [T1137.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1137.001) Office Template Macros | MuddyWater has used a Word Template, Normal.dotm, for persistence. | 2 | 1 | — |
| [T1547.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1547.001) Registry Run Keys / Startup Folder | MuddyWater has added Registry Run key KCU\Software\Microsoft\Windows\CurrentVersion\Run\SystemTextEncoding to establish persistence. | 299 | 21 | 2 |

### Privilege Escalation (TA0004) — 3

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1053.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1053.005) Scheduled Task | MuddyWater has used scheduled tasks to establish persistence. | 248 | 14 | 11 |
| [T1547.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1547.001) Registry Run Keys / Startup Folder | MuddyWater has added Registry Run key KCU\Software\Microsoft\Windows\CurrentVersion\Run\SystemTextEncoding to establish persistence. | 299 | 21 | 2 |
| [T1548.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1548.002) Bypass User Account Control | MuddyWater uses various techniques to bypass UAC. | 379 | 28 | 14 |

### Stealth (TA0005) — 10

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1027.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1027.003) Steganography | MuddyWater has stored obfuscated JavaScript code in an image file named temp.jpg. | 13 | — | — |
| [T1027.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1027.004) Compile After Delivery | MuddyWater has used the .NET csc.exe tool to compile executables from downloaded C# code. | 32 | 5 | — |
| [T1027.010](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1027.010) Command Obfuscation | MuddyWater has used Daniel Bohannon’s Invoke-Obfuscation framework and obfuscated PowerShell scripts. The group has also used other obfuscation methods, including Base64 obfuscation of VBScripts and PowerShell commands. | 78 | — | — |
| [T1036.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1036.005) Match Legitimate Resource Name or Location | MuddyWater has disguised malicious executables and used filenames and Registry key names associated with Windows Defender. | 116 | 4 | — |
| [T1140](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1140) Deobfuscate/Decode Files or Information | MuddyWater has decoded base64-encoded PowerShell, JavaScript, and VBScript. | 173 | 11 | 1 |
| [T1218.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1218.003) CMSTP | MuddyWater has used CMSTP.exe and a malicious INF to execute its POWERSTATS payload. | 61 | 2 | — |
| [T1218.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1218.005) Mshta | MuddyWater has used mshta.exe to execute its POWERSTATS payload and to pass a PowerShell one-liner for execution. | 130 | 10 | 4 |
| [T1218.011](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1218.011) Rundll32 | MuddyWater has used malware that leveraged rundll32.exe in a Registry Run key to execute a .dll. | 274 | 16 | 12 |
| [T1574.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1574.001) DLL | MuddyWater maintains persistence on victim networks through side-loading dlls to trick legitimate programs into running malware. | 455 | 7 | 5 |
| [T1684.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1684.001) Impersonation | MuddyWater has used support@microsoftonlines[.]com to send phishing emails that masqueraded as security updates from Microsoft. MuddyWater has also impersonated TMCell (Altyn Asyr CJSC), the primary mobile operator in Turkmenistan, sending phishing emails with… | 1 | — | — |

### Defense Impairment (TA0112) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1685](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1685) Disable or Modify Tools | MuddyWater can disable the system's local proxy settings. | 1275 | 78 | 19 |

### Credential Access (TA0006) — 6

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1003.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1003.001) LSASS Memory | MuddyWater has performed credential dumping with Mimikatz and procdump64.exe. | 580 | 14 | 10 |
| [T1003.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1003.004) LSA Secrets | MuddyWater has performed credential dumping with LaZagne. | 72 | 2 | — |
| [T1003.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1003.005) Cached Domain Credentials | MuddyWater has performed credential dumping with LaZagne. | 32 | 1 | — |
| [T1552.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1552.001) Credentials In Files | MuddyWater has run a tool that steals passwords saved in victim email. | 166 | 32 | — |
| [T1555](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1555) Credentials from Password Stores | MuddyWater has performed credential dumping with LaZagne and other tools, including by dumping passwords saved in victim email. | 160 | 9 | 2 |
| [T1555.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1555.003) Credentials from Web Browsers | MuddyWater has run tools including Browser64 to steal passwords saved in victim web browsers. | 59 | 18 | 5 |

### Discovery (TA0007) — 9

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1016](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1016) System Network Configuration Discovery | MuddyWater has used malware to collect the victim’s IP address and domain name. | 99 | 10 | 5 |
| [T1033](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1033) System Owner/User Discovery | MuddyWater has used malware that can collect the victim’s username. | 181 | 8 | — |
| [T1049](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1049) System Network Connections Discovery | MuddyWater has used a PowerShell backdoor to check for Skype connections on the target machine. | 47 | 7 | — |
| [T1057](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1057) Process Discovery | MuddyWater has used malware to obtain a list of running processes on the system. | 82 | 10 | — |
| [T1082](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1082) System Information Discovery | MuddyWater has used malware that can collect the victim’s OS version and machine name. | 264 | 41 | — |
| [T1083](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1083) File and Directory Discovery | MuddyWater has used malware that checked if the ProgramData folder had folders or files with the keywords "Kasper," "Panda," or "ESET." | 137 | 9 | — |
| [T1087.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1087.002) Domain Account | MuddyWater has used cmd.exe net user /domain to enumerate domain users. | 180 | 25 | 1 |
| [T1518](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1518) Software Discovery | MuddyWater has used a PowerShell backdoor to check for Skype connectivity on the target machine. | 58 | 6 | — |
| [T1518.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1518.001) Security Software Discovery | MuddyWater has used malware to check running processes against a hard-coded list of security tools often used by malware researchers. | 54 | 12 | — |

### Lateral Movement (TA0008) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1210](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1210) Exploitation of Remote Services | MuddyWater has exploited the Microsoft Netlogon vulnerability (CVE-2020-1472). | 192 | — | 4 |
| [T1534](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1534) Internal Spearphishing | MuddyWater has used compromised mailboxes within target organizations to send spearphishing emails. | 5 | — | — |

### Collection (TA0009) — 3

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1074.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1074.001) Local Data Staging | MuddyWater has stored a decoy PDF file within a victim's `%temp%` folder. | 37 | 3 | — |
| [T1113](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1113) Screen Capture | MuddyWater has used malware that can capture screenshots of the victim’s machine. | 60 | 10 | — |
| [T1560.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1560.001) Archive via Utility | MuddyWater has used the native Windows cabinet creation tool, makecab.exe, likely to compress stolen data to be uploaded. | 76 | 13 | — |

### Command and Control (TA0011) — 10

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1071.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1071.001) Web Protocols | MuddyWater has used HTTP for C2 communications. | 228 | 3 | — |
| [T1090](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1090) Proxy | MuddyWater has used NordVPN to proxy phishing emails, making them appear to originate from France. | 162 | — | 1 |
| [T1090.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1090.002) External Proxy | MuddyWater has controlled POWERSTATS from behind a proxy network to obfuscate the C2 location. MuddyWater has used a series of compromised websites that victims connected to randomly to relay information to command and control (C2). MuddyWater has also used go… | 18 | — | — |
| [T1102.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1102.002) Bidirectional Communication | MuddyWater has used web services including OneHub to distribute remote access tools. | 27 | — | — |
| [T1104](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1104) Multi-Stage Channels | MuddyWater has used one C2 to obtain enumeration scripts and monitor web logs, but a different C2 to send data back. | 1 | — | — |
| [T1105](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1105) Ingress Tool Transfer | MuddyWater has used malware that can upload additional files to the victim’s machine. MuddyWater has used PowerShell commands to install remote management and monitoring (RMM) software on the victim’s machine to conduct espionage and to exfiltrate data. | 644 | 39 | — |
| [T1132.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1132.001) Standard Encoding | MuddyWater has used tools to encode C2 communications including Base64 encoding. | 26 | 3 | — |
| [T1219.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1219.002) Remote Desktop Software | MuddyWater has leveraged RMM solutions including ScreenConnect, AteraAgent, SimpleHelp, Action1, Level, and PDQ to facilitate follow-on actions within compromised hosts to include data exfiltration. | 221 | — | — |
| [T1571](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1571) Non-Standard Port | MuddyWater has used ports 8043 and 8848 for botnet C2 communication. | 163 | 2 | — |
| [T1573.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1573.001) Symmetric Cryptography | MuddyWater has used AES to encrypt C2 responses. | 5 | — | — |

### Exfiltration (TA0010) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1041](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1041) Exfiltration Over C2 Channel | MuddyWater has used C2 infrastructure to receive exfiltrated data. | 135 | 2 | — |
| [T1567.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1567.002) Exfiltration to Cloud Storage | MuddyWater has attempted to exfiltrate data to Wasabi, a cloud storage service, using Rclone. | 85 | 2 | — |

## 4. Assinatura comportamental

Técnicas que este grupo usa e que poucos dos 178 grupos do ATT&CK usam. Pesam mais numa atribuição por TTP: ver várias delas juntas é mais informativo do que ver técnicas comuns como PowerShell.

| Técnica | Outros grupos que usam | Peso (raridade) |
|---|---:|---:|
| T1137.001 Office Template Macros | 0 | 4.49 |
| T1218.003 CMSTP | 1 | 4.09 |
| T1204.004 Malicious Copy and Paste | 2 | 3.80 |
| T1003.005 Cached Domain Credentials | 3 | 3.58 |
| T1027.004 Compile After Delivery | 3 | 3.58 |
| T1104 Multi-Stage Channels | 3 | 3.58 |
| T1559.001 Component Object Model | 3 | 3.58 |
| T1590.004 Network Topology | 3 | 3.58 |
| T1534 Internal Spearphishing | 6 | 3.11 |
| T1566 Phishing | 7 | 2.99 |

## 5. Arsenal

| Software | Tipo | Técnicas no ATT&CK | Uso relatado (EN) |
|---|---|---:|---|
| [Empire](https://attack.mitre.org/software/S0363/) | ferramenta | 73 |  |
| [PowerSploit](https://attack.mitre.org/software/S0194/) | ferramenta | 28 |  |
| [POWERSTATS](https://attack.mitre.org/software/S0223/) | malware | 27 |  |
| [Koadic](https://attack.mitre.org/software/S0250/) | ferramenta | 27 |  |
| [RustyWater](https://attack.mitre.org/software/S9037/) | malware | 20 |  |
| [CrackMapExec](https://attack.mitre.org/software/S0488/) | ferramenta | 20 |  |
| [MuddyViper](https://attack.mitre.org/software/S9032/) | malware | 18 | MuddyWater has used MuddyViper during operations. |
| [Tsundere Botnet](https://attack.mitre.org/software/S9034/) | malware | 17 |  |
| [Mimikatz](https://attack.mitre.org/software/S0002/) | ferramenta | 17 |  |
| [STARWHALE](https://attack.mitre.org/software/S1037/) | malware | 14 |  |
| [Small Sieve](https://attack.mitre.org/software/S1035/) | malware | 13 |  |
| [LP-Notes](https://attack.mitre.org/software/S9036/) | malware | 11 | MuddyWater has used LP-Notes during operations. |
| [LaZagne](https://attack.mitre.org/software/S0349/) | ferramenta | 10 |  |
| [Mori](https://attack.mitre.org/software/S1047/) | malware | 9 |  |
| [PowGoop](https://attack.mitre.org/software/S1046/) | malware | 8 |  |
| [SHARPSTATS](https://attack.mitre.org/software/S0450/) | malware | 7 |  |
| [Fooder](https://attack.mitre.org/software/S9033/) | malware | 7 | MuddyWater has used Fooder during operations. |
| [Rclone](https://attack.mitre.org/software/S1040/) | ferramenta | 6 |  |
| [Out1](https://attack.mitre.org/software/S0594/) | ferramenta | 5 |  |
| [RemoteUtilities](https://attack.mitre.org/software/S0592/) | ferramenta | 4 |  |
| [ConnectWise](https://attack.mitre.org/software/S0591/) | ferramenta | 3 |  |

## 6. Campanhas

Nenhuma campanha atribuída no ATT&CK.

## 7. Cobertura defensiva

**67 de 68 técnicas (99%)** têm ao menos uma regra pública no catálogo Detection Rules.

### Técnicas sem regra pública (prioridade para engenharia de detecção)

- **T1590.004 Network Topology** — Reconnaissance

### Regras recomendadas por técnica

Melhor regra disponível por técnica (formato portável e maduro primeiro).

| Técnica | Regra | Formato | Fonte |
|---|---|---|---|
| T1003.001 | [Antivirus - Password Dumper Signature](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A78cc2dd2-7d20-4d32-93ff-057084c38b93) | Sigma | SigmaHQ |
| T1003.001 | [Mimikatz through Windows Remote Management](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Aaa35a627-33fb-4d04-a165-d33b4afca3e8) | Sigma | OpenSearch Security Analytics |
| T1003.004 | [Possible Impacket SecretDump Remote Activity - Zeek](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A92dae1ed-1c9d-4eff-a567-33acbd95b00e) | Sigma | SigmaHQ |
| T1003.004 | [Cred Dump Tools Dropped Files](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A8fbf3271-1ef6-4e94-8210-03c2317947f6) | Sigma | SigmaHQ |
| T1003.005 | [Cred Dump Tools Dropped Files](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A8fbf3271-1ef6-4e94-8210-03c2317947f6) | Sigma | SigmaHQ |
| T1003.005 | [Potential Reconnaissance For Cached Credentials Via Cmdkey.EXE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A07f8bdc2-c9b3-472a-9817-5a670b872f53) | Sigma | SigmaHQ |
| T1016 | [Potential Pikabot Discovery Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A698d4431-514f-4c82-af4d-cf573872a9f5) | Sigma | SigmaHQ |
| T1016 | [OpenCanary - SNMP OID Request](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae9856028-fd4e-46e6-b3d1-10f7ceb95078) | Sigma | SigmaHQ |
| T1027.003 | [Steganography Hide Files with Steghide](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ace446a9e-30b9-4483-8e38-d2c9ad0a2280) | Sigma | SigmaHQ |
| T1027.003 | [Steganography Unzip Hidden Information From Picture File](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aedd595d7-7895-4fa7-acb3-85a18a8772ca) | Sigma | SigmaHQ |
| T1027.004 | [Visual Basic Command Line Compiler Usage](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A7b10f171-7f04-47c7-9fa2-5be43c76e535) | Sigma | SigmaHQ |
| T1027.004 | [Csc.EXE Execution Form Potentially Suspicious Parent](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab730a276-6b63-41b8-bcf8-55930c8fc6ee) | Sigma | SigmaHQ |
| T1027.010 | [Decoded Payload Piped to Interpreter Detected via Defend for Containers](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A0fb83aa0-3d17-41e9-b09c-56397bf7a7d9) | Elastic | Elastic detection-rules |
| T1027.010 | [Potential PowerShell Obfuscation via String Concatenation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Af6d8c743-0916-4483-8333-3c6f107e0caa) | Elastic | Elastic detection-rules |
| T1033 | [Potential Dridex Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae6eb5a96-9e6f-4a18-9cdd-642cfda21c8e) | Sigma | SigmaHQ |
| T1033 | [Dridex Process Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Ae6eb5a96-9e6f-4a18-9cdd-642cfda21c8e) | Sigma | OpenSearch Security Analytics |
| T1036.005 | [Exploit for CVE-2015-1641](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A7993792c-5ce2-4475-a3db-a3a5539827ef) | Sigma | SigmaHQ |
| T1036.005 | [Exploit for CVE-2015-1641](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A7993792c-5ce2-4475-a3db-a3a5539827ef) | Sigma | OpenSearch Security Analytics |
| T1041 | [Equation Group C2 Communication](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A881834a4-6659-4773-821e-1c151789d873) | Sigma | SigmaHQ |
| T1041 | [OpenCanary - TFTP Request](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab4e6b016-a2ac-4759-ad85-8000b300d61e) | Sigma | SigmaHQ |
| T1047 | [HackTool - Potential Impacket Lateral Movement Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A10c14723-61c7-4c75-92ca-9af245723ad2) | Sigma | SigmaHQ |
| T1047 | [CrackMapExec Command Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A058f4380-962d-40a5-afce-50207d36d7e2) | Sigma | OpenSearch Security Analytics |
| T1049 | [Potential Pikabot Discovery Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A698d4431-514f-4c82-af4d-cf573872a9f5) | Sigma | SigmaHQ |
| T1049 | [HackTool - SharpView Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab2317cfa-4a47-4ead-b3ff-297438c0bc2d) | Sigma | SigmaHQ |
| T1053.005 | [Operation Wocao Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1cfac73c-be78-4f9a-9b08-5bde0c3953ab) | Sigma | SigmaHQ |
| T1053.005 | [Operation Wocao Activity - Security](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A74ad4314-482e-4c3e-b237-3f7ed3b9ca8d) | Sigma | SigmaHQ |
| T1057 | [Process Discovery](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4e2f5868-08d4-413d-899f-dc2f1508627b) | Sigma | SigmaHQ |
| T1057 | [HackTool - PCHunter Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Afca949cc-79ca-446e-8064-01aa7e52ece5) | Sigma | SigmaHQ |
| T1059.001 | [Potential Emotet Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad02e8cf5-6099-48cf-9bfc-1eec2d0c7b18) | Sigma | SigmaHQ |
| T1059.001 | [TropicTrooper Campaign November 2018](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A8c7090c3-e0a0-4944-bd08-08c3a0cecf79) | Sigma | SigmaHQ |
| T1059.003 | [HackTool - CrackMapExec Execution Patterns](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A058f4380-962d-40a5-afce-50207d36d7e2) | Sigma | SigmaHQ |
| T1059.003 | [CrackMapExec Command Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A058f4380-962d-40a5-afce-50207d36d7e2) | Sigma | OpenSearch Security Analytics |
| T1059.005 | [Potential QBot Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4fcac6eb-0287-4090-8eea-2602e4c20040) | Sigma | SigmaHQ |
| T1059.005 | [QBot Process Creation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A4fcac6eb-0287-4090-8eea-2602e4c20040) | Sigma | OpenSearch Security Analytics |
| T1059.006 | [Emotet Loader Execution Via .LNK File](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1f32d820-1d5c-43fe-8fe2-feef0c952eb7) | Sigma | SigmaHQ |
| T1059.006 | [Serpent Backdoor Payload Execution Via Scheduled Task](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad5eb7432-fda4-4bba-a37f-ffa74d9ed639) | Sigma | SigmaHQ |
| T1059.007 | [Adwind RAT / JRAT](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1fac1481-2dbc-48b2-9096-753c49b4ec71) | Sigma | SigmaHQ |
| T1059.007 | [WScript or CScript Dropper - File](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A002bdb95-0cf1-46a6-9e08-d38c128a6127) | Sigma | SigmaHQ |
| T1071.001 | [Ursnif Malware Download URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aa36ce77e-30db-4ea0-8795-644d7af5dfb4) | Sigma | SigmaHQ |
| T1071.001 | [Ursnif Malware C2 URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A932ac737-33ca-4afd-9869-0d48b391fcc9) | Sigma | SigmaHQ |
| T1074.001 | [Sensitive File Access followed by Compression](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Aa0fbd7a9-1923-4e05-92df-b484168f17bc) | Elastic | Elastic detection-rules |
| T1074.001 | [Folder Compress To Potentially Suspicious Output Via Compress-Archive Cmdlet](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A85a8e5ba-bd03-4bfb-bbfa-a4409a8f8b98+%23+Process+Creation) | Sigma | SigmaHQ |
| T1082 | [Potential GobRAT File Discovery Via Grep](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae34cfa0c-0a50-4210-9cb3-5632d08eb041) | Sigma | SigmaHQ |
| T1082 | [System Information Discovery](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A42df45e7-e6e9-43b5-8f26-bec5b39cc239) | Sigma | SigmaHQ |
| T1083 | [Turla Group Lateral Movement](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac601f20d-570a-4cde-a7d6-e17f99cb8e7f) | Sigma | SigmaHQ |
| T1083 | [WannaCry Ransomware Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A41d40bff-377a-43e2-8e1b-2e543069e079) | Sigma | SigmaHQ |
| T1087.002 | [BloodHound Collection Files](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A02773bed-83bf-469f-b7ff-e676e7d78bab) | Sigma | SigmaHQ |
| T1087.002 | [Suspicious Active Directory Database Snapshot Via ADExplorer](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aef61af62-bc74-4f58-b49b-626448227652) | Sigma | SigmaHQ |
| T1090 | [Communication To LocaltoNet Tunneling Service Initiated - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac4568f5d-131f-4e78-83d4-45b2da0ec4f1) | Sigma | SigmaHQ |
| T1090 | [Communication To Ngrok Tunneling Service - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A19bf6fdb-7721-4f3d-867f-53467f6a5db6) | Sigma | SigmaHQ |
| T1090.002 | [RDP over Reverse SSH Tunnel WFP](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A5bed80b6-b3e8-428e-a3ae-d3c757589e41) | Sigma | SigmaHQ |
| T1090.002 | [Potential Tunneling via AWS IoT Secure Tunneling Localproxy](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Adeab559f-f3ab-4ce3-b17c-8f70c4169fd6) | Elastic | Elastic detection-rules |
| T1102.002 | [Potential Etherhiding C2 via Blockchain Connection](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Abba8c7d1-172b-435d-9034-02ed9289c628) | Elastic | Elastic detection-rules |
| T1102.002 | [Google Calendar C2 via Script Interpreter](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Aabc7a2be-479e-428b-b0b3-1d22bda46dd9) | Elastic | Elastic detection-rules |
| T1104 | [PowerShell DownloadFile](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A8f70ac5f-1f6f-4f8e-b454-db19561216c5) | Sigma | OpenSearch Security Analytics |
| T1105 | [Greenbug Espionage Group Indicators](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A3711eee4-a808-4849-8a14-faf733da3612) | Sigma | SigmaHQ |
| T1105 | [Pandemic Registry Key](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A47e0852a-cf81-4494-a8e6-31864f8c86ed) | Sigma | SigmaHQ |
| T1113 | [PowerShell Suspicious Script with Screenshot Capabilities](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A959a7353-1129-4aa7-9084-30746b256a70) | Elastic | Elastic detection-rules |
| T1113 | [Potential Remote Desktop Shadowing Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ac57f8579-e2a5-4804-847f-f2732edc5156) | Elastic | Elastic detection-rules |
| T1132.001 | [DNS Exfiltration and Tunneling Tools Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A98a96a5a-64a0-4c42-92c5-489da3866cb0) | Sigma | SigmaHQ |
| T1132.001 | [DNS Exfiltration and Tunneling Tools Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A98a96a5a-64a0-4c42-92c5-489da3866cb0) | Sigma | OpenSearch Security Analytics |
| T1137.001 | [Persistence via Microsoft Outlook VBA](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A397945f3-d39a-4e6f-8bcb-9656c2031438) | Elastic | Elastic detection-rules |
| T1137.001 | [Office Application Startup via Template File Modification](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-protections-artifacts-behavior%3A%3A608eae71-6797-4ded-bfaa-41bcb17a8498) | Elastic | Elastic protections-artifacts (behavior) |
| T1140 | [UNC4841 - SSL Certificate Exfiltration Via Openssl](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A60911c07-f989-4362-84af-c609828ef829) | Sigma | SigmaHQ |
| T1140 | [UNC4841 - Download Compressed Files From Temp.sh Using Wget](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A60d050c4-e253-4d9a-b673-5ac100cfddfb) | Sigma | SigmaHQ |
| T1190 | [OMIGOD HTTP No Authentication RCE - CVE-2021-38647](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aab6b1a39-a9ee-4ab4-b075-e83acf6e346b) | Sigma | SigmaHQ |
| T1190 | [Exploited CVE-2020-10189 Zoho ManageEngine](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A846b866e-2a57-46ee-8e16-85fa92759be7) | Sigma | OpenSearch Security Analytics |
| T1203 | [Droppers Exploiting CVE-2017-11882](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A678eb5f4-8597-4be6-8be7-905e4234b53a) | Sigma | SigmaHQ |
| T1203 | [OMIGOD HTTP No Authentication RCE - CVE-2021-38647](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aab6b1a39-a9ee-4ab4-b075-e83acf6e346b) | Sigma | SigmaHQ |
| T1204.001 | [Google Workspace Object Copied from External Drive with App Consent](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Af33e68a4-bd19-11ed-b02f-f661ea17fbcc) | Elastic | Elastic detection-rules |
| T1204.001 | [Suspicious ClickFix/FileFix Execution Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad487ed4a-fd24-436d-a0b2-f4e95f7b2635) | Sigma | SigmaHQ |
| T1204.002 | [Ursnif Malware C2 URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A932ac737-33ca-4afd-9869-0d48b391fcc9) | Sigma | SigmaHQ |
| T1204.002 | [Droppers Exploiting CVE-2017-11882](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A678eb5f4-8597-4be6-8be7-905e4234b53a) | Sigma | SigmaHQ |
| T1204.004 | [Potential TerminalFix Cloudflare Lure in PowerShell](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Aa4071476-76c8-4dc4-a3e2-956148d22aa2) | Elastic | Elastic detection-rules |
| T1204.004 | [Potential Fake CAPTCHA Phishing Attack](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Afbad57ec-4442-48db-a34f-5ee907b44a22) | Elastic | Elastic detection-rules |
| T1210 | [OMIGOD HTTP No Authentication RCE - CVE-2021-38647](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aab6b1a39-a9ee-4ab4-b075-e83acf6e346b) | Sigma | SigmaHQ |
| T1210 | [OMIGOD HTTP No Authentication RCE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Aab6b1a39-a9ee-4ab4-b075-e83acf6e346b) | Sigma | OpenSearch Security Analytics |
| T1218.003 | [CMSTP UAC Bypass via COM Object Access](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4b60e6f2-bf39-47b4-b4ea-398e33cfe253) | Sigma | SigmaHQ |
| T1218.003 | [CMSTP Execution Process Creation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A7d4cdc5a-0076-40ca-aac8-f7e714570e47) | Sigma | SigmaHQ |
| T1218.005 | [Potential Baby Shark Malware Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A2b30fa36-3a18-402f-a22d-bf4ce2189f35) | Sigma | SigmaHQ |
| T1218.005 | [Remotely Hosted HTA File Executed Via Mshta.EXE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab98d0db6-511d-45de-ad02-e82a98729620) | Sigma | SigmaHQ |
| T1218.011 | [Equation Group DLL_U Export Function Load](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad465d1d8-27a2-4cca-9621-a800f37cf72e) | Sigma | SigmaHQ |
| T1218.011 | [APT29 2018 Phishing Campaign File Indicators](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A3a3f81ca-652c-482b-adeb-b1c804727f74) | Sigma | SigmaHQ |
| T1219.002 | [Antivirus - Exploitation Framework Signature](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A238527ad-3c2c-4e4f-a1f6-92fd63adb864) | Sigma | SigmaHQ |
| T1219.002 | [Potential SocGholish Second Stage C2 DNS Query](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A70761fe8-6aa2-4f80-98c1-a57049c08e66) | Sigma | SigmaHQ |
| T1518 | [HackTool - WinPwn Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad557dc06-62e8-4468-a8e8-7984124908ce) | Sigma | SigmaHQ |
| T1518 | [HackTool - WinPwn Execution - ScriptBlock](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A851fd622-b675-4d26-b803-14bc7baa517a) | Sigma | SigmaHQ |
| T1518.001 | [Sysmon Discovery Via Default Driver Altitude Using Findstr.EXE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A37db85d1-b089-490a-a59a-c7b6f984f480) | Sigma | SigmaHQ |
| T1518.001 | [Local Firewall Rules Enumeration Via NetFirewallRule Cmdlet](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aea207a23-b441-4a17-9f76-ad5be47d51d3) | Sigma | SigmaHQ |
| T1534 | [AWS SNS Topic Message Publish by Rare User](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A2112ecce-cd34-11ef-873f-f661ea17fbcd) | Elastic | Elastic detection-rules |
| T1534 | [OpenAI ChatGPT Enterprise Gmail Message Sent via Connector](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A7184e35d-5605-4283-badf-435e1974e488) | Elastic | Elastic detection-rules |
| T1547.001 | [Potential Ryuk Ransomware Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac37510b8-2107-4b78-aa32-72f251e7a844) | Sigma | SigmaHQ |
| T1547.001 | [Ryuk Ransomware](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Ac37510b8-2107-4b78-aa32-72f251e7a844) | Sigma | OpenSearch Security Analytics |
| T1548.002 | [CMSTP UAC Bypass via COM Object Access](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4b60e6f2-bf39-47b4-b4ea-398e33cfe253) | Sigma | SigmaHQ |
| T1548.002 | [HackTool - Empire PowerShell UAC Bypass](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A3268b746-88d8-4cd3-bffc-30077d02c787) | Sigma | SigmaHQ |
| T1552.001 | [Potential Russian APT Credential Theft Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab83f5166-9237-4b5e-9cd4-7b5d52f4d8ee) | Sigma | SigmaHQ |
| T1552.001 | [Copy Passwd Or Shadow From TMP Path](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Afa4aaed5-4fe0-498d-bbc0-08e3346387ba) | Sigma | SigmaHQ |
| T1555 | [HackTool - SecurityXploded Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A7679d464-4f74-45e2-9e01-ac66c5eb041a) | Sigma | SigmaHQ |
| T1555 | [SecurityXploded Tool](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A7679d464-4f74-45e2-9e01-ac66c5eb041a) | Sigma | OpenSearch Security Analytics |
| T1555.003 | [SQLite Chromium Profile Data DB Access](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A24c77512-782b-448a-8950-eddb0785fc71) | Sigma | SigmaHQ |
| T1555.003 | [HackTool - WinPwn Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad557dc06-62e8-4468-a8e8-7984124908ce) | Sigma | SigmaHQ |
| T1559.001 | [CMSTP Execution Process Access](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A3b4b232a-af90-427c-a22f-30b0c0837b95) | Sigma | SigmaHQ |
| T1559.001 | [CMSTP Execution Process Access](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A3b4b232a-af90-427c-a22f-30b0c0837b95) | Sigma | OpenSearch Security Analytics |
| T1559.002 | [Enable Microsoft Dynamic Data Exchange](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A63647769-326d-4dde-a419-b925cc0caf42) | Sigma | SigmaHQ |
| T1559.002 | [Enable Microsoft Dynamic Data Exchange](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A63647769-326d-4dde-a419-b925cc0caf42) | Sigma | OpenSearch Security Analytics |
| T1560.001 | [APT31 Judgement Panda Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A03e2746e-2b31-42f1-ab7a-eb39365b2422) | Sigma | SigmaHQ |
| T1560.001 | [Suspicious Manipulation Of Default Accounts Via Net.EXE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A5b768e71-86f2-4879-b448-81061cbae951) | Sigma | SigmaHQ |
| T1566 | [CVE-2021-31979 CVE-2021-33771 Exploits by Sourgum](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aad7085ac-92e4-4b76-8ce2-276d2c0e68ef) | Sigma | SigmaHQ |
| T1566 | [CVE-2021-31979 CVE-2021-33771 Exploits](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A32b5db62-cb5f-4266-9639-0fa48376ac00) | Sigma | SigmaHQ |
| T1566.001 | [Ursnif Malware C2 URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A932ac737-33ca-4afd-9869-0d48b391fcc9) | Sigma | SigmaHQ |
| T1566.001 | [Droppers Exploiting CVE-2017-11882](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A678eb5f4-8597-4be6-8be7-905e4234b53a) | Sigma | SigmaHQ |
| T1566.002 | [Potential Malicious Usage of CloudTrail System Manager](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A38e7f511-3f74-41d4-836e-f57dfa18eead) | Sigma | SigmaHQ |
| T1566.002 | [Google Workspace Device Registration After OAuth from Suspicious ASN](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A012bfca7-45cb-4507-a3ba-3777167f8b81) | Elastic | Elastic detection-rules |
| T1567.002 | [APT40 Dropbox Tool User Agent](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A5ba715b6-71b7-44fd-8245-f66893e81b3d) | Sigma | SigmaHQ |
| T1567.002 | [PUA - Rclone Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae37db05d-d1f9-49c8-b464-cee1a4b11638) | Sigma | SigmaHQ |
| T1571 | [Potentially Suspicious Malware Callback Communication - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Adbfc7c98-04ab-4ab7-aa94-c74d22aa7376) | Sigma | SigmaHQ |
| T1571 | [Potentially Suspicious Malware Callback Communication](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4b89abaa-99fe-4232-afdd-8f9aa4d20382) | Sigma | SigmaHQ |
| T1573.001 | [CYFIRMA - High severity Command & Control Network Indicators with Monitor Recommendation Rule](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A6d8fb3fe-2501-4103-8137-34261fa3a596) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1573.001 | [CYFIRMA - High severity Command & Control Network Indicators with Block Recommendation Rule](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A6b61b716-afd9-4f6c-ad00-965d5987cafd) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1574.001 | [Winnti Pipemon Characteristics](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A73d70463-75c9-4258-92c6-17500fe972f2) | Sigma | SigmaHQ |
| T1574.001 | [Winnti Pipemon Characteristics](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A73d70463-75c9-4258-92c6-17500fe972f2) | Sigma | OpenSearch Security Analytics |
| T1583.001 | [AWS Route 53 Private Hosted Zone Associated With a VPC](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ae3c27562-709a-42bd-82f2-3ed926cced19) | Elastic | Elastic detection-rules |
| T1583.001 | [AWS SES Email Identity Verified Then Deleted](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A8e4bde35-125d-4eb3-9a2e-d7e77a053a08) | Elastic | Elastic detection-rules |
| T1583.006 | [GitHub Repo Created](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A6cea88e4-6ce2-4238-9981-a54c140d6336) | Elastic | Elastic detection-rules |
| T1583.006 | [Cisco Secure Firewall - Rare Snort Rule Triggered](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=splunk-security-content%3A%3Ae20313d2-7d63-4fcf-b2d9-d6e12c6c7bd7) | Splunk | Splunk security_content |
| T1588.001 | [Relevant ClamAV Message](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A36aa86ca-fd9d-4456-814e-d3b1b8e1e0bb) | Sigma | SigmaHQ |
| T1588.001 | [Relevant ClamAV Message](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A36aa86ca-fd9d-4456-814e-d3b1b8e1e0bb) | Sigma | OpenSearch Security Analytics |
| T1588.002 | [Hacktool Execution - Imphash](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A24e3e58a-646b-4b50-adef-02ef935b9fc8) | Sigma | SigmaHQ |
| T1588.002 | [Renamed SysInternals DebugView Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acd764533-2e07-40d6-a718-cfeec7f2da7f) | Sigma | SigmaHQ |
| T1684.001 | [Entra ID OAuth user_impersonation Scope for Unusual User and Client](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A9563dace-5822-11f0-b1d3-f661ea17fbcd) | Elastic | Elastic detection-rules |
| T1685 | [Windows Defender Configuration Changes](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A801bd44f-ceed-4eb6-887c-11544633c0aa) | Sigma | SigmaHQ |
| T1685 | [Windows Defender Virus Scanning Feature Disabled](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A686c0b4b-9dd3-4847-9077-d6c1bbe36fcb) | Sigma | SigmaHQ |

## 8. Plano de emulação e validação

Use num laboratório isolado e autorizado para confirmar que as regras disparam. Os comandos estão nos repositórios oficiais.

| Tática | Técnica | Teste Atomic Red Team | Plataformas |
|---|---|---|---|
| Initial Access | [T1566.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1566.001/T1566.001.md) | Download Macro-Enabled Phishing Attachment | windows |
| Initial Access | [T1566.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1566.001/T1566.001.md) | Word spawned a command shell and used an IP address in the command line | windows |
| Initial Access | [T1566.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1566.002/T1566.002.md) | Paste and run technique | windows |
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
| Execution | [T1059.007](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.007/T1059.007.md) | JScript execution to gather local computer information via cscript | windows |
| Execution | [T1059.007](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.007/T1059.007.md) | JScript execution to gather local computer information via wscript | windows |
| Execution | [T1204.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1204.002/T1204.002.md) | OSTap Style Macro Execution | windows |
| Execution | [T1204.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1204.002/T1204.002.md) | OSTap Payload Download | windows |
| Execution | [T1559.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1559.002/T1559.002.md) | Execute Commands | windows |
| Execution | [T1559.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1559.002/T1559.002.md) | Execute PowerShell script via Word DDE | windows |
| Persistence | [T1137.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1137.001/T1137.001.md) | Injecting a Macro into the Word Normal.dotm Template for Persistence via PowerShell | windows |
| Persistence | [T1547.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1547.001/T1547.001.md) | Reg Key Run | windows |
| Persistence | [T1547.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1547.001/T1547.001.md) | Reg Key RunOnce | windows |
| Privilege Escalation | [T1548.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1548.002/T1548.002.md) | Bypass UAC using Event Viewer (cmd) | windows |
| Privilege Escalation | [T1548.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1548.002/T1548.002.md) | Bypass UAC using Event Viewer (PowerShell) | windows |
| Stealth | [T1027.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027.004/T1027.004.md) | Compile After Delivery using csc.exe | windows |
| Stealth | [T1027.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027.004/T1027.004.md) | Dynamic C# Compile | windows |
| Stealth | [T1036.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.005/T1036.005.md) | Execute a process from a directory masquerading as the current parent directory | linux, macos |
| Stealth | [T1036.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.005/T1036.005.md) | Masquerade as a built-in system executable | windows |
| Stealth | [T1140](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1140/T1140.md) | Deobfuscate/Decode Files Or Information | windows |
| Stealth | [T1140](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1140/T1140.md) | Certutil Rename and Decode | windows |
| Stealth | [T1218.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.003/T1218.003.md) | CMSTP Executing Remote Scriptlet | windows |
| Stealth | [T1218.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.003/T1218.003.md) | CMSTP Executing UAC Bypass | windows |
| Stealth | [T1218.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.005/T1218.005.md) | Mshta executes JavaScript Scheme Fetch Remote Payload With GetObject | windows |
| Stealth | [T1218.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.005/T1218.005.md) | Mshta executes VBScript to execute malicious command | windows |
| Stealth | [T1218.011](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.011/T1218.011.md) | Rundll32 execute JavaScript Remote Payload With GetObject | windows |
| Stealth | [T1218.011](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.011/T1218.011.md) | Rundll32 execute VBscript command | windows |
| Stealth | [T1574.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1574.001/T1574.001.md) | DLL Search Order Hijacking - amsi.dll | windows |
| Stealth | [T1574.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1574.001/T1574.001.md) | Phantom Dll Hijacking - WinAppXRT.dll | windows |
| Defense Impairment | [T1685](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1685/T1685.md) | Windows Disable LSA Protection | windows |
| Defense Impairment | [T1685](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1685/T1685.md) | Disable journal logging via systemctl utility | linux |
| Credential Access | [T1003.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/T1003.001.md) | Dump LSASS.exe Memory using ProcDump | windows |
| Credential Access | [T1003.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/T1003.001.md) | Dump LSASS.exe Memory using comsvcs.dll | windows |
| Credential Access | [T1003.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.004/T1003.004.md) | Dumping LSA Secrets | windows |
| Credential Access | [T1003.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.004/T1003.004.md) | Dump Kerberos Tickets from LSA using dumper.ps1 | windows |
| Credential Access | [T1003.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.005/T1003.005.md) | Cached Credential Dump via Cmdkey | windows |
| Credential Access | [T1552.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1552.001/T1552.001.md) | Find AWS credentials | linux, macos |
| Credential Access | [T1552.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1552.001/T1552.001.md) | Extract Browser and System credentials with LaZagne | macos |
| Credential Access | [T1555](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1555/T1555.md) | Extract Windows Credential Manager via VBA | windows |
| Credential Access | [T1555](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1555/T1555.md) | Dump credentials from Windows Credential Manager With PowerShell [windows Credentials] | windows |
| Credential Access | [T1555.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1555.003/T1555.003.md) | Run Chrome-password Collector | windows |
| Credential Access | [T1555.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1555.003/T1555.003.md) | Search macOS Safari Cookies | macos |
| Discovery | [T1016](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1016/T1016.md) | System Network Configuration Discovery on Windows | windows |
| Discovery | [T1016](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1016/T1016.md) | List Windows Firewall Rules | windows |
| Discovery | [T1033](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1033/T1033.md) | System Owner/User Discovery | windows |
| Discovery | [T1033](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1033/T1033.md) | System Owner/User Discovery | linux, macos |
| Discovery | [T1049](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1049/T1049.md) | System Network Connections Discovery | windows |
| Discovery | [T1049](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1049/T1049.md) | System Network Connections Discovery with PowerShell | windows |
| Discovery | [T1057](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1057/T1057.md) | Process Discovery - ps | linux, macos |
| Discovery | [T1057](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1057/T1057.md) | Process Discovery - tasklist | windows |
| Discovery | [T1082](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1082/T1082.md) | System Information Discovery | windows |
| Discovery | [T1082](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1082/T1082.md) | System Information Discovery | macos |
| Discovery | [T1083](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1083/T1083.md) | File and Directory Discovery (cmd.exe) | windows |
| Discovery | [T1083](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1083/T1083.md) | File and Directory Discovery (PowerShell) | windows |
| Discovery | [T1087.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1087.002/T1087.002.md) | Enumerate all accounts (Domain) | windows |
| Discovery | [T1087.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1087.002/T1087.002.md) | Enumerate all accounts via PowerShell (Domain) | windows |
| Discovery | [T1518](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1518/T1518.md) | Find and Display Internet Explorer Browser Version | windows |
| Discovery | [T1518](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1518/T1518.md) | Applications Installed | windows |
| Discovery | [T1518.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1518.001/T1518.001.md) | Security Software Discovery | windows |
| Discovery | [T1518.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1518.001/T1518.001.md) | Security Software Discovery - powershell | windows |
| Collection | [T1074.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1074.001/T1074.001.md) | Stage data from Discovery.bat | windows |
| Collection | [T1074.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1074.001/T1074.001.md) | Stage data from Discovery.sh | linux, macos |
| Collection | [T1113](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1113/T1113.md) | Screencapture | macos |
| Collection | [T1113](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1113/T1113.md) | Screencapture (silent) | macos |
| Collection | [T1560.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1560.001/T1560.001.md) | Compress Data for Exfiltration With Rar | windows |
| Collection | [T1560.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1560.001/T1560.001.md) | Compress Data and lock with password for Exfiltration with winrar | windows |
| Command and Control | [T1071.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1071.001/T1071.001.md) | Malicious User Agents - Powershell | windows |
| Command and Control | [T1071.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1071.001/T1071.001.md) | Malicious User Agents - CMD | windows |
| Command and Control | [T1105](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1105/T1105.md) | rsync remote file copy (push) | linux, macos |
| Command and Control | [T1105](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1105/T1105.md) | rsync remote file copy (pull) | linux, macos |
| Command and Control | [T1132.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1132.001/T1132.001.md) | Base64 Encoded data. | linux, macos |
| Command and Control | [T1132.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1132.001/T1132.001.md) | Base64 Encoded data (freebsd) | linux |
| Command and Control | [T1571](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1571/T1571.md) | Testing usage of uncommonly used port with PowerShell | windows |
| Command and Control | [T1571](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1571/T1571.md) | Testing usage of uncommonly used port | linux, macos |
| Exfiltration | [T1041](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1041/T1041.md) | C2 Data Exfiltration | windows |
| Exfiltration | [T1041](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1041/T1041.md) | Text Based Data Exfiltration using DNS subdomains | windows |
| Exfiltration | [T1567.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1567.002/T1567.002.md) | Exfiltrate data with rclone to cloud Storage - Mega (Windows) | windows |
| Exfiltration | [T1567.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1567.002/T1567.002.md) | Exfiltrate data with rclone to cloud Storage - AWS S3 | linux, macos |

**Logs reais de ataque (EVTX) para testar sem executar nada:**

- T1003.001 — [CA_hashdump_4663_4656_lsass_access](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Credential%20Access/CA_hashdump_4663_4656_lsass_access.evtx) _(inferido)_
- T1003.001 — [LsassSilentProcessExit_process_exit_monitor_3001_lsass](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Credential%20Access/LsassSilentProcessExit_process_exit_monitor_3001_lsass.evtx) _(inferido)_
- T1016 — [ID4688-Audit policy enumerated](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1016-System%20Network%20Configuration%20Discovery/ID4688-Audit%20policy%20enumerated.evtx) _(explícito)_
- T1016 — [ID4688-Firewall configuration enumerated (command)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1016-System%20Network%20Configuration%20Discovery/ID4688-Firewall%20configuration%20enumerated%20%28command%29.evtx) _(explícito)_
- T1047 — [ID1-WMI spwaning PowerShell process - WMImplant](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1047-Windows%20Management%20Instrumentation/ID1-WMI%20spwaning%20PowerShell%20process%20-%20WMImplant.evtx) _(explícito)_
- T1047 — [ID1-WMIexec process execution](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1047-Windows%20Management%20Instrumentation/ID1-WMIexec%20process%20execution.evtx) _(explícito)_
- T1053.005 — [ID4688-4698 Persistent scheduled task with SYSTEM privileges creation](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1053.005-Scheduled%20Task/ID4688-4698%20Persistent%20scheduled%20task%20with%20SYSTEM%20privileges%20creation.evtx) _(explícito)_
- T1053.005 — [ID4688-Interactive shell using AT schedule task](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1053.005-Scheduled%20Task/ID4688-Interactive%20shell%20using%20AT%20schedule%20task.evtx) _(explícito)_
- T1059.001 — [ID4103-4104-Payload download via PowerShell](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1059.001-PowerShell/ID4103-4104-Payload%20download%20via%20PowerShell.evtx) _(explícito)_
- T1059.001 — [ID4688-Encoded PowerShell MSF payload via process execution](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1059.001-PowerShell/ID4688-Encoded%20PowerShell%20MSF%20payload%20via%20process%20execution.evtx) _(explícito)_
- T1059.003 — [ID4688-SQL Server payload injectection for reverse shell (MSF)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1059.003-Windows%20Command%20Shell/ID4688-SQL%20Server%20payload%20injectection%20for%20reverse%20shell%20%28MSF%29.evtx) _(explícito)_
- T1087.002 — [discovery_bloodhound](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Discovery/discovery_bloodhound.evtx) _(inferido)_
- T1090 — [ID5600-proxy configuration changed](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0011-Command%20and%20Control/T1090-Proxy/ID5600-proxy%20configuration%20changed.evtx) _(explícito)_
- T1140 — [ID4688-Certutil download](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0005-Defense%20Evasion/T1140-Deobfuscate-Decode%20Files%20or%20Information/ID4688-Certutil%20download.evtx) _(explícito)_
- T1210 — [Zerologon_CVE-2020-1472_DFIR_System_NetLogon_Error_EventID_5805](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Credential%20Access/Zerologon_CVE-2020-1472_DFIR_System_NetLogon_Error_EventID_5805.evtx) _(inferido)_
- T1210 — [Zerologon_VoidSec_CVE-2020-1472_4626_LT3_Anonym_follwedby_4742_DC_Anony_DC](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Credential%20Access/Zerologon_VoidSec_CVE-2020-1472_4626_LT3_Anonym_follwedby_4742_DC_Anony_DC.evtx) _(inferido)_
- T1218.005 — [exec_persist_rundll32_mshta_scheduledtask_sysmon_1_3_11](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Execution/exec_persist_rundll32_mshta_scheduledtask_sysmon_1_3_11.evtx) _(inferido)_
- T1218.005 — [sysmon_mshta_sharpshooter_stageless_meterpreter](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Execution/sysmon_mshta_sharpshooter_stageless_meterpreter.evtx) _(inferido)_
- T1218.011 — [rundll32_cmd_schtask](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/AutomatedTestingTools/Malware/rundll32_cmd_schtask.evtx) _(inferido)_
- T1218.011 — [rundll32_hollowing_wermgr_masquerading](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/AutomatedTestingTools/Malware/rundll32_hollowing_wermgr_masquerading.evtx) _(inferido)_
- T1547.001 — [sideloading_injection_persistence_run_key](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/AutomatedTestingTools/Malware/sideloading_injection_persistence_run_key.evtx) _(inferido)_
- T1547.001 — [evasion_persis_hidden_run_keyvalue_sysmon_13](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Persistence/evasion_persis_hidden_run_keyvalue_sysmon_13.evtx) _(inferido)_
- T1548.002 — [sideloading_uacbypass_rundll32_injection_c2](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/AutomatedTestingTools/Malware/sideloading_uacbypass_rundll32_injection_c2.evtx) _(inferido)_
- T1548.002 — [Invoke_TokenDuplication_UAC_Bypass4624](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Privilege%20Escalation/Invoke_TokenDuplication_UAC_Bypass4624.evtx) _(inferido)_
- T1555 — [ID4662-Sensitve DPAPI attributes accessed](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0006-Credential%20Access/T1555-Credentials%20from%20Password%20Stores/ID4662-Sensitve%20DPAPI%20attributes%20accessed.evtx) _(explícito)_

## 9. Hipóteses de hunting

Se MuddyWater estiver no seu ambiente, estas são as perguntas a fazer aos seus dados (fontes de log segundo as estratégias de detecção do MITRE ATT&CK).

1. **T1137.001 Office Template Macros** — Adversaries inject VBA macros into Office templates such as Normal.dotm or Personal.xlsb or redirect Office template load path via registry key (GlobalDotName) to gain persistence. Template macros trigger execution of malicious code on application startup. Dados: `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Sysmon` (EventCode=15), `WinEventLog:Sysmon` (EventCode=1).
2. **T1218.003 CMSTP** — Execution of CMSTP.exe with arguments pointing to suspicious or remote INF/SCT/DLL payloads, optionally followed by outbound network connections to untrusted IPs, process injection via COM interfaces (CMSTPLUA, CMLUAUTIL), registry modifications registering… Dados: `WinEventLog:PowerShell` (EventCode=4103, 4104, 4105, 4106), `WinEventLog:Sysmon` (EventCode=3, 22), `WinEventLog:Sysmon` (EventCode=1).
3. **T1204.004 Malicious Copy and Paste** — A user is socially engineered (web page, email, document) to open Run/PowerShell/CMD and paste an obfuscated one-liner. The chain is: (1) user context active in a browser/email/office app → (2) process creation of a command interpreter with suspicious… Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:PowerShell` (EventCode=4103, 4104, 4105, 4106), `WinEventLog:Sysmon` (EventCode=11).
4. **T1003.005 Cached Domain Credentials** — Detects adversary behavior accessing Windows cached domain credential files using tools like Mimikatz, reg.exe, or PowerShell, often combined with registry exports or LSASS memory scraping. Dados: `WinEventLog:Security` (EventCode=4663, 4670, 4656), `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=10).
5. **T1027.004 Compile After Delivery** — Detects compilation activity using csc.exe, ilasm.exe, or msbuild.exe initiated by user-space processes outside typical development environments, followed by execution or network activity from newly written binaries. Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Sysmon` (EventCode=3, 22).
6. **T1104 Multi-Stage Channels** — Initial process initiates outbound connection to first-stage C2, receives payloads or commands, then spawns or injects into a second process that establishes a new outbound connection to an unrelated destination (second-stage C2). Dados: `WinEventLog:Sysmon` (EventCode=3, 22), `WinEventLog:Sysmon` (EventCode=1).
7. **T1559.001 Component Object Model** — Detects anomalous use of COM objects for execution, such as Office applications spawning scripting engines, enumeration of COM interfaces via registry queries, or processes loading atypical DLLs through COM activation. Correlates process creation, module… Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=7), `WinEventLog:Security` (EventCode=4663, 4670, 4656).
8. **T1534 Internal Spearphishing** — Sequence of internal email sent from a recently compromised user account (preceded by abnormal logon or device activity), with attachments or links leading to execution or credential harvesting. Defender observes: internal mail delivery to peers with high… Dados: `WinEventLog:Security` (EventCode=4624, 4648), `WinEventLog:Security` (EventCode=4625), `WinEventLog:Security` (EventCode=4672).
9. **T1566 Phishing** — Unusual inbound email activity where attachments or embedded URLs are delivered to users followed by execution of new processes or suspicious document behavior. Detection involves correlating email metadata, file creation, and network activity after a… Dados: `m365:unified` (Send/Receive: Emails with suspicious sender domains, spoofed headers, or anomalous attachment types), `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Sysmon` (EventCode=1).
10. **T1003.004 LSA Secrets** — Detects adversary activity aimed at accessing LSA Secrets, including registry key export of HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets or memory scraping via tools such as Mimikatz or PowerSploit's Invoke-Mimikatz. Dados: `WinEventLog:Security` (EventCode=4663, 4670, 4656), `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=10).
11. **T1027.003 Steganography** — Detects execution of image viewers or PowerShell scripts accessing or decoding files with mismatched MIME headers or embedded script-like byte patterns; often correlated with suspicious parent-child process lineage and outbound connections. Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=3, 22), `WinEventLog:Security` (EventCode=4663, 4670, 4656).
12. **T1090.002 External Proxy** — Unusual process (e.g., `rundll32`, `mshta`, `wscript`, or custom payloads) initiates network connection to external IPs/domains that proxy C2 traffic, often over uncommon ports or high entropy HTTP/S connections. Dados: `WinEventLog:Sysmon` (EventCode=3, 22), `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Microsoft-Windows-Windows Defender/Operational` (Unusual external domain access).

## 10. OSINT — onde pesquisar

Consultas prontas com todos os nomes conhecidos do grupo:

- Relatórios técnicos: [busca web](https://duckduckgo.com/?q=%28%22MuddyWater%22+OR+%22Earth+Vetala%22+OR+%22MERCURY%22+OR+%22Static+Kitten%22+OR+%22Seedworm%22+OR+%22TEMP.Zagros%22%29+threat+report) · [PDFs](https://duckduckgo.com/?q=%28%22MuddyWater%22+OR+%22Earth+Vetala%22+OR+%22MERCURY%22+OR+%22Static+Kitten%22+OR+%22Seedworm%22+OR+%22TEMP.Zagros%22%29+filetype%3Apdf)
- Regras e IOCs publicados: [GitHub](https://github.com/search?type=code&q=%22MuddyWater%22+OR+%22Earth+Vetala%22+OR+%22MERCURY%22+OR+%22Static+Kitten%22+OR+%22Seedworm%22+OR+%22TEMP.Zagros%22)
- Pulsos de ameaça: [AlienVault OTX](https://otx.alienvault.com/browse/global/pulses?q=MuddyWater)
- Família de malware e atores: [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/actors) (busque por MuddyWater, Earth Vetala, MERCURY)
- Cartões de grupo: [ThaiCERT Threat Group Cards](https://apt.etda.or.th/cgi-bin/listgroups.cgi)
- Página oficial: [MITRE ATT&CK G0069](https://attack.mitre.org/groups/G0069/)

**Relatórios na coleção CyberMonitor** (ligados pelo nome do grupo, conferir antes de citar):

- 2017 — [muddywater-apt-targeting-middle-east](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2017/2017.11.22.MuddyWater_APT/muddywater-apt-targeting-middle-east.pdf) _(via “MuddyWater”)_
- 2018 — [MuddyWater's Recent Activity](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2018/2018.03.01.a-quick-dip-into-muddywaters-recent/MuddyWater%27s%20Recent%20Activity.pdf) _(via “MuddyWater”)_
- 2018 — [MuddyWater_Middle_East_and_Central_Asia](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2018/2018.03.12.MuddyWater_Middle_East_and_Central_Asia/MuddyWater_Middle_East_and_Central_Asia.pdf) _(via “MuddyWater”)_
- 2018 — [another-potential-muddywater-campaign-uses-powershell-based-prb-backdoor](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2018/2018.06.14.another-potential-muddywater-campaign/another-potential-muddywater-campaign-uses-powershell-based-prb-backdoor.pdf) _(via “MuddyWater”)_
- 2018 — [MuddyWater expands operations](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2018/2018.10.10.MuddyWater_expands/MuddyWater%20expands%20operations.pdf) _(via “MuddyWater”)_
- 2018 — [MuddyWater-Operations-in-Lebanon-and-Oman](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2018/2018.11.28.MuddyWater-Operations-in-Lebanon-and-Oman/MuddyWater-Operations-in-Lebanon-and-Oman.pdf) _(via “MuddyWater”)_
- 2018 — [PowerShell-based Backdoor Found in Turkey Strikingly Similar to MuddyWater Tools](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2018/2018.11.30.MuddyWater_Turkey/PowerShell-based%20Backdoor%20Found%20in%20Turkey%20Strikingly%20Similar%20to%20MuddyWater%20Tools.pdf) _(via “MuddyWater”)_
- 2019 — [blog_new_muddywater_findings_uncovered](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2019/2019.06.10.MuddyWater_Resurfaces/blog_new_muddywater_findings_uncovered.pdf) _(via “MuddyWater”)_
- 2019 — [wp_new_muddywater_findings_uncovered](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2019/2019.06.10.MuddyWater_Resurfaces/wp_new_muddywater_findings_uncovered.pdf) _(via “MuddyWater”)_
- 2020 — [Reviving MuddyC3 Used by MuddyWater (IRAN) APT](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2020/2020.01.13.muddyc3.Revived/Reviving%20MuddyC3%20Used%20by%20MuddyWater%20%28IRAN%29%20APT.pdf) _(via “MuddyWater”)_
- 2021 — [MuddyWater Binder Project Part 1](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2021/2021.05.01.MuddyWater_Binder_1/MuddyWater%20Binder%20Project%20Part%201.pdf) _(via “MuddyWater”)_
- 2021 — [MuddyWater Binder Project Part 2](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2021/2021.05.07.MuddyWater_Binder_2/MuddyWater%20Binder%20Project%20Part%202.pdf) _(via “MuddyWater”)_
- 2022 — [Cisco Talos Intelligence Group - Comprehensive Threat Intelligence_ Iranian APT MuddyWater targets Turkish users via mal](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2022/2022.01.31.MuddyWater_Turkish/Cisco%20Talos%20Intelligence%20Group%20-%20Comprehensive%20Threat%20Intelligence_%20Iranian%20APT%20MuddyWater%20targets%20Turkish%20users%20via%20malicious%20PDFs%2C%20executables.pdf) _(via “MuddyWater”)_
- 2023 — [Seedworm_ Iranian Hackers Target Telecoms Orgs in North and East Africa _ Symantec Enterprise Blogs](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2023/2023.12.19.Seedworm/Seedworm_%20Iranian%20Hackers%20Target%20Telecoms%20Orgs%20in%20North%20and%20East%20Africa%20_%20Symantec%20Enterprise%20Blogs.pdf) _(via “Seedworm”)_
- 2024 — [new-bugsleep-backdoor-deployed-in-recent-muddywater-campaigns](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2024/2024.07.15.New_BugSleep_Backdoor_Deployed_in_Recent_MuddyWater_Campaigns/new-bugsleep-backdoor-deployed-in-recent-muddywater-campaigns.pdf) _(via “MuddyWater”)_

## 11. Bibliografia (30 fontes citadas pelo ATT&CK)

- [Anomali Static Kitten February 2021](https://www.anomali.com/blog/probable-iranian-cyber-actors-static-kitten-conducting-cyberespionage-campaign-targeting-uae-and-kuwait-government-agencies) — Mele, G. et al. (2021, February 10). Probable Iranian Cyber Actors, Static Kitten, Conducting Cyberespionage Campaign Targeting UAE and Kuwait Government Agencies. Retrieved March 17, 2021.
- [Checkpoint_MOISCyberCrime_Mar2026](https://research.checkpoint.com/2026/iranian-mois-actors-the-cyber-crime-connection/) — CheckPoint Research. (2026, March 10). Iranian MOIS Actors & the Cyber Crime Connection. Retrieved March 12, 2026.
- [ClearSky MuddyWater June 2019](https://www.clearskysec.com/wp-content/uploads/2019/06/Clearsky-Iranian-APT-group-%E2%80%98MuddyWater%E2%80%99-Adds-Exploits-to-Their-Arsenal.pdf) — ClearSky. (2019, June). Iranian APT group ‘MuddyWater’ Adds Exploits to Their Arsenal. Retrieved May 14, 2020.
- [ClearSky MuddyWater Nov 2018](https://www.clearskysec.com/wp-content/uploads/2018/11/MuddyWater-Operations-in-Lebanon-and-Oman.pdf) — ClearSky Cyber Security. (2018, November). MuddyWater Operations in Lebanon and Oman: Using an Israeli compromised domain for a two-stage campaign. Retrieved November 29, 2018.
- [Cloudflare 2026 Threat Report New Threat Actors March 2026](https://blog.cloudflare.com/2026-threat-report/) — Cloudflare. (2026, March 3). Introducing the 2026 Cloudflare Threat Report. Retrieved April 18, 2026.
- [CloudSEK_RustyWater_Jan2026](https://www.cloudsek.com/blog/reborn-in-rust-muddywater-evolves-tooling-with-rustywater-implant) — Awasthi, P. (2026, January 8). Reborn in Rust: Muddy Water Evolves Tooling with RustyWater Implant. Retrieved March 19, 2026.
- [CYBERCOM Iranian Intel Cyber January 2022](https://www.cybercom.mil/Media/News/Article/2897570/iranian-intel-cyber-suite-of-malware-uses-open-source-tools/) — Cyber National Mission Force. (2022, January 12). Iranian intel cyber suite of malware uses open source tools. Retrieved September 30, 2022.
- [DHS CISA AA22-055A MuddyWater February 2022](https://www.cisa.gov/uscert/ncas/alerts/aa22-055a) — FBI, CISA, CNMF, NCSC-UK. (2022, February 24). Iranian Government-Sponsored Actors Conduct Cyber Operations Against Global Government and Commercial Networks. Retrieved September 27, 2022.
- [ESET_MuddyWater_Dec2025](https://www.welivesecurity.com/en/eset-research/muddywater-snakes-riverbank/) — ESET Research. (2025, December 2). MuddyWater: Snakes by the riverbank. Retrieved February 17, 2026.
- [FalconFeeds_Iran_Mar2026](https://falconfeeds.io/blogs/the-digital-redoubt-irans-national-information-network-cyber-conflict) — FalconFeeds.io. (2026, March 5). The Digital Redoubt: Iran’s National Information Network and the Asymmetry of Modern Cyber Conflict. Retrieved March 9, 2026.
- [FalconFeeds_MuddyWaterPSRust_Mar2026](https://falconfeeds.io/blogs/muddywater-in-the-iran-israel-cyber-war-from-powershell-scripts-to-rust-implants) — FalconFeeds.io. (2026, March 6). MuddyWater in the Iran–Israel Cyber War: From PowerShell Scripts to Rust Implants. Retrieved March 12, 2026.
- [FireEye MuddyWater Mar 2018](https://www.fireeye.com/blog/threat-research/2018/03/iranian-threat-group-updates-ttps-in-spear-phishing-campaign.html) — Singh, S. et al.. (2018, March 13). Iranian Threat Group Updates Tactics, Techniques and Procedures in Spear Phishing Campaign. Retrieved April 11, 2018.
- [GitHub Invoke-Obfuscation](https://github.com/danielbohannon/Invoke-Obfuscation) — Bohannon, D.. (2017, March 13). Invoke-Obfuscation - PowerShell Obfuscator. Retrieved June 18, 2017.
- [group-ib_muddywater_infra](https://www.group-ib.com/blog/muddywater-infrastructure/) — Rostovcev, N. (2023, April 18). SimpleHarm: Tracking MuddyWater’s infrastructure. Retrieved July 11, 2024.
- [Huntio_IranInfra_Mar2026](https://hunt.io/blog/iranian-apt-infrastructure-state-aligned-clusters) — Hunt.io. (2026, March 4). Iranian APT Infrastructure in Focus: Mapping State-Aligned Clusters During Geopolitical Escalation. Retrieved April 16, 2026.
- [Microsoft Threat Actor Naming July 2023](https://learn.microsoft.com/en-us/microsoft-365/security/intelligence/microsoft-threat-actor-naming?view=o365-worldwide) — Microsoft . (2023, July 12). How Microsoft names threat actors. Retrieved November 17, 2023.
- [MuddyWater TrendMicro June 2018](https://blog.trendmicro.com/trendlabs-security-intelligence/another-potential-muddywater-campaign-uses-powershell-based-prb-backdoor/) — Villanueva, M., Co, M. (2018, June 14). Another Potential MuddyWater Campaign uses Powershell-based PRB-Backdoor. Retrieved July 3, 2018.
- [NaumaanProofpoint_GlobalClickFix_April2025](https://www.proofpoint.com/us/blog/threat-insight/around-world-90-days-state-sponsored-actors-try-clickfix) — Naumaan, S., et al. (2025, April 17). Around the World in 90 Days: State-Sponsored Actors Try ClickFix . Retrieved January 21, 2026.
- [NCSC GCHQ Small Sieve Jan 2022](https://www.ncsc.gov.uk/files/NCSC-Malware-Analysis-Report-Small-Sieve.pdf) — NCSC GCHQ. (2022, January 27). Small Sieve Malware Analysis Report. Retrieved August 22, 2022.
- [Proofpoint TA450 Phishing March 2024](https://www.proofpoint.com/us/blog/threat-insight/security-brief-ta450-uses-embedded-links-pdf-attachments-latest-campaign) — Miller, J. et al. (2024, March 21). Security Brief: TA450 Uses Embedded Links in PDF Attachments in Latest Campaign. Retrieved March 27, 2024.
- [Reaqta MuddyWater November 2017](https://reaqta.com/2017/11/muddywater-apt-targeting-middle-east/) — Reaqta. (2017, November 22). A dive into MuddyWater APT targeting Middle-East. Retrieved May 18, 2020.
- [Securelist MuddyWater Oct 2018](https://securelist.com/muddywater/88059/) — Kaspersky Lab's Global Research & Analysis Team. (2018, October 10). MuddyWater expands operations. Retrieved November 2, 2018.
- [SOCRadar_MuddyWaterDindoor_Mar2026](https://socradar.io/blog/iran-muddywater-dindoor-malware-us-networks/) — SOCRadar. (2026, March 9). MuddyWater Uses Dindoor Malware Targeting U.S. Networks. Retrieved March 12, 2026.
- [Symantec MuddyWater Dec 2018](https://www.symantec.com/blogs/threat-intelligence/seedworm-espionage-group) — Symantec DeepSight Adversary Intelligence Team. (2018, December 10). Seedworm: Group Compromises Government Agencies, Oil & Gas, NGOs, Telecoms, and IT Firms. Retrieved December 14, 2018.
- [SymantecCarbonBlack_Seedworm_Mar2026](https://www.security.com/threat-intelligence/iran-cyber-threat-activity-us) — Threat Hunter Team. (2026, March 5). Seedworm: Iranian APT on Networks of U.S. Bank, Airport, Software Company. Retrieved March 5, 2026.
- [Talos MuddyWater Jan 2022](https://blog.talosintelligence.com/2022/01/iranian-apt-muddywater-targets-turkey.html) — Malhortra, A and Ventura, V. (2022, January 31). Iranian APT MuddyWater targets Turkish users via malicious PDFs, executables. Retrieved June 22, 2022.
- [Talos MuddyWater May 2019](https://blog.talosintelligence.com/2019/05/recent-muddywater-associated-blackwater.html) — Adamitis, D. et al. (2019, May 20). Recent MuddyWater-associated BlackWater campaign shows signs of new anti-detection techniques. Retrieved June 5, 2019.
- [Trend Micro Muddy Water March 2021](https://www.trendmicro.com/en_us/research/21/c/earth-vetala---muddywater-continues-to-target-organizations-in-t.html) — Peretz, A. and Theck, E. (2021, March 5). Earth Vetala – MuddyWater Continues to Target Organizations in the Middle East. Retrieved March 18, 2021.
- [TrendMicro POWERSTATS V3 June 2019](https://blog.trendmicro.com/trendlabs-security-intelligence/muddywater-resurfaces-uses-multi-stage-backdoor-powerstats-v3-and-new-post-exploitation-tools/) — Lunghi, D. and Horejsi, J.. (2019, June 10). MuddyWater Resurfaces, Uses Multi-Stage Backdoor POWERSTATS V3 and New Post-Exploitation Tools. Retrieved May 14, 2020.
- [Unit 42 MuddyWater Nov 2017](https://researchcenter.paloaltonetworks.com/2017/11/unit42-muddying-the-water-targeted-attacks-in-the-middle-east/) — Lancaster, T.. (2017, November 14). Muddying the Water: Targeted Attacks in the Middle East. Retrieved March 15, 2018.

## 12. Limites e confiança

- O ATT&CK registra o que foi **relatado publicamente**, não tudo o que o grupo faz. Ausência de uma técnica não prova que o grupo não a usa.
- **Sobreposição de TTP não é atribuição.** Muitas técnicas são compartilhadas entre grupos e com red teams. Use a assinatura comportamental como hipótese, junto com infraestrutura, malware e contexto.
- Cobertura de detecção refere-se ao catálogo público Detection Rules, não ao seu ambiente: confira se a telemetria necessária chega ao seu SIEM.
- Ligações marcadas como _inferidas_ (EVTX por palavra-chave, relatórios por nome) devem ser verificadas.

---
Fontes: MITRE ATT&CK® (uso livre com atribuição, © The MITRE Corporation), Atomic Red Team (Red Canary, MIT), EVTX-to-MITRE-Attack, EVTX-ATTACK-SAMPLES, APT & CyberCriminal Campaign Collections. Gerado por [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules).
