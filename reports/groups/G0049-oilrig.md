# OilRig (G0049) — Dossiê de inteligência

> **TLP:CLEAR** · gerado em 2026-10-25 a partir de fontes abertas · MITRE ATT&CK v20.0 · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0049) · [ATT&CK](https://attack.mitre.org/groups/G0049/)

**Também conhecido como:** COBALT GYPSY, IRN2, APT34, Helix Kitten, Evasive Serpens, Hazel Sandstorm, EUROPIUM, ITG13, Earth Simnavaz, Crambus, TA452  
**Registro no ATT&CK:** criado em 2017-12-14, atualizado em 2026-07-31 · referências de 2016 a 2024

## 1. Sumário executivo

- **76 técnicas** atribuídas publicamente, concentradas em **Discovery, Credential Access, Stealth**.
- **Arsenal:** 18 malware e 12 ferramentas (ex.: Helminth, POWRUNER, RDAT, OopsIE, QUADAGENT).
- **Campanhas atribuídas:** 2 (Outer Space, Juicy Mix).
- **Cobertura de detecção pública:** 100% das técnicas têm ao menos uma regra no catálogo; **0 técnicas sem nenhuma regra pública**.
- **Assinatura comportamental** (técnicas raras entre os 178 grupos, as mais úteis para atribuição): T1137.004 Outlook Home Page, T1195 Supply Chain Compromise, T1201 Password Policy Discovery, T1556.002 Password Filter DLL, T1003.005 Cached Domain Credentials.

## 2. Quem é

> OilRig is a suspected Iranian threat group that has targeted Middle Eastern and international victims since at least 2014. The group has targeted a variety of sectors, including financial, government, energy, chemical, and telecommunications. It appears the group carries out supply chain attacks, leveraging the trust relationship between organizations to attack their primary targets. The group works on behalf of the Iranian government based on infrastructure details that contain references to Iran, use of Iranian infrastructure, and targeting that aligns with nation-state interests.

_Texto original do MITRE ATT&CK, em inglês._

## 3. Perfil TTP por tática (kill chain)

Cada linha: técnica, como o grupo a usou segundo relatos públicos, e o que existe para detectar e testar.

### Resource Development (TA0042) — 6

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1583.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1583.001) Domains | OilRig has set up fake VPN portals, conference sign ups, and job application websites to target victims. | 7 | — | — |
| [T1586.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1586.002) Email Accounts | OilRig has compromised email accounts to send phishing emails. | 3 | — | — |
| [T1587.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1587.001) Malware | OilRig actively developed and used a series of downloaders during 2022. | 43 | — | — |
| [T1588.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1588.002) Tool | OilRig has made use of the publicly available tools including Plink and Mimikatz. | 35 | — | — |
| [T1588.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1588.003) Code Signing Certificates | OilRig has obtained stolen code signing certificates to digitally sign malware. | 1 | — | — |
| [T1608.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1608.001) Upload Malware | OilRig has hosted malware on fake websites designed to target specific audiences. | 3 | — | — |

### Initial Access (TA0001) — 7

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | OilRig has used compromised credentials to access other systems on a victim network. | 825 | — | 3 |
| [T1078.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.002) Domain Accounts | OilRig has used an exfiltration tool named STEALHOOK to retreive valid domain credentials. | 36 | — | 1 |
| [T1133](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1133) External Remote Services | OilRig uses remote services such as VPN, Citrix, or OWA to persist in an environment. | 361 | 1 | — |
| [T1195](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1195) Supply Chain Compromise | OilRig has leveraged compromised organizations to conduct supply chain attacks on government entities. | 83 | 1 | — |
| [T1566.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1566.001) Spearphishing Attachment | OilRig has sent spearphising emails with malicious attachments to potential victims using compromised and/or spoofed email accounts. | 230 | 2 | — |
| [T1566.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1566.002) Spearphishing Link | OilRig has sent spearphising emails with malicious links to potential victims. | 138 | 1 | — |
| [T1566.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1566.003) Spearphishing via Service | OilRig has used LinkedIn to send spearphishing links. | 8 | — | — |

### Execution (TA0002) — 9

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1047](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1047) Windows Management Instrumentation | OilRig has used WMI for execution. | 370 | 12 | 11 |
| [T1053.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1053.005) Scheduled Task | OilRig has created scheduled tasks that run a VBScript to execute a payload on victim machines. | 248 | 14 | 11 |
| [T1059](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059) Command and Scripting Interpreter | OilRig has used various types of scripting for execution. | 1467 | 1 | — |
| [T1059.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.001) PowerShell | OilRig has used PowerShell scripts for execution, including use of a macro to run a PowerShell command to decode file contents. | 1340 | 22 | 15 |
| [T1059.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.003) Windows Command Shell | OilRig has used macros to deliver malware such as QUADAGENT and OopsIE. OilRig has used batch scripts. | 269 | 6 | 1 |
| [T1059.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.005) Visual Basic | OilRig has used VBScript macros for execution on compromised hosts. | 192 | 3 | — |
| [T1203](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1203) Exploitation for Client Execution | OilRig has exploited CVE-2024-30088 to run arbitrary code in the context of `SYSTEM`. | 202 | — | — |
| [T1204.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1204.001) Malicious Link | OilRig has delivered malicious links to achieve execution on the target system. | 52 | — | — |
| [T1204.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1204.002) Malicious File | OilRig has delivered macro-enabled documents that required targets to click the "enable content" button to execute the payload on the system. | 259 | 13 | — |

### Persistence (TA0003) — 9

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1053.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1053.005) Scheduled Task | OilRig has created scheduled tasks that run a VBScript to execute a payload on victim machines. | 248 | 14 | 11 |
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | OilRig has used compromised credentials to access other systems on a victim network. | 825 | — | 3 |
| [T1078.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.002) Domain Accounts | OilRig has used an exfiltration tool named STEALHOOK to retreive valid domain credentials. | 36 | — | 1 |
| [T1112](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1112) Modify Registry | OilRig has used reg.exe to modify system configuration. | 601 | 92 | 3 |
| [T1133](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1133) External Remote Services | OilRig uses remote services such as VPN, Citrix, or OWA to persist in an environment. | 361 | 1 | — |
| [T1137.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1137.004) Outlook Home Page | OilRig has abused the Outlook Home Page feature for persistence. OilRig has also used CVE-2017-11774 to roll back the initial patch designed to protect against Home Page abuse. | 5 | 1 | — |
| [T1505.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1505.003) Web Shell | OilRig has used web shells, often to maintain access to a victim network. | 210 | 1 | — |
| [T1543.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1543.003) Windows Service | OilRig has used a compromised Domain Controller to create a service on a remote host. | 1916 | 6 | 19 |
| [T1556.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1556.002) Password Filter DLL | OilRig has registered a password filter DLL in order to drop malware. | 16 | 2 | — |

### Privilege Escalation (TA0004) — 5

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1053.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1053.005) Scheduled Task | OilRig has created scheduled tasks that run a VBScript to execute a payload on victim machines. | 248 | 14 | 11 |
| [T1068](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1068) Exploitation for Privilege Escalation | OilRig has exploited the Windows Kernel Elevation of Privilege vulnerability, CVE-2024-30088. | 408 | 2 | 2 |
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | OilRig has used compromised credentials to access other systems on a victim network. | 825 | — | 3 |
| [T1078.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.002) Domain Accounts | OilRig has used an exfiltration tool named STEALHOOK to retreive valid domain credentials. | 36 | — | 1 |
| [T1543.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1543.003) Windows Service | OilRig has used a compromised Domain Controller to create a service on a remote host. | 1916 | 6 | 19 |

### Stealth (TA0005) — 10

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1027.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1027.005) Indicator Removal from Tools | OilRig has tested malware samples to determine AV detection and subsequently modified the samples to ensure AV evasion. | 24 | — | — |
| [T1027.013](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1027.013) Encrypted/Encoded File | OilRig has encrypted and encoded data in its malware, including by using base64. | 8 | 4 | — |
| [T1036](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1036) Masquerading | OilRig has used .doc file extensions to mask malicious executables. | 453 | 2 | 1 |
| [T1036.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1036.005) Match Legitimate Resource Name or Location | OilRig has named a downloaded copy of the Plink tunneling utility as \ProgramData\Adobe.exe. | 116 | 4 | — |
| [T1070.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1070.004) File Deletion | OilRig has deleted files associated with their payload after execution. | 132 | 11 | — |
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | OilRig has used compromised credentials to access other systems on a victim network. | 825 | — | 3 |
| [T1078.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.002) Domain Accounts | OilRig has used an exfiltration tool named STEALHOOK to retreive valid domain credentials. | 36 | — | 1 |
| [T1140](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1140) Deobfuscate/Decode Files or Information | A OilRig macro has run a PowerShell command to decode file contents. OilRig has also used certutil to decode base64-encoded files on victims. | 173 | 11 | 1 |
| [T1218.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1218.001) Compiled HTML File | OilRig has used a CHM payload to load and execute another malicious file once delivered to a victim. | 28 | 8 | — |
| [T1497.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1497.001) System Checks | OilRig has used macros to verify if a mouse is connected to a compromised machine. | 16 | 9 | — |

### Defense Impairment (TA0112) — 4

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1112](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1112) Modify Registry | OilRig has used reg.exe to modify system configuration. | 601 | 92 | 3 |
| [T1553.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1553.002) Code Signing | OilRig has signed its malware with stolen certificates. | 11 | — | — |
| [T1556.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1556.002) Password Filter DLL | OilRig has registered a password filter DLL in order to drop malware. | 16 | 2 | — |
| [T1686.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1686.003) Windows Host Firewall | OilRig has modified Windows firewall rules to enable remote access. | 64 | 2 | — |

### Credential Access (TA0006) — 10

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1003.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1003.001) LSASS Memory | OilRig has used credential dumping tools such as Mimikatz to steal credentials to accounts logged into the compromised system and to Outlook Web Access. | 580 | 14 | 10 |
| [T1003.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1003.004) LSA Secrets | OilRig has used credential dumping tools such as LaZagne to steal credentials to accounts logged into the compromised system and to Outlook Web Access. | 72 | 2 | — |
| [T1003.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1003.005) Cached Domain Credentials | OilRig has used credential dumping tools such as LaZagne to steal credentials to accounts logged into the compromised system and to Outlook Web Access. | 32 | 1 | — |
| [T1056.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1056.001) Keylogging | OilRig has employed keyloggers including KEYPUNCH and LONGWATCH. | 40 | 8 | 1 |
| [T1110](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1110) Brute Force | OilRig has used brute force techniques to obtain credentials. | 381 | — | 12 |
| [T1552.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1552.001) Credentials In Files | OilRig has used credential dumping tools such as LaZagne to steal credentials to accounts logged into the compromised system and to Outlook Web Access. | 166 | 32 | — |
| [T1555](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1555) Credentials from Password Stores | OilRig has used credential dumping tools such as LaZagne to steal credentials to accounts logged into the compromised system and to Outlook Web Access. | 160 | 9 | 2 |
| [T1555.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1555.003) Credentials from Web Browsers | OilRig has used credential dumping tools such as LaZagne to steal credentials to accounts logged into the compromised system and to Outlook Web Access. OilRig has also used tool named PICKPOCKET to dump passwords from web browsers. | 59 | 18 | 5 |
| [T1555.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1555.004) Windows Credential Manager | OilRig has used credential dumping tool named VALUEVAULT to steal credentials from the Windows Credential Manager. | 37 | 2 | 1 |
| [T1556.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1556.002) Password Filter DLL | OilRig has registered a password filter DLL in order to drop malware. | 16 | 2 | — |

### Discovery (TA0007) — 15

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1007](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1007) System Service Discovery | OilRig has used sc query on a victim to gather information about services. | 37 | 8 | — |
| [T1012](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1012) Query Registry | OilRig has used reg query “HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client\Default” on a victim to query the Registry. | 92 | 6 | — |
| [T1016](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1016) System Network Configuration Discovery | OilRig has run ipconfig /all on a victim. | 99 | 10 | 5 |
| [T1033](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1033) System Owner/User Discovery | OilRig has run whoami on a victim. | 181 | 8 | — |
| [T1046](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1046) Network Service Discovery | OilRig has used the publicly available tool SoftPerfect Network Scanner as well as a custom tool called GOLDIRONY to conduct network scanning. | 212 | 13 | 2 |
| [T1049](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1049) System Network Connections Discovery | OilRig has used netstat -an on a victim to get a listing of network connections. | 47 | 7 | — |
| [T1057](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1057) Process Discovery | OilRig has run tasklist on a victim's machine and used infostealers to capture processes. | 82 | 10 | — |
| [T1069.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1069.001) Local Groups | OilRig has used net localgroup administrators to find local administrators on compromised systems. | 50 | 7 | — |
| [T1069.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1069.002) Domain Groups | OilRig has used net group /domain, net group “domain admins” /domain, and net group “Exchange Trusted Subsystem” /domain to find domain group permission settings. | 91 | 15 | — |
| [T1082](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1082) System Information Discovery | OilRig has run hostname and systeminfo on a victim. | 264 | 41 | — |
| [T1087.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1087.001) Local Account | OilRig has run net user, net user /domain, net group “domain admins” /domain, and net group “Exchange Trusted Subsystem” /domain to get account listings on a victim. | 98 | 11 | — |
| [T1087.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1087.002) Domain Account | OilRig has run net user, net user /domain, net group “domain admins” /domain, and net group “Exchange Trusted Subsystem” /domain to get account listings on a victim. | 180 | 25 | 1 |
| [T1120](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1120) Peripheral Device Discovery | OilRig has used tools to identify if a mouse is connected to a targeted system. | 11 | 4 | — |
| [T1201](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1201) Password Policy Discovery | OilRig has used net.exe in a script with net accounts /domain to find the password policy of a domain. | 43 | 12 | 2 |
| [T1497.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1497.001) System Checks | OilRig has used macros to verify if a mouse is connected to a compromised machine. | 16 | 9 | — |

### Lateral Movement (TA0008) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1021.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1021.001) Remote Desktop Protocol | OilRig has used Remote Desktop Protocol for lateral movement. The group has also used tunneling tools to tunnel RDP into the environment. | 139 | 4 | 7 |
| [T1021.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1021.004) SSH | OilRig has used Putty to access compromised systems. | 60 | 2 | 3 |

### Collection (TA0009) — 6

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1005) Data from Local System | OilRig has used PowerShell to upload files from compromised systems. | 170 | 3 | — |
| [T1025](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1025) Data from Removable Media | OilRig has used Wireshark’s usbcapcmd utility to capture USB traffic. | 4 | 1 | — |
| [T1056.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1056.001) Keylogging | OilRig has employed keyloggers including KEYPUNCH and LONGWATCH. | 40 | 8 | 1 |
| [T1113](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1113) Screen Capture | OilRig has a tool called CANDYKING to capture a screenshot of user's desktop. | 60 | 10 | — |
| [T1115](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1115) Clipboard Data | OilRig has used infostealer tools to copy clipboard data. | 33 | 5 | — |
| [T1119](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1119) Automated Collection | OilRig has used automated collection. | 72 | 4 | — |

### Command and Control (TA0011) — 7

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1008](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1008) Fallback Channels | OilRig malware ISMAgent falls back to its DNS tunneling mechanism if it is unable to reach the C2 server over HTTP. | 55 | — | — |
| [T1071.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1071.001) Web Protocols | OilRig has used HTTP for C2. | 228 | 3 | — |
| [T1071.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1071.004) DNS | OilRig has used DNS for C2 including the publicly available requestbin.net tunneling service. | 117 | 4 | — |
| [T1105](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1105) Ingress Tool Transfer | OilRig had downloaded remote files onto victim infrastructure. | 644 | 39 | — |
| [T1219](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1219) Remote Access Tools | OilRig has incorporated remote monitoring and management (RMM) tools into their operations including ngrok. | 119 | 15 | — |
| [T1572](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1572) Protocol Tunneling | OilRig has used the Plink utility and other tools to create tunnels to C2 servers. | 173 | 9 | 1 |
| [T1573.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1573.002) Asymmetric Cryptography | OilRig used the PowerExchange utility and other tools to create tunnels to C2 servers. | 14 | — | — |

### Exfiltration (TA0010) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1048.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1048.003) Exfiltration Over Unencrypted Non-C2 Protocol | OilRig has exfiltrated data via Microsoft Exchange and over FTP separately from its primary C2 channel over DNS. | 51 | 8 | — |

## 4. Assinatura comportamental

Técnicas que este grupo usa e que poucos dos 178 grupos do ATT&CK usam. Pesam mais numa atribuição por TTP: ver várias delas juntas é mais informativo do que ver técnicas comuns como PowerShell.

| Técnica | Outros grupos que usam | Peso (raridade) |
|---|---:|---:|
| T1137.004 Outlook Home Page | 0 | 4.49 |
| T1195 Supply Chain Compromise | 2 | 3.80 |
| T1201 Password Policy Discovery | 2 | 3.80 |
| T1556.002 Password Filter DLL | 2 | 3.80 |
| T1003.005 Cached Domain Credentials | 3 | 3.58 |
| T1025 Data from Removable Media | 3 | 3.58 |
| T1115 Clipboard Data | 3 | 3.58 |
| T1555.004 Windows Credential Manager | 3 | 3.58 |
| T1008 Fallback Channels | 4 | 3.40 |
| T1218.001 Compiled HTML File | 4 | 3.40 |

## 5. Arsenal

| Software | Tipo | Técnicas no ATT&CK | Uso relatado (EN) |
|---|---|---:|---|
| [Helminth](https://attack.mitre.org/software/S0170/) | malware | 21 |  |
| [POWRUNER](https://attack.mitre.org/software/S0184/) | malware | 20 |  |
| [RDAT](https://attack.mitre.org/software/S0495/) | malware | 20 |  |
| [OopsIE](https://attack.mitre.org/software/S0264/) | malware | 19 |  |
| [QUADAGENT](https://attack.mitre.org/software/S0269/) | malware | 17 |  |
| [Mimikatz](https://attack.mitre.org/software/S0002/) | ferramenta | 17 |  |
| [Net](https://attack.mitre.org/software/S0039/) | ferramenta | 16 |  |
| [OilBooster](https://attack.mitre.org/software/S1172/) | malware | 15 |  |
| [SideTwist](https://attack.mitre.org/software/S0610/) | malware | 15 |  |
| [Mango](https://attack.mitre.org/software/S1169/) | malware | 13 |  |
| [SampleCheck5000](https://attack.mitre.org/software/S1168/) | malware | 10 |  |
| [LaZagne](https://attack.mitre.org/software/S0349/) | ferramenta | 10 |  |
| [ODAgent](https://attack.mitre.org/software/S1170/) | malware | 9 |  |
| [ZeroCleare](https://attack.mitre.org/software/S1151/) | malware | 8 | OilRig collaborated on the destructive portion of the ZeroCleare attack. |
| [Solar](https://attack.mitre.org/software/S1166/) | malware | 8 |  |
| [RGDoor](https://attack.mitre.org/software/S0258/) | malware | 7 |  |
| [BONDUPDATER](https://attack.mitre.org/software/S0360/) | malware | 7 |  |
| [PowerExchange](https://attack.mitre.org/software/S1173/) | malware | 5 |  |
| [ngrok](https://attack.mitre.org/software/S0508/) | ferramenta | 5 |  |
| [PsExec](https://attack.mitre.org/software/S0029/) | ferramenta | 5 |  |
| [SEASHARPEE](https://attack.mitre.org/software/S0185/) | malware | 4 |  |
| [ISMInjector](https://attack.mitre.org/software/S0189/) | malware | 4 |  |
| [certutil](https://attack.mitre.org/software/S0160/) | ferramenta | 4 |  |
| [OilCheck](https://attack.mitre.org/software/S1171/) | malware | 3 |  |
| [Tasklist](https://attack.mitre.org/software/S0057/) | ferramenta | 3 |  |
| [Reg](https://attack.mitre.org/software/S0075/) | ferramenta | 3 |  |
| [ftp](https://attack.mitre.org/software/S0095/) | ferramenta | 3 |  |
| [ipconfig](https://attack.mitre.org/software/S0100/) | ferramenta | 1 |  |
| [netstat](https://attack.mitre.org/software/S0104/) | ferramenta | 1 |  |
| [Systeminfo](https://attack.mitre.org/software/S0096/) | ferramenta | 1 |  |

## 6. Campanhas

| Campanha | Período | Resumo (EN) |
|---|---|---|
| [Outer Space](https://attack.mitre.org/campaigns/C0042/) | 2021-01 → 2021-12 | Outer Space was a campaign conducted by OilRig throughout 2021 that used the SampleCheck5000 downloader and Solar backdoor to target Israeli organizations. |
| [Juicy Mix](https://attack.mitre.org/campaigns/C0044/) | 2022-01 → 2022-12 | Juicy Mix was a campaign conducted by OilRig throughout 2022 that targeted Israeli organizations with the Mango backdoor. |

## 7. Cobertura defensiva

**76 de 76 técnicas (100%)** têm ao menos uma regra pública no catálogo Detection Rules.

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
| T1005 | [Potential Conti Ransomware Database Dumping Activity Via SQLCmd](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A2f47f1fd-0901-466e-a770-3b7092834a1b) | Sigma | SigmaHQ |
| T1005 | [OpenCanary - SMB File Open Request](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A22777c9e-873a-4b49-855f-6072ab861a52) | Sigma | SigmaHQ |
| T1007 | [HackTool - PCHunter Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Afca949cc-79ca-446e-8064-01aa7e52ece5) | Sigma | SigmaHQ |
| T1007 | [SC.EXE Query Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A57712d7a-679c-4a41-a913-87e7175ae429) | Sigma | SigmaHQ |
| T1008 | [Suspicious Outlook Macro Created](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A117d3d3a-755c-4a61-b23e-9171146d094c) | Sigma | SigmaHQ |
| T1008 | [Outlook Macro Execution Without Warning Setting Enabled](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae3b50fa5-3c3f-444e-937b-0a99d33731cd) | Sigma | SigmaHQ |
| T1012 | [Potential Baby Shark Malware Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A2b30fa36-3a18-402f-a22d-bf4ce2189f35) | Sigma | SigmaHQ |
| T1012 | [Operation Wocao Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1cfac73c-be78-4f9a-9b08-5bde0c3953ab) | Sigma | SigmaHQ |
| T1016 | [Potential Pikabot Discovery Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A698d4431-514f-4c82-af4d-cf573872a9f5) | Sigma | SigmaHQ |
| T1016 | [OpenCanary - SNMP OID Request](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae9856028-fd4e-46e6-b3d1-10f7ceb95078) | Sigma | SigmaHQ |
| T1021.001 | [Hermetic Wiper TG Process Patterns](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A2f974656-6d83-4059-bbdf-68ac5403422f) | Sigma | SigmaHQ |
| T1021.001 | [Publicly Accessible RDP Service](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1fc0809e-06bf-4de3-ad52-25e5263b7623) | Sigma | SigmaHQ |
| T1021.004 | [Potential THC Tool Downloaded](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A2ddc468e-b39b-4f5b-9825-f3dcb0e998ea) | Elastic | Elastic detection-rules |
| T1021.004 | [AWS EC2 CreateKeyPair by New Principal from Non-Cloud AS Organization](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ac8e4f1a2-9b3d-4c5e-a6f7-8b9c0d1e2f3a) | Elastic | Elastic detection-rules |
| T1025 | [Windows Process Executed From Removable Media](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=splunk-security-content%3A%3Ab483804a-4cc0-49a4-9f00-ac29ba844d08) | Splunk | Splunk security_content |
| T1025 | [Windows WPDBusEnum Registry Key Modification](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=splunk-security-content%3A%3A52b48e8b-eb6e-48b0-b8f1-73273f6b134e) | Splunk | Splunk security_content |
| T1027.005 | [PUA - DefenderCheck Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Af0ca6c24-3225-47d5-b1f5-352bf07ecfa7) | Sigma | SigmaHQ |
| T1027.005 | [HackTool - CrackMapExec PowerShell Obfuscation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A6f8b3439-a203-45dc-a88b-abf57ea15ccf) | Sigma | SigmaHQ |
| T1027.013 | [ROT Encoded Python Script Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A5ab49127-b1b3-46e6-8a38-9e8512a2a363) | Elastic | Elastic detection-rules |
| T1027.013 | [Data Encrypted via OpenSSL Utility](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Afeba48f6-40ca-4d04-b41f-5dfa327de865) | Elastic | Elastic detection-rules |
| T1033 | [Potential Dridex Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae6eb5a96-9e6f-4a18-9cdd-642cfda21c8e) | Sigma | SigmaHQ |
| T1033 | [Dridex Process Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Ae6eb5a96-9e6f-4a18-9cdd-642cfda21c8e) | Sigma | OpenSearch Security Analytics |
| T1036 | [Potential LSASS Process Dump Via Procdump](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A5afee48e-67dd-4e03-a783-f74259dcf998) | Sigma | SigmaHQ |
| T1036 | [Suspicious Use of Procdump on LSASS](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A5afee48e-67dd-4e03-a783-f74259dcf998) | Sigma | OpenSearch Security Analytics |
| T1036.005 | [Exploit for CVE-2015-1641](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A7993792c-5ce2-4475-a3db-a3a5539827ef) | Sigma | SigmaHQ |
| T1036.005 | [Exploit for CVE-2015-1641](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A7993792c-5ce2-4475-a3db-a3a5539827ef) | Sigma | OpenSearch Security Analytics |
| T1046 | [HackTool - winPEAS Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A98b53e78-ebaf-46f8-be06-421aafd176d9) | Sigma | SigmaHQ |
| T1046 | [HackTool - WinPwn Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad557dc06-62e8-4468-a8e8-7984124908ce) | Sigma | SigmaHQ |
| T1047 | [HackTool - Potential Impacket Lateral Movement Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A10c14723-61c7-4c75-92ca-9af245723ad2) | Sigma | SigmaHQ |
| T1047 | [CrackMapExec Command Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A058f4380-962d-40a5-afce-50207d36d7e2) | Sigma | OpenSearch Security Analytics |
| T1048.003 | [Suspicious WebDav Client Execution Via Rundll32.EXE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A982e9f2d-1a85-4d5b-aea4-31f5e97c6555) | Sigma | SigmaHQ |
| T1048.003 | [Possible DNS Tunneling](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A1ec4b281-aa65-46a2-bdae-5fd830ed914e) | Sigma | OpenSearch Security Analytics |
| T1049 | [Potential Pikabot Discovery Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A698d4431-514f-4c82-af4d-cf573872a9f5) | Sigma | SigmaHQ |
| T1049 | [HackTool - SharpView Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab2317cfa-4a47-4ead-b3ff-297438c0bc2d) | Sigma | SigmaHQ |
| T1053.005 | [Operation Wocao Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1cfac73c-be78-4f9a-9b08-5bde0c3953ab) | Sigma | SigmaHQ |
| T1053.005 | [Operation Wocao Activity - Security](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A74ad4314-482e-4c3e-b237-3f7ed3b9ca8d) | Sigma | SigmaHQ |
| T1056.001 | [Linux Keylogging with Pam.d](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A49aae26c-450e-448b-911d-b3c13d178dfc) | Sigma | SigmaHQ |
| T1056.001 | [Linux Keylogging with Pam.d](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A49aae26c-450e-448b-911d-b3c13d178dfc) | Sigma | OpenSearch Security Analytics |
| T1057 | [Process Discovery](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4e2f5868-08d4-413d-899f-dc2f1508627b) | Sigma | SigmaHQ |
| T1057 | [HackTool - PCHunter Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Afca949cc-79ca-446e-8064-01aa7e52ece5) | Sigma | SigmaHQ |
| T1059 | [Windows Defender Threat Detected](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A57b649ef-ff42-4fb0-8bf6-62da243a1708) | Sigma | OpenSearch Security Analytics |
| T1059 | [Windows Defender AMSI Trigger Detected](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Aea9bf0fa-edec-4fb8-8b78-b119f2528186) | Sigma | OpenSearch Security Analytics |
| T1059.001 | [Potential Emotet Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad02e8cf5-6099-48cf-9bfc-1eec2d0c7b18) | Sigma | SigmaHQ |
| T1059.001 | [TropicTrooper Campaign November 2018](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A8c7090c3-e0a0-4944-bd08-08c3a0cecf79) | Sigma | SigmaHQ |
| T1059.003 | [HackTool - CrackMapExec Execution Patterns](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A058f4380-962d-40a5-afce-50207d36d7e2) | Sigma | SigmaHQ |
| T1059.003 | [CrackMapExec Command Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A058f4380-962d-40a5-afce-50207d36d7e2) | Sigma | OpenSearch Security Analytics |
| T1059.005 | [Potential QBot Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4fcac6eb-0287-4090-8eea-2602e4c20040) | Sigma | SigmaHQ |
| T1059.005 | [QBot Process Creation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A4fcac6eb-0287-4090-8eea-2602e4c20040) | Sigma | OpenSearch Security Analytics |
| T1068 | [Exploiting CVE-2019-1388](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A02e0b2ea-a597-428e-b04a-af6a1a403e5c) | Sigma | SigmaHQ |
| T1068 | [OMIGOD HTTP No Authentication RCE - CVE-2021-38647](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aab6b1a39-a9ee-4ab4-b075-e83acf6e346b) | Sigma | SigmaHQ |
| T1069.001 | [BloodHound Collection Files](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A02773bed-83bf-469f-b7ff-e676e7d78bab) | Sigma | SigmaHQ |
| T1069.001 | [HackTool - Bloodhound/Sharphound Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Af376c8a7-a2d0-4ddc-aa0c-16c17236d962) | Sigma | SigmaHQ |
| T1069.002 | [BloodHound Collection Files](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A02773bed-83bf-469f-b7ff-e676e7d78bab) | Sigma | SigmaHQ |
| T1069.002 | [HackTool - SharpView Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab2317cfa-4a47-4ead-b3ff-297438c0bc2d) | Sigma | SigmaHQ |
| T1070.004 | [File Deletion](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A30aed7b6-d2c1-4eaf-9382-b6bc43e50c57) | Sigma | SigmaHQ |
| T1070.004 | [Prefetch File Deleted](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A0a1f9d29-6465-4776-b091-7f43b26e4c89) | Sigma | SigmaHQ |
| T1071.001 | [Ursnif Malware Download URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aa36ce77e-30db-4ea0-8795-644d7af5dfb4) | Sigma | SigmaHQ |
| T1071.001 | [Ursnif Malware C2 URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A932ac737-33ca-4afd-9869-0d48b391fcc9) | Sigma | SigmaHQ |
| T1071.004 | [OilRig APT Registry Persistence](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A7bdf2a7c-3acc-4091-9581-0a77dad1c5b5) | Sigma | SigmaHQ |
| T1071.004 | [OilRig APT Schedule Task Persistence - Security](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac0580559-a6bd-4ef6-b9b7-83703d98b561) | Sigma | SigmaHQ |
| T1078 | [Privilege Role Sign-In Outside Expected Controls](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acf1e5687-84e1-41af-97a9-158094efef53) | Sigma | SigmaHQ |
| T1078 | [OpenCanary - SSH Login Attempt](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aff7139bc-fdb1-4437-92f2-6afefe8884cb) | Sigma | SigmaHQ |
| T1078.002 | [Malicious Usage Of IMDS Credentials Outside Of AWS Infrastructure](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A352a918a-34d8-4882-8470-44830c507aa3) | Sigma | SigmaHQ |
| T1078.002 | [AdminSDHolder SDProp Exclusion Added](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A61d29caf-6c15-4d1e-9ccb-7ad12ccc0bc7) | Elastic | Elastic detection-rules |
| T1082 | [Potential GobRAT File Discovery Via Grep](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae34cfa0c-0a50-4210-9cb3-5632d08eb041) | Sigma | SigmaHQ |
| T1082 | [System Information Discovery](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A42df45e7-e6e9-43b5-8f26-bec5b39cc239) | Sigma | SigmaHQ |
| T1087.001 | [BloodHound Collection Files](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A02773bed-83bf-469f-b7ff-e676e7d78bab) | Sigma | SigmaHQ |
| T1087.001 | [HackTool - Bloodhound/Sharphound Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Af376c8a7-a2d0-4ddc-aa0c-16c17236d962) | Sigma | SigmaHQ |
| T1087.002 | [BloodHound Collection Files](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A02773bed-83bf-469f-b7ff-e676e7d78bab) | Sigma | SigmaHQ |
| T1087.002 | [Suspicious Active Directory Database Snapshot Via ADExplorer](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aef61af62-bc74-4f58-b49b-626448227652) | Sigma | SigmaHQ |
| T1105 | [Greenbug Espionage Group Indicators](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A3711eee4-a808-4849-8a14-faf733da3612) | Sigma | SigmaHQ |
| T1105 | [Pandemic Registry Key](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A47e0852a-cf81-4494-a8e6-31864f8c86ed) | Sigma | SigmaHQ |
| T1110 | [Hack Tool User Agent](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac42a3073-30fb-48ae-8c99-c23ada84b103) | Sigma | SigmaHQ |
| T1110 | [HackTool - CrackMapExec Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A42a993dd-bb3e-48c8-b372-4d6684c4106c) | Sigma | SigmaHQ |
| T1112 | [ShimCache Flush](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab0524451-19af-4efa-a46f-562a977f792e) | Sigma | SigmaHQ |
| T1112 | [ShimCache Flush](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Ab0524451-19af-4efa-a46f-562a977f792e) | Sigma | OpenSearch Security Analytics |
| T1113 | [PowerShell Suspicious Script with Screenshot Capabilities](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A959a7353-1129-4aa7-9084-30746b256a70) | Elastic | Elastic detection-rules |
| T1113 | [Potential Remote Desktop Shadowing Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ac57f8579-e2a5-4804-847f-f2732edc5156) | Elastic | Elastic detection-rules |
| T1115 | [Pbpaste Execution via Unusual Parent Process](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ad7182e12-df8f-4ecf-b8f8-7cc0adcec425) | Elastic | Elastic detection-rules |
| T1115 | [Clipboard Data Collection Via Pbpaste](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad8af0da1-2959-40f9-a3e4-37a6aa1228b7) | Sigma | SigmaHQ |
| T1119 | [iOS Implant URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Ae06ac91d-b9e6-443d-8e5b-af749e7aa6b6) | Sigma | OpenSearch Security Analytics |
| T1119 | [Shai-Hulud Malicious GitHub Workflow Creation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A0aba5685-6db6-486f-88ef-29a99c545cfd) | Sigma | SigmaHQ |
| T1120 | [PowerShell Suspicious Script with Audio Capture Capabilities](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A2f2f4939-0b34-40c2-a0a3-844eb7889f43) | Elastic | Elastic detection-rules |
| T1120 | [Fsutil Drive Enumeration](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A63de06b9-a385-40b5-8b32-73f2b9ef84b6) | Sigma | SigmaHQ |
| T1133 | [OpenCanary - SSH Login Attempt](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aff7139bc-fdb1-4437-92f2-6afefe8884cb) | Sigma | SigmaHQ |
| T1133 | [OpenCanary - SSH New Connection Attempt](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acd55f721-5623-4663-bd9b-5229cab5237d) | Sigma | SigmaHQ |
| T1137.004 | [Outlook Home Page Registry Modification](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Aac5a2759-5c34-440a-b0c4-51fe674611d6) | Elastic | Elastic detection-rules |
| T1137.004 | [Outlook Home Page Registry Modification](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-protections-artifacts-behavior%3A%3Af65102b4-15b1-4e9f-af76-3b8f67201185) | Elastic | Elastic protections-artifacts (behavior) |
| T1140 | [UNC4841 - SSL Certificate Exfiltration Via Openssl](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A60911c07-f989-4362-84af-c609828ef829) | Sigma | SigmaHQ |
| T1140 | [UNC4841 - Download Compressed Files From Temp.sh Using Wget](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A60d050c4-e253-4d9a-b673-5ac100cfddfb) | Sigma | SigmaHQ |
| T1195 | [Octopus Scanner Malware](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A805c55d9-31e6-4846-9878-c34c75054fe9) | Sigma | SigmaHQ |
| T1195 | [Elastic Defend Alert from Package Manager Install Ancestry](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A344e6c7d-ceb0-4f20-ba04-7c75569a7e38) | Elastic | Elastic detection-rules |
| T1201 | [Password Policy Discovery - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aca94a6db-8106-4737-9ed2-3e3bb826af0a) | Sigma | SigmaHQ |
| T1201 | [HackTool - CrackMapExec Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A42a993dd-bb3e-48c8-b372-4d6684c4106c) | Sigma | SigmaHQ |
| T1203 | [Droppers Exploiting CVE-2017-11882](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A678eb5f4-8597-4be6-8be7-905e4234b53a) | Sigma | SigmaHQ |
| T1203 | [OMIGOD HTTP No Authentication RCE - CVE-2021-38647](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aab6b1a39-a9ee-4ab4-b075-e83acf6e346b) | Sigma | SigmaHQ |
| T1204.001 | [Google Workspace Object Copied from External Drive with App Consent](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Af33e68a4-bd19-11ed-b02f-f661ea17fbcc) | Elastic | Elastic detection-rules |
| T1204.001 | [Suspicious ClickFix/FileFix Execution Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad487ed4a-fd24-436d-a0b2-f4e95f7b2635) | Sigma | SigmaHQ |
| T1204.002 | [Ursnif Malware C2 URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A932ac737-33ca-4afd-9869-0d48b391fcc9) | Sigma | SigmaHQ |
| T1204.002 | [Droppers Exploiting CVE-2017-11882](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A678eb5f4-8597-4be6-8be7-905e4234b53a) | Sigma | SigmaHQ |
| T1218.001 | [HTML Help HH.EXE Suspicious Child Process](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A52cad028-0ff0-4854-8f67-d25dfcbc78b4) | Sigma | SigmaHQ |
| T1218.001 | [Remote CHM File Download/Execution Via HH.EXE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Af57c58b3-ee69-4ef5-9041-455bf39aaa89) | Sigma | SigmaHQ |
| T1219 | [Renamed Visual Studio Code Tunnel Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A2cf29f11-e356-4f61-98c0-1bdb9393d6da) | Sigma | SigmaHQ |
| T1219 | [Hijack Legit RDP Session to Move Laterally](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A52753ea4-b3a0-4365-910d-36cff487b789) | Sigma | OpenSearch Security Analytics |
| T1497.001 | [Virtual Machine Fingerprinting](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A5b03c9fb-9945-4d2f-9568-fd690fee3fba) | Elastic | Elastic detection-rules |
| T1497.001 | [Powershell Detect Virtualization Environment](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad93129cd-1ee0-479f-bc03-ca6f129882e3) | Sigma | SigmaHQ |
| T1505.003 | [MOVEit CVE-2023-34362 Exploitation Attempt - Potential Web Shell Request](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A435e41f2-48eb-4c95-8a2b-ed24b50ec30b) | Sigma | SigmaHQ |
| T1505.003 | [Solarwinds SUPERNOVA Webshell Access](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aa2cee20b-eacc-459f-861d-c02e5d12f1db) | Sigma | SigmaHQ |
| T1543.003 | [PSExec Lateral Movement](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=hayabusa-native%3A%3A0694c340-3a46-40ac-acfc-c3444ae6572c) | Sigma | Hayabusa (native) |
| T1543.003 | [Suspicious Service Name](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=hayabusa-native%3A%3Acc429813-21db-4019-b520-2f19648e1ef1) | Sigma | Hayabusa (native) |
| T1552.001 | [Potential Russian APT Credential Theft Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab83f5166-9237-4b5e-9cd4-7b5d52f4d8ee) | Sigma | SigmaHQ |
| T1552.001 | [Copy Passwd Or Shadow From TMP Path](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Afa4aaed5-4fe0-498d-bbc0-08e3346387ba) | Sigma | SigmaHQ |
| T1553.002 | [Driver Loaded (Invalid Signature)](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=hayabusa-native%3A%3A1f666722-3948-40a2-9d78-d9d374477a90) | Sigma | Hayabusa (native) |
| T1553.002 | [Driver Loaded (Expired/Revoked Cert)](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=hayabusa-native%3A%3Ac837dd6d-0c91-4593-aeab-f6a1f3ca1961) | Sigma | Hayabusa (native) |
| T1555 | [HackTool - SecurityXploded Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A7679d464-4f74-45e2-9e01-ac66c5eb041a) | Sigma | SigmaHQ |
| T1555 | [SecurityXploded Tool](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A7679d464-4f74-45e2-9e01-ac66c5eb041a) | Sigma | OpenSearch Security Analytics |
| T1555.003 | [SQLite Chromium Profile Data DB Access](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A24c77512-782b-448a-8950-eddb0785fc71) | Sigma | SigmaHQ |
| T1555.003 | [HackTool - WinPwn Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad557dc06-62e8-4468-a8e8-7984124908ce) | Sigma | SigmaHQ |
| T1555.004 | [Suspicious Key Manager Access](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aa4694263-59a8-4608-a3a0-6f8d3a51664c) | Sigma | SigmaHQ |
| T1555.004 | [Potential Credential Access via Trusted Developer Utility](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A9d110cb3-5f4b-4c9a-b9f5-53f0a1707ae5) | Elastic | Elastic detection-rules |
| T1556.002 | [Powershell Install a DLL in System Directory](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A63bf8794-9917-45bc-88dd-e1b5abc0ecfd) | Sigma | SigmaHQ |
| T1556.002 | [Dropping Of Password Filter DLL](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab7966f4a-b333-455b-8370-8ca53c229762) | Sigma | SigmaHQ |
| T1566.001 | [Ursnif Malware C2 URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A932ac737-33ca-4afd-9869-0d48b391fcc9) | Sigma | SigmaHQ |
| T1566.001 | [Droppers Exploiting CVE-2017-11882](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A678eb5f4-8597-4be6-8be7-905e4234b53a) | Sigma | SigmaHQ |
| T1566.002 | [Potential Malicious Usage of CloudTrail System Manager](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A38e7f511-3f74-41d4-836e-f57dfa18eead) | Sigma | SigmaHQ |
| T1566.002 | [Google Workspace Device Registration After OAuth from Suspicious ASN](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A012bfca7-45cb-4507-a3ba-3777167f8b81) | Elastic | Elastic detection-rules |
| T1566.003 | [M365 Teams Rogue Help Desk Chat Created](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ae8e7b6b6-78b0-4015-97fe-c2f28468e0d4) | Elastic | Elastic detection-rules |
| T1566.003 | [M365 Azure Monitor Alert Email with Financial or Billing Theme](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Aa6129187-c47b-48ab-a412-67a44836d918) | Elastic | Elastic detection-rules |
| T1572 | [Communication To LocaltoNet Tunneling Service Initiated - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac4568f5d-131f-4e78-83d4-45b2da0ec4f1) | Sigma | SigmaHQ |
| T1572 | [Communication To Ngrok Tunneling Service - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A19bf6fdb-7721-4f3d-867f-53467f6a5db6) | Sigma | SigmaHQ |
| T1573.002 | [Potential Self-Signed TLS Certificate Recently Issued on External Connection](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A869fe008-5dd4-4f07-9c2e-aa90c3926fd9) | Elastic | Elastic detection-rules |
| T1573.002 | [Openssl Client or Server Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Aad5a3757-c872-4719-8c72-12d3f08db655) | Elastic | Elastic detection-rules |
| T1583.001 | [AWS Route 53 Private Hosted Zone Associated With a VPC](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ae3c27562-709a-42bd-82f2-3ed926cced19) | Elastic | Elastic detection-rules |
| T1583.001 | [AWS SES Email Identity Verified Then Deleted](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A8e4bde35-125d-4eb3-9a2e-d7e77a053a08) | Elastic | Elastic detection-rules |
| T1586.002 | [CYFIRMA - Brand Intelligence - Domain Impersonation High Rule](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A10bdf525-5b89-4a25-933a-e63e73b915f1) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1586.002 | [CYFIRMA - Brand Intelligence - Domain Impersonation Medium Rule](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A8f97ddbe-ab66-4f6c-b675-73b5eeb07259) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1587.001 | [Formbook Process Creation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A032f5fb3-d959-41a5-9263-4173c802dc2b) | Sigma | SigmaHQ |
| T1587.001 | [Uncommon File Created In Office Startup Folder](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aa10a2c40-2c4d-49f8-b557-1a946bc55d9d) | Sigma | SigmaHQ |
| T1588.002 | [Hacktool Execution - Imphash](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A24e3e58a-646b-4b50-adef-02ef935b9fc8) | Sigma | SigmaHQ |
| T1588.002 | [Renamed SysInternals DebugView Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acd764533-2e07-40d6-a718-cfeec7f2da7f) | Sigma | SigmaHQ |
| T1588.003 | [Short-lived ephemeral code signing certificates](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-hunting-queries%3A%3Ae920899f-edf0-446c-bb13-effbaf61b27b) | Sentinel KQL | Microsoft Sentinel (Hunting Queries) |
| T1608.001 | [M365 OneDrive Malware File Upload](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Abba1b212-b85c-41c6-9b28-be0e5cdfc9b1) | Elastic | Elastic detection-rules |
| T1608.001 | [M365 SharePoint Malware File Detected](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A0e52157a-8e96-4a95-a6e3-5faae5081a74) | Elastic | Elastic detection-rules |
| T1686.003 | [Suspicious Program Location Whitelisted In Firewall Via Netsh.EXE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aa35f5a72-f347-4e36-8895-9869b0d5fc6d) | Sigma | SigmaHQ |
| T1686.003 | [RDP Connection Allowed Via Netsh.EXE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A01aeb693-138d-49d2-9403-c4f52d7d3d62) | Sigma | SigmaHQ |

## 8. Plano de emulação e validação

Use num laboratório isolado e autorizado para confirmar que as regras disparam. Os comandos estão nos repositórios oficiais.

| Tática | Técnica | Teste Atomic Red Team | Plataformas |
|---|---|---|---|
| Initial Access | [T1195](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1195/T1195.md) | Octopus Scanner Malware Open Source Supply Chain | windows |
| Initial Access | [T1566.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1566.001/T1566.001.md) | Download Macro-Enabled Phishing Attachment | windows |
| Initial Access | [T1566.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1566.001/T1566.001.md) | Word spawned a command shell and used an IP address in the command line | windows |
| Initial Access | [T1566.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1566.002/T1566.002.md) | Paste and run technique | windows |
| Execution | [T1047](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1047/T1047.md) | WMI Reconnaissance Users | windows |
| Execution | [T1047](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1047/T1047.md) | WMI Reconnaissance Processes | windows |
| Execution | [T1053.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1053.005/T1053.005.md) | Scheduled Task Startup Script | windows |
| Execution | [T1053.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1053.005/T1053.005.md) | Scheduled task Local | windows |
| Execution | [T1059](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059/T1059.md) | AutoIt Script Execution | windows |
| Execution | [T1059.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md) | Mimikatz | windows |
| Execution | [T1059.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md) | Run BloodHound from local disk | windows |
| Execution | [T1059.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.003/T1059.003.md) | Create and Execute Batch Script | windows |
| Execution | [T1059.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.003/T1059.003.md) | Writes text to a file and displays it. | windows |
| Execution | [T1059.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.005/T1059.005.md) | Visual Basic script execution to gather local computer information | windows |
| Execution | [T1059.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.005/T1059.005.md) | Encoded VBS code execution | windows |
| Execution | [T1204.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1204.002/T1204.002.md) | OSTap Style Macro Execution | windows |
| Execution | [T1204.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1204.002/T1204.002.md) | OSTap Payload Download | windows |
| Persistence | [T1133](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1133/T1133.md) | Running Chrome VPN Extensions via the Registry 2 vpn extension | windows |
| Persistence | [T1137.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1137.004/T1137.004.md) | Install Outlook Home Page Persistence | windows |
| Persistence | [T1505.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1505.003/T1505.003.md) | Web Shell Written to Disk | windows |
| Persistence | [T1543.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1543.003/T1543.003.md) | Modify Fax service to run PowerShell | windows |
| Persistence | [T1543.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1543.003/T1543.003.md) | Service Installation CMD | windows |
| Privilege Escalation | [T1068](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1068/T1068.md) | Scattered Spider BYOVD (CVE-2015-2291 for Intel Ethernet Diagnostics Driver) | windows |
| Privilege Escalation | [T1068](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1068/T1068.md) | Turla Snake Malware Privilege Escalation Through VM Driver | windows |
| Stealth | [T1027.013](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027.013/T1027.013.md) | Decode Eicar File and Write to File | linux, macos, windows |
| Stealth | [T1027.013](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027.013/T1027.013.md) | Decrypt Eicar File and Write to File | linux, macos, windows |
| Stealth | [T1036](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036/T1036.md) | System File Copied to Unusual Location | windows |
| Stealth | [T1036](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036/T1036.md) | Malware Masquerading and Execution from Zip File | windows |
| Stealth | [T1036.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.005/T1036.005.md) | Execute a process from a directory masquerading as the current parent directory | linux, macos |
| Stealth | [T1036.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.005/T1036.005.md) | Masquerade as a built-in system executable | windows |
| Stealth | [T1070.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.004/T1070.004.md) | Delete a single file - FreeBSD/Linux/macOS | linux, macos |
| Stealth | [T1070.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.004/T1070.004.md) | Delete an entire folder - FreeBSD/Linux/macOS | linux, macos |
| Stealth | [T1140](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1140/T1140.md) | Deobfuscate/Decode Files Or Information | windows |
| Stealth | [T1140](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1140/T1140.md) | Certutil Rename and Decode | windows |
| Stealth | [T1218.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.001/T1218.001.md) | Compiled HTML Help Local Payload | windows |
| Stealth | [T1218.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.001/T1218.001.md) | Compiled HTML Help Remote Payload | windows |
| Stealth | [T1497.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1497.001/T1497.001.md) | Detect Virtualization Environment (Linux) | linux |
| Stealth | [T1497.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1497.001/T1497.001.md) | Detect Virtualization Environment (FreeBSD) | linux |
| Defense Impairment | [T1112](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1112/T1112.md) | Modify Registry of Current User Profile - cmd | windows |
| Defense Impairment | [T1112](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1112/T1112.md) | Modify Registry of Local Machine - cmd | windows |
| Defense Impairment | [T1556.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1556.002/T1556.002.md) | Install and Register Password Filter DLL | windows |
| Defense Impairment | [T1556.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1556.002/T1556.002.md) | Install Additional Authentication Packages | windows |
| Defense Impairment | [T1686.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1686.003/T1686.003.md) | Enable Firewall Rule Group via COM Object (HNetCfg.FwPolicy2) | windows |
| Defense Impairment | [T1686.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1686.003/T1686.003.md) | Set All Network Profiles to Private via Registry | windows |
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
| Credential Access | [T1555.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1555.004/T1555.004.md) | Access Saved Credentials via VaultCmd | windows |
| Credential Access | [T1555.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1555.004/T1555.004.md) | WinPwn - Loot local Credentials - Invoke-WCMDump | windows |
| Discovery | [T1007](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1007/T1007.md) | System Service Discovery | windows |
| Discovery | [T1007](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1007/T1007.md) | System Service Discovery - net.exe | windows |
| Discovery | [T1012](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1012/T1012.md) | Query Registry | windows |
| Discovery | [T1012](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1012/T1012.md) | Query Registry with Powershell cmdlets | windows |
| Discovery | [T1016](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1016/T1016.md) | System Network Configuration Discovery on Windows | windows |
| Discovery | [T1016](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1016/T1016.md) | List Windows Firewall Rules | windows |
| Discovery | [T1033](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1033/T1033.md) | System Owner/User Discovery | windows |
| Discovery | [T1033](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1033/T1033.md) | System Owner/User Discovery | linux, macos |
| Discovery | [T1046](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1046/T1046.md) | Port Scan | linux, macos |
| Discovery | [T1046](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1046/T1046.md) | Port Scan Nmap | linux, macos |
| Discovery | [T1049](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1049/T1049.md) | System Network Connections Discovery | windows |
| Discovery | [T1049](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1049/T1049.md) | System Network Connections Discovery with PowerShell | windows |
| Discovery | [T1057](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1057/T1057.md) | Process Discovery - ps | linux, macos |
| Discovery | [T1057](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1057/T1057.md) | Process Discovery - tasklist | windows |
| Discovery | [T1069.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1069.001/T1069.001.md) | Permission Groups Discovery (Local) | linux, macos |
| Discovery | [T1069.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1069.001/T1069.001.md) | Basic Permission Groups Discovery Windows (Local) | windows |
| Discovery | [T1069.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1069.002/T1069.002.md) | Basic Permission Groups Discovery Windows (Domain) | windows |
| Discovery | [T1069.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1069.002/T1069.002.md) | Permission Groups Discovery PowerShell (Domain) | windows |
| Discovery | [T1082](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1082/T1082.md) | System Information Discovery | windows |
| Discovery | [T1082](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1082/T1082.md) | System Information Discovery | macos |
| Discovery | [T1087.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1087.001/T1087.001.md) | Enumerate all accounts (Local) | linux |
| Discovery | [T1087.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1087.001/T1087.001.md) | View sudoers access | linux, macos |
| Discovery | [T1087.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1087.002/T1087.002.md) | Enumerate all accounts (Domain) | windows |
| Discovery | [T1087.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1087.002/T1087.002.md) | Enumerate all accounts via PowerShell (Domain) | windows |
| Discovery | [T1120](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1120/T1120.md) | Win32_PnPEntity Hardware Inventory | windows |
| Discovery | [T1120](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1120/T1120.md) | WinPwn - printercheck | windows |
| Discovery | [T1201](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1201/T1201.md) | Examine password complexity policy - Ubuntu | linux |
| Discovery | [T1201](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1201/T1201.md) | Examine password complexity policy - FreeBSD | linux |
| Lateral Movement | [T1021.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.001/T1021.001.md) | RDP to Remote Host | windows |
| Lateral Movement | [T1021.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.001/T1021.001.md) | Changing RDP Port to Non Standard Port via Powershell | windows |
| Lateral Movement | [T1021.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.004/T1021.004.md) | ESXi - Enable SSH via PowerCLI | windows |
| Lateral Movement | [T1021.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.004/T1021.004.md) | ESXi - Enable SSH via VIM-CMD | windows |
| Collection | [T1005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1005/T1005.md) | Search files of interest and save them to a single zip file (Windows) | windows |
| Collection | [T1005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1005/T1005.md) | Find and dump sqlite databases (Linux) | linux |
| Collection | [T1025](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1025/T1025.md) | Identify Documents on USB and Removable Media via PowerShell | windows |
| Collection | [T1056.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1056.001/T1056.001.md) | Input Capture | windows |
| Collection | [T1056.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1056.001/T1056.001.md) | Living off the land Terminal Input Capture on Linux with pam.d | linux |
| Collection | [T1113](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1113/T1113.md) | Screencapture | macos |
| Collection | [T1113](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1113/T1113.md) | Screencapture (silent) | macos |
| Collection | [T1115](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1115/T1115.md) | Utilize Clipboard to store or execute commands from | windows |
| Collection | [T1115](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1115/T1115.md) | Execute Commands from Clipboard using PowerShell | windows |
| Collection | [T1119](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1119/T1119.md) | Automated Collection Command Prompt | windows |
| Collection | [T1119](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1119/T1119.md) | Automated Collection PowerShell | windows |
| Command and Control | [T1071.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1071.001/T1071.001.md) | Malicious User Agents - Powershell | windows |
| Command and Control | [T1071.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1071.001/T1071.001.md) | Malicious User Agents - CMD | windows |
| Command and Control | [T1071.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1071.004/T1071.004.md) | DNS Large Query Volume | windows |
| Command and Control | [T1071.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1071.004/T1071.004.md) | DNS Regular Beaconing | windows |
| Command and Control | [T1105](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1105/T1105.md) | rsync remote file copy (push) | linux, macos |
| Command and Control | [T1105](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1105/T1105.md) | rsync remote file copy (pull) | linux, macos |
| Command and Control | [T1219](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1219/T1219.md) | TeamViewer Files Detected Test on Windows | windows |
| Command and Control | [T1219](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1219/T1219.md) | AnyDesk Files Detected Test on Windows | windows |
| Command and Control | [T1572](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1572/T1572.md) | DNS over HTTPS Large Query Volume | windows |
| Command and Control | [T1572](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1572/T1572.md) | DNS over HTTPS Regular Beaconing | windows |
| Exfiltration | [T1048.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1048.003/T1048.003.md) | Exfiltration Over Alternative Protocol - HTTP | linux, macos |
| Exfiltration | [T1048.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1048.003/T1048.003.md) | Exfiltration Over Alternative Protocol - ICMP | windows |

**Logs reais de ataque (EVTX) para testar sem executar nada:**

- T1003.001 — [CA_hashdump_4663_4656_lsass_access](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Credential%20Access/CA_hashdump_4663_4656_lsass_access.evtx) _(inferido)_
- T1003.001 — [LsassSilentProcessExit_process_exit_monitor_3001_lsass](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Credential%20Access/LsassSilentProcessExit_process_exit_monitor_3001_lsass.evtx) _(inferido)_
- T1016 — [ID4688-Audit policy enumerated](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1016-System%20Network%20Configuration%20Discovery/ID4688-Audit%20policy%20enumerated.evtx) _(explícito)_
- T1016 — [ID4688-Firewall configuration enumerated (command)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1016-System%20Network%20Configuration%20Discovery/ID4688-Firewall%20configuration%20enumerated%20%28command%29.evtx) _(explícito)_
- T1021.001 — [ID4688,4778,4779 RDP hijack direct](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0008-Lateral%20Movement/T1021.001-Remote%20Desktop%20Protocol/ID4688%2C4778%2C4779%20RDP%20hijack%20direct.evtx) _(explícito)_
- T1021.001 — [ID4688-4778 RDP hijack command execution](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0008-Lateral%20Movement/T1021.001-Remote%20Desktop%20Protocol/ID4688-4778%20RDP%20hijack%20command%20execution.evtx) _(explícito)_
- T1021.004 — [ID4-OpenSSH server listening](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0008-Lateral%20Movement/T1021.004-Remote%20Service%20SSH/ID4-OpenSSH%20server%20listening.evtx) _(explícito)_
- T1021.004 — [ID4103-4104-OpenSSH server activation and config](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0008-Lateral%20Movement/T1021.004-Remote%20Service%20SSH/ID4103-4104-OpenSSH%20server%20activation%20and%20config.evtx) _(explícito)_
- T1036 — [rundll32_hollowing_wermgr_masquerading](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/AutomatedTestingTools/Malware/rundll32_hollowing_wermgr_masquerading.evtx) _(inferido)_
- T1046 — [ID131-RDP brutforce (no user info)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1046-Network%20Service%20Scanning/ID131-RDP%20brutforce%20%28no%20user%20info%29.evtx) _(explícito)_
- T1046 — [ID4624-Anonymous login with domain specified (DonPapi)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1046-Network%20Service%20Scanning/ID4624-Anonymous%20login%20with%20domain%20specified%20%28DonPapi%29.evtx) _(explícito)_
- T1047 — [ID1-WMI spwaning PowerShell process - WMImplant](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1047-Windows%20Management%20Instrumentation/ID1-WMI%20spwaning%20PowerShell%20process%20-%20WMImplant.evtx) _(explícito)_
- T1047 — [ID1-WMIexec process execution](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1047-Windows%20Management%20Instrumentation/ID1-WMIexec%20process%20execution.evtx) _(explícito)_
- T1053.005 — [ID4688-4698 Persistent scheduled task with SYSTEM privileges creation](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1053.005-Scheduled%20Task/ID4688-4698%20Persistent%20scheduled%20task%20with%20SYSTEM%20privileges%20creation.evtx) _(explícito)_
- T1053.005 — [ID4688-Interactive shell using AT schedule task](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1053.005-Scheduled%20Task/ID4688-Interactive%20shell%20using%20AT%20schedule%20task.evtx) _(explícito)_
- T1056.001 — [sysmon_13_keylogger_directx](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Credential%20Access/sysmon_13_keylogger_directx.evtx) _(inferido)_
- T1059.001 — [ID4103-4104-Payload download via PowerShell](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1059.001-PowerShell/ID4103-4104-Payload%20download%20via%20PowerShell.evtx) _(explícito)_
- T1059.001 — [ID4688-Encoded PowerShell MSF payload via process execution](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1059.001-PowerShell/ID4688-Encoded%20PowerShell%20MSF%20payload%20via%20process%20execution.evtx) _(explícito)_
- T1059.003 — [ID4688-SQL Server payload injectection for reverse shell (MSF)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1059.003-Windows%20Command%20Shell/ID4688-SQL%20Server%20payload%20injectection%20for%20reverse%20shell%20%28MSF%29.evtx) _(explícito)_
- T1068 — [ID12-13 Mini_Plasma_PoC_AbortHydration_ArbitraryRegKey_EoP](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0004-Privilege%20Escalation/T1068-Exploitation%20for%20Privilege%20Escalation/ID12-13%20Mini_Plasma_PoC_AbortHydration_ArbitraryRegKey_EoP.evtx) _(explícito)_
- T1068 — [ID4673-Privilege SeMachineAccountPrivilege called](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0004-Privilege%20Escalation/T1068-Exploitation%20for%20Privilege%20Escalation/ID4673-Privilege%20SeMachineAccountPrivilege%20called.evtx) _(explícito)_
- T1078 — [ID1149-RDP success logins to multiple hosts](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0001-Initial%20access/T1078-Valid%20accounts/ID1149-RDP%20success%20logins%20to%20multiple%20hosts.evtx) _(explícito)_
- T1078 — [ID33205-SQL Server failed login with disabled SA account](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0001-Initial%20access/T1078-Valid%20accounts/ID33205-SQL%20Server%20failed%20login%20with%20disabled%20SA%20account.evtx) _(explícito)_
- T1078.002 — [ID4964-Login of a member of a special group](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0005-Defense%20Evasion/T1078.002-Valid%20accounts-Domain%20accounts/ID4964-Login%20of%20a%20member%20of%20a%20special%20group.evtx) _(explícito)_
- T1087.002 — [discovery_bloodhound](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Discovery/discovery_bloodhound.evtx) _(inferido)_

## 9. Hipóteses de hunting

Se OilRig estiver no seu ambiente, estas são as perguntas a fazer aos seus dados (fontes de log segundo as estratégias de detecção do MITRE ATT&CK).

1. **T1137.004 Outlook Home Page** — Adversary uses a tool like Ruler to configure a malicious Outlook folder Home Page that loads a remote or embedded HTML payload upon folder interaction. Execution chain begins with Outlook launching, a specific folder being accessed, and a suspicious child… Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=7), `WinEventLog:Application` (Outlook logs indicating failure to load or render HTML page in Home Page view).
2. **T1195 Supply Chain Compromise** — 1) New or updated software is delivered/installed from atypical sources or with signature/hash mismatches; 2) installer/updater writes binaries to unexpected paths or replaces existing signed files; 3) first run causes unsigned/abnormally signed modules to… Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=7), `WinEventLog:Sysmon` (EventCode=11).
3. **T1201 Password Policy Discovery** — Cause→effect chain: (1) a user or service spawns a shell/PowerShell that queries local/domain password policy via commands/cmdlets (e.g., `net accounts`, `Get-ADDefaultDomainPasswordPolicy`, `secedit /export`); (2) optional directory/LDAP reads from DCs; (3)… Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:PowerShell` (EventCode=4103, 4104, 4105, 4106), `WinEventLog:Security` (EventCode=4662).
4. **T1556.002 Password Filter DLL** — Detects suspicious registration of new password filter DLLs into the authentication process. Correlates registry modifications to LSASS Notification Packages with subsequent DLL creation and loading events. Observes anomalous file placement of DLLs in system… Dados: `WinEventLog:Security` (EventCode=4657), `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Sysmon` (EventCode=7).
5. **T1003.005 Cached Domain Credentials** — Detects adversary behavior accessing Windows cached domain credential files using tools like Mimikatz, reg.exe, or PowerShell, often combined with registry exports or LSASS memory scraping. Dados: `WinEventLog:Security` (EventCode=4663, 4670, 4656), `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=10).
6. **T1025 Data from Removable Media** — Adversary mounts a USB device and begins enumerating, copying, or compressing files using scripting engines, cmd, or remote access tools. Dados: `WinEventLog:Security` (EventCode=4663, 4670, 4656), `WinEventLog:System` (EventCode=2003), `WinEventLog:Sysmon` (EventCode=1).
7. **T1115 Clipboard Data** — Detection of clipboard access via OS utilities (e.g., clip.exe, Get-Clipboard) by non-interactive or abnormal parent processes, potentially chained with staging or exfiltration commands. Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=10).
8. **T1555.004 Windows Credential Manager** — Detects unauthorized access to Windows Credential Manager through anomalous process execution (vaultcmd.exe, rundll32.exe keymgr.dll), suspicious API calls (CredEnumerateA), or direct file access to Credential Locker files. Correlates process creation with… Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=10), `WinEventLog:Sysmon` (EventCode=15).
9. **T1008 Fallback Channels** — Establishing network connections on uncommon ports or protocols following C2 disruption or blocking. Often executed by processes that typically exhibit no network activity. Dados: `WinEventLog:Sysmon` (EventCode=3, 22), `NSM:Flow` (uncommon ports).
10. **T1218.001 Compiled HTML File** — Execution of hh.exe to open a .chm file followed by suspicious child processes or script engine invocation (VBScript, JScript, mshta, powershell). Behavior includes loading a CHM file from untrusted locations, or immediately spawning commands indicative of… Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Sysmon` (EventCode=7).
11. **T1686.003 Windows Host Firewall** — Detects processes or users modifying Windows Defender Firewall profiles, policies, or rules followed by measurable network exposure changes. Correlates firewall management execution, registry/policy mutation, service state changes, and subsequent inbound or… Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=13, 14).
12. **T1027.005 Indicator Removal from Tools** — Detection of known tools or malware flagged by antivirus, followed by a near-term drop of a similar binary with modified signature and resumed activity (execution, C2, or persistence). Dados: `WinEventLog:Application` (EventCode=1000), `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=11).

## 10. OSINT — onde pesquisar

Consultas prontas com todos os nomes conhecidos do grupo:

- Relatórios técnicos: [busca web](https://duckduckgo.com/?q=%28%22OilRig%22+OR+%22COBALT+GYPSY%22+OR+%22IRN2%22+OR+%22APT34%22+OR+%22Helix+Kitten%22+OR+%22Evasive+Serpens%22%29+threat+report) · [PDFs](https://duckduckgo.com/?q=%28%22OilRig%22+OR+%22COBALT+GYPSY%22+OR+%22IRN2%22+OR+%22APT34%22+OR+%22Helix+Kitten%22+OR+%22Evasive+Serpens%22%29+filetype%3Apdf)
- Regras e IOCs publicados: [GitHub](https://github.com/search?type=code&q=%22OilRig%22+OR+%22COBALT+GYPSY%22+OR+%22IRN2%22+OR+%22APT34%22+OR+%22Helix+Kitten%22+OR+%22Evasive+Serpens%22)
- Pulsos de ameaça: [AlienVault OTX](https://otx.alienvault.com/browse/global/pulses?q=OilRig)
- Família de malware e atores: [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/actors) (busque por OilRig, COBALT GYPSY, IRN2)
- Cartões de grupo: [ThaiCERT Threat Group Cards](https://apt.etda.or.th/cgi-bin/listgroups.cgi)
- Página oficial: [MITRE ATT&CK G0049](https://attack.mitre.org/groups/G0049/)

**Relatórios na coleção CyberMonitor** (ligados pelo nome do grupo, conferir antes de citar):

- 2016 — [the-oilrig-campaign-attacks-on-saudi-arabian-organizations-deliver-helminth-backdoor](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2016/2016.05.26.OilRig_Campaign/the-oilrig-campaign-attacks-on-saudi-arabian-organizations-deliver-helminth-backdoor.pdf) _(via “OilRig”)_
- 2017 — [Iranian Fileless Attack Infiltrates Israeli Organizations](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2017/2017.01.05.Iranian_Threat_Agent_OilRig/Iranian%20Fileless%20Attack%20Infiltrates%20Israeli%20Organizations.pdf) _(via “OilRig”)_
- 2017 — [Iranian Threat Agent OilRig Delivers Digitally Signed Malware, Impersonates University of Oxford _ ClearSky Cybersecurit](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2017/2017.01.05.Iranian_Threat_Agent_OilRig/Iranian%20Threat%20Agent%20OilRig%20Delivers%20Digitally%20Signed%20Malware%2C%20Impersonates%20University%20of%20Oxford%20_%20ClearSky%20Cybersecurity.pdf) _(via “OilRig”)_
- 2017 — [unit42-oilrig-uses-ismdoor-variant-possibly-linked-greenbug-threat-group](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2017/2017.07.27.oilrig-uses-ismdoor-variant-possibly-linked-greenbug-threat-group/unit42-oilrig-uses-ismdoor-variant-possibly-linked-greenbug-threat-group.pdf) _(via “OilRig”)_
- 2017 — [targeted-attack-in-middle-east-by-apt34.html](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2017/2017.12.07.New_Targeted_Attack_in_the_Middle_East_by_APT34/targeted-attack-in-middle-east-by-apt34.html.pdf) _(via “APT34”)_
- 2018 — [unit42-oilrig-uses-rgdoor-iis-backdoor-targets-middle-east](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2018/2018.01.25.oilrig_Middle_East/unit42-oilrig-uses-rgdoor-iis-backdoor-targets-middle-east.pdf) _(via “OilRig”)_
- 2018 — [oilrig-targets-middle-eastern-government-adds-evasion-techniques-oopsie](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2018/2018.09.04.OilRig_Targets_Middle_Eastern/oilrig-targets-middle-eastern-government-adds-evasion-techniques-oopsie.pdf) _(via “OilRig”)_
- 2020 — [apt34-aka-oilrig-attacks-lebanon-government-entities-with-maildropper-implant](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2020/2020.03.02_APT34_MAILDROPPER/apt34-aka-oilrig-attacks-lebanon-government-entities-with-maildropper-implant.pdf) _(via “OilRig”)_
- 2020 — [OilRig Targets Middle Eastern Telecommunications Organization and Adds Novel C2 Channel with Steganography to Its Invent](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2020/2020.07.22.OilRig_Middle_Eastern_Telecommunication/OilRig%20Targets%20Middle%20Eastern%20Telecommunications%20Organization%20and%20Adds%20Novel%20C2%20Channel%20with%20Steganography%20to%20Its%20Inventory.pdf) _(via “OilRig”)_

## 11. Bibliografia (31 fontes citadas pelo ATT&CK)

- [Check Point APT34 April 2021](https://research.checkpoint.com/2021/irans-apt34-returns-with-an-updated-arsenal/) — Check Point. (2021, April 8). Iran’s APT34 Returns with an Updated Arsenal. Retrieved May 5, 2021.
- [ClearSky OilRig Jan 2017](http://www.clearskysec.com/oilrig/) — ClearSky Cybersecurity. (2017, January 5). Iranian Threat Agent OilRig Delivers Digitally Signed Malware, Impersonates University of Oxford. Retrieved May 3, 2017.
- [Crowdstrike GTR2020 Mar 2020](https://go.crowdstrike.com/rs/281-OBQ-266/images/Report2020CrowdStrikeGlobalThreatReport.pdf) — Crowdstrike. (2020, March 2). 2020 Global Threat Report. Retrieved December 11, 2020.
- [Crowdstrike Helix Kitten Nov 2018](https://www.crowdstrike.com/blog/meet-crowdstrikes-adversary-of-the-month-for-november-helix-kitten/) — Meyers, A. (2018, November 27). Meet CrowdStrike’s Adversary of the Month for November: HELIX KITTEN. Retrieved December 18, 2018.
- [ESET OilRig Campaigns Sep 2023](https://www.welivesecurity.com/en/eset-research/oilrigs-outer-space-juicy-mix-same-ol-rig-new-drill-pipes/) — Hromcova, Z. and Burgher, A. (2023, September 21). OilRig’s Outer Space and Juicy Mix: Same ol’ rig, new drill pipes. Retrieved November 21, 2024.
- [ESET OilRig Downloaders DEC 2023](https://www.welivesecurity.com/en/eset-research/oilrig-persistent-attacks-cloud-service-powered-downloaders/) — Hromcova, Z. and Burgher, A. (2023, December 14). OilRig’s persistent attacks using cloud service-powered downloaders. Retrieved November 26, 2024.
- [FireEye APT34 Dec 2017](https://www.fireeye.com/blog/threat-research/2017/12/targeted-attack-in-middle-east-by-apt34.html) — Sardiwal, M, et al. (2017, December 7). New Targeted Attack in the Middle East by APT34, a Suspected Iranian Threat Group, Using CVE-2017-11882 Exploit. Retrieved December 20, 2017.
- [FireEye APT34 July 2019](https://www.fireeye.com/blog/threat-research/2019/07/hard-pass-declining-apt34-invite-to-join-their-professional-network.html) — Bromiley, M., et al.. (2019, July 18). Hard Pass: Declining APT34’s Invite to Join Their Professional Network. Retrieved August 26, 2019.
- [FireEye APT34 Webinar Dec 2017](https://www.brighttalk.com/webcast/10703/296317/apt34-new-targeted-attack-in-the-middle-east) — Davis, S. and Caban, D. (2017, December 19). APT34 - New Targeted Attack in the Middle East. Retrieved December 20, 2017.
- [FireEye APT35 2018](https://static.carahsoft.com/concrete/files/1015/2779/3571/M-Trends-2018-Report.pdf) — Mandiant. (2018). Mandiant M-Trends 2018. Retrieved November 17, 2024.
- [FireEye Outlook Dec 2019](https://www.fireeye.com/blog/threat-research/2019/12/breaking-the-rules-tough-outlook-for-home-page-attacks.html) — McWhirt, M., Carr, N., Bienstock, D. (2019, December 4). Breaking the Rules: A Tough Outlook for Home Page Attacks (CVE-2017-11774). Retrieved June 23, 2020.
- [FireEye Targeted Attacks Middle East Banks](https://web.archive.org/web/20200618235708/https://www.fireeye.com/blog/threat-research/2016/05/targeted_attacksaga.html) — Singh, S., Yin, H. (2016, May 22). https://www.fireeye.com/blog/threat-research/2016/05/targeted_attacksaga.html. Retrieved November 17, 2024.
- [IBM ZeroCleare Wiper December 2019](https://securityintelligence.com/posts/new-destructive-wiper-zerocleare-targets-energy-sector-in-the-middle-east/) — Kessem, L. (2019, December 4). New Destructive Wiper ZeroCleare Targets Energy Sector in the Middle East. Retrieved September 4, 2024.
- [Microsoft Threat Actor Naming July 2023](https://learn.microsoft.com/en-us/microsoft-365/security/intelligence/microsoft-threat-actor-naming?view=o365-worldwide) — Microsoft . (2023, July 12). How Microsoft names threat actors. Retrieved November 17, 2023.
- [OilRig ISMAgent July 2017](https://researchcenter.paloaltonetworks.com/2017/07/unit42-oilrig-uses-ismdoor-variant-possibly-linked-greenbug-threat-group/) — Falcone, R. and Lee, B. (2017, July 27). OilRig Uses ISMDoor Variant; Possibly Linked to Greenbug Threat Group. Retrieved January 8, 2018.
- [OilRig New Delivery Oct 2017](https://researchcenter.paloaltonetworks.com/2017/10/unit42-oilrig-group-steps-attacks-new-delivery-documents-new-injector-trojan/) — Falcone, R. and Lee, B. (2017, October 9). OilRig Group Steps Up Attacks with New Delivery Documents and New Injector Trojan. Retrieved January 8, 2018.
- [Palo Alto OilRig April 2017](http://researchcenter.paloaltonetworks.com/2017/04/unit42-oilrig-actors-provide-glimpse-development-testing-efforts/) — Falcone, R.. (2017, April 27). OilRig Actors Provide a Glimpse into Development and Testing Efforts. Retrieved May 3, 2017.
- [Palo Alto OilRig May 2016](http://researchcenter.paloaltonetworks.com/2016/05/the-oilrig-campaign-attacks-on-saudi-arabian-organizations-deliver-helminth-backdoor/) — Falcone, R. and Lee, B.. (2016, May 26). The OilRig Campaign: Attacks on Saudi Arabian Organizations Deliver Helminth Backdoor. Retrieved May 3, 2017.
- [Palo Alto OilRig Oct 2016](http://researchcenter.paloaltonetworks.com/2016/10/unit42-oilrig-malware-campaign-updates-toolset-and-expands-targets/) — Grunzweig, J. and Falcone, R.. (2016, October 4). OilRig Malware Campaign Updates Toolset and Expands Targets. Retrieved May 3, 2017.
- [Palo Alto OilRig Sep 2018](https://unit42.paloaltonetworks.com/unit42-oilrig-uses-updated-bondupdater-target-middle-eastern-government/) — Wilhoit, K. and Falcone, R. (2018, September 12). OilRig Uses Updated BONDUPDATER to Target Middle Eastern Government. Retrieved February 18, 2019.
- [Proofpoint Iranian Aligned Attacks JAN 2020](https://www.proofpoint.com/us/corporate-blog/post/iranian-state-sponsored-and-aligned-attacks-what-you-need-know-and-steps-protect) — Proofpoint. (2020, January 10). Iranian State-Sponsored and Aligned Attacks: What You Need to Know and Steps to Protect Yourself. Retrieved January 16, 2025.
- [Secureworks COBALT GYPSY Threat Profile](https://www.secureworks.com/research/threat-profiles/cobalt-gypsy) — Secureworks. (n.d.). COBALT GYPSY Threat Profile. Retrieved April 14, 2021.
- [Symantec Crambus OCT 2023](https://www.security.com/threat-intelligence/crambus-middle-east-government) — Symantec Threat Hunter Team. (2023, October 19). Crambus: New Campaign Targets Middle Eastern Government. Retrieved November 27, 2024.
- [Trend Micro Earth Simnavaz October 2024](https://www.trendmicro.com/en_us/research/24/j/earth-simnavaz-cyberattacks.html) — Fahmy, M. et al. (2024, October 11). Earth Simnavaz (aka APT34) Levies Advanced Cyberattacks Against Middle East. Retrieved November 27, 2024.
- [Unit 42 OopsIE! Feb 2018](https://researchcenter.paloaltonetworks.com/2018/02/unit42-oopsie-oilrig-uses-threedollars-deliver-new-trojan/) — Lee, B., Falcone, R. (2018, February 23). OopsIE! OilRig Uses ThreeDollars to Deliver New Trojan. Retrieved July 16, 2018.
- [Unit 42 Playbook Dec 2017](https://pan-unit42.github.io/playbook_viewer/) — Unit 42. (2017, December 15). Unit 42 Playbook Viewer. Retrieved December 20, 2017.
- [Unit 42 QUADAGENT July 2018](https://researchcenter.paloaltonetworks.com/2018/07/unit42-oilrig-targets-technology-service-provider-government-agency-quadagent/) — Lee, B., Falcone, R. (2018, July 25). OilRig Targets Technology Service Provider and Government Agency with QUADAGENT. Retrieved August 9, 2018.
- [Unit 42 RGDoor Jan 2018](https://researchcenter.paloaltonetworks.com/2018/01/unit42-oilrig-uses-rgdoor-iis-backdoor-targets-middle-east/) — Falcone, R. (2018, January 25). OilRig uses RGDoor IIS Backdoor on Targets in the Middle East. Retrieved July 6, 2018.
- [Unit42 OilRig Nov 2018](https://unit42.paloaltonetworks.com/unit42-analyzing-oilrigs-ops-tempo-testing-weaponization-delivery/) — Falcone, R., Wilhoit, K.. (2018, November 16). Analyzing OilRig’s Ops Tempo from Testing to Weaponization to Delivery. Retrieved April 23, 2019.
- [Unit42 OilRig Playbook 2023](https://pan-unit42.github.io/playbook_viewer/?pb=evasive-serpens) — Unit42. (2016, May 1). Evasive Serpens Unit 42 Playbook Viewer. Retrieved February 6, 2023.
- [Unit42 RDAT July 2020](https://unit42.paloaltonetworks.com/oilrig-novel-c2-channel-steganography/) — Falcone, R. (2020, July 22). OilRig Targets Middle Eastern Telecommunications Organization and Adds Novel C2 Channel with Steganography to Its Inventory. Retrieved July 28, 2020.

## 12. Limites e confiança

- O ATT&CK registra o que foi **relatado publicamente**, não tudo o que o grupo faz. Ausência de uma técnica não prova que o grupo não a usa.
- **Sobreposição de TTP não é atribuição.** Muitas técnicas são compartilhadas entre grupos e com red teams. Use a assinatura comportamental como hipótese, junto com infraestrutura, malware e contexto.
- Cobertura de detecção refere-se ao catálogo público Detection Rules, não ao seu ambiente: confira se a telemetria necessária chega ao seu SIEM.
- Ligações marcadas como _inferidas_ (EVTX por palavra-chave, relatórios por nome) devem ser verificadas.

---
Fontes: MITRE ATT&CK® (uso livre com atribuição, © The MITRE Corporation), Atomic Red Team (Red Canary, MIT), EVTX-to-MITRE-Attack, EVTX-ATTACK-SAMPLES, APT & CyberCriminal Campaign Collections. Gerado por [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules).
