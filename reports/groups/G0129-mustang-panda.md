# Mustang Panda (G0129) — Dossiê de inteligência

> **TLP:CLEAR** · gerado em 2026-10-25 a partir de fontes abertas · MITRE ATT&CK v20.0 · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0129) · [ATT&CK](https://attack.mitre.org/groups/G0129/)

**Também conhecido como:** TA416, RedDelta, BRONZE PRESIDENT, STATELY TAURUS, FIREANT, CAMARO DRAGON, EARTH PRETA, HIVE0154, TWILL TYPHOON, TANTALUM, LUMINOUS MOTH, UNC6384, TEMP.Hex, Red Lich, ClumsyToad  
**Registro no ATT&CK:** criado em 2021-04-12, atualizado em 2026-07-31 · referências de 2015 a 2026

## 1. Sumário executivo

- **85 técnicas** atribuídas publicamente, concentradas em **Stealth, Execution, Discovery**.
- **Arsenal:** 18 malware e 5 ferramentas (ex.: Cobalt Strike, PlugX, TONESHELL, PUBLOAD, RCSession).
- **Campanhas atribuídas:** 1 (RedDelta Modified PlugX Infection Chain Operations).
- **Cobertura de detecção pública:** 93% das técnicas têm ao menos uma regra no catálogo; **6 técnicas sem nenhuma regra pública**.
- **Assinatura comportamental** (técnicas raras entre os 178 grupos, as mais úteis para atribuição): T1129 Shared Modules, T1219.001 IDE Tunneling, T1574.005 Executable Installer File Permissions Weakness, T1608 Stage Capabilities, T1622 Debugger Evasion.

## 2. Quem é

> Mustang Panda is a China-based cyber espionage threat actor that has been conducting operations since at least 2012. Mustang Panda has been known to use tailored phishing lures and decoy documents to deliver malicious payloads. Mustang Panda has targeted government, diplomatic, and non-governmental organizations, including think tanks, religious institutions, and research entities, across the United States, Europe, and Asia, with notable activity in Russia, Mongolia, Myanmar, Pakistan, and Vietnam.

_Texto original do MITRE ATT&CK, em inglês._

## 3. Perfil TTP por tática (kill chain)

Cada linha: técnica, como o grupo a usou segundo relatos públicos, e o que existe para detectar e testar.

### Reconnaissance (TA0043) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1593](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1593) Search Open Websites/Domains | Mustang Panda has used open-source research to identify information about victims to use in targeting to include creating weaponized phishing lures and attachments. | 8 | — | — |
| [T1598.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1598.003) Spearphishing Link | Mustang Panda has delivered web bugs to profile their intended targets. | **0** | — | — |

### Resource Development (TA0042) — 10

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1583.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1583.001) Domains | Mustang Panda has acquired C2 domains prior to operations. | 7 | — | — |
| [T1583.006](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1583.006) Web Services | Mustang Panda has set up Dropbox and Google Drive to host malicious downloads. | 2 | — | — |
| [T1585.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1585.002) Email Accounts | Mustang Panda has leveraged the legitimate email marketing service SMTP2Go for phishing campaigns. Mustang Panda has also created fake Google accounts to distribute malware via spear-phishing emails. Mustang Panda has also created accounts for spearphishing op… | **0** | — | — |
| [T1586.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1586.002) Email Accounts | Mustang Panda has compromised legitimate email accounts to use in their spear-phishing operations. | 3 | — | — |
| [T1587.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1587.001) Malware | Mustang Panda has developed custom malware for use in their operations. | 43 | — | — |
| [T1588.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1588.002) Tool | Mustang Panda has obtained and leveraged publicly-available tools for intrusion activities. | 35 | — | — |
| [T1588.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1588.003) Code Signing Certificates | Mustang Panda has used revoked code signing certificates for its malicious payloads. | 1 | — | — |
| [T1588.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1588.004) Digital Certificates | Mustang Panda has obtained SSL certificates for their C2 domains. | 1 | — | — |
| [T1608](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1608) Stage Capabilities | Mustang Panda has used servers under their control to validate tracking pixels sent to phishing victims. | 20 | — | — |
| [T1608.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1608.001) Upload Malware | Mustang Panda has hosted malicious payloads on DropBox including PlugX. | 3 | — | — |

### Initial Access (TA0001) — 3

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1091](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1091) Replication Through Removable Media | Mustang Panda has used a customized PlugX variant which could spread through USB connections. | 10 | 1 | — |
| [T1566.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1566.001) Spearphishing Attachment | Mustang Panda has used spearphishing attachments to deliver initial access payloads. Mustang Panda has also delivered archive files such as RAR and ZIP files containing legitimate EXEs and malicious DLLs. | 230 | 2 | — |
| [T1566.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1566.002) Spearphishing Link | Mustang Panda has delivered malicious links to their intended targets. Mustang Panda has distributed spear-phishing emails with embedded links that direct the victim to a malicious archive hosted on Google or Dropbox. | 138 | 1 | — |

### Execution (TA0002) — 15

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1047](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1047) Windows Management Instrumentation | Mustang Panda has executed PowerShell scripts via WMI. | 370 | 12 | 11 |
| [T1053.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1053.005) Scheduled Task | Mustang Panda has created a scheduled task to execute additional malicious software, as well as maintain persistence. Mustang Panda has also created a scheduled task that creates a reverse shell. | 248 | 14 | 11 |
| [T1059](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059) Command and Scripting Interpreter | Mustang Panda has utilized meterpreter shellcode. | 1467 | 1 | — |
| [T1059.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.001) PowerShell | Mustang Panda has used malicious PowerShell scripts to enable execution. | 1340 | 22 | 15 |
| [T1059.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.003) Windows Command Shell | Mustang Panda has executed HTA files via cmd.exe, and used batch scripts for collection. Mustang Panda has also utilized cmd.exe to execute commands on an infected host such as `cmd.exe /c ping.exe 8.8.8.8 -n 70&&"%temp%\FontEDL.exe"`. | 269 | 6 | 1 |
| [T1059.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.005) Visual Basic | Mustang Panda has embedded VBScript components in LNK files to download additional files and automate collection. Mustang Panda has also used VBA macros in maldocs to execute malicious DLLs. Mustang Panda also utilized a VBS Script “autorun.vbs” that created p… | 192 | 3 | — |
| [T1059.007](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.007) JavaScript | Mustang Panda has executed a JavaScript payload utilizing wscript.exe on the endpoint. | 205 | 5 | — |
| [T1072](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1072) Software Deployment Tools | Mustang Panda has leveraged legitimate software tools such as AntiVirus Agents, Security Services, and App Development tools to execute scripts and to side-load dlls. | 59 | 3 | — |
| [T1106](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1106) Native API | Mustang Panda has used various Windows API calls during execution and defense evasion. | 118 | 5 | — |
| [T1129](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1129) Shared Modules | Mustang Panda has leveraged `LoadLibrary` to load DLLs. | 33 | 1 | — |
| [T1203](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1203) Exploitation for Client Execution | Mustang Panda has exploited CVE-2017-0199 in Microsoft Word to execute code. | 202 | — | — |
| [T1204.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1204.001) Malicious Link | Mustang Panda has sent malicious links including links directing victims to a Google Drive folder. Mustang Panda has also utilized webpages with Javascript code that downloads malicious payloads to the victim device. | 52 | — | — |
| [T1204.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1204.002) Malicious File | Mustang Panda has sent malicious files requiring direct victim interaction to execute. Mustang Panda has also leveraged executable files that display decoy documents to the victim to provide a resemblance of legitimacy with customized themes related to the vic… | 259 | 13 | — |
| [T1574.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1574.001) DLL | Mustang Panda has used a legitimately signed executable to execute a malicious payload within a DLL file. Mustang Panda has abused legitimate executables to side-load malicious DLLs. | 455 | 7 | 5 |
| [T1574.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1574.005) Executable Installer File Permissions Weakness | Mustang Panda has leveraged legitimate software installer executables such as Setup Factory “IRSetup.exe” to drop and execute their payload. | 14 | — | — |

### Persistence (TA0003) — 6

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1053.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1053.005) Scheduled Task | Mustang Panda has created a scheduled task to execute additional malicious software, as well as maintain persistence. Mustang Panda has also created a scheduled task that creates a reverse shell. | 248 | 14 | 11 |
| [T1176.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1176.002) IDE Extensions | Mustang Panda has leveraged Visual Studio Code’s (VSCode) embedded reverse shell feature using the command `code.exe tunnel` to execute code and deliver additional payloads. | **0** | — | — |
| [T1205](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1205) Traffic Signaling | Mustang Panda has utilized a magic value in C2 communications and only executes in memory when response packets match specific values of “17 03 03” or “46 77 4d”. | 4 | — | — |
| [T1505.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1505.003) Web Shell | Mustang Panda has used China Chopper web shells to maintain access to victims’ environments. | 210 | 1 | — |
| [T1546.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1546.003) Windows Management Instrumentation Event Subscription | Mustang Panda's custom ORat tool uses a WMI event consumer to maintain persistence. | 99 | 4 | — |
| [T1547.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1547.001) Registry Run Keys / Startup Folder | Mustang Panda has created the registry key HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run\AdobelmdyU to maintain persistence. Mustang Panda has also established persistence via the registry key `HKCU\Software\Microsoft\Windows\Cur… | 299 | 21 | 2 |

### Privilege Escalation (TA0004) — 3

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1053.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1053.005) Scheduled Task | Mustang Panda has created a scheduled task to execute additional malicious software, as well as maintain persistence. Mustang Panda has also created a scheduled task that creates a reverse shell. | 248 | 14 | 11 |
| [T1546.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1546.003) Windows Management Instrumentation Event Subscription | Mustang Panda's custom ORat tool uses a WMI event consumer to maintain persistence. | 99 | 4 | — |
| [T1547.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1547.001) Registry Run Keys / Startup Folder | Mustang Panda has created the registry key HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run\AdobelmdyU to maintain persistence. Mustang Panda has also established persistence via the registry key `HKCU\Software\Microsoft\Windows\Cur… | 299 | 21 | 2 |

### Stealth (TA0005) — 19

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1027](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1027) Obfuscated Files or Information | Mustang Panda has delivered initial payloads hidden using archives and encoding measures. Mustang Panda has also utilized opaque predicates in payloads to hinder analysis. | 520 | 11 | 5 |
| [T1027.007](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1027.007) Dynamic API Resolution | Mustang Panda has leveraged obfuscated Windows API function calls that were concealed as unique names, or hashes of the Windows API. | 2 | 1 | — |
| [T1027.012](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1027.012) LNK Icon Smuggling | Mustang Panda has utilized LNK files to hide malicious scripts for execution. Mustang Panda has also leveraged LNK files that were programmed to display a PDF icon to entice the victim to click on the file to execute an office.exe binary. | 1 | — | — |
| [T1027.016](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1027.016) Junk Code Insertion | Mustang Panda has used junk code within their DLL files to hinder analysis. | **0** | — | — |
| [T1036.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1036.005) Match Legitimate Resource Name or Location | Mustang Panda has used names like `adobeupdate.dat` and `PotPlayerDB.dat` to disguise PlugX, and a file named `OneDrive.exe` to load a Cobalt Strike payload. Mustang Panda has also masqueraded legitimate browser plugin updates to include AdobePlugins.exe. | 116 | 4 | — |
| [T1036.007](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1036.007) Double File Extension | Mustang Panda has used an additional filename extension to hide the true file type. | 25 | — | — |
| [T1036.008](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1036.008) Masquerade File Type | Mustang Panda has masqueraded malicious executables as legitimate files that download PlugX malware. | 8 | — | — |
| [T1070](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1070) Indicator Removal | Mustang Panda has deleted registry keys that store data and maintained persistence. | 263 | 2 | — |
| [T1070.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1070.004) File Deletion | Mustang Panda will delete their tools and files, and kill processes after their objectives are reached. | 132 | 11 | — |
| [T1070.006](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1070.006) Timestomp | Mustang Panda has modified file timestamps from the export address table (EAT) in malware to make it difficult to identify creation times. | 28 | 10 | 3 |
| [T1140](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1140) Deobfuscate/Decode Files or Information | Mustang Panda has the ability to decrypt its payload prior to execution. Mustang Panda has also utilized RC4 encryption for malicious payloads. | 173 | 11 | 1 |
| [T1205](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1205) Traffic Signaling | Mustang Panda has utilized a magic value in C2 communications and only executes in memory when response packets match specific values of “17 03 03” or “46 77 4d”. | 4 | — | — |
| [T1218.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1218.004) InstallUtil | Mustang Panda has used InstallUtil.exe to execute a malicious Beacon stager. | 35 | 8 | — |
| [T1218.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1218.005) Mshta | Mustang Panda has used mshta.exe to launch collection scripts. | 130 | 10 | 4 |
| [T1564.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1564.001) Hidden Files and Directories | Mustang Panda's PlugX variant has created a hidden folder on USB drives named RECYCLE.BIN to store malicious executables and collected data. Mustang Panda has also modified file attributes to `hidden` and `system`. | 76 | 10 | — |
| [T1574.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1574.001) DLL | Mustang Panda has used a legitimately signed executable to execute a malicious payload within a DLL file. Mustang Panda has abused legitimate executables to side-load malicious DLLs. | 455 | 7 | 5 |
| [T1574.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1574.005) Executable Installer File Permissions Weakness | Mustang Panda has leveraged legitimate software installer executables such as Setup Factory “IRSetup.exe” to drop and execute their payload. | 14 | — | — |
| [T1622](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1622) Debugger Evasion | Mustang Panda has embedded debug strings with messages to distract analysts. Mustang Panda has also made calls to Windows API `CheckRemoteDebuggerPresent` and exits if it detects a debugger. | 22 | 1 | — |
| [T1678](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1678) Delay Execution | Mustang Panda has delayed the execution of payloads leveraging ping echo requests `cmd /c ping 8.8.8.8 -n 70&&"%temp%\"`. | **0** | — | — |

### Defense Impairment (TA0112) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1553.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1553.002) Code Signing | Mustang Panda has used valid legitimate digital signatures and certificates to evade detection. | 11 | — | — |

### Credential Access (TA0006) — 5

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1003) OS Credential Dumping | Mustang Panda utilized “Hdump” to dump credentials from memory. | 399 | 7 | 19 |
| [T1003.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1003.001) LSASS Memory | Mustang Panda has harvested credentials from memory of lssas.exe with Mimikatz. | 580 | 14 | 10 |
| [T1003.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1003.003) NTDS | Mustang Panda has used vssadmin to create a volume shadow copy and retrieve the NTDS.dit file. Mustang Panda has also used reg save on the SYSTEM file Registry location to help extract the NTDS.dit file. | 157 | 11 | 2 |
| [T1003.006](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1003.006) DCSync | Mustang Panda has leveraged Mimikatz DCSync feature to obtain user credentials. | 33 | 2 | 2 |
| [T1557](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1557) Adversary-in-the-Middle | Mustang Panda leveraged a captive portal hijack that redirected the victim to a webpage that prompted the victim to download a malicious payload. | 67 | — | 2 |

### Discovery (TA0007) — 12

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1016](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1016) System Network Configuration Discovery | Mustang Panda has used ipconfig and arp to determine network configuration information. Mustang Panda has also utilized SharpNBTScan to scan the victim environment. | 99 | 10 | 5 |
| [T1018](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1018) Remote System Discovery | Mustang Panda has queried Active Directory for computers using AdFind. Mustang Panda has also utilized SharpNBTScan to scan the victim environment. | 157 | 23 | 1 |
| [T1046](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1046) Network Service Discovery | Mustang Panda has leveraged NBTscan to scan IP networks. | 212 | 13 | 2 |
| [T1049](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1049) System Network Connections Discovery | Mustang Panda has used netstat -ano to determine network connection information. | 47 | 7 | — |
| [T1057](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1057) Process Discovery | Mustang Panda has used tasklist /v to determine active process information. Mustang Panda has also used TONESHELL malware to check the process name and process path to ensure it matches the expected one prior to triggering a custom exception handler. | 82 | 10 | — |
| [T1069.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1069.002) Domain Groups | Mustang Panda has leveraged AdFind to enumerate domain groups. | 91 | 15 | — |
| [T1082](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1082) System Information Discovery | Mustang Panda has gathered system information using systeminfo. | 264 | 41 | — |
| [T1083](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1083) File and Directory Discovery | Mustang Panda has searched the entire target system for DOC, DOCX, PPT, PPTX, XLS, XLSX, and PDF files. | 137 | 9 | — |
| [T1087.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1087.002) Domain Account | Mustang Panda has utilized AdFind to identify domain users. | 180 | 25 | 1 |
| [T1518](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1518) Software Discovery | Mustang Panda has searched the victim system for the InstallUtil.exe program and its version. | 58 | 6 | — |
| [T1622](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1622) Debugger Evasion | Mustang Panda has embedded debug strings with messages to distract analysts. Mustang Panda has also made calls to Windows API `CheckRemoteDebuggerPresent` and exits if it detects a debugger. | 22 | 1 | — |
| [T1654](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1654) Log Enumeration | Mustang Panda has used Wevtutil to gather Windows Security Event Logs. | 3 | 2 | — |

### Lateral Movement (TA0008) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1072](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1072) Software Deployment Tools | Mustang Panda has leveraged legitimate software tools such as AntiVirus Agents, Security Services, and App Development tools to execute scripts and to side-load dlls. | 59 | 3 | — |
| [T1091](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1091) Replication Through Removable Media | Mustang Panda has used a customized PlugX variant which could spread through USB connections. | 10 | 1 | — |

### Collection (TA0009) — 5

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1074.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1074.001) Local Data Staging | Mustang Panda has stored collected credential files in c:\windows\temp prior to exfiltration. Mustang Panda has also stored documents for exfiltration in a hidden folder on USB drives. | 37 | 3 | — |
| [T1119](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1119) Automated Collection | Mustang Panda used custom batch scripts to collect files automatically from a targeted system. | 72 | 4 | — |
| [T1557](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1557) Adversary-in-the-Middle | Mustang Panda leveraged a captive portal hijack that redirected the victim to a webpage that prompted the victim to download a malicious payload. | 67 | — | 2 |
| [T1560.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1560.001) Archive via Utility | Mustang Panda has used RAR to create password-protected archives of collected documents prior to exfiltration. Mustang Panda has used WinRAR “Rar.exe” to archive stolen files before exfiltration. Mustang Panda has also used TONESHELL and post-exploitation tool… | 76 | 13 | — |
| [T1560.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1560.003) Archive via Custom Method | Mustang Panda has encrypted documents with RC4 prior to exfiltration. | 1 | — | — |

### Command and Control (TA0011) — 10

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1001.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1001.003) Protocol or Service Impersonation | Mustang Panda has utilized TLS record headers in network packets to impersonate various versions of TLS protocols to blend in with legitimate network traffic. Mustang Panda has used FakeTLS to communicate with its C2 servers. | 7 | — | — |
| [T1071.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1071.001) Web Protocols | Mustang Panda has communicated with its C2 via HTTP POST requests. | 228 | 3 | — |
| [T1095](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1095) Non-Application Layer Protocol | Mustang Panda has utilized TCP-based reverse shells using cmd.exe. | 72 | 5 | — |
| [T1102](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1102) Web Service | Mustang Panda has used DropBox URLs to deliver variants of PlugX. Mustang Panda has also used Google Drive to host malicious downloads. | 98 | — | — |
| [T1105](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1105) Ingress Tool Transfer | Mustang Panda has downloaded additional executables following the initial infection stage. Mustang Panda has also leveraged Visual Studio Code `code.exe` and Dev Tunnels using `DevTunnel.exe` to propagate additional tools and payloads. | 644 | 39 | — |
| [T1205](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1205) Traffic Signaling | Mustang Panda has utilized a magic value in C2 communications and only executes in memory when response packets match specific values of “17 03 03” or “46 77 4d”. | 4 | — | — |
| [T1219.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1219.001) IDE Tunneling | Mustang Panda has utilized an established Github account to create a tunnel within the victim environment using Visual Studio Code through the `code.exe tunnel` command. | **0** | — | — |
| [T1219.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1219.002) Remote Desktop Software | Mustang Panda has installed TeamViewer on targeted systems. | 221 | — | — |
| [T1572](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1572) Protocol Tunneling | Mustang Panda has leveraged OpenSSH (sshd.exe) to execute commands, transfer files and spread across the environment communicating over SMB port 445. | 173 | 9 | 1 |
| [T1573.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1573.001) Symmetric Cryptography | Mustang Panda has encrypted C2 communications with RC4. Mustang Panda has also leveraged encryption and compression algorithms to obfuscate the traffic between the system and C2 server, methods observed included RC4, AES, XOR with 0x5a, and LZO. | 5 | — | — |

### Exfiltration (TA0010) — 4

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1041](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1041) Exfiltration Over C2 Channel | Mustang Panda has exfiltrated stolen data and files to its C2 server. | 135 | 2 | — |
| [T1048.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1048.003) Exfiltration Over Unencrypted Non-C2 Protocol | Mustang Panda has used FTP to exfiltrate archive files. | 51 | 8 | — |
| [T1052.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1052.001) Exfiltration over USB | Mustang Panda has used a customized PlugX variant which could exfiltrate documents from air-gapped networks. | 5 | — | — |
| [T1567.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1567.002) Exfiltration to Cloud Storage | Mustang Panda has also exfiltrated archived files to cloud services such as Dropbox using `curl`. | 85 | 2 | — |

## 4. Assinatura comportamental

Técnicas que este grupo usa e que poucos dos 178 grupos do ATT&CK usam. Pesam mais numa atribuição por TTP: ver várias delas juntas é mais informativo do que ver técnicas comuns como PowerShell.

| Técnica | Outros grupos que usam | Peso (raridade) |
|---|---:|---:|
| T1129 Shared Modules | 0 | 4.49 |
| T1219.001 IDE Tunneling | 0 | 4.49 |
| T1574.005 Executable Installer File Permissions Weakness | 0 | 4.49 |
| T1608 Stage Capabilities | 0 | 4.49 |
| T1622 Debugger Evasion | 0 | 4.49 |
| T1036.007 Double File Extension | 1 | 4.09 |
| T1052.001 Exfiltration over USB | 1 | 4.09 |
| T1176.002 IDE Extensions | 1 | 4.09 |
| T1218.004 InstallUtil | 1 | 4.09 |
| T1001.003 Protocol or Service Impersonation | 2 | 3.80 |

## 5. Arsenal

| Software | Tipo | Técnicas no ATT&CK | Uso relatado (EN) |
|---|---|---:|---|
| [Cobalt Strike](https://attack.mitre.org/software/S0154/) | malware | 73 |  |
| [PlugX](https://attack.mitre.org/software/S0013/) | malware | 49 |  |
| [TONESHELL](https://attack.mitre.org/software/S1239/) | malware | 43 |  |
| [PUBLOAD](https://attack.mitre.org/software/S1228/) | malware | 35 |  |
| [RCSession](https://attack.mitre.org/software/S0662/) | malware | 22 |  |
| [ShadowPad](https://attack.mitre.org/software/S0596/) | malware | 21 |  |
| [BOOKWORM](https://attack.mitre.org/software/S1226/) | malware | 17 |  |
| [Mimikatz](https://attack.mitre.org/software/S0002/) | ferramenta | 17 |  |
| [PoisonIvy](https://attack.mitre.org/software/S0012/) | malware | 15 |  |
| [CLAIMLOADER](https://attack.mitre.org/software/S1236/) | malware | 11 |  |
| [Impacket](https://attack.mitre.org/software/S0357/) | ferramenta | 11 | Mustang Panda leveraged Impacket to gather information about the network, discover devices, users and query directories on remote machines to identify files to exfiltrate. |
| [PAKLOG](https://attack.mitre.org/software/S1233/) | malware | 10 |  |
| [China Chopper](https://attack.mitre.org/software/S0020/) | malware | 10 | Mustang Panda has used China Chopper web shells to maintain access to victims’ environments. |
| [HIUPAN](https://attack.mitre.org/software/S1230/) | malware | 9 |  |
| [StarProxy](https://attack.mitre.org/software/S1227/) | malware | 9 |  |
| [SplatDropper](https://attack.mitre.org/software/S1232/) | malware | 8 |  |
| [CorKLOG](https://attack.mitre.org/software/S1235/) | malware | 8 |  |
| [CANONSTAGER](https://attack.mitre.org/software/S1237/) | malware | 6 |  |
| [SplatCloak](https://attack.mitre.org/software/S1234/) | malware | 6 |  |
| [STATICPLUGIN](https://attack.mitre.org/software/S1238/) | malware | 5 |  |
| [NBTscan](https://attack.mitre.org/software/S0590/) | ferramenta | 5 |  |
| [AdFind](https://attack.mitre.org/software/S0552/) | ferramenta | 5 | Mustang Panda has utilized AdFind for enumerating domain groups, users, and computers. |
| [Wevtutil](https://attack.mitre.org/software/S0645/) | ferramenta | 3 | Mustang Panda has leveraged Wevtutil to gather information about usernames and Windows Security Event logs. |

## 6. Campanhas

| Campanha | Período | Resumo (EN) |
|---|---|---|
| [RedDelta Modified PlugX Infection Chain Operations](https://attack.mitre.org/campaigns/C0047/) | 2023-07 → 2024-12 | RedDelta Modified PlugX Infection Chain Operations was executed by Mustang Panda from mid-2023 through the end of 2024 against multiple entities in East and Southeast Asia. RedDelta Modified PlugX Infection Chain Operati |

## 7. Cobertura defensiva

**79 de 85 técnicas (93%)** têm ao menos uma regra pública no catálogo Detection Rules.

### Técnicas sem regra pública (prioridade para engenharia de detecção)

- **T1219.001 IDE Tunneling** — Command and Control. Fonte de log sugerida pelo MITRE: `WinEventLog:Sysmon` EventCode=1; `auditd:SYSCALL` execve on code or jetbrains-gateway with remote flags; `macos:unifiedlog` process: code or jetbrains-gateway launching with --tunnel or --remote
- **T1176.002 IDE Extensions** — Persistence. Fonte de log sugerida pelo MITRE: `WinEventLog:Security` EventCode=4688; `auditd:SYSCALL` execve; `macos:unifiedlog` Execution of Code.app, idea, JetBrainsToolbox, eclipse with install/extension flags
- **T1678 Delay Execution** — Stealth. Fonte de log sugerida pelo MITRE: `WinEventLog:Sysmon` EventCode=1; `auditd:SYSCALL` execve or nanosleep with no stdout/stderr I/O; `macos:unifiedlog` launchd or osascript spawns process with delay command
- **T1027.016 Junk Code Insertion** — Stealth. Fonte de log sugerida pelo MITRE: `WinEventLog:Sysmon` EventCode=11; `auditd:SYSCALL` write; `macos:endpointsecurity` ES_EVENT_TYPE_NOTIFY_EXEC
- **T1598.003 Spearphishing Link** — Reconnaissance. Fonte de log sugerida pelo MITRE: `Application Log` None
- **T1585.002 Email Accounts** — Resource Development

### Regras recomendadas por técnica

Melhor regra disponível por técnica (formato portável e maduro primeiro).

| Técnica | Regra | Formato | Fonte |
|---|---|---|---|
| T1001.003 | [DNSCat2 Powershell Implementation Detection Via Process Creation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Ab11d75d6-d7c1-11ea-87d0-0242ac130003) | Sigma | OpenSearch Security Analytics |
| T1001.003 | [Sigma: Suspicious LDAP-Attributes Used](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=evtx-wazuh-rules-saifbelaarbi%3A%3Awazuh-110011) | Wazuh | EVTX-Wazuh-Rules (saifbelaarbi) |
| T1003 | [Antivirus - Password Dumper Signature](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A78cc2dd2-7d20-4d32-93ff-057084c38b93) | Sigma | SigmaHQ |
| T1003 | [HackTool - Rubeus Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A7ec2c172-dceb-4c10-92c9-87c1881b7e18) | Sigma | SigmaHQ |
| T1003.001 | [Antivirus - Password Dumper Signature](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A78cc2dd2-7d20-4d32-93ff-057084c38b93) | Sigma | SigmaHQ |
| T1003.001 | [Mimikatz through Windows Remote Management](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Aaa35a627-33fb-4d04-a165-d33b4afca3e8) | Sigma | OpenSearch Security Analytics |
| T1003.003 | [Potential Russian APT Credential Theft Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab83f5166-9237-4b5e-9cd4-7b5d52f4d8ee) | Sigma | SigmaHQ |
| T1003.003 | [VolumeShadowCopy Symlink Creation Via Mklink](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A40b19fa6-d835-400c-b301-41f3a2baacaf) | Sigma | SigmaHQ |
| T1003.006 | [HackTool - Mimikatz Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aa642964e-bead-4bed-8910-1bb4d63e3b4d) | Sigma | SigmaHQ |
| T1003.006 | [Mimikatz Use](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A06d71506-7beb-4f22-8888-e2e5e2ca7fd8) | Sigma | SigmaHQ |
| T1016 | [Potential Pikabot Discovery Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A698d4431-514f-4c82-af4d-cf573872a9f5) | Sigma | SigmaHQ |
| T1016 | [OpenCanary - SNMP OID Request](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae9856028-fd4e-46e6-b3d1-10f7ceb95078) | Sigma | SigmaHQ |
| T1018 | [Chopper Webshell Process Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Afa3c117a-bc0d-416e-a31b-0c0e80653efb) | Sigma | SigmaHQ |
| T1018 | [Webshell Hacking Activity Patterns](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4ebc877f-4612-45cb-b3a5-8e3834db36c9) | Sigma | SigmaHQ |
| T1027 | [Potential Emotet Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad02e8cf5-6099-48cf-9bfc-1eec2d0c7b18) | Sigma | SigmaHQ |
| T1027 | [Emotet Process Creation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Ad02e8cf5-6099-48cf-9bfc-1eec2d0c7b18) | Sigma | OpenSearch Security Analytics |
| T1027.007 | [Sysmon - Event 1: Process creation $(win.eventdata.description)](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=socfortress-wazuh-rules%3A%3Awazuh-101142) | Wazuh | SOCFortress Wazuh-Rules |
| T1027.007 | [Sysmon - Event 7: Image loaded by $(win.eventdata.image)](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=socfortress-wazuh-rules%3A%3Awazuh-106131) | Wazuh | SOCFortress Wazuh-Rules |
| T1027.012 | [Rare .lnk File Created on Desktop](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=bert-janp-hunting-queries%3A%3A64f8f89949bb) | KQL hunting | Bert-JanP Hunting Queries |
| T1036.005 | [Exploit for CVE-2015-1641](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A7993792c-5ce2-4475-a3db-a3a5539827ef) | Sigma | SigmaHQ |
| T1036.005 | [Exploit for CVE-2015-1641](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A7993792c-5ce2-4475-a3db-a3a5539827ef) | Sigma | OpenSearch Security Analytics |
| T1036.007 | [Suspicious Double Extension Files](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab4926b47-a9d7-434c-b3a0-adc3fa0bd13e) | Sigma | SigmaHQ |
| T1036.007 | [Suspicious Parent Double Extension File Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A5e6a80c8-2d45-4633-9ef4-fa2671a39c5c) | Sigma | SigmaHQ |
| T1036.008 | [Process Started from Process ID (PID) File](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A3688577a-d196-11ec-90b0-f661ea17fbce) | Elastic | Elastic detection-rules |
| T1036.008 | [Non-DLL Extension File Renamed With DLL Extension](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Abbfd974c-248e-4435-8de6-1e938c79c5c1) | Sigma | SigmaHQ |
| T1041 | [Equation Group C2 Communication](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A881834a4-6659-4773-821e-1c151789d873) | Sigma | SigmaHQ |
| T1041 | [OpenCanary - TFTP Request](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab4e6b016-a2ac-4759-ad85-8000b300d61e) | Sigma | SigmaHQ |
| T1046 | [HackTool - winPEAS Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A98b53e78-ebaf-46f8-be06-421aafd176d9) | Sigma | SigmaHQ |
| T1046 | [HackTool - WinPwn Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad557dc06-62e8-4468-a8e8-7984124908ce) | Sigma | SigmaHQ |
| T1047 | [HackTool - Potential Impacket Lateral Movement Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A10c14723-61c7-4c75-92ca-9af245723ad2) | Sigma | SigmaHQ |
| T1047 | [CrackMapExec Command Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A058f4380-962d-40a5-afce-50207d36d7e2) | Sigma | OpenSearch Security Analytics |
| T1048.003 | [Suspicious WebDav Client Execution Via Rundll32.EXE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A982e9f2d-1a85-4d5b-aea4-31f5e97c6555) | Sigma | SigmaHQ |
| T1048.003 | [Possible DNS Tunneling](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A1ec4b281-aa65-46a2-bdae-5fd830ed914e) | Sigma | OpenSearch Security Analytics |
| T1049 | [Potential Pikabot Discovery Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A698d4431-514f-4c82-af4d-cf573872a9f5) | Sigma | SigmaHQ |
| T1049 | [HackTool - SharpView Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab2317cfa-4a47-4ead-b3ff-297438c0bc2d) | Sigma | SigmaHQ |
| T1052.001 | [New USB Storage Device Mounted](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A483832a8-ffdd-4e11-8e96-e0224f7bda9b) | Elastic | Elastic detection-rules |
| T1052.001 | [Unusual Process Writing Data to an External Device](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A4b95ecea-7225-4690-9938-2a2c0bad9c99) | Elastic | Elastic detection-rules |
| T1053.005 | [Operation Wocao Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1cfac73c-be78-4f9a-9b08-5bde0c3953ab) | Sigma | SigmaHQ |
| T1053.005 | [Operation Wocao Activity - Security](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A74ad4314-482e-4c3e-b237-3f7ed3b9ca8d) | Sigma | SigmaHQ |
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
| T1059.007 | [Adwind RAT / JRAT](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1fac1481-2dbc-48b2-9096-753c49b4ec71) | Sigma | SigmaHQ |
| T1059.007 | [WScript or CScript Dropper - File](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A002bdb95-0cf1-46a6-9e08-d38c128a6127) | Sigma | SigmaHQ |
| T1069.002 | [BloodHound Collection Files](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A02773bed-83bf-469f-b7ff-e676e7d78bab) | Sigma | SigmaHQ |
| T1069.002 | [HackTool - SharpView Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab2317cfa-4a47-4ead-b3ff-297438c0bc2d) | Sigma | SigmaHQ |
| T1070 | [Shadow Copies Deletion Using Operating Systems Utilities](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac947b146-0abc-4c87-9c64-b17e9d7274a2) | Sigma | SigmaHQ |
| T1070 | [Fsutil Suspicious Invocation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aadd64136-62e5-48ea-807e-88638d02df1e) | Sigma | SigmaHQ |
| T1070.004 | [File Deletion](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A30aed7b6-d2c1-4eaf-9382-b6bc43e50c57) | Sigma | SigmaHQ |
| T1070.004 | [Prefetch File Deleted](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A0a1f9d29-6465-4776-b091-7f43b26e4c89) | Sigma | SigmaHQ |
| T1070.006 | [File Creation Date Changed to Another Year](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A558eebe5-f2ba-4104-b339-36f7902bcc1a) | Sigma | SigmaHQ |
| T1070.006 | [Touch Suspicious Service File](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A31545105-3444-4584-bebf-c466353230d2) | Sigma | SigmaHQ |
| T1071.001 | [Ursnif Malware Download URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aa36ce77e-30db-4ea0-8795-644d7af5dfb4) | Sigma | SigmaHQ |
| T1071.001 | [Ursnif Malware C2 URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A932ac737-33ca-4afd-9869-0d48b391fcc9) | Sigma | SigmaHQ |
| T1072 | [Restricted Software Access By SRP](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab4c8da4a-1c12-46b0-8a2b-0a8521d03442) | Sigma | SigmaHQ |
| T1072 | [Suspicious Curl to Jamf Endpoint](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Aa8256685-9736-465b-b159-f25a172d08e8) | Elastic | Elastic detection-rules |
| T1074.001 | [Sensitive File Access followed by Compression](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Aa0fbd7a9-1923-4e05-92df-b484168f17bc) | Elastic | Elastic detection-rules |
| T1074.001 | [Folder Compress To Potentially Suspicious Output Via Compress-Archive Cmdlet](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A85a8e5ba-bd03-4bfb-bbfa-a4409a8f8b98+%23+Process+Creation) | Sigma | SigmaHQ |
| T1082 | [Potential GobRAT File Discovery Via Grep](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae34cfa0c-0a50-4210-9cb3-5632d08eb041) | Sigma | SigmaHQ |
| T1082 | [System Information Discovery](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A42df45e7-e6e9-43b5-8f26-bec5b39cc239) | Sigma | SigmaHQ |
| T1083 | [Turla Group Lateral Movement](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac601f20d-570a-4cde-a7d6-e17f99cb8e7f) | Sigma | SigmaHQ |
| T1083 | [WannaCry Ransomware Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A41d40bff-377a-43e2-8e1b-2e543069e079) | Sigma | SigmaHQ |
| T1087.002 | [BloodHound Collection Files](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A02773bed-83bf-469f-b7ff-e676e7d78bab) | Sigma | SigmaHQ |
| T1087.002 | [Suspicious Active Directory Database Snapshot Via ADExplorer](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aef61af62-bc74-4f58-b49b-626448227652) | Sigma | SigmaHQ |
| T1091 | [New USB Storage Device Mounted](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A483832a8-ffdd-4e11-8e96-e0224f7bda9b) | Elastic | Elastic detection-rules |
| T1091 | [Execution from a Removable Media with Network Connection](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A1542fa53-955e-4330-8e4d-b2d812adeb5f) | Elastic | Elastic detection-rules |
| T1095 | [PUA - Netcat Suspicious Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae31033fc-33f0-4020-9a16-faf9b31cbf08) | Sigma | SigmaHQ |
| T1095 | [Suspicious React Server Child Process](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Aae3e9625-89ad-4fc3-a7bf-fced5e64f01b) | Elastic | Elastic detection-rules |
| T1102 | [Communication To LocaltoNet Tunneling Service Initiated - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac4568f5d-131f-4e78-83d4-45b2da0ec4f1) | Sigma | SigmaHQ |
| T1102 | [Communication To Ngrok Tunneling Service - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A19bf6fdb-7721-4f3d-867f-53467f6a5db6) | Sigma | SigmaHQ |
| T1105 | [Greenbug Espionage Group Indicators](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A3711eee4-a808-4849-8a14-faf733da3612) | Sigma | SigmaHQ |
| T1105 | [Pandemic Registry Key](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A47e0852a-cf81-4494-a8e6-31864f8c86ed) | Sigma | SigmaHQ |
| T1106 | [Turla Group Named Pipes](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A739915e4-1e70-4778-8b8a-17db02f66db1) | Sigma | SigmaHQ |
| T1106 | [BPFDoor Abnormal Process ID or Lock File Accessed](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A808146b2-9332-4d78-9416-d7e47012d83d) | Sigma | SigmaHQ |
| T1119 | [iOS Implant URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Ae06ac91d-b9e6-443d-8e5b-af749e7aa6b6) | Sigma | OpenSearch Security Analytics |
| T1119 | [Shai-Hulud Malicious GitHub Workflow Creation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A0aba5685-6db6-486f-88ef-29a99c545cfd) | Sigma | SigmaHQ |
| T1129 | [Suspicious Execution from Foomatic-rip or Cupsd Parent](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A986361cd-3dac-47fe-afa1-5c5dd89f2fb4) | Elastic | Elastic detection-rules |
| T1129 | [WPS Office Exploitation via DLL Hijack](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Aac6bc744-e82b-41ad-b58d-90654fa4ebfb) | Elastic | Elastic detection-rules |
| T1140 | [UNC4841 - SSL Certificate Exfiltration Via Openssl](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A60911c07-f989-4362-84af-c609828ef829) | Sigma | SigmaHQ |
| T1140 | [UNC4841 - Download Compressed Files From Temp.sh Using Wget](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A60d050c4-e253-4d9a-b673-5ac100cfddfb) | Sigma | SigmaHQ |
| T1203 | [Droppers Exploiting CVE-2017-11882](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A678eb5f4-8597-4be6-8be7-905e4234b53a) | Sigma | SigmaHQ |
| T1203 | [OMIGOD HTTP No Authentication RCE - CVE-2021-38647](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aab6b1a39-a9ee-4ab4-b075-e83acf6e346b) | Sigma | SigmaHQ |
| T1204.001 | [Google Workspace Object Copied from External Drive with App Consent](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Af33e68a4-bd19-11ed-b02f-f661ea17fbcc) | Elastic | Elastic detection-rules |
| T1204.001 | [Suspicious ClickFix/FileFix Execution Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad487ed4a-fd24-436d-a0b2-f4e95f7b2635) | Sigma | SigmaHQ |
| T1204.002 | [Ursnif Malware C2 URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A932ac737-33ca-4afd-9869-0d48b391fcc9) | Sigma | SigmaHQ |
| T1204.002 | [Droppers Exploiting CVE-2017-11882](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A678eb5f4-8597-4be6-8be7-905e4234b53a) | Sigma | SigmaHQ |
| T1205 | [Unusual Linux Network Port Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A3c7e32e6-6104-46d9-a06e-da0f8b5795a0) | Elastic | Elastic detection-rules |
| T1205 | [Potential rootkit activity: insmod command executed](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=socfortress-wazuh-rules%3A%3Awazuh-700003) | Wazuh | SOCFortress Wazuh-Rules |
| T1218.004 | [Possible Applocker Bypass](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A82a19e3a-2bfe-4a91-8c0d-5d4c98fbb719) | Sigma | OpenSearch Security Analytics |
| T1218.004 | [Suspicious PDF Reader Child Process](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A53a26770-9cbd-40c5-8b57-61d01a325e14) | Elastic | Elastic detection-rules |
| T1218.005 | [Potential Baby Shark Malware Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A2b30fa36-3a18-402f-a22d-bf4ce2189f35) | Sigma | SigmaHQ |
| T1218.005 | [Remotely Hosted HTA File Executed Via Mshta.EXE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab98d0db6-511d-45de-ad02-e82a98729620) | Sigma | SigmaHQ |
| T1219.002 | [Antivirus - Exploitation Framework Signature](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A238527ad-3c2c-4e4f-a1f6-92fd63adb864) | Sigma | SigmaHQ |
| T1219.002 | [Potential SocGholish Second Stage C2 DNS Query](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A70761fe8-6aa2-4f80-98c1-a57049c08e66) | Sigma | SigmaHQ |
| T1505.003 | [MOVEit CVE-2023-34362 Exploitation Attempt - Potential Web Shell Request](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A435e41f2-48eb-4c95-8a2b-ed24b50ec30b) | Sigma | SigmaHQ |
| T1505.003 | [Solarwinds SUPERNOVA Webshell Access](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aa2cee20b-eacc-459f-861d-c02e5d12f1db) | Sigma | SigmaHQ |
| T1518 | [HackTool - WinPwn Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad557dc06-62e8-4468-a8e8-7984124908ce) | Sigma | SigmaHQ |
| T1518 | [HackTool - WinPwn Execution - ScriptBlock](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A851fd622-b675-4d26-b803-14bc7baa517a) | Sigma | SigmaHQ |
| T1546.003 | [WMI Persistence - Script Event Consumer File Write](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A33f41cdd-35ac-4ba8-814b-c6a4244a1ad4) | Sigma | SigmaHQ |
| T1546.003 | [NewActiveScriptEventConsumer Creation Attempt via Wmic.EXE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aebef4391-1a81-4761-a40a-1db446c0e625) | Sigma | SigmaHQ |
| T1547.001 | [Potential Ryuk Ransomware Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac37510b8-2107-4b78-aa32-72f251e7a844) | Sigma | SigmaHQ |
| T1547.001 | [Ryuk Ransomware](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Ac37510b8-2107-4b78-aa32-72f251e7a844) | Sigma | OpenSearch Security Analytics |
| T1553.002 | [Driver Loaded (Invalid Signature)](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=hayabusa-native%3A%3A1f666722-3948-40a2-9d78-d9d374477a90) | Sigma | Hayabusa (native) |
| T1553.002 | [Driver Loaded (Expired/Revoked Cert)](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=hayabusa-native%3A%3Ac837dd6d-0c91-4593-aeab-f6a1f3ca1961) | Sigma | Hayabusa (native) |
| T1557 | [ICMP Redirect Message from Internal Host](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A2014ebd8-b847-4cc0-a827-d0d61ec88680) | Elastic | Elastic detection-rules |
| T1557 | [Multiple DHCP Servers Responding to the Same Transaction](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A44b8d933-8fed-485d-a0af-bd97d0093439) | Elastic | Elastic detection-rules |
| T1560.001 | [APT31 Judgement Panda Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A03e2746e-2b31-42f1-ab7a-eb39365b2422) | Sigma | SigmaHQ |
| T1560.001 | [Suspicious Manipulation Of Default Accounts Via Net.EXE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A5b768e71-86f2-4879-b448-81061cbae951) | Sigma | SigmaHQ |
| T1560.003 | [Potential Data Collection in Temporary Directory by Hidden Executable](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-protections-artifacts-behavior%3A%3Aa6994646-d314-4ee0-be1f-1d694dc969e7) | Elastic | Elastic protections-artifacts (behavior) |
| T1564.001 | [Set Suspicious Files as System Files Using Attrib.EXE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aefec536f-72e8-4656-8960-5e85d091345b) | Sigma | SigmaHQ |
| T1564.001 | [PowerShell Logging Disabled Via Registry Key Tampering](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Afecfd1a1-cc78-4313-a1ea-2ee2e8ec27a7) | Sigma | SigmaHQ |
| T1566.001 | [Ursnif Malware C2 URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A932ac737-33ca-4afd-9869-0d48b391fcc9) | Sigma | SigmaHQ |
| T1566.001 | [Droppers Exploiting CVE-2017-11882](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A678eb5f4-8597-4be6-8be7-905e4234b53a) | Sigma | SigmaHQ |
| T1566.002 | [Potential Malicious Usage of CloudTrail System Manager](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A38e7f511-3f74-41d4-836e-f57dfa18eead) | Sigma | SigmaHQ |
| T1566.002 | [Google Workspace Device Registration After OAuth from Suspicious ASN](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A012bfca7-45cb-4507-a3ba-3777167f8b81) | Elastic | Elastic detection-rules |
| T1567.002 | [APT40 Dropbox Tool User Agent](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A5ba715b6-71b7-44fd-8245-f66893e81b3d) | Sigma | SigmaHQ |
| T1567.002 | [PUA - Rclone Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae37db05d-d1f9-49c8-b464-cee1a4b11638) | Sigma | SigmaHQ |
| T1572 | [Communication To LocaltoNet Tunneling Service Initiated - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac4568f5d-131f-4e78-83d4-45b2da0ec4f1) | Sigma | SigmaHQ |
| T1572 | [Communication To Ngrok Tunneling Service - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A19bf6fdb-7721-4f3d-867f-53467f6a5db6) | Sigma | SigmaHQ |
| T1573.001 | [CYFIRMA - High severity Command & Control Network Indicators with Monitor Recommendation Rule](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A6d8fb3fe-2501-4103-8137-34261fa3a596) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1573.001 | [CYFIRMA - High severity Command & Control Network Indicators with Block Recommendation Rule](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A6b61b716-afd9-4f6c-ad00-965d5987cafd) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1574.001 | [Winnti Pipemon Characteristics](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A73d70463-75c9-4258-92c6-17500fe972f2) | Sigma | SigmaHQ |
| T1574.001 | [Winnti Pipemon Characteristics](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A73d70463-75c9-4258-92c6-17500fe972f2) | Sigma | OpenSearch Security Analytics |
| T1574.005 | [HackTool - SharpUp PrivEsc Tool Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac484e533-ee16-4a93-b6ac-f0ea4868b2f1) | Sigma | SigmaHQ |
| T1574.005 | [Setup16.EXE Execution With Custom .Lst File](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A99c8be4f-3087-4f9f-9c24-8c7e257b442e) | Sigma | SigmaHQ |
| T1583.001 | [AWS Route 53 Private Hosted Zone Associated With a VPC](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ae3c27562-709a-42bd-82f2-3ed926cced19) | Elastic | Elastic detection-rules |
| T1583.001 | [AWS SES Email Identity Verified Then Deleted](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A8e4bde35-125d-4eb3-9a2e-d7e77a053a08) | Elastic | Elastic detection-rules |
| T1583.006 | [GitHub Repo Created](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A6cea88e4-6ce2-4238-9981-a54c140d6336) | Elastic | Elastic detection-rules |
| T1583.006 | [Cisco Secure Firewall - Rare Snort Rule Triggered](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=splunk-security-content%3A%3Ae20313d2-7d63-4fcf-b2d9-d6e12c6c7bd7) | Splunk | Splunk security_content |
| T1586.002 | [CYFIRMA - Brand Intelligence - Domain Impersonation High Rule](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A10bdf525-5b89-4a25-933a-e63e73b915f1) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1586.002 | [CYFIRMA - Brand Intelligence - Domain Impersonation Medium Rule](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A8f97ddbe-ab66-4f6c-b675-73b5eeb07259) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1587.001 | [Formbook Process Creation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A032f5fb3-d959-41a5-9263-4173c802dc2b) | Sigma | SigmaHQ |
| T1587.001 | [Uncommon File Created In Office Startup Folder](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aa10a2c40-2c4d-49f8-b557-1a946bc55d9d) | Sigma | SigmaHQ |
| T1588.002 | [Hacktool Execution - Imphash](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A24e3e58a-646b-4b50-adef-02ef935b9fc8) | Sigma | SigmaHQ |
| T1588.002 | [Renamed SysInternals DebugView Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acd764533-2e07-40d6-a718-cfeec7f2da7f) | Sigma | SigmaHQ |
| T1588.003 | [Short-lived ephemeral code signing certificates](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-hunting-queries%3A%3Ae920899f-edf0-446c-bb13-effbaf61b27b) | Sentinel KQL | Microsoft Sentinel (Hunting Queries) |
| T1588.004 | [Cisco Secure Firewall - Blacklisted SSL Certificate Fingerprint](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=splunk-security-content%3A%3Ac43f7b49-2dab-4e76-892e-7f971c2f20f1) | Splunk | Splunk security_content |
| T1593 | [CYFIRMA - Social and Public Exposure -  Social Media Threats  Activity Detected Rule](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A4fe04459-13f1-4ff7-9b7c-f9be0c2aad6d) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1593 | [CYFIRMA - Social and Public Exposure - Confidential Files Information Exposure Rule](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A67e9c4aa-a2fa-4e4e-9272-1a8da41475c6) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1608 | [Suspicious Download from Office Domain](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A00d49ed5-4491-4271-a8db-650a4ef6f8c1) | Sigma | SigmaHQ |
| T1608 | [HybridConnectionManager Service Installation - Registry](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aac8866c7-ce44-46fd-8c17-b24acff96ca8) | Sigma | SigmaHQ |
| T1608.001 | [M365 OneDrive Malware File Upload](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Abba1b212-b85c-41c6-9b28-be0e5cdfc9b1) | Elastic | Elastic detection-rules |
| T1608.001 | [M365 SharePoint Malware File Detected](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A0e52157a-8e96-4a95-a6e3-5faae5081a74) | Elastic | Elastic detection-rules |
| T1622 | [PUA - Process Hacker Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A811e0002-b13b-4a15-9d00-a613fce66e42) | Sigma | SigmaHQ |
| T1622 | [Sysmon - Event 1: Process creation $(win.eventdata.description)](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=socfortress-wazuh-rules%3A%3Awazuh-100697) | Wazuh | SOCFortress Wazuh-Rules |
| T1654 | [Sysmon - Event 1: Process creation $(win.eventdata.description)](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=socfortress-wazuh-rules%3A%3Awazuh-100950) | Wazuh | SOCFortress Wazuh-Rules |
| T1654 | [Sysmon - Event 1: Process creation $(win.eventdata.description)](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=socfortress-wazuh-rules%3A%3Awazuh-100951) | Wazuh | SOCFortress Wazuh-Rules |

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
| Execution | [T1059](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059/T1059.md) | AutoIt Script Execution | windows |
| Execution | [T1059.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md) | Mimikatz | windows |
| Execution | [T1059.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md) | Run BloodHound from local disk | windows |
| Execution | [T1059.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.003/T1059.003.md) | Create and Execute Batch Script | windows |
| Execution | [T1059.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.003/T1059.003.md) | Writes text to a file and displays it. | windows |
| Execution | [T1059.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.005/T1059.005.md) | Visual Basic script execution to gather local computer information | windows |
| Execution | [T1059.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.005/T1059.005.md) | Encoded VBS code execution | windows |
| Execution | [T1059.007](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.007/T1059.007.md) | JScript execution to gather local computer information via cscript | windows |
| Execution | [T1059.007](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.007/T1059.007.md) | JScript execution to gather local computer information via wscript | windows |
| Execution | [T1072](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1072/T1072.md) | Radmin Viewer Utility | windows |
| Execution | [T1072](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1072/T1072.md) | PDQ Deploy RAT | windows |
| Execution | [T1106](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1106/T1106.md) | Execution through API - CreateProcess | windows |
| Execution | [T1106](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1106/T1106.md) | WinPwn - Get SYSTEM shell - Pop System Shell using CreateProcess technique | windows |
| Execution | [T1129](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1129/T1129.md) | ESXi - Install a custom VIB on an ESXi host | windows |
| Execution | [T1204.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1204.002/T1204.002.md) | OSTap Style Macro Execution | windows |
| Execution | [T1204.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1204.002/T1204.002.md) | OSTap Payload Download | windows |
| Persistence | [T1505.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1505.003/T1505.003.md) | Web Shell Written to Disk | windows |
| Persistence | [T1547.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1547.001/T1547.001.md) | Reg Key Run | windows |
| Persistence | [T1547.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1547.001/T1547.001.md) | Reg Key RunOnce | windows |
| Privilege Escalation | [T1546.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1546.003/T1546.003.md) | Persistence via WMI Event Subscription - CommandLineEventConsumer | windows |
| Privilege Escalation | [T1546.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1546.003/T1546.003.md) | Persistence via WMI Event Subscription - ActiveScriptEventConsumer | windows |
| Stealth | [T1027](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027/T1027.md) | Decode base64 Data into Script | linux, macos |
| Stealth | [T1027](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027/T1027.md) | Execute base64-encoded PowerShell | windows |
| Stealth | [T1027.007](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027.007/T1027.007.md) | Dynamic API Resolution-Ninja-syscall | windows |
| Stealth | [T1036.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.005/T1036.005.md) | Execute a process from a directory masquerading as the current parent directory | linux, macos |
| Stealth | [T1036.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.005/T1036.005.md) | Masquerade as a built-in system executable | windows |
| Stealth | [T1070](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070/T1070.md) | Indicator Removal using FSUtil | windows |
| Stealth | [T1070](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070/T1070.md) | Indicator Manipulation using FSUtil | windows |
| Stealth | [T1070.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.004/T1070.004.md) | Delete a single file - FreeBSD/Linux/macOS | linux, macos |
| Stealth | [T1070.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.004/T1070.004.md) | Delete an entire folder - FreeBSD/Linux/macOS | linux, macos |
| Stealth | [T1070.006](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.006/T1070.006.md) | Set a file's access timestamp | linux, macos |
| Stealth | [T1070.006](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.006/T1070.006.md) | Set a file's modification timestamp | linux, macos |
| Stealth | [T1140](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1140/T1140.md) | Deobfuscate/Decode Files Or Information | windows |
| Stealth | [T1140](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1140/T1140.md) | Certutil Rename and Decode | windows |
| Stealth | [T1218.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.004/T1218.004.md) | CheckIfInstallable method call | windows |
| Stealth | [T1218.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.004/T1218.004.md) | InstallHelper method call | windows |
| Stealth | [T1218.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.005/T1218.005.md) | Mshta executes JavaScript Scheme Fetch Remote Payload With GetObject | windows |
| Stealth | [T1218.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.005/T1218.005.md) | Mshta executes VBScript to execute malicious command | windows |
| Stealth | [T1564.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1564.001/T1564.001.md) | Create a hidden file in a hidden directory | linux, macos |
| Stealth | [T1564.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1564.001/T1564.001.md) | Mac Hidden file | macos |
| Stealth | [T1574.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1574.001/T1574.001.md) | DLL Search Order Hijacking - amsi.dll | windows |
| Stealth | [T1574.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1574.001/T1574.001.md) | Phantom Dll Hijacking - WinAppXRT.dll | windows |
| Stealth | [T1622](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1622/T1622.md) | Detect a Debugger Presence in the Machine | windows |
| Credential Access | [T1003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003/T1003.md) | Gsecdump | windows |
| Credential Access | [T1003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003/T1003.md) | Credential Dumping with NPPSpy | windows |
| Credential Access | [T1003.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/T1003.001.md) | Dump LSASS.exe Memory using ProcDump | windows |
| Credential Access | [T1003.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/T1003.001.md) | Dump LSASS.exe Memory using comsvcs.dll | windows |
| Credential Access | [T1003.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.003/T1003.003.md) | Create Volume Shadow Copy with vssadmin | windows |
| Credential Access | [T1003.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.003/T1003.003.md) | Copy NTDS.dit from Volume Shadow Copy | windows |
| Credential Access | [T1003.006](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.006/T1003.006.md) | DCSync (Active Directory) | windows |
| Credential Access | [T1003.006](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.006/T1003.006.md) | Run DSInternals Get-ADReplAccount | windows |
| Discovery | [T1016](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1016/T1016.md) | System Network Configuration Discovery on Windows | windows |
| Discovery | [T1016](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1016/T1016.md) | List Windows Firewall Rules | windows |
| Discovery | [T1018](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1018/T1018.md) | Remote System Discovery - net | windows |
| Discovery | [T1018](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1018/T1018.md) | Remote System Discovery - net group Domain Computers | windows |
| Discovery | [T1046](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1046/T1046.md) | Port Scan | linux, macos |
| Discovery | [T1046](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1046/T1046.md) | Port Scan Nmap | linux, macos |
| Discovery | [T1049](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1049/T1049.md) | System Network Connections Discovery | windows |
| Discovery | [T1049](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1049/T1049.md) | System Network Connections Discovery with PowerShell | windows |
| Discovery | [T1057](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1057/T1057.md) | Process Discovery - ps | linux, macos |
| Discovery | [T1057](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1057/T1057.md) | Process Discovery - tasklist | windows |
| Discovery | [T1069.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1069.002/T1069.002.md) | Basic Permission Groups Discovery Windows (Domain) | windows |
| Discovery | [T1069.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1069.002/T1069.002.md) | Permission Groups Discovery PowerShell (Domain) | windows |
| Discovery | [T1082](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1082/T1082.md) | System Information Discovery | windows |
| Discovery | [T1082](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1082/T1082.md) | System Information Discovery | macos |
| Discovery | [T1083](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1083/T1083.md) | File and Directory Discovery (cmd.exe) | windows |
| Discovery | [T1083](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1083/T1083.md) | File and Directory Discovery (PowerShell) | windows |
| Discovery | [T1087.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1087.002/T1087.002.md) | Enumerate all accounts (Domain) | windows |
| Discovery | [T1087.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1087.002/T1087.002.md) | Enumerate all accounts via PowerShell (Domain) | windows |
| Discovery | [T1518](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1518/T1518.md) | Find and Display Internet Explorer Browser Version | windows |
| Discovery | [T1518](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1518/T1518.md) | Applications Installed | windows |
| Discovery | [T1654](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1654/T1654.md) | Get-EventLog To Enumerate Windows Security Log | windows |
| Discovery | [T1654](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1654/T1654.md) | Enumerate Windows Security Log via WevtUtil | windows |
| Lateral Movement | [T1091](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1091/T1091.md) | USB Malware Spread Simulation | windows |
| Collection | [T1074.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1074.001/T1074.001.md) | Stage data from Discovery.bat | windows |
| Collection | [T1074.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1074.001/T1074.001.md) | Stage data from Discovery.sh | linux, macos |
| Collection | [T1119](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1119/T1119.md) | Automated Collection Command Prompt | windows |
| Collection | [T1119](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1119/T1119.md) | Automated Collection PowerShell | windows |
| Collection | [T1560.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1560.001/T1560.001.md) | Compress Data for Exfiltration With Rar | windows |
| Collection | [T1560.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1560.001/T1560.001.md) | Compress Data and lock with password for Exfiltration with winrar | windows |
| Command and Control | [T1071.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1071.001/T1071.001.md) | Malicious User Agents - Powershell | windows |
| Command and Control | [T1071.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1071.001/T1071.001.md) | Malicious User Agents - CMD | windows |
| Command and Control | [T1095](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1095/T1095.md) | ICMP C2 | windows |
| Command and Control | [T1095](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1095/T1095.md) | Netcat C2 | windows |
| Command and Control | [T1105](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1105/T1105.md) | rsync remote file copy (push) | linux, macos |
| Command and Control | [T1105](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1105/T1105.md) | rsync remote file copy (pull) | linux, macos |
| Command and Control | [T1572](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1572/T1572.md) | DNS over HTTPS Large Query Volume | windows |
| Command and Control | [T1572](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1572/T1572.md) | DNS over HTTPS Regular Beaconing | windows |
| Exfiltration | [T1041](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1041/T1041.md) | C2 Data Exfiltration | windows |
| Exfiltration | [T1041](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1041/T1041.md) | Text Based Data Exfiltration using DNS subdomains | windows |
| Exfiltration | [T1048.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1048.003/T1048.003.md) | Exfiltration Over Alternative Protocol - HTTP | linux, macos |
| Exfiltration | [T1048.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1048.003/T1048.003.md) | Exfiltration Over Alternative Protocol - ICMP | windows |
| Exfiltration | [T1567.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1567.002/T1567.002.md) | Exfiltrate data with rclone to cloud Storage - Mega (Windows) | windows |
| Exfiltration | [T1567.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1567.002/T1567.002.md) | Exfiltrate data with rclone to cloud Storage - AWS S3 | linux, macos |

**Logs reais de ataque (EVTX) para testar sem executar nada:**

- T1003 — [ID1-12-13-Wdigest authentication activation](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0006-Credential%20Access/T1003-Credential%20dumping/ID1-12-13-Wdigest%20authentication%20activation.evtx) _(explícito)_
- T1003 — [ID1-LSASS dump with LSASSY (SYSMON)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0006-Credential%20Access/T1003-Credential%20dumping/ID1-LSASS%20dump%20with%20LSASSY%20%28SYSMON%29.evtx) _(explícito)_
- T1003.001 — [CA_hashdump_4663_4656_lsass_access](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Credential%20Access/CA_hashdump_4663_4656_lsass_access.evtx) _(inferido)_
- T1003.001 — [LsassSilentProcessExit_process_exit_monitor_3001_lsass](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Credential%20Access/LsassSilentProcessExit_process_exit_monitor_3001_lsass.evtx) _(inferido)_
- T1003.003 — [dc_applog_ntdsutil_dfir_325_326_327](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Credential%20Access/dc_applog_ntdsutil_dfir_325_326_327.evtx) _(inferido)_
- T1003.003 — [LM_regsvc_DirectoryServiceExtPt_Lsass_NTDS_AdamXpn](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Lateral%20Movement/LM_regsvc_DirectoryServiceExtPt_Lsass_NTDS_AdamXpn.evtx) _(inferido)_
- T1003.006 — [CA_DCSync_4662](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Credential%20Access/CA_DCSync_4662.evtx) _(inferido)_
- T1003.006 — [DACL_DCSync_Right_Powerview_ Add-DomainObjectAcl](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Persistence/DACL_DCSync_Right_Powerview_%20Add-DomainObjectAcl.evtx) _(inferido)_
- T1016 — [ID4688-Audit policy enumerated](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1016-System%20Network%20Configuration%20Discovery/ID4688-Audit%20policy%20enumerated.evtx) _(explícito)_
- T1016 — [ID4688-Firewall configuration enumerated (command)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1016-System%20Network%20Configuration%20Discovery/ID4688-Firewall%20configuration%20enumerated%20%28command%29.evtx) _(explícito)_
- T1018 — [ID5145-DNS hosts files access via network share](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1018-Remote%20System%20Discovery/ID5145-DNS%20hosts%20files%20access%20via%20network%20share.evtx) _(explícito)_
- T1027 — [4624,4674,4688- CrackMap Exec SMB mimikatz](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0005-Defense%20Evasion/T1027-Obfuscated%20Files%20or%20Information/4624%2C4674%2C4688-%20CrackMap%20Exec%20SMB%20mimikatz.evtx) _(explícito)_
- T1027 — [ID1-CrackMapExec payload execution](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0005-Defense%20Evasion/T1027-Obfuscated%20Files%20or%20Information/ID1-CrackMapExec%20payload%20execution.evtx) _(explícito)_
- T1046 — [ID131-RDP brutforce (no user info)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1046-Network%20Service%20Scanning/ID131-RDP%20brutforce%20%28no%20user%20info%29.evtx) _(explícito)_
- T1046 — [ID4624-Anonymous login with domain specified (DonPapi)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1046-Network%20Service%20Scanning/ID4624-Anonymous%20login%20with%20domain%20specified%20%28DonPapi%29.evtx) _(explícito)_
- T1047 — [ID1-WMI spwaning PowerShell process - WMImplant](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1047-Windows%20Management%20Instrumentation/ID1-WMI%20spwaning%20PowerShell%20process%20-%20WMImplant.evtx) _(explícito)_
- T1047 — [ID1-WMIexec process execution](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1047-Windows%20Management%20Instrumentation/ID1-WMIexec%20process%20execution.evtx) _(explícito)_
- T1053.005 — [ID4688-4698 Persistent scheduled task with SYSTEM privileges creation](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1053.005-Scheduled%20Task/ID4688-4698%20Persistent%20scheduled%20task%20with%20SYSTEM%20privileges%20creation.evtx) _(explícito)_
- T1053.005 — [ID4688-Interactive shell using AT schedule task](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1053.005-Scheduled%20Task/ID4688-Interactive%20shell%20using%20AT%20schedule%20task.evtx) _(explícito)_
- T1059.001 — [ID4103-4104-Payload download via PowerShell](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1059.001-PowerShell/ID4103-4104-Payload%20download%20via%20PowerShell.evtx) _(explícito)_
- T1059.001 — [ID4688-Encoded PowerShell MSF payload via process execution](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1059.001-PowerShell/ID4688-Encoded%20PowerShell%20MSF%20payload%20via%20process%20execution.evtx) _(explícito)_
- T1059.003 — [ID4688-SQL Server payload injectection for reverse shell (MSF)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1059.003-Windows%20Command%20Shell/ID4688-SQL%20Server%20payload%20injectection%20for%20reverse%20shell%20%28MSF%29.evtx) _(explícito)_
- T1070.006 — [ID4616-system time changed](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0005-Defense%20Evasion/T1070.006-Timestomp/ID4616-system%20time%20changed.evtx) _(explícito)_
- T1070.006 — [DE_timestomp_and_dll_sideloading_and_RunPersist](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/AutomatedTestingTools/Malware/DE_timestomp_and_dll_sideloading_and_RunPersist.evtx) _(inferido)_
- T1087.002 — [discovery_bloodhound](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Discovery/discovery_bloodhound.evtx) _(inferido)_

## 9. Hipóteses de hunting

Se Mustang Panda estiver no seu ambiente, estas são as perguntas a fazer aos seus dados (fontes de log segundo as estratégias de detecção do MITRE ATT&CK).

1. **T1129 Shared Modules** — A process (often LOLBin or user-launched program) loads a DLL from a user-writable/UNC/Temp path or unsigned/invalid signer. Within a short window the DLL is (a) newly written to disk, (b) spawned as follow-on execution (rundll32/regsvr32), or (c) establishes… Dados: `WinEventLog:Sysmon` (EventCode=7), `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Security` (EventCode=4688).
2. **T1219.001 IDE Tunneling** — Detection of the creation of VSCode or JetBrains CLI tunneling profiles followed by persistent remote access via IDE-integrated tunnels, potentially authenticated via GitHub or JetBrains accounts. Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=11), `NSM:Flow` (Outbound connection to *.tunnels.api.visualstudio.com or *.devtunnels.ms).
3. **T1574.005 Executable Installer File Permissions Weakness** — Executables written or modified in installer directories (e.g., %TEMP% subdirectories or Program Files installer paths) followed by execution under elevated context. Defender observes abnormal file replacement activity, process creation by installer processes… Dados: `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Sysmon` (EventCode=15), `WinEventLog:Sysmon` (EventCode=1).
4. **T1608 Stage Capabilities** — If infrastructure or patterns in malware, tooling, certificates, or malicious web content have been previously identified, internet scanning may uncover when an adversary has staged their capabilities. Much of this activity will take place outside the… Dados: `Internet Scan` (None).
5. **T1622 Debugger Evasion** — Monitor for suspicious use of Windows API calls such as IsDebuggerPresent() and NtQueryInformationProcess(), or processes manually checking the BeingDebugged flag in the Process Environment Block (PEB). Detect sequences of OutputDebugStringW() calls in short… Dados: `WinEventLog:Sysmon` (EventCode=1), `etw:Microsoft-Windows-Kernel-Process` (NtQueryInformationProcess).
6. **T1036.007 Double File Extension** — Detects adversary behavior where a file with a benign-looking first extension (e.g., .txt, .jpg) ends with a dangerous second extension (e.g., .exe, .scr), and is subsequently executed. The behavior chain includes file creation with misleading naming and user… Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=11).
7. **T1052.001 Exfiltration over USB** — Detects USB device insertion followed by high-volume or sensitive file access and staging activity by suspicious processes or accounts. Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Security` (EventCode=4663, 4670, 4656).
8. **T1176.002 IDE Extensions** — Adversary installs or side-loads an IDE extension (VS Code, IntelliJ/JetBrains, Eclipse) or enables IDE tunneling. Chain: (1) IDE binary starts on a non-developer endpoint or server, often with install/force/tunnel flags → (2) extension files/registrations… Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=3, 22), `WinEventLog:Sysmon` (EventCode=11).
9. **T1218.004 InstallUtil** — Execution of InstallUtil.exe from .NET framework directories with arguments specifying non-standard or attacker-supplied assemblies, especially when followed by suspicious child process creation or script execution. Detection also includes correlation of… Dados: `WinEventLog:PowerShell` (EventCode=4103, 4104, 4105, 4106), `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=11).
10. **T1001.003 Protocol or Service Impersonation** — Untrusted processes creating outbound TLS/HTTPS connections with malformed certificates or header fields, often mismatched with target service behavior. Detects protocol impersonation attempts via traffic metadata analysis and host process lineage. Dados: `WinEventLog:Sysmon` (EventCode=3, 22), `NSM:Flow` (SSL/TLS Handshake Analysis).
11. **T1027.007 Dynamic API Resolution** — Behavioral chain involving suspicious use of GetProcAddress and LoadLibrary following memory allocation and manual mapping, often paired with low entropy strings, abnormal API use without static import tables, or delayed module load behaviors. Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=7), `etw:Microsoft-Windows-Kernel-Process` (API tracing / stack tracing via ETW or telemetry-based EDR).
12. **T1027.012 LNK Icon Smuggling** — Correlates LNK file execution with embedded resource extraction or suspicious network activity following initial launch, often leading to payload delivery via disguised icons. Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=15), `WinEventLog:Sysmon` (EventCode=3, 22).

## 10. OSINT — onde pesquisar

Consultas prontas com todos os nomes conhecidos do grupo:

- Relatórios técnicos: [busca web](https://duckduckgo.com/?q=%28%22Mustang+Panda%22+OR+%22TA416%22+OR+%22RedDelta%22+OR+%22BRONZE+PRESIDENT%22+OR+%22STATELY+TAURUS%22+OR+%22FIREANT%22%29+threat+report) · [PDFs](https://duckduckgo.com/?q=%28%22Mustang+Panda%22+OR+%22TA416%22+OR+%22RedDelta%22+OR+%22BRONZE+PRESIDENT%22+OR+%22STATELY+TAURUS%22+OR+%22FIREANT%22%29+filetype%3Apdf)
- Regras e IOCs publicados: [GitHub](https://github.com/search?type=code&q=%22Mustang+Panda%22+OR+%22TA416%22+OR+%22RedDelta%22+OR+%22BRONZE+PRESIDENT%22+OR+%22STATELY+TAURUS%22+OR+%22FIREANT%22)
- Pulsos de ameaça: [AlienVault OTX](https://otx.alienvault.com/browse/global/pulses?q=Mustang+Panda)
- Família de malware e atores: [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/actors) (busque por Mustang Panda, TA416, RedDelta)
- Cartões de grupo: [ThaiCERT Threat Group Cards](https://apt.etda.or.th/cgi-bin/listgroups.cgi)
- Página oficial: [MITRE ATT&CK G0129](https://attack.mitre.org/groups/G0129/)

**Relatórios na coleção CyberMonitor** (ligados pelo nome do grupo, conferir antes de citar):

- 2018 — [Mustang Panda _ Threat Actor Profile _ CrowdStrike](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2018/2018.06.15.Mustang_Panda/Mustang%20Panda%20_%20Threat%20Actor%20Profile%20_%20CrowdStrike.pdf) _(via “Mustang Panda”)_
- 2019 — [China-Based APT Mustang Panda Targets Minority Groups, Public and Private Sector Organizations](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2019/2019.10.07.Panda_minority-groups/China-Based%20APT%20Mustang%20Panda%20Targets%20Minority%20Groups%2C%20Public%20and%20Private%20Sector%20Organizations.pdf) _(via “Mustang Panda”)_
- 2019 — [BRONZE PRESIDENT Targets NGOs](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2019/2019.12.29_BRONZE_PRESIDENT_NGO/BRONZE%20PRESIDENT%20Targets%20NGOs.pdf) _(via “BRONZE PRESIDENT”)_
- 2020 — [cta-2020-0728](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2020/2020.07.28.RedDelta_APT/cta-2020-0728.pdf) _(via “RedDelta”)_
- 2022 — [The Good, the Bad, and the Web Bug_ TA416 Increases Operational Tempo Against European Governments as Conflict in Ukrain](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2022/2022.03.07.TA416/The%20Good%2C%20the%20Bad%2C%20and%20the%20Web%20Bug_%20TA416%20Increases%20Operational%20Tempo%20Against%20European%20Governments%20as%20Conflict%20in%20Ukraine%20Escalates%20_%20Proofpoint%20US.pdf) _(via “TA416”)_
- 2022 — [Cisco Talos Intelligence Group - Comprehensive Threat Intelligence_ Mustang Panda deploys a new wave of malware targetin](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2022/2022.05.05.Mustang_Panda_Europe/Cisco%20Talos%20Intelligence%20Group%20-%20Comprehensive%20Threat%20Intelligence_%20Mustang%20Panda%20deploys%20a%20new%20wave%20of%20malware%20targeting%20Europe.pdf) _(via “Mustang Panda”)_
- 2022 — [BRONZE PRESIDENT Targets Government Officials _ Secureworks](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2022/2022.09.08.BRONZE_PRESIDENT/BRONZE%20PRESIDENT%20Targets%20Government%20Officials%20_%20Secureworks.pdf) _(via “BRONZE PRESIDENT”)_
- 2022 — [Mustang Panda Abuses Legitimate Apps to Target Myanmar Based Victims](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2022/2022.10.06.Mustang_Panda_Myanmar/Mustang%20Panda%20Abuses%20Legitimate%20Apps%20to%20Target%20Myanmar%20Based%20Victims.pdf) _(via “Mustang Panda”)_
- 2022 — [Mustang Panda Uses the Russian-Ukrainian War to Attack Europe and Asia Pacific Targets](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2022/2022.12.06.Mustang_Panda/Mustang%20Panda%20Uses%20the%20Russian-Ukrainian%20War%20to%20Attack%20Europe%20and%20Asia%20Pacific%20Targets.pdf) _(via “Mustang Panda”)_

## 11. Bibliografia (38 fontes citadas pelo ATT&CK)

- [2022 November_TrendMicro_Earth Preta_Toneshell_Pubload](https://www.trendmicro.com/en_us/research/22/k/earth-preta-spear-phishing-governments-worldwide.html) — Nick Dai, Vickie Su, Sunny Lu. (2022, November 18). Earth Preta Spear-Phishing Governments Worldwide. Retrieved August 4, 2025.
- [2025_IBM_PUBLOAD_TONESHELL_HIUPAN_CLAIMLOADER_MUSTANG PANDA](https://www.ibm.com/think/x-force/hive0154-targeting-us-philippines-pakistan-taiwan) — Golo Muhr, Joshua Chung. (2025, May 15). Hive0154 targeting US, Philippines, Pakistan and Taiwan in suspected espionage campaign. Retrieved August 4, 2025.
- [Anomali MUSTANG PANDA October 2019](https://www.anomali.com/blog/china-based-apt-mustang-panda-targets-minority-groups-public-and-private-sector-organizations) — Anomali Threat Research. (2019, October 7). China-Based APT Mustang Panda Targets Minority Groups, Public and Private Sector Organizations. Retrieved April 12, 2021.
- [ATTACKIQ MUSTANG PANDA TONESHELL March 2023](https://www.attackiq.com/2023/03/23/emulating-the-politically-motivated-chinese-apt-mustang-panda/) — Ken Towne, Francis Guibernau. (2023, March 23). Emulating the Politically Motivated Chinese APT Mustang Panda. Retrieved September 10, 2025.
- [Avira Mustang Panda January 2020](https://www.avira.com/en/blog/new-wave-of-plugx-targets-hong-kong) — Hamzeloofard, S. (2020, January 31). New wave of PlugX targets Hong Kong | Avira Blog. Retrieved April 13, 2021.
- [BlackBerry MUSTANG PANDA October 2022](https://blogs.blackberry.com/en/2022/10/mustang-panda-abuses-legitimate-apps-to-target-myanmar-based-victims) — The BlackBerry Research and Intelligence Team. (2022, October 6). Mustang Panda Abuses Legitimate Apps to Target Myanmar Based Victims. Retrieved October 14, 2025.
- [Broadcom](https://www.broadcom.com/support/security-center/protection-bulletin/bookworm-malware-linked-to-fireant-aka-stately-tarurus-activity-observed-in-southeast-asia) — Broadcom Protection Bulletins. (2025, February 20). Bookworm malware linked to Fireant (aka Stately Tarurus) activity observed in Southeast Asia. Retrieved July 21, 2025.
- [Cisco Talos MUSTANG PANDA PLUGX PUBLOAD MAY 2022](https://blog.talosintelligence.com/mustang-panda-targets-europe/) — Asheer Malhotra, Jungsoo An, Kendall Mc. (2022, May 5). Mustang Panda deploys a new wave of malware targeting Europe. Retrieved August 4, 2025.
- [Cloudflare 2026 Threat Report New Threat Actors March 2026](https://blog.cloudflare.com/2026-threat-report/) — Cloudflare. (2026, March 3). Introducing the 2026 Cloudflare Threat Report. Retrieved April 18, 2026.
- [Crowdstrike MUSTANG PANDA June 2018](https://www.crowdstrike.com/blog/meet-crowdstrikes-adversary-of-the-month-for-june-mustang-panda/) — Meyers, A. (2018, June 15). Meet CrowdStrike’s Adversary of the Month for June: MUSTANG PANDA. Retrieved April 12, 2021.
- [CSIRT CTI MUSTANG PANDA PUBLOAD TONESHELL JAN 2024](https://csirt-cti.net/2024/01/23/stately-taurus-targets-myanmar/) — CSIRT CTI. (2024, January 23). Stately Taurus Targets Myanmar Amidst Concerns over Military Junta’s Handling of Rebel Attacks. Retrieved August 4, 2025.
- [DOJ Affidavit Search and Seizure PlugX December 2024](https://www.justice.gov/archives/opa/media/1384136/dl) — DOJ. (2024, December 20). Mag. No. 24-mj-1387 AFFIDAVIT IN SUPPORT OF AN APPLICATION FOR A NINTH SEARCH AND SEIZURE WARRANT- IN THE MATTER OF THE SEARCH AND SEIZURE OF COMPUTERS IN THE UNITED STATES INFECTED WITH PLUGX M
- [EclecticIQ Mustang Panda PlugX](https://blog.eclecticiq.com/mustang-panda-apt-group-uses-european-commission-themed-lure-to-deliver-plugx-malware) — EclecticIQ Threat Research Team. (2023, February 2). Mustang Panda APT Group Uses European Commission-Themed Lure to Deliver PlugX Malware. Retrieved September 9, 2025.
- [Eset PlugX Korplug Mustang Panda March 2022](https://www.welivesecurity.com/2022/03/23/mustang-panda-hodur-old-tricks-new-korplug-variant/) — Alexandre Cote Cyr. (2022, March 23). Mustang Panda’s Hodur: Old tricks, new Korplug variant. Retrieved September 9, 2025.
- [Google TAG Ukraine Threat Landscape March 2022](https://blog.google/threat-analysis-group/update-threat-landscape-ukraine) — Huntley, S. (2022, March 7). An update on the threat landscape. Retrieved March 16, 2022.
- [Google Threat Intelligence Group MUSTANG PANDA PLUGX August 2025](https://cloud.google.com/blog/topics/threat-intelligence/prc-nexus-espionage-targets-diplomats) — Patrick Whitsell. (2025, August 25). Deception in Depth: PRC-Nexus Espionage Campaign Hijacks Web Traffic to Target Diplomats. Retrieved September 9, 2025.
- [HorseShell](https://research.checkpoint.com/2023/the-dragon-who-sold-his-camaro-analyzing-custom-router-implant/) — Cohen, Itay. Madej, Radoslaw. Threat Intelligence Team. (2023, May 16). THE DRAGON WHO SOLD HIS CAMARO: ANALYZING CUSTOM ROUTER IMPLANT. Retrieved December 26, 2023.
- [IBM MUSTANG PANDA PUBLOAD CLAIMLOADER JUNE 2025](https://www.ibm.com/think/x-force/hive0154-mustang-panda-shifts-focus-tibetan-community-deploy-pubload-backdoor) — Golo Muhr, Joshua Chung. (2025, June 23). Hive0154 aka Mustang Panda shifts focus on Tibetan community to deploy Pubload backdoor. Retrieved August 4, 2025.
- [Lab52 MUSTANG PANDA PUBLOAD MAY 2023](https://lab52.io/blog/new-mustang-pandas-campaing-against-australia/) — Dex. (n.d.). New Mustang Panda’s campaing against Australia. Retrieved August 4, 2025.
- [McAfee Dianxun March 2021](https://www.mcafee.com/enterprise/en-us/assets/reports/rp-operation-dianxun.pdf) — Roccia, T., Seret, T., Fokker, J. (2021, March 16). Technical Analysis of Operation Dianxun. Retrieved April 13, 2021.
- [Microsoft Naming Conventions Frequently Updated](https://learn.microsoft.com/en-us/unified-secops-platform/microsoft-threat-actor-naming) — Microsoft. (2025, September 8). How Microsoft names threat actors. Retrieved September 10, 2025.
- [Palo Alto Networks, Unit 42](https://unit42.paloaltonetworks.com/stately-taurus-uses-bookworm-malware/) — Robert Falcone. (2025, February 20). Stately Taurus Activity in Southeast Asia Links to Bookworm Malware. Retrieved July 21, 2025.
- [Palo Alto Unit42 STATELY TAURUS TONESHELL September 2023](https://unit42.paloaltonetworks.com/stately-taurus-attacks-se-asian-government/) — Lior Rochberger, Tom Fakterman, Robert Falcone. (2023, September 22). Cyberespionage Attacks Against Southeast Asian Government Linked to Stately Taurus, Aka Mustang Panda. Retrieved September 9, 2025.
- [PaloAlto MUSTANG PANDA PUBLOAD MARCH 2024](https://unit42.paloaltonetworks.com/chinese-apts-target-asean-entities/) — Unit42. (2024, March 26). ASEAN Entities in the Spotlight: Chinese APT Group Targeting. Retrieved August 4, 2025.
- [Proofpoint TA416 Europe March 2022](https://www.proofpoint.com/us/blog/threat-insight/good-bad-and-web-bug-ta416-increases-operational-tempo-against-european) — Raggi, M. et al. (2022, March 7). The Good, the Bad, and the Web Bug: TA416 Increases Operational Tempo Against European Governments as Conflict in Ukraine Escalates. Retrieved March 16, 2022.
- [Proofpoint TA416 November 2020](https://www.proofpoint.com/us/blog/threat-insight/ta416-goes-ground-and-returns-golang-plugx-malware-loader) — Proofpoint Threat Research Team. (2020, November 23). TA416 Goes to Ground and Returns with a Golang PlugX Malware Loader. Retrieved April 13, 2021.
- [PWC UK MUSTANG PANDA RED LICH February 2021](https://www.pwc.co.uk/cyber-security/pdf/pwc-cyber-threats-2020-a-year-in-retrospect.pdf) — PWC UK. (2021, February 28). Cyber Threats 2020: A Year in Retrospect. Retrieved October 15, 2025.
- [Recorded Future REDDELTA July 2020](https://go.recordedfuture.com/hubfs/reports/cta-2020-0728.pdf) — Insikt Group. (2020, July 28). CHINESE STATE-SPONSORED GROUP ‘REDDELTA’ TARGETS THE VATICAN AND CATHOLIC ORGANIZATIONS. Retrieved April 13, 2021.
- [Secureworks BRONZE PRESIDENT December 2019](https://www.secureworks.com/research/bronze-president-targets-ngos) — Counter Threat Unit Research Team. (2019, December 29). BRONZE PRESIDENT Targets NGOs. Retrieved April 13, 2021.
- [Sophos Mustang Panda PLUGX](https://www.secureworks.com/blog/bronze-president-targets-government-officials) — Secureworks Counter Threat Unit Research Team. (2022, September 8). BRONZE PRESIDENT Targets Government Officials. Retrieved September 9, 2025.
- [Sophos PlugX September 2022](https://www.secureworks.com/blog/bronze-president-targets-russian-speakers-with-updated-plugx) — Secureworks Counter Threat Unit Research Team. (2022, April 27). BRONZE PRESIDENT Targets Russian Speakers with Updated PlugX. Retrieved September 9, 2025.
- [Trend Micro Mustang Panda Earth Preta Toneshell February 2025](https://www.trendmicro.com/en_us/research/25/b/earth-preta-mixes-legitimate-and-malicious-components-to-sidestep-detection.html) — Nathaniel Morales, Nick Dai. (2025, February 18). Earth Preta Mixes Legitimate and Malicious Components to Sidestep Detection. Retrieved September 10, 2025.
- [Trend Micro Mustang Panda Earth Preta TONESHELL June 2023](https://www.trendmicro.com/en_us/research/23/f/behind-the-scenes-unveiling-the-hidden-workings-of-earth-preta.html) — Sunny Lu, Vickie Su, Nick Dai. (2023, June 14). Behind the Scenes: Unveiling the Hidden Workings of Earth Preta. Retrieved September 10, 2025.
- [Trend Micro MUSTANG PANDA PUBLOAD HIUPAN SEPTEMBER 2024](https://www.trendmicro.com/en_us/research/24/i/earth-preta-new-malware-and-strategies.html) — Lenart Bermejo, Sunny Lu, Ted Lee. (2024, September 9). Earth Preta Evolves its Attacks with New Malware and Strategies. Retrieved August 4, 2025.
- [Unit42 Bookworm Nov2015](https://unit42.paloaltonetworks.com/bookworm-trojan-a-model-of-modular-architecture/) — Robert Falcone, Mike Scott, Juan Cortes. (2015, November 10). Bookworm Trojan: A Model of Modular Architecture. Retrieved July 21, 2025.
- [Unit42 Chinese VSCode 06 September 2024](https://unit42.paloaltonetworks.com/stately-taurus-abuses-vscode-southeast-asian-espionage/) — Tom Fakterman. (2024, September 6). Chinese APT Abuses VSCode to Target Government in Asia. Retrieved March 24, 2025.
- [Zscaler](https://www.zscaler.com/blogs/security-research/latest-mustang-panda-arsenal-toneshell-and-starproxy-p1) — Sudeep Singh. (2025, April 16). Latest Mustang Panda Arsenal: ToneShell and StarProxy | P1. Retrieved July 21, 2025.
- [Zscaler PAKLOG CorkLog SplatCloak Splatdropper April 2025](https://www.zscaler.com/blogs/security-research/latest-mustang-panda-arsenal-paklog-corklog-and-splatcloak-p2) — Sudeep Singh. (2025, April 16). Latest Mustang Panda Arsenal: PAKLOG, CorKLOG, and SplatCloak | P2. Retrieved September 12, 2025.

## 12. Limites e confiança

- O ATT&CK registra o que foi **relatado publicamente**, não tudo o que o grupo faz. Ausência de uma técnica não prova que o grupo não a usa.
- **Sobreposição de TTP não é atribuição.** Muitas técnicas são compartilhadas entre grupos e com red teams. Use a assinatura comportamental como hipótese, junto com infraestrutura, malware e contexto.
- Cobertura de detecção refere-se ao catálogo público Detection Rules, não ao seu ambiente: confira se a telemetria necessária chega ao seu SIEM.
- Ligações marcadas como _inferidas_ (EVTX por palavra-chave, relatórios por nome) devem ser verificadas.

---
Fontes: MITRE ATT&CK® (uso livre com atribuição, © The MITRE Corporation), Atomic Red Team (Red Canary, MIT), EVTX-to-MITRE-Attack, EVTX-ATTACK-SAMPLES, APT & CyberCriminal Campaign Collections. Gerado por [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules).
