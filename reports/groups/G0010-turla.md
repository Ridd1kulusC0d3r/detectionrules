# Turla (G0010) — Dossiê de inteligência

> **TLP:CLEAR** · gerado em 2026-10-25 a partir de fontes abertas · MITRE ATT&CK v20.0 · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0010) · [ATT&CK](https://attack.mitre.org/groups/G0010/)

**Também conhecido como:** IRON HUNTER, Group 88, Waterbug, WhiteBear, Snake, Krypton, Venomous Bear, Secret Blizzard, BELUGASTURGEON  
**Registro no ATT&CK:** criado em 2017-05-31, atualizado em 2026-07-31 · referências de 2013 a 2024

## 1. Sumário executivo

- **68 técnicas** atribuídas publicamente, concentradas em **Discovery, Stealth, Privilege Escalation**.
- **Arsenal:** 17 malware e 13 ferramentas (ex.: Empire, Uroburos, Kazuar, LunarWeb, Epic).
- **Campanhas atribuídas:** 0.
- **Cobertura de detecção pública:** 96% das técnicas têm ao menos uma regra no catálogo; **3 técnicas sem nenhuma regra pública**.
- **Assinatura comportamental** (técnicas raras entre os 178 grupos, as mais úteis para atribuição): T1546.013 PowerShell Profile, T1615 Group Policy Discovery, T1027.011 Fileless Storage, T1134.002 Create Process with Token, T1553.006 Code Signing Policy Modification.

## 2. Quem é

> Turla is a cyber espionage threat group that has been attributed to Russia's Federal Security Service (FSB). They have compromised victims in over 50 countries since at least 2004, spanning a range of industries including government, embassies, military, education, research and pharmaceutical companies. Turla is known for conducting watering hole and spearphishing campaigns, and leveraging in-house tools and malware, such as Uroburos.

_Texto original do MITRE ATT&CK, em inglês._

## 3. Perfil TTP por tática (kill chain)

Cada linha: técnica, como o grupo a usou segundo relatos públicos, e o que existe para detectar e testar.

### Resource Development (TA0042) — 7

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1583.006](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1583.006) Web Services | Turla has created web accounts including Dropbox and GitHub for C2 and document exfiltration. | 2 | — | — |
| [T1584.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1584.003) Virtual Private Server | Turla has used the VPS infrastructure of compromised Iranian threat actors. | **0** | — | — |
| [T1584.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1584.004) Server | Turla has used compromised servers as infrastructure. | **0** | — | — |
| [T1584.006](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1584.006) Web Services | Turla has frequently used compromised WordPress sites for C2 infrastructure. | 1 | — | — |
| [T1587.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1587.001) Malware | Turla has developed its own unique malware for use in operations. | 43 | — | — |
| [T1588.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1588.001) Malware | Turla has used malware obtained after compromising other threat actors, such as OilRig. | 7 | — | — |
| [T1588.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1588.002) Tool | Turla has obtained and customized publicly-available tools like Mimikatz. | 35 | — | — |

### Initial Access (TA0001) — 3

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1078.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.003) Local Accounts | Turla has abused local accounts that have the same password across the victim’s network. | 32 | 13 | — |
| [T1189](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1189) Drive-by Compromise | Turla has infected victims using watering holes. | 57 | — | — |
| [T1566.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1566.002) Spearphishing Link | Turla attempted to trick targets into clicking on a link featuring a seemingly legitimate domain from Adobe.com to download their malware and gain initial access. | 138 | 1 | — |

### Execution (TA0002) — 7

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1059.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.001) PowerShell | Turla has used PowerShell to execute commands/scripts, in some cases via a custom executable or code from Empire's PSInject. Turla has also used PowerShell scripts to load and execute malware in memory. | 1340 | 22 | 15 |
| [T1059.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.003) Windows Command Shell | Turla RPC backdoors have used cmd.exe to execute commands. | 269 | 6 | 1 |
| [T1059.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.005) Visual Basic | Turla has used VBS scripts throughout its operations. | 192 | 3 | — |
| [T1059.006](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.006) Python | Turla has used IronPython scripts as part of the IronNetInjector toolchain to drop payloads. | 122 | — | — |
| [T1059.007](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.007) JavaScript | Turla has used various JavaScript-based backdoors. | 205 | 5 | — |
| [T1106](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1106) Native API | Turla and its RPC backdoors have used APIs calls for various tasks related to subverting AMSI and accessing then executing commands through RPC and/or named pipes. | 118 | 5 | — |
| [T1204.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1204.001) Malicious Link | Turla has used spearphishing via a link to get users to download and run their malware. | 52 | — | — |

### Persistence (TA0003) — 6

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1078.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.003) Local Accounts | Turla has abused local accounts that have the same password across the victim’s network. | 32 | 13 | — |
| [T1112](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1112) Modify Registry | Turla has modified Registry values to store payloads. | 601 | 92 | 3 |
| [T1546.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1546.003) Windows Management Instrumentation Event Subscription | Turla has used WMI event filters and consumers to establish persistence. | 99 | 4 | — |
| [T1546.013](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1546.013) PowerShell Profile | Turla has used PowerShell profiles to maintain persistence on an infected machine. | 17 | 2 | — |
| [T1547.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1547.001) Registry Run Keys / Startup Folder | A Turla Javascript backdoor added a local_update_check value under the Registry key HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run to establish persistence. Additionally, a Turla custom executable containing Metasploit shellcode is saved to the Startup fol… | 299 | 21 | 2 |
| [T1547.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1547.004) Winlogon Helper DLL | Turla established persistence by adding a Shell value under the Registry key HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon. | 25 | 5 | — |

### Privilege Escalation (TA0004) — 9

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1055](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1055) Process Injection | Turla has also used PowerSploit's Invoke-ReflectivePEInjection.ps1 to reflectively load a PowerShell payload into a random process on the victim system. | 481 | 13 | 4 |
| [T1055.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1055.001) Dynamic-link Library Injection | Turla has used Metasploit to perform reflective DLL injection in order to escalate privileges. | 40 | 2 | — |
| [T1068](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1068) Exploitation for Privilege Escalation | Turla has exploited vulnerabilities in the VBoxDrv.sys driver to obtain kernel mode privileges. | 408 | 2 | 2 |
| [T1078.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.003) Local Accounts | Turla has abused local accounts that have the same password across the victim’s network. | 32 | 13 | — |
| [T1134.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1134.002) Create Process with Token | Turla RPC backdoors can impersonate or steal process tokens before executing commands. | 60 | 2 | — |
| [T1546.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1546.003) Windows Management Instrumentation Event Subscription | Turla has used WMI event filters and consumers to establish persistence. | 99 | 4 | — |
| [T1546.013](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1546.013) PowerShell Profile | Turla has used PowerShell profiles to maintain persistence on an infected machine. | 17 | 2 | — |
| [T1547.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1547.001) Registry Run Keys / Startup Folder | A Turla Javascript backdoor added a local_update_check value under the Registry key HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run to establish persistence. Additionally, a Turla custom executable containing Metasploit shellcode is saved to the Startup fol… | 299 | 21 | 2 |
| [T1547.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1547.004) Winlogon Helper DLL | Turla established persistence by adding a Shell value under the Registry key HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon. | 25 | 5 | — |

### Stealth (TA0005) — 10

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1027.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1027.005) Indicator Removal from Tools | Based on comparison of Gazer versions, Turla made an effort to obfuscate strings in the malware that could be used as IoCs, including the mutex name and named pipe. | 24 | — | — |
| [T1027.010](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1027.010) Command Obfuscation | Turla has used encryption (including salted 3DES via PowerSploit's Out-EncryptedScript.ps1), random variable names, and base64 encoding to obfuscate PowerShell commands and payloads. | 78 | — | — |
| [T1027.011](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1027.011) Fileless Storage | Turla has used the Registry to store encrypted and encoded payloads. | 3 | — | — |
| [T1036.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1036.005) Match Legitimate Resource Name or Location | Turla has named components of LunarWeb to mimic Zabbix agent logs. | 116 | 4 | — |
| [T1055](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1055) Process Injection | Turla has also used PowerSploit's Invoke-ReflectivePEInjection.ps1 to reflectively load a PowerShell payload into a random process on the victim system. | 481 | 13 | 4 |
| [T1055.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1055.001) Dynamic-link Library Injection | Turla has used Metasploit to perform reflective DLL injection in order to escalate privileges. | 40 | 2 | — |
| [T1078.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.003) Local Accounts | Turla has abused local accounts that have the same password across the victim’s network. | 32 | 13 | — |
| [T1134.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1134.002) Create Process with Token | Turla RPC backdoors can impersonate or steal process tokens before executing commands. | 60 | 2 | — |
| [T1140](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1140) Deobfuscate/Decode Files or Information | Turla has used a custom decryption routine, which pulls key and salt values from other artifacts such as a WMI filter or PowerShell Profile, to decode encrypted PowerShell payloads. | 173 | 11 | 1 |
| [T1564.012](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1564.012) File/Path Exclusions | Turla has placed LunarWeb install files into directories that are excluded from scanning. | **0** | 1 | — |

### Defense Impairment (TA0112) — 3

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1112](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1112) Modify Registry | Turla has modified Registry values to store payloads. | 601 | 92 | 3 |
| [T1553.006](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1553.006) Code Signing Policy Modification | Turla has modified variables in kernel memory to turn off Driver Signature Enforcement after exploiting vulnerabilities that obtained kernel mode privileges. | 5 | 1 | — |
| [T1685](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1685) Disable or Modify Tools | Turla has used a AMSI bypass, which patches the in-memory amsi.dll, in PowerShell scripts to bypass Windows antimalware products. | 1275 | 78 | 19 |

### Credential Access (TA0006) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1110](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1110) Brute Force | Turla may attempt to connect to systems within a victim's network using net use commands and a predefined list or collection of passwords. | 381 | — | 12 |
| [T1555.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1555.004) Windows Credential Manager | Turla has gathered credentials from the Windows Credential Manager tool. | 37 | 2 | 1 |

### Discovery (TA0007) — 18

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1007](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1007) System Service Discovery | Turla surveys a system upon check-in to discover running services and associated processes using the tasklist /svc command. | 37 | 8 | — |
| [T1012](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1012) Query Registry | Turla surveys a system upon check-in to discover information in the Windows Registry with the reg query command. Turla has also retrieved PowerShell payloads hidden in Registry keys as well as checking keys associated with null session named pipes . | 92 | 6 | — |
| [T1016](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1016) System Network Configuration Discovery | Turla surveys a system upon check-in to discover network configuration details using the arp -a, nbtstat -n, net config, ipconfig /all, and route commands, as well as NBTscan. Turla RPC backdoors have also retrieved registered RPC interface information from pr… | 99 | 10 | 5 |
| [T1016.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1016.001) Internet Connection Discovery | Turla has used tracert to check internet connectivity. | 14 | 5 | — |
| [T1018](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1018) Remote System Discovery | Turla surveys a system upon check-in to discover remote systems on a local network using the net view and net view /DOMAIN commands. Turla has also used net group "Domain Computers" /domain, net group "Domain Controllers" /domain, and net group "Exchange Serve… | 157 | 23 | 1 |
| [T1049](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1049) System Network Connections Discovery | Turla surveys a system upon check-in to discover active local network connections using the netstat -an, net use, net file, and net session commands. Turla RPC backdoors have also enumerated the IPv4 TCP connection table via the GetTcpTable2 API call. | 47 | 7 | — |
| [T1057](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1057) Process Discovery | Turla surveys a system upon check-in to discover running processes using the tasklist /v command. Turla RPC backdoors have also enumerated processes associated with specific open ports or named pipes. | 82 | 10 | — |
| [T1069.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1069.001) Local Groups | Turla has used net localgroup and net localgroup Administrators to enumerate group information, including members of the local administrators group. | 50 | 7 | — |
| [T1069.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1069.002) Domain Groups | Turla has used net group "Domain Admins" /domain to identify domain administrators. | 91 | 15 | — |
| [T1082](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1082) System Information Discovery | Turla surveys a system upon check-in to discover operating system configuration details using the systeminfo and set commands. | 264 | 41 | — |
| [T1083](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1083) File and Directory Discovery | Turla surveys a system upon check-in to discover files in specific locations on the hard disk %TEMP% directory, the current user's desktop, the Program Files directory, and Recent. Turla RPC backdoors have also searched for files matching the lPH*.dll pattern. | 137 | 9 | — |
| [T1087.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1087.001) Local Account | Turla has used net user to enumerate local accounts on the system. | 98 | 11 | — |
| [T1087.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1087.002) Domain Account | Turla has used net user /domain to enumerate domain accounts. | 180 | 25 | 1 |
| [T1120](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1120) Peripheral Device Discovery | Turla has used fsutil fsinfo drives to list connected drives. | 11 | 4 | — |
| [T1124](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1124) System Time Discovery | Turla surveys a system upon check-in to discover the system time by using the net time command. | 18 | 6 | — |
| [T1201](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1201) Password Policy Discovery | Turla has used net accounts and net accounts /domain to acquire password policy information. | 43 | 12 | 2 |
| [T1518.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1518.001) Security Software Discovery | Turla has obtained information on security software, including security logging information that may indicate whether their malware has been detected. | 54 | 12 | — |
| [T1615](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1615) Group Policy Discovery | Turla surveys a system upon check-in to discover Group Policy details using the gpresult command. | 39 | 5 | — |

### Lateral Movement (TA0008) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1021.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1021.002) SMB/Windows Admin Shares | Turla used net use commands to connect to lateral systems within a network. | 272 | 4 | 20 |
| [T1570](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1570) Lateral Tool Transfer | Turla RPC backdoors can be used to transfer files to/from victim machines on the local network. | 58 | 2 | — |

### Collection (TA0009) — 4

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1005) Data from Local System | Turla RPC backdoors can upload files from victim machines. | 170 | 3 | — |
| [T1025](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1025) Data from Removable Media | Turla RPC backdoors can collect files from USB thumb drives. | 4 | 1 | — |
| [T1213.006](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1213.006) Databases | Turla has used a custom .NET tool to collect documents from an organization's internal central database. | 2 | — | — |
| [T1560.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1560.001) Archive via Utility | Turla has encrypted files stolen from connected USB drives into a RAR file before exfiltration. | 76 | 13 | — |

### Command and Control (TA0011) — 7

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1071.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1071.001) Web Protocols | Turla has used HTTP and HTTPS for C2 communications. | 228 | 3 | — |
| [T1071.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1071.003) Mail Protocols | Turla has used multiple backdoors which communicate with a C2 server via email attachments. | 6 | — | — |
| [T1090](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1090) Proxy | Turla RPC backdoors have included local UPnP RPC proxies. | 162 | — | 1 |
| [T1090.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1090.001) Internal Proxy | Turla has compromised internal network systems to act as a proxy to forward traffic to C2. | 43 | 3 | — |
| [T1102](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1102) Web Service | Turla has used legitimate web services including Pastebin, Dropbox, and GitHub for C2 communications. | 98 | — | — |
| [T1102.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1102.002) Bidirectional Communication | A Turla JavaScript backdoor has used Google Apps Script as its C2 server. | 27 | — | — |
| [T1105](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1105) Ingress Tool Transfer | Turla has used shellcode to download Meterpreter after compromising a victim. | 644 | 39 | — |

### Exfiltration (TA0010) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1567.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1567.002) Exfiltration to Cloud Storage | Turla has used WebDAV to upload stolen USB files to a cloud drive. Turla has also exfiltrated stolen files to OneDrive and 4shared. | 85 | 2 | — |

## 4. Assinatura comportamental

Técnicas que este grupo usa e que poucos dos 178 grupos do ATT&CK usam. Pesam mais numa atribuição por TTP: ver várias delas juntas é mais informativo do que ver técnicas comuns como PowerShell.

| Técnica | Outros grupos que usam | Peso (raridade) |
|---|---:|---:|
| T1546.013 PowerShell Profile | 0 | 4.49 |
| T1615 Group Policy Discovery | 0 | 4.49 |
| T1027.011 Fileless Storage | 1 | 4.09 |
| T1134.002 Create Process with Token | 1 | 4.09 |
| T1553.006 Code Signing Policy Modification | 1 | 4.09 |
| T1564.012 File/Path Exclusions | 1 | 4.09 |
| T1584.003 Virtual Private Server | 1 | 4.09 |
| T1201 Password Policy Discovery | 2 | 3.80 |
| T1547.004 Winlogon Helper DLL | 2 | 3.80 |
| T1025 Data from Removable Media | 3 | 3.58 |

## 5. Arsenal

| Software | Tipo | Técnicas no ATT&CK | Uso relatado (EN) |
|---|---|---:|---|
| [Empire](https://attack.mitre.org/software/S0363/) | ferramenta | 73 |  |
| [Uroburos](https://attack.mitre.org/software/S0022/) | malware | 36 |  |
| [Kazuar](https://attack.mitre.org/software/S0265/) | malware | 31 |  |
| [LunarWeb](https://attack.mitre.org/software/S1141/) | malware | 30 |  |
| [Epic](https://attack.mitre.org/software/S0091/) | malware | 22 |  |
| [LightNeuron](https://attack.mitre.org/software/S0395/) | malware | 22 |  |
| [ComRAT](https://attack.mitre.org/software/S0126/) | malware | 22 |  |
| [Gazer](https://attack.mitre.org/software/S0168/) | malware | 18 |  |
| [Carbon](https://attack.mitre.org/software/S0335/) | malware | 18 |  |
| [Penquin](https://attack.mitre.org/software/S0587/) | malware | 18 |  |
| [Mosquito](https://attack.mitre.org/software/S0256/) | malware | 17 |  |
| [LunarMail](https://attack.mitre.org/software/S1142/) | malware | 17 |  |
| [Mimikatz](https://attack.mitre.org/software/S0002/) | ferramenta | 17 |  |
| [Net](https://attack.mitre.org/software/S0039/) | ferramenta | 16 |  |
| [Crutch](https://attack.mitre.org/software/S0538/) | malware | 15 |  |
| [TinyTurla](https://attack.mitre.org/software/S0668/) | malware | 14 |  |
| [KOPILUWAK](https://attack.mitre.org/software/S1075/) | malware | 13 |  |
| [IronNetInjector](https://attack.mitre.org/software/S0581/) | ferramenta | 8 |  |
| [HyperStack](https://attack.mitre.org/software/S0537/) | malware | 6 |  |
| [LunarLoader](https://attack.mitre.org/software/S1143/) | malware | 5 |  |
| [PowerStallion](https://attack.mitre.org/software/S0393/) | malware | 5 |  |
| [NBTscan](https://attack.mitre.org/software/S0590/) | ferramenta | 5 |  |
| [PsExec](https://attack.mitre.org/software/S0029/) | ferramenta | 5 |  |
| [certutil](https://attack.mitre.org/software/S0160/) | ferramenta | 4 |  |
| [Tasklist](https://attack.mitre.org/software/S0057/) | ferramenta | 3 |  |
| [Reg](https://attack.mitre.org/software/S0075/) | ferramenta | 3 |  |
| [Arp](https://attack.mitre.org/software/S0099/) | ferramenta | 2 |  |
| [nbtstat](https://attack.mitre.org/software/S0102/) | ferramenta | 2 |  |
| [netstat](https://attack.mitre.org/software/S0104/) | ferramenta | 1 |  |
| [Systeminfo](https://attack.mitre.org/software/S0096/) | ferramenta | 1 |  |

## 6. Campanhas

Nenhuma campanha atribuída no ATT&CK.

## 7. Cobertura defensiva

**65 de 68 técnicas (96%)** têm ao menos uma regra pública no catálogo Detection Rules.

### Técnicas sem regra pública (prioridade para engenharia de detecção)

- **T1564.012 File/Path Exclusions** — Stealth. Fonte de log sugerida pelo MITRE: `WinEventLog:Sysmon` EventCode=11; `auditd:SYSCALL` open or creat syscalls targeting excluded paths; `macos:unifiedlog` file creation in AV exclusion directories
- **T1584.003 Virtual Private Server** — Resource Development. Fonte de log sugerida pelo MITRE: `Internet Scan` None
- **T1584.004 Server** — Resource Development. Fonte de log sugerida pelo MITRE: `Internet Scan` None

### Regras recomendadas por técnica

Melhor regra disponível por técnica (formato portável e maduro primeiro).

| Técnica | Regra | Formato | Fonte |
|---|---|---|---|
| T1005 | [Potential Conti Ransomware Database Dumping Activity Via SQLCmd](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A2f47f1fd-0901-466e-a770-3b7092834a1b) | Sigma | SigmaHQ |
| T1005 | [OpenCanary - SMB File Open Request](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A22777c9e-873a-4b49-855f-6072ab861a52) | Sigma | SigmaHQ |
| T1007 | [HackTool - PCHunter Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Afca949cc-79ca-446e-8064-01aa7e52ece5) | Sigma | SigmaHQ |
| T1007 | [SC.EXE Query Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A57712d7a-679c-4a41-a913-87e7175ae429) | Sigma | SigmaHQ |
| T1012 | [Potential Baby Shark Malware Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A2b30fa36-3a18-402f-a22d-bf4ce2189f35) | Sigma | SigmaHQ |
| T1012 | [Operation Wocao Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1cfac73c-be78-4f9a-9b08-5bde0c3953ab) | Sigma | SigmaHQ |
| T1016 | [Potential Pikabot Discovery Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A698d4431-514f-4c82-af4d-cf573872a9f5) | Sigma | SigmaHQ |
| T1016 | [OpenCanary - SNMP OID Request](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae9856028-fd4e-46e6-b3d1-10f7ceb95078) | Sigma | SigmaHQ |
| T1016.001 | [System Public IP Discovery via DNS Query](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A642ce354-4252-4d43-80c9-6603f16571c1) | Elastic | Elastic detection-rules |
| T1016.001 | [Suspicious PDF Reader Child Process](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A53a26770-9cbd-40c5-8b57-61d01a325e14) | Elastic | Elastic detection-rules |
| T1018 | [Chopper Webshell Process Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Afa3c117a-bc0d-416e-a31b-0c0e80653efb) | Sigma | SigmaHQ |
| T1018 | [Webshell Hacking Activity Patterns](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4ebc877f-4612-45cb-b3a5-8e3834db36c9) | Sigma | SigmaHQ |
| T1021.002 | [PSExec Lateral Movement](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=hayabusa-native%3A%3A0694c340-3a46-40ac-acfc-c3444ae6572c) | Sigma | Hayabusa (native) |
| T1021.002 | [Turla Group Lateral Movement](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac601f20d-570a-4cde-a7d6-e17f99cb8e7f) | Sigma | SigmaHQ |
| T1025 | [Windows Process Executed From Removable Media](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=splunk-security-content%3A%3Ab483804a-4cc0-49a4-9f00-ac29ba844d08) | Splunk | Splunk security_content |
| T1025 | [Windows WPDBusEnum Registry Key Modification](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=splunk-security-content%3A%3A52b48e8b-eb6e-48b0-b8f1-73273f6b134e) | Splunk | Splunk security_content |
| T1027.005 | [PUA - DefenderCheck Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Af0ca6c24-3225-47d5-b1f5-352bf07ecfa7) | Sigma | SigmaHQ |
| T1027.005 | [HackTool - CrackMapExec PowerShell Obfuscation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A6f8b3439-a203-45dc-a88b-abf57ea15ccf) | Sigma | SigmaHQ |
| T1027.010 | [Decoded Payload Piped to Interpreter Detected via Defend for Containers](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A0fb83aa0-3d17-41e9-b09c-56397bf7a7d9) | Elastic | Elastic detection-rules |
| T1027.010 | [Potential PowerShell Obfuscation via String Concatenation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Af6d8c743-0916-4483-8333-3c6f107e0caa) | Elastic | Elastic detection-rules |
| T1027.011 | [Process Execution From Shared Memory Directory](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A5cd16c8f-44a6-4654-81e7-a84d6db507d4) | Sigma | SigmaHQ |
| T1027.011 | [PowerShell WebRequest Using Memory Stream](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=splunk-security-content%3A%3A103affa6-924a-4b53-aff4-1d5075342aab) | Splunk | Splunk security_content |
| T1036.005 | [Exploit for CVE-2015-1641](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A7993792c-5ce2-4475-a3db-a3a5539827ef) | Sigma | SigmaHQ |
| T1036.005 | [Exploit for CVE-2015-1641](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A7993792c-5ce2-4475-a3db-a3a5539827ef) | Sigma | OpenSearch Security Analytics |
| T1049 | [Potential Pikabot Discovery Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A698d4431-514f-4c82-af4d-cf573872a9f5) | Sigma | SigmaHQ |
| T1049 | [HackTool - SharpView Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab2317cfa-4a47-4ead-b3ff-297438c0bc2d) | Sigma | SigmaHQ |
| T1055 | [Potential Dridex Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae6eb5a96-9e6f-4a18-9cdd-642cfda21c8e) | Sigma | SigmaHQ |
| T1055 | [Antivirus PrinterNightmare CVE-2021-34527 Exploit Detection](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A6fe1719e-ecdf-4caf-bffe-4f501cb0a561) | Sigma | SigmaHQ |
| T1055.001 | [TAIDOOR RAT DLL Load](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad1aa3382-abab-446f-96ea-4de52908210b) | Sigma | SigmaHQ |
| T1055.001 | [Renamed ZOHO Dctask64 Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A340a090b-c4e9-412e-bb36-b4b16fe96f9b) | Sigma | SigmaHQ |
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
| T1068 | [Exploiting CVE-2019-1388](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A02e0b2ea-a597-428e-b04a-af6a1a403e5c) | Sigma | SigmaHQ |
| T1068 | [OMIGOD HTTP No Authentication RCE - CVE-2021-38647](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aab6b1a39-a9ee-4ab4-b075-e83acf6e346b) | Sigma | SigmaHQ |
| T1069.001 | [BloodHound Collection Files](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A02773bed-83bf-469f-b7ff-e676e7d78bab) | Sigma | SigmaHQ |
| T1069.001 | [HackTool - Bloodhound/Sharphound Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Af376c8a7-a2d0-4ddc-aa0c-16c17236d962) | Sigma | SigmaHQ |
| T1069.002 | [BloodHound Collection Files](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A02773bed-83bf-469f-b7ff-e676e7d78bab) | Sigma | SigmaHQ |
| T1069.002 | [HackTool - SharpView Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab2317cfa-4a47-4ead-b3ff-297438c0bc2d) | Sigma | SigmaHQ |
| T1071.001 | [Ursnif Malware Download URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aa36ce77e-30db-4ea0-8795-644d7af5dfb4) | Sigma | SigmaHQ |
| T1071.001 | [Ursnif Malware C2 URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A932ac737-33ca-4afd-9869-0d48b391fcc9) | Sigma | SigmaHQ |
| T1071.003 | [SMTP to the Internet on Port 26/TCP](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ad7e62693-aab9-4f66-a21a-3d79ecdd603d) | Elastic | Elastic detection-rules |
| T1071.003 | [CYFIRMA - Brand Intelligence - Domain Impersonation High Rule](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A10bdf525-5b89-4a25-933a-e63e73b915f1) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1078.003 | [Potential Successful SSH Brute Force Attack via macOS Security Events](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Af5898b1e-3071-4597-b066-43d298c7b415) | Elastic | Elastic detection-rules |
| T1078.003 | [Admin User Remote Logon](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A0f63e1ef-1eb9-4226-9d54-8927ca08520a) | Sigma | SigmaHQ |
| T1082 | [Potential GobRAT File Discovery Via Grep](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae34cfa0c-0a50-4210-9cb3-5632d08eb041) | Sigma | SigmaHQ |
| T1082 | [System Information Discovery](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A42df45e7-e6e9-43b5-8f26-bec5b39cc239) | Sigma | SigmaHQ |
| T1083 | [Turla Group Lateral Movement](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac601f20d-570a-4cde-a7d6-e17f99cb8e7f) | Sigma | SigmaHQ |
| T1083 | [WannaCry Ransomware Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A41d40bff-377a-43e2-8e1b-2e543069e079) | Sigma | SigmaHQ |
| T1087.001 | [BloodHound Collection Files](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A02773bed-83bf-469f-b7ff-e676e7d78bab) | Sigma | SigmaHQ |
| T1087.001 | [HackTool - Bloodhound/Sharphound Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Af376c8a7-a2d0-4ddc-aa0c-16c17236d962) | Sigma | SigmaHQ |
| T1087.002 | [BloodHound Collection Files](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A02773bed-83bf-469f-b7ff-e676e7d78bab) | Sigma | SigmaHQ |
| T1087.002 | [Suspicious Active Directory Database Snapshot Via ADExplorer](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aef61af62-bc74-4f58-b49b-626448227652) | Sigma | SigmaHQ |
| T1090 | [Communication To LocaltoNet Tunneling Service Initiated - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac4568f5d-131f-4e78-83d4-45b2da0ec4f1) | Sigma | SigmaHQ |
| T1090 | [Communication To Ngrok Tunneling Service - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A19bf6fdb-7721-4f3d-867f-53467f6a5db6) | Sigma | SigmaHQ |
| T1090.001 | [Renamed Cloudflared.EXE Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae0c69ebd-b54f-4aed-8ae3-e3467843f3f0) | Sigma | SigmaHQ |
| T1090.001 | [PUA - Chisel Tunneling Tool Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A8b0e12da-d3c3-49db-bb4f-256703f380e5) | Sigma | SigmaHQ |
| T1102 | [Communication To LocaltoNet Tunneling Service Initiated - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac4568f5d-131f-4e78-83d4-45b2da0ec4f1) | Sigma | SigmaHQ |
| T1102 | [Communication To Ngrok Tunneling Service - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A19bf6fdb-7721-4f3d-867f-53467f6a5db6) | Sigma | SigmaHQ |
| T1102.002 | [Potential Etherhiding C2 via Blockchain Connection](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Abba8c7d1-172b-435d-9034-02ed9289c628) | Elastic | Elastic detection-rules |
| T1102.002 | [Google Calendar C2 via Script Interpreter](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Aabc7a2be-479e-428b-b0b3-1d22bda46dd9) | Elastic | Elastic detection-rules |
| T1105 | [Greenbug Espionage Group Indicators](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A3711eee4-a808-4849-8a14-faf733da3612) | Sigma | SigmaHQ |
| T1105 | [Pandemic Registry Key](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A47e0852a-cf81-4494-a8e6-31864f8c86ed) | Sigma | SigmaHQ |
| T1106 | [Turla Group Named Pipes](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A739915e4-1e70-4778-8b8a-17db02f66db1) | Sigma | SigmaHQ |
| T1106 | [BPFDoor Abnormal Process ID or Lock File Accessed](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A808146b2-9332-4d78-9416-d7e47012d83d) | Sigma | SigmaHQ |
| T1110 | [Hack Tool User Agent](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac42a3073-30fb-48ae-8c99-c23ada84b103) | Sigma | SigmaHQ |
| T1110 | [HackTool - CrackMapExec Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A42a993dd-bb3e-48c8-b372-4d6684c4106c) | Sigma | SigmaHQ |
| T1112 | [ShimCache Flush](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab0524451-19af-4efa-a46f-562a977f792e) | Sigma | SigmaHQ |
| T1112 | [ShimCache Flush](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Ab0524451-19af-4efa-a46f-562a977f792e) | Sigma | OpenSearch Security Analytics |
| T1120 | [PowerShell Suspicious Script with Audio Capture Capabilities](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A2f2f4939-0b34-40c2-a0a3-844eb7889f43) | Elastic | Elastic detection-rules |
| T1120 | [Fsutil Drive Enumeration](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A63de06b9-a385-40b5-8b32-73f2b9ef84b6) | Sigma | SigmaHQ |
| T1124 | [Use of W32tm as Timer](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A6da2c9f5-7c53-401b-aacb-92c040ce1215) | Sigma | SigmaHQ |
| T1124 | [Cisco Discovery](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A9705a6a1-6db6-4a16-a987-15b7151e299b) | Sigma | SigmaHQ |
| T1134.002 | [Suspicious Child Process Created as System](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A590a5f4c-6c8c-4f10-8307-89afe9453a9d) | Sigma | SigmaHQ |
| T1134.002 | [PUA - AdvancedRun Suspicious Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Afa00b701-44c6-4679-994d-5a18afa8a707) | Sigma | SigmaHQ |
| T1140 | [UNC4841 - SSL Certificate Exfiltration Via Openssl](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A60911c07-f989-4362-84af-c609828ef829) | Sigma | SigmaHQ |
| T1140 | [UNC4841 - Download Compressed Files From Temp.sh Using Wget](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A60d050c4-e253-4d9a-b673-5ac100cfddfb) | Sigma | SigmaHQ |
| T1189 | [Flash Player Update from Suspicious Location](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4922a5dd-6743-4fc2-8e81-144374280997) | Sigma | SigmaHQ |
| T1189 | [Cross Site Scripting Strings](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A65354b83-a2ea-4ea6-8414-3ab38be0d409) | Sigma | SigmaHQ |
| T1201 | [Password Policy Discovery - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aca94a6db-8106-4737-9ed2-3e3bb826af0a) | Sigma | SigmaHQ |
| T1201 | [HackTool - CrackMapExec Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A42a993dd-bb3e-48c8-b372-4d6684c4106c) | Sigma | SigmaHQ |
| T1204.001 | [Google Workspace Object Copied from External Drive with App Consent](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Af33e68a4-bd19-11ed-b02f-f661ea17fbcc) | Elastic | Elastic detection-rules |
| T1204.001 | [Suspicious ClickFix/FileFix Execution Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad487ed4a-fd24-436d-a0b2-f4e95f7b2635) | Sigma | SigmaHQ |
| T1213.006 | [AWS RDS Snapshot Export](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A119c8877-8613-416d-a98a-96b6664ee73a) | Elastic | Elastic detection-rules |
| T1213.006 | [AWS Secrets Manager Rapid Secrets Retrieval](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A185c782e-f86a-11ee-9d9f-f661ea17fbce) | Elastic | Elastic detection-rules |
| T1518.001 | [Sysmon Discovery Via Default Driver Altitude Using Findstr.EXE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A37db85d1-b089-490a-a59a-c7b6f984f480) | Sigma | SigmaHQ |
| T1518.001 | [Local Firewall Rules Enumeration Via NetFirewallRule Cmdlet](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aea207a23-b441-4a17-9f76-ad5be47d51d3) | Sigma | SigmaHQ |
| T1546.003 | [WMI Persistence - Script Event Consumer File Write](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A33f41cdd-35ac-4ba8-814b-c6a4244a1ad4) | Sigma | SigmaHQ |
| T1546.003 | [NewActiveScriptEventConsumer Creation Attempt via Wmic.EXE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aebef4391-1a81-4761-a40a-1db446c0e625) | Sigma | SigmaHQ |
| T1546.013 | [Powershell Profile.ps1 Modification](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Ab5b78988-486d-4a80-b991-930eff3ff8bf) | Sigma | OpenSearch Security Analytics |
| T1546.013 | [PowerShell Profile Modification](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab5b78988-486d-4a80-b991-930eff3ff8bf) | Sigma | SigmaHQ |
| T1547.001 | [Potential Ryuk Ransomware Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac37510b8-2107-4b78-aa32-72f251e7a844) | Sigma | SigmaHQ |
| T1547.001 | [Ryuk Ransomware](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Ac37510b8-2107-4b78-aa32-72f251e7a844) | Sigma | OpenSearch Security Analytics |
| T1547.004 | [Winlogon Notify Key Logon Persistence](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Abbf59793-6efb-4fa1-95ca-a7d288e52c88) | Sigma | SigmaHQ |
| T1547.004 | [Persistence via WMI Standard Registry Provider](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A70d12c9c-0dbd-4a1a-bc44-1467502c9cf6) | Elastic | Elastic detection-rules |
| T1553.006 | [ESXi Host Prepared for an Unsigned Install](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A12c56e4a-8d36-5dab-a5b6-5322db31c901) | Elastic | Elastic detection-rules |
| T1553.006 | [ESXi Attempt to Force Install a VMware VIB Package](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A3c9a356d-d878-555c-9d27-a7028c9a074f) | Elastic | Elastic detection-rules |
| T1555.004 | [Suspicious Key Manager Access](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aa4694263-59a8-4608-a3a0-6f8d3a51664c) | Sigma | SigmaHQ |
| T1555.004 | [Potential Credential Access via Trusted Developer Utility](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A9d110cb3-5f4b-4c9a-b9f5-53f0a1707ae5) | Elastic | Elastic detection-rules |
| T1560.001 | [APT31 Judgement Panda Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A03e2746e-2b31-42f1-ab7a-eb39365b2422) | Sigma | SigmaHQ |
| T1560.001 | [Suspicious Manipulation Of Default Accounts Via Net.EXE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A5b768e71-86f2-4879-b448-81061cbae951) | Sigma | SigmaHQ |
| T1566.002 | [Potential Malicious Usage of CloudTrail System Manager](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A38e7f511-3f74-41d4-836e-f57dfa18eead) | Sigma | SigmaHQ |
| T1566.002 | [Google Workspace Device Registration After OAuth from Suspicious ASN](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A012bfca7-45cb-4507-a3ba-3777167f8b81) | Elastic | Elastic detection-rules |
| T1567.002 | [APT40 Dropbox Tool User Agent](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A5ba715b6-71b7-44fd-8245-f66893e81b3d) | Sigma | SigmaHQ |
| T1567.002 | [PUA - Rclone Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae37db05d-d1f9-49c8-b464-cee1a4b11638) | Sigma | SigmaHQ |
| T1570 | [PSExec Lateral Movement](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=hayabusa-native%3A%3A0694c340-3a46-40ac-acfc-c3444ae6572c) | Sigma | Hayabusa (native) |
| T1570 | [PSEXEC Remote Execution File Artefact](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A304afd73-55a5-4bb9-8c21-0b1fc84ea9e4) | Sigma | SigmaHQ |
| T1583.006 | [GitHub Repo Created](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A6cea88e4-6ce2-4238-9981-a54c140d6336) | Elastic | Elastic detection-rules |
| T1583.006 | [Cisco Secure Firewall - Rare Snort Rule Triggered](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=splunk-security-content%3A%3Ae20313d2-7d63-4fcf-b2d9-d6e12c6c7bd7) | Splunk | Splunk security_content |
| T1584.006 | [Suspicious PowerShell Mailbox Export to Share](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A889719ef-dd62-43df-86c3-768fb08dc7c0) | Sigma | OpenSearch Security Analytics |
| T1587.001 | [Formbook Process Creation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A032f5fb3-d959-41a5-9263-4173c802dc2b) | Sigma | SigmaHQ |
| T1587.001 | [Uncommon File Created In Office Startup Folder](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aa10a2c40-2c4d-49f8-b557-1a946bc55d9d) | Sigma | SigmaHQ |
| T1588.001 | [Relevant ClamAV Message](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A36aa86ca-fd9d-4456-814e-d3b1b8e1e0bb) | Sigma | SigmaHQ |
| T1588.001 | [Relevant ClamAV Message](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A36aa86ca-fd9d-4456-814e-d3b1b8e1e0bb) | Sigma | OpenSearch Security Analytics |
| T1588.002 | [Hacktool Execution - Imphash](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A24e3e58a-646b-4b50-adef-02ef935b9fc8) | Sigma | SigmaHQ |
| T1588.002 | [Renamed SysInternals DebugView Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acd764533-2e07-40d6-a718-cfeec7f2da7f) | Sigma | SigmaHQ |
| T1615 | [Suspicious Reconnaissance Activity Via GatherNetworkInfo.VBS](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A07aa184a-870d-413d-893a-157f317f6f58) | Sigma | SigmaHQ |
| T1615 | [HackTool - SharpUp PrivEsc Tool Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac484e533-ee16-4a93-b6ac-f0ea4868b2f1) | Sigma | SigmaHQ |
| T1685 | [Windows Defender Configuration Changes](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A801bd44f-ceed-4eb6-887c-11544633c0aa) | Sigma | SigmaHQ |
| T1685 | [Windows Defender Virus Scanning Feature Disabled](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A686c0b4b-9dd3-4847-9077-d6c1bbe36fcb) | Sigma | SigmaHQ |

## 8. Plano de emulação e validação

Use num laboratório isolado e autorizado para confirmar que as regras disparam. Os comandos estão nos repositórios oficiais.

| Tática | Técnica | Teste Atomic Red Team | Plataformas |
|---|---|---|---|
| Initial Access | [T1566.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1566.002/T1566.002.md) | Paste and run technique | windows |
| Execution | [T1059.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md) | Mimikatz | windows |
| Execution | [T1059.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md) | Run BloodHound from local disk | windows |
| Execution | [T1059.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.003/T1059.003.md) | Create and Execute Batch Script | windows |
| Execution | [T1059.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.003/T1059.003.md) | Writes text to a file and displays it. | windows |
| Execution | [T1059.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.005/T1059.005.md) | Visual Basic script execution to gather local computer information | windows |
| Execution | [T1059.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.005/T1059.005.md) | Encoded VBS code execution | windows |
| Execution | [T1059.007](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.007/T1059.007.md) | JScript execution to gather local computer information via cscript | windows |
| Execution | [T1059.007](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.007/T1059.007.md) | JScript execution to gather local computer information via wscript | windows |
| Execution | [T1106](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1106/T1106.md) | Execution through API - CreateProcess | windows |
| Execution | [T1106](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1106/T1106.md) | WinPwn - Get SYSTEM shell - Pop System Shell using CreateProcess technique | windows |
| Persistence | [T1547.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1547.001/T1547.001.md) | Reg Key Run | windows |
| Persistence | [T1547.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1547.001/T1547.001.md) | Reg Key RunOnce | windows |
| Persistence | [T1547.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1547.004/T1547.004.md) | Winlogon Shell Key Persistence - PowerShell | windows |
| Persistence | [T1547.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1547.004/T1547.004.md) | Winlogon Userinit Key Persistence - PowerShell | windows |
| Privilege Escalation | [T1068](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1068/T1068.md) | Scattered Spider BYOVD (CVE-2015-2291 for Intel Ethernet Diagnostics Driver) | windows |
| Privilege Escalation | [T1068](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1068/T1068.md) | Turla Snake Malware Privilege Escalation Through VM Driver | windows |
| Privilege Escalation | [T1546.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1546.003/T1546.003.md) | Persistence via WMI Event Subscription - CommandLineEventConsumer | windows |
| Privilege Escalation | [T1546.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1546.003/T1546.003.md) | Persistence via WMI Event Subscription - ActiveScriptEventConsumer | windows |
| Privilege Escalation | [T1546.013](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1546.013/T1546.013.md) | Append malicious start-process cmdlet | windows |
| Privilege Escalation | [T1546.013](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1546.013/T1546.013.md) | Turla Malicious Powershell Profile for Persistence | windows |
| Stealth | [T1036.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.005/T1036.005.md) | Execute a process from a directory masquerading as the current parent directory | linux, macos |
| Stealth | [T1036.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.005/T1036.005.md) | Masquerade as a built-in system executable | windows |
| Stealth | [T1055](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1055/T1055.md) | Shellcode execution via VBA | windows |
| Stealth | [T1055](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1055/T1055.md) | Remote Process Injection in LSASS via mimikatz | windows |
| Stealth | [T1055.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1055.001/T1055.001.md) | Process Injection via mavinject.exe | windows |
| Stealth | [T1055.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1055.001/T1055.001.md) | WinPwn - Get SYSTEM shell - Bind System Shell using UsoClient DLL load technique | windows |
| Stealth | [T1078.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1078.003/T1078.003.md) | Create local account with admin privileges | windows |
| Stealth | [T1078.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1078.003/T1078.003.md) | Create local account with admin privileges - MacOS | macos |
| Stealth | [T1134.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1134.002/T1134.002.md) | Access Token Manipulation | windows |
| Stealth | [T1134.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1134.002/T1134.002.md) | WinPwn - Get SYSTEM shell - Pop System Shell using Token Manipulation technique | windows |
| Stealth | [T1140](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1140/T1140.md) | Deobfuscate/Decode Files Or Information | windows |
| Stealth | [T1140](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1140/T1140.md) | Certutil Rename and Decode | windows |
| Stealth | [T1564.012](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1564.012/T1564.012.md) | Stage and execute a payload from a Windows Defender excluded path | windows |
| Defense Impairment | [T1112](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1112/T1112.md) | Modify Registry of Current User Profile - cmd | windows |
| Defense Impairment | [T1112](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1112/T1112.md) | Modify Registry of Local Machine - cmd | windows |
| Defense Impairment | [T1553.006](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1553.006/T1553.006.md) | Code Signing Policy Modification | windows |
| Defense Impairment | [T1685](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1685/T1685.md) | Windows Disable LSA Protection | windows |
| Defense Impairment | [T1685](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1685/T1685.md) | Disable journal logging via systemctl utility | linux |
| Credential Access | [T1555.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1555.004/T1555.004.md) | Access Saved Credentials via VaultCmd | windows |
| Credential Access | [T1555.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1555.004/T1555.004.md) | WinPwn - Loot local Credentials - Invoke-WCMDump | windows |
| Discovery | [T1007](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1007/T1007.md) | System Service Discovery | windows |
| Discovery | [T1007](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1007/T1007.md) | System Service Discovery - net.exe | windows |
| Discovery | [T1012](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1012/T1012.md) | Query Registry | windows |
| Discovery | [T1012](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1012/T1012.md) | Query Registry with Powershell cmdlets | windows |
| Discovery | [T1016](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1016/T1016.md) | System Network Configuration Discovery on Windows | windows |
| Discovery | [T1016](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1016/T1016.md) | List Windows Firewall Rules | windows |
| Discovery | [T1016.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1016.001/T1016.001.md) | Check internet connection using ping Windows | windows |
| Discovery | [T1016.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1016.001/T1016.001.md) | Check internet connection using ping freebsd, linux or macos | linux, macos |
| Discovery | [T1018](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1018/T1018.md) | Remote System Discovery - net | windows |
| Discovery | [T1018](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1018/T1018.md) | Remote System Discovery - net group Domain Computers | windows |
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
| Discovery | [T1083](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1083/T1083.md) | File and Directory Discovery (cmd.exe) | windows |
| Discovery | [T1083](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1083/T1083.md) | File and Directory Discovery (PowerShell) | windows |
| Discovery | [T1087.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1087.001/T1087.001.md) | Enumerate all accounts (Local) | linux |
| Discovery | [T1087.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1087.001/T1087.001.md) | View sudoers access | linux, macos |
| Discovery | [T1087.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1087.002/T1087.002.md) | Enumerate all accounts (Domain) | windows |
| Discovery | [T1087.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1087.002/T1087.002.md) | Enumerate all accounts via PowerShell (Domain) | windows |
| Discovery | [T1120](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1120/T1120.md) | Win32_PnPEntity Hardware Inventory | windows |
| Discovery | [T1120](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1120/T1120.md) | WinPwn - printercheck | windows |
| Discovery | [T1124](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1124/T1124.md) | System Time Discovery | windows |
| Discovery | [T1124](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1124/T1124.md) | System Time Discovery - PowerShell | windows |
| Discovery | [T1201](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1201/T1201.md) | Examine password complexity policy - Ubuntu | linux |
| Discovery | [T1201](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1201/T1201.md) | Examine password complexity policy - FreeBSD | linux |
| Discovery | [T1518.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1518.001/T1518.001.md) | Security Software Discovery | windows |
| Discovery | [T1518.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1518.001/T1518.001.md) | Security Software Discovery - powershell | windows |
| Discovery | [T1615](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1615/T1615.md) | Display group policy information via gpresult | windows |
| Discovery | [T1615](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1615/T1615.md) | Get-DomainGPO to display group policy information via PowerView | windows |
| Lateral Movement | [T1021.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.002/T1021.002.md) | Map admin share | windows |
| Lateral Movement | [T1021.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.002/T1021.002.md) | Map Admin Share PowerShell | windows |
| Lateral Movement | [T1570](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1570/T1570.md) | Exfiltration Over SMB over QUIC (New-SmbMapping) | windows |
| Lateral Movement | [T1570](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1570/T1570.md) | Exfiltration Over SMB over QUIC (NET USE) | windows |
| Collection | [T1005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1005/T1005.md) | Search files of interest and save them to a single zip file (Windows) | windows |
| Collection | [T1005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1005/T1005.md) | Find and dump sqlite databases (Linux) | linux |
| Collection | [T1025](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1025/T1025.md) | Identify Documents on USB and Removable Media via PowerShell | windows |
| Collection | [T1560.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1560.001/T1560.001.md) | Compress Data for Exfiltration With Rar | windows |
| Collection | [T1560.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1560.001/T1560.001.md) | Compress Data and lock with password for Exfiltration with winrar | windows |
| Command and Control | [T1071.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1071.001/T1071.001.md) | Malicious User Agents - Powershell | windows |
| Command and Control | [T1071.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1071.001/T1071.001.md) | Malicious User Agents - CMD | windows |
| Command and Control | [T1090.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1090.001/T1090.001.md) | Connection Proxy | linux, macos |
| Command and Control | [T1090.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1090.001/T1090.001.md) | Connection Proxy for macOS UI | macos |
| Command and Control | [T1105](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1105/T1105.md) | rsync remote file copy (push) | linux, macos |
| Command and Control | [T1105](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1105/T1105.md) | rsync remote file copy (pull) | linux, macos |
| Exfiltration | [T1567.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1567.002/T1567.002.md) | Exfiltrate data with rclone to cloud Storage - Mega (Windows) | windows |
| Exfiltration | [T1567.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1567.002/T1567.002.md) | Exfiltrate data with rclone to cloud Storage - AWS S3 | linux, macos |

**Logs reais de ataque (EVTX) para testar sem executar nada:**

- T1016 — [ID4688-Audit policy enumerated](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1016-System%20Network%20Configuration%20Discovery/ID4688-Audit%20policy%20enumerated.evtx) _(explícito)_
- T1016 — [ID4688-Firewall configuration enumerated (command)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1016-System%20Network%20Configuration%20Discovery/ID4688-Firewall%20configuration%20enumerated%20%28command%29.evtx) _(explícito)_
- T1018 — [ID5145-DNS hosts files access via network share](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1018-Remote%20System%20Discovery/ID5145-DNS%20hosts%20files%20access%20via%20network%20share.evtx) _(explícito)_
- T1021.002 — [ID4688,4697,5140-5145 PSexec remote execution + admin share](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0008-Lateral%20Movement/T1021.002-SMB%20Windows%20Admin%20Shares/ID4688%2C4697%2C5140-5145%20PSexec%20remote%20execution%20%2B%20admin%20share.evtx) _(explícito)_
- T1021.002 — [ID4688-4648 Lateral movement with net use](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0008-Lateral%20Movement/T1021.002-SMB%20Windows%20Admin%20Shares/ID4688-4648%20Lateral%20movement%20with%20net%20use.evtx) _(explícito)_
- T1055 — [sideloading_injection_persistence_run_key](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/AutomatedTestingTools/Malware/sideloading_injection_persistence_run_key.evtx) _(inferido)_
- T1055 — [sideloading_uacbypass_rundll32_injection_c2](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/AutomatedTestingTools/Malware/sideloading_uacbypass_rundll32_injection_c2.evtx) _(inferido)_
- T1059.001 — [ID4103-4104-Payload download via PowerShell](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1059.001-PowerShell/ID4103-4104-Payload%20download%20via%20PowerShell.evtx) _(explícito)_
- T1059.001 — [ID4688-Encoded PowerShell MSF payload via process execution](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1059.001-PowerShell/ID4688-Encoded%20PowerShell%20MSF%20payload%20via%20process%20execution.evtx) _(explícito)_
- T1059.003 — [ID4688-SQL Server payload injectection for reverse shell (MSF)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1059.003-Windows%20Command%20Shell/ID4688-SQL%20Server%20payload%20injectection%20for%20reverse%20shell%20%28MSF%29.evtx) _(explícito)_
- T1068 — [ID12-13 Mini_Plasma_PoC_AbortHydration_ArbitraryRegKey_EoP](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0004-Privilege%20Escalation/T1068-Exploitation%20for%20Privilege%20Escalation/ID12-13%20Mini_Plasma_PoC_AbortHydration_ArbitraryRegKey_EoP.evtx) _(explícito)_
- T1068 — [ID4673-Privilege SeMachineAccountPrivilege called](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0004-Privilege%20Escalation/T1068-Exploitation%20for%20Privilege%20Escalation/ID4673-Privilege%20SeMachineAccountPrivilege%20called.evtx) _(explícito)_
- T1087.002 — [discovery_bloodhound](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Discovery/discovery_bloodhound.evtx) _(inferido)_
- T1090 — [ID5600-proxy configuration changed](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0011-Command%20and%20Control/T1090-Proxy/ID5600-proxy%20configuration%20changed.evtx) _(explícito)_
- T1110 — [ID 4776,4625-AccountRestore local bruteforce](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0006-Credential%20Access/T1110.xxx-Brut%20force/ID%204776%2C4625-AccountRestore%20local%20bruteforce.evtx) _(explícito)_
- T1110 — [ID18456-SQL Server failed login because only Windows auth](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0006-Credential%20Access/T1110.xxx-Brut%20force/ID18456-SQL%20Server%20failed%20login%20because%20only%20Windows%20auth.evtx) _(explícito)_
- T1112 — [ID11,13-SMBexec service registration](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0005-Defense%20Evasion/T1112-Modify%20registry/ID11%2C13-SMBexec%20service%20registration.evtx) _(explícito)_
- T1112 — [ID4624,4670,4688,4674-Registry permission change via WMI (DAMP)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0005-Defense%20Evasion/T1112-Modify%20registry/ID4624%2C4670%2C4688%2C4674-Registry%20permission%20change%20via%20WMI%20%28DAMP%29.evtx) _(explícito)_
- T1140 — [ID4688-Certutil download](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0005-Defense%20Evasion/T1140-Deobfuscate-Decode%20Files%20or%20Information/ID4688-Certutil%20download.evtx) _(explícito)_
- T1201 — [ID4661-Password policy enumeration](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1201-Password%20Policy%20Discovery/ID4661-Password%20policy%20enumeration.evtx) _(explícito)_
- T1201 — [ID4688-Password policy discovery via commandline](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1201-Password%20Policy%20Discovery/ID4688-Password%20policy%20discovery%20via%20commandline.evtx) _(explícito)_
- T1547.001 — [sideloading_injection_persistence_run_key](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/AutomatedTestingTools/Malware/sideloading_injection_persistence_run_key.evtx) _(inferido)_
- T1547.001 — [evasion_persis_hidden_run_keyvalue_sysmon_13](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Persistence/evasion_persis_hidden_run_keyvalue_sysmon_13.evtx) _(inferido)_
- T1555.004 — [ID 5376, 5379, 5382, 5381, 5382 credential manager and vault](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0005-Defense%20Evasion/T1555.004-Windows%20Credential%20Manager/ID%205376%2C%205379%2C%205382%2C%205381%2C%205382%20credential%20manager%20and%20vault.evtx) _(explícito)_
- T1685 — [ID1-SYSMON driver unload (FilterManager)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0005-Defense%20Evasion/T1562.001-Impair%20Defenses-Disable%20or%20Modify%20tool/ID1-SYSMON%20driver%20unload%20%28FilterManager%29.evtx) _(explícito)_

## 9. Hipóteses de hunting

Se Turla estiver no seu ambiente, estas são as perguntas a fazer aos seus dados (fontes de log segundo as estratégias de detecção do MITRE ATT&CK).

1. **T1546.013 PowerShell Profile** — Defenders can identify PowerShell profile-based persistence by correlating file creation or modification in known profile locations with subsequent PowerShell process launches that do not use the `-NoProfile` flag. Profile scripts loading unusual modules or… Dados: `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Sysmon` (EventCode=2), `WinEventLog:Sysmon` (EventCode=1).
2. **T1615 Group Policy Discovery** — Detection of adversary attempts to enumerate Group Policy settings through suspicious command execution (gpresult), PowerShell enumeration (Get-DomainGPO, Get-DomainGPOLocalGroup), and abnormal LDAP queries targeting groupPolicyContainer objects. Defenders… Dados: `WinEventLog:Security` (EventCode=4661), `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:PowerShell` (EventCode=4103, 4104, 4105, 4106).
3. **T1027.011 Fileless Storage** — Detects abuse of fileless storage mechanisms such as Registry keys, WMI classes, and Event Logs used to stage payloads, scripts, or encoded content outside traditional files. Dados: `WinEventLog:Security` (EventCode=4657), `WinEventLog:Application` (WMI Object Creation Events).
4. **T1134.002 Create Process with Token** — A process (often after stealing/creating a token) calls CreateProcessWithTokenW/CreateProcessAsUserW or uses runas to spawn a **new** process whose security context (SID/LogonId/IntegrityLevel) differs from its parent. Chain: (1) suspicious command/API → (2)… Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=10), `ETW:ProcThread` (api_call: CreateProcessWithTokenW, CreateProcessAsUserW).
5. **T1553.006 Code Signing Policy Modification** — Monitors execution of administrative utilities (e.g., bcdedit.exe) or registry modifications that disable Driver Signature Enforcement (DSE) or enable Test Signing. Correlates command-line activity, registry changes, and subsequent process executions that… Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:Security` (EventCode=4657).
6. **T1564.012 File/Path Exclusions** — Creation or modification of files in directories known to be excluded from AV scanning (e.g., C:\Windows\Temp, Exchange server directories, or default AV exclusions). Defender perspective: correlate file creation with execution behavior or anomalous parent… Dados: `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Security` (EventCode=4663, 4670, 4656).
7. **T1584.003 Virtual Private Server** — Once adversaries have provisioned software on a compromised VPS (ex: for use as a command and control server), internet scans may reveal VPSs that adversaries have compromised. Consider looking for identifiable patterns such as services listening,… Dados: `Internet Scan` (None), `Internet Scan` (None).
8. **T1201 Password Policy Discovery** — Cause→effect chain: (1) a user or service spawns a shell/PowerShell that queries local/domain password policy via commands/cmdlets (e.g., `net accounts`, `Get-ADDefaultDomainPasswordPolicy`, `secedit /export`); (2) optional directory/LDAP reads from DCs; (3)… Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:PowerShell` (EventCode=4103, 4104, 4105, 4106), `WinEventLog:Security` (EventCode=4662).
9. **T1547.004 Winlogon Helper DLL** — Monitor Windows Registry modifications to Winlogon keys (Shell, Userinit, Notify) that introduce new executable or DLL paths. Correlate these changes with subsequent DLL loading, image loads, or process creation originating from winlogon.exe or userinit.exe.… Dados: `WinEventLog:Sysmon` (EventCode=7), `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Security` (modification to Winlogon registry keys such as Shell, Notify, or Userinit).
10. **T1025 Data from Removable Media** — Adversary mounts a USB device and begins enumerating, copying, or compressing files using scripting engines, cmd, or remote access tools. Dados: `WinEventLog:Security` (EventCode=4663, 4670, 4656), `WinEventLog:System` (EventCode=2003), `WinEventLog:Sysmon` (EventCode=1).
11. **T1555.004 Windows Credential Manager** — Detects unauthorized access to Windows Credential Manager through anomalous process execution (vaultcmd.exe, rundll32.exe keymgr.dll), suspicious API calls (CredEnumerateA), or direct file access to Credential Locker files. Correlates process creation with… Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=10), `WinEventLog:Sysmon` (EventCode=15).
12. **T1584.006 Web Services** — Once adversaries leverage the abused web service as infrastructure (ex: for command and control), it may be possible to look for unique characteristics associated with adversary software, if known. Much of this activity will take place outside the visibility… Dados: `Internet Scan` (None).

## 10. OSINT — onde pesquisar

Consultas prontas com todos os nomes conhecidos do grupo:

- Relatórios técnicos: [busca web](https://duckduckgo.com/?q=%28%22Turla%22+OR+%22IRON+HUNTER%22+OR+%22Group+88%22+OR+%22Waterbug%22+OR+%22WhiteBear%22+OR+%22Snake%22%29+threat+report) · [PDFs](https://duckduckgo.com/?q=%28%22Turla%22+OR+%22IRON+HUNTER%22+OR+%22Group+88%22+OR+%22Waterbug%22+OR+%22WhiteBear%22+OR+%22Snake%22%29+filetype%3Apdf)
- Regras e IOCs publicados: [GitHub](https://github.com/search?type=code&q=%22Turla%22+OR+%22IRON+HUNTER%22+OR+%22Group+88%22+OR+%22Waterbug%22+OR+%22WhiteBear%22+OR+%22Snake%22)
- Pulsos de ameaça: [AlienVault OTX](https://otx.alienvault.com/browse/global/pulses?q=Turla)
- Família de malware e atores: [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/actors) (busque por Turla, IRON HUNTER, Group 88)
- Cartões de grupo: [ThaiCERT Threat Group Cards](https://apt.etda.or.th/cgi-bin/listgroups.cgi)
- Página oficial: [MITRE ATT&CK G0010](https://attack.mitre.org/groups/G0010/)

**Relatórios na coleção CyberMonitor** (ligados pelo nome do grupo, conferir antes de citar):

- 2014 — [snake_whitepaper](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2014/2014.03.07.Snake_Campaign/snake_whitepaper.pdf) _(via “Snake”)_
- 2014 — [Reuters_Turla](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2014/2014.03.08.Russian_spyware_Turla/Reuters_Turla.pdf) _(via “Turla”)_
- 2014 — [circl-tr25-analysis-turla-pfinet-snake-uroburos](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2014/2014.07.10.Turla_Pfinet_Snake_Uroburos/circl-tr25-analysis-turla-pfinet-snake-uroburos.pdf) _(via “Turla”)_
- 2014 — [KL_Epic_Turla_Technical_Appendix_20140806](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2014/2014.08.07.Epic_Turla_Operation_Appendix/KL_Epic_Turla_Technical_Appendix_20140806.pdf) _(via “Turla”)_
- 2014 — [The_Epic_Turla_Operation](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2014/2014.08.07.Epic_Turla_Operation_Appendix/The_Epic_Turla_Operation.pdf) _(via “Turla”)_
- 2014 — [Turla_2_Penquin](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2014/2014.12.08.Penquin_Turla/Turla_2_Penquin.pdf) _(via “Turla”)_
- 2015 — [waterbug-attack-group](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2015/2015.01.22.Waterbug.group/waterbug-attack-group.pdf) _(via “Waterbug”)_
- 2015 — [Satellite Turla_ APT Command and Control in the Sky - Securelist](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2015/2015.09.09.satellite-turla-apt/Satellite%20Turla_%20APT%20Command%20and%20Control%20in%20the%20Sky%20-%20Securelist.pdf) _(via “Turla”)_
- 2015 — [Satellite-turla-apt-command-and-control-in-the-sky](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2015/2015.09.09.satellite-turla-apt/Satellite-turla-apt-command-and-control-in-the-sky.pdf) _(via “Turla”)_
- 2016 — [waterbug-attack-group](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2016/2016.01.14.The.Waterbug.Attack.Group/waterbug-attack-group.pdf) _(via “Waterbug”)_
- 2017 — [Turla_APT](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2017/2017.08.17.turla-apt-actor-refreshes-kopiluwak-javascript-backdoor/Turla_APT.pdf) _(via “Turla”)_
- 2017 — [Introducing WhiteBear - Securelist](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2017/2017.08.30.Introducing_WhiteBear/Introducing%20WhiteBear%20-%20Securelist.pdf) _(via “WhiteBear”)_
- 2018 — [ESET_Turla_Mosquito](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2018/2018.01.09.Turla_Mosquito/ESET_Turla_Mosquito.pdf) _(via “Turla”)_
- 2018 — [blog](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2018/2018.01.09.Turla_Mosquito/blog.pdf) _(via “Turla”)_
- 2018 — [Turla Neuron Malware Update](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2018/2018.01.18.Turla_group_update_Neuron_malware/Turla%20Neuron%20Malware%20Update.pdf) _(via “Turla”)_
- 2018 — [turla-mosquito-shift-towards-generic-tools](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2018/2018.05.22.Turla_Mosquito/turla-mosquito-shift-towards-generic-tools.pdf) _(via “Turla”)_
- 2018 — [Eset-Turla-Outlook-Backdoor](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2018/2018.08.21.Turla.Outlook.Backdoor/Eset-Turla-Outlook-Backdoor.pdf) _(via “Turla”)_
- 2019 — [ESET-LightNeuron](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2019/2019.05.07.Turla_LightNeuron/ESET-LightNeuron.pdf) _(via “Turla”)_
- 2019 — [A dive into Turla PowerShell usage](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2019/2019.05.29.Turla_PowerShell/A%20dive%20into%20Turla%20PowerShell%20usage.pdf) _(via “Turla”)_
- 2019 — [Waterbug_ Espionage Group Rolls Out Brand-New Toolset in Attacks Against Governments](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2019/2019.06.21.Waterbug/Waterbug_%20Espionage%20Group%20Rolls%20Out%20Brand-New%20Toolset%20in%20Attacks%20Against%20Governments.pdf) _(via “Waterbug”)_
- 2020 — [Tracking Turla_ New backdoor delivered via Armenian watering holes _ WeLiveSecurity](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2020/2020.03.12_Tracking_Turla/Tracking%20Turla_%20New%20backdoor%20delivered%20via%20Armenian%20watering%20holes%20_%20WeLiveSecurity.pdf) _(via “Turla”)_
- 2020 — [ESET_Turla_ComRAT](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2020/2020.05.26_From_Agent.BTZ_to_ComRAT/ESET_Turla_ComRAT.pdf) _(via “Turla”)_
- 2020 — [AcidBox_ Rare Malware Repurposing Turla Group Exploit Targeted Russian Organizations](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2020/2020.06.17.AcidBox/AcidBox_%20Rare%20Malware%20Repurposing%20Turla%20Group%20Exploit%20Targeted%20Russian%20Organizations.pdf) _(via “Turla”)_
- 2020 — [Turla _ Venomous Bear updates its arsenal_ _NewPass_ appears on the APT threat scene - Telsy](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2020/2020.07.14_Turla_VENOMOUS_BEAR/Turla%20_%20Venomous%20Bear%20updates%20its%20arsenal_%20_NewPass_%20appears%20on%20the%20APT%20threat%20scene%20-%20Telsy.pdf) _(via “Turla”)_

## 11. Bibliografia (30 fontes citadas pelo ATT&CK)

- [Accenture HyperStack October 2020](https://web.archive.org/web/20201101015247/https://www.accenture.com/us-en/blogs/cyber-defense/turla-belugasturgeon-compromises-government-entity) — Accenture. (2020, October). Turla uses HyperStack, Carbon, and Kazuar to compromise government entity. Retrieved December 2, 2020.
- [Crowdstrike GTR2020 Mar 2020](https://go.crowdstrike.com/rs/281-OBQ-266/images/Report2020CrowdStrikeGlobalThreatReport.pdf) — Crowdstrike. (2020, March 2). 2020 Global Threat Report. Retrieved December 11, 2020.
- [CrowdStrike VENOMOUS BEAR](https://www.crowdstrike.com/blog/meet-crowdstrikes-adversary-of-the-month-for-march-venomous-bear/) — Meyers, A. (2018, March 12). Meet CrowdStrike’s Adversary of the Month for March: VENOMOUS BEAR. Retrieved May 16, 2018.
- [ESET Carbon Mar 2017](https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/) — ESET. (2017, March 30). Carbon Paper: Peering into Turla’s second stage backdoor. Retrieved November 7, 2018.
- [ESET ComRAT May 2020](https://www.welivesecurity.com/wp-content/uploads/2020/05/ESET_Turla_ComRAT.pdf) — Faou, M. (2020, May). From Agent.btz to ComRAT v4: A ten-year journey. Retrieved June 15, 2020.
- [ESET Crutch December 2020](https://www.welivesecurity.com/2020/12/02/turla-crutch-keeping-back-door-open/) — Faou, M. (2020, December 2). Turla Crutch: Keeping the “back door” open. Retrieved December 4, 2020.
- [ESET Gazer Aug 2017](https://www.welivesecurity.com/wp-content/uploads/2017/08/eset-gazer.pdf) — ESET. (2017, August). Gazing at Gazer: Turla’s new second stage backdoor. Retrieved September 14, 2017.
- [ESET LightNeuron May 2019](https://www.welivesecurity.com/wp-content/uploads/2019/05/ESET-LightNeuron.pdf) — Faou, M. (2019, May). Turla LightNeuron: One email away from remote code execution. Retrieved June 24, 2019.
- [ESET Turla August 2018](https://www.welivesecurity.com/wp-content/uploads/2018/08/Eset-Turla-Outlook-Backdoor.pdf) — ESET. (2018, August). Turla Outlook Backdoor: Analysis of an unusual Turla backdoor. Retrieved March 11, 2019.
- [ESET Turla Lunar toolset May 2024](https://www.welivesecurity.com/en/eset-research/moon-backdoors-lunar-landing-diplomatic-missions/) — Jurčacko, F. (2024, May 15). To the Moon and back(doors): Lunar landing in diplomatic missions. Retrieved June 26, 2024.
- [ESET Turla Mosquito Jan 2018](https://www.welivesecurity.com/wp-content/uploads/2018/01/ESET_Turla_Mosquito.pdf) — ESET, et al. (2018, January). Diplomats in Eastern Europe bitten by a Turla mosquito. Retrieved July 3, 2018.
- [ESET Turla Mosquito May 2018](https://www.welivesecurity.com/2018/05/22/turla-mosquito-shift-towards-generic-tools/) — ESET Research. (2018, May 22). Turla Mosquito: A shift towards more generic tools. Retrieved July 3, 2018.
- [ESET Turla PowerShell May 2019](https://www.welivesecurity.com/2019/05/29/turla-powershell-usage/) — Faou, M. and Dumont R.. (2019, May 29). A dive into Turla PowerShell usage. Retrieved June 14, 2019.
- [Github Rapid7 Meterpreter Elevate](https://github.com/rapid7/meterpreter/tree/master/source/extensions/priv/server/elevate) — Rapid7. (2013, November 26). meterpreter/source/extensions/priv/server/elevate/. Retrieved July 8, 2018.
- [GitHub Turla Driver Loader](https://github.com/hfiref0x/TDL) — TDL Project. (2016, February 4). TDL (Turla Driver Loader). Retrieved April 22, 2021.
- [Joint Cybersecurity Advisory AA23-129A Snake Malware May 2023](https://www.cisa.gov/sites/default/files/2023-05/aa23-129a_snake_malware_2.pdf) — FBI et al. (2023, May 9). Hunting Russian Intelligence “Snake” Malware. Retrieved June 8, 2023.
- [Kaspersky Turla](https://securelist.com/the-epic-turla-operation/65545/) — Kaspersky Lab's Global Research and Analysis Team. (2014, August 7). The Epic Turla Operation: Solving some of the mysteries of Snake/Uroburos. Retrieved December 11, 2014.
- [Leonardo Turla Penquin May 2020](https://www.leonardo.com/documents/20142/10868623/Malware+Technical+Insight+_Turla+%E2%80%9CPenquin_x64%E2%80%9D.pdf) — Leonardo. (2020, May 29). MALWARE TECHNICAL INSIGHT TURLA “Penquin_x64”. Retrieved March 11, 2021.
- [Mandiant Suspected Turla Campaign February 2023](https://www.mandiant.com/resources/blog/turla-galaxy-opportunity) — Hawley, S. et al. (2023, February 2). Turla: A Galaxy of Opportunity. Retrieved May 15, 2023.
- [Microsoft Threat Actor Naming July 2023](https://learn.microsoft.com/en-us/microsoft-365/security/intelligence/microsoft-threat-actor-naming?view=o365-worldwide) — Microsoft . (2023, July 12). How Microsoft names threat actors. Retrieved November 17, 2023.
- [NSA NCSC Turla OilRig](https://media.defense.gov/2019/Oct/18/2002197242/-1/-1/0/NSA_CSA_Turla_20191021%20ver%204%20-%20nsa.gov.pdf) — NSA/NCSC. (2019, October 21). Cybersecurity Advisory: Turla Group Exploits Iranian APT To Expand Coverage Of Victims. Retrieved October 16, 2020.
- [Recorded Future Turla Infra 2020](https://www.recordedfuture.com/research/turla-apt-infrastructure) — Insikt Group. (2020, March 12). Swallowing the Snake’s Tail: Tracking Turla Infrastructure. Retrieved September 16, 2024.
- [Securelist WhiteBear Aug 2017](https://securelist.com/introducing-whitebear/81638/) — Kaspersky Lab's Global Research & Analysis Team. (2017, August 30). Introducing WhiteBear. Retrieved September 21, 2017.
- [Secureworks IRON HUNTER Profile](http://www.secureworks.com/research/threat-profiles/iron-hunter) — Secureworks CTU. (n.d.). IRON HUNTER. Retrieved February 22, 2022.
- [Symantec Waterbug](https://www.threatminer.org/report.php?q=waterbug-attack-group.pdf&y=2015#gsc.tab=0&gsc.q=waterbug-attack-group.pdf&gsc.page=1) — Symantec. (2015, January 26). The Waterbug attack group. Retrieved April 10, 2015.
- [Symantec Waterbug Jun 2019](https://www.symantec.com/blogs/threat-intelligence/waterbug-espionage-governments) — Symantec DeepSight Adversary Intelligence Team. (2019, June 20). Waterbug: Espionage Group Rolls Out Brand-New Toolset in Attacks Against Governments. Retrieved July 8, 2019.
- [Talos TinyTurla September 2021](https://blog.talosintelligence.com/2021/09/tinyturla.html) — Cisco Talos. (2021, September 21). TinyTurla - Turla deploys new malware to keep a secret backdoor on victim machines. Retrieved December 2, 2021.
- [Unit 42 IronNetInjector February 2021 ](https://unit42.paloaltonetworks.com/ironnetinjector/) — Reichel, D. (2021, February 19). IronNetInjector: Turla’s New Malware Loading Tool. Retrieved February 24, 2021.
- [Unit 42 Kazuar May 2017](https://researchcenter.paloaltonetworks.com/2017/05/unit42-kazuar-multiplatform-espionage-backdoor-api-access/) — Levene, B, et al. (2017, May 03). Kazuar: Multiplatform Espionage Backdoor with API Access. Retrieved July 17, 2018.
- [Unit42 AcidBox June 2020](https://unit42.paloaltonetworks.com/acidbox-rare-malware/) — Reichel, D. and Idrizovic, E. (2020, June 17). AcidBox: Rare Malware Repurposing Turla Group Exploit Targeted Russian Organizations. Retrieved March 16, 2021.

## 12. Limites e confiança

- O ATT&CK registra o que foi **relatado publicamente**, não tudo o que o grupo faz. Ausência de uma técnica não prova que o grupo não a usa.
- **Sobreposição de TTP não é atribuição.** Muitas técnicas são compartilhadas entre grupos e com red teams. Use a assinatura comportamental como hipótese, junto com infraestrutura, malware e contexto.
- Cobertura de detecção refere-se ao catálogo público Detection Rules, não ao seu ambiente: confira se a telemetria necessária chega ao seu SIEM.
- Ligações marcadas como _inferidas_ (EVTX por palavra-chave, relatórios por nome) devem ser verificadas.

---
Fontes: MITRE ATT&CK® (uso livre com atribuição, © The MITRE Corporation), Atomic Red Team (Red Canary, MIT), EVTX-to-MITRE-Attack, EVTX-ATTACK-SAMPLES, APT & CyberCriminal Campaign Collections. Gerado por [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules).
