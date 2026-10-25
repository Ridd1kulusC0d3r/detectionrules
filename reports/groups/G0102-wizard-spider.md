# Wizard Spider (G0102) — Dossiê de inteligência

> **TLP:CLEAR** · gerado em 2026-10-25 a partir de fontes abertas · MITRE ATT&CK v20.0 · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0102) · [ATT&CK](https://attack.mitre.org/groups/G0102/)

**Também conhecido como:** UNC1878, TEMP.MixMaster, Grim Spider, FIN12, GOLD BLACKBURN, ITG23, Periwinkle Tempest, DEV-0193, Pistachio Tempest, DEV-0237  
**Registro no ATT&CK:** criado em 2020-05-12, atualizado em 2026-07-31 · referências de 2017 a 2024

## 1. Sumário executivo

- **64 técnicas** atribuídas publicamente, concentradas em **Persistence, Stealth, Discovery**.
- **Arsenal:** 11 malware e 11 ferramentas (ex.: Cobalt Strike, Empire, TrickBot, Bazar, Emotet).
- **Campanhas atribuídas:** 0.
- **Cobertura de detecção pública:** 97% das técnicas têm ao menos uma regra no catálogo; **2 técnicas sem nenhuma regra pública**.
- **Assinatura comportamental** (técnicas raras entre os 178 grupos, as mais úteis para atribuição): T1518.002 Backup Software Discovery, T1222.001 Windows Permissions, T1552.006 Group Policy Preferences, T1557.001 Name Resolution Poisoning and SMB Relay, T1021 Remote Services.

## 2. Quem é

> Wizard Spider is a Russia-based financially motivated threat group originally known for the creation and deployment of TrickBot since at least 2016. Wizard Spider possesses a diverse arsenal of tools and has conducted ransomware campaigns against a variety of organizations, ranging from major corporations to hospitals.

_Texto original do MITRE ATT&CK, em inglês._

## 3. Perfil TTP por tática (kill chain)

Cada linha: técnica, como o grupo a usou segundo relatos públicos, e o que existe para detectar e testar.

### Resource Development (TA0042) — 3

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1585.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1585.002) Email Accounts | Wizard Spider has leveraged ProtonMail email addresses in ransom notes when delivering Ryuk ransomware. | **0** | — | — |
| [T1588.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1588.002) Tool | Wizard Spider has utilized tools such as Empire, Cobalt Strike, Cobalt Strike, Rubeus, AdFind, BloodHound, Metasploit, Advanced IP Scanner, Nirsoft PingInfoView, and SoftPerfect Network Scanner for targeting efforts. | 35 | — | — |
| [T1588.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1588.003) Code Signing Certificates | Wizard Spider has obtained code signing certificates signed by DigiCert, GlobalSign, and COMOOD for malware payloads. | 1 | — | — |

### Initial Access (TA0001) — 5

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | Wizard Spider has used valid credentials for privileged accounts with the goal of accessing domain controllers. | 825 | — | 3 |
| [T1078.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.002) Domain Accounts | Wizard Spider has used administrative accounts, including Domain Admin, to move laterally within a victim network. | 36 | — | 1 |
| [T1133](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1133) External Remote Services | Wizard Spider has accessed victim networks by using stolen credentials to access the corporate VPN infrastructure. | 361 | 1 | — |
| [T1566.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1566.001) Spearphishing Attachment | Wizard Spider has used spearphishing attachments to deliver Microsoft documents containing macros or PDFs containing malicious links to download either Emotet, Bokbot, TrickBot, or Bazar. | 230 | 2 | — |
| [T1566.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1566.002) Spearphishing Link | Wizard Spider has sent phishing emails containing a link to an actor-controlled Google Drive document or other free online file hosting services. | 138 | 1 | — |

### Execution (TA0002) — 8

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1047](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1047) Windows Management Instrumentation | Wizard Spider has used WMI and LDAP queries for network discovery and to move laterally. Wizard Spider has also used batch scripts to leverage WMIC to deploy ransomware. | 370 | 12 | 11 |
| [T1053.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1053.005) Scheduled Task | Wizard Spider has used scheduled tasks to establish persistence for TrickBot and other malware. | 248 | 14 | 11 |
| [T1059.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.001) PowerShell | Wizard Spider has used macros to execute PowerShell scripts to download malware on victim's machines. It has also used PowerShell to execute commands and move laterally through a victim network. | 1340 | 22 | 15 |
| [T1059.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.003) Windows Command Shell | Wizard Spider has used `cmd.exe` to execute commands on a victim's machine. | 269 | 6 | 1 |
| [T1197](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1197) BITS Jobs | Wizard Spider has used batch scripts that utilizes WMIC to execute a BITSAdmin transfer of a ransomware payload to each compromised machine. | 94 | 4 | 8 |
| [T1204.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1204.001) Malicious Link | Wizard Spider has lured victims into clicking a malicious link delivered through spearphishing. | 52 | — | — |
| [T1204.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1204.002) Malicious File | Wizard Spider has lured victims to execute malware with spearphishing attachments containing macros to download either Emotet, Bokbot, TrickBot, or Bazar. | 259 | 13 | — |
| [T1569.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1569.002) Service Execution | Wizard Spider has used `services.exe` to execute scripts and executables during lateral movement within a victim's network. Wizard Spider has also used batch scripts that leverage PsExec to execute a previously transferred ransomware payload on a victim's netw… | 230 | 8 | 8 |

### Persistence (TA0003) — 11

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1053.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1053.005) Scheduled Task | Wizard Spider has used scheduled tasks to establish persistence for TrickBot and other malware. | 248 | 14 | 11 |
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | Wizard Spider has used valid credentials for privileged accounts with the goal of accessing domain controllers. | 825 | — | 3 |
| [T1078.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.002) Domain Accounts | Wizard Spider has used administrative accounts, including Domain Admin, to move laterally within a victim network. | 36 | — | 1 |
| [T1112](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1112) Modify Registry | Wizard Spider has modified the Registry key HKLM\System\CurrentControlSet\Control\SecurityProviders\WDigest by setting the UseLogonCredential registry value to 1 in order to force credentials to be stored in clear text in memory. Wizard Spider has also modifie… | 601 | 92 | 3 |
| [T1133](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1133) External Remote Services | Wizard Spider has accessed victim networks by using stolen credentials to access the corporate VPN infrastructure. | 361 | 1 | — |
| [T1136.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1136.001) Local Account | Wizard Spider has created local administrator accounts to maintain persistence in compromised networks. | 103 | 10 | — |
| [T1136.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1136.002) Domain Account | Wizard Spider has created and used new accounts within a victim's Active Directory environment to maintain persistence. | 27 | 5 | — |
| [T1197](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1197) BITS Jobs | Wizard Spider has used batch scripts that utilizes WMIC to execute a BITSAdmin transfer of a ransomware payload to each compromised machine. | 94 | 4 | 8 |
| [T1543.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1543.003) Windows Service | Wizard Spider has installed TrickBot as a service named ControlServiceA in order to establish persistence. | 1916 | 6 | 19 |
| [T1547.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1547.001) Registry Run Keys / Startup Folder | Wizard Spider has established persistence via the Registry key HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run and a shortcut within the startup folder. | 299 | 21 | 2 |
| [T1547.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1547.004) Winlogon Helper DLL | Wizard Spider has established persistence using Userinit by adding the Registry key HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon. | 25 | 5 | — |

### Privilege Escalation (TA0004) — 8

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1053.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1053.005) Scheduled Task | Wizard Spider has used scheduled tasks to establish persistence for TrickBot and other malware. | 248 | 14 | 11 |
| [T1055](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1055) Process Injection | Wizard Spider has used process injection to execute payloads to escalate privileges. | 481 | 13 | 4 |
| [T1055.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1055.001) Dynamic-link Library Injection | Wizard Spider has injected malicious DLLs into memory with read, write, and execute permissions. | 40 | 2 | — |
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | Wizard Spider has used valid credentials for privileged accounts with the goal of accessing domain controllers. | 825 | — | 3 |
| [T1078.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.002) Domain Accounts | Wizard Spider has used administrative accounts, including Domain Admin, to move laterally within a victim network. | 36 | — | 1 |
| [T1543.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1543.003) Windows Service | Wizard Spider has installed TrickBot as a service named ControlServiceA in order to establish persistence. | 1916 | 6 | 19 |
| [T1547.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1547.001) Registry Run Keys / Startup Folder | Wizard Spider has established persistence via the Registry key HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run and a shortcut within the startup folder. | 299 | 21 | 2 |
| [T1547.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1547.004) Winlogon Helper DLL | Wizard Spider has established persistence using Userinit by adding the Registry key HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon. | 25 | 5 | — |

### Stealth (TA0005) — 9

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1027.010](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1027.010) Command Obfuscation | Wizard Spider used Base64 encoding to obfuscate an Empire service and PowerShell commands. | 78 | — | — |
| [T1036.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1036.004) Masquerade Task or Service | Wizard Spider has used scheduled tasks to install TrickBot, using task names to appear legitimate such as WinDotNet, GoogleTask, or Sysnetsf. It has also used common document file names for other malware binaries. | 31 | 4 | — |
| [T1055](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1055) Process Injection | Wizard Spider has used process injection to execute payloads to escalate privileges. | 481 | 13 | 4 |
| [T1055.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1055.001) Dynamic-link Library Injection | Wizard Spider has injected malicious DLLs into memory with read, write, and execute permissions. | 40 | 2 | — |
| [T1070.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1070.004) File Deletion | Wizard Spider has used file deletion to remove some modules and configurations from an infected host after use. | 132 | 11 | — |
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | Wizard Spider has used valid credentials for privileged accounts with the goal of accessing domain controllers. | 825 | — | 3 |
| [T1078.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.002) Domain Accounts | Wizard Spider has used administrative accounts, including Domain Admin, to move laterally within a victim network. | 36 | — | 1 |
| [T1197](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1197) BITS Jobs | Wizard Spider has used batch scripts that utilizes WMIC to execute a BITSAdmin transfer of a ransomware payload to each compromised machine. | 94 | 4 | 8 |
| [T1218.011](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1218.011) Rundll32 | Wizard Spider has utilized `rundll32.exe` to deploy ransomware commands with the use of WebDAV. | 274 | 16 | 12 |

### Defense Impairment (TA0112) — 4

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1112](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1112) Modify Registry | Wizard Spider has modified the Registry key HKLM\System\CurrentControlSet\Control\SecurityProviders\WDigest by setting the UseLogonCredential registry value to 1 in order to force credentials to be stored in clear text in memory. Wizard Spider has also modifie… | 601 | 92 | 3 |
| [T1222.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1222.001) Windows Permissions | Wizard Spider has used the icacls command to modify access control to backup servers, providing them with full control of all the system folders. | 31 | 6 | 6 |
| [T1553.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1553.002) Code Signing | Wizard Spider has used Digicert code-signing certificates for some of its malware. | 11 | — | — |
| [T1685](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1685) Disable or Modify Tools | Wizard Spider has shut down or uninstalled security applications on victim systems that might prevent ransomware from executing. | 1275 | 78 | 19 |

### Credential Access (TA0006) — 7

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1003.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1003.001) LSASS Memory | Wizard Spider has dumped the lsass.exe memory to harvest credentials with the use of open-source tool LaZagne. | 580 | 14 | 10 |
| [T1003.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1003.002) Security Account Manager | Wizard Spider has acquired credentials from the SAM/SECURITY registry hives. | 169 | 8 | — |
| [T1003.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1003.003) NTDS | Wizard Spider has gained access to credentials via exported copies of the ntds.dit Active Directory database. Wizard Spider has also created a volume shadow copy and used a batch script file to collect NTDS.dit with the use of the Windows utility, ntdsutil. | 157 | 11 | 2 |
| [T1552.006](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1552.006) Group Policy Preferences | Wizard Spider has used PowerShell cmdlets `Get-GPPPassword` and `Find-GPOPassword` to find unsecured credentials in a compromised network group policy. | 31 | 2 | — |
| [T1555.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1555.004) Windows Credential Manager | Wizard Spider has used PowerShell cmdlet `Invoke-WCMDump` to enumerate Windows credentials in the Credential Manager in a compromised network. | 37 | 2 | 1 |
| [T1557.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1557.001) Name Resolution Poisoning and SMB Relay | Wizard Spider has used the Invoke-Inveigh PowerShell cmdlets, likely for name service poisoning. | 68 | 1 | — |
| [T1558.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1558.003) Kerberoasting | Wizard Spider has used Rubeus, MimiKatz Kerberos module, and the Invoke-Kerberoast cmdlet to steal AES hashes. | 132 | 7 | — |

### Discovery (TA0007) — 8

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1016](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1016) System Network Configuration Discovery | Wizard Spider has used ipconfig to identify the network configuration of a victim machine. Wizard Spider has also used the PowerShell cmdlet `Get-ADComputer` to collect IP address data from Active Directory. | 99 | 10 | 5 |
| [T1018](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1018) Remote System Discovery | Wizard Spider has used networkdll for network discovery and psfin specifically for financial and point of sale indicators. Wizard Spider has also used AdFind, nltest/dclist, and PowerShell script Get-DataInfo.ps1 to enumerate domain computers, including the do… | 157 | 23 | 1 |
| [T1033](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1033) System Owner/User Discovery | Wizard Spider has used "whoami" to identify the local user and their privileges. | 181 | 8 | — |
| [T1082](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1082) System Information Discovery | Wizard Spider has used Systeminfo and similar commands to acquire detailed configuration information of a victim's machine. Wizard Spider has also utilized the PowerShell cmdlet `Get-ADComputer` to collect DNS hostnames, last logon dates, and operating system … | 264 | 41 | — |
| [T1087.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1087.002) Domain Account | Wizard Spider has identified domain admins through the use of `net group "Domain admins" /DOMAIN`. Wizard Spider has also leveraged the PowerShell cmdlet `Get-ADComputer` to collect account names from Active Directory data. | 180 | 25 | 1 |
| [T1135](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1135) Network Share Discovery | Wizard Spider has used the “net view” command to locate mapped network shares. | 73 | 12 | 3 |
| [T1518.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1518.001) Security Software Discovery | Wizard Spider has used WMI to identify anti-virus products installed on a victim's machine. | 54 | 12 | — |
| [T1518.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1518.002) Backup Software Discovery | Wizard Spider has utilized the PowerShell script `Get-DataInfo.ps1` to collect installed backup software information from a compromised machine. | **0** | — | — |

### Lateral Movement (TA0008) — 7

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1021](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1021) Remote Services | Wizard Spider has used the WebDAV protocol to execute Ryuk payloads hosted on network file shares. | 289 | — | 47 |
| [T1021.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1021.001) Remote Desktop Protocol | Wizard Spider has used RDP for lateral movement and to deploy ransomware interactively. | 139 | 4 | 7 |
| [T1021.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1021.002) SMB/Windows Admin Shares | Wizard Spider has used SMB to drop Cobalt Strike Beacon on a domain controller for lateral movement. | 272 | 4 | 20 |
| [T1021.006](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1021.006) Windows Remote Management | Wizard Spider has used Window Remote Management to move laterally through a victim network. | 74 | 3 | 5 |
| [T1210](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1210) Exploitation of Remote Services | Wizard Spider has exploited or attempted to exploit Zerologon (CVE-2020-1472) and EternalBlue (MS17-010) vulnerabilities. | 192 | — | 4 |
| [T1550.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1550.002) Pass the Hash | Wizard Spider has used the `Invoke-SMBExec` PowerShell cmdlet to execute the pass-the-hash technique and utilized stolen password hashes to move laterally. | 43 | 3 | 1 |
| [T1570](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1570) Lateral Tool Transfer | Wizard Spider has used stolen credentials to copy tools into the %TEMP% directory of domain controllers. | 58 | 2 | — |

### Collection (TA0009) — 5

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1005) Data from Local System | Wizard Spider has collected data from a compromised host prior to exfiltration. | 170 | 3 | — |
| [T1074](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1074) Data Staged | Wizard Spider has collected and staged credentials and network enumeration information, using the networkdll and psfin TrickBot modules. | 40 | — | — |
| [T1074.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1074.001) Local Data Staging | Wizard Spider has staged ZIP files in local directories such as, `C:\PerfLogs\1\` and `C:\User\1\` prior to exfiltration. | 37 | 3 | — |
| [T1557.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1557.001) Name Resolution Poisoning and SMB Relay | Wizard Spider has used the Invoke-Inveigh PowerShell cmdlets, likely for name service poisoning. | 68 | 1 | — |
| [T1560.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1560.001) Archive via Utility | Wizard Spider has archived data into ZIP files on compromised machines. | 76 | 13 | — |

### Command and Control (TA0011) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1071.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1071.001) Web Protocols | Wizard Spider has used HTTP for network communications. | 228 | 3 | — |
| [T1105](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1105) Ingress Tool Transfer | Wizard Spider can transfer malicious payloads such as ransomware to compromised machines. | 644 | 39 | — |

### Exfiltration (TA0010) — 3

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1041](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1041) Exfiltration Over C2 Channel | Wizard Spider has exfiltrated domain credentials and network enumeration information over command and control (C2) channels. | 135 | 2 | — |
| [T1048.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1048.003) Exfiltration Over Unencrypted Non-C2 Protocol | Wizard Spider has exfiltrated victim information using FTP. | 51 | 8 | — |
| [T1567.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1567.002) Exfiltration to Cloud Storage | Wizard Spider has exfiltrated stolen victim data to various cloud storage providers. | 85 | 2 | — |

### Impact (TA0040) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1489](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1489) Service Stop | Wizard Spider has used taskkill.exe and net.exe to stop backup, catalog, cloud, and other services prior to network encryption. | 112 | 9 | — |
| [T1490](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1490) Inhibit System Recovery | Wizard Spider has used WMIC and vssadmin to manually delete volume shadow copies. Wizard Spider has also used Conti ransomware to delete volume shadow copies automatically with the use of vssadmin. | 188 | 13 | 5 |

## 4. Assinatura comportamental

Técnicas que este grupo usa e que poucos dos 178 grupos do ATT&CK usam. Pesam mais numa atribuição por TTP: ver várias delas juntas é mais informativo do que ver técnicas comuns como PowerShell.

| Técnica | Outros grupos que usam | Peso (raridade) |
|---|---:|---:|
| T1518.002 Backup Software Discovery | 0 | 4.49 |
| T1222.001 Windows Permissions | 1 | 4.09 |
| T1552.006 Group Policy Preferences | 1 | 4.09 |
| T1557.001 Name Resolution Poisoning and SMB Relay | 1 | 4.09 |
| T1021 Remote Services | 2 | 3.80 |
| T1547.004 Winlogon Helper DLL | 2 | 3.80 |
| T1555.004 Windows Credential Manager | 3 | 3.58 |
| T1558.003 Kerberoasting | 3 | 3.58 |
| T1021.006 Windows Remote Management | 4 | 3.40 |
| T1074 Data Staged | 4 | 3.40 |

## 5. Arsenal

| Software | Tipo | Técnicas no ATT&CK | Uso relatado (EN) |
|---|---|---:|---|
| [Cobalt Strike](https://attack.mitre.org/software/S0154/) | malware | 73 |  |
| [Empire](https://attack.mitre.org/software/S0363/) | ferramenta | 73 |  |
| [TrickBot](https://attack.mitre.org/software/S0266/) | malware | 55 |  |
| [Bazar](https://attack.mitre.org/software/S0534/) | malware | 51 |  |
| [Emotet](https://attack.mitre.org/software/S0367/) | malware | 47 |  |
| [GrimAgent](https://attack.mitre.org/software/S0632/) | malware | 25 |  |
| [Ryuk](https://attack.mitre.org/software/S0446/) | malware | 22 |  |
| [SystemBC](https://attack.mitre.org/software/S9001/) | malware | 21 |  |
| [Anchor](https://attack.mitre.org/software/S0504/) | malware | 20 |  |
| [Diavol](https://attack.mitre.org/software/S0659/) | malware | 19 |  |
| [Mimikatz](https://attack.mitre.org/software/S0002/) | ferramenta | 17 |  |
| [Conti](https://attack.mitre.org/software/S0575/) | malware | 16 |  |
| [Dyre](https://attack.mitre.org/software/S0024/) | malware | 16 |  |
| [Net](https://attack.mitre.org/software/S0039/) | ferramenta | 16 |  |
| [BloodHound](https://attack.mitre.org/software/S0521/) | ferramenta | 11 |  |
| [LaZagne](https://attack.mitre.org/software/S0349/) | ferramenta | 10 |  |
| [Rubeus](https://attack.mitre.org/software/S1071/) | ferramenta | 5 |  |
| [AdFind](https://attack.mitre.org/software/S0552/) | ferramenta | 5 |  |
| [PsExec](https://attack.mitre.org/software/S0029/) | ferramenta | 5 |  |
| [BITSAdmin](https://attack.mitre.org/software/S0190/) | ferramenta | 4 |  |
| [Nltest](https://attack.mitre.org/software/S0359/) | ferramenta | 3 |  |
| [Ping](https://attack.mitre.org/software/S0097/) | ferramenta | 1 |  |

## 6. Campanhas

Nenhuma campanha atribuída no ATT&CK.

## 7. Cobertura defensiva

**62 de 64 técnicas (97%)** têm ao menos uma regra pública no catálogo Detection Rules.

### Técnicas sem regra pública (prioridade para engenharia de detecção)

- **T1518.002 Backup Software Discovery** — Discovery. Fonte de log sugerida pelo MITRE: `WinEventLog:Security` EventCode=4688; `auditd:SYSCALL` execve: Execution of discovery commands targeting backup binaries, processes, or config paths; `macos:unifiedlog` Process execution logs showing
- **T1585.002 Email Accounts** — Resource Development

### Regras recomendadas por técnica

Melhor regra disponível por técnica (formato portável e maduro primeiro).

| Técnica | Regra | Formato | Fonte |
|---|---|---|---|
| T1003.001 | [Antivirus - Password Dumper Signature](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A78cc2dd2-7d20-4d32-93ff-057084c38b93) | Sigma | SigmaHQ |
| T1003.001 | [Mimikatz through Windows Remote Management](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Aaa35a627-33fb-4d04-a165-d33b4afca3e8) | Sigma | OpenSearch Security Analytics |
| T1003.002 | [Antivirus - Password Dumper Signature](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A78cc2dd2-7d20-4d32-93ff-057084c38b93) | Sigma | SigmaHQ |
| T1003.002 | [VolumeShadowCopy Symlink Creation Via Mklink](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A40b19fa6-d835-400c-b301-41f3a2baacaf) | Sigma | SigmaHQ |
| T1003.003 | [Potential Russian APT Credential Theft Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab83f5166-9237-4b5e-9cd4-7b5d52f4d8ee) | Sigma | SigmaHQ |
| T1003.003 | [VolumeShadowCopy Symlink Creation Via Mklink](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A40b19fa6-d835-400c-b301-41f3a2baacaf) | Sigma | SigmaHQ |
| T1005 | [Potential Conti Ransomware Database Dumping Activity Via SQLCmd](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A2f47f1fd-0901-466e-a770-3b7092834a1b) | Sigma | SigmaHQ |
| T1005 | [OpenCanary - SMB File Open Request](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A22777c9e-873a-4b49-855f-6072ab861a52) | Sigma | SigmaHQ |
| T1016 | [Potential Pikabot Discovery Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A698d4431-514f-4c82-af4d-cf573872a9f5) | Sigma | SigmaHQ |
| T1016 | [OpenCanary - SNMP OID Request](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae9856028-fd4e-46e6-b3d1-10f7ceb95078) | Sigma | SigmaHQ |
| T1018 | [Chopper Webshell Process Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Afa3c117a-bc0d-416e-a31b-0c0e80653efb) | Sigma | SigmaHQ |
| T1018 | [Webshell Hacking Activity Patterns](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4ebc877f-4612-45cb-b3a5-8e3834db36c9) | Sigma | SigmaHQ |
| T1021 | [New RDP Connection Initiated From Domain Controller](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Afda34293-718e-4b36-b018-38caab0d1209) | Sigma | SigmaHQ |
| T1021 | [OpenCanary - VNC Connection Attempt](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A9db5446c-b44a-4291-8b89-fcab5609c3b3) | Sigma | SigmaHQ |
| T1021.001 | [Hermetic Wiper TG Process Patterns](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A2f974656-6d83-4059-bbdf-68ac5403422f) | Sigma | SigmaHQ |
| T1021.001 | [Publicly Accessible RDP Service](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1fc0809e-06bf-4de3-ad52-25e5263b7623) | Sigma | SigmaHQ |
| T1021.002 | [PSExec Lateral Movement](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=hayabusa-native%3A%3A0694c340-3a46-40ac-acfc-c3444ae6572c) | Sigma | Hayabusa (native) |
| T1021.002 | [Turla Group Lateral Movement](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac601f20d-570a-4cde-a7d6-e17f99cb8e7f) | Sigma | SigmaHQ |
| T1021.006 | [OMIGOD HTTP No Authentication RCE - CVE-2021-38647](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aab6b1a39-a9ee-4ab4-b075-e83acf6e346b) | Sigma | SigmaHQ |
| T1021.006 | [Remote LSASS Process Access Through Windows Remote Management](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aaa35a627-33fb-4d04-a165-d33b4afca3e8) | Sigma | SigmaHQ |
| T1027.010 | [Decoded Payload Piped to Interpreter Detected via Defend for Containers](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A0fb83aa0-3d17-41e9-b09c-56397bf7a7d9) | Elastic | Elastic detection-rules |
| T1027.010 | [Potential PowerShell Obfuscation via String Concatenation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Af6d8c743-0916-4483-8333-3c6f107e0caa) | Elastic | Elastic detection-rules |
| T1033 | [Potential Dridex Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae6eb5a96-9e6f-4a18-9cdd-642cfda21c8e) | Sigma | SigmaHQ |
| T1033 | [Dridex Process Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Ae6eb5a96-9e6f-4a18-9cdd-642cfda21c8e) | Sigma | OpenSearch Security Analytics |
| T1036.004 | [Operation Wocao Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1cfac73c-be78-4f9a-9b08-5bde0c3953ab) | Sigma | SigmaHQ |
| T1036.004 | [Operation Wocao Activity - Security](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A74ad4314-482e-4c3e-b237-3f7ed3b9ca8d) | Sigma | SigmaHQ |
| T1041 | [Equation Group C2 Communication](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A881834a4-6659-4773-821e-1c151789d873) | Sigma | SigmaHQ |
| T1041 | [OpenCanary - TFTP Request](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab4e6b016-a2ac-4759-ad85-8000b300d61e) | Sigma | SigmaHQ |
| T1047 | [HackTool - Potential Impacket Lateral Movement Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A10c14723-61c7-4c75-92ca-9af245723ad2) | Sigma | SigmaHQ |
| T1047 | [CrackMapExec Command Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A058f4380-962d-40a5-afce-50207d36d7e2) | Sigma | OpenSearch Security Analytics |
| T1048.003 | [Suspicious WebDav Client Execution Via Rundll32.EXE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A982e9f2d-1a85-4d5b-aea4-31f5e97c6555) | Sigma | SigmaHQ |
| T1048.003 | [Possible DNS Tunneling](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A1ec4b281-aa65-46a2-bdae-5fd830ed914e) | Sigma | OpenSearch Security Analytics |
| T1053.005 | [Operation Wocao Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1cfac73c-be78-4f9a-9b08-5bde0c3953ab) | Sigma | SigmaHQ |
| T1053.005 | [Operation Wocao Activity - Security](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A74ad4314-482e-4c3e-b237-3f7ed3b9ca8d) | Sigma | SigmaHQ |
| T1055 | [Potential Dridex Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae6eb5a96-9e6f-4a18-9cdd-642cfda21c8e) | Sigma | SigmaHQ |
| T1055 | [Antivirus PrinterNightmare CVE-2021-34527 Exploit Detection](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A6fe1719e-ecdf-4caf-bffe-4f501cb0a561) | Sigma | SigmaHQ |
| T1055.001 | [TAIDOOR RAT DLL Load](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad1aa3382-abab-446f-96ea-4de52908210b) | Sigma | SigmaHQ |
| T1055.001 | [Renamed ZOHO Dctask64 Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A340a090b-c4e9-412e-bb36-b4b16fe96f9b) | Sigma | SigmaHQ |
| T1059.001 | [Potential Emotet Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad02e8cf5-6099-48cf-9bfc-1eec2d0c7b18) | Sigma | SigmaHQ |
| T1059.001 | [TropicTrooper Campaign November 2018](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A8c7090c3-e0a0-4944-bd08-08c3a0cecf79) | Sigma | SigmaHQ |
| T1059.003 | [HackTool - CrackMapExec Execution Patterns](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A058f4380-962d-40a5-afce-50207d36d7e2) | Sigma | SigmaHQ |
| T1059.003 | [CrackMapExec Command Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A058f4380-962d-40a5-afce-50207d36d7e2) | Sigma | OpenSearch Security Analytics |
| T1070.004 | [File Deletion](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A30aed7b6-d2c1-4eaf-9382-b6bc43e50c57) | Sigma | SigmaHQ |
| T1070.004 | [Prefetch File Deleted](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A0a1f9d29-6465-4776-b091-7f43b26e4c89) | Sigma | SigmaHQ |
| T1071.001 | [Ursnif Malware Download URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aa36ce77e-30db-4ea0-8795-644d7af5dfb4) | Sigma | SigmaHQ |
| T1071.001 | [Ursnif Malware C2 URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A932ac737-33ca-4afd-9869-0d48b391fcc9) | Sigma | SigmaHQ |
| T1074 | [Sensitive File Access followed by Compression](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Aa0fbd7a9-1923-4e05-92df-b484168f17bc) | Elastic | Elastic detection-rules |
| T1074 | [Cisco Stage Data](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A5e51acb2-bcbe-435b-99c6-0e3cd5e2aa59) | Sigma | SigmaHQ |
| T1074.001 | [Sensitive File Access followed by Compression](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Aa0fbd7a9-1923-4e05-92df-b484168f17bc) | Elastic | Elastic detection-rules |
| T1074.001 | [Folder Compress To Potentially Suspicious Output Via Compress-Archive Cmdlet](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A85a8e5ba-bd03-4bfb-bbfa-a4409a8f8b98+%23+Process+Creation) | Sigma | SigmaHQ |
| T1078 | [Privilege Role Sign-In Outside Expected Controls](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acf1e5687-84e1-41af-97a9-158094efef53) | Sigma | SigmaHQ |
| T1078 | [OpenCanary - SSH Login Attempt](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aff7139bc-fdb1-4437-92f2-6afefe8884cb) | Sigma | SigmaHQ |
| T1078.002 | [Malicious Usage Of IMDS Credentials Outside Of AWS Infrastructure](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A352a918a-34d8-4882-8470-44830c507aa3) | Sigma | SigmaHQ |
| T1078.002 | [AdminSDHolder SDProp Exclusion Added](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A61d29caf-6c15-4d1e-9ccb-7ad12ccc0bc7) | Elastic | Elastic detection-rules |
| T1082 | [Potential GobRAT File Discovery Via Grep](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae34cfa0c-0a50-4210-9cb3-5632d08eb041) | Sigma | SigmaHQ |
| T1082 | [System Information Discovery](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A42df45e7-e6e9-43b5-8f26-bec5b39cc239) | Sigma | SigmaHQ |
| T1087.002 | [BloodHound Collection Files](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A02773bed-83bf-469f-b7ff-e676e7d78bab) | Sigma | SigmaHQ |
| T1087.002 | [Suspicious Active Directory Database Snapshot Via ADExplorer](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aef61af62-bc74-4f58-b49b-626448227652) | Sigma | SigmaHQ |
| T1105 | [Greenbug Espionage Group Indicators](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A3711eee4-a808-4849-8a14-faf733da3612) | Sigma | SigmaHQ |
| T1105 | [Pandemic Registry Key](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A47e0852a-cf81-4494-a8e6-31864f8c86ed) | Sigma | SigmaHQ |
| T1112 | [ShimCache Flush](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab0524451-19af-4efa-a46f-562a977f792e) | Sigma | SigmaHQ |
| T1112 | [ShimCache Flush](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Ab0524451-19af-4efa-a46f-562a977f792e) | Sigma | OpenSearch Security Analytics |
| T1133 | [OpenCanary - SSH Login Attempt](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aff7139bc-fdb1-4437-92f2-6afefe8884cb) | Sigma | SigmaHQ |
| T1133 | [OpenCanary - SSH New Connection Attempt](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acd55f721-5623-4663-bd9b-5229cab5237d) | Sigma | SigmaHQ |
| T1135 | [Potential Dridex Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae6eb5a96-9e6f-4a18-9cdd-642cfda21c8e) | Sigma | SigmaHQ |
| T1135 | [Dridex Process Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Ae6eb5a96-9e6f-4a18-9cdd-642cfda21c8e) | Sigma | OpenSearch Security Analytics |
| T1136.001 | [DarkGate - User Created Via Net.EXE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Abf906d7b-7070-4642-8383-e404cf26eba5) | Sigma | SigmaHQ |
| T1136.001 | [Serv-U Exploitation CVE-2021-35211 by DEV-0322](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A75578840-9526-4b2a-9462-af469a45e767) | Sigma | SigmaHQ |
| T1136.002 | [PSExec Lateral Movement](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=hayabusa-native%3A%3A0694c340-3a46-40ac-acfc-c3444ae6572c) | Sigma | Hayabusa (native) |
| T1136.002 | [PSEXEC Remote Execution File Artefact](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A304afd73-55a5-4bb9-8c21-0b1fc84ea9e4) | Sigma | SigmaHQ |
| T1197 | [Bitsadmin to Uncommon TLD](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A9eb68894-7476-4cd6-8752-23b51f5883a7) | Sigma | SigmaHQ |
| T1197 | [Bitsadmin to Uncommon IP Server Address](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A8ccd35a2-1c7c-468b-b568-ac6cdf80eec3) | Sigma | SigmaHQ |
| T1204.001 | [Google Workspace Object Copied from External Drive with App Consent](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Af33e68a4-bd19-11ed-b02f-f661ea17fbcc) | Elastic | Elastic detection-rules |
| T1204.001 | [Suspicious ClickFix/FileFix Execution Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad487ed4a-fd24-436d-a0b2-f4e95f7b2635) | Sigma | SigmaHQ |
| T1204.002 | [Ursnif Malware C2 URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A932ac737-33ca-4afd-9869-0d48b391fcc9) | Sigma | SigmaHQ |
| T1204.002 | [Droppers Exploiting CVE-2017-11882](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A678eb5f4-8597-4be6-8be7-905e4234b53a) | Sigma | SigmaHQ |
| T1210 | [OMIGOD HTTP No Authentication RCE - CVE-2021-38647](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aab6b1a39-a9ee-4ab4-b075-e83acf6e346b) | Sigma | SigmaHQ |
| T1210 | [OMIGOD HTTP No Authentication RCE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Aab6b1a39-a9ee-4ab4-b075-e83acf6e346b) | Sigma | OpenSearch Security Analytics |
| T1218.011 | [Equation Group DLL_U Export Function Load](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad465d1d8-27a2-4cca-9621-a800f37cf72e) | Sigma | SigmaHQ |
| T1218.011 | [APT29 2018 Phishing Campaign File Indicators](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A3a3f81ca-652c-482b-adeb-b1c804727f74) | Sigma | SigmaHQ |
| T1222.001 | [WannaCry Ransomware Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A41d40bff-377a-43e2-8e1b-2e543069e079) | Sigma | SigmaHQ |
| T1222.001 | [AD Object WriteDAC Access](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A028c7842-4243-41cd-be6f-12f3cf1a26c7) | Sigma | SigmaHQ |
| T1489 | [Delete Important Scheduled Task](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Adbc1f800-0fe0-4bc0-9c66-292c2abe3f78) | Sigma | SigmaHQ |
| T1489 | [Suspicious Windows Service Tampering](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ace72ef99-22f1-43d4-8695-419dcb5d9330) | Sigma | SigmaHQ |
| T1490 | [Potential Dtrack RAT Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Af1531fa4-5b84-4342-8f68-9cf3fdbd83d4) | Sigma | SigmaHQ |
| T1490 | [Boot Configuration Tampering Via Bcdedit.EXE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1444443e-6757-43e4-9ea4-c8fc705f79a2) | Sigma | SigmaHQ |
| T1518.001 | [Sysmon Discovery Via Default Driver Altitude Using Findstr.EXE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A37db85d1-b089-490a-a59a-c7b6f984f480) | Sigma | SigmaHQ |
| T1518.001 | [Local Firewall Rules Enumeration Via NetFirewallRule Cmdlet](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aea207a23-b441-4a17-9f76-ad5be47d51d3) | Sigma | SigmaHQ |
| T1543.003 | [PSExec Lateral Movement](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=hayabusa-native%3A%3A0694c340-3a46-40ac-acfc-c3444ae6572c) | Sigma | Hayabusa (native) |
| T1543.003 | [Suspicious Service Name](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=hayabusa-native%3A%3Acc429813-21db-4019-b520-2f19648e1ef1) | Sigma | Hayabusa (native) |
| T1547.001 | [Potential Ryuk Ransomware Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac37510b8-2107-4b78-aa32-72f251e7a844) | Sigma | SigmaHQ |
| T1547.001 | [Ryuk Ransomware](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Ac37510b8-2107-4b78-aa32-72f251e7a844) | Sigma | OpenSearch Security Analytics |
| T1547.004 | [Winlogon Notify Key Logon Persistence](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Abbf59793-6efb-4fa1-95ca-a7d288e52c88) | Sigma | SigmaHQ |
| T1547.004 | [Persistence via WMI Standard Registry Provider](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A70d12c9c-0dbd-4a1a-bc44-1467502c9cf6) | Elastic | Elastic detection-rules |
| T1550.002 | [Hacktool Ruler](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A24549159-ac1b-479c-8175-d42aea947cae) | Sigma | SigmaHQ |
| T1550.002 | [Pass the Hash Activity 2](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A8eef149c-bd26-49f2-9e5a-9b00e3af499b) | Sigma | SigmaHQ |
| T1552.006 | [LSASS Process Reconnaissance Via Findstr.EXE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Afe63010f-8823-4864-a96b-a7b4a0f7b929) | Sigma | SigmaHQ |
| T1552.006 | [Findstr GPP Passwords](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A91a2c315-9ee6-4052-a853-6f6a8238f90d) | Sigma | SigmaHQ |
| T1553.002 | [Driver Loaded (Invalid Signature)](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=hayabusa-native%3A%3A1f666722-3948-40a2-9d78-d9d374477a90) | Sigma | Hayabusa (native) |
| T1553.002 | [Driver Loaded (Expired/Revoked Cert)](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=hayabusa-native%3A%3Ac837dd6d-0c91-4593-aeab-f6a1f3ca1961) | Sigma | Hayabusa (native) |
| T1555.004 | [Suspicious Key Manager Access](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aa4694263-59a8-4608-a3a0-6f8d3a51664c) | Sigma | SigmaHQ |
| T1555.004 | [Potential Credential Access via Trusted Developer Utility](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A9d110cb3-5f4b-4c9a-b9f5-53f0a1707ae5) | Elastic | Elastic detection-rules |
| T1557.001 | [HackTool - Impacket Tools Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4627c6ae-6899-46e2-aa0c-6ebcb1becd19) | Sigma | SigmaHQ |
| T1557.001 | [HackTool - ADCSPwn Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acd8c163e-a19b-402e-bdd5-419ff5859f12) | Sigma | SigmaHQ |
| T1558.003 | [HackTool - Rubeus Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A7ec2c172-dceb-4c10-92c9-87c1881b7e18) | Sigma | SigmaHQ |
| T1558.003 | [Rubeus Hack Tool](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A7ec2c172-dceb-4c10-92c9-87c1881b7e18) | Sigma | OpenSearch Security Analytics |
| T1560.001 | [APT31 Judgement Panda Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A03e2746e-2b31-42f1-ab7a-eb39365b2422) | Sigma | SigmaHQ |
| T1560.001 | [Suspicious Manipulation Of Default Accounts Via Net.EXE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A5b768e71-86f2-4879-b448-81061cbae951) | Sigma | SigmaHQ |
| T1566.001 | [Ursnif Malware C2 URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A932ac737-33ca-4afd-9869-0d48b391fcc9) | Sigma | SigmaHQ |
| T1566.001 | [Droppers Exploiting CVE-2017-11882](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A678eb5f4-8597-4be6-8be7-905e4234b53a) | Sigma | SigmaHQ |
| T1566.002 | [Potential Malicious Usage of CloudTrail System Manager](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A38e7f511-3f74-41d4-836e-f57dfa18eead) | Sigma | SigmaHQ |
| T1566.002 | [Google Workspace Device Registration After OAuth from Suspicious ASN](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A012bfca7-45cb-4507-a3ba-3777167f8b81) | Elastic | Elastic detection-rules |
| T1567.002 | [APT40 Dropbox Tool User Agent](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A5ba715b6-71b7-44fd-8245-f66893e81b3d) | Sigma | SigmaHQ |
| T1567.002 | [PUA - Rclone Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae37db05d-d1f9-49c8-b464-cee1a4b11638) | Sigma | SigmaHQ |
| T1569.002 | [PSExec Lateral Movement](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=hayabusa-native%3A%3A0694c340-3a46-40ac-acfc-c3444ae6572c) | Sigma | Hayabusa (native) |
| T1569.002 | [DNS RCE CVE-2020-1350](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab5281f31-f9cc-4d0d-95d0-45b91c45b487) | Sigma | SigmaHQ |
| T1570 | [PSExec Lateral Movement](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=hayabusa-native%3A%3A0694c340-3a46-40ac-acfc-c3444ae6572c) | Sigma | Hayabusa (native) |
| T1570 | [PSEXEC Remote Execution File Artefact](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A304afd73-55a5-4bb9-8c21-0b1fc84ea9e4) | Sigma | SigmaHQ |
| T1588.002 | [Hacktool Execution - Imphash](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A24e3e58a-646b-4b50-adef-02ef935b9fc8) | Sigma | SigmaHQ |
| T1588.002 | [Renamed SysInternals DebugView Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acd764533-2e07-40d6-a718-cfeec7f2da7f) | Sigma | SigmaHQ |
| T1588.003 | [Short-lived ephemeral code signing certificates](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-hunting-queries%3A%3Ae920899f-edf0-446c-bb13-effbaf61b27b) | Sentinel KQL | Microsoft Sentinel (Hunting Queries) |
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
| Execution | [T1204.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1204.002/T1204.002.md) | OSTap Style Macro Execution | windows |
| Execution | [T1204.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1204.002/T1204.002.md) | OSTap Payload Download | windows |
| Execution | [T1569.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1569.002/T1569.002.md) | Execute a Command as a Service | windows |
| Execution | [T1569.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1569.002/T1569.002.md) | Use PsExec to execute a command on a remote host | windows |
| Persistence | [T1133](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1133/T1133.md) | Running Chrome VPN Extensions via the Registry 2 vpn extension | windows |
| Persistence | [T1136.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1136.001/T1136.001.md) | Create a user account on a Linux system | linux |
| Persistence | [T1136.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1136.001/T1136.001.md) | Create a user account on a FreeBSD system | linux |
| Persistence | [T1136.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1136.002/T1136.002.md) | Create a new Windows domain admin user | windows |
| Persistence | [T1136.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1136.002/T1136.002.md) | Create a new account similar to ANONYMOUS LOGON | windows |
| Persistence | [T1543.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1543.003/T1543.003.md) | Modify Fax service to run PowerShell | windows |
| Persistence | [T1543.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1543.003/T1543.003.md) | Service Installation CMD | windows |
| Persistence | [T1547.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1547.001/T1547.001.md) | Reg Key Run | windows |
| Persistence | [T1547.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1547.001/T1547.001.md) | Reg Key RunOnce | windows |
| Persistence | [T1547.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1547.004/T1547.004.md) | Winlogon Shell Key Persistence - PowerShell | windows |
| Persistence | [T1547.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1547.004/T1547.004.md) | Winlogon Userinit Key Persistence - PowerShell | windows |
| Stealth | [T1036.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.004/T1036.004.md) | Creating W32Time similar named service using schtasks | windows |
| Stealth | [T1036.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.004/T1036.004.md) | Creating W32Time similar named service using sc | windows |
| Stealth | [T1055](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1055/T1055.md) | Shellcode execution via VBA | windows |
| Stealth | [T1055](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1055/T1055.md) | Remote Process Injection in LSASS via mimikatz | windows |
| Stealth | [T1055.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1055.001/T1055.001.md) | Process Injection via mavinject.exe | windows |
| Stealth | [T1055.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1055.001/T1055.001.md) | WinPwn - Get SYSTEM shell - Bind System Shell using UsoClient DLL load technique | windows |
| Stealth | [T1070.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.004/T1070.004.md) | Delete a single file - FreeBSD/Linux/macOS | linux, macos |
| Stealth | [T1070.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.004/T1070.004.md) | Delete an entire folder - FreeBSD/Linux/macOS | linux, macos |
| Stealth | [T1197](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1197/T1197.md) | Bitsadmin Download (cmd) | windows |
| Stealth | [T1197](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1197/T1197.md) | Bitsadmin Download (PowerShell) | windows |
| Stealth | [T1218.011](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.011/T1218.011.md) | Rundll32 execute JavaScript Remote Payload With GetObject | windows |
| Stealth | [T1218.011](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.011/T1218.011.md) | Rundll32 execute VBscript command | windows |
| Defense Impairment | [T1112](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1112/T1112.md) | Modify Registry of Current User Profile - cmd | windows |
| Defense Impairment | [T1112](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1112/T1112.md) | Modify Registry of Local Machine - cmd | windows |
| Defense Impairment | [T1222.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1222.001/T1222.001.md) | Take ownership using takeown utility | windows |
| Defense Impairment | [T1222.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1222.001/T1222.001.md) | cacls - Grant permission to specified user or group recursively | windows |
| Defense Impairment | [T1685](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1685/T1685.md) | Windows Disable LSA Protection | windows |
| Defense Impairment | [T1685](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1685/T1685.md) | Disable journal logging via systemctl utility | linux |
| Credential Access | [T1003.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/T1003.001.md) | Dump LSASS.exe Memory using ProcDump | windows |
| Credential Access | [T1003.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/T1003.001.md) | Dump LSASS.exe Memory using comsvcs.dll | windows |
| Credential Access | [T1003.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.002/T1003.002.md) | Registry dump of SAM, creds, and secrets | windows |
| Credential Access | [T1003.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.002/T1003.002.md) | Registry parse with pypykatz | windows |
| Credential Access | [T1003.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.003/T1003.003.md) | Create Volume Shadow Copy with vssadmin | windows |
| Credential Access | [T1003.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.003/T1003.003.md) | Copy NTDS.dit from Volume Shadow Copy | windows |
| Credential Access | [T1552.006](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1552.006/T1552.006.md) | GPP Passwords (findstr) | windows |
| Credential Access | [T1552.006](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1552.006/T1552.006.md) | GPP Passwords (Get-GPPPassword) | windows |
| Credential Access | [T1555.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1555.004/T1555.004.md) | Access Saved Credentials via VaultCmd | windows |
| Credential Access | [T1555.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1555.004/T1555.004.md) | WinPwn - Loot local Credentials - Invoke-WCMDump | windows |
| Credential Access | [T1557.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1557.001/T1557.001.md) | LLMNR Poisoning with Inveigh (PowerShell) | windows |
| Credential Access | [T1558.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1558.003/T1558.003.md) | Request for service tickets | windows |
| Credential Access | [T1558.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1558.003/T1558.003.md) | Rubeus kerberoast | windows |
| Discovery | [T1016](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1016/T1016.md) | System Network Configuration Discovery on Windows | windows |
| Discovery | [T1016](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1016/T1016.md) | List Windows Firewall Rules | windows |
| Discovery | [T1018](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1018/T1018.md) | Remote System Discovery - net | windows |
| Discovery | [T1018](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1018/T1018.md) | Remote System Discovery - net group Domain Computers | windows |
| Discovery | [T1033](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1033/T1033.md) | System Owner/User Discovery | windows |
| Discovery | [T1033](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1033/T1033.md) | System Owner/User Discovery | linux, macos |
| Discovery | [T1082](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1082/T1082.md) | System Information Discovery | windows |
| Discovery | [T1082](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1082/T1082.md) | System Information Discovery | macos |
| Discovery | [T1087.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1087.002/T1087.002.md) | Enumerate all accounts (Domain) | windows |
| Discovery | [T1087.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1087.002/T1087.002.md) | Enumerate all accounts via PowerShell (Domain) | windows |
| Discovery | [T1135](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1135/T1135.md) | Network Share Discovery | macos |
| Discovery | [T1135](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1135/T1135.md) | Network Share Discovery - linux | linux |
| Discovery | [T1518.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1518.001/T1518.001.md) | Security Software Discovery | windows |
| Discovery | [T1518.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1518.001/T1518.001.md) | Security Software Discovery - powershell | windows |
| Lateral Movement | [T1021.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.001/T1021.001.md) | RDP to Remote Host | windows |
| Lateral Movement | [T1021.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.001/T1021.001.md) | Changing RDP Port to Non Standard Port via Powershell | windows |
| Lateral Movement | [T1021.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.002/T1021.002.md) | Map admin share | windows |
| Lateral Movement | [T1021.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.002/T1021.002.md) | Map Admin Share PowerShell | windows |
| Lateral Movement | [T1021.006](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.006/T1021.006.md) | Enable Windows Remote Management | windows |
| Lateral Movement | [T1021.006](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.006/T1021.006.md) | Remote Code Execution with PS Credentials Using Invoke-Command | windows |
| Lateral Movement | [T1550.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1550.002/T1550.002.md) | Mimikatz Pass the Hash | windows |
| Lateral Movement | [T1550.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1550.002/T1550.002.md) | crackmapexec Pass the Hash | windows |
| Lateral Movement | [T1570](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1570/T1570.md) | Exfiltration Over SMB over QUIC (New-SmbMapping) | windows |
| Lateral Movement | [T1570](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1570/T1570.md) | Exfiltration Over SMB over QUIC (NET USE) | windows |
| Collection | [T1005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1005/T1005.md) | Search files of interest and save them to a single zip file (Windows) | windows |
| Collection | [T1005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1005/T1005.md) | Find and dump sqlite databases (Linux) | linux |
| Collection | [T1074.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1074.001/T1074.001.md) | Stage data from Discovery.bat | windows |
| Collection | [T1074.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1074.001/T1074.001.md) | Stage data from Discovery.sh | linux, macos |
| Collection | [T1560.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1560.001/T1560.001.md) | Compress Data for Exfiltration With Rar | windows |
| Collection | [T1560.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1560.001/T1560.001.md) | Compress Data and lock with password for Exfiltration with winrar | windows |
| Command and Control | [T1071.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1071.001/T1071.001.md) | Malicious User Agents - Powershell | windows |
| Command and Control | [T1071.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1071.001/T1071.001.md) | Malicious User Agents - CMD | windows |
| Command and Control | [T1105](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1105/T1105.md) | rsync remote file copy (push) | linux, macos |
| Command and Control | [T1105](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1105/T1105.md) | rsync remote file copy (pull) | linux, macos |
| Exfiltration | [T1041](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1041/T1041.md) | C2 Data Exfiltration | windows |
| Exfiltration | [T1041](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1041/T1041.md) | Text Based Data Exfiltration using DNS subdomains | windows |
| Exfiltration | [T1048.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1048.003/T1048.003.md) | Exfiltration Over Alternative Protocol - HTTP | linux, macos |
| Exfiltration | [T1048.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1048.003/T1048.003.md) | Exfiltration Over Alternative Protocol - ICMP | windows |
| Exfiltration | [T1567.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1567.002/T1567.002.md) | Exfiltrate data with rclone to cloud Storage - Mega (Windows) | windows |
| Exfiltration | [T1567.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1567.002/T1567.002.md) | Exfiltrate data with rclone to cloud Storage - AWS S3 | linux, macos |
| Impact | [T1489](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1489/T1489.md) | Windows - Stop service using Service Controller | windows |
| Impact | [T1489](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1489/T1489.md) | Windows - Stop service using net.exe | windows |
| Impact | [T1490](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1490/T1490.md) | Windows - Delete Volume Shadow Copies | windows |
| Impact | [T1490](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1490/T1490.md) | Windows - Delete Volume Shadow Copies via WMI | windows |

**Logs reais de ataque (EVTX) para testar sem executar nada:**

- T1003.001 — [CA_hashdump_4663_4656_lsass_access](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Credential%20Access/CA_hashdump_4663_4656_lsass_access.evtx) _(inferido)_
- T1003.001 — [LsassSilentProcessExit_process_exit_monitor_3001_lsass](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Credential%20Access/LsassSilentProcessExit_process_exit_monitor_3001_lsass.evtx) _(inferido)_
- T1003.003 — [dc_applog_ntdsutil_dfir_325_326_327](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Credential%20Access/dc_applog_ntdsutil_dfir_325_326_327.evtx) _(inferido)_
- T1003.003 — [LM_regsvc_DirectoryServiceExtPt_Lsass_NTDS_AdamXpn](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Lateral%20Movement/LM_regsvc_DirectoryServiceExtPt_Lsass_NTDS_AdamXpn.evtx) _(inferido)_
- T1016 — [ID4688-Audit policy enumerated](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1016-System%20Network%20Configuration%20Discovery/ID4688-Audit%20policy%20enumerated.evtx) _(explícito)_
- T1016 — [ID4688-Firewall configuration enumerated (command)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1016-System%20Network%20Configuration%20Discovery/ID4688-Firewall%20configuration%20enumerated%20%28command%29.evtx) _(explícito)_
- T1018 — [ID5145-DNS hosts files access via network share](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1018-Remote%20System%20Discovery/ID5145-DNS%20hosts%20files%20access%20via%20network%20share.evtx) _(explícito)_
- T1021 — [DFIR_RDP_Client_TimeZone_RdpCoreTs_104_example](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Lateral%20Movement/DFIR_RDP_Client_TimeZone_RdpCoreTs_104_example.evtx) _(inferido)_
- T1021 — [ImpersonateUser-via local Pass The Hash Sysmon and Security](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Lateral%20Movement/ImpersonateUser-via%20local%20Pass%20The%20Hash%20Sysmon%20and%20Security.evtx) _(inferido)_
- T1021.001 — [ID4688,4778,4779 RDP hijack direct](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0008-Lateral%20Movement/T1021.001-Remote%20Desktop%20Protocol/ID4688%2C4778%2C4779%20RDP%20hijack%20direct.evtx) _(explícito)_
- T1021.001 — [ID4688-4778 RDP hijack command execution](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0008-Lateral%20Movement/T1021.001-Remote%20Desktop%20Protocol/ID4688-4778%20RDP%20hijack%20command%20execution.evtx) _(explícito)_
- T1021.002 — [ID4688,4697,5140-5145 PSexec remote execution + admin share](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0008-Lateral%20Movement/T1021.002-SMB%20Windows%20Admin%20Shares/ID4688%2C4697%2C5140-5145%20PSexec%20remote%20execution%20%2B%20admin%20share.evtx) _(explícito)_
- T1021.002 — [ID4688-4648 Lateral movement with net use](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0008-Lateral%20Movement/T1021.002-SMB%20Windows%20Admin%20Shares/ID4688-4648%20Lateral%20movement%20with%20net%20use.evtx) _(explícito)_
- T1021.006 — [ID4656-WS Management listener enumeration](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0008-Lateral%20Movement/T1021.006-Windows%20Remote%20Management/ID4656-WS%20Management%20listener%20enumeration.evtx) _(explícito)_
- T1021.006 — [LM_PowershellRemoting_sysmon_1_wsmprovhost](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Lateral%20Movement/LM_PowershellRemoting_sysmon_1_wsmprovhost.evtx) _(inferido)_
- T1047 — [ID1-WMI spwaning PowerShell process - WMImplant](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1047-Windows%20Management%20Instrumentation/ID1-WMI%20spwaning%20PowerShell%20process%20-%20WMImplant.evtx) _(explícito)_
- T1047 — [ID1-WMIexec process execution](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1047-Windows%20Management%20Instrumentation/ID1-WMIexec%20process%20execution.evtx) _(explícito)_
- T1053.005 — [ID4688-4698 Persistent scheduled task with SYSTEM privileges creation](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1053.005-Scheduled%20Task/ID4688-4698%20Persistent%20scheduled%20task%20with%20SYSTEM%20privileges%20creation.evtx) _(explícito)_
- T1053.005 — [ID4688-Interactive shell using AT schedule task](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1053.005-Scheduled%20Task/ID4688-Interactive%20shell%20using%20AT%20schedule%20task.evtx) _(explícito)_
- T1055 — [sideloading_injection_persistence_run_key](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/AutomatedTestingTools/Malware/sideloading_injection_persistence_run_key.evtx) _(inferido)_
- T1055 — [sideloading_uacbypass_rundll32_injection_c2](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/AutomatedTestingTools/Malware/sideloading_uacbypass_rundll32_injection_c2.evtx) _(inferido)_
- T1059.001 — [ID4103-4104-Payload download via PowerShell](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1059.001-PowerShell/ID4103-4104-Payload%20download%20via%20PowerShell.evtx) _(explícito)_
- T1059.001 — [ID4688-Encoded PowerShell MSF payload via process execution](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1059.001-PowerShell/ID4688-Encoded%20PowerShell%20MSF%20payload%20via%20process%20execution.evtx) _(explícito)_
- T1059.003 — [ID4688-SQL Server payload injectection for reverse shell (MSF)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1059.003-Windows%20Command%20Shell/ID4688-SQL%20Server%20payload%20injectection%20for%20reverse%20shell%20%28MSF%29.evtx) _(explícito)_
- T1078 — [ID1149-RDP success logins to multiple hosts](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0001-Initial%20access/T1078-Valid%20accounts/ID1149-RDP%20success%20logins%20to%20multiple%20hosts.evtx) _(explícito)_

## 9. Hipóteses de hunting

Se Wizard Spider estiver no seu ambiente, estas são as perguntas a fazer aos seus dados (fontes de log segundo as estratégias de detecção do MITRE ATT&CK).

1. **T1518.002 Backup Software Discovery** — Defender observes execution of commands like `tasklist`, `sc query`, `reg query`, or PowerShell WMI/Registry queries targeting known backup products (e.g., Veeam, Acronis, CrashPlan). Behavior often includes parent-child lineage involving PowerShell or… Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=13, 14), `WinEventLog:Sysmon` (EventCode=11).
2. **T1222.001 Windows Permissions** — Multi-stage Windows DACL manipulation behavioral chain: (1) Process creation of permission-modifying utilities (icacls.exe, takeown.exe, attrib.exe, cacls.exe) or PowerShell ACL cmdlets, (2) Command-line analysis revealing privilege escalation intent through… Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:Security` (EventCode=4663, 4670, 4656), `WinEventLog:Security` (EventCode=4663, 4656, 4658).
3. **T1552.006 Group Policy Preferences** — Correlates file enumeration of XML files in the SYSVOL share with suspicious process execution that decodes or reads encrypted credentials embedded in Group Policy Preference files (e.g., Get-GPPPassword.ps1, gpprefdecrypt.py, Metasploit). Detects abnormal… Dados: `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Security` (EventCode=5145).
4. **T1557.001 Name Resolution Poisoning and SMB Relay** — Detects anomalous network traffic on UDP 5355 (LLMNR) and UDP 137 (NBT-NS) combined with unauthorized SMB relay attempts, registry modifications re-enabling multicast name resolution, or suspicious service creation indicative of adversary-in-the-middle… Dados: `WinEventLog:Security` (EventCode=4697), `WinEventLog:Security` (Registry key modification HKLM\Software\Policies\Microsoft\Windows NT\DNSClient\EnableMulticast), `NSM:Flow` (Unusual responses to LLMNR (UDP 5355) or NBT-NS (UDP 137) queries from unauthorized hosts).
5. **T1021 Remote Services** — Logon via RDP or WMI by a user account followed by uncommon command execution, file manipulation, or lateral network connections. Dados: `WinEventLog:Security` (EventCode=4624, 4648), `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=3, 22).
6. **T1547.004 Winlogon Helper DLL** — Monitor Windows Registry modifications to Winlogon keys (Shell, Userinit, Notify) that introduce new executable or DLL paths. Correlate these changes with subsequent DLL loading, image loads, or process creation originating from winlogon.exe or userinit.exe.… Dados: `WinEventLog:Sysmon` (EventCode=7), `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Security` (modification to Winlogon registry keys such as Shell, Notify, or Userinit).
7. **T1555.004 Windows Credential Manager** — Detects unauthorized access to Windows Credential Manager through anomalous process execution (vaultcmd.exe, rundll32.exe keymgr.dll), suspicious API calls (CredEnumerateA), or direct file access to Credential Locker files. Correlates process creation with… Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=10), `WinEventLog:Sysmon` (EventCode=15).
8. **T1558.003 Kerberoasting** — Detects Kerberoasting attempts by monitoring for anomalous Kerberos TGS requests (Event ID 4769) with RC4 encryption (etype 0x17), accounts requesting an unusual number of service tickets in a short period, or service accounts targeted outside normal usage… Dados: `WinEventLog:Security` (EventCode=4769), `WinEventLog:Sysmon` (EventCode=10), `WinEventLog:Security` (EventCode=4624, 4648).
9. **T1021.006 Windows Remote Management** — Adversaries using WinRM to remotely execute commands, launch child processes, or access WMI. The detection chain includes service use, network activity, remote session logon, and process creation within a short temporal window. Dados: `WinEventLog:Security` (EventCode=4624, 4648), `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:WinRM` (EventCode=6).
10. **T1074 Data Staged** — Detects staging of sensitive files into temporary or public directories, compression with 7zip/WinRAR, or batch copy prior to exfiltration. Dados: `WinEventLog:Security` (EventCode=4663, 4670, 4656), `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Sysmon` (EventCode=1).
11. **T1136.002 Domain Account** — Adversary uses built-in tools such as 'net user /add /domain' or PowerShell to create a domain user account. The behavior chain includes: (1) suspicious process execution on a domain controller followed by (2) user account creation event (Event ID 4720) on… Dados: `WinEventLog:Security` (EventCode=4720), `WinEventLog:Sysmon` (EventCode=1).
12. **T1197 BITS Jobs** — Behavioral chain: (1) An actor creates or modifies a BITS job via bitsadmin.exe, PowerShell BITS cmdlets, or COM; (2) the job performs HTTP(S)/SMB network transfers while the owning user is logged on; (3) upon job completion/error, BITS launches a notify… Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=3, 22), `WinEventLog:PowerShell` (EventCode=4103, 4104, 4105, 4106).

## 10. OSINT — onde pesquisar

Consultas prontas com todos os nomes conhecidos do grupo:

- Relatórios técnicos: [busca web](https://duckduckgo.com/?q=%28%22Wizard+Spider%22+OR+%22UNC1878%22+OR+%22TEMP.MixMaster%22+OR+%22Grim+Spider%22+OR+%22FIN12%22+OR+%22GOLD+BLACKBURN%22%29+threat+report) · [PDFs](https://duckduckgo.com/?q=%28%22Wizard+Spider%22+OR+%22UNC1878%22+OR+%22TEMP.MixMaster%22+OR+%22Grim+Spider%22+OR+%22FIN12%22+OR+%22GOLD+BLACKBURN%22%29+filetype%3Apdf)
- Regras e IOCs publicados: [GitHub](https://github.com/search?type=code&q=%22Wizard+Spider%22+OR+%22UNC1878%22+OR+%22TEMP.MixMaster%22+OR+%22Grim+Spider%22+OR+%22FIN12%22+OR+%22GOLD+BLACKBURN%22)
- Pulsos de ameaça: [AlienVault OTX](https://otx.alienvault.com/browse/global/pulses?q=Wizard+Spider)
- Família de malware e atores: [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/actors) (busque por Wizard Spider, UNC1878, TEMP.MixMaster)
- Cartões de grupo: [ThaiCERT Threat Group Cards](https://apt.etda.or.th/cgi-bin/listgroups.cgi)
- Página oficial: [MITRE ATT&CK G0102](https://attack.mitre.org/groups/G0102/)

## 11. Bibliografia (21 fontes citadas pelo ATT&CK)

- [CrowdStrike Grim Spider May 2019](https://www.crowdstrike.com/blog/timelining-grim-spiders-big-game-hunting-tactics/) — John, E. and Carvey, H. (2019, May 30). Unraveling the Spiderweb: Timelining ATT&CK Artifacts Used by GRIM SPIDER. Retrieved May 12, 2020.
- [CrowdStrike Ryuk January 2019](https://www.crowdstrike.com/blog/big-game-hunting-with-ryuk-another-lucrative-targeted-ransomware/) — Hanel, A. (2019, January 10). Big Game Hunting with Ryuk: Another Lucrative Targeted Ransomware. Retrieved May 12, 2020.
- [CrowdStrike Wizard Spider March 2019](https://www.crowdstrike.com/blog/wizard-spider-lunar-spider-shared-proxy-module/) — Feeley, B. and Stone-Gross, B. (2019, March 20). New Evidence Proves Ongoing WIZARD SPIDER / LUNAR SPIDER Collaboration. Retrieved June 15, 2020.
- [CrowdStrike Wizard Spider October 2020](https://www.crowdstrike.com/blog/wizard-spider-adversary-update/) — Podlosky, A., Hanel, A. et al. (2020, October 16). WIZARD SPIDER Update: Resilient, Reactive and Resolute. Retrieved June 15, 2021.
- [DFIR Ryuk 2 Hour Speed Run November 2020](https://thedfirreport.com/2020/11/05/ryuk-speed-run-2-hours-to-ransom/) — The DFIR Report. (2020, November 5). Ryuk Speed Run, 2 Hours to Ransom. Retrieved November 6, 2020.
- [DFIR Ryuk in 5 Hours October 2020](https://thedfirreport.com/2020/10/18/ryuk-in-5-hours/) — The DFIR Report. (2020, October 18). Ryuk in 5 Hours. Retrieved October 19, 2020.
- [DFIR Ryuk's Return October 2020](https://thedfirreport.com/2020/10/08/ryuks-return/) — The DFIR Report. (2020, October 8). Ryuk’s Return. Retrieved October 9, 2020.
- [DHS/CISA Ransomware Targeting Healthcare October 2020](https://us-cert.cisa.gov/ncas/alerts/aa20-302a) — DHS/CISA. (2020, October 28). Ransomware Activity Targeting the Healthcare and Public Health Sector. Retrieved October 28, 2020.
- [FireEye KEGTAP SINGLEMALT October 2020](https://www.fireeye.com/blog/threat-research/2020/10/kegtap-and-singlemalt-with-a-ransomware-chaser.html) — Kimberly Goody, Jeremy Kennelly, Joshua Shilko, Steve Elovitz, Douglas Bienstock. (2020, October 28). Unhappy Hour Special: KEGTAP and SINGLEMALT With a Ransomware Chaser. Retrieved October 28, 2020.
- [FireEye Ryuk and Trickbot January 2019](https://www.fireeye.com/blog/threat-research/2019/01/a-nasty-trick-from-credential-theft-malware-to-business-disruption.html) — Goody, K., et al (2019, January 11). A Nasty Trick: From Credential Theft Malware to Business Disruption. Retrieved May 12, 2020.
- [Forbes Dyre May 2017](https://www.forbes.com/sites/thomasbrewster/2017/05/04/dyre-hackers-stealing-millions-from-american-coporates/#601c77842a0a) — Brewster, T. (2017, May 4). https://www.forbes.com/sites/thomasbrewster/2017/05/04/dyre-hackers-stealing-millions-from-american-coporates/#601c77842a0a. Retrieved June 15, 2020.
- [Group IB GrimAgent July 2021](https://www.group-ib.com/blog/grimagent/) — Priego, A. (2021, July). THE BROTHERS GRIM: THE REVERSING TALE OF GRIMAGENT MALWARE USED BY RYUK. Retrieved September 19, 2024.
- [IBM X-Force ITG23 Oct 2021](https://securityintelligence.com/posts/trickbot-gang-doubles-down-enterprise-infection/) — Villadsen, O., et al. (2021, October 13). Trickbot Rising - Gang Doubles Down on Infection Efforts to Amass Network Footholds. Retrieved June 15, 2023.
- [Malwarebytes TrickBot Sep 2019](https://blog.malwarebytes.com/trojans/2019/09/trickbot-adds-new-trick-to-its-arsenal-tampering-with-trusted-texts/) — Umawing, J. (2019, September 3). TrickBot adds new trick to its arsenal: tampering with trusted texts. Retrieved June 15, 2020.
- [Mandiant FIN12 Oct 2021](https://web.archive.org/web/20220313061955/https://www.mandiant.com/sites/default/files/2021-10/fin12-group-profile.pdf) — Shilko, J., et al. (2021, October 7). FIN12: The Prolific Ransomware Intrusion Threat Actor That Has Aggressively Pursued Healthcare Targets. Retrieved June 15, 2023.
- [Microsoft Ransomware as a Service](https://www.microsoft.com/en-us/security/blog/2022/05/09/ransomware-as-a-service-understanding-the-cybercrime-gig-economy-and-how-to-protect-yourself/) — Microsoft. (2022, May 9). Ransomware as a service: Understanding the cybercrime gig economy and how to protect yourself. Retrieved March 10, 2023.
- [Microsoft Threat Actor Naming July 2023](https://learn.microsoft.com/en-us/microsoft-365/security/intelligence/microsoft-threat-actor-naming?view=o365-worldwide) — Microsoft . (2023, July 12). How Microsoft names threat actors. Retrieved November 17, 2023.
- [Microsoft_PistachioTempest_Jan2024](https://www.microsoft.com/en-us/security/security-insider/threat-landscape/pistachio-tempest) — Microsoft. (2024, January 25). Financially Motivated Threat Actor Pistachio Tempest. Retrieved December 15, 2025.
- [Red Canary Hospital Thwarted Ryuk October 2020](https://redcanary.com/blog/how-one-hospital-thwarted-a-ryuk-ransomware-outbreak/) — Brian Donohue, Katie Nickels, Paul Michaud, Adina Bodkins, Taylor Chapman, Tony Lambert, Jeff Felling, Kyle Rainey, Mike Haag, Matt Graeber, Aaron Didier.. (2020, October 29). A Bazar start: How one hospital thwarted a R
- [Secureworks Gold Blackburn Mar 2022](https://www.secureworks.com/research/threat-profiles/gold-blackburn) — Secureworks Counter Threat Unit. (2022, March 1). Gold Blackburn Threat Profile. Retrieved June 15, 2023.
- [Sophos New Ryuk Attack October 2020](https://news.sophos.com/en-us/2020/10/14/inside-a-new-ryuk-ransomware-attack/) — Sean Gallagher, Peter Mackenzie, Elida Leite, Syed Shahram, Bill Kearney, Anand Aijan, Sivagnanam Gn, Suraj Mundalik. (2020, October 14). They’re back: inside a new Ryuk ransomware attack. Retrieved October 14, 2020.

## 12. Limites e confiança

- O ATT&CK registra o que foi **relatado publicamente**, não tudo o que o grupo faz. Ausência de uma técnica não prova que o grupo não a usa.
- **Sobreposição de TTP não é atribuição.** Muitas técnicas são compartilhadas entre grupos e com red teams. Use a assinatura comportamental como hipótese, junto com infraestrutura, malware e contexto.
- Cobertura de detecção refere-se ao catálogo público Detection Rules, não ao seu ambiente: confira se a telemetria necessária chega ao seu SIEM.
- Ligações marcadas como _inferidas_ (EVTX por palavra-chave, relatórios por nome) devem ser verificadas.

---
Fontes: MITRE ATT&CK® (uso livre com atribuição, © The MITRE Corporation), Atomic Red Team (Red Canary, MIT), EVTX-to-MITRE-Attack, EVTX-ATTACK-SAMPLES, APT & CyberCriminal Campaign Collections. Gerado por [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules).
