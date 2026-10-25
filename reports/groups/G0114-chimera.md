# Chimera (G0114) — Dossiê de inteligência

> **TLP:CLEAR** · gerado em 2026-10-25 a partir de fontes abertas · MITRE ATT&CK v20.0 · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0114) · [ATT&CK](https://attack.mitre.org/groups/G0114/)

**Também conhecido como:** —  
**Registro no ATT&CK:** criado em 2020-08-24, atualizado em 2026-07-31 · referências de 2020 a 2021

## 1. Sumário executivo

- **59 técnicas** atribuídas publicamente, concentradas em **Discovery, Collection, Stealth**.
- **Arsenal:** 1 malware e 5 ferramentas (ex.: Cobalt Strike, Mimikatz, Net, BloodHound, esentutl).
- **Campanhas atribuídas:** 0.
- **Cobertura de detecção pública:** 97% das técnicas têm ao menos uma regra no catálogo; **2 técnicas sem nenhuma regra pública**.
- **Assinatura comportamental** (técnicas raras entre os 178 grupos, as mais úteis para atribuição): T1556.001 Domain Controller Authentication, T1110.004 Credential Stuffing, T1201 Password Policy Discovery, T1111 Multi-Factor Authentication Interception, T1021.006 Windows Remote Management.

## 2. Quem é

> Chimera is a suspected China-based threat group that has been active since at least 2018 targeting the semiconductor industry in Taiwan as well as data from the airline industry.

_Texto original do MITRE ATT&CK, em inglês._

## 3. Perfil TTP por tática (kill chain)

Cada linha: técnica, como o grupo a usou segundo relatos públicos, e o que existe para detectar e testar.

### Reconnaissance (TA0043) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1589.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1589.001) Credentials | Chimera has collected credentials for the target organization from previous breaches for use in brute force attacks. | 2 | — | — |

### Resource Development (TA0042) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1588.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1588.002) Tool | Chimera has obtained and used tools such as BloodHound, Cobalt Strike, Mimikatz, and PsExec. | 35 | — | — |

### Initial Access (TA0001) — 3

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | Chimera has used a valid account to maintain persistence via scheduled task. | 825 | — | 3 |
| [T1078.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.002) Domain Accounts | Chimera has used compromised domain accounts to gain access to the target environment. | 36 | — | 1 |
| [T1133](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1133) External Remote Services | Chimera has used legitimate credentials to login to an external VPN, Citrix, SSH, and other remote services. | 361 | 1 | — |

### Execution (TA0002) — 7

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1047](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1047) Windows Management Instrumentation | Chimera has used WMIC to execute remote commands. | 370 | 12 | 11 |
| [T1053.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1053.005) Scheduled Task | Chimera has used scheduled tasks to invoke Cobalt Strike including through batch script schtasks /create /ru "SYSTEM" /tn "update" /tr "cmd /c c:\windows\temp\update.bat" /sc once /f /st and to maintain persistence. | 248 | 14 | 11 |
| [T1059.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.001) PowerShell | Chimera has used PowerShell scripts to execute malicious payloads and the DSInternals PowerShell module to make use of Active Directory features. | 1340 | 22 | 15 |
| [T1059.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.003) Windows Command Shell | Chimera has used the Windows Command Shell and batch scripts for execution on compromised hosts. | 269 | 6 | 1 |
| [T1106](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1106) Native API | Chimera has used direct Windows system calls by leveraging Dumpert. | 118 | 5 | — |
| [T1569.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1569.002) Service Execution | Chimera has used PsExec to deploy beacons on compromised systems. | 230 | 8 | 8 |
| [T1574.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1574.001) DLL | Chimera has used side loading to place malicious DLLs in memory. | 455 | 7 | 5 |

### Persistence (TA0003) — 5

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1053.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1053.005) Scheduled Task | Chimera has used scheduled tasks to invoke Cobalt Strike including through batch script schtasks /create /ru "SYSTEM" /tn "update" /tr "cmd /c c:\windows\temp\update.bat" /sc once /f /st and to maintain persistence. | 248 | 14 | 11 |
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | Chimera has used a valid account to maintain persistence via scheduled task. | 825 | — | 3 |
| [T1078.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.002) Domain Accounts | Chimera has used compromised domain accounts to gain access to the target environment. | 36 | — | 1 |
| [T1133](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1133) External Remote Services | Chimera has used legitimate credentials to login to an external VPN, Citrix, SSH, and other remote services. | 361 | 1 | — |
| [T1556.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1556.001) Domain Controller Authentication | Chimera's malware has altered the NTLM authentication program on domain controllers to allow Chimera to login without a valid credential. | **0** | 1 | — |

### Privilege Escalation (TA0004) — 3

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1053.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1053.005) Scheduled Task | Chimera has used scheduled tasks to invoke Cobalt Strike including through batch script schtasks /create /ru "SYSTEM" /tn "update" /tr "cmd /c c:\windows\temp\update.bat" /sc once /f /st and to maintain persistence. | 248 | 14 | 11 |
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | Chimera has used a valid account to maintain persistence via scheduled task. | 825 | — | 3 |
| [T1078.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.002) Domain Accounts | Chimera has used compromised domain accounts to gain access to the target environment. | 36 | — | 1 |

### Stealth (TA0005) — 7

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1027.010](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1027.010) Command Obfuscation | Chimera has encoded PowerShell commands. | 78 | — | — |
| [T1036.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1036.005) Match Legitimate Resource Name or Location | Chimera has renamed malware to GoogleUpdate.exe and WinRAR to jucheck.exe, RecordedTV.ms, teredo.tmp, update.exe, and msadcs1.exe. | 116 | 4 | — |
| [T1070.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1070.004) File Deletion | Chimera has performed file deletion to evade detection. | 132 | 11 | — |
| [T1070.006](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1070.006) Timestomp | Chimera has used a Windows version of the Linux touch command to modify the date and time stamp on DLLs. | 28 | 10 | 3 |
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | Chimera has used a valid account to maintain persistence via scheduled task. | 825 | — | 3 |
| [T1078.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.002) Domain Accounts | Chimera has used compromised domain accounts to gain access to the target environment. | 36 | — | 1 |
| [T1574.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1574.001) DLL | Chimera has used side loading to place malicious DLLs in memory. | 455 | 7 | 5 |

### Defense Impairment (TA0112) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1556.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1556.001) Domain Controller Authentication | Chimera's malware has altered the NTLM authentication program on domain controllers to allow Chimera to login without a valid credential. | **0** | 1 | — |
| [T1685.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1685.005) Clear Windows Event Logs | Chimera has cleared event logs on compromised hosts. | 68 | 4 | 5 |

### Credential Access (TA0006) — 5

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1003.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1003.003) NTDS | Chimera has gathered the SYSTEM registry and ntds.dit files from target systems. Chimera specifically has used the NtdsAudit tool to dump the password hashes of domain users via msadcs.exe "NTDS.dit" -s "SYSTEM" -p RecordedTV_pdmp.txt --users-csv RecordedTV_us… | 157 | 11 | 2 |
| [T1110.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1110.003) Password Spraying | Chimera has used multiple password spraying attacks against victim's remote services to obtain valid user and administrator accounts. | 62 | 9 | 1 |
| [T1110.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1110.004) Credential Stuffing | Chimera has used credential stuffing against victim's remote services to obtain valid accounts. | 35 | 4 | — |
| [T1111](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1111) Multi-Factor Authentication Interception | Chimera has registered alternate phone numbers for compromised users to intercept 2FA codes sent via SMS. | 3 | — | — |
| [T1556.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1556.001) Domain Controller Authentication | Chimera's malware has altered the NTLM authentication program on domain controllers to allow Chimera to login without a valid credential. | **0** | 1 | — |

### Discovery (TA0007) — 18

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1007](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1007) System Service Discovery | Chimera has used net start and net use for system service discovery. | 37 | 8 | — |
| [T1012](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1012) Query Registry | Chimera has queried Registry keys using reg query \\\HKU\\SOFTWARE\Microsoft\Terminal Server Client\Servers and reg query \\\HKU\\Software\Microsoft\Windows\CurrentVersion\Internet Settings. | 92 | 6 | — |
| [T1016](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1016) System Network Configuration Discovery | Chimera has used ipconfig, Ping, and tracert to enumerate the IP address and network environment and settings of the local host. | 99 | 10 | 5 |
| [T1018](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1018) Remote System Discovery | Chimera has utilized various scans and queries to find domain controllers and remote services in the target environment. | 157 | 23 | 1 |
| [T1033](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1033) System Owner/User Discovery | Chimera has used the quser command to show currently logged on users. | 181 | 8 | — |
| [T1046](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1046) Network Service Discovery | Chimera has used the get -b -e -p command for network scanning as well as a custom Python tool packed into a Windows executable named Get.exe to scan IP ranges for HTTP. | 212 | 13 | 2 |
| [T1049](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1049) System Network Connections Discovery | Chimera has used netstat -ano \| findstr EST to discover network connections. | 47 | 7 | — |
| [T1057](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1057) Process Discovery | Chimera has used tasklist to enumerate processes. | 82 | 10 | — |
| [T1069.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1069.001) Local Groups | Chimera has used net localgroup administrators to identify accounts with local administrative rights. | 50 | 7 | — |
| [T1083](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1083) File and Directory Discovery | Chimera has utilized multiple commands to identify data of interest in file and directory listings. | 137 | 9 | — |
| [T1087.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1087.001) Local Account | Chimera has used net user for account discovery. | 98 | 11 | — |
| [T1087.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1087.002) Domain Account | Chimera has has used net user /dom and net user Administrator to enumerate domain accounts including administrator accounts. | 180 | 25 | 1 |
| [T1124](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1124) System Time Discovery | Chimera has used time /t and net time \\ip/hostname for system time discovery. | 18 | 6 | — |
| [T1135](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1135) Network Share Discovery | Chimera has used net share and net view to identify network shares of interest. | 73 | 12 | 3 |
| [T1201](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1201) Password Policy Discovery | Chimera has used the NtdsAudit utility to collect information related to accounts and passwords. | 43 | 12 | 2 |
| [T1217](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1217) Browser Information Discovery | Chimera has used type \\\c$\Users\\Favorites\Links\Bookmarks bar\Imported From IE\*citrix* for bookmark discovery. | 19 | 11 | — |
| [T1482](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1482) Domain Trust Discovery | Chimera has nltest /domain_trusts to identify domain trust relationships. | 158 | 8 | 1 |
| [T1680](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1680) Local Storage Discovery | Chimera has used `fsutil fsinfo drives`, `systeminfo`, and `vssadmin list shadows` for system information including shadow volumes and drive information. | **0** | — | — |

### Lateral Movement (TA0008) — 5

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1021.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1021.001) Remote Desktop Protocol | Chimera has used RDP to access targeted systems. | 139 | 4 | 7 |
| [T1021.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1021.002) SMB/Windows Admin Shares | Chimera has used Windows admin shares to move laterally. | 272 | 4 | 20 |
| [T1021.006](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1021.006) Windows Remote Management | Chimera has used WinRM for lateral movement. | 74 | 3 | 5 |
| [T1550.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1550.002) Pass the Hash | Chimera has dumped password hashes for use in pass the hash authentication attacks. | 43 | 3 | 1 |
| [T1570](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1570) Lateral Tool Transfer | Chimera has copied tools between compromised hosts using SMB. | 58 | 2 | — |

### Collection (TA0009) — 8

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1039](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1039) Data from Network Shared Drive | Chimera has collected data of interest from network shares. | 24 | 2 | — |
| [T1074.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1074.001) Local Data Staging | Chimera has staged stolen data locally on compromised hosts. | 37 | 3 | — |
| [T1074.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1074.002) Remote Data Staging | Chimera has staged stolen data on designated servers in the target environment. | 5 | — | — |
| [T1114.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1114.001) Local Email Collection | Chimera has harvested data from victim's e-mail including through execution of wmic /node: process call create "cmd /c copy c:\Users\\\backup.pst c:\windows\temp\backup.pst" copy "i:\\\My Documents\.pst" copy. | 15 | 1 | — |
| [T1114.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1114.002) Remote Email Collection | Chimera has harvested data from remote mailboxes including through execution of \\\c$\Users\\AppData\Local\Microsoft\Outlook*.ost. | 11 | 1 | — |
| [T1119](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1119) Automated Collection | Chimera has used custom DLLs for continuous retrieval of data from memory. | 72 | 4 | — |
| [T1213.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1213.002) Sharepoint | Chimera has collected documents from the victim's SharePoint. | 7 | — | — |
| [T1560.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1560.001) Archive via Utility | Chimera has used gzip for Linux OS and a modified RAR software to archive data on Windows hosts. | 76 | 13 | — |

### Command and Control (TA0011) — 4

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1071.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1071.001) Web Protocols | Chimera has used HTTPS for C2 communications. | 228 | 3 | — |
| [T1071.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1071.004) DNS | Chimera has used Cobalt Strike to encapsulate C2 in DNS traffic. | 117 | 4 | — |
| [T1105](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1105) Ingress Tool Transfer | Chimera has remotely copied tools and malware onto targeted systems. | 644 | 39 | — |
| [T1572](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1572) Protocol Tunneling | Chimera has encapsulated Cobalt Strike's C2 protocol in DNS and HTTPS. | 173 | 9 | 1 |

### Exfiltration (TA0010) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1041](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1041) Exfiltration Over C2 Channel | Chimera has used Cobalt Strike C2 beacons for data exfiltration. | 135 | 2 | — |
| [T1567.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1567.002) Exfiltration to Cloud Storage | Chimera has exfiltrated stolen data to OneDrive accounts. | 85 | 2 | — |

## 4. Assinatura comportamental

Técnicas que este grupo usa e que poucos dos 178 grupos do ATT&CK usam. Pesam mais numa atribuição por TTP: ver várias delas juntas é mais informativo do que ver técnicas comuns como PowerShell.

| Técnica | Outros grupos que usam | Peso (raridade) |
|---|---:|---:|
| T1556.001 Domain Controller Authentication | 0 | 4.49 |
| T1110.004 Credential Stuffing | 1 | 4.09 |
| T1201 Password Policy Discovery | 2 | 3.80 |
| T1111 Multi-Factor Authentication Interception | 3 | 3.58 |
| T1021.006 Windows Remote Management | 4 | 3.40 |
| T1589.001 Credentials | 5 | 3.24 |
| T1069.001 Local Groups | 6 | 3.11 |
| T1217 Browser Information Discovery | 6 | 3.11 |
| T1213.002 Sharepoint | 7 | 2.99 |
| T1039 Data from Network Shared Drive | 8 | 2.88 |

## 5. Arsenal

| Software | Tipo | Técnicas no ATT&CK | Uso relatado (EN) |
|---|---|---:|---|
| [Cobalt Strike](https://attack.mitre.org/software/S0154/) | malware | 73 |  |
| [Mimikatz](https://attack.mitre.org/software/S0002/) | ferramenta | 17 |  |
| [Net](https://attack.mitre.org/software/S0039/) | ferramenta | 16 |  |
| [BloodHound](https://attack.mitre.org/software/S0521/) | ferramenta | 11 |  |
| [esentutl](https://attack.mitre.org/software/S0404/) | ferramenta | 6 |  |
| [PsExec](https://attack.mitre.org/software/S0029/) | ferramenta | 5 |  |

## 6. Campanhas

Nenhuma campanha atribuída no ATT&CK.

## 7. Cobertura defensiva

**57 de 59 técnicas (97%)** têm ao menos uma regra pública no catálogo Detection Rules.

### Técnicas sem regra pública (prioridade para engenharia de detecção)

- **T1556.001 Domain Controller Authentication** — Defense Impairment. Fonte de log sugerida pelo MITRE: `WinEventLog:Sysmon` EventCode=10
- **T1680 Local Storage Discovery** — Discovery. Fonte de log sugerida pelo MITRE: `WinEventLog:Sysmon` EventCode=1; `auditd:SYSCALL` execve call with argv matching known disk enumeration commands (lsblk, parted, fdisk); `macos:unifiedlog` process launch of diskutil or system_profil

### Regras recomendadas por técnica

Melhor regra disponível por técnica (formato portável e maduro primeiro).

| Técnica | Regra | Formato | Fonte |
|---|---|---|---|
| T1003.003 | [Potential Russian APT Credential Theft Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab83f5166-9237-4b5e-9cd4-7b5d52f4d8ee) | Sigma | SigmaHQ |
| T1003.003 | [VolumeShadowCopy Symlink Creation Via Mklink](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A40b19fa6-d835-400c-b301-41f3a2baacaf) | Sigma | SigmaHQ |
| T1007 | [HackTool - PCHunter Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Afca949cc-79ca-446e-8064-01aa7e52ece5) | Sigma | SigmaHQ |
| T1007 | [SC.EXE Query Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A57712d7a-679c-4a41-a913-87e7175ae429) | Sigma | SigmaHQ |
| T1012 | [Potential Baby Shark Malware Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A2b30fa36-3a18-402f-a22d-bf4ce2189f35) | Sigma | SigmaHQ |
| T1012 | [Operation Wocao Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1cfac73c-be78-4f9a-9b08-5bde0c3953ab) | Sigma | SigmaHQ |
| T1016 | [Potential Pikabot Discovery Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A698d4431-514f-4c82-af4d-cf573872a9f5) | Sigma | SigmaHQ |
| T1016 | [OpenCanary - SNMP OID Request](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae9856028-fd4e-46e6-b3d1-10f7ceb95078) | Sigma | SigmaHQ |
| T1018 | [Chopper Webshell Process Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Afa3c117a-bc0d-416e-a31b-0c0e80653efb) | Sigma | SigmaHQ |
| T1018 | [Webshell Hacking Activity Patterns](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4ebc877f-4612-45cb-b3a5-8e3834db36c9) | Sigma | SigmaHQ |
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
| T1036.005 | [Exploit for CVE-2015-1641](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A7993792c-5ce2-4475-a3db-a3a5539827ef) | Sigma | SigmaHQ |
| T1036.005 | [Exploit for CVE-2015-1641](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A7993792c-5ce2-4475-a3db-a3a5539827ef) | Sigma | OpenSearch Security Analytics |
| T1039 | [Copy from Admin Share](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A855bc8b5-2ae8-402e-a9ed-b889e6df1900) | Sigma | OpenSearch Security Analytics |
| T1039 | [PowerShell Share Enumeration Script](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A4c59cff1-b78a-41b8-a9f1-4231984d1fb6) | Elastic | Elastic detection-rules |
| T1041 | [Equation Group C2 Communication](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A881834a4-6659-4773-821e-1c151789d873) | Sigma | SigmaHQ |
| T1041 | [OpenCanary - TFTP Request](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab4e6b016-a2ac-4759-ad85-8000b300d61e) | Sigma | SigmaHQ |
| T1046 | [HackTool - winPEAS Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A98b53e78-ebaf-46f8-be06-421aafd176d9) | Sigma | SigmaHQ |
| T1046 | [HackTool - WinPwn Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad557dc06-62e8-4468-a8e8-7984124908ce) | Sigma | SigmaHQ |
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
| T1069.001 | [BloodHound Collection Files](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A02773bed-83bf-469f-b7ff-e676e7d78bab) | Sigma | SigmaHQ |
| T1069.001 | [HackTool - Bloodhound/Sharphound Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Af376c8a7-a2d0-4ddc-aa0c-16c17236d962) | Sigma | SigmaHQ |
| T1070.004 | [File Deletion](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A30aed7b6-d2c1-4eaf-9382-b6bc43e50c57) | Sigma | SigmaHQ |
| T1070.004 | [Prefetch File Deleted](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A0a1f9d29-6465-4776-b091-7f43b26e4c89) | Sigma | SigmaHQ |
| T1070.006 | [File Creation Date Changed to Another Year](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A558eebe5-f2ba-4104-b339-36f7902bcc1a) | Sigma | SigmaHQ |
| T1070.006 | [Touch Suspicious Service File](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A31545105-3444-4584-bebf-c466353230d2) | Sigma | SigmaHQ |
| T1071.001 | [Ursnif Malware Download URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aa36ce77e-30db-4ea0-8795-644d7af5dfb4) | Sigma | SigmaHQ |
| T1071.001 | [Ursnif Malware C2 URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A932ac737-33ca-4afd-9869-0d48b391fcc9) | Sigma | SigmaHQ |
| T1071.004 | [OilRig APT Registry Persistence](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A7bdf2a7c-3acc-4091-9581-0a77dad1c5b5) | Sigma | SigmaHQ |
| T1071.004 | [OilRig APT Schedule Task Persistence - Security](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac0580559-a6bd-4ef6-b9b7-83703d98b561) | Sigma | SigmaHQ |
| T1074.001 | [Sensitive File Access followed by Compression](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Aa0fbd7a9-1923-4e05-92df-b484168f17bc) | Elastic | Elastic detection-rules |
| T1074.001 | [Folder Compress To Potentially Suspicious Output Via Compress-Archive Cmdlet](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A85a8e5ba-bd03-4bfb-bbfa-a4409a8f8b98+%23+Process+Creation) | Sigma | SigmaHQ |
| T1074.002 | [Google Workspace Drive Data Transfer or Takeout Export Initiated](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A07b5f85a-240f-11ed-b3d9-f661ea17fbce) | Elastic | Elastic detection-rules |
| T1074.002 | [AWS RDS DB Instance Restored](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Abf1073bf-ce26-4607-b405-ba1ed8e9e204) | Elastic | Elastic detection-rules |
| T1078 | [Privilege Role Sign-In Outside Expected Controls](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acf1e5687-84e1-41af-97a9-158094efef53) | Sigma | SigmaHQ |
| T1078 | [OpenCanary - SSH Login Attempt](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aff7139bc-fdb1-4437-92f2-6afefe8884cb) | Sigma | SigmaHQ |
| T1078.002 | [Malicious Usage Of IMDS Credentials Outside Of AWS Infrastructure](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A352a918a-34d8-4882-8470-44830c507aa3) | Sigma | SigmaHQ |
| T1078.002 | [AdminSDHolder SDProp Exclusion Added](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A61d29caf-6c15-4d1e-9ccb-7ad12ccc0bc7) | Elastic | Elastic detection-rules |
| T1083 | [Turla Group Lateral Movement](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac601f20d-570a-4cde-a7d6-e17f99cb8e7f) | Sigma | SigmaHQ |
| T1083 | [WannaCry Ransomware Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A41d40bff-377a-43e2-8e1b-2e543069e079) | Sigma | SigmaHQ |
| T1087.001 | [BloodHound Collection Files](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A02773bed-83bf-469f-b7ff-e676e7d78bab) | Sigma | SigmaHQ |
| T1087.001 | [HackTool - Bloodhound/Sharphound Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Af376c8a7-a2d0-4ddc-aa0c-16c17236d962) | Sigma | SigmaHQ |
| T1087.002 | [BloodHound Collection Files](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A02773bed-83bf-469f-b7ff-e676e7d78bab) | Sigma | SigmaHQ |
| T1087.002 | [Suspicious Active Directory Database Snapshot Via ADExplorer](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aef61af62-bc74-4f58-b49b-626448227652) | Sigma | SigmaHQ |
| T1105 | [Greenbug Espionage Group Indicators](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A3711eee4-a808-4849-8a14-faf733da3612) | Sigma | SigmaHQ |
| T1105 | [Pandemic Registry Key](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A47e0852a-cf81-4494-a8e6-31864f8c86ed) | Sigma | SigmaHQ |
| T1106 | [Turla Group Named Pipes](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A739915e4-1e70-4778-8b8a-17db02f66db1) | Sigma | SigmaHQ |
| T1106 | [BPFDoor Abnormal Process ID or Lock File Accessed](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A808146b2-9332-4d78-9416-d7e47012d83d) | Sigma | SigmaHQ |
| T1110.003 | [Multiple SonicWall Login Failures Followed by Successful Login](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Aefe7ac71-3b13-41cf-8263-30af68ce3f19) | Elastic | Elastic detection-rules |
| T1110.003 | [Potential Successful SSH Brute Force Attack](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A8cb84371-d053-4f4f-bce0-c74990e28f28) | Elastic | Elastic detection-rules |
| T1110.004 | [Multiple SonicWall Login Failures Followed by Successful Login](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Aefe7ac71-3b13-41cf-8263-30af68ce3f19) | Elastic | Elastic detection-rules |
| T1110.004 | [Okta Successful Login After Credential Attack](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A50742e15-c5ef-49c8-9a2d-31221d45af58) | Elastic | Elastic detection-rules |
| T1111 | [Attempted Bypass of Okta MFA](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A3805c3dc-f82c-4f8d-891e-63c24d3102b0) | Elastic | Elastic detection-rules |
| T1111 | [Possible AiTM Phishing Attempt Against Microsoft Entra ID](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A16daa67c-b137-48dc-8eb7-76598a44791a) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1114.001 | [Powershell Local Email Collection](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A2837e152-93c8-43d2-85ba-c3cd3c2ae614) | Sigma | SigmaHQ |
| T1114.001 | [Exporting Exchange Mailbox via PowerShell](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A6aace640-e631-4870-ba8e-5fdda09325db) | Elastic | Elastic detection-rules |
| T1114.002 | [Microsoft Graph Email Access by Unusual User and Client](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ae882e934-2aaa-11f0-8272-f661ea17fbcc) | Elastic | Elastic detection-rules |
| T1114.002 | [M365 Exchange Mailbox Accessed by Unusual Client](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A48819484-9826-4083-9eba-1da74cd0eaf2) | Elastic | Elastic detection-rules |
| T1119 | [iOS Implant URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Ae06ac91d-b9e6-443d-8e5b-af749e7aa6b6) | Sigma | OpenSearch Security Analytics |
| T1119 | [Shai-Hulud Malicious GitHub Workflow Creation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A0aba5685-6db6-486f-88ef-29a99c545cfd) | Sigma | SigmaHQ |
| T1124 | [Use of W32tm as Timer](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A6da2c9f5-7c53-401b-aacb-92c040ce1215) | Sigma | SigmaHQ |
| T1124 | [Cisco Discovery](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A9705a6a1-6db6-4a16-a987-15b7151e299b) | Sigma | SigmaHQ |
| T1133 | [OpenCanary - SSH Login Attempt](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aff7139bc-fdb1-4437-92f2-6afefe8884cb) | Sigma | SigmaHQ |
| T1133 | [OpenCanary - SSH New Connection Attempt](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acd55f721-5623-4663-bd9b-5229cab5237d) | Sigma | SigmaHQ |
| T1135 | [Potential Dridex Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae6eb5a96-9e6f-4a18-9cdd-642cfda21c8e) | Sigma | SigmaHQ |
| T1135 | [Dridex Process Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Ae6eb5a96-9e6f-4a18-9cdd-642cfda21c8e) | Sigma | OpenSearch Security Analytics |
| T1201 | [Password Policy Discovery - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aca94a6db-8106-4737-9ed2-3e3bb826af0a) | Sigma | SigmaHQ |
| T1201 | [HackTool - CrackMapExec Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A42a993dd-bb3e-48c8-b372-4d6684c4106c) | Sigma | SigmaHQ |
| T1213.002 | [M365 SharePoint/OneDrive File Access via PowerShell](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A491651da-125b-11f1-af7d-f661ea17fbce) | Elastic | Elastic detection-rules |
| T1213.002 | [Entra ID Sharepoint or OneDrive Accessed by Unusual Client](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Aa3cc60d8-2701-11f0-accf-f661ea17fbcd) | Elastic | Elastic detection-rules |
| T1217 | [File And SubFolder Enumeration Via Dir Command](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A7c9340a9-e2ee-4e43-94c5-c54ebbea1006) | Sigma | SigmaHQ |
| T1217 | [Suspicious Where Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A725a9768-0f5e-4cb3-aec2-bc5719c6831a) | Sigma | SigmaHQ |
| T1482 | [BloodHound Collection Files](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A02773bed-83bf-469f-b7ff-e676e7d78bab) | Sigma | SigmaHQ |
| T1482 | [HackTool - TruffleSnout Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A69ca006d-b9a9-47f5-80ff-ecd4d25d481a) | Sigma | SigmaHQ |
| T1550.002 | [Hacktool Ruler](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A24549159-ac1b-479c-8175-d42aea947cae) | Sigma | SigmaHQ |
| T1550.002 | [Pass the Hash Activity 2](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A8eef149c-bd26-49f2-9e5a-9b00e3af499b) | Sigma | SigmaHQ |
| T1560.001 | [APT31 Judgement Panda Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A03e2746e-2b31-42f1-ab7a-eb39365b2422) | Sigma | SigmaHQ |
| T1560.001 | [Suspicious Manipulation Of Default Accounts Via Net.EXE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A5b768e71-86f2-4879-b448-81061cbae951) | Sigma | SigmaHQ |
| T1567.002 | [APT40 Dropbox Tool User Agent](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A5ba715b6-71b7-44fd-8245-f66893e81b3d) | Sigma | SigmaHQ |
| T1567.002 | [PUA - Rclone Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae37db05d-d1f9-49c8-b464-cee1a4b11638) | Sigma | SigmaHQ |
| T1569.002 | [PSExec Lateral Movement](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=hayabusa-native%3A%3A0694c340-3a46-40ac-acfc-c3444ae6572c) | Sigma | Hayabusa (native) |
| T1569.002 | [DNS RCE CVE-2020-1350](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab5281f31-f9cc-4d0d-95d0-45b91c45b487) | Sigma | SigmaHQ |
| T1570 | [PSExec Lateral Movement](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=hayabusa-native%3A%3A0694c340-3a46-40ac-acfc-c3444ae6572c) | Sigma | Hayabusa (native) |
| T1570 | [PSEXEC Remote Execution File Artefact](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A304afd73-55a5-4bb9-8c21-0b1fc84ea9e4) | Sigma | SigmaHQ |
| T1572 | [Communication To LocaltoNet Tunneling Service Initiated - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac4568f5d-131f-4e78-83d4-45b2da0ec4f1) | Sigma | SigmaHQ |
| T1572 | [Communication To Ngrok Tunneling Service - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A19bf6fdb-7721-4f3d-867f-53467f6a5db6) | Sigma | SigmaHQ |
| T1574.001 | [Winnti Pipemon Characteristics](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A73d70463-75c9-4258-92c6-17500fe972f2) | Sigma | SigmaHQ |
| T1574.001 | [Winnti Pipemon Characteristics](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A73d70463-75c9-4258-92c6-17500fe972f2) | Sigma | OpenSearch Security Analytics |
| T1588.002 | [Hacktool Execution - Imphash](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A24e3e58a-646b-4b50-adef-02ef935b9fc8) | Sigma | SigmaHQ |
| T1588.002 | [Renamed SysInternals DebugView Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acd764533-2e07-40d6-a718-cfeec7f2da7f) | Sigma | SigmaHQ |
| T1589.001 | [Linux Medusa Rootkit](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=splunk-security-content%3A%3A7add8520-71d5-43aa-b262-ee082b1f0238) | Splunk | Splunk security_content |
| T1589.001 | [MS Graph message: A user's credentials were compromised or stolen. This is a true positive alert.](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=wazuh-ruleset-oficial%3A%3Awazuh-99612) | Wazuh | Wazuh ruleset (oficial) |
| T1685.005 | [Suspicious Eventlog Clearing or Configuration Change Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acc36992a-4671-4f21-a91d-6c2b72a2edf5) | Sigma | SigmaHQ |
| T1685.005 | [Log Cleared](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=hayabusa-native%3A%3Ac2f690ac-53f8-4745-8cfe-7127dda28c74) | Sigma | Hayabusa (native) |

## 8. Plano de emulação e validação

Use num laboratório isolado e autorizado para confirmar que as regras disparam. Os comandos estão nos repositórios oficiais.

| Tática | Técnica | Teste Atomic Red Team | Plataformas |
|---|---|---|---|
| Execution | [T1047](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1047/T1047.md) | WMI Reconnaissance Users | windows |
| Execution | [T1047](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1047/T1047.md) | WMI Reconnaissance Processes | windows |
| Execution | [T1053.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1053.005/T1053.005.md) | Scheduled Task Startup Script | windows |
| Execution | [T1053.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1053.005/T1053.005.md) | Scheduled task Local | windows |
| Execution | [T1059.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md) | Mimikatz | windows |
| Execution | [T1059.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md) | Run BloodHound from local disk | windows |
| Execution | [T1059.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.003/T1059.003.md) | Create and Execute Batch Script | windows |
| Execution | [T1059.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.003/T1059.003.md) | Writes text to a file and displays it. | windows |
| Execution | [T1106](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1106/T1106.md) | Execution through API - CreateProcess | windows |
| Execution | [T1106](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1106/T1106.md) | WinPwn - Get SYSTEM shell - Pop System Shell using CreateProcess technique | windows |
| Execution | [T1569.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1569.002/T1569.002.md) | Execute a Command as a Service | windows |
| Execution | [T1569.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1569.002/T1569.002.md) | Use PsExec to execute a command on a remote host | windows |
| Persistence | [T1133](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1133/T1133.md) | Running Chrome VPN Extensions via the Registry 2 vpn extension | windows |
| Stealth | [T1036.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.005/T1036.005.md) | Execute a process from a directory masquerading as the current parent directory | linux, macos |
| Stealth | [T1036.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.005/T1036.005.md) | Masquerade as a built-in system executable | windows |
| Stealth | [T1070.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.004/T1070.004.md) | Delete a single file - FreeBSD/Linux/macOS | linux, macos |
| Stealth | [T1070.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.004/T1070.004.md) | Delete an entire folder - FreeBSD/Linux/macOS | linux, macos |
| Stealth | [T1070.006](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.006/T1070.006.md) | Set a file's access timestamp | linux, macos |
| Stealth | [T1070.006](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.006/T1070.006.md) | Set a file's modification timestamp | linux, macos |
| Stealth | [T1574.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1574.001/T1574.001.md) | DLL Search Order Hijacking - amsi.dll | windows |
| Stealth | [T1574.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1574.001/T1574.001.md) | Phantom Dll Hijacking - WinAppXRT.dll | windows |
| Defense Impairment | [T1556.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1556.001/T1556.001.md) | Skeleton Key via Mimikatz | windows |
| Defense Impairment | [T1685.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1685.005/T1685.005.md) | Clear Logs | windows |
| Defense Impairment | [T1685.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1685.005/T1685.005.md) | Delete System Logs Using Clear-EventLog | windows |
| Credential Access | [T1003.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.003/T1003.003.md) | Create Volume Shadow Copy with vssadmin | windows |
| Credential Access | [T1003.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.003/T1003.003.md) | Copy NTDS.dit from Volume Shadow Copy | windows |
| Credential Access | [T1110.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1110.003/T1110.003.md) | Password Spray all Domain Users | windows |
| Credential Access | [T1110.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1110.003/T1110.003.md) | Password Spray (DomainPasswordSpray) | windows |
| Credential Access | [T1110.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1110.004/T1110.004.md) | SSH Credential Stuffing From Linux | linux |
| Credential Access | [T1110.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1110.004/T1110.004.md) | SSH Credential Stuffing From MacOS | macos |
| Discovery | [T1007](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1007/T1007.md) | System Service Discovery | windows |
| Discovery | [T1007](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1007/T1007.md) | System Service Discovery - net.exe | windows |
| Discovery | [T1012](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1012/T1012.md) | Query Registry | windows |
| Discovery | [T1012](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1012/T1012.md) | Query Registry with Powershell cmdlets | windows |
| Discovery | [T1016](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1016/T1016.md) | System Network Configuration Discovery on Windows | windows |
| Discovery | [T1016](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1016/T1016.md) | List Windows Firewall Rules | windows |
| Discovery | [T1018](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1018/T1018.md) | Remote System Discovery - net | windows |
| Discovery | [T1018](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1018/T1018.md) | Remote System Discovery - net group Domain Computers | windows |
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
| Discovery | [T1083](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1083/T1083.md) | File and Directory Discovery (cmd.exe) | windows |
| Discovery | [T1083](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1083/T1083.md) | File and Directory Discovery (PowerShell) | windows |
| Discovery | [T1087.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1087.001/T1087.001.md) | Enumerate all accounts (Local) | linux |
| Discovery | [T1087.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1087.001/T1087.001.md) | View sudoers access | linux, macos |
| Discovery | [T1087.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1087.002/T1087.002.md) | Enumerate all accounts (Domain) | windows |
| Discovery | [T1087.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1087.002/T1087.002.md) | Enumerate all accounts via PowerShell (Domain) | windows |
| Discovery | [T1124](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1124/T1124.md) | System Time Discovery | windows |
| Discovery | [T1124](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1124/T1124.md) | System Time Discovery - PowerShell | windows |
| Discovery | [T1135](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1135/T1135.md) | Network Share Discovery | macos |
| Discovery | [T1135](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1135/T1135.md) | Network Share Discovery - linux | linux |
| Discovery | [T1201](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1201/T1201.md) | Examine password complexity policy - Ubuntu | linux |
| Discovery | [T1201](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1201/T1201.md) | Examine password complexity policy - FreeBSD | linux |
| Discovery | [T1217](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1217/T1217.md) | List Mozilla Firefox Bookmark Database Files on FreeBSD/Linux | linux |
| Discovery | [T1217](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1217/T1217.md) | List Mozilla Firefox Bookmark Database Files on macOS | macos |
| Discovery | [T1482](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1482/T1482.md) | Windows - Discover domain trusts with dsquery | windows |
| Discovery | [T1482](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1482/T1482.md) | Windows - Discover domain trusts with nltest | windows |
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
| Collection | [T1039](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1039/T1039.md) | Copy a sensitive File over Administrative share with copy | windows |
| Collection | [T1039](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1039/T1039.md) | Copy a sensitive File over Administrative share with Powershell | windows |
| Collection | [T1074.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1074.001/T1074.001.md) | Stage data from Discovery.bat | windows |
| Collection | [T1074.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1074.001/T1074.001.md) | Stage data from Discovery.sh | linux, macos |
| Collection | [T1114.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1114.001/T1114.001.md) | Email Collection with PowerShell Get-Inbox | windows |
| Collection | [T1114.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1114.002/T1114.002.md) | Office365 - Remote Mail Collected | office-365 |
| Collection | [T1119](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1119/T1119.md) | Automated Collection Command Prompt | windows |
| Collection | [T1119](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1119/T1119.md) | Automated Collection PowerShell | windows |
| Collection | [T1560.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1560.001/T1560.001.md) | Compress Data for Exfiltration With Rar | windows |
| Collection | [T1560.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1560.001/T1560.001.md) | Compress Data and lock with password for Exfiltration with winrar | windows |
| Command and Control | [T1071.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1071.001/T1071.001.md) | Malicious User Agents - Powershell | windows |
| Command and Control | [T1071.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1071.001/T1071.001.md) | Malicious User Agents - CMD | windows |
| Command and Control | [T1071.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1071.004/T1071.004.md) | DNS Large Query Volume | windows |
| Command and Control | [T1071.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1071.004/T1071.004.md) | DNS Regular Beaconing | windows |
| Command and Control | [T1105](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1105/T1105.md) | rsync remote file copy (push) | linux, macos |
| Command and Control | [T1105](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1105/T1105.md) | rsync remote file copy (pull) | linux, macos |
| Command and Control | [T1572](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1572/T1572.md) | DNS over HTTPS Large Query Volume | windows |
| Command and Control | [T1572](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1572/T1572.md) | DNS over HTTPS Regular Beaconing | windows |
| Exfiltration | [T1041](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1041/T1041.md) | C2 Data Exfiltration | windows |
| Exfiltration | [T1041](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1041/T1041.md) | Text Based Data Exfiltration using DNS subdomains | windows |
| Exfiltration | [T1567.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1567.002/T1567.002.md) | Exfiltrate data with rclone to cloud Storage - Mega (Windows) | windows |
| Exfiltration | [T1567.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1567.002/T1567.002.md) | Exfiltrate data with rclone to cloud Storage - AWS S3 | linux, macos |

**Logs reais de ataque (EVTX) para testar sem executar nada:**

- T1003.003 — [dc_applog_ntdsutil_dfir_325_326_327](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Credential%20Access/dc_applog_ntdsutil_dfir_325_326_327.evtx) _(inferido)_
- T1003.003 — [LM_regsvc_DirectoryServiceExtPt_Lsass_NTDS_AdamXpn](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Lateral%20Movement/LM_regsvc_DirectoryServiceExtPt_Lsass_NTDS_AdamXpn.evtx) _(inferido)_
- T1016 — [ID4688-Audit policy enumerated](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1016-System%20Network%20Configuration%20Discovery/ID4688-Audit%20policy%20enumerated.evtx) _(explícito)_
- T1016 — [ID4688-Firewall configuration enumerated (command)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1016-System%20Network%20Configuration%20Discovery/ID4688-Firewall%20configuration%20enumerated%20%28command%29.evtx) _(explícito)_
- T1018 — [ID5145-DNS hosts files access via network share](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1018-Remote%20System%20Discovery/ID5145-DNS%20hosts%20files%20access%20via%20network%20share.evtx) _(explícito)_
- T1021.001 — [ID4688,4778,4779 RDP hijack direct](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0008-Lateral%20Movement/T1021.001-Remote%20Desktop%20Protocol/ID4688%2C4778%2C4779%20RDP%20hijack%20direct.evtx) _(explícito)_
- T1021.001 — [ID4688-4778 RDP hijack command execution](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0008-Lateral%20Movement/T1021.001-Remote%20Desktop%20Protocol/ID4688-4778%20RDP%20hijack%20command%20execution.evtx) _(explícito)_
- T1021.002 — [ID4688,4697,5140-5145 PSexec remote execution + admin share](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0008-Lateral%20Movement/T1021.002-SMB%20Windows%20Admin%20Shares/ID4688%2C4697%2C5140-5145%20PSexec%20remote%20execution%20%2B%20admin%20share.evtx) _(explícito)_
- T1021.002 — [ID4688-4648 Lateral movement with net use](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0008-Lateral%20Movement/T1021.002-SMB%20Windows%20Admin%20Shares/ID4688-4648%20Lateral%20movement%20with%20net%20use.evtx) _(explícito)_
- T1021.006 — [ID4656-WS Management listener enumeration](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0008-Lateral%20Movement/T1021.006-Windows%20Remote%20Management/ID4656-WS%20Management%20listener%20enumeration.evtx) _(explícito)_
- T1021.006 — [LM_PowershellRemoting_sysmon_1_wsmprovhost](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Lateral%20Movement/LM_PowershellRemoting_sysmon_1_wsmprovhost.evtx) _(inferido)_
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
- T1078 — [ID1149-RDP success logins to multiple hosts](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0001-Initial%20access/T1078-Valid%20accounts/ID1149-RDP%20success%20logins%20to%20multiple%20hosts.evtx) _(explícito)_
- T1078 — [ID33205-SQL Server failed login with disabled SA account](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0001-Initial%20access/T1078-Valid%20accounts/ID33205-SQL%20Server%20failed%20login%20with%20disabled%20SA%20account.evtx) _(explícito)_
- T1078.002 — [ID4964-Login of a member of a special group](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0005-Defense%20Evasion/T1078.002-Valid%20accounts-Domain%20accounts/ID4964-Login%20of%20a%20member%20of%20a%20special%20group.evtx) _(explícito)_

## 9. Hipóteses de hunting

Se Chimera estiver no seu ambiente, estas são as perguntas a fazer aos seus dados (fontes de log segundo as estratégias de detecção do MITRE ATT&CK).

1. **T1556.001 Domain Controller Authentication** — Detects anomalous process access to LSASS on domain controllers, suspicious module loads of authentication DLLs, and registry or file modifications indicative of Skeleton Key–style patching. Correlates LSASS access attempts with subsequent abnormal logon… Dados: `WinEventLog:Sysmon` (EventCode=10), `WinEventLog:Sysmon` (EventCode=7), `WinEventLog:Security` (EventCode=4624, 4648).
2. **T1110.004 Credential Stuffing** — Multiple failed authentication attempts using distinct username/password pairs from a single IP address or session within a short time window, targeting common services like RDP or SMB Dados: `WinEventLog:Security` (EventCode=4625).
3. **T1201 Password Policy Discovery** — Cause→effect chain: (1) a user or service spawns a shell/PowerShell that queries local/domain password policy via commands/cmdlets (e.g., `net accounts`, `Get-ADDefaultDomainPasswordPolicy`, `secedit /export`); (2) optional directory/LDAP reads from DCs; (3)… Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:PowerShell` (EventCode=4103, 4104, 4105, 4106), `WinEventLog:Security` (EventCode=4662).
4. **T1111 Multi-Factor Authentication Interception** — Behavior chain involving unexpected API calls to capture keyboard input, driver loads for keyloggers, or remote use of smart card authentication via logon sessions not initiated by local user interaction Dados: `WinEventLog:Sysmon` (EventCode=10), `WinEventLog:Security` (EventCode=4624, 4648), `WinEventLog:Sysmon` (EventCode=13, 14).
5. **T1021.006 Windows Remote Management** — Adversaries using WinRM to remotely execute commands, launch child processes, or access WMI. The detection chain includes service use, network activity, remote session logon, and process creation within a short temporal window. Dados: `WinEventLog:Security` (EventCode=4624, 4648), `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:WinRM` (EventCode=6).
6. **T1069.001 Local Groups** — Detects attempts to enumerate local groups via Net.exe, PowerShell, or native API calls that precede lateral movement or privilege abuse. Dados: `WinEventLog:Security` (EventCode=4688).
7. **T1217 Browser Information Discovery** — Access to browser artifact locations (e.g., Chrome, Edge, Firefox) by processes like PowerShell, cmd.exe, or unknown tools, followed by file reads, decoding, or export operations indicating enumeration of bookmarks, autofill, or history databases. Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:PowerShell` (EventCode=4103, 4104, 4105, 4106).
8. **T1213.002 Sharepoint** — Privileged or rarely used accounts performing bulk access to SharePoint files or metadata over a short time window, indicating potential scripted collection of sensitive internal documents. Dados: `m365:unified` (FileAccessed, FileDownloaded, SearchQueried), `azure:signinlogs` (UserLogin, ConditionalAccessPolicyEvaluated), `m365:sharepoint` (Multiple file download operations on a site by a privileged account in a short time window).
9. **T1039 Data from Network Shared Drive** — Monitoring of file access to network shares (e.g., C$, Admin$) followed by unusual read or copy operations by processes not typically associated with such activity (e.g., PowerShell, certutil). Dados: `WinEventLog:Security` (EventCode=5145), `WinEventLog:Sysmon` (EventCode=11).
10. **T1114.001 Local Email Collection** — Detection focuses on processes that attempt to locate, access, or exfiltrate local Outlook data files (.pst/.ost) using file system access, native Windows utilities (e.g., PowerShell, WMI), or remote access tools with file browsing capabilities. The behavior… Dados: `WinEventLog:Security` (EventCode=4663, 4670, 4656), `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=11).
11. **T1482 Domain Trust Discovery** — Adversary uses nltest, PowerShell, or Win32/.NET API to enumerate domain trust relationships (via DSEnumerateDomainTrusts, GetAllTrustRelationships, or LDAP queries), followed by discovery or authentication staging. Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=7), `WinEventLog:Sysmon` (EventCode=10).
12. **T1680 Local Storage Discovery** — Drive enumeration using PowerShell (`Get-PSDrive`), `wmic logicaldisk`, or Win32 API indicative of local volume enumeration by non-admin users or executed outside of baseline system inventory scripts. Dados: `WinEventLog:Sysmon` (EventCode=1).

## 10. OSINT — onde pesquisar

Consultas prontas com todos os nomes conhecidos do grupo:

- Relatórios técnicos: [busca web](https://duckduckgo.com/?q=%28%22Chimera%22%29+threat+report) · [PDFs](https://duckduckgo.com/?q=%28%22Chimera%22%29+filetype%3Apdf)
- Regras e IOCs publicados: [GitHub](https://github.com/search?type=code&q=%22Chimera%22)
- Pulsos de ameaça: [AlienVault OTX](https://otx.alienvault.com/browse/global/pulses?q=Chimera)
- Família de malware e atores: [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/actors) (busque por Chimera)
- Cartões de grupo: [ThaiCERT Threat Group Cards](https://apt.etda.or.th/cgi-bin/listgroups.cgi)
- Página oficial: [MITRE ATT&CK G0114](https://attack.mitre.org/groups/G0114/)

**Relatórios na coleção CyberMonitor** (ligados pelo nome do grupo, conferir antes de citar):

- 2020 — [[TLP-White]20200415 Chimera_V4.1](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2020/2020.04.15_Chimera_APT/%5BTLP-White%5D20200415%20Chimera_V4.1.pdf) _(via “Chimera”)_
- 2021 — [research.nccgroup.com-Abusing cloud services to fly under the radar](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2021/2021.01.12.Abusing_cloud_services_Chimera/research.nccgroup.com-Abusing%20cloud%20services%20to%20fly%20under%20the%20radar.pdf) _(via “Chimera”)_

## 11. Bibliografia (2 fontes citadas pelo ATT&CK)

- [Cycraft Chimera April 2020](https://cycraft.com/download/CyCraft-Whitepaper-Chimera_V4.1.pdf) — Cycraft. (2020, April 15). APT Group Chimera - APT Operation Skeleton key Targets Taiwan Semiconductor Vendors. Retrieved August 24, 2020..
- [NCC Group Chimera January 2021](https://web.archive.org/web/20230218064220/https://research.nccgroup.com/2021/01/12/abusing-cloud-services-to-fly-under-the-radar/) — Jansen, W . (2021, January 12). Abusing cloud services to fly under the radar. Retrieved September 12, 2024.

## 12. Limites e confiança

- O ATT&CK registra o que foi **relatado publicamente**, não tudo o que o grupo faz. Ausência de uma técnica não prova que o grupo não a usa.
- **Sobreposição de TTP não é atribuição.** Muitas técnicas são compartilhadas entre grupos e com red teams. Use a assinatura comportamental como hipótese, junto com infraestrutura, malware e contexto.
- Cobertura de detecção refere-se ao catálogo público Detection Rules, não ao seu ambiente: confira se a telemetria necessária chega ao seu SIEM.
- Ligações marcadas como _inferidas_ (EVTX por palavra-chave, relatórios por nome) devem ser verificadas.

---
Fontes: MITRE ATT&CK® (uso livre com atribuição, © The MITRE Corporation), Atomic Red Team (Red Canary, MIT), EVTX-to-MITRE-Attack, EVTX-ATTACK-SAMPLES, APT & CyberCriminal Campaign Collections. Gerado por [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules).
