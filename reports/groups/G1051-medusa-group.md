# Medusa Group (G1051) — Dossiê de inteligência

> **TLP:CLEAR** · gerado em 2026-10-25 a partir de fontes abertas · MITRE ATT&CK v20.0 · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1051) · [ATT&CK](https://attack.mitre.org/groups/G1051/)

**Também conhecido como:** —  
**Registro no ATT&CK:** criado em 2025-10-15, atualizado em 2026-07-31 · referências de 2024 a 2025

## 1. Sumário executivo

- **57 técnicas** atribuídas publicamente, concentradas em **Discovery, Stealth, Execution**.
- **Arsenal:** 1 malware e 4 ferramentas (ex.: Medusa Ransomware, Mimikatz, Rclone, PsExec, certutil).
- **Campanhas atribuídas:** 0.
- **Cobertura de detecção pública:** 96% das técnicas têm ao menos uma regra no catálogo; **2 técnicas sem nenhuma regra pública**.
- **Assinatura comportamental** (técnicas raras entre os 178 grupos, as mais úteis para atribuição): T1218.014 MMC, T1650 Acquire Access, T1652 Device Driver Discovery, T1608.002 Upload Tool, T1529 System Shutdown/Reboot.

## 2. Quem é

> Medusa Group has been active since at least 2021 and was initially operated as a closed ransomware group before evolving into a Ransomware-as-a-Service (RaaS) operation. Some reporting indicates that certain attacks may still be conducted directly by the ransomware’s core developers. Public sources have also referred to the group as “Spearwing” or “Medusa Actors.” Medusa Group employs living-off-the-land techniques, frequently leveraging publicly available tools and common remote management software to conduct operations. The group engages in double extortion tactics, exfiltrating data prior to encryption and threatening to publish stolen information if ransom demands are not met. For initial access, Medusa Group has exploited publicly known vulnerabilities, conducted phishing campaigns, and used credentials or access purchased from Initial Access Brokers (IABs). The group is opportunistic and has targeted a wide range of sectors globally.

_Texto original do MITRE ATT&CK, em inglês._

## 3. Perfil TTP por tática (kill chain)

Cada linha: técnica, como o grupo a usou segundo relatos públicos, e o que existe para detectar e testar.

### Resource Development (TA0042) — 6

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1583.006](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1583.006) Web Services | Medusa Group has utilized a file hosting service named filemail[.]com to host a zip file that contained malicious payloads that facilitated follow-on actions. | 2 | — | — |
| [T1585.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1585.001) Social Media Accounts | Medusa Group has created social media accounts including Telegram and X to publicize their activities. | 4 | — | — |
| [T1585.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1585.002) Email Accounts | Medusa Group has created email accounts used in ransomware negotiations. | **0** | — | — |
| [T1588.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1588.002) Tool | Medusa Group has obtained and leveraged numerous RMM services, along with publicly available tools used for scanning. Medusa Group has utilized tools such as Advanced IP Scanner and SoftPerfect Network scanner for user, system and network discovery. Medusa Gro… | 35 | — | — |
| [T1608.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1608.002) Upload Tool | Medusa Group has utilized a file hosting service called filemail[.]com to host a zip file that contained a RMM service such as ConnectWise. | 1 | — | — |
| [T1650](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1650) Acquire Access | Medusa Group has purchased user credentials and other sensitive data from Initial Access Brokers (IABs). | **0** | — | — |

### Initial Access (TA0001) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | Medusa Group has utilized compromised legitimate local and domain accounts within the victim environment to facilitate remote access and lateral movement sometimes in combination with PsExec. | 825 | — | 3 |
| [T1190](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1190) Exploit Public-Facing Application | Medusa Group has leveraged public facing vulnerabilities in their campaigns against victim organizations to gain initial access. Medusa Group has also utilized CVE-2024-1709 in ScreenConnect, and CVE-2023-48788 in Fortinet EMS for initial access to victim envi… | 580 | — | — |

### Execution (TA0002) — 7

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1047](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1047) Windows Management Instrumentation | Medusa Group has utilized Windows Management Instrumentation to query system information. | 370 | 12 | 11 |
| [T1059.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.001) PowerShell | Medusa Group has leveraged PowerShell for execution and defense evasion. Medusa Group has also utilized PowerShell to execute a bitsadmin transfer from file hosting site. | 1340 | 22 | 15 |
| [T1059.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.003) Windows Command Shell | Medusa Group has used Windows Command Prompt to control and execute commands on the system to include ingress, network, and filesystem enumeration activities. | 269 | 6 | 1 |
| [T1072](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1072) Software Deployment Tools | Medusa Group has utilized software deployment and management solutions to deploy their encryption payload to include BigFix and PDQ Deploy. | 59 | 3 | — |
| [T1106](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1106) Native API | Medusa Group has leveraged Windows Native API functions to execute payloads. | 118 | 5 | — |
| [T1559.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1559.001) Component Object Model | Medusa Group has leveraged Component Object Model (COM) to bypass UAC. | 35 | — | — |
| [T1569.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1569.002) Service Execution | Medusa Group has utilized PsExec to execute scripts and commands within victim environments. Medusa Group has also used the Windows service RoboCopy to search and copy data for exfiltration. | 230 | 8 | 8 |

### Persistence (TA0003) — 5

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | Medusa Group has utilized compromised legitimate local and domain accounts within the victim environment to facilitate remote access and lateral movement sometimes in combination with PsExec. | 825 | — | 3 |
| [T1112](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1112) Modify Registry | Medusa Group has modified Registry keys to elevate privileges, maintain persistence and allow remote access. | 601 | 92 | 3 |
| [T1136.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1136.002) Domain Account | Medusa Group has created a domain account within the victim environment. | 27 | 5 | — |
| [T1505.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1505.003) Web Shell | Medusa Group has utilized webshells to an exploited Microsoft Exchange Server. | 210 | 1 | — |
| [T1543.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1543.003) Windows Service | Medusa Group has used vulnerable or signed drivers to modify security solutions on victim devices. | 1916 | 6 | 19 |

### Privilege Escalation (TA0004) — 3

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | Medusa Group has utilized compromised legitimate local and domain accounts within the victim environment to facilitate remote access and lateral movement sometimes in combination with PsExec. | 825 | — | 3 |
| [T1543.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1543.003) Windows Service | Medusa Group has used vulnerable or signed drivers to modify security solutions on victim devices. | 1916 | 6 | 19 |
| [T1548.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1548.002) Bypass User Account Control | Medusa Group has attempted to bypass UAC using Component Object Model (COM) interface. | 379 | 28 | 14 |

### Stealth (TA0005) — 7

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1027.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1027.002) Software Packing | Medusa Group has packed the code of dropped kernel drivers using the packer ASM Guard. | 12 | 4 | — |
| [T1027.010](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1027.010) Command Obfuscation | Medusa Group has obfuscated PowerShell scripts with Base64 encoding. Medusa Group has also obfuscated the code of dropped kernel drivers using a software known as Safengine Shielden which randomized the code through code mutations and then leveraged an embedde… | 78 | — | — |
| [T1070.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1070.003) Clear Command History | Medusa Group has cleared command history by running the PowerShell command `Remove-Item (Get-PSReadlineOption).HistorySavePath`. | 63 | 14 | — |
| [T1070.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1070.004) File Deletion | Medusa Group has deleted previously installed tools. | 132 | 11 | — |
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | Medusa Group has utilized compromised legitimate local and domain accounts within the victim environment to facilitate remote access and lateral movement sometimes in combination with PsExec. | 825 | — | 3 |
| [T1218.014](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1218.014) MMC | Medusa Group has leveraged Microsoft Management Console (MMC) to facilitate lateral movement and to interact locally or remotely with victim devices using the command `mmc.exe compmgmt.msc /computer:{hostname/ip}`. | 18 | — | — |
| [T1564.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1564.003) Hidden Window | Medusa Group has utilized the `ShowWindow` API function to hide the current window. | 51 | 3 | — |

### Defense Impairment (TA0112) — 5

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1112](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1112) Modify Registry | Medusa Group has modified Registry keys to elevate privileges, maintain persistence and allow remote access. | 601 | 92 | 3 |
| [T1553.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1553.002) Code Signing | Medusa Group has utilized vulnerable or signed drivers to kill or delete services associated with endpoint detection and response (EDR) tools. | 11 | — | — |
| [T1685](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1685) Disable or Modify Tools | Medusa Group has terminated antivirus services utilizing the gaze.exe executable and utilizing `psexec.exe`. Medusa Group has also leveraged I/O control codes (IOCTLs) for terminating and deleting processes of identified security tools. | 1275 | 78 | 19 |
| [T1686](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1686) Disable or Modify System Firewall | Medusa Group has utilized PsExec to execute batch scripts that modify firewall settings. Medusa Group has also enabled and modified firewall rules to allow for RDP connections for lateral movement and device interactions. | 56 | 25 | 6 |
| [T1690](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1690) Prevent Command History Logging | Medusa Group has removed PowerShell command history through the use of the PSReadLine module by running the PowerShell command `Remove-Item (Get-PSReadlineOption).HistorySavePath`. | 12 | 12 | — |

### Credential Access (TA0006) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1003.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1003.001) LSASS Memory | Medusa Group has leveraged Mimikatz to dump LSASS to harvest credentials. | 580 | 14 | 10 |
| [T1003.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1003.003) NTDS | Medusa Group has accessed the ntds.dit file to engage in credential dumping. | 157 | 11 | 2 |

### Discovery (TA0007) — 12

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1016](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1016) System Network Configuration Discovery | Medusa Group has obtained host network details utilizing the command `cmd.exe /c ipconfig /all`. | 99 | 10 | 5 |
| [T1018](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1018) Remote System Discovery | Medusa Group has used PDQ Inventory to get an inventory of the endpoints on the network. | 157 | 23 | 1 |
| [T1033](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1033) System Owner/User Discovery | Medusa Group has utilized PsExec to execute `quser` to discover the user session information. | 181 | 8 | — |
| [T1046](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1046) Network Service Discovery | Medusa Group has the capability to use living off the land (LOTL) binaries to perform network enumeration. Medusa Group has also utilized the publicly available scanning tool SoftPerfect Network Scanner (`netscan.exe`) to discover device hostnames and network … | 212 | 13 | 2 |
| [T1057](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1057) Process Discovery | Medusa Group has utilized a hard-coded security tool process list that identifies and terminates using an undocumented IOCTL code 0x222094. | 82 | 10 | — |
| [T1069.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1069.002) Domain Groups | Medusa Group has utilized the `net group` command to query domain groups within the victim environment. | 91 | 15 | — |
| [T1082](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1082) System Information Discovery | Medusa Group has leveraged `cmd.exe` to identify system info `cmd.exe /c systeminfo`. | 264 | 41 | — |
| [T1083](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1083) File and Directory Discovery | Medusa Group has searched for files within the victim environment for encryption and exfiltration. Medusa Group has also identified files associated with remote management services. | 137 | 9 | — |
| [T1087.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1087.001) Local Account | Medusa Group has leveraged `net user` for account discovery. | 98 | 11 | — |
| [T1135](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1135) Network Share Discovery | Medusa Group has identified network shares using `cmd.exe /c net share`. | 73 | 12 | 3 |
| [T1518.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1518.001) Security Software Discovery | Medusa Group has detected security solutions for termination or deletion within the victim device using hard-coded lists of strings containing security product executables. | 54 | 12 | — |
| [T1652](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1652) Device Driver Discovery | Medusa Group has queried drivers on the victim device through the command `driverquery`. | 3 | 5 | — |

### Lateral Movement (TA0008) — 3

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1021.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1021.001) Remote Desktop Protocol | Medusa Group has used RDP to conduct lateral movement and exfiltrate data. Medusa Group has also utilized the Windows executable `mstsc.exe` for RDP activities through the command `mstsc.exe /v:{hostname/ip}`. | 139 | 4 | 7 |
| [T1072](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1072) Software Deployment Tools | Medusa Group has utilized software deployment and management solutions to deploy their encryption payload to include BigFix and PDQ Deploy. | 59 | 3 | — |
| [T1570](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1570) Lateral Tool Transfer | Medusa Group has utilized legitimate software services such as PDQ Deploy to transfer malicious binaries and tools to other victimized hosts within the target environment. | 58 | 2 | — |

### Command and Control (TA0011) — 5

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1071.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1071.001) Web Protocols | Medusa Group has communicated through reverse or bind shells over port 443 (HTTPS). | 228 | 3 | — |
| [T1090.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1090.003) Multi-hop Proxy | Medusa Group has used TOR nodes for communications. | 44 | 4 | — |
| [T1105](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1105) Ingress Tool Transfer | Medusa Group has leveraged certutil, PowerShell, and Windows Command to download additional tools to include RMM services. Medusa Group has also engaged in “Bring Your Own Vulnerable Driver” (BYOVD) and downloaded vulnerable or signed drivers to the victim env… | 644 | 39 | — |
| [T1219](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1219) Remote Access Tools | Medusa Group has leveraged Remote Access Software for lateral movement and data exfiltration. Medusa Group has also been known to utilize Remote Access Software such as AnyDesk, Atera, ConnectWise, eHorus, N-Able, PDQ Deploy, PDQ Inventory, SimpleHelp and Spla… | 119 | 15 | — |
| [T1573.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1573.002) Asymmetric Cryptography | Medusa Group has used HTTPS for command and control. | 14 | — | — |

### Exfiltration (TA0010) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1567.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1567.002) Exfiltration to Cloud Storage | Medusa Group has utilized Rclone to exfiltrate data from victim environments to cloud storage. | 85 | 2 | — |

### Impact (TA0040) — 5

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1486](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1486) Data Encrypted for Impact | Medusa Group has encrypted files using AES-256 encryption which then appends the file extension “.medusa” to encrypted files and leaves a ransomware note named “!READ_ME_MEDUSA!!!.txt.” | 160 | 10 | 1 |
| [T1489](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1489) Service Stop | Medusa Group has terminated services related to backups, security, databases, communication, filesharing and websites. | 112 | 9 | — |
| [T1490](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1490) Inhibit System Recovery | Medusa Group has deleted recovery files such as shadow copies using `vssadmin.exe`. | 188 | 13 | 5 |
| [T1529](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1529) System Shutdown/Reboot | Medusa Group has manually turned off and encrypted virtual machines. | 52 | 16 | — |
| [T1657](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1657) Financial Theft | Medusa Group has stolen and encrypted victims' data in order to extort victims into paying a ransom. | 2 | — | — |

## 4. Assinatura comportamental

Técnicas que este grupo usa e que poucos dos 178 grupos do ATT&CK usam. Pesam mais numa atribuição por TTP: ver várias delas juntas é mais informativo do que ver técnicas comuns como PowerShell.

| Técnica | Outros grupos que usam | Peso (raridade) |
|---|---:|---:|
| T1218.014 MMC | 0 | 4.49 |
| T1650 Acquire Access | 0 | 4.49 |
| T1652 Device Driver Discovery | 0 | 4.49 |
| T1608.002 Upload Tool | 1 | 4.09 |
| T1529 System Shutdown/Reboot | 3 | 3.58 |
| T1559.001 Component Object Model | 3 | 3.58 |
| T1690 Prevent Command History Logging | 3 | 3.58 |
| T1136.002 Domain Account | 4 | 3.40 |
| T1489 Service Stop | 6 | 3.11 |
| T1490 Inhibit System Recovery | 6 | 3.11 |

## 5. Arsenal

| Software | Tipo | Técnicas no ATT&CK | Uso relatado (EN) |
|---|---|---:|---|
| [Medusa Ransomware](https://attack.mitre.org/software/S1244/) | malware | 22 | Medusa Group has used Medusa Ransomware for ransomware activities. |
| [Mimikatz](https://attack.mitre.org/software/S0002/) | ferramenta | 17 | Medusa Group has used Mimikatz to dump LSASS for credential harvesting. |
| [Rclone](https://attack.mitre.org/software/S1040/) | ferramenta | 6 | Medusa Group has leveraged Rclone to exfiltrate data from victim environments. |
| [PsExec](https://attack.mitre.org/software/S0029/) | ferramenta | 5 | Medusa Group has utilized PsExec to facilitate execution, lateral movement, defense evasion, and exfiltration. |
| [certutil](https://attack.mitre.org/software/S0160/) | ferramenta | 4 | Medusa Group has utilized certutil to download additional tools within victim environments. |

## 6. Campanhas

Nenhuma campanha atribuída no ATT&CK.

## 7. Cobertura defensiva

**55 de 57 técnicas (96%)** têm ao menos uma regra pública no catálogo Detection Rules.

### Técnicas sem regra pública (prioridade para engenharia de detecção)

- **T1650 Acquire Access** — Resource Development
- **T1585.002 Email Accounts** — Resource Development

### Regras recomendadas por técnica

Melhor regra disponível por técnica (formato portável e maduro primeiro).

| Técnica | Regra | Formato | Fonte |
|---|---|---|---|
| T1003.001 | [Antivirus - Password Dumper Signature](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A78cc2dd2-7d20-4d32-93ff-057084c38b93) | Sigma | SigmaHQ |
| T1003.001 | [Mimikatz through Windows Remote Management](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Aaa35a627-33fb-4d04-a165-d33b4afca3e8) | Sigma | OpenSearch Security Analytics |
| T1003.003 | [Potential Russian APT Credential Theft Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab83f5166-9237-4b5e-9cd4-7b5d52f4d8ee) | Sigma | SigmaHQ |
| T1003.003 | [VolumeShadowCopy Symlink Creation Via Mklink](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A40b19fa6-d835-400c-b301-41f3a2baacaf) | Sigma | SigmaHQ |
| T1016 | [Potential Pikabot Discovery Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A698d4431-514f-4c82-af4d-cf573872a9f5) | Sigma | SigmaHQ |
| T1016 | [OpenCanary - SNMP OID Request](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae9856028-fd4e-46e6-b3d1-10f7ceb95078) | Sigma | SigmaHQ |
| T1018 | [Chopper Webshell Process Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Afa3c117a-bc0d-416e-a31b-0c0e80653efb) | Sigma | SigmaHQ |
| T1018 | [Webshell Hacking Activity Patterns](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4ebc877f-4612-45cb-b3a5-8e3834db36c9) | Sigma | SigmaHQ |
| T1021.001 | [Hermetic Wiper TG Process Patterns](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A2f974656-6d83-4059-bbdf-68ac5403422f) | Sigma | SigmaHQ |
| T1021.001 | [Publicly Accessible RDP Service](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1fc0809e-06bf-4de3-ad52-25e5263b7623) | Sigma | SigmaHQ |
| T1027.002 | [Python Image Load By Non-Python Process](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acbb56d62-4060-40f7-9466-d8aaf3123f83) | Sigma | SigmaHQ |
| T1027.002 | [Python Py2Exe Image Load](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Acbb56d62-4060-40f7-9466-d8aaf3123f83) | Sigma | OpenSearch Security Analytics |
| T1027.010 | [Decoded Payload Piped to Interpreter Detected via Defend for Containers](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A0fb83aa0-3d17-41e9-b09c-56397bf7a7d9) | Elastic | Elastic detection-rules |
| T1027.010 | [Potential PowerShell Obfuscation via String Concatenation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Af6d8c743-0916-4483-8333-3c6f107e0caa) | Elastic | Elastic detection-rules |
| T1033 | [Potential Dridex Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae6eb5a96-9e6f-4a18-9cdd-642cfda21c8e) | Sigma | SigmaHQ |
| T1033 | [Dridex Process Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Ae6eb5a96-9e6f-4a18-9cdd-642cfda21c8e) | Sigma | OpenSearch Security Analytics |
| T1046 | [HackTool - winPEAS Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A98b53e78-ebaf-46f8-be06-421aafd176d9) | Sigma | SigmaHQ |
| T1046 | [HackTool - WinPwn Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad557dc06-62e8-4468-a8e8-7984124908ce) | Sigma | SigmaHQ |
| T1047 | [HackTool - Potential Impacket Lateral Movement Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A10c14723-61c7-4c75-92ca-9af245723ad2) | Sigma | SigmaHQ |
| T1047 | [CrackMapExec Command Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A058f4380-962d-40a5-afce-50207d36d7e2) | Sigma | OpenSearch Security Analytics |
| T1057 | [Process Discovery](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4e2f5868-08d4-413d-899f-dc2f1508627b) | Sigma | SigmaHQ |
| T1057 | [HackTool - PCHunter Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Afca949cc-79ca-446e-8064-01aa7e52ece5) | Sigma | SigmaHQ |
| T1059.001 | [Potential Emotet Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad02e8cf5-6099-48cf-9bfc-1eec2d0c7b18) | Sigma | SigmaHQ |
| T1059.001 | [TropicTrooper Campaign November 2018](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A8c7090c3-e0a0-4944-bd08-08c3a0cecf79) | Sigma | SigmaHQ |
| T1059.003 | [HackTool - CrackMapExec Execution Patterns](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A058f4380-962d-40a5-afce-50207d36d7e2) | Sigma | SigmaHQ |
| T1059.003 | [CrackMapExec Command Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A058f4380-962d-40a5-afce-50207d36d7e2) | Sigma | OpenSearch Security Analytics |
| T1069.002 | [BloodHound Collection Files](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A02773bed-83bf-469f-b7ff-e676e7d78bab) | Sigma | SigmaHQ |
| T1069.002 | [HackTool - SharpView Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab2317cfa-4a47-4ead-b3ff-297438c0bc2d) | Sigma | SigmaHQ |
| T1070.003 | [Cisco Clear Logs](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aceb407f6-8277-439b-951f-e4210e3ed956) | Sigma | SigmaHQ |
| T1070.003 | [Linux Command History Tampering](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Afdc88d25-96fb-4b7c-9633-c0e417fdbd4e) | Sigma | SigmaHQ |
| T1070.004 | [File Deletion](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A30aed7b6-d2c1-4eaf-9382-b6bc43e50c57) | Sigma | SigmaHQ |
| T1070.004 | [Prefetch File Deleted](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A0a1f9d29-6465-4776-b091-7f43b26e4c89) | Sigma | SigmaHQ |
| T1071.001 | [Ursnif Malware Download URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aa36ce77e-30db-4ea0-8795-644d7af5dfb4) | Sigma | SigmaHQ |
| T1071.001 | [Ursnif Malware C2 URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A932ac737-33ca-4afd-9869-0d48b391fcc9) | Sigma | SigmaHQ |
| T1072 | [Restricted Software Access By SRP](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab4c8da4a-1c12-46b0-8a2b-0a8521d03442) | Sigma | SigmaHQ |
| T1072 | [Suspicious Curl to Jamf Endpoint](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Aa8256685-9736-465b-b159-f25a172d08e8) | Elastic | Elastic detection-rules |
| T1078 | [Privilege Role Sign-In Outside Expected Controls](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acf1e5687-84e1-41af-97a9-158094efef53) | Sigma | SigmaHQ |
| T1078 | [OpenCanary - SSH Login Attempt](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aff7139bc-fdb1-4437-92f2-6afefe8884cb) | Sigma | SigmaHQ |
| T1082 | [Potential GobRAT File Discovery Via Grep](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae34cfa0c-0a50-4210-9cb3-5632d08eb041) | Sigma | SigmaHQ |
| T1082 | [System Information Discovery](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A42df45e7-e6e9-43b5-8f26-bec5b39cc239) | Sigma | SigmaHQ |
| T1083 | [Turla Group Lateral Movement](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac601f20d-570a-4cde-a7d6-e17f99cb8e7f) | Sigma | SigmaHQ |
| T1083 | [WannaCry Ransomware Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A41d40bff-377a-43e2-8e1b-2e543069e079) | Sigma | SigmaHQ |
| T1087.001 | [BloodHound Collection Files](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A02773bed-83bf-469f-b7ff-e676e7d78bab) | Sigma | SigmaHQ |
| T1087.001 | [HackTool - Bloodhound/Sharphound Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Af376c8a7-a2d0-4ddc-aa0c-16c17236d962) | Sigma | SigmaHQ |
| T1090.003 | [Tor Client/Browser Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A62f7c9bf-9135-49b2-8aeb-1e54a6ecc13c) | Sigma | SigmaHQ |
| T1090.003 | [Query Tor Onion Address - DNS Client](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A8384bd26-bde6-4da9-8e5d-4174a7a47ca2) | Sigma | SigmaHQ |
| T1105 | [Greenbug Espionage Group Indicators](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A3711eee4-a808-4849-8a14-faf733da3612) | Sigma | SigmaHQ |
| T1105 | [Pandemic Registry Key](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A47e0852a-cf81-4494-a8e6-31864f8c86ed) | Sigma | SigmaHQ |
| T1106 | [Turla Group Named Pipes](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A739915e4-1e70-4778-8b8a-17db02f66db1) | Sigma | SigmaHQ |
| T1106 | [BPFDoor Abnormal Process ID or Lock File Accessed](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A808146b2-9332-4d78-9416-d7e47012d83d) | Sigma | SigmaHQ |
| T1112 | [ShimCache Flush](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab0524451-19af-4efa-a46f-562a977f792e) | Sigma | SigmaHQ |
| T1112 | [ShimCache Flush](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Ab0524451-19af-4efa-a46f-562a977f792e) | Sigma | OpenSearch Security Analytics |
| T1135 | [Potential Dridex Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae6eb5a96-9e6f-4a18-9cdd-642cfda21c8e) | Sigma | SigmaHQ |
| T1135 | [Dridex Process Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Ae6eb5a96-9e6f-4a18-9cdd-642cfda21c8e) | Sigma | OpenSearch Security Analytics |
| T1136.002 | [PSExec Lateral Movement](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=hayabusa-native%3A%3A0694c340-3a46-40ac-acfc-c3444ae6572c) | Sigma | Hayabusa (native) |
| T1136.002 | [PSEXEC Remote Execution File Artefact](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A304afd73-55a5-4bb9-8c21-0b1fc84ea9e4) | Sigma | SigmaHQ |
| T1190 | [OMIGOD HTTP No Authentication RCE - CVE-2021-38647](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aab6b1a39-a9ee-4ab4-b075-e83acf6e346b) | Sigma | SigmaHQ |
| T1190 | [Exploited CVE-2020-10189 Zoho ManageEngine](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A846b866e-2a57-46ee-8e16-85fa92759be7) | Sigma | OpenSearch Security Analytics |
| T1218.014 | [Incoming DCOM Lateral Movement with MMC](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A51ce96fb-9e52-4dad-b0ba-99b54440fc9a) | Elastic | Elastic detection-rules |
| T1218.014 | [Unusual Execution via Microsoft Common Console File](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ae760c72b-bb1f-44f0-9f0d-37d51744ee75) | Elastic | Elastic detection-rules |
| T1219 | [Renamed Visual Studio Code Tunnel Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A2cf29f11-e356-4f61-98c0-1bdb9393d6da) | Sigma | SigmaHQ |
| T1219 | [Hijack Legit RDP Session to Move Laterally](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A52753ea4-b3a0-4365-910d-36cff487b789) | Sigma | OpenSearch Security Analytics |
| T1486 | [LockerGoga Ransomware Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A74db3488-fd28-480a-95aa-b7af626de068) | Sigma | SigmaHQ |
| T1486 | [LockerGoga Ransomware](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A74db3488-fd28-480a-95aa-b7af626de068) | Sigma | OpenSearch Security Analytics |
| T1489 | [Delete Important Scheduled Task](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Adbc1f800-0fe0-4bc0-9c66-292c2abe3f78) | Sigma | SigmaHQ |
| T1489 | [Suspicious Windows Service Tampering](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ace72ef99-22f1-43d4-8695-419dcb5d9330) | Sigma | SigmaHQ |
| T1490 | [Potential Dtrack RAT Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Af1531fa4-5b84-4342-8f68-9cf3fdbd83d4) | Sigma | SigmaHQ |
| T1490 | [Boot Configuration Tampering Via Bcdedit.EXE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1444443e-6757-43e4-9ea4-c8fc705f79a2) | Sigma | SigmaHQ |
| T1505.003 | [MOVEit CVE-2023-34362 Exploitation Attempt - Potential Web Shell Request](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A435e41f2-48eb-4c95-8a2b-ed24b50ec30b) | Sigma | SigmaHQ |
| T1505.003 | [Solarwinds SUPERNOVA Webshell Access](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aa2cee20b-eacc-459f-861d-c02e5d12f1db) | Sigma | SigmaHQ |
| T1518.001 | [Sysmon Discovery Via Default Driver Altitude Using Findstr.EXE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A37db85d1-b089-490a-a59a-c7b6f984f480) | Sigma | SigmaHQ |
| T1518.001 | [Local Firewall Rules Enumeration Via NetFirewallRule Cmdlet](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aea207a23-b441-4a17-9f76-ad5be47d51d3) | Sigma | SigmaHQ |
| T1529 | [Silence.EDA Detection](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A3ceb2083-a27f-449a-be33-14ec1b7cc973) | Sigma | SigmaHQ |
| T1529 | [Silence.EDA Detection](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A3ceb2083-a27f-449a-be33-14ec1b7cc973) | Sigma | OpenSearch Security Analytics |
| T1543.003 | [PSExec Lateral Movement](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=hayabusa-native%3A%3A0694c340-3a46-40ac-acfc-c3444ae6572c) | Sigma | Hayabusa (native) |
| T1543.003 | [Suspicious Service Name](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=hayabusa-native%3A%3Acc429813-21db-4019-b520-2f19648e1ef1) | Sigma | Hayabusa (native) |
| T1548.002 | [CMSTP UAC Bypass via COM Object Access](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4b60e6f2-bf39-47b4-b4ea-398e33cfe253) | Sigma | SigmaHQ |
| T1548.002 | [HackTool - Empire PowerShell UAC Bypass](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A3268b746-88d8-4cd3-bffc-30077d02c787) | Sigma | SigmaHQ |
| T1553.002 | [Driver Loaded (Invalid Signature)](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=hayabusa-native%3A%3A1f666722-3948-40a2-9d78-d9d374477a90) | Sigma | Hayabusa (native) |
| T1553.002 | [Driver Loaded (Expired/Revoked Cert)](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=hayabusa-native%3A%3Ac837dd6d-0c91-4593-aeab-f6a1f3ca1961) | Sigma | Hayabusa (native) |
| T1559.001 | [CMSTP Execution Process Access](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A3b4b232a-af90-427c-a22f-30b0c0837b95) | Sigma | SigmaHQ |
| T1559.001 | [CMSTP Execution Process Access](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A3b4b232a-af90-427c-a22f-30b0c0837b95) | Sigma | OpenSearch Security Analytics |
| T1564.003 | [Potential Data Stealing Via Chromium Headless Debugging](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A3e8207c5-fcd2-4ea6-9418-15d45b4890e4) | Sigma | SigmaHQ |
| T1564.003 | [HackTool - Covenant PowerShell Launcher](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac260b6db-48ba-4b4a-a76f-2f67644e99d2) | Sigma | SigmaHQ |
| T1567.002 | [APT40 Dropbox Tool User Agent](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A5ba715b6-71b7-44fd-8245-f66893e81b3d) | Sigma | SigmaHQ |
| T1567.002 | [PUA - Rclone Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae37db05d-d1f9-49c8-b464-cee1a4b11638) | Sigma | SigmaHQ |
| T1569.002 | [PSExec Lateral Movement](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=hayabusa-native%3A%3A0694c340-3a46-40ac-acfc-c3444ae6572c) | Sigma | Hayabusa (native) |
| T1569.002 | [DNS RCE CVE-2020-1350](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab5281f31-f9cc-4d0d-95d0-45b91c45b487) | Sigma | SigmaHQ |
| T1570 | [PSExec Lateral Movement](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=hayabusa-native%3A%3A0694c340-3a46-40ac-acfc-c3444ae6572c) | Sigma | Hayabusa (native) |
| T1570 | [PSEXEC Remote Execution File Artefact](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A304afd73-55a5-4bb9-8c21-0b1fc84ea9e4) | Sigma | SigmaHQ |
| T1573.002 | [Potential Self-Signed TLS Certificate Recently Issued on External Connection](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A869fe008-5dd4-4f07-9c2e-aa90c3926fd9) | Elastic | Elastic detection-rules |
| T1573.002 | [Openssl Client or Server Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Aad5a3757-c872-4719-8c72-12d3f08db655) | Elastic | Elastic detection-rules |
| T1583.006 | [GitHub Repo Created](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A6cea88e4-6ce2-4238-9981-a54c140d6336) | Elastic | Elastic detection-rules |
| T1583.006 | [Cisco Secure Firewall - Rare Snort Rule Triggered](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=splunk-security-content%3A%3Ae20313d2-7d63-4fcf-b2d9-d6e12c6c7bd7) | Splunk | Splunk security_content |
| T1585.001 | [CYFIRMA - Brand Intelligence - Social Media Handle Impersonation Detected High Rule](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A22f49d67-7da7-4809-8d07-89e4478aa6b0) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1585.001 | [CYFIRMA - Brand Intelligence - Executive/People Impersonation High Rule](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A159d26a1-591c-4f70-b1ca-2843c881aaec) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1588.002 | [Hacktool Execution - Imphash](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A24e3e58a-646b-4b50-adef-02ef935b9fc8) | Sigma | SigmaHQ |
| T1588.002 | [Renamed SysInternals DebugView Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acd764533-2e07-40d6-a718-cfeec7f2da7f) | Sigma | SigmaHQ |
| T1608.002 | [Windows Unusual File Creation in Confluence Directory](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=splunk-security-content%3A%3Aaa9d80d9-ed47-44da-aceb-2909ca4dc19e) | Splunk | Splunk security_content |
| T1652 | [Sysmon - Event 1: Process creation $(win.eventdata.description)](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=socfortress-wazuh-rules%3A%3Awazuh-100774) | Wazuh | SOCFortress Wazuh-Rules |
| T1652 | [Sysmon - Event 1: Process creation $(win.eventdata.description)](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=socfortress-wazuh-rules%3A%3Awazuh-100775) | Wazuh | SOCFortress Wazuh-Rules |
| T1657 | [AWS S3 Bucket Enumeration or Brute Force](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A5f0234fd-7f21-42af-8391-511d5fd11d5c) | Elastic | Elastic detection-rules |
| T1657 | [Monitor ransomwarelive for companies of interest on ransowmare data leak sites (DLS)](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=bert-janp-hunting-queries%3A%3A8b9af12a820a) | KQL hunting | Bert-JanP Hunting Queries |
| T1685 | [Windows Defender Configuration Changes](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A801bd44f-ceed-4eb6-887c-11544633c0aa) | Sigma | SigmaHQ |
| T1685 | [Windows Defender Virus Scanning Feature Disabled](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A686c0b4b-9dd3-4847-9077-d6c1bbe36fcb) | Sigma | SigmaHQ |
| T1686 | [Disable System Firewall](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A53059bc0-1472-438b-956a-7508a94a91f0) | Sigma | SigmaHQ |
| T1686 | [Netsh RDP Port Opening](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A01aeb693-138d-49d2-9403-c4f52d7d3d62) | Sigma | OpenSearch Security Analytics |
| T1690 | [ESXi Syslog Configuration Change Via ESXCLI](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A38eb1dbb-011f-40b1-a126-cf03a0210563) | Sigma | SigmaHQ |
| T1690 | [ESXi Syslog Configuration Change Via ESXCLI](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A38eb1dbb-011f-40b1-a126-cf03a0210563) | Sigma | OpenSearch Security Analytics |

## 8. Plano de emulação e validação

Use num laboratório isolado e autorizado para confirmar que as regras disparam. Os comandos estão nos repositórios oficiais.

| Tática | Técnica | Teste Atomic Red Team | Plataformas |
|---|---|---|---|
| Execution | [T1047](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1047/T1047.md) | WMI Reconnaissance Users | windows |
| Execution | [T1047](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1047/T1047.md) | WMI Reconnaissance Processes | windows |
| Execution | [T1059.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md) | Mimikatz | windows |
| Execution | [T1059.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md) | Run BloodHound from local disk | windows |
| Execution | [T1059.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.003/T1059.003.md) | Create and Execute Batch Script | windows |
| Execution | [T1059.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.003/T1059.003.md) | Writes text to a file and displays it. | windows |
| Execution | [T1072](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1072/T1072.md) | Radmin Viewer Utility | windows |
| Execution | [T1072](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1072/T1072.md) | PDQ Deploy RAT | windows |
| Execution | [T1106](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1106/T1106.md) | Execution through API - CreateProcess | windows |
| Execution | [T1106](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1106/T1106.md) | WinPwn - Get SYSTEM shell - Pop System Shell using CreateProcess technique | windows |
| Execution | [T1569.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1569.002/T1569.002.md) | Execute a Command as a Service | windows |
| Execution | [T1569.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1569.002/T1569.002.md) | Use PsExec to execute a command on a remote host | windows |
| Persistence | [T1136.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1136.002/T1136.002.md) | Create a new Windows domain admin user | windows |
| Persistence | [T1136.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1136.002/T1136.002.md) | Create a new account similar to ANONYMOUS LOGON | windows |
| Persistence | [T1505.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1505.003/T1505.003.md) | Web Shell Written to Disk | windows |
| Persistence | [T1543.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1543.003/T1543.003.md) | Modify Fax service to run PowerShell | windows |
| Persistence | [T1543.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1543.003/T1543.003.md) | Service Installation CMD | windows |
| Privilege Escalation | [T1548.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1548.002/T1548.002.md) | Bypass UAC using Event Viewer (cmd) | windows |
| Privilege Escalation | [T1548.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1548.002/T1548.002.md) | Bypass UAC using Event Viewer (PowerShell) | windows |
| Stealth | [T1027.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027.002/T1027.002.md) | Binary simply packed by UPX (linux) | linux |
| Stealth | [T1027.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027.002/T1027.002.md) | Binary packed by UPX, with modified headers (linux) | linux |
| Stealth | [T1070.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.003/T1070.003.md) | Clear Bash history (rm) |  |
| Stealth | [T1070.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.003/T1070.003.md) | Clear Bash history (echo) |  |
| Stealth | [T1070.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.004/T1070.004.md) | Delete a single file - FreeBSD/Linux/macOS | linux, macos |
| Stealth | [T1070.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.004/T1070.004.md) | Delete an entire folder - FreeBSD/Linux/macOS | linux, macos |
| Stealth | [T1564.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1564.003/T1564.003.md) | Hidden Window | windows |
| Stealth | [T1564.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1564.003/T1564.003.md) | Headless Browser Accessing Mockbin | windows |
| Defense Impairment | [T1112](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1112/T1112.md) | Modify Registry of Current User Profile - cmd | windows |
| Defense Impairment | [T1112](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1112/T1112.md) | Modify Registry of Local Machine - cmd | windows |
| Defense Impairment | [T1685](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1685/T1685.md) | Windows Disable LSA Protection | windows |
| Defense Impairment | [T1685](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1685/T1685.md) | Disable journal logging via systemctl utility | linux |
| Defense Impairment | [T1686](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1686/T1686.md) | Disable Microsoft Defender Firewall | windows |
| Defense Impairment | [T1686](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1686/T1686.md) | Disable Microsoft Defender Firewall via Registry | windows |
| Defense Impairment | [T1690](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1690/T1690.md) | Disable history collection | linux, macos |
| Defense Impairment | [T1690](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1690/T1690.md) | Disable history collection (freebsd) | linux |
| Credential Access | [T1003.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/T1003.001.md) | Dump LSASS.exe Memory using ProcDump | windows |
| Credential Access | [T1003.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/T1003.001.md) | Dump LSASS.exe Memory using comsvcs.dll | windows |
| Credential Access | [T1003.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.003/T1003.003.md) | Create Volume Shadow Copy with vssadmin | windows |
| Credential Access | [T1003.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.003/T1003.003.md) | Copy NTDS.dit from Volume Shadow Copy | windows |
| Discovery | [T1016](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1016/T1016.md) | System Network Configuration Discovery on Windows | windows |
| Discovery | [T1016](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1016/T1016.md) | List Windows Firewall Rules | windows |
| Discovery | [T1018](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1018/T1018.md) | Remote System Discovery - net | windows |
| Discovery | [T1018](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1018/T1018.md) | Remote System Discovery - net group Domain Computers | windows |
| Discovery | [T1033](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1033/T1033.md) | System Owner/User Discovery | windows |
| Discovery | [T1033](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1033/T1033.md) | System Owner/User Discovery | linux, macos |
| Discovery | [T1046](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1046/T1046.md) | Port Scan | linux, macos |
| Discovery | [T1046](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1046/T1046.md) | Port Scan Nmap | linux, macos |
| Discovery | [T1057](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1057/T1057.md) | Process Discovery - ps | linux, macos |
| Discovery | [T1057](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1057/T1057.md) | Process Discovery - tasklist | windows |
| Discovery | [T1069.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1069.002/T1069.002.md) | Basic Permission Groups Discovery Windows (Domain) | windows |
| Discovery | [T1069.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1069.002/T1069.002.md) | Permission Groups Discovery PowerShell (Domain) | windows |
| Discovery | [T1082](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1082/T1082.md) | System Information Discovery | windows |
| Discovery | [T1082](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1082/T1082.md) | System Information Discovery | macos |
| Discovery | [T1083](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1083/T1083.md) | File and Directory Discovery (cmd.exe) | windows |
| Discovery | [T1083](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1083/T1083.md) | File and Directory Discovery (PowerShell) | windows |
| Discovery | [T1087.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1087.001/T1087.001.md) | Enumerate all accounts (Local) | linux |
| Discovery | [T1087.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1087.001/T1087.001.md) | View sudoers access | linux, macos |
| Discovery | [T1135](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1135/T1135.md) | Network Share Discovery | macos |
| Discovery | [T1135](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1135/T1135.md) | Network Share Discovery - linux | linux |
| Discovery | [T1518.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1518.001/T1518.001.md) | Security Software Discovery | windows |
| Discovery | [T1518.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1518.001/T1518.001.md) | Security Software Discovery - powershell | windows |
| Discovery | [T1652](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1652/T1652.md) | Device Driver Discovery | windows |
| Discovery | [T1652](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1652/T1652.md) | Device Driver Discovery (Linux) | linux |
| Lateral Movement | [T1021.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.001/T1021.001.md) | RDP to Remote Host | windows |
| Lateral Movement | [T1021.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.001/T1021.001.md) | Changing RDP Port to Non Standard Port via Powershell | windows |
| Lateral Movement | [T1570](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1570/T1570.md) | Exfiltration Over SMB over QUIC (New-SmbMapping) | windows |
| Lateral Movement | [T1570](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1570/T1570.md) | Exfiltration Over SMB over QUIC (NET USE) | windows |
| Command and Control | [T1071.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1071.001/T1071.001.md) | Malicious User Agents - Powershell | windows |
| Command and Control | [T1071.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1071.001/T1071.001.md) | Malicious User Agents - CMD | windows |
| Command and Control | [T1090.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1090.003/T1090.003.md) | Psiphon | windows |
| Command and Control | [T1090.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1090.003/T1090.003.md) | Tor Proxy Usage - Windows | windows |
| Command and Control | [T1105](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1105/T1105.md) | rsync remote file copy (push) | linux, macos |
| Command and Control | [T1105](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1105/T1105.md) | rsync remote file copy (pull) | linux, macos |
| Command and Control | [T1219](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1219/T1219.md) | TeamViewer Files Detected Test on Windows | windows |
| Command and Control | [T1219](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1219/T1219.md) | AnyDesk Files Detected Test on Windows | windows |
| Exfiltration | [T1567.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1567.002/T1567.002.md) | Exfiltrate data with rclone to cloud Storage - Mega (Windows) | windows |
| Exfiltration | [T1567.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1567.002/T1567.002.md) | Exfiltrate data with rclone to cloud Storage - AWS S3 | linux, macos |
| Impact | [T1486](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1486/T1486.md) | Encrypt files using gpg (FreeBSD/Linux) | linux |
| Impact | [T1486](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1486/T1486.md) | Encrypt files using 7z (FreeBSD/Linux) | linux |
| Impact | [T1489](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1489/T1489.md) | Windows - Stop service using Service Controller | windows |
| Impact | [T1489](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1489/T1489.md) | Windows - Stop service using net.exe | windows |
| Impact | [T1490](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1490/T1490.md) | Windows - Delete Volume Shadow Copies | windows |
| Impact | [T1490](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1490/T1490.md) | Windows - Delete Volume Shadow Copies via WMI | windows |
| Impact | [T1529](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1529/T1529.md) | Shutdown System - Windows | windows |
| Impact | [T1529](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1529/T1529.md) | Restart System - Windows | windows |

**Logs reais de ataque (EVTX) para testar sem executar nada:**

- T1003.001 — [CA_hashdump_4663_4656_lsass_access](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Credential%20Access/CA_hashdump_4663_4656_lsass_access.evtx) _(inferido)_
- T1003.001 — [LsassSilentProcessExit_process_exit_monitor_3001_lsass](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Credential%20Access/LsassSilentProcessExit_process_exit_monitor_3001_lsass.evtx) _(inferido)_
- T1003.003 — [dc_applog_ntdsutil_dfir_325_326_327](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Credential%20Access/dc_applog_ntdsutil_dfir_325_326_327.evtx) _(inferido)_
- T1003.003 — [LM_regsvc_DirectoryServiceExtPt_Lsass_NTDS_AdamXpn](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Lateral%20Movement/LM_regsvc_DirectoryServiceExtPt_Lsass_NTDS_AdamXpn.evtx) _(inferido)_
- T1016 — [ID4688-Audit policy enumerated](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1016-System%20Network%20Configuration%20Discovery/ID4688-Audit%20policy%20enumerated.evtx) _(explícito)_
- T1016 — [ID4688-Firewall configuration enumerated (command)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1016-System%20Network%20Configuration%20Discovery/ID4688-Firewall%20configuration%20enumerated%20%28command%29.evtx) _(explícito)_
- T1018 — [ID5145-DNS hosts files access via network share](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1018-Remote%20System%20Discovery/ID5145-DNS%20hosts%20files%20access%20via%20network%20share.evtx) _(explícito)_
- T1021.001 — [ID4688,4778,4779 RDP hijack direct](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0008-Lateral%20Movement/T1021.001-Remote%20Desktop%20Protocol/ID4688%2C4778%2C4779%20RDP%20hijack%20direct.evtx) _(explícito)_
- T1021.001 — [ID4688-4778 RDP hijack command execution](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0008-Lateral%20Movement/T1021.001-Remote%20Desktop%20Protocol/ID4688-4778%20RDP%20hijack%20command%20execution.evtx) _(explícito)_
- T1046 — [ID131-RDP brutforce (no user info)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1046-Network%20Service%20Scanning/ID131-RDP%20brutforce%20%28no%20user%20info%29.evtx) _(explícito)_
- T1046 — [ID4624-Anonymous login with domain specified (DonPapi)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1046-Network%20Service%20Scanning/ID4624-Anonymous%20login%20with%20domain%20specified%20%28DonPapi%29.evtx) _(explícito)_
- T1047 — [ID1-WMI spwaning PowerShell process - WMImplant](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1047-Windows%20Management%20Instrumentation/ID1-WMI%20spwaning%20PowerShell%20process%20-%20WMImplant.evtx) _(explícito)_
- T1047 — [ID1-WMIexec process execution](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1047-Windows%20Management%20Instrumentation/ID1-WMIexec%20process%20execution.evtx) _(explícito)_
- T1059.001 — [ID4103-4104-Payload download via PowerShell](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1059.001-PowerShell/ID4103-4104-Payload%20download%20via%20PowerShell.evtx) _(explícito)_
- T1059.001 — [ID4688-Encoded PowerShell MSF payload via process execution](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1059.001-PowerShell/ID4688-Encoded%20PowerShell%20MSF%20payload%20via%20process%20execution.evtx) _(explícito)_
- T1059.003 — [ID4688-SQL Server payload injectection for reverse shell (MSF)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1059.003-Windows%20Command%20Shell/ID4688-SQL%20Server%20payload%20injectection%20for%20reverse%20shell%20%28MSF%29.evtx) _(explícito)_
- T1078 — [ID1149-RDP success logins to multiple hosts](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0001-Initial%20access/T1078-Valid%20accounts/ID1149-RDP%20success%20logins%20to%20multiple%20hosts.evtx) _(explícito)_
- T1078 — [ID33205-SQL Server failed login with disabled SA account](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0001-Initial%20access/T1078-Valid%20accounts/ID33205-SQL%20Server%20failed%20login%20with%20disabled%20SA%20account.evtx) _(explícito)_
- T1112 — [ID11,13-SMBexec service registration](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0005-Defense%20Evasion/T1112-Modify%20registry/ID11%2C13-SMBexec%20service%20registration.evtx) _(explícito)_
- T1112 — [ID4624,4670,4688,4674-Registry permission change via WMI (DAMP)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0005-Defense%20Evasion/T1112-Modify%20registry/ID4624%2C4670%2C4688%2C4674-Registry%20permission%20change%20via%20WMI%20%28DAMP%29.evtx) _(explícito)_
- T1135 — [ID4688-Network share discovery or connection via commandline](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1135.xxx-Network%20Share%20Discovery/ID4688-Network%20share%20discovery%20or%20connection%20via%20commandline.evtx) _(explícito)_
- T1135 — [ID5140-5145-Bloodhound-SharpHound enumeration via SMB](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1135.xxx-Network%20Share%20Discovery/ID5140-5145-Bloodhound-SharpHound%20enumeration%20via%20SMB.evtx) _(explícito)_
- T1486 — [ID 768,775,793,796,817,840-BitLocker encryption activated](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0040-Impact/T1486-Data%20Encrypted%20for%20Impact/ID%20768%2C775%2C793%2C796%2C817%2C840-BitLocker%20encryption%20activated.evtx) _(explícito)_
- T1490 — [ID4688-Delete VSS backup (WMI)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0040-Impact/T1490-Inhibit%20System%20Recovery/ID4688-Delete%20VSS%20backup%20%28WMI%29.evtx) _(explícito)_
- T1490 — [ID4688-Delete Window backup (webadmin)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0040-Impact/T1490-Inhibit%20System%20Recovery/ID4688-Delete%20Window%20backup%20%28webadmin%29.evtx) _(explícito)_

## 9. Hipóteses de hunting

Se Medusa Group estiver no seu ambiente, estas são as perguntas a fazer aos seus dados (fontes de log segundo as estratégias de detecção do MITRE ATT&CK).

1. **T1218.014 MMC** — Abuse of mmc.exe to execute non-Microsoft or user-staged .msc files and malicious COM CLSIDs. Behavioral chain: (1) suspicious mmc.exe invocation with /a or -Embedding and non-standard .msc path → (2) COM activation of non-baseline CLSIDs by mmc.exe → (3)… Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=7), `WinEventLog:Sysmon` (EventCode=11).
2. **T1652 Device Driver Discovery** — Monitor for suspicious usage of driver enumeration utilities (driverquery.exe) or API calls such as EnumDeviceDrivers(). Registry queries against HKLM\SYSTEM\CurrentControlSet\Services and HardwareProfiles that are abnormal may also indicate attempts to… Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=13, 14).
3. **T1608.002 Upload Tool** — If infrastructure or patterns in tooling have been previously identified, internet scanning may uncover when an adversary has staged tools to make them accessible for targeting. Much of this activity will take place outside the visibility of the target… Dados: `Internet Scan` (None).
4. **T1529 System Shutdown/Reboot** — Correlate process execution of shutdown/reboot commands (e.g., shutdown.exe, restart-computer) with host status change logs (Event IDs 1074, 6006) and absence of related administrative context (e.g., user not in Helpdesk group). Dados: `WinEventLog:Security` (EventCode=1074), `WinEventLog:Sysmon` (EventCode=1).
5. **T1559.001 Component Object Model** — Detects anomalous use of COM objects for execution, such as Office applications spawning scripting engines, enumeration of COM interfaces via registry queries, or processes loading atypical DLLs through COM activation. Correlates process creation, module… Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=7), `WinEventLog:Security` (EventCode=4663, 4670, 4656).
6. **T1690 Prevent Command History Logging** — Detection of environment variable tampering (HISTFILE, HISTCONTROL, HISTFILESIZE) and absence of expected bash history writes. Correlation of unset or zeroed history variables with active shell sessions is indicative of adversarial evasion. Dados: `auditd:SYSCALL` (execve calls modifying HISTFILE or HISTCONTROL via unset/export), `linux:osquery` (processes modifying environment variables related to history logging).
7. **T1136.002 Domain Account** — Adversary uses built-in tools such as 'net user /add /domain' or PowerShell to create a domain user account. The behavior chain includes: (1) suspicious process execution on a domain controller followed by (2) user account creation event (Event ID 4720) on… Dados: `WinEventLog:Security` (EventCode=4720), `WinEventLog:Sysmon` (EventCode=1).
8. **T1489 Service Stop** — Adversary disables or stops critical services (e.g., Exchange, SQL, AV, endpoint monitoring) using native utilities or API calls, often preceding destructive actions (T1485, T1486). Behavioral chain: Elevated execution context + stop-service or sc.exe or… Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Security` (EventCode=4672), `WinEventLog:System` (EventCode=7036).
9. **T1490 Inhibit System Recovery** — Process chains that use native utilities (vssadmin, wbadmin, diskshadow, bcdedit, REAgentC, wmic) with arguments to delete shadow copies, disable recovery, or remove backup catalogs Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Microsoft-Windows-Backup` (Windows Backup Catalog deletion or catalog corruption), `WinEventLog:System` (Service stopped or RecoveryDisabled set via REAgentC).
10. **T1070.003 Clear Command History** — Detects adversary behavior clearing command history via `history -c`, deletion or modification of ~/.bash_history, or manipulation of the HISTFILE environment variable post-login. Dados: `auditd:SYSCALL` (execve), `auditd:SYSCALL` (PATH).
11. **T1072 Software Deployment Tools** — Detects SCCM, Intune, or remote push execution spawning scripts or binaries from SYSTEM context or unusual consoles (e.g., cmtrace.exe launching PowerShell or cmd.exe). Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:Application` (SCCM, Intune logs).
12. **T1548.002 Bypass User Account Control** — Detects a multi-event behavior chain involving UAC bypass attempts via known auto-elevated binaries (e.g., eventvwr.exe, sdclt.exe), unauthorized Registry changes to UAC-related keys, and anomalous process execution with elevated privileges but lacking… Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:Security` (EventCode=4672), `WinEventLog:Sysmon` (EventCode=13, 14).

## 10. OSINT — onde pesquisar

Consultas prontas com todos os nomes conhecidos do grupo:

- Relatórios técnicos: [busca web](https://duckduckgo.com/?q=%28%22Medusa+Group%22%29+threat+report) · [PDFs](https://duckduckgo.com/?q=%28%22Medusa+Group%22%29+filetype%3Apdf)
- Regras e IOCs publicados: [GitHub](https://github.com/search?type=code&q=%22Medusa+Group%22)
- Pulsos de ameaça: [AlienVault OTX](https://otx.alienvault.com/browse/global/pulses?q=Medusa+Group)
- Família de malware e atores: [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/actors) (busque por Medusa Group)
- Cartões de grupo: [ThaiCERT Threat Group Cards](https://apt.etda.or.th/cgi-bin/listgroups.cgi)
- Página oficial: [MITRE ATT&CK G1051](https://attack.mitre.org/groups/G1051/)

## 11. Bibliografia (6 fontes citadas pelo ATT&CK)

- [Broadcom Medusa Ransomware Medusa Group March 2025](https://www.security.com/threat-intelligence/medusa-ransomware-attacks) — Threat Hunter Team Symantec and Carbon Black. (2025, March 6). Medusa Ransomware Activity Continues to Increase. Retrieved October 15, 2025.
- [Check Point Medusa Ransomware April 2025](https://www.checkpoint.com/cyber-hub/threat-prevention/ransomware/medusa-ransomware-group/) — Check Point. (2025, April 16). The 2025 Ransomware Surge: Context for Medusa’s Rise. Retrieved October 15, 2025.
- [CISA Medusa Group Medusa Ransomware March 2025](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-071a) — Cybersecurity and Infrastructure Security Agency. (2025, March 12). AA25-071A #StopRansomware: Medusa Ransomware. Retrieved October 15, 2025.
- [Intel471 Medusa Ransomware May 2025](https://www.intel471.com/blog/threat-hunting-case-study-medusa-ransomware) — Intel471. (2025, May 14). Threat hunting case study: Medusa ransomware. Retrieved October 15, 2025.
- [Palo Alto Unit 42 Medusa Group Medusa Ransomware January 2024](https://unit42.paloaltonetworks.com/medusa-ransomware-escalation-new-leak-site/) — Anthony Galiette, Doel Santos. (2024, January 11). Medusa Ransomware Turning Your Files into Stone. Retrieved October 15, 2025.
- [Security Scorecard Medusa Ransomware January 2024](https://securityscorecard.com/wp-content/uploads/2024/01/deep-dive-into-medusa-ransomware.pdf) — Vlad Pasca. (2024, January 1). A Deep Dive into Medusa Ransomware. Retrieved October 15, 2025.

## 12. Limites e confiança

- O ATT&CK registra o que foi **relatado publicamente**, não tudo o que o grupo faz. Ausência de uma técnica não prova que o grupo não a usa.
- **Sobreposição de TTP não é atribuição.** Muitas técnicas são compartilhadas entre grupos e com red teams. Use a assinatura comportamental como hipótese, junto com infraestrutura, malware e contexto.
- Cobertura de detecção refere-se ao catálogo público Detection Rules, não ao seu ambiente: confira se a telemetria necessária chega ao seu SIEM.
- Ligações marcadas como _inferidas_ (EVTX por palavra-chave, relatórios por nome) devem ser verificadas.

---
Fontes: MITRE ATT&CK® (uso livre com atribuição, © The MITRE Corporation), Atomic Red Team (Red Canary, MIT), EVTX-to-MITRE-Attack, EVTX-ATTACK-SAMPLES, APT & CyberCriminal Campaign Collections. Gerado por [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules).
