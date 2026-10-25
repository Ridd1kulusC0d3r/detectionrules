# Magic Hound (G0059) — Dossiê de inteligência

> **TLP:CLEAR** · gerado em 2026-10-25 a partir de fontes abertas · MITRE ATT&CK v20.0 · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0059) · [ATT&CK](https://attack.mitre.org/groups/G0059/)

**Também conhecido como:** TA453, COBALT ILLUSION, Charming Kitten, ITG18, Phosphorus, Newscaster, APT35, Mint Sandstorm  
**Registro no ATT&CK:** criado em 2018-01-16, atualizado em 2026-07-31 · referências de 2014 a 2023

## 1. Sumário executivo

- **78 técnicas** atribuídas publicamente, concentradas em **Discovery, Stealth, Persistence**.
- **Arsenal:** 3 malware e 10 ferramentas (ex.: Pupy, CharmPower, Mimikatz, Net, Impacket).
- **Campanhas atribuídas:** 0.
- **Cobertura de detecção pública:** 96% das técnicas têm ao menos uma regra no catálogo; **3 técnicas sem nenhuma regra pública**.
- **Assinatura comportamental** (técnicas raras entre os 178 grupos, as mais úteis para atribuição): T1016.002 Wi-Fi Discovery, T1591.001 Determine Physical Locations, T1685.001 Disable or Modify Windows Event Log, T1098.002 Additional Email Delegate Permissions, T1590.005 IP Addresses.

## 2. Quem é

> Magic Hound is an Iranian-sponsored threat group that conducts long term, resource-intensive cyber espionage operations, likely on behalf of the Islamic Revolutionary Guard Corps. They have targeted European, U.S., and Middle Eastern government and military personnel, academics, journalists, and organizations such as the World Health Organization (WHO), via complex social engineering campaigns since at least 2014.

_Texto original do MITRE ATT&CK, em inglês._

## 3. Perfil TTP por tática (kill chain)

Cada linha: técnica, como o grupo a usou segundo relatos públicos, e o que existe para detectar e testar.

### Reconnaissance (TA0043) — 8

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1589](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1589) Gather Victim Identity Information | Magic Hound has acquired mobile phone numbers of potential targets, possibly for mobile malware or additional phishing operations. | 11 | — | — |
| [T1589.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1589.001) Credentials | Magic Hound gathered credentials from two victims that they then attempted to validate across 75 different websites. Magic Hound has also collected credentials from over 900 Fortinet VPN servers in the US, Europe, and Israel. | 2 | — | — |
| [T1589.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1589.002) Email Addresses | Magic Hound has identified high-value email accounts in academia, journalism, NGO's, foreign policy, and national security for targeting. | 5 | — | — |
| [T1590.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1590.005) IP Addresses | Magic Hound has captured the IP addresses of visitors to their phishing sites. | 1 | — | — |
| [T1591.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1591.001) Determine Physical Locations | Magic Hound has collected location information from visitors to their phishing sites. | **0** | — | — |
| [T1592.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1592.002) Software | Magic Hound has captured the user-agent strings from visitors to their phishing sites. | 2 | — | — |
| [T1595.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1595.002) Vulnerability Scanning | Magic Hound has conducted widespread scanning to identify public-facing systems vulnerable to CVE-2021-44228 in Log4j and ProxyShell vulnerabilities; CVE-2021-26855, CVE-2021-26857, CVE-2021-26858, and CVE-2021-27065 in on-premises MS Exchange Servers; and CVE… | 27 | — | — |
| [T1598.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1598.003) Spearphishing Link | Magic Hound has used SMS and email messages with links designed to steal credentials or track victims. | **0** | — | — |

### Resource Development (TA0042) — 7

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1583.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1583.001) Domains | Magic Hound has registered fraudulent domains such as "mail-newyorker.com" and "news12.com.recover-session-service.site" to target specific victims with phishing attacks. | 7 | — | — |
| [T1583.006](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1583.006) Web Services | Magic Hound has acquired Amazon S3 buckets to use in C2. | 2 | — | — |
| [T1584.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1584.001) Domains | Magic Hound has used compromised domains to host links targeted to specific phishing victims. | 3 | — | — |
| [T1585.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1585.001) Social Media Accounts | Magic Hound has created fake LinkedIn and other social media accounts to contact targets and convince them--through messages and voice communications--to open malicious links. | 4 | — | — |
| [T1585.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1585.002) Email Accounts | Magic Hound has established email accounts using fake personas for spearphishing operations. | **0** | — | — |
| [T1586.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1586.002) Email Accounts | Magic Hound has compromised personal email accounts through the use of legitimate credentials and gathered additional victim information. | 3 | — | — |
| [T1588.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1588.002) Tool | Magic Hound has obtained and used tools like Havij, sqlmap, Metasploit, Mimikatz, and Plink. | 35 | — | — |

### Initial Access (TA0001) — 6

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1078.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.001) Default Accounts | Magic Hound enabled and used the default system managed account, DefaultAccount, via `"powershell.exe" /c net user DefaultAccount /active:yes` to connect to a targeted Exchange server over RDP. | 16 | 3 | — |
| [T1078.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.002) Domain Accounts | Magic Hound has used domain administrator accounts after dumping LSASS process memory. | 36 | — | 1 |
| [T1189](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1189) Drive-by Compromise | Magic Hound has conducted watering-hole attacks through media and magazine websites. | 57 | — | — |
| [T1190](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1190) Exploit Public-Facing Application | Magic Hound has exploited the Log4j utility (CVE-2021-44228), on-premises MS Exchange servers via "ProxyShell" (CVE-2021-34473, CVE-2021-34523, CVE-2021-31207), and Fortios SSL VPNs (CVE-2018-13379). | 580 | — | — |
| [T1566.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1566.002) Spearphishing Link | Magic Hound has sent malicious URL links through email to victims. In some cases the URLs were shortened or linked to Word documents with malicious macros that executed PowerShells scripts to download Pupy. | 138 | 1 | — |
| [T1566.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1566.003) Spearphishing via Service | Magic Hound used various social media channels (such as LinkedIn) as well as messaging services (such as WhatsApp) to spearphish victims. | 8 | — | — |

### Execution (TA0002) — 7

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1047](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1047) Windows Management Instrumentation | Magic Hound has used a tool to run `cmd /c wmic computersystem get domain` for discovery. | 370 | 12 | 11 |
| [T1053.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1053.005) Scheduled Task | Magic Hound has used scheduled tasks to establish persistence and execution. | 248 | 14 | 11 |
| [T1059.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.001) PowerShell | Magic Hound has used PowerShell for execution and privilege escalation. | 1340 | 22 | 15 |
| [T1059.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.003) Windows Command Shell | Magic Hound has used the command-line interface for code execution. | 269 | 6 | 1 |
| [T1059.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.005) Visual Basic | Magic Hound malware has used VBS scripts for execution. | 192 | 3 | — |
| [T1204.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1204.001) Malicious Link | Magic Hound has attempted to lure victims into opening malicious links embedded in emails. | 52 | — | — |
| [T1204.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1204.002) Malicious File | Magic Hound has attempted to lure victims into opening malicious email attachments. | 259 | 13 | — |

### Persistence (TA0003) — 9

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1053.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1053.005) Scheduled Task | Magic Hound has used scheduled tasks to establish persistence and execution. | 248 | 14 | 11 |
| [T1078.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.001) Default Accounts | Magic Hound enabled and used the default system managed account, DefaultAccount, via `"powershell.exe" /c net user DefaultAccount /active:yes` to connect to a targeted Exchange server over RDP. | 16 | 3 | — |
| [T1078.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.002) Domain Accounts | Magic Hound has used domain administrator accounts after dumping LSASS process memory. | 36 | — | 1 |
| [T1098.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1098.002) Additional Email Delegate Permissions | Magic Hound granted compromised email accounts read access to the email boxes of additional targeted accounts. The group then was able to authenticate to the intended victim's OWA (Outlook Web Access) portal and read hundreds of email communications for inform… | 10 | 1 | — |
| [T1098.007](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1098.007) Additional Local or Domain Groups | Magic Hound has added a user named DefaultAccount to the Administrators and Remote Desktop Users groups. | 10 | — | — |
| [T1112](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1112) Modify Registry | Magic Hound has modified Registry settings for security tools. | 601 | 92 | 3 |
| [T1136.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1136.001) Local Account | Magic Hound has created local accounts named `help` and `DefaultAccount` on compromised machines. | 103 | 10 | — |
| [T1505.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1505.003) Web Shell | Magic Hound has used multiple web shells to gain execution. | 210 | 1 | — |
| [T1547.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1547.001) Registry Run Keys / Startup Folder | Magic Hound malware has used Registry Run keys to establish persistence. | 299 | 21 | 2 |

### Privilege Escalation (TA0004) — 6

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1053.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1053.005) Scheduled Task | Magic Hound has used scheduled tasks to establish persistence and execution. | 248 | 14 | 11 |
| [T1078.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.001) Default Accounts | Magic Hound enabled and used the default system managed account, DefaultAccount, via `"powershell.exe" /c net user DefaultAccount /active:yes` to connect to a targeted Exchange server over RDP. | 16 | 3 | — |
| [T1078.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.002) Domain Accounts | Magic Hound has used domain administrator accounts after dumping LSASS process memory. | 36 | — | 1 |
| [T1098.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1098.002) Additional Email Delegate Permissions | Magic Hound granted compromised email accounts read access to the email boxes of additional targeted accounts. The group then was able to authenticate to the intended victim's OWA (Outlook Web Access) portal and read hundreds of email communications for inform… | 10 | 1 | — |
| [T1098.007](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1098.007) Additional Local or Domain Groups | Magic Hound has added a user named DefaultAccount to the Administrators and Remote Desktop Users groups. | 10 | — | — |
| [T1547.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1547.001) Registry Run Keys / Startup Folder | Magic Hound malware has used Registry Run keys to establish persistence. | 299 | 21 | 2 |

### Stealth (TA0005) — 11

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1027.010](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1027.010) Command Obfuscation | Magic Hound has used base64-encoded commands. | 78 | — | — |
| [T1027.013](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1027.013) Encrypted/Encoded File | Magic Hound malware has used base64-encoded files and has also encrypted embedded strings with AES. | 8 | 4 | — |
| [T1036.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1036.004) Masquerade Task or Service | Magic Hound has named a malicious script CacheTask.bat to mimic a legitimate task. | 31 | 4 | — |
| [T1036.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1036.005) Match Legitimate Resource Name or Location | Magic Hound has used `dllhost.exe` to mask Fast Reverse Proxy (FRP) and `MicrosoftOutLookUpdater.exe` for Plink. | 116 | 4 | — |
| [T1036.010](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1036.010) Masquerade Account Name | Magic Hound has created local accounts named `help` and `DefaultAccount` on compromised machines. | 1 | — | — |
| [T1070.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1070.003) Clear Command History | Magic Hound has removed mailbox export requests from compromised Exchange servers. | 63 | 14 | — |
| [T1070.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1070.004) File Deletion | Magic Hound has deleted and overwrote files to cover tracks. | 132 | 11 | — |
| [T1078.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.001) Default Accounts | Magic Hound enabled and used the default system managed account, DefaultAccount, via `"powershell.exe" /c net user DefaultAccount /active:yes` to connect to a targeted Exchange server over RDP. | 16 | 3 | — |
| [T1078.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.002) Domain Accounts | Magic Hound has used domain administrator accounts after dumping LSASS process memory. | 36 | — | 1 |
| [T1218.011](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1218.011) Rundll32 | Magic Hound has used rundll32.exe to execute MiniDump from comsvcs.dll when dumping LSASS memory. | 274 | 16 | 12 |
| [T1564.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1564.003) Hidden Window | Magic Hound malware has a function to determine whether the C2 server wishes to execute the newly dropped file in a hidden window. | 51 | 3 | — |

### Defense Impairment (TA0112) — 4

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1112](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1112) Modify Registry | Magic Hound has modified Registry settings for security tools. | 601 | 92 | 3 |
| [T1685](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1685) Disable or Modify Tools | Magic Hound has disabled antivirus services on targeted systems in order to upload malicious payloads. | 1275 | 78 | 19 |
| [T1685.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1685.001) Disable or Modify Windows Event Log | Magic Hound has executed scripts to disable the event log service. | 138 | 10 | 13 |
| [T1686.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1686.003) Windows Host Firewall | Magic Hound has added the following rule to a victim's Windows firewall to allow RDP traffic - `"netsh" advfirewall firewall add rule name="Terminal Server" dir=in action=allow protocol=TCP localport=3389`. | 64 | 2 | — |

### Credential Access (TA0006) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1003.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1003.001) LSASS Memory | Magic Hound has stolen domain credentials by dumping LSASS process memory using Task Manager, comsvcs.dll, and from a Microsoft Active Directory Domain Controller using Mimikatz. | 580 | 14 | 10 |
| [T1056.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1056.001) Keylogging | Magic Hound malware is capable of keylogging. | 40 | 8 | 1 |

### Discovery (TA0007) — 12

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1016](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1016) System Network Configuration Discovery | Magic Hound malware gathers the victim's local IP address, MAC address, and external IP address. | 99 | 10 | 5 |
| [T1016.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1016.001) Internet Connection Discovery | Magic Hound has conducted a network call out to a specific website as part of their initial discovery activity. | 14 | 5 | — |
| [T1016.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1016.002) Wi-Fi Discovery | Magic Hound has collected names and passwords of all Wi-Fi networks to which a device has previously connected. | 1 | 1 | — |
| [T1018](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1018) Remote System Discovery | Magic Hound has used Ping for discovery on targeted networks. | 157 | 23 | 1 |
| [T1033](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1033) System Owner/User Discovery | Magic Hound malware has obtained the victim username and sent it to the C2 server. | 181 | 8 | — |
| [T1046](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1046) Network Service Discovery | Magic Hound has used KPortScan 3.0 to perform SMB, RDP, and LDAP scanning. | 212 | 13 | 2 |
| [T1049](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1049) System Network Connections Discovery | Magic Hound has used quser.exe to identify existing RDP connections. | 47 | 7 | — |
| [T1057](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1057) Process Discovery | Magic Hound malware can list running processes. | 82 | 10 | — |
| [T1082](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1082) System Information Discovery | Magic Hound malware has used a PowerShell command to check the victim system architecture to determine if it is an x64 machine. Other malware has obtained the OS version, UUID, and computer/host name to send to the C2 server. | 264 | 41 | — |
| [T1083](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1083) File and Directory Discovery | Magic Hound malware can list a victim's logical drives and the type, as well the total/free space of the fixed devices. Other malware can list a directory's contents. | 137 | 9 | — |
| [T1087.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1087.003) Email Account | Magic Hound has used Powershell to discover email accounts. | 1 | — | — |
| [T1482](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1482) Domain Trust Discovery | Magic Hound has used a web shell to execute `nltest /trusted_domains` to identify trust relationships. | 158 | 8 | 1 |

### Lateral Movement (TA0008) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1021.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1021.001) Remote Desktop Protocol | Magic Hound has used Remote Desktop Services to copy tools on targeted systems. | 139 | 4 | 7 |
| [T1570](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1570) Lateral Tool Transfer | Magic Hound has copied tools within a compromised network using RDP. | 58 | 2 | — |

### Collection (TA0009) — 7

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1005) Data from Local System | Magic Hound has used a web shell to exfiltrate a ZIP file containing a dump of LSASS memory on a compromised machine. | 170 | 3 | — |
| [T1056.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1056.001) Keylogging | Magic Hound malware is capable of keylogging. | 40 | 8 | 1 |
| [T1113](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1113) Screen Capture | Magic Hound malware can take a screenshot and upload the file to its C2 server. | 60 | 10 | — |
| [T1114](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1114) Email Collection | Magic Hound has compromised email credentials in order to steal sensitive data. | 119 | — | — |
| [T1114.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1114.001) Local Email Collection | Magic Hound has collected .PST archives. | 15 | 1 | — |
| [T1114.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1114.002) Remote Email Collection | Magic Hound has exported emails from compromised Exchange servers including through use of the cmdlet `New-MailboxExportRequest.` | 11 | 1 | — |
| [T1560.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1560.001) Archive via Utility | Magic Hound has used gzip to archive dumped LSASS process memory and RAR to stage and compress local folders. | 76 | 13 | — |

### Command and Control (TA0011) — 8

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1071](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1071) Application Layer Protocol | Magic Hound malware has used IRC for C2. | 511 | 1 | — |
| [T1071.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1071.001) Web Protocols | Magic Hound has used HTTP for C2. | 228 | 3 | — |
| [T1090](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1090) Proxy | Magic Hound has used Fast Reverse Proxy (FRP) for RDP traffic. | 162 | — | 1 |
| [T1102.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1102.002) Bidirectional Communication | Magic Hound malware can use a SOAP Web service to communicate with its C2 server. | 27 | — | — |
| [T1105](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1105) Ingress Tool Transfer | Magic Hound has downloaded additional code and files from servers onto victims. | 644 | 39 | — |
| [T1571](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1571) Non-Standard Port | Magic Hound malware has communicated with its C2 server over TCP ports 4443 and 10151 using HTTP. | 163 | 2 | — |
| [T1572](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1572) Protocol Tunneling | Magic Hound has used Plink to tunnel RDP over SSH. | 173 | 9 | 1 |
| [T1573](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1573) Encrypted Channel | Magic Hound has used an encrypted http proxy in C2 communications. | 33 | 1 | — |

### Exfiltration (TA0010) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1567](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1567) Exfiltration Over Web Service | Magic Hound has used the Telegram API `sendMessage` to relay data on compromised devices. | 162 | — | — |

### Impact (TA0040) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1486](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1486) Data Encrypted for Impact | Magic Hound has used BitLocker and DiskCryptor to encrypt targeted workstations. | 160 | 10 | 1 |

## 4. Assinatura comportamental

Técnicas que este grupo usa e que poucos dos 178 grupos do ATT&CK usam. Pesam mais numa atribuição por TTP: ver várias delas juntas é mais informativo do que ver técnicas comuns como PowerShell.

| Técnica | Outros grupos que usam | Peso (raridade) |
|---|---:|---:|
| T1016.002 Wi-Fi Discovery | 0 | 4.49 |
| T1591.001 Determine Physical Locations | 0 | 4.49 |
| T1685.001 Disable or Modify Windows Event Log | 1 | 4.09 |
| T1098.002 Additional Email Delegate Permissions | 2 | 3.80 |
| T1590.005 IP Addresses | 2 | 3.80 |
| T1592.002 Software | 2 | 3.80 |
| T1036.010 Masquerade Account Name | 3 | 3.58 |
| T1078.001 Default Accounts | 3 | 3.58 |
| T1087.003 Email Account | 3 | 3.58 |
| T1114 Email Collection | 3 | 3.58 |

## 5. Arsenal

| Software | Tipo | Técnicas no ATT&CK | Uso relatado (EN) |
|---|---|---:|---|
| [Pupy](https://attack.mitre.org/software/S0192/) | ferramenta | 41 |  |
| [CharmPower](https://attack.mitre.org/software/S0674/) | malware | 24 |  |
| [Mimikatz](https://attack.mitre.org/software/S0002/) | ferramenta | 17 |  |
| [Net](https://attack.mitre.org/software/S0039/) | ferramenta | 16 |  |
| [Impacket](https://attack.mitre.org/software/S0357/) | ferramenta | 11 |  |
| [FRP](https://attack.mitre.org/software/S1144/) | ferramenta | 10 |  |
| [PowerLess](https://attack.mitre.org/software/S1012/) | malware | 9 |  |
| [DownPaper](https://attack.mitre.org/software/S0186/) | malware | 7 |  |
| [PsExec](https://attack.mitre.org/software/S0029/) | ferramenta | 5 |  |
| [netsh](https://attack.mitre.org/software/S0108/) | ferramenta | 4 |  |
| [ipconfig](https://attack.mitre.org/software/S0100/) | ferramenta | 1 |  |
| [Systeminfo](https://attack.mitre.org/software/S0096/) | ferramenta | 1 |  |
| [Ping](https://attack.mitre.org/software/S0097/) | ferramenta | 1 |  |

## 6. Campanhas

Nenhuma campanha atribuída no ATT&CK.

## 7. Cobertura defensiva

**75 de 78 técnicas (96%)** têm ao menos uma regra pública no catálogo Detection Rules.

### Técnicas sem regra pública (prioridade para engenharia de detecção)

- **T1591.001 Determine Physical Locations** — Reconnaissance
- **T1598.003 Spearphishing Link** — Reconnaissance. Fonte de log sugerida pelo MITRE: `Application Log` None
- **T1585.002 Email Accounts** — Resource Development

### Regras recomendadas por técnica

Melhor regra disponível por técnica (formato portável e maduro primeiro).

| Técnica | Regra | Formato | Fonte |
|---|---|---|---|
| T1003.001 | [Antivirus - Password Dumper Signature](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A78cc2dd2-7d20-4d32-93ff-057084c38b93) | Sigma | SigmaHQ |
| T1003.001 | [Mimikatz through Windows Remote Management](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Aaa35a627-33fb-4d04-a165-d33b4afca3e8) | Sigma | OpenSearch Security Analytics |
| T1005 | [Potential Conti Ransomware Database Dumping Activity Via SQLCmd](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A2f47f1fd-0901-466e-a770-3b7092834a1b) | Sigma | SigmaHQ |
| T1005 | [OpenCanary - SMB File Open Request](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A22777c9e-873a-4b49-855f-6072ab861a52) | Sigma | SigmaHQ |
| T1016 | [Potential Pikabot Discovery Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A698d4431-514f-4c82-af4d-cf573872a9f5) | Sigma | SigmaHQ |
| T1016 | [OpenCanary - SNMP OID Request](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae9856028-fd4e-46e6-b3d1-10f7ceb95078) | Sigma | SigmaHQ |
| T1016.001 | [System Public IP Discovery via DNS Query](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A642ce354-4252-4d43-80c9-6603f16571c1) | Elastic | Elastic detection-rules |
| T1016.001 | [Suspicious PDF Reader Child Process](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A53a26770-9cbd-40c5-8b57-61d01a325e14) | Elastic | Elastic detection-rules |
| T1016.002 | [Sysmon - Event 1: Process creation $(win.eventdata.description)](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=socfortress-wazuh-rules%3A%3Awazuh-100829) | Wazuh | SOCFortress Wazuh-Rules |
| T1018 | [Chopper Webshell Process Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Afa3c117a-bc0d-416e-a31b-0c0e80653efb) | Sigma | SigmaHQ |
| T1018 | [Webshell Hacking Activity Patterns](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4ebc877f-4612-45cb-b3a5-8e3834db36c9) | Sigma | SigmaHQ |
| T1021.001 | [Hermetic Wiper TG Process Patterns](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A2f974656-6d83-4059-bbdf-68ac5403422f) | Sigma | SigmaHQ |
| T1021.001 | [Publicly Accessible RDP Service](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1fc0809e-06bf-4de3-ad52-25e5263b7623) | Sigma | SigmaHQ |
| T1027.010 | [Decoded Payload Piped to Interpreter Detected via Defend for Containers](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A0fb83aa0-3d17-41e9-b09c-56397bf7a7d9) | Elastic | Elastic detection-rules |
| T1027.010 | [Potential PowerShell Obfuscation via String Concatenation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Af6d8c743-0916-4483-8333-3c6f107e0caa) | Elastic | Elastic detection-rules |
| T1027.013 | [ROT Encoded Python Script Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A5ab49127-b1b3-46e6-8a38-9e8512a2a363) | Elastic | Elastic detection-rules |
| T1027.013 | [Data Encrypted via OpenSSL Utility](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Afeba48f6-40ca-4d04-b41f-5dfa327de865) | Elastic | Elastic detection-rules |
| T1033 | [Potential Dridex Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae6eb5a96-9e6f-4a18-9cdd-642cfda21c8e) | Sigma | SigmaHQ |
| T1033 | [Dridex Process Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Ae6eb5a96-9e6f-4a18-9cdd-642cfda21c8e) | Sigma | OpenSearch Security Analytics |
| T1036.004 | [Operation Wocao Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1cfac73c-be78-4f9a-9b08-5bde0c3953ab) | Sigma | SigmaHQ |
| T1036.004 | [Operation Wocao Activity - Security](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A74ad4314-482e-4c3e-b237-3f7ed3b9ca8d) | Sigma | SigmaHQ |
| T1036.005 | [Exploit for CVE-2015-1641](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A7993792c-5ce2-4475-a3db-a3a5539827ef) | Sigma | SigmaHQ |
| T1036.005 | [Exploit for CVE-2015-1641](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A7993792c-5ce2-4475-a3db-a3a5539827ef) | Sigma | OpenSearch Security Analytics |
| T1036.010 | [Windows Builtin Account Name Was Changed](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=splunk-security-content%3A%3A65e6e8b9-c68c-460f-beb8-48cfe91b4d21) | Splunk | Splunk security_content |
| T1046 | [HackTool - winPEAS Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A98b53e78-ebaf-46f8-be06-421aafd176d9) | Sigma | SigmaHQ |
| T1046 | [HackTool - WinPwn Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad557dc06-62e8-4468-a8e8-7984124908ce) | Sigma | SigmaHQ |
| T1047 | [HackTool - Potential Impacket Lateral Movement Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A10c14723-61c7-4c75-92ca-9af245723ad2) | Sigma | SigmaHQ |
| T1047 | [CrackMapExec Command Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A058f4380-962d-40a5-afce-50207d36d7e2) | Sigma | OpenSearch Security Analytics |
| T1049 | [Potential Pikabot Discovery Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A698d4431-514f-4c82-af4d-cf573872a9f5) | Sigma | SigmaHQ |
| T1049 | [HackTool - SharpView Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab2317cfa-4a47-4ead-b3ff-297438c0bc2d) | Sigma | SigmaHQ |
| T1053.005 | [Operation Wocao Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1cfac73c-be78-4f9a-9b08-5bde0c3953ab) | Sigma | SigmaHQ |
| T1053.005 | [Operation Wocao Activity - Security](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A74ad4314-482e-4c3e-b237-3f7ed3b9ca8d) | Sigma | SigmaHQ |
| T1056.001 | [Linux Keylogging with Pam.d](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A49aae26c-450e-448b-911d-b3c13d178dfc) | Sigma | SigmaHQ |
| T1056.001 | [Linux Keylogging with Pam.d](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A49aae26c-450e-448b-911d-b3c13d178dfc) | Sigma | OpenSearch Security Analytics |
| T1057 | [Process Discovery](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4e2f5868-08d4-413d-899f-dc2f1508627b) | Sigma | SigmaHQ |
| T1057 | [HackTool - PCHunter Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Afca949cc-79ca-446e-8064-01aa7e52ece5) | Sigma | SigmaHQ |
| T1059.001 | [Potential Emotet Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad02e8cf5-6099-48cf-9bfc-1eec2d0c7b18) | Sigma | SigmaHQ |
| T1059.001 | [TropicTrooper Campaign November 2018](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A8c7090c3-e0a0-4944-bd08-08c3a0cecf79) | Sigma | SigmaHQ |
| T1059.003 | [HackTool - CrackMapExec Execution Patterns](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A058f4380-962d-40a5-afce-50207d36d7e2) | Sigma | SigmaHQ |
| T1059.003 | [CrackMapExec Command Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A058f4380-962d-40a5-afce-50207d36d7e2) | Sigma | OpenSearch Security Analytics |
| T1059.005 | [Potential QBot Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4fcac6eb-0287-4090-8eea-2602e4c20040) | Sigma | SigmaHQ |
| T1059.005 | [QBot Process Creation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A4fcac6eb-0287-4090-8eea-2602e4c20040) | Sigma | OpenSearch Security Analytics |
| T1070.003 | [Cisco Clear Logs](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aceb407f6-8277-439b-951f-e4210e3ed956) | Sigma | SigmaHQ |
| T1070.003 | [Linux Command History Tampering](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Afdc88d25-96fb-4b7c-9633-c0e417fdbd4e) | Sigma | SigmaHQ |
| T1070.004 | [File Deletion](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A30aed7b6-d2c1-4eaf-9382-b6bc43e50c57) | Sigma | SigmaHQ |
| T1070.004 | [Prefetch File Deleted](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A0a1f9d29-6465-4776-b091-7f43b26e4c89) | Sigma | SigmaHQ |
| T1071 | [GALLIUM IOCs](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A440a56bf-7873-4439-940a-1c8a671073c2) | Sigma | SigmaHQ |
| T1071 | [GALLIUM Artefacts - Builtin](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A3db10f25-2527-4b79-8d4b-471eb900ee29) | Sigma | SigmaHQ |
| T1071.001 | [Ursnif Malware Download URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aa36ce77e-30db-4ea0-8795-644d7af5dfb4) | Sigma | SigmaHQ |
| T1071.001 | [Ursnif Malware C2 URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A932ac737-33ca-4afd-9869-0d48b391fcc9) | Sigma | SigmaHQ |
| T1078.001 | [Admin User Remote Logon](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A0f63e1ef-1eb9-4226-9d54-8927ca08520a) | Sigma | SigmaHQ |
| T1078.001 | [Guest Account Enabled Via Sysadminctl](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad7329412-13bd-44ba-a072-3387f804a106) | Sigma | SigmaHQ |
| T1078.002 | [Malicious Usage Of IMDS Credentials Outside Of AWS Infrastructure](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A352a918a-34d8-4882-8470-44830c507aa3) | Sigma | SigmaHQ |
| T1078.002 | [AdminSDHolder SDProp Exclusion Added](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A61d29caf-6c15-4d1e-9ccb-7ad12ccc0bc7) | Elastic | Elastic detection-rules |
| T1082 | [Potential GobRAT File Discovery Via Grep](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae34cfa0c-0a50-4210-9cb3-5632d08eb041) | Sigma | SigmaHQ |
| T1082 | [System Information Discovery](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A42df45e7-e6e9-43b5-8f26-bec5b39cc239) | Sigma | SigmaHQ |
| T1083 | [Turla Group Lateral Movement](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac601f20d-570a-4cde-a7d6-e17f99cb8e7f) | Sigma | SigmaHQ |
| T1083 | [WannaCry Ransomware Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A41d40bff-377a-43e2-8e1b-2e543069e079) | Sigma | SigmaHQ |
| T1087.003 | [AWSCloudTrail - IAM AccessDenied discovery events](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-hunting-queries%3A%3A7e258a45-b356-44f6-9a62-2643cef7b869) | Sentinel KQL | Microsoft Sentinel (Hunting Queries) |
| T1090 | [Communication To LocaltoNet Tunneling Service Initiated - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac4568f5d-131f-4e78-83d4-45b2da0ec4f1) | Sigma | SigmaHQ |
| T1090 | [Communication To Ngrok Tunneling Service - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A19bf6fdb-7721-4f3d-867f-53467f6a5db6) | Sigma | SigmaHQ |
| T1098.002 | [M365 Exchange Mailbox High-Risk Permission Delegated](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A0ce6487d-8069-4888-9ddd-61b52490cebc) | Elastic | Elastic detection-rules |
| T1098.002 | [New ActiveSyncAllowedDeviceID Added via PowerShell](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ace64d965-6cb0-466d-b74f-8d2c76f47f05) | Elastic | Elastic detection-rules |
| T1098.007 | [User or Group Creation/Modification](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Afcf733d5-7801-4eb0-92ac-8ffacf3658f2) | Elastic | Elastic detection-rules |
| T1098.007 | [Linux User Added to Privileged Group](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A43d6ec12-2b1c-47b5-8f35-e9de65551d3b) | Elastic | Elastic detection-rules |
| T1102.002 | [Potential Etherhiding C2 via Blockchain Connection](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Abba8c7d1-172b-435d-9034-02ed9289c628) | Elastic | Elastic detection-rules |
| T1102.002 | [Google Calendar C2 via Script Interpreter](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Aabc7a2be-479e-428b-b0b3-1d22bda46dd9) | Elastic | Elastic detection-rules |
| T1105 | [Greenbug Espionage Group Indicators](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A3711eee4-a808-4849-8a14-faf733da3612) | Sigma | SigmaHQ |
| T1105 | [Pandemic Registry Key](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A47e0852a-cf81-4494-a8e6-31864f8c86ed) | Sigma | SigmaHQ |
| T1112 | [ShimCache Flush](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab0524451-19af-4efa-a46f-562a977f792e) | Sigma | SigmaHQ |
| T1112 | [ShimCache Flush](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Ab0524451-19af-4efa-a46f-562a977f792e) | Sigma | OpenSearch Security Analytics |
| T1113 | [PowerShell Suspicious Script with Screenshot Capabilities](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A959a7353-1129-4aa7-9084-30746b256a70) | Elastic | Elastic detection-rules |
| T1113 | [Potential Remote Desktop Shadowing Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ac57f8579-e2a5-4804-847f-f2732edc5156) | Elastic | Elastic detection-rules |
| T1114 | [Exchange PowerShell Snap-Ins Usage](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A25676e10-2121-446e-80a4-71ff8506af47) | Sigma | SigmaHQ |
| T1114 | [Hacktool Ruler](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A24549159-ac1b-479c-8175-d42aea947cae) | Sigma | SigmaHQ |
| T1114.001 | [Powershell Local Email Collection](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A2837e152-93c8-43d2-85ba-c3cd3c2ae614) | Sigma | SigmaHQ |
| T1114.001 | [Exporting Exchange Mailbox via PowerShell](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A6aace640-e631-4870-ba8e-5fdda09325db) | Elastic | Elastic detection-rules |
| T1114.002 | [Microsoft Graph Email Access by Unusual User and Client](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ae882e934-2aaa-11f0-8272-f661ea17fbcc) | Elastic | Elastic detection-rules |
| T1114.002 | [M365 Exchange Mailbox Accessed by Unusual Client](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A48819484-9826-4083-9eba-1da74cd0eaf2) | Elastic | Elastic detection-rules |
| T1136.001 | [DarkGate - User Created Via Net.EXE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Abf906d7b-7070-4642-8383-e404cf26eba5) | Sigma | SigmaHQ |
| T1136.001 | [Serv-U Exploitation CVE-2021-35211 by DEV-0322](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A75578840-9526-4b2a-9462-af469a45e767) | Sigma | SigmaHQ |
| T1189 | [Flash Player Update from Suspicious Location](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4922a5dd-6743-4fc2-8e81-144374280997) | Sigma | SigmaHQ |
| T1189 | [Cross Site Scripting Strings](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A65354b83-a2ea-4ea6-8414-3ab38be0d409) | Sigma | SigmaHQ |
| T1190 | [OMIGOD HTTP No Authentication RCE - CVE-2021-38647](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aab6b1a39-a9ee-4ab4-b075-e83acf6e346b) | Sigma | SigmaHQ |
| T1190 | [Exploited CVE-2020-10189 Zoho ManageEngine](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A846b866e-2a57-46ee-8e16-85fa92759be7) | Sigma | OpenSearch Security Analytics |
| T1204.001 | [Google Workspace Object Copied from External Drive with App Consent](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Af33e68a4-bd19-11ed-b02f-f661ea17fbcc) | Elastic | Elastic detection-rules |
| T1204.001 | [Suspicious ClickFix/FileFix Execution Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad487ed4a-fd24-436d-a0b2-f4e95f7b2635) | Sigma | SigmaHQ |
| T1204.002 | [Ursnif Malware C2 URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A932ac737-33ca-4afd-9869-0d48b391fcc9) | Sigma | SigmaHQ |
| T1204.002 | [Droppers Exploiting CVE-2017-11882](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A678eb5f4-8597-4be6-8be7-905e4234b53a) | Sigma | SigmaHQ |
| T1218.011 | [Equation Group DLL_U Export Function Load](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad465d1d8-27a2-4cca-9621-a800f37cf72e) | Sigma | SigmaHQ |
| T1218.011 | [APT29 2018 Phishing Campaign File Indicators](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A3a3f81ca-652c-482b-adeb-b1c804727f74) | Sigma | SigmaHQ |
| T1482 | [BloodHound Collection Files](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A02773bed-83bf-469f-b7ff-e676e7d78bab) | Sigma | SigmaHQ |
| T1482 | [HackTool - TruffleSnout Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A69ca006d-b9a9-47f5-80ff-ecd4d25d481a) | Sigma | SigmaHQ |
| T1486 | [LockerGoga Ransomware Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A74db3488-fd28-480a-95aa-b7af626de068) | Sigma | SigmaHQ |
| T1486 | [LockerGoga Ransomware](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A74db3488-fd28-480a-95aa-b7af626de068) | Sigma | OpenSearch Security Analytics |
| T1505.003 | [MOVEit CVE-2023-34362 Exploitation Attempt - Potential Web Shell Request](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A435e41f2-48eb-4c95-8a2b-ed24b50ec30b) | Sigma | SigmaHQ |
| T1505.003 | [Solarwinds SUPERNOVA Webshell Access](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aa2cee20b-eacc-459f-861d-c02e5d12f1db) | Sigma | SigmaHQ |
| T1547.001 | [Potential Ryuk Ransomware Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac37510b8-2107-4b78-aa32-72f251e7a844) | Sigma | SigmaHQ |
| T1547.001 | [Ryuk Ransomware](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Ac37510b8-2107-4b78-aa32-72f251e7a844) | Sigma | OpenSearch Security Analytics |
| T1560.001 | [APT31 Judgement Panda Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A03e2746e-2b31-42f1-ab7a-eb39365b2422) | Sigma | SigmaHQ |
| T1560.001 | [Suspicious Manipulation Of Default Accounts Via Net.EXE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A5b768e71-86f2-4879-b448-81061cbae951) | Sigma | SigmaHQ |
| T1564.003 | [Potential Data Stealing Via Chromium Headless Debugging](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A3e8207c5-fcd2-4ea6-9418-15d45b4890e4) | Sigma | SigmaHQ |
| T1564.003 | [HackTool - Covenant PowerShell Launcher](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac260b6db-48ba-4b4a-a76f-2f67644e99d2) | Sigma | SigmaHQ |
| T1566.002 | [Potential Malicious Usage of CloudTrail System Manager](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A38e7f511-3f74-41d4-836e-f57dfa18eead) | Sigma | SigmaHQ |
| T1566.002 | [Google Workspace Device Registration After OAuth from Suspicious ASN](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A012bfca7-45cb-4507-a3ba-3777167f8b81) | Elastic | Elastic detection-rules |
| T1566.003 | [M365 Teams Rogue Help Desk Chat Created](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ae8e7b6b6-78b0-4015-97fe-c2f28468e0d4) | Elastic | Elastic detection-rules |
| T1566.003 | [M365 Azure Monitor Alert Email with Financial or Billing Theme](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Aa6129187-c47b-48ab-a412-67a44836d918) | Elastic | Elastic detection-rules |
| T1567 | [Monero Crypto Coin Mining Pool Lookup](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab593fd50-7335-4682-a36c-4edcb68e4641) | Sigma | SigmaHQ |
| T1567 | [Monero Crypto Coin Mining Pool Lookup](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Ab593fd50-7335-4682-a36c-4edcb68e4641) | Sigma | OpenSearch Security Analytics |
| T1570 | [PSExec Lateral Movement](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=hayabusa-native%3A%3A0694c340-3a46-40ac-acfc-c3444ae6572c) | Sigma | Hayabusa (native) |
| T1570 | [PSEXEC Remote Execution File Artefact](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A304afd73-55a5-4bb9-8c21-0b1fc84ea9e4) | Sigma | SigmaHQ |
| T1571 | [Potentially Suspicious Malware Callback Communication - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Adbfc7c98-04ab-4ab7-aa94-c74d22aa7376) | Sigma | SigmaHQ |
| T1571 | [Potentially Suspicious Malware Callback Communication](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4b89abaa-99fe-4232-afdd-8f9aa4d20382) | Sigma | SigmaHQ |
| T1572 | [Communication To LocaltoNet Tunneling Service Initiated - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac4568f5d-131f-4e78-83d4-45b2da0ec4f1) | Sigma | SigmaHQ |
| T1572 | [Communication To Ngrok Tunneling Service - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A19bf6fdb-7721-4f3d-867f-53467f6a5db6) | Sigma | SigmaHQ |
| T1573 | [Potential Pikabot C2 Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acae6cee6-0244-44d2-84ed-e65f548eb7dc) | Sigma | SigmaHQ |
| T1573 | [Default Cobalt Strike Team Server Certificate](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ae7075e8d-a966-458e-a183-85cd331af255) | Elastic | Elastic detection-rules |
| T1583.001 | [AWS Route 53 Private Hosted Zone Associated With a VPC](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ae3c27562-709a-42bd-82f2-3ed926cced19) | Elastic | Elastic detection-rules |
| T1583.001 | [AWS SES Email Identity Verified Then Deleted](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A8e4bde35-125d-4eb3-9a2e-d7e77a053a08) | Elastic | Elastic detection-rules |
| T1583.006 | [GitHub Repo Created](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A6cea88e4-6ce2-4238-9981-a54c140d6336) | Elastic | Elastic detection-rules |
| T1583.006 | [Cisco Secure Firewall - Rare Snort Rule Triggered](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=splunk-security-content%3A%3Ae20313d2-7d63-4fcf-b2d9-d6e12c6c7bd7) | Splunk | Splunk security_content |
| T1584.001 | [AWS Route 53 Domain Transferred to Another Account](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A2045567e-b0af-444a-8c0b-0b6e2dae9e13) | Elastic | Elastic detection-rules |
| T1584.001 | [AWS Route 53 Domain Transfer Lock Disabled](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A12051077-0124-4394-9522-8f4f4db1d674) | Elastic | Elastic detection-rules |
| T1585.001 | [CYFIRMA - Brand Intelligence - Social Media Handle Impersonation Detected High Rule](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A22f49d67-7da7-4809-8d07-89e4478aa6b0) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1585.001 | [CYFIRMA - Brand Intelligence - Executive/People Impersonation High Rule](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A159d26a1-591c-4f70-b1ca-2843c881aaec) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1586.002 | [CYFIRMA - Brand Intelligence - Domain Impersonation High Rule](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A10bdf525-5b89-4a25-933a-e63e73b915f1) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1586.002 | [CYFIRMA - Brand Intelligence - Domain Impersonation Medium Rule](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A8f97ddbe-ab66-4f6c-b675-73b5eeb07259) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1588.002 | [Hacktool Execution - Imphash](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A24e3e58a-646b-4b50-adef-02ef935b9fc8) | Sigma | SigmaHQ |
| T1588.002 | [Renamed SysInternals DebugView Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acd764533-2e07-40d6-a718-cfeec7f2da7f) | Sigma | SigmaHQ |
| T1589 | [SSHD Error Message CVE-2018-15473](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4c9d903d-4939-4094-ade0-3cb748f4d7da) | Sigma | SigmaHQ |
| T1589 | [SSHD Error Message CVE-2018-15473](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A4c9d903d-4939-4094-ade0-3cb748f4d7da) | Sigma | OpenSearch Security Analytics |
| T1589.001 | [Linux Medusa Rootkit](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=splunk-security-content%3A%3A7add8520-71d5-43aa-b262-ee082b1f0238) | Splunk | Splunk security_content |
| T1589.001 | [MS Graph message: A user's credentials were compromised or stolen. This is a true positive alert.](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=wazuh-ruleset-oficial%3A%3Awazuh-99612) | Wazuh | Wazuh ruleset (oficial) |
| T1589.002 | [Potential Unconstrained Delegation Discovery Via Get-ADComputer - ScriptBlock](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acdfa73b6-3c9d-4bb8-97f8-ddbd8921f5c5) | Sigma | SigmaHQ |
| T1589.002 | [AWSCloudTrail - Suspicious AWS CLI Command Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A8c2dc344-9352-4ca1-8863-b1b7a5e09e59) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1590.005 | [Cisco ASA - Reconnaissance Command Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=splunk-security-content%3A%3A6e9d4f7a-3c8b-4a9e-8d2f-7b5c9e1a6f3d) | Splunk | Splunk security_content |
| T1592.002 | [Windows WinPEAS PowerShell Script Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=splunk-security-content%3A%3A5cb208df-e1aa-478d-ab2f-8270ff9999b9) | Splunk | Splunk security_content |
| T1592.002 | [Possible IP geolocation lookup with curl (T1592.002)](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=socfortress-wazuh-rules%3A%3Awazuh-700182) | Wazuh | SOCFortress Wazuh-Rules |
| T1595.002 | [DNS Query to External Service Interaction Domains](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aaff715fa-4dd5-497a-8db3-910bea555566) | Sigma | SigmaHQ |
| T1595.002 | [Web Server Potential SQL Injection Request](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A7f7a0ee1-7b6f-466a-85b4-110fb105f5e2) | Elastic | Elastic detection-rules |
| T1685 | [Windows Defender Configuration Changes](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A801bd44f-ceed-4eb6-887c-11544633c0aa) | Sigma | SigmaHQ |
| T1685 | [Windows Defender Virus Scanning Feature Disabled](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A686c0b4b-9dd3-4847-9077-d6c1bbe36fcb) | Sigma | SigmaHQ |
| T1685.001 | [Suspicious Eventlog Clearing or Configuration Change Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acc36992a-4671-4f21-a91d-6c2b72a2edf5) | Sigma | SigmaHQ |
| T1685.001 | [Forest Blizzard APT - File Creation Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab92d1d19-f5c9-4ed6-bbd5-7476709dc389) | Sigma | SigmaHQ |
| T1686.003 | [Suspicious Program Location Whitelisted In Firewall Via Netsh.EXE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aa35f5a72-f347-4e36-8895-9869b0d5fc6d) | Sigma | SigmaHQ |
| T1686.003 | [RDP Connection Allowed Via Netsh.EXE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A01aeb693-138d-49d2-9403-c4f52d7d3d62) | Sigma | SigmaHQ |

## 8. Plano de emulação e validação

Use num laboratório isolado e autorizado para confirmar que as regras disparam. Os comandos estão nos repositórios oficiais.

| Tática | Técnica | Teste Atomic Red Team | Plataformas |
|---|---|---|---|
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
| Execution | [T1204.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1204.002/T1204.002.md) | OSTap Style Macro Execution | windows |
| Execution | [T1204.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1204.002/T1204.002.md) | OSTap Payload Download | windows |
| Persistence | [T1098.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1098.002/T1098.002.md) | EXO - Full access mailbox permission granted to a user | office-365 |
| Persistence | [T1136.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1136.001/T1136.001.md) | Create a user account on a Linux system | linux |
| Persistence | [T1136.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1136.001/T1136.001.md) | Create a user account on a FreeBSD system | linux |
| Persistence | [T1505.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1505.003/T1505.003.md) | Web Shell Written to Disk | windows |
| Persistence | [T1547.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1547.001/T1547.001.md) | Reg Key Run | windows |
| Persistence | [T1547.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1547.001/T1547.001.md) | Reg Key RunOnce | windows |
| Stealth | [T1027.013](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027.013/T1027.013.md) | Decode Eicar File and Write to File | linux, macos, windows |
| Stealth | [T1027.013](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027.013/T1027.013.md) | Decrypt Eicar File and Write to File | linux, macos, windows |
| Stealth | [T1036.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.004/T1036.004.md) | Creating W32Time similar named service using schtasks | windows |
| Stealth | [T1036.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.004/T1036.004.md) | Creating W32Time similar named service using sc | windows |
| Stealth | [T1036.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.005/T1036.005.md) | Execute a process from a directory masquerading as the current parent directory | linux, macos |
| Stealth | [T1036.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.005/T1036.005.md) | Masquerade as a built-in system executable | windows |
| Stealth | [T1070.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.003/T1070.003.md) | Clear Bash history (rm) |  |
| Stealth | [T1070.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.003/T1070.003.md) | Clear Bash history (echo) |  |
| Stealth | [T1070.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.004/T1070.004.md) | Delete a single file - FreeBSD/Linux/macOS | linux, macos |
| Stealth | [T1070.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.004/T1070.004.md) | Delete an entire folder - FreeBSD/Linux/macOS | linux, macos |
| Stealth | [T1078.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1078.001/T1078.001.md) | Enable Guest account with RDP capability and admin privileges | windows |
| Stealth | [T1078.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1078.001/T1078.001.md) | Activate Guest Account | windows |
| Stealth | [T1218.011](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.011/T1218.011.md) | Rundll32 execute JavaScript Remote Payload With GetObject | windows |
| Stealth | [T1218.011](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.011/T1218.011.md) | Rundll32 execute VBscript command | windows |
| Stealth | [T1564.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1564.003/T1564.003.md) | Hidden Window | windows |
| Stealth | [T1564.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1564.003/T1564.003.md) | Headless Browser Accessing Mockbin | windows |
| Defense Impairment | [T1112](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1112/T1112.md) | Modify Registry of Current User Profile - cmd | windows |
| Defense Impairment | [T1112](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1112/T1112.md) | Modify Registry of Local Machine - cmd | windows |
| Defense Impairment | [T1685](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1685/T1685.md) | Windows Disable LSA Protection | windows |
| Defense Impairment | [T1685](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1685/T1685.md) | Disable journal logging via systemctl utility | linux |
| Defense Impairment | [T1685.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1685.001/T1685.001.md) | Disable Windows IIS HTTP Logging | windows |
| Defense Impairment | [T1685.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1685.001/T1685.001.md) | Disable Windows IIS HTTP Logging via PowerShell | windows |
| Defense Impairment | [T1686.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1686.003/T1686.003.md) | Enable Firewall Rule Group via COM Object (HNetCfg.FwPolicy2) | windows |
| Defense Impairment | [T1686.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1686.003/T1686.003.md) | Set All Network Profiles to Private via Registry | windows |
| Credential Access | [T1003.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/T1003.001.md) | Dump LSASS.exe Memory using ProcDump | windows |
| Credential Access | [T1003.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/T1003.001.md) | Dump LSASS.exe Memory using comsvcs.dll | windows |
| Discovery | [T1016](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1016/T1016.md) | System Network Configuration Discovery on Windows | windows |
| Discovery | [T1016](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1016/T1016.md) | List Windows Firewall Rules | windows |
| Discovery | [T1016.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1016.001/T1016.001.md) | Check internet connection using ping Windows | windows |
| Discovery | [T1016.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1016.001/T1016.001.md) | Check internet connection using ping freebsd, linux or macos | linux, macos |
| Discovery | [T1016.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1016.002/T1016.002.md) | Enumerate Stored Wi-Fi Profiles And Passwords via netsh | windows |
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
| Discovery | [T1082](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1082/T1082.md) | System Information Discovery | windows |
| Discovery | [T1082](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1082/T1082.md) | System Information Discovery | macos |
| Discovery | [T1083](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1083/T1083.md) | File and Directory Discovery (cmd.exe) | windows |
| Discovery | [T1083](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1083/T1083.md) | File and Directory Discovery (PowerShell) | windows |
| Discovery | [T1482](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1482/T1482.md) | Windows - Discover domain trusts with dsquery | windows |
| Discovery | [T1482](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1482/T1482.md) | Windows - Discover domain trusts with nltest | windows |
| Lateral Movement | [T1021.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.001/T1021.001.md) | RDP to Remote Host | windows |
| Lateral Movement | [T1021.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.001/T1021.001.md) | Changing RDP Port to Non Standard Port via Powershell | windows |
| Lateral Movement | [T1570](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1570/T1570.md) | Exfiltration Over SMB over QUIC (New-SmbMapping) | windows |
| Lateral Movement | [T1570](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1570/T1570.md) | Exfiltration Over SMB over QUIC (NET USE) | windows |
| Collection | [T1005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1005/T1005.md) | Search files of interest and save them to a single zip file (Windows) | windows |
| Collection | [T1005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1005/T1005.md) | Find and dump sqlite databases (Linux) | linux |
| Collection | [T1056.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1056.001/T1056.001.md) | Input Capture | windows |
| Collection | [T1056.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1056.001/T1056.001.md) | Living off the land Terminal Input Capture on Linux with pam.d | linux |
| Collection | [T1113](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1113/T1113.md) | Screencapture | macos |
| Collection | [T1113](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1113/T1113.md) | Screencapture (silent) | macos |
| Collection | [T1114.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1114.001/T1114.001.md) | Email Collection with PowerShell Get-Inbox | windows |
| Collection | [T1114.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1114.002/T1114.002.md) | Office365 - Remote Mail Collected | office-365 |
| Collection | [T1560.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1560.001/T1560.001.md) | Compress Data for Exfiltration With Rar | windows |
| Collection | [T1560.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1560.001/T1560.001.md) | Compress Data and lock with password for Exfiltration with winrar | windows |
| Command and Control | [T1071](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1071/T1071.md) | Telnet C2 | windows |
| Command and Control | [T1071.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1071.001/T1071.001.md) | Malicious User Agents - Powershell | windows |
| Command and Control | [T1071.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1071.001/T1071.001.md) | Malicious User Agents - CMD | windows |
| Command and Control | [T1105](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1105/T1105.md) | rsync remote file copy (push) | linux, macos |
| Command and Control | [T1105](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1105/T1105.md) | rsync remote file copy (pull) | linux, macos |
| Command and Control | [T1571](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1571/T1571.md) | Testing usage of uncommonly used port with PowerShell | windows |
| Command and Control | [T1571](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1571/T1571.md) | Testing usage of uncommonly used port | linux, macos |
| Command and Control | [T1572](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1572/T1572.md) | DNS over HTTPS Large Query Volume | windows |
| Command and Control | [T1572](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1572/T1572.md) | DNS over HTTPS Regular Beaconing | windows |
| Command and Control | [T1573](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1573/T1573.md) | OpenSSL C2 | windows |
| Impact | [T1486](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1486/T1486.md) | Encrypt files using gpg (FreeBSD/Linux) | linux |
| Impact | [T1486](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1486/T1486.md) | Encrypt files using 7z (FreeBSD/Linux) | linux |

**Logs reais de ataque (EVTX) para testar sem executar nada:**

- T1003.001 — [CA_hashdump_4663_4656_lsass_access](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Credential%20Access/CA_hashdump_4663_4656_lsass_access.evtx) _(inferido)_
- T1003.001 — [LsassSilentProcessExit_process_exit_monitor_3001_lsass](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Credential%20Access/LsassSilentProcessExit_process_exit_monitor_3001_lsass.evtx) _(inferido)_
- T1016 — [ID4688-Audit policy enumerated](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1016-System%20Network%20Configuration%20Discovery/ID4688-Audit%20policy%20enumerated.evtx) _(explícito)_
- T1016 — [ID4688-Firewall configuration enumerated (command)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1016-System%20Network%20Configuration%20Discovery/ID4688-Firewall%20configuration%20enumerated%20%28command%29.evtx) _(explícito)_
- T1018 — [ID5145-DNS hosts files access via network share](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1018-Remote%20System%20Discovery/ID5145-DNS%20hosts%20files%20access%20via%20network%20share.evtx) _(explícito)_
- T1021.001 — [ID4688,4778,4779 RDP hijack direct](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0008-Lateral%20Movement/T1021.001-Remote%20Desktop%20Protocol/ID4688%2C4778%2C4779%20RDP%20hijack%20direct.evtx) _(explícito)_
- T1021.001 — [ID4688-4778 RDP hijack command execution](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0008-Lateral%20Movement/T1021.001-Remote%20Desktop%20Protocol/ID4688-4778%20RDP%20hijack%20command%20execution.evtx) _(explícito)_
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
- T1078.002 — [ID4964-Login of a member of a special group](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0005-Defense%20Evasion/T1078.002-Valid%20accounts-Domain%20accounts/ID4964-Login%20of%20a%20member%20of%20a%20special%20group.evtx) _(explícito)_
- T1090 — [ID5600-proxy configuration changed](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0011-Command%20and%20Control/T1090-Proxy/ID5600-proxy%20configuration%20changed.evtx) _(explícito)_
- T1112 — [ID11,13-SMBexec service registration](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0005-Defense%20Evasion/T1112-Modify%20registry/ID11%2C13-SMBexec%20service%20registration.evtx) _(explícito)_
- T1112 — [ID4624,4670,4688,4674-Registry permission change via WMI (DAMP)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0005-Defense%20Evasion/T1112-Modify%20registry/ID4624%2C4670%2C4688%2C4674-Registry%20permission%20change%20via%20WMI%20%28DAMP%29.evtx) _(explícito)_
- T1218.011 — [rundll32_cmd_schtask](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/AutomatedTestingTools/Malware/rundll32_cmd_schtask.evtx) _(inferido)_
- T1218.011 — [rundll32_hollowing_wermgr_masquerading](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/AutomatedTestingTools/Malware/rundll32_hollowing_wermgr_masquerading.evtx) _(inferido)_
- T1482 — [ID800,4103,4104-Active Directory Forest PowerShell class](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1482-Domain%20Trust%20Discovery/ID800%2C4103%2C4104-Active%20Directory%20Forest%20PowerShell%20class.evtx) _(explícito)_
- T1486 — [ID 768,775,793,796,817,840-BitLocker encryption activated](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0040-Impact/T1486-Data%20Encrypted%20for%20Impact/ID%20768%2C775%2C793%2C796%2C817%2C840-BitLocker%20encryption%20activated.evtx) _(explícito)_

## 9. Hipóteses de hunting

Se Magic Hound estiver no seu ambiente, estas são as perguntas a fazer aos seus dados (fontes de log segundo as estratégias de detecção do MITRE ATT&CK).

1. **T1016.002 Wi-Fi Discovery** — Enumeration of saved Wi-Fi profiles and cleartext password retrieval using `netsh wlan` or API-level access to `wlanAPI.dll`. Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:PowerShell` (EventCode=4103, 4104, 4105, 4106).
2. **T1685.001 Disable or Modify Windows Event Log** — Detection of attempts to disable or tamper with Windows Event Logging. This includes stopping or disabling the EventLog service, modifying registry keys related to EventLog and Autologger, using `auditpol` or `wevtutil` to disable categories or clear audit… Dados: `WinEventLog:System` (EventCode=7035), `WinEventLog:Security` (EventCode=1102), `WinEventLog:Sysmon` (EventCode=13, 14).
3. **T1098.002 Additional Email Delegate Permissions** — Detection of anomalous or unauthorized mailbox delegation activity (e.g., Add-MailboxPermission, Default/Anonymous mailbox permissions, Gmail delegation setup). Dados: `m365:unified` (Add-MailboxPermission, UpdateFolderPermissions).
4. **T1592.002 Software** — Internet scanners may be used to look for patterns associated with malicious content designed to collect host software information from visitors. Much of this activity may have a very high occurrence and associated false positive rate, as well as potentially… Dados: `Internet Scan` (None).
5. **T1036.010 Masquerade Account Name** — Detects adversary behavior where a newly created or renamed user account closely resembles existing service or administrator accounts to blend in and avoid detection. Common patterns include prefix/suffix modifications, homoglyphs, or use of names like… Dados: `WinEventLog:Security` (EventCode=4720), `windows:osquery` (User enumeration with creation/last modified timestamps).
6. **T1078.001 Default Accounts** — Detection of default account usage such as Guest or Administrator performing interactive or remote logons on systems outside of installation or maintenance windows. Dados: `WinEventLog:Security` (EventCode=4624, 4648).
7. **T1087.003 Email Account** — Enumeration of global address lists or email account metadata via PowerShell cmdlets (e.g., Get-GlobalAddressList) or MAPI/RPC from non-admin, non-mailserver systems. Dados: `WinEventLog:PowerShell` (EventCode=4103, 4104, 4105, 4106), `WinEventLog:Sysmon` (EventCode=1).
8. **T1114 Email Collection** — Correlates creation of email forwarding rules or header anomalies (e.g., X-MS-Exchange-Organization-AutoForwarded) with suspicious process execution, file access of .pst/.ost files, and network connections to external SMTP servers. Dados: `WinEventLog:Security` (EventCode=5145), `WinEventLog:PowerShell` (EventCode=4103, 4104, 4105, 4106), `WinEventLog:Application` (Exchange logs or header artifacts).
9. **T1573 Encrypted Channel** — Processes that normally do not initiate network connections establishing outbound encrypted TLS/SSL sessions, especially with asymmetric traffic volumes (client sending more than receiving) or non-standard certificate chains. Defender observations correlate… Dados: `WinEventLog:Sysmon` (EventCode=3, 22), `WinEventLog:Sysmon` (EventCode=7).
10. **T1071 Application Layer Protocol** — Detects suspicious usage of common application-layer protocols (e.g., HTTP, HTTPS, DNS, SMB) by abnormal processes, with high outbound byte counts or irregular ports, possibly indicating command and control or data exfiltration. Dados: `NSM:Flow` (http, dns, smb, ssl logs), `WinEventLog:Sysmon` (EventCode=3, 22).
11. **T1567 Exfiltration Over Web Service** — Processes that normally do not initiate network communications suddenly making outbound HTTPS connections with high outbound-to-inbound data ratios. Defender view: correlation between process creation logs (e.g., Word, Excel, PowerShell) and subsequent… Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=3, 22), `WinEventLog:Sysmon` (EventCode=11).
12. **T1584.001 Domains** — Monitor for logged domain name system (DNS) registry data that may hijack domains and/or subdomains that can be used during targeting. In some cases, abnormal subdomain IP addresses (such as those originating in a different country from the root domain) may… Dados: `Domain Name` (None), `Domain Name` (None), `Domain Name` (None).

## 10. OSINT — onde pesquisar

Consultas prontas com todos os nomes conhecidos do grupo:

- Relatórios técnicos: [busca web](https://duckduckgo.com/?q=%28%22Magic+Hound%22+OR+%22TA453%22+OR+%22COBALT+ILLUSION%22+OR+%22Charming+Kitten%22+OR+%22ITG18%22+OR+%22Phosphorus%22%29+threat+report) · [PDFs](https://duckduckgo.com/?q=%28%22Magic+Hound%22+OR+%22TA453%22+OR+%22COBALT+ILLUSION%22+OR+%22Charming+Kitten%22+OR+%22ITG18%22+OR+%22Phosphorus%22%29+filetype%3Apdf)
- Regras e IOCs publicados: [GitHub](https://github.com/search?type=code&q=%22Magic+Hound%22+OR+%22TA453%22+OR+%22COBALT+ILLUSION%22+OR+%22Charming+Kitten%22+OR+%22ITG18%22+OR+%22Phosphorus%22)
- Pulsos de ameaça: [AlienVault OTX](https://otx.alienvault.com/browse/global/pulses?q=Magic+Hound)
- Família de malware e atores: [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/actors) (busque por Magic Hound, TA453, COBALT ILLUSION)
- Cartões de grupo: [ThaiCERT Threat Group Cards](https://apt.etda.or.th/cgi-bin/listgroups.cgi)
- Página oficial: [MITRE ATT&CK G0059](https://attack.mitre.org/groups/G0059/)

**Relatórios na coleção CyberMonitor** (ligados pelo nome do grupo, conferir antes de citar):

- 2014 — [Iranian Hackers Targeted US Officials in Elaborate Social Media Attack Operation _ SecurityWeek](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2014/2014.05.28.NewsCaster_An_Iranian_Threat_Within_Social_Networks/Iranian%20Hackers%20Targeted%20US%20Officials%20in%20Elaborate%20Social%20Media%20Attack%20Operation%20_%20SecurityWeek.pdf) _(via “Newscaster”)_
- 2014 — [file-2581720763-pdf](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2014/2014.05.28.NewsCaster_An_Iranian_Threat_Within_Social_Networks/file-2581720763-pdf.pdf) _(via “Newscaster”)_
- 2014 — [newscaster-iranian-threat-inside-social-media](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2014/2014.05.28.NewsCaster_An_Iranian_Threat_Within_Social_Networks/newscaster-iranian-threat-inside-social-media.pdf) _(via “Newscaster”)_
- 2017 — [unit42-magic-hound-campaign-attacks-saudi-targets](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2017/2017.02.15.magic-hound-campaign/unit42-magic-hound-campaign-attacks-saudi-targets.pdf) _(via “Magic Hound”)_
- 2017 — [Charming_Kitten_2017](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2017/2017.12.05.Charming_Kitten/Charming_Kitten_2017.pdf) _(via “Charming Kitten”)_
- 2018 — [The Return of The Charming Kitten](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2018/2018.12.13.Charming_Kitten_Return/The%20Return%20of%20The%20Charming%20Kitten.pdf) _(via “Charming Kitten”)_
- 2019 — [The-Kittens-Are-Back-in-Town-Charming-Kitten-2019](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2019/2019.09.15_Kittens_back/The-Kittens-Are-Back-in-Town-Charming-Kitten-2019.pdf) _(via “Charming Kitten”)_
- 2019 — [The Kittens Are Back in Town 2 - Charming Kitten Campaign Keeps Going on, Using New Impersonation Methods - ClearSky Cyb](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2019/2019.10.07.Charming_Kitten_Back_in_Town_2/The%20Kittens%20Are%20Back%20in%20Town%202%20-%20Charming%20Kitten%20Campaign%20Keeps%20Going%20on%2C%20Using%20New%20Impersonation%20Methods%20-%20ClearSky%20Cyber%20Security.pdf) _(via “Charming Kitten”)_
- 2019 — [The-Kittens-Are-Back-in-Town-2](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2019/2019.10.07.Charming_Kitten_Back_in_Town_2/The-Kittens-Are-Back-in-Town-2.pdf) _(via “Charming Kitten”)_
- 2021 — [BadBlood_ TA453 Targets US and Israeli Medical Research Personnel in Credential Phishing Campaigns _ Proofpoint US](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2021/2021.03.30.BadBlood_TA453/BadBlood_%20TA453%20Targets%20US%20and%20Israeli%20Medical%20Research%20Personnel%20in%20Credential%20Phishing%20Campaigns%20_%20Proofpoint%20US.pdf) _(via “TA453”)_
- 2022 — [PowerLess Trojan_ Iranian APT Phosphorus Adds New PowerShell Backdoor for Espionage](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2022/2022.02.01.Phosphorus_APT/PowerLess%20Trojan_%20Iranian%20APT%20Phosphorus%20Adds%20New%20PowerShell%20Backdoor%20for%20Espionage.pdf) _(via “Phosphorus”)_
- 2022 — [Old cat, new tricks, bad habits](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2022/2022.07.26.Charming_Kitten_APT/Old%20cat%2C%20new%20tricks%2C%20bad%20habits.pdf) _(via “Charming Kitten”)_

## 11. Bibliografia (25 fontes citadas pelo ATT&CK)

- [Certfa Charming Kitten January 2021](https://blog.certfa.com/posts/charming-kitten-christmas-gift/) — Certfa Labs. (2021, January 8). Charming Kitten’s Christmas Gift. Retrieved May 3, 2021.
- [Check Point APT35 CharmPower January 2022](https://research.checkpoint.com/2022/apt35-exploits-log4j-vulnerability-to-distribute-new-modular-powershell-toolkit/) — Check Point. (2022, January 11). APT35 exploits Log4j vulnerability to distribute new modular PowerShell toolkit. Retrieved January 24, 2022.
- [Check Point Rocket Kitten](https://blog.checkpoint.com/wp-content/uploads/2015/11/rocket-kitten-report.pdf) — Check Point Software Technologies. (2015). ROCKET KITTEN: A CAMPAIGN WITH 9 LIVES. Retrieved March 16, 2018.
- [ClearSky Charming Kitten Dec 2017](http://www.clearskysec.com/wp-content/uploads/2017/12/Charming_Kitten_2017.pdf) — ClearSky Cyber Security. (2017, December). Charming Kitten. Retrieved December 27, 2017.
- [ClearSky Kittens Back 2 Oct 2019](https://www.clearskysec.com/wp-content/uploads/2019/10/The-Kittens-Are-Back-in-Town-2-1.pdf) — ClearSky Research Team. (2019, October 1). The Kittens Are Back in Town2 - Charming Kitten Campaign KeepsGoing on, Using New Impersonation Methods. Retrieved April 21, 2021.
- [ClearSky Kittens Back 3 August 2020](https://www.clearskysec.com/wp-content/uploads/2020/08/The-Kittens-are-Back-in-Town-3.pdf) — ClearSky Research Team. (2020, August 1). The Kittens Are Back in Town 3 - Charming Kitten Campaign Evolved and Deploying Spear-Phishing link by WhatsApp. Retrieved April 21, 2021.
- [Cybereason PowerLess February 2022](https://www.cybereason.com/blog/research/powerless-trojan-iranian-apt-phosphorus-adds-new-powershell-backdoor-for-espionage) — Cybereason Nocturnus. (2022, February 1). PowerLess Trojan: Iranian APT Phosphorus Adds New PowerShell Backdoor for Espionage. Retrieved June 1, 2022.
- [DFIR Phosphorus November 2021](https://thedfirreport.com/2021/11/15/exchange-exploit-leads-to-domain-wide-ransomware/) — DFIR Report. (2021, November 15). Exchange Exploit Leads to Domain Wide Ransomware. Retrieved January 5, 2023.
- [DFIR Report APT35 ProxyShell March 2022](https://thedfirreport.com/2022/03/21/apt35-automates-initial-access-using-proxyshell) — DFIR Report. (2022, March 21). APT35 Automates Initial Access Using ProxyShell. Retrieved May 25, 2022.
- [Eweek Newscaster and Charming Kitten May 2014](https://www.eweek.com/security/newscaster-threat-uses-social-media-for-intelligence-gathering) — Kerner, S. (2014, May 29). Newscaster Threat Uses Social Media for Intelligence Gathering. Retrieved April 14, 2021.
- [FireEye APT35 2018](https://static.carahsoft.com/concrete/files/1015/2779/3571/M-Trends-2018-Report.pdf) — Mandiant. (2018). Mandiant M-Trends 2018. Retrieved November 17, 2024.
- [Google Iran Threats October 2021](https://blog.google/threat-analysis-group/countering-threats-iran/) — Bash, A. (2021, October 14). Countering threats from Iran. Retrieved January 4, 2023.
- [IBM ITG18 2020](https://securityintelligence.com/posts/new-research-exposes-iranian-threat-group-operations/) — Wikoff, A. Emerson, R. (2020, July 16). New Research Exposes Iranian Threat Group Operations. Retrieved March 8, 2021.
- [Microsoft Iranian Threat Actor Trends November 2021](https://www.microsoft.com/en-us/security/blog/2021/11/16/evolving-trends-in-iranian-threat-actor-activity-mstic-presentation-at-cyberwarcon-2021) — MSTIC. (2021, November 16). Evolving trends in Iranian threat actor activity – MSTIC presentation at CyberWarCon 2021. Retrieved January 12, 2023.
- [Microsoft Log4j Vulnerability Exploitation December 2021](https://www.microsoft.com/en-us/security/blog/2021/12/11/guidance-for-preventing-detecting-and-hunting-for-cve-2021-44228-log4j-2-exploitation/) — Microsoft Threat Intelligence. (2021, December 11). Guidance for preventing, detecting, and hunting for exploitation of the Log4j 2 vulnerability. Retrieved December 7, 2023.
- [Microsoft Phosphorus Mar 2019](https://blogs.microsoft.com/on-the-issues/2019/03/27/new-steps-to-protect-customers-from-hacking/) — Burt, T. (2019, March 27). New steps to protect customers from hacking. Retrieved May 27, 2020.
- [Microsoft Phosphorus Oct 2020](https://blogs.microsoft.com/on-the-issues/2020/10/28/cyberattacks-phosphorus-t20-munich-security-conference/) — Burt, T. (2020, October 28). Cyberattacks target international conference attendees. Retrieved March 8, 2021.
- [Microsoft Threat Actor Naming July 2023](https://learn.microsoft.com/en-us/microsoft-365/security/intelligence/microsoft-threat-actor-naming?view=o365-worldwide) — Microsoft . (2023, July 12). How Microsoft names threat actors. Retrieved November 17, 2023.
- [Proofpoint TA453 July2021](https://www.proofpoint.com/us/blog/threat-insight/operation-spoofedscholars-conversation-ta453) — Miller, J. et al. (2021, July 13). Operation SpoofedScholars: A Conversation with TA453. Retrieved August 18, 2021.
- [Proofpoint TA453 March 2021](https://www.proofpoint.com/us/blog/threat-insight/badblood-ta453-targets-us-and-israeli-medical-research-personnel-credential) — Miller, J. et al. (2021, March 30). BadBlood: TA453 Targets US and Israeli Medical Research Personnel in Credential Phishing Campaigns. Retrieved May 4, 2021.
- [Secureworks Cobalt Gypsy Feb 2017](https://www.secureworks.com/blog/iranian-pupyrat-bites-middle-eastern-organizations) — Counter Threat Unit Research Team. (2017, February 15). Iranian PupyRAT Bites Middle Eastern Organizations. Retrieved December 27, 2017.
- [Secureworks COBALT ILLUSION Threat Profile](https://www.secureworks.com/research/threat-profiles/cobalt-illusion) — Secureworks. (n.d.). COBALT ILLUSION Threat Profile. Retrieved April 14, 2021.
- [SecureWorks Mia Ash July 2017](https://www.secureworks.com/research/the-curious-case-of-mia-ash) — Counter Threat Unit Research Team. (2017, July 27). The Curious Case of Mia Ash: Fake Persona Lures Middle Eastern Targets. Retrieved February 26, 2018.
- [Unit 42 Magic Hound Feb 2017](https://researchcenter.paloaltonetworks.com/2017/02/unit42-magic-hound-campaign-attacks-saudi-targets/) — Lee, B. and Falcone, R. (2017, February 15). Magic Hound Campaign Attacks Saudi Targets. Retrieved December 27, 2017.
- [US District Court of DC Phosphorus Complaint 2019](https://noticeofpleadings.com/phosphorus/files/Complaint.pdf) — US District Court of DC. (2019, March 14). MICROSOFT CORPORATION v. JOHN DOES 1-2, CONTROLLING A COMPUTER NETWORK AND THEREBY INJURING PLAINTIFF AND ITS CUSTOMERS. Retrieved March 8, 2021.

## 12. Limites e confiança

- O ATT&CK registra o que foi **relatado publicamente**, não tudo o que o grupo faz. Ausência de uma técnica não prova que o grupo não a usa.
- **Sobreposição de TTP não é atribuição.** Muitas técnicas são compartilhadas entre grupos e com red teams. Use a assinatura comportamental como hipótese, junto com infraestrutura, malware e contexto.
- Cobertura de detecção refere-se ao catálogo público Detection Rules, não ao seu ambiente: confira se a telemetria necessária chega ao seu SIEM.
- Ligações marcadas como _inferidas_ (EVTX por palavra-chave, relatórios por nome) devem ser verificadas.

---
Fontes: MITRE ATT&CK® (uso livre com atribuição, © The MITRE Corporation), Atomic Red Team (Red Canary, MIT), EVTX-to-MITRE-Attack, EVTX-ATTACK-SAMPLES, APT & CyberCriminal Campaign Collections. Gerado por [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules).
