# NIMBUS MANTICORE (G1059) — Dossiê de inteligência

> **TLP:CLEAR** · gerado em 2026-10-25 a partir de fontes abertas · MITRE ATT&CK v20.0 · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1059) · [ATT&CK](https://attack.mitre.org/groups/G1059/)

**Também conhecido como:** UNC1549, TA455, COBALT SMOKEY  
**Registro no ATT&CK:** criado em 2026-10-01, atualizado em 2026-10-05 · referências de 2024 a 2026

## 1. Sumário executivo

- **65 técnicas** atribuídas publicamente, concentradas em **Stealth, Resource Development, Execution**.
- **Arsenal:** 13 malware e 0 ferramentas (ex.: MiniFast, MiniJunk, TWOSTROKE, MiniBrowse, DEEPROOT).
- **Campanhas atribuídas:** 0.
- **Cobertura de detecção pública:** 82% das técnicas têm ao menos uma regra no catálogo; **12 técnicas sem nenhuma regra pública**.
- **Assinatura comportamental** (técnicas raras entre os 178 grupos, as mais úteis para atribuição): T1574.014 AppDomainManager, T1598.001 Spearphishing Service, T1213 Data from Information Repositories, T1552 Unsecured Credentials, T1563.002 RDP Hijacking.

## 2. Quem é

> NIMBUS MANTICORE is a State Sponsored cyber espionage group associated with the Iranian Regime specifically the Iranian Revolutionary Guard Corps (IRGC). NIMBUS MANTICORE has employed social engineering attacks to include HR related themes and has leveraged custom malware against its victims. NIMBUS MANTICORE has sought sensitive information in victims’ environments to include network/IT documentation, intellectual property and emails. NIMBUS MANTICORE has also leveraged compromised organizations as pivot points to access other organizations of interest. NIMBUS MANTICORE has been active since 2021 and has targeted critical infrastructure organizations to include aviation, aerospace, telecommunications and defense and information technology related organizations within the United States, Australia, Midde East and Europe.

_Texto original do MITRE ATT&CK, em inglês._

## 3. Perfil TTP por tática (kill chain)

Cada linha: técnica, como o grupo a usou segundo relatos públicos, e o que existe para detectar e testar.

### Reconnaissance (TA0043) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1591](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1591) Gather Victim Org Information | NIMBUS MANTICORE has gathered details on victims to ensure they target members of organizations within software or aviation. | 2 | — | — |
| [T1598.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1598.001) Spearphishing Service | NIMBUS MANTICORE has corresponded and disseminated links to victims through social media. | **0** | — | — |

### Resource Development (TA0042) — 13

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1583.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1583.001) Domains | NIMBUS MANTICORE has created fake domains that imitate legitimate brands and services. | 7 | — | — |
| [T1583.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1583.003) Virtual Private Server | NIMBUS MANTICORE has utilized Azure C2 subdomains that resemble `*[.]*[.]cloudapp[.]azure[.]com`.   NIMBUS MANTICORE also utilized services that would reflect the geolocation of their targeted victims. | **0** | — | — |
| [T1583.006](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1583.006) Web Services | NIMBUS MANTICORE has utilized the OnlyOffice platform to deliver malicious payloads to victims.  NIMBUS MANTICORE has utilized webservices in attempts to provide a sense of legitimacy to its infrastructure to include *[.]azurewebsites[.]net.   NIMBUS MANTICORE… | 2 | — | — |
| [T1585.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1585.001) Social Media Accounts | NIMBUS MANTICORE has leveraged social media accounts to correspond with victims. | 4 | — | — |
| [T1587.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1587.001) Malware | NIMBUS MANTICORE has generated custom malware.    NIMBUS MANTICORE has incorporated AI-generated code in its malware development. | 43 | — | — |
| [T1588.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1588.002) Tool | NIMBUS MANTICORE has leveraged legitimate tools and publicly available utilities to include AD Explorer. | 35 | — | — |
| [T1588.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1588.003) Code Signing Certificates | NIMBUS MANTICORE has obtained and utilized valid digital signatures via SSL[.]com. | 1 | — | — |
| [T1588.007](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1588.007) Artificial Intelligence | NIMBUS MANTICORE has appeared to have leveraged AI to assist in malware generation due to coding patterns and modular code organization. | **0** | — | — |
| [T1608.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1608.001) Upload Malware | NIMBUS MANTICORE has staged malicious payloads on actor-controlled infrastructure for download to the victim environment. | 3 | — | — |
| [T1608.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1608.005) Link Target | NIMBUS MANTICORE had registered domains that would point to a typo-squatted domain used to deliver malicious payloads.   NIMBUS MANTICORE has also pre-shared credentials with a link to spoofed phishing login pages that enable the download of malicious payloads… | **0** | — | — |
| [T1608.006](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1608.006) SEO Poisoning | NIMBUS MANTICORE has utilized Search Engine Optimization (SEO) poisoning to deliver malware to unsuspecting victims.   NIMBUS MANTICORE has also registered dozens of domains that link to a typosquatted domain to generate link-based reputation signals and incor… | **0** | — | — |
| [T1683.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1683.001) Written Content | NIMBUS MANTICORE has created career-themed phishing lures to entice victims. | **0** | — | — |
| [T1683.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1683.002) Audio-Visual Content | NIMBUS MANTICORE has generated fictitious job-related themed websites that entice users to interact and launch malicious actions.   NIMBUS MANTICORE has also utilized decoy documents and files to provide a sense of legitimacy to the user.   NIMBUS MANTICORE ha… | **0** | — | — |

### Initial Access (TA0001) — 6

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1078.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.002) Domain Accounts | NIMBUS MANTICORE has leveraged domain accounts for lateral movement and privilege escalation. | 36 | — | 1 |
| [T1078.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.003) Local Accounts | NIMBUS MANTICORE has leveraged valid accounts belonging to victim organizations to include those belonging to their trusted partners for initial access and lateral movement. | 32 | 13 | — |
| [T1078.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.004) Cloud Accounts | NIMBUS MANTICORE has gained access to Azure AD Connect accounts to modify permissions and to create accounts for persistence. | 356 | 3 | — |
| [T1199](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1199) Trusted Relationship | NIMBUS MANTICORE has gained access to victim environments using trusted connections granted to third party partners, collaborators and contractors.   NIMBUS MANTICORE has also leveraged trusted third-party services to include Citrix, VMware, Azure Virtual Desk… | 18 | — | — |
| [T1566.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1566.001) Spearphishing Attachment | NIMBUS MANTICORE has used spearphishing emails with malicious attachments to entice victims. | 230 | 2 | — |
| [T1566.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1566.002) Spearphishing Link | NIMBUS MANTICORE has utilized malicious links in phishing emails that direct users to download a malicious payload. | 138 | 1 | — |

### Execution (TA0002) — 10

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1047](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1047) Windows Management Instrumentation | NIMBUS MANTICORE has leveraged `wmic.exe` to enumerate logged in users on compromised devices. | 370 | 12 | 11 |
| [T1053.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1053.005) Scheduled Task | NIMBUS MANTICORE has created scheduled tasks to maintain persistence. | 248 | 14 | 11 |
| [T1059.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.001) PowerShell | NIMBUS MANTICORE has leveraged PowerShell scripts to execute commands in the victim environment. | 1340 | 22 | 15 |
| [T1059.007](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.007) JavaScript | NIMBUS MANTICORE has used React templates to generate impersonated branded websites that deliver malicious payloads to victims. | 205 | 5 | — |
| [T1072](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1072) Software Deployment Tools | NIMBUS MANTICORE has utilized commercial remote access tools such as Atelier Web Remote Commander (AWRC) and Microsoft System Center Configuration Manager (SCCM) within victim environments. | 59 | 3 | — |
| [T1106](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1106) Native API | NIMBUS MANTICORE has utilized Native Windows API calls to execute on victim devices to include `GetModuleHandle`. | 118 | 5 | — |
| [T1204.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1204.001) Malicious Link | NIMBUS MANTICORE has enticed victims to click on links delivered in phishing campaigns. | 52 | — | — |
| [T1204.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1204.002) Malicious File | NIMBUS MANTICORE has distributed malicious payloads by enticing users to open or run the executables contained within zip files. | 259 | 13 | — |
| [T1574.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1574.001) DLL | NIMBUS MANTICORE has leveraged DLL search order hijacking and DLL sideloading to execute malicious payloads. | 455 | 7 | 5 |
| [T1574.014](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1574.014) AppDomainManager | NIMBUS MANTICORE has leveraged AppDomain Hijacking facilitated through a trojanized `.config` file. | **0** | — | — |

### Persistence (TA0003) — 7

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1053.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1053.005) Scheduled Task | NIMBUS MANTICORE has created scheduled tasks to maintain persistence. | 248 | 14 | 11 |
| [T1078.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.002) Domain Accounts | NIMBUS MANTICORE has leveraged domain accounts for lateral movement and privilege escalation. | 36 | — | 1 |
| [T1078.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.003) Local Accounts | NIMBUS MANTICORE has leveraged valid accounts belonging to victim organizations to include those belonging to their trusted partners for initial access and lateral movement. | 32 | 13 | — |
| [T1078.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.004) Cloud Accounts | NIMBUS MANTICORE has gained access to Azure AD Connect accounts to modify permissions and to create accounts for persistence. | 356 | 3 | — |
| [T1098](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1098) Account Manipulation | NIMBUS MANTICORE has reset passwords of valid accounts to include domain accounts in order to obtain persistence and escalate privileges.   NIMBUS MANTICORE has reset passwords for domain controller accounts using `net.exe` through the command `net user DC-01$… | 535 | 17 | 30 |
| [T1136.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1136.001) Local Account | NIMBUS MANTICORE has created rogue accounts within the compromised environments. | 103 | 10 | — |
| [T1547.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1547.001) Registry Run Keys / Startup Folder | NIMBUS MANTICORE has utilized auto-run registry keys to execute benign Windows executables that trigger the execution of a malicious payload. | 299 | 21 | 2 |

### Privilege Escalation (TA0004) — 6

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1053.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1053.005) Scheduled Task | NIMBUS MANTICORE has created scheduled tasks to maintain persistence. | 248 | 14 | 11 |
| [T1078.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.002) Domain Accounts | NIMBUS MANTICORE has leveraged domain accounts for lateral movement and privilege escalation. | 36 | — | 1 |
| [T1078.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.003) Local Accounts | NIMBUS MANTICORE has leveraged valid accounts belonging to victim organizations to include those belonging to their trusted partners for initial access and lateral movement. | 32 | 13 | — |
| [T1078.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.004) Cloud Accounts | NIMBUS MANTICORE has gained access to Azure AD Connect accounts to modify permissions and to create accounts for persistence. | 356 | 3 | — |
| [T1098](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1098) Account Manipulation | NIMBUS MANTICORE has reset passwords of valid accounts to include domain accounts in order to obtain persistence and escalate privileges.   NIMBUS MANTICORE has reset passwords for domain controller accounts using `net.exe` through the command `net user DC-01$… | 535 | 17 | 30 |
| [T1547.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1547.001) Registry Run Keys / Startup Folder | NIMBUS MANTICORE has utilized auto-run registry keys to execute benign Windows executables that trigger the execution of a malicious payload. | 299 | 21 | 2 |

### Stealth (TA0005) — 13

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1027](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1027) Obfuscated Files or Information | NIMBUS MANTICORE has utilized a mix of obfuscation techniques to hamper analysis of custom malware. | 520 | 11 | 5 |
| [T1027.015](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1027.015) Compression | NIMBUS MANTICORE has leveraged compressed archives to deliver malicious payloads to include zip files. | 3 | — | — |
| [T1036.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1036.004) Masquerade Task or Service | NIMBUS MANTICORE has masqueraded as legitimate services. | 31 | 4 | — |
| [T1036.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1036.005) Match Legitimate Resource Name or Location | NIMBUS MANTICORE has masqueraded as legitimate software.   NIMBUS MANTICORE has also mimicked legitimate installers to include Zoom. | 116 | 4 | — |
| [T1070.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1070.004) File Deletion | NIMBUS MANTICORE has deleted files after successful actions. | 132 | 11 | — |
| [T1070.007](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1070.007) Clear Network Connection History and Configurations | NIMBUS MANTICORE has cleared RDP connection history registry keys to include `HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client\Default` and ` HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client\Servers`. | **0** | — | — |
| [T1078.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.002) Domain Accounts | NIMBUS MANTICORE has leveraged domain accounts for lateral movement and privilege escalation. | 36 | — | 1 |
| [T1078.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.003) Local Accounts | NIMBUS MANTICORE has leveraged valid accounts belonging to victim organizations to include those belonging to their trusted partners for initial access and lateral movement. | 32 | 13 | — |
| [T1078.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.004) Cloud Accounts | NIMBUS MANTICORE has gained access to Azure AD Connect accounts to modify permissions and to create accounts for persistence. | 356 | 3 | — |
| [T1574.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1574.001) DLL | NIMBUS MANTICORE has leveraged DLL search order hijacking and DLL sideloading to execute malicious payloads. | 455 | 7 | 5 |
| [T1574.014](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1574.014) AppDomainManager | NIMBUS MANTICORE has leveraged AppDomain Hijacking facilitated through a trojanized `.config` file. | **0** | — | — |
| [T1678](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1678) Delay Execution | NIMBUS MANTICORE has planted backdoors that beacon silently for long-term persistence, activating them again after the victim has attempted eradication. | **0** | — | — |
| [T1684.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1684.001) Impersonation | NIMBUS MANTICORE has impersonated legitimate companies with fake career opportunities. | 1 | — | — |

### Defense Impairment (TA0112) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1685.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1685.003) Modify or Spoof Tool UI | NIMBUS MANTICORE has prompted victims with fake warnings and error messages to appear as legitimate failures to reduce user suspicion. | **0** | — | — |

### Credential Access (TA0006) — 5

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1003.006](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1003.006) DCSync | NIMBUS MANTICORE has utilized DCSync to obtain NTLM password hashes for domain users. | 33 | 2 | 2 |
| [T1110.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1110.003) Password Spraying | NIMBUS MANTICORE has conducted password spraying attacks against victim environments. | 62 | 9 | 1 |
| [T1552](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1552) Unsecured Credentials | NIMBUS MANTICORE has obtained credentials from internal service ticketing systems. | 266 | 2 | — |
| [T1558.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1558.003) Kerberoasting | NIMBUS MANTICORE has also performed Kerberoasting for credential access using an obfuscated `Invoke-Kerberroast`. | 132 | 7 | — |
| [T1649](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1649) Steal or Forge Authentication Certificates | NIMBUS MANTICORE has stolen and leveraged vulnerable Active Directory Certificate Services templates to impersonate higher-privileged user accounts. | 43 | 1 | 5 |

### Discovery (TA0007) — 6

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1007](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1007) System Service Discovery | NIMBUS MANTICORE has identified running services using remote management services to include Atelier Web Remote Commander (AWRC). | 37 | 8 | — |
| [T1046](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1046) Network Service Discovery | NIMBUS MANTICORE has utilized PowerShell scripts to conduct ping and port scanning of victim subnets. | 212 | 13 | 2 |
| [T1049](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1049) System Network Connections Discovery | NIMBUS MANTICORE has enumerated existing RDP sessions using remote management services to include Atelier Web Remote Commander (AWRC). | 47 | 7 | — |
| [T1057](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1057) Process Discovery | NIMBUS MANTICORE has enumerated active processes using remote management services to include Atelier Web Remote Commander (AWRC). | 82 | 10 | — |
| [T1087.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1087.001) Local Account | NIMBUS MANTICORE has identified logged in users on victim hosts using `quser.exe` and `wmic.exe`. | 98 | 11 | — |
| [T1087.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1087.002) Domain Account | NIMBUS MANTICORE has enumerated user accounts and group memberships using `net user` and `net group`.   NIMBUS MANTICORE also leveraged the legitimate tool AD Explorer to query Active Directory. | 180 | 25 | 1 |

### Lateral Movement (TA0008) — 5

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1021.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1021.001) Remote Desktop Protocol | NIMBUS MANTICORE has utilized RDP to log into victim devices using compromised user credentials. | 139 | 4 | 7 |
| [T1021.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1021.002) SMB/Windows Admin Shares | NIMBUS MANTICORE has accessed SMB shares within the victim network to gather and exfiltrate data. | 272 | 4 | 20 |
| [T1072](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1072) Software Deployment Tools | NIMBUS MANTICORE has utilized commercial remote access tools such as Atelier Web Remote Commander (AWRC) and Microsoft System Center Configuration Manager (SCCM) within victim environments. | 59 | 3 | — |
| [T1534](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1534) Internal Spearphishing | NIMBUS MANTICORE has conducted internal spearphishing attacks against IT staff and administrators. | 5 | — | — |
| [T1563.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1563.002) RDP Hijacking | NIMBUS MANTICORE has conducted RDP session hijacking to gain access to victim devices. | 16 | 1 | — |

### Collection (TA0009) — 5

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1039](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1039) Data from Network Shared Drive | NIMBUS MANTICORE has collected data from SMB shares within the victim network. | 24 | 2 | — |
| [T1114.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1114.001) Local Email Collection | NIMBUS MANTICORE has reviewed older emails within compromised inboxes to aid in crafting custom email lures. | 15 | 1 | — |
| [T1213](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1213) Data from Information Repositories | NIMBUS MANTICORE has gathered data from internal service ticketing systems to include credentials. | 112 | — | — |
| [T1213.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1213.002) Sharepoint | NIMBUS MANTICORE has downloaded files from SharePoint services. | 7 | — | — |
| [T1213.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1213.005) Messaging Applications | NIMBUS MANTICORE has browsed Microsoft Teams and downloaded files. | **0** | — | — |

### Command and Control (TA0011) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1071](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1071) Application Layer Protocol | NIMBUS MANTICORE has leveraged reverse SSH shells for command and control. | 511 | 1 | — |
| [T1105](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1105) Ingress Tool Transfer | NIMBUS MANTICORE has transferred and deployed malware to compromised hosts using remove management services, such as Atelier Web Remote Commander (AWRC), and SSH reverse tunnels. | 644 | 39 | — |

## 4. Assinatura comportamental

Técnicas que este grupo usa e que poucos dos 178 grupos do ATT&CK usam. Pesam mais numa atribuição por TTP: ver várias delas juntas é mais informativo do que ver técnicas comuns como PowerShell.

| Técnica | Outros grupos que usam | Peso (raridade) |
|---|---:|---:|
| T1574.014 AppDomainManager | 0 | 4.49 |
| T1598.001 Spearphishing Service | 0 | 4.49 |
| T1213 Data from Information Repositories | 1 | 4.09 |
| T1552 Unsecured Credentials | 1 | 4.09 |
| T1563.002 RDP Hijacking | 1 | 4.09 |
| T1608.006 SEO Poisoning | 1 | 4.09 |
| T1649 Steal or Forge Authentication Certificates | 1 | 4.09 |
| T1685.003 Modify or Spoof Tool UI | 1 | 4.09 |
| T1070.007 Clear Network Connection History and Configurations | 3 | 3.58 |
| T1558.003 Kerberoasting | 3 | 3.58 |

## 5. Arsenal

| Software | Tipo | Técnicas no ATT&CK | Uso relatado (EN) |
|---|---|---:|---|
| [MiniFast](https://attack.mitre.org/software/S9052/) | malware | 21 | MiniFast has been affiliated with the cyber espionage threat group NIMBUS MANTICORE. |
| [MiniJunk](https://attack.mitre.org/software/S9053/) | malware | 15 | MiniJunk has been affiliated with the cyber espionage threat group NIMBUS MANTICORE. |
| [TWOSTROKE](https://attack.mitre.org/software/S9067/) | malware | 13 | TWOSTROKE has been affiliated with the cyber espionage threat group NIMBUS MANTICORE. |
| [MiniBrowse](https://attack.mitre.org/software/S9062/) | malware | 11 | MiniBrowse has been affiliated with the cyber espionage threat group NIMBUS MANTICORE. |
| [DEEPROOT](https://attack.mitre.org/software/S9063/) | malware | 10 | DEEPROOT has been affiliated with the cyber espionage threat group NIMBUS MANTICORE. |
| [MiniBike](https://attack.mitre.org/software/S9059/) | malware | 9 | MiniBike has been affiliated with the cyber espionage threat group NIMBUS MANTICORE. |
| [MiniBus](https://attack.mitre.org/software/S9060/) | malware | 8 | MiniBus has been affiliated with the cyber espionage threat group NIMBUS MANTICORE. |
| [SIGHTGRAB](https://attack.mitre.org/software/S9058/) | malware | 8 | SIGHTGRAB has been affiliated with the cyber espionage threat group NIMBUS MANTICORE. |
| [LIGHTRAIL](https://attack.mitre.org/software/S9061/) | malware | 7 | LIGHTRAIL has been affiliated with the cyber espionage threat group NIMBUS MANTICORE. |
| [DCSYNCER.SLICK](https://attack.mitre.org/software/S9065/) | malware | 7 | DCSYNCER.SLICK has been affiliated with the cyber espionage threat group NIMBUS MANTICORE. |
| [POLLBLEND](https://attack.mitre.org/software/S9066/) | malware | 5 | POLLBLEND has been affiliated with the cyber espionage threat group NIMBUS MANTICORE. |
| [CRASHPAD](https://attack.mitre.org/software/S9057/) | malware | 4 | CRASHPAD  has been affiliated with the cyber espionage threat group NIMBUS MANTICORE. |
| [TRUSTTRAP](https://attack.mitre.org/software/S9064/) | malware | 3 | TRUSTTRAP has been affiliated with the cyber espionage threat group NIMBUS MANTICORE. |

## 6. Campanhas

Nenhuma campanha atribuída no ATT&CK.

## 7. Cobertura defensiva

**53 de 65 técnicas (82%)** têm ao menos uma regra pública no catálogo Detection Rules.

### Técnicas sem regra pública (prioridade para engenharia de detecção)

- **T1574.014 AppDomainManager** — Stealth. Fonte de log sugerida pelo MITRE: `WinEventLog:Security` EventCode=4688
- **T1598.001 Spearphishing Service** — Reconnaissance. Fonte de log sugerida pelo MITRE: `Application Log` None
- **T1608.006 SEO Poisoning** — Resource Development. Fonte de log sugerida pelo MITRE: `Internet Scan` None
- **T1685.003 Modify or Spoof Tool UI** — Defense Impairment. Fonte de log sugerida pelo MITRE: `WinEventLog:System` EventCode=7036; `auditd:SYSCALL` execve: Execution of binaries/scripts presenting false health messages for security daemons; `macos:unifiedlog` Execution of processes mimicking A
- **T1070.007 Clear Network Connection History and Configurations** — Stealth. Fonte de log sugerida pelo MITRE: `WinEventLog:Security` EventCode=4663, 4670, 4656; `auditd:SYSCALL` execve; `macos:unifiedlog` log stream --predicate 'eventMessage contains "loginwindow" or "pfctl"'; `networkdevice:syslog` Command A
- **T1588.007 Artificial Intelligence** — Resource Development
- **T1608.005 Link Target** — Resource Development. Fonte de log sugerida pelo MITRE: `Internet Scan` None
- **T1678 Delay Execution** — Stealth. Fonte de log sugerida pelo MITRE: `WinEventLog:Sysmon` EventCode=1; `auditd:SYSCALL` execve or nanosleep with no stdout/stderr I/O; `macos:unifiedlog` launchd or osascript spawns process with delay command
- **T1213.005 Messaging Applications** — Collection. Fonte de log sugerida pelo MITRE: `saas:slack` conversations.history, files.list, users.info, audit_logs; `m365:unified` TeamsMessagesAccessedViaEDiscovery, TeamsGraphMessageExport
- **T1683.002 Audio-Visual Content** — Resource Development
- **T1683.001 Written Content** — Resource Development
- **T1583.003 Virtual Private Server** — Resource Development. Fonte de log sugerida pelo MITRE: `Internet Scan` None

### Regras recomendadas por técnica

Melhor regra disponível por técnica (formato portável e maduro primeiro).

| Técnica | Regra | Formato | Fonte |
|---|---|---|---|
| T1003.006 | [HackTool - Mimikatz Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aa642964e-bead-4bed-8910-1bb4d63e3b4d) | Sigma | SigmaHQ |
| T1003.006 | [Mimikatz Use](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A06d71506-7beb-4f22-8888-e2e5e2ca7fd8) | Sigma | SigmaHQ |
| T1007 | [HackTool - PCHunter Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Afca949cc-79ca-446e-8064-01aa7e52ece5) | Sigma | SigmaHQ |
| T1007 | [SC.EXE Query Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A57712d7a-679c-4a41-a913-87e7175ae429) | Sigma | SigmaHQ |
| T1021.001 | [Hermetic Wiper TG Process Patterns](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A2f974656-6d83-4059-bbdf-68ac5403422f) | Sigma | SigmaHQ |
| T1021.001 | [Publicly Accessible RDP Service](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1fc0809e-06bf-4de3-ad52-25e5263b7623) | Sigma | SigmaHQ |
| T1021.002 | [PSExec Lateral Movement](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=hayabusa-native%3A%3A0694c340-3a46-40ac-acfc-c3444ae6572c) | Sigma | Hayabusa (native) |
| T1021.002 | [Turla Group Lateral Movement](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac601f20d-570a-4cde-a7d6-e17f99cb8e7f) | Sigma | SigmaHQ |
| T1027 | [Potential Emotet Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad02e8cf5-6099-48cf-9bfc-1eec2d0c7b18) | Sigma | SigmaHQ |
| T1027 | [Emotet Process Creation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Ad02e8cf5-6099-48cf-9bfc-1eec2d0c7b18) | Sigma | OpenSearch Security Analytics |
| T1027.015 | [PowerShell Suspicious Payload Encoded and Compressed](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A81fe9dc6-a2d7-4192-a2d8-eed98afc766a) | Elastic | Elastic detection-rules |
| T1027.015 | [Suspicious Content Extracted or Decompressed via Funzip](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Adc0b7782-0df0-47ff-8337-db0d678bdb66) | Elastic | Elastic detection-rules |
| T1036.004 | [Operation Wocao Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1cfac73c-be78-4f9a-9b08-5bde0c3953ab) | Sigma | SigmaHQ |
| T1036.004 | [Operation Wocao Activity - Security](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A74ad4314-482e-4c3e-b237-3f7ed3b9ca8d) | Sigma | SigmaHQ |
| T1036.005 | [Exploit for CVE-2015-1641](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A7993792c-5ce2-4475-a3db-a3a5539827ef) | Sigma | SigmaHQ |
| T1036.005 | [Exploit for CVE-2015-1641](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A7993792c-5ce2-4475-a3db-a3a5539827ef) | Sigma | OpenSearch Security Analytics |
| T1039 | [Copy from Admin Share](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A855bc8b5-2ae8-402e-a9ed-b889e6df1900) | Sigma | OpenSearch Security Analytics |
| T1039 | [PowerShell Share Enumeration Script](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A4c59cff1-b78a-41b8-a9f1-4231984d1fb6) | Elastic | Elastic detection-rules |
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
| T1059.007 | [Adwind RAT / JRAT](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1fac1481-2dbc-48b2-9096-753c49b4ec71) | Sigma | SigmaHQ |
| T1059.007 | [WScript or CScript Dropper - File](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A002bdb95-0cf1-46a6-9e08-d38c128a6127) | Sigma | SigmaHQ |
| T1070.004 | [File Deletion](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A30aed7b6-d2c1-4eaf-9382-b6bc43e50c57) | Sigma | SigmaHQ |
| T1070.004 | [Prefetch File Deleted](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A0a1f9d29-6465-4776-b091-7f43b26e4c89) | Sigma | SigmaHQ |
| T1071 | [GALLIUM IOCs](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A440a56bf-7873-4439-940a-1c8a671073c2) | Sigma | SigmaHQ |
| T1071 | [GALLIUM Artefacts - Builtin](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A3db10f25-2527-4b79-8d4b-471eb900ee29) | Sigma | SigmaHQ |
| T1072 | [Restricted Software Access By SRP](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab4c8da4a-1c12-46b0-8a2b-0a8521d03442) | Sigma | SigmaHQ |
| T1072 | [Suspicious Curl to Jamf Endpoint](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Aa8256685-9736-465b-b159-f25a172d08e8) | Elastic | Elastic detection-rules |
| T1078.002 | [Malicious Usage Of IMDS Credentials Outside Of AWS Infrastructure](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A352a918a-34d8-4882-8470-44830c507aa3) | Sigma | SigmaHQ |
| T1078.002 | [AdminSDHolder SDProp Exclusion Added](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A61d29caf-6c15-4d1e-9ccb-7ad12ccc0bc7) | Elastic | Elastic detection-rules |
| T1078.003 | [Potential Successful SSH Brute Force Attack via macOS Security Events](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Af5898b1e-3071-4597-b066-43d298c7b415) | Elastic | Elastic detection-rules |
| T1078.003 | [Admin User Remote Logon](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A0f63e1ef-1eb9-4226-9d54-8927ca08520a) | Sigma | SigmaHQ |
| T1078.004 | [Okta New Admin Console Behaviours](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aa0b38b70-3cb5-484b-a4eb-c4d8e7bcc0a9) | Sigma | SigmaHQ |
| T1078.004 | [AWS IAM S3Browser User or AccessKey Creation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Adb014773-d9d9-4792-91e5-133337c0ffee) | Sigma | SigmaHQ |
| T1087.001 | [BloodHound Collection Files](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A02773bed-83bf-469f-b7ff-e676e7d78bab) | Sigma | SigmaHQ |
| T1087.001 | [HackTool - Bloodhound/Sharphound Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Af376c8a7-a2d0-4ddc-aa0c-16c17236d962) | Sigma | SigmaHQ |
| T1087.002 | [BloodHound Collection Files](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A02773bed-83bf-469f-b7ff-e676e7d78bab) | Sigma | SigmaHQ |
| T1087.002 | [Suspicious Active Directory Database Snapshot Via ADExplorer](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aef61af62-bc74-4f58-b49b-626448227652) | Sigma | SigmaHQ |
| T1098 | [Password Change on Directory Service Restore Mode (DSRM) Account](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A53ad8e36-f573-46bf-97e4-15ba5bf4bb51) | Sigma | SigmaHQ |
| T1098 | [User Added To Global Domain Admins Grp](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=hayabusa-native%3A%3A4bb89c86-a138-42a0-baaf-fc2f777a4506) | Sigma | Hayabusa (native) |
| T1105 | [Greenbug Espionage Group Indicators](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A3711eee4-a808-4849-8a14-faf733da3612) | Sigma | SigmaHQ |
| T1105 | [Pandemic Registry Key](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A47e0852a-cf81-4494-a8e6-31864f8c86ed) | Sigma | SigmaHQ |
| T1106 | [Turla Group Named Pipes](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A739915e4-1e70-4778-8b8a-17db02f66db1) | Sigma | SigmaHQ |
| T1106 | [BPFDoor Abnormal Process ID or Lock File Accessed](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A808146b2-9332-4d78-9416-d7e47012d83d) | Sigma | SigmaHQ |
| T1110.003 | [Multiple SonicWall Login Failures Followed by Successful Login](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Aefe7ac71-3b13-41cf-8263-30af68ce3f19) | Elastic | Elastic detection-rules |
| T1110.003 | [Potential Successful SSH Brute Force Attack](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A8cb84371-d053-4f4f-bce0-c74990e28f28) | Elastic | Elastic detection-rules |
| T1114.001 | [Powershell Local Email Collection](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A2837e152-93c8-43d2-85ba-c3cd3c2ae614) | Sigma | SigmaHQ |
| T1114.001 | [Exporting Exchange Mailbox via PowerShell](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A6aace640-e631-4870-ba8e-5fdda09325db) | Elastic | Elastic detection-rules |
| T1136.001 | [DarkGate - User Created Via Net.EXE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Abf906d7b-7070-4642-8383-e404cf26eba5) | Sigma | SigmaHQ |
| T1136.001 | [Serv-U Exploitation CVE-2021-35211 by DEV-0322](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A75578840-9526-4b2a-9462-af469a45e767) | Sigma | SigmaHQ |
| T1199 | [Microsoft 365 - User Restricted from Sending Email](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aff246f56-7f24-402a-baca-b86540e3925c) | Sigma | SigmaHQ |
| T1199 | [Microsoft 365 - User Restricted from Sending Email](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Aff246f56-7f24-402a-baca-b86540e3925c) | Sigma | OpenSearch Security Analytics |
| T1204.001 | [Google Workspace Object Copied from External Drive with App Consent](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Af33e68a4-bd19-11ed-b02f-f661ea17fbcc) | Elastic | Elastic detection-rules |
| T1204.001 | [Suspicious ClickFix/FileFix Execution Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad487ed4a-fd24-436d-a0b2-f4e95f7b2635) | Sigma | SigmaHQ |
| T1204.002 | [Ursnif Malware C2 URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A932ac737-33ca-4afd-9869-0d48b391fcc9) | Sigma | SigmaHQ |
| T1204.002 | [Droppers Exploiting CVE-2017-11882](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A678eb5f4-8597-4be6-8be7-905e4234b53a) | Sigma | SigmaHQ |
| T1213 | [OpenCanary - MSSQL Login Attempt Via Windows Authentication](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A6e78f90f-0043-4a01-ac41-f97681613a66) | Sigma | SigmaHQ |
| T1213 | [OpenCanary - GIT Clone Request](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4fe17521-aef3-4e6a-9d6b-4a7c8de155a8) | Sigma | SigmaHQ |
| T1213.002 | [M365 SharePoint/OneDrive File Access via PowerShell](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A491651da-125b-11f1-af7d-f661ea17fbce) | Elastic | Elastic detection-rules |
| T1213.002 | [Entra ID Sharepoint or OneDrive Accessed by Unusual Client](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Aa3cc60d8-2701-11f0-accf-f661ea17fbcd) | Elastic | Elastic detection-rules |
| T1534 | [AWS SNS Topic Message Publish by Rare User](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A2112ecce-cd34-11ef-873f-f661ea17fbcd) | Elastic | Elastic detection-rules |
| T1534 | [OpenAI ChatGPT Enterprise Gmail Message Sent via Connector](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A7184e35d-5605-4283-badf-435e1974e488) | Elastic | Elastic detection-rules |
| T1547.001 | [Potential Ryuk Ransomware Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac37510b8-2107-4b78-aa32-72f251e7a844) | Sigma | SigmaHQ |
| T1547.001 | [Ryuk Ransomware](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Ac37510b8-2107-4b78-aa32-72f251e7a844) | Sigma | OpenSearch Security Analytics |
| T1552 | [Potential Okta Password in AlternateID Field](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A91b76b84-8589-47aa-9605-c837583b82a9) | Sigma | SigmaHQ |
| T1552 | [Application AppID Uri Configuration Changes](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1b45b0d1-773f-4f23-aedc-814b759563b1) | Sigma | SigmaHQ |
| T1558.003 | [HackTool - Rubeus Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A7ec2c172-dceb-4c10-92c9-87c1881b7e18) | Sigma | SigmaHQ |
| T1558.003 | [Rubeus Hack Tool](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A7ec2c172-dceb-4c10-92c9-87c1881b7e18) | Sigma | OpenSearch Security Analytics |
| T1563.002 | [Suspicious RDP Redirect Using TSCON](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Af72aa3e8-49f9-4c7d-bd74-f8ab84ff9bbb) | Sigma | SigmaHQ |
| T1563.002 | [Potential MSTSC Shadowing Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A6ba5a05f-b095-4f0a-8654-b825f4f16334) | Sigma | SigmaHQ |
| T1566.001 | [Ursnif Malware C2 URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A932ac737-33ca-4afd-9869-0d48b391fcc9) | Sigma | SigmaHQ |
| T1566.001 | [Droppers Exploiting CVE-2017-11882](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A678eb5f4-8597-4be6-8be7-905e4234b53a) | Sigma | SigmaHQ |
| T1566.002 | [Potential Malicious Usage of CloudTrail System Manager](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A38e7f511-3f74-41d4-836e-f57dfa18eead) | Sigma | SigmaHQ |
| T1566.002 | [Google Workspace Device Registration After OAuth from Suspicious ASN](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A012bfca7-45cb-4507-a3ba-3777167f8b81) | Elastic | Elastic detection-rules |
| T1574.001 | [Winnti Pipemon Characteristics](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A73d70463-75c9-4258-92c6-17500fe972f2) | Sigma | SigmaHQ |
| T1574.001 | [Winnti Pipemon Characteristics](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A73d70463-75c9-4258-92c6-17500fe972f2) | Sigma | OpenSearch Security Analytics |
| T1583.001 | [AWS Route 53 Private Hosted Zone Associated With a VPC](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ae3c27562-709a-42bd-82f2-3ed926cced19) | Elastic | Elastic detection-rules |
| T1583.001 | [AWS SES Email Identity Verified Then Deleted](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A8e4bde35-125d-4eb3-9a2e-d7e77a053a08) | Elastic | Elastic detection-rules |
| T1583.006 | [GitHub Repo Created](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A6cea88e4-6ce2-4238-9981-a54c140d6336) | Elastic | Elastic detection-rules |
| T1583.006 | [Cisco Secure Firewall - Rare Snort Rule Triggered](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=splunk-security-content%3A%3Ae20313d2-7d63-4fcf-b2d9-d6e12c6c7bd7) | Splunk | Splunk security_content |
| T1585.001 | [CYFIRMA - Brand Intelligence - Social Media Handle Impersonation Detected High Rule](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A22f49d67-7da7-4809-8d07-89e4478aa6b0) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1585.001 | [CYFIRMA - Brand Intelligence - Executive/People Impersonation High Rule](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A159d26a1-591c-4f70-b1ca-2843c881aaec) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1587.001 | [Formbook Process Creation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A032f5fb3-d959-41a5-9263-4173c802dc2b) | Sigma | SigmaHQ |
| T1587.001 | [Uncommon File Created In Office Startup Folder](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aa10a2c40-2c4d-49f8-b557-1a946bc55d9d) | Sigma | SigmaHQ |
| T1588.002 | [Hacktool Execution - Imphash](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A24e3e58a-646b-4b50-adef-02ef935b9fc8) | Sigma | SigmaHQ |
| T1588.002 | [Renamed SysInternals DebugView Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acd764533-2e07-40d6-a718-cfeec7f2da7f) | Sigma | SigmaHQ |
| T1588.003 | [Short-lived ephemeral code signing certificates](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-hunting-queries%3A%3Ae920899f-edf0-446c-bb13-effbaf61b27b) | Sentinel KQL | Microsoft Sentinel (Hunting Queries) |
| T1591 | [AWSCloudTrail - Suspicious AWS CLI Command Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A8c2dc344-9352-4ca1-8863-b1b7a5e09e59) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1591 | [MailGuard 365 - Malware Threats](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-hunting-queries%3A%3Adaaae6ad-1fd0-4efa-b571-116689e67a20) | Sentinel KQL | Microsoft Sentinel (Hunting Queries) |
| T1608.001 | [M365 OneDrive Malware File Upload](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Abba1b212-b85c-41c6-9b28-be0e5cdfc9b1) | Elastic | Elastic detection-rules |
| T1608.001 | [M365 SharePoint Malware File Detected](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A0e52157a-8e96-4a95-a6e3-5faae5081a74) | Elastic | Elastic detection-rules |
| T1649 | [HackTool - Certipy Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A6938366d-8954-4ddc-baff-c830b3ba8fcd) | Sigma | SigmaHQ |
| T1649 | [HackTool - Certify Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A762f2482-ff21-4970-8939-0aa317a886bb) | Sigma | SigmaHQ |
| T1684.001 | [Entra ID OAuth user_impersonation Scope for Unusual User and Client](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A9563dace-5822-11f0-b1d3-f661ea17fbcd) | Elastic | Elastic detection-rules |

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
| Execution | [T1059.007](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.007/T1059.007.md) | JScript execution to gather local computer information via cscript | windows |
| Execution | [T1059.007](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.007/T1059.007.md) | JScript execution to gather local computer information via wscript | windows |
| Execution | [T1072](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1072/T1072.md) | Radmin Viewer Utility | windows |
| Execution | [T1072](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1072/T1072.md) | PDQ Deploy RAT | windows |
| Execution | [T1106](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1106/T1106.md) | Execution through API - CreateProcess | windows |
| Execution | [T1106](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1106/T1106.md) | WinPwn - Get SYSTEM shell - Pop System Shell using CreateProcess technique | windows |
| Execution | [T1204.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1204.002/T1204.002.md) | OSTap Style Macro Execution | windows |
| Execution | [T1204.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1204.002/T1204.002.md) | OSTap Payload Download | windows |
| Persistence | [T1098](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1098/T1098.md) | Admin Account Manipulate | windows |
| Persistence | [T1098](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1098/T1098.md) | Domain Account and Group Manipulate | windows |
| Persistence | [T1136.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1136.001/T1136.001.md) | Create a user account on a Linux system | linux |
| Persistence | [T1136.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1136.001/T1136.001.md) | Create a user account on a FreeBSD system | linux |
| Persistence | [T1547.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1547.001/T1547.001.md) | Reg Key Run | windows |
| Persistence | [T1547.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1547.001/T1547.001.md) | Reg Key RunOnce | windows |
| Stealth | [T1027](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027/T1027.md) | Decode base64 Data into Script | linux, macos |
| Stealth | [T1027](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027/T1027.md) | Execute base64-encoded PowerShell | windows |
| Stealth | [T1036.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.004/T1036.004.md) | Creating W32Time similar named service using schtasks | windows |
| Stealth | [T1036.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.004/T1036.004.md) | Creating W32Time similar named service using sc | windows |
| Stealth | [T1036.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.005/T1036.005.md) | Execute a process from a directory masquerading as the current parent directory | linux, macos |
| Stealth | [T1036.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.005/T1036.005.md) | Masquerade as a built-in system executable | windows |
| Stealth | [T1070.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.004/T1070.004.md) | Delete a single file - FreeBSD/Linux/macOS | linux, macos |
| Stealth | [T1070.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.004/T1070.004.md) | Delete an entire folder - FreeBSD/Linux/macOS | linux, macos |
| Stealth | [T1078.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1078.003/T1078.003.md) | Create local account with admin privileges | windows |
| Stealth | [T1078.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1078.003/T1078.003.md) | Create local account with admin privileges - MacOS | macos |
| Stealth | [T1078.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1078.004/T1078.004.md) | Creating GCP Service Account and Service Account Key | google-workspace, iaas:gcp |
| Stealth | [T1078.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1078.004/T1078.004.md) | Azure Persistence Automation Runbook Created or Modified | iaas:azure |
| Stealth | [T1574.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1574.001/T1574.001.md) | DLL Search Order Hijacking - amsi.dll | windows |
| Stealth | [T1574.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1574.001/T1574.001.md) | Phantom Dll Hijacking - WinAppXRT.dll | windows |
| Credential Access | [T1003.006](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.006/T1003.006.md) | DCSync (Active Directory) | windows |
| Credential Access | [T1003.006](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.006/T1003.006.md) | Run DSInternals Get-ADReplAccount | windows |
| Credential Access | [T1110.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1110.003/T1110.003.md) | Password Spray all Domain Users | windows |
| Credential Access | [T1110.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1110.003/T1110.003.md) | Password Spray (DomainPasswordSpray) | windows |
| Credential Access | [T1552](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1552/T1552.md) | AWS - Retrieve EC2 Password Data using stratus | iaas:aws, linux, macos |
| Credential Access | [T1552](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1552/T1552.md) | Search for Passwords in Powershell History | windows |
| Credential Access | [T1558.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1558.003/T1558.003.md) | Request for service tickets | windows |
| Credential Access | [T1558.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1558.003/T1558.003.md) | Rubeus kerberoast | windows |
| Credential Access | [T1649](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1649/T1649.md) | Staging Local Certificates via Export-Certificate | windows |
| Discovery | [T1007](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1007/T1007.md) | System Service Discovery | windows |
| Discovery | [T1007](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1007/T1007.md) | System Service Discovery - net.exe | windows |
| Discovery | [T1046](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1046/T1046.md) | Port Scan | linux, macos |
| Discovery | [T1046](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1046/T1046.md) | Port Scan Nmap | linux, macos |
| Discovery | [T1049](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1049/T1049.md) | System Network Connections Discovery | windows |
| Discovery | [T1049](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1049/T1049.md) | System Network Connections Discovery with PowerShell | windows |
| Discovery | [T1057](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1057/T1057.md) | Process Discovery - ps | linux, macos |
| Discovery | [T1057](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1057/T1057.md) | Process Discovery - tasklist | windows |
| Discovery | [T1087.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1087.001/T1087.001.md) | Enumerate all accounts (Local) | linux |
| Discovery | [T1087.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1087.001/T1087.001.md) | View sudoers access | linux, macos |
| Discovery | [T1087.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1087.002/T1087.002.md) | Enumerate all accounts (Domain) | windows |
| Discovery | [T1087.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1087.002/T1087.002.md) | Enumerate all accounts via PowerShell (Domain) | windows |
| Lateral Movement | [T1021.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.001/T1021.001.md) | RDP to Remote Host | windows |
| Lateral Movement | [T1021.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.001/T1021.001.md) | Changing RDP Port to Non Standard Port via Powershell | windows |
| Lateral Movement | [T1021.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.002/T1021.002.md) | Map admin share | windows |
| Lateral Movement | [T1021.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.002/T1021.002.md) | Map Admin Share PowerShell | windows |
| Lateral Movement | [T1563.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1563.002/T1563.002.md) | RDP hijacking | windows |
| Collection | [T1039](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1039/T1039.md) | Copy a sensitive File over Administrative share with copy | windows |
| Collection | [T1039](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1039/T1039.md) | Copy a sensitive File over Administrative share with Powershell | windows |
| Collection | [T1114.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1114.001/T1114.001.md) | Email Collection with PowerShell Get-Inbox | windows |
| Command and Control | [T1071](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1071/T1071.md) | Telnet C2 | windows |
| Command and Control | [T1105](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1105/T1105.md) | rsync remote file copy (push) | linux, macos |
| Command and Control | [T1105](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1105/T1105.md) | rsync remote file copy (pull) | linux, macos |

**Logs reais de ataque (EVTX) para testar sem executar nada:**

- T1003.006 — [CA_DCSync_4662](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Credential%20Access/CA_DCSync_4662.evtx) _(inferido)_
- T1003.006 — [DACL_DCSync_Right_Powerview_ Add-DomainObjectAcl](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Persistence/DACL_DCSync_Right_Powerview_%20Add-DomainObjectAcl.evtx) _(inferido)_
- T1021.001 — [ID4688,4778,4779 RDP hijack direct](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0008-Lateral%20Movement/T1021.001-Remote%20Desktop%20Protocol/ID4688%2C4778%2C4779%20RDP%20hijack%20direct.evtx) _(explícito)_
- T1021.001 — [ID4688-4778 RDP hijack command execution](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0008-Lateral%20Movement/T1021.001-Remote%20Desktop%20Protocol/ID4688-4778%20RDP%20hijack%20command%20execution.evtx) _(explícito)_
- T1021.002 — [ID4688,4697,5140-5145 PSexec remote execution + admin share](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0008-Lateral%20Movement/T1021.002-SMB%20Windows%20Admin%20Shares/ID4688%2C4697%2C5140-5145%20PSexec%20remote%20execution%20%2B%20admin%20share.evtx) _(explícito)_
- T1021.002 — [ID4688-4648 Lateral movement with net use](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0008-Lateral%20Movement/T1021.002-SMB%20Windows%20Admin%20Shares/ID4688-4648%20Lateral%20movement%20with%20net%20use.evtx) _(explícito)_
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
- T1078.002 — [ID4964-Login of a member of a special group](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0005-Defense%20Evasion/T1078.002-Valid%20accounts-Domain%20accounts/ID4964-Login%20of%20a%20member%20of%20a%20special%20group.evtx) _(explícito)_
- T1087.002 — [discovery_bloodhound](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Discovery/discovery_bloodhound.evtx) _(inferido)_
- T1098 — [ID33205-SQL Server member added to database role](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0003-Persistence/T1098.xxx-Account%20manipulation/ID33205-SQL%20Server%20member%20added%20to%20database%20role.evtx) _(explícito)_
- T1098 — [ID33205-SQL Server member added to server role](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0003-Persistence/T1098.xxx-Account%20manipulation/ID33205-SQL%20Server%20member%20added%20to%20server%20role.evtx) _(explícito)_
- T1110.003 — [kerberos_pwd_spray_4771](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Credential%20Access/kerberos_pwd_spray_4771.evtx) _(inferido)_
- T1547.001 — [sideloading_injection_persistence_run_key](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/AutomatedTestingTools/Malware/sideloading_injection_persistence_run_key.evtx) _(inferido)_
- T1547.001 — [evasion_persis_hidden_run_keyvalue_sysmon_13](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Persistence/evasion_persis_hidden_run_keyvalue_sysmon_13.evtx) _(inferido)_
- T1574.001 — [DE_timestomp_and_dll_sideloading_and_RunPersist](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/AutomatedTestingTools/Malware/DE_timestomp_and_dll_sideloading_and_RunPersist.evtx) _(inferido)_
- T1574.001 — [sideloading_injection_persistence_run_key](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/AutomatedTestingTools/Malware/sideloading_injection_persistence_run_key.evtx) _(inferido)_

## 9. Hipóteses de hunting

Se NIMBUS MANTICORE estiver no seu ambiente, estas são as perguntas a fazer aos seus dados (fontes de log segundo as estratégias de detecção do MITRE ATT&CK).

1. **T1574.014 AppDomainManager** — Detection focuses on unauthorized manipulation of .NET AppDomainManager behavior. Defenders may observe suspicious creation of new AppDomains within trusted processes, anomalous loading of assemblies via non-standard configuration files, or… Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Sysmon` (EventCode=7).
2. **T1598.001 Spearphishing Service** — Monitor social media traffic for suspicious activity, including messages requesting information as well as abnormal file or data transfers (especially those involving unknown, or otherwise suspicious accounts). Much of this activity may have a very high… Dados: `Application Log` (None), `Network Traffic` (None), `Network Traffic` (None).
3. **T1213 Data from Information Repositories** — Programmatic or excessive access to file shares, SharePoint, or database repositories by users not typically interacting with them. This includes abnormal access by privileged accounts, enumeration of large numbers of files, or downloads of sensitive content… Dados: `WinEventLog:Security` (EventCode=5145), `m365:unified` (Accessed SharePoint files or pages).
4. **T1552 Unsecured Credentials** — Unusual access to bash history, registry credentials paths, or private key files by unauthorized or scripting tools, with correlated file and process activity. Dados: `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=13, 14).
5. **T1563.002 RDP Hijacking** — Detection of suspicious use of `tscon.exe` or equivalent methods to hijack legitimate RDP sessions. Defenders can observe anomalies such as session reassignments without corresponding authentication, processes spawned in the context of hijacked sessions, or… Dados: `WinEventLog:Security` (EventCode=4624, 4648), `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=3, 22).
6. **T1608.006 SEO Poisoning** — If infrastructure or patterns in the malicious web content related to SEO poisoning or Drive-by Target have been previously identified, internet scanning may uncover when an adversary has staged web content supporting a strategic web compromise. Much of this… Dados: `Internet Scan` (None).
7. **T1649 Steal or Forge Authentication Certificates** — Monitor for abnormal certificate enrollment and usage activity in Active Directory Certificate Services (AD CS), registry access to certificate storage locations, and unusual process executions that attempt to export or access private keys. Dados: `WinEventLog:Security` (EventCode=4768), `WinEventLog:Security` (EventCode=4657).
8. **T1685.003 Modify or Spoof Tool UI** — Detection of inconsistencies between reported sensor health and actual process/service state. For example, Windows Defender tray icon/UI showing healthy status while corresponding Defender services (WinDefend, MsMpEng) are stopped or disabled. Correlates… Dados: `WinEventLog:System` (EventCode=7036), `WinEventLog:Sysmon` (EventCode=1).
9. **T1070.007 Clear Network Connection History and Configurations** — Detects attempts to clear RDP/network history and modify network configuration artifacts through command execution, registry key deletion, firewall rule changes, and suspicious file deletions (e.g., Default.rdp, registry edits to Terminal Server Client keys). Dados: `WinEventLog:Security` (EventCode=4663, 4670, 4656), `WinEventLog:Sysmon` (EventCode=1), `EDR:cli` (Command Line Telemetry).
10. **T1558.003 Kerberoasting** — Detects Kerberoasting attempts by monitoring for anomalous Kerberos TGS requests (Event ID 4769) with RC4 encryption (etype 0x17), accounts requesting an unusual number of service tickets in a short period, or service accounts targeted outside normal usage… Dados: `WinEventLog:Security` (EventCode=4769), `WinEventLog:Sysmon` (EventCode=10), `WinEventLog:Security` (EventCode=4624, 4648).
11. **T1608.005 Link Target** — If infrastructure or patterns in malicious web content have been previously identified, internet scanning may uncover when an adversary has staged web content to make it accessible for targeting. Much of this activity will take place outside the visibility of… Dados: `Internet Scan` (None).
12. **T1678 Delay Execution** — Correlated use of sleep/delay mechanisms (e.g., kernel32!Sleep, NTDLL APIs) in short-lived processes, combined with parent processes invoking suspicious scripts (e.g., wscript, powershell) with minimal user interaction. Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=7).

## 10. OSINT — onde pesquisar

Consultas prontas com todos os nomes conhecidos do grupo:

- Relatórios técnicos: [busca web](https://duckduckgo.com/?q=%28%22NIMBUS+MANTICORE%22+OR+%22UNC1549%22+OR+%22TA455%22+OR+%22COBALT+SMOKEY%22%29+threat+report) · [PDFs](https://duckduckgo.com/?q=%28%22NIMBUS+MANTICORE%22+OR+%22UNC1549%22+OR+%22TA455%22+OR+%22COBALT+SMOKEY%22%29+filetype%3Apdf)
- Regras e IOCs publicados: [GitHub](https://github.com/search?type=code&q=%22NIMBUS+MANTICORE%22+OR+%22UNC1549%22+OR+%22TA455%22+OR+%22COBALT+SMOKEY%22)
- Pulsos de ameaça: [AlienVault OTX](https://otx.alienvault.com/browse/global/pulses?q=NIMBUS+MANTICORE)
- Família de malware e atores: [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/actors) (busque por NIMBUS MANTICORE, UNC1549, TA455)
- Cartões de grupo: [ThaiCERT Threat Group Cards](https://apt.etda.or.th/cgi-bin/listgroups.cgi)
- Página oficial: [MITRE ATT&CK G1059](https://attack.mitre.org/groups/G1059/)

**Relatórios na coleção CyberMonitor** (ligados pelo nome do grupo, conferir antes de citar):

- 2024 — [When Cats Fly_ Suspected Iranian Threat Actor UNC1549 Targets Israeli and Middle East Aerospace and Defense Sectors _ Ma](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2024/2024.02.27.UNC1549/When%20Cats%20Fly_%20Suspected%20Iranian%20Threat%20Actor%20UNC1549%20Targets%20Israeli%20and%20Middle%20East%20Aerospace%20and%20Defense%20Sectors%20_%20Mandiant.pdf) _(via “UNC1549”)_

## 11. Bibliografia (7 fontes citadas pelo ATT&CK)

- [CheckPoint_NimbusManticore_May2026](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/) — Check Point. (2026, May 22). Fast and Furious – Nimbus Manticore Operations During the Iranian Conflict. Retrieved September 23, 2026.
- [CheckPoint_NimbusManticoreEurope_Sept2025](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/) — Check Point. (2025, September 22). Nimbus Manticore Deploys New Malware Targeting Europe. Retrieved September 24, 2026.
- [Mandiant_UNC1549_Feb2024](https://cloud.google.com/blog/topics/threat-intelligence/suspected-iranian-unc1549-targets-israel-middle-east) — Rozmann, O., et al. (2024, February 27). When Cats Fly: Suspected Iranian Threat Actor UNC1549 Targets Israeli and Middle East Aerospace and Defense Sectors. Retrieved September 28, 2026.
- [Mandiant_UNC1549_Nov2025](https://cloud.google.com/blog/topics/threat-intelligence/analysis-of-unc1549-ttps-targeting-aerospace-defense) — El-Banna, M., et al. (2025, November 17). Frontline Intelligence: Analysis of UNC1549 TTPs, Custom Tools, and Malware Targeting the Aerospace and Defense Ecosystem. Retrieved September 28, 2026.
- [Mandiant_UNC1549TTPsTools_Nov2025](https://cloud.google.com/blog/topics/threat-intelligence/analysis-of-unc1549-ttps-targeting-aerospace-defense) — El-Banna, M., et al. (2025, November 17). Frontline Intelligence: Analysis of UNC1549 TTPs, Custom Tools, and Malware Targeting the Aerospace and Defense Ecosystem. Retrieved September 28, 2026.
- [Proofpoint NIMBUS MANTICORE TA455  TA453 TA450 November 2025](https://www.proofpoint.com/us/blog/threat-insight/crossed-wires-case-study-iranian-espionage-and-attribution) — Saher Naumaan and The Proofpoint Threat Research Team. (2025, November 5). Crossed wires: a case study of Iranian espionage and attribution. Retrieved October 5, 2026.
- [Sophos Iran Cobalt Smokey Nimbus Manticore October 2026](https://www.sophos.com/en-us/threat-profiles/cobalt-smokey) — Sophos. (2026, October 5). Iran COBALT SMOKEY. Retrieved October 5, 2026.

## 12. Limites e confiança

- O ATT&CK registra o que foi **relatado publicamente**, não tudo o que o grupo faz. Ausência de uma técnica não prova que o grupo não a usa.
- **Sobreposição de TTP não é atribuição.** Muitas técnicas são compartilhadas entre grupos e com red teams. Use a assinatura comportamental como hipótese, junto com infraestrutura, malware e contexto.
- Cobertura de detecção refere-se ao catálogo público Detection Rules, não ao seu ambiente: confira se a telemetria necessária chega ao seu SIEM.
- Ligações marcadas como _inferidas_ (EVTX por palavra-chave, relatórios por nome) devem ser verificadas.

---
Fontes: MITRE ATT&CK® (uso livre com atribuição, © The MITRE Corporation), Atomic Red Team (Red Canary, MIT), EVTX-to-MITRE-Attack, EVTX-ATTACK-SAMPLES, APT & CyberCriminal Campaign Collections. Gerado por [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules).
