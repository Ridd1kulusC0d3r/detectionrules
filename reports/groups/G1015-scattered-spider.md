# Scattered Spider (G1015) — Dossiê de inteligência

> **TLP:CLEAR** · gerado em 2026-10-26 a partir de fontes abertas · MITRE ATT&CK v20.0 · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1015) · [ATT&CK](https://attack.mitre.org/groups/G1015/)

**Também conhecido como:** Roasted 0ktapus, Octo Tempest, Storm-0875, UNC3944  
**Origem atribuída:** Sem país atribuído · **Motivação:** financeiro · **Setores-alvo:** —  
**Registro no ATT&CK:** criado em 2023-07-05, atualizado em 2026-09-11 · referências de 2022 a 2025

## 1. Sumário executivo

- **64 técnicas** atribuídas publicamente, concentradas em **Discovery, Persistence, Credential Access**.
- **Arsenal:** 4 malware e 6 ferramentas (ex.: Vidar, WarzoneRAT, Raccoon Stealer, BlackCat, Mimikatz).
- **Campanhas atribuídas:** 1 (C0027).
- **Cobertura de detecção pública:** 95% das técnicas têm ao menos uma regra no catálogo; **3 técnicas sem nenhuma regra pública**.
- **Origem e alvos (APT4ALL):** atribuído a **Sem país atribuído**, motivação financeiro.
- **Onde a cobertura está:** Windows (48 técnicas com regra), AWS (42 técnicas com regra), EDR / XDR (41 técnicas com regra), Outros / genérico (40 técnicas com regra).
- **Assinatura comportamental** (técnicas raras entre os 178 grupos, as mais úteis para atribuição): T1538 Cloud Service Dashboard, T1556.006 Multi-Factor Authentication, T1006 Direct Volume Access, T1070.008 Clear Mailbox Data, T1204 User Execution.

## 2. Quem é

> Scattered Spider is a native English-speaking cybercriminal group active since at least 2022. The group initially targeted customer relationship management (CRM) providers, business process outsourcing (BPO) firms, and telecommunications and technology companies before expanding in 2023 to gaming, hospitality, retail, managed service provider (MSP), manufacturing, and financial sectors. 
> Scattered Spider relies heavily on social engineering, including impersonating IT and help-desk staff, to gain initial access, bypass multi-factor authentication (MFA), and compromise enterprise networks. The group has adapted its tooling to evade endpoint detection and response (EDR) defenses and used ransomware for financial gain. 
> Scattered Spider had expanded into hybrid cloud and identity environments, using help-desk impersonation and MFA bypass to obtain administrator access in Okta, AWS, and Office 365.

_Texto original do MITRE ATT&CK, em inglês._

## 3. Contexto, nomes e alvos

Consolidado pelo [APT4ALL](https://github.com/Ridd1kulusC0d3r/apt4all) a partir de MISP Galaxy, planilha APT Groups & Operations, EternalLiberty e APTnotes. Atribuição é afirmação de quem publicou; confira a fonte.

| Campo | Valor |
|---|---|
| Origem atribuída | Sem país atribuído |
| Motivação | financeiro |
| Setores-alvo | — |
| Vítimas citadas | — |
| Alvos (planilha) | — |
| Operações conhecidas | — |
| Confiança de atribuição (MISP) | High |

**Como cada fornecedor chama este grupo** (útil para cruzar relatórios):

| Fornecedor | Nome(s) |
|---|---|
| MITRE ATT&CK | G1015 |

**Outros nomes no APT4ALL (não listados pelo ATT&CK):** Muddled Libra, Oktapus, Scattered Swine, Scatter Swine, 0ktapus, Storm-0971, DEV-0971, Starfraud, Octo Tempest/DEV-0875, Gold Harvest

## 4. Perfil TTP por tática (kill chain)

Cada linha: técnica, como o grupo a usou segundo relatos públicos, e o que existe para detectar e testar.

### Reconnaissance (TA0043) — 4

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1589](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1589) Gather Victim Identity Information | Scattered Spider has used information from previous data breaches to identify employee names to be used in social engineering. | 11 | — | — |
| [T1598](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1598) Phishing for Information | Scattered Spider has used a combination of credential phishing and social engineering to capture one-time-password (OTP) codes. | 4 | — | — |
| [T1598.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1598.003) Spearphishing Link | Scattered Spider has used domains mirroring corporate login portals to socially engineer victims into providing credentials. | **0** | — | — |
| [T1598.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1598.004) Spearphishing Voice | Scattered Spider has used help desk voice-based phishing and also called employees at target organizations and compelled them to navigate to fake login portals using adversary-in-the-middle toolkits. | **0** | — | — |

### Resource Development (TA0042) — 4

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1583.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1583.001) Domains | Scattered Spider has registered domains to spoof legitimate corporate login portals. | 7 | — | — |
| [T1585.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1585.001) Social Media Accounts | Scattered Spider has created matching fake social media profiles to support new accounts created in victim environments. | 4 | — | — |
| [T1588.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1588.001) Malware | Scattered Spider has obtained malware to use at multiple stages of operations including information stealers, remote access tools, and ransomware. | 7 | — | — |
| [T1588.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1588.002) Tool | Scattered Spider has obtained tools for use throughout the attack lifecycle to include remote access software, protocol tunneling and proxy tools, exploitation frameworks, and reconnaissance tools. | 35 | — | — |

### Initial Access (TA0001) — 3

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | Scattered Spider has used compromised credentials for initial access. | 825 | — | 3 |
| [T1078.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.004) Cloud Accounts | Scattered Spider has used compromised Microsoft Entra ID accounts to pivot in victim environments. | 356 | 3 | — |
| [T1133](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1133) External Remote Services | Scattered Spider has leveraged legitimate remote management tools to maintain persistent access. | 361 | 1 | — |

### Execution (TA0002) — 3

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1059.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.001) PowerShell | Scattered Spider has used the PowerShell cmdlet Get-ADUser. | 1340 | 22 | 15 |
| [T1059.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.004) Unix Shell | Scattered Spider has used the command shell to upload and install the Teleport remote access tool to a compromised vCenter Server Appliance. | 395 | 17 | — |
| [T1204](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1204) User Execution | Scattered Spider has impersonated organization IT and helpdesk staff to instruct victims to execute commercial remote access tools to gain initial access. | 326 | — | 1 |

### Persistence (TA0003) — 9

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | Scattered Spider has used compromised credentials for initial access. | 825 | — | 3 |
| [T1078.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.004) Cloud Accounts | Scattered Spider has used compromised Microsoft Entra ID accounts to pivot in victim environments. | 356 | 3 | — |
| [T1098](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1098) Account Manipulation | Scattered Spider has added accounts to the ESX Admins group to grant them full admin rights in vSphere. | 535 | 17 | 30 |
| [T1098.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1098.003) Additional Cloud Roles | Scattered Spider has assigned user access admin roles in order to gain Tenant Root Group management permissions in Azure. | 122 | 2 | — |
| [T1133](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1133) External Remote Services | Scattered Spider has leveraged legitimate remote management tools to maintain persistent access. | 361 | 1 | — |
| [T1136](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1136) Create Account | Scattered Spider creates new user identities within the compromised organization. | 127 | — | 11 |
| [T1543.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1543.002) Systemd Service | Scattered Spider has run `SYSTEMD_UNIT_PATH="/lib/systemd/ system/teleport.service` to establish persistence for the Teleport remote access tool. | 23 | 4 | — |
| [T1556.006](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1556.006) Multi-Factor Authentication | After compromising user accounts, Scattered Spider registers their own MFA tokens. | 41 | — | — |
| [T1556.009](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1556.009) Conditional Access Policies | Scattered Spider has added additional trusted locations to Azure AD conditional access policies. | 14 | — | — |

### Privilege Escalation (TA0004) — 7

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1068](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1068) Exploitation for Privilege Escalation | Scattered Spider has deployed a malicious kernel driver through exploitation of CVE-2015-2291 in the Intel Ethernet diagnostics driver for Windows (iqvw64.sys). | 408 | 2 | 2 |
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | Scattered Spider has used compromised credentials for initial access. | 825 | — | 3 |
| [T1078.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.004) Cloud Accounts | Scattered Spider has used compromised Microsoft Entra ID accounts to pivot in victim environments. | 356 | 3 | — |
| [T1098](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1098) Account Manipulation | Scattered Spider has added accounts to the ESX Admins group to grant them full admin rights in vSphere. | 535 | 17 | 30 |
| [T1098.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1098.003) Additional Cloud Roles | Scattered Spider has assigned user access admin roles in order to gain Tenant Root Group management permissions in Azure. | 122 | 2 | — |
| [T1484.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1484.002) Trust Modification | Scattered Spider adds a federated identity provider to the victim’s SSO tenant and activates automatic account linking. | 19 | 1 | — |
| [T1543.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1543.002) Systemd Service | Scattered Spider has run `SYSTEMD_UNIT_PATH="/lib/systemd/ system/teleport.service` to establish persistence for the Teleport remote access tool. | 23 | 4 | — |

### Stealth (TA0005) — 6

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1006](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1006) Direct Volume Access | Scattered Spider has created volume shadow copies of virtual domain controller disks to extract the `NTDS.dit` file. | 12 | 1 | — |
| [T1070.008](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1070.008) Clear Mailbox Data | Scattered Spider has manually deleted emails notifying users of suspicious account activity. | 10 | 6 | — |
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | Scattered Spider has used compromised credentials for initial access. | 825 | — | 3 |
| [T1078.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.004) Cloud Accounts | Scattered Spider has used compromised Microsoft Entra ID accounts to pivot in victim environments. | 356 | 3 | — |
| [T1564.008](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1564.008) Email Hiding Rules | Scattered Spider creates inbound rules on the compromised email accounts of security personnel to automatically delete emails from vendor security products. | 21 | 1 | — |
| [T1684.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1684.001) Impersonation | Scattered Spider utilized social engineering to compel IT help desk personnel to reset passwords and MFA tokens. Scattered Spider has also used Microsoft Teams to pose as internal IT support or help desk personnel. | 1 | — | — |

### Defense Impairment (TA0112) — 6

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1484.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1484.002) Trust Modification | Scattered Spider adds a federated identity provider to the victim’s SSO tenant and activates automatic account linking. | 19 | 1 | — |
| [T1553.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1553.002) Code Signing | Scattered Spider has used self-signed and stolen certificates originally issued to NVIDIA and Global Software LLC. | 11 | — | — |
| [T1556.006](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1556.006) Multi-Factor Authentication | After compromising user accounts, Scattered Spider registers their own MFA tokens. | 41 | — | — |
| [T1556.009](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1556.009) Conditional Access Policies | Scattered Spider has added additional trusted locations to Azure AD conditional access policies. | 14 | — | — |
| [T1578.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1578.002) Create Cloud Instance | Scattered Spider has created Amazon EC2 instances within the victim's environment. | 6 | — | — |
| [T1685](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1685) Disable or Modify Tools | Scattered Spider has uninstalled and disabled security tools. | 1275 | 78 | 19 |

### Credential Access (TA0006) — 8

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1003.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1003.003) NTDS | Scattered Spider has extracted the `NTDS.dit` file by creating volume shadow copies of virtual domain controller disks. | 157 | 11 | 2 |
| [T1539](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1539) Steal Web Session Cookie | Scattered Spider retrieves browser cookies via Raccoon Stealer. | 54 | 5 | — |
| [T1552.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1552.001) Credentials In Files | Scattered Spider Spider searches for credential storage documentation on a compromised host. | 166 | 32 | — |
| [T1552.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1552.004) Private Keys | Scattered Spider enumerate and exfiltrate code-signing certificates from a compromised host. | 60 | 17 | 1 |
| [T1555.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1555.005) Password Managers | Scattered Spider has searched for credentials in password vaults and Privileged Access Management (PAM) solutions including HashiCorp Vault. | 6 | — | — |
| [T1556.006](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1556.006) Multi-Factor Authentication | After compromising user accounts, Scattered Spider registers their own MFA tokens. | 41 | — | — |
| [T1556.009](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1556.009) Conditional Access Policies | Scattered Spider has added additional trusted locations to Azure AD conditional access policies. | 14 | — | — |
| [T1621](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1621) Multi-Factor Authentication Request Generation | Scattered Spider has used multifactor authentication (MFA) fatigue by sending repeated MFA authentication requests to targets. | 27 | — | — |

### Discovery (TA0007) — 11

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1016](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1016) System Network Configuration Discovery | Scattered Spider has used network reconnaissance commands for discovery including `ping` and `nltest`. | 99 | 10 | 5 |
| [T1018](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1018) Remote System Discovery | Scattered Spider can enumerate remote systems, such as VMware vCenter infrastructure. | 157 | 23 | 1 |
| [T1069](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1069) Permission Groups Discovery | Scattered Spider has enumerated the vSphere Admins and ESX Admins groups in targeted environments. | 81 | — | 7 |
| [T1069.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1069.002) Domain Groups | Scattered Spider has enumerated Active Directory security groups including through the use of ADExplorer, ADRecon.ps1, and Get-ADUser. | 91 | 15 | — |
| [T1082](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1082) System Information Discovery | Scattered Spider has executed scripts to identify the underlying operating system to ensure it uses the correct installation package for malicious payloads. | 264 | 41 | — |
| [T1083](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1083) File and Directory Discovery | Scattered Spider Spider enumerates a target organization for files and directories of interest, including source code, user provisioning, MFA device registration, network diagrams, and shared credentials in documents or spreadsheets. | 137 | 9 | — |
| [T1087](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1087) Account Discovery | Scattered Spider has identified vSphere administrator accounts. | 230 | — | 8 |
| [T1087.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1087.002) Domain Account | Scattered Spider has enumerated legitimate domain accounts which are used in the targeted environment. | 180 | 25 | 1 |
| [T1217](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1217) Browser Information Discovery | Scattered Spider retrieves browser histories via infostealer malware such as Raccoon Stealer. | 19 | 11 | — |
| [T1538](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1538) Cloud Service Dashboard | Scattered Spider abused AWS Systems Manager Inventory to identify targets on the compromised network prior to lateral movement. | 4 | — | — |
| [T1580](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1580) Cloud Infrastructure Discovery | Scattered Spider enumerates cloud environments including Amazon Web Services (AWS) S3 buckets to identify server and backup management infrastructure, resource access, databases and storage containers . | 48 | 2 | — |

### Lateral Movement (TA0008) — 3

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1021.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1021.001) Remote Desktop Protocol | Scattered Spider has used RDP to enable lateral movement. | 139 | 4 | 7 |
| [T1021.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1021.004) SSH | Scattered Spider has used SSH to move laterally in victim environments and to access the vSphere vCenter Server GUI. | 60 | 2 | 3 |
| [T1021.007](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1021.007) Cloud Services | Scattered Spider has also leveraged pre-existing AWS EC2 instances for lateral movement and data collection purposes. | 20 | — | — |

### Collection (TA0009) — 6

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1074](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1074) Data Staged | Scattered Spider stages data in a centralized database prior to exfiltration. | 40 | — | — |
| [T1114](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1114) Email Collection | Scattered Spider searched the victim’s Microsoft Exchange for emails about the intrusion and incident response. | 119 | — | — |
| [T1114.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1114.003) Email Forwarding Rule | Scattered Spider has redirected emails notifying users of suspicious account activity. | 10 | 1 | — |
| [T1213.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1213.003) Code Repositories | Scattered Spider enumerates data stored within victim code repositories, such as internal GitHub repositories. | 21 | — | — |
| [T1213.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1213.005) Messaging Applications | Scattered Spider threat actors search the victim’s Slack and Microsoft Teams for conversations about the intrusion and incident response. | **0** | — | — |
| [T1530](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1530) Data from Cloud Storage | Scattered Spider enumerates data stored in cloud resources for collection and exfiltration purposes. | 150 | 2 | — |

### Command and Control (TA0011) — 4

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1090](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1090) Proxy | Scattered Spider has used proxy networks to hamper detection and has installed legitimate proxy tools on VMware vCenter and adversary-controlled VMs. | 162 | — | 1 |
| [T1105](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1105) Ingress Tool Transfer | Scattered Spider has downloaded the Teleport remote access tool to compromised VMware vCenter Servers. | 644 | 39 | — |
| [T1219.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1219.002) Remote Desktop Software | In addition to directing victims to run remote software, Scattered Spider members themselves also deploy RMM software including TeamViewer, AnyDesk, LogMeIn, ngrok, and ConnectWise to establish persistence on the compromised network. | 221 | — | — |
| [T1572](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1572) Protocol Tunneling | Scattered Spider has installed protocol-tunneling tools on VMware vCenter and adversary-controlled VMs, including Teleport.sh, Chisel (configured to communicate with trycloudflare[.]com subdomains), MobaXterm, ngrok, Pinggy, and Teleport. | 173 | 9 | 1 |

### Exfiltration (TA0010) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1041](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1041) Exfiltration Over C2 Channel | Scattered Spider has exfiltrated data from compromised VMware vCenter servers through an established C2 channel using the Teleport remote access tool. | 135 | 2 | — |
| [T1567.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1567.002) Exfiltration to Cloud Storage | Scattered Spider has exfiltrated victim data to the MEGA file sharing site, SnowFlake, and AWS S3 buckets. | 85 | 2 | — |

### Impact (TA0040) — 3

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1486](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1486) Data Encrypted for Impact | Scattered Spider has used BlackCat and DragonForce ransomware to encrypt files including on VMWare ESXi servers. | 160 | 10 | 1 |
| [T1490](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1490) Inhibit System Recovery | Scattered Spider has stopped the Volume Shadow Copy service on compromised hosts. | 188 | 13 | 5 |
| [T1657](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1657) Financial Theft | Scattered Spider has deployed ransomware on compromised hosts and threatened to leak stolen data for financial gain. | 2 | — | — |

## 5. Assinatura comportamental

Técnicas que este grupo usa e que poucos dos 178 grupos do ATT&CK usam. Pesam mais numa atribuição por TTP: ver várias delas juntas é mais informativo do que ver técnicas comuns como PowerShell.

| Técnica | Outros grupos que usam | Peso (raridade) |
|---|---:|---:|
| T1538 Cloud Service Dashboard | 0 | 4.49 |
| T1556.006 Multi-Factor Authentication | 0 | 4.49 |
| T1006 Direct Volume Access | 1 | 4.09 |
| T1070.008 Clear Mailbox Data | 1 | 4.09 |
| T1204 User Execution | 1 | 4.09 |
| T1484.002 Trust Modification | 1 | 4.09 |
| T1556.009 Conditional Access Policies | 1 | 4.09 |
| T1564.008 Email Hiding Rules | 1 | 4.09 |
| T1578.002 Create Cloud Instance | 1 | 4.09 |
| T1598.004 Spearphishing Voice | 1 | 4.09 |

## 6. Arsenal

| Software | Tipo | Técnicas no ATT&CK | Uso relatado (EN) |
|---|---|---:|---|
| [Vidar](https://attack.mitre.org/software/S9050/) | malware | 53 |  |
| [WarzoneRAT](https://attack.mitre.org/software/S0670/) | malware | 30 | Scattered Spider has utilized WarzoneRAT to remotely access a compromised system. |
| [Raccoon Stealer](https://attack.mitre.org/software/S1148/) | malware | 24 |  |
| [BlackCat](https://attack.mitre.org/software/S1068/) | malware | 21 | Scattered Spider has deployed BlackCat ransomware to victim environments for financial gain. |
| [Mimikatz](https://attack.mitre.org/software/S0002/) | ferramenta | 17 | Scattered Spider has gathered credentials using Mimikatz. |
| [LaZagne](https://attack.mitre.org/software/S0349/) | ferramenta | 10 | Scattered Spider can obtain credential information using LaZagne. |
| [Rclone](https://attack.mitre.org/software/S1040/) | ferramenta | 6 |  |
| [ngrok](https://attack.mitre.org/software/S0508/) | ferramenta | 5 | Scattered Spider has used ngrok to create secure tunnels to remote web servers. |
| [ConnectWise](https://attack.mitre.org/software/S0591/) | ferramenta | 3 | Scattered Spider has used ConnectWise to maintain persistence. |
| [Tor](https://attack.mitre.org/software/S0183/) | ferramenta | 2 | Scattered Spider has used Tor to communicate with targeted organizations. |

**Outras ferramentas e malware relatados (planilha APT Groups & Operations / MISP):** Linpeas

### Ferramentas observadas em intrusões (Scattered Spider) — Ransomware Tool Matrix

Ferramentas legítimas e ofensivas que afiliados usam dentro da rede. Cada uma é um ponto de detecção: veja quantas regras do catálogo a citam.

| Ferramenta | Categoria | Regras que citam |
|---|---|---:|
| PsExec | lolbas | 260 |
| Mimikatz | credenciais | 253 |
| OpenSSH | rede | 130 |
| ProcDump | credenciais | 109 |
| TeamViewer | rmm | 104 |
| ScreenConnect | rmm | 93 |
| Impacket | offsec | 78 |
| MEGA | exfiltracao | 74 |
| Socat | rede | 71 |
| Dropbox | exfiltracao | 67 |
| PingCastle | descoberta | 66 |
| TryCloudflare | rede | 65 |
| Tailscale | rede | 60 |
| Ngrok | rede | 51 |
| Cloudflared | rede | 45 |
| SharpHound | descoberta | 44 |
| N-Able | rmm | 40 |
| RClone | exfiltracao | 35 |
| ADExplorer | descoberta | 32 |
| ADRecon | descoberta | 32 |
| Get-ADUser | descoberta | 29 |
| Plink | rede | 26 |
| Teleport | rede | 25 |
| Snaffler | credenciais | 22 |
| Trufflehog | credenciais | 20 |
| LINpeas | offsec | 19 |
| Splashtop | rmm | 19 |
| TightVNC | rmm | 19 |
| RPort | rmm | 18 |
| Advanced Port Scanner | descoberta | 16 |
| Parsec | rmm | 16 |
| TacticalRMM | rmm | 16 |
| Chrome Remote Desktop | rmm | 13 |
| RemotePC | rmm | 12 |
| Fleetdeck | rmm | 11 |
| Chisel | rede | 10 |
| Pacu | offsec | 10 |
| S3 Browser | descoberta | 10 |
| BeAnywhere | rmm | 9 |
| FileZilla | exfiltracao | 9 |
| MobaXterm | rmm | 9 |
| ZohoAssist | rmm | 8 |
| Level.io | rmm | 7 |
| Pulseway | rmm | 7 |
| RustDesk | rmm | 7 |
| PDQ Inventory | descoberta | 6 |
| Cyberduck | exfiltracao | 5 |
| aws_consoler | credenciais | 5 |
| Domotz | rmm | 4 |
| Twingate | rede | 4 |
| Windscribe (Wstunnel) | rede | 4 |
| DWAgent | rmm | 2 |
| ITarian | rmm | 2 |
| Sorillus | rmm | 1 |
| TrendMicro Basecamp | rmm | 1 |
| ZeroTier | rmm | 1 |
| ASG Remote Desktop | rmm | **0** |
| AWS Systems Manager Inventory | descoberta | **0** |
| Bedevil | evasao | **0** |
| CIMplant | offsec | **0** |
| GitGuardian | credenciais | **0** |
| Intel Ethernet driver (BYOVD) | evasao | **0** |
| Jecretz | credenciais | **0** |
| LAPS Toolkit | offsec | **0** |
| MAGNET RAM Capture | credenciais | **0** |
| MIT Kerberos Ticket Manager | credenciais | **0** |
| ManageEngine LANDESK | descoberta | **0** |
| ManageEngineRMM | rmm | **0** |
| MicroBurst | offsec | **0** |
| NSOCKS | rede | **0** |
| Pinggy | rede | **0** |
| Proxifier | rede | **0** |
| RSAT | rmm | **0** |
| RVTools | descoberta | **0** |
| Rsocks | rede | **0** |
| RustScan | descoberta | **0** |
| Sshimpanzee | rede | **0** |
| TrueSocks | rede | **0** |
| VMware PowerCLI | descoberta | **0** |
| Volatility | credenciais | **0** |
| Xeox | rmm | **0** |

## 7. Campanhas

| Campanha | Período | Resumo (EN) |
|---|---|---|
| [C0027](https://attack.mitre.org/campaigns/C0027/) | 2022-06 → 2022-12 | C0027 was a financially-motivated campaign linked to Scattered Spider that targeted telecommunications and business process outsourcing (BPO) companies from at least June through December of 2022. During C0027 Scattered  |

## 8. Cobertura defensiva

**61 de 64 técnicas (95%)** têm ao menos uma regra pública no catálogo Detection Rules.

### Técnicas sem regra pública (prioridade para engenharia de detecção)

- **T1598.004 Spearphishing Voice** — Reconnaissance. Fonte de log sugerida pelo MITRE: `Application Log` None
- **T1213.005 Messaging Applications** — Collection. Fonte de log sugerida pelo MITRE: `saas:slack` conversations.history, files.list, users.info, audit_logs; `m365:unified` TeamsMessagesAccessedViaEDiscovery, TeamsGraphMessageExport
- **T1598.003 Spearphishing Link** — Reconnaissance. Fonte de log sugerida pelo MITRE: `Application Log` None

### Onde procurar — cobertura por tecnologia

Quantas técnicas deste grupo têm ao menos uma regra em cada tecnologia. Comece a caça pelas tecnologias que você tem e que aparecem aqui.

| Tecnologia | Técnicas do grupo com regra |
|---|---:|
| Windows | 48 |
| AWS | 42 |
| EDR / XDR | 41 |
| Outros / genérico | 40 |
| Linux | 39 |
| Azure (recursos) | 38 |
| Microsoft 365 | 35 |
| Integridade, conformidade & vulnerabilidade | 31 |
| Servidores web & aplicações | 30 |
| Bancos de dados | 30 |
| Active Directory | 29 |
| Firewall & perímetro | 29 |

### Regras recomendadas por técnica

Melhor regra disponível por técnica (formato portável e maduro primeiro).

| Técnica | Regra | Formato | Fonte |
|---|---|---|---|
| T1003.003 | [Potential Russian APT Credential Theft Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab83f5166-9237-4b5e-9cd4-7b5d52f4d8ee) | Sigma | SigmaHQ |
| T1003.003 | [VolumeShadowCopy Symlink Creation Via Mklink](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A40b19fa6-d835-400c-b301-41f3a2baacaf) | Sigma | SigmaHQ |
| T1006 | [PowerShell Invoke-NinjaCopy script](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ab8386923-b02c-4b94-986a-d223d9b01f88) | Elastic | Elastic detection-rules |
| T1006 | [TCC Bypass via Mounted APFS Snapshot Access](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ab00bcd89-000c-4425-b94c-716ef67762f6) | Elastic | Elastic detection-rules |
| T1016 | [Potential Pikabot Discovery Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A698d4431-514f-4c82-af4d-cf573872a9f5) | Sigma | SigmaHQ |
| T1016 | [OpenCanary - SNMP OID Request](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae9856028-fd4e-46e6-b3d1-10f7ceb95078) | Sigma | SigmaHQ |
| T1018 | [Chopper Webshell Process Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Afa3c117a-bc0d-416e-a31b-0c0e80653efb) | Sigma | SigmaHQ |
| T1018 | [Webshell Hacking Activity Patterns](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4ebc877f-4612-45cb-b3a5-8e3834db36c9) | Sigma | SigmaHQ |
| T1021.001 | [Hermetic Wiper TG Process Patterns](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A2f974656-6d83-4059-bbdf-68ac5403422f) | Sigma | SigmaHQ |
| T1021.001 | [Publicly Accessible RDP Service](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1fc0809e-06bf-4de3-ad52-25e5263b7623) | Sigma | SigmaHQ |
| T1021.004 | [Potential THC Tool Downloaded](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A2ddc468e-b39b-4f5b-9825-f3dcb0e998ea) | Elastic | Elastic detection-rules |
| T1021.004 | [AWS EC2 CreateKeyPair by New Principal from Non-Cloud AS Organization](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ac8e4f1a2-9b3d-4c5e-a6f7-8b9c0d1e2f3a) | Elastic | Elastic detection-rules |
| T1021.007 | [AWS EC2 Instance Console Login via Assumed Role](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ad1e5e410-3e34-412e-9b1f-dd500b3b55cd) | Elastic | Elastic detection-rules |
| T1021.007 | [AWS SSM Session Started to EC2 Instance](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A804a7ac8-fc00-11ee-924b-f661ea17fbce) | Elastic | Elastic detection-rules |
| T1041 | [Equation Group C2 Communication](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A881834a4-6659-4773-821e-1c151789d873) | Sigma | SigmaHQ |
| T1041 | [OpenCanary - TFTP Request](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab4e6b016-a2ac-4759-ad85-8000b300d61e) | Sigma | SigmaHQ |
| T1059.001 | [Potential Emotet Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad02e8cf5-6099-48cf-9bfc-1eec2d0c7b18) | Sigma | SigmaHQ |
| T1059.001 | [TropicTrooper Campaign November 2018](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A8c7090c3-e0a0-4944-bd08-08c3a0cecf79) | Sigma | SigmaHQ |
| T1059.004 | [Shell Invocation via Env Command - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Abed978f8-7f3a-432b-82c5-9286a9b3031a) | Sigma | SigmaHQ |
| T1059.004 | [Suspicious Reverse Shell Command Line](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A738d9bcf-6999-4fdb-b4ac-3033037db8ab) | Sigma | SigmaHQ |
| T1068 | [Exploiting CVE-2019-1388](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A02e0b2ea-a597-428e-b04a-af6a1a403e5c) | Sigma | SigmaHQ |
| T1068 | [OMIGOD HTTP No Authentication RCE - CVE-2021-38647](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aab6b1a39-a9ee-4ab4-b075-e83acf6e346b) | Sigma | SigmaHQ |
| T1069 | [Malicious PowerShell Commandlets - ProcessCreation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A02030f2f-6199-49ec-b258-ea71b07e03dc) | Sigma | SigmaHQ |
| T1069 | [Malicious PowerShell Commandlets - ScriptBlock](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A89819aa4-bbd6-46bc-88ec-c7f7fe30efa6) | Sigma | SigmaHQ |
| T1069.002 | [BloodHound Collection Files](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A02773bed-83bf-469f-b7ff-e676e7d78bab) | Sigma | SigmaHQ |
| T1069.002 | [HackTool - SharpView Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab2317cfa-4a47-4ead-b3ff-297438c0bc2d) | Sigma | SigmaHQ |
| T1070.008 | [Access To Windows Outlook Mail Files By Uncommon Applications](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Afc3e237f-2fef-406c-b90d-b3ae7e02fa8f) | Sigma | SigmaHQ |
| T1070.008 | [Windows Mail App Mailbox Access Via PowerShell Script](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4e485d01-e18a-43f6-a46b-ef20496fa9d3) | Sigma | SigmaHQ |
| T1074 | [Sensitive File Access followed by Compression](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Aa0fbd7a9-1923-4e05-92df-b484168f17bc) | Elastic | Elastic detection-rules |
| T1074 | [Cisco Stage Data](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A5e51acb2-bcbe-435b-99c6-0e3cd5e2aa59) | Sigma | SigmaHQ |
| T1078 | [Privilege Role Sign-In Outside Expected Controls](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acf1e5687-84e1-41af-97a9-158094efef53) | Sigma | SigmaHQ |
| T1078 | [OpenCanary - SSH Login Attempt](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aff7139bc-fdb1-4437-92f2-6afefe8884cb) | Sigma | SigmaHQ |
| T1078.004 | [Okta New Admin Console Behaviours](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aa0b38b70-3cb5-484b-a4eb-c4d8e7bcc0a9) | Sigma | SigmaHQ |
| T1078.004 | [AWS IAM S3Browser User or AccessKey Creation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Adb014773-d9d9-4792-91e5-133337c0ffee) | Sigma | SigmaHQ |
| T1082 | [Potential GobRAT File Discovery Via Grep](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae34cfa0c-0a50-4210-9cb3-5632d08eb041) | Sigma | SigmaHQ |
| T1082 | [System Information Discovery](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A42df45e7-e6e9-43b5-8f26-bec5b39cc239) | Sigma | SigmaHQ |
| T1083 | [Turla Group Lateral Movement](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac601f20d-570a-4cde-a7d6-e17f99cb8e7f) | Sigma | SigmaHQ |
| T1083 | [WannaCry Ransomware Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A41d40bff-377a-43e2-8e1b-2e543069e079) | Sigma | SigmaHQ |
| T1087 | [Potential Pikabot Discovery Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A698d4431-514f-4c82-af4d-cf573872a9f5) | Sigma | SigmaHQ |
| T1087 | [HackTool - winPEAS Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A98b53e78-ebaf-46f8-be06-421aafd176d9) | Sigma | SigmaHQ |
| T1087.002 | [BloodHound Collection Files](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A02773bed-83bf-469f-b7ff-e676e7d78bab) | Sigma | SigmaHQ |
| T1087.002 | [Suspicious Active Directory Database Snapshot Via ADExplorer](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aef61af62-bc74-4f58-b49b-626448227652) | Sigma | SigmaHQ |
| T1090 | [Communication To LocaltoNet Tunneling Service Initiated - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac4568f5d-131f-4e78-83d4-45b2da0ec4f1) | Sigma | SigmaHQ |
| T1090 | [Communication To Ngrok Tunneling Service - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A19bf6fdb-7721-4f3d-867f-53467f6a5db6) | Sigma | SigmaHQ |
| T1098 | [Password Change on Directory Service Restore Mode (DSRM) Account](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A53ad8e36-f573-46bf-97e4-15ba5bf4bb51) | Sigma | SigmaHQ |
| T1098 | [User Added To Global Domain Admins Grp](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=hayabusa-native%3A%3A4bb89c86-a138-42a0-baaf-fc2f777a4506) | Sigma | Hayabusa (native) |
| T1098.003 | [App Granted Privileged Delegated Or App Permissions](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A5aecf3d5-f8a0-48e7-99be-3a759df7358f) | Sigma | SigmaHQ |
| T1098.003 | [App Granted Privileged Delegated Or App Permissions](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A5aecf3d5-f8a0-48e7-99be-3a759df7358f) | Sigma | OpenSearch Security Analytics |
| T1105 | [Greenbug Espionage Group Indicators](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A3711eee4-a808-4849-8a14-faf733da3612) | Sigma | SigmaHQ |
| T1105 | [Pandemic Registry Key](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A47e0852a-cf81-4494-a8e6-31864f8c86ed) | Sigma | SigmaHQ |
| T1114 | [Exchange PowerShell Snap-Ins Usage](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A25676e10-2121-446e-80a4-71ff8506af47) | Sigma | SigmaHQ |
| T1114 | [Hacktool Ruler](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A24549159-ac1b-479c-8175-d42aea947cae) | Sigma | SigmaHQ |
| T1114.003 | [Google Workspace Gmail Routing or Forwarding Rule Created or Modified](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A9510add4-3392-11ed-bd01-f661ea17fbce) | Elastic | Elastic detection-rules |
| T1114.003 | [Mail Forwarding/Redirecting Activity In O365](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac726e007-2cd0-4a55-abfb-79730fbedee5) | Sigma | SigmaHQ |
| T1133 | [OpenCanary - SSH Login Attempt](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aff7139bc-fdb1-4437-92f2-6afefe8884cb) | Sigma | SigmaHQ |
| T1133 | [OpenCanary - SSH New Connection Attempt](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acd55f721-5623-4663-bd9b-5229cab5237d) | Sigma | SigmaHQ |
| T1136 | [FortiGate SSO Login Followed by Administrator Account Creation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ae3a7b1c2-5d9f-4e8a-b6c3-2f1d4e5a6b7c) | Elastic | Elastic detection-rules |
| T1136 | [Potential Linux Backdoor User Account Creation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A494ebba4-ecb7-4be4-8c6f-654c686549ad) | Elastic | Elastic detection-rules |
| T1204 | [Potential Snatch Ransomware Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A5325945e-f1f0-406e-97b8-65104d393fff) | Sigma | SigmaHQ |
| T1204 | [Antivirus - Hacktool Signature](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Afa0c05b6-8ad3-468d-8231-c1cbccb64fba) | Sigma | SigmaHQ |
| T1213.003 | [Bitbucket Unauthorized Full Data Export Triggered](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A34d81081-03c9-4a7f-91c9-5e46af625cde) | Sigma | SigmaHQ |
| T1213.003 | [Bitbucket Full Data Export Triggered](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A195e1b9d-bfc2-4ffa-ab4e-35aef69815f8) | Sigma | SigmaHQ |
| T1217 | [File And SubFolder Enumeration Via Dir Command](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A7c9340a9-e2ee-4e43-94c5-c54ebbea1006) | Sigma | SigmaHQ |
| T1217 | [Suspicious Where Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A725a9768-0f5e-4cb3-aec2-bc5719c6831a) | Sigma | SigmaHQ |
| T1219.002 | [Antivirus - Exploitation Framework Signature](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A238527ad-3c2c-4e4f-a1f6-92fd63adb864) | Sigma | SigmaHQ |
| T1219.002 | [Potential SocGholish Second Stage C2 DNS Query](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A70761fe8-6aa2-4f80-98c1-a57049c08e66) | Sigma | SigmaHQ |
| T1484.002 | [Domain Added to Google Workspace Trusted Domains](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Acf549724-c577-4fd6-8f9b-d1b8ec519ec0) | Elastic | Elastic detection-rules |
| T1484.002 | [AWS IAM OIDC Provider Created by Rare User](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A47403d72-3ee2-4752-a676-19dc8ff2b9d6) | Elastic | Elastic detection-rules |
| T1486 | [LockerGoga Ransomware Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A74db3488-fd28-480a-95aa-b7af626de068) | Sigma | SigmaHQ |
| T1486 | [LockerGoga Ransomware](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A74db3488-fd28-480a-95aa-b7af626de068) | Sigma | OpenSearch Security Analytics |
| T1490 | [Potential Dtrack RAT Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Af1531fa4-5b84-4342-8f68-9cf3fdbd83d4) | Sigma | SigmaHQ |
| T1490 | [Boot Configuration Tampering Via Bcdedit.EXE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1444443e-6757-43e4-9ea4-c8fc705f79a2) | Sigma | SigmaHQ |
| T1530 | [Google Workspace Drive Encryption Key(s) Accessed from Anonymous User](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A980b70a0-c820-11ed-8799-f661ea17fbcc) | Elastic | Elastic detection-rules |
| T1530 | [AWS CloudTrail Log Updated](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A3e002465-876f-4f04-b016-84ef48ce7e5d) | Elastic | Elastic detection-rules |
| T1538 | [AWS SSM Inventory Reconnaissance by Rare User](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A1004ad5b-6900-4d28-ab5b-472f02e1fdfb) | Elastic | Elastic detection-rules |
| T1538 | [Okta Multiple Failed Requests to Access Applications](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=splunk-security-content%3A%3A1c21fed1-7000-4a2e-9105-5aaafa437247) | Splunk | Splunk security_content |
| T1539 | [SQLite Firefox Profile Data DB Access](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4833155a-4053-4c9c-a997-777fcea0baa7) | Sigma | SigmaHQ |
| T1539 | [SQLite Chromium Profile Data DB Access](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A24c77512-782b-448a-8950-eddb0785fc71) | Sigma | SigmaHQ |
| T1543.002 | [LiteLLM / TeamPCP Supply Chain Attack Indicators](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A36603778-030c-43c4-8cbb-cd3c1d1a80c7) | Sigma | SigmaHQ |
| T1543.002 | [TeamPCP LiteLLM Supply Chain Attack Persistence Indicators](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A81c0b7f5-81c9-435e-a291-bc32fc2b72cd) | Sigma | SigmaHQ |
| T1552.001 | [Potential Russian APT Credential Theft Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab83f5166-9237-4b5e-9cd4-7b5d52f4d8ee) | Sigma | SigmaHQ |
| T1552.001 | [Copy Passwd Or Shadow From TMP Path](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Afa4aaed5-4fe0-498d-bbc0-08e3346387ba) | Sigma | SigmaHQ |
| T1552.004 | [Cisco Crypto Commands](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1f978c6a-4415-47fb-aca5-736a44d7ca3d) | Sigma | SigmaHQ |
| T1552.004 | [DPAPI Backup Keys And Certificate Export Activity IOC](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A7892ec59-c5bb-496d-8968-e5d210ca3ac4) | Sigma | SigmaHQ |
| T1553.002 | [Driver Loaded (Invalid Signature)](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=hayabusa-native%3A%3A1f666722-3948-40a2-9d78-d9d374477a90) | Sigma | Hayabusa (native) |
| T1553.002 | [Driver Loaded (Expired/Revoked Cert)](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=hayabusa-native%3A%3Ac837dd6d-0c91-4593-aeab-f6a1f3ca1961) | Sigma | Hayabusa (native) |
| T1555.005 | [Remote Thread Created In KeePass.EXE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A77564cc2-7382-438b-a7f6-395c2ae53b9a) | Sigma | SigmaHQ |
| T1555.005 | [KeePass Password Dumping](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A77564cc2-7382-438b-a7f6-395c2ae53b9a) | Sigma | OpenSearch Security Analytics |
| T1556.006 | [Disabling Multi Factor Authentication](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A60de9b57-dc4d-48b9-a6a0-b39e0469f876) | Sigma | SigmaHQ |
| T1556.006 | [Google Workspace MFA Enforcement Disabled For Organization](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Acad4500a-abd7-4ef3-b5d3-95524de7cfe1) | Elastic | Elastic detection-rules |
| T1556.009 | [Entra ID Conditional Access Policy (CAP) Modified](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Abc48bba7-4a23-4232-b551-eca3ca1e3f20) | Elastic | Elastic detection-rules |
| T1556.009 | [AWS RDS DB Instance Made Public](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A9efb3f79-b77b-466a-9fa0-3645d22d1e7f) | Elastic | Elastic detection-rules |
| T1564.008 | [M365 Exchange Inbox Phishing Evasion Rule Created](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A40fe11c2-376e-11f0-9a82-f661ea17fbcd) | Elastic | Elastic detection-rules |
| T1564.008 | [Mail Forwarding/Redirecting Activity In O365](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac726e007-2cd0-4a55-abfb-79730fbedee5) | Sigma | SigmaHQ |
| T1567.002 | [APT40 Dropbox Tool User Agent](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A5ba715b6-71b7-44fd-8245-f66893e81b3d) | Sigma | SigmaHQ |
| T1567.002 | [PUA - Rclone Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae37db05d-d1f9-49c8-b464-cee1a4b11638) | Sigma | SigmaHQ |
| T1572 | [Communication To LocaltoNet Tunneling Service Initiated - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac4568f5d-131f-4e78-83d4-45b2da0ec4f1) | Sigma | SigmaHQ |
| T1572 | [Communication To Ngrok Tunneling Service - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A19bf6fdb-7721-4f3d-867f-53467f6a5db6) | Sigma | SigmaHQ |
| T1578.002 | [AWS RDS DB Instance Restored](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Abf1073bf-ce26-4607-b405-ba1ed8e9e204) | Elastic | Elastic detection-rules |
| T1578.002 | [Azure VM Extension Deployment by User](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ae842d39d-ead1-48c6-97f1-6b055476c2f3) | Elastic | Elastic detection-rules |
| T1580 | [AWS Discovery API Calls from VPN ASN for the First Time by Identity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ae3c7a891-4b2d-4e8c-a1f0-9d8e7c6b5a4d) | Elastic | Elastic detection-rules |
| T1580 | [Entra ID Sign-in BloodHound Suite User-Agent Detected](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ac28750fa-4092-11f0-aca6-f661ea17fbcd) | Elastic | Elastic detection-rules |
| T1583.001 | [AWS Route 53 Private Hosted Zone Associated With a VPC](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ae3c27562-709a-42bd-82f2-3ed926cced19) | Elastic | Elastic detection-rules |
| T1583.001 | [AWS SES Email Identity Verified Then Deleted](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A8e4bde35-125d-4eb3-9a2e-d7e77a053a08) | Elastic | Elastic detection-rules |
| T1585.001 | [CYFIRMA - Brand Intelligence - Social Media Handle Impersonation Detected High Rule](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A22f49d67-7da7-4809-8d07-89e4478aa6b0) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1585.001 | [CYFIRMA - Brand Intelligence - Executive/People Impersonation High Rule](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A159d26a1-591c-4f70-b1ca-2843c881aaec) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1588.001 | [Relevant ClamAV Message](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A36aa86ca-fd9d-4456-814e-d3b1b8e1e0bb) | Sigma | SigmaHQ |
| T1588.001 | [Relevant ClamAV Message](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A36aa86ca-fd9d-4456-814e-d3b1b8e1e0bb) | Sigma | OpenSearch Security Analytics |
| T1588.002 | [Hacktool Execution - Imphash](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A24e3e58a-646b-4b50-adef-02ef935b9fc8) | Sigma | SigmaHQ |
| T1588.002 | [Renamed SysInternals DebugView Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acd764533-2e07-40d6-a718-cfeec7f2da7f) | Sigma | SigmaHQ |
| T1589 | [SSHD Error Message CVE-2018-15473](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4c9d903d-4939-4094-ade0-3cb748f4d7da) | Sigma | SigmaHQ |
| T1589 | [SSHD Error Message CVE-2018-15473](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A4c9d903d-4939-4094-ade0-3cb748f4d7da) | Sigma | OpenSearch Security Analytics |
| T1598 | [CyberBlindSpot - Any Issue Detected](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3Aabe1a662-d00d-482e-aa68-9394622ae02e) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1598 | [Proofpoint Phishing Email Detected](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=panther-panther-analysis%3A%3AProofpoint.PhishingDetected) | Panther | Panther panther-analysis |
| T1621 | [Potentially Successful Okta MFA Bombing via Push Notifications](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A97a8e584-fd3b-421f-9b9d-9c9d9e57e9d7) | Elastic | Elastic detection-rules |
| T1621 | [Potential Okta MFA Bombing via Push Notifications](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A8a0fbd26-867f-11ee-947c-f661ea17fbcd) | Elastic | Elastic detection-rules |
| T1657 | [AWS S3 Bucket Enumeration or Brute Force](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A5f0234fd-7f21-42af-8391-511d5fd11d5c) | Elastic | Elastic detection-rules |
| T1657 | [Monitor ransomwarelive for companies of interest on ransowmare data leak sites (DLS)](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=bert-janp-hunting-queries%3A%3A8b9af12a820a) | KQL hunting | Bert-JanP Hunting Queries |
| T1684.001 | [Entra ID OAuth user_impersonation Scope for Unusual User and Client](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A9563dace-5822-11f0-b1d3-f661ea17fbcd) | Elastic | Elastic detection-rules |
| T1685 | [Windows Defender Configuration Changes](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A801bd44f-ceed-4eb6-887c-11544633c0aa) | Sigma | SigmaHQ |
| T1685 | [Windows Defender Virus Scanning Feature Disabled](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A686c0b4b-9dd3-4847-9077-d6c1bbe36fcb) | Sigma | SigmaHQ |

## 9. Plano de emulação e validação

Use num laboratório isolado e autorizado para confirmar que as regras disparam. Os comandos estão nos repositórios oficiais.

| Tática | Técnica | Teste Atomic Red Team | Plataformas |
|---|---|---|---|
| Execution | [T1059.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md) | Mimikatz | windows |
| Execution | [T1059.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md) | Run BloodHound from local disk | windows |
| Execution | [T1059.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.004/T1059.004.md) | Create and Execute Bash Shell Script | linux, macos |
| Execution | [T1059.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.004/T1059.004.md) | Command-Line Interface | linux, macos |
| Persistence | [T1098](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1098/T1098.md) | Admin Account Manipulate | windows |
| Persistence | [T1098](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1098/T1098.md) | Domain Account and Group Manipulate | windows |
| Persistence | [T1098.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1098.003/T1098.003.md) | Azure AD - Add Company Administrator Role to a user | azure-ad |
| Persistence | [T1098.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1098.003/T1098.003.md) | Simulate - Post BEC persistence via user password reset followed by user added to company administrator role | azure-ad |
| Persistence | [T1133](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1133/T1133.md) | Running Chrome VPN Extensions via the Registry 2 vpn extension | windows |
| Persistence | [T1543.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1543.002/T1543.002.md) | Create Systemd Service | linux |
| Persistence | [T1543.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1543.002/T1543.002.md) | Create SysV Service | linux |
| Privilege Escalation | [T1068](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1068/T1068.md) | Scattered Spider BYOVD (CVE-2015-2291 for Intel Ethernet Diagnostics Driver) | windows |
| Privilege Escalation | [T1068](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1068/T1068.md) | Turla Snake Malware Privilege Escalation Through VM Driver | windows |
| Stealth | [T1006](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1006/T1006.md) | Read volume boot sector via DOS device path (PowerShell) | windows |
| Stealth | [T1070.008](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.008/T1070.008.md) | Copy and Delete Mailbox Data on Windows | windows |
| Stealth | [T1070.008](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.008/T1070.008.md) | Copy and Delete Mailbox Data on Linux | linux |
| Stealth | [T1078.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1078.004/T1078.004.md) | Creating GCP Service Account and Service Account Key | google-workspace, iaas:gcp |
| Stealth | [T1078.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1078.004/T1078.004.md) | Azure Persistence Automation Runbook Created or Modified | iaas:azure |
| Stealth | [T1564.008](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1564.008/T1564.008.md) | New-Inbox Rule to Hide E-mail in M365 | office-365 |
| Defense Impairment | [T1484.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1484.002/T1484.002.md) | Add Federation to Azure AD | azure-ad |
| Defense Impairment | [T1685](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1685/T1685.md) | Windows Disable LSA Protection | windows |
| Defense Impairment | [T1685](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1685/T1685.md) | Disable journal logging via systemctl utility | linux |
| Credential Access | [T1003.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.003/T1003.003.md) | Create Volume Shadow Copy with vssadmin | windows |
| Credential Access | [T1003.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.003/T1003.003.md) | Copy NTDS.dit from Volume Shadow Copy | windows |
| Credential Access | [T1539](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1539/T1539.md) | Steal Firefox Cookies (Windows) | windows |
| Credential Access | [T1539](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1539/T1539.md) | Steal Chrome Cookies (Windows) | windows |
| Credential Access | [T1552.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1552.001/T1552.001.md) | Find AWS credentials | linux, macos |
| Credential Access | [T1552.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1552.001/T1552.001.md) | Extract Browser and System credentials with LaZagne | macos |
| Credential Access | [T1552.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1552.004/T1552.004.md) | Private Keys | windows |
| Credential Access | [T1552.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1552.004/T1552.004.md) | Discover Private SSH Keys | linux, macos |
| Discovery | [T1016](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1016/T1016.md) | System Network Configuration Discovery on Windows | windows |
| Discovery | [T1016](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1016/T1016.md) | List Windows Firewall Rules | windows |
| Discovery | [T1018](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1018/T1018.md) | Remote System Discovery - net | windows |
| Discovery | [T1018](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1018/T1018.md) | Remote System Discovery - net group Domain Computers | windows |
| Discovery | [T1069.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1069.002/T1069.002.md) | Basic Permission Groups Discovery Windows (Domain) | windows |
| Discovery | [T1069.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1069.002/T1069.002.md) | Permission Groups Discovery PowerShell (Domain) | windows |
| Discovery | [T1082](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1082/T1082.md) | System Information Discovery | windows |
| Discovery | [T1082](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1082/T1082.md) | System Information Discovery | macos |
| Discovery | [T1083](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1083/T1083.md) | File and Directory Discovery (cmd.exe) | windows |
| Discovery | [T1083](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1083/T1083.md) | File and Directory Discovery (PowerShell) | windows |
| Discovery | [T1087.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1087.002/T1087.002.md) | Enumerate all accounts (Domain) | windows |
| Discovery | [T1087.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1087.002/T1087.002.md) | Enumerate all accounts via PowerShell (Domain) | windows |
| Discovery | [T1217](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1217/T1217.md) | List Mozilla Firefox Bookmark Database Files on FreeBSD/Linux | linux |
| Discovery | [T1217](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1217/T1217.md) | List Mozilla Firefox Bookmark Database Files on macOS | macos |
| Discovery | [T1580](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1580/T1580.md) | AWS - EC2 Enumeration from Cloud Instance | iaas:aws, linux, macos |
| Discovery | [T1580](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1580/T1580.md) | AWS - EC2 Security Group Enumeration | iaas:aws |
| Lateral Movement | [T1021.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.001/T1021.001.md) | RDP to Remote Host | windows |
| Lateral Movement | [T1021.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.001/T1021.001.md) | Changing RDP Port to Non Standard Port via Powershell | windows |
| Lateral Movement | [T1021.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.004/T1021.004.md) | ESXi - Enable SSH via PowerCLI | windows |
| Lateral Movement | [T1021.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.004/T1021.004.md) | ESXi - Enable SSH via VIM-CMD | windows |
| Collection | [T1114.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1114.003/T1114.003.md) | Office365 - Email Forwarding | office-365 |
| Collection | [T1530](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1530/T1530.md) | AWS - Scan for Anonymous Access to S3 | iaas:aws |
| Collection | [T1530](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1530/T1530.md) | Azure - Dump Azure Storage Account Objects via Azure CLI | iaas:azure |
| Command and Control | [T1105](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1105/T1105.md) | rsync remote file copy (push) | linux, macos |
| Command and Control | [T1105](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1105/T1105.md) | rsync remote file copy (pull) | linux, macos |
| Command and Control | [T1572](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1572/T1572.md) | DNS over HTTPS Large Query Volume | windows |
| Command and Control | [T1572](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1572/T1572.md) | DNS over HTTPS Regular Beaconing | windows |
| Exfiltration | [T1041](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1041/T1041.md) | C2 Data Exfiltration | windows |
| Exfiltration | [T1041](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1041/T1041.md) | Text Based Data Exfiltration using DNS subdomains | windows |
| Exfiltration | [T1567.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1567.002/T1567.002.md) | Exfiltrate data with rclone to cloud Storage - Mega (Windows) | windows |
| Exfiltration | [T1567.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1567.002/T1567.002.md) | Exfiltrate data with rclone to cloud Storage - AWS S3 | linux, macos |
| Impact | [T1486](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1486/T1486.md) | Encrypt files using gpg (FreeBSD/Linux) | linux |
| Impact | [T1486](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1486/T1486.md) | Encrypt files using 7z (FreeBSD/Linux) | linux |
| Impact | [T1490](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1490/T1490.md) | Windows - Delete Volume Shadow Copies | windows |
| Impact | [T1490](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1490/T1490.md) | Windows - Delete Volume Shadow Copies via WMI | windows |

**Logs reais de ataque (EVTX) para testar sem executar nada:**

- T1003.003 — [dc_applog_ntdsutil_dfir_325_326_327](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Credential%20Access/dc_applog_ntdsutil_dfir_325_326_327.evtx) _(inferido)_
- T1003.003 — [LM_regsvc_DirectoryServiceExtPt_Lsass_NTDS_AdamXpn](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Lateral%20Movement/LM_regsvc_DirectoryServiceExtPt_Lsass_NTDS_AdamXpn.evtx) _(inferido)_
- T1016 — [ID4688-Audit policy enumerated](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1016-System%20Network%20Configuration%20Discovery/ID4688-Audit%20policy%20enumerated.evtx) _(explícito)_
- T1016 — [ID4688-Firewall configuration enumerated (command)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1016-System%20Network%20Configuration%20Discovery/ID4688-Firewall%20configuration%20enumerated%20%28command%29.evtx) _(explícito)_
- T1018 — [ID5145-DNS hosts files access via network share](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1018-Remote%20System%20Discovery/ID5145-DNS%20hosts%20files%20access%20via%20network%20share.evtx) _(explícito)_
- T1021.001 — [ID4688,4778,4779 RDP hijack direct](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0008-Lateral%20Movement/T1021.001-Remote%20Desktop%20Protocol/ID4688%2C4778%2C4779%20RDP%20hijack%20direct.evtx) _(explícito)_
- T1021.001 — [ID4688-4778 RDP hijack command execution](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0008-Lateral%20Movement/T1021.001-Remote%20Desktop%20Protocol/ID4688-4778%20RDP%20hijack%20command%20execution.evtx) _(explícito)_
- T1021.004 — [ID4-OpenSSH server listening](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0008-Lateral%20Movement/T1021.004-Remote%20Service%20SSH/ID4-OpenSSH%20server%20listening.evtx) _(explícito)_
- T1021.004 — [ID4103-4104-OpenSSH server activation and config](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0008-Lateral%20Movement/T1021.004-Remote%20Service%20SSH/ID4103-4104-OpenSSH%20server%20activation%20and%20config.evtx) _(explícito)_
- T1059.001 — [ID4103-4104-Payload download via PowerShell](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1059.001-PowerShell/ID4103-4104-Payload%20download%20via%20PowerShell.evtx) _(explícito)_
- T1059.001 — [ID4688-Encoded PowerShell MSF payload via process execution](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1059.001-PowerShell/ID4688-Encoded%20PowerShell%20MSF%20payload%20via%20process%20execution.evtx) _(explícito)_
- T1068 — [ID12-13 Mini_Plasma_PoC_AbortHydration_ArbitraryRegKey_EoP](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0004-Privilege%20Escalation/T1068-Exploitation%20for%20Privilege%20Escalation/ID12-13%20Mini_Plasma_PoC_AbortHydration_ArbitraryRegKey_EoP.evtx) _(explícito)_
- T1068 — [ID4673-Privilege SeMachineAccountPrivilege called](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0004-Privilege%20Escalation/T1068-Exploitation%20for%20Privilege%20Escalation/ID4673-Privilege%20SeMachineAccountPrivilege%20called.evtx) _(explícito)_
- T1069 — [ID4661-Local group enumeration with RID brutforce with CME](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1069-Permission%20Groups%20Discovery/ID4661-Local%20group%20enumeration%20with%20RID%20brutforce%20with%20CME.evtx) _(explícito)_
- T1069 — [ID4661-SAM sensitive domain users & groups discovery](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1069-Permission%20Groups%20Discovery/ID4661-SAM%20sensitive%20domain%20users%20%26%20groups%20discovery.evtx) _(explícito)_
- T1078 — [ID1149-RDP success logins to multiple hosts](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0001-Initial%20access/T1078-Valid%20accounts/ID1149-RDP%20success%20logins%20to%20multiple%20hosts.evtx) _(explícito)_
- T1078 — [ID33205-SQL Server failed login with disabled SA account](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0001-Initial%20access/T1078-Valid%20accounts/ID33205-SQL%20Server%20failed%20login%20with%20disabled%20SA%20account.evtx) _(explícito)_
- T1087 — [ID1-SPN discovery (SYSMON process)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1087-Account%20discovery/ID1-SPN%20discovery%20%28SYSMON%20process%29.evtx) _(explícito)_
- T1087 — [ID4103-4104 - SPN discovery (moder nPowerShell)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1087-Account%20discovery/ID4103-4104%20-%20SPN%20discovery%20%28moder%20nPowerShell%29.evtx) _(explícito)_
- T1087.002 — [discovery_bloodhound](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Discovery/discovery_bloodhound.evtx) _(inferido)_
- T1090 — [ID5600-proxy configuration changed](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0011-Command%20and%20Control/T1090-Proxy/ID5600-proxy%20configuration%20changed.evtx) _(explícito)_
- T1098 — [ID33205-SQL Server member added to database role](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0003-Persistence/T1098.xxx-Account%20manipulation/ID33205-SQL%20Server%20member%20added%20to%20database%20role.evtx) _(explícito)_
- T1098 — [ID33205-SQL Server member added to server role](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0003-Persistence/T1098.xxx-Account%20manipulation/ID33205-SQL%20Server%20member%20added%20to%20server%20role.evtx) _(explícito)_
- T1136 — [ID33205-SQL Server Disabled SA user activated](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0003-Persistence/T1136-Create%20account/ID33205-SQL%20Server%20Disabled%20SA%20user%20activated.evtx) _(explícito)_
- T1136 — [ID33205-SQL Server local user created](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0003-Persistence/T1136-Create%20account/ID33205-SQL%20Server%20local%20user%20created.evtx) _(explícito)_

## 10. Hipóteses de hunting

Se Scattered Spider estiver no seu ambiente, estas são as perguntas a fazer aos seus dados (fontes de log segundo as estratégias de detecção do MITRE ATT&CK).

1. **T1538 Cloud Service Dashboard** — Detects web console login events followed by read-only or metadata retrieval activity from GUI sources (e.g., browser session, mobile client) rather than API/CLI sources. Correlates across CloudTrail, IAM identity logs, and user-agent context. Dados: `AWS:CloudTrail` (ConsoleLogin), `AWS:CloudTrail` (Post-authentication metadata enumeration from GUI session).
2. **T1556.006 Multi-Factor Authentication** — Detects registry and Group Policy modifications that disable or weaken MFA, suspicious PowerShell usage modifying MFA-related attributes, and anomalous login sessions succeeding without expected MFA challenge. Dados: `WinEventLog:Security` (EventCode=4739), `WinEventLog:PowerShell` (Set-ADUser or Set-ADAuthenticationPolicy with MFA attributes disabled).
3. **T1006 Direct Volume Access** — Processes accessing raw logical drives (e.g., \.\C:) to bypass file system protections or directly manipulate data structures. Dados: `WinEventLog:Sysmon` (EventCode=10), `WinEventLog:Security` (EventCode=4688).
4. **T1070.008 Clear Mailbox Data** — Detects mailbox manipulation or deletion via PowerShell (e.g., Remove-MailboxExportRequest), file deletion from Outlook data stores (Unistore.db), or tampering with quarantined mail logs. Dados: `WinEventLog:PowerShell` (EventCode=4103, 4104, 4105, 4106), `WinEventLog:Sysmon` (EventCode=23), `WinEventLog:Security` (EventCode=4663, 4670, 4656).
5. **T1204 User Execution** — Cause→effect chain: (1) User-facing app (Office/PDF/archiver/browser) records an open/click or abnormal event, then (2) a downloaded file is created in a user-writable path and/or decompressed, (3) the parent user app spawns a living-off-the-land binary… Dados: `WinEventLog:Application` (EventCode=1000), `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Security` (EventCode=4688).
6. **T1484.002 Trust Modification** — Adversary modifies Active Directory domain trust settings via `netdom`, `nltest`, or PowerShell to add new domain trust or alter federation. Modifications occur in AD object attributes like trustDirection, trustType, trustAttributes, often paired with… Dados: `WinEventLog:Security` (EventCode=5136), `WinEventLog:Security` (EventCode=4704), `WinEventLog:Sysmon` (EventCode=1).
7. **T1556.009 Conditional Access Policies** — Detects modifications to IAM conditions or policies that alter authentication behavior, such as adding permissive trusted IPs, removing MFA requirements, or changing regional access restrictions. Behavioral detection focuses on anomalous policy updates tied… Dados: `AWS:CloudTrail` (PutUserPolicy, PutGroupPolicy, PutRolePolicy, CreatePolicyVersion).
8. **T1564.008 Email Hiding Rules** — Suspicious creation or modification of inbox rules through PowerShell (New-InboxRule, Set-InboxRule) to automatically delete, move, or hide emails. Defender perspective: unusual rule activity correlated with mailbox access and filtering patterns. Dados: `WinEventLog:PowerShell` (EventCode=4103, 4104, 4105, 4106), `m365:unified` (New-InboxRule or Set-InboxRule events recorded in Exchange Online).
9. **T1578.002 Create Cloud Instance** — Detection focuses on abnormal or unauthorized cloud instance creation events. From a defender’s perspective, suspicious behavior includes VM/instance creation by rarely used or newly created accounts, creation events from unusual geolocations, or rapid… Dados: `AWS:CloudTrail` (RunInstances), `AWS:CloudTrail` (DescribeInstances), `azure:activity` (MICROSOFT.COMPUTE/VIRTUALMACHINES/WRITE).
10. **T1598.004 Spearphishing Voice** — Monitor call logs from corporate devices to identify patterns of potential voice phishing, such as calls to/from known malicious phone numbers. Dados: `Application Log` (None).
11. **T1021.007 Cloud Services** — Cloud login from atypical geolocation or user-agent string, followed by resource enumeration or infrastructure manipulation using cloud CLI/API Dados: `AWS:CloudTrail` (ConsoleLogin, AssumeRole, ListResources), `gcp:audit` (None).
12. **T1087 Account Discovery** — Detection of processes performing local or domain account enumeration by invoking account directory queries or security APIs followed by structured output of account lists. The defender observes command execution or API invocation patterns that retrieve… Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Security` (EventCode=4688), `WinEventLog:Security` (EventCode=4798, 4799).

## 11. OSINT — onde pesquisar

Consultas prontas com todos os nomes conhecidos do grupo:

- Relatórios técnicos: [busca web](https://duckduckgo.com/?q=%28%22Scattered+Spider%22+OR+%22Roasted+0ktapus%22+OR+%22Octo+Tempest%22+OR+%22Storm-0875%22+OR+%22UNC3944%22%29+threat+report) · [PDFs](https://duckduckgo.com/?q=%28%22Scattered+Spider%22+OR+%22Roasted+0ktapus%22+OR+%22Octo+Tempest%22+OR+%22Storm-0875%22+OR+%22UNC3944%22%29+filetype%3Apdf)
- Regras e IOCs publicados: [GitHub](https://github.com/search?type=code&q=%22Scattered+Spider%22+OR+%22Roasted+0ktapus%22+OR+%22Octo+Tempest%22+OR+%22Storm-0875%22+OR+%22UNC3944%22)
- Pulsos de ameaça: [AlienVault OTX](https://otx.alienvault.com/browse/global/pulses?q=Scattered+Spider)
- Família de malware e atores: [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/actors) (busque por Scattered Spider, Roasted 0ktapus, Octo Tempest)
- Cartões de grupo: [ThaiCERT Threat Group Cards](https://apt.etda.or.th/cgi-bin/listgroups.cgi)
- Página oficial: [MITRE ATT&CK G1015](https://attack.mitre.org/groups/G1015/)

## 12. Bibliografia (11 fontes citadas pelo ATT&CK)

- [Check Point Scattered Spider JUL 2025](https://blog.checkpoint.com/research/exposing-scattered-spider-new-indicators-highlight-growing-threat-to-enterprises-and-aviation/) — Check Point Team. (2025, July 7). Exposing Scattered Spider: New Indicators Highlight Growing Threat to Enterprises and Aviation. Retrieved October 13, 2025.
- [CISA Scattered Spider Advisory November 2023](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a) — CISA. (2023, November 16). Cybersecurity Advisory: Scattered Spider (AA23-320A). Retrieved March 18, 2024.
- [CrowdStrike Scattered Spider BYOVD January 2023](https://www.crowdstrike.com/blog/scattered-spider-attempts-to-avoid-detection-with-bring-your-own-vulnerable-driver-tactic/) — CrowdStrike. (2023, January 10). SCATTERED SPIDER Exploits Windows Security Deficiencies with Bring-Your-Own-Vulnerable-Driver Tactic in Attempt to Bypass Endpoint Security. Retrieved July 5, 2023.
- [CrowdStrike Scattered Spider JUL 2025](https://www.crowdstrike.com/en-us/blog/crowdstrike-services-observes-scattered-spider-escalate-attacks/) — Counter Adversary Operations. (2025, July 2). CrowdStrike Services Observes SCATTERED SPIDER Escalate Attacks Across Industries. Retrieved October 13, 2025.
- [CrowdStrike Scattered Spider Profile](https://www.crowdstrike.com/adversaries/scattered-spider/) — CrowdStrike. (n.d.). Scattered Spider. Retrieved July 5, 2023.
- [Crowdstrike TELCO BPO Campaign December 2022](https://www.crowdstrike.com/blog/analysis-of-intrusion-campaign-targeting-telecom-and-bpo-companies/) — Parisi, T. (2022, December 2). Not a SIMulation: CrowdStrike Investigations Reveal Intrusion Campaign Targeting Telco and BPO Companies. Retrieved June 30, 2023.
- [Mandiant UNC3944 May 2025](https://cloud.google.com/blog/topics/threat-intelligence/unc3944-proactive-hardening-recommendations) — Mandiant Incident Response. (2025, May 6). Defending Against UNC3944: Cybercrime Hardening Guidance from the Frontlines. Retrieved October 13, 2025.
- [Mandiant VMware vSphere JUL 2025](https://cloud.google.com/blog/topics/threat-intelligence/defending-vsphere-from-unc3944) — Mandiant Incident Response. (2025, July 23). From Help Desk to Hypervisor: Defending Your VMware vSphere Estate from UNC3944. Retrieved October 13, 2025.
- [Microsoft Threat Actor Naming July 2023](https://learn.microsoft.com/en-us/microsoft-365/security/intelligence/microsoft-threat-actor-naming?view=o365-worldwide) — Microsoft . (2023, July 12). How Microsoft names threat actors. Retrieved November 17, 2023.
- [MSTIC Octo Tempest Operations October 2023](https://www.microsoft.com/en-us/security/blog/2023/10/25/octo-tempest-crosses-boundaries-to-facilitate-extortion-encryption-and-destruction/) — Microsoft. (2023, October 25). Octo Tempest crosses boundaries to facilitate extortion, encryption, and destruction. Retrieved March 18, 2024.
- [Trellix Scattered Spider MO August 2023](https://www.trellix.com/blogs/research/scattered-spider-the-modus-operandi/) — Trellix et. al.. (2023, August 17). Scattered Spider: The Modus Operandi. Retrieved March 18, 2024.

## 13. Limites e confiança

- O ATT&CK registra o que foi **relatado publicamente**, não tudo o que o grupo faz. Ausência de uma técnica não prova que o grupo não a usa.
- **Sobreposição de TTP não é atribuição.** Muitas técnicas são compartilhadas entre grupos e com red teams. Use a assinatura comportamental como hipótese, junto com infraestrutura, malware e contexto.
- Cobertura de detecção refere-se ao catálogo público Detection Rules, não ao seu ambiente: confira se a telemetria necessária chega ao seu SIEM.
- Ligações marcadas como _inferidas_ (EVTX por palavra-chave, relatórios por nome) devem ser verificadas.

---
Fontes: MITRE ATT&CK® (uso livre com atribuição, © The MITRE Corporation), APT4ALL (MISP Galaxy CC0/BSD-2, APT Groups & Operations CC BY 4.0, EternalLiberty, APTnotes, Ransomware Tool Matrix CC BY 4.0), Atomic Red Team (Red Canary, MIT), EVTX-to-MITRE-Attack, EVTX-ATTACK-SAMPLES, APT & CyberCriminal Campaign Collections. Gerado por [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules).
