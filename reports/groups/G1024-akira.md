# Akira (G1024) — Dossiê de inteligência

> **TLP:CLEAR** · gerado em 2026-10-25 a partir de fontes abertas · MITRE ATT&CK v20.0 · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1024) · [ATT&CK](https://attack.mitre.org/groups/G1024/)

**Também conhecido como:** GOLD SAHARA, PUNK SPIDER, Howling Scorpius  
**Registro no ATT&CK:** criado em 2024-02-20, atualizado em 2026-07-31 · referências de 2023 a 2024

## 1. Sumário executivo

- **17 técnicas** atribuídas publicamente, concentradas em **Stealth, Impact, Discovery**.
- **Arsenal:** 3 malware e 5 ferramentas (ex.: Mimikatz, Akira, LaZagne, Megazord, Akira _v2).
- **Campanhas atribuídas:** 0.
- **Cobertura de detecção pública:** 100% das técnicas têm ao menos uma regra no catálogo; **0 técnicas sem nenhuma regra pública**.
- **Assinatura comportamental** (técnicas raras entre os 178 grupos, as mais úteis para atribuição): T1558 Steal or Forge Kerberos Tickets, T1531 Account Access Removal, T1027.001 Binary Padding, T1213.002 Sharepoint, T1482 Domain Trust Discovery.

## 2. Quem é

> Akira is a ransomware variant and ransomware deployment entity active since at least March 2023. Akira uses compromised credentials to access single-factor external access mechanisms such as VPNs for initial access, then various publicly-available tools and techniques for lateral movement. Akira operations are associated with "double extortion" ransomware activity, where data is exfiltrated from victim environments prior to encryption, with threats to publish files if a ransom is not paid. Technical analysis of Akira ransomware indicates variants capable of targeting Windows or VMWare ESXi hypervisors and multiple overlaps with Conti ransomware.

_Texto original do MITRE ATT&CK, em inglês._

## 3. Perfil TTP por tática (kill chain)

Cada linha: técnica, como o grupo a usou segundo relatos públicos, e o que existe para detectar e testar.

### Initial Access (TA0001) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | Akira uses valid account information to remotely access victim networks, such as VPN credentials. | 825 | — | 3 |
| [T1133](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1133) External Remote Services | Akira uses compromised VPN accounts for initial access to victim networks. | 361 | 1 | — |

### Execution (TA0002) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1059.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.001) PowerShell | Akira has used PowerShell scripts for credential harvesting and privilege escalation. | 1340 | 22 | 15 |

### Persistence (TA0003) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | Akira uses valid account information to remotely access victim networks, such as VPN credentials. | 825 | — | 3 |
| [T1133](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1133) External Remote Services | Akira uses compromised VPN accounts for initial access to victim networks. | 361 | 1 | — |

### Privilege Escalation (TA0004) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | Akira uses valid account information to remotely access victim networks, such as VPN credentials. | 825 | — | 3 |

### Stealth (TA0005) — 3

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1027.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1027.001) Binary Padding | Akira has used binary padding to obfuscate payloads. | 13 | 3 | — |
| [T1036.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1036.005) Match Legitimate Resource Name or Location | Akira has used legitimate names and locations for files to evade defenses. | 116 | 4 | — |
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | Akira uses valid account information to remotely access victim networks, such as VPN credentials. | 825 | — | 3 |

### Defense Impairment (TA0112) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1685](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1685) Disable or Modify Tools | Akira has disabled or modified security tools for defense evasion. | 1275 | 78 | 19 |

### Credential Access (TA0006) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1558](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1558) Steal or Forge Kerberos Tickets | Akira have used scripts to dump Kerberos authentication credentials. | 73 | — | 5 |

### Discovery (TA0007) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1018](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1018) Remote System Discovery | Akira uses software such as Advanced IP Scanner and MASSCAN to identify remote hosts within victim networks. | 157 | 23 | 1 |
| [T1482](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1482) Domain Trust Discovery | Akira uses the built-in Nltest utility or tools such as AdFind to enumerate Active Directory trusts in victim environments. | 158 | 8 | 1 |

### Lateral Movement (TA0008) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1021.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1021.001) Remote Desktop Protocol | Akira has used RDP for lateral movement. | 139 | 4 | 7 |

### Collection (TA0009) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1213.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1213.002) Sharepoint | Akira has accessed and downloaded information stored in SharePoint instances as part of data gathering and exfiltration activity. | 7 | — | — |
| [T1560.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1560.001) Archive via Utility | Akira uses utilities such as WinRAR to archive data prior to exfiltration. | 76 | 13 | — |

### Command and Control (TA0011) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1219](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1219) Remote Access Tools | Akira uses legitimate utilities such as AnyDesk and PuTTy for maintaining remote access to victim environments. | 119 | 15 | — |

### Exfiltration (TA0010) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1567.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1567.002) Exfiltration to Cloud Storage | Akira will exfiltrate victim data using applications such as Rclone. | 85 | 2 | — |

### Impact (TA0040) — 3

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1486](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1486) Data Encrypted for Impact | Akira encrypts files in victim environments as part of ransomware operations. | 160 | 10 | 1 |
| [T1531](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1531) Account Access Removal | Akira deletes administrator accounts in victim networks prior to encryption. | 101 | 8 | — |
| [T1657](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1657) Financial Theft | Akira engages in double-extortion ransomware, exfiltrating files then encrypting them, in order to prompt victims to pay a ransom. | 2 | — | — |

## 4. Assinatura comportamental

Técnicas que este grupo usa e que poucos dos 178 grupos do ATT&CK usam. Pesam mais numa atribuição por TTP: ver várias delas juntas é mais informativo do que ver técnicas comuns como PowerShell.

| Técnica | Outros grupos que usam | Peso (raridade) |
|---|---:|---:|
| T1558 Steal or Forge Kerberos Tickets | 0 | 4.49 |
| T1531 Account Access Removal | 1 | 4.09 |
| T1027.001 Binary Padding | 7 | 2.99 |
| T1213.002 Sharepoint | 7 | 2.99 |
| T1482 Domain Trust Discovery | 9 | 2.79 |
| T1219 Remote Access Tools | 12 | 2.55 |
| T1657 Financial Theft | 18 | 2.19 |
| T1486 Data Encrypted for Impact | 19 | 2.14 |
| T1567.002 Exfiltration to Cloud Storage | 24 | 1.93 |
| T1133 External Remote Services | 27 | 1.82 |

## 5. Arsenal

| Software | Tipo | Técnicas no ATT&CK | Uso relatado (EN) |
|---|---|---:|---|
| [Mimikatz](https://attack.mitre.org/software/S0002/) | ferramenta | 17 |  |
| [Akira](https://attack.mitre.org/software/S1129/) | malware | 10 |  |
| [LaZagne](https://attack.mitre.org/software/S0349/) | ferramenta | 10 |  |
| [Megazord](https://attack.mitre.org/software/S1191/) | malware | 6 |  |
| [Akira _v2](https://attack.mitre.org/software/S1194/) | malware | 6 |  |
| [Rclone](https://attack.mitre.org/software/S1040/) | ferramenta | 6 |  |
| [AdFind](https://attack.mitre.org/software/S0552/) | ferramenta | 5 |  |
| [PsExec](https://attack.mitre.org/software/S0029/) | ferramenta | 5 |  |

## 6. Campanhas

Nenhuma campanha atribuída no ATT&CK.

## 7. Cobertura defensiva

**17 de 17 técnicas (100%)** têm ao menos uma regra pública no catálogo Detection Rules.

### Regras recomendadas por técnica

Melhor regra disponível por técnica (formato portável e maduro primeiro).

| Técnica | Regra | Formato | Fonte |
|---|---|---|---|
| T1018 | [Chopper Webshell Process Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Afa3c117a-bc0d-416e-a31b-0c0e80653efb) | Sigma | SigmaHQ |
| T1018 | [Webshell Hacking Activity Patterns](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4ebc877f-4612-45cb-b3a5-8e3834db36c9) | Sigma | SigmaHQ |
| T1021.001 | [Hermetic Wiper TG Process Patterns](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A2f974656-6d83-4059-bbdf-68ac5403422f) | Sigma | SigmaHQ |
| T1021.001 | [Publicly Accessible RDP Service](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1fc0809e-06bf-4de3-ad52-25e5263b7623) | Sigma | SigmaHQ |
| T1027.001 | [Binary Padding - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac52a914f-3d8b-4b2a-bb75-b3991e75f8ba) | Sigma | SigmaHQ |
| T1027.001 | [Failed Code Integrity Checks](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A470ec5fa-7b4e-4071-b200-4c753100f49b) | Sigma | SigmaHQ |
| T1036.005 | [Exploit for CVE-2015-1641](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A7993792c-5ce2-4475-a3db-a3a5539827ef) | Sigma | SigmaHQ |
| T1036.005 | [Exploit for CVE-2015-1641](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A7993792c-5ce2-4475-a3db-a3a5539827ef) | Sigma | OpenSearch Security Analytics |
| T1059.001 | [Potential Emotet Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad02e8cf5-6099-48cf-9bfc-1eec2d0c7b18) | Sigma | SigmaHQ |
| T1059.001 | [TropicTrooper Campaign November 2018](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A8c7090c3-e0a0-4944-bd08-08c3a0cecf79) | Sigma | SigmaHQ |
| T1078 | [Privilege Role Sign-In Outside Expected Controls](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acf1e5687-84e1-41af-97a9-158094efef53) | Sigma | SigmaHQ |
| T1078 | [OpenCanary - SSH Login Attempt](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aff7139bc-fdb1-4437-92f2-6afefe8884cb) | Sigma | SigmaHQ |
| T1133 | [OpenCanary - SSH Login Attempt](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aff7139bc-fdb1-4437-92f2-6afefe8884cb) | Sigma | SigmaHQ |
| T1133 | [OpenCanary - SSH New Connection Attempt](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acd55f721-5623-4663-bd9b-5229cab5237d) | Sigma | SigmaHQ |
| T1213.002 | [M365 SharePoint/OneDrive File Access via PowerShell](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A491651da-125b-11f1-af7d-f661ea17fbce) | Elastic | Elastic detection-rules |
| T1213.002 | [Entra ID Sharepoint or OneDrive Accessed by Unusual Client](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Aa3cc60d8-2701-11f0-accf-f661ea17fbcd) | Elastic | Elastic detection-rules |
| T1219 | [Renamed Visual Studio Code Tunnel Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A2cf29f11-e356-4f61-98c0-1bdb9393d6da) | Sigma | SigmaHQ |
| T1219 | [Hijack Legit RDP Session to Move Laterally](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A52753ea4-b3a0-4365-910d-36cff487b789) | Sigma | OpenSearch Security Analytics |
| T1482 | [BloodHound Collection Files](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A02773bed-83bf-469f-b7ff-e676e7d78bab) | Sigma | SigmaHQ |
| T1482 | [HackTool - TruffleSnout Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A69ca006d-b9a9-47f5-80ff-ecd4d25d481a) | Sigma | SigmaHQ |
| T1486 | [LockerGoga Ransomware Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A74db3488-fd28-480a-95aa-b7af626de068) | Sigma | SigmaHQ |
| T1486 | [LockerGoga Ransomware](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A74db3488-fd28-480a-95aa-b7af626de068) | Sigma | OpenSearch Security Analytics |
| T1531 | [Potential Destructive AWS CLI Command Executed by GenAI Agent](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A2635d2ba-51e7-404a-9b17-db413a1351d5) | Elastic | Elastic detection-rules |
| T1531 | [Google Workspace MFA Enforcement Disabled For Organization](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Acad4500a-abd7-4ef3-b5d3-95524de7cfe1) | Elastic | Elastic detection-rules |
| T1558 | [Antivirus - Password Dumper Signature](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A78cc2dd2-7d20-4d32-93ff-057084c38b93) | Sigma | SigmaHQ |
| T1558 | [HackTool - Mimikatz Kirbi File Creation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A9e099d99-44c2-42b6-a6d8-54c3545cab29) | Sigma | SigmaHQ |
| T1560.001 | [APT31 Judgement Panda Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A03e2746e-2b31-42f1-ab7a-eb39365b2422) | Sigma | SigmaHQ |
| T1560.001 | [Suspicious Manipulation Of Default Accounts Via Net.EXE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A5b768e71-86f2-4879-b448-81061cbae951) | Sigma | SigmaHQ |
| T1567.002 | [APT40 Dropbox Tool User Agent](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A5ba715b6-71b7-44fd-8245-f66893e81b3d) | Sigma | SigmaHQ |
| T1567.002 | [PUA - Rclone Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae37db05d-d1f9-49c8-b464-cee1a4b11638) | Sigma | SigmaHQ |
| T1657 | [AWS S3 Bucket Enumeration or Brute Force](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A5f0234fd-7f21-42af-8391-511d5fd11d5c) | Elastic | Elastic detection-rules |
| T1657 | [Monitor ransomwarelive for companies of interest on ransowmare data leak sites (DLS)](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=bert-janp-hunting-queries%3A%3A8b9af12a820a) | KQL hunting | Bert-JanP Hunting Queries |
| T1685 | [Windows Defender Configuration Changes](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A801bd44f-ceed-4eb6-887c-11544633c0aa) | Sigma | SigmaHQ |
| T1685 | [Windows Defender Virus Scanning Feature Disabled](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A686c0b4b-9dd3-4847-9077-d6c1bbe36fcb) | Sigma | SigmaHQ |

## 8. Plano de emulação e validação

Use num laboratório isolado e autorizado para confirmar que as regras disparam. Os comandos estão nos repositórios oficiais.

| Tática | Técnica | Teste Atomic Red Team | Plataformas |
|---|---|---|---|
| Execution | [T1059.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md) | Mimikatz | windows |
| Execution | [T1059.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md) | Run BloodHound from local disk | windows |
| Persistence | [T1133](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1133/T1133.md) | Running Chrome VPN Extensions via the Registry 2 vpn extension | windows |
| Stealth | [T1027.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027.001/T1027.001.md) | Pad Binary to Change Hash - Linux/macOS dd | linux, macos |
| Stealth | [T1027.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027.001/T1027.001.md) | Pad Binary to Change Hash using truncate command - Linux/macOS | linux, macos |
| Stealth | [T1036.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.005/T1036.005.md) | Execute a process from a directory masquerading as the current parent directory | linux, macos |
| Stealth | [T1036.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.005/T1036.005.md) | Masquerade as a built-in system executable | windows |
| Defense Impairment | [T1685](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1685/T1685.md) | Windows Disable LSA Protection | windows |
| Defense Impairment | [T1685](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1685/T1685.md) | Disable journal logging via systemctl utility | linux |
| Discovery | [T1018](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1018/T1018.md) | Remote System Discovery - net | windows |
| Discovery | [T1018](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1018/T1018.md) | Remote System Discovery - net group Domain Computers | windows |
| Discovery | [T1482](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1482/T1482.md) | Windows - Discover domain trusts with dsquery | windows |
| Discovery | [T1482](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1482/T1482.md) | Windows - Discover domain trusts with nltest | windows |
| Lateral Movement | [T1021.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.001/T1021.001.md) | RDP to Remote Host | windows |
| Lateral Movement | [T1021.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.001/T1021.001.md) | Changing RDP Port to Non Standard Port via Powershell | windows |
| Collection | [T1560.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1560.001/T1560.001.md) | Compress Data for Exfiltration With Rar | windows |
| Collection | [T1560.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1560.001/T1560.001.md) | Compress Data and lock with password for Exfiltration with winrar | windows |
| Command and Control | [T1219](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1219/T1219.md) | TeamViewer Files Detected Test on Windows | windows |
| Command and Control | [T1219](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1219/T1219.md) | AnyDesk Files Detected Test on Windows | windows |
| Exfiltration | [T1567.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1567.002/T1567.002.md) | Exfiltrate data with rclone to cloud Storage - Mega (Windows) | windows |
| Exfiltration | [T1567.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1567.002/T1567.002.md) | Exfiltrate data with rclone to cloud Storage - AWS S3 | linux, macos |
| Impact | [T1486](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1486/T1486.md) | Encrypt files using gpg (FreeBSD/Linux) | linux |
| Impact | [T1486](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1486/T1486.md) | Encrypt files using 7z (FreeBSD/Linux) | linux |
| Impact | [T1531](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1531/T1531.md) | Change User Password - Windows | windows |
| Impact | [T1531](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1531/T1531.md) | Delete User - Windows | windows |

**Logs reais de ataque (EVTX) para testar sem executar nada:**

- T1018 — [ID5145-DNS hosts files access via network share](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1018-Remote%20System%20Discovery/ID5145-DNS%20hosts%20files%20access%20via%20network%20share.evtx) _(explícito)_
- T1021.001 — [ID4688,4778,4779 RDP hijack direct](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0008-Lateral%20Movement/T1021.001-Remote%20Desktop%20Protocol/ID4688%2C4778%2C4779%20RDP%20hijack%20direct.evtx) _(explícito)_
- T1021.001 — [ID4688-4778 RDP hijack command execution](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0008-Lateral%20Movement/T1021.001-Remote%20Desktop%20Protocol/ID4688-4778%20RDP%20hijack%20command%20execution.evtx) _(explícito)_
- T1059.001 — [ID4103-4104-Payload download via PowerShell](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1059.001-PowerShell/ID4103-4104-Payload%20download%20via%20PowerShell.evtx) _(explícito)_
- T1059.001 — [ID4688-Encoded PowerShell MSF payload via process execution](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1059.001-PowerShell/ID4688-Encoded%20PowerShell%20MSF%20payload%20via%20process%20execution.evtx) _(explícito)_
- T1078 — [ID1149-RDP success logins to multiple hosts](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0001-Initial%20access/T1078-Valid%20accounts/ID1149-RDP%20success%20logins%20to%20multiple%20hosts.evtx) _(explícito)_
- T1078 — [ID33205-SQL Server failed login with disabled SA account](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0001-Initial%20access/T1078-Valid%20accounts/ID33205-SQL%20Server%20failed%20login%20with%20disabled%20SA%20account.evtx) _(explícito)_
- T1482 — [ID800,4103,4104-Active Directory Forest PowerShell class](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1482-Domain%20Trust%20Discovery/ID800%2C4103%2C4104-Active%20Directory%20Forest%20PowerShell%20class.evtx) _(explícito)_
- T1486 — [ID 768,775,793,796,817,840-BitLocker encryption activated](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0040-Impact/T1486-Data%20Encrypted%20for%20Impact/ID%20768%2C775%2C793%2C796%2C817%2C840-BitLocker%20encryption%20activated.evtx) _(explícito)_
- T1558 — [ID4624-Success login with Golden ticket](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0006-Credential%20Access/T1558-Steal%20or%20Forge%20Kerberos%20Tickets/ID4624-Success%20login%20with%20Golden%20ticket.evtx) _(explícito)_
- T1558 — [ID4768-4769-Kerberos host ticket without a trailing $](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0006-Credential%20Access/T1558-Steal%20or%20Forge%20Kerberos%20Tickets/ID4768-4769-Kerberos%20host%20ticket%20without%20a%20trailing%20%24.evtx) _(explícito)_
- T1685 — [ID1-SYSMON driver unload (FilterManager)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0005-Defense%20Evasion/T1562.001-Impair%20Defenses-Disable%20or%20Modify%20tool/ID1-SYSMON%20driver%20unload%20%28FilterManager%29.evtx) _(explícito)_
- T1685 — [ID13-Defender service configuration disabled](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0005-Defense%20Evasion/T1562.001-Impair%20Defenses-Disable%20or%20Modify%20tool/ID13-Defender%20service%20configuration%20disabled.evtx) _(explícito)_

## 9. Hipóteses de hunting

Se Akira estiver no seu ambiente, estas são as perguntas a fazer aos seus dados (fontes de log segundo as estratégias de detecção do MITRE ATT&CK).

1. **T1558 Steal or Forge Kerberos Tickets** — Detects anomalous Kerberos activity such as forged or stolen tickets by correlating malformed fields in logon events, RC4-encrypted TGTs, or TGS requests without corresponding TGT requests. Also detects suspicious processes accessing LSASS memory for ticket… Dados: `WinEventLog:Security` (EventCode=4672, 4634), `WinEventLog:Sysmon` (EventCode=10).
2. **T1531 Account Access Removal** — Correlated user account modification (reset, disable, deletion) events with anomalous process lineage (e.g., PowerShell or net.exe from an interactive session), especially outside of IT admin change windows or by non-admin users. Dados: `WinEventLog:Security` (EventCode=4723, 4724, 4740), `WinEventLog:Sysmon` (EventCode=1).
3. **T1027.001 Binary Padding** — Detects the creation or execution of padded binary files (e.g., large size but minimal legitimate content) followed by process execution or lateral movement from the host. Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:Security` (EventCode=4663, 4670, 4656), `WinEventLog:Sysmon` (EventCode=11).
4. **T1213.002 Sharepoint** — Privileged or rarely used accounts performing bulk access to SharePoint files or metadata over a short time window, indicating potential scripted collection of sensitive internal documents. Dados: `m365:unified` (FileAccessed, FileDownloaded, SearchQueried), `azure:signinlogs` (UserLogin, ConditionalAccessPolicyEvaluated), `m365:sharepoint` (Multiple file download operations on a site by a privileged account in a short time window).
5. **T1482 Domain Trust Discovery** — Adversary uses nltest, PowerShell, or Win32/.NET API to enumerate domain trust relationships (via DSEnumerateDomainTrusts, GetAllTrustRelationships, or LDAP queries), followed by discovery or authentication staging. Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=7), `WinEventLog:Sysmon` (EventCode=10).
6. **T1219 Remote Access Tools** — Chain of remote access tool behavior: (1) initial execution of remote-control/assist agent or GUI under user context; (2) persistence via service or autorun; (3) long-lived outbound connection/tunnel to external infrastructure; (4) interactive control signals… Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:System` (EventCode=7045), `WinEventLog:Sysmon` (EventCode=12).
7. **T1657 Financial Theft** — Monitor for anomalous access to financial applications, browser-based banking sessions, or enterprise ERP systems from Windows endpoints. Detect mass emailing of payment instructions, sudden rule changes in Outlook for financial staff, or use of clipboard… Dados: `WinEventLog:Security` (EventCode=4624, 4648), `WinEventLog:Sysmon` (EventCode=1).
8. **T1486 Data Encrypted for Impact** — High-frequency file write operations using uncommon extensions, followed by ransom note creation, registry tampering, or shadow copy deletion. Often uses CLI tools like vssadmin, wbadmin, cipher, or PowerShell. Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Sysmon` (EventCode=2).
9. **T1567.002 Exfiltration to Cloud Storage** — Unusual processes (e.g., powershell.exe, excel.exe) accessing large local files and subsequently initiating HTTPS POST requests to domains associated with cloud storage services (e.g., dropbox.com, drive.google.com, box.com). Defender perspective: correlation… Dados: `WinEventLog:Security` (EventCode=4663, 4670, 4656), `WinEventLog:Sysmon` (EventCode=3, 22), `WinEventLog:Sysmon` (EventCode=1).
10. **T1133 External Remote Services** — Unusual or unauthorized external remote access attempts (e.g., RDP, VPN, Citrix) → repeated failed logins followed by a successful session from uncommon geolocations or outside business hours → subsequent internal lateral movement or data exfiltration… Dados: `WinEventLog:Security` (EventCode=4776, 4625), `WinEventLog:Application` (VPN, Citrix, or remote access gateway logs showing external IP addresses), `WinEventLog:Sysmon` (EventCode=3, 22).
11. **T1685 Disable or Modify Tools** — Detection of adversary behavior that disables or modifies security tools, including killing AV/EDR processes, stopping services, altering Sysmon registry keys, or tampering with exclusion lists. Defenders observe process/service termination, registry… Dados: `WinEventLog:System` (EventCode=7045), `WinEventLog:Sysmon` (EventCode=5), `WinEventLog:Sysmon` (EventCode=13, 14).
12. **T1021.001 Remote Desktop Protocol** — Remote Desktop (RDP) logon by a user followed by unusual process execution, file access, or lateral movement activity within a short timeframe. Dados: `WinEventLog:Security` (EventCode=4624, 4648), `WinEventLog:Security` (EventCode=4778, EventCode=4779), `WinEventLog:Sysmon` (EventCode=3, 22).

## 10. OSINT — onde pesquisar

Consultas prontas com todos os nomes conhecidos do grupo:

- Relatórios técnicos: [busca web](https://duckduckgo.com/?q=%28%22Akira%22+OR+%22GOLD+SAHARA%22+OR+%22PUNK+SPIDER%22+OR+%22Howling+Scorpius%22%29+threat+report) · [PDFs](https://duckduckgo.com/?q=%28%22Akira%22+OR+%22GOLD+SAHARA%22+OR+%22PUNK+SPIDER%22+OR+%22Howling+Scorpius%22%29+filetype%3Apdf)
- Regras e IOCs publicados: [GitHub](https://github.com/search?type=code&q=%22Akira%22+OR+%22GOLD+SAHARA%22+OR+%22PUNK+SPIDER%22+OR+%22Howling+Scorpius%22)
- Pulsos de ameaça: [AlienVault OTX](https://otx.alienvault.com/browse/global/pulses?q=Akira)
- Família de malware e atores: [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/actors) (busque por Akira, GOLD SAHARA, PUNK SPIDER)
- Cartões de grupo: [ThaiCERT Threat Group Cards](https://apt.etda.or.th/cgi-bin/listgroups.cgi)
- Página oficial: [MITRE ATT&CK G1024](https://attack.mitre.org/groups/G1024/)

## 11. Bibliografia (8 fontes citadas pelo ATT&CK)

- [Arctic Wolf Akira 2023](https://arcticwolf.com/resources/blog/conti-and-akira-chained-together/) — Steven Campbell, Akshay Suthar, & Connor Belfiorre. (2023, July 26). Conti and Akira: Chained Together. Retrieved February 20, 2024.
- [BushidoToken Akira 2023](https://blog.bushidotoken.net/2023/09/tracking-adversaries-akira-another.html) — Will Thomas. (2023, September 15). Tracking Adversaries: Akira, another descendent of Conti. Retrieved February 21, 2024.
- [CISA Akira Ransomware APR 2024](https://www.cisa.gov/sites/default/files/2024-04/aa24-109a-stopransomware-akira-ransomware_2.pdf) — CISA et al. (2024, April 18). #StopRansomware: Akira Ransomware. Retrieved December 10, 2024.
- [Cisco Akira Ransomware OCT 2024](https://blog.talosintelligence.com/akira-ransomware-continues-to-evolve/) — Nutland, J. and Szeliga, M. (2024, October 21). Akira ransomware continues to evolve. Retrieved December 10, 2024.
- [CrowdStrike PUNK SPIDER](https://www.crowdstrike.com/adversaries/punk-spider/) — CrowdStrike. (n.d.). Punk Spider. Retrieved February 20, 2024.
- [Kersten Akira 2023](https://www.trellix.com/blogs/research/akira-ransomware/) — Max Kersten & Alexandre Mundo. (2023, November 29). Akira Ransomware. Retrieved April 4, 2024.
- [Palo Alto Howling Scorpius DEC 2024](https://unit42.paloaltonetworks.com/threat-assessment-howling-scorpius-akira-ransomware/) — Zemah, Y. (2024, December 2). Threat Assessment: Howling Scorpius (Akira Ransomware). Retrieved January 8, 2025.
- [Secureworks GOLD SAHARA](https://www.secureworks.com/research/threat-profiles/gold-sahara) — Secureworks. (n.d.). GOLD SAHARA. Retrieved February 20, 2024.

## 12. Limites e confiança

- O ATT&CK registra o que foi **relatado publicamente**, não tudo o que o grupo faz. Ausência de uma técnica não prova que o grupo não a usa.
- **Sobreposição de TTP não é atribuição.** Muitas técnicas são compartilhadas entre grupos e com red teams. Use a assinatura comportamental como hipótese, junto com infraestrutura, malware e contexto.
- Cobertura de detecção refere-se ao catálogo público Detection Rules, não ao seu ambiente: confira se a telemetria necessária chega ao seu SIEM.
- Ligações marcadas como _inferidas_ (EVTX por palavra-chave, relatórios por nome) devem ser verificadas.

---
Fontes: MITRE ATT&CK® (uso livre com atribuição, © The MITRE Corporation), Atomic Red Team (Red Canary, MIT), EVTX-to-MITRE-Attack, EVTX-ATTACK-SAMPLES, APT & CyberCriminal Campaign Collections. Gerado por [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules).
