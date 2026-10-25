# Cinnamon Tempest (G1021) — Dossiê de inteligência

> **TLP:CLEAR** · gerado em 2026-10-25 a partir de fontes abertas · MITRE ATT&CK v20.0 · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1021) · [ATT&CK](https://attack.mitre.org/groups/G1021/)

**Também conhecido como:** DEV-0401, Emperor Dragonfly, BRONZE STARLIGHT  
**Registro no ATT&CK:** criado em 2023-12-06, atualizado em 2026-07-31 · referências de 2021 a 2023

## 1. Sumário executivo

- **19 técnicas** atribuídas publicamente, concentradas em **Execution, Stealth, Privilege Escalation**.
- **Arsenal:** 5 malware e 3 ferramentas (ex.: Cobalt Strike, PlugX, Sliver, Pandora, Impacket).
- **Campanhas atribuídas:** 0.
- **Cobertura de detecção pública:** 100% das técnicas têm ao menos uma regra no catálogo; **0 técnicas sem nenhuma regra pública**.
- **Assinatura comportamental** (técnicas raras entre os 178 grupos, as mais úteis para atribuição): T1080 Taint Shared Content, T1484.001 Group Policy Modification, T1572 Protocol Tunneling, T1657 Financial Theft, T1090 Proxy.

## 2. Quem é

> Cinnamon Tempest is a China-based threat group that has been active since at least 2021 deploying multiple strains of ransomware based on the leaked Babuk source code. Cinnamon Tempest does not operate their ransomware on an affiliate model or purchase access but appears to act independently in all stages of the attack lifecycle. Based on victimology, the short lifespan of each ransomware variant, and use of malware attributed to government-sponsored threat groups, Cinnamon Tempest may be motivated by intellectual property theft or cyberespionage rather than financial gain.

_Texto original do MITRE ATT&CK, em inglês._

## 3. Perfil TTP por tática (kill chain)

Cada linha: técnica, como o grupo a usou segundo relatos públicos, e o que existe para detectar e testar.

### Resource Development (TA0042) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1588.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1588.002) Tool | Cinnamon Tempest has used open-source tools including customized versions of the Iox proxy tool, NPS tunneling tool, Meterpreter, and a keylogger that uploads data to Alibaba cloud storage. | 35 | — | — |

### Initial Access (TA0001) — 3

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | Cinnamon Tempest has used compromised user accounts to deploy payloads and create system services. | 825 | — | 3 |
| [T1078.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.002) Domain Accounts | Cinnamon Tempest has obtained highly privileged credentials such as domain administrator in order to deploy malware. | 36 | — | 1 |
| [T1190](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1190) Exploit Public-Facing Application | Cinnamon Tempest has exploited multiple unpatched vulnerabilities for initial access including vulnerabilities in Microsoft Exchange, Manage Engine AdSelfService Plus, Confluence, and Log4j. | 580 | — | — |

### Execution (TA0002) — 5

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1047](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1047) Windows Management Instrumentation | Cinnamon Tempest has used Impacket for lateral movement via WMI. | 370 | 12 | 11 |
| [T1059.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.001) PowerShell | Cinnamon Tempest has used PowerShell to communicate with C2, download files, and execute reconnaissance commands. | 1340 | 22 | 15 |
| [T1059.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.003) Windows Command Shell | Cinnamon Tempest has executed ransomware using batch scripts deployed via GPO. | 269 | 6 | 1 |
| [T1059.006](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.006) Python | Cinnamon Tempest has used a customized version of the Impacket wmiexec.py module to create renamed output files. | 122 | — | — |
| [T1574.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1574.001) DLL | Cinnamon Tempest has used search order hijacking to launch Cobalt Strike Beacons. Cinnamon Tempest has also abused legitimate executables to side-load weaponized DLLs. | 455 | 7 | 5 |

### Persistence (TA0003) — 3

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | Cinnamon Tempest has used compromised user accounts to deploy payloads and create system services. | 825 | — | 3 |
| [T1078.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.002) Domain Accounts | Cinnamon Tempest has obtained highly privileged credentials such as domain administrator in order to deploy malware. | 36 | — | 1 |
| [T1543.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1543.003) Windows Service | Cinnamon Tempest has created system services to establish persistence for deployed tooling. | 1916 | 6 | 19 |

### Privilege Escalation (TA0004) — 4

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | Cinnamon Tempest has used compromised user accounts to deploy payloads and create system services. | 825 | — | 3 |
| [T1078.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.002) Domain Accounts | Cinnamon Tempest has obtained highly privileged credentials such as domain administrator in order to deploy malware. | 36 | — | 1 |
| [T1484.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1484.001) Group Policy Modification | Cinnamon Tempest has used Group Policy to deploy batch scripts for ransomware deployment. | 47 | 2 | 1 |
| [T1543.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1543.003) Windows Service | Cinnamon Tempest has created system services to establish persistence for deployed tooling. | 1916 | 6 | 19 |

### Stealth (TA0005) — 4

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | Cinnamon Tempest has used compromised user accounts to deploy payloads and create system services. | 825 | — | 3 |
| [T1078.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.002) Domain Accounts | Cinnamon Tempest has obtained highly privileged credentials such as domain administrator in order to deploy malware. | 36 | — | 1 |
| [T1140](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1140) Deobfuscate/Decode Files or Information | Cinnamon Tempest has used weaponized DLLs to load and decrypt payloads. | 173 | 11 | 1 |
| [T1574.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1574.001) DLL | Cinnamon Tempest has used search order hijacking to launch Cobalt Strike Beacons. Cinnamon Tempest has also abused legitimate executables to side-load weaponized DLLs. | 455 | 7 | 5 |

### Defense Impairment (TA0112) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1484.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1484.001) Group Policy Modification | Cinnamon Tempest has used Group Policy to deploy batch scripts for ransomware deployment. | 47 | 2 | 1 |

### Lateral Movement (TA0008) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1021.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1021.002) SMB/Windows Admin Shares | Cinnamon Tempest has used SMBexec for lateral movement. | 272 | 4 | 20 |
| [T1080](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1080) Taint Shared Content | Cinnamon Tempest has deployed ransomware from a batch file in a network share. | 12 | — | — |

### Command and Control (TA0011) — 3

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1090](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1090) Proxy | Cinnamon Tempest has used a customized version of the Iox port-forwarding and proxy tool. | 162 | — | 1 |
| [T1105](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1105) Ingress Tool Transfer | Cinnamon Tempest has downloaded files, including Cobalt Strike, to compromised hosts. | 644 | 39 | — |
| [T1572](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1572) Protocol Tunneling | Cinnamon Tempest has used the Iox and NPS proxy and tunneling tools in combination create multiple connections through a single tunnel. | 173 | 9 | 1 |

### Exfiltration (TA0010) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1567.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1567.002) Exfiltration to Cloud Storage | Cinnamon Tempest has uploaded captured keystroke logs to the Alibaba Cloud Object Storage Service, Aliyun OSS. | 85 | 2 | — |

### Impact (TA0040) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1657](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1657) Financial Theft | Cinnamon Tempest has maintained leak sites for exfiltrated data in attempt to extort victims into paying a ransom. | 2 | — | — |

## 4. Assinatura comportamental

Técnicas que este grupo usa e que poucos dos 178 grupos do ATT&CK usam. Pesam mais numa atribuição por TTP: ver várias delas juntas é mais informativo do que ver técnicas comuns como PowerShell.

| Técnica | Outros grupos que usam | Peso (raridade) |
|---|---:|---:|
| T1080 Taint Shared Content | 4 | 3.40 |
| T1484.001 Group Policy Modification | 4 | 3.40 |
| T1572 Protocol Tunneling | 14 | 2.42 |
| T1657 Financial Theft | 18 | 2.19 |
| T1090 Proxy | 19 | 2.14 |
| T1059.006 Python | 20 | 2.10 |
| T1078.002 Domain Accounts | 20 | 2.10 |
| T1567.002 Exfiltration to Cloud Storage | 24 | 1.93 |
| T1543.003 Windows Service | 25 | 1.89 |
| T1021.002 SMB/Windows Admin Shares | 27 | 1.82 |

## 5. Arsenal

| Software | Tipo | Técnicas no ATT&CK | Uso relatado (EN) |
|---|---|---:|---|
| [Cobalt Strike](https://attack.mitre.org/software/S0154/) | malware | 73 |  |
| [PlugX](https://attack.mitre.org/software/S0013/) | malware | 49 |  |
| [Sliver](https://attack.mitre.org/software/S0633/) | ferramenta | 23 |  |
| [Pandora](https://attack.mitre.org/software/S0664/) | malware | 13 |  |
| [Impacket](https://attack.mitre.org/software/S0357/) | ferramenta | 11 |  |
| [Rclone](https://attack.mitre.org/software/S1040/) | ferramenta | 6 |  |
| [Cheerscrypt](https://attack.mitre.org/software/S1096/) | malware | 5 |  |
| [HUI Loader](https://attack.mitre.org/software/S1097/) | malware | 3 |  |

## 6. Campanhas

Nenhuma campanha atribuída no ATT&CK.

## 7. Cobertura defensiva

**19 de 19 técnicas (100%)** têm ao menos uma regra pública no catálogo Detection Rules.

### Regras recomendadas por técnica

Melhor regra disponível por técnica (formato portável e maduro primeiro).

| Técnica | Regra | Formato | Fonte |
|---|---|---|---|
| T1021.002 | [PSExec Lateral Movement](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=hayabusa-native%3A%3A0694c340-3a46-40ac-acfc-c3444ae6572c) | Sigma | Hayabusa (native) |
| T1021.002 | [Turla Group Lateral Movement](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac601f20d-570a-4cde-a7d6-e17f99cb8e7f) | Sigma | SigmaHQ |
| T1047 | [HackTool - Potential Impacket Lateral Movement Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A10c14723-61c7-4c75-92ca-9af245723ad2) | Sigma | SigmaHQ |
| T1047 | [CrackMapExec Command Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A058f4380-962d-40a5-afce-50207d36d7e2) | Sigma | OpenSearch Security Analytics |
| T1059.001 | [Potential Emotet Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad02e8cf5-6099-48cf-9bfc-1eec2d0c7b18) | Sigma | SigmaHQ |
| T1059.001 | [TropicTrooper Campaign November 2018](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A8c7090c3-e0a0-4944-bd08-08c3a0cecf79) | Sigma | SigmaHQ |
| T1059.003 | [HackTool - CrackMapExec Execution Patterns](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A058f4380-962d-40a5-afce-50207d36d7e2) | Sigma | SigmaHQ |
| T1059.003 | [CrackMapExec Command Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A058f4380-962d-40a5-afce-50207d36d7e2) | Sigma | OpenSearch Security Analytics |
| T1059.006 | [Emotet Loader Execution Via .LNK File](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1f32d820-1d5c-43fe-8fe2-feef0c952eb7) | Sigma | SigmaHQ |
| T1059.006 | [Serpent Backdoor Payload Execution Via Scheduled Task](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad5eb7432-fda4-4bba-a37f-ffa74d9ed639) | Sigma | SigmaHQ |
| T1078 | [Privilege Role Sign-In Outside Expected Controls](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acf1e5687-84e1-41af-97a9-158094efef53) | Sigma | SigmaHQ |
| T1078 | [OpenCanary - SSH Login Attempt](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aff7139bc-fdb1-4437-92f2-6afefe8884cb) | Sigma | SigmaHQ |
| T1078.002 | [Malicious Usage Of IMDS Credentials Outside Of AWS Infrastructure](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A352a918a-34d8-4882-8470-44830c507aa3) | Sigma | SigmaHQ |
| T1078.002 | [AdminSDHolder SDProp Exclusion Added](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A61d29caf-6c15-4d1e-9ccb-7ad12ccc0bc7) | Elastic | Elastic detection-rules |
| T1080 | [M365 OneDrive Malware File Upload](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Abba1b212-b85c-41c6-9b28-be0e5cdfc9b1) | Elastic | Elastic detection-rules |
| T1080 | [M365 SharePoint Malware File Detected](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A0e52157a-8e96-4a95-a6e3-5faae5081a74) | Elastic | Elastic detection-rules |
| T1090 | [Communication To LocaltoNet Tunneling Service Initiated - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac4568f5d-131f-4e78-83d4-45b2da0ec4f1) | Sigma | SigmaHQ |
| T1090 | [Communication To Ngrok Tunneling Service - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A19bf6fdb-7721-4f3d-867f-53467f6a5db6) | Sigma | SigmaHQ |
| T1105 | [Greenbug Espionage Group Indicators](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A3711eee4-a808-4849-8a14-faf733da3612) | Sigma | SigmaHQ |
| T1105 | [Pandemic Registry Key](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A47e0852a-cf81-4494-a8e6-31864f8c86ed) | Sigma | SigmaHQ |
| T1140 | [UNC4841 - SSL Certificate Exfiltration Via Openssl](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A60911c07-f989-4362-84af-c609828ef829) | Sigma | SigmaHQ |
| T1140 | [UNC4841 - Download Compressed Files From Temp.sh Using Wget](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A60d050c4-e253-4d9a-b673-5ac100cfddfb) | Sigma | SigmaHQ |
| T1190 | [OMIGOD HTTP No Authentication RCE - CVE-2021-38647](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aab6b1a39-a9ee-4ab4-b075-e83acf6e346b) | Sigma | SigmaHQ |
| T1190 | [Exploited CVE-2020-10189 Zoho ManageEngine](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A846b866e-2a57-46ee-8e16-85fa92759be7) | Sigma | OpenSearch Security Analytics |
| T1484.001 | [Group Policy Abuse for Privilege Addition](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ab9554892-5e0e-424b-83a0-5aef95aa43bf) | Elastic | Elastic detection-rules |
| T1484.001 | [Modify Group Policy Settings](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aada4b0c4-758b-46ac-9033-9004613a150d) | Sigma | SigmaHQ |
| T1543.003 | [PSExec Lateral Movement](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=hayabusa-native%3A%3A0694c340-3a46-40ac-acfc-c3444ae6572c) | Sigma | Hayabusa (native) |
| T1543.003 | [Suspicious Service Name](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=hayabusa-native%3A%3Acc429813-21db-4019-b520-2f19648e1ef1) | Sigma | Hayabusa (native) |
| T1567.002 | [APT40 Dropbox Tool User Agent](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A5ba715b6-71b7-44fd-8245-f66893e81b3d) | Sigma | SigmaHQ |
| T1567.002 | [PUA - Rclone Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae37db05d-d1f9-49c8-b464-cee1a4b11638) | Sigma | SigmaHQ |
| T1572 | [Communication To LocaltoNet Tunneling Service Initiated - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac4568f5d-131f-4e78-83d4-45b2da0ec4f1) | Sigma | SigmaHQ |
| T1572 | [Communication To Ngrok Tunneling Service - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A19bf6fdb-7721-4f3d-867f-53467f6a5db6) | Sigma | SigmaHQ |
| T1574.001 | [Winnti Pipemon Characteristics](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A73d70463-75c9-4258-92c6-17500fe972f2) | Sigma | SigmaHQ |
| T1574.001 | [Winnti Pipemon Characteristics](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A73d70463-75c9-4258-92c6-17500fe972f2) | Sigma | OpenSearch Security Analytics |
| T1588.002 | [Hacktool Execution - Imphash](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A24e3e58a-646b-4b50-adef-02ef935b9fc8) | Sigma | SigmaHQ |
| T1588.002 | [Renamed SysInternals DebugView Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acd764533-2e07-40d6-a718-cfeec7f2da7f) | Sigma | SigmaHQ |
| T1657 | [AWS S3 Bucket Enumeration or Brute Force](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A5f0234fd-7f21-42af-8391-511d5fd11d5c) | Elastic | Elastic detection-rules |
| T1657 | [Monitor ransomwarelive for companies of interest on ransowmare data leak sites (DLS)](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=bert-janp-hunting-queries%3A%3A8b9af12a820a) | KQL hunting | Bert-JanP Hunting Queries |

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
| Persistence | [T1543.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1543.003/T1543.003.md) | Modify Fax service to run PowerShell | windows |
| Persistence | [T1543.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1543.003/T1543.003.md) | Service Installation CMD | windows |
| Stealth | [T1140](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1140/T1140.md) | Deobfuscate/Decode Files Or Information | windows |
| Stealth | [T1140](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1140/T1140.md) | Certutil Rename and Decode | windows |
| Stealth | [T1574.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1574.001/T1574.001.md) | DLL Search Order Hijacking - amsi.dll | windows |
| Stealth | [T1574.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1574.001/T1574.001.md) | Phantom Dll Hijacking - WinAppXRT.dll | windows |
| Defense Impairment | [T1484.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1484.001/T1484.001.md) | LockBit Black - Modify Group policy settings -cmd | windows |
| Defense Impairment | [T1484.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1484.001/T1484.001.md) | LockBit Black - Modify Group policy settings -Powershell | windows |
| Lateral Movement | [T1021.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.002/T1021.002.md) | Map admin share | windows |
| Lateral Movement | [T1021.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.002/T1021.002.md) | Map Admin Share PowerShell | windows |
| Command and Control | [T1105](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1105/T1105.md) | rsync remote file copy (push) | linux, macos |
| Command and Control | [T1105](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1105/T1105.md) | rsync remote file copy (pull) | linux, macos |
| Command and Control | [T1572](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1572/T1572.md) | DNS over HTTPS Large Query Volume | windows |
| Command and Control | [T1572](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1572/T1572.md) | DNS over HTTPS Regular Beaconing | windows |
| Exfiltration | [T1567.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1567.002/T1567.002.md) | Exfiltrate data with rclone to cloud Storage - Mega (Windows) | windows |
| Exfiltration | [T1567.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1567.002/T1567.002.md) | Exfiltrate data with rclone to cloud Storage - AWS S3 | linux, macos |

**Logs reais de ataque (EVTX) para testar sem executar nada:**

- T1021.002 — [ID4688,4697,5140-5145 PSexec remote execution + admin share](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0008-Lateral%20Movement/T1021.002-SMB%20Windows%20Admin%20Shares/ID4688%2C4697%2C5140-5145%20PSexec%20remote%20execution%20%2B%20admin%20share.evtx) _(explícito)_
- T1021.002 — [ID4688-4648 Lateral movement with net use](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0008-Lateral%20Movement/T1021.002-SMB%20Windows%20Admin%20Shares/ID4688-4648%20Lateral%20movement%20with%20net%20use.evtx) _(explícito)_
- T1047 — [ID1-WMI spwaning PowerShell process - WMImplant](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1047-Windows%20Management%20Instrumentation/ID1-WMI%20spwaning%20PowerShell%20process%20-%20WMImplant.evtx) _(explícito)_
- T1047 — [ID1-WMIexec process execution](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1047-Windows%20Management%20Instrumentation/ID1-WMIexec%20process%20execution.evtx) _(explícito)_
- T1059.001 — [ID4103-4104-Payload download via PowerShell](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1059.001-PowerShell/ID4103-4104-Payload%20download%20via%20PowerShell.evtx) _(explícito)_
- T1059.001 — [ID4688-Encoded PowerShell MSF payload via process execution](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1059.001-PowerShell/ID4688-Encoded%20PowerShell%20MSF%20payload%20via%20process%20execution.evtx) _(explícito)_
- T1059.003 — [ID4688-SQL Server payload injectection for reverse shell (MSF)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1059.003-Windows%20Command%20Shell/ID4688-SQL%20Server%20payload%20injectection%20for%20reverse%20shell%20%28MSF%29.evtx) _(explícito)_
- T1078 — [ID1149-RDP success logins to multiple hosts](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0001-Initial%20access/T1078-Valid%20accounts/ID1149-RDP%20success%20logins%20to%20multiple%20hosts.evtx) _(explícito)_
- T1078 — [ID33205-SQL Server failed login with disabled SA account](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0001-Initial%20access/T1078-Valid%20accounts/ID33205-SQL%20Server%20failed%20login%20with%20disabled%20SA%20account.evtx) _(explícito)_
- T1078.002 — [ID4964-Login of a member of a special group](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0005-Defense%20Evasion/T1078.002-Valid%20accounts-Domain%20accounts/ID4964-Login%20of%20a%20member%20of%20a%20special%20group.evtx) _(explícito)_
- T1090 — [ID5600-proxy configuration changed](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0011-Command%20and%20Control/T1090-Proxy/ID5600-proxy%20configuration%20changed.evtx) _(explícito)_
- T1140 — [ID4688-Certutil download](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0005-Defense%20Evasion/T1140-Deobfuscate-Decode%20Files%20or%20Information/ID4688-Certutil%20download.evtx) _(explícito)_
- T1484.001 — [ID5136-4662 sensitive GPO edited](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0004-Privilege%20Escalation/T1484.001-Domain%20Policy%20Modification-Group%20Policy%20Modification/ID5136-4662%20sensitive%20GPO%20edited.evtx) _(explícito)_
- T1543.003 — [ID13-New service for Mimikatz](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0003-Persistence/T1543.003-Create%20or%20Modify%20System%20Process-Windows%20Service/ID13-New%20service%20for%20Mimikatz.evtx) _(explícito)_
- T1543.003 — [ID4688-4697 RDP hijack via service creation](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0003-Persistence/T1543.003-Create%20or%20Modify%20System%20Process-Windows%20Service/ID4688-4697%20RDP%20hijack%20via%20service%20creation.evtx) _(explícito)_
- T1572 — [ID4688-netsh RDP port forwarding abuse](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0011-Command%20and%20Control/T1572-Protocol%20tunneling/ID4688-netsh%20RDP%20port%20forwarding%20abuse.evtx) _(explícito)_
- T1574.001 — [DE_timestomp_and_dll_sideloading_and_RunPersist](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/AutomatedTestingTools/Malware/DE_timestomp_and_dll_sideloading_and_RunPersist.evtx) _(inferido)_
- T1574.001 — [sideloading_injection_persistence_run_key](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/AutomatedTestingTools/Malware/sideloading_injection_persistence_run_key.evtx) _(inferido)_

## 9. Hipóteses de hunting

Se Cinnamon Tempest estiver no seu ambiente, estas são as perguntas a fazer aos seus dados (fontes de log segundo as estratégias de detecção do MITRE ATT&CK).

1. **T1080 Taint Shared Content** — Detects adversary tampering of shared directories via file drops (e.g., malicious LNK, EXE, VBS) followed by user execution or suspicious network activity. Dados: `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Security` (EventCode=5145).
2. **T1484.001 Group Policy Modification** — Adversary modifies GPO containers or files under SYSVOL using LDAP, ADSI, PowerShell (e.g., New-GPOImmediateTask) or GUI tools. This includes directory object changes (e.g., gPCFileSysPath), delegation assignments (SeEnableDelegationPrivilege), and SYSVOL… Dados: `WinEventLog:Security` (EventCode=5136), `WinEventLog:Security` (EventCode=4663, 4670, 4656), `WinEventLog:Security` (EventCode=4704).
3. **T1572 Protocol Tunneling** — Processes such as plink.exe, ssh.exe, or netsh.exe establishing outbound network connections where traffic patterns show encapsulated protocols (e.g., RDP over SSH). Defender observations include anomalous process-to-network relationships, large asymmetric… Dados: `WinEventLog:Sysmon` (EventCode=3, 22), `WinEventLog:Sysmon` (EventCode=1).
4. **T1657 Financial Theft** — Monitor for anomalous access to financial applications, browser-based banking sessions, or enterprise ERP systems from Windows endpoints. Detect mass emailing of payment instructions, sudden rule changes in Outlook for financial staff, or use of clipboard… Dados: `WinEventLog:Security` (EventCode=4624, 4648), `WinEventLog:Sysmon` (EventCode=1).
5. **T1090 Proxy** — Suspicious process spawning (e.g., `rundll32`, `svchost`, `powershell`, or `netsh`) followed by network connection creation to internal hosts or uncommon external endpoints on high or non-standard ports. Dados: `WinEventLog:Sysmon` (EventCode=3, 22), `WinEventLog:Sysmon` (EventCode=1), `NSM:Connections` (Outbound Connection).
6. **T1059.006 Python** — Detects Python execution via python.exe or py.exe with anomalous parent lineage (e.g., Office macros, LOLBAS), execution from unusual directories, or chained network/PowerShell/system-level activity. Dados: `WinEventLog:Sysmon` (EventCode=1), `EDR:hunting` (Advanced Hunting: DeviceProcessEvents + DeviceNetworkEvents).
7. **T1078.002 Domain Accounts** — Detection of suspicious logon behavior using valid domain accounts across multiple hosts, off-hours, or simultaneous sessions from geographically distant locations. Dados: `WinEventLog:Security` (EventCode=4624, 4625, 4768, 4769), `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=3, 22).
8. **T1567.002 Exfiltration to Cloud Storage** — Unusual processes (e.g., powershell.exe, excel.exe) accessing large local files and subsequently initiating HTTPS POST requests to domains associated with cloud storage services (e.g., dropbox.com, drive.google.com, box.com). Defender perspective: correlation… Dados: `WinEventLog:Security` (EventCode=4663, 4670, 4656), `WinEventLog:Sysmon` (EventCode=3, 22), `WinEventLog:Sysmon` (EventCode=1).
9. **T1543.003 Windows Service** — Detects creation or modification of Windows Services through command-line tools (e.g., `sc.exe`, `powershell.exe`), Registry key changes under `HKLM\System\CurrentControlSet\Services`, and service execution under SYSTEM with unsigned or anomalous binary… Dados: `WinEventLog:Security` (EventCode=4697), `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=13, 14).
10. **T1021.002 SMB/Windows Admin Shares** — An SMB-based remote file share access followed by lateral movement actions such as remote service creation, task scheduling, or suspicious process execution on the target host using ADMIN$ or C$ shares. Dados: `WinEventLog:Security` (EventCode=4624, 4648), `WinEventLog:Sysmon` (EventCode=3, 22), `WinEventLog:Sysmon` (EventCode=1).
11. **T1574.001 DLL** — DLL hijacking behaviors including unexpected DLL loads from non-standard directories, replacement of DLLs, phantom DLL insertion, redirection file creation, and substitution of legitimate DLLs. Defender correlates file system modifications, registry changes,… Dados: `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Sysmon` (EventCode=15), `WinEventLog:Sysmon` (EventCode=7).
12. **T1140 Deobfuscate/Decode Files or Information** — An adversary leverages built-in tools such as certutil.exe, powershell.exe, or copy.exe to decode, reassemble, or extract hidden malicious content from obfuscated containers or encoded formats. The decoding utility often spawns shortly after file staging or… Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Sysmon` (EventCode=10).

## 10. OSINT — onde pesquisar

Consultas prontas com todos os nomes conhecidos do grupo:

- Relatórios técnicos: [busca web](https://duckduckgo.com/?q=%28%22Cinnamon+Tempest%22+OR+%22DEV-0401%22+OR+%22Emperor+Dragonfly%22+OR+%22BRONZE+STARLIGHT%22%29+threat+report) · [PDFs](https://duckduckgo.com/?q=%28%22Cinnamon+Tempest%22+OR+%22DEV-0401%22+OR+%22Emperor+Dragonfly%22+OR+%22BRONZE+STARLIGHT%22%29+filetype%3Apdf)
- Regras e IOCs publicados: [GitHub](https://github.com/search?type=code&q=%22Cinnamon+Tempest%22+OR+%22DEV-0401%22+OR+%22Emperor+Dragonfly%22+OR+%22BRONZE+STARLIGHT%22)
- Pulsos de ameaça: [AlienVault OTX](https://otx.alienvault.com/browse/global/pulses?q=Cinnamon+Tempest)
- Família de malware e atores: [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/actors) (busque por Cinnamon Tempest, DEV-0401, Emperor Dragonfly)
- Cartões de grupo: [ThaiCERT Threat Group Cards](https://apt.etda.or.th/cgi-bin/listgroups.cgi)
- Página oficial: [MITRE ATT&CK G1021](https://attack.mitre.org/groups/G1021/)

## 11. Bibliografia (7 fontes citadas pelo ATT&CK)

- [Dell SecureWorks BRONZE STARLIGHT Profile](https://www.secureworks.com/research/threat-profiles/bronze-starlight) — SecureWorks. (n.d.). BRONZE STARLIGHT. Retrieved December 6, 2023.
- [Microsoft Log4j Vulnerability Exploitation December 2021](https://www.microsoft.com/en-us/security/blog/2021/12/11/guidance-for-preventing-detecting-and-hunting-for-cve-2021-44228-log4j-2-exploitation/) — Microsoft Threat Intelligence. (2021, December 11). Guidance for preventing, detecting, and hunting for exploitation of the Log4j 2 vulnerability. Retrieved December 7, 2023.
- [Microsoft Ransomware as a Service](https://www.microsoft.com/en-us/security/blog/2022/05/09/ransomware-as-a-service-understanding-the-cybercrime-gig-economy-and-how-to-protect-yourself/) — Microsoft. (2022, May 9). Ransomware as a service: Understanding the cybercrime gig economy and how to protect yourself. Retrieved March 10, 2023.
- [Microsoft Threat Actor Naming July 2023](https://learn.microsoft.com/en-us/microsoft-365/security/intelligence/microsoft-threat-actor-naming?view=o365-worldwide) — Microsoft . (2023, July 12). How Microsoft names threat actors. Retrieved November 17, 2023.
- [SecureWorks BRONZE STARLIGHT Ransomware Operations June 2022](https://www.secureworks.com/research/bronze-starlight-ransomware-operations-use-hui-loader) — Counter Threat Unit Research Team . (2022, June 23). BRONZE STARLIGHT RANSOMWARE OPERATIONS USE HUI LOADER. Retrieved December 7, 2023.
- [Sygnia Emperor Dragonfly October 2022](https://blog.sygnia.co/revealing-emperor-dragonfly-a-chinese-ransomware-group) — Biderman, O. et al. (2022, October 3). REVEALING EMPEROR DRAGONFLY: NIGHT SKY AND CHEERSCRYPT - A SINGLE RANSOMWARE GROUP. Retrieved December 6, 2023.
- [Trend Micro Cheerscrypt May 2022](https://www.trendmicro.com/en_se/research/22/e/new-linux-based-ransomware-cheerscrypt-targets-exsi-devices.html) — Dela Cruz, A. et al. (2022, May 25). New Linux-Based Ransomware Cheerscrypt Targeting ESXi Devices Linked to Leaked Babuk Source Code. Retrieved December 19, 2023.

## 12. Limites e confiança

- O ATT&CK registra o que foi **relatado publicamente**, não tudo o que o grupo faz. Ausência de uma técnica não prova que o grupo não a usa.
- **Sobreposição de TTP não é atribuição.** Muitas técnicas são compartilhadas entre grupos e com red teams. Use a assinatura comportamental como hipótese, junto com infraestrutura, malware e contexto.
- Cobertura de detecção refere-se ao catálogo público Detection Rules, não ao seu ambiente: confira se a telemetria necessária chega ao seu SIEM.
- Ligações marcadas como _inferidas_ (EVTX por palavra-chave, relatórios por nome) devem ser verificadas.

---
Fontes: MITRE ATT&CK® (uso livre com atribuição, © The MITRE Corporation), Atomic Red Team (Red Canary, MIT), EVTX-to-MITRE-Attack, EVTX-ATTACK-SAMPLES, APT & CyberCriminal Campaign Collections. Gerado por [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules).
