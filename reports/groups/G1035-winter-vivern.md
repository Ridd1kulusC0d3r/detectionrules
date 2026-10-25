# Winter Vivern (G1035) — Dossiê de inteligência

> **TLP:CLEAR** · gerado em 2026-10-25 a partir de fontes abertas · MITRE ATT&CK v20.0 · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1035) · [ATT&CK](https://attack.mitre.org/groups/G1035/)

**Também conhecido como:** TA473, UAC-0114  
**Registro no ATT&CK:** criado em 2024-07-29, atualizado em 2026-07-31 · referências de 2021 a 2023

## 1. Sumário executivo

- **27 técnicas** atribuídas publicamente, concentradas em **Execution, Collection, Discovery**.
- **Arsenal:** 0 malware e 0 ferramentas.
- **Campanhas atribuídas:** 0.
- **Cobertura de detecção pública:** 93% das técnicas têm ao menos uma regra no catálogo; **2 técnicas sem nenhuma regra pública**.
- **Assinatura comportamental** (técnicas raras entre os 178 grupos, as mais úteis para atribuição): T1056.003 Web Portal Capture, T1584.006 Web Services, T1020 Automated Exfiltration, T1114.001 Local Email Collection, T1595.002 Vulnerability Scanning.

## 2. Quem é

> Winter Vivern is a group linked to Russian and Belorussian interests active since at least 2020 targeting various European government and NGO entities, along with sporadic targeting of Indian and US victims. The group leverages a combination of document-based phishing activity and server-side exploitation for initial access, leveraging adversary-controlled and -created infrastructure for follow-on command and control.

_Texto original do MITRE ATT&CK, em inglês._

## 3. Perfil TTP por tática (kill chain)

Cada linha: técnica, como o grupo a usou segundo relatos públicos, e o que existe para detectar e testar.

### Reconnaissance (TA0043) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1595.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1595.002) Vulnerability Scanning | Winter Vivern has used remotely-hosted instances of the Acunetix vulnerability scanner. | 27 | — | — |

### Resource Development (TA0042) — 3

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1583.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1583.001) Domains | Winter Vivern registered domains mimicking other entities throughout various campaigns. | 7 | — | — |
| [T1583.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1583.003) Virtual Private Server | Winter Vivern used adversary-owned and -controlled servers to host web vulnerability scanning applications. | **0** | — | — |
| [T1584.006](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1584.006) Web Services | Winter Vivern has used compromised WordPress sites to host malicious payloads for download. | 1 | — | — |

### Initial Access (TA0001) — 3

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1189](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1189) Drive-by Compromise | Winter Vivern created dedicated web pages mimicking legitimate government websites to deliver malicious fake anti-virus software. | 57 | — | — |
| [T1190](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1190) Exploit Public-Facing Application | Winter Vivern has exploited known and zero-day vulnerabilities in software usch as Roundcube Webmail servers and the "Follina" vulnerability. | 580 | — | — |
| [T1566.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1566.001) Spearphishing Attachment | Winter Vivern leverages malicious attachments delivered via email for initial access activity. | 230 | 2 | — |

### Execution (TA0002) — 6

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1053.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1053.005) Scheduled Task | Winter Vivern executed PowerShell scripts that would subsequently attempt to establish persistence by creating scheduled tasks objects to periodically retrieve and execute remotely-hosted payloads. | 248 | 14 | 11 |
| [T1059](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059) Command and Scripting Interpreter | Winter Vivern used XLM 4.0 macros for initial code execution for malicious document files. | 1467 | 1 | — |
| [T1059.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.001) PowerShell | Winter Vivern passed execution from document macros to PowerShell scripts during initial access operations. Winter Vivern used batch scripts that called PowerShell commands as part of initial access and installation operations. | 1340 | 22 | 15 |
| [T1059.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.003) Windows Command Shell | Winter Vivern distributed Windows batch scripts disguised as virus scanners to prompt download of malicious payloads using built-in system tools. | 269 | 6 | 1 |
| [T1059.007](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.007) JavaScript | Winter Vivern delivered malicious JavaScript to exploit targets when exploiting Roundcube Webmail servers. | 205 | 5 | — |
| [T1204.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1204.001) Malicious Link | Winter Vivern has mimicked legitimate government-related domains to deliver malicious webpages containing links to documents or other content for user execution. | 52 | — | — |

### Persistence (TA0003) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1053.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1053.005) Scheduled Task | Winter Vivern executed PowerShell scripts that would subsequently attempt to establish persistence by creating scheduled tasks objects to periodically retrieve and execute remotely-hosted payloads. | 248 | 14 | 11 |

### Privilege Escalation (TA0004) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1053.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1053.005) Scheduled Task | Winter Vivern executed PowerShell scripts that would subsequently attempt to establish persistence by creating scheduled tasks objects to periodically retrieve and execute remotely-hosted payloads. | 248 | 14 | 11 |

### Stealth (TA0005) — 3

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1036](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1036) Masquerading | Winter Vivern created specially-crafted documents mimicking legitimate government or similar documents during phishing campaigns. | 453 | 2 | 1 |
| [T1036.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1036.004) Masquerade Task or Service | Winter Vivern has distributed malicious scripts and executables mimicking virus scanners. | 31 | 4 | — |
| [T1140](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1140) Deobfuscate/Decode Files or Information | Winter Vivern delivered exploit payloads via base64-encoded payloads in malicious email messages. | 173 | 11 | 1 |

### Credential Access (TA0006) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1056.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1056.003) Web Portal Capture | Winter Vivern registered and hosted domains to allow for creation of web pages mimicking legitimate government email logon sites to collect logon information. | **0** | — | — |

### Discovery (TA0007) — 3

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1033](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1033) System Owner/User Discovery | Winter Vivern PowerShell scripts execute `whoami` to identify the executing user. | 181 | 8 | — |
| [T1082](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1082) System Information Discovery | Winter Vivern script execution includes basic victim information gathering steps which are then transmitted to command and control servers. | 264 | 41 | — |
| [T1083](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1083) File and Directory Discovery | Winter Vivern delivered malicious JavaScript payloads capable of listing folders and emails in exploited email servers. | 137 | 9 | — |

### Collection (TA0009) — 4

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1056.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1056.003) Web Portal Capture | Winter Vivern registered and hosted domains to allow for creation of web pages mimicking legitimate government email logon sites to collect logon information. | **0** | — | — |
| [T1113](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1113) Screen Capture | Winter Vivern delivered PowerShell scripts capable of taking screenshots of victim machines. | 60 | 10 | — |
| [T1114.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1114.001) Local Email Collection | Winter Vivern delivered malicious JavaScript payloads capable of exfiltrating email messages from exploited email servers. | 15 | 1 | — |
| [T1119](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1119) Automated Collection | Winter Vivern delivered a PowerShell script capable of recursively scanning victim machines looking for various file types before exfiltrating identified files via HTTP. | 72 | 4 | — |

### Command and Control (TA0011) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1071.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1071.001) Web Protocols | Winter Vivern uses HTTP and HTTPS protocols for exfiltration and command and control activity. | 228 | 3 | — |
| [T1105](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1105) Ingress Tool Transfer | Winter Vivern executed PowerShell scripts to create scheduled tasks to retrieve remotely-hosted payloads. | 644 | 39 | — |

### Exfiltration (TA0010) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1020](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1020) Automated Exfiltration | Winter Vivern delivered a PowerShell script capable of recursively scanning victim machines looking for various file types before exfiltrating identified files via HTTP. | 69 | 2 | — |
| [T1041](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1041) Exfiltration Over C2 Channel | Winter Vivern delivered a PowerShell script capable of recursively scanning victim machines looking for various file types before exfiltrating identified files via HTTP. | 135 | 2 | — |

## 4. Assinatura comportamental

Técnicas que este grupo usa e que poucos dos 178 grupos do ATT&CK usam. Pesam mais numa atribuição por TTP: ver várias delas juntas é mais informativo do que ver técnicas comuns como PowerShell.

| Técnica | Outros grupos que usam | Peso (raridade) |
|---|---:|---:|
| T1056.003 Web Portal Capture | 1 | 4.09 |
| T1584.006 Web Services | 3 | 3.58 |
| T1020 Automated Exfiltration | 6 | 3.11 |
| T1114.001 Local Email Collection | 8 | 2.88 |
| T1595.002 Vulnerability Scanning | 14 | 2.42 |
| T1059 Command and Scripting Interpreter | 16 | 2.30 |
| T1113 Screen Capture | 18 | 2.19 |
| T1583.003 Virtual Private Server | 18 | 2.19 |
| T1036 Masquerading | 20 | 2.10 |
| T1119 Automated Collection | 20 | 2.10 |

## 5. Arsenal

Nenhum software atribuído no ATT&CK.

## 6. Campanhas

Nenhuma campanha atribuída no ATT&CK.

## 7. Cobertura defensiva

**25 de 27 técnicas (93%)** têm ao menos uma regra pública no catálogo Detection Rules.

### Técnicas sem regra pública (prioridade para engenharia de detecção)

- **T1056.003 Web Portal Capture** — Collection. Fonte de log sugerida pelo MITRE: `auditd:SYSCALL` write; `WinEventLog:Sysmon` EventCode=11; `fs:fsusage` Filesystem Access Logging
- **T1583.003 Virtual Private Server** — Resource Development. Fonte de log sugerida pelo MITRE: `Internet Scan` None

### Regras recomendadas por técnica

Melhor regra disponível por técnica (formato portável e maduro primeiro).

| Técnica | Regra | Formato | Fonte |
|---|---|---|---|
| T1020 | [Restore Public AWS RDS Instance](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac3f265c7-ff03-4056-8ab2-d486227b4599) | Sigma | SigmaHQ |
| T1020 | [Restore Public AWS RDS Instance](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Ac3f265c7-ff03-4056-8ab2-d486227b4599) | Sigma | OpenSearch Security Analytics |
| T1033 | [Potential Dridex Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae6eb5a96-9e6f-4a18-9cdd-642cfda21c8e) | Sigma | SigmaHQ |
| T1033 | [Dridex Process Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Ae6eb5a96-9e6f-4a18-9cdd-642cfda21c8e) | Sigma | OpenSearch Security Analytics |
| T1036 | [Potential LSASS Process Dump Via Procdump](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A5afee48e-67dd-4e03-a783-f74259dcf998) | Sigma | SigmaHQ |
| T1036 | [Suspicious Use of Procdump on LSASS](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A5afee48e-67dd-4e03-a783-f74259dcf998) | Sigma | OpenSearch Security Analytics |
| T1036.004 | [Operation Wocao Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1cfac73c-be78-4f9a-9b08-5bde0c3953ab) | Sigma | SigmaHQ |
| T1036.004 | [Operation Wocao Activity - Security](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A74ad4314-482e-4c3e-b237-3f7ed3b9ca8d) | Sigma | SigmaHQ |
| T1041 | [Equation Group C2 Communication](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A881834a4-6659-4773-821e-1c151789d873) | Sigma | SigmaHQ |
| T1041 | [OpenCanary - TFTP Request](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab4e6b016-a2ac-4759-ad85-8000b300d61e) | Sigma | SigmaHQ |
| T1053.005 | [Operation Wocao Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1cfac73c-be78-4f9a-9b08-5bde0c3953ab) | Sigma | SigmaHQ |
| T1053.005 | [Operation Wocao Activity - Security](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A74ad4314-482e-4c3e-b237-3f7ed3b9ca8d) | Sigma | SigmaHQ |
| T1059 | [Windows Defender Threat Detected](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A57b649ef-ff42-4fb0-8bf6-62da243a1708) | Sigma | OpenSearch Security Analytics |
| T1059 | [Windows Defender AMSI Trigger Detected](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Aea9bf0fa-edec-4fb8-8b78-b119f2528186) | Sigma | OpenSearch Security Analytics |
| T1059.001 | [Potential Emotet Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad02e8cf5-6099-48cf-9bfc-1eec2d0c7b18) | Sigma | SigmaHQ |
| T1059.001 | [TropicTrooper Campaign November 2018](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A8c7090c3-e0a0-4944-bd08-08c3a0cecf79) | Sigma | SigmaHQ |
| T1059.003 | [HackTool - CrackMapExec Execution Patterns](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A058f4380-962d-40a5-afce-50207d36d7e2) | Sigma | SigmaHQ |
| T1059.003 | [CrackMapExec Command Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A058f4380-962d-40a5-afce-50207d36d7e2) | Sigma | OpenSearch Security Analytics |
| T1059.007 | [Adwind RAT / JRAT](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1fac1481-2dbc-48b2-9096-753c49b4ec71) | Sigma | SigmaHQ |
| T1059.007 | [WScript or CScript Dropper - File](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A002bdb95-0cf1-46a6-9e08-d38c128a6127) | Sigma | SigmaHQ |
| T1071.001 | [Ursnif Malware Download URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aa36ce77e-30db-4ea0-8795-644d7af5dfb4) | Sigma | SigmaHQ |
| T1071.001 | [Ursnif Malware C2 URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A932ac737-33ca-4afd-9869-0d48b391fcc9) | Sigma | SigmaHQ |
| T1082 | [Potential GobRAT File Discovery Via Grep](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae34cfa0c-0a50-4210-9cb3-5632d08eb041) | Sigma | SigmaHQ |
| T1082 | [System Information Discovery](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A42df45e7-e6e9-43b5-8f26-bec5b39cc239) | Sigma | SigmaHQ |
| T1083 | [Turla Group Lateral Movement](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac601f20d-570a-4cde-a7d6-e17f99cb8e7f) | Sigma | SigmaHQ |
| T1083 | [WannaCry Ransomware Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A41d40bff-377a-43e2-8e1b-2e543069e079) | Sigma | SigmaHQ |
| T1105 | [Greenbug Espionage Group Indicators](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A3711eee4-a808-4849-8a14-faf733da3612) | Sigma | SigmaHQ |
| T1105 | [Pandemic Registry Key](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A47e0852a-cf81-4494-a8e6-31864f8c86ed) | Sigma | SigmaHQ |
| T1113 | [PowerShell Suspicious Script with Screenshot Capabilities](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A959a7353-1129-4aa7-9084-30746b256a70) | Elastic | Elastic detection-rules |
| T1113 | [Potential Remote Desktop Shadowing Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ac57f8579-e2a5-4804-847f-f2732edc5156) | Elastic | Elastic detection-rules |
| T1114.001 | [Powershell Local Email Collection](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A2837e152-93c8-43d2-85ba-c3cd3c2ae614) | Sigma | SigmaHQ |
| T1114.001 | [Exporting Exchange Mailbox via PowerShell](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A6aace640-e631-4870-ba8e-5fdda09325db) | Elastic | Elastic detection-rules |
| T1119 | [iOS Implant URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Ae06ac91d-b9e6-443d-8e5b-af749e7aa6b6) | Sigma | OpenSearch Security Analytics |
| T1119 | [Shai-Hulud Malicious GitHub Workflow Creation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A0aba5685-6db6-486f-88ef-29a99c545cfd) | Sigma | SigmaHQ |
| T1140 | [UNC4841 - SSL Certificate Exfiltration Via Openssl](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A60911c07-f989-4362-84af-c609828ef829) | Sigma | SigmaHQ |
| T1140 | [UNC4841 - Download Compressed Files From Temp.sh Using Wget](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A60d050c4-e253-4d9a-b673-5ac100cfddfb) | Sigma | SigmaHQ |
| T1189 | [Flash Player Update from Suspicious Location](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4922a5dd-6743-4fc2-8e81-144374280997) | Sigma | SigmaHQ |
| T1189 | [Cross Site Scripting Strings](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A65354b83-a2ea-4ea6-8414-3ab38be0d409) | Sigma | SigmaHQ |
| T1190 | [OMIGOD HTTP No Authentication RCE - CVE-2021-38647](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aab6b1a39-a9ee-4ab4-b075-e83acf6e346b) | Sigma | SigmaHQ |
| T1190 | [Exploited CVE-2020-10189 Zoho ManageEngine](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A846b866e-2a57-46ee-8e16-85fa92759be7) | Sigma | OpenSearch Security Analytics |
| T1204.001 | [Google Workspace Object Copied from External Drive with App Consent](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Af33e68a4-bd19-11ed-b02f-f661ea17fbcc) | Elastic | Elastic detection-rules |
| T1204.001 | [Suspicious ClickFix/FileFix Execution Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad487ed4a-fd24-436d-a0b2-f4e95f7b2635) | Sigma | SigmaHQ |
| T1566.001 | [Ursnif Malware C2 URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A932ac737-33ca-4afd-9869-0d48b391fcc9) | Sigma | SigmaHQ |
| T1566.001 | [Droppers Exploiting CVE-2017-11882](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A678eb5f4-8597-4be6-8be7-905e4234b53a) | Sigma | SigmaHQ |
| T1583.001 | [AWS Route 53 Private Hosted Zone Associated With a VPC](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ae3c27562-709a-42bd-82f2-3ed926cced19) | Elastic | Elastic detection-rules |
| T1583.001 | [AWS SES Email Identity Verified Then Deleted](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A8e4bde35-125d-4eb3-9a2e-d7e77a053a08) | Elastic | Elastic detection-rules |
| T1584.006 | [Suspicious PowerShell Mailbox Export to Share](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A889719ef-dd62-43df-86c3-768fb08dc7c0) | Sigma | OpenSearch Security Analytics |
| T1595.002 | [DNS Query to External Service Interaction Domains](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aaff715fa-4dd5-497a-8db3-910bea555566) | Sigma | SigmaHQ |
| T1595.002 | [Web Server Potential SQL Injection Request](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A7f7a0ee1-7b6f-466a-85b4-110fb105f5e2) | Elastic | Elastic detection-rules |

## 8. Plano de emulação e validação

Use num laboratório isolado e autorizado para confirmar que as regras disparam. Os comandos estão nos repositórios oficiais.

| Tática | Técnica | Teste Atomic Red Team | Plataformas |
|---|---|---|---|
| Initial Access | [T1566.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1566.001/T1566.001.md) | Download Macro-Enabled Phishing Attachment | windows |
| Initial Access | [T1566.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1566.001/T1566.001.md) | Word spawned a command shell and used an IP address in the command line | windows |
| Execution | [T1053.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1053.005/T1053.005.md) | Scheduled Task Startup Script | windows |
| Execution | [T1053.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1053.005/T1053.005.md) | Scheduled task Local | windows |
| Execution | [T1059](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059/T1059.md) | AutoIt Script Execution | windows |
| Execution | [T1059.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md) | Mimikatz | windows |
| Execution | [T1059.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md) | Run BloodHound from local disk | windows |
| Execution | [T1059.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.003/T1059.003.md) | Create and Execute Batch Script | windows |
| Execution | [T1059.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.003/T1059.003.md) | Writes text to a file and displays it. | windows |
| Execution | [T1059.007](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.007/T1059.007.md) | JScript execution to gather local computer information via cscript | windows |
| Execution | [T1059.007](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.007/T1059.007.md) | JScript execution to gather local computer information via wscript | windows |
| Stealth | [T1036](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036/T1036.md) | System File Copied to Unusual Location | windows |
| Stealth | [T1036](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036/T1036.md) | Malware Masquerading and Execution from Zip File | windows |
| Stealth | [T1036.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.004/T1036.004.md) | Creating W32Time similar named service using schtasks | windows |
| Stealth | [T1036.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.004/T1036.004.md) | Creating W32Time similar named service using sc | windows |
| Stealth | [T1140](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1140/T1140.md) | Deobfuscate/Decode Files Or Information | windows |
| Stealth | [T1140](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1140/T1140.md) | Certutil Rename and Decode | windows |
| Discovery | [T1033](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1033/T1033.md) | System Owner/User Discovery | windows |
| Discovery | [T1033](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1033/T1033.md) | System Owner/User Discovery | linux, macos |
| Discovery | [T1082](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1082/T1082.md) | System Information Discovery | windows |
| Discovery | [T1082](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1082/T1082.md) | System Information Discovery | macos |
| Discovery | [T1083](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1083/T1083.md) | File and Directory Discovery (cmd.exe) | windows |
| Discovery | [T1083](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1083/T1083.md) | File and Directory Discovery (PowerShell) | windows |
| Collection | [T1113](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1113/T1113.md) | Screencapture | macos |
| Collection | [T1113](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1113/T1113.md) | Screencapture (silent) | macos |
| Collection | [T1114.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1114.001/T1114.001.md) | Email Collection with PowerShell Get-Inbox | windows |
| Collection | [T1119](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1119/T1119.md) | Automated Collection Command Prompt | windows |
| Collection | [T1119](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1119/T1119.md) | Automated Collection PowerShell | windows |
| Command and Control | [T1071.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1071.001/T1071.001.md) | Malicious User Agents - Powershell | windows |
| Command and Control | [T1071.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1071.001/T1071.001.md) | Malicious User Agents - CMD | windows |
| Command and Control | [T1105](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1105/T1105.md) | rsync remote file copy (push) | linux, macos |
| Command and Control | [T1105](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1105/T1105.md) | rsync remote file copy (pull) | linux, macos |
| Exfiltration | [T1020](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1020/T1020.md) | IcedID Botnet HTTP PUT | windows |
| Exfiltration | [T1020](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1020/T1020.md) | Exfiltration via Encrypted FTP | windows |
| Exfiltration | [T1041](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1041/T1041.md) | C2 Data Exfiltration | windows |
| Exfiltration | [T1041](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1041/T1041.md) | Text Based Data Exfiltration using DNS subdomains | windows |

**Logs reais de ataque (EVTX) para testar sem executar nada:**

- T1036 — [rundll32_hollowing_wermgr_masquerading](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/AutomatedTestingTools/Malware/rundll32_hollowing_wermgr_masquerading.evtx) _(inferido)_
- T1053.005 — [ID4688-4698 Persistent scheduled task with SYSTEM privileges creation](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1053.005-Scheduled%20Task/ID4688-4698%20Persistent%20scheduled%20task%20with%20SYSTEM%20privileges%20creation.evtx) _(explícito)_
- T1053.005 — [ID4688-Interactive shell using AT schedule task](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1053.005-Scheduled%20Task/ID4688-Interactive%20shell%20using%20AT%20schedule%20task.evtx) _(explícito)_
- T1059.001 — [ID4103-4104-Payload download via PowerShell](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1059.001-PowerShell/ID4103-4104-Payload%20download%20via%20PowerShell.evtx) _(explícito)_
- T1059.001 — [ID4688-Encoded PowerShell MSF payload via process execution](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1059.001-PowerShell/ID4688-Encoded%20PowerShell%20MSF%20payload%20via%20process%20execution.evtx) _(explícito)_
- T1059.003 — [ID4688-SQL Server payload injectection for reverse shell (MSF)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1059.003-Windows%20Command%20Shell/ID4688-SQL%20Server%20payload%20injectection%20for%20reverse%20shell%20%28MSF%29.evtx) _(explícito)_
- T1140 — [ID4688-Certutil download](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0005-Defense%20Evasion/T1140-Deobfuscate-Decode%20Files%20or%20Information/ID4688-Certutil%20download.evtx) _(explícito)_

## 9. Hipóteses de hunting

Se Winter Vivern estiver no seu ambiente, estas são as perguntas a fazer aos seus dados (fontes de log segundo as estratégias de detecção do MITRE ATT&CK).

1. **T1056.003 Web Portal Capture** — Detects unauthorized modifications to login-facing web server files (e.g., index.php, login.js) typically tied to VPN, SSO, or intranet portals. Correlates suspicious file changes with remote access artifacts or web shell behavior. Dados: `auditd:SYSCALL` (write), `NSM:Flow` (HTTP Request Logging).
2. **T1584.006 Web Services** — Once adversaries leverage the abused web service as infrastructure (ex: for command and control), it may be possible to look for unique characteristics associated with adversary software, if known. Much of this activity will take place outside the visibility… Dados: `Internet Scan` (None).
3. **T1020 Automated Exfiltration** — Detection of automated tools or scripts periodically transmitting data to external destinations using scheduled tasks or background processes. Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=3, 22).
4. **T1114.001 Local Email Collection** — Detection focuses on processes that attempt to locate, access, or exfiltrate local Outlook data files (.pst/.ost) using file system access, native Windows utilities (e.g., PowerShell, WMI), or remote access tools with file browsing capabilities. The behavior… Dados: `WinEventLog:Security` (EventCode=4663, 4670, 4656), `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=11).
5. **T1595.002 Vulnerability Scanning** — Monitor and analyze traffic patterns and packet inspection associated to protocol(s) that do not follow the expected protocol standards and traffic flows (e.g extraneous packets that do not belong to established flows, gratuitous or anomalous traffic… Dados: `Network Traffic` (None), `Network Traffic` (None).
6. **T1059 Command and Scripting Interpreter** — Detects the execution of scripting or command interpreters (e.g., powershell.exe, cmd.exe, wscript.exe) outside expected administrative time windows or from abnormal user contexts, often followed by encoded/obfuscated arguments or secondary execution events. Dados: `WinEventLog:Sysmon` (EventCode=1).
7. **T1113 Screen Capture** — Unusual use of screen capture APIs (e.g., CopyFromScreen) or command-line tools to write image files to disk. Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=7).
8. **T1583.003 Virtual Private Server** — Once adversaries have provisioned a VPS (ex: for use as a command and control server), internet scans may reveal servers that adversaries have acquired. Consider looking for identifiable patterns such as services listening, certificates in use, SSL/TLS… Dados: `Internet Scan` (None), `Internet Scan` (None).
9. **T1036 Masquerading** — Adversary renames LOLBINs or deploys binaries with spoofed file names, internal PE metadata, or misleading icons to appear legitimate. File creation is followed by execution or service registration inconsistent with known usage. Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:System` (EventCode=7045).
10. **T1119 Automated Collection** — Automated execution of native utilities and scripts to discover, enumerate, and exfiltrate files and clipboard content. Focus is on detecting repeated file access, scripting engine use, and use of command-line utilities commonly leveraged by collection… Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=11).
11. **T1036.004 Masquerade Task or Service** — Creation or modification of Windows services or scheduled tasks with names or descriptions mimicking legitimate entries, followed by anomalous execution of untrusted binaries or LOLBAS. Dados: `WinEventLog:System` (EventCode=7045), `WinEventLog:Security` (EventCode=4698), `WinEventLog:Sysmon` (EventCode=1).
12. **T1041 Exfiltration Over C2 Channel** — Identifies suspicious outbound traffic volume mismatches from processes that typically do not generate network activity, particularly over C2 protocols like HTTPS, DNS, or custom TCP/UDP ports, following file or data access. Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=3, 22), `NSM:Flow` (Flow/PCAP analysis for outbound payloads).

## 10. OSINT — onde pesquisar

Consultas prontas com todos os nomes conhecidos do grupo:

- Relatórios técnicos: [busca web](https://duckduckgo.com/?q=%28%22Winter+Vivern%22+OR+%22TA473%22+OR+%22UAC-0114%22%29+threat+report) · [PDFs](https://duckduckgo.com/?q=%28%22Winter+Vivern%22+OR+%22TA473%22+OR+%22UAC-0114%22%29+filetype%3Apdf)
- Regras e IOCs publicados: [GitHub](https://github.com/search?type=code&q=%22Winter+Vivern%22+OR+%22TA473%22+OR+%22UAC-0114%22)
- Pulsos de ameaça: [AlienVault OTX](https://otx.alienvault.com/browse/global/pulses?q=Winter+Vivern)
- Família de malware e atores: [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/actors) (busque por Winter Vivern, TA473, UAC-0114)
- Cartões de grupo: [ThaiCERT Threat Group Cards](https://apt.etda.or.th/cgi-bin/listgroups.cgi)
- Página oficial: [MITRE ATT&CK G1035](https://attack.mitre.org/groups/G1035/)

## 11. Bibliografia (5 fontes citadas pelo ATT&CK)

- [CERT-UA WinterVivern 2023](https://cert.gov.ua/article/3761104) — CERT-UA. (2023, February 1). UAC-0114 aka Winter Vivern to target Ukrainian and Polish GOV entities (CERT-UA#5909). Retrieved July 29, 2024.
- [DomainTools WinterVivern 2021](https://www.domaintools.com/resources/blog/winter-vivern-a-look-at-re-crafted-government-maldocs/) — Chad Anderson. (2021, April 27). Winter Vivern: A Look At Re-Crafted Government MalDocs Targeting Multiple Languages. Retrieved July 29, 2024.
- [ESET WinterVivern 2023](https://www.welivesecurity.com/en/eset-research/winter-vivern-exploits-zero-day-vulnerability-roundcube-webmail-servers/) — Matthieu Faou. (2023, October 25). Winter Vivern exploits zero-day vulnerability in Roundcube Webmail servers. Retrieved July 29, 2024.
- [Proofpoint WinterVivern 2023](https://www.proofpoint.com/us/blog/threat-insight/exploitation-dish-best-served-cold-winter-vivern-uses-known-zimbra-vulnerability) — Michael Raggi & The Proofpoint Threat Research Team. (2023, March 30). Exploitation is a Dish Best Served Cold: Winter Vivern Uses Known Zimbra Vulnerability to Target Webmail Portals of NATO-Aligned Governments in Europ
- [SentinelOne WinterVivern 2023](https://www.sentinelone.com/labs/winter-vivern-uncovering-a-wave-of-global-espionage/) — Tom Hegel. (2023, March 16). Winter Vivern | Uncovering a Wave of Global Espionage. Retrieved July 29, 2024.

## 12. Limites e confiança

- O ATT&CK registra o que foi **relatado publicamente**, não tudo o que o grupo faz. Ausência de uma técnica não prova que o grupo não a usa.
- **Sobreposição de TTP não é atribuição.** Muitas técnicas são compartilhadas entre grupos e com red teams. Use a assinatura comportamental como hipótese, junto com infraestrutura, malware e contexto.
- Cobertura de detecção refere-se ao catálogo público Detection Rules, não ao seu ambiente: confira se a telemetria necessária chega ao seu SIEM.
- Ligações marcadas como _inferidas_ (EVTX por palavra-chave, relatórios por nome) devem ser verificadas.

---
Fontes: MITRE ATT&CK® (uso livre com atribuição, © The MITRE Corporation), Atomic Red Team (Red Canary, MIT), EVTX-to-MITRE-Attack, EVTX-ATTACK-SAMPLES, APT & CyberCriminal Campaign Collections. Gerado por [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules).
