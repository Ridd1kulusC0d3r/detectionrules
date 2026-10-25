# Moonstone Sleet (G1036) — Dossiê de inteligência

> **TLP:CLEAR** · gerado em 2026-10-25 a partir de fontes abertas · MITRE ATT&CK v20.0 · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1036) · [ATT&CK](https://attack.mitre.org/groups/G1036/)

**Também conhecido como:** Storm-1789  
**Registro no ATT&CK:** criado em 2024-08-26, atualizado em 2026-07-31 · referências de 2024 a 2025

## 1. Sumário executivo

- **30 técnicas** atribuídas publicamente, concentradas em **Resource Development, Discovery, Stealth**.
- **Arsenal:** 1 malware e 0 ferramentas (ex.: Qilin).
- **Campanhas atribuídas:** 0.
- **Cobertura de detecção pública:** 90% das técnicas têm ao menos uma regra no catálogo; **3 técnicas sem nenhuma regra pública**.
- **Assinatura comportamental** (técnicas raras entre os 178 grupos, as mais úteis para atribuição): T1027.009 Embedded Payloads, T1587 Develop Capabilities, T1598 Phishing for Information, T1217 Browser Information Discovery, T1591 Gather Victim Org Information.

## 2. Quem é

> Moonstone Sleet is a North Korean-linked threat actor executing both financially motivated attacks and espionage operations. The group previously overlapped significantly with another North Korean-linked entity, Lazarus Group, but has differentiated its tradecraft since 2023. Moonstone Sleet is notable for creating fake companies and personas to interact with victim entities, as well as developing unique malware such as a variant delivered via a fully functioning game.

_Texto original do MITRE ATT&CK, em inglês._

## 3. Perfil TTP por tática (kill chain)

Cada linha: técnica, como o grupo a usou segundo relatos públicos, e o que existe para detectar e testar.

### Reconnaissance (TA0043) — 4

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1589.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1589.002) Email Addresses | Moonstone Sleet gathered victim email address information for follow-on phishing activity. | 5 | — | — |
| [T1591](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1591) Gather Victim Org Information | Moonstone Sleet has gathered information on victim organizations through email and social media interaction. | 2 | — | — |
| [T1598](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1598) Phishing for Information | Moonstone Sleet has interacted with victims to gather information via email. | 4 | — | — |
| [T1598.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1598.003) Spearphishing Link | Moonstone Sleet used spearphishing messages containing items such as tracking pixels to determine if users interacted with malicious messages. | **0** | — | — |

### Resource Development (TA0042) — 7

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1583.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1583.001) Domains | Moonstone Sleet registered domains to develop effective personas for fake companies used in phishing activity. | 7 | — | — |
| [T1583.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1583.003) Virtual Private Server | Moonstone Sleet registered virtual private servers to host payloads for download. | **0** | — | — |
| [T1585.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1585.001) Social Media Accounts | Moonstone Sleet has created social media accounts to interact with victims. | 4 | — | — |
| [T1585.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1585.002) Email Accounts | Moonstone Sleet has created email accounts to interact with victims, including for phishing purposes. | **0** | — | — |
| [T1587](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1587) Develop Capabilities | Moonstone Sleet developed malicious npm packages for delivery to or retrieval by victims. | 22 | — | — |
| [T1587.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1587.001) Malware | Moonstone Sleet has developed custom malware, including a malware delivery mechanism masquerading as a legitimate game. | 43 | — | — |
| [T1608.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1608.001) Upload Malware | Moonstone Sleet staged malicious capabilities online for follow-on download by victims or malware. | 3 | — | — |

### Initial Access (TA0001) — 3

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1195.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1195.002) Compromise Software Supply Chain | Moonstone Sleet has distributed a trojanized version of PuTTY software for initial access to victims. | 74 | 1 | — |
| [T1566.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1566.001) Spearphishing Attachment | Moonstone Sleet delivered various payloads to victims as spearphishing attachments. | 230 | 2 | — |
| [T1566.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1566.003) Spearphishing via Service | Moonstone Sleet has used social media services to spear phish victims to deliver trojainized software. | 8 | — | — |

### Execution (TA0002) — 3

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1053.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1053.005) Scheduled Task | Moonstone Sleet used scheduled tasks for program execution during initial access to victim machines. | 248 | 14 | 11 |
| [T1204.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1204.002) Malicious File | Moonstone Sleet relied on users interacting with malicious files, such as a trojanized PuTTY installer, for initial execution. | 259 | 13 | — |
| [T1569.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1569.002) Service Execution | Moonstone Sleet used intermediate loader malware such as YouieLoader and SplitLoader that create malicious services. | 230 | 8 | 8 |

### Persistence (TA0003) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1053.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1053.005) Scheduled Task | Moonstone Sleet used scheduled tasks for program execution during initial access to victim machines. | 248 | 14 | 11 |
| [T1547.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1547.001) Registry Run Keys / Startup Folder | Moonstone Sleet used registry run keys for process execution during initial victim infection. | 299 | 21 | 2 |

### Privilege Escalation (TA0004) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1053.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1053.005) Scheduled Task | Moonstone Sleet used scheduled tasks for program execution during initial access to victim machines. | 248 | 14 | 11 |
| [T1547.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1547.001) Registry Run Keys / Startup Folder | Moonstone Sleet used registry run keys for process execution during initial victim infection. | 299 | 21 | 2 |

### Stealth (TA0005) — 4

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1027](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1027) Obfuscated Files or Information | Moonstone Sleet delivers encrypted payloads in pieces that are then combined together to form a new portable executable (PE) file during installation. | 520 | 11 | 5 |
| [T1027.009](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1027.009) Embedded Payloads | Moonstone Sleet embedded payloads in trojanized software for follow-on execution. | 4 | — | — |
| [T1027.013](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1027.013) Encrypted/Encoded File | Moonstone Sleet has used encrypted payloads within files for follow-on execution and defense evasion. | 8 | 4 | — |
| [T1140](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1140) Deobfuscate/Decode Files or Information | Moonstone Sleet delivered payloads using multiple rounds of obfuscation and encoding to evade defenses and analysis. | 173 | 11 | 1 |

### Credential Access (TA0006) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1003.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1003.001) LSASS Memory | Moonstone Sleet retrieved credentials from LSASS memory. | 580 | 14 | 10 |

### Discovery (TA0007) — 4

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1016](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1016) System Network Configuration Discovery | Moonstone Sleet has gathered information on victim network configuration. | 99 | 10 | 5 |
| [T1033](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1033) System Owner/User Discovery | Moonstone Sleet deployed various malware such as YouieLoader that can perform system user discovery actions. | 181 | 8 | — |
| [T1082](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1082) System Information Discovery | Moonstone Sleet has gathered information on victim systems. | 264 | 41 | — |
| [T1217](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1217) Browser Information Discovery | Moonstone Sleet deployed malware such as YouieLoader capable of capturing victim system browser information. | 19 | 11 | — |

### Command and Control (TA0011) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1071.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1071.001) Web Protocols | Moonstone Sleet used curl to connect to adversary-controlled infrastructure and retrieve additional payloads. | 228 | 3 | — |
| [T1105](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1105) Ingress Tool Transfer | Moonstone Sleet retrieved a final stage payload from command and control infrastructure during initial installation on victim systems. | 644 | 39 | — |

### Impact (TA0040) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1486](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1486) Data Encrypted for Impact | Moonstone Sleet has deployed ransomware in victim environments. | 160 | 10 | 1 |

## 4. Assinatura comportamental

Técnicas que este grupo usa e que poucos dos 178 grupos do ATT&CK usam. Pesam mais numa atribuição por TTP: ver várias delas juntas é mais informativo do que ver técnicas comuns como PowerShell.

| Técnica | Outros grupos que usam | Peso (raridade) |
|---|---:|---:|
| T1027.009 Embedded Payloads | 2 | 3.80 |
| T1587 Develop Capabilities | 3 | 3.58 |
| T1598 Phishing for Information | 5 | 3.24 |
| T1217 Browser Information Discovery | 6 | 3.11 |
| T1591 Gather Victim Org Information | 7 | 2.99 |
| T1195.002 Compromise Software Supply Chain | 8 | 2.88 |
| T1589.002 Email Addresses | 13 | 2.48 |
| T1566.003 Spearphishing via Service | 14 | 2.42 |
| T1569.002 Service Execution | 15 | 2.35 |
| T1598.003 Spearphishing Link | 15 | 2.35 |

## 5. Arsenal

| Software | Tipo | Técnicas no ATT&CK | Uso relatado (EN) |
|---|---|---:|---|
| [Qilin](https://attack.mitre.org/software/S1242/) | malware | 52 | Moonstone Sleet has deployed Qilin ransomware. |

## 6. Campanhas

Nenhuma campanha atribuída no ATT&CK.

## 7. Cobertura defensiva

**27 de 30 técnicas (90%)** têm ao menos uma regra pública no catálogo Detection Rules.

### Técnicas sem regra pública (prioridade para engenharia de detecção)

- **T1598.003 Spearphishing Link** — Reconnaissance. Fonte de log sugerida pelo MITRE: `Application Log` None
- **T1583.003 Virtual Private Server** — Resource Development. Fonte de log sugerida pelo MITRE: `Internet Scan` None
- **T1585.002 Email Accounts** — Resource Development

### Regras recomendadas por técnica

Melhor regra disponível por técnica (formato portável e maduro primeiro).

| Técnica | Regra | Formato | Fonte |
|---|---|---|---|
| T1003.001 | [Antivirus - Password Dumper Signature](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A78cc2dd2-7d20-4d32-93ff-057084c38b93) | Sigma | SigmaHQ |
| T1003.001 | [Mimikatz through Windows Remote Management](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Aaa35a627-33fb-4d04-a165-d33b4afca3e8) | Sigma | OpenSearch Security Analytics |
| T1016 | [Potential Pikabot Discovery Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A698d4431-514f-4c82-af4d-cf573872a9f5) | Sigma | SigmaHQ |
| T1016 | [OpenCanary - SNMP OID Request](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae9856028-fd4e-46e6-b3d1-10f7ceb95078) | Sigma | SigmaHQ |
| T1027 | [Potential Emotet Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad02e8cf5-6099-48cf-9bfc-1eec2d0c7b18) | Sigma | SigmaHQ |
| T1027 | [Emotet Process Creation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Ad02e8cf5-6099-48cf-9bfc-1eec2d0c7b18) | Sigma | OpenSearch Security Analytics |
| T1027.009 | [Powershell Token Obfuscation - Process Creation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Adeb9b646-a508-44ee-b7c9-d8965921c6b6) | Sigma | SigmaHQ |
| T1027.009 | [Powershell Token Obfuscation - Powershell](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Af3a98ce4-6164-4dd4-867c-4d83de7eca51) | Sigma | SigmaHQ |
| T1027.013 | [ROT Encoded Python Script Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A5ab49127-b1b3-46e6-8a38-9e8512a2a363) | Elastic | Elastic detection-rules |
| T1027.013 | [Data Encrypted via OpenSSL Utility](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Afeba48f6-40ca-4d04-b41f-5dfa327de865) | Elastic | Elastic detection-rules |
| T1033 | [Potential Dridex Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae6eb5a96-9e6f-4a18-9cdd-642cfda21c8e) | Sigma | SigmaHQ |
| T1033 | [Dridex Process Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Ae6eb5a96-9e6f-4a18-9cdd-642cfda21c8e) | Sigma | OpenSearch Security Analytics |
| T1053.005 | [Operation Wocao Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1cfac73c-be78-4f9a-9b08-5bde0c3953ab) | Sigma | SigmaHQ |
| T1053.005 | [Operation Wocao Activity - Security](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A74ad4314-482e-4c3e-b237-3f7ed3b9ca8d) | Sigma | SigmaHQ |
| T1071.001 | [Ursnif Malware Download URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aa36ce77e-30db-4ea0-8795-644d7af5dfb4) | Sigma | SigmaHQ |
| T1071.001 | [Ursnif Malware C2 URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A932ac737-33ca-4afd-9869-0d48b391fcc9) | Sigma | SigmaHQ |
| T1082 | [Potential GobRAT File Discovery Via Grep](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae34cfa0c-0a50-4210-9cb3-5632d08eb041) | Sigma | SigmaHQ |
| T1082 | [System Information Discovery](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A42df45e7-e6e9-43b5-8f26-bec5b39cc239) | Sigma | SigmaHQ |
| T1105 | [Greenbug Espionage Group Indicators](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A3711eee4-a808-4849-8a14-faf733da3612) | Sigma | SigmaHQ |
| T1105 | [Pandemic Registry Key](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A47e0852a-cf81-4494-a8e6-31864f8c86ed) | Sigma | SigmaHQ |
| T1140 | [UNC4841 - SSL Certificate Exfiltration Via Openssl](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A60911c07-f989-4362-84af-c609828ef829) | Sigma | SigmaHQ |
| T1140 | [UNC4841 - Download Compressed Files From Temp.sh Using Wget](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A60d050c4-e253-4d9a-b673-5ac100cfddfb) | Sigma | SigmaHQ |
| T1195.002 | [Elastic Defend Alert from Package Manager Install Ancestry](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A344e6c7d-ceb0-4f20-ba04-7c75569a7e38) | Elastic | Elastic detection-rules |
| T1195.002 | [Elastic Defend Alert from GenAI Utility or Descendant](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ad4e5f6a7-b8c9-7d0e-1f2a-3b4c5d6e7f8a) | Elastic | Elastic detection-rules |
| T1204.002 | [Ursnif Malware C2 URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A932ac737-33ca-4afd-9869-0d48b391fcc9) | Sigma | SigmaHQ |
| T1204.002 | [Droppers Exploiting CVE-2017-11882](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A678eb5f4-8597-4be6-8be7-905e4234b53a) | Sigma | SigmaHQ |
| T1217 | [File And SubFolder Enumeration Via Dir Command](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A7c9340a9-e2ee-4e43-94c5-c54ebbea1006) | Sigma | SigmaHQ |
| T1217 | [Suspicious Where Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A725a9768-0f5e-4cb3-aec2-bc5719c6831a) | Sigma | SigmaHQ |
| T1486 | [LockerGoga Ransomware Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A74db3488-fd28-480a-95aa-b7af626de068) | Sigma | SigmaHQ |
| T1486 | [LockerGoga Ransomware](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A74db3488-fd28-480a-95aa-b7af626de068) | Sigma | OpenSearch Security Analytics |
| T1547.001 | [Potential Ryuk Ransomware Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac37510b8-2107-4b78-aa32-72f251e7a844) | Sigma | SigmaHQ |
| T1547.001 | [Ryuk Ransomware](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Ac37510b8-2107-4b78-aa32-72f251e7a844) | Sigma | OpenSearch Security Analytics |
| T1566.001 | [Ursnif Malware C2 URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A932ac737-33ca-4afd-9869-0d48b391fcc9) | Sigma | SigmaHQ |
| T1566.001 | [Droppers Exploiting CVE-2017-11882](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A678eb5f4-8597-4be6-8be7-905e4234b53a) | Sigma | SigmaHQ |
| T1566.003 | [M365 Teams Rogue Help Desk Chat Created](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ae8e7b6b6-78b0-4015-97fe-c2f28468e0d4) | Elastic | Elastic detection-rules |
| T1566.003 | [M365 Azure Monitor Alert Email with Financial or Billing Theme](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Aa6129187-c47b-48ab-a412-67a44836d918) | Elastic | Elastic detection-rules |
| T1569.002 | [PSExec Lateral Movement](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=hayabusa-native%3A%3A0694c340-3a46-40ac-acfc-c3444ae6572c) | Sigma | Hayabusa (native) |
| T1569.002 | [DNS RCE CVE-2020-1350](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab5281f31-f9cc-4d0d-95d0-45b91c45b487) | Sigma | SigmaHQ |
| T1583.001 | [AWS Route 53 Private Hosted Zone Associated With a VPC](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ae3c27562-709a-42bd-82f2-3ed926cced19) | Elastic | Elastic detection-rules |
| T1583.001 | [AWS SES Email Identity Verified Then Deleted](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A8e4bde35-125d-4eb3-9a2e-d7e77a053a08) | Elastic | Elastic detection-rules |
| T1585.001 | [CYFIRMA - Brand Intelligence - Social Media Handle Impersonation Detected High Rule](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A22f49d67-7da7-4809-8d07-89e4478aa6b0) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1585.001 | [CYFIRMA - Brand Intelligence - Executive/People Impersonation High Rule](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A159d26a1-591c-4f70-b1ca-2843c881aaec) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1587 | [FoggyWeb Backdoor DLL Loading](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A640dc51c-7713-4faa-8a0e-e7c0d9d4654c) | Sigma | SigmaHQ |
| T1587 | [CVE-2021-1675 Print Spooler Exploitation Filename Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A2131cfb3-8c12-45e8-8fa0-31f5924e9f07) | Sigma | SigmaHQ |
| T1587.001 | [Formbook Process Creation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A032f5fb3-d959-41a5-9263-4173c802dc2b) | Sigma | SigmaHQ |
| T1587.001 | [Uncommon File Created In Office Startup Folder](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aa10a2c40-2c4d-49f8-b557-1a946bc55d9d) | Sigma | SigmaHQ |
| T1589.002 | [Potential Unconstrained Delegation Discovery Via Get-ADComputer - ScriptBlock](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acdfa73b6-3c9d-4bb8-97f8-ddbd8921f5c5) | Sigma | SigmaHQ |
| T1589.002 | [AWSCloudTrail - Suspicious AWS CLI Command Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A8c2dc344-9352-4ca1-8863-b1b7a5e09e59) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1591 | [AWSCloudTrail - Suspicious AWS CLI Command Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A8c2dc344-9352-4ca1-8863-b1b7a5e09e59) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1591 | [MailGuard 365 - Malware Threats](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-hunting-queries%3A%3Adaaae6ad-1fd0-4efa-b571-116689e67a20) | Sentinel KQL | Microsoft Sentinel (Hunting Queries) |
| T1598 | [CyberBlindSpot - Any Issue Detected](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3Aabe1a662-d00d-482e-aa68-9394622ae02e) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1598 | [Proofpoint Phishing Email Detected](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=panther-panther-analysis%3A%3AProofpoint.PhishingDetected) | Panther | Panther panther-analysis |
| T1608.001 | [M365 OneDrive Malware File Upload](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Abba1b212-b85c-41c6-9b28-be0e5cdfc9b1) | Elastic | Elastic detection-rules |
| T1608.001 | [M365 SharePoint Malware File Detected](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A0e52157a-8e96-4a95-a6e3-5faae5081a74) | Elastic | Elastic detection-rules |

## 8. Plano de emulação e validação

Use num laboratório isolado e autorizado para confirmar que as regras disparam. Os comandos estão nos repositórios oficiais.

| Tática | Técnica | Teste Atomic Red Team | Plataformas |
|---|---|---|---|
| Initial Access | [T1195.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1195.002/T1195.002.md) | Simulate npm package installation on a Linux system | containers, linux |
| Initial Access | [T1566.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1566.001/T1566.001.md) | Download Macro-Enabled Phishing Attachment | windows |
| Initial Access | [T1566.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1566.001/T1566.001.md) | Word spawned a command shell and used an IP address in the command line | windows |
| Execution | [T1053.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1053.005/T1053.005.md) | Scheduled Task Startup Script | windows |
| Execution | [T1053.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1053.005/T1053.005.md) | Scheduled task Local | windows |
| Execution | [T1204.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1204.002/T1204.002.md) | OSTap Style Macro Execution | windows |
| Execution | [T1204.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1204.002/T1204.002.md) | OSTap Payload Download | windows |
| Execution | [T1569.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1569.002/T1569.002.md) | Execute a Command as a Service | windows |
| Execution | [T1569.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1569.002/T1569.002.md) | Use PsExec to execute a command on a remote host | windows |
| Persistence | [T1547.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1547.001/T1547.001.md) | Reg Key Run | windows |
| Persistence | [T1547.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1547.001/T1547.001.md) | Reg Key RunOnce | windows |
| Stealth | [T1027](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027/T1027.md) | Decode base64 Data into Script | linux, macos |
| Stealth | [T1027](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027/T1027.md) | Execute base64-encoded PowerShell | windows |
| Stealth | [T1027.013](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027.013/T1027.013.md) | Decode Eicar File and Write to File | linux, macos, windows |
| Stealth | [T1027.013](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027.013/T1027.013.md) | Decrypt Eicar File and Write to File | linux, macos, windows |
| Stealth | [T1140](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1140/T1140.md) | Deobfuscate/Decode Files Or Information | windows |
| Stealth | [T1140](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1140/T1140.md) | Certutil Rename and Decode | windows |
| Credential Access | [T1003.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/T1003.001.md) | Dump LSASS.exe Memory using ProcDump | windows |
| Credential Access | [T1003.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/T1003.001.md) | Dump LSASS.exe Memory using comsvcs.dll | windows |
| Discovery | [T1016](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1016/T1016.md) | System Network Configuration Discovery on Windows | windows |
| Discovery | [T1016](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1016/T1016.md) | List Windows Firewall Rules | windows |
| Discovery | [T1033](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1033/T1033.md) | System Owner/User Discovery | windows |
| Discovery | [T1033](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1033/T1033.md) | System Owner/User Discovery | linux, macos |
| Discovery | [T1082](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1082/T1082.md) | System Information Discovery | windows |
| Discovery | [T1082](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1082/T1082.md) | System Information Discovery | macos |
| Discovery | [T1217](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1217/T1217.md) | List Mozilla Firefox Bookmark Database Files on FreeBSD/Linux | linux |
| Discovery | [T1217](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1217/T1217.md) | List Mozilla Firefox Bookmark Database Files on macOS | macos |
| Command and Control | [T1071.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1071.001/T1071.001.md) | Malicious User Agents - Powershell | windows |
| Command and Control | [T1071.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1071.001/T1071.001.md) | Malicious User Agents - CMD | windows |
| Command and Control | [T1105](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1105/T1105.md) | rsync remote file copy (push) | linux, macos |
| Command and Control | [T1105](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1105/T1105.md) | rsync remote file copy (pull) | linux, macos |
| Impact | [T1486](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1486/T1486.md) | Encrypt files using gpg (FreeBSD/Linux) | linux |
| Impact | [T1486](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1486/T1486.md) | Encrypt files using 7z (FreeBSD/Linux) | linux |

**Logs reais de ataque (EVTX) para testar sem executar nada:**

- T1003.001 — [CA_hashdump_4663_4656_lsass_access](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Credential%20Access/CA_hashdump_4663_4656_lsass_access.evtx) _(inferido)_
- T1003.001 — [LsassSilentProcessExit_process_exit_monitor_3001_lsass](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Credential%20Access/LsassSilentProcessExit_process_exit_monitor_3001_lsass.evtx) _(inferido)_
- T1016 — [ID4688-Audit policy enumerated](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1016-System%20Network%20Configuration%20Discovery/ID4688-Audit%20policy%20enumerated.evtx) _(explícito)_
- T1016 — [ID4688-Firewall configuration enumerated (command)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1016-System%20Network%20Configuration%20Discovery/ID4688-Firewall%20configuration%20enumerated%20%28command%29.evtx) _(explícito)_
- T1027 — [4624,4674,4688- CrackMap Exec SMB mimikatz](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0005-Defense%20Evasion/T1027-Obfuscated%20Files%20or%20Information/4624%2C4674%2C4688-%20CrackMap%20Exec%20SMB%20mimikatz.evtx) _(explícito)_
- T1027 — [ID1-CrackMapExec payload execution](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0005-Defense%20Evasion/T1027-Obfuscated%20Files%20or%20Information/ID1-CrackMapExec%20payload%20execution.evtx) _(explícito)_
- T1053.005 — [ID4688-4698 Persistent scheduled task with SYSTEM privileges creation](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1053.005-Scheduled%20Task/ID4688-4698%20Persistent%20scheduled%20task%20with%20SYSTEM%20privileges%20creation.evtx) _(explícito)_
- T1053.005 — [ID4688-Interactive shell using AT schedule task](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1053.005-Scheduled%20Task/ID4688-Interactive%20shell%20using%20AT%20schedule%20task.evtx) _(explícito)_
- T1140 — [ID4688-Certutil download](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0005-Defense%20Evasion/T1140-Deobfuscate-Decode%20Files%20or%20Information/ID4688-Certutil%20download.evtx) _(explícito)_
- T1486 — [ID 768,775,793,796,817,840-BitLocker encryption activated](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0040-Impact/T1486-Data%20Encrypted%20for%20Impact/ID%20768%2C775%2C793%2C796%2C817%2C840-BitLocker%20encryption%20activated.evtx) _(explícito)_
- T1547.001 — [sideloading_injection_persistence_run_key](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/AutomatedTestingTools/Malware/sideloading_injection_persistence_run_key.evtx) _(inferido)_
- T1547.001 — [evasion_persis_hidden_run_keyvalue_sysmon_13](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Persistence/evasion_persis_hidden_run_keyvalue_sysmon_13.evtx) _(inferido)_
- T1569.002 — [ID5145-remote service creation over SMB](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1569.002-Service%20execution/ID5145-remote%20service%20creation%20over%20SMB.evtx) _(explícito)_
- T1569.002 — [ID5145-service massive remote creation via named pipe - Tchopper](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1569.002-Service%20execution/ID5145-service%20massive%20remote%20creation%20via%20named%20pipe%20-%20Tchopper.evtx) _(explícito)_

## 9. Hipóteses de hunting

Se Moonstone Sleet estiver no seu ambiente, estas são as perguntas a fazer aos seus dados (fontes de log segundo as estratégias de detecção do MITRE ATT&CK).

1. **T1027.009 Embedded Payloads** — Detection of executables or scripts containing hidden embedded resources or secondary payloads, often with anomalies in file size vs. functionality or dropped child binaries. Dados: `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Sysmon` (EventCode=1), `EDR:file` (File Metadata Analysis (PE overlays, entropy)).
2. **T1587 Develop Capabilities** — Consider analyzing malware for features that may be associated with the adversary and/or their developers, such as compiler used, debugging artifacts, or code similarities. Malware repositories can also be used to identify additional samples associated with… Dados: `Malware Repository` (None), `Malware Repository` (None), `Internet Scan` (None).
3. **T1598 Phishing for Information** — Monitor and analyze traffic patterns and packet inspection associated to protocol(s) that do not follow the expected protocol standards and traffic flows (e.g extraneous packets that do not belong to established flows, gratuitous or anomalous traffic… Dados: `Network Traffic` (None), `Application Log` (None), `Network Traffic` (None).
4. **T1217 Browser Information Discovery** — Access to browser artifact locations (e.g., Chrome, Edge, Firefox) by processes like PowerShell, cmd.exe, or unknown tools, followed by file reads, decoding, or export operations indicating enumeration of bookmarks, autofill, or history databases. Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:PowerShell` (EventCode=4103, 4104, 4105, 4106).
5. **T1195.002 Compromise Software Supply Chain** — Adversary ships a tampered application or update: an updater/installer (msiexec/setup/update.exe/vendor service) writes or replaces binaries; on first run it spawns scripts/shells or unsigned DLLs and beacons to non-approved update CDNs/hosts. Detection… Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=6), `WinEventLog:Sysmon` (EventCode=7).
6. **T1589.002 Email Addresses** — Monitor for suspicious network traffic that could be indicative of probing for email addresses and/or usernames, such as large/iterative quantities of authentication requests originating from a single source (especially if the source is known to be associated… Dados: `Network Traffic` (None).
7. **T1566.003 Spearphishing via Service** — Inbound spearphishing attempts delivered via third-party services (e.g., Gmail, LinkedIn messages) leading to malicious file downloads or browser-initiated script execution. Defender view includes correlation of external service logins, unexpected file write… Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Sysmon` (EventCode=3, 22).
8. **T1569.002 Service Execution** — Detection focuses on abnormal service executions initiated via service control manager APIs, sc.exe, net.exe, or PsExec creating temporary services. Defenders observe process creation of services.exe spawning non-standard binaries, registry changes in service… Dados: `WinEventLog:Security` (EventCode=4697), `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=13, 14).
9. **T1598.003 Spearphishing Link** — Monitor for suspicious email activity, such as numerous accounts receiving messages from a single unusual/unknown sender. Filtering based on DKIM+SPF or header analysis can help detect when the email sender is spoofed. Monitor for references to uncategorized… Dados: `Application Log` (None), `Network Traffic` (None), `Network Traffic` (None).
10. **T1027 Obfuscated Files or Information** — Correlates script execution or suspicious parent processes with creation or modification of encoded, compressed, or encrypted file formats (e.g., .zip, .7z, .enc) and abnormal command-line syntax or PowerShell obfuscation. Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Sysmon` (EventCode=1).
11. **T1583.003 Virtual Private Server** — Once adversaries have provisioned a VPS (ex: for use as a command and control server), internet scans may reveal servers that adversaries have acquired. Consider looking for identifiable patterns such as services listening, certificates in use, SSL/TLS… Dados: `Internet Scan` (None), `Internet Scan` (None).
12. **T1486 Data Encrypted for Impact** — High-frequency file write operations using uncommon extensions, followed by ransom note creation, registry tampering, or shadow copy deletion. Often uses CLI tools like vssadmin, wbadmin, cipher, or PowerShell. Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Sysmon` (EventCode=2).

## 10. OSINT — onde pesquisar

Consultas prontas com todos os nomes conhecidos do grupo:

- Relatórios técnicos: [busca web](https://duckduckgo.com/?q=%28%22Moonstone+Sleet%22+OR+%22Storm-1789%22%29+threat+report) · [PDFs](https://duckduckgo.com/?q=%28%22Moonstone+Sleet%22+OR+%22Storm-1789%22%29+filetype%3Apdf)
- Regras e IOCs publicados: [GitHub](https://github.com/search?type=code&q=%22Moonstone+Sleet%22+OR+%22Storm-1789%22)
- Pulsos de ameaça: [AlienVault OTX](https://otx.alienvault.com/browse/global/pulses?q=Moonstone+Sleet)
- Família de malware e atores: [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/actors) (busque por Moonstone Sleet, Storm-1789)
- Cartões de grupo: [ThaiCERT Threat Group Cards](https://apt.etda.or.th/cgi-bin/listgroups.cgi)
- Página oficial: [MITRE ATT&CK G1036](https://attack.mitre.org/groups/G1036/)

## 11. Bibliografia (2 fontes citadas pelo ATT&CK)

- [Microsoft Moonstone Sleet 2024](https://www.microsoft.com/en-us/security/blog/2024/05/28/moonstone-sleet-emerges-as-new-north-korean-threat-actor-with-new-bag-of-tricks/) — Microsoft Threat Intelligence. (2024, May 28). Moonstone Sleet emerges as new North Korean threat actor with new bag of tricks. Retrieved August 26, 2024.
- [MIcrosoft Moonstone Sleet Qilin MAR 2025](https://x.com/MsftSecIntel/status/1897738961348374621) — Microsoft Threat Intelligence (@MsftSecIntel). (2025, March 6). Microsoft Threat Intelligence on X. Retrieved September 26, 2025.

## 12. Limites e confiança

- O ATT&CK registra o que foi **relatado publicamente**, não tudo o que o grupo faz. Ausência de uma técnica não prova que o grupo não a usa.
- **Sobreposição de TTP não é atribuição.** Muitas técnicas são compartilhadas entre grupos e com red teams. Use a assinatura comportamental como hipótese, junto com infraestrutura, malware e contexto.
- Cobertura de detecção refere-se ao catálogo público Detection Rules, não ao seu ambiente: confira se a telemetria necessária chega ao seu SIEM.
- Ligações marcadas como _inferidas_ (EVTX por palavra-chave, relatórios por nome) devem ser verificadas.

---
Fontes: MITRE ATT&CK® (uso livre com atribuição, © The MITRE Corporation), Atomic Red Team (Red Canary, MIT), EVTX-to-MITRE-Attack, EVTX-ATTACK-SAMPLES, APT & CyberCriminal Campaign Collections. Gerado por [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules).
