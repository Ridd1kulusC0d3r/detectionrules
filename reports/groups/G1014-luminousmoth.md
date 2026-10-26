# LuminousMoth (G1014) — Dossiê de inteligência

> **TLP:CLEAR** · gerado em 2026-10-26 a partir de fontes abertas · MITRE ATT&CK v20.0 · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1014) · [ATT&CK](https://attack.mitre.org/groups/G1014/)

**Também conhecido como:** —  
**Origem atribuída:** Sem país atribuído · **Motivação:** espionagem · **Setores-alvo:** —  
**Registro no ATT&CK:** criado em 2023-02-23, atualizado em 2026-07-31 · referências de 2021 a 2021

## 1. Sumário executivo

- **28 técnicas** atribuídas publicamente, concentradas em **Resource Development, Collection, Exfiltration**.
- **Arsenal:** 2 malware e 0 ferramentas (ex.: Cobalt Strike, PlugX).
- **Campanhas atribuídas:** 0.
- **Cobertura de detecção pública:** 93% das técnicas têm ao menos uma regra no catálogo; **2 técnicas sem nenhuma regra pública**.
- **Origem e alvos (APT4ALL):** atribuído a **Sem país atribuído**, motivação espionagem.
- **Onde a cobertura está:** Windows (24 técnicas com regra), Linux (20 técnicas com regra), EDR / XDR (20 técnicas com regra), Outros / genérico (18 técnicas com regra).
- **Assinatura comportamental** (técnicas raras entre os 178 grupos, as mais úteis para atribuição): T1557.002 ARP Cache Poisoning, T1608.005 Link Target, T1030 Data Transfer Size Limits, T1588.004 Digital Certificates, T1091 Replication Through Removable Media.

## 2. Quem é

> LuminousMoth is a Chinese-speaking cyber espionage group that has been active since at least October 2020. LuminousMoth has targeted high-profile organizations, including government entities, in Myanmar, the Philippines, Thailand, and other parts of Southeast Asia. Some security researchers have concluded there is a connection between LuminousMoth and Mustang Panda based on similar targeting and TTPs, as well as network infrastructure overlaps.

_Texto original do MITRE ATT&CK, em inglês._

## 3. Contexto, nomes e alvos

Consolidado pelo [APT4ALL](https://github.com/Ridd1kulusC0d3r/apt4all) a partir de MISP Galaxy, planilha APT Groups & Operations, EternalLiberty e APTnotes. Atribuição é afirmação de quem publicou; confira a fonte.

| Campo | Valor |
|---|---|
| Origem atribuída | Sem país atribuído |
| Motivação | espionagem |
| Setores-alvo | — |
| Vítimas citadas | — |
| Alvos (planilha) | — |
| Operações conhecidas | — |
| Confiança de atribuição (MISP) | — |

**Como cada fornecedor chama este grupo** (útil para cruzar relatórios):

| Fornecedor | Nome(s) |
|---|---|
| MITRE ATT&CK | G1014 |

## 4. Perfil TTP por tática (kill chain)

Cada linha: técnica, como o grupo a usou segundo relatos públicos, e o que existe para detectar e testar.

### Resource Development (TA0042) — 7

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1587.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1587.001) Malware | LuminousMoth has used unique malware for information theft and exfiltration. | 43 | — | — |
| [T1588.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1588.001) Malware | LuminousMoth has obtained and used malware such as Cobalt Strike. | 7 | — | — |
| [T1588.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1588.002) Tool | LuminousMoth has obtained an ARP spoofing tool from GitHub. | 35 | — | — |
| [T1588.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1588.004) Digital Certificates | LuminousMoth has used a valid digital certificate for some of their malware. | 1 | — | — |
| [T1608.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1608.001) Upload Malware | LuminousMoth has hosted malicious payloads on Dropbox. | 3 | — | — |
| [T1608.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1608.004) Drive-by Target | LuminousMoth has redirected compromised machines to an actor-controlled webpage through HTML injection. | **0** | — | — |
| [T1608.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1608.005) Link Target | LuminousMoth has created a link to a Dropbox file that has been used in their spear-phishing operations. | **0** | — | — |

### Initial Access (TA0001) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1091](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1091) Replication Through Removable Media | LuminousMoth has used malicious DLLs to spread malware to connected removable USB drives on infected machines. | 10 | 1 | — |
| [T1566.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1566.002) Spearphishing Link | LuminousMoth has sent spearphishing emails containing a malicious Dropbox download link. | 138 | 1 | — |

### Execution (TA0002) — 3

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1053.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1053.005) Scheduled Task | LuminousMoth has created scheduled tasks to establish persistence for their tools. | 248 | 14 | 11 |
| [T1204.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1204.001) Malicious Link | LuminousMoth has lured victims into clicking malicious Dropbox download links delivered through spearphishing. | 52 | — | — |
| [T1574.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1574.001) DLL | LuminousMoth has used legitimate executables such as `winword.exe` and `igfxem.exe` to side-load their malware. | 455 | 7 | 5 |

### Persistence (TA0003) — 3

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1053.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1053.005) Scheduled Task | LuminousMoth has created scheduled tasks to establish persistence for their tools. | 248 | 14 | 11 |
| [T1112](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1112) Modify Registry | LuminousMoth has used malware that adds Registry keys for persistence. | 601 | 92 | 3 |
| [T1547.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1547.001) Registry Run Keys / Startup Folder | LuminousMoth has used malicious DLLs that setup persistence in the Registry Key `HKCU\Software\Microsoft\Windows\Current Version\Run`. | 299 | 21 | 2 |

### Privilege Escalation (TA0004) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1053.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1053.005) Scheduled Task | LuminousMoth has created scheduled tasks to establish persistence for their tools. | 248 | 14 | 11 |
| [T1547.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1547.001) Registry Run Keys / Startup Folder | LuminousMoth has used malicious DLLs that setup persistence in the Registry Key `HKCU\Software\Microsoft\Windows\Current Version\Run`. | 299 | 21 | 2 |

### Stealth (TA0005) — 3

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1036.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1036.005) Match Legitimate Resource Name or Location | LuminousMoth has disguised their exfiltration malware as `ZoomVideoApp.exe`. | 116 | 4 | — |
| [T1564.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1564.001) Hidden Files and Directories | LuminousMoth has used malware to store malicious binaries in hidden directories on victim's USB drives. | 76 | 10 | — |
| [T1574.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1574.001) DLL | LuminousMoth has used legitimate executables such as `winword.exe` and `igfxem.exe` to side-load their malware. | 455 | 7 | 5 |

### Defense Impairment (TA0112) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1112](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1112) Modify Registry | LuminousMoth has used malware that adds Registry keys for persistence. | 601 | 92 | 3 |
| [T1553.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1553.002) Code Signing | LuminousMoth has signed their malware with a valid digital signature. | 11 | — | — |

### Credential Access (TA0006) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1539](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1539) Steal Web Session Cookie | LuminousMoth has used an unnamed post-exploitation tool to steal cookies from the Chrome browser. | 54 | 5 | — |
| [T1557.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1557.002) ARP Cache Poisoning | LuminousMoth has used ARP spoofing to redirect a compromised machine to an actor-controlled website. | 5 | — | — |

### Discovery (TA0007) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1033](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1033) System Owner/User Discovery | LuminousMoth has used a malicious DLL to collect the username from compromised hosts. | 181 | 8 | — |
| [T1083](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1083) File and Directory Discovery | LuminousMoth has used malware that scans for files in the Documents, Desktop, and Download folders and in other drives. | 137 | 9 | — |

### Lateral Movement (TA0008) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1091](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1091) Replication Through Removable Media | LuminousMoth has used malicious DLLs to spread malware to connected removable USB drives on infected machines. | 10 | 1 | — |

### Collection (TA0009) — 3

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1005) Data from Local System | LuminousMoth has collected files and data from compromised machines. | 170 | 3 | — |
| [T1557.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1557.002) ARP Cache Poisoning | LuminousMoth has used ARP spoofing to redirect a compromised machine to an actor-controlled website. | 5 | — | — |
| [T1560](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1560) Archive Collected Data | LuminousMoth has manually archived stolen files from victim machines before exfiltration. | 53 | 1 | — |

### Command and Control (TA0011) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1071.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1071.001) Web Protocols | LuminousMoth has used HTTP for C2. | 228 | 3 | — |
| [T1105](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1105) Ingress Tool Transfer | LuminousMoth has downloaded additional malware and tools onto a compromised host. | 644 | 39 | — |

### Exfiltration (TA0010) — 3

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1030](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1030) Data Transfer Size Limits | LuminousMoth has split archived files into multiple parts to bypass a 5MB limit. | 17 | 2 | — |
| [T1041](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1041) Exfiltration Over C2 Channel | LuminousMoth has used malware that exfiltrates stolen data to its C2 server. | 135 | 2 | — |
| [T1567.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1567.002) Exfiltration to Cloud Storage | LuminousMoth has exfiltrated data to Google Drive. | 85 | 2 | — |

## 5. Assinatura comportamental

Técnicas que este grupo usa e que poucos dos 178 grupos do ATT&CK usam. Pesam mais numa atribuição por TTP: ver várias delas juntas é mais informativo do que ver técnicas comuns como PowerShell.

| Técnica | Outros grupos que usam | Peso (raridade) |
|---|---:|---:|
| T1557.002 ARP Cache Poisoning | 1 | 4.09 |
| T1608.005 Link Target | 3 | 3.58 |
| T1030 Data Transfer Size Limits | 4 | 3.40 |
| T1588.004 Digital Certificates | 6 | 3.11 |
| T1091 Replication Through Removable Media | 7 | 2.99 |
| T1539 Steal Web Session Cookie | 7 | 2.99 |
| T1608.004 Drive-by Target | 7 | 2.99 |
| T1560 Archive Collected Data | 12 | 2.55 |
| T1564.001 Hidden Files and Directories | 12 | 2.55 |
| T1588.001 Malware | 17 | 2.24 |

## 6. Arsenal

| Software | Tipo | Técnicas no ATT&CK | Uso relatado (EN) |
|---|---|---:|---|
| [Cobalt Strike](https://attack.mitre.org/software/S0154/) | malware | 73 |  |
| [PlugX](https://attack.mitre.org/software/S0013/) | malware | 49 |  |

## 7. Campanhas

Nenhuma campanha atribuída no ATT&CK.

## 8. Cobertura defensiva

**26 de 28 técnicas (93%)** têm ao menos uma regra pública no catálogo Detection Rules.

### Técnicas sem regra pública (prioridade para engenharia de detecção)

- **T1608.005 Link Target** — Resource Development. Fonte de log sugerida pelo MITRE: `Internet Scan` None
- **T1608.004 Drive-by Target** — Resource Development. Fonte de log sugerida pelo MITRE: `Internet Scan` None

### Onde procurar — cobertura por tecnologia

Quantas técnicas deste grupo têm ao menos uma regra em cada tecnologia. Comece a caça pelas tecnologias que você tem e que aparecem aqui.

| Tecnologia | Técnicas do grupo com regra |
|---|---:|
| Windows | 24 |
| Linux | 20 |
| EDR / XDR | 20 |
| Outros / genérico | 18 |
| macOS | 15 |
| Firewall & perímetro | 15 |
| Servidores web & aplicações | 15 |
| IA, LLMs & agentes | 15 |
| Proxy / SWG | 14 |
| Microsoft 365 | 13 |
| Integridade, conformidade & vulnerabilidade | 13 |
| Contêineres (Docker/runtime) | 12 |

### Regras recomendadas por técnica

Melhor regra disponível por técnica (formato portável e maduro primeiro).

| Técnica | Regra | Formato | Fonte |
|---|---|---|---|
| T1005 | [Potential Conti Ransomware Database Dumping Activity Via SQLCmd](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A2f47f1fd-0901-466e-a770-3b7092834a1b) | Sigma | SigmaHQ |
| T1005 | [OpenCanary - SMB File Open Request](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A22777c9e-873a-4b49-855f-6072ab861a52) | Sigma | SigmaHQ |
| T1030 | [Split A File Into Pieces - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A2dad0cba-c62a-4a4f-949f-5f6ecd619769) | Sigma | SigmaHQ |
| T1030 | [Split A File Into Pieces](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A7f2bb9d5-6395-4de5-969c-70c11fbe6b12) | Sigma | SigmaHQ |
| T1033 | [Potential Dridex Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae6eb5a96-9e6f-4a18-9cdd-642cfda21c8e) | Sigma | SigmaHQ |
| T1033 | [Dridex Process Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Ae6eb5a96-9e6f-4a18-9cdd-642cfda21c8e) | Sigma | OpenSearch Security Analytics |
| T1036.005 | [Exploit for CVE-2015-1641](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A7993792c-5ce2-4475-a3db-a3a5539827ef) | Sigma | SigmaHQ |
| T1036.005 | [Exploit for CVE-2015-1641](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A7993792c-5ce2-4475-a3db-a3a5539827ef) | Sigma | OpenSearch Security Analytics |
| T1041 | [Equation Group C2 Communication](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A881834a4-6659-4773-821e-1c151789d873) | Sigma | SigmaHQ |
| T1041 | [OpenCanary - TFTP Request](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab4e6b016-a2ac-4759-ad85-8000b300d61e) | Sigma | SigmaHQ |
| T1053.005 | [Operation Wocao Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1cfac73c-be78-4f9a-9b08-5bde0c3953ab) | Sigma | SigmaHQ |
| T1053.005 | [Operation Wocao Activity - Security](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A74ad4314-482e-4c3e-b237-3f7ed3b9ca8d) | Sigma | SigmaHQ |
| T1071.001 | [Ursnif Malware Download URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aa36ce77e-30db-4ea0-8795-644d7af5dfb4) | Sigma | SigmaHQ |
| T1071.001 | [Ursnif Malware C2 URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A932ac737-33ca-4afd-9869-0d48b391fcc9) | Sigma | SigmaHQ |
| T1083 | [Turla Group Lateral Movement](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac601f20d-570a-4cde-a7d6-e17f99cb8e7f) | Sigma | SigmaHQ |
| T1083 | [WannaCry Ransomware Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A41d40bff-377a-43e2-8e1b-2e543069e079) | Sigma | SigmaHQ |
| T1091 | [New USB Storage Device Mounted](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A483832a8-ffdd-4e11-8e96-e0224f7bda9b) | Elastic | Elastic detection-rules |
| T1091 | [Execution from a Removable Media with Network Connection](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A1542fa53-955e-4330-8e4d-b2d812adeb5f) | Elastic | Elastic detection-rules |
| T1105 | [Greenbug Espionage Group Indicators](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A3711eee4-a808-4849-8a14-faf733da3612) | Sigma | SigmaHQ |
| T1105 | [Pandemic Registry Key](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A47e0852a-cf81-4494-a8e6-31864f8c86ed) | Sigma | SigmaHQ |
| T1112 | [ShimCache Flush](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab0524451-19af-4efa-a46f-562a977f792e) | Sigma | SigmaHQ |
| T1112 | [ShimCache Flush](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Ab0524451-19af-4efa-a46f-562a977f792e) | Sigma | OpenSearch Security Analytics |
| T1204.001 | [Google Workspace Object Copied from External Drive with App Consent](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Af33e68a4-bd19-11ed-b02f-f661ea17fbcc) | Elastic | Elastic detection-rules |
| T1204.001 | [Suspicious ClickFix/FileFix Execution Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad487ed4a-fd24-436d-a0b2-f4e95f7b2635) | Sigma | SigmaHQ |
| T1539 | [SQLite Firefox Profile Data DB Access](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4833155a-4053-4c9c-a997-777fcea0baa7) | Sigma | SigmaHQ |
| T1539 | [SQLite Chromium Profile Data DB Access](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A24c77512-782b-448a-8950-eddb0785fc71) | Sigma | SigmaHQ |
| T1547.001 | [Potential Ryuk Ransomware Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac37510b8-2107-4b78-aa32-72f251e7a844) | Sigma | SigmaHQ |
| T1547.001 | [Ryuk Ransomware](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Ac37510b8-2107-4b78-aa32-72f251e7a844) | Sigma | OpenSearch Security Analytics |
| T1553.002 | [Driver Loaded (Invalid Signature)](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=hayabusa-native%3A%3A1f666722-3948-40a2-9d78-d9d374477a90) | Sigma | Hayabusa (native) |
| T1553.002 | [Driver Loaded (Expired/Revoked Cert)](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=hayabusa-native%3A%3Ac837dd6d-0c91-4593-aeab-f6a1f3ca1961) | Sigma | Hayabusa (native) |
| T1557.002 | [Detect Port Security Violation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=splunk-security-content%3A%3A2de3d5b8-a4fa-45c5-8540-6d071c194d24) | Splunk | Splunk security_content |
| T1557.002 | [Detect ARP Poisoning](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=splunk-security-content%3A%3Ab44bebd6-bd39-467b-9321-73971bcd1aac) | Splunk | Splunk security_content |
| T1560 | [Conti NTDS Exfiltration Command](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aaa92fd02-09f2-48b0-8a93-864813fb8f41) | Sigma | SigmaHQ |
| T1560 | [Sensitive Files Compression Inside A Container](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ad9faf1ba-a216-4c29-b8e0-a05a9d14b027) | Elastic | Elastic detection-rules |
| T1564.001 | [Set Suspicious Files as System Files Using Attrib.EXE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aefec536f-72e8-4656-8960-5e85d091345b) | Sigma | SigmaHQ |
| T1564.001 | [PowerShell Logging Disabled Via Registry Key Tampering](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Afecfd1a1-cc78-4313-a1ea-2ee2e8ec27a7) | Sigma | SigmaHQ |
| T1566.002 | [Potential Malicious Usage of CloudTrail System Manager](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A38e7f511-3f74-41d4-836e-f57dfa18eead) | Sigma | SigmaHQ |
| T1566.002 | [Google Workspace Device Registration After OAuth from Suspicious ASN](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A012bfca7-45cb-4507-a3ba-3777167f8b81) | Elastic | Elastic detection-rules |
| T1567.002 | [APT40 Dropbox Tool User Agent](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A5ba715b6-71b7-44fd-8245-f66893e81b3d) | Sigma | SigmaHQ |
| T1567.002 | [PUA - Rclone Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae37db05d-d1f9-49c8-b464-cee1a4b11638) | Sigma | SigmaHQ |
| T1574.001 | [Winnti Pipemon Characteristics](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A73d70463-75c9-4258-92c6-17500fe972f2) | Sigma | SigmaHQ |
| T1574.001 | [Winnti Pipemon Characteristics](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A73d70463-75c9-4258-92c6-17500fe972f2) | Sigma | OpenSearch Security Analytics |
| T1587.001 | [Formbook Process Creation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A032f5fb3-d959-41a5-9263-4173c802dc2b) | Sigma | SigmaHQ |
| T1587.001 | [Uncommon File Created In Office Startup Folder](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aa10a2c40-2c4d-49f8-b557-1a946bc55d9d) | Sigma | SigmaHQ |
| T1588.001 | [Relevant ClamAV Message](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A36aa86ca-fd9d-4456-814e-d3b1b8e1e0bb) | Sigma | SigmaHQ |
| T1588.001 | [Relevant ClamAV Message](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A36aa86ca-fd9d-4456-814e-d3b1b8e1e0bb) | Sigma | OpenSearch Security Analytics |
| T1588.002 | [Hacktool Execution - Imphash](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A24e3e58a-646b-4b50-adef-02ef935b9fc8) | Sigma | SigmaHQ |
| T1588.002 | [Renamed SysInternals DebugView Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acd764533-2e07-40d6-a718-cfeec7f2da7f) | Sigma | SigmaHQ |
| T1588.004 | [Cisco Secure Firewall - Blacklisted SSL Certificate Fingerprint](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=splunk-security-content%3A%3Ac43f7b49-2dab-4e76-892e-7f971c2f20f1) | Splunk | Splunk security_content |
| T1608.001 | [M365 OneDrive Malware File Upload](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Abba1b212-b85c-41c6-9b28-be0e5cdfc9b1) | Elastic | Elastic detection-rules |
| T1608.001 | [M365 SharePoint Malware File Detected](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A0e52157a-8e96-4a95-a6e3-5faae5081a74) | Elastic | Elastic detection-rules |

## 9. Plano de emulação e validação

Use num laboratório isolado e autorizado para confirmar que as regras disparam. Os comandos estão nos repositórios oficiais.

| Tática | Técnica | Teste Atomic Red Team | Plataformas |
|---|---|---|---|
| Initial Access | [T1566.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1566.002/T1566.002.md) | Paste and run technique | windows |
| Execution | [T1053.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1053.005/T1053.005.md) | Scheduled Task Startup Script | windows |
| Execution | [T1053.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1053.005/T1053.005.md) | Scheduled task Local | windows |
| Persistence | [T1547.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1547.001/T1547.001.md) | Reg Key Run | windows |
| Persistence | [T1547.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1547.001/T1547.001.md) | Reg Key RunOnce | windows |
| Stealth | [T1036.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.005/T1036.005.md) | Execute a process from a directory masquerading as the current parent directory | linux, macos |
| Stealth | [T1036.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.005/T1036.005.md) | Masquerade as a built-in system executable | windows |
| Stealth | [T1564.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1564.001/T1564.001.md) | Create a hidden file in a hidden directory | linux, macos |
| Stealth | [T1564.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1564.001/T1564.001.md) | Mac Hidden file | macos |
| Stealth | [T1574.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1574.001/T1574.001.md) | DLL Search Order Hijacking - amsi.dll | windows |
| Stealth | [T1574.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1574.001/T1574.001.md) | Phantom Dll Hijacking - WinAppXRT.dll | windows |
| Defense Impairment | [T1112](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1112/T1112.md) | Modify Registry of Current User Profile - cmd | windows |
| Defense Impairment | [T1112](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1112/T1112.md) | Modify Registry of Local Machine - cmd | windows |
| Credential Access | [T1539](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1539/T1539.md) | Steal Firefox Cookies (Windows) | windows |
| Credential Access | [T1539](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1539/T1539.md) | Steal Chrome Cookies (Windows) | windows |
| Discovery | [T1033](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1033/T1033.md) | System Owner/User Discovery | windows |
| Discovery | [T1033](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1033/T1033.md) | System Owner/User Discovery | linux, macos |
| Discovery | [T1083](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1083/T1083.md) | File and Directory Discovery (cmd.exe) | windows |
| Discovery | [T1083](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1083/T1083.md) | File and Directory Discovery (PowerShell) | windows |
| Lateral Movement | [T1091](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1091/T1091.md) | USB Malware Spread Simulation | windows |
| Collection | [T1005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1005/T1005.md) | Search files of interest and save them to a single zip file (Windows) | windows |
| Collection | [T1005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1005/T1005.md) | Find and dump sqlite databases (Linux) | linux |
| Collection | [T1560](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1560/T1560.md) | Compress Data for Exfiltration With PowerShell | windows |
| Command and Control | [T1071.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1071.001/T1071.001.md) | Malicious User Agents - Powershell | windows |
| Command and Control | [T1071.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1071.001/T1071.001.md) | Malicious User Agents - CMD | windows |
| Command and Control | [T1105](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1105/T1105.md) | rsync remote file copy (push) | linux, macos |
| Command and Control | [T1105](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1105/T1105.md) | rsync remote file copy (pull) | linux, macos |
| Exfiltration | [T1030](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1030/T1030.md) | Data Transfer Size Limits | linux, macos |
| Exfiltration | [T1030](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1030/T1030.md) | Network-Based Data Transfer in Small Chunks |  |
| Exfiltration | [T1041](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1041/T1041.md) | C2 Data Exfiltration | windows |
| Exfiltration | [T1041](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1041/T1041.md) | Text Based Data Exfiltration using DNS subdomains | windows |
| Exfiltration | [T1567.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1567.002/T1567.002.md) | Exfiltrate data with rclone to cloud Storage - Mega (Windows) | windows |
| Exfiltration | [T1567.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1567.002/T1567.002.md) | Exfiltrate data with rclone to cloud Storage - AWS S3 | linux, macos |

**Logs reais de ataque (EVTX) para testar sem executar nada:**

- T1053.005 — [ID4688-4698 Persistent scheduled task with SYSTEM privileges creation](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1053.005-Scheduled%20Task/ID4688-4698%20Persistent%20scheduled%20task%20with%20SYSTEM%20privileges%20creation.evtx) _(explícito)_
- T1053.005 — [ID4688-Interactive shell using AT schedule task](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1053.005-Scheduled%20Task/ID4688-Interactive%20shell%20using%20AT%20schedule%20task.evtx) _(explícito)_
- T1112 — [ID11,13-SMBexec service registration](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0005-Defense%20Evasion/T1112-Modify%20registry/ID11%2C13-SMBexec%20service%20registration.evtx) _(explícito)_
- T1112 — [ID4624,4670,4688,4674-Registry permission change via WMI (DAMP)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0005-Defense%20Evasion/T1112-Modify%20registry/ID4624%2C4670%2C4688%2C4674-Registry%20permission%20change%20via%20WMI%20%28DAMP%29.evtx) _(explícito)_
- T1547.001 — [sideloading_injection_persistence_run_key](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/AutomatedTestingTools/Malware/sideloading_injection_persistence_run_key.evtx) _(inferido)_
- T1547.001 — [evasion_persis_hidden_run_keyvalue_sysmon_13](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Persistence/evasion_persis_hidden_run_keyvalue_sysmon_13.evtx) _(inferido)_
- T1574.001 — [DE_timestomp_and_dll_sideloading_and_RunPersist](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/AutomatedTestingTools/Malware/DE_timestomp_and_dll_sideloading_and_RunPersist.evtx) _(inferido)_
- T1574.001 — [sideloading_injection_persistence_run_key](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/AutomatedTestingTools/Malware/sideloading_injection_persistence_run_key.evtx) _(inferido)_

## 10. Hipóteses de hunting

Se LuminousMoth estiver no seu ambiente, estas são as perguntas a fazer aos seus dados (fontes de log segundo as estratégias de detecção do MITRE ATT&CK).

1. **T1557.002 ARP Cache Poisoning** — Detects anomalous ARP traffic or cache modifications on Windows endpoints that indicate ARP poisoning. Behavioral focus is on multiple IP addresses resolving to a single MAC, or unsolicited ARP replies from unauthorized devices. Dados: `WinEventLog:Sysmon` (EventCode=3, 22), `WinEventLog:Security` (ARP cache modification attempts observed through event tracing or security baselines).
2. **T1608.005 Link Target** — If infrastructure or patterns in malicious web content have been previously identified, internet scanning may uncover when an adversary has staged web content to make it accessible for targeting. Much of this activity will take place outside the visibility of… Dados: `Internet Scan` (None).
3. **T1030 Data Transfer Size Limits** — Adversary uses a process to establish outbound connections that transmit uniform packet sizes at a consistent interval, avoiding threshold-based network alerts. Dados: `WinEventLog:Sysmon` (EventCode=3, 22), `NSM:Flow` (NetFlow/sFlow/PCAP).
4. **T1588.004 Digital Certificates** — Consider use of services that may aid in the tracking of newly issued certificates and/or certificates in use on sites across the Internet. In some cases it may be possible to pivot on known pieces of certificate information to uncover other adversary… Dados: `Certificate` (None), `Internet Scan` (None).
5. **T1091 Replication Through Removable Media** — Execution of files originating from removable media after drive mount, with correlation to file write activity, autorun usage, or lateral spread via staged tools. Dados: `WinEventLog:System` (EventCode=1006), `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Sysmon` (EventCode=1).
6. **T1539 Steal Web Session Cookie** — Detects suspicious access to browser session cookie storage (e.g., Chrome’s `Cookies` SQLite DB) or memory reads of browser processes. Anomalous injection or memory dump utilities targeting browser processes such as `chrome.exe`, `firefox.exe`, or… Dados: `WinEventLog:Sysmon` (EventCode=10), `WinEventLog:Sysmon` (EventCode=2), `WinEventLog:Security` (EventCode=4688).
7. **T1608.004 Drive-by Target** — If infrastructure or patterns in the malicious web content utilized to deliver a Drive-by Compromise have been previously identified, internet scanning may uncover when an adversary has staged web content for use in a strategic web compromise. Much of this… Dados: `Internet Scan` (None).
8. **T1560 Archive Collected Data** — Detects adversarial archiving of files prior to exfiltration by correlating execution of compression/encryption utilities (e.g., makecab.exe, rar.exe, 7z.exe, powershell Compress-Archive) with subsequent creation of large compressed or encrypted files.… Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Sysmon` (EventCode=7).
9. **T1564.001 Hidden Files and Directories** — Suspicious use of attrib.exe or PowerShell commands to set hidden attributes on files/directories. Defender view: processes modifying file attributes to 'hidden' or creating files with ADS (alternate data streams). Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=11).
10. **T1588.001 Malware** — Monitor for contextual data about a malicious payload, such as compilation times, file hashes, as well as watermarks or other identifiable configuration information. Much of this activity will take place outside the visibility of the target organization,… Dados: `Malware Repository` (None), `Malware Repository` (None).
11. **T1567.002 Exfiltration to Cloud Storage** — Unusual processes (e.g., powershell.exe, excel.exe) accessing large local files and subsequently initiating HTTPS POST requests to domains associated with cloud storage services (e.g., dropbox.com, drive.google.com, box.com). Defender perspective: correlation… Dados: `WinEventLog:Security` (EventCode=4663, 4670, 4656), `WinEventLog:Sysmon` (EventCode=3, 22), `WinEventLog:Sysmon` (EventCode=1).
12. **T1587.001 Malware** — Consider analyzing malware for features that may be associated with the adversary and/or their developers, such as compiler used, debugging artifacts, or code similarities. Malware repositories can also be used to identify additional samples associated with… Dados: `Malware Repository` (None), `Malware Repository` (None).

## 11. OSINT — onde pesquisar

Consultas prontas com todos os nomes conhecidos do grupo:

- Relatórios técnicos: [busca web](https://duckduckgo.com/?q=%28%22LuminousMoth%22%29+threat+report) · [PDFs](https://duckduckgo.com/?q=%28%22LuminousMoth%22%29+filetype%3Apdf)
- Regras e IOCs publicados: [GitHub](https://github.com/search?type=code&q=%22LuminousMoth%22)
- Pulsos de ameaça: [AlienVault OTX](https://otx.alienvault.com/browse/global/pulses?q=LuminousMoth)
- Família de malware e atores: [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/actors) (busque por LuminousMoth)
- Cartões de grupo: [ThaiCERT Threat Group Cards](https://apt.etda.or.th/cgi-bin/listgroups.cgi)
- Página oficial: [MITRE ATT&CK G1014](https://attack.mitre.org/groups/G1014/)

**Relatórios públicos ligados pelo APT4ALL** (1 no total, mais recentes primeiro):

- 2021 — [LuminousMoth APT: Sweeping attacks for the chosen few](https://app.box.com/s/v7po0a45ua8rz0vhbb7pnc6gocrs3lfq) _(Kaspersky)_

## 12. Bibliografia (2 fontes citadas pelo ATT&CK)

- [Bitdefender LuminousMoth July 2021](https://www.bitdefender.com/blog/labs/luminousmoth-plugx-file-exfiltration-and-persistence-revisited) — Botezatu, B and etl. (2021, July 21). LuminousMoth - PlugX, File Exfiltration and Persistence Revisited. Retrieved October 20, 2022.
- [Kaspersky LuminousMoth July 2021](https://securelist.com/apt-luminousmoth/103332/) — Lechtik, M, and etl. (2021, July 14). LuminousMoth APT: Sweeping attacks for the chosen few. Retrieved October 20, 2022.

## 13. Limites e confiança

- O ATT&CK registra o que foi **relatado publicamente**, não tudo o que o grupo faz. Ausência de uma técnica não prova que o grupo não a usa.
- **Sobreposição de TTP não é atribuição.** Muitas técnicas são compartilhadas entre grupos e com red teams. Use a assinatura comportamental como hipótese, junto com infraestrutura, malware e contexto.
- Cobertura de detecção refere-se ao catálogo público Detection Rules, não ao seu ambiente: confira se a telemetria necessária chega ao seu SIEM.
- Ligações marcadas como _inferidas_ (EVTX por palavra-chave, relatórios por nome) devem ser verificadas.

---
Fontes: MITRE ATT&CK® (uso livre com atribuição, © The MITRE Corporation), APT4ALL (MISP Galaxy CC0/BSD-2, APT Groups & Operations CC BY 4.0, EternalLiberty, APTnotes, Ransomware Tool Matrix CC BY 4.0), Atomic Red Team (Red Canary, MIT), EVTX-to-MITRE-Attack, EVTX-ATTACK-SAMPLES, APT & CyberCriminal Campaign Collections. Gerado por [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules).
