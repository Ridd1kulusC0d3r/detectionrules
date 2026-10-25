# ZIRCONIUM (G0128) — Dossiê de inteligência

> **TLP:CLEAR** · gerado em 2026-10-25 a partir de fontes abertas · MITRE ATT&CK v20.0 · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0128) · [ATT&CK](https://attack.mitre.org/groups/G0128/)

**Também conhecido como:** APT31, Violet Typhoon  
**Registro no ATT&CK:** criado em 2021-03-24, atualizado em 2026-07-31 · referências de 2020 a 2024

## 1. Sumário executivo

- **29 técnicas** atribuídas publicamente, concentradas em **Discovery, Stealth, Command and Control**.
- **Arsenal:** 0 malware e 0 ferramentas.
- **Campanhas atribuídas:** 0.
- **Cobertura de detecção pública:** 90% das técnicas têm ao menos uma regra no catálogo; **3 técnicas sem nenhuma regra pública**.
- **Assinatura comportamental** (técnicas raras entre os 178 grupos, as mais úteis para atribuição): T1665 Hide Infrastructure, T1584.008 Network Devices, T1218.007 Msiexec, T1598 Phishing for Information, T1090.003 Multi-hop Proxy.

## 2. Quem é

> ZIRCONIUM is a threat group operating out of China, active since at least 2017, that has targeted individuals associated with the 2020 US presidential election and prominent leaders in the international affairs community.

_Texto original do MITRE ATT&CK, em inglês._

## 3. Perfil TTP por tática (kill chain)

Cada linha: técnica, como o grupo a usou segundo relatos públicos, e o que existe para detectar e testar.

### Reconnaissance (TA0043) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1598](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1598) Phishing for Information | ZIRCONIUM targeted presidential campaign staffers with credential phishing e-mails. | 4 | — | — |
| [T1598.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1598.003) Spearphishing Link | ZIRCONIUM has used web beacons in e-mails to track hits to attacker-controlled URL's. | **0** | — | — |

### Resource Development (TA0042) — 3

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1583.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1583.001) Domains | ZIRCONIUM has purchased domains for use in targeted campaigns. | 7 | — | — |
| [T1583.006](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1583.006) Web Services | ZIRCONIUM has used GitHub to host malware linked in spearphishing e-mails. | 2 | — | — |
| [T1584.008](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1584.008) Network Devices | ZIRCONIUM has compromised network devices such as small office and home office (SOHO) routers and IoT devices for ORB (operational relay box) Proxy networks. | **0** | — | — |

### Initial Access (TA0001) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1566.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1566.002) Spearphishing Link | ZIRCONIUM has used malicious links in e-mails to deliver malware. | 138 | 1 | — |

### Execution (TA0002) — 3

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1059.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.003) Windows Command Shell | ZIRCONIUM has used a tool to open a Windows Command Shell on a remote host. | 269 | 6 | 1 |
| [T1059.006](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.006) Python | ZIRCONIUM has used Python-based implants to interact with compromised hosts. | 122 | — | — |
| [T1204.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1204.001) Malicious Link | ZIRCONIUM has used malicious links in e-mails to lure victims into downloading malware. | 52 | — | — |

### Persistence (TA0003) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1547.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1547.001) Registry Run Keys / Startup Folder | ZIRCONIUM has created a Registry Run key named Dropbox Update Setup to establish persistence for a malicious Python binary. | 299 | 21 | 2 |

### Privilege Escalation (TA0004) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1068](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1068) Exploitation for Privilege Escalation | ZIRCONIUM has exploited CVE-2017-0005 for local privilege escalation. | 408 | 2 | 2 |
| [T1547.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1547.001) Registry Run Keys / Startup Folder | ZIRCONIUM has created a Registry Run key named Dropbox Update Setup to establish persistence for a malicious Python binary. | 299 | 21 | 2 |

### Stealth (TA0005) — 5

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1027.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1027.002) Software Packing | ZIRCONIUM has used multi-stage packers for exploit code. | 12 | 4 | — |
| [T1036](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1036) Masquerading | ZIRCONIUM has spoofed legitimate applications in phishing lures and changed file extensions to conceal installation of malware. | 453 | 2 | 1 |
| [T1036.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1036.004) Masquerade Task or Service | ZIRCONIUM has created a run key named Dropbox Update Setup to mask a persistence mechanism for a malicious binary. | 31 | 4 | — |
| [T1140](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1140) Deobfuscate/Decode Files or Information | ZIRCONIUM has used the AES256 algorithm with a SHA1 derived key to decrypt exploit code. | 173 | 11 | 1 |
| [T1218.007](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1218.007) Msiexec | ZIRCONIUM has used the msiexec.exe command-line utility to download and execute malicious MSI files. | 85 | 11 | — |

### Credential Access (TA0006) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1555.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1555.003) Credentials from Web Browsers | ZIRCONIUM has used a tool to steal credentials from installed web browsers including Microsoft Internet Explorer and Google Chrome. | 59 | 18 | 5 |

### Discovery (TA0007) — 5

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1012](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1012) Query Registry | ZIRCONIUM has used a tool to query the Registry for proxy settings. | 92 | 6 | — |
| [T1016](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1016) System Network Configuration Discovery | ZIRCONIUM has used a tool to enumerate proxy settings in the target environment. | 99 | 10 | 5 |
| [T1033](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1033) System Owner/User Discovery | ZIRCONIUM has used a tool to capture the username on a compromised host in order to register it with C2. | 181 | 8 | — |
| [T1082](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1082) System Information Discovery | ZIRCONIUM has used a tool to capture the processor architecture of a compromised host in order to register it with C2. | 264 | 41 | — |
| [T1124](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1124) System Time Discovery | ZIRCONIUM has used a tool to capture the time on a compromised host in order to register it with C2. | 18 | 6 | — |

### Command and Control (TA0011) — 5

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1090.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1090.003) Multi-hop Proxy | ZIRCONIUM has utilized an ORB (operational relay box) network – consisting compromised devices such as small office and home office (SOHO) routers, IoT devices, and leased virtual private servers (VPS) – to proxy traffic. | 44 | 4 | — |
| [T1102.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1102.002) Bidirectional Communication | ZIRCONIUM has used Dropbox for C2 allowing upload and download of files as well as execution of arbitrary commands. | 27 | — | — |
| [T1105](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1105) Ingress Tool Transfer | ZIRCONIUM has used tools to download malicious files to compromised hosts. | 644 | 39 | — |
| [T1573.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1573.001) Symmetric Cryptography | ZIRCONIUM has used AES encrypted communications in C2. | 5 | — | — |
| [T1665](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1665) Hide Infrastructure | ZIRCONIUM has utilized an ORB (operational relay box) network – consisting compromised devices such as small office and home office (SOHO) routers, IoT devices, and leased virtual private servers (VPS) – to obfuscate the origin of C2 traffic. | **0** | — | — |

### Exfiltration (TA0010) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1041](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1041) Exfiltration Over C2 Channel | ZIRCONIUM has exfiltrated files via the Dropbox API C2. | 135 | 2 | — |
| [T1567.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1567.002) Exfiltration to Cloud Storage | ZIRCONIUM has exfiltrated stolen data to Dropbox. | 85 | 2 | — |

## 4. Assinatura comportamental

Técnicas que este grupo usa e que poucos dos 178 grupos do ATT&CK usam. Pesam mais numa atribuição por TTP: ver várias delas juntas é mais informativo do que ver técnicas comuns como PowerShell.

| Técnica | Outros grupos que usam | Peso (raridade) |
|---|---:|---:|
| T1665 Hide Infrastructure | 1 | 4.09 |
| T1584.008 Network Devices | 4 | 3.40 |
| T1218.007 Msiexec | 5 | 3.24 |
| T1598 Phishing for Information | 5 | 3.24 |
| T1090.003 Multi-hop Proxy | 12 | 2.55 |
| T1573.001 Symmetric Cryptography | 13 | 2.48 |
| T1124 System Time Discovery | 14 | 2.42 |
| T1102.002 Bidirectional Communication | 15 | 2.35 |
| T1598.003 Spearphishing Link | 15 | 2.35 |
| T1012 Query Registry | 19 | 2.14 |

## 5. Arsenal

Nenhum software atribuído no ATT&CK.

## 6. Campanhas

Nenhuma campanha atribuída no ATT&CK.

## 7. Cobertura defensiva

**26 de 29 técnicas (90%)** têm ao menos uma regra pública no catálogo Detection Rules.

### Técnicas sem regra pública (prioridade para engenharia de detecção)

- **T1665 Hide Infrastructure** — Command and Control. Fonte de log sugerida pelo MITRE: `WinEventLog:Security` EventCode=5156, 5157; `auditd:SYSCALL` execve: Execution of commands modifying iptables/nftables to block selective IPs; `macos:unifiedlog` System process modifications altering
- **T1584.008 Network Devices** — Resource Development. Fonte de log sugerida pelo MITRE: `Internet Scan` None
- **T1598.003 Spearphishing Link** — Reconnaissance. Fonte de log sugerida pelo MITRE: `Application Log` None

### Regras recomendadas por técnica

Melhor regra disponível por técnica (formato portável e maduro primeiro).

| Técnica | Regra | Formato | Fonte |
|---|---|---|---|
| T1012 | [Potential Baby Shark Malware Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A2b30fa36-3a18-402f-a22d-bf4ce2189f35) | Sigma | SigmaHQ |
| T1012 | [Operation Wocao Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1cfac73c-be78-4f9a-9b08-5bde0c3953ab) | Sigma | SigmaHQ |
| T1016 | [Potential Pikabot Discovery Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A698d4431-514f-4c82-af4d-cf573872a9f5) | Sigma | SigmaHQ |
| T1016 | [OpenCanary - SNMP OID Request](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae9856028-fd4e-46e6-b3d1-10f7ceb95078) | Sigma | SigmaHQ |
| T1027.002 | [Python Image Load By Non-Python Process](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acbb56d62-4060-40f7-9466-d8aaf3123f83) | Sigma | SigmaHQ |
| T1027.002 | [Python Py2Exe Image Load](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Acbb56d62-4060-40f7-9466-d8aaf3123f83) | Sigma | OpenSearch Security Analytics |
| T1033 | [Potential Dridex Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae6eb5a96-9e6f-4a18-9cdd-642cfda21c8e) | Sigma | SigmaHQ |
| T1033 | [Dridex Process Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Ae6eb5a96-9e6f-4a18-9cdd-642cfda21c8e) | Sigma | OpenSearch Security Analytics |
| T1036 | [Potential LSASS Process Dump Via Procdump](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A5afee48e-67dd-4e03-a783-f74259dcf998) | Sigma | SigmaHQ |
| T1036 | [Suspicious Use of Procdump on LSASS](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A5afee48e-67dd-4e03-a783-f74259dcf998) | Sigma | OpenSearch Security Analytics |
| T1036.004 | [Operation Wocao Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1cfac73c-be78-4f9a-9b08-5bde0c3953ab) | Sigma | SigmaHQ |
| T1036.004 | [Operation Wocao Activity - Security](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A74ad4314-482e-4c3e-b237-3f7ed3b9ca8d) | Sigma | SigmaHQ |
| T1041 | [Equation Group C2 Communication](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A881834a4-6659-4773-821e-1c151789d873) | Sigma | SigmaHQ |
| T1041 | [OpenCanary - TFTP Request](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab4e6b016-a2ac-4759-ad85-8000b300d61e) | Sigma | SigmaHQ |
| T1059.003 | [HackTool - CrackMapExec Execution Patterns](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A058f4380-962d-40a5-afce-50207d36d7e2) | Sigma | SigmaHQ |
| T1059.003 | [CrackMapExec Command Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A058f4380-962d-40a5-afce-50207d36d7e2) | Sigma | OpenSearch Security Analytics |
| T1059.006 | [Emotet Loader Execution Via .LNK File](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1f32d820-1d5c-43fe-8fe2-feef0c952eb7) | Sigma | SigmaHQ |
| T1059.006 | [Serpent Backdoor Payload Execution Via Scheduled Task](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad5eb7432-fda4-4bba-a37f-ffa74d9ed639) | Sigma | SigmaHQ |
| T1068 | [Exploiting CVE-2019-1388](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A02e0b2ea-a597-428e-b04a-af6a1a403e5c) | Sigma | SigmaHQ |
| T1068 | [OMIGOD HTTP No Authentication RCE - CVE-2021-38647](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aab6b1a39-a9ee-4ab4-b075-e83acf6e346b) | Sigma | SigmaHQ |
| T1082 | [Potential GobRAT File Discovery Via Grep](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae34cfa0c-0a50-4210-9cb3-5632d08eb041) | Sigma | SigmaHQ |
| T1082 | [System Information Discovery](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A42df45e7-e6e9-43b5-8f26-bec5b39cc239) | Sigma | SigmaHQ |
| T1090.003 | [Tor Client/Browser Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A62f7c9bf-9135-49b2-8aeb-1e54a6ecc13c) | Sigma | SigmaHQ |
| T1090.003 | [Query Tor Onion Address - DNS Client](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A8384bd26-bde6-4da9-8e5d-4174a7a47ca2) | Sigma | SigmaHQ |
| T1102.002 | [Potential Etherhiding C2 via Blockchain Connection](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Abba8c7d1-172b-435d-9034-02ed9289c628) | Elastic | Elastic detection-rules |
| T1102.002 | [Google Calendar C2 via Script Interpreter](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Aabc7a2be-479e-428b-b0b3-1d22bda46dd9) | Elastic | Elastic detection-rules |
| T1105 | [Greenbug Espionage Group Indicators](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A3711eee4-a808-4849-8a14-faf733da3612) | Sigma | SigmaHQ |
| T1105 | [Pandemic Registry Key](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A47e0852a-cf81-4494-a8e6-31864f8c86ed) | Sigma | SigmaHQ |
| T1124 | [Use of W32tm as Timer](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A6da2c9f5-7c53-401b-aacb-92c040ce1215) | Sigma | SigmaHQ |
| T1124 | [Cisco Discovery](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A9705a6a1-6db6-4a16-a987-15b7151e299b) | Sigma | SigmaHQ |
| T1140 | [UNC4841 - SSL Certificate Exfiltration Via Openssl](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A60911c07-f989-4362-84af-c609828ef829) | Sigma | SigmaHQ |
| T1140 | [UNC4841 - Download Compressed Files From Temp.sh Using Wget](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A60d050c4-e253-4d9a-b673-5ac100cfddfb) | Sigma | SigmaHQ |
| T1204.001 | [Google Workspace Object Copied from External Drive with App Consent](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Af33e68a4-bd19-11ed-b02f-f661ea17fbcc) | Elastic | Elastic detection-rules |
| T1204.001 | [Suspicious ClickFix/FileFix Execution Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad487ed4a-fd24-436d-a0b2-f4e95f7b2635) | Sigma | SigmaHQ |
| T1218.007 | [Potential Remote Install via MsiExec](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ac9847fe9-3bed-4e6b-b319-f9956d6dd02a) | Elastic | Elastic detection-rules |
| T1218.007 | [Potential Escalation via Vulnerable MSI Repair](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A043d80a3-c49e-43ef-9c72-1088f0c7b278) | Elastic | Elastic detection-rules |
| T1547.001 | [Potential Ryuk Ransomware Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac37510b8-2107-4b78-aa32-72f251e7a844) | Sigma | SigmaHQ |
| T1547.001 | [Ryuk Ransomware](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Ac37510b8-2107-4b78-aa32-72f251e7a844) | Sigma | OpenSearch Security Analytics |
| T1555.003 | [SQLite Chromium Profile Data DB Access](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A24c77512-782b-448a-8950-eddb0785fc71) | Sigma | SigmaHQ |
| T1555.003 | [HackTool - WinPwn Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad557dc06-62e8-4468-a8e8-7984124908ce) | Sigma | SigmaHQ |
| T1566.002 | [Potential Malicious Usage of CloudTrail System Manager](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A38e7f511-3f74-41d4-836e-f57dfa18eead) | Sigma | SigmaHQ |
| T1566.002 | [Google Workspace Device Registration After OAuth from Suspicious ASN](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A012bfca7-45cb-4507-a3ba-3777167f8b81) | Elastic | Elastic detection-rules |
| T1567.002 | [APT40 Dropbox Tool User Agent](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A5ba715b6-71b7-44fd-8245-f66893e81b3d) | Sigma | SigmaHQ |
| T1567.002 | [PUA - Rclone Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae37db05d-d1f9-49c8-b464-cee1a4b11638) | Sigma | SigmaHQ |
| T1573.001 | [CYFIRMA - High severity Command & Control Network Indicators with Monitor Recommendation Rule](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A6d8fb3fe-2501-4103-8137-34261fa3a596) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1573.001 | [CYFIRMA - High severity Command & Control Network Indicators with Block Recommendation Rule](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A6b61b716-afd9-4f6c-ad00-965d5987cafd) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1583.001 | [AWS Route 53 Private Hosted Zone Associated With a VPC](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ae3c27562-709a-42bd-82f2-3ed926cced19) | Elastic | Elastic detection-rules |
| T1583.001 | [AWS SES Email Identity Verified Then Deleted](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A8e4bde35-125d-4eb3-9a2e-d7e77a053a08) | Elastic | Elastic detection-rules |
| T1583.006 | [GitHub Repo Created](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A6cea88e4-6ce2-4238-9981-a54c140d6336) | Elastic | Elastic detection-rules |
| T1583.006 | [Cisco Secure Firewall - Rare Snort Rule Triggered](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=splunk-security-content%3A%3Ae20313d2-7d63-4fcf-b2d9-d6e12c6c7bd7) | Splunk | Splunk security_content |
| T1598 | [CyberBlindSpot - Any Issue Detected](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3Aabe1a662-d00d-482e-aa68-9394622ae02e) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1598 | [Proofpoint Phishing Email Detected](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=panther-panther-analysis%3A%3AProofpoint.PhishingDetected) | Panther | Panther panther-analysis |

## 8. Plano de emulação e validação

Use num laboratório isolado e autorizado para confirmar que as regras disparam. Os comandos estão nos repositórios oficiais.

| Tática | Técnica | Teste Atomic Red Team | Plataformas |
|---|---|---|---|
| Initial Access | [T1566.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1566.002/T1566.002.md) | Paste and run technique | windows |
| Execution | [T1059.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.003/T1059.003.md) | Create and Execute Batch Script | windows |
| Execution | [T1059.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.003/T1059.003.md) | Writes text to a file and displays it. | windows |
| Persistence | [T1547.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1547.001/T1547.001.md) | Reg Key Run | windows |
| Persistence | [T1547.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1547.001/T1547.001.md) | Reg Key RunOnce | windows |
| Privilege Escalation | [T1068](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1068/T1068.md) | Scattered Spider BYOVD (CVE-2015-2291 for Intel Ethernet Diagnostics Driver) | windows |
| Privilege Escalation | [T1068](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1068/T1068.md) | Turla Snake Malware Privilege Escalation Through VM Driver | windows |
| Stealth | [T1027.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027.002/T1027.002.md) | Binary simply packed by UPX (linux) | linux |
| Stealth | [T1027.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027.002/T1027.002.md) | Binary packed by UPX, with modified headers (linux) | linux |
| Stealth | [T1036](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036/T1036.md) | System File Copied to Unusual Location | windows |
| Stealth | [T1036](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036/T1036.md) | Malware Masquerading and Execution from Zip File | windows |
| Stealth | [T1036.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.004/T1036.004.md) | Creating W32Time similar named service using schtasks | windows |
| Stealth | [T1036.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.004/T1036.004.md) | Creating W32Time similar named service using sc | windows |
| Stealth | [T1140](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1140/T1140.md) | Deobfuscate/Decode Files Or Information | windows |
| Stealth | [T1140](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1140/T1140.md) | Certutil Rename and Decode | windows |
| Stealth | [T1218.007](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.007/T1218.007.md) | Msiexec.exe - Execute Local MSI file with embedded JScript | windows |
| Stealth | [T1218.007](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.007/T1218.007.md) | Msiexec.exe - Execute Local MSI file with embedded VBScript | windows |
| Credential Access | [T1555.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1555.003/T1555.003.md) | Run Chrome-password Collector | windows |
| Credential Access | [T1555.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1555.003/T1555.003.md) | Search macOS Safari Cookies | macos |
| Discovery | [T1012](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1012/T1012.md) | Query Registry | windows |
| Discovery | [T1012](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1012/T1012.md) | Query Registry with Powershell cmdlets | windows |
| Discovery | [T1016](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1016/T1016.md) | System Network Configuration Discovery on Windows | windows |
| Discovery | [T1016](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1016/T1016.md) | List Windows Firewall Rules | windows |
| Discovery | [T1033](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1033/T1033.md) | System Owner/User Discovery | windows |
| Discovery | [T1033](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1033/T1033.md) | System Owner/User Discovery | linux, macos |
| Discovery | [T1082](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1082/T1082.md) | System Information Discovery | windows |
| Discovery | [T1082](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1082/T1082.md) | System Information Discovery | macos |
| Discovery | [T1124](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1124/T1124.md) | System Time Discovery | windows |
| Discovery | [T1124](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1124/T1124.md) | System Time Discovery - PowerShell | windows |
| Command and Control | [T1090.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1090.003/T1090.003.md) | Psiphon | windows |
| Command and Control | [T1090.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1090.003/T1090.003.md) | Tor Proxy Usage - Windows | windows |
| Command and Control | [T1105](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1105/T1105.md) | rsync remote file copy (push) | linux, macos |
| Command and Control | [T1105](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1105/T1105.md) | rsync remote file copy (pull) | linux, macos |
| Exfiltration | [T1041](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1041/T1041.md) | C2 Data Exfiltration | windows |
| Exfiltration | [T1041](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1041/T1041.md) | Text Based Data Exfiltration using DNS subdomains | windows |
| Exfiltration | [T1567.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1567.002/T1567.002.md) | Exfiltrate data with rclone to cloud Storage - Mega (Windows) | windows |
| Exfiltration | [T1567.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1567.002/T1567.002.md) | Exfiltrate data with rclone to cloud Storage - AWS S3 | linux, macos |

**Logs reais de ataque (EVTX) para testar sem executar nada:**

- T1016 — [ID4688-Audit policy enumerated](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1016-System%20Network%20Configuration%20Discovery/ID4688-Audit%20policy%20enumerated.evtx) _(explícito)_
- T1016 — [ID4688-Firewall configuration enumerated (command)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1016-System%20Network%20Configuration%20Discovery/ID4688-Firewall%20configuration%20enumerated%20%28command%29.evtx) _(explícito)_
- T1036 — [rundll32_hollowing_wermgr_masquerading](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/AutomatedTestingTools/Malware/rundll32_hollowing_wermgr_masquerading.evtx) _(inferido)_
- T1059.003 — [ID4688-SQL Server payload injectection for reverse shell (MSF)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1059.003-Windows%20Command%20Shell/ID4688-SQL%20Server%20payload%20injectection%20for%20reverse%20shell%20%28MSF%29.evtx) _(explícito)_
- T1068 — [ID12-13 Mini_Plasma_PoC_AbortHydration_ArbitraryRegKey_EoP](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0004-Privilege%20Escalation/T1068-Exploitation%20for%20Privilege%20Escalation/ID12-13%20Mini_Plasma_PoC_AbortHydration_ArbitraryRegKey_EoP.evtx) _(explícito)_
- T1068 — [ID4673-Privilege SeMachineAccountPrivilege called](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0004-Privilege%20Escalation/T1068-Exploitation%20for%20Privilege%20Escalation/ID4673-Privilege%20SeMachineAccountPrivilege%20called.evtx) _(explícito)_
- T1140 — [ID4688-Certutil download](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0005-Defense%20Evasion/T1140-Deobfuscate-Decode%20Files%20or%20Information/ID4688-Certutil%20download.evtx) _(explícito)_
- T1547.001 — [sideloading_injection_persistence_run_key](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/AutomatedTestingTools/Malware/sideloading_injection_persistence_run_key.evtx) _(inferido)_
- T1547.001 — [evasion_persis_hidden_run_keyvalue_sysmon_13](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Persistence/evasion_persis_hidden_run_keyvalue_sysmon_13.evtx) _(inferido)_
- T1555.003 — [CA_4624_4625_LogonType2_LogonProc_chrome](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Credential%20Access/CA_4624_4625_LogonType2_LogonProc_chrome.evtx) _(inferido)_
- T1555.003 — [CA_chrome_firefox_opera_4663](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Credential%20Access/CA_chrome_firefox_opera_4663.evtx) _(inferido)_

## 9. Hipóteses de hunting

Se ZIRCONIUM estiver no seu ambiente, estas são as perguntas a fazer aos seus dados (fontes de log segundo as estratégias de detecção do MITRE ATT&CK).

1. **T1665 Hide Infrastructure** — Monitor DNS queries, proxy logs, and user-agent strings for anomalous patterns associated with adversary attempts to hide infrastructure. Defenders may observe DNS resolutions to short-lived domains, abnormal WHOIS registration data, or filtering of known… Dados: `WinEventLog:Security` (EventCode=5156, 5157), `dns:query` (Excessive lookups for domains with suspicious WHOIS or short TTL values).
2. **T1584.008 Network Devices** — Once adversaries leverage compromised network devices as infrastructure (ex: for command and control), it may be possible to look for unique characteristics associated with adversary software, if known. Much of this activity will take place outside the… Dados: `Internet Scan` (None).
3. **T1218.007 Msiexec** — Detection of msiexec.exe execution where command-line arguments reference remote MSI packages, UNC paths, HTTP/HTTPS URLs, or DLLs, correlated with subsequent module loads and/or network connections to previously unseen destinations. The behavioral chain… Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=7), `WinEventLog:Sysmon` (EventCode=3, 22).
4. **T1598 Phishing for Information** — Monitor and analyze traffic patterns and packet inspection associated to protocol(s) that do not follow the expected protocol standards and traffic flows (e.g extraneous packets that do not belong to established flows, gratuitous or anomalous traffic… Dados: `Network Traffic` (None), `Application Log` (None), `Network Traffic` (None).
5. **T1090.003 Multi-hop Proxy** — Suspicious processes (e.g., Tor clients, relays, unknown binaries) launch with sustained encrypted outbound traffic to known anonymity infrastructure (e.g., Tor, I2P), and may relay to additional internal systems via reverse proxying, ICMP tunneling, or… Dados: `WinEventLog:Sysmon` (EventCode=3, 22), `WinEventLog:Sysmon` (EventCode=1), `dns:query` (Outbound resolution to hidden service domains (e.g., `.onion`)).
6. **T1573.001 Symmetric Cryptography** — Processes that typically do not perform cryptographic operations loading symmetric encryption libraries (e.g., bcryptprimitives.dll, aes.dll), then initiating outbound connections with high-entropy payloads. Defender correlates process creation, DLL load, and… Dados: `WinEventLog:Sysmon` (EventCode=7), `WinEventLog:Sysmon` (EventCode=3, 22).
7. **T1124 System Time Discovery** — Untrusted or unusual process/script (cmd.exe, powershell.exe, w32tm.exe, net.exe, custom binaries) queries system time/timezone (e.g., w32tm /tz, net time \\host, Get-TimeZone, GetTickCount API) and (optionally) is followed within a short window by time-based… Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=7), `WinEventLog:Sysmon` (EventCode=10).
8. **T1102.002 Bidirectional Communication** — Suspicious processes initiating encrypted HTTPS connections to common web service domains, followed by abnormal data upload behavior or automated posting behavior indicative of C2 bidirectional traffic. Dados: `WinEventLog:Sysmon` (EventCode=3, 22), `WinEventLog:Sysmon` (EventCode=1), `etw:Microsoft-Windows-WinINet` (HTTPS Inspection).
9. **T1598.003 Spearphishing Link** — Monitor for suspicious email activity, such as numerous accounts receiving messages from a single unusual/unknown sender. Filtering based on DKIM+SPF or header analysis can help detect when the email sender is spoofed. Monitor for references to uncategorized… Dados: `Application Log` (None), `Network Traffic` (None), `Network Traffic` (None).
10. **T1012 Query Registry** — Registry read access associated with suspicious or non-interactive processes querying system config, installed software, or security settings. Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=13, 14), `WinEventLog:PowerShell` (EventCode=4103, 4104, 4105, 4106).
11. **T1036 Masquerading** — Adversary renames LOLBINs or deploys binaries with spoofed file names, internal PE metadata, or misleading icons to appear legitimate. File creation is followed by execution or service registration inconsistent with known usage. Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:System` (EventCode=7045).
12. **T1059.006 Python** — Detects Python execution via python.exe or py.exe with anomalous parent lineage (e.g., Office macros, LOLBAS), execution from unusual directories, or chained network/PowerShell/system-level activity. Dados: `WinEventLog:Sysmon` (EventCode=1), `EDR:hunting` (Advanced Hunting: DeviceProcessEvents + DeviceNetworkEvents).

## 10. OSINT — onde pesquisar

Consultas prontas com todos os nomes conhecidos do grupo:

- Relatórios técnicos: [busca web](https://duckduckgo.com/?q=%28%22ZIRCONIUM%22+OR+%22APT31%22+OR+%22Violet+Typhoon%22%29+threat+report) · [PDFs](https://duckduckgo.com/?q=%28%22ZIRCONIUM%22+OR+%22APT31%22+OR+%22Violet+Typhoon%22%29+filetype%3Apdf)
- Regras e IOCs publicados: [GitHub](https://github.com/search?type=code&q=%22ZIRCONIUM%22+OR+%22APT31%22+OR+%22Violet+Typhoon%22)
- Pulsos de ameaça: [AlienVault OTX](https://otx.alienvault.com/browse/global/pulses?q=ZIRCONIUM)
- Família de malware e atores: [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/actors) (busque por ZIRCONIUM, APT31, Violet Typhoon)
- Cartões de grupo: [ThaiCERT Threat Group Cards](https://apt.etda.or.th/cgi-bin/listgroups.cgi)
- Página oficial: [MITRE ATT&CK G0128](https://attack.mitre.org/groups/G0128/)

**Relatórios na coleção CyberMonitor** (ligados pelo nome do grupo, conferir antes de citar):

- 2021 — [research.checkpoint.com-The Story of Jian  How APT31 Stole and Used an Unknown Equation Group 0-Day](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2021/2021.02.22.APT31_Equation_Group/research.checkpoint.com-The%20Story%20of%20Jian%20%20How%20APT31%20Stole%20and%20Used%20an%20Unknown%20Equation%20Group%200-Day.pdf) _(via “APT31”)_
- 2021 — [APT31 new dropper. Target destinations_ Mongolia, Russia, the U.S., and elsewhere](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2021/2021.08.03.APT31_new_dropper/APT31%20new%20dropper.%20Target%20destinations_%20Mongolia%2C%20Russia%2C%20the%20U.S.%2C%20and%20elsewhere.pdf) _(via “APT31”)_

## 11. Bibliografia (7 fontes citadas pelo ATT&CK)

- [Check Point APT31 February 2021](https://research.checkpoint.com/2021/the-story-of-jian/) — Itkin, E. and Cohen, I. (2021, February 22). The Story of Jian – How APT31 Stole and Used an Unknown Equation Group 0-Day. Retrieved March 24, 2021.
- [Google Election Threats October 2020](https://blog.google/threat-analysis-group/how-were-tackling-evolving-online-threats/) — Huntley, S. (2020, October 16). How We're Tackling Evolving Online Threats. Retrieved March 24, 2021.
- [Microsoft Targeting Elections September 2020](https://blogs.microsoft.com/on-the-issues/2020/09/10/cyberattacks-us-elections-trump-biden/) — Burt, T. (2020, September 10). New cyberattacks targeting U.S. elections. Retrieved March 24, 2021.
- [Microsoft Threat Actor Naming July 2023](https://learn.microsoft.com/en-us/microsoft-365/security/intelligence/microsoft-threat-actor-naming?view=o365-worldwide) — Microsoft . (2023, July 12). How Microsoft names threat actors. Retrieved November 17, 2023.
- [ORB APT31](https://therecord.media/chinese-hacking-group-apt31-uses-mesh-of-home-routers-to-disguise-attacks) — Cimpanu, Catalin. (2021, July 20). Chinese hacking group APT31 uses mesh of home routers to disguise attacks. Retrieved July 8, 2024.
- [ORB Mandiant](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks) — Raggi, Michael. (2024, May 22). IOC Extinction? China-Nexus Cyber Espionage Actors Use ORB Networks to Raise Cost on Defenders. Retrieved July 8, 2024.
- [Zscaler APT31 Covid-19 October 2020](https://www.zscaler.com/blogs/security-research/apt-31-leverages-covid-19-vaccine-theme-and-abuses-legitimate-online) — Singh, S. and Antil, S. (2020, October 27). APT-31 Leverages COVID-19 Vaccine Theme and Abuses Legitimate Online Services. Retrieved March 24, 2021.

## 12. Limites e confiança

- O ATT&CK registra o que foi **relatado publicamente**, não tudo o que o grupo faz. Ausência de uma técnica não prova que o grupo não a usa.
- **Sobreposição de TTP não é atribuição.** Muitas técnicas são compartilhadas entre grupos e com red teams. Use a assinatura comportamental como hipótese, junto com infraestrutura, malware e contexto.
- Cobertura de detecção refere-se ao catálogo público Detection Rules, não ao seu ambiente: confira se a telemetria necessária chega ao seu SIEM.
- Ligações marcadas como _inferidas_ (EVTX por palavra-chave, relatórios por nome) devem ser verificadas.

---
Fontes: MITRE ATT&CK® (uso livre com atribuição, © The MITRE Corporation), Atomic Red Team (Red Canary, MIT), EVTX-to-MITRE-Attack, EVTX-ATTACK-SAMPLES, APT & CyberCriminal Campaign Collections. Gerado por [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules).
