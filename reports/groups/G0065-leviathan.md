# Leviathan (G0065) — Dossiê de inteligência

> **TLP:CLEAR** · gerado em 2026-10-26 a partir de fontes abertas · MITRE ATT&CK v20.0 · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0065) · [ATT&CK](https://attack.mitre.org/groups/G0065/)

**Também conhecido como:** MUDCARP, Kryptonite Panda, Gadolinium, BRONZE MOHAWK, TEMP.Jumper, APT40, TEMP.Periscope, Gingham Typhoon  
**Origem atribuída:** China · **Motivação:** espionagem · **Setores-alvo:** Educação e pesquisa, Governo, Indústria, Defesa e militar, Setor privado (genérico), Transporte e logística  
**Registro no ATT&CK:** criado em 2018-04-18, atualizado em 2026-07-31 · referências de 2017 a 2024

## 1. Sumário executivo

- **50 técnicas** atribuídas publicamente, concentradas em **Stealth, Execution, Resource Development**.
- **Arsenal:** 10 malware e 7 ferramentas (ex.: Cobalt Strike, Empire, PowerSploit, gh0st RAT, Derusbi).
- **Campanhas atribuídas:** 1 (Leviathan Australian Intrusions).
- **Cobertura de detecção pública:** 92% das técnicas têm ao menos uma regra no catálogo; **4 técnicas sem nenhuma regra pública**.
- **Origem e alvos (APT4ALL):** atribuído a **China**, motivação espionagem; setores Educação e pesquisa, Governo, Indústria, Defesa e militar, Setor privado (genérico); 11 países vítimas citados.
- **Onde a cobertura está:** Windows (40 técnicas com regra), EDR / XDR (34 técnicas com regra), Linux (31 técnicas com regra), Outros / genérico (29 técnicas com regra).
- **Assinatura comportamental** (técnicas raras entre os 178 grupos, as mais úteis para atribuição): T1102.003 One-Way Communication, T1586.001 Social Media Accounts, T1547.009 Shortcut Modification, T1587.004 Exploits, T1197 BITS Jobs.

## 2. Quem é

> Leviathan is a Chinese state-sponsored cyber espionage group that has been attributed to the Ministry of State Security's (MSS) Hainan State Security Department and an affiliated front company. Active since at least 2009, Leviathan has targeted the following sectors: academia, aerospace/aviation, biomedical, defense industrial base, government, healthcare, manufacturing, maritime, and transportation across the US, Canada, Australia, Europe, the Middle East, and Southeast Asia.

_Texto original do MITRE ATT&CK, em inglês._

## 3. Contexto, nomes e alvos

Consolidado pelo [APT4ALL](https://github.com/Ridd1kulusC0d3r/apt4all) a partir de MISP Galaxy, planilha APT Groups & Operations, EternalLiberty e APTnotes. Atribuição é afirmação de quem publicou; confira a fonte.

| Campo | Valor |
|---|---|
| Origem atribuída | China |
| Motivação | espionagem |
| Setores-alvo | Educação e pesquisa, Governo, Indústria, Defesa e militar, Setor privado (genérico), Transporte e logística |
| Vítimas citadas | Asia Pacific Economic Cooperation, Belgium, Cambodia, Germany, Hong Kong, Malaysia, Norway, Philippines, Saudi Arabia, Switzerland, The Philippines, United Kingdom, United States |
| Alvos (planilha) | maritime-related targets across multiple verticals, including engineering firms, shipping and transportation, manufacturing, defense, government offices, and research universities \| Cambodia |
| Operações conhecidas | — |
| Confiança de atribuição (MISP) | 50 |

**Como cada fornecedor chama este grupo** (útil para cruzar relatórios):

| Fornecedor | Nome(s) |
|---|---|
| CrowdStrike | Leviathan |
| FireEye | Temp.Periscope |
| MITRE ATT&CK | G0065 |
| Mandiant | APT40 |
| Microsoft | Gingham Typhoon, GADOLINIUM (antigo · old) |

**Outros nomes no APT4ALL (não listados pelo ATT&CK):** Hainan Xiandun Technology Company, TA423, Red Ladon, ScanBox, ATK29, ITG09, ISLANDDREAMS, ISLAND CASTLE, Temp.Periscope/Temp.Jumper/APT40, Gadolinium/Gingham Typhoon, Pickleworm, Jumper Taurus, Flaccid Rose, Nanhaishu

## 4. Perfil TTP por tática (kill chain)

Cada linha: técnica, como o grupo a usou segundo relatos públicos, e o que existe para detectar e testar.

### Reconnaissance (TA0043) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1589.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1589.001) Credentials | Leviathan has collected compromised credentials to use for targeting efforts. | 2 | — | — |
| [T1595.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1595.002) Vulnerability Scanning | Leviathan has conducted reconnaissance against target networks of interest looking for vulnerable, end-of-life, or no longer maintainted devices against which to rapidly deploy exploits. | 27 | — | — |

### Resource Development (TA0042) — 8

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1583.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1583.001) Domains | Leviathan has established domains that impersonate legitimate entities to use for targeting efforts. | 7 | — | — |
| [T1584.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1584.004) Server | Leviathan has used compromised legitimate websites as command and control nodes for operations. | **0** | — | — |
| [T1584.008](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1584.008) Network Devices | Leviathan has used compromised networking devices, such as small office/home office (SOHO) devices, as operational command and control infrastructure. | **0** | — | — |
| [T1585.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1585.001) Social Media Accounts | Leviathan has created new social media accounts for targeting efforts. | 4 | — | — |
| [T1585.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1585.002) Email Accounts | Leviathan has created new email accounts for targeting efforts. | **0** | — | — |
| [T1586.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1586.001) Social Media Accounts | Leviathan has compromised social media accounts to conduct social engineering attacks. | **0** | — | — |
| [T1586.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1586.002) Email Accounts | Leviathan has compromised email accounts to conduct social engineering attacks. | 3 | — | — |
| [T1587.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1587.004) Exploits | Leviathan has rapidly transformed and adapted public exploit proof-of-concept code for new vulnerabilities and utilized them against target networks. | 4 | — | — |

### Initial Access (TA0001) — 6

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | Leviathan has obtained valid accounts to gain initial access. | 825 | — | 3 |
| [T1133](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1133) External Remote Services | Leviathan has used external remote services such as virtual private networks (VPN) to gain initial access. | 361 | 1 | — |
| [T1189](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1189) Drive-by Compromise | Leviathan has infected victims using watering holes. | 57 | — | — |
| [T1190](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1190) Exploit Public-Facing Application | Leviathan has used exploits against publicly-disclosed vulnerabilities for initial access into victim networks. | 580 | — | — |
| [T1566.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1566.001) Spearphishing Attachment | Leviathan has sent spearphishing emails with malicious attachments, including .rtf, .doc, and .xls files. | 230 | 2 | — |
| [T1566.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1566.002) Spearphishing Link | Leviathan has sent spearphishing emails with links, often using a fraudulent lookalike domain and stolen branding. | 138 | 1 | — |

### Execution (TA0002) — 8

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1047](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1047) Windows Management Instrumentation | Leviathan has used WMI for execution. | 370 | 12 | 11 |
| [T1059.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.001) PowerShell | Leviathan has used PowerShell for execution. | 1340 | 22 | 15 |
| [T1059.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.005) Visual Basic | Leviathan has used VBScript. | 192 | 3 | — |
| [T1197](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1197) BITS Jobs | Leviathan has used BITSAdmin to download additional tools. | 94 | 4 | 8 |
| [T1203](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1203) Exploitation for Client Execution | Leviathan has exploited multiple Microsoft Office and .NET vulnerabilities for execution, including CVE-2017-0199, CVE-2017-8759, and CVE-2017-11882. | 202 | — | — |
| [T1204.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1204.001) Malicious Link | Leviathan has sent spearphishing email links attempting to get a user to click. | 52 | — | — |
| [T1204.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1204.002) Malicious File | Leviathan has sent spearphishing attachments attempting to get a user to click. | 259 | 13 | — |
| [T1559.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1559.002) Dynamic Data Exchange | Leviathan has utilized OLE as a method to insert malicious content inside various phishing documents. | 10 | 3 | — |

### Persistence (TA0003) — 7

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | Leviathan has obtained valid accounts to gain initial access. | 825 | — | 3 |
| [T1133](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1133) External Remote Services | Leviathan has used external remote services such as virtual private networks (VPN) to gain initial access. | 361 | 1 | — |
| [T1197](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1197) BITS Jobs | Leviathan has used BITSAdmin to download additional tools. | 94 | 4 | 8 |
| [T1505.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1505.003) Web Shell | Leviathan relies on web shells for an initial foothold as well as persistence into the victim's systems. | 210 | 1 | — |
| [T1546.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1546.003) Windows Management Instrumentation Event Subscription | Leviathan has used WMI for persistence. | 99 | 4 | — |
| [T1547.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1547.001) Registry Run Keys / Startup Folder | Leviathan has used JavaScript to create a shortcut file in the Startup folder that points to its main backdoor. | 299 | 21 | 2 |
| [T1547.009](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1547.009) Shortcut Modification | Leviathan has used JavaScript to create a shortcut file in the Startup folder that points to its main backdoor. | 28 | 2 | — |

### Privilege Escalation (TA0004) — 5

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1055.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1055.001) Dynamic-link Library Injection | Leviathan has utilized techniques like reflective DLL loading to write a DLL into memory and load a shell that provides backdoor access to the victim. | 40 | 2 | — |
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | Leviathan has obtained valid accounts to gain initial access. | 825 | — | 3 |
| [T1546.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1546.003) Windows Management Instrumentation Event Subscription | Leviathan has used WMI for persistence. | 99 | 4 | — |
| [T1547.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1547.001) Registry Run Keys / Startup Folder | Leviathan has used JavaScript to create a shortcut file in the Startup folder that points to its main backdoor. | 299 | 21 | 2 |
| [T1547.009](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1547.009) Shortcut Modification | Leviathan has used JavaScript to create a shortcut file in the Startup folder that points to its main backdoor. | 28 | 2 | — |

### Stealth (TA0005) — 9

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1027.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1027.001) Binary Padding | Leviathan has inserted garbage characters into code, presumably to avoid anti-virus detection. | 13 | 3 | — |
| [T1027.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1027.003) Steganography | Leviathan has used steganography to hide stolen data inside other files stored on Github. | 13 | — | — |
| [T1027.013](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1027.013) Encrypted/Encoded File | Leviathan has obfuscated code using base64. | 8 | 4 | — |
| [T1027.015](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1027.015) Compression | Leviathan has obfuscated code using gzip compression. | 3 | — | — |
| [T1055.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1055.001) Dynamic-link Library Injection | Leviathan has utilized techniques like reflective DLL loading to write a DLL into memory and load a shell that provides backdoor access to the victim. | 40 | 2 | — |
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | Leviathan has obtained valid accounts to gain initial access. | 825 | — | 3 |
| [T1140](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1140) Deobfuscate/Decode Files or Information | Leviathan has used a DLL known as SeDll to decrypt and execute other JavaScript backdoors. | 173 | 11 | 1 |
| [T1197](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1197) BITS Jobs | Leviathan has used BITSAdmin to download additional tools. | 94 | 4 | 8 |
| [T1218.010](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1218.010) Regsvr32 | Leviathan has used regsvr32 for execution. | 150 | 5 | 2 |

### Defense Impairment (TA0112) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1553.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1553.002) Code Signing | Leviathan has used stolen code signing certificates to sign malware. | 11 | — | — |

### Credential Access (TA0006) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1003) OS Credential Dumping | Leviathan has used publicly available tools to dump password hashes, including HOMEFRY. | 399 | 7 | 19 |
| [T1003.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1003.001) LSASS Memory | Leviathan has used publicly available tools to dump password hashes, including ProcDump and WCE. | 580 | 14 | 10 |

### Lateral Movement (TA0008) — 3

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1021.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1021.001) Remote Desktop Protocol | Leviathan has targeted RDP credentials and used it to move through the victim environment. | 139 | 4 | 7 |
| [T1021.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1021.004) SSH | Leviathan used ssh for internal reconnaissance. | 60 | 2 | 3 |
| [T1534](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1534) Internal Spearphishing | Leviathan has conducted internal spearphishing within the victim's environment for lateral movement. | 5 | — | — |

### Collection (TA0009) — 3

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1074.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1074.001) Local Data Staging | Leviathan has used C:\Windows\Debug and C:\Perflogs as staging directories. | 37 | 3 | — |
| [T1074.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1074.002) Remote Data Staging | Leviathan has staged data remotely prior to exfiltration. | 5 | — | — |
| [T1560](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1560) Archive Collected Data | Leviathan has archived victim's data prior to exfiltration. | 53 | 1 | — |

### Command and Control (TA0011) — 4

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1090.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1090.003) Multi-hop Proxy | Leviathan has used multi-hop proxies to disguise the source of their malicious traffic. | 44 | 4 | — |
| [T1102.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1102.003) One-Way Communication | Leviathan has received C2 instructions from user profiles created on legitimate websites such as Github and TechNet. | 6 | — | — |
| [T1105](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1105) Ingress Tool Transfer | Leviathan has downloaded additional scripts and files from adversary-controlled servers. | 644 | 39 | — |
| [T1572](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1572) Protocol Tunneling | Leviathan has used protocol tunneling to further conceal C2 communications and infrastructure. | 173 | 9 | 1 |

### Exfiltration (TA0010) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1041](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1041) Exfiltration Over C2 Channel | Leviathan has exfiltrated data over its C2 channel. | 135 | 2 | — |
| [T1567.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1567.002) Exfiltration to Cloud Storage | Leviathan has used an uploader known as LUNCHMONEY that can exfiltrate files to Dropbox. | 85 | 2 | — |

## 5. Assinatura comportamental

Técnicas que este grupo usa e que poucos dos 178 grupos do ATT&CK usam. Pesam mais numa atribuição por TTP: ver várias delas juntas é mais informativo do que ver técnicas comuns como PowerShell.

| Técnica | Outros grupos que usam | Peso (raridade) |
|---|---:|---:|
| T1102.003 One-Way Communication | 1 | 4.09 |
| T1586.001 Social Media Accounts | 1 | 4.09 |
| T1547.009 Shortcut Modification | 3 | 3.58 |
| T1587.004 Exploits | 3 | 3.58 |
| T1197 BITS Jobs | 4 | 3.40 |
| T1584.008 Network Devices | 4 | 3.40 |
| T1589.001 Credentials | 5 | 3.24 |
| T1534 Internal Spearphishing | 6 | 3.11 |
| T1027.001 Binary Padding | 7 | 2.99 |
| T1027.003 Steganography | 9 | 2.79 |

## 6. Arsenal

| Software | Tipo | Técnicas no ATT&CK | Uso relatado (EN) |
|---|---|---:|---|
| [Cobalt Strike](https://attack.mitre.org/software/S0154/) | malware | 73 |  |
| [Empire](https://attack.mitre.org/software/S0363/) | ferramenta | 73 |  |
| [PowerSploit](https://attack.mitre.org/software/S0194/) | ferramenta | 28 |  |
| [gh0st RAT](https://attack.mitre.org/software/S0032/) | malware | 24 |  |
| [Derusbi](https://attack.mitre.org/software/S0021/) | malware | 18 |  |
| [Net](https://attack.mitre.org/software/S0039/) | ferramenta | 16 |  |
| [Orz](https://attack.mitre.org/software/S0229/) | malware | 13 |  |
| [NanHaiShu](https://attack.mitre.org/software/S0228/) | malware | 12 |  |
| [BADFLICK](https://attack.mitre.org/software/S0642/) | malware | 10 |  |
| [China Chopper](https://attack.mitre.org/software/S0020/) | malware | 10 |  |
| [MURKYTOP](https://attack.mitre.org/software/S0233/) | malware | 9 |  |
| [BLACKCOFFEE](https://attack.mitre.org/software/S0069/) | malware | 7 |  |
| [BITSAdmin](https://attack.mitre.org/software/S0190/) | ferramenta | 4 |  |
| [HOMEFRY](https://attack.mitre.org/software/S0232/) | malware | 3 |  |
| [Tor](https://attack.mitre.org/software/S0183/) | ferramenta | 2 |  |
| [at](https://attack.mitre.org/software/S0110/) | ferramenta | 1 |  |
| [Windows Credential Editor](https://attack.mitre.org/software/S0005/) | ferramenta | 1 |  |

**Outras ferramentas e malware relatados (planilha APT Groups & Operations / MISP):** AIRBREAK, PHOTO, LUNCHMONEY, Beacon, CVE-2017-11882, RoyalRoad RTF Weaponizer, 8.t exploit document builder

## 7. Campanhas

| Campanha | Período | Resumo (EN) |
|---|---|---|
| [Leviathan Australian Intrusions](https://attack.mitre.org/campaigns/C0049/) | 2022-04 → 2022-09 | Leviathan Australian Intrusions consisted of at least two long-term intrusions against victims in Australia by Leviathan, relying on similar tradecraft such as external service exploitation followed by extensive credenti |

## 8. Cobertura defensiva

**46 de 50 técnicas (92%)** têm ao menos uma regra pública no catálogo Detection Rules.

### Técnicas sem regra pública (prioridade para engenharia de detecção)

- **T1586.001 Social Media Accounts** — Resource Development. Fonte de log sugerida pelo MITRE: `Persona` None
- **T1584.008 Network Devices** — Resource Development. Fonte de log sugerida pelo MITRE: `Internet Scan` None
- **T1584.004 Server** — Resource Development. Fonte de log sugerida pelo MITRE: `Internet Scan` None
- **T1585.002 Email Accounts** — Resource Development

### Onde procurar — cobertura por tecnologia

Quantas técnicas deste grupo têm ao menos uma regra em cada tecnologia. Comece a caça pelas tecnologias que você tem e que aparecem aqui.

| Tecnologia | Técnicas do grupo com regra |
|---|---:|
| Windows | 40 |
| EDR / XDR | 34 |
| Linux | 31 |
| Outros / genérico | 29 |
| Servidores web & aplicações | 28 |
| Proxy / SWG | 25 |
| Microsoft 365 | 24 |
| E-mail | 23 |
| macOS | 22 |
| Firewall & perímetro | 22 |
| IDS / NSM / NDR | 22 |
| AWS | 21 |

### Regras recomendadas por técnica

Melhor regra disponível por técnica (formato portável e maduro primeiro).

| Técnica | Regra | Formato | Fonte |
|---|---|---|---|
| T1003 | [Antivirus - Password Dumper Signature](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A78cc2dd2-7d20-4d32-93ff-057084c38b93) | Sigma | SigmaHQ |
| T1003 | [HackTool - Rubeus Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A7ec2c172-dceb-4c10-92c9-87c1881b7e18) | Sigma | SigmaHQ |
| T1003.001 | [Antivirus - Password Dumper Signature](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A78cc2dd2-7d20-4d32-93ff-057084c38b93) | Sigma | SigmaHQ |
| T1003.001 | [Mimikatz through Windows Remote Management](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Aaa35a627-33fb-4d04-a165-d33b4afca3e8) | Sigma | OpenSearch Security Analytics |
| T1021.001 | [Hermetic Wiper TG Process Patterns](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A2f974656-6d83-4059-bbdf-68ac5403422f) | Sigma | SigmaHQ |
| T1021.001 | [Publicly Accessible RDP Service](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1fc0809e-06bf-4de3-ad52-25e5263b7623) | Sigma | SigmaHQ |
| T1021.004 | [Potential THC Tool Downloaded](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A2ddc468e-b39b-4f5b-9825-f3dcb0e998ea) | Elastic | Elastic detection-rules |
| T1021.004 | [AWS EC2 CreateKeyPair by New Principal from Non-Cloud AS Organization](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ac8e4f1a2-9b3d-4c5e-a6f7-8b9c0d1e2f3a) | Elastic | Elastic detection-rules |
| T1027.001 | [Binary Padding - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac52a914f-3d8b-4b2a-bb75-b3991e75f8ba) | Sigma | SigmaHQ |
| T1027.001 | [Failed Code Integrity Checks](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A470ec5fa-7b4e-4071-b200-4c753100f49b) | Sigma | SigmaHQ |
| T1027.003 | [Steganography Hide Files with Steghide](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ace446a9e-30b9-4483-8e38-d2c9ad0a2280) | Sigma | SigmaHQ |
| T1027.003 | [Steganography Unzip Hidden Information From Picture File](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aedd595d7-7895-4fa7-acb3-85a18a8772ca) | Sigma | SigmaHQ |
| T1027.013 | [ROT Encoded Python Script Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A5ab49127-b1b3-46e6-8a38-9e8512a2a363) | Elastic | Elastic detection-rules |
| T1027.013 | [Data Encrypted via OpenSSL Utility](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Afeba48f6-40ca-4d04-b41f-5dfa327de865) | Elastic | Elastic detection-rules |
| T1027.015 | [PowerShell Suspicious Payload Encoded and Compressed](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A81fe9dc6-a2d7-4192-a2d8-eed98afc766a) | Elastic | Elastic detection-rules |
| T1027.015 | [Suspicious Content Extracted or Decompressed via Funzip](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Adc0b7782-0df0-47ff-8337-db0d678bdb66) | Elastic | Elastic detection-rules |
| T1041 | [Equation Group C2 Communication](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A881834a4-6659-4773-821e-1c151789d873) | Sigma | SigmaHQ |
| T1041 | [OpenCanary - TFTP Request](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab4e6b016-a2ac-4759-ad85-8000b300d61e) | Sigma | SigmaHQ |
| T1047 | [HackTool - Potential Impacket Lateral Movement Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A10c14723-61c7-4c75-92ca-9af245723ad2) | Sigma | SigmaHQ |
| T1047 | [CrackMapExec Command Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A058f4380-962d-40a5-afce-50207d36d7e2) | Sigma | OpenSearch Security Analytics |
| T1055.001 | [TAIDOOR RAT DLL Load](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad1aa3382-abab-446f-96ea-4de52908210b) | Sigma | SigmaHQ |
| T1055.001 | [Renamed ZOHO Dctask64 Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A340a090b-c4e9-412e-bb36-b4b16fe96f9b) | Sigma | SigmaHQ |
| T1059.001 | [Potential Emotet Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad02e8cf5-6099-48cf-9bfc-1eec2d0c7b18) | Sigma | SigmaHQ |
| T1059.001 | [TropicTrooper Campaign November 2018](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A8c7090c3-e0a0-4944-bd08-08c3a0cecf79) | Sigma | SigmaHQ |
| T1059.005 | [Potential QBot Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4fcac6eb-0287-4090-8eea-2602e4c20040) | Sigma | SigmaHQ |
| T1059.005 | [QBot Process Creation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A4fcac6eb-0287-4090-8eea-2602e4c20040) | Sigma | OpenSearch Security Analytics |
| T1074.001 | [Sensitive File Access followed by Compression](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Aa0fbd7a9-1923-4e05-92df-b484168f17bc) | Elastic | Elastic detection-rules |
| T1074.001 | [Folder Compress To Potentially Suspicious Output Via Compress-Archive Cmdlet](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A85a8e5ba-bd03-4bfb-bbfa-a4409a8f8b98+%23+Process+Creation) | Sigma | SigmaHQ |
| T1074.002 | [Google Workspace Drive Data Transfer or Takeout Export Initiated](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A07b5f85a-240f-11ed-b3d9-f661ea17fbce) | Elastic | Elastic detection-rules |
| T1074.002 | [AWS RDS DB Instance Restored](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Abf1073bf-ce26-4607-b405-ba1ed8e9e204) | Elastic | Elastic detection-rules |
| T1078 | [Privilege Role Sign-In Outside Expected Controls](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acf1e5687-84e1-41af-97a9-158094efef53) | Sigma | SigmaHQ |
| T1078 | [OpenCanary - SSH Login Attempt](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aff7139bc-fdb1-4437-92f2-6afefe8884cb) | Sigma | SigmaHQ |
| T1090.003 | [Tor Client/Browser Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A62f7c9bf-9135-49b2-8aeb-1e54a6ecc13c) | Sigma | SigmaHQ |
| T1090.003 | [Query Tor Onion Address - DNS Client](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A8384bd26-bde6-4da9-8e5d-4174a7a47ca2) | Sigma | SigmaHQ |
| T1102.003 | [Raw Paste Service Access](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A5468045b-4fcc-4d1a-973c-c9c9578edacb) | Sigma | SigmaHQ |
| T1102.003 | [PwnDrp Access](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A2b1ee7e4-89b6-4739-b7bb-b811b6607e5e) | Sigma | SigmaHQ |
| T1105 | [Greenbug Espionage Group Indicators](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A3711eee4-a808-4849-8a14-faf733da3612) | Sigma | SigmaHQ |
| T1105 | [Pandemic Registry Key](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A47e0852a-cf81-4494-a8e6-31864f8c86ed) | Sigma | SigmaHQ |
| T1133 | [OpenCanary - SSH Login Attempt](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aff7139bc-fdb1-4437-92f2-6afefe8884cb) | Sigma | SigmaHQ |
| T1133 | [OpenCanary - SSH New Connection Attempt](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acd55f721-5623-4663-bd9b-5229cab5237d) | Sigma | SigmaHQ |
| T1140 | [UNC4841 - SSL Certificate Exfiltration Via Openssl](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A60911c07-f989-4362-84af-c609828ef829) | Sigma | SigmaHQ |
| T1140 | [UNC4841 - Download Compressed Files From Temp.sh Using Wget](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A60d050c4-e253-4d9a-b673-5ac100cfddfb) | Sigma | SigmaHQ |
| T1189 | [Flash Player Update from Suspicious Location](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4922a5dd-6743-4fc2-8e81-144374280997) | Sigma | SigmaHQ |
| T1189 | [Cross Site Scripting Strings](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A65354b83-a2ea-4ea6-8414-3ab38be0d409) | Sigma | SigmaHQ |
| T1190 | [OMIGOD HTTP No Authentication RCE - CVE-2021-38647](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aab6b1a39-a9ee-4ab4-b075-e83acf6e346b) | Sigma | SigmaHQ |
| T1190 | [Exploited CVE-2020-10189 Zoho ManageEngine](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A846b866e-2a57-46ee-8e16-85fa92759be7) | Sigma | OpenSearch Security Analytics |
| T1197 | [Bitsadmin to Uncommon TLD](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A9eb68894-7476-4cd6-8752-23b51f5883a7) | Sigma | SigmaHQ |
| T1197 | [Bitsadmin to Uncommon IP Server Address](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A8ccd35a2-1c7c-468b-b568-ac6cdf80eec3) | Sigma | SigmaHQ |
| T1203 | [Droppers Exploiting CVE-2017-11882](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A678eb5f4-8597-4be6-8be7-905e4234b53a) | Sigma | SigmaHQ |
| T1203 | [OMIGOD HTTP No Authentication RCE - CVE-2021-38647](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aab6b1a39-a9ee-4ab4-b075-e83acf6e346b) | Sigma | SigmaHQ |
| T1204.001 | [Google Workspace Object Copied from External Drive with App Consent](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Af33e68a4-bd19-11ed-b02f-f661ea17fbcc) | Elastic | Elastic detection-rules |
| T1204.001 | [Suspicious ClickFix/FileFix Execution Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad487ed4a-fd24-436d-a0b2-f4e95f7b2635) | Sigma | SigmaHQ |
| T1204.002 | [Ursnif Malware C2 URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A932ac737-33ca-4afd-9869-0d48b391fcc9) | Sigma | SigmaHQ |
| T1204.002 | [Droppers Exploiting CVE-2017-11882](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A678eb5f4-8597-4be6-8be7-905e4234b53a) | Sigma | SigmaHQ |
| T1218.010 | [Potential EmpireMonkey Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A10152a7b-b566-438f-a33c-390b607d1c8d) | Sigma | SigmaHQ |
| T1218.010 | [Suspicious Microsoft Office Child Process](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A438025f9-5856-4663-83f7-52f878a70a50) | Sigma | SigmaHQ |
| T1505.003 | [MOVEit CVE-2023-34362 Exploitation Attempt - Potential Web Shell Request](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A435e41f2-48eb-4c95-8a2b-ed24b50ec30b) | Sigma | SigmaHQ |
| T1505.003 | [Solarwinds SUPERNOVA Webshell Access](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aa2cee20b-eacc-459f-861d-c02e5d12f1db) | Sigma | SigmaHQ |
| T1534 | [AWS SNS Topic Message Publish by Rare User](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A2112ecce-cd34-11ef-873f-f661ea17fbcd) | Elastic | Elastic detection-rules |
| T1534 | [OpenAI ChatGPT Enterprise Gmail Message Sent via Connector](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A7184e35d-5605-4283-badf-435e1974e488) | Elastic | Elastic detection-rules |
| T1546.003 | [WMI Persistence - Script Event Consumer File Write](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A33f41cdd-35ac-4ba8-814b-c6a4244a1ad4) | Sigma | SigmaHQ |
| T1546.003 | [NewActiveScriptEventConsumer Creation Attempt via Wmic.EXE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aebef4391-1a81-4761-a40a-1db446c0e625) | Sigma | SigmaHQ |
| T1547.001 | [Potential Ryuk Ransomware Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac37510b8-2107-4b78-aa32-72f251e7a844) | Sigma | SigmaHQ |
| T1547.001 | [Ryuk Ransomware](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Ac37510b8-2107-4b78-aa32-72f251e7a844) | Sigma | OpenSearch Security Analytics |
| T1547.009 | [Creation Exe for Service with Unquoted Path](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A8c3c76ca-8f8b-4b1d-aaf3-81aebcd367c9) | Sigma | SigmaHQ |
| T1547.009 | [New Custom Shim Database Created](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aee63c85c-6d51-4d12-ad09-04e25877a947) | Sigma | SigmaHQ |
| T1553.002 | [Driver Loaded (Invalid Signature)](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=hayabusa-native%3A%3A1f666722-3948-40a2-9d78-d9d374477a90) | Sigma | Hayabusa (native) |
| T1553.002 | [Driver Loaded (Expired/Revoked Cert)](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=hayabusa-native%3A%3Ac837dd6d-0c91-4593-aeab-f6a1f3ca1961) | Sigma | Hayabusa (native) |
| T1559.002 | [Enable Microsoft Dynamic Data Exchange](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A63647769-326d-4dde-a419-b925cc0caf42) | Sigma | SigmaHQ |
| T1559.002 | [Enable Microsoft Dynamic Data Exchange](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A63647769-326d-4dde-a419-b925cc0caf42) | Sigma | OpenSearch Security Analytics |
| T1560 | [Conti NTDS Exfiltration Command](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aaa92fd02-09f2-48b0-8a93-864813fb8f41) | Sigma | SigmaHQ |
| T1560 | [Sensitive Files Compression Inside A Container](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ad9faf1ba-a216-4c29-b8e0-a05a9d14b027) | Elastic | Elastic detection-rules |
| T1566.001 | [Ursnif Malware C2 URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A932ac737-33ca-4afd-9869-0d48b391fcc9) | Sigma | SigmaHQ |
| T1566.001 | [Droppers Exploiting CVE-2017-11882](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A678eb5f4-8597-4be6-8be7-905e4234b53a) | Sigma | SigmaHQ |
| T1566.002 | [Potential Malicious Usage of CloudTrail System Manager](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A38e7f511-3f74-41d4-836e-f57dfa18eead) | Sigma | SigmaHQ |
| T1566.002 | [Google Workspace Device Registration After OAuth from Suspicious ASN](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A012bfca7-45cb-4507-a3ba-3777167f8b81) | Elastic | Elastic detection-rules |
| T1567.002 | [APT40 Dropbox Tool User Agent](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A5ba715b6-71b7-44fd-8245-f66893e81b3d) | Sigma | SigmaHQ |
| T1567.002 | [PUA - Rclone Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae37db05d-d1f9-49c8-b464-cee1a4b11638) | Sigma | SigmaHQ |
| T1572 | [Communication To LocaltoNet Tunneling Service Initiated - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac4568f5d-131f-4e78-83d4-45b2da0ec4f1) | Sigma | SigmaHQ |
| T1572 | [Communication To Ngrok Tunneling Service - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A19bf6fdb-7721-4f3d-867f-53467f6a5db6) | Sigma | SigmaHQ |
| T1583.001 | [AWS Route 53 Private Hosted Zone Associated With a VPC](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ae3c27562-709a-42bd-82f2-3ed926cced19) | Elastic | Elastic detection-rules |
| T1583.001 | [AWS SES Email Identity Verified Then Deleted](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A8e4bde35-125d-4eb3-9a2e-d7e77a053a08) | Elastic | Elastic detection-rules |
| T1585.001 | [CYFIRMA - Brand Intelligence - Social Media Handle Impersonation Detected High Rule](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A22f49d67-7da7-4809-8d07-89e4478aa6b0) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1585.001 | [CYFIRMA - Brand Intelligence - Executive/People Impersonation High Rule](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A159d26a1-591c-4f70-b1ca-2843c881aaec) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1586.002 | [CYFIRMA - Brand Intelligence - Domain Impersonation High Rule](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A10bdf525-5b89-4a25-933a-e63e73b915f1) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1586.002 | [CYFIRMA - Brand Intelligence - Domain Impersonation Medium Rule](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A8f97ddbe-ab66-4f6c-b675-73b5eeb07259) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1587.004 | [MS Graph message: Indicators of vulnerability exploitation on the system have been detected. However, this ale](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=wazuh-ruleset-oficial%3A%3Awazuh-99549) | Wazuh | Wazuh ruleset (oficial) |
| T1587.004 | [MS Graph message: Indicators of vulnerability exploitation on the system have been detected. This alert may be](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=wazuh-ruleset-oficial%3A%3Awazuh-99568) | Wazuh | Wazuh ruleset (oficial) |
| T1589.001 | [Linux Medusa Rootkit](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=splunk-security-content%3A%3A7add8520-71d5-43aa-b262-ee082b1f0238) | Splunk | Splunk security_content |
| T1589.001 | [MS Graph message: A user's credentials were compromised or stolen. This is a true positive alert.](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=wazuh-ruleset-oficial%3A%3Awazuh-99612) | Wazuh | Wazuh ruleset (oficial) |
| T1595.002 | [DNS Query to External Service Interaction Domains](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aaff715fa-4dd5-497a-8db3-910bea555566) | Sigma | SigmaHQ |
| T1595.002 | [Web Server Potential SQL Injection Request](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A7f7a0ee1-7b6f-466a-85b4-110fb105f5e2) | Elastic | Elastic detection-rules |

## 9. Plano de emulação e validação

Use num laboratório isolado e autorizado para confirmar que as regras disparam. Os comandos estão nos repositórios oficiais.

| Tática | Técnica | Teste Atomic Red Team | Plataformas |
|---|---|---|---|
| Initial Access | [T1566.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1566.001/T1566.001.md) | Download Macro-Enabled Phishing Attachment | windows |
| Initial Access | [T1566.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1566.001/T1566.001.md) | Word spawned a command shell and used an IP address in the command line | windows |
| Initial Access | [T1566.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1566.002/T1566.002.md) | Paste and run technique | windows |
| Execution | [T1047](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1047/T1047.md) | WMI Reconnaissance Users | windows |
| Execution | [T1047](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1047/T1047.md) | WMI Reconnaissance Processes | windows |
| Execution | [T1059.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md) | Mimikatz | windows |
| Execution | [T1059.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md) | Run BloodHound from local disk | windows |
| Execution | [T1059.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.005/T1059.005.md) | Visual Basic script execution to gather local computer information | windows |
| Execution | [T1059.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.005/T1059.005.md) | Encoded VBS code execution | windows |
| Execution | [T1204.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1204.002/T1204.002.md) | OSTap Style Macro Execution | windows |
| Execution | [T1204.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1204.002/T1204.002.md) | OSTap Payload Download | windows |
| Execution | [T1559.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1559.002/T1559.002.md) | Execute Commands | windows |
| Execution | [T1559.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1559.002/T1559.002.md) | Execute PowerShell script via Word DDE | windows |
| Persistence | [T1133](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1133/T1133.md) | Running Chrome VPN Extensions via the Registry 2 vpn extension | windows |
| Persistence | [T1505.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1505.003/T1505.003.md) | Web Shell Written to Disk | windows |
| Persistence | [T1547.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1547.001/T1547.001.md) | Reg Key Run | windows |
| Persistence | [T1547.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1547.001/T1547.001.md) | Reg Key RunOnce | windows |
| Persistence | [T1547.009](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1547.009/T1547.009.md) | Shortcut Modification | windows |
| Persistence | [T1547.009](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1547.009/T1547.009.md) | Create shortcut to cmd in startup folders | windows |
| Privilege Escalation | [T1546.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1546.003/T1546.003.md) | Persistence via WMI Event Subscription - CommandLineEventConsumer | windows |
| Privilege Escalation | [T1546.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1546.003/T1546.003.md) | Persistence via WMI Event Subscription - ActiveScriptEventConsumer | windows |
| Stealth | [T1027.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027.001/T1027.001.md) | Pad Binary to Change Hash - Linux/macOS dd | linux, macos |
| Stealth | [T1027.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027.001/T1027.001.md) | Pad Binary to Change Hash using truncate command - Linux/macOS | linux, macos |
| Stealth | [T1027.013](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027.013/T1027.013.md) | Decode Eicar File and Write to File | linux, macos, windows |
| Stealth | [T1027.013](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027.013/T1027.013.md) | Decrypt Eicar File and Write to File | linux, macos, windows |
| Stealth | [T1055.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1055.001/T1055.001.md) | Process Injection via mavinject.exe | windows |
| Stealth | [T1055.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1055.001/T1055.001.md) | WinPwn - Get SYSTEM shell - Bind System Shell using UsoClient DLL load technique | windows |
| Stealth | [T1140](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1140/T1140.md) | Deobfuscate/Decode Files Or Information | windows |
| Stealth | [T1140](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1140/T1140.md) | Certutil Rename and Decode | windows |
| Stealth | [T1197](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1197/T1197.md) | Bitsadmin Download (cmd) | windows |
| Stealth | [T1197](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1197/T1197.md) | Bitsadmin Download (PowerShell) | windows |
| Stealth | [T1218.010](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.010/T1218.010.md) | Regsvr32 local COM scriptlet execution | windows |
| Stealth | [T1218.010](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.010/T1218.010.md) | Regsvr32 remote COM scriptlet execution | windows |
| Credential Access | [T1003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003/T1003.md) | Gsecdump | windows |
| Credential Access | [T1003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003/T1003.md) | Credential Dumping with NPPSpy | windows |
| Credential Access | [T1003.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/T1003.001.md) | Dump LSASS.exe Memory using ProcDump | windows |
| Credential Access | [T1003.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/T1003.001.md) | Dump LSASS.exe Memory using comsvcs.dll | windows |
| Lateral Movement | [T1021.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.001/T1021.001.md) | RDP to Remote Host | windows |
| Lateral Movement | [T1021.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.001/T1021.001.md) | Changing RDP Port to Non Standard Port via Powershell | windows |
| Lateral Movement | [T1021.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.004/T1021.004.md) | ESXi - Enable SSH via PowerCLI | windows |
| Lateral Movement | [T1021.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.004/T1021.004.md) | ESXi - Enable SSH via VIM-CMD | windows |
| Collection | [T1074.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1074.001/T1074.001.md) | Stage data from Discovery.bat | windows |
| Collection | [T1074.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1074.001/T1074.001.md) | Stage data from Discovery.sh | linux, macos |
| Collection | [T1560](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1560/T1560.md) | Compress Data for Exfiltration With PowerShell | windows |
| Command and Control | [T1090.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1090.003/T1090.003.md) | Psiphon | windows |
| Command and Control | [T1090.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1090.003/T1090.003.md) | Tor Proxy Usage - Windows | windows |
| Command and Control | [T1105](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1105/T1105.md) | rsync remote file copy (push) | linux, macos |
| Command and Control | [T1105](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1105/T1105.md) | rsync remote file copy (pull) | linux, macos |
| Command and Control | [T1572](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1572/T1572.md) | DNS over HTTPS Large Query Volume | windows |
| Command and Control | [T1572](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1572/T1572.md) | DNS over HTTPS Regular Beaconing | windows |
| Exfiltration | [T1041](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1041/T1041.md) | C2 Data Exfiltration | windows |
| Exfiltration | [T1041](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1041/T1041.md) | Text Based Data Exfiltration using DNS subdomains | windows |
| Exfiltration | [T1567.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1567.002/T1567.002.md) | Exfiltrate data with rclone to cloud Storage - Mega (Windows) | windows |
| Exfiltration | [T1567.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1567.002/T1567.002.md) | Exfiltrate data with rclone to cloud Storage - AWS S3 | linux, macos |

**Logs reais de ataque (EVTX) para testar sem executar nada:**

- T1003 — [ID1-12-13-Wdigest authentication activation](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0006-Credential%20Access/T1003-Credential%20dumping/ID1-12-13-Wdigest%20authentication%20activation.evtx) _(explícito)_
- T1003 — [ID1-LSASS dump with LSASSY (SYSMON)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0006-Credential%20Access/T1003-Credential%20dumping/ID1-LSASS%20dump%20with%20LSASSY%20%28SYSMON%29.evtx) _(explícito)_
- T1003.001 — [CA_hashdump_4663_4656_lsass_access](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Credential%20Access/CA_hashdump_4663_4656_lsass_access.evtx) _(inferido)_
- T1003.001 — [LsassSilentProcessExit_process_exit_monitor_3001_lsass](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Credential%20Access/LsassSilentProcessExit_process_exit_monitor_3001_lsass.evtx) _(inferido)_
- T1021.001 — [ID4688,4778,4779 RDP hijack direct](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0008-Lateral%20Movement/T1021.001-Remote%20Desktop%20Protocol/ID4688%2C4778%2C4779%20RDP%20hijack%20direct.evtx) _(explícito)_
- T1021.001 — [ID4688-4778 RDP hijack command execution](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0008-Lateral%20Movement/T1021.001-Remote%20Desktop%20Protocol/ID4688-4778%20RDP%20hijack%20command%20execution.evtx) _(explícito)_
- T1021.004 — [ID4-OpenSSH server listening](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0008-Lateral%20Movement/T1021.004-Remote%20Service%20SSH/ID4-OpenSSH%20server%20listening.evtx) _(explícito)_
- T1021.004 — [ID4103-4104-OpenSSH server activation and config](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0008-Lateral%20Movement/T1021.004-Remote%20Service%20SSH/ID4103-4104-OpenSSH%20server%20activation%20and%20config.evtx) _(explícito)_
- T1047 — [ID1-WMI spwaning PowerShell process - WMImplant](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1047-Windows%20Management%20Instrumentation/ID1-WMI%20spwaning%20PowerShell%20process%20-%20WMImplant.evtx) _(explícito)_
- T1047 — [ID1-WMIexec process execution](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1047-Windows%20Management%20Instrumentation/ID1-WMIexec%20process%20execution.evtx) _(explícito)_
- T1059.001 — [ID4103-4104-Payload download via PowerShell](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1059.001-PowerShell/ID4103-4104-Payload%20download%20via%20PowerShell.evtx) _(explícito)_
- T1059.001 — [ID4688-Encoded PowerShell MSF payload via process execution](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1059.001-PowerShell/ID4688-Encoded%20PowerShell%20MSF%20payload%20via%20process%20execution.evtx) _(explícito)_
- T1078 — [ID1149-RDP success logins to multiple hosts](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0001-Initial%20access/T1078-Valid%20accounts/ID1149-RDP%20success%20logins%20to%20multiple%20hosts.evtx) _(explícito)_
- T1078 — [ID33205-SQL Server failed login with disabled SA account](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0001-Initial%20access/T1078-Valid%20accounts/ID33205-SQL%20Server%20failed%20login%20with%20disabled%20SA%20account.evtx) _(explícito)_
- T1140 — [ID4688-Certutil download](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0005-Defense%20Evasion/T1140-Deobfuscate-Decode%20Files%20or%20Information/ID4688-Certutil%20download.evtx) _(explícito)_
- T1197 — [ID3-59-60-BITS job created](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0003-Persistence/T1197-BITS%20jobs/ID3-59-60-BITS%20job%20created.evtx) _(explícito)_
- T1197 — [ID4688-BITS transfer initiated](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0003-Persistence/T1197-BITS%20jobs/ID4688-BITS%20transfer%20initiated.evtx) _(explícito)_
- T1218.010 — [exec_sysmon_1_lolbin_renamed_regsvr32_scrobj](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Execution/exec_sysmon_1_lolbin_renamed_regsvr32_scrobj.evtx) _(inferido)_
- T1218.010 — [exec_sysmon_lobin_regsvr32_sct](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Execution/exec_sysmon_lobin_regsvr32_sct.evtx) _(inferido)_
- T1547.001 — [sideloading_injection_persistence_run_key](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/AutomatedTestingTools/Malware/sideloading_injection_persistence_run_key.evtx) _(inferido)_
- T1547.001 — [evasion_persis_hidden_run_keyvalue_sysmon_13](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Persistence/evasion_persis_hidden_run_keyvalue_sysmon_13.evtx) _(inferido)_
- T1572 — [ID4688-netsh RDP port forwarding abuse](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0011-Command%20and%20Control/T1572-Protocol%20tunneling/ID4688-netsh%20RDP%20port%20forwarding%20abuse.evtx) _(explícito)_

## 10. Hipóteses de hunting

Se Leviathan estiver no seu ambiente, estas são as perguntas a fazer aos seus dados (fontes de log segundo as estratégias de detecção do MITRE ATT&CK).

1. **T1102.003 One-Way Communication** — Suspicious process initiating outbound connections to web services without corresponding response or return traffic, indicative of one-way command channels. Dados: `WinEventLog:Sysmon` (EventCode=3, 22), `etw:Microsoft-Windows-WinINet` (WinINet API telemetry).
2. **T1586.001 Social Media Accounts** — Consider monitoring social media activity related to your organization. Suspicious activity may include personas claiming to work for your organization or recently modified accounts making numerous connection requests to accounts affiliated with your… Dados: `Persona` (None), `Network Traffic` (None).
3. **T1547.009 Shortcut Modification** — Detection correlates file creation or modification of `.lnk` (shortcut) files in autostart locations with anomalous parent-child process lineage or unsigned binaries. Defenders should watch for LNK creation/modification events outside of known software… Dados: `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Sysmon` (EventCode=2), `WinEventLog:Sysmon` (EventCode=1).
4. **T1197 BITS Jobs** — Behavioral chain: (1) An actor creates or modifies a BITS job via bitsadmin.exe, PowerShell BITS cmdlets, or COM; (2) the job performs HTTP(S)/SMB network transfers while the owning user is logged on; (3) upon job completion/error, BITS launches a notify… Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=3, 22), `WinEventLog:PowerShell` (EventCode=4103, 4104, 4105, 4106).
5. **T1584.008 Network Devices** — Once adversaries leverage compromised network devices as infrastructure (ex: for command and control), it may be possible to look for unique characteristics associated with adversary software, if known. Much of this activity will take place outside the… Dados: `Internet Scan` (None).
6. **T1534 Internal Spearphishing** — Sequence of internal email sent from a recently compromised user account (preceded by abnormal logon or device activity), with attachments or links leading to execution or credential harvesting. Defender observes: internal mail delivery to peers with high… Dados: `WinEventLog:Security` (EventCode=4624, 4648), `WinEventLog:Security` (EventCode=4625), `WinEventLog:Security` (EventCode=4672).
7. **T1027.001 Binary Padding** — Detects the creation or execution of padded binary files (e.g., large size but minimal legitimate content) followed by process execution or lateral movement from the host. Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:Security` (EventCode=4663, 4670, 4656), `WinEventLog:Sysmon` (EventCode=11).
8. **T1027.003 Steganography** — Detects execution of image viewers or PowerShell scripts accessing or decoding files with mismatched MIME headers or embedded script-like byte patterns; often correlated with suspicious parent-child process lineage and outbound connections. Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=3, 22), `WinEventLog:Security` (EventCode=4663, 4670, 4656).
9. **T1055.001 Dynamic-link Library Injection** — Detects DLL injection through correlation of memory allocation and writing to remote process memory (e.g., VirtualAllocEx, WriteProcessMemory), followed by remote thread creation (e.g., CreateRemoteThread) that loads a suspicious or unsigned DLL using… Dados: `WinEventLog:Sysmon` (EventCode=10), `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=7).
10. **T1546.003 Windows Management Instrumentation Event Subscription** — Monitor for creation of WMI EventFilter, EventConsumer, and FilterToConsumerBinding objects through WMI or MOF file execution. Detect command-line execution of `mofcomp.exe`, usage of `Register-WmiEvent` via PowerShell, and anomalous child processes of… Dados: `WinEventLog:WMI` (EventCode=5857, 5858, 5860, 5861), `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=7).
11. **T1584.004 Server** — Once adversaries have provisioned software on a compromised server (ex: for use as a command and control server), internet scans may reveal servers that adversaries have compromised. Consider looking for identifiable patterns such as services listening,… Dados: `Internet Scan` (None), `Internet Scan` (None).
12. **T1074.002 Remote Data Staging** — Detects file transfers or mounting operations from remote hosts followed by write actions into a local staging directory, often using SMB or remote shell activity. Dados: `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Microsoft-Windows-SMBClient/Security` (EventCode=31001), `WinEventLog:PowerShell` (CommandLine=copy-item or robocopy from UNC path).

## 11. OSINT — onde pesquisar

Consultas prontas com todos os nomes conhecidos do grupo:

- Relatórios técnicos: [busca web](https://duckduckgo.com/?q=%28%22Leviathan%22+OR+%22MUDCARP%22+OR+%22Kryptonite+Panda%22+OR+%22Gadolinium%22+OR+%22BRONZE+MOHAWK%22+OR+%22TEMP.Jumper%22%29+threat+report) · [PDFs](https://duckduckgo.com/?q=%28%22Leviathan%22+OR+%22MUDCARP%22+OR+%22Kryptonite+Panda%22+OR+%22Gadolinium%22+OR+%22BRONZE+MOHAWK%22+OR+%22TEMP.Jumper%22%29+filetype%3Apdf)
- Regras e IOCs publicados: [GitHub](https://github.com/search?type=code&q=%22Leviathan%22+OR+%22MUDCARP%22+OR+%22Kryptonite+Panda%22+OR+%22Gadolinium%22+OR+%22BRONZE+MOHAWK%22+OR+%22TEMP.Jumper%22)
- Pulsos de ameaça: [AlienVault OTX](https://otx.alienvault.com/browse/global/pulses?q=Leviathan)
- Família de malware e atores: [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/actors) (busque por Leviathan, MUDCARP, Kryptonite Panda)
- Cartões de grupo: [ThaiCERT Threat Group Cards](https://apt.etda.or.th/cgi-bin/listgroups.cgi)
- Página oficial: [MITRE ATT&CK G0065](https://attack.mitre.org/groups/G0065/)

**Relatórios na coleção CyberMonitor** (ligados pelo nome do grupo, conferir antes de citar):

- 2017 — [Leviathan_Espionage_actor](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2017/2017.10.16.Leviathan/Leviathan_Espionage_actor.pdf) _(via “Leviathan”)_
- 2018 — [cta-2018-1113](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2018/2018.11.13.China.TEMP.Periscope.Using.Russian_APT/cta-2018-1113.pdf) _(via “TEMP.Periscope”)_
- 2019 — [APT40 Examining a China-Nexus Espionage Actor  APT40 Examining a China-Nexus Espionage Actor](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2019/2019.03.04.APT40/APT40%20Examining%20a%20China-Nexus%20Espionage%20Actor%20%20APT40%20Examining%20a%20China-Nexus%20Espionage%20Actor.pdf) _(via “APT40”)_
- 2020 — [Leviathan APT campaign in 2020 Malaysian political crisis _ Elastic Blog](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2020/2020.06.25.Malaysian-focused-APT_campaign/Leviathan%20APT%20campaign%20in%202020%20Malaysian%20political%20crisis%20_%20Elastic%20Blog.pdf) _(via “Leviathan”)_
- 2021 — [CSA_TTPs-of-Indicted-APT40-Actors-Associated-with-China-MSS-Hainan-State-Security-Department](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2021/2021.07.19.APT40_TTP/CSA_TTPs-of-Indicted-APT40-Actors-Associated-with-China-MSS-Hainan-State-Security-Department.pdf) _(via “APT40”)_

**Relatórios públicos ligados pelo APT4ALL** (3 no total, mais recentes primeiro):

- 2015 — [Scanbox Ii](https://app.box.com/s/o83u5pekus9251w0cl5lo2m1k5u0u2vn) _(PWC)_
- 2014 — [Scanbox Framework: Who's Affected, And Who's Using It?](https://app.box.com/s/u273q9utje6wds8mtv17efskdu5oj8la) _(PWC)_
- 2014 — [Scanbox: A Reconnaissance Framework Used With Watering Hole Attacks](https://app.box.com/s/vlbe0y40djeaadl2l4iqdm13cju3v3n6) _(Alienvault)_

## 12. Bibliografia (10 fontes citadas pelo ATT&CK)

- [Accenture MUDCARP March 2019](https://www.accenture.com/us-en/blogs/cyber-defense/mudcarps-focus-on-submarine-technologies) — Accenture iDefense Unit. (2019, March 5). Mudcarp's Focus on Submarine Technologies. Retrieved August 24, 2021.
- [CISA AA21-200A APT40 July 2021](https://us-cert.cisa.gov/ncas/alerts/aa21-200a) — CISA. (2021, July 19). (AA21-200A) Joint Cybersecurity Advisory – Tactics, Techniques, and Procedures of Indicted APT40 Actors Associated with China’s MSS Hainan State Security Department. Retrieved August 12, 2021.
- [CISA Leviathan 2024](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-190a) — CISA et al. (2024, July 8). People’s Republic of China (PRC) Ministry of State Security APT40 Tradecraft in Action. Retrieved February 3, 2025.
- [Crowdstrike KRYPTONITE PANDA August 2018](https://www.crowdstrike.com/blog/two-birds-one-stone-panda/) — Adam Kozy. (2018, August 30). Two Birds, One Stone Panda. Retrieved August 24, 2021.
- [FireEye APT40 March 2019](https://www.fireeye.com/blog/threat-research/2019/03/apt40-examining-a-china-nexus-espionage-actor.html) — Plan, F., et al. (2019, March 4). APT40: Examining a China-Nexus Espionage Actor. Retrieved March 18, 2019.
- [FireEye Periscope March 2018](https://www.fireeye.com/blog/threat-research/2018/03/suspected-chinese-espionage-group-targeting-maritime-and-engineering-industries.html) — FireEye. (2018, March 16). Suspected Chinese Cyber Espionage Group (TEMP.Periscope) Targeting U.S. Engineering and Maritime Industries. Retrieved April 11, 2018.
- [Microsoft Threat Actor Naming July 2023](https://learn.microsoft.com/en-us/microsoft-365/security/intelligence/microsoft-threat-actor-naming?view=o365-worldwide) — Microsoft . (2023, July 12). How Microsoft names threat actors. Retrieved November 17, 2023.
- [MSTIC GADOLINIUM September 2020](https://www.microsoft.com/security/blog/2020/09/24/gadolinium-detecting-empires-cloud/) — Ben Koehl, Joe Hannon. (2020, September 24). Microsoft Security - Detecting Empires in the Cloud. Retrieved August 24, 2021.
- [Proofpoint Leviathan Oct 2017](https://www.proofpoint.com/us/threat-insight/post/leviathan-espionage-actor-spearphishes-maritime-and-defense-targets) — Axel F, Pierre T. (2017, October 16). Leviathan: Espionage actor spearphishes maritime and defense targets. Retrieved February 15, 2018.
- [SecureWorks BRONZE MOHAWK n.d.](https://www.secureworks.com/research/threat-profiles/bronze-mohawk) — SecureWorks. (n.d.). Threat Profile - BRONZE MOHAWK. Retrieved August 24, 2021.

## 13. Limites e confiança

- O ATT&CK registra o que foi **relatado publicamente**, não tudo o que o grupo faz. Ausência de uma técnica não prova que o grupo não a usa.
- **Sobreposição de TTP não é atribuição.** Muitas técnicas são compartilhadas entre grupos e com red teams. Use a assinatura comportamental como hipótese, junto com infraestrutura, malware e contexto.
- Cobertura de detecção refere-se ao catálogo público Detection Rules, não ao seu ambiente: confira se a telemetria necessária chega ao seu SIEM.
- Ligações marcadas como _inferidas_ (EVTX por palavra-chave, relatórios por nome) devem ser verificadas.

---
Fontes: MITRE ATT&CK® (uso livre com atribuição, © The MITRE Corporation), APT4ALL (MISP Galaxy CC0/BSD-2, APT Groups & Operations CC BY 4.0, EternalLiberty, APTnotes, Ransomware Tool Matrix CC BY 4.0), Atomic Red Team (Red Canary, MIT), EVTX-to-MITRE-Attack, EVTX-ATTACK-SAMPLES, APT & CyberCriminal Campaign Collections. Gerado por [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules).
