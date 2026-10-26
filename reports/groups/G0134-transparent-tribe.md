# Transparent Tribe (G0134) — Dossiê de inteligência

> **TLP:CLEAR** · gerado em 2026-10-26 a partir de fontes abertas · MITRE ATT&CK v20.0 · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0134) · [ATT&CK](https://attack.mitre.org/groups/G0134/)

**Também conhecido como:** COPPER FIELDSTONE, APT36, Mythic Leopard, ProjectM  
**Origem atribuída:** Vietnã · **Motivação:** hacktivismo · **Setores-alvo:** Sociedade civil e mídia, Governo, Defesa e militar  
**Registro no ATT&CK:** criado em 2021-09-02, atualizado em 2026-07-31 · referências de 2016 a 2022

## 1. Sumário executivo

- **14 técnicas** atribuídas publicamente, concentradas em **Execution, Stealth, Initial Access**.
- **Arsenal:** 5 malware e 0 ferramentas (ex.: njRAT, Crimson, DarkComet, ObliqueRAT, Peppy).
- **Campanhas atribuídas:** 1 (C0011).
- **Cobertura de detecção pública:** 93% das técnicas têm ao menos uma regra no catálogo; **1 técnicas sem nenhuma regra pública**.
- **Origem e alvos (APT4ALL):** atribuído a **Vietnã**, motivação hacktivismo; setores Sociedade civil e mídia, Governo, Defesa e militar.
- **Onde a cobertura está:** Windows (12 técnicas com regra), EDR / XDR (11 técnicas com regra), Linux (10 técnicas com regra), macOS (10 técnicas com regra).
- **Assinatura comportamental** (técnicas raras entre os 178 grupos, as mais úteis para atribuição): T1584.001 Domains, T1568 Dynamic Resolution, T1608.004 Drive-by Target, T1564.001 Hidden Files and Directories, T1189 Drive-by Compromise.

## 2. Quem é

> Transparent Tribe is a suspected Pakistan-based threat group that has been active since at least 2013, primarily targeting diplomatic, defense, and research organizations in India and Afghanistan.

_Texto original do MITRE ATT&CK, em inglês._

## 3. Contexto, nomes e alvos

Consolidado pelo [APT4ALL](https://github.com/Ridd1kulusC0d3r/apt4all) a partir de MISP Galaxy, planilha APT Groups & Operations, EternalLiberty e APTnotes. Atribuição é afirmação de quem publicou; confira a fonte.

| Campo | Valor |
|---|---|
| Origem atribuída | Vietnã |
| Motivação | hacktivismo |
| Setores-alvo | Sociedade civil e mídia, Governo, Defesa e militar |
| Vítimas citadas | — |
| Alvos (planilha) | Government of India diplomatic and military |
| Operações conhecidas | Operation C-Major |
| Confiança de atribuição (MISP) | 50 |

**Como cada fornecedor chama este grupo** (útil para cruzar relatórios):

| Fornecedor | Nome(s) |
|---|---|
| MITRE ATT&CK | G0134 |

**Outros nomes no APT4ALL (não listados pelo ATT&CK):** Temp.Lapis, Green Havildar, APT-C-56, Operation C-Major, C-Major, TMP.Lapis, Earth Karkaddan, Storm-0156, ATK64, ProjectM/Pasty Draco/Opaque Draco

## 4. Perfil TTP por tática (kill chain)

Cada linha: técnica, como o grupo a usou segundo relatos públicos, e o que existe para detectar e testar.

### Resource Development (TA0042) — 3

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1583.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1583.001) Domains | Transparent Tribe has registered domains to mimic file sharing, government, defense, and research websites for use in targeted campaigns. | 7 | — | — |
| [T1584.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1584.001) Domains | Transparent Tribe has compromised domains for use in targeted malicious campaigns. | 3 | — | — |
| [T1608.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1608.004) Drive-by Target | Transparent Tribe has set up websites with malicious hyperlinks and iframes to infect targeted victims with Crimson, njRAT, and other malicious tools. | **0** | — | — |

### Initial Access (TA0001) — 3

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1189](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1189) Drive-by Compromise | Transparent Tribe has used websites with malicious hyperlinks and iframes to infect targeted victims with Crimson, njRAT, and other malicious tools. | 57 | — | — |
| [T1566.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1566.001) Spearphishing Attachment | Transparent Tribe has sent spearphishing e-mails with attachments to deliver malicious payloads. | 230 | 2 | — |
| [T1566.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1566.002) Spearphishing Link | Transparent Tribe has embedded links to malicious downloads in e-mails. | 138 | 1 | — |

### Execution (TA0002) — 4

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1059.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.005) Visual Basic | Transparent Tribe has crafted VBS-based malicious documents. | 192 | 3 | — |
| [T1203](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1203) Exploitation for Client Execution | Transparent Tribe has crafted malicious files to exploit CVE-2012-0158 and CVE-2010-3333 for execution. | 202 | — | — |
| [T1204.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1204.001) Malicious Link | Transparent Tribe has directed users to open URLs hosting malicious content. | 52 | — | — |
| [T1204.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1204.002) Malicious File | Transparent Tribe has used weaponized documents in e-mail to compromise targeted systems. | 259 | 13 | — |

### Stealth (TA0005) — 3

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1027.013](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1027.013) Encrypted/Encoded File | Transparent Tribe has dropped encoded executables on compromised hosts. | 8 | 4 | — |
| [T1036.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1036.005) Match Legitimate Resource Name or Location | Transparent Tribe can mimic legitimate Windows directories by using the same icons and names. | 116 | 4 | — |
| [T1564.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1564.001) Hidden Files and Directories | Transparent Tribe can hide legitimate directories and replace them with malicious copies of the same name. | 76 | 10 | — |

### Command and Control (TA0011) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1568](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1568) Dynamic Resolution | Transparent Tribe has used dynamic DNS services to set up C2. | 32 | — | — |

## 5. Assinatura comportamental

Técnicas que este grupo usa e que poucos dos 178 grupos do ATT&CK usam. Pesam mais numa atribuição por TTP: ver várias delas juntas é mais informativo do que ver técnicas comuns como PowerShell.

| Técnica | Outros grupos que usam | Peso (raridade) |
|---|---:|---:|
| T1584.001 Domains | 5 | 3.24 |
| T1568 Dynamic Resolution | 7 | 2.99 |
| T1608.004 Drive-by Target | 7 | 2.99 |
| T1564.001 Hidden Files and Directories | 12 | 2.55 |
| T1189 Drive-by Compromise | 30 | 1.72 |
| T1027.013 Encrypted/Encoded File | 39 | 1.47 |
| T1203 Exploitation for Client Execution | 41 | 1.43 |
| T1059.005 Visual Basic | 45 | 1.34 |
| T1566.002 Spearphishing Link | 47 | 1.30 |
| T1583.001 Domains | 47 | 1.30 |

## 6. Arsenal

| Software | Tipo | Técnicas no ATT&CK | Uso relatado (EN) |
|---|---|---:|---|
| [njRAT](https://attack.mitre.org/software/S0385/) | malware | 31 |  |
| [Crimson](https://attack.mitre.org/software/S0115/) | malware | 30 |  |
| [DarkComet](https://attack.mitre.org/software/S0334/) | malware | 18 |  |
| [ObliqueRAT](https://attack.mitre.org/software/S0644/) | malware | 14 |  |
| [Peppy](https://attack.mitre.org/software/S0643/) | malware | 7 |  |

**Outras ferramentas e malware relatados (planilha APT Groups & Operations / MISP):** Crimson RAT, Limepad

## 7. Campanhas

| Campanha | Período | Resumo (EN) |
|---|---|---|
| [C0011](https://attack.mitre.org/campaigns/C0011/) | 2021-12 → 2022-07 | C0011 was a suspected cyber espionage campaign conducted by Transparent Tribe that targeted students at universities and colleges in India. Security researchers noted this campaign against students was a significant shif |

## 8. Cobertura defensiva

**13 de 14 técnicas (93%)** têm ao menos uma regra pública no catálogo Detection Rules.

### Técnicas sem regra pública (prioridade para engenharia de detecção)

- **T1608.004 Drive-by Target** — Resource Development. Fonte de log sugerida pelo MITRE: `Internet Scan` None

### Onde procurar — cobertura por tecnologia

Quantas técnicas deste grupo têm ao menos uma regra em cada tecnologia. Comece a caça pelas tecnologias que você tem e que aparecem aqui.

| Tecnologia | Técnicas do grupo com regra |
|---|---:|
| Windows | 12 |
| EDR / XDR | 11 |
| Linux | 10 |
| macOS | 10 |
| Outros / genérico | 10 |
| Microsoft 365 | 9 |
| E-mail | 9 |
| Proxy / SWG | 8 |
| Servidores web & aplicações | 8 |
| IA, LLMs & agentes | 8 |
| AWS | 8 |
| IDS / NSM / NDR | 8 |

### Regras recomendadas por técnica

Melhor regra disponível por técnica (formato portável e maduro primeiro).

| Técnica | Regra | Formato | Fonte |
|---|---|---|---|
| T1027.013 | [ROT Encoded Python Script Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A5ab49127-b1b3-46e6-8a38-9e8512a2a363) | Elastic | Elastic detection-rules |
| T1027.013 | [Data Encrypted via OpenSSL Utility](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Afeba48f6-40ca-4d04-b41f-5dfa327de865) | Elastic | Elastic detection-rules |
| T1036.005 | [Exploit for CVE-2015-1641](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A7993792c-5ce2-4475-a3db-a3a5539827ef) | Sigma | SigmaHQ |
| T1036.005 | [Exploit for CVE-2015-1641](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A7993792c-5ce2-4475-a3db-a3a5539827ef) | Sigma | OpenSearch Security Analytics |
| T1059.005 | [Potential QBot Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4fcac6eb-0287-4090-8eea-2602e4c20040) | Sigma | SigmaHQ |
| T1059.005 | [QBot Process Creation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A4fcac6eb-0287-4090-8eea-2602e4c20040) | Sigma | OpenSearch Security Analytics |
| T1189 | [Flash Player Update from Suspicious Location](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4922a5dd-6743-4fc2-8e81-144374280997) | Sigma | SigmaHQ |
| T1189 | [Cross Site Scripting Strings](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A65354b83-a2ea-4ea6-8414-3ab38be0d409) | Sigma | SigmaHQ |
| T1203 | [Droppers Exploiting CVE-2017-11882](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A678eb5f4-8597-4be6-8be7-905e4234b53a) | Sigma | SigmaHQ |
| T1203 | [OMIGOD HTTP No Authentication RCE - CVE-2021-38647](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aab6b1a39-a9ee-4ab4-b075-e83acf6e346b) | Sigma | SigmaHQ |
| T1204.001 | [Google Workspace Object Copied from External Drive with App Consent](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Af33e68a4-bd19-11ed-b02f-f661ea17fbcc) | Elastic | Elastic detection-rules |
| T1204.001 | [Suspicious ClickFix/FileFix Execution Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad487ed4a-fd24-436d-a0b2-f4e95f7b2635) | Sigma | SigmaHQ |
| T1204.002 | [Ursnif Malware C2 URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A932ac737-33ca-4afd-9869-0d48b391fcc9) | Sigma | SigmaHQ |
| T1204.002 | [Droppers Exploiting CVE-2017-11882](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A678eb5f4-8597-4be6-8be7-905e4234b53a) | Sigma | SigmaHQ |
| T1564.001 | [Set Suspicious Files as System Files Using Attrib.EXE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aefec536f-72e8-4656-8960-5e85d091345b) | Sigma | SigmaHQ |
| T1564.001 | [PowerShell Logging Disabled Via Registry Key Tampering](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Afecfd1a1-cc78-4313-a1ea-2ee2e8ec27a7) | Sigma | SigmaHQ |
| T1566.001 | [Ursnif Malware C2 URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A932ac737-33ca-4afd-9869-0d48b391fcc9) | Sigma | SigmaHQ |
| T1566.001 | [Droppers Exploiting CVE-2017-11882](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A678eb5f4-8597-4be6-8be7-905e4234b53a) | Sigma | SigmaHQ |
| T1566.002 | [Potential Malicious Usage of CloudTrail System Manager](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A38e7f511-3f74-41d4-836e-f57dfa18eead) | Sigma | SigmaHQ |
| T1566.002 | [Google Workspace Device Registration After OAuth from Suspicious ASN](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A012bfca7-45cb-4507-a3ba-3777167f8b81) | Elastic | Elastic detection-rules |
| T1568 | [Possible FIN7 DGA Command and Control Behavior](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A4a4e23cf-78a2-449c-bac3-701924c269d3) | Elastic | Elastic detection-rules |
| T1568 | [Cobalt Strike Command and Control Beacon](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Acf53f532-9cc9-445a-9ae7-fced307ec53c) | Elastic | Elastic detection-rules |
| T1583.001 | [AWS Route 53 Private Hosted Zone Associated With a VPC](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ae3c27562-709a-42bd-82f2-3ed926cced19) | Elastic | Elastic detection-rules |
| T1583.001 | [AWS SES Email Identity Verified Then Deleted](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A8e4bde35-125d-4eb3-9a2e-d7e77a053a08) | Elastic | Elastic detection-rules |
| T1584.001 | [AWS Route 53 Domain Transferred to Another Account](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A2045567e-b0af-444a-8c0b-0b6e2dae9e13) | Elastic | Elastic detection-rules |
| T1584.001 | [AWS Route 53 Domain Transfer Lock Disabled](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A12051077-0124-4394-9522-8f4f4db1d674) | Elastic | Elastic detection-rules |

## 9. Plano de emulação e validação

Use num laboratório isolado e autorizado para confirmar que as regras disparam. Os comandos estão nos repositórios oficiais.

| Tática | Técnica | Teste Atomic Red Team | Plataformas |
|---|---|---|---|
| Initial Access | [T1566.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1566.001/T1566.001.md) | Download Macro-Enabled Phishing Attachment | windows |
| Initial Access | [T1566.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1566.001/T1566.001.md) | Word spawned a command shell and used an IP address in the command line | windows |
| Initial Access | [T1566.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1566.002/T1566.002.md) | Paste and run technique | windows |
| Execution | [T1059.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.005/T1059.005.md) | Visual Basic script execution to gather local computer information | windows |
| Execution | [T1059.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.005/T1059.005.md) | Encoded VBS code execution | windows |
| Execution | [T1204.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1204.002/T1204.002.md) | OSTap Style Macro Execution | windows |
| Execution | [T1204.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1204.002/T1204.002.md) | OSTap Payload Download | windows |
| Stealth | [T1027.013](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027.013/T1027.013.md) | Decode Eicar File and Write to File | linux, macos, windows |
| Stealth | [T1027.013](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027.013/T1027.013.md) | Decrypt Eicar File and Write to File | linux, macos, windows |
| Stealth | [T1036.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.005/T1036.005.md) | Execute a process from a directory masquerading as the current parent directory | linux, macos |
| Stealth | [T1036.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.005/T1036.005.md) | Masquerade as a built-in system executable | windows |
| Stealth | [T1564.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1564.001/T1564.001.md) | Create a hidden file in a hidden directory | linux, macos |
| Stealth | [T1564.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1564.001/T1564.001.md) | Mac Hidden file | macos |

## 10. Hipóteses de hunting

Se Transparent Tribe estiver no seu ambiente, estas são as perguntas a fazer aos seus dados (fontes de log segundo as estratégias de detecção do MITRE ATT&CK).

1. **T1584.001 Domains** — Monitor for logged domain name system (DNS) registry data that may hijack domains and/or subdomains that can be used during targeting. In some cases, abnormal subdomain IP addresses (such as those originating in a different country from the root domain) may… Dados: `Domain Name` (None), `Domain Name` (None), `Domain Name` (None).
2. **T1568 Dynamic Resolution** — Correlate high-frequency or anomalous DNS query activity with processes that do not normally generate network requests (e.g., Office apps, system utilities). Detect pseudo-random or high-entropy domain lookups indicative of domain generation algorithms (DGAs). Dados: `WinEventLog:Sysmon` (EventCode=3, 22), `WinEventLog:Sysmon` (EventCode=1).
3. **T1608.004 Drive-by Target** — If infrastructure or patterns in the malicious web content utilized to deliver a Drive-by Compromise have been previously identified, internet scanning may uncover when an adversary has staged web content for use in a strategic web compromise. Much of this… Dados: `Internet Scan` (None).
4. **T1564.001 Hidden Files and Directories** — Suspicious use of attrib.exe or PowerShell commands to set hidden attributes on files/directories. Defender view: processes modifying file attributes to 'hidden' or creating files with ADS (alternate data streams). Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=11).
5. **T1189 Drive-by Compromise** — Correlated evidence of anomalous browser/network behavior (suspicious external resource fetches and script injection patterns) followed by atypical child processes, ephemeral execution contexts, memory modification or process injection, and unexpected file… Dados: `WinEventLog:Security` (EventCode=4624, 4648), `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=3, 22).
6. **T1027.013 Encrypted/Encoded File** — Detection of processes that load or decode encrypted/encoded files in memory and subsequently execute or inject them, indicating payload unpacking or memory-resident malware. Dados: `WinEventLog:Sysmon` (EventCode=7), `WinEventLog:Sysmon` (EventCode=10), `WinEventLog:Security` (EventCode=4688).
7. **T1203 Exploitation for Client Execution** — Cause→effect chain: (1) A client app (browser, Office, PDF/Flash/reader) experiences a crash/abnormal exit or loads from an unusual location, then (2) drops or modifies a file in user-writable paths, and/or (3) spawns an unexpected child (e.g.,… Dados: `WinEventLog:Application` (EventCode=1000), `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Sysmon` (EventCode=1).
8. **T1059.005 Visual Basic** — Detects execution of VB-based scripts or macros (VBS/VBA/VBScript) through cscript.exe/wscript.exe, Office-based process chains, or HTA usage. Focuses on chained behavior: Office or HTML container spawns script host > script host spawns PowerShell, network… Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=7).
9. **T1566.002 Spearphishing Link** — Correlation of inbound emails with embedded links followed by user-driven browser navigation to suspicious or obfuscated domains. Detection chain includes malicious URL in email → user click recorded in Office logs → browser process spawning unusual child… Dados: `m365:unified` (Send/Receive: Inbound emails containing embedded or shortened URLs), `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=3, 22).
10. **T1583.001 Domains** — Monitor logged domain name system (DNS) data for purchased domains that can be used during targeting. Reputation/category-based detection may be difficult until the categorization is updated. Detection efforts may be focused on related stages of the adversary… Dados: `Domain Name` (None), `Domain Name` (None), `Domain Name` (None).
11. **T1204.001 Malicious Link** — Behavioral chain: (1) a user-facing app (browser/Office/email client) launches a URL or handles a link, then (2) the same process lineage makes an outbound connection to an untrusted domain/IP, (3) a file is downloaded or unpacked to a user-writable location… Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=3, 22), `WinEventLog:Sysmon` (EventCode=11).
12. **T1036.005 Match Legitimate Resource Name or Location** — Detects processes or binaries executed from trusted directories (e.g., System32) or using trusted names (e.g., svchost.exe) where the metadata, hash, or parent process does not align with legitimate activity patterns. Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=11).

## 11. OSINT — onde pesquisar

Consultas prontas com todos os nomes conhecidos do grupo:

- Relatórios técnicos: [busca web](https://duckduckgo.com/?q=%28%22Transparent+Tribe%22+OR+%22COPPER+FIELDSTONE%22+OR+%22APT36%22+OR+%22Mythic+Leopard%22+OR+%22ProjectM%22%29+threat+report) · [PDFs](https://duckduckgo.com/?q=%28%22Transparent+Tribe%22+OR+%22COPPER+FIELDSTONE%22+OR+%22APT36%22+OR+%22Mythic+Leopard%22+OR+%22ProjectM%22%29+filetype%3Apdf)
- Regras e IOCs publicados: [GitHub](https://github.com/search?type=code&q=%22Transparent+Tribe%22+OR+%22COPPER+FIELDSTONE%22+OR+%22APT36%22+OR+%22Mythic+Leopard%22+OR+%22ProjectM%22)
- Pulsos de ameaça: [AlienVault OTX](https://otx.alienvault.com/browse/global/pulses?q=Transparent+Tribe)
- Família de malware e atores: [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/actors) (busque por Transparent Tribe, COPPER FIELDSTONE, APT36)
- Cartões de grupo: [ThaiCERT Threat Group Cards](https://apt.etda.or.th/cgi-bin/listgroups.cgi)
- Página oficial: [MITRE ATT&CK G0134](https://attack.mitre.org/groups/G0134/)

**Relatórios na coleção CyberMonitor** (ligados pelo nome do grupo, conferir antes de citar):

- 2016 — [proofpoint-operation-transparent-tribe-threat-insight-en](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2016/2016.03.01.Operation_Transparent_Tribe/proofpoint-operation-transparent-tribe-threat-insight-en.pdf) _(via “Transparent Tribe”)_
- 2016 — [unit42-projectm-link-found-between-pakistani-actor-and-operation-transparent-tribe](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2016/2016.03.25.ProjectM/unit42-projectm-link-found-between-pakistani-actor-and-operation-transparent-tribe.pdf) _(via “Transparent Tribe”)_
- 2020 — [APT36 jumps on the coronavirus bandwagon, delivers Crimson RAT _ Malwarebytes Labs](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2020/2020.03.15_APT36_Crimson_RAT/APT36%20jumps%20on%20the%20coronavirus%20bandwagon%2C%20delivers%20Crimson%20RAT%20_%20Malwarebytes%20Labs.pdf) _(via “APT36”)_
- 2020 — [Transparent Tribe_ Evolution analysis, part 2 _ Securelist](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2020/2020.08.28_Transparent_Tribe/Transparent%20Tribe_%20Evolution%20analysis%2C%20part%202%20_%20Securelist.pdf) _(via “Transparent Tribe”)_
- 2020 — [cyberstanc.com-A look into APT36s Transparent Tribe tradecraft](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2020/2020.11.01.Transparent_Tribe_APT/cyberstanc.com-A%20look%20into%20APT36s%20Transparent%20Tribe%20tradecraft.pdf) _(via “Transparent Tribe”)_
- 2021 — [blog.talosintelligence.com-Transparent Tribe APT expands its Windows malware arsenal](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2021/2021.05.13.Transparent_Tribe_APT/blog.talosintelligence.com-Transparent%20Tribe%20APT%20expands%20its%20Windows%20malware%20arsenal.pdf) _(via “Transparent Tribe”)_

**Relatórios públicos ligados pelo APT4ALL** (6 no total, mais recentes primeiro):

- 2023 — [Analysis of APT-C-56 (Transparent Tribe) camouflage resume attack campaign](https://app.box.com/s/rnoc7ldxv29za832xasqohm1ammp3g2d) _(CoreSec360)_
- 2022 — [Transparent Tribe campaign uses new bespoke malware to target Indian government officials](https://app.box.com/s/x4c798599srccjv65ciodew9hrv7mss1) _(Cisco)_
- 2020 — [Transparent Tribe: Evolution analysis, part 2](https://app.box.com/s/2cpsj31ackb2zx5mzayhds76mcndofxr) _(Kaspersky)_
- 2020 — [Transparent Tribe: Evolution analysis, part 1](https://app.box.com/s/ujm0zncu4yslx1tvu6aes0qzm5nhvjyg) _(Kaspersky)_
- 2016 — [Operation C-Major Actors Also Used Android BlackBerry Mobile Spyware Against Targets](https://app.box.com/s/xua6557tccyx7h0ksmjnu8u5bra3z15n) _(Trend Micro)_
- 2016 — [Operation Transparent Tribe](https://app.box.com/s/2terwf3c3e8iunw8v7kj83p2zw44nns2) _(Proofpoint)_

## 12. Bibliografia (8 fontes citadas pelo ATT&CK)

- [Cisco Talos Transparent Tribe Education Campaign July 2022](https://blog.talosintelligence.com/2022/07/transparent-tribe-targets-education.html) — N. Baisini. (2022, July 13). Transparent Tribe begins targeting education sector in latest campaign. Retrieved September 22, 2022.
- [Crowdstrike Mythic Leopard Profile](https://adversary.crowdstrike.com/en-US/adversary/mythic-leopard/) — Crowdstrike. (n.d.). Mythic Leopard. Retrieved October 6, 2021.
- [Kaspersky Transparent Tribe August 2020](https://securelist.com/transparent-tribe-part-1/98127/) — Dedola, G. (2020, August 20). Transparent Tribe: Evolution analysis, part 1. Retrieved September 2, 2021.
- [Proofpoint Operation Transparent Tribe March 2016](https://www.proofpoint.com/sites/default/files/proofpoint-operation-transparent-tribe-threat-insight-en.pdf) — Huss, D. (2016, March 1). Operation Transparent Tribe. Retrieved June 8, 2016.
- [Secureworks COPPER FIELDSTONE Profile](https://www.secureworks.com/research/threat-profiles/copper-fieldstone) — Secureworks. (n.d.). COPPER FIELDSTONE. Retrieved October 6, 2021.
- [Talos Oblique RAT March 2021](https://blog.talosintelligence.com/2021/02/obliquerat-new-campaign.html) — Malhotra, A. (2021, March 2). ObliqueRAT returns with new campaign using hijacked websites. Retrieved September 2, 2021.
- [Talos Transparent Tribe May 2021](https://blog.talosintelligence.com/2021/05/transparent-tribe-infra-and-targeting.html) — Malhotra, A. et al. (2021, May 13). Transparent Tribe APT expands its Windows malware arsenal. Retrieved September 2, 2021.
- [Unit 42 ProjectM March 2016](https://unit42.paloaltonetworks.com/unit42-projectm-link-found-between-pakistani-actor-and-operation-transparent-tribe/) — Falcone, R. and Conant S. (2016, March 25). ProjectM: Link Found Between Pakistani Actor and Operation Transparent Tribe. Retrieved September 2, 2021.

## 13. Limites e confiança

- O ATT&CK registra o que foi **relatado publicamente**, não tudo o que o grupo faz. Ausência de uma técnica não prova que o grupo não a usa.
- **Sobreposição de TTP não é atribuição.** Muitas técnicas são compartilhadas entre grupos e com red teams. Use a assinatura comportamental como hipótese, junto com infraestrutura, malware e contexto.
- Cobertura de detecção refere-se ao catálogo público Detection Rules, não ao seu ambiente: confira se a telemetria necessária chega ao seu SIEM.
- Ligações marcadas como _inferidas_ (EVTX por palavra-chave, relatórios por nome) devem ser verificadas.

---
Fontes: MITRE ATT&CK® (uso livre com atribuição, © The MITRE Corporation), APT4ALL (MISP Galaxy CC0/BSD-2, APT Groups & Operations CC BY 4.0, EternalLiberty, APTnotes, Ransomware Tool Matrix CC BY 4.0), Atomic Red Team (Red Canary, MIT), EVTX-to-MITRE-Attack, EVTX-ATTACK-SAMPLES, APT & CyberCriminal Campaign Collections. Gerado por [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules).
