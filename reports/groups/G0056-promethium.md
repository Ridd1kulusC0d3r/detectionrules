# PROMETHIUM (G0056) — Dossiê de inteligência

> **TLP:CLEAR** · gerado em 2026-10-25 a partir de fontes abertas · MITRE ATT&CK v20.0 · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0056) · [ATT&CK](https://attack.mitre.org/groups/G0056/)

**Também conhecido como:** StrongPity  
**Registro no ATT&CK:** criado em 2018-01-16, atualizado em 2026-07-31 · referências de 2016 a 2020

## 1. Sumário executivo

- **11 técnicas** atribuídas publicamente, concentradas em **Stealth, Persistence, Privilege Escalation**.
- **Arsenal:** 2 malware e 0 ferramentas (ex.: StrongPity, Truvasys).
- **Campanhas atribuídas:** 1 (C0033).
- **Cobertura de detecção pública:** 82% das técnicas têm ao menos uma regra no catálogo; **2 técnicas sem nenhuma regra pública**.
- **Assinatura comportamental** (técnicas raras entre os 178 grupos, as mais úteis para atribuição): T1205.001 Port Knocking, T1587.002 Code Signing Certificates, T1587.003 Digital Certificates, T1078.003 Local Accounts, T1036.004 Masquerade Task or Service.

## 2. Quem é

> PROMETHIUM is an activity group focused on espionage that has been active since at least 2012. The group has conducted operations globally with a heavy emphasis on Turkish targets. PROMETHIUM has demonstrated similarity to another activity group called NEODYMIUM due to overlapping victim and campaign characteristics.

_Texto original do MITRE ATT&CK, em inglês._

## 3. Perfil TTP por tática (kill chain)

Cada linha: técnica, como o grupo a usou segundo relatos públicos, e o que existe para detectar e testar.

### Resource Development (TA0042) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1587.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1587.002) Code Signing Certificates | PROMETHIUM has created self-signed certificates to sign malicious installers. | **0** | — | — |
| [T1587.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1587.003) Digital Certificates | PROMETHIUM has created self-signed digital certificates for use in HTTPS C2 traffic. | **0** | — | — |

### Initial Access (TA0001) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1078.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.003) Local Accounts | PROMETHIUM has created admin accounts on a compromised host. | 32 | 13 | — |
| [T1189](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1189) Drive-by Compromise | PROMETHIUM has used watering hole attacks to deliver malicious versions of legitimate installers. | 57 | — | — |

### Execution (TA0002) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1204.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1204.002) Malicious File | PROMETHIUM has attempted to get users to execute compromised installation files for legitimate software including compression applications, security software, browsers, file recovery applications, and other tools and utilities. | 259 | 13 | — |

### Persistence (TA0003) — 4

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1078.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.003) Local Accounts | PROMETHIUM has created admin accounts on a compromised host. | 32 | 13 | — |
| [T1205.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1205.001) Port Knocking | PROMETHIUM has used a script that configures the knockd service and firewall to only accept C2 connections from systems that use a specified sequence of knock ports. | 3 | — | — |
| [T1543.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1543.003) Windows Service | PROMETHIUM has created new services and modified existing services for persistence. | 1916 | 6 | 19 |
| [T1547.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1547.001) Registry Run Keys / Startup Folder | PROMETHIUM has used Registry run keys to establish persistence. | 299 | 21 | 2 |

### Privilege Escalation (TA0004) — 3

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1078.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.003) Local Accounts | PROMETHIUM has created admin accounts on a compromised host. | 32 | 13 | — |
| [T1543.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1543.003) Windows Service | PROMETHIUM has created new services and modified existing services for persistence. | 1916 | 6 | 19 |
| [T1547.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1547.001) Registry Run Keys / Startup Folder | PROMETHIUM has used Registry run keys to establish persistence. | 299 | 21 | 2 |

### Stealth (TA0005) — 4

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1036.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1036.004) Masquerade Task or Service | PROMETHIUM has named services to appear legitimate. | 31 | 4 | — |
| [T1036.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1036.005) Match Legitimate Resource Name or Location | PROMETHIUM has disguised malicious installer files by bundling them with legitimate software installers. | 116 | 4 | — |
| [T1078.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.003) Local Accounts | PROMETHIUM has created admin accounts on a compromised host. | 32 | 13 | — |
| [T1205.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1205.001) Port Knocking | PROMETHIUM has used a script that configures the knockd service and firewall to only accept C2 connections from systems that use a specified sequence of knock ports. | 3 | — | — |

### Defense Impairment (TA0112) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1553.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1553.002) Code Signing | PROMETHIUM has signed code with self-signed certificates. | 11 | — | — |

### Command and Control (TA0011) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1205.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1205.001) Port Knocking | PROMETHIUM has used a script that configures the knockd service and firewall to only accept C2 connections from systems that use a specified sequence of knock ports. | 3 | — | — |

## 4. Assinatura comportamental

Técnicas que este grupo usa e que poucos dos 178 grupos do ATT&CK usam. Pesam mais numa atribuição por TTP: ver várias delas juntas é mais informativo do que ver técnicas comuns como PowerShell.

| Técnica | Outros grupos que usam | Peso (raridade) |
|---|---:|---:|
| T1205.001 Port Knocking | 1 | 4.09 |
| T1587.002 Code Signing Certificates | 2 | 3.80 |
| T1587.003 Digital Certificates | 3 | 3.58 |
| T1078.003 Local Accounts | 13 | 2.48 |
| T1036.004 Masquerade Task or Service | 23 | 1.97 |
| T1543.003 Windows Service | 25 | 1.89 |
| T1553.002 Code Signing | 27 | 1.82 |
| T1189 Drive-by Compromise | 30 | 1.72 |
| T1547.001 Registry Run Keys / Startup Folder | 58 | 1.09 |
| T1036.005 Match Legitimate Resource Name or Location | 65 | 0.98 |

## 5. Arsenal

| Software | Tipo | Técnicas no ATT&CK | Uso relatado (EN) |
|---|---|---:|---|
| [StrongPity](https://attack.mitre.org/software/S0491/) | malware | 26 |  |
| [Truvasys](https://attack.mitre.org/software/S0178/) | malware | 2 |  |

## 6. Campanhas

| Campanha | Período | Resumo (EN) |
|---|---|---|
| [C0033](https://attack.mitre.org/campaigns/C0033/) | 2016-05 → 2023-01 | C0033 was a PROMETHIUM campaign during which they used StrongPity to target Android users. C0033 was the first publicly documented mobile campaign for PROMETHIUM, who previously used Windows-based techniques. |

## 7. Cobertura defensiva

**9 de 11 técnicas (82%)** têm ao menos uma regra pública no catálogo Detection Rules.

### Técnicas sem regra pública (prioridade para engenharia de detecção)

- **T1587.002 Code Signing Certificates** — Resource Development. Fonte de log sugerida pelo MITRE: `Malware Repository` None
- **T1587.003 Digital Certificates** — Resource Development. Fonte de log sugerida pelo MITRE: `Internet Scan` None

### Regras recomendadas por técnica

Melhor regra disponível por técnica (formato portável e maduro primeiro).

| Técnica | Regra | Formato | Fonte |
|---|---|---|---|
| T1036.004 | [Operation Wocao Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1cfac73c-be78-4f9a-9b08-5bde0c3953ab) | Sigma | SigmaHQ |
| T1036.004 | [Operation Wocao Activity - Security](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A74ad4314-482e-4c3e-b237-3f7ed3b9ca8d) | Sigma | SigmaHQ |
| T1036.005 | [Exploit for CVE-2015-1641](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A7993792c-5ce2-4475-a3db-a3a5539827ef) | Sigma | SigmaHQ |
| T1036.005 | [Exploit for CVE-2015-1641](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A7993792c-5ce2-4475-a3db-a3a5539827ef) | Sigma | OpenSearch Security Analytics |
| T1078.003 | [Potential Successful SSH Brute Force Attack via macOS Security Events](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Af5898b1e-3071-4597-b066-43d298c7b415) | Elastic | Elastic detection-rules |
| T1078.003 | [Admin User Remote Logon](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A0f63e1ef-1eb9-4226-9d54-8927ca08520a) | Sigma | SigmaHQ |
| T1189 | [Flash Player Update from Suspicious Location](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4922a5dd-6743-4fc2-8e81-144374280997) | Sigma | SigmaHQ |
| T1189 | [Cross Site Scripting Strings](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A65354b83-a2ea-4ea6-8414-3ab38be0d409) | Sigma | SigmaHQ |
| T1204.002 | [Ursnif Malware C2 URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A932ac737-33ca-4afd-9869-0d48b391fcc9) | Sigma | SigmaHQ |
| T1204.002 | [Droppers Exploiting CVE-2017-11882](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A678eb5f4-8597-4be6-8be7-905e4234b53a) | Sigma | SigmaHQ |
| T1205.001 | [Unusual Linux Network Port Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A3c7e32e6-6104-46d9-a06e-da0f8b5795a0) | Elastic | Elastic detection-rules |
| T1205.001 | [Unexpected K8s NodePort Connection](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=falco-rules%3A%3Aa272e1fc63fd) | Falco | Falco rules |
| T1543.003 | [PSExec Lateral Movement](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=hayabusa-native%3A%3A0694c340-3a46-40ac-acfc-c3444ae6572c) | Sigma | Hayabusa (native) |
| T1543.003 | [Suspicious Service Name](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=hayabusa-native%3A%3Acc429813-21db-4019-b520-2f19648e1ef1) | Sigma | Hayabusa (native) |
| T1547.001 | [Potential Ryuk Ransomware Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac37510b8-2107-4b78-aa32-72f251e7a844) | Sigma | SigmaHQ |
| T1547.001 | [Ryuk Ransomware](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Ac37510b8-2107-4b78-aa32-72f251e7a844) | Sigma | OpenSearch Security Analytics |
| T1553.002 | [Driver Loaded (Invalid Signature)](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=hayabusa-native%3A%3A1f666722-3948-40a2-9d78-d9d374477a90) | Sigma | Hayabusa (native) |
| T1553.002 | [Driver Loaded (Expired/Revoked Cert)](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=hayabusa-native%3A%3Ac837dd6d-0c91-4593-aeab-f6a1f3ca1961) | Sigma | Hayabusa (native) |

## 8. Plano de emulação e validação

Use num laboratório isolado e autorizado para confirmar que as regras disparam. Os comandos estão nos repositórios oficiais.

| Tática | Técnica | Teste Atomic Red Team | Plataformas |
|---|---|---|---|
| Execution | [T1204.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1204.002/T1204.002.md) | OSTap Style Macro Execution | windows |
| Execution | [T1204.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1204.002/T1204.002.md) | OSTap Payload Download | windows |
| Persistence | [T1543.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1543.003/T1543.003.md) | Modify Fax service to run PowerShell | windows |
| Persistence | [T1543.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1543.003/T1543.003.md) | Service Installation CMD | windows |
| Persistence | [T1547.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1547.001/T1547.001.md) | Reg Key Run | windows |
| Persistence | [T1547.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1547.001/T1547.001.md) | Reg Key RunOnce | windows |
| Stealth | [T1036.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.004/T1036.004.md) | Creating W32Time similar named service using schtasks | windows |
| Stealth | [T1036.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.004/T1036.004.md) | Creating W32Time similar named service using sc | windows |
| Stealth | [T1036.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.005/T1036.005.md) | Execute a process from a directory masquerading as the current parent directory | linux, macos |
| Stealth | [T1036.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.005/T1036.005.md) | Masquerade as a built-in system executable | windows |
| Stealth | [T1078.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1078.003/T1078.003.md) | Create local account with admin privileges | windows |
| Stealth | [T1078.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1078.003/T1078.003.md) | Create local account with admin privileges - MacOS | macos |

**Logs reais de ataque (EVTX) para testar sem executar nada:**

- T1543.003 — [ID13-New service for Mimikatz](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0003-Persistence/T1543.003-Create%20or%20Modify%20System%20Process-Windows%20Service/ID13-New%20service%20for%20Mimikatz.evtx) _(explícito)_
- T1543.003 — [ID4688-4697 RDP hijack via service creation](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0003-Persistence/T1543.003-Create%20or%20Modify%20System%20Process-Windows%20Service/ID4688-4697%20RDP%20hijack%20via%20service%20creation.evtx) _(explícito)_
- T1547.001 — [sideloading_injection_persistence_run_key](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/AutomatedTestingTools/Malware/sideloading_injection_persistence_run_key.evtx) _(inferido)_
- T1547.001 — [evasion_persis_hidden_run_keyvalue_sysmon_13](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Persistence/evasion_persis_hidden_run_keyvalue_sysmon_13.evtx) _(inferido)_

## 9. Hipóteses de hunting

Se PROMETHIUM estiver no seu ambiente, estas são as perguntas a fazer aos seus dados (fontes de log segundo as estratégias de detecção do MITRE ATT&CK).

1. **T1205.001 Port Knocking** — A remote source rapidly touches a short sequence of closed ports (SYN→RST/S0) on a Windows host. Within a short window the host changes firewall state (WFP rule added/modified or service starts listening) and then the same source completes the first… Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=3, 22), `WinEventLog:Microsoft-Windows-Windows Firewall With Advanced Security/Firewall` (EventCode=2004, 2005, 2006).
2. **T1587.002 Code Signing Certificates** — Consider analyzing self-signed code signing certificates for features that may be associated with the adversary and/or their developers, such as the thumbprint, algorithm used, validity period, and common name. Malware repositories can also be used to… Dados: `Malware Repository` (None).
3. **T1587.003 Digital Certificates** — Consider use of services that may aid in the tracking of certificates in use on sites across the Internet. In some cases it may be possible to pivot on known pieces of certificate information to uncover other adversary infrastructure. Detection efforts may be… Dados: `Internet Scan` (None).
4. **T1078.003 Local Accounts** — Detects anomalous usage of local accounts to log into a system, especially accounts not typically used interactively or outside business hours. Dados: `WinEventLog:Security` (EventCode=4624, 4648), `WinEventLog:Security` (EventCode=4672).
5. **T1036.004 Masquerade Task or Service** — Creation or modification of Windows services or scheduled tasks with names or descriptions mimicking legitimate entries, followed by anomalous execution of untrusted binaries or LOLBAS. Dados: `WinEventLog:System` (EventCode=7045), `WinEventLog:Security` (EventCode=4698), `WinEventLog:Sysmon` (EventCode=1).
6. **T1543.003 Windows Service** — Detects creation or modification of Windows Services through command-line tools (e.g., `sc.exe`, `powershell.exe`), Registry key changes under `HKLM\System\CurrentControlSet\Services`, and service execution under SYSTEM with unsigned or anomalous binary… Dados: `WinEventLog:Security` (EventCode=4697), `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=13, 14).
7. **T1553.002 Code Signing** — Detects execution of binaries signed with unusual or recently issued certificates, correlation of process execution with abnormal publisher metadata, and mismatched certificate chains. Monitors for revoked or unknown code signing certificates used in… Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=7).
8. **T1189 Drive-by Compromise** — Correlated evidence of anomalous browser/network behavior (suspicious external resource fetches and script injection patterns) followed by atypical child processes, ephemeral execution contexts, memory modification or process injection, and unexpected file… Dados: `WinEventLog:Security` (EventCode=4624, 4648), `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=3, 22).
9. **T1547.001 Registry Run Keys / Startup Folder** — Correlation of Registry key creation/modification events under known Run/Startup keys with new or unusual binary paths or script-based payloads. Multi-event detection includes registry modification followed by process execution from non-standard directories… Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=13, 14), `WinEventLog:Microsoft-Windows-Shell-Core` (New startup folder shortcut or binary placed in Startup directory).
10. **T1036.005 Match Legitimate Resource Name or Location** — Detects processes or binaries executed from trusted directories (e.g., System32) or using trusted names (e.g., svchost.exe) where the metadata, hash, or parent process does not align with legitimate activity patterns. Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=11).
11. **T1204.002 Malicious File** — User opens a file delivered by email, web, chat, or share. The handler application (Word/PDF reader/archiver) creates a file in user-controlled paths (Downloads, Temp, Desktop) and then spawns a new or unusual child process (e.g., powershell.exe, wscript.exe,… Dados: `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=15).

## 10. OSINT — onde pesquisar

Consultas prontas com todos os nomes conhecidos do grupo:

- Relatórios técnicos: [busca web](https://duckduckgo.com/?q=%28%22PROMETHIUM%22+OR+%22StrongPity%22%29+threat+report) · [PDFs](https://duckduckgo.com/?q=%28%22PROMETHIUM%22+OR+%22StrongPity%22%29+filetype%3Apdf)
- Regras e IOCs publicados: [GitHub](https://github.com/search?type=code&q=%22PROMETHIUM%22+OR+%22StrongPity%22)
- Pulsos de ameaça: [AlienVault OTX](https://otx.alienvault.com/browse/global/pulses?q=PROMETHIUM)
- Família de malware e atores: [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/actors) (busque por PROMETHIUM, StrongPity)
- Cartões de grupo: [ThaiCERT Threat Group Cards](https://apt.etda.or.th/cgi-bin/listgroups.cgi)
- Página oficial: [MITRE ATT&CK G0056](https://attack.mitre.org/groups/G0056/)

**Relatórios na coleção CyberMonitor** (ligados pelo nome do grupo, conferir antes de citar):

- 2016 — [On the StrongPity Waterhole Attacks - Securelist](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2016/2016.10.03.StrongPity/On%20the%20StrongPity%20Waterhole%20Attacks%20-%20Securelist.pdf) _(via “StrongPity”)_
- 2016 — [Microsoft_Security_Intelligence_Report_Volume_21_English](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2016/2016.12.15.PROMETHIUM_and_NEODYMIUM/Microsoft_Security_Intelligence_Report_Volume_21_English.pdf) _(via “PROMETHIUM”)_
- 2019 — [Newly identified StrongPity operations _ AT&T Alien Labs](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2019/2019.07.17.StrongPity_operations/Newly%20identified%20StrongPity%20operations%20_%20AT%26T%20Alien%20Labs.pdf) _(via “StrongPity”)_
- 2020 — [Talos Blog __ Cisco Talos Intelligence Group - Comprehensive Threat Intelligence_ PROMETHIUM extends global reach with S](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2020/2020.06.29.PROMETHIUM_StrongPity3_APT/Talos%20Blog%20__%20Cisco%20Talos%20Intelligence%20Group%20-%20Comprehensive%20Threat%20Intelligence_%20PROMETHIUM%20extends%20global%20reach%20with%20StrongPity3%20APT.pdf) _(via “PROMETHIUM”)_
- 2020 — [Bitdefender-Whitepaper-StrongPity-APT](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2020/2020.06.30_StrongPity_APT/Bitdefender-Whitepaper-StrongPity-APT.pdf) _(via “StrongPity”)_

## 11. Bibliografia (4 fontes citadas pelo ATT&CK)

- [Bitdefender StrongPity June 2020](https://www.bitdefender.com/files/News/CaseStudies/study/353/Bitdefender-Whitepaper-StrongPity-APT.pdf) — Tudorica, R. et al. (2020, June 30). StrongPity APT - Revealing Trojanized Tools, Working Hours and Infrastructure. Retrieved July 20, 2020.
- [Microsoft NEODYMIUM Dec 2016](https://blogs.technet.microsoft.com/mmpc/2016/12/14/twin-zero-day-attacks-promethium-and-neodymium-target-individuals-in-europe/) — Microsoft. (2016, December 14). Twin zero-day attacks: PROMETHIUM and NEODYMIUM target individuals in Europe. Retrieved November 27, 2017.
- [Microsoft SIR Vol 21](http://download.microsoft.com/download/E/B/0/EB0F50CC-989C-4B66-B7F6-68CD3DC90DE3/Microsoft_Security_Intelligence_Report_Volume_21_English.pdf) — Anthe, C. et al. (2016, December 14). Microsoft Security Intelligence Report Volume 21. Retrieved November 27, 2017.
- [Talos Promethium June 2020](https://blog.talosintelligence.com/2020/06/promethium-extends-with-strongpity3.html) — Mercer, W. et al. (2020, June 29). PROMETHIUM extends global reach with StrongPity3 APT. Retrieved July 20, 2020.

## 12. Limites e confiança

- O ATT&CK registra o que foi **relatado publicamente**, não tudo o que o grupo faz. Ausência de uma técnica não prova que o grupo não a usa.
- **Sobreposição de TTP não é atribuição.** Muitas técnicas são compartilhadas entre grupos e com red teams. Use a assinatura comportamental como hipótese, junto com infraestrutura, malware e contexto.
- Cobertura de detecção refere-se ao catálogo público Detection Rules, não ao seu ambiente: confira se a telemetria necessária chega ao seu SIEM.
- Ligações marcadas como _inferidas_ (EVTX por palavra-chave, relatórios por nome) devem ser verificadas.

---
Fontes: MITRE ATT&CK® (uso livre com atribuição, © The MITRE Corporation), Atomic Red Team (Red Canary, MIT), EVTX-to-MITRE-Attack, EVTX-ATTACK-SAMPLES, APT & CyberCriminal Campaign Collections. Gerado por [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules).
