# MoustachedBouncer (G1019) — Dossiê de inteligência

> **TLP:CLEAR** · gerado em 2026-10-25 a partir de fontes abertas · MITRE ATT&CK v20.0 · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1019) · [ATT&CK](https://attack.mitre.org/groups/G1019/)

**Também conhecido como:** —  
**Registro no ATT&CK:** criado em 2023-09-25, atualizado em 2026-07-31 · referências de 2023 a 2023

## 1. Sumário executivo

- **8 técnicas** atribuídas publicamente, concentradas em **Execution, Collection, Command and Control**.
- **Arsenal:** 3 malware e 0 ferramentas (ex.: NightClub, SharpDisco, Disco).
- **Campanhas atribuídas:** 0.
- **Cobertura de detecção pública:** 100% das técnicas têm ao menos uma regra no catálogo; **0 técnicas sem nenhuma regra pública**.
- **Assinatura comportamental** (técnicas raras entre os 178 grupos, as mais úteis para atribuição): T1659 Content Injection, T1074.002 Remote Data Staging, T1113 Screen Capture, T1090 Proxy, T1068 Exploitation for Privilege Escalation.

## 2. Quem é

> MoustachedBouncer is a cyberespionage group that has been active since at least 2014 targeting foreign embassies in Belarus.

_Texto original do MITRE ATT&CK, em inglês._

## 3. Perfil TTP por tática (kill chain)

Cada linha: técnica, como o grupo a usou segundo relatos públicos, e o que existe para detectar e testar.

### Initial Access (TA0001) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1659](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1659) Content Injection | MoustachedBouncer has injected content into DNS, HTTP, and SMB replies to redirect specifically-targeted victims to a fake Windows Update page to download malware. | 4 | — | — |

### Execution (TA0002) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1059.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.001) PowerShell | MoustachedBouncer has used plugins to execute PowerShell scripts. | 1340 | 22 | 15 |
| [T1059.007](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.007) JavaScript | MoustachedBouncer has used JavaScript to deliver malware hosted on HTML pages. | 205 | 5 | — |

### Privilege Escalation (TA0004) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1068](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1068) Exploitation for Privilege Escalation | MoustachedBouncer has exploited CVE-2021-1732 to execute malware components with elevated rights. | 408 | 2 | 2 |

### Stealth (TA0005) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1027.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1027.002) Software Packing | MoustachedBouncer has used malware plugins packed with Themida. | 12 | 4 | — |

### Collection (TA0009) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1074.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1074.002) Remote Data Staging | MoustachedBouncer has used plugins to save captured screenshots to `.\AActdata\` on an SMB share. | 5 | — | — |
| [T1113](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1113) Screen Capture | MoustachedBouncer has used plugins to take screenshots on targeted systems. | 60 | 10 | — |

### Command and Control (TA0011) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1090](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1090) Proxy | MoustachedBouncer has used a reverse proxy tool similar to the GitHub repository revsocks. | 162 | — | 1 |
| [T1659](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1659) Content Injection | MoustachedBouncer has injected content into DNS, HTTP, and SMB replies to redirect specifically-targeted victims to a fake Windows Update page to download malware. | 4 | — | — |

## 4. Assinatura comportamental

Técnicas que este grupo usa e que poucos dos 178 grupos do ATT&CK usam. Pesam mais numa atribuição por TTP: ver várias delas juntas é mais informativo do que ver técnicas comuns como PowerShell.

| Técnica | Outros grupos que usam | Peso (raridade) |
|---|---:|---:|
| T1659 Content Injection | 0 | 4.49 |
| T1074.002 Remote Data Staging | 10 | 2.70 |
| T1113 Screen Capture | 18 | 2.19 |
| T1090 Proxy | 19 | 2.14 |
| T1068 Exploitation for Privilege Escalation | 22 | 2.01 |
| T1027.002 Software Packing | 23 | 1.97 |
| T1059.007 JavaScript | 29 | 1.75 |
| T1059.001 PowerShell | 85 | 0.72 |

## 5. Arsenal

| Software | Tipo | Técnicas no ATT&CK | Uso relatado (EN) |
|---|---|---:|---|
| [NightClub](https://attack.mitre.org/software/S1090/) | malware | 21 |  |
| [SharpDisco](https://attack.mitre.org/software/S1089/) | malware | 11 |  |
| [Disco](https://attack.mitre.org/software/S1088/) | malware | 5 |  |

## 6. Campanhas

Nenhuma campanha atribuída no ATT&CK.

## 7. Cobertura defensiva

**8 de 8 técnicas (100%)** têm ao menos uma regra pública no catálogo Detection Rules.

### Regras recomendadas por técnica

Melhor regra disponível por técnica (formato portável e maduro primeiro).

| Técnica | Regra | Formato | Fonte |
|---|---|---|---|
| T1027.002 | [Python Image Load By Non-Python Process](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acbb56d62-4060-40f7-9466-d8aaf3123f83) | Sigma | SigmaHQ |
| T1027.002 | [Python Py2Exe Image Load](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Acbb56d62-4060-40f7-9466-d8aaf3123f83) | Sigma | OpenSearch Security Analytics |
| T1059.001 | [Potential Emotet Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad02e8cf5-6099-48cf-9bfc-1eec2d0c7b18) | Sigma | SigmaHQ |
| T1059.001 | [TropicTrooper Campaign November 2018](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A8c7090c3-e0a0-4944-bd08-08c3a0cecf79) | Sigma | SigmaHQ |
| T1059.007 | [Adwind RAT / JRAT](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1fac1481-2dbc-48b2-9096-753c49b4ec71) | Sigma | SigmaHQ |
| T1059.007 | [WScript or CScript Dropper - File](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A002bdb95-0cf1-46a6-9e08-d38c128a6127) | Sigma | SigmaHQ |
| T1068 | [Exploiting CVE-2019-1388](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A02e0b2ea-a597-428e-b04a-af6a1a403e5c) | Sigma | SigmaHQ |
| T1068 | [OMIGOD HTTP No Authentication RCE - CVE-2021-38647](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aab6b1a39-a9ee-4ab4-b075-e83acf6e346b) | Sigma | SigmaHQ |
| T1074.002 | [Google Workspace Drive Data Transfer or Takeout Export Initiated](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A07b5f85a-240f-11ed-b3d9-f661ea17fbce) | Elastic | Elastic detection-rules |
| T1074.002 | [AWS RDS DB Instance Restored](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Abf1073bf-ce26-4607-b405-ba1ed8e9e204) | Elastic | Elastic detection-rules |
| T1090 | [Communication To LocaltoNet Tunneling Service Initiated - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac4568f5d-131f-4e78-83d4-45b2da0ec4f1) | Sigma | SigmaHQ |
| T1090 | [Communication To Ngrok Tunneling Service - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A19bf6fdb-7721-4f3d-867f-53467f6a5db6) | Sigma | SigmaHQ |
| T1113 | [PowerShell Suspicious Script with Screenshot Capabilities](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A959a7353-1129-4aa7-9084-30746b256a70) | Elastic | Elastic detection-rules |
| T1113 | [Potential Remote Desktop Shadowing Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ac57f8579-e2a5-4804-847f-f2732edc5156) | Elastic | Elastic detection-rules |
| T1659 | [Dynatrace - Problem detection](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A415978ff-074e-4203-824a-b06153d77bf7) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1659 | [Dynatrace Application Security - Non-critical runtime vulnerability detection](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3Aff0af873-a2f2-4233-8412-0ef4e00b0156) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |

## 8. Plano de emulação e validação

Use num laboratório isolado e autorizado para confirmar que as regras disparam. Os comandos estão nos repositórios oficiais.

| Tática | Técnica | Teste Atomic Red Team | Plataformas |
|---|---|---|---|
| Execution | [T1059.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md) | Mimikatz | windows |
| Execution | [T1059.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md) | Run BloodHound from local disk | windows |
| Execution | [T1059.007](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.007/T1059.007.md) | JScript execution to gather local computer information via cscript | windows |
| Execution | [T1059.007](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.007/T1059.007.md) | JScript execution to gather local computer information via wscript | windows |
| Privilege Escalation | [T1068](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1068/T1068.md) | Scattered Spider BYOVD (CVE-2015-2291 for Intel Ethernet Diagnostics Driver) | windows |
| Privilege Escalation | [T1068](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1068/T1068.md) | Turla Snake Malware Privilege Escalation Through VM Driver | windows |
| Stealth | [T1027.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027.002/T1027.002.md) | Binary simply packed by UPX (linux) | linux |
| Stealth | [T1027.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027.002/T1027.002.md) | Binary packed by UPX, with modified headers (linux) | linux |
| Collection | [T1113](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1113/T1113.md) | Screencapture | macos |
| Collection | [T1113](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1113/T1113.md) | Screencapture (silent) | macos |

**Logs reais de ataque (EVTX) para testar sem executar nada:**

- T1059.001 — [ID4103-4104-Payload download via PowerShell](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1059.001-PowerShell/ID4103-4104-Payload%20download%20via%20PowerShell.evtx) _(explícito)_
- T1059.001 — [ID4688-Encoded PowerShell MSF payload via process execution](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1059.001-PowerShell/ID4688-Encoded%20PowerShell%20MSF%20payload%20via%20process%20execution.evtx) _(explícito)_
- T1068 — [ID12-13 Mini_Plasma_PoC_AbortHydration_ArbitraryRegKey_EoP](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0004-Privilege%20Escalation/T1068-Exploitation%20for%20Privilege%20Escalation/ID12-13%20Mini_Plasma_PoC_AbortHydration_ArbitraryRegKey_EoP.evtx) _(explícito)_
- T1068 — [ID4673-Privilege SeMachineAccountPrivilege called](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0004-Privilege%20Escalation/T1068-Exploitation%20for%20Privilege%20Escalation/ID4673-Privilege%20SeMachineAccountPrivilege%20called.evtx) _(explícito)_
- T1090 — [ID5600-proxy configuration changed](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0011-Command%20and%20Control/T1090-Proxy/ID5600-proxy%20configuration%20changed.evtx) _(explícito)_

## 9. Hipóteses de hunting

Se MoustachedBouncer estiver no seu ambiente, estas são as perguntas a fazer aos seus dados (fontes de log segundo as estratégias de detecção do MITRE ATT&CK).

1. **T1659 Content Injection** — Detect suspicious file creations and process executions triggered by browser activity (e.g., injected payloads written to %AppData% or Temp directories, then executed). Correlate network anomalies with subsequent local process creation or script execution. Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=11), `NSM:Flow` (Unexpected script or binary content returned in HTTP response body).
2. **T1074.002 Remote Data Staging** — Detects file transfers or mounting operations from remote hosts followed by write actions into a local staging directory, often using SMB or remote shell activity. Dados: `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Microsoft-Windows-SMBClient/Security` (EventCode=31001), `WinEventLog:PowerShell` (CommandLine=copy-item or robocopy from UNC path).
3. **T1113 Screen Capture** — Unusual use of screen capture APIs (e.g., CopyFromScreen) or command-line tools to write image files to disk. Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=7).
4. **T1090 Proxy** — Suspicious process spawning (e.g., `rundll32`, `svchost`, `powershell`, or `netsh`) followed by network connection creation to internal hosts or uncommon external endpoints on high or non-standard ports. Dados: `WinEventLog:Sysmon` (EventCode=3, 22), `WinEventLog:Sysmon` (EventCode=1), `NSM:Connections` (Outbound Connection).
5. **T1068 Exploitation for Privilege Escalation** — Detects exploitation attempts targeting vulnerable kernel drivers or OS components, often followed by unusual process or token behavior. Dados: `WinEventLog:Sysmon` (EventCode=6), `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Security` (EventCode=4672).
6. **T1027.002 Software Packing** — Detection of unpacking behavior through abnormal memory allocation, followed by executable code injection and execution from non-image sections. Dados: `WinEventLog:Sysmon` (EventCode=10), `WinEventLog:Sysmon` (EventCode=1).
7. **T1059.007 JavaScript** — Detects JavaScript execution through WSH (wscript.exe, cscript.exe) or HTA (mshta.exe), particularly when spawned from Office macros, web browsers, or abnormal user paths. Correlates script execution with outbound network activity or system modification. Dados: `WinEventLog:Sysmon` (EventCode=1), `m365:defender` (ScriptBlockLogging + AMSI), `WinEventLog:Sysmon` (EventCode=7).
8. **T1059.001 PowerShell** — Detects behavioral chains where PowerShell is launched with encoded commands, unusual parent processes, or suspicious modules loaded, potentially followed by network connections or child process spawning. Supports detection of both direct (powershell.exe) and… Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:PowerShell` (EventCode=4103, 4104, 4105, 4106), `WinEventLog:PowerShell` (EventCode=400, 403).

## 10. OSINT — onde pesquisar

Consultas prontas com todos os nomes conhecidos do grupo:

- Relatórios técnicos: [busca web](https://duckduckgo.com/?q=%28%22MoustachedBouncer%22%29+threat+report) · [PDFs](https://duckduckgo.com/?q=%28%22MoustachedBouncer%22%29+filetype%3Apdf)
- Regras e IOCs publicados: [GitHub](https://github.com/search?type=code&q=%22MoustachedBouncer%22)
- Pulsos de ameaça: [AlienVault OTX](https://otx.alienvault.com/browse/global/pulses?q=MoustachedBouncer)
- Família de malware e atores: [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/actors) (busque por MoustachedBouncer)
- Cartões de grupo: [ThaiCERT Threat Group Cards](https://apt.etda.or.th/cgi-bin/listgroups.cgi)
- Página oficial: [MITRE ATT&CK G1019](https://attack.mitre.org/groups/G1019/)

## 11. Bibliografia (1 fontes citadas pelo ATT&CK)

- [MoustachedBouncer ESET August 2023](https://www.welivesecurity.com/en/eset-research/moustachedbouncer-espionage-against-foreign-diplomats-in-belarus/) — Faou, M. (2023, August 10). MoustachedBouncer: Espionage against foreign diplomats in Belarus. Retrieved September 25, 2023.

## 12. Limites e confiança

- O ATT&CK registra o que foi **relatado publicamente**, não tudo o que o grupo faz. Ausência de uma técnica não prova que o grupo não a usa.
- **Sobreposição de TTP não é atribuição.** Muitas técnicas são compartilhadas entre grupos e com red teams. Use a assinatura comportamental como hipótese, junto com infraestrutura, malware e contexto.
- Cobertura de detecção refere-se ao catálogo público Detection Rules, não ao seu ambiente: confira se a telemetria necessária chega ao seu SIEM.
- Ligações marcadas como _inferidas_ (EVTX por palavra-chave, relatórios por nome) devem ser verificadas.

---
Fontes: MITRE ATT&CK® (uso livre com atribuição, © The MITRE Corporation), Atomic Red Team (Red Canary, MIT), EVTX-to-MITRE-Attack, EVTX-ATTACK-SAMPLES, APT & CyberCriminal Campaign Collections. Gerado por [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules).
