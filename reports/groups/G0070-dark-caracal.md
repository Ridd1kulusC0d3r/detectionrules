# Dark Caracal (G0070) — Dossiê de inteligência

> **TLP:CLEAR** · gerado em 2026-10-25 a partir de fontes abertas · MITRE ATT&CK v20.0 · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0070) · [ATT&CK](https://attack.mitre.org/groups/G0070/)

**Também conhecido como:** —  
**Registro no ATT&CK:** criado em 2018-10-17, atualizado em 2026-09-02 · referências de 2018 a 2020

## 1. Sumário executivo

- **12 técnicas** atribuídas publicamente, concentradas em **Stealth, Collection, Execution**.
- **Arsenal:** 3 malware e 0 ferramentas (ex.: Bandook, FinFisher, CrossRAT).
- **Campanhas atribuídas:** 0.
- **Cobertura de detecção pública:** 100% das técnicas têm ao menos uma regra no catálogo; **0 técnicas sem nenhuma regra pública**.
- **Assinatura comportamental** (técnicas raras entre os 178 grupos, as mais úteis para atribuição): T1218.001 Compiled HTML File, T1566.003 Spearphishing via Service, T1113 Screen Capture, T1027.002 Software Packing, T1189 Drive-by Compromise.

## 2. Quem é

> Dark Caracal is threat group that has been attributed to the Lebanese General Directorate of General Security (GDGS) and has operated since at least 2012.

_Texto original do MITRE ATT&CK, em inglês._

## 3. Perfil TTP por tática (kill chain)

Cada linha: técnica, como o grupo a usou segundo relatos públicos, e o que existe para detectar e testar.

### Initial Access (TA0001) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1189](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1189) Drive-by Compromise | Dark Caracal leveraged a watering hole to serve up malicious code. | 57 | — | — |
| [T1566.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1566.003) Spearphishing via Service | Dark Caracal spearphished victims via Facebook and Whatsapp. | 8 | — | — |

### Execution (TA0002) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1059.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.003) Windows Command Shell | Dark Caracal has used macros in Word documents that would download a second stage if executed. | 269 | 6 | 1 |
| [T1204.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1204.002) Malicious File | Dark Caracal makes their malware look like Flash Player, Office, or PDF documents in order to entice a user to click on it. | 259 | 13 | — |

### Persistence (TA0003) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1547.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1547.001) Registry Run Keys / Startup Folder | Dark Caracal's version of Bandook adds a registry key to HKEY_USERS\Software\Microsoft\Windows\CurrentVersion\Run for persistence. | 299 | 21 | 2 |

### Privilege Escalation (TA0004) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1547.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1547.001) Registry Run Keys / Startup Folder | Dark Caracal's version of Bandook adds a registry key to HKEY_USERS\Software\Microsoft\Windows\CurrentVersion\Run for persistence. | 299 | 21 | 2 |

### Stealth (TA0005) — 3

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1027.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1027.002) Software Packing | Dark Caracal has used UPX to pack Bandook. | 12 | 4 | — |
| [T1027.013](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1027.013) Encrypted/Encoded File | Dark Caracal has obfuscated strings in Bandook by base64 encoding, and then encrypting them. | 8 | 4 | — |
| [T1218.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1218.001) Compiled HTML File | Dark Caracal leveraged a compiled HTML file that contained a command to download and run an executable. | 28 | 8 | — |

### Discovery (TA0007) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1083](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1083) File and Directory Discovery | Dark Caracal collected file listings of all default Windows directories. | 137 | 9 | — |

### Collection (TA0009) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1005) Data from Local System | Dark Caracal collected complete contents of the 'Pictures' folder from compromised Windows systems. | 170 | 3 | — |
| [T1113](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1113) Screen Capture | Dark Caracal took screenshots using their Windows malware. | 60 | 10 | — |

### Command and Control (TA0011) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1071.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1071.001) Web Protocols | Dark Caracal's version of Bandook communicates with their server over a TCP port using HTTP payloads Base64 encoded and suffixed with the string “&&&”. | 228 | 3 | — |

## 4. Assinatura comportamental

Técnicas que este grupo usa e que poucos dos 178 grupos do ATT&CK usam. Pesam mais numa atribuição por TTP: ver várias delas juntas é mais informativo do que ver técnicas comuns como PowerShell.

| Técnica | Outros grupos que usam | Peso (raridade) |
|---|---:|---:|
| T1218.001 Compiled HTML File | 4 | 3.40 |
| T1566.003 Spearphishing via Service | 14 | 2.42 |
| T1113 Screen Capture | 18 | 2.19 |
| T1027.002 Software Packing | 23 | 1.97 |
| T1189 Drive-by Compromise | 30 | 1.72 |
| T1027.013 Encrypted/Encoded File | 39 | 1.47 |
| T1005 Data from Local System | 46 | 1.32 |
| T1083 File and Directory Discovery | 51 | 1.22 |
| T1071.001 Web Protocols | 57 | 1.11 |
| T1547.001 Registry Run Keys / Startup Folder | 58 | 1.09 |

## 5. Arsenal

| Software | Tipo | Técnicas no ATT&CK | Uso relatado (EN) |
|---|---|---:|---|
| [Bandook](https://attack.mitre.org/software/S0234/) | malware | 26 |  |
| [FinFisher](https://attack.mitre.org/software/S0182/) | malware | 22 |  |
| [CrossRAT](https://attack.mitre.org/software/S0235/) | malware | 5 |  |

## 6. Campanhas

Nenhuma campanha atribuída no ATT&CK.

## 7. Cobertura defensiva

**12 de 12 técnicas (100%)** têm ao menos uma regra pública no catálogo Detection Rules.

### Regras recomendadas por técnica

Melhor regra disponível por técnica (formato portável e maduro primeiro).

| Técnica | Regra | Formato | Fonte |
|---|---|---|---|
| T1005 | [Potential Conti Ransomware Database Dumping Activity Via SQLCmd](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A2f47f1fd-0901-466e-a770-3b7092834a1b) | Sigma | SigmaHQ |
| T1005 | [OpenCanary - SMB File Open Request](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A22777c9e-873a-4b49-855f-6072ab861a52) | Sigma | SigmaHQ |
| T1027.002 | [Python Image Load By Non-Python Process](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acbb56d62-4060-40f7-9466-d8aaf3123f83) | Sigma | SigmaHQ |
| T1027.002 | [Python Py2Exe Image Load](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Acbb56d62-4060-40f7-9466-d8aaf3123f83) | Sigma | OpenSearch Security Analytics |
| T1027.013 | [ROT Encoded Python Script Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A5ab49127-b1b3-46e6-8a38-9e8512a2a363) | Elastic | Elastic detection-rules |
| T1027.013 | [Data Encrypted via OpenSSL Utility](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Afeba48f6-40ca-4d04-b41f-5dfa327de865) | Elastic | Elastic detection-rules |
| T1059.003 | [HackTool - CrackMapExec Execution Patterns](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A058f4380-962d-40a5-afce-50207d36d7e2) | Sigma | SigmaHQ |
| T1059.003 | [CrackMapExec Command Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A058f4380-962d-40a5-afce-50207d36d7e2) | Sigma | OpenSearch Security Analytics |
| T1071.001 | [Ursnif Malware Download URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aa36ce77e-30db-4ea0-8795-644d7af5dfb4) | Sigma | SigmaHQ |
| T1071.001 | [Ursnif Malware C2 URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A932ac737-33ca-4afd-9869-0d48b391fcc9) | Sigma | SigmaHQ |
| T1083 | [Turla Group Lateral Movement](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac601f20d-570a-4cde-a7d6-e17f99cb8e7f) | Sigma | SigmaHQ |
| T1083 | [WannaCry Ransomware Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A41d40bff-377a-43e2-8e1b-2e543069e079) | Sigma | SigmaHQ |
| T1113 | [PowerShell Suspicious Script with Screenshot Capabilities](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A959a7353-1129-4aa7-9084-30746b256a70) | Elastic | Elastic detection-rules |
| T1113 | [Potential Remote Desktop Shadowing Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ac57f8579-e2a5-4804-847f-f2732edc5156) | Elastic | Elastic detection-rules |
| T1189 | [Flash Player Update from Suspicious Location](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4922a5dd-6743-4fc2-8e81-144374280997) | Sigma | SigmaHQ |
| T1189 | [Cross Site Scripting Strings](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A65354b83-a2ea-4ea6-8414-3ab38be0d409) | Sigma | SigmaHQ |
| T1204.002 | [Ursnif Malware C2 URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A932ac737-33ca-4afd-9869-0d48b391fcc9) | Sigma | SigmaHQ |
| T1204.002 | [Droppers Exploiting CVE-2017-11882](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A678eb5f4-8597-4be6-8be7-905e4234b53a) | Sigma | SigmaHQ |
| T1218.001 | [HTML Help HH.EXE Suspicious Child Process](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A52cad028-0ff0-4854-8f67-d25dfcbc78b4) | Sigma | SigmaHQ |
| T1218.001 | [Remote CHM File Download/Execution Via HH.EXE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Af57c58b3-ee69-4ef5-9041-455bf39aaa89) | Sigma | SigmaHQ |
| T1547.001 | [Potential Ryuk Ransomware Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac37510b8-2107-4b78-aa32-72f251e7a844) | Sigma | SigmaHQ |
| T1547.001 | [Ryuk Ransomware](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Ac37510b8-2107-4b78-aa32-72f251e7a844) | Sigma | OpenSearch Security Analytics |
| T1566.003 | [M365 Teams Rogue Help Desk Chat Created](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ae8e7b6b6-78b0-4015-97fe-c2f28468e0d4) | Elastic | Elastic detection-rules |
| T1566.003 | [M365 Azure Monitor Alert Email with Financial or Billing Theme](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Aa6129187-c47b-48ab-a412-67a44836d918) | Elastic | Elastic detection-rules |

## 8. Plano de emulação e validação

Use num laboratório isolado e autorizado para confirmar que as regras disparam. Os comandos estão nos repositórios oficiais.

| Tática | Técnica | Teste Atomic Red Team | Plataformas |
|---|---|---|---|
| Execution | [T1059.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.003/T1059.003.md) | Create and Execute Batch Script | windows |
| Execution | [T1059.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.003/T1059.003.md) | Writes text to a file and displays it. | windows |
| Execution | [T1204.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1204.002/T1204.002.md) | OSTap Style Macro Execution | windows |
| Execution | [T1204.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1204.002/T1204.002.md) | OSTap Payload Download | windows |
| Persistence | [T1547.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1547.001/T1547.001.md) | Reg Key Run | windows |
| Persistence | [T1547.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1547.001/T1547.001.md) | Reg Key RunOnce | windows |
| Stealth | [T1027.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027.002/T1027.002.md) | Binary simply packed by UPX (linux) | linux |
| Stealth | [T1027.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027.002/T1027.002.md) | Binary packed by UPX, with modified headers (linux) | linux |
| Stealth | [T1027.013](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027.013/T1027.013.md) | Decode Eicar File and Write to File | linux, macos, windows |
| Stealth | [T1027.013](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027.013/T1027.013.md) | Decrypt Eicar File and Write to File | linux, macos, windows |
| Stealth | [T1218.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.001/T1218.001.md) | Compiled HTML Help Local Payload | windows |
| Stealth | [T1218.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.001/T1218.001.md) | Compiled HTML Help Remote Payload | windows |
| Discovery | [T1083](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1083/T1083.md) | File and Directory Discovery (cmd.exe) | windows |
| Discovery | [T1083](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1083/T1083.md) | File and Directory Discovery (PowerShell) | windows |
| Collection | [T1005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1005/T1005.md) | Search files of interest and save them to a single zip file (Windows) | windows |
| Collection | [T1005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1005/T1005.md) | Find and dump sqlite databases (Linux) | linux |
| Collection | [T1113](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1113/T1113.md) | Screencapture | macos |
| Collection | [T1113](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1113/T1113.md) | Screencapture (silent) | macos |
| Command and Control | [T1071.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1071.001/T1071.001.md) | Malicious User Agents - Powershell | windows |
| Command and Control | [T1071.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1071.001/T1071.001.md) | Malicious User Agents - CMD | windows |

**Logs reais de ataque (EVTX) para testar sem executar nada:**

- T1059.003 — [ID4688-SQL Server payload injectection for reverse shell (MSF)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1059.003-Windows%20Command%20Shell/ID4688-SQL%20Server%20payload%20injectection%20for%20reverse%20shell%20%28MSF%29.evtx) _(explícito)_
- T1547.001 — [sideloading_injection_persistence_run_key](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/AutomatedTestingTools/Malware/sideloading_injection_persistence_run_key.evtx) _(inferido)_
- T1547.001 — [evasion_persis_hidden_run_keyvalue_sysmon_13](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Persistence/evasion_persis_hidden_run_keyvalue_sysmon_13.evtx) _(inferido)_

## 9. Hipóteses de hunting

Se Dark Caracal estiver no seu ambiente, estas são as perguntas a fazer aos seus dados (fontes de log segundo as estratégias de detecção do MITRE ATT&CK).

1. **T1218.001 Compiled HTML File** — Execution of hh.exe to open a .chm file followed by suspicious child processes or script engine invocation (VBScript, JScript, mshta, powershell). Behavior includes loading a CHM file from untrusted locations, or immediately spawning commands indicative of… Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Sysmon` (EventCode=7).
2. **T1566.003 Spearphishing via Service** — Inbound spearphishing attempts delivered via third-party services (e.g., Gmail, LinkedIn messages) leading to malicious file downloads or browser-initiated script execution. Defender view includes correlation of external service logins, unexpected file write… Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Sysmon` (EventCode=3, 22).
3. **T1113 Screen Capture** — Unusual use of screen capture APIs (e.g., CopyFromScreen) or command-line tools to write image files to disk. Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=7).
4. **T1027.002 Software Packing** — Detection of unpacking behavior through abnormal memory allocation, followed by executable code injection and execution from non-image sections. Dados: `WinEventLog:Sysmon` (EventCode=10), `WinEventLog:Sysmon` (EventCode=1).
5. **T1189 Drive-by Compromise** — Correlated evidence of anomalous browser/network behavior (suspicious external resource fetches and script injection patterns) followed by atypical child processes, ephemeral execution contexts, memory modification or process injection, and unexpected file… Dados: `WinEventLog:Security` (EventCode=4624, 4648), `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=3, 22).
6. **T1027.013 Encrypted/Encoded File** — Detection of processes that load or decode encrypted/encoded files in memory and subsequently execute or inject them, indicating payload unpacking or memory-resident malware. Dados: `WinEventLog:Sysmon` (EventCode=7), `WinEventLog:Sysmon` (EventCode=10), `WinEventLog:Security` (EventCode=4688).
7. **T1005 Data from Local System** — Adversaries collecting local files via PowerShell, WMI, or direct file API calls often include recursive file listings, targeted file reads, and temporary file staging. Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=11).
8. **T1083 File and Directory Discovery** — Execution of file enumeration commands (e.g., 'dir', 'tree') from non-standard processes or unusual user contexts, followed by recursive directory traversal or access to sensitive locations. Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=11).
9. **T1071.001 Web Protocols** — Detects unexpected or high-volume HTTP/S/WebSocket communication from suspicious processes (e.g., PowerShell, rundll32) using uncommon user agents or mimicking browser traffic to unusual domains or IPs. Dados: `NSM:Flow` (http.log, ssl.log), `WinEventLog:Sysmon` (EventCode=3, 22).
10. **T1547.001 Registry Run Keys / Startup Folder** — Correlation of Registry key creation/modification events under known Run/Startup keys with new or unusual binary paths or script-based payloads. Multi-event detection includes registry modification followed by process execution from non-standard directories… Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=13, 14), `WinEventLog:Microsoft-Windows-Shell-Core` (New startup folder shortcut or binary placed in Startup directory).
11. **T1059.003 Windows Command Shell** — Detects interactive or scripted abuse of cmd.exe, batch files, or shell invocation chains. Focuses on parent-child relationships (e.g., cmd.exe launched from unusual parents), anomalous command-line parameters, and chaining with discovery, credential access,… Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=7), `EDR:scriptblock` (Process Tree + Script Block Logging).
12. **T1204.002 Malicious File** — User opens a file delivered by email, web, chat, or share. The handler application (Word/PDF reader/archiver) creates a file in user-controlled paths (Downloads, Temp, Desktop) and then spawns a new or unusual child process (e.g., powershell.exe, wscript.exe,… Dados: `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=15).

## 10. OSINT — onde pesquisar

Consultas prontas com todos os nomes conhecidos do grupo:

- Relatórios técnicos: [busca web](https://duckduckgo.com/?q=%28%22Dark+Caracal%22%29+threat+report) · [PDFs](https://duckduckgo.com/?q=%28%22Dark+Caracal%22%29+filetype%3Apdf)
- Regras e IOCs publicados: [GitHub](https://github.com/search?type=code&q=%22Dark+Caracal%22)
- Pulsos de ameaça: [AlienVault OTX](https://otx.alienvault.com/browse/global/pulses?q=Dark+Caracal)
- Família de malware e atores: [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/actors) (busque por Dark Caracal)
- Cartões de grupo: [ThaiCERT Threat Group Cards](https://apt.etda.or.th/cgi-bin/listgroups.cgi)
- Página oficial: [MITRE ATT&CK G0070](https://attack.mitre.org/groups/G0070/)

**Relatórios na coleção CyberMonitor** (ligados pelo nome do grupo, conferir antes de citar):

- 2018 — [Lookout_Dark-Caracal_srr_20180118_us_v.1.0](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2018/2018.01.18.Dark_Caracal/Lookout_Dark-Caracal_srr_20180118_us_v.1.0.pdf) _(via “Dark Caracal”)_

## 11. Bibliografia (2 fontes citadas pelo ATT&CK)

- [CheckPoint Bandook Nov 2020](https://research.checkpoint.com/2020/bandook-signed-delivered/) — Check Point. (2020, November 26). Bandook: Signed & Delivered. Retrieved May 31, 2021.
- [Lookout Dark Caracal Jan 2018](https://info.lookout.com/rs/051-ESQ-475/images/Lookout_Dark-Caracal_srr_20180118_us_v.1.0.pdf) — Blaich, A., et al. (2018, January 18). Dark Caracal: Cyber-espionage at a Global Scale. Retrieved April 11, 2018.

## 12. Limites e confiança

- O ATT&CK registra o que foi **relatado publicamente**, não tudo o que o grupo faz. Ausência de uma técnica não prova que o grupo não a usa.
- **Sobreposição de TTP não é atribuição.** Muitas técnicas são compartilhadas entre grupos e com red teams. Use a assinatura comportamental como hipótese, junto com infraestrutura, malware e contexto.
- Cobertura de detecção refere-se ao catálogo público Detection Rules, não ao seu ambiente: confira se a telemetria necessária chega ao seu SIEM.
- Ligações marcadas como _inferidas_ (EVTX por palavra-chave, relatórios por nome) devem ser verificadas.

---
Fontes: MITRE ATT&CK® (uso livre com atribuição, © The MITRE Corporation), Atomic Red Team (Red Canary, MIT), EVTX-to-MITRE-Attack, EVTX-ATTACK-SAMPLES, APT & CyberCriminal Campaign Collections. Gerado por [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules).
