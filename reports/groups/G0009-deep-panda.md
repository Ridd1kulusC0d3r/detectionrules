# Deep Panda (G0009) — Dossiê de inteligência

> **TLP:CLEAR** · gerado em 2026-10-26 a partir de fontes abertas · MITRE ATT&CK v20.0 · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0009) · [ATT&CK](https://attack.mitre.org/groups/G0009/)

**Também conhecido como:** Shell Crew, WebMasters, KungFu Kittens, PinkPanther, Black Vine  
**Origem atribuída:** China · **Motivação:** indefinido · **Setores-alvo:** —  
**Registro no ATT&CK:** criado em 2017-05-31, atualizado em 2026-07-31 · referências de 2014 a 2017

## 1. Sumário executivo

- **10 técnicas** atribuídas publicamente, concentradas em **Stealth, Discovery, Execution**.
- **Arsenal:** 4 malware e 3 ferramentas (ex.: Derusbi, Net, Sakula, StreamEx, Mivast).
- **Campanhas atribuídas:** 0.
- **Cobertura de detecção pública:** 100% das técnicas têm ao menos uma regra no catálogo; **0 técnicas sem nenhuma regra pública**.
- **Origem e alvos (APT4ALL):** atribuído a **China**, motivação indefinido.
- **Onde a cobertura está:** Windows (10 técnicas com regra), EDR / XDR (9 técnicas com regra), Firewall & perímetro (6 técnicas com regra), DNS (6 técnicas com regra).
- **Assinatura comportamental** (técnicas raras entre os 178 grupos, as mais úteis para atribuição): T1546.008 Accessibility Features, T1027.005 Indicator Removal from Tools, T1218.010 Regsvr32, T1564.003 Hidden Window, T1021.002 SMB/Windows Admin Shares.

## 2. Quem é

> Deep Panda is a suspected Chinese threat group known to target many industries, including government, defense, financial, and telecommunications. The intrusion into healthcare company Anthem has been attributed to Deep Panda. This group is also known as Shell Crew, WebMasters, KungFu Kittens, and PinkPanther. Deep Panda also appears to be known as Black Vine based on the attribution of both group names to the Anthem intrusion. Some analysts track Deep Panda and APT19 as the same group, but it is unclear from open source information if the groups are the same.

_Texto original do MITRE ATT&CK, em inglês._

## 3. Contexto, nomes e alvos

Consolidado pelo [APT4ALL](https://github.com/Ridd1kulusC0d3r/apt4all) a partir de MISP Galaxy, planilha APT Groups & Operations, EternalLiberty e APTnotes. Atribuição é afirmação de quem publicou; confira a fonte.

| Campo | Valor |
|---|---|
| Origem atribuída | China |
| Motivação | indefinido |
| Setores-alvo | — |
| Vítimas citadas | — |
| Alvos (planilha) | — |
| Operações conhecidas | Anthem, OPM, Anthem Hack |
| Confiança de atribuição (MISP) | — |

**Como cada fornecedor chama este grupo** (útil para cruzar relatórios):

| Fornecedor | Nome(s) |
|---|---|
| Cisco Talos | Group 13 |
| CrowdStrike | Deep Panda |
| FireEye | KungFu Kittens |
| Kaspersky | WebMasters |
| MITRE ATT&CK | G0009 |
| Mandiant | APT19 |

**Outros nomes no APT4ALL (não listados pelo ATT&CK):** APT19, Group 13, Sh3llCr3w, Winnti Group

## 4. Perfil TTP por tática (kill chain)

Cada linha: técnica, como o grupo a usou segundo relatos públicos, e o que existe para detectar e testar.

### Execution (TA0002) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1047](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1047) Windows Management Instrumentation | The Deep Panda group is known to utilize WMI for lateral movement. | 370 | 12 | 11 |
| [T1059.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.001) PowerShell | Deep Panda has used PowerShell scripts to download and execute programs in memory, without writing to disk. | 1340 | 22 | 15 |

### Persistence (TA0003) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1505.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1505.003) Web Shell | Deep Panda uses Web shells on publicly accessible Web servers to access victim networks. | 210 | 1 | — |
| [T1546.008](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1546.008) Accessibility Features | Deep Panda has used the sticky-keys technique to bypass the RDP login screen on remote systems during intrusions. | 40 | 10 | — |

### Privilege Escalation (TA0004) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1546.008](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1546.008) Accessibility Features | Deep Panda has used the sticky-keys technique to bypass the RDP login screen on remote systems during intrusions. | 40 | 10 | — |

### Stealth (TA0005) — 3

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1027.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1027.005) Indicator Removal from Tools | Deep Panda has updated and modified its malware, resulting in different hash values that evade detection. | 24 | — | — |
| [T1218.010](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1218.010) Regsvr32 | Deep Panda has used regsvr32.exe to execute a server variant of Derusbi in victim networks. | 150 | 5 | 2 |
| [T1564.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1564.003) Hidden Window | Deep Panda has used -w hidden to conceal PowerShell windows by setting the WindowStyle parameter to hidden. | 51 | 3 | — |

### Discovery (TA0007) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1018](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1018) Remote System Discovery | Deep Panda has used ping to identify other machines of interest. | 157 | 23 | 1 |
| [T1057](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1057) Process Discovery | Deep Panda uses the Microsoft Tasklist utility to list processes running on systems. | 82 | 10 | — |

### Lateral Movement (TA0008) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1021.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1021.002) SMB/Windows Admin Shares | Deep Panda uses net.exe to connect to network shares using net use commands with compromised credentials. | 272 | 4 | 20 |

## 5. Assinatura comportamental

Técnicas que este grupo usa e que poucos dos 178 grupos do ATT&CK usam. Pesam mais numa atribuição por TTP: ver várias delas juntas é mais informativo do que ver técnicas comuns como PowerShell.

| Técnica | Outros grupos que usam | Peso (raridade) |
|---|---:|---:|
| T1546.008 Accessibility Features | 5 | 3.24 |
| T1027.005 Indicator Removal from Tools | 6 | 3.11 |
| T1218.010 Regsvr32 | 10 | 2.70 |
| T1564.003 Hidden Window | 18 | 2.19 |
| T1021.002 SMB/Windows Admin Shares | 27 | 1.82 |
| T1505.003 Web Shell | 30 | 1.72 |
| T1057 Process Discovery | 41 | 1.43 |
| T1018 Remote System Discovery | 42 | 1.40 |
| T1047 Windows Management Instrumentation | 42 | 1.40 |
| T1059.001 PowerShell | 85 | 0.72 |

## 6. Arsenal

| Software | Tipo | Técnicas no ATT&CK | Uso relatado (EN) |
|---|---|---:|---|
| [Derusbi](https://attack.mitre.org/software/S0021/) | malware | 18 |  |
| [Net](https://attack.mitre.org/software/S0039/) | ferramenta | 16 |  |
| [Sakula](https://attack.mitre.org/software/S0074/) | malware | 11 |  |
| [StreamEx](https://attack.mitre.org/software/S0142/) | malware | 9 |  |
| [Mivast](https://attack.mitre.org/software/S0080/) | malware | 4 |  |
| [Tasklist](https://attack.mitre.org/software/S0057/) | ferramenta | 3 |  |
| [Ping](https://attack.mitre.org/software/S0097/) | ferramenta | 1 |  |

**Outras ferramentas e malware relatados (planilha APT Groups & Operations / MISP):** Sakula/Sakurel, Scanbox Framework, many Webshells including China Chopper, WCE

## 7. Campanhas

Nenhuma campanha atribuída no ATT&CK.

## 8. Cobertura defensiva

**10 de 10 técnicas (100%)** têm ao menos uma regra pública no catálogo Detection Rules.

### Onde procurar — cobertura por tecnologia

Quantas técnicas deste grupo têm ao menos uma regra em cada tecnologia. Comece a caça pelas tecnologias que você tem e que aparecem aqui.

| Tecnologia | Técnicas do grupo com regra |
|---|---:|
| Windows | 10 |
| EDR / XDR | 9 |
| Firewall & perímetro | 6 |
| DNS | 6 |
| Outros / genérico | 6 |
| macOS | 5 |
| IDS / NSM / NDR | 5 |
| VPN & acesso remoto | 5 |
| Servidores web & aplicações | 5 |
| Proxy / SWG | 5 |
| Linux | 4 |
| Active Directory | 4 |

### Regras recomendadas por técnica

Melhor regra disponível por técnica (formato portável e maduro primeiro).

| Técnica | Regra | Formato | Fonte |
|---|---|---|---|
| T1018 | [Chopper Webshell Process Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Afa3c117a-bc0d-416e-a31b-0c0e80653efb) | Sigma | SigmaHQ |
| T1018 | [Webshell Hacking Activity Patterns](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4ebc877f-4612-45cb-b3a5-8e3834db36c9) | Sigma | SigmaHQ |
| T1021.002 | [PSExec Lateral Movement](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=hayabusa-native%3A%3A0694c340-3a46-40ac-acfc-c3444ae6572c) | Sigma | Hayabusa (native) |
| T1021.002 | [Turla Group Lateral Movement](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac601f20d-570a-4cde-a7d6-e17f99cb8e7f) | Sigma | SigmaHQ |
| T1027.005 | [PUA - DefenderCheck Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Af0ca6c24-3225-47d5-b1f5-352bf07ecfa7) | Sigma | SigmaHQ |
| T1027.005 | [HackTool - CrackMapExec PowerShell Obfuscation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A6f8b3439-a203-45dc-a88b-abf57ea15ccf) | Sigma | SigmaHQ |
| T1047 | [HackTool - Potential Impacket Lateral Movement Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A10c14723-61c7-4c75-92ca-9af245723ad2) | Sigma | SigmaHQ |
| T1047 | [CrackMapExec Command Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A058f4380-962d-40a5-afce-50207d36d7e2) | Sigma | OpenSearch Security Analytics |
| T1057 | [Process Discovery](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4e2f5868-08d4-413d-899f-dc2f1508627b) | Sigma | SigmaHQ |
| T1057 | [HackTool - PCHunter Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Afca949cc-79ca-446e-8064-01aa7e52ece5) | Sigma | SigmaHQ |
| T1059.001 | [Potential Emotet Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad02e8cf5-6099-48cf-9bfc-1eec2d0c7b18) | Sigma | SigmaHQ |
| T1059.001 | [TropicTrooper Campaign November 2018](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A8c7090c3-e0a0-4944-bd08-08c3a0cecf79) | Sigma | SigmaHQ |
| T1218.010 | [Potential EmpireMonkey Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A10152a7b-b566-438f-a33c-390b607d1c8d) | Sigma | SigmaHQ |
| T1218.010 | [Suspicious Microsoft Office Child Process](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A438025f9-5856-4663-83f7-52f878a70a50) | Sigma | SigmaHQ |
| T1505.003 | [MOVEit CVE-2023-34362 Exploitation Attempt - Potential Web Shell Request](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A435e41f2-48eb-4c95-8a2b-ed24b50ec30b) | Sigma | SigmaHQ |
| T1505.003 | [Solarwinds SUPERNOVA Webshell Access](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aa2cee20b-eacc-459f-861d-c02e5d12f1db) | Sigma | SigmaHQ |
| T1546.008 | [Suspicious Debugger Registration Cmdline](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aae215552-081e-44c7-805f-be16f975c8a2) | Sigma | SigmaHQ |
| T1546.008 | [Sticky Key Like Backdoor Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A2fdefcb3-dbda-401e-ae23-f0db027628bc) | Sigma | SigmaHQ |
| T1564.003 | [Potential Data Stealing Via Chromium Headless Debugging](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A3e8207c5-fcd2-4ea6-9418-15d45b4890e4) | Sigma | SigmaHQ |
| T1564.003 | [HackTool - Covenant PowerShell Launcher](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac260b6db-48ba-4b4a-a76f-2f67644e99d2) | Sigma | SigmaHQ |

## 9. Plano de emulação e validação

Use num laboratório isolado e autorizado para confirmar que as regras disparam. Os comandos estão nos repositórios oficiais.

| Tática | Técnica | Teste Atomic Red Team | Plataformas |
|---|---|---|---|
| Execution | [T1047](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1047/T1047.md) | WMI Reconnaissance Users | windows |
| Execution | [T1047](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1047/T1047.md) | WMI Reconnaissance Processes | windows |
| Execution | [T1059.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md) | Mimikatz | windows |
| Execution | [T1059.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md) | Run BloodHound from local disk | windows |
| Persistence | [T1505.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1505.003/T1505.003.md) | Web Shell Written to Disk | windows |
| Privilege Escalation | [T1546.008](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1546.008/T1546.008.md) | Attaches Command Prompt as a Debugger to a List of Target Processes | windows |
| Privilege Escalation | [T1546.008](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1546.008/T1546.008.md) | Replace binary of sticky keys | windows |
| Stealth | [T1218.010](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.010/T1218.010.md) | Regsvr32 local COM scriptlet execution | windows |
| Stealth | [T1218.010](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.010/T1218.010.md) | Regsvr32 remote COM scriptlet execution | windows |
| Stealth | [T1564.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1564.003/T1564.003.md) | Hidden Window | windows |
| Stealth | [T1564.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1564.003/T1564.003.md) | Headless Browser Accessing Mockbin | windows |
| Discovery | [T1018](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1018/T1018.md) | Remote System Discovery - net | windows |
| Discovery | [T1018](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1018/T1018.md) | Remote System Discovery - net group Domain Computers | windows |
| Discovery | [T1057](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1057/T1057.md) | Process Discovery - ps | linux, macos |
| Discovery | [T1057](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1057/T1057.md) | Process Discovery - tasklist | windows |
| Lateral Movement | [T1021.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.002/T1021.002.md) | Map admin share | windows |
| Lateral Movement | [T1021.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.002/T1021.002.md) | Map Admin Share PowerShell | windows |

**Logs reais de ataque (EVTX) para testar sem executar nada:**

- T1018 — [ID5145-DNS hosts files access via network share](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1018-Remote%20System%20Discovery/ID5145-DNS%20hosts%20files%20access%20via%20network%20share.evtx) _(explícito)_
- T1021.002 — [ID4688,4697,5140-5145 PSexec remote execution + admin share](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0008-Lateral%20Movement/T1021.002-SMB%20Windows%20Admin%20Shares/ID4688%2C4697%2C5140-5145%20PSexec%20remote%20execution%20%2B%20admin%20share.evtx) _(explícito)_
- T1021.002 — [ID4688-4648 Lateral movement with net use](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0008-Lateral%20Movement/T1021.002-SMB%20Windows%20Admin%20Shares/ID4688-4648%20Lateral%20movement%20with%20net%20use.evtx) _(explícito)_
- T1047 — [ID1-WMI spwaning PowerShell process - WMImplant](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1047-Windows%20Management%20Instrumentation/ID1-WMI%20spwaning%20PowerShell%20process%20-%20WMImplant.evtx) _(explícito)_
- T1047 — [ID1-WMIexec process execution](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1047-Windows%20Management%20Instrumentation/ID1-WMIexec%20process%20execution.evtx) _(explícito)_
- T1059.001 — [ID4103-4104-Payload download via PowerShell](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1059.001-PowerShell/ID4103-4104-Payload%20download%20via%20PowerShell.evtx) _(explícito)_
- T1059.001 — [ID4688-Encoded PowerShell MSF payload via process execution](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1059.001-PowerShell/ID4688-Encoded%20PowerShell%20MSF%20payload%20via%20process%20execution.evtx) _(explícito)_
- T1218.010 — [exec_sysmon_1_lolbin_renamed_regsvr32_scrobj](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Execution/exec_sysmon_1_lolbin_renamed_regsvr32_scrobj.evtx) _(inferido)_
- T1218.010 — [exec_sysmon_lobin_regsvr32_sct](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Execution/exec_sysmon_lobin_regsvr32_sct.evtx) _(inferido)_

## 10. Hipóteses de hunting

Se Deep Panda estiver no seu ambiente, estas são as perguntas a fazer aos seus dados (fontes de log segundo as estratégias de detecção do MITRE ATT&CK).

1. **T1546.008 Accessibility Features** — Defenders can observe suspicious replacement or tampering of system accessibility binaries (e.g., utilman.exe, sethc.exe, osk.exe) and anomalous modifications to registry keys used to redirect accessibility programs (such as IFEO keys). Additionally,… Dados: `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=13, 14).
2. **T1027.005 Indicator Removal from Tools** — Detection of known tools or malware flagged by antivirus, followed by a near-term drop of a similar binary with modified signature and resumed activity (execution, C2, or persistence). Dados: `WinEventLog:Application` (EventCode=1000), `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=11).
3. **T1218.010 Regsvr32** — Detection focuses on identifying anomalous regsvr32.exe executions that deviate from normal administrative or system use. Defenders may observe regsvr32.exe loading scriptlets or DLLs from unusual paths (especially temporary directories or remote URLs),… Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=7), `WinEventLog:Sysmon` (EventCode=3, 22).
4. **T1564.003 Hidden Window** — Suspicious use of scripting parameters or registry edits to hide process windows (e.g., powershell.exe -WindowStyle Hidden, or registry modifications pushing window positions off screen). Defender view: correlation of hidden execution with anomalous process… Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=13, 14).
5. **T1021.002 SMB/Windows Admin Shares** — An SMB-based remote file share access followed by lateral movement actions such as remote service creation, task scheduling, or suspicious process execution on the target host using ADMIN$ or C$ shares. Dados: `WinEventLog:Security` (EventCode=4624, 4648), `WinEventLog:Sysmon` (EventCode=3, 22), `WinEventLog:Sysmon` (EventCode=1).
6. **T1505.003 Web Shell** — Unexpected file creation in web directories followed by web server processes (e.g., w3wp.exe) spawning command shells or script interpreters (e.g., cmd.exe, powershell.exe) Dados: `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Security` (EventCode=4624, 4648).
7. **T1057 Process Discovery** — Identifies adversary behavior that launches commands or invokes APIs to enumerate active processes (e.g., tasklist.exe, Get-Process, or CreateToolhelp32Snapshot). Detects execution combined with parent process lineage, network session context, or remote… Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=10).
8. **T1018 Remote System Discovery** — Execution of network enumeration utilities (e.g., net.exe, ping.exe, tracert.exe) in short succession, often chained with lateral movement tools or system enumeration commands. Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=3, 22).
9. **T1047 Windows Management Instrumentation** — Detects adversarial abuse of WMI to execute local or remote commands via WMIC, PowerShell, or COM API through a multi-event chain: process creation, command execution, and corresponding network connection if remote. Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=3, 22), `WinEventLog:WMI` (EventCode=5857, 5858, 5860, 5861).
10. **T1059.001 PowerShell** — Detects behavioral chains where PowerShell is launched with encoded commands, unusual parent processes, or suspicious modules loaded, potentially followed by network connections or child process spawning. Supports detection of both direct (powershell.exe) and… Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:PowerShell` (EventCode=4103, 4104, 4105, 4106), `WinEventLog:PowerShell` (EventCode=400, 403).

## 11. OSINT — onde pesquisar

Consultas prontas com todos os nomes conhecidos do grupo:

- Relatórios técnicos: [busca web](https://duckduckgo.com/?q=%28%22Deep+Panda%22+OR+%22Shell+Crew%22+OR+%22WebMasters%22+OR+%22KungFu+Kittens%22+OR+%22PinkPanther%22+OR+%22Black+Vine%22%29+threat+report) · [PDFs](https://duckduckgo.com/?q=%28%22Deep+Panda%22+OR+%22Shell+Crew%22+OR+%22WebMasters%22+OR+%22KungFu+Kittens%22+OR+%22PinkPanther%22+OR+%22Black+Vine%22%29+filetype%3Apdf)
- Regras e IOCs publicados: [GitHub](https://github.com/search?type=code&q=%22Deep+Panda%22+OR+%22Shell+Crew%22+OR+%22WebMasters%22+OR+%22KungFu+Kittens%22+OR+%22PinkPanther%22+OR+%22Black+Vine%22)
- Pulsos de ameaça: [AlienVault OTX](https://otx.alienvault.com/browse/global/pulses?q=Deep+Panda)
- Família de malware e atores: [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/actors) (busque por Deep Panda, Shell Crew, WebMasters)
- Cartões de grupo: [ThaiCERT Threat Group Cards](https://apt.etda.or.th/cgi-bin/listgroups.cgi)
- Página oficial: [MITRE ATT&CK G0009](https://attack.mitre.org/groups/G0009/)

**Relatórios na coleção CyberMonitor** (ligados pelo nome do grupo, conferir antes de citar):

- 2013 — [crowdstrike-deep-panda-report](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2013/2013.00.00.Deep.Panda/crowdstrike-deep-panda-report.pdf) _(via “Deep Panda”)_
- 2014 — [h12756-wp-shell-crew](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2014/2014.01.21.Shell_Crew/h12756-wp-shell-crew.pdf) _(via “Shell Crew”)_
- 2014 — [deep-panda-webshells](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2014/2014.02.20.deep-panda-webshells/deep-panda-webshells.pdf) _(via “Deep Panda”)_
- 2014 — [DEEP_PANDA_Sakula](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2014/2014.11.24.Ironman/DEEP_PANDA_Sakula.pdf) _(via “Deep Panda”)_
- 2014 — [ironman-deep-panda-uses-sakula-malware-target-organizations-multiple-sectors](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2014/2014.11.24.Ironman/ironman-deep-panda-uses-sakula-malware-target-organizations-multiple-sectors.pdf) _(via “Deep Panda”)_
- 2015 — [the-black-vine-cyberespionage-group](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2015/2015.07.28.Black_Vine/the-black-vine-cyberespionage-group.pdf) _(via “Black Vine”)_
- 2022 — [New Milestones for Deep Panda_ Log4Shell and Digitally Signed Fire Chili Rootkits](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2022/2022.03.30.Deep_Panda_New_Milestones/New%20Milestones%20for%20Deep%20Panda_%20Log4Shell%20and%20Digitally%20Signed%20Fire%20Chili%20Rootkits.pdf) _(via “Deep Panda”)_

**Relatórios públicos ligados pelo APT4ALL** (5 no total, mais recentes primeiro):

- 2022 — [New Milestones for Deep Panda: Log4Shell and Digitally Signed Fire Chili Rootkits](https://app.box.com/s/y1uuj9no6pq6acfcne8lb1laj23jyxtj) _(Fortinet)_
- 2015 — [The Black Vine Cyberespionage Group](https://app.box.com/s/0ahidgtzecyx94hgvxoai9kmu5r6yw49) _(Symantec)_
- 2014 — [I Am Ironman: Deep Panda Uses Sakula Malware To Target Organizations In Multiple Sectors](https://app.box.com/s/4dfaheem1io3i71o51rf4lfo2ivotuol) _(Crowdstrike)_
- 2014 — [Mo' Shells Mo' Problems - Deep Panda Web Shells](https://app.box.com/s/pn1mtot3a2d2seuqx46unamdl7udlwq0) _(Crowdstrike)_
- 2013 — [Deep Panda](https://app.box.com/s/6po2pgedkjf4br5p7tm51go7p5g3z6g3) _(Crowdstrike)_

## 12. Bibliografia (7 fontes citadas pelo ATT&CK)

- [Alperovitch 2014](https://web.archive.org/web/20200424075623/https:/www.crowdstrike.com/blog/deep-thought-chinese-targeting-national-security-think-tanks/) — Alperovitch, D. (2014, July 7). Deep in Thought: Chinese Targeting of National Security Think Tanks. Retrieved November 12, 2014.
- [CrowdStrike Deep Panda Web Shells](http://www.crowdstrike.com/blog/mo-shells-mo-problems-deep-panda-web-shells/) — RYANJ. (2014, February 20). Mo’ Shells Mo’ Problems – Deep Panda Web Shells. Retrieved September 16, 2015.
- [Cylance Shell Crew Feb 2017](https://www.cylance.com/shell-crew-variants-continue-to-fly-under-big-avs-radar) — Cylance SPEAR Team. (2017, February 9). Shell Crew Variants Continue to Fly Under Big AV’s Radar. Retrieved February 15, 2017.
- [ICIT China's Espionage Jul 2016](https://web.archive.org/web/20171017072306/https://icitech.org/icit-brief-chinas-espionage-dynasty-economic-death-by-a-thousand-cuts/) — Scott, J. and Spaniel, D. (2016, July 28). ICIT Brief - China’s Espionage Dynasty: Economic Death by a Thousand Cuts. Retrieved June 7, 2018.
- [RSA Shell Crew](https://www.rsa.com/content/dam/en/white-paper/rsa-incident-response-emerging-threat-profile-shell-crew.pdf) — RSA Incident Response. (2014, January). RSA Incident Response Emerging Threat Profile: Shell Crew. Retrieved January 14, 2016.
- [Symantec Black Vine](https://web.archive.org/web/20170823094836/http:/www.symantec.com/content/en/us/enterprise/media/security_response/whitepapers/the-black-vine-cyberespionage-group.pdf) — DiMaggio, J.. (2015, August 6). The Black Vine cyberespionage group. Retrieved January 26, 2016.
- [ThreatConnect Anthem](https://www.threatconnect.com/the-anthem-hack-all-roads-lead-to-china/) — ThreatConnect Research Team. (2015, February 27). The Anthem Hack: All Roads Lead to China. Retrieved January 26, 2016.

## 13. Limites e confiança

- O ATT&CK registra o que foi **relatado publicamente**, não tudo o que o grupo faz. Ausência de uma técnica não prova que o grupo não a usa.
- **Sobreposição de TTP não é atribuição.** Muitas técnicas são compartilhadas entre grupos e com red teams. Use a assinatura comportamental como hipótese, junto com infraestrutura, malware e contexto.
- Cobertura de detecção refere-se ao catálogo público Detection Rules, não ao seu ambiente: confira se a telemetria necessária chega ao seu SIEM.
- Ligações marcadas como _inferidas_ (EVTX por palavra-chave, relatórios por nome) devem ser verificadas.

---
Fontes: MITRE ATT&CK® (uso livre com atribuição, © The MITRE Corporation), APT4ALL (MISP Galaxy CC0/BSD-2, APT Groups & Operations CC BY 4.0, EternalLiberty, APTnotes, Ransomware Tool Matrix CC BY 4.0), Atomic Red Team (Red Canary, MIT), EVTX-to-MITRE-Attack, EVTX-ATTACK-SAMPLES, APT & CyberCriminal Campaign Collections. Gerado por [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules).
