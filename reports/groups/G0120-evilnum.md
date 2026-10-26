# Evilnum (G0120) — Dossiê de inteligência

> **TLP:CLEAR** · gerado em 2026-10-26 a partir de fontes abertas · MITRE ATT&CK v20.0 · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0120) · [ATT&CK](https://attack.mitre.org/groups/G0120/)

**Também conhecido como:** —  
**Origem atribuída:** Sem país atribuído · **Motivação:** financeiro · **Setores-alvo:** —  
**Registro no ATT&CK:** criado em 2021-01-22, atualizado em 2026-07-31 · referências de 2020 a 2020

## 1. Sumário executivo

- **11 técnicas** atribuídas publicamente, concentradas em **Execution, Stealth, Command and Control**.
- **Arsenal:** 2 malware e 1 ferramentas (ex.: More_eggs, EVILNUM, LaZagne).
- **Campanhas atribuídas:** 0.
- **Cobertura de detecção pública:** 100% das técnicas têm ao menos uma regra no catálogo; **0 técnicas sem nenhuma regra pública**.
- **Origem e alvos (APT4ALL):** atribuído a **Sem país atribuído**, motivação financeiro.
- **Onde a cobertura está:** Windows (11 técnicas com regra), EDR / XDR (11 técnicas com regra), Linux (10 técnicas com regra), macOS (9 técnicas com regra).
- **Assinatura comportamental** (técnicas raras entre os 178 grupos, as mais úteis para atribuição): T1497.001 System Checks, T1539 Steal Web Session Cookie, T1548.002 Bypass User Account Control, T1219.002 Remote Desktop Software, T1555 Credentials from Password Stores.

## 2. Quem é

> Evilnum is a financially motivated threat group that has been active since at least 2018.

_Texto original do MITRE ATT&CK, em inglês._

## 3. Contexto, nomes e alvos

Consolidado pelo [APT4ALL](https://github.com/Ridd1kulusC0d3r/apt4all) a partir de MISP Galaxy, planilha APT Groups & Operations, EternalLiberty e APTnotes. Atribuição é afirmação de quem publicou; confira a fonte.

| Campo | Valor |
|---|---|
| Origem atribuída | Sem país atribuído |
| Motivação | financeiro |
| Setores-alvo | — |
| Vítimas citadas | — |
| Alvos (planilha) | — |
| Operações conhecidas | — |
| Confiança de atribuição (MISP) | High |

**Como cada fornecedor chama este grupo** (útil para cruzar relatórios):

| Fornecedor | Nome(s) |
|---|---|
| MITRE ATT&CK | G0120 |

**Outros nomes no APT4ALL (não listados pelo ATT&CK):** Decepticons, DeathStalker, TA4563, Jointworm, KNOCKOUT SPIDER

## 4. Perfil TTP por tática (kill chain)

Cada linha: técnica, como o grupo a usou segundo relatos públicos, e o que existe para detectar e testar.

### Initial Access (TA0001) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1566.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1566.002) Spearphishing Link | Evilnum has sent spearphishing emails containing a link to a zip file hosted on Google Drive. | 138 | 1 | — |

### Execution (TA0002) — 3

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1059.007](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.007) JavaScript | Evilnum has used malicious JavaScript files on the victim's machine. | 205 | 5 | — |
| [T1204.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1204.001) Malicious Link | Evilnum has sent spearphishing emails designed to trick the recipient into opening malicious shortcut links which downloads a .LNK file. | 52 | — | — |
| [T1574.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1574.001) DLL | Evilnum has used the malware variant, TerraTV, to load a malicious DLL placed in the TeamViewer directory, instead of the original Windows DLL located in a system folder. | 455 | 7 | 5 |

### Privilege Escalation (TA0004) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1548.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1548.002) Bypass User Account Control | Evilnum has used PowerShell to bypass UAC. | 379 | 28 | 14 |

### Stealth (TA0005) — 3

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1070.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1070.004) File Deletion | Evilnum has deleted files used during infection. | 132 | 11 | — |
| [T1497.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1497.001) System Checks | Evilnum has used a component called TerraLoader to check certain hardware and file information to detect sandboxed environments. | 16 | 9 | — |
| [T1574.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1574.001) DLL | Evilnum has used the malware variant, TerraTV, to load a malicious DLL placed in the TeamViewer directory, instead of the original Windows DLL located in a system folder. | 455 | 7 | 5 |

### Credential Access (TA0006) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1539](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1539) Steal Web Session Cookie | Evilnum can steal cookies and session information from browsers. | 54 | 5 | — |
| [T1555](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1555) Credentials from Password Stores | Evilnum can collect email credentials from victims. | 160 | 9 | 2 |

### Discovery (TA0007) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1497.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1497.001) System Checks | Evilnum has used a component called TerraLoader to check certain hardware and file information to detect sandboxed environments. | 16 | 9 | — |

### Command and Control (TA0011) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1105](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1105) Ingress Tool Transfer | Evilnum can deploy additional components or tools as needed. | 644 | 39 | — |
| [T1219.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1219.002) Remote Desktop Software | EVILNUM has used the malware variant, TerraTV, to run a legitimate TeamViewer application to connect to compromised machines. | 221 | — | — |

## 5. Assinatura comportamental

Técnicas que este grupo usa e que poucos dos 178 grupos do ATT&CK usam. Pesam mais numa atribuição por TTP: ver várias delas juntas é mais informativo do que ver técnicas comuns como PowerShell.

| Técnica | Outros grupos que usam | Peso (raridade) |
|---|---:|---:|
| T1497.001 System Checks | 6 | 3.11 |
| T1539 Steal Web Session Cookie | 7 | 2.99 |
| T1548.002 Bypass User Account Control | 10 | 2.70 |
| T1219.002 Remote Desktop Software | 11 | 2.62 |
| T1555 Credentials from Password Stores | 12 | 2.55 |
| T1059.007 JavaScript | 29 | 1.75 |
| T1574.001 DLL | 35 | 1.58 |
| T1070.004 File Deletion | 47 | 1.30 |
| T1566.002 Spearphishing Link | 47 | 1.30 |
| T1204.001 Malicious Link | 49 | 1.26 |

## 6. Arsenal

| Software | Tipo | Técnicas no ATT&CK | Uso relatado (EN) |
|---|---|---:|---|
| [More_eggs](https://attack.mitre.org/software/S0284/) | malware | 15 |  |
| [EVILNUM](https://attack.mitre.org/software/S0568/) | malware | 14 |  |
| [LaZagne](https://attack.mitre.org/software/S0349/) | ferramenta | 10 |  |

## 7. Campanhas

Nenhuma campanha atribuída no ATT&CK.

## 8. Cobertura defensiva

**11 de 11 técnicas (100%)** têm ao menos uma regra pública no catálogo Detection Rules.

### Onde procurar — cobertura por tecnologia

Quantas técnicas deste grupo têm ao menos uma regra em cada tecnologia. Comece a caça pelas tecnologias que você tem e que aparecem aqui.

| Tecnologia | Técnicas do grupo com regra |
|---|---:|
| Windows | 11 |
| EDR / XDR | 11 |
| Linux | 10 |
| macOS | 9 |
| VPN & acesso remoto | 8 |
| Servidores web & aplicações | 8 |
| AWS | 7 |
| Microsoft 365 | 7 |
| IA, LLMs & agentes | 7 |
| Outros / genérico | 7 |
| Firewall & perímetro | 6 |
| DNS | 6 |

### Regras recomendadas por técnica

Melhor regra disponível por técnica (formato portável e maduro primeiro).

| Técnica | Regra | Formato | Fonte |
|---|---|---|---|
| T1059.007 | [Adwind RAT / JRAT](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1fac1481-2dbc-48b2-9096-753c49b4ec71) | Sigma | SigmaHQ |
| T1059.007 | [WScript or CScript Dropper - File](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A002bdb95-0cf1-46a6-9e08-d38c128a6127) | Sigma | SigmaHQ |
| T1070.004 | [File Deletion](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A30aed7b6-d2c1-4eaf-9382-b6bc43e50c57) | Sigma | SigmaHQ |
| T1070.004 | [Prefetch File Deleted](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A0a1f9d29-6465-4776-b091-7f43b26e4c89) | Sigma | SigmaHQ |
| T1105 | [Greenbug Espionage Group Indicators](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A3711eee4-a808-4849-8a14-faf733da3612) | Sigma | SigmaHQ |
| T1105 | [Pandemic Registry Key](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A47e0852a-cf81-4494-a8e6-31864f8c86ed) | Sigma | SigmaHQ |
| T1204.001 | [Google Workspace Object Copied from External Drive with App Consent](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Af33e68a4-bd19-11ed-b02f-f661ea17fbcc) | Elastic | Elastic detection-rules |
| T1204.001 | [Suspicious ClickFix/FileFix Execution Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad487ed4a-fd24-436d-a0b2-f4e95f7b2635) | Sigma | SigmaHQ |
| T1219.002 | [Antivirus - Exploitation Framework Signature](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A238527ad-3c2c-4e4f-a1f6-92fd63adb864) | Sigma | SigmaHQ |
| T1219.002 | [Potential SocGholish Second Stage C2 DNS Query](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A70761fe8-6aa2-4f80-98c1-a57049c08e66) | Sigma | SigmaHQ |
| T1497.001 | [Virtual Machine Fingerprinting](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A5b03c9fb-9945-4d2f-9568-fd690fee3fba) | Elastic | Elastic detection-rules |
| T1497.001 | [Powershell Detect Virtualization Environment](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad93129cd-1ee0-479f-bc03-ca6f129882e3) | Sigma | SigmaHQ |
| T1539 | [SQLite Firefox Profile Data DB Access](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4833155a-4053-4c9c-a997-777fcea0baa7) | Sigma | SigmaHQ |
| T1539 | [SQLite Chromium Profile Data DB Access](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A24c77512-782b-448a-8950-eddb0785fc71) | Sigma | SigmaHQ |
| T1548.002 | [CMSTP UAC Bypass via COM Object Access](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4b60e6f2-bf39-47b4-b4ea-398e33cfe253) | Sigma | SigmaHQ |
| T1548.002 | [HackTool - Empire PowerShell UAC Bypass](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A3268b746-88d8-4cd3-bffc-30077d02c787) | Sigma | SigmaHQ |
| T1555 | [HackTool - SecurityXploded Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A7679d464-4f74-45e2-9e01-ac66c5eb041a) | Sigma | SigmaHQ |
| T1555 | [SecurityXploded Tool](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A7679d464-4f74-45e2-9e01-ac66c5eb041a) | Sigma | OpenSearch Security Analytics |
| T1566.002 | [Potential Malicious Usage of CloudTrail System Manager](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A38e7f511-3f74-41d4-836e-f57dfa18eead) | Sigma | SigmaHQ |
| T1566.002 | [Google Workspace Device Registration After OAuth from Suspicious ASN](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A012bfca7-45cb-4507-a3ba-3777167f8b81) | Elastic | Elastic detection-rules |
| T1574.001 | [Winnti Pipemon Characteristics](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A73d70463-75c9-4258-92c6-17500fe972f2) | Sigma | SigmaHQ |
| T1574.001 | [Winnti Pipemon Characteristics](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A73d70463-75c9-4258-92c6-17500fe972f2) | Sigma | OpenSearch Security Analytics |

## 9. Plano de emulação e validação

Use num laboratório isolado e autorizado para confirmar que as regras disparam. Os comandos estão nos repositórios oficiais.

| Tática | Técnica | Teste Atomic Red Team | Plataformas |
|---|---|---|---|
| Initial Access | [T1566.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1566.002/T1566.002.md) | Paste and run technique | windows |
| Execution | [T1059.007](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.007/T1059.007.md) | JScript execution to gather local computer information via cscript | windows |
| Execution | [T1059.007](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.007/T1059.007.md) | JScript execution to gather local computer information via wscript | windows |
| Privilege Escalation | [T1548.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1548.002/T1548.002.md) | Bypass UAC using Event Viewer (cmd) | windows |
| Privilege Escalation | [T1548.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1548.002/T1548.002.md) | Bypass UAC using Event Viewer (PowerShell) | windows |
| Stealth | [T1070.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.004/T1070.004.md) | Delete a single file - FreeBSD/Linux/macOS | linux, macos |
| Stealth | [T1070.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.004/T1070.004.md) | Delete an entire folder - FreeBSD/Linux/macOS | linux, macos |
| Stealth | [T1497.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1497.001/T1497.001.md) | Detect Virtualization Environment (Linux) | linux |
| Stealth | [T1497.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1497.001/T1497.001.md) | Detect Virtualization Environment (FreeBSD) | linux |
| Stealth | [T1574.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1574.001/T1574.001.md) | DLL Search Order Hijacking - amsi.dll | windows |
| Stealth | [T1574.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1574.001/T1574.001.md) | Phantom Dll Hijacking - WinAppXRT.dll | windows |
| Credential Access | [T1539](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1539/T1539.md) | Steal Firefox Cookies (Windows) | windows |
| Credential Access | [T1539](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1539/T1539.md) | Steal Chrome Cookies (Windows) | windows |
| Credential Access | [T1555](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1555/T1555.md) | Extract Windows Credential Manager via VBA | windows |
| Credential Access | [T1555](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1555/T1555.md) | Dump credentials from Windows Credential Manager With PowerShell [windows Credentials] | windows |
| Command and Control | [T1105](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1105/T1105.md) | rsync remote file copy (push) | linux, macos |
| Command and Control | [T1105](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1105/T1105.md) | rsync remote file copy (pull) | linux, macos |

**Logs reais de ataque (EVTX) para testar sem executar nada:**

- T1548.002 — [sideloading_uacbypass_rundll32_injection_c2](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/AutomatedTestingTools/Malware/sideloading_uacbypass_rundll32_injection_c2.evtx) _(inferido)_
- T1548.002 — [Invoke_TokenDuplication_UAC_Bypass4624](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Privilege%20Escalation/Invoke_TokenDuplication_UAC_Bypass4624.evtx) _(inferido)_
- T1555 — [ID4662-Sensitve DPAPI attributes accessed](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0006-Credential%20Access/T1555-Credentials%20from%20Password%20Stores/ID4662-Sensitve%20DPAPI%20attributes%20accessed.evtx) _(explícito)_
- T1555 — [ID5145-user file-credentials-browser dump via network share](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0006-Credential%20Access/T1555-Credentials%20from%20Password%20Stores/ID5145-user%20file-credentials-browser%20dump%20via%20network%20share.evtx) _(explícito)_
- T1574.001 — [DE_timestomp_and_dll_sideloading_and_RunPersist](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/AutomatedTestingTools/Malware/DE_timestomp_and_dll_sideloading_and_RunPersist.evtx) _(inferido)_
- T1574.001 — [sideloading_injection_persistence_run_key](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/AutomatedTestingTools/Malware/sideloading_injection_persistence_run_key.evtx) _(inferido)_

## 10. Hipóteses de hunting

Se Evilnum estiver no seu ambiente, estas são as perguntas a fazer aos seus dados (fontes de log segundo as estratégias de detecção do MITRE ATT&CK).

1. **T1497.001 System Checks** — Script or binary performs a rapid sequence of system discovery checks (e.g., CPU count, RAM size, registry keys, running processes) indicative of VM detection Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=7), `WinEventLog:Sysmon` (EventCode=10).
2. **T1539 Steal Web Session Cookie** — Detects suspicious access to browser session cookie storage (e.g., Chrome’s `Cookies` SQLite DB) or memory reads of browser processes. Anomalous injection or memory dump utilities targeting browser processes such as `chrome.exe`, `firefox.exe`, or… Dados: `WinEventLog:Sysmon` (EventCode=10), `WinEventLog:Sysmon` (EventCode=2), `WinEventLog:Security` (EventCode=4688).
3. **T1548.002 Bypass User Account Control** — Detects a multi-event behavior chain involving UAC bypass attempts via known auto-elevated binaries (e.g., eventvwr.exe, sdclt.exe), unauthorized Registry changes to UAC-related keys, and anomalous process execution with elevated privileges but lacking… Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:Security` (EventCode=4672), `WinEventLog:Sysmon` (EventCode=13, 14).
4. **T1219.002 Remote Desktop Software** — Adversary installation or use of RMM software (e.g., TeamViewer, AnyDesk, ScreenConnect) followed by outbound beaconing or remote session establishment Dados: `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Sysmon` (EventCode=3, 22), `WinEventLog:Microsoft-Windows-Windows Firewall With Advanced Security/Firewall` (new rule allowing inbound or outbound connections for remote desktop software).
5. **T1555 Credentials from Password Stores** — Monitors suspicious access to password stores such as LSASS, DPAPI, Windows Credential Manager, or browser credential databases. Detects anomalous process-to-process access (e.g., Mimikatz accessing LSASS) and correlation of credential store file reads with… Dados: `WinEventLog:Sysmon` (EventCode=10), `WinEventLog:Security` (EventCode=4663, 4670, 4656), `WinEventLog:Sysmon` (EventCode=1).
6. **T1059.007 JavaScript** — Detects JavaScript execution through WSH (wscript.exe, cscript.exe) or HTA (mshta.exe), particularly when spawned from Office macros, web browsers, or abnormal user paths. Correlates script execution with outbound network activity or system modification. Dados: `WinEventLog:Sysmon` (EventCode=1), `m365:defender` (ScriptBlockLogging + AMSI), `WinEventLog:Sysmon` (EventCode=7).
7. **T1574.001 DLL** — DLL hijacking behaviors including unexpected DLL loads from non-standard directories, replacement of DLLs, phantom DLL insertion, redirection file creation, and substitution of legitimate DLLs. Defender correlates file system modifications, registry changes,… Dados: `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Sysmon` (EventCode=15), `WinEventLog:Sysmon` (EventCode=7).
8. **T1070.004 File Deletion** — Detects adversary behavior deleting artifacts (e.g., dropped payloads, evidence files) using native or external utilities (e.g., del, erase, SDelete). Detects deletion events correlated with unusual process lineage or timing post-execution. Dados: `WinEventLog:Sysmon` (EventCode=23), `WinEventLog:Security` (EventCode=4663, 4670, 4656), `WinEventLog:PowerShell` (EventCode=4103, 4104, 4105, 4106).
9. **T1566.002 Spearphishing Link** — Correlation of inbound emails with embedded links followed by user-driven browser navigation to suspicious or obfuscated domains. Detection chain includes malicious URL in email → user click recorded in Office logs → browser process spawning unusual child… Dados: `m365:unified` (Send/Receive: Inbound emails containing embedded or shortened URLs), `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=3, 22).
10. **T1204.001 Malicious Link** — Behavioral chain: (1) a user-facing app (browser/Office/email client) launches a URL or handles a link, then (2) the same process lineage makes an outbound connection to an untrusted domain/IP, (3) a file is downloaded or unpacked to a user-writable location… Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=3, 22), `WinEventLog:Sysmon` (EventCode=11).
11. **T1105 Ingress Tool Transfer** — Unusual or uncommon processes initiate network connections to external destinations followed by file creation (tools downloaded). Dados: `WinEventLog:Sysmon` (EventCode=3, 22), `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Sysmon` (EventCode=1).

## 11. OSINT — onde pesquisar

Consultas prontas com todos os nomes conhecidos do grupo:

- Relatórios técnicos: [busca web](https://duckduckgo.com/?q=%28%22Evilnum%22%29+threat+report) · [PDFs](https://duckduckgo.com/?q=%28%22Evilnum%22%29+filetype%3Apdf)
- Regras e IOCs publicados: [GitHub](https://github.com/search?type=code&q=%22Evilnum%22)
- Pulsos de ameaça: [AlienVault OTX](https://otx.alienvault.com/browse/global/pulses?q=Evilnum)
- Família de malware e atores: [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/actors) (busque por Evilnum)
- Cartões de grupo: [ThaiCERT Threat Group Cards](https://apt.etda.or.th/cgi-bin/listgroups.cgi)
- Página oficial: [MITRE ATT&CK G0120](https://attack.mitre.org/groups/G0120/)

**Relatórios na coleção CyberMonitor** (ligados pelo nome do grupo, conferir antes de citar):

- 2020 — [Prevailion Blog_ Phantom in the Command Shell](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2020/2020.05.06_Phantom_EVILNUM/Prevailion%20Blog_%20Phantom%20in%20the%20Command%20Shell.pdf) _(via “Evilnum”)_
- 2020 — [IoCs](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2020/2020.07.09_Evilnum_Toolset/IoCs.pdf) _(via “Evilnum”)_
- 2020 — [More evil_ A deep look at Evilnum and its toolset _ WeLiveSecurity](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2020/2020.07.09_Evilnum_Toolset/More%20evil_%20A%20deep%20look%20at%20Evilnum%20and%20its%20toolset%20_%20WeLiveSecurity.pdf) _(via “Evilnum”)_
- 2020 — [Evilnum IOCs](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2020/2020.09.03.Evilnum_Pyvil/Evilnum%20IOCs.pdf) _(via “Evilnum”)_
- 2020 — [No Rest for the Wicked_ Evilnum Unleashes PyVil RAT](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2020/2020.09.03.Evilnum_Pyvil/No%20Rest%20for%20the%20Wicked_%20Evilnum%20Unleashes%20PyVil%20RAT.pdf) _(via “Evilnum”)_

## 12. Bibliografia (2 fontes citadas pelo ATT&CK)

- [ESET EvilNum July 2020](https://www.welivesecurity.com/2020/07/09/more-evil-deep-look-evilnum-toolset/) — Porolli, M. (2020, July 9). More evil: A deep look at Evilnum and its toolset. Retrieved January 22, 2021.
- [Prevailion EvilNum May 2020](https://web.archive.org/web/20221209052853/https://www.prevailion.com/phantom-in-the-command-shell-2/) — Adamitis, D. (2020, May 6). Phantom in the Command Shell. Retrieved November 17, 2024.

## 13. Limites e confiança

- O ATT&CK registra o que foi **relatado publicamente**, não tudo o que o grupo faz. Ausência de uma técnica não prova que o grupo não a usa.
- **Sobreposição de TTP não é atribuição.** Muitas técnicas são compartilhadas entre grupos e com red teams. Use a assinatura comportamental como hipótese, junto com infraestrutura, malware e contexto.
- Cobertura de detecção refere-se ao catálogo público Detection Rules, não ao seu ambiente: confira se a telemetria necessária chega ao seu SIEM.
- Ligações marcadas como _inferidas_ (EVTX por palavra-chave, relatórios por nome) devem ser verificadas.

---
Fontes: MITRE ATT&CK® (uso livre com atribuição, © The MITRE Corporation), APT4ALL (MISP Galaxy CC0/BSD-2, APT Groups & Operations CC BY 4.0, EternalLiberty, APTnotes, Ransomware Tool Matrix CC BY 4.0), Atomic Red Team (Red Canary, MIT), EVTX-to-MITRE-Attack, EVTX-ATTACK-SAMPLES, APT & CyberCriminal Campaign Collections. Gerado por [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules).
