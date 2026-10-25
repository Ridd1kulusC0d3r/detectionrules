# Gorgon Group (G0078) — Dossiê de inteligência

> **TLP:CLEAR** · gerado em 2026-10-25 a partir de fontes abertas · MITRE ATT&CK v20.0 · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0078) · [ATT&CK](https://attack.mitre.org/groups/G0078/)

**Também conhecido como:** —  
**Registro no ATT&CK:** criado em 2018-10-17, atualizado em 2026-07-31 · referências de 2018 a 2018

## 1. Sumário executivo

- **16 técnicas** atribuídas publicamente, concentradas em **Execution, Stealth, Privilege Escalation**.
- **Arsenal:** 2 malware e 2 ferramentas (ex.: Remcos, njRAT, QuasarRAT, NanoCore).
- **Campanhas atribuídas:** 0.
- **Cobertura de detecção pública:** 100% das técnicas têm ao menos uma regra no catálogo; **0 técnicas sem nenhuma regra pública**.
- **Assinatura comportamental** (técnicas raras entre os 178 grupos, as mais úteis para atribuição): T1055.002 Portable Executable Injection, T1547.009 Shortcut Modification, T1055.012 Process Hollowing, T1564.003 Hidden Window, T1106 Native API.

## 2. Quem é

> Gorgon Group is a threat group consisting of members who are suspected to be Pakistan-based or have other connections to Pakistan. The group has performed a mix of criminal and targeted attacks, including campaigns against government organizations in the United Kingdom, Spain, Russia, and the United States.

_Texto original do MITRE ATT&CK, em inglês._

## 3. Perfil TTP por tática (kill chain)

Cada linha: técnica, como o grupo a usou segundo relatos públicos, e o que existe para detectar e testar.

### Resource Development (TA0042) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1588.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1588.002) Tool | Gorgon Group has obtained and used tools such as QuasarRAT and Remcos. | 35 | — | — |

### Initial Access (TA0001) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1566.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1566.001) Spearphishing Attachment | Gorgon Group sent emails to victims with malicious Microsoft Office documents attached. | 230 | 2 | — |

### Execution (TA0002) — 5

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1059.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.001) PowerShell | Gorgon Group malware can use PowerShell commands to download and execute a payload and open a decoy document on the victim’s machine. | 1340 | 22 | 15 |
| [T1059.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.003) Windows Command Shell | Gorgon Group malware can use cmd.exe to download and execute payloads and to execute commands on the system. | 269 | 6 | 1 |
| [T1059.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.005) Visual Basic | Gorgon Group has used macros in Spearphishing Attachments as well as executed VBScripts on victim machines. | 192 | 3 | — |
| [T1106](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1106) Native API | Gorgon Group malware can leverage the Windows API call, CreateProcessA(), for execution. | 118 | 5 | — |
| [T1204.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1204.002) Malicious File | Gorgon Group attempted to get users to launch malicious Microsoft Office attachments delivered via spearphishing emails. | 259 | 13 | — |

### Persistence (TA0003) — 3

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1112](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1112) Modify Registry | Gorgon Group malware can deactivate security mechanisms in Microsoft Office by editing several keys and values under HKCU\Software\Microsoft\Office\. | 601 | 92 | 3 |
| [T1547.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1547.001) Registry Run Keys / Startup Folder | Gorgon Group malware can create a .lnk file and add a Registry Run key to establish persistence. | 299 | 21 | 2 |
| [T1547.009](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1547.009) Shortcut Modification | Gorgon Group malware can create a .lnk file and add a Registry Run key to establish persistence. | 28 | 2 | — |

### Privilege Escalation (TA0004) — 4

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1055.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1055.002) Portable Executable Injection | Gorgon Group malware can download a remote access tool, ShiftyBug, and inject into another process. | 3 | 1 | — |
| [T1055.012](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1055.012) Process Hollowing | Gorgon Group malware can use process hollowing to inject one of its trojans into another process. | 29 | 4 | 2 |
| [T1547.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1547.001) Registry Run Keys / Startup Folder | Gorgon Group malware can create a .lnk file and add a Registry Run key to establish persistence. | 299 | 21 | 2 |
| [T1547.009](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1547.009) Shortcut Modification | Gorgon Group malware can create a .lnk file and add a Registry Run key to establish persistence. | 28 | 2 | — |

### Stealth (TA0005) — 4

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1055.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1055.002) Portable Executable Injection | Gorgon Group malware can download a remote access tool, ShiftyBug, and inject into another process. | 3 | 1 | — |
| [T1055.012](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1055.012) Process Hollowing | Gorgon Group malware can use process hollowing to inject one of its trojans into another process. | 29 | 4 | 2 |
| [T1140](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1140) Deobfuscate/Decode Files or Information | Gorgon Group malware can decode contents from a payload that was Base64 encoded and write the contents to a file. | 173 | 11 | 1 |
| [T1564.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1564.003) Hidden Window | Gorgon Group has used -W Hidden to conceal PowerShell windows by setting the WindowStyle parameter to hidden. | 51 | 3 | — |

### Defense Impairment (TA0112) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1112](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1112) Modify Registry | Gorgon Group malware can deactivate security mechanisms in Microsoft Office by editing several keys and values under HKCU\Software\Microsoft\Office\. | 601 | 92 | 3 |
| [T1685](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1685) Disable or Modify Tools | Gorgon Group malware can attempt to disable security features in Microsoft Office and Windows Defender using the taskkill command. | 1275 | 78 | 19 |

### Command and Control (TA0011) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1105](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1105) Ingress Tool Transfer | Gorgon Group malware can download additional files from C2 servers. | 644 | 39 | — |

## 4. Assinatura comportamental

Técnicas que este grupo usa e que poucos dos 178 grupos do ATT&CK usam. Pesam mais numa atribuição por TTP: ver várias delas juntas é mais informativo do que ver técnicas comuns como PowerShell.

| Técnica | Outros grupos que usam | Peso (raridade) |
|---|---:|---:|
| T1055.002 Portable Executable Injection | 1 | 4.09 |
| T1547.009 Shortcut Modification | 3 | 3.58 |
| T1055.012 Process Hollowing | 7 | 2.99 |
| T1564.003 Hidden Window | 18 | 2.19 |
| T1106 Native API | 20 | 2.10 |
| T1112 Modify Registry | 28 | 1.79 |
| T1685 Disable or Modify Tools | 32 | 1.66 |
| T1140 Deobfuscate/Decode Files or Information | 37 | 1.52 |
| T1059.005 Visual Basic | 45 | 1.34 |
| T1547.001 Registry Run Keys / Startup Folder | 58 | 1.09 |

## 5. Arsenal

| Software | Tipo | Técnicas no ATT&CK | Uso relatado (EN) |
|---|---|---:|---|
| [Remcos](https://attack.mitre.org/software/S0332/) | ferramenta | 38 | Gorgon Group has used Remcos as the final payload during operations. |
| [njRAT](https://attack.mitre.org/software/S0385/) | malware | 31 |  |
| [QuasarRAT](https://attack.mitre.org/software/S0262/) | ferramenta | 25 |  |
| [NanoCore](https://attack.mitre.org/software/S0336/) | malware | 13 |  |

## 6. Campanhas

Nenhuma campanha atribuída no ATT&CK.

## 7. Cobertura defensiva

**16 de 16 técnicas (100%)** têm ao menos uma regra pública no catálogo Detection Rules.

### Regras recomendadas por técnica

Melhor regra disponível por técnica (formato portável e maduro primeiro).

| Técnica | Regra | Formato | Fonte |
|---|---|---|---|
| T1055.002 | [Potential Process Injection via PowerShell](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A2e29e96a-b67c-455a-afe4-de6183431d0d) | Elastic | Elastic detection-rules |
| T1055.002 | [Suspicious .NET Reflection via PowerShell](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ae26f042e-c590-4e82-8e05-41e81bd822ad) | Elastic | Elastic detection-rules |
| T1055.012 | [Potential Pikabot Hollowing Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad8937fe7-42d5-4b4d-8178-e089c908f63f) | Sigma | SigmaHQ |
| T1055.012 | [HackTool - CACTUSTORCH Remote Thread Creation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A2e4e488a-6164-4811-9ea1-f960c7359c40) | Sigma | SigmaHQ |
| T1059.001 | [Potential Emotet Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad02e8cf5-6099-48cf-9bfc-1eec2d0c7b18) | Sigma | SigmaHQ |
| T1059.001 | [TropicTrooper Campaign November 2018](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A8c7090c3-e0a0-4944-bd08-08c3a0cecf79) | Sigma | SigmaHQ |
| T1059.003 | [HackTool - CrackMapExec Execution Patterns](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A058f4380-962d-40a5-afce-50207d36d7e2) | Sigma | SigmaHQ |
| T1059.003 | [CrackMapExec Command Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A058f4380-962d-40a5-afce-50207d36d7e2) | Sigma | OpenSearch Security Analytics |
| T1059.005 | [Potential QBot Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4fcac6eb-0287-4090-8eea-2602e4c20040) | Sigma | SigmaHQ |
| T1059.005 | [QBot Process Creation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A4fcac6eb-0287-4090-8eea-2602e4c20040) | Sigma | OpenSearch Security Analytics |
| T1105 | [Greenbug Espionage Group Indicators](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A3711eee4-a808-4849-8a14-faf733da3612) | Sigma | SigmaHQ |
| T1105 | [Pandemic Registry Key](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A47e0852a-cf81-4494-a8e6-31864f8c86ed) | Sigma | SigmaHQ |
| T1106 | [Turla Group Named Pipes](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A739915e4-1e70-4778-8b8a-17db02f66db1) | Sigma | SigmaHQ |
| T1106 | [BPFDoor Abnormal Process ID or Lock File Accessed](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A808146b2-9332-4d78-9416-d7e47012d83d) | Sigma | SigmaHQ |
| T1112 | [ShimCache Flush](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab0524451-19af-4efa-a46f-562a977f792e) | Sigma | SigmaHQ |
| T1112 | [ShimCache Flush](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Ab0524451-19af-4efa-a46f-562a977f792e) | Sigma | OpenSearch Security Analytics |
| T1140 | [UNC4841 - SSL Certificate Exfiltration Via Openssl](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A60911c07-f989-4362-84af-c609828ef829) | Sigma | SigmaHQ |
| T1140 | [UNC4841 - Download Compressed Files From Temp.sh Using Wget](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A60d050c4-e253-4d9a-b673-5ac100cfddfb) | Sigma | SigmaHQ |
| T1204.002 | [Ursnif Malware C2 URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A932ac737-33ca-4afd-9869-0d48b391fcc9) | Sigma | SigmaHQ |
| T1204.002 | [Droppers Exploiting CVE-2017-11882](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A678eb5f4-8597-4be6-8be7-905e4234b53a) | Sigma | SigmaHQ |
| T1547.001 | [Potential Ryuk Ransomware Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac37510b8-2107-4b78-aa32-72f251e7a844) | Sigma | SigmaHQ |
| T1547.001 | [Ryuk Ransomware](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Ac37510b8-2107-4b78-aa32-72f251e7a844) | Sigma | OpenSearch Security Analytics |
| T1547.009 | [Creation Exe for Service with Unquoted Path](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A8c3c76ca-8f8b-4b1d-aaf3-81aebcd367c9) | Sigma | SigmaHQ |
| T1547.009 | [New Custom Shim Database Created](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aee63c85c-6d51-4d12-ad09-04e25877a947) | Sigma | SigmaHQ |
| T1564.003 | [Potential Data Stealing Via Chromium Headless Debugging](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A3e8207c5-fcd2-4ea6-9418-15d45b4890e4) | Sigma | SigmaHQ |
| T1564.003 | [HackTool - Covenant PowerShell Launcher](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac260b6db-48ba-4b4a-a76f-2f67644e99d2) | Sigma | SigmaHQ |
| T1566.001 | [Ursnif Malware C2 URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A932ac737-33ca-4afd-9869-0d48b391fcc9) | Sigma | SigmaHQ |
| T1566.001 | [Droppers Exploiting CVE-2017-11882](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A678eb5f4-8597-4be6-8be7-905e4234b53a) | Sigma | SigmaHQ |
| T1588.002 | [Hacktool Execution - Imphash](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A24e3e58a-646b-4b50-adef-02ef935b9fc8) | Sigma | SigmaHQ |
| T1588.002 | [Renamed SysInternals DebugView Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acd764533-2e07-40d6-a718-cfeec7f2da7f) | Sigma | SigmaHQ |
| T1685 | [Windows Defender Configuration Changes](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A801bd44f-ceed-4eb6-887c-11544633c0aa) | Sigma | SigmaHQ |
| T1685 | [Windows Defender Virus Scanning Feature Disabled](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A686c0b4b-9dd3-4847-9077-d6c1bbe36fcb) | Sigma | SigmaHQ |

## 8. Plano de emulação e validação

Use num laboratório isolado e autorizado para confirmar que as regras disparam. Os comandos estão nos repositórios oficiais.

| Tática | Técnica | Teste Atomic Red Team | Plataformas |
|---|---|---|---|
| Initial Access | [T1566.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1566.001/T1566.001.md) | Download Macro-Enabled Phishing Attachment | windows |
| Initial Access | [T1566.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1566.001/T1566.001.md) | Word spawned a command shell and used an IP address in the command line | windows |
| Execution | [T1059.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md) | Mimikatz | windows |
| Execution | [T1059.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md) | Run BloodHound from local disk | windows |
| Execution | [T1059.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.003/T1059.003.md) | Create and Execute Batch Script | windows |
| Execution | [T1059.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.003/T1059.003.md) | Writes text to a file and displays it. | windows |
| Execution | [T1059.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.005/T1059.005.md) | Visual Basic script execution to gather local computer information | windows |
| Execution | [T1059.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.005/T1059.005.md) | Encoded VBS code execution | windows |
| Execution | [T1106](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1106/T1106.md) | Execution through API - CreateProcess | windows |
| Execution | [T1106](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1106/T1106.md) | WinPwn - Get SYSTEM shell - Pop System Shell using CreateProcess technique | windows |
| Execution | [T1204.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1204.002/T1204.002.md) | OSTap Style Macro Execution | windows |
| Execution | [T1204.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1204.002/T1204.002.md) | OSTap Payload Download | windows |
| Persistence | [T1547.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1547.001/T1547.001.md) | Reg Key Run | windows |
| Persistence | [T1547.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1547.001/T1547.001.md) | Reg Key RunOnce | windows |
| Persistence | [T1547.009](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1547.009/T1547.009.md) | Shortcut Modification | windows |
| Persistence | [T1547.009](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1547.009/T1547.009.md) | Create shortcut to cmd in startup folders | windows |
| Stealth | [T1055.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1055.002/T1055.002.md) | Portable Executable Injection | windows |
| Stealth | [T1055.012](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1055.012/T1055.012.md) | Process Hollowing using PowerShell | windows |
| Stealth | [T1055.012](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1055.012/T1055.012.md) | RunPE via VBA | windows |
| Stealth | [T1140](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1140/T1140.md) | Deobfuscate/Decode Files Or Information | windows |
| Stealth | [T1140](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1140/T1140.md) | Certutil Rename and Decode | windows |
| Stealth | [T1564.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1564.003/T1564.003.md) | Hidden Window | windows |
| Stealth | [T1564.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1564.003/T1564.003.md) | Headless Browser Accessing Mockbin | windows |
| Defense Impairment | [T1112](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1112/T1112.md) | Modify Registry of Current User Profile - cmd | windows |
| Defense Impairment | [T1112](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1112/T1112.md) | Modify Registry of Local Machine - cmd | windows |
| Defense Impairment | [T1685](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1685/T1685.md) | Windows Disable LSA Protection | windows |
| Defense Impairment | [T1685](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1685/T1685.md) | Disable journal logging via systemctl utility | linux |
| Command and Control | [T1105](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1105/T1105.md) | rsync remote file copy (push) | linux, macos |
| Command and Control | [T1105](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1105/T1105.md) | rsync remote file copy (pull) | linux, macos |

**Logs reais de ataque (EVTX) para testar sem executar nada:**

- T1055.012 — [rundll32_hollowing_wermgr_masquerading](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/AutomatedTestingTools/Malware/rundll32_hollowing_wermgr_masquerading.evtx) _(inferido)_
- T1055.012 — [apt10_jjs_sideloading_prochollowing_persist_as_service_sysmon_1_7_8_13](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Defense%20Evasion/apt10_jjs_sideloading_prochollowing_persist_as_service_sysmon_1_7_8_13.evtx) _(inferido)_
- T1059.001 — [ID4103-4104-Payload download via PowerShell](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1059.001-PowerShell/ID4103-4104-Payload%20download%20via%20PowerShell.evtx) _(explícito)_
- T1059.001 — [ID4688-Encoded PowerShell MSF payload via process execution](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1059.001-PowerShell/ID4688-Encoded%20PowerShell%20MSF%20payload%20via%20process%20execution.evtx) _(explícito)_
- T1059.003 — [ID4688-SQL Server payload injectection for reverse shell (MSF)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1059.003-Windows%20Command%20Shell/ID4688-SQL%20Server%20payload%20injectection%20for%20reverse%20shell%20%28MSF%29.evtx) _(explícito)_
- T1112 — [ID11,13-SMBexec service registration](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0005-Defense%20Evasion/T1112-Modify%20registry/ID11%2C13-SMBexec%20service%20registration.evtx) _(explícito)_
- T1112 — [ID4624,4670,4688,4674-Registry permission change via WMI (DAMP)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0005-Defense%20Evasion/T1112-Modify%20registry/ID4624%2C4670%2C4688%2C4674-Registry%20permission%20change%20via%20WMI%20%28DAMP%29.evtx) _(explícito)_
- T1140 — [ID4688-Certutil download](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0005-Defense%20Evasion/T1140-Deobfuscate-Decode%20Files%20or%20Information/ID4688-Certutil%20download.evtx) _(explícito)_
- T1547.001 — [sideloading_injection_persistence_run_key](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/AutomatedTestingTools/Malware/sideloading_injection_persistence_run_key.evtx) _(inferido)_
- T1547.001 — [evasion_persis_hidden_run_keyvalue_sysmon_13](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Persistence/evasion_persis_hidden_run_keyvalue_sysmon_13.evtx) _(inferido)_
- T1685 — [ID1-SYSMON driver unload (FilterManager)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0005-Defense%20Evasion/T1562.001-Impair%20Defenses-Disable%20or%20Modify%20tool/ID1-SYSMON%20driver%20unload%20%28FilterManager%29.evtx) _(explícito)_
- T1685 — [ID13-Defender service configuration disabled](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0005-Defense%20Evasion/T1562.001-Impair%20Defenses-Disable%20or%20Modify%20tool/ID13-Defender%20service%20configuration%20disabled.evtx) _(explícito)_

## 9. Hipóteses de hunting

Se Gorgon Group estiver no seu ambiente, estas são as perguntas a fazer aos seus dados (fontes de log segundo as estratégias de detecção do MITRE ATT&CK).

1. **T1055.002 Portable Executable Injection** — Detects PE injection through a behavioral sequence where one process opens (OpenProcess) a handle to another, allocates remote memory (VirtualAllocEx), writes a PE header (MZ) or shellcode (WriteProcessMemory), then initiates a new thread (CreateRemoteThread… Dados: `WinEventLog:Sysmon` (EventCode=10), `WinEventLog:Sysmon` (EventCode=8), `WinEventLog:Sysmon` (EventCode=1).
2. **T1547.009 Shortcut Modification** — Detection correlates file creation or modification of `.lnk` (shortcut) files in autostart locations with anomalous parent-child process lineage or unsigned binaries. Defenders should watch for LNK creation/modification events outside of known software… Dados: `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Sysmon` (EventCode=2), `WinEventLog:Sysmon` (EventCode=1).
3. **T1055.012 Process Hollowing** — Detects adversary use of suspended process creation, using the CREATE_SUSPENDED flag via CreateProcess, followed by unmapping the memory of the child process (NtUnmapViewOfSection) and replacing it with malicious code via VirtualAllocEx/WriteProcessMemory,… Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=10), `WinEventLog:Sysmon` (EventCode=8).
4. **T1564.003 Hidden Window** — Suspicious use of scripting parameters or registry edits to hide process windows (e.g., powershell.exe -WindowStyle Hidden, or registry modifications pushing window positions off screen). Defender view: correlation of hidden execution with anomalous process… Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=13, 14).
5. **T1106 Native API** — Unusual or suspicious processes loading critical native API DLLs (e.g., ntdll.dll, kernel32.dll) followed by direct syscall behavior, memory manipulation, or hollowing. Dados: `WinEventLog:Sysmon` (EventCode=7), `WinEventLog:Sysmon` (EventCode=10), `WinEventLog:Sysmon` (EventCode=1).
6. **T1112 Modify Registry** — Behavior chain involving abnormal registry modifications via CLI, PowerShell, WMI, or direct API calls, especially targeting persistence, privilege escalation, or defense evasion keys, potentially followed by service restart or process execution. Such as… Dados: `WinEventLog:Sysmon` (EventCode=13, 14), `WinEventLog:Sysmon` (EventCode=1).
7. **T1685 Disable or Modify Tools** — Detection of adversary behavior that disables or modifies security tools, including killing AV/EDR processes, stopping services, altering Sysmon registry keys, or tampering with exclusion lists. Defenders observe process/service termination, registry… Dados: `WinEventLog:System` (EventCode=7045), `WinEventLog:Sysmon` (EventCode=5), `WinEventLog:Sysmon` (EventCode=13, 14).
8. **T1140 Deobfuscate/Decode Files or Information** — An adversary leverages built-in tools such as certutil.exe, powershell.exe, or copy.exe to decode, reassemble, or extract hidden malicious content from obfuscated containers or encoded formats. The decoding utility often spawns shortly after file staging or… Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Sysmon` (EventCode=10).
9. **T1059.005 Visual Basic** — Detects execution of VB-based scripts or macros (VBS/VBA/VBScript) through cscript.exe/wscript.exe, Office-based process chains, or HTA usage. Focuses on chained behavior: Office or HTML container spawns script host > script host spawns PowerShell, network… Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=7).
10. **T1547.001 Registry Run Keys / Startup Folder** — Correlation of Registry key creation/modification events under known Run/Startup keys with new or unusual binary paths or script-based payloads. Multi-event detection includes registry modification followed by process execution from non-standard directories… Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=13, 14), `WinEventLog:Microsoft-Windows-Shell-Core` (New startup folder shortcut or binary placed in Startup directory).
11. **T1059.003 Windows Command Shell** — Detects interactive or scripted abuse of cmd.exe, batch files, or shell invocation chains. Focuses on parent-child relationships (e.g., cmd.exe launched from unusual parents), anomalous command-line parameters, and chaining with discovery, credential access,… Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=7), `EDR:scriptblock` (Process Tree + Script Block Logging).
12. **T1566.001 Spearphishing Attachment** — Detection of spearphishing attachments by correlating suspicious email delivery with subsequent file creation and abnormal process execution (e.g., Office spawning PowerShell or CMD). Behavior chain includes inbound email metadata → attachment stored on disk… Dados: `m365:unified` (Send/Receive: Inbound emails with attachments from suspicious or spoofed senders), `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Sysmon` (EventCode=1).

## 10. OSINT — onde pesquisar

Consultas prontas com todos os nomes conhecidos do grupo:

- Relatórios técnicos: [busca web](https://duckduckgo.com/?q=%28%22Gorgon+Group%22%29+threat+report) · [PDFs](https://duckduckgo.com/?q=%28%22Gorgon+Group%22%29+filetype%3Apdf)
- Regras e IOCs publicados: [GitHub](https://github.com/search?type=code&q=%22Gorgon+Group%22)
- Pulsos de ameaça: [AlienVault OTX](https://otx.alienvault.com/browse/global/pulses?q=Gorgon+Group)
- Família de malware e atores: [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/actors) (busque por Gorgon Group)
- Cartões de grupo: [ThaiCERT Threat Group Cards](https://apt.etda.or.th/cgi-bin/listgroups.cgi)
- Página oficial: [MITRE ATT&CK G0078](https://attack.mitre.org/groups/G0078/)

**Relatórios na coleção CyberMonitor** (ligados pelo nome do grupo, conferir antes de citar):

- 2018 — [The Gorgon Group Slithering Between Nation State and Cybercrime](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2018/2018.08.02.Gorgon_Group/The%20Gorgon%20Group%20Slithering%20Between%20Nation%20State%20and%20Cybercrime.pdf) _(via “Gorgon Group”)_

## 11. Bibliografia (1 fontes citadas pelo ATT&CK)

- [Unit 42 Gorgon Group Aug 2018](https://researchcenter.paloaltonetworks.com/2018/08/unit42-gorgon-group-slithering-nation-state-cybercrime/) — Falcone, R., et al. (2018, August 02). The Gorgon Group: Slithering Between Nation State and Cybercrime. Retrieved August 7, 2018.

## 12. Limites e confiança

- O ATT&CK registra o que foi **relatado publicamente**, não tudo o que o grupo faz. Ausência de uma técnica não prova que o grupo não a usa.
- **Sobreposição de TTP não é atribuição.** Muitas técnicas são compartilhadas entre grupos e com red teams. Use a assinatura comportamental como hipótese, junto com infraestrutura, malware e contexto.
- Cobertura de detecção refere-se ao catálogo público Detection Rules, não ao seu ambiente: confira se a telemetria necessária chega ao seu SIEM.
- Ligações marcadas como _inferidas_ (EVTX por palavra-chave, relatórios por nome) devem ser verificadas.

---
Fontes: MITRE ATT&CK® (uso livre com atribuição, © The MITRE Corporation), Atomic Red Team (Red Canary, MIT), EVTX-to-MITRE-Attack, EVTX-ATTACK-SAMPLES, APT & CyberCriminal Campaign Collections. Gerado por [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules).
