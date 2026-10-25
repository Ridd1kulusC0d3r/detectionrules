# Molerats (G0021) — Dossiê de inteligência

> **TLP:CLEAR** · gerado em 2026-10-25 a partir de fontes abertas · MITRE ATT&CK v20.0 · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0021) · [ATT&CK](https://attack.mitre.org/groups/G0021/)

**Também conhecido como:** Operation Molerats, Gaza Cybergang  
**Registro no ATT&CK:** criado em 2017-05-31, atualizado em 2026-07-31 · referências de 2013 a 2020

## 1. Sumário executivo

- **16 técnicas** atribuídas publicamente, concentradas em **Execution, Stealth, Persistence**.
- **Arsenal:** 6 malware e 0 ferramentas (ex.: DustySky, PoisonIvy, SharpStage, Spark, DropBook).
- **Campanhas atribuídas:** 0.
- **Cobertura de detecção pública:** 100% das técnicas têm ao menos uma regra no catálogo; **0 técnicas sem nenhuma regra pública**.
- **Assinatura comportamental** (técnicas raras entre os 178 grupos, as mais úteis para atribuição): T1218.007 Msiexec, T1027.015 Compression, T1555.003 Credentials from Web Browsers, T1553.002 Code Signing, T1059.007 JavaScript.

## 2. Quem é

> Molerats is an Arabic-speaking, politically-motivated threat group that has been operating since 2012. The group's victims have primarily been in the Middle East, Europe, and the United States.

_Texto original do MITRE ATT&CK, em inglês._

## 3. Perfil TTP por tática (kill chain)

Cada linha: técnica, como o grupo a usou segundo relatos públicos, e o que existe para detectar e testar.

### Initial Access (TA0001) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1566.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1566.001) Spearphishing Attachment | Molerats has sent phishing emails with malicious Microsoft Word and PDF attachments. | 230 | 2 | — |
| [T1566.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1566.002) Spearphishing Link | Molerats has sent phishing emails with malicious links included. | 138 | 1 | — |

### Execution (TA0002) — 6

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1053.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1053.005) Scheduled Task | Molerats has created scheduled tasks to persistently run VBScripts. | 248 | 14 | 11 |
| [T1059.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.001) PowerShell | Molerats used PowerShell implants on target machines. | 1340 | 22 | 15 |
| [T1059.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.005) Visual Basic | Molerats used various implants, including those built with VBScript, on target machines. | 192 | 3 | — |
| [T1059.007](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.007) JavaScript | Molerats used various implants, including those built with JS, on target machines. | 205 | 5 | — |
| [T1204.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1204.001) Malicious Link | Molerats has sent malicious links via email trick users into opening a RAR archive and running an executable. | 52 | — | — |
| [T1204.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1204.002) Malicious File | Molerats has sent malicious files via email that tricked users into clicking Enable Content to run an embedded macro and to download malicious archives. | 259 | 13 | — |

### Persistence (TA0003) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1053.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1053.005) Scheduled Task | Molerats has created scheduled tasks to persistently run VBScripts. | 248 | 14 | 11 |
| [T1547.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1547.001) Registry Run Keys / Startup Folder | Molerats saved malicious files within the AppData and Startup folders to maintain persistence. | 299 | 21 | 2 |

### Privilege Escalation (TA0004) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1053.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1053.005) Scheduled Task | Molerats has created scheduled tasks to persistently run VBScripts. | 248 | 14 | 11 |
| [T1547.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1547.001) Registry Run Keys / Startup Folder | Molerats saved malicious files within the AppData and Startup folders to maintain persistence. | 299 | 21 | 2 |

### Stealth (TA0005) — 3

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1027.015](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1027.015) Compression | Molerats has delivered compressed executables within ZIP files to victims. | 3 | — | — |
| [T1140](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1140) Deobfuscate/Decode Files or Information | Molerats decompresses ZIP files once on the victim machine. | 173 | 11 | 1 |
| [T1218.007](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1218.007) Msiexec | Molerats has used msiexec.exe to execute an MSI payload. | 85 | 11 | — |

### Defense Impairment (TA0112) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1553.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1553.002) Code Signing | Molerats has used forged Microsoft code-signing certificates on malware. | 11 | — | — |

### Credential Access (TA0006) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1555.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1555.003) Credentials from Web Browsers | Molerats used the public tool BrowserPasswordDump10 to dump passwords saved in browsers on victims. | 59 | 18 | 5 |

### Discovery (TA0007) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1057](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1057) Process Discovery | Molerats actors obtained a list of active processes on the victim and sent them to C2 servers. | 82 | 10 | — |

### Command and Control (TA0011) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1105](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1105) Ingress Tool Transfer | Molerats used executables to download malicious files from different sources. | 644 | 39 | — |

## 4. Assinatura comportamental

Técnicas que este grupo usa e que poucos dos 178 grupos do ATT&CK usam. Pesam mais numa atribuição por TTP: ver várias delas juntas é mais informativo do que ver técnicas comuns como PowerShell.

| Técnica | Outros grupos que usam | Peso (raridade) |
|---|---:|---:|
| T1218.007 Msiexec | 5 | 3.24 |
| T1027.015 Compression | 11 | 2.62 |
| T1555.003 Credentials from Web Browsers | 23 | 1.97 |
| T1553.002 Code Signing | 27 | 1.82 |
| T1059.007 JavaScript | 29 | 1.75 |
| T1140 Deobfuscate/Decode Files or Information | 37 | 1.52 |
| T1057 Process Discovery | 41 | 1.43 |
| T1059.005 Visual Basic | 45 | 1.34 |
| T1566.002 Spearphishing Link | 47 | 1.30 |
| T1204.001 Malicious Link | 49 | 1.26 |

## 5. Arsenal

| Software | Tipo | Técnicas no ATT&CK | Uso relatado (EN) |
|---|---|---:|---|
| [DustySky](https://attack.mitre.org/software/S0062/) | malware | 19 |  |
| [PoisonIvy](https://attack.mitre.org/software/S0012/) | malware | 15 |  |
| [SharpStage](https://attack.mitre.org/software/S0546/) | malware | 11 |  |
| [Spark](https://attack.mitre.org/software/S0543/) | malware | 10 |  |
| [DropBook](https://attack.mitre.org/software/S0547/) | malware | 9 |  |
| [MoleNet](https://attack.mitre.org/software/S0553/) | malware | 7 |  |

## 6. Campanhas

Nenhuma campanha atribuída no ATT&CK.

## 7. Cobertura defensiva

**16 de 16 técnicas (100%)** têm ao menos uma regra pública no catálogo Detection Rules.

### Regras recomendadas por técnica

Melhor regra disponível por técnica (formato portável e maduro primeiro).

| Técnica | Regra | Formato | Fonte |
|---|---|---|---|
| T1027.015 | [PowerShell Suspicious Payload Encoded and Compressed](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A81fe9dc6-a2d7-4192-a2d8-eed98afc766a) | Elastic | Elastic detection-rules |
| T1027.015 | [Suspicious Content Extracted or Decompressed via Funzip](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Adc0b7782-0df0-47ff-8337-db0d678bdb66) | Elastic | Elastic detection-rules |
| T1053.005 | [Operation Wocao Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1cfac73c-be78-4f9a-9b08-5bde0c3953ab) | Sigma | SigmaHQ |
| T1053.005 | [Operation Wocao Activity - Security](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A74ad4314-482e-4c3e-b237-3f7ed3b9ca8d) | Sigma | SigmaHQ |
| T1057 | [Process Discovery](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4e2f5868-08d4-413d-899f-dc2f1508627b) | Sigma | SigmaHQ |
| T1057 | [HackTool - PCHunter Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Afca949cc-79ca-446e-8064-01aa7e52ece5) | Sigma | SigmaHQ |
| T1059.001 | [Potential Emotet Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad02e8cf5-6099-48cf-9bfc-1eec2d0c7b18) | Sigma | SigmaHQ |
| T1059.001 | [TropicTrooper Campaign November 2018](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A8c7090c3-e0a0-4944-bd08-08c3a0cecf79) | Sigma | SigmaHQ |
| T1059.005 | [Potential QBot Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4fcac6eb-0287-4090-8eea-2602e4c20040) | Sigma | SigmaHQ |
| T1059.005 | [QBot Process Creation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A4fcac6eb-0287-4090-8eea-2602e4c20040) | Sigma | OpenSearch Security Analytics |
| T1059.007 | [Adwind RAT / JRAT](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1fac1481-2dbc-48b2-9096-753c49b4ec71) | Sigma | SigmaHQ |
| T1059.007 | [WScript or CScript Dropper - File](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A002bdb95-0cf1-46a6-9e08-d38c128a6127) | Sigma | SigmaHQ |
| T1105 | [Greenbug Espionage Group Indicators](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A3711eee4-a808-4849-8a14-faf733da3612) | Sigma | SigmaHQ |
| T1105 | [Pandemic Registry Key](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A47e0852a-cf81-4494-a8e6-31864f8c86ed) | Sigma | SigmaHQ |
| T1140 | [UNC4841 - SSL Certificate Exfiltration Via Openssl](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A60911c07-f989-4362-84af-c609828ef829) | Sigma | SigmaHQ |
| T1140 | [UNC4841 - Download Compressed Files From Temp.sh Using Wget](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A60d050c4-e253-4d9a-b673-5ac100cfddfb) | Sigma | SigmaHQ |
| T1204.001 | [Google Workspace Object Copied from External Drive with App Consent](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Af33e68a4-bd19-11ed-b02f-f661ea17fbcc) | Elastic | Elastic detection-rules |
| T1204.001 | [Suspicious ClickFix/FileFix Execution Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad487ed4a-fd24-436d-a0b2-f4e95f7b2635) | Sigma | SigmaHQ |
| T1204.002 | [Ursnif Malware C2 URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A932ac737-33ca-4afd-9869-0d48b391fcc9) | Sigma | SigmaHQ |
| T1204.002 | [Droppers Exploiting CVE-2017-11882](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A678eb5f4-8597-4be6-8be7-905e4234b53a) | Sigma | SigmaHQ |
| T1218.007 | [Potential Remote Install via MsiExec](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ac9847fe9-3bed-4e6b-b319-f9956d6dd02a) | Elastic | Elastic detection-rules |
| T1218.007 | [Potential Escalation via Vulnerable MSI Repair](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A043d80a3-c49e-43ef-9c72-1088f0c7b278) | Elastic | Elastic detection-rules |
| T1547.001 | [Potential Ryuk Ransomware Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac37510b8-2107-4b78-aa32-72f251e7a844) | Sigma | SigmaHQ |
| T1547.001 | [Ryuk Ransomware](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Ac37510b8-2107-4b78-aa32-72f251e7a844) | Sigma | OpenSearch Security Analytics |
| T1553.002 | [Driver Loaded (Invalid Signature)](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=hayabusa-native%3A%3A1f666722-3948-40a2-9d78-d9d374477a90) | Sigma | Hayabusa (native) |
| T1553.002 | [Driver Loaded (Expired/Revoked Cert)](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=hayabusa-native%3A%3Ac837dd6d-0c91-4593-aeab-f6a1f3ca1961) | Sigma | Hayabusa (native) |
| T1555.003 | [SQLite Chromium Profile Data DB Access](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A24c77512-782b-448a-8950-eddb0785fc71) | Sigma | SigmaHQ |
| T1555.003 | [HackTool - WinPwn Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad557dc06-62e8-4468-a8e8-7984124908ce) | Sigma | SigmaHQ |
| T1566.001 | [Ursnif Malware C2 URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A932ac737-33ca-4afd-9869-0d48b391fcc9) | Sigma | SigmaHQ |
| T1566.001 | [Droppers Exploiting CVE-2017-11882](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A678eb5f4-8597-4be6-8be7-905e4234b53a) | Sigma | SigmaHQ |
| T1566.002 | [Potential Malicious Usage of CloudTrail System Manager](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A38e7f511-3f74-41d4-836e-f57dfa18eead) | Sigma | SigmaHQ |
| T1566.002 | [Google Workspace Device Registration After OAuth from Suspicious ASN](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A012bfca7-45cb-4507-a3ba-3777167f8b81) | Elastic | Elastic detection-rules |

## 8. Plano de emulação e validação

Use num laboratório isolado e autorizado para confirmar que as regras disparam. Os comandos estão nos repositórios oficiais.

| Tática | Técnica | Teste Atomic Red Team | Plataformas |
|---|---|---|---|
| Initial Access | [T1566.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1566.001/T1566.001.md) | Download Macro-Enabled Phishing Attachment | windows |
| Initial Access | [T1566.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1566.001/T1566.001.md) | Word spawned a command shell and used an IP address in the command line | windows |
| Initial Access | [T1566.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1566.002/T1566.002.md) | Paste and run technique | windows |
| Execution | [T1053.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1053.005/T1053.005.md) | Scheduled Task Startup Script | windows |
| Execution | [T1053.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1053.005/T1053.005.md) | Scheduled task Local | windows |
| Execution | [T1059.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md) | Mimikatz | windows |
| Execution | [T1059.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md) | Run BloodHound from local disk | windows |
| Execution | [T1059.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.005/T1059.005.md) | Visual Basic script execution to gather local computer information | windows |
| Execution | [T1059.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.005/T1059.005.md) | Encoded VBS code execution | windows |
| Execution | [T1059.007](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.007/T1059.007.md) | JScript execution to gather local computer information via cscript | windows |
| Execution | [T1059.007](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.007/T1059.007.md) | JScript execution to gather local computer information via wscript | windows |
| Execution | [T1204.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1204.002/T1204.002.md) | OSTap Style Macro Execution | windows |
| Execution | [T1204.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1204.002/T1204.002.md) | OSTap Payload Download | windows |
| Persistence | [T1547.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1547.001/T1547.001.md) | Reg Key Run | windows |
| Persistence | [T1547.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1547.001/T1547.001.md) | Reg Key RunOnce | windows |
| Stealth | [T1140](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1140/T1140.md) | Deobfuscate/Decode Files Or Information | windows |
| Stealth | [T1140](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1140/T1140.md) | Certutil Rename and Decode | windows |
| Stealth | [T1218.007](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.007/T1218.007.md) | Msiexec.exe - Execute Local MSI file with embedded JScript | windows |
| Stealth | [T1218.007](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.007/T1218.007.md) | Msiexec.exe - Execute Local MSI file with embedded VBScript | windows |
| Credential Access | [T1555.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1555.003/T1555.003.md) | Run Chrome-password Collector | windows |
| Credential Access | [T1555.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1555.003/T1555.003.md) | Search macOS Safari Cookies | macos |
| Discovery | [T1057](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1057/T1057.md) | Process Discovery - ps | linux, macos |
| Discovery | [T1057](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1057/T1057.md) | Process Discovery - tasklist | windows |
| Command and Control | [T1105](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1105/T1105.md) | rsync remote file copy (push) | linux, macos |
| Command and Control | [T1105](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1105/T1105.md) | rsync remote file copy (pull) | linux, macos |

**Logs reais de ataque (EVTX) para testar sem executar nada:**

- T1053.005 — [ID4688-4698 Persistent scheduled task with SYSTEM privileges creation](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1053.005-Scheduled%20Task/ID4688-4698%20Persistent%20scheduled%20task%20with%20SYSTEM%20privileges%20creation.evtx) _(explícito)_
- T1053.005 — [ID4688-Interactive shell using AT schedule task](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1053.005-Scheduled%20Task/ID4688-Interactive%20shell%20using%20AT%20schedule%20task.evtx) _(explícito)_
- T1059.001 — [ID4103-4104-Payload download via PowerShell](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1059.001-PowerShell/ID4103-4104-Payload%20download%20via%20PowerShell.evtx) _(explícito)_
- T1059.001 — [ID4688-Encoded PowerShell MSF payload via process execution](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1059.001-PowerShell/ID4688-Encoded%20PowerShell%20MSF%20payload%20via%20process%20execution.evtx) _(explícito)_
- T1140 — [ID4688-Certutil download](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0005-Defense%20Evasion/T1140-Deobfuscate-Decode%20Files%20or%20Information/ID4688-Certutil%20download.evtx) _(explícito)_
- T1547.001 — [sideloading_injection_persistence_run_key](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/AutomatedTestingTools/Malware/sideloading_injection_persistence_run_key.evtx) _(inferido)_
- T1547.001 — [evasion_persis_hidden_run_keyvalue_sysmon_13](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Persistence/evasion_persis_hidden_run_keyvalue_sysmon_13.evtx) _(inferido)_
- T1555.003 — [CA_4624_4625_LogonType2_LogonProc_chrome](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Credential%20Access/CA_4624_4625_LogonType2_LogonProc_chrome.evtx) _(inferido)_
- T1555.003 — [CA_chrome_firefox_opera_4663](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Credential%20Access/CA_chrome_firefox_opera_4663.evtx) _(inferido)_

## 9. Hipóteses de hunting

Se Molerats estiver no seu ambiente, estas são as perguntas a fazer aos seus dados (fontes de log segundo as estratégias de detecção do MITRE ATT&CK).

1. **T1218.007 Msiexec** — Detection of msiexec.exe execution where command-line arguments reference remote MSI packages, UNC paths, HTTP/HTTPS URLs, or DLLs, correlated with subsequent module loads and/or network connections to previously unseen destinations. The behavioral chain… Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=7), `WinEventLog:Sysmon` (EventCode=3, 22).
2. **T1027.015 Compression** — Monitors for compression tool usage (e.g., 7zip, WinRAR, MakeCab) that follows or precedes file modification, suspicious file types (e.g., .exe, .dll) being compressed, or dropped from self-extracting archives followed by immediate execution. Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=11).
3. **T1555.003 Credentials from Web Browsers** — Detects unauthorized access to web browser credential stores (e.g., Chrome Login Data, Edge Credential Locker) by processes other than the browser itself. Correlates file reads of credential databases with subsequent API calls to `CryptUnprotectData` or… Dados: `WinEventLog:Security` (EventCode=4663, 4670, 4656), `WinEventLog:Sysmon` (EventCode=10), `WinEventLog:Sysmon` (EventCode=1).
4. **T1553.002 Code Signing** — Detects execution of binaries signed with unusual or recently issued certificates, correlation of process execution with abnormal publisher metadata, and mismatched certificate chains. Monitors for revoked or unknown code signing certificates used in… Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=7).
5. **T1059.007 JavaScript** — Detects JavaScript execution through WSH (wscript.exe, cscript.exe) or HTA (mshta.exe), particularly when spawned from Office macros, web browsers, or abnormal user paths. Correlates script execution with outbound network activity or system modification. Dados: `WinEventLog:Sysmon` (EventCode=1), `m365:defender` (ScriptBlockLogging + AMSI), `WinEventLog:Sysmon` (EventCode=7).
6. **T1140 Deobfuscate/Decode Files or Information** — An adversary leverages built-in tools such as certutil.exe, powershell.exe, or copy.exe to decode, reassemble, or extract hidden malicious content from obfuscated containers or encoded formats. The decoding utility often spawns shortly after file staging or… Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Sysmon` (EventCode=10).
7. **T1057 Process Discovery** — Identifies adversary behavior that launches commands or invokes APIs to enumerate active processes (e.g., tasklist.exe, Get-Process, or CreateToolhelp32Snapshot). Detects execution combined with parent process lineage, network session context, or remote… Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=10).
8. **T1059.005 Visual Basic** — Detects execution of VB-based scripts or macros (VBS/VBA/VBScript) through cscript.exe/wscript.exe, Office-based process chains, or HTA usage. Focuses on chained behavior: Office or HTML container spawns script host > script host spawns PowerShell, network… Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=7).
9. **T1566.002 Spearphishing Link** — Correlation of inbound emails with embedded links followed by user-driven browser navigation to suspicious or obfuscated domains. Detection chain includes malicious URL in email → user click recorded in Office logs → browser process spawning unusual child… Dados: `m365:unified` (Send/Receive: Inbound emails containing embedded or shortened URLs), `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=3, 22).
10. **T1204.001 Malicious Link** — Behavioral chain: (1) a user-facing app (browser/Office/email client) launches a URL or handles a link, then (2) the same process lineage makes an outbound connection to an untrusted domain/IP, (3) a file is downloaded or unpacked to a user-writable location… Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=3, 22), `WinEventLog:Sysmon` (EventCode=11).
11. **T1053.005 Scheduled Task** — Detects the creation, modification, or deletion of scheduled tasks through Task Scheduler, WMI, PowerShell, or API-based methods followed by execution from svchost.exe or taskeng.exe. Includes detection of hidden or anomalous scheduled tasks, especially those… Dados: `WinEventLog:Security` (EventCode=4698), `WinEventLog:Security` (EventCode=4702), `WinEventLog:Sysmon` (EventCode=1).
12. **T1547.001 Registry Run Keys / Startup Folder** — Correlation of Registry key creation/modification events under known Run/Startup keys with new or unusual binary paths or script-based payloads. Multi-event detection includes registry modification followed by process execution from non-standard directories… Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=13, 14), `WinEventLog:Microsoft-Windows-Shell-Core` (New startup folder shortcut or binary placed in Startup directory).

## 10. OSINT — onde pesquisar

Consultas prontas com todos os nomes conhecidos do grupo:

- Relatórios técnicos: [busca web](https://duckduckgo.com/?q=%28%22Molerats%22+OR+%22Operation+Molerats%22+OR+%22Gaza+Cybergang%22%29+threat+report) · [PDFs](https://duckduckgo.com/?q=%28%22Molerats%22+OR+%22Operation+Molerats%22+OR+%22Gaza+Cybergang%22%29+filetype%3Apdf)
- Regras e IOCs publicados: [GitHub](https://github.com/search?type=code&q=%22Molerats%22+OR+%22Operation+Molerats%22+OR+%22Gaza+Cybergang%22)
- Pulsos de ameaça: [AlienVault OTX](https://otx.alienvault.com/browse/global/pulses?q=Molerats)
- Família de malware e atores: [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/actors) (busque por Molerats, Operation Molerats, Gaza Cybergang)
- Cartões de grupo: [ThaiCERT Threat Group Cards](https://apt.etda.or.th/cgi-bin/listgroups.cgi)
- Página oficial: [MITRE ATT&CK G0021](https://attack.mitre.org/groups/G0021/)

**Relatórios na coleção CyberMonitor** (ligados pelo nome do grupo, conferir antes de citar):

- 2013 — [fireeye.com-Operation Molerats Middle East Cyber Attacks Using Poison Ivy](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2013/2013.08.23.Operation_Molerats/fireeye.com-Operation%20Molerats%20Middle%20East%20Cyber%20Attacks%20Using%20Poison%20Ivy.pdf) _(via “Molerats”)_
- 2017 — [Gaza Cybergang - updated activity in 2017_ - Securelist](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2017/2017.10.30.Gaza_Cybergang/Gaza%20Cybergang%20-%20updated%20activity%20in%202017_%20-%20Securelist.pdf) _(via “Gaza Cybergang”)_
- 2019 — [suspected-molerats-new-attack-in-the-middle-east-cn](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2019/2019.02.14.Molerats_APT/suspected-molerats-new-attack-in-the-middle-east-cn.pdf) _(via “Molerats”)_
- 2019 — [suspected-molerats-new-attack-in-the-middle-east-en](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2019/2019.02.14.Molerats_APT/suspected-molerats-new-attack-in-the-middle-east-en.pdf) _(via “Molerats”)_
- 2019 — [Gaza Cybergang Group1 operation SneakyPastes](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2019/2019.04.10.Operation_SneakyPastes/Gaza%20Cybergang%20Group1%20operation%20SneakyPastes.pdf) _(via “Gaza Cybergang”)_
- 2020 — [Welcome Chat as a secure messaging app_ Nothing could be further from the truth _ WeLiveSecurity](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2020/2020.07.14_Molerats_Middle_East_APT/Welcome%20Chat%20as%20a%20secure%20messaging%20app_%20Nothing%20could%20be%20further%20from%20the%20truth%20_%20WeLiveSecurity.pdf) _(via “Molerats”)_

## 11. Bibliografia (6 fontes citadas pelo ATT&CK)

- [Cybereason Molerats Dec 2020](https://www.cybereason.com/hubfs/dam/collateral/reports/Molerats-in-the-Cloud-New-Malware-Arsenal-Abuses-Cloud-Platforms-in-Middle-East-Espionage-Campaign.pdf) — Cybereason Nocturnus Team. (2020, December 9). MOLERATS IN THE CLOUD: New Malware Arsenal Abuses Cloud Platforms in Middle East Espionage Campaign. Retrieved December 22, 2020.
- [DustySky](https://www.clearskysec.com/wp-content/uploads/2016/01/Operation%20DustySky_TLP_WHITE.pdf) — ClearSky. (2016, January 7). Operation DustySky. Retrieved January 8, 2016.
- [DustySky2](http://www.clearskysec.com/wp-content/uploads/2016/06/Operation-DustySky2_-6.2016_TLP_White.pdf) — ClearSky Cybersecurity. (2016, June 9). Operation DustySky - Part 2. Retrieved August 3, 2016.
- [FireEye Operation Molerats](https://web.archive.org/web/20201031075438/https://www.fireeye.com/blog/threat-research/2013/08/operation-molerats-middle-east-cyber-attacks-using-poison-ivy.html) — Villeneuve, N., Haq, H., Moran, N. (2013, August 23). OPERATION MOLERATS: MIDDLE EAST CYBER ATTACKS USING POISON IVY. Retrieved November 17, 2024.
- [Kaspersky MoleRATs April 2019](https://securelist.com/gaza-cybergang-group1-operation-sneakypastes/90068/) — GReAT. (2019, April 10). Gaza Cybergang Group1, operation SneakyPastes. Retrieved May 13, 2020.
- [Unit42 Molerat Mar 2020](https://unit42.paloaltonetworks.com/molerats-delivers-spark-backdoor/) — Falcone, R., et al. (2020, March 3). Molerats Delivers Spark Backdoor to Government and Telecommunications Organizations. Retrieved December 14, 2020.

## 12. Limites e confiança

- O ATT&CK registra o que foi **relatado publicamente**, não tudo o que o grupo faz. Ausência de uma técnica não prova que o grupo não a usa.
- **Sobreposição de TTP não é atribuição.** Muitas técnicas são compartilhadas entre grupos e com red teams. Use a assinatura comportamental como hipótese, junto com infraestrutura, malware e contexto.
- Cobertura de detecção refere-se ao catálogo público Detection Rules, não ao seu ambiente: confira se a telemetria necessária chega ao seu SIEM.
- Ligações marcadas como _inferidas_ (EVTX por palavra-chave, relatórios por nome) devem ser verificadas.

---
Fontes: MITRE ATT&CK® (uso livre com atribuição, © The MITRE Corporation), Atomic Red Team (Red Canary, MIT), EVTX-to-MITRE-Attack, EVTX-ATTACK-SAMPLES, APT & CyberCriminal Campaign Collections. Gerado por [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules).
