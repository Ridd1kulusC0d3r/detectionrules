# SideCopy (G1008) — Dossiê de inteligência

> **TLP:CLEAR** · gerado em 2026-10-25 a partir de fontes abertas · MITRE ATT&CK v20.0 · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1008) · [ATT&CK](https://attack.mitre.org/groups/G1008/)

**Também conhecido como:** —  
**Registro no ATT&CK:** criado em 2022-08-07, atualizado em 2026-07-31 · referências de 2021 a 2021

## 1. Sumário executivo

- **16 técnicas** atribuídas publicamente, concentradas em **Discovery, Execution, Stealth**.
- **Arsenal:** 2 malware e 0 ferramentas (ex.: Action RAT, AuTo Stealer).
- **Campanhas atribuídas:** 0.
- **Cobertura de detecção pública:** 94% das técnicas têm ao menos uma regra no catálogo; **1 técnicas sem nenhuma regra pública**.
- **Assinatura comportamental** (técnicas raras entre os 178 grupos, as mais úteis para atribuição): T1614 System Location Discovery, T1598.002 Spearphishing Attachment, T1584.001 Domains, T1518 Software Discovery, T1218.005 Mshta.

## 2. Quem é

> SideCopy is a Pakistani threat group that has primarily targeted South Asian countries, including Indian and Afghani government personnel, since at least 2019. SideCopy's name comes from its infection chain that tries to mimic that of Sidewinder, a suspected Indian threat group.

_Texto original do MITRE ATT&CK, em inglês._

## 3. Perfil TTP por tática (kill chain)

Cada linha: técnica, como o grupo a usou segundo relatos públicos, e o que existe para detectar e testar.

### Reconnaissance (TA0043) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1598.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1598.002) Spearphishing Attachment | SideCopy has crafted generic lures for spam campaigns to collect emails and credentials for targeting efforts. | **0** | — | — |

### Resource Development (TA0042) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1584.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1584.001) Domains | SideCopy has compromised domains for some of their infrastructure, including for C2 and staging malware. | 3 | — | — |
| [T1608.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1608.001) Upload Malware | SideCopy has used compromised domains to host its malicious payloads. | 3 | — | — |

### Initial Access (TA0001) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1566.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1566.001) Spearphishing Attachment | SideCopy has sent spearphishing emails with malicious hta file attachments. | 230 | 2 | — |

### Execution (TA0002) — 4

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1059.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.005) Visual Basic | SideCopy has sent Microsoft Office Publisher documents to victims that have embedded malicious macros that execute an hta file via calling `mshta.exe`. | 192 | 3 | — |
| [T1106](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1106) Native API | SideCopy has executed malware by calling the API function `CreateProcessW`. | 118 | 5 | — |
| [T1204.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1204.002) Malicious File | SideCopy has attempted to lure victims into clicking on malicious embedded archive files sent via spearphishing campaigns. | 259 | 13 | — |
| [T1574.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1574.001) DLL | SideCopy has used a malicious loader DLL file to execute the `credwiz.exe` process and side-load the malicious payload `Duser.dll`. | 455 | 7 | 5 |

### Stealth (TA0005) — 3

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1036.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1036.005) Match Legitimate Resource Name or Location | SideCopy has used a legitimate DLL file name, `Duser.dll` to disguise a malicious remote access tool. | 116 | 4 | — |
| [T1218.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1218.005) Mshta | SideCopy has utilized `mshta.exe` to execute a malicious hta file. | 130 | 10 | 4 |
| [T1574.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1574.001) DLL | SideCopy has used a malicious loader DLL file to execute the `credwiz.exe` process and side-load the malicious payload `Duser.dll`. | 455 | 7 | 5 |

### Discovery (TA0007) — 5

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1016](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1016) System Network Configuration Discovery | SideCopy has identified the IP address of a compromised host. | 99 | 10 | 5 |
| [T1082](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1082) System Information Discovery | SideCopy has identified the OS version of a compromised host. | 264 | 41 | — |
| [T1518](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1518) Software Discovery | SideCopy has collected browser information from a compromised host. | 58 | 6 | — |
| [T1518.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1518.001) Security Software Discovery | SideCopy uses a loader DLL file to collect AV product names from an infected host. | 54 | 12 | — |
| [T1614](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1614) System Location Discovery | SideCopy has identified the country location of a compromised host. | 12 | 2 | — |

### Command and Control (TA0011) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1105](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1105) Ingress Tool Transfer | SideCopy has delivered trojanized executables via spearphishing emails that contacts actor-controlled servers to download malicious payloads. | 644 | 39 | — |

## 4. Assinatura comportamental

Técnicas que este grupo usa e que poucos dos 178 grupos do ATT&CK usam. Pesam mais numa atribuição por TTP: ver várias delas juntas é mais informativo do que ver técnicas comuns como PowerShell.

| Técnica | Outros grupos que usam | Peso (raridade) |
|---|---:|---:|
| T1614 System Location Discovery | 1 | 4.09 |
| T1598.002 Spearphishing Attachment | 3 | 3.58 |
| T1584.001 Domains | 5 | 3.24 |
| T1518 Software Discovery | 11 | 2.62 |
| T1218.005 Mshta | 16 | 2.30 |
| T1106 Native API | 20 | 2.10 |
| T1518.001 Security Software Discovery | 26 | 1.85 |
| T1608.001 Upload Malware | 29 | 1.75 |
| T1574.001 DLL | 35 | 1.58 |
| T1016 System Network Configuration Discovery | 44 | 1.36 |

## 5. Arsenal

| Software | Tipo | Técnicas no ATT&CK | Uso relatado (EN) |
|---|---|---:|---|
| [Action RAT](https://attack.mitre.org/software/S1028/) | malware | 12 |  |
| [AuTo Stealer](https://attack.mitre.org/software/S1029/) | malware | 10 |  |

## 6. Campanhas

Nenhuma campanha atribuída no ATT&CK.

## 7. Cobertura defensiva

**15 de 16 técnicas (94%)** têm ao menos uma regra pública no catálogo Detection Rules.

### Técnicas sem regra pública (prioridade para engenharia de detecção)

- **T1598.002 Spearphishing Attachment** — Reconnaissance. Fonte de log sugerida pelo MITRE: `Network Traffic` None

### Regras recomendadas por técnica

Melhor regra disponível por técnica (formato portável e maduro primeiro).

| Técnica | Regra | Formato | Fonte |
|---|---|---|---|
| T1016 | [Potential Pikabot Discovery Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A698d4431-514f-4c82-af4d-cf573872a9f5) | Sigma | SigmaHQ |
| T1016 | [OpenCanary - SNMP OID Request](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae9856028-fd4e-46e6-b3d1-10f7ceb95078) | Sigma | SigmaHQ |
| T1036.005 | [Exploit for CVE-2015-1641](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A7993792c-5ce2-4475-a3db-a3a5539827ef) | Sigma | SigmaHQ |
| T1036.005 | [Exploit for CVE-2015-1641](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A7993792c-5ce2-4475-a3db-a3a5539827ef) | Sigma | OpenSearch Security Analytics |
| T1059.005 | [Potential QBot Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4fcac6eb-0287-4090-8eea-2602e4c20040) | Sigma | SigmaHQ |
| T1059.005 | [QBot Process Creation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A4fcac6eb-0287-4090-8eea-2602e4c20040) | Sigma | OpenSearch Security Analytics |
| T1082 | [Potential GobRAT File Discovery Via Grep](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae34cfa0c-0a50-4210-9cb3-5632d08eb041) | Sigma | SigmaHQ |
| T1082 | [System Information Discovery](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A42df45e7-e6e9-43b5-8f26-bec5b39cc239) | Sigma | SigmaHQ |
| T1105 | [Greenbug Espionage Group Indicators](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A3711eee4-a808-4849-8a14-faf733da3612) | Sigma | SigmaHQ |
| T1105 | [Pandemic Registry Key](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A47e0852a-cf81-4494-a8e6-31864f8c86ed) | Sigma | SigmaHQ |
| T1106 | [Turla Group Named Pipes](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A739915e4-1e70-4778-8b8a-17db02f66db1) | Sigma | SigmaHQ |
| T1106 | [BPFDoor Abnormal Process ID or Lock File Accessed](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A808146b2-9332-4d78-9416-d7e47012d83d) | Sigma | SigmaHQ |
| T1204.002 | [Ursnif Malware C2 URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A932ac737-33ca-4afd-9869-0d48b391fcc9) | Sigma | SigmaHQ |
| T1204.002 | [Droppers Exploiting CVE-2017-11882](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A678eb5f4-8597-4be6-8be7-905e4234b53a) | Sigma | SigmaHQ |
| T1218.005 | [Potential Baby Shark Malware Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A2b30fa36-3a18-402f-a22d-bf4ce2189f35) | Sigma | SigmaHQ |
| T1218.005 | [Remotely Hosted HTA File Executed Via Mshta.EXE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab98d0db6-511d-45de-ad02-e82a98729620) | Sigma | SigmaHQ |
| T1518 | [HackTool - WinPwn Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad557dc06-62e8-4468-a8e8-7984124908ce) | Sigma | SigmaHQ |
| T1518 | [HackTool - WinPwn Execution - ScriptBlock](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A851fd622-b675-4d26-b803-14bc7baa517a) | Sigma | SigmaHQ |
| T1518.001 | [Sysmon Discovery Via Default Driver Altitude Using Findstr.EXE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A37db85d1-b089-490a-a59a-c7b6f984f480) | Sigma | SigmaHQ |
| T1518.001 | [Local Firewall Rules Enumeration Via NetFirewallRule Cmdlet](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aea207a23-b441-4a17-9f76-ad5be47d51d3) | Sigma | SigmaHQ |
| T1566.001 | [Ursnif Malware C2 URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A932ac737-33ca-4afd-9869-0d48b391fcc9) | Sigma | SigmaHQ |
| T1566.001 | [Droppers Exploiting CVE-2017-11882](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A678eb5f4-8597-4be6-8be7-905e4234b53a) | Sigma | SigmaHQ |
| T1574.001 | [Winnti Pipemon Characteristics](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A73d70463-75c9-4258-92c6-17500fe972f2) | Sigma | SigmaHQ |
| T1574.001 | [Winnti Pipemon Characteristics](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A73d70463-75c9-4258-92c6-17500fe972f2) | Sigma | OpenSearch Security Analytics |
| T1584.001 | [AWS Route 53 Domain Transferred to Another Account](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A2045567e-b0af-444a-8c0b-0b6e2dae9e13) | Elastic | Elastic detection-rules |
| T1584.001 | [AWS Route 53 Domain Transfer Lock Disabled](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A12051077-0124-4394-9522-8f4f4db1d674) | Elastic | Elastic detection-rules |
| T1608.001 | [M365 OneDrive Malware File Upload](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Abba1b212-b85c-41c6-9b28-be0e5cdfc9b1) | Elastic | Elastic detection-rules |
| T1608.001 | [M365 SharePoint Malware File Detected](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A0e52157a-8e96-4a95-a6e3-5faae5081a74) | Elastic | Elastic detection-rules |
| T1614 | [System Time Discovery](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A06568a02-af29-4f20-929c-f3af281e41aa) | Elastic | Elastic detection-rules |
| T1614 | [External IP Lookup from Non-Browser Process](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A1d72d014-e2ab-4707-b056-9b96abe7b511) | Elastic | Elastic detection-rules |

## 8. Plano de emulação e validação

Use num laboratório isolado e autorizado para confirmar que as regras disparam. Os comandos estão nos repositórios oficiais.

| Tática | Técnica | Teste Atomic Red Team | Plataformas |
|---|---|---|---|
| Initial Access | [T1566.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1566.001/T1566.001.md) | Download Macro-Enabled Phishing Attachment | windows |
| Initial Access | [T1566.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1566.001/T1566.001.md) | Word spawned a command shell and used an IP address in the command line | windows |
| Execution | [T1059.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.005/T1059.005.md) | Visual Basic script execution to gather local computer information | windows |
| Execution | [T1059.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.005/T1059.005.md) | Encoded VBS code execution | windows |
| Execution | [T1106](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1106/T1106.md) | Execution through API - CreateProcess | windows |
| Execution | [T1106](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1106/T1106.md) | WinPwn - Get SYSTEM shell - Pop System Shell using CreateProcess technique | windows |
| Execution | [T1204.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1204.002/T1204.002.md) | OSTap Style Macro Execution | windows |
| Execution | [T1204.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1204.002/T1204.002.md) | OSTap Payload Download | windows |
| Stealth | [T1036.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.005/T1036.005.md) | Execute a process from a directory masquerading as the current parent directory | linux, macos |
| Stealth | [T1036.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.005/T1036.005.md) | Masquerade as a built-in system executable | windows |
| Stealth | [T1218.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.005/T1218.005.md) | Mshta executes JavaScript Scheme Fetch Remote Payload With GetObject | windows |
| Stealth | [T1218.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.005/T1218.005.md) | Mshta executes VBScript to execute malicious command | windows |
| Stealth | [T1574.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1574.001/T1574.001.md) | DLL Search Order Hijacking - amsi.dll | windows |
| Stealth | [T1574.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1574.001/T1574.001.md) | Phantom Dll Hijacking - WinAppXRT.dll | windows |
| Discovery | [T1016](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1016/T1016.md) | System Network Configuration Discovery on Windows | windows |
| Discovery | [T1016](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1016/T1016.md) | List Windows Firewall Rules | windows |
| Discovery | [T1082](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1082/T1082.md) | System Information Discovery | windows |
| Discovery | [T1082](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1082/T1082.md) | System Information Discovery | macos |
| Discovery | [T1518](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1518/T1518.md) | Find and Display Internet Explorer Browser Version | windows |
| Discovery | [T1518](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1518/T1518.md) | Applications Installed | windows |
| Discovery | [T1518.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1518.001/T1518.001.md) | Security Software Discovery | windows |
| Discovery | [T1518.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1518.001/T1518.001.md) | Security Software Discovery - powershell | windows |
| Discovery | [T1614](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1614/T1614.md) | Get geolocation info through IP-Lookup services using curl Windows | windows |
| Discovery | [T1614](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1614/T1614.md) | Get geolocation info through IP-Lookup services using curl freebsd, linux or macos | linux, macos |
| Command and Control | [T1105](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1105/T1105.md) | rsync remote file copy (push) | linux, macos |
| Command and Control | [T1105](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1105/T1105.md) | rsync remote file copy (pull) | linux, macos |

**Logs reais de ataque (EVTX) para testar sem executar nada:**

- T1016 — [ID4688-Audit policy enumerated](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1016-System%20Network%20Configuration%20Discovery/ID4688-Audit%20policy%20enumerated.evtx) _(explícito)_
- T1016 — [ID4688-Firewall configuration enumerated (command)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1016-System%20Network%20Configuration%20Discovery/ID4688-Firewall%20configuration%20enumerated%20%28command%29.evtx) _(explícito)_
- T1218.005 — [exec_persist_rundll32_mshta_scheduledtask_sysmon_1_3_11](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Execution/exec_persist_rundll32_mshta_scheduledtask_sysmon_1_3_11.evtx) _(inferido)_
- T1218.005 — [sysmon_mshta_sharpshooter_stageless_meterpreter](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Execution/sysmon_mshta_sharpshooter_stageless_meterpreter.evtx) _(inferido)_
- T1574.001 — [DE_timestomp_and_dll_sideloading_and_RunPersist](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/AutomatedTestingTools/Malware/DE_timestomp_and_dll_sideloading_and_RunPersist.evtx) _(inferido)_
- T1574.001 — [sideloading_injection_persistence_run_key](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/AutomatedTestingTools/Malware/sideloading_injection_persistence_run_key.evtx) _(inferido)_

## 9. Hipóteses de hunting

Se SideCopy estiver no seu ambiente, estas são as perguntas a fazer aos seus dados (fontes de log segundo as estratégias de detecção do MITRE ATT&CK).

1. **T1614 System Location Discovery** — Unusual process or API usage attempting to query system locale, timezone, or keyboard layout (e.g., calls to GetLocaleInfoW, GetTimeZoneInformation). Detection can be enhanced by correlating with processes not typically associated with system configuration… Dados: `WinEventLog:Security` (EventCode=4688), `etw:Microsoft-Windows-Kernel-Base` (GetLocaleInfoW, GetTimeZoneInformation API calls).
2. **T1598.002 Spearphishing Attachment** — Monitor network data for uncommon data flows. Processes utilizing the network that do not normally have network communication or have never been seen before are suspicious. Monitor for suspicious email activity, such as numerous accounts receiving messages… Dados: `Network Traffic` (None), `Application Log` (None), `Network Traffic` (None).
3. **T1584.001 Domains** — Monitor for logged domain name system (DNS) registry data that may hijack domains and/or subdomains that can be used during targeting. In some cases, abnormal subdomain IP addresses (such as those originating in a different country from the root domain) may… Dados: `Domain Name` (None), `Domain Name` (None), `Domain Name` (None).
4. **T1518 Software Discovery** — Adversary spawns a process or script to enumerate installed software using WMI, registry, or PowerShell, potentially followed by additional discovery or evasion behavior. Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:PowerShell` (Execution of 'Get-WmiObject Win32_Product' or similar PowerShell cmdlets).
5. **T1218.005 Mshta** — Detection of mshta.exe execution where command-line arguments reference remote or local HTA/script content (VBScript/JScript) followed by subsequent file creation, network retrieval, or process spawning that indicates payload execution outside standard… Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=3, 22), `WinEventLog:Sysmon` (EventCode=11).
6. **T1106 Native API** — Unusual or suspicious processes loading critical native API DLLs (e.g., ntdll.dll, kernel32.dll) followed by direct syscall behavior, memory manipulation, or hollowing. Dados: `WinEventLog:Sysmon` (EventCode=7), `WinEventLog:Sysmon` (EventCode=10), `WinEventLog:Sysmon` (EventCode=1).
7. **T1518.001 Security Software Discovery** — Adversary executes commands to enumerate installed antivirus, EDR, or firewall agents using WMI, registry queries, and built-in tools (e.g., tasklist, netsh, sc query). Correlated with elevated process privileges or scripting engine usage. Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=7).
8. **T1608.001 Upload Malware** — If infrastructure or patterns in malware have been previously identified, internet scanning may uncover when an adversary has staged malware to make it accessible for targeting. Much of this activity will take place outside the visibility of the target… Dados: `Internet Scan` (None).
9. **T1574.001 DLL** — DLL hijacking behaviors including unexpected DLL loads from non-standard directories, replacement of DLLs, phantom DLL insertion, redirection file creation, and substitution of legitimate DLLs. Defender correlates file system modifications, registry changes,… Dados: `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Sysmon` (EventCode=15), `WinEventLog:Sysmon` (EventCode=7).
10. **T1016 System Network Configuration Discovery** — Execution of built-in tools (e.g., ipconfig, route, netsh) or PowerShell/WMI queries to enumerate IP, MAC, interface status, or routing configuration. Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:PowerShell` (EventCode=4103, 4104, 4105, 4106).
11. **T1059.005 Visual Basic** — Detects execution of VB-based scripts or macros (VBS/VBA/VBScript) through cscript.exe/wscript.exe, Office-based process chains, or HTA usage. Focuses on chained behavior: Office or HTML container spawns script host > script host spawns PowerShell, network… Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=7).
12. **T1082 System Information Discovery** — Detection of processes executing system environment inspection operations followed by access to OS configuration APIs or registry locations that expose OS version, architecture, patch level, or hardware characteristics. Defenders observe process execution… Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:PowerShell` (EventCode=4103, 4104, 4105, 4106), `WinEventLog:Sysmon` (EventCode=1).

## 10. OSINT — onde pesquisar

Consultas prontas com todos os nomes conhecidos do grupo:

- Relatórios técnicos: [busca web](https://duckduckgo.com/?q=%28%22SideCopy%22%29+threat+report) · [PDFs](https://duckduckgo.com/?q=%28%22SideCopy%22%29+filetype%3Apdf)
- Regras e IOCs publicados: [GitHub](https://github.com/search?type=code&q=%22SideCopy%22)
- Pulsos de ameaça: [AlienVault OTX](https://otx.alienvault.com/browse/global/pulses?q=SideCopy)
- Família de malware e atores: [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/actors) (busque por SideCopy)
- Cartões de grupo: [ThaiCERT Threat Group Cards](https://apt.etda.or.th/cgi-bin/listgroups.cgi)
- Página oficial: [MITRE ATT&CK G1008](https://attack.mitre.org/groups/G1008/)

**Relatórios na coleção CyberMonitor** (ligados pelo nome do grupo, conferir antes de citar):

- 2020 — [Seqrite-WhitePaper-Operation-SideCopy](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2020/2020.09.23.Operation_SideCopy/Seqrite-WhitePaper-Operation-SideCopy.pdf) _(via “SideCopy”)_

## 11. Bibliografia (1 fontes citadas pelo ATT&CK)

- [MalwareBytes SideCopy Dec 2021](https://www.malwarebytes.com/blog/news/2021/12/sidecopy-apt-connecting-lures-to-victims-payloads-to-infrastructure) — Threat Intelligence Team. (2021, December 2). SideCopy APT: Connecting lures victims, payloads to infrastructure. Retrieved June 13, 2022.

## 12. Limites e confiança

- O ATT&CK registra o que foi **relatado publicamente**, não tudo o que o grupo faz. Ausência de uma técnica não prova que o grupo não a usa.
- **Sobreposição de TTP não é atribuição.** Muitas técnicas são compartilhadas entre grupos e com red teams. Use a assinatura comportamental como hipótese, junto com infraestrutura, malware e contexto.
- Cobertura de detecção refere-se ao catálogo público Detection Rules, não ao seu ambiente: confira se a telemetria necessária chega ao seu SIEM.
- Ligações marcadas como _inferidas_ (EVTX por palavra-chave, relatórios por nome) devem ser verificadas.

---
Fontes: MITRE ATT&CK® (uso livre com atribuição, © The MITRE Corporation), Atomic Red Team (Red Canary, MIT), EVTX-to-MITRE-Attack, EVTX-ATTACK-SAMPLES, APT & CyberCriminal Campaign Collections. Gerado por [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules).
