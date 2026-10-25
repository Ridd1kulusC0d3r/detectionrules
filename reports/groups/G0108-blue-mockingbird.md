# Blue Mockingbird (G0108) — Dossiê de inteligência

> **TLP:CLEAR** · gerado em 2026-10-25 a partir de fontes abertas · MITRE ATT&CK v20.0 · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0108) · [ATT&CK](https://attack.mitre.org/groups/G0108/)

**Também conhecido como:** —  
**Registro no ATT&CK:** criado em 2020-05-26, atualizado em 2026-07-31 · referências de 2020 a 2020

## 1. Sumário executivo

- **22 técnicas** atribuídas publicamente, concentradas em **Stealth, Execution, Persistence**.
- **Arsenal:** 0 malware e 2 ferramentas (ex.: Mimikatz, FRP).
- **Campanhas atribuídas:** 0.
- **Cobertura de detecção pública:** 100% das técnicas têm ao menos uma regra no catálogo; **0 técnicas sem nenhuma regra pública**.
- **Assinatura comportamental** (técnicas raras entre os 178 grupos, as mais úteis para atribuição): T1574.012 COR_PROFILER, T1134 Access Token Manipulation, T1496.001 Compute Hijacking, T1546.003 Windows Management Instrumentation Event Subscription, T1218.010 Regsvr32.

## 2. Quem é

> Blue Mockingbird is a cluster of observed activity involving Monero cryptocurrency-mining payloads in dynamic-link library (DLL) form on Windows systems. The earliest observed Blue Mockingbird tools were created in December 2019.

_Texto original do MITRE ATT&CK, em inglês._

## 3. Perfil TTP por tática (kill chain)

Cada linha: técnica, como o grupo a usou segundo relatos públicos, e o que existe para detectar e testar.

### Resource Development (TA0042) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1588.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1588.002) Tool | Blue Mockingbird has obtained and used tools such as Mimikatz. | 35 | — | — |

### Initial Access (TA0001) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1190](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1190) Exploit Public-Facing Application | Blue Mockingbird has gained initial access by exploiting CVE-2019-18935, a vulnerability within Telerik UI for ASP.NET AJAX. | 580 | — | — |

### Execution (TA0002) — 6

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1047](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1047) Windows Management Instrumentation | Blue Mockingbird has used wmic.exe to set environment variables. | 370 | 12 | 11 |
| [T1053.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1053.005) Scheduled Task | Blue Mockingbird has used Windows Scheduled Tasks to establish persistence on local and remote hosts. | 248 | 14 | 11 |
| [T1059.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.001) PowerShell | Blue Mockingbird has used PowerShell reverse TCP shells to issue interactive commands over a network connection. | 1340 | 22 | 15 |
| [T1059.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.003) Windows Command Shell | Blue Mockingbird has used batch script files to automate execution and deployment of payloads. | 269 | 6 | 1 |
| [T1569.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1569.002) Service Execution | Blue Mockingbird has executed custom-compiled XMRIG miner DLLs by configuring them to execute via the "wercplsupport" service. | 230 | 8 | 8 |
| [T1574.012](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1574.012) COR_PROFILER | Blue Mockingbird has used wmic.exe and Windows Registry modifications to set the COR_PROFILER environment variable to execute a malicious DLL whenever a process loads the .NET CLR. | 15 | 3 | — |

### Persistence (TA0003) — 4

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1053.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1053.005) Scheduled Task | Blue Mockingbird has used Windows Scheduled Tasks to establish persistence on local and remote hosts. | 248 | 14 | 11 |
| [T1112](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1112) Modify Registry | Blue Mockingbird has used Windows Registry modifications to specify a DLL payload. | 601 | 92 | 3 |
| [T1543.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1543.003) Windows Service | Blue Mockingbird has made their XMRIG payloads persistent as a Windows Service. | 1916 | 6 | 19 |
| [T1546.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1546.003) Windows Management Instrumentation Event Subscription | Blue Mockingbird has used mofcomp.exe to establish WMI Event Subscription persistence mechanisms configured from a *.mof file. | 99 | 4 | — |

### Privilege Escalation (TA0004) — 4

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1053.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1053.005) Scheduled Task | Blue Mockingbird has used Windows Scheduled Tasks to establish persistence on local and remote hosts. | 248 | 14 | 11 |
| [T1134](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1134) Access Token Manipulation | Blue Mockingbird has used JuicyPotato to abuse the SeImpersonate token privilege to escalate from web application pool accounts to NT Authority\SYSTEM. | 82 | — | 14 |
| [T1543.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1543.003) Windows Service | Blue Mockingbird has made their XMRIG payloads persistent as a Windows Service. | 1916 | 6 | 19 |
| [T1546.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1546.003) Windows Management Instrumentation Event Subscription | Blue Mockingbird has used mofcomp.exe to establish WMI Event Subscription persistence mechanisms configured from a *.mof file. | 99 | 4 | — |

### Stealth (TA0005) — 6

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1027.013](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1027.013) Encrypted/Encoded File | Blue Mockingbird has obfuscated the wallet address in the payload binary. | 8 | 4 | — |
| [T1036.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1036.005) Match Legitimate Resource Name or Location | Blue Mockingbird has masqueraded their XMRIG payload name by naming it wercplsupporte.dll after the legitimate wercplsupport.dll file. | 116 | 4 | — |
| [T1134](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1134) Access Token Manipulation | Blue Mockingbird has used JuicyPotato to abuse the SeImpersonate token privilege to escalate from web application pool accounts to NT Authority\SYSTEM. | 82 | — | 14 |
| [T1218.010](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1218.010) Regsvr32 | Blue Mockingbird has executed custom-compiled XMRIG miner DLLs using regsvr32.exe. | 150 | 5 | 2 |
| [T1218.011](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1218.011) Rundll32 | Blue Mockingbird has executed custom-compiled XMRIG miner DLLs using rundll32.exe. | 274 | 16 | 12 |
| [T1574.012](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1574.012) COR_PROFILER | Blue Mockingbird has used wmic.exe and Windows Registry modifications to set the COR_PROFILER environment variable to execute a malicious DLL whenever a process loads the .NET CLR. | 15 | 3 | — |

### Defense Impairment (TA0112) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1112](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1112) Modify Registry | Blue Mockingbird has used Windows Registry modifications to specify a DLL payload. | 601 | 92 | 3 |

### Credential Access (TA0006) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1003.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1003.001) LSASS Memory | Blue Mockingbird has used Mimikatz to retrieve credentials from LSASS memory. | 580 | 14 | 10 |

### Discovery (TA0007) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1082](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1082) System Information Discovery | Blue Mockingbird has collected hardware details for the victim's system, including CPU and memory information. | 264 | 41 | — |

### Lateral Movement (TA0008) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1021.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1021.001) Remote Desktop Protocol | Blue Mockingbird has used Remote Desktop to log on to servers interactively and manually copy files to remote hosts. | 139 | 4 | 7 |
| [T1021.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1021.002) SMB/Windows Admin Shares | Blue Mockingbird has used Windows Explorer to manually copy malicious files to remote hosts over SMB. | 272 | 4 | 20 |

### Command and Control (TA0011) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1090](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1090) Proxy | Blue Mockingbird has used FRP, ssf, and Venom to establish SOCKS proxy connections. | 162 | — | 1 |

### Impact (TA0040) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1496.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1496.001) Compute Hijacking | Blue Mockingbird has used XMRIG to mine cryptocurrency on victim systems. | 2 | — | — |

## 4. Assinatura comportamental

Técnicas que este grupo usa e que poucos dos 178 grupos do ATT&CK usam. Pesam mais numa atribuição por TTP: ver várias delas juntas é mais informativo do que ver técnicas comuns como PowerShell.

| Técnica | Outros grupos que usam | Peso (raridade) |
|---|---:|---:|
| T1574.012 COR_PROFILER | 0 | 4.49 |
| T1134 Access Token Manipulation | 2 | 3.80 |
| T1496.001 Compute Hijacking | 3 | 3.58 |
| T1546.003 Windows Management Instrumentation Event Subscription | 9 | 2.79 |
| T1218.010 Regsvr32 | 10 | 2.70 |
| T1569.002 Service Execution | 15 | 2.35 |
| T1090 Proxy | 19 | 2.14 |
| T1218.011 Rundll32 | 25 | 1.89 |
| T1543.003 Windows Service | 25 | 1.89 |
| T1021.002 SMB/Windows Admin Shares | 27 | 1.82 |

## 5. Arsenal

| Software | Tipo | Técnicas no ATT&CK | Uso relatado (EN) |
|---|---|---:|---|
| [Mimikatz](https://attack.mitre.org/software/S0002/) | ferramenta | 17 |  |
| [FRP](https://attack.mitre.org/software/S1144/) | ferramenta | 10 |  |

## 6. Campanhas

Nenhuma campanha atribuída no ATT&CK.

## 7. Cobertura defensiva

**22 de 22 técnicas (100%)** têm ao menos uma regra pública no catálogo Detection Rules.

### Regras recomendadas por técnica

Melhor regra disponível por técnica (formato portável e maduro primeiro).

| Técnica | Regra | Formato | Fonte |
|---|---|---|---|
| T1003.001 | [Antivirus - Password Dumper Signature](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A78cc2dd2-7d20-4d32-93ff-057084c38b93) | Sigma | SigmaHQ |
| T1003.001 | [Mimikatz through Windows Remote Management](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Aaa35a627-33fb-4d04-a165-d33b4afca3e8) | Sigma | OpenSearch Security Analytics |
| T1021.001 | [Hermetic Wiper TG Process Patterns](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A2f974656-6d83-4059-bbdf-68ac5403422f) | Sigma | SigmaHQ |
| T1021.001 | [Publicly Accessible RDP Service](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1fc0809e-06bf-4de3-ad52-25e5263b7623) | Sigma | SigmaHQ |
| T1021.002 | [PSExec Lateral Movement](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=hayabusa-native%3A%3A0694c340-3a46-40ac-acfc-c3444ae6572c) | Sigma | Hayabusa (native) |
| T1021.002 | [Turla Group Lateral Movement](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac601f20d-570a-4cde-a7d6-e17f99cb8e7f) | Sigma | SigmaHQ |
| T1027.013 | [ROT Encoded Python Script Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A5ab49127-b1b3-46e6-8a38-9e8512a2a363) | Elastic | Elastic detection-rules |
| T1027.013 | [Data Encrypted via OpenSSL Utility](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Afeba48f6-40ca-4d04-b41f-5dfa327de865) | Elastic | Elastic detection-rules |
| T1036.005 | [Exploit for CVE-2015-1641](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A7993792c-5ce2-4475-a3db-a3a5539827ef) | Sigma | SigmaHQ |
| T1036.005 | [Exploit for CVE-2015-1641](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A7993792c-5ce2-4475-a3db-a3a5539827ef) | Sigma | OpenSearch Security Analytics |
| T1047 | [HackTool - Potential Impacket Lateral Movement Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A10c14723-61c7-4c75-92ca-9af245723ad2) | Sigma | SigmaHQ |
| T1047 | [CrackMapExec Command Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A058f4380-962d-40a5-afce-50207d36d7e2) | Sigma | OpenSearch Security Analytics |
| T1053.005 | [Operation Wocao Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1cfac73c-be78-4f9a-9b08-5bde0c3953ab) | Sigma | SigmaHQ |
| T1053.005 | [Operation Wocao Activity - Security](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A74ad4314-482e-4c3e-b237-3f7ed3b9ca8d) | Sigma | SigmaHQ |
| T1059.001 | [Potential Emotet Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad02e8cf5-6099-48cf-9bfc-1eec2d0c7b18) | Sigma | SigmaHQ |
| T1059.001 | [TropicTrooper Campaign November 2018](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A8c7090c3-e0a0-4944-bd08-08c3a0cecf79) | Sigma | SigmaHQ |
| T1059.003 | [HackTool - CrackMapExec Execution Patterns](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A058f4380-962d-40a5-afce-50207d36d7e2) | Sigma | SigmaHQ |
| T1059.003 | [CrackMapExec Command Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A058f4380-962d-40a5-afce-50207d36d7e2) | Sigma | OpenSearch Security Analytics |
| T1082 | [Potential GobRAT File Discovery Via Grep](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae34cfa0c-0a50-4210-9cb3-5632d08eb041) | Sigma | SigmaHQ |
| T1082 | [System Information Discovery](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A42df45e7-e6e9-43b5-8f26-bec5b39cc239) | Sigma | SigmaHQ |
| T1090 | [Communication To LocaltoNet Tunneling Service Initiated - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac4568f5d-131f-4e78-83d4-45b2da0ec4f1) | Sigma | SigmaHQ |
| T1090 | [Communication To Ngrok Tunneling Service - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A19bf6fdb-7721-4f3d-867f-53467f6a5db6) | Sigma | SigmaHQ |
| T1112 | [ShimCache Flush](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab0524451-19af-4efa-a46f-562a977f792e) | Sigma | SigmaHQ |
| T1112 | [ShimCache Flush](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Ab0524451-19af-4efa-a46f-562a977f792e) | Sigma | OpenSearch Security Analytics |
| T1134 | [Suspicious SYSTEM User Process Creation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A2617e7ed-adb7-40ba-b0f3-8f9945fe6c09) | Sigma | SigmaHQ |
| T1134 | [HackTool - NoFilter Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A7b14c76a-c602-4ae6-9717-eff868153fc0) | Sigma | SigmaHQ |
| T1190 | [OMIGOD HTTP No Authentication RCE - CVE-2021-38647](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aab6b1a39-a9ee-4ab4-b075-e83acf6e346b) | Sigma | SigmaHQ |
| T1190 | [Exploited CVE-2020-10189 Zoho ManageEngine](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A846b866e-2a57-46ee-8e16-85fa92759be7) | Sigma | OpenSearch Security Analytics |
| T1218.010 | [Potential EmpireMonkey Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A10152a7b-b566-438f-a33c-390b607d1c8d) | Sigma | SigmaHQ |
| T1218.010 | [Suspicious Microsoft Office Child Process](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A438025f9-5856-4663-83f7-52f878a70a50) | Sigma | SigmaHQ |
| T1218.011 | [Equation Group DLL_U Export Function Load](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad465d1d8-27a2-4cca-9621-a800f37cf72e) | Sigma | SigmaHQ |
| T1218.011 | [APT29 2018 Phishing Campaign File Indicators](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A3a3f81ca-652c-482b-adeb-b1c804727f74) | Sigma | SigmaHQ |
| T1496.001 | [Newly Observed Process Exhibiting High CPU Usage](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Af9de0949-94d8-441d-ae9a-8eb1e040acf2) | Elastic | Elastic detection-rules |
| T1496.001 | [Memory Swap Modification](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A5e4023e7-6357-4061-ae1c-9df33e78c674) | Elastic | Elastic detection-rules |
| T1543.003 | [PSExec Lateral Movement](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=hayabusa-native%3A%3A0694c340-3a46-40ac-acfc-c3444ae6572c) | Sigma | Hayabusa (native) |
| T1543.003 | [Suspicious Service Name](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=hayabusa-native%3A%3Acc429813-21db-4019-b520-2f19648e1ef1) | Sigma | Hayabusa (native) |
| T1546.003 | [WMI Persistence - Script Event Consumer File Write](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A33f41cdd-35ac-4ba8-814b-c6a4244a1ad4) | Sigma | SigmaHQ |
| T1546.003 | [NewActiveScriptEventConsumer Creation Attempt via Wmic.EXE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aebef4391-1a81-4761-a40a-1db446c0e625) | Sigma | SigmaHQ |
| T1569.002 | [PSExec Lateral Movement](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=hayabusa-native%3A%3A0694c340-3a46-40ac-acfc-c3444ae6572c) | Sigma | Hayabusa (native) |
| T1569.002 | [DNS RCE CVE-2020-1350](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab5281f31-f9cc-4d0d-95d0-45b91c45b487) | Sigma | SigmaHQ |
| T1574.012 | [Enabling COR Profiler Environment Variables](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Aad89044a-8f49-4673-9a55-cbd88a1b374f) | Sigma | OpenSearch Security Analytics |
| T1574.012 | [Enabling COR Profiler Environment Variables](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aad89044a-8f49-4673-9a55-cbd88a1b374f) | Sigma | SigmaHQ |
| T1588.002 | [Hacktool Execution - Imphash](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A24e3e58a-646b-4b50-adef-02ef935b9fc8) | Sigma | SigmaHQ |
| T1588.002 | [Renamed SysInternals DebugView Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acd764533-2e07-40d6-a718-cfeec7f2da7f) | Sigma | SigmaHQ |

## 8. Plano de emulação e validação

Use num laboratório isolado e autorizado para confirmar que as regras disparam. Os comandos estão nos repositórios oficiais.

| Tática | Técnica | Teste Atomic Red Team | Plataformas |
|---|---|---|---|
| Execution | [T1047](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1047/T1047.md) | WMI Reconnaissance Users | windows |
| Execution | [T1047](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1047/T1047.md) | WMI Reconnaissance Processes | windows |
| Execution | [T1053.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1053.005/T1053.005.md) | Scheduled Task Startup Script | windows |
| Execution | [T1053.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1053.005/T1053.005.md) | Scheduled task Local | windows |
| Execution | [T1059.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md) | Mimikatz | windows |
| Execution | [T1059.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md) | Run BloodHound from local disk | windows |
| Execution | [T1059.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.003/T1059.003.md) | Create and Execute Batch Script | windows |
| Execution | [T1059.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.003/T1059.003.md) | Writes text to a file and displays it. | windows |
| Execution | [T1569.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1569.002/T1569.002.md) | Execute a Command as a Service | windows |
| Execution | [T1569.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1569.002/T1569.002.md) | Use PsExec to execute a command on a remote host | windows |
| Persistence | [T1543.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1543.003/T1543.003.md) | Modify Fax service to run PowerShell | windows |
| Persistence | [T1543.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1543.003/T1543.003.md) | Service Installation CMD | windows |
| Privilege Escalation | [T1546.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1546.003/T1546.003.md) | Persistence via WMI Event Subscription - CommandLineEventConsumer | windows |
| Privilege Escalation | [T1546.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1546.003/T1546.003.md) | Persistence via WMI Event Subscription - ActiveScriptEventConsumer | windows |
| Stealth | [T1027.013](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027.013/T1027.013.md) | Decode Eicar File and Write to File | linux, macos, windows |
| Stealth | [T1027.013](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027.013/T1027.013.md) | Decrypt Eicar File and Write to File | linux, macos, windows |
| Stealth | [T1036.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.005/T1036.005.md) | Execute a process from a directory masquerading as the current parent directory | linux, macos |
| Stealth | [T1036.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.005/T1036.005.md) | Masquerade as a built-in system executable | windows |
| Stealth | [T1218.010](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.010/T1218.010.md) | Regsvr32 local COM scriptlet execution | windows |
| Stealth | [T1218.010](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.010/T1218.010.md) | Regsvr32 remote COM scriptlet execution | windows |
| Stealth | [T1218.011](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.011/T1218.011.md) | Rundll32 execute JavaScript Remote Payload With GetObject | windows |
| Stealth | [T1218.011](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.011/T1218.011.md) | Rundll32 execute VBscript command | windows |
| Stealth | [T1574.012](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1574.012/T1574.012.md) | User scope COR_PROFILER | windows |
| Stealth | [T1574.012](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1574.012/T1574.012.md) | System Scope COR_PROFILER | windows |
| Defense Impairment | [T1112](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1112/T1112.md) | Modify Registry of Current User Profile - cmd | windows |
| Defense Impairment | [T1112](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1112/T1112.md) | Modify Registry of Local Machine - cmd | windows |
| Credential Access | [T1003.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/T1003.001.md) | Dump LSASS.exe Memory using ProcDump | windows |
| Credential Access | [T1003.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/T1003.001.md) | Dump LSASS.exe Memory using comsvcs.dll | windows |
| Discovery | [T1082](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1082/T1082.md) | System Information Discovery | windows |
| Discovery | [T1082](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1082/T1082.md) | System Information Discovery | macos |
| Lateral Movement | [T1021.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.001/T1021.001.md) | RDP to Remote Host | windows |
| Lateral Movement | [T1021.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.001/T1021.001.md) | Changing RDP Port to Non Standard Port via Powershell | windows |
| Lateral Movement | [T1021.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.002/T1021.002.md) | Map admin share | windows |
| Lateral Movement | [T1021.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.002/T1021.002.md) | Map Admin Share PowerShell | windows |

**Logs reais de ataque (EVTX) para testar sem executar nada:**

- T1003.001 — [CA_hashdump_4663_4656_lsass_access](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Credential%20Access/CA_hashdump_4663_4656_lsass_access.evtx) _(inferido)_
- T1003.001 — [LsassSilentProcessExit_process_exit_monitor_3001_lsass](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Credential%20Access/LsassSilentProcessExit_process_exit_monitor_3001_lsass.evtx) _(inferido)_
- T1021.001 — [ID4688,4778,4779 RDP hijack direct](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0008-Lateral%20Movement/T1021.001-Remote%20Desktop%20Protocol/ID4688%2C4778%2C4779%20RDP%20hijack%20direct.evtx) _(explícito)_
- T1021.001 — [ID4688-4778 RDP hijack command execution](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0008-Lateral%20Movement/T1021.001-Remote%20Desktop%20Protocol/ID4688-4778%20RDP%20hijack%20command%20execution.evtx) _(explícito)_
- T1021.002 — [ID4688,4697,5140-5145 PSexec remote execution + admin share](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0008-Lateral%20Movement/T1021.002-SMB%20Windows%20Admin%20Shares/ID4688%2C4697%2C5140-5145%20PSexec%20remote%20execution%20%2B%20admin%20share.evtx) _(explícito)_
- T1021.002 — [ID4688-4648 Lateral movement with net use](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0008-Lateral%20Movement/T1021.002-SMB%20Windows%20Admin%20Shares/ID4688-4648%20Lateral%20movement%20with%20net%20use.evtx) _(explícito)_
- T1047 — [ID1-WMI spwaning PowerShell process - WMImplant](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1047-Windows%20Management%20Instrumentation/ID1-WMI%20spwaning%20PowerShell%20process%20-%20WMImplant.evtx) _(explícito)_
- T1047 — [ID1-WMIexec process execution](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1047-Windows%20Management%20Instrumentation/ID1-WMIexec%20process%20execution.evtx) _(explícito)_
- T1053.005 — [ID4688-4698 Persistent scheduled task with SYSTEM privileges creation](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1053.005-Scheduled%20Task/ID4688-4698%20Persistent%20scheduled%20task%20with%20SYSTEM%20privileges%20creation.evtx) _(explícito)_
- T1053.005 — [ID4688-Interactive shell using AT schedule task](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1053.005-Scheduled%20Task/ID4688-Interactive%20shell%20using%20AT%20schedule%20task.evtx) _(explícito)_
- T1059.001 — [ID4103-4104-Payload download via PowerShell](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1059.001-PowerShell/ID4103-4104-Payload%20download%20via%20PowerShell.evtx) _(explícito)_
- T1059.001 — [ID4688-Encoded PowerShell MSF payload via process execution](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1059.001-PowerShell/ID4688-Encoded%20PowerShell%20MSF%20payload%20via%20process%20execution.evtx) _(explícito)_
- T1059.003 — [ID4688-SQL Server payload injectection for reverse shell (MSF)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1059.003-Windows%20Command%20Shell/ID4688-SQL%20Server%20payload%20injectection%20for%20reverse%20shell%20%28MSF%29.evtx) _(explícito)_
- T1090 — [ID5600-proxy configuration changed](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0011-Command%20and%20Control/T1090-Proxy/ID5600-proxy%20configuration%20changed.evtx) _(explícito)_
- T1112 — [ID11,13-SMBexec service registration](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0005-Defense%20Evasion/T1112-Modify%20registry/ID11%2C13-SMBexec%20service%20registration.evtx) _(explícito)_
- T1112 — [ID4624,4670,4688,4674-Registry permission change via WMI (DAMP)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0005-Defense%20Evasion/T1112-Modify%20registry/ID4624%2C4670%2C4688%2C4674-Registry%20permission%20change%20via%20WMI%20%28DAMP%29.evtx) _(explícito)_
- T1134 — [ID4648-4624-RunAsCS login](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0004-Privilege%20Escalation/T1134-Access%20Token%20Manipulation/ID4648-4624-RunAsCS%20login.evtx) _(explícito)_
- T1134 — [ID4688,4624-RottenPotatoNG](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0004-Privilege%20Escalation/T1134-Access%20Token%20Manipulation/ID4688%2C4624-RottenPotatoNG.evtx) _(explícito)_
- T1218.010 — [exec_sysmon_1_lolbin_renamed_regsvr32_scrobj](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Execution/exec_sysmon_1_lolbin_renamed_regsvr32_scrobj.evtx) _(inferido)_
- T1218.010 — [exec_sysmon_lobin_regsvr32_sct](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Execution/exec_sysmon_lobin_regsvr32_sct.evtx) _(inferido)_
- T1218.011 — [rundll32_cmd_schtask](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/AutomatedTestingTools/Malware/rundll32_cmd_schtask.evtx) _(inferido)_
- T1218.011 — [rundll32_hollowing_wermgr_masquerading](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/AutomatedTestingTools/Malware/rundll32_hollowing_wermgr_masquerading.evtx) _(inferido)_
- T1543.003 — [ID13-New service for Mimikatz](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0003-Persistence/T1543.003-Create%20or%20Modify%20System%20Process-Windows%20Service/ID13-New%20service%20for%20Mimikatz.evtx) _(explícito)_
- T1543.003 — [ID4688-4697 RDP hijack via service creation](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0003-Persistence/T1543.003-Create%20or%20Modify%20System%20Process-Windows%20Service/ID4688-4697%20RDP%20hijack%20via%20service%20creation.evtx) _(explícito)_
- T1569.002 — [ID5145-remote service creation over SMB](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1569.002-Service%20execution/ID5145-remote%20service%20creation%20over%20SMB.evtx) _(explícito)_

## 9. Hipóteses de hunting

Se Blue Mockingbird estiver no seu ambiente, estas são as perguntas a fazer aos seus dados (fontes de log segundo as estratégias de detecção do MITRE ATT&CK).

1. **T1574.012 COR_PROFILER** — Modification of COR_PROFILER-related environment variables or Registry keys (COR_ENABLE_PROFILING, COR_PROFILER, COR_PROFILER_PATH), combined with anomalous .NET process creation or unmanaged DLL loads. Defender observes registry modifications, suspicious… Dados: `WinEventLog:Security` (EventCode=4657), `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=7).
2. **T1134 Access Token Manipulation** — Detection of suspicious token manipulation chains: use of token-related APIs (e.g., LogonUser, DuplicateTokenEx) or commands (runas) → spawning of a new process under a different security context (e.g., SYSTEM) → mismatched parent-child process lineage or… Dados: `WinEventLog:Security` (EventCode=4672, 4634), `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=10).
3. **T1496.001 Compute Hijacking** — Sustained execution of resource-intensive processes (e.g., cryptocurrency miners), often launched via scheduled tasks, WMI, or PowerShell. These processes frequently establish persistent external connections and attempt to evade detection using masqueraded or… Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=3, 22), `WinEventLog:Security` (EventCode=4698).
4. **T1546.003 Windows Management Instrumentation Event Subscription** — Monitor for creation of WMI EventFilter, EventConsumer, and FilterToConsumerBinding objects through WMI or MOF file execution. Detect command-line execution of `mofcomp.exe`, usage of `Register-WmiEvent` via PowerShell, and anomalous child processes of… Dados: `WinEventLog:WMI` (EventCode=5857, 5858, 5860, 5861), `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=7).
5. **T1218.010 Regsvr32** — Detection focuses on identifying anomalous regsvr32.exe executions that deviate from normal administrative or system use. Defenders may observe regsvr32.exe loading scriptlets or DLLs from unusual paths (especially temporary directories or remote URLs),… Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=7), `WinEventLog:Sysmon` (EventCode=3, 22).
6. **T1569.002 Service Execution** — Detection focuses on abnormal service executions initiated via service control manager APIs, sc.exe, net.exe, or PsExec creating temporary services. Defenders observe process creation of services.exe spawning non-standard binaries, registry changes in service… Dados: `WinEventLog:Security` (EventCode=4697), `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=13, 14).
7. **T1090 Proxy** — Suspicious process spawning (e.g., `rundll32`, `svchost`, `powershell`, or `netsh`) followed by network connection creation to internal hosts or uncommon external endpoints on high or non-standard ports. Dados: `WinEventLog:Sysmon` (EventCode=3, 22), `WinEventLog:Sysmon` (EventCode=1), `NSM:Connections` (Outbound Connection).
8. **T1218.011 Rundll32** — Detects rundll32.exe invoked with atypical arguments (.dll, .cpl, javascript:, mshtml). DLLs not normally loaded by rundll32 are mapped into memory. Control_RunDLL or RunHTMLApplication invoked. Suspicious DLLs or scripts accessed from disk or network.… Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=7), `WinEventLog:Sysmon` (EventCode=11).
9. **T1543.003 Windows Service** — Detects creation or modification of Windows Services through command-line tools (e.g., `sc.exe`, `powershell.exe`), Registry key changes under `HKLM\System\CurrentControlSet\Services`, and service execution under SYSTEM with unsigned or anomalous binary… Dados: `WinEventLog:Security` (EventCode=4697), `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=13, 14).
10. **T1021.002 SMB/Windows Admin Shares** — An SMB-based remote file share access followed by lateral movement actions such as remote service creation, task scheduling, or suspicious process execution on the target host using ADMIN$ or C$ shares. Dados: `WinEventLog:Security` (EventCode=4624, 4648), `WinEventLog:Sysmon` (EventCode=3, 22), `WinEventLog:Sysmon` (EventCode=1).
11. **T1112 Modify Registry** — Behavior chain involving abnormal registry modifications via CLI, PowerShell, WMI, or direct API calls, especially targeting persistence, privilege escalation, or defense evasion keys, potentially followed by service restart or process execution. Such as… Dados: `WinEventLog:Sysmon` (EventCode=13, 14), `WinEventLog:Sysmon` (EventCode=1).
12. **T1021.001 Remote Desktop Protocol** — Remote Desktop (RDP) logon by a user followed by unusual process execution, file access, or lateral movement activity within a short timeframe. Dados: `WinEventLog:Security` (EventCode=4624, 4648), `WinEventLog:Security` (EventCode=4778, EventCode=4779), `WinEventLog:Sysmon` (EventCode=3, 22).

## 10. OSINT — onde pesquisar

Consultas prontas com todos os nomes conhecidos do grupo:

- Relatórios técnicos: [busca web](https://duckduckgo.com/?q=%28%22Blue+Mockingbird%22%29+threat+report) · [PDFs](https://duckduckgo.com/?q=%28%22Blue+Mockingbird%22%29+filetype%3Apdf)
- Regras e IOCs publicados: [GitHub](https://github.com/search?type=code&q=%22Blue+Mockingbird%22)
- Pulsos de ameaça: [AlienVault OTX](https://otx.alienvault.com/browse/global/pulses?q=Blue+Mockingbird)
- Família de malware e atores: [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/actors) (busque por Blue Mockingbird)
- Cartões de grupo: [ThaiCERT Threat Group Cards](https://apt.etda.or.th/cgi-bin/listgroups.cgi)
- Página oficial: [MITRE ATT&CK G0108](https://attack.mitre.org/groups/G0108/)

**Relatórios na coleção CyberMonitor** (ligados pelo nome do grupo, conferir antes de citar):

- 2020 — [Blue Mockingbird activity mines Monero cryptocurrency](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2020/2020.05.07_Blue_Mockingbird/Blue%20Mockingbird%20activity%20mines%20Monero%20cryptocurrency.pdf) _(via “Blue Mockingbird”)_
- 2020 — [Cryptocurrency-Miners-XMRig-Based-CoinMiner-by-Blue-Mockingbird-Group](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2020/2020.06.01.Blue_Mockingbird_Group/Cryptocurrency-Miners-XMRig-Based-CoinMiner-by-Blue-Mockingbird-Group.pdf) _(via “Blue Mockingbird”)_

## 11. Bibliografia (1 fontes citadas pelo ATT&CK)

- [RedCanary Mockingbird May 2020](https://redcanary.com/blog/blue-mockingbird-cryptominer/) — Lambert, T. (2020, May 7). Introducing Blue Mockingbird. Retrieved May 26, 2020.

## 12. Limites e confiança

- O ATT&CK registra o que foi **relatado publicamente**, não tudo o que o grupo faz. Ausência de uma técnica não prova que o grupo não a usa.
- **Sobreposição de TTP não é atribuição.** Muitas técnicas são compartilhadas entre grupos e com red teams. Use a assinatura comportamental como hipótese, junto com infraestrutura, malware e contexto.
- Cobertura de detecção refere-se ao catálogo público Detection Rules, não ao seu ambiente: confira se a telemetria necessária chega ao seu SIEM.
- Ligações marcadas como _inferidas_ (EVTX por palavra-chave, relatórios por nome) devem ser verificadas.

---
Fontes: MITRE ATT&CK® (uso livre com atribuição, © The MITRE Corporation), Atomic Red Team (Red Canary, MIT), EVTX-to-MITRE-Attack, EVTX-ATTACK-SAMPLES, APT & CyberCriminal Campaign Collections. Gerado por [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules).
