# Moses Staff (G1009) — Dossiê de inteligência

> **TLP:CLEAR** · gerado em 2026-10-25 a partir de fontes abertas · MITRE ATT&CK v20.0 · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1009) · [ATT&CK](https://attack.mitre.org/groups/G1009/)

**Também conhecido como:** DEV-0500, Marigold Sandstorm  
**Registro no ATT&CK:** criado em 2022-08-11, atualizado em 2026-07-31 · referências de 2021 a 2023

## 1. Sumário executivo

- **12 técnicas** atribuídas publicamente, concentradas em **Discovery, Defense Impairment, Resource Development**.
- **Arsenal:** 3 malware e 1 ferramentas (ex.: StrifeWater, PyDCrypt, DCSrv, PsExec).
- **Campanhas atribuídas:** 0.
- **Cobertura de detecção pública:** 100% das técnicas têm ao menos uma regra no catálogo; **0 técnicas sem nenhuma regra pública**.
- **Assinatura comportamental** (técnicas raras entre os 178 grupos, as mais úteis para atribuição): T1686.003 Windows Host Firewall, T1087.001 Local Account, T1587.001 Malware, T1021.002 SMB/Windows Admin Shares, T1553.002 Code Signing.

## 2. Quem é

> Moses Staff is a suspected Iranian threat group that has primarily targeted Israeli companies since at least September 2021. Moses Staff openly stated their motivation in attacking Israeli companies is to cause damage by leaking stolen sensitive data and encrypting the victim's networks without a ransom demand. 
> 
> Security researchers assess Moses Staff is politically motivated, and has targeted government, finance, travel, energy, manufacturing, and utility companies outside of Israel as well, including those in Italy, India, Germany, Chile, Turkey, the UAE, and the US.

_Texto original do MITRE ATT&CK, em inglês._

## 3. Perfil TTP por tática (kill chain)

Cada linha: técnica, como o grupo a usou segundo relatos públicos, e o que existe para detectar e testar.

### Resource Development (TA0042) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1587.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1587.001) Malware | Moses Staff has built malware, such as DCSrv and PyDCrypt, for targeting victims' machines. | 43 | — | — |
| [T1588.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1588.002) Tool | Moses Staff has used the commercial tool DiskCryptor. | 35 | — | — |

### Initial Access (TA0001) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1190](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1190) Exploit Public-Facing Application | Moses Staff has exploited known vulnerabilities in public-facing infrastructure such as Microsoft Exchange Servers. | 580 | — | — |

### Persistence (TA0003) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1505.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1505.003) Web Shell | Moses Staff has dropped a web shell onto a compromised system. | 210 | 1 | — |

### Stealth (TA0005) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1027.013](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1027.013) Encrypted/Encoded File | Moses Staff has used obfuscated web shells in their operations. | 8 | 4 | — |

### Defense Impairment (TA0112) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1553.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1553.002) Code Signing | Moses Staff has used signed drivers from an open source tool called DiskCryptor to evade detection. | 11 | — | — |
| [T1686.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1686.003) Windows Host Firewall | Moses Staff has used batch scripts that can disable the Windows firewall on specific remote machines. | 64 | 2 | — |

### Discovery (TA0007) — 3

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1016](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1016) System Network Configuration Discovery | Moses Staff has collected the domain name of a compromised network. | 99 | 10 | 5 |
| [T1082](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1082) System Information Discovery | Moses Staff collected information about the infected host, including the machine names and OS architecture. | 264 | 41 | — |
| [T1087.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1087.001) Local Account | Moses Staff has collected the administrator username from a compromised host. | 98 | 11 | — |

### Lateral Movement (TA0008) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1021.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1021.002) SMB/Windows Admin Shares | Moses Staff has used batch scripts that can enable SMB on a compromised host. | 272 | 4 | 20 |

### Command and Control (TA0011) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1105](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1105) Ingress Tool Transfer | Moses Staff has downloaded and installed web shells to following path C:\inetpub\wwwroot\aspnet_client\system_web\IISpool.aspx. | 644 | 39 | — |

## 4. Assinatura comportamental

Técnicas que este grupo usa e que poucos dos 178 grupos do ATT&CK usam. Pesam mais numa atribuição por TTP: ver várias delas juntas é mais informativo do que ver técnicas comuns como PowerShell.

| Técnica | Outros grupos que usam | Peso (raridade) |
|---|---:|---:|
| T1686.003 Windows Host Firewall | 5 | 3.24 |
| T1087.001 Local Account | 18 | 2.19 |
| T1587.001 Malware | 26 | 1.85 |
| T1021.002 SMB/Windows Admin Shares | 27 | 1.82 |
| T1553.002 Code Signing | 27 | 1.82 |
| T1505.003 Web Shell | 30 | 1.72 |
| T1027.013 Encrypted/Encoded File | 39 | 1.47 |
| T1016 System Network Configuration Discovery | 44 | 1.36 |
| T1190 Exploit Public-Facing Application | 46 | 1.32 |
| T1082 System Information Discovery | 58 | 1.09 |

## 5. Arsenal

| Software | Tipo | Técnicas no ATT&CK | Uso relatado (EN) |
|---|---|---:|---|
| [StrifeWater](https://attack.mitre.org/software/S1034/) | malware | 15 |  |
| [PyDCrypt](https://attack.mitre.org/software/S1032/) | malware | 11 |  |
| [DCSrv](https://attack.mitre.org/software/S1033/) | malware | 8 |  |
| [PsExec](https://attack.mitre.org/software/S0029/) | ferramenta | 5 |  |

## 6. Campanhas

Nenhuma campanha atribuída no ATT&CK.

## 7. Cobertura defensiva

**12 de 12 técnicas (100%)** têm ao menos uma regra pública no catálogo Detection Rules.

### Regras recomendadas por técnica

Melhor regra disponível por técnica (formato portável e maduro primeiro).

| Técnica | Regra | Formato | Fonte |
|---|---|---|---|
| T1016 | [Potential Pikabot Discovery Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A698d4431-514f-4c82-af4d-cf573872a9f5) | Sigma | SigmaHQ |
| T1016 | [OpenCanary - SNMP OID Request](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae9856028-fd4e-46e6-b3d1-10f7ceb95078) | Sigma | SigmaHQ |
| T1021.002 | [PSExec Lateral Movement](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=hayabusa-native%3A%3A0694c340-3a46-40ac-acfc-c3444ae6572c) | Sigma | Hayabusa (native) |
| T1021.002 | [Turla Group Lateral Movement](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac601f20d-570a-4cde-a7d6-e17f99cb8e7f) | Sigma | SigmaHQ |
| T1027.013 | [ROT Encoded Python Script Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A5ab49127-b1b3-46e6-8a38-9e8512a2a363) | Elastic | Elastic detection-rules |
| T1027.013 | [Data Encrypted via OpenSSL Utility](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Afeba48f6-40ca-4d04-b41f-5dfa327de865) | Elastic | Elastic detection-rules |
| T1082 | [Potential GobRAT File Discovery Via Grep](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae34cfa0c-0a50-4210-9cb3-5632d08eb041) | Sigma | SigmaHQ |
| T1082 | [System Information Discovery](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A42df45e7-e6e9-43b5-8f26-bec5b39cc239) | Sigma | SigmaHQ |
| T1087.001 | [BloodHound Collection Files](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A02773bed-83bf-469f-b7ff-e676e7d78bab) | Sigma | SigmaHQ |
| T1087.001 | [HackTool - Bloodhound/Sharphound Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Af376c8a7-a2d0-4ddc-aa0c-16c17236d962) | Sigma | SigmaHQ |
| T1105 | [Greenbug Espionage Group Indicators](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A3711eee4-a808-4849-8a14-faf733da3612) | Sigma | SigmaHQ |
| T1105 | [Pandemic Registry Key](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A47e0852a-cf81-4494-a8e6-31864f8c86ed) | Sigma | SigmaHQ |
| T1190 | [OMIGOD HTTP No Authentication RCE - CVE-2021-38647](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aab6b1a39-a9ee-4ab4-b075-e83acf6e346b) | Sigma | SigmaHQ |
| T1190 | [Exploited CVE-2020-10189 Zoho ManageEngine](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A846b866e-2a57-46ee-8e16-85fa92759be7) | Sigma | OpenSearch Security Analytics |
| T1505.003 | [MOVEit CVE-2023-34362 Exploitation Attempt - Potential Web Shell Request](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A435e41f2-48eb-4c95-8a2b-ed24b50ec30b) | Sigma | SigmaHQ |
| T1505.003 | [Solarwinds SUPERNOVA Webshell Access](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aa2cee20b-eacc-459f-861d-c02e5d12f1db) | Sigma | SigmaHQ |
| T1553.002 | [Driver Loaded (Invalid Signature)](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=hayabusa-native%3A%3A1f666722-3948-40a2-9d78-d9d374477a90) | Sigma | Hayabusa (native) |
| T1553.002 | [Driver Loaded (Expired/Revoked Cert)](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=hayabusa-native%3A%3Ac837dd6d-0c91-4593-aeab-f6a1f3ca1961) | Sigma | Hayabusa (native) |
| T1587.001 | [Formbook Process Creation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A032f5fb3-d959-41a5-9263-4173c802dc2b) | Sigma | SigmaHQ |
| T1587.001 | [Uncommon File Created In Office Startup Folder](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aa10a2c40-2c4d-49f8-b557-1a946bc55d9d) | Sigma | SigmaHQ |
| T1588.002 | [Hacktool Execution - Imphash](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A24e3e58a-646b-4b50-adef-02ef935b9fc8) | Sigma | SigmaHQ |
| T1588.002 | [Renamed SysInternals DebugView Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acd764533-2e07-40d6-a718-cfeec7f2da7f) | Sigma | SigmaHQ |
| T1686.003 | [Suspicious Program Location Whitelisted In Firewall Via Netsh.EXE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aa35f5a72-f347-4e36-8895-9869b0d5fc6d) | Sigma | SigmaHQ |
| T1686.003 | [RDP Connection Allowed Via Netsh.EXE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A01aeb693-138d-49d2-9403-c4f52d7d3d62) | Sigma | SigmaHQ |

## 8. Plano de emulação e validação

Use num laboratório isolado e autorizado para confirmar que as regras disparam. Os comandos estão nos repositórios oficiais.

| Tática | Técnica | Teste Atomic Red Team | Plataformas |
|---|---|---|---|
| Persistence | [T1505.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1505.003/T1505.003.md) | Web Shell Written to Disk | windows |
| Stealth | [T1027.013](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027.013/T1027.013.md) | Decode Eicar File and Write to File | linux, macos, windows |
| Stealth | [T1027.013](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027.013/T1027.013.md) | Decrypt Eicar File and Write to File | linux, macos, windows |
| Defense Impairment | [T1686.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1686.003/T1686.003.md) | Enable Firewall Rule Group via COM Object (HNetCfg.FwPolicy2) | windows |
| Defense Impairment | [T1686.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1686.003/T1686.003.md) | Set All Network Profiles to Private via Registry | windows |
| Discovery | [T1016](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1016/T1016.md) | System Network Configuration Discovery on Windows | windows |
| Discovery | [T1016](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1016/T1016.md) | List Windows Firewall Rules | windows |
| Discovery | [T1082](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1082/T1082.md) | System Information Discovery | windows |
| Discovery | [T1082](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1082/T1082.md) | System Information Discovery | macos |
| Discovery | [T1087.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1087.001/T1087.001.md) | Enumerate all accounts (Local) | linux |
| Discovery | [T1087.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1087.001/T1087.001.md) | View sudoers access | linux, macos |
| Lateral Movement | [T1021.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.002/T1021.002.md) | Map admin share | windows |
| Lateral Movement | [T1021.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.002/T1021.002.md) | Map Admin Share PowerShell | windows |
| Command and Control | [T1105](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1105/T1105.md) | rsync remote file copy (push) | linux, macos |
| Command and Control | [T1105](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1105/T1105.md) | rsync remote file copy (pull) | linux, macos |

**Logs reais de ataque (EVTX) para testar sem executar nada:**

- T1016 — [ID4688-Audit policy enumerated](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1016-System%20Network%20Configuration%20Discovery/ID4688-Audit%20policy%20enumerated.evtx) _(explícito)_
- T1016 — [ID4688-Firewall configuration enumerated (command)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1016-System%20Network%20Configuration%20Discovery/ID4688-Firewall%20configuration%20enumerated%20%28command%29.evtx) _(explícito)_
- T1021.002 — [ID4688,4697,5140-5145 PSexec remote execution + admin share](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0008-Lateral%20Movement/T1021.002-SMB%20Windows%20Admin%20Shares/ID4688%2C4697%2C5140-5145%20PSexec%20remote%20execution%20%2B%20admin%20share.evtx) _(explícito)_
- T1021.002 — [ID4688-4648 Lateral movement with net use](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0008-Lateral%20Movement/T1021.002-SMB%20Windows%20Admin%20Shares/ID4688-4648%20Lateral%20movement%20with%20net%20use.evtx) _(explícito)_

## 9. Hipóteses de hunting

Se Moses Staff estiver no seu ambiente, estas são as perguntas a fazer aos seus dados (fontes de log segundo as estratégias de detecção do MITRE ATT&CK).

1. **T1686.003 Windows Host Firewall** — Detects processes or users modifying Windows Defender Firewall profiles, policies, or rules followed by measurable network exposure changes. Correlates firewall management execution, registry/policy mutation, service state changes, and subsequent inbound or… Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=13, 14).
2. **T1087.001 Local Account** — Adversary enumeration of local user accounts using Net.exe, WMI, or PowerShell. Dados: `WinEventLog:Sysmon` (EventCode=1).
3. **T1587.001 Malware** — Consider analyzing malware for features that may be associated with the adversary and/or their developers, such as compiler used, debugging artifacts, or code similarities. Malware repositories can also be used to identify additional samples associated with… Dados: `Malware Repository` (None), `Malware Repository` (None).
4. **T1021.002 SMB/Windows Admin Shares** — An SMB-based remote file share access followed by lateral movement actions such as remote service creation, task scheduling, or suspicious process execution on the target host using ADMIN$ or C$ shares. Dados: `WinEventLog:Security` (EventCode=4624, 4648), `WinEventLog:Sysmon` (EventCode=3, 22), `WinEventLog:Sysmon` (EventCode=1).
5. **T1553.002 Code Signing** — Detects execution of binaries signed with unusual or recently issued certificates, correlation of process execution with abnormal publisher metadata, and mismatched certificate chains. Monitors for revoked or unknown code signing certificates used in… Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=7).
6. **T1505.003 Web Shell** — Unexpected file creation in web directories followed by web server processes (e.g., w3wp.exe) spawning command shells or script interpreters (e.g., cmd.exe, powershell.exe) Dados: `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Security` (EventCode=4624, 4648).
7. **T1027.013 Encrypted/Encoded File** — Detection of processes that load or decode encrypted/encoded files in memory and subsequently execute or inject them, indicating payload unpacking or memory-resident malware. Dados: `WinEventLog:Sysmon` (EventCode=7), `WinEventLog:Sysmon` (EventCode=10), `WinEventLog:Security` (EventCode=4688).
8. **T1016 System Network Configuration Discovery** — Execution of built-in tools (e.g., ipconfig, route, netsh) or PowerShell/WMI queries to enumerate IP, MAC, interface status, or routing configuration. Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:PowerShell` (EventCode=4103, 4104, 4105, 4106).
9. **T1190 Exploit Public-Facing Application** — Adversary sends crafted HTTP/S (or other service) input to an Internet-facing app (IIS/ASP.NET, API, device portal). Chain: (1) abnormal request patterns to public endpoint → (2) elevated 4xx/5xx or unusual methods/paths → (3) server process (w3wp.exe/other… Dados: `ApplicationLog:IIS` (IIS W3C logs in C:\inetpub\logs\LogFiles\W3SVC* (spikes in 5xx, RCE/SQLi/path traversal/JNDI patterns)), `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=7).
10. **T1082 System Information Discovery** — Detection of processes executing system environment inspection operations followed by access to OS configuration APIs or registry locations that expose OS version, architecture, patch level, or hardware characteristics. Defenders observe process execution… Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:PowerShell` (EventCode=4103, 4104, 4105, 4106), `WinEventLog:Sysmon` (EventCode=1).
11. **T1588.002 Tool** — Monitor for contextual data about a malicious payload, such as compilation times, file hashes, as well as watermarks or other identifiable configuration information. In some cases, malware repositories can also be used to identify features of tool use… Dados: `Malware Repository` (None).
12. **T1105 Ingress Tool Transfer** — Unusual or uncommon processes initiate network connections to external destinations followed by file creation (tools downloaded). Dados: `WinEventLog:Sysmon` (EventCode=3, 22), `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Sysmon` (EventCode=1).

## 10. OSINT — onde pesquisar

Consultas prontas com todos os nomes conhecidos do grupo:

- Relatórios técnicos: [busca web](https://duckduckgo.com/?q=%28%22Moses+Staff%22+OR+%22DEV-0500%22+OR+%22Marigold+Sandstorm%22%29+threat+report) · [PDFs](https://duckduckgo.com/?q=%28%22Moses+Staff%22+OR+%22DEV-0500%22+OR+%22Marigold+Sandstorm%22%29+filetype%3Apdf)
- Regras e IOCs publicados: [GitHub](https://github.com/search?type=code&q=%22Moses+Staff%22+OR+%22DEV-0500%22+OR+%22Marigold+Sandstorm%22)
- Pulsos de ameaça: [AlienVault OTX](https://otx.alienvault.com/browse/global/pulses?q=Moses+Staff)
- Família de malware e atores: [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/actors) (busque por Moses Staff, DEV-0500, Marigold Sandstorm)
- Cartões de grupo: [ThaiCERT Threat Group Cards](https://apt.etda.or.th/cgi-bin/listgroups.cgi)
- Página oficial: [MITRE ATT&CK G1009](https://attack.mitre.org/groups/G1009/)

## 11. Bibliografia (3 fontes citadas pelo ATT&CK)

- [Checkpoint MosesStaff Nov 2021](https://research.checkpoint.com/2021/mosesstaff-targeting-israeli-companies/) — Checkpoint Research. (2021, November 15). Uncovering MosesStaff techniques: Ideology over Money. Retrieved August 11, 2022.
- [Cybereason StrifeWater Feb 2022](https://www.cybereason.com/blog/research/strifewater-rat-iranian-apt-moses-staff-adds-new-trojan-to-ransomware-operations) — Cybereason Nocturnus. (2022, February 1). StrifeWater RAT: Iranian APT Moses Staff Adds New Trojan to Ransomware Operations. Retrieved August 15, 2022.
- [Microsoft Threat Actor Naming July 2023](https://learn.microsoft.com/en-us/microsoft-365/security/intelligence/microsoft-threat-actor-naming?view=o365-worldwide) — Microsoft . (2023, July 12). How Microsoft names threat actors. Retrieved November 17, 2023.

## 12. Limites e confiança

- O ATT&CK registra o que foi **relatado publicamente**, não tudo o que o grupo faz. Ausência de uma técnica não prova que o grupo não a usa.
- **Sobreposição de TTP não é atribuição.** Muitas técnicas são compartilhadas entre grupos e com red teams. Use a assinatura comportamental como hipótese, junto com infraestrutura, malware e contexto.
- Cobertura de detecção refere-se ao catálogo público Detection Rules, não ao seu ambiente: confira se a telemetria necessária chega ao seu SIEM.
- Ligações marcadas como _inferidas_ (EVTX por palavra-chave, relatórios por nome) devem ser verificadas.

---
Fontes: MITRE ATT&CK® (uso livre com atribuição, © The MITRE Corporation), Atomic Red Team (Red Canary, MIT), EVTX-to-MITRE-Attack, EVTX-ATTACK-SAMPLES, APT & CyberCriminal Campaign Collections. Gerado por [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules).
