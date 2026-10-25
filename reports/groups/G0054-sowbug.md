# Sowbug (G0054) — Dossiê de inteligência

> **TLP:CLEAR** · gerado em 2026-10-25 a partir de fontes abertas · MITRE ATT&CK v20.0 · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0054) · [ATT&CK](https://attack.mitre.org/groups/G0054/)

**Também conhecido como:** —  
**Registro no ATT&CK:** criado em 2018-01-16, atualizado em 2026-07-31 · referências de 2017 a 2017

## 1. Sumário executivo

- **9 técnicas** atribuídas publicamente, concentradas em **Collection, Discovery, Credential Access**.
- **Arsenal:** 2 malware e 0 ferramentas (ex.: Felismus, Starloader).
- **Campanhas atribuídas:** 0.
- **Cobertura de detecção pública:** 100% das técnicas têm ao menos uma regra no catálogo; **0 técnicas sem nenhuma regra pública**.
- **Assinatura comportamental** (técnicas raras entre os 178 grupos, as mais úteis para atribuição): T1039 Data from Network Shared Drive, T1003 OS Credential Dumping, T1135 Network Share Discovery, T1056.001 Keylogging, T1560.001 Archive via Utility.

## 2. Quem é

> Sowbug is a threat group that has conducted targeted attacks against organizations in South America and Southeast Asia, particularly government entities, since at least 2015.

_Texto original do MITRE ATT&CK, em inglês._

## 3. Perfil TTP por tática (kill chain)

Cada linha: técnica, como o grupo a usou segundo relatos públicos, e o que existe para detectar e testar.

### Execution (TA0002) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1059.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.003) Windows Command Shell | Sowbug has used command line during its intrusions. | 269 | 6 | 1 |

### Stealth (TA0005) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1036.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1036.005) Match Legitimate Resource Name or Location | Sowbug named its tools to masquerade as Windows or Adobe Reader software, such as by using the file name adobecms.exe and the directory CSIDL_APPDATA\microsoft\security. | 116 | 4 | — |

### Credential Access (TA0006) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1003) OS Credential Dumping | Sowbug has used credential dumping tools. | 399 | 7 | 19 |
| [T1056.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1056.001) Keylogging | Sowbug has used keylogging tools. | 40 | 8 | 1 |

### Discovery (TA0007) — 3

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1082](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1082) System Information Discovery | Sowbug obtained OS version and hardware configuration from a victim. | 264 | 41 | — |
| [T1083](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1083) File and Directory Discovery | Sowbug identified and extracted all Word documents on a server by using a command containing * .doc and *.docx. The actors also searched for documents based on a specific date range and attempted to identify all installed software on a victim. | 137 | 9 | — |
| [T1135](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1135) Network Share Discovery | Sowbug listed remote shared drives that were accessible from a victim. | 73 | 12 | 3 |

### Collection (TA0009) — 3

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1039](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1039) Data from Network Shared Drive | Sowbug extracted Word documents from a file server on a victim network. | 24 | 2 | — |
| [T1056.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1056.001) Keylogging | Sowbug has used keylogging tools. | 40 | 8 | 1 |
| [T1560.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1560.001) Archive via Utility | Sowbug extracted documents and bundled them into a RAR archive. | 76 | 13 | — |

## 4. Assinatura comportamental

Técnicas que este grupo usa e que poucos dos 178 grupos do ATT&CK usam. Pesam mais numa atribuição por TTP: ver várias delas juntas é mais informativo do que ver técnicas comuns como PowerShell.

| Técnica | Outros grupos que usam | Peso (raridade) |
|---|---:|---:|
| T1039 Data from Network Shared Drive | 8 | 2.88 |
| T1003 OS Credential Dumping | 12 | 2.55 |
| T1135 Network Share Discovery | 15 | 2.35 |
| T1056.001 Keylogging | 25 | 1.89 |
| T1560.001 Archive via Utility | 39 | 1.47 |
| T1083 File and Directory Discovery | 51 | 1.22 |
| T1082 System Information Discovery | 58 | 1.09 |
| T1036.005 Match Legitimate Resource Name or Location | 65 | 0.98 |
| T1059.003 Windows Command Shell | 72 | 0.88 |

## 5. Arsenal

| Software | Tipo | Técnicas no ATT&CK | Uso relatado (EN) |
|---|---|---:|---|
| [Felismus](https://attack.mitre.org/software/S0171/) | malware | 10 |  |
| [Starloader](https://attack.mitre.org/software/S0188/) | malware | 2 |  |

## 6. Campanhas

Nenhuma campanha atribuída no ATT&CK.

## 7. Cobertura defensiva

**9 de 9 técnicas (100%)** têm ao menos uma regra pública no catálogo Detection Rules.

### Regras recomendadas por técnica

Melhor regra disponível por técnica (formato portável e maduro primeiro).

| Técnica | Regra | Formato | Fonte |
|---|---|---|---|
| T1003 | [Antivirus - Password Dumper Signature](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A78cc2dd2-7d20-4d32-93ff-057084c38b93) | Sigma | SigmaHQ |
| T1003 | [HackTool - Rubeus Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A7ec2c172-dceb-4c10-92c9-87c1881b7e18) | Sigma | SigmaHQ |
| T1036.005 | [Exploit for CVE-2015-1641](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A7993792c-5ce2-4475-a3db-a3a5539827ef) | Sigma | SigmaHQ |
| T1036.005 | [Exploit for CVE-2015-1641](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A7993792c-5ce2-4475-a3db-a3a5539827ef) | Sigma | OpenSearch Security Analytics |
| T1039 | [Copy from Admin Share](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A855bc8b5-2ae8-402e-a9ed-b889e6df1900) | Sigma | OpenSearch Security Analytics |
| T1039 | [PowerShell Share Enumeration Script](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A4c59cff1-b78a-41b8-a9f1-4231984d1fb6) | Elastic | Elastic detection-rules |
| T1056.001 | [Linux Keylogging with Pam.d](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A49aae26c-450e-448b-911d-b3c13d178dfc) | Sigma | SigmaHQ |
| T1056.001 | [Linux Keylogging with Pam.d](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A49aae26c-450e-448b-911d-b3c13d178dfc) | Sigma | OpenSearch Security Analytics |
| T1059.003 | [HackTool - CrackMapExec Execution Patterns](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A058f4380-962d-40a5-afce-50207d36d7e2) | Sigma | SigmaHQ |
| T1059.003 | [CrackMapExec Command Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A058f4380-962d-40a5-afce-50207d36d7e2) | Sigma | OpenSearch Security Analytics |
| T1082 | [Potential GobRAT File Discovery Via Grep](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae34cfa0c-0a50-4210-9cb3-5632d08eb041) | Sigma | SigmaHQ |
| T1082 | [System Information Discovery](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A42df45e7-e6e9-43b5-8f26-bec5b39cc239) | Sigma | SigmaHQ |
| T1083 | [Turla Group Lateral Movement](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac601f20d-570a-4cde-a7d6-e17f99cb8e7f) | Sigma | SigmaHQ |
| T1083 | [WannaCry Ransomware Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A41d40bff-377a-43e2-8e1b-2e543069e079) | Sigma | SigmaHQ |
| T1135 | [Potential Dridex Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae6eb5a96-9e6f-4a18-9cdd-642cfda21c8e) | Sigma | SigmaHQ |
| T1135 | [Dridex Process Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Ae6eb5a96-9e6f-4a18-9cdd-642cfda21c8e) | Sigma | OpenSearch Security Analytics |
| T1560.001 | [APT31 Judgement Panda Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A03e2746e-2b31-42f1-ab7a-eb39365b2422) | Sigma | SigmaHQ |
| T1560.001 | [Suspicious Manipulation Of Default Accounts Via Net.EXE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A5b768e71-86f2-4879-b448-81061cbae951) | Sigma | SigmaHQ |

## 8. Plano de emulação e validação

Use num laboratório isolado e autorizado para confirmar que as regras disparam. Os comandos estão nos repositórios oficiais.

| Tática | Técnica | Teste Atomic Red Team | Plataformas |
|---|---|---|---|
| Execution | [T1059.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.003/T1059.003.md) | Create and Execute Batch Script | windows |
| Execution | [T1059.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.003/T1059.003.md) | Writes text to a file and displays it. | windows |
| Stealth | [T1036.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.005/T1036.005.md) | Execute a process from a directory masquerading as the current parent directory | linux, macos |
| Stealth | [T1036.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.005/T1036.005.md) | Masquerade as a built-in system executable | windows |
| Credential Access | [T1003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003/T1003.md) | Gsecdump | windows |
| Credential Access | [T1003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003/T1003.md) | Credential Dumping with NPPSpy | windows |
| Discovery | [T1082](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1082/T1082.md) | System Information Discovery | windows |
| Discovery | [T1082](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1082/T1082.md) | System Information Discovery | macos |
| Discovery | [T1083](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1083/T1083.md) | File and Directory Discovery (cmd.exe) | windows |
| Discovery | [T1083](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1083/T1083.md) | File and Directory Discovery (PowerShell) | windows |
| Discovery | [T1135](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1135/T1135.md) | Network Share Discovery | macos |
| Discovery | [T1135](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1135/T1135.md) | Network Share Discovery - linux | linux |
| Collection | [T1039](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1039/T1039.md) | Copy a sensitive File over Administrative share with copy | windows |
| Collection | [T1039](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1039/T1039.md) | Copy a sensitive File over Administrative share with Powershell | windows |
| Collection | [T1056.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1056.001/T1056.001.md) | Input Capture | windows |
| Collection | [T1056.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1056.001/T1056.001.md) | Living off the land Terminal Input Capture on Linux with pam.d | linux |
| Collection | [T1560.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1560.001/T1560.001.md) | Compress Data for Exfiltration With Rar | windows |
| Collection | [T1560.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1560.001/T1560.001.md) | Compress Data and lock with password for Exfiltration with winrar | windows |

**Logs reais de ataque (EVTX) para testar sem executar nada:**

- T1003 — [ID1-12-13-Wdigest authentication activation](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0006-Credential%20Access/T1003-Credential%20dumping/ID1-12-13-Wdigest%20authentication%20activation.evtx) _(explícito)_
- T1003 — [ID1-LSASS dump with LSASSY (SYSMON)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0006-Credential%20Access/T1003-Credential%20dumping/ID1-LSASS%20dump%20with%20LSASSY%20%28SYSMON%29.evtx) _(explícito)_
- T1056.001 — [sysmon_13_keylogger_directx](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Credential%20Access/sysmon_13_keylogger_directx.evtx) _(inferido)_
- T1059.003 — [ID4688-SQL Server payload injectection for reverse shell (MSF)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1059.003-Windows%20Command%20Shell/ID4688-SQL%20Server%20payload%20injectection%20for%20reverse%20shell%20%28MSF%29.evtx) _(explícito)_
- T1135 — [ID4688-Network share discovery or connection via commandline](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1135.xxx-Network%20Share%20Discovery/ID4688-Network%20share%20discovery%20or%20connection%20via%20commandline.evtx) _(explícito)_
- T1135 — [ID5140-5145-Bloodhound-SharpHound enumeration via SMB](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1135.xxx-Network%20Share%20Discovery/ID5140-5145-Bloodhound-SharpHound%20enumeration%20via%20SMB.evtx) _(explícito)_

## 9. Hipóteses de hunting

Se Sowbug estiver no seu ambiente, estas são as perguntas a fazer aos seus dados (fontes de log segundo as estratégias de detecção do MITRE ATT&CK).

1. **T1039 Data from Network Shared Drive** — Monitoring of file access to network shares (e.g., C$, Admin$) followed by unusual read or copy operations by processes not typically associated with such activity (e.g., PowerShell, certutil). Dados: `WinEventLog:Security` (EventCode=5145), `WinEventLog:Sysmon` (EventCode=11).
2. **T1003 OS Credential Dumping** — Processes accessing LSASS memory or SAM registry hives outside of trusted security tools, often followed by file creation or lateral movement. Detects unauthorized access to sensitive OS subsystems for credential extraction. Dados: `WinEventLog:Sysmon` (EventCode=10), `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Security` (EventCode=4663, 4670, 4656).
3. **T1135 Network Share Discovery** — Process or script enumerates network shares via CLI (net view/net share, PowerShell Get-SmbShare/WMI) or OS APIs (NetShareEnum/ srvsvc.NetShareEnumAll RPC) → bursts of outbound SMB/RPC connections (445/139, \\host\IPC$ / srvsvc) to many hosts inside a short… Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=3, 22), `WinEventLog:Sysmon` (EventCode=17).
4. **T1056.001 Keylogging** — Monitors suspicious usage of Windows API calls like SetWindowsHookEx, GetKeyState, or polling functions within non-UI service processes, combined with Registry or driver modifications. Dados: `WinEventLog:Sysmon` (EventCode=10), `WinEventLog:Security` (EventCode=4663, 4670, 4656), `WinEventLog:System` (EventCode=7045).
5. **T1560.001 Archive via Utility** — Detects adversarial archiving using built-in or third-party utilities (makecab, diantz, xcopy, certutil, 7z, WinRAR, WinZip). Correlates suspicious process creation events with command-line arguments for compression/encoding, followed by creation of archive… Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Sysmon` (EventCode=7).
6. **T1083 File and Directory Discovery** — Execution of file enumeration commands (e.g., 'dir', 'tree') from non-standard processes or unusual user contexts, followed by recursive directory traversal or access to sensitive locations. Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=11).
7. **T1082 System Information Discovery** — Detection of processes executing system environment inspection operations followed by access to OS configuration APIs or registry locations that expose OS version, architecture, patch level, or hardware characteristics. Defenders observe process execution… Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:PowerShell` (EventCode=4103, 4104, 4105, 4106), `WinEventLog:Sysmon` (EventCode=1).
8. **T1036.005 Match Legitimate Resource Name or Location** — Detects processes or binaries executed from trusted directories (e.g., System32) or using trusted names (e.g., svchost.exe) where the metadata, hash, or parent process does not align with legitimate activity patterns. Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=11).
9. **T1059.003 Windows Command Shell** — Detects interactive or scripted abuse of cmd.exe, batch files, or shell invocation chains. Focuses on parent-child relationships (e.g., cmd.exe launched from unusual parents), anomalous command-line parameters, and chaining with discovery, credential access,… Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=7), `EDR:scriptblock` (Process Tree + Script Block Logging).

## 10. OSINT — onde pesquisar

Consultas prontas com todos os nomes conhecidos do grupo:

- Relatórios técnicos: [busca web](https://duckduckgo.com/?q=%28%22Sowbug%22%29+threat+report) · [PDFs](https://duckduckgo.com/?q=%28%22Sowbug%22%29+filetype%3Apdf)
- Regras e IOCs publicados: [GitHub](https://github.com/search?type=code&q=%22Sowbug%22)
- Pulsos de ameaça: [AlienVault OTX](https://otx.alienvault.com/browse/global/pulses?q=Sowbug)
- Família de malware e atores: [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/actors) (busque por Sowbug)
- Cartões de grupo: [ThaiCERT Threat Group Cards](https://apt.etda.or.th/cgi-bin/listgroups.cgi)
- Página oficial: [MITRE ATT&CK G0054](https://attack.mitre.org/groups/G0054/)

**Relatórios na coleção CyberMonitor** (ligados pelo nome do grupo, conferir antes de citar):

- 2017 — [sowbug-cyber-espionage-group](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2017/2017.11.07.sowbug-cyber-espionage-group-targets/sowbug-cyber-espionage-group.pdf) _(via “Sowbug”)_

## 11. Bibliografia (1 fontes citadas pelo ATT&CK)

- [Symantec Sowbug Nov 2017](https://www.symantec.com/connect/blogs/sowbug-cyber-espionage-group-targets-south-american-and-southeast-asian-governments) — Symantec Security Response. (2017, November 7). Sowbug: Cyber espionage group targets South American and Southeast Asian governments. Retrieved November 16, 2017.

## 12. Limites e confiança

- O ATT&CK registra o que foi **relatado publicamente**, não tudo o que o grupo faz. Ausência de uma técnica não prova que o grupo não a usa.
- **Sobreposição de TTP não é atribuição.** Muitas técnicas são compartilhadas entre grupos e com red teams. Use a assinatura comportamental como hipótese, junto com infraestrutura, malware e contexto.
- Cobertura de detecção refere-se ao catálogo público Detection Rules, não ao seu ambiente: confira se a telemetria necessária chega ao seu SIEM.
- Ligações marcadas como _inferidas_ (EVTX por palavra-chave, relatórios por nome) devem ser verificadas.

---
Fontes: MITRE ATT&CK® (uso livre com atribuição, © The MITRE Corporation), Atomic Red Team (Red Canary, MIT), EVTX-to-MITRE-Attack, EVTX-ATTACK-SAMPLES, APT & CyberCriminal Campaign Collections. Gerado por [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules).
