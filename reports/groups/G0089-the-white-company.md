# The White Company (G0089) — Dossiê de inteligência

> **TLP:CLEAR** · gerado em 2026-10-25 a partir de fontes abertas · MITRE ATT&CK v20.0 · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0089) · [ATT&CK](https://attack.mitre.org/groups/G0089/)

**Também conhecido como:** —  
**Registro no ATT&CK:** criado em 2019-05-02, atualizado em 2026-07-31 · referências de 2018 a 2018

## 1. Sumário executivo

- **7 técnicas** atribuídas publicamente, concentradas em **Stealth, Discovery, Execution**.
- **Arsenal:** 2 malware e 0 ferramentas (ex.: NETWIRE, Revenge RAT).
- **Campanhas atribuídas:** 0.
- **Cobertura de detecção pública:** 100% das técnicas têm ao menos uma regra no catálogo; **0 técnicas sem nenhuma regra pública**.
- **Assinatura comportamental** (técnicas raras entre os 178 grupos, as mais úteis para atribuição): T1124 System Time Discovery, T1027.002 Software Packing, T1518.001 Security Software Discovery, T1203 Exploitation for Client Execution, T1070.004 File Deletion.

## 2. Quem é

> The White Company is a likely state-sponsored threat actor with advanced capabilities. From 2017 through 2018, the group led an espionage campaign called Operation Shaheen targeting government and military organizations in Pakistan.

_Texto original do MITRE ATT&CK, em inglês._

## 3. Perfil TTP por tática (kill chain)

Cada linha: técnica, como o grupo a usou segundo relatos públicos, e o que existe para detectar e testar.

### Initial Access (TA0001) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1566.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1566.001) Spearphishing Attachment | The White Company has sent phishing emails with malicious Microsoft Word attachments to victims. | 230 | 2 | — |

### Execution (TA0002) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1203](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1203) Exploitation for Client Execution | The White Company has taken advantage of a known vulnerability in Microsoft Word (CVE 2012-0158) to execute code. | 202 | — | — |
| [T1204.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1204.002) Malicious File | The White Company has used phishing lure documents that trick users into opening them and infecting their computers. | 259 | 13 | — |

### Stealth (TA0005) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1027.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1027.002) Software Packing | The White Company has obfuscated their payloads through packing. | 12 | 4 | — |
| [T1070.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1070.004) File Deletion | The White Company has the ability to delete its malware entirely from the target system. | 132 | 11 | — |

### Discovery (TA0007) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1124](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1124) System Time Discovery | The White Company has checked the current date on the victim system. | 18 | 6 | — |
| [T1518.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1518.001) Security Software Discovery | The White Company has checked for specific antivirus products on the target’s computer, including Kaspersky, Quick Heal, AVG, BitDefender, Avira, Sophos, Avast!, and ESET. | 54 | 12 | — |

## 4. Assinatura comportamental

Técnicas que este grupo usa e que poucos dos 178 grupos do ATT&CK usam. Pesam mais numa atribuição por TTP: ver várias delas juntas é mais informativo do que ver técnicas comuns como PowerShell.

| Técnica | Outros grupos que usam | Peso (raridade) |
|---|---:|---:|
| T1124 System Time Discovery | 14 | 2.42 |
| T1027.002 Software Packing | 23 | 1.97 |
| T1518.001 Security Software Discovery | 26 | 1.85 |
| T1203 Exploitation for Client Execution | 41 | 1.43 |
| T1070.004 File Deletion | 47 | 1.30 |
| T1566.001 Spearphishing Attachment | 78 | 0.81 |
| T1204.002 Malicious File | 86 | 0.71 |

## 5. Arsenal

| Software | Tipo | Técnicas no ATT&CK | Uso relatado (EN) |
|---|---|---:|---|
| [NETWIRE](https://attack.mitre.org/software/S0198/) | malware | 45 |  |
| [Revenge RAT](https://attack.mitre.org/software/S0379/) | malware | 18 |  |

## 6. Campanhas

Nenhuma campanha atribuída no ATT&CK.

## 7. Cobertura defensiva

**7 de 7 técnicas (100%)** têm ao menos uma regra pública no catálogo Detection Rules.

### Regras recomendadas por técnica

Melhor regra disponível por técnica (formato portável e maduro primeiro).

| Técnica | Regra | Formato | Fonte |
|---|---|---|---|
| T1027.002 | [Python Image Load By Non-Python Process](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acbb56d62-4060-40f7-9466-d8aaf3123f83) | Sigma | SigmaHQ |
| T1027.002 | [Python Py2Exe Image Load](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Acbb56d62-4060-40f7-9466-d8aaf3123f83) | Sigma | OpenSearch Security Analytics |
| T1070.004 | [File Deletion](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A30aed7b6-d2c1-4eaf-9382-b6bc43e50c57) | Sigma | SigmaHQ |
| T1070.004 | [Prefetch File Deleted](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A0a1f9d29-6465-4776-b091-7f43b26e4c89) | Sigma | SigmaHQ |
| T1124 | [Use of W32tm as Timer](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A6da2c9f5-7c53-401b-aacb-92c040ce1215) | Sigma | SigmaHQ |
| T1124 | [Cisco Discovery](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A9705a6a1-6db6-4a16-a987-15b7151e299b) | Sigma | SigmaHQ |
| T1203 | [Droppers Exploiting CVE-2017-11882](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A678eb5f4-8597-4be6-8be7-905e4234b53a) | Sigma | SigmaHQ |
| T1203 | [OMIGOD HTTP No Authentication RCE - CVE-2021-38647](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aab6b1a39-a9ee-4ab4-b075-e83acf6e346b) | Sigma | SigmaHQ |
| T1204.002 | [Ursnif Malware C2 URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A932ac737-33ca-4afd-9869-0d48b391fcc9) | Sigma | SigmaHQ |
| T1204.002 | [Droppers Exploiting CVE-2017-11882](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A678eb5f4-8597-4be6-8be7-905e4234b53a) | Sigma | SigmaHQ |
| T1518.001 | [Sysmon Discovery Via Default Driver Altitude Using Findstr.EXE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A37db85d1-b089-490a-a59a-c7b6f984f480) | Sigma | SigmaHQ |
| T1518.001 | [Local Firewall Rules Enumeration Via NetFirewallRule Cmdlet](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aea207a23-b441-4a17-9f76-ad5be47d51d3) | Sigma | SigmaHQ |
| T1566.001 | [Ursnif Malware C2 URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A932ac737-33ca-4afd-9869-0d48b391fcc9) | Sigma | SigmaHQ |
| T1566.001 | [Droppers Exploiting CVE-2017-11882](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A678eb5f4-8597-4be6-8be7-905e4234b53a) | Sigma | SigmaHQ |

## 8. Plano de emulação e validação

Use num laboratório isolado e autorizado para confirmar que as regras disparam. Os comandos estão nos repositórios oficiais.

| Tática | Técnica | Teste Atomic Red Team | Plataformas |
|---|---|---|---|
| Initial Access | [T1566.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1566.001/T1566.001.md) | Download Macro-Enabled Phishing Attachment | windows |
| Initial Access | [T1566.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1566.001/T1566.001.md) | Word spawned a command shell and used an IP address in the command line | windows |
| Execution | [T1204.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1204.002/T1204.002.md) | OSTap Style Macro Execution | windows |
| Execution | [T1204.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1204.002/T1204.002.md) | OSTap Payload Download | windows |
| Stealth | [T1027.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027.002/T1027.002.md) | Binary simply packed by UPX (linux) | linux |
| Stealth | [T1027.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027.002/T1027.002.md) | Binary packed by UPX, with modified headers (linux) | linux |
| Stealth | [T1070.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.004/T1070.004.md) | Delete a single file - FreeBSD/Linux/macOS | linux, macos |
| Stealth | [T1070.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.004/T1070.004.md) | Delete an entire folder - FreeBSD/Linux/macOS | linux, macos |
| Discovery | [T1124](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1124/T1124.md) | System Time Discovery | windows |
| Discovery | [T1124](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1124/T1124.md) | System Time Discovery - PowerShell | windows |
| Discovery | [T1518.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1518.001/T1518.001.md) | Security Software Discovery | windows |
| Discovery | [T1518.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1518.001/T1518.001.md) | Security Software Discovery - powershell | windows |

## 9. Hipóteses de hunting

Se The White Company estiver no seu ambiente, estas são as perguntas a fazer aos seus dados (fontes de log segundo as estratégias de detecção do MITRE ATT&CK).

1. **T1124 System Time Discovery** — Untrusted or unusual process/script (cmd.exe, powershell.exe, w32tm.exe, net.exe, custom binaries) queries system time/timezone (e.g., w32tm /tz, net time \\host, Get-TimeZone, GetTickCount API) and (optionally) is followed within a short window by time-based… Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=7), `WinEventLog:Sysmon` (EventCode=10).
2. **T1027.002 Software Packing** — Detection of unpacking behavior through abnormal memory allocation, followed by executable code injection and execution from non-image sections. Dados: `WinEventLog:Sysmon` (EventCode=10), `WinEventLog:Sysmon` (EventCode=1).
3. **T1518.001 Security Software Discovery** — Adversary executes commands to enumerate installed antivirus, EDR, or firewall agents using WMI, registry queries, and built-in tools (e.g., tasklist, netsh, sc query). Correlated with elevated process privileges or scripting engine usage. Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=7).
4. **T1203 Exploitation for Client Execution** — Cause→effect chain: (1) A client app (browser, Office, PDF/Flash/reader) experiences a crash/abnormal exit or loads from an unusual location, then (2) drops or modifies a file in user-writable paths, and/or (3) spawns an unexpected child (e.g.,… Dados: `WinEventLog:Application` (EventCode=1000), `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Sysmon` (EventCode=1).
5. **T1070.004 File Deletion** — Detects adversary behavior deleting artifacts (e.g., dropped payloads, evidence files) using native or external utilities (e.g., del, erase, SDelete). Detects deletion events correlated with unusual process lineage or timing post-execution. Dados: `WinEventLog:Sysmon` (EventCode=23), `WinEventLog:Security` (EventCode=4663, 4670, 4656), `WinEventLog:PowerShell` (EventCode=4103, 4104, 4105, 4106).
6. **T1566.001 Spearphishing Attachment** — Detection of spearphishing attachments by correlating suspicious email delivery with subsequent file creation and abnormal process execution (e.g., Office spawning PowerShell or CMD). Behavior chain includes inbound email metadata → attachment stored on disk… Dados: `m365:unified` (Send/Receive: Inbound emails with attachments from suspicious or spoofed senders), `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Sysmon` (EventCode=1).
7. **T1204.002 Malicious File** — User opens a file delivered by email, web, chat, or share. The handler application (Word/PDF reader/archiver) creates a file in user-controlled paths (Downloads, Temp, Desktop) and then spawns a new or unusual child process (e.g., powershell.exe, wscript.exe,… Dados: `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=15).

## 10. OSINT — onde pesquisar

Consultas prontas com todos os nomes conhecidos do grupo:

- Relatórios técnicos: [busca web](https://duckduckgo.com/?q=%28%22The+White+Company%22%29+threat+report) · [PDFs](https://duckduckgo.com/?q=%28%22The+White+Company%22%29+filetype%3Apdf)
- Regras e IOCs publicados: [GitHub](https://github.com/search?type=code&q=%22The+White+Company%22)
- Pulsos de ameaça: [AlienVault OTX](https://otx.alienvault.com/browse/global/pulses?q=The+White+Company)
- Família de malware e atores: [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/actors) (busque por The White Company)
- Cartões de grupo: [ThaiCERT Threat Group Cards](https://apt.etda.or.th/cgi-bin/listgroups.cgi)
- Página oficial: [MITRE ATT&CK G0089](https://attack.mitre.org/groups/G0089/)

## 11. Bibliografia (1 fontes citadas pelo ATT&CK)

- [Cylance Shaheen Nov 2018](https://www.cylance.com/content/dam/cylance-web/en-us/resources/knowledge-center/resource-library/reports/WhiteCompanyOperationShaheenReport.pdf?_ga=2.161661948.1943296560.1555683782-1066572390.1555511517) — Livelli, K, et al. (2018, November 12). Operation Shaheen. Retrieved May 1, 2019.

## 12. Limites e confiança

- O ATT&CK registra o que foi **relatado publicamente**, não tudo o que o grupo faz. Ausência de uma técnica não prova que o grupo não a usa.
- **Sobreposição de TTP não é atribuição.** Muitas técnicas são compartilhadas entre grupos e com red teams. Use a assinatura comportamental como hipótese, junto com infraestrutura, malware e contexto.
- Cobertura de detecção refere-se ao catálogo público Detection Rules, não ao seu ambiente: confira se a telemetria necessária chega ao seu SIEM.
- Ligações marcadas como _inferidas_ (EVTX por palavra-chave, relatórios por nome) devem ser verificadas.

---
Fontes: MITRE ATT&CK® (uso livre com atribuição, © The MITRE Corporation), Atomic Red Team (Red Canary, MIT), EVTX-to-MITRE-Attack, EVTX-ATTACK-SAMPLES, APT & CyberCriminal Campaign Collections. Gerado por [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules).
