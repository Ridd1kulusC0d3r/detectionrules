# Carbanak (G0008) — Dossiê de inteligência

> **TLP:CLEAR** · gerado em 2026-10-26 a partir de fontes abertas · MITRE ATT&CK v20.0 · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0008) · [ATT&CK](https://attack.mitre.org/groups/G0008/)

**Também conhecido como:** Anunak  
**Origem atribuída:** Ucrânia · **Motivação:** financeiro · **Setores-alvo:** Financeiro  
**Registro no ATT&CK:** criado em 2017-05-31, atualizado em 2026-07-31 · referências de 2014 a 2021

## 1. Sumário executivo

- **9 técnicas** atribuídas publicamente, concentradas em **Stealth, Persistence, Privilege Escalation**.
- **Arsenal:** 1 malware e 3 ferramentas (ex.: Carbanak, Mimikatz, PsExec, netsh).
- **Campanhas atribuídas:** 0.
- **Cobertura de detecção pública:** 100% das técnicas têm ao menos uma regra no catálogo; **0 técnicas sem nenhuma regra pública**.
- **Origem e alvos (APT4ALL):** atribuído a **Ucrânia**, motivação financeiro; setores Financeiro.
- **Onde a cobertura está:** Windows (9 técnicas com regra), Linux (8 técnicas com regra), EDR / XDR (8 técnicas com regra), DNS (7 técnicas com regra).
- **Assinatura comportamental** (técnicas raras entre os 178 grupos, as mais úteis para atribuição): T1219 Remote Access Tools, T1686 Disable or Modify System Firewall, T1102.002 Bidirectional Communication, T1036.004 Masquerade Task or Service, T1218.011 Rundll32.

## 2. Quem é

> Carbanak is a cybercriminal group that has used Carbanak malware to target financial institutions since at least 2013. Carbanak may be linked to groups tracked separately as Cobalt Group and FIN7 that have also used Carbanak malware.

_Texto original do MITRE ATT&CK, em inglês._

## 3. Contexto, nomes e alvos

Consolidado pelo [APT4ALL](https://github.com/Ridd1kulusC0d3r/apt4all) a partir de MISP Galaxy, planilha APT Groups & Operations, EternalLiberty e APTnotes. Atribuição é afirmação de quem publicou; confira a fonte.

| Campo | Valor |
|---|---|
| Origem atribuída | Ucrânia |
| Motivação | financeiro |
| Setores-alvo | Financeiro |
| Vítimas citadas | — |
| Alvos (planilha) | Banks of Russia and payment system |
| Operações conhecidas | Odinaff |
| Confiança de atribuição (MISP) | 50 |

**Como cada fornecedor chama este grupo** (útil para cruzar relatórios):

| Fornecedor | Nome(s) |
|---|---|
| MITRE ATT&CK | G0008 |
| Microsoft | Sangria Tempest, ELBRUS (antigo · old) |

**Outros nomes no APT4ALL (não listados pelo ATT&CK):** Carbanak Group, Carbon Spider, FIN7, GOLD NIAGARA, Calcium, ATK32, Coreid, Sangria Tempest, ELBRUS, JokerStash, WILD COMET

## 4. Perfil TTP por tática (kill chain)

Cada linha: técnica, como o grupo a usou segundo relatos públicos, e o que existe para detectar e testar.

### Resource Development (TA0042) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1588.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1588.002) Tool | Carbanak has obtained and used open-source tools such as PsExec and Mimikatz. | 35 | — | — |

### Initial Access (TA0001) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | Carbanak actors used legitimate credentials of banking employees to perform operations that sent them millions of dollars. | 825 | — | 3 |

### Persistence (TA0003) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | Carbanak actors used legitimate credentials of banking employees to perform operations that sent them millions of dollars. | 825 | — | 3 |
| [T1543.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1543.003) Windows Service | Carbanak malware installs itself as a service to provide persistence and SYSTEM privileges. | 1916 | 6 | 19 |

### Privilege Escalation (TA0004) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | Carbanak actors used legitimate credentials of banking employees to perform operations that sent them millions of dollars. | 825 | — | 3 |
| [T1543.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1543.003) Windows Service | Carbanak malware installs itself as a service to provide persistence and SYSTEM privileges. | 1916 | 6 | 19 |

### Stealth (TA0005) — 4

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1036.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1036.004) Masquerade Task or Service | Carbanak has copied legitimate service names to use for malicious services. | 31 | 4 | — |
| [T1036.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1036.005) Match Legitimate Resource Name or Location | Carbanak has named malware "svchost.exe," which is the name of the Windows shared service host program. | 116 | 4 | — |
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | Carbanak actors used legitimate credentials of banking employees to perform operations that sent them millions of dollars. | 825 | — | 3 |
| [T1218.011](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1218.011) Rundll32 | Carbanak installs VNC server software that executes through rundll32. | 274 | 16 | 12 |

### Defense Impairment (TA0112) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1686](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1686) Disable or Modify System Firewall | Carbanak may use netsh to add local firewall rule exceptions. | 56 | 25 | 6 |

### Command and Control (TA0011) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1102.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1102.002) Bidirectional Communication | Carbanak has used a VBScript named "ggldr" that uses Google Apps Script, Sheets, and Forms services for C2. | 27 | — | — |
| [T1219](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1219) Remote Access Tools | Carbanak used legitimate programs such as AmmyyAdmin and Team Viewer for remote interactive C2 to target systems. | 119 | 15 | — |

## 5. Assinatura comportamental

Técnicas que este grupo usa e que poucos dos 178 grupos do ATT&CK usam. Pesam mais numa atribuição por TTP: ver várias delas juntas é mais informativo do que ver técnicas comuns como PowerShell.

| Técnica | Outros grupos que usam | Peso (raridade) |
|---|---:|---:|
| T1219 Remote Access Tools | 12 | 2.55 |
| T1686 Disable or Modify System Firewall | 12 | 2.55 |
| T1102.002 Bidirectional Communication | 15 | 2.35 |
| T1036.004 Masquerade Task or Service | 23 | 1.97 |
| T1218.011 Rundll32 | 25 | 1.89 |
| T1543.003 Windows Service | 25 | 1.89 |
| T1078 Valid Accounts | 48 | 1.27 |
| T1036.005 Match Legitimate Resource Name or Location | 65 | 0.98 |
| T1588.002 Tool | 83 | 0.74 |

## 6. Arsenal

| Software | Tipo | Técnicas no ATT&CK | Uso relatado (EN) |
|---|---|---:|---|
| [Carbanak](https://attack.mitre.org/software/S0030/) | malware | 18 |  |
| [Mimikatz](https://attack.mitre.org/software/S0002/) | ferramenta | 17 |  |
| [PsExec](https://attack.mitre.org/software/S0029/) | ferramenta | 5 |  |
| [netsh](https://attack.mitre.org/software/S0108/) | ferramenta | 4 |  |

**Outras ferramentas e malware relatados (planilha APT Groups & Operations / MISP):** MBR Eraser, SoftPerfect Network Scanner, SSHd with BackDoor, Ammy Admin, CVE-2012-2539 and CVE-2012-0158, Netscan, Backdoor Batel, Bateleur JScript Backdoor, Cobalt Strike, Sekur, Agent ORM, VB Flash, JS FLash, Bateleur

## 7. Campanhas

Nenhuma campanha atribuída no ATT&CK.

## 8. Cobertura defensiva

**9 de 9 técnicas (100%)** têm ao menos uma regra pública no catálogo Detection Rules.

### Onde procurar — cobertura por tecnologia

Quantas técnicas deste grupo têm ao menos uma regra em cada tecnologia. Comece a caça pelas tecnologias que você tem e que aparecem aqui.

| Tecnologia | Técnicas do grupo com regra |
|---|---:|
| Windows | 9 |
| Linux | 8 |
| EDR / XDR | 8 |
| DNS | 7 |
| Microsoft 365 | 7 |
| Firewall & perímetro | 7 |
| Active Directory | 6 |
| Servidores web & aplicações | 6 |
| macOS | 5 |
| IA, LLMs & agentes | 5 |
| Outros / genérico | 5 |
| Proxy / SWG | 4 |

### Regras recomendadas por técnica

Melhor regra disponível por técnica (formato portável e maduro primeiro).

| Técnica | Regra | Formato | Fonte |
|---|---|---|---|
| T1036.004 | [Operation Wocao Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1cfac73c-be78-4f9a-9b08-5bde0c3953ab) | Sigma | SigmaHQ |
| T1036.004 | [Operation Wocao Activity - Security](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A74ad4314-482e-4c3e-b237-3f7ed3b9ca8d) | Sigma | SigmaHQ |
| T1036.005 | [Exploit for CVE-2015-1641](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A7993792c-5ce2-4475-a3db-a3a5539827ef) | Sigma | SigmaHQ |
| T1036.005 | [Exploit for CVE-2015-1641](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A7993792c-5ce2-4475-a3db-a3a5539827ef) | Sigma | OpenSearch Security Analytics |
| T1078 | [Privilege Role Sign-In Outside Expected Controls](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acf1e5687-84e1-41af-97a9-158094efef53) | Sigma | SigmaHQ |
| T1078 | [OpenCanary - SSH Login Attempt](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aff7139bc-fdb1-4437-92f2-6afefe8884cb) | Sigma | SigmaHQ |
| T1102.002 | [Potential Etherhiding C2 via Blockchain Connection](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Abba8c7d1-172b-435d-9034-02ed9289c628) | Elastic | Elastic detection-rules |
| T1102.002 | [Google Calendar C2 via Script Interpreter](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Aabc7a2be-479e-428b-b0b3-1d22bda46dd9) | Elastic | Elastic detection-rules |
| T1218.011 | [Equation Group DLL_U Export Function Load](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad465d1d8-27a2-4cca-9621-a800f37cf72e) | Sigma | SigmaHQ |
| T1218.011 | [APT29 2018 Phishing Campaign File Indicators](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A3a3f81ca-652c-482b-adeb-b1c804727f74) | Sigma | SigmaHQ |
| T1219 | [Renamed Visual Studio Code Tunnel Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A2cf29f11-e356-4f61-98c0-1bdb9393d6da) | Sigma | SigmaHQ |
| T1219 | [Hijack Legit RDP Session to Move Laterally](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A52753ea4-b3a0-4365-910d-36cff487b789) | Sigma | OpenSearch Security Analytics |
| T1543.003 | [PSExec Lateral Movement](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=hayabusa-native%3A%3A0694c340-3a46-40ac-acfc-c3444ae6572c) | Sigma | Hayabusa (native) |
| T1543.003 | [Suspicious Service Name](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=hayabusa-native%3A%3Acc429813-21db-4019-b520-2f19648e1ef1) | Sigma | Hayabusa (native) |
| T1588.002 | [Hacktool Execution - Imphash](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A24e3e58a-646b-4b50-adef-02ef935b9fc8) | Sigma | SigmaHQ |
| T1588.002 | [Renamed SysInternals DebugView Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acd764533-2e07-40d6-a718-cfeec7f2da7f) | Sigma | SigmaHQ |
| T1686 | [Disable System Firewall](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A53059bc0-1472-438b-956a-7508a94a91f0) | Sigma | SigmaHQ |
| T1686 | [Netsh RDP Port Opening](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A01aeb693-138d-49d2-9403-c4f52d7d3d62) | Sigma | OpenSearch Security Analytics |

## 9. Plano de emulação e validação

Use num laboratório isolado e autorizado para confirmar que as regras disparam. Os comandos estão nos repositórios oficiais.

| Tática | Técnica | Teste Atomic Red Team | Plataformas |
|---|---|---|---|
| Persistence | [T1543.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1543.003/T1543.003.md) | Modify Fax service to run PowerShell | windows |
| Persistence | [T1543.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1543.003/T1543.003.md) | Service Installation CMD | windows |
| Stealth | [T1036.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.004/T1036.004.md) | Creating W32Time similar named service using schtasks | windows |
| Stealth | [T1036.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.004/T1036.004.md) | Creating W32Time similar named service using sc | windows |
| Stealth | [T1036.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.005/T1036.005.md) | Execute a process from a directory masquerading as the current parent directory | linux, macos |
| Stealth | [T1036.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.005/T1036.005.md) | Masquerade as a built-in system executable | windows |
| Stealth | [T1218.011](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.011/T1218.011.md) | Rundll32 execute JavaScript Remote Payload With GetObject | windows |
| Stealth | [T1218.011](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.011/T1218.011.md) | Rundll32 execute VBscript command | windows |
| Defense Impairment | [T1686](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1686/T1686.md) | Disable Microsoft Defender Firewall | windows |
| Defense Impairment | [T1686](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1686/T1686.md) | Disable Microsoft Defender Firewall via Registry | windows |
| Command and Control | [T1219](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1219/T1219.md) | TeamViewer Files Detected Test on Windows | windows |
| Command and Control | [T1219](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1219/T1219.md) | AnyDesk Files Detected Test on Windows | windows |

**Logs reais de ataque (EVTX) para testar sem executar nada:**

- T1078 — [ID1149-RDP success logins to multiple hosts](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0001-Initial%20access/T1078-Valid%20accounts/ID1149-RDP%20success%20logins%20to%20multiple%20hosts.evtx) _(explícito)_
- T1078 — [ID33205-SQL Server failed login with disabled SA account](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0001-Initial%20access/T1078-Valid%20accounts/ID33205-SQL%20Server%20failed%20login%20with%20disabled%20SA%20account.evtx) _(explícito)_
- T1218.011 — [rundll32_cmd_schtask](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/AutomatedTestingTools/Malware/rundll32_cmd_schtask.evtx) _(inferido)_
- T1218.011 — [rundll32_hollowing_wermgr_masquerading](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/AutomatedTestingTools/Malware/rundll32_hollowing_wermgr_masquerading.evtx) _(inferido)_
- T1543.003 — [ID13-New service for Mimikatz](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0003-Persistence/T1543.003-Create%20or%20Modify%20System%20Process-Windows%20Service/ID13-New%20service%20for%20Mimikatz.evtx) _(explícito)_
- T1543.003 — [ID4688-4697 RDP hijack via service creation](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0003-Persistence/T1543.003-Create%20or%20Modify%20System%20Process-Windows%20Service/ID4688-4697%20RDP%20hijack%20via%20service%20creation.evtx) _(explícito)_
- T1686 — [ID2003-4950-Firewall disabled](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0005-Defense%20Evasion/T1562.004-Impair%20Defenses-Disable%20or%20Modify%20System%20Firewall/ID2003-4950-Firewall%20disabled.evtx) _(explícito)_
- T1686 — [ID2004-Any any firewall rule created](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0005-Defense%20Evasion/T1562.004-Impair%20Defenses-Disable%20or%20Modify%20System%20Firewall/ID2004-Any%20any%20firewall%20rule%20created.evtx) _(explícito)_

## 10. Hipóteses de hunting

Se Carbanak estiver no seu ambiente, estas são as perguntas a fazer aos seus dados (fontes de log segundo as estratégias de detecção do MITRE ATT&CK).

1. **T1219 Remote Access Tools** — Chain of remote access tool behavior: (1) initial execution of remote-control/assist agent or GUI under user context; (2) persistence via service or autorun; (3) long-lived outbound connection/tunnel to external infrastructure; (4) interactive control signals… Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:System` (EventCode=7045), `WinEventLog:Sysmon` (EventCode=12).
2. **T1686 Disable or Modify System Firewall** — Detection of firewall tampering by monitoring processes executing netsh, PowerShell Set-NetFirewallProfile, or sc stop mpssvc. Registry modifications under HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy also indicate adversarial… Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=13, 14).
3. **T1102.002 Bidirectional Communication** — Suspicious processes initiating encrypted HTTPS connections to common web service domains, followed by abnormal data upload behavior or automated posting behavior indicative of C2 bidirectional traffic. Dados: `WinEventLog:Sysmon` (EventCode=3, 22), `WinEventLog:Sysmon` (EventCode=1), `etw:Microsoft-Windows-WinINet` (HTTPS Inspection).
4. **T1036.004 Masquerade Task or Service** — Creation or modification of Windows services or scheduled tasks with names or descriptions mimicking legitimate entries, followed by anomalous execution of untrusted binaries or LOLBAS. Dados: `WinEventLog:System` (EventCode=7045), `WinEventLog:Security` (EventCode=4698), `WinEventLog:Sysmon` (EventCode=1).
5. **T1218.011 Rundll32** — Detects rundll32.exe invoked with atypical arguments (.dll, .cpl, javascript:, mshtml). DLLs not normally loaded by rundll32 are mapped into memory. Control_RunDLL or RunHTMLApplication invoked. Suspicious DLLs or scripts accessed from disk or network.… Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=7), `WinEventLog:Sysmon` (EventCode=11).
6. **T1543.003 Windows Service** — Detects creation or modification of Windows Services through command-line tools (e.g., `sc.exe`, `powershell.exe`), Registry key changes under `HKLM\System\CurrentControlSet\Services`, and service execution under SYSTEM with unsigned or anomalous binary… Dados: `WinEventLog:Security` (EventCode=4697), `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=13, 14).
7. **T1078 Valid Accounts** — Detection of compromised or misused valid accounts via anomalous logon patterns, abnormal logon types, and inconsistent geographic or time-based activity across Windows endpoints. Dados: `WinEventLog:Security` (EventCode=4624), `WinEventLog:Security` (EventCode=4776, 4625), `WinEventLog:Sysmon` (EventCode=1).
8. **T1036.005 Match Legitimate Resource Name or Location** — Detects processes or binaries executed from trusted directories (e.g., System32) or using trusted names (e.g., svchost.exe) where the metadata, hash, or parent process does not align with legitimate activity patterns. Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=11).
9. **T1588.002 Tool** — Monitor for contextual data about a malicious payload, such as compilation times, file hashes, as well as watermarks or other identifiable configuration information. In some cases, malware repositories can also be used to identify features of tool use… Dados: `Malware Repository` (None).

## 11. OSINT — onde pesquisar

Consultas prontas com todos os nomes conhecidos do grupo:

- Relatórios técnicos: [busca web](https://duckduckgo.com/?q=%28%22Carbanak%22+OR+%22Anunak%22%29+threat+report) · [PDFs](https://duckduckgo.com/?q=%28%22Carbanak%22+OR+%22Anunak%22%29+filetype%3Apdf)
- Regras e IOCs publicados: [GitHub](https://github.com/search?type=code&q=%22Carbanak%22+OR+%22Anunak%22)
- Pulsos de ameaça: [AlienVault OTX](https://otx.alienvault.com/browse/global/pulses?q=Carbanak)
- Família de malware e atores: [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/actors) (busque por Carbanak, Anunak)
- Cartões de grupo: [ThaiCERT Threat Group Cards](https://apt.etda.or.th/cgi-bin/listgroups.cgi)
- Página oficial: [MITRE ATT&CK G0008](https://attack.mitre.org/groups/G0008/)

**Relatórios na coleção CyberMonitor** (ligados pelo nome do grupo, conferir antes de citar):

- 2014 — [Anunak_APT_against_financial_institutions](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2014/2014.12.22.Anunak_APT/Anunak_APT_against_financial_institutions.pdf) _(via “Anunak”)_
- 2015 — [Carbanak_APT_eng](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2015/2015.02.16.Carbanak.APT/Carbanak_APT_eng.pdf) _(via “Carbanak”)_
- 2016 — [proofpoint-threat-insight-carbanak-group-en](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2016/2016.03.14.Carbanak_cybercrime_group/proofpoint-threat-insight-carbanak-group-en.pdf) _(via “Carbanak”)_
- 2017 — [blog_anatomy-of-an-attack-carbanak](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2017/2017.12.04.The_Shadows_of_Ghosts/blog_anatomy-of-an-attack-carbanak.pdf) _(via “Carbanak”)_
- 2017 — [paper_the-shadows-of-ghosts-carbanak-report](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2017/2017.12.04.The_Shadows_of_Ghosts/paper_the-shadows-of-ghosts-carbanak-report.pdf) _(via “Carbanak”)_
- 2021 — [[Morphisec]_The_Evolution_of_the_FIN7_JssLoader](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2021/2021.01.04.Carbanak_evolution_of_FIN7_JssLoader/%5BMorphisec%5D_The_Evolution_of_the_FIN7_JssLoader.pdf) _(via “Carbanak”)_

**Relatórios públicos ligados pelo APT4ALL** (12 no total, mais recentes primeiro):

- 2019 — [CARBANAK Week Part Four: The CARBANAK Desktop Video Player](https://app.box.com/s/30mizln4f525yv482qqampa8vybjj764) _(FireEye)_
- 2019 — [CARBANAK Week Part Three: Behind the CARBANAK Backdoor](https://app.box.com/s/rel5slouyleepdl3u7xilbmzsuk091n3) _(FireEye)_
- 2019 — [CARBANAK Week Part Two: Continuing the CARBANAK Source Code Analysis](https://app.box.com/s/etrhh2gb4df9sybsieg3xs1j9mx6yw8s) _(FireEye)_
- 2019 — [CARBANAK Week Part One: A Rare Occurrence](https://app.box.com/s/l3dcqd6i8rnmxgi0ykd9zfmlwctcaq1g) _(FireEye)_
- 2017 — [Inside the Response of a Unique CARBANAK Intrusion](https://app.box.com/s/egwg3so00e433s191jow7xlb1o27z7m7) _(RSA)_
- 2017 — [The Carbanak/Fin7 syndicate](https://app.box.com/s/kos1krnm5s1r47do98nlyv6y9jcybf12) _(RSA)_
- 2017 — [The Digital Plagiarist Campaign: TelePorting the Carbanak Crew to a New Dimension](https://app.box.com/s/7pr8b7cy9liv1bi88ha7frtzgrjycex3) _(tr1adx)_
- 2016 — [New Carbanak / Anunak Attack Methodology](https://app.box.com/s/cbclbgiu54ihivxe7bvblwsv1e8jq44h) _(Trustwave)_
- 2016 — [Carbanak Oracle Breach](https://app.box.com/s/4sfhcqaaxwui1dbvd13254wm5wfy9bmk) _(Visa)_
- 2015 — [Carbanak is packing new guns](https://app.box.com/s/h1dn7d6ptcpwjbcfj468fy5201ev4bbz) _(ESET)_
- 2015 — [Carbanak APT The Great Bank Robbery](https://app.box.com/s/p7qzcury97tuwk26694uutujwqmwqyhe) _(Kaspersky)_
- 2014 — [Anunak: Apt Against Financial Institutions](https://app.box.com/s/exmsfcvad1sjqtmvtzbiil9k52js62ir) _(Group-IB, FOX-IT)_

## 12. Bibliografia (8 fontes citadas pelo ATT&CK)

- [Europol Cobalt Mar 2018](https://www.europol.europa.eu/newsroom/news/mastermind-behind-eur-1-billion-cyber-bank-robbery-arrested-in-spain) — Europol. (2018, March 26). Mastermind Behind EUR 1 Billion Cyber Bank Robbery Arrested in Spain. Retrieved October 10, 2018.
- [FireEye FIN7 April 2017](https://www.fireeye.com/blog/threat-research/2017/04/fin7-phishing-lnk.html) — Carr, N., et al. (2017, April 24). FIN7 Evolution and the Phishing LNK. Retrieved April 24, 2017.
- [Forcepoint Carbanak Google C2](https://blogs.forcepoint.com/security-labs/carbanak-group-uses-google-malware-command-and-control) — Griffin, N. (2017, January 17). CARBANAK GROUP USES GOOGLE FOR MALWARE COMMAND-AND-CONTROL. Retrieved February 15, 2017.
- [Fox-It Anunak Feb 2015](https://www.fox-it.com/en/news/blog/anunak-aka-carbanak-update/) — Prins, R. (2015, February 16). Anunak (aka Carbanak) Update. Retrieved January 20, 2017.
- [Group-IB Anunak](http://www.group-ib.com/files/Anunak_APT_against_financial_institutions.pdf) — Group-IB and Fox-IT. (2014, December). Anunak: APT against financial institutions. Retrieved April 20, 2016.
- [Kaspersky Carbanak](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/08064518/Carbanak_APT_eng.pdf) — Kaspersky Lab's Global Research and Analysis Team. (2015, February). CARBANAK APT THE GREAT BANK ROBBERY. Retrieved August 23, 2018.
- [Secureworks GOLD KINGSWOOD Threat Profile](https://www.secureworks.com/research/threat-profiles/gold-kingswood?filter=item-financial-gain) — Secureworks. (n.d.). GOLD KINGSWOOD. Retrieved October 18, 2021.
- [Secureworks GOLD NIAGARA Threat Profile](https://www.secureworks.com/research/threat-profiles/gold-niagara) — CTU. (n.d.). GOLD NIAGARA. Retrieved September 21, 2021.

## 13. Limites e confiança

- O ATT&CK registra o que foi **relatado publicamente**, não tudo o que o grupo faz. Ausência de uma técnica não prova que o grupo não a usa.
- **Sobreposição de TTP não é atribuição.** Muitas técnicas são compartilhadas entre grupos e com red teams. Use a assinatura comportamental como hipótese, junto com infraestrutura, malware e contexto.
- Cobertura de detecção refere-se ao catálogo público Detection Rules, não ao seu ambiente: confira se a telemetria necessária chega ao seu SIEM.
- Ligações marcadas como _inferidas_ (EVTX por palavra-chave, relatórios por nome) devem ser verificadas.

---
Fontes: MITRE ATT&CK® (uso livre com atribuição, © The MITRE Corporation), APT4ALL (MISP Galaxy CC0/BSD-2, APT Groups & Operations CC BY 4.0, EternalLiberty, APTnotes, Ransomware Tool Matrix CC BY 4.0), Atomic Red Team (Red Canary, MIT), EVTX-to-MITRE-Attack, EVTX-ATTACK-SAMPLES, APT & CyberCriminal Campaign Collections. Gerado por [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules).
