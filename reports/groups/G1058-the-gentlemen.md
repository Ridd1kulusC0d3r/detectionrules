# The Gentlemen (G1058) — Dossiê de inteligência

> **TLP:CLEAR** · gerado em 2026-10-26 a partir de fontes abertas · MITRE ATT&CK v20.0 · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1058) · [ATT&CK](https://attack.mitre.org/groups/G1058/)

**Também conhecido como:** Storm-2697, GOLD SHERWOOD  
**Registro no ATT&CK:** criado em 2026-09-18, atualizado em 2026-09-30 · referências de 2025 a 2026

## 1. Sumário executivo

- **17 técnicas** atribuídas publicamente, concentradas em **Resource Development, Stealth, Privilege Escalation**.
- **Arsenal:** 1 malware e 2 ferramentas (ex.: The Gentlemen Ransomware, PsExec, Wevtutil).
- **Campanhas atribuídas:** 0.
- **Cobertura de detecção pública:** 88% das técnicas têm ao menos uma regra no catálogo; **2 técnicas sem nenhuma regra pública**.
- **Onde a cobertura está:** Windows (12 técnicas com regra), DNS (10 técnicas com regra), Outros / genérico (10 técnicas com regra), Linux (9 técnicas com regra).
- **Assinatura comportamental** (técnicas raras entre os 178 grupos, as mais úteis para atribuição): T1036.001 Invalid Code Signature, T1683.002 Audio-Visual Content, T1585 Establish Accounts, T1683.001 Written Content, T1219.002 Remote Desktop Software.

## 2. Quem é

> The Gentlemen is a group that maintains the The Gentlemen Ransomware-as-a-service (RaaS). The Gentlemen was first observed in mid-2025 who had posed The Gentlemen Ransomware as a closed ransomware and shortly later opened the ransomware as a RaaS to affiliates in September 2025. The Gentlemen has been affiliated with the threat group Storm-2697 and GOLD SHERWOOD.

_Texto original do MITRE ATT&CK, em inglês._

## 3. Contexto, nomes e alvos

Este grupo ainda não tem registro consolidado no APT4ALL (país, setores e nomes por fornecedor).

## 4. Perfil TTP por tática (kill chain)

Cada linha: técnica, como o grupo a usou segundo relatos públicos, e o que existe para detectar e testar.

### Resource Development (TA0042) — 6

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1583.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1583.001) Domains | The Gentlemen has maintained a TOR Data Leak Site (DLS) to post stolen victim data. | 7 | — | — |
| [T1585](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1585) Establish Accounts | The Gentlemen and its affiliates have leveraged Tox to communicate with victims. | 1 | — | — |
| [T1585.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1585.001) Social Media Accounts | The Gentlemen has established social media accounts on X. | 4 | — | — |
| [T1588.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1588.002) Tool | The Gentlemen has provided a custom EDR killing tool called GentleKiller and other like software that abuse vulnerable drivers via the Bring Your Own Vulnerable Driver (BYOVD) technique to their affiliates that attempts to disable EDR solutions.  The Gentlemen… | 35 | — | — |
| [T1683.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1683.001) Written Content | The Gentlemen has utilized branded code and ransom notes. | **0** | — | — |
| [T1683.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1683.002) Audio-Visual Content | The Gentlemen has leveraged a branded graphic that is placed on the systems desktop wallpaper that symbolizes the association of malicious activity to the group. | **0** | — | — |

### Initial Access (TA0001) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | The Gentlemen has leveraged compromised user credentials to gain access to victim hosts. | 825 | — | 3 |
| [T1190](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1190) Exploit Public-Facing Application | The Gentlemen has exploited vulnerable public-facing devices and services to gain access to victim environments. | 580 | — | — |

### Persistence (TA0003) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | The Gentlemen has leveraged compromised user credentials to gain access to victim hosts. | 825 | — | 3 |

### Privilege Escalation (TA0004) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1068](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1068) Exploitation for Privilege Escalation | The Gentlemen has assisted affiliates with gaining privilege escalation through the use of BYOVD. | 408 | 2 | 2 |
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | The Gentlemen has leveraged compromised user credentials to gain access to victim hosts. | 825 | — | 3 |

### Stealth (TA0005) — 5

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1027.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1027.002) Software Packing | The Gentlemen has packed The Gentlemen Ransomware binaries utilizing either Themida or Enigma to obfuscate the malicious payloads. | 12 | 4 | — |
| [T1036](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1036) Masquerading | The Gentlemen has fabricated the version information of payload files to evade detection. | 453 | 2 | 1 |
| [T1036.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1036.001) Invalid Code Signature | The Gentlemen has copied digital signatures from legitimate executables in attempts to circumvent detection. | 19 | — | — |
| [T1036.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1036.005) Match Legitimate Resource Name or Location | The Gentlemen has named The Gentlemen Ransomware payload files to resemble well-known software vendors to include security vendors. The Gentlemen has also utilized icons that match impersonated vendors. | 116 | 4 | — |
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | The Gentlemen has leveraged compromised user credentials to gain access to victim hosts. | 825 | — | 3 |

### Discovery (TA0007) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1018](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1018) Remote System Discovery | The Gentlemen has utilized internal network scanning tools to enumerate additional hosts in the victim environment to include Advanced IP Scanner. | 157 | 23 | 1 |

### Command and Control (TA0011) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1219.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1219.002) Remote Desktop Software | The Gentlemen has relied on remote access tools, such as AnyDesk, as a means of maintaining access to victim environment. | 221 | — | — |

### Impact (TA0040) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1486](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1486) Data Encrypted for Impact | The Gentlemen has used The Gentlemen Ransomware to encrypt victim’s data. | 160 | 10 | 1 |
| [T1657](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1657) Financial Theft | The Gentlemen has used double-extortion tactics to sway victims to pay a ransom to include exfiltrating sensitive data, encrypting files, and threatening public release if a payment is not received. | 2 | — | — |

## 5. Assinatura comportamental

Técnicas que este grupo usa e que poucos dos 178 grupos do ATT&CK usam. Pesam mais numa atribuição por TTP: ver várias delas juntas é mais informativo do que ver técnicas comuns como PowerShell.

| Técnica | Outros grupos que usam | Peso (raridade) |
|---|---:|---:|
| T1036.001 Invalid Code Signature | 2 | 3.80 |
| T1683.002 Audio-Visual Content | 4 | 3.40 |
| T1585 Establish Accounts | 5 | 3.24 |
| T1683.001 Written Content | 5 | 3.24 |
| T1219.002 Remote Desktop Software | 11 | 2.62 |
| T1657 Financial Theft | 18 | 2.19 |
| T1486 Data Encrypted for Impact | 19 | 2.14 |
| T1036 Masquerading | 20 | 2.10 |
| T1068 Exploitation for Privilege Escalation | 22 | 2.01 |
| T1585.001 Social Media Accounts | 22 | 2.01 |

## 6. Arsenal

| Software | Tipo | Técnicas no ATT&CK | Uso relatado (EN) |
|---|---|---:|---|
| [The Gentlemen Ransomware](https://attack.mitre.org/software/S9051/) | malware | 45 |  |
| [PsExec](https://attack.mitre.org/software/S0029/) | ferramenta | 5 |  |
| [Wevtutil](https://attack.mitre.org/software/S0645/) | ferramenta | 3 |  |

## 7. Campanhas

Nenhuma campanha atribuída no ATT&CK.

## 8. Cobertura defensiva

**15 de 17 técnicas (88%)** têm ao menos uma regra pública no catálogo Detection Rules.

### Técnicas sem regra pública (prioridade para engenharia de detecção)

- **T1683.002 Audio-Visual Content** — Resource Development
- **T1683.001 Written Content** — Resource Development

### Onde procurar — cobertura por tecnologia

Quantas técnicas deste grupo têm ao menos uma regra em cada tecnologia. Comece a caça pelas tecnologias que você tem e que aparecem aqui.

| Tecnologia | Técnicas do grupo com regra |
|---|---:|
| Windows | 12 |
| DNS | 10 |
| Outros / genérico | 10 |
| Linux | 9 |
| macOS | 9 |
| EDR / XDR | 9 |
| AWS | 8 |
| Firewall & perímetro | 8 |
| Microsoft 365 | 8 |
| Azure (recursos) | 7 |
| IDS / NSM / NDR | 7 |
| Servidores web & aplicações | 7 |

### Regras recomendadas por técnica

Melhor regra disponível por técnica (formato portável e maduro primeiro).

| Técnica | Regra | Formato | Fonte |
|---|---|---|---|
| T1018 | [Chopper Webshell Process Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Afa3c117a-bc0d-416e-a31b-0c0e80653efb) | Sigma | SigmaHQ |
| T1018 | [Webshell Hacking Activity Patterns](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4ebc877f-4612-45cb-b3a5-8e3834db36c9) | Sigma | SigmaHQ |
| T1027.002 | [Python Image Load By Non-Python Process](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acbb56d62-4060-40f7-9466-d8aaf3123f83) | Sigma | SigmaHQ |
| T1027.002 | [Python Py2Exe Image Load](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Acbb56d62-4060-40f7-9466-d8aaf3123f83) | Sigma | OpenSearch Security Analytics |
| T1036 | [Potential LSASS Process Dump Via Procdump](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A5afee48e-67dd-4e03-a783-f74259dcf998) | Sigma | SigmaHQ |
| T1036 | [Suspicious Use of Procdump on LSASS](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A5afee48e-67dd-4e03-a783-f74259dcf998) | Sigma | OpenSearch Security Analytics |
| T1036.001 | [Untrusted Driver Loaded](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ad8ab1ec1-feeb-48b9-89e7-c12e189448aa) | Elastic | Elastic detection-rules |
| T1036.001 | [Suspicious DLL Loaded for Persistence or Privilege Escalation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Abfeaf89b-a2a7-48a3-817f-e41829dc61ee) | Elastic | Elastic detection-rules |
| T1036.005 | [Exploit for CVE-2015-1641](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A7993792c-5ce2-4475-a3db-a3a5539827ef) | Sigma | SigmaHQ |
| T1036.005 | [Exploit for CVE-2015-1641](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A7993792c-5ce2-4475-a3db-a3a5539827ef) | Sigma | OpenSearch Security Analytics |
| T1068 | [Exploiting CVE-2019-1388](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A02e0b2ea-a597-428e-b04a-af6a1a403e5c) | Sigma | SigmaHQ |
| T1068 | [OMIGOD HTTP No Authentication RCE - CVE-2021-38647](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aab6b1a39-a9ee-4ab4-b075-e83acf6e346b) | Sigma | SigmaHQ |
| T1078 | [Privilege Role Sign-In Outside Expected Controls](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acf1e5687-84e1-41af-97a9-158094efef53) | Sigma | SigmaHQ |
| T1078 | [OpenCanary - SSH Login Attempt](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aff7139bc-fdb1-4437-92f2-6afefe8884cb) | Sigma | SigmaHQ |
| T1190 | [OMIGOD HTTP No Authentication RCE - CVE-2021-38647](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aab6b1a39-a9ee-4ab4-b075-e83acf6e346b) | Sigma | SigmaHQ |
| T1190 | [Exploited CVE-2020-10189 Zoho ManageEngine](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A846b866e-2a57-46ee-8e16-85fa92759be7) | Sigma | OpenSearch Security Analytics |
| T1219.002 | [Antivirus - Exploitation Framework Signature](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A238527ad-3c2c-4e4f-a1f6-92fd63adb864) | Sigma | SigmaHQ |
| T1219.002 | [Potential SocGholish Second Stage C2 DNS Query](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A70761fe8-6aa2-4f80-98c1-a57049c08e66) | Sigma | SigmaHQ |
| T1486 | [LockerGoga Ransomware Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A74db3488-fd28-480a-95aa-b7af626de068) | Sigma | SigmaHQ |
| T1486 | [LockerGoga Ransomware](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A74db3488-fd28-480a-95aa-b7af626de068) | Sigma | OpenSearch Security Analytics |
| T1583.001 | [AWS Route 53 Private Hosted Zone Associated With a VPC](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ae3c27562-709a-42bd-82f2-3ed926cced19) | Elastic | Elastic detection-rules |
| T1583.001 | [AWS SES Email Identity Verified Then Deleted](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A8e4bde35-125d-4eb3-9a2e-d7e77a053a08) | Elastic | Elastic detection-rules |
| T1585 | [A SAML Connector was created or modified](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=panther-panther-analysis%3A%3ATeleport.SAMLCreated) | Panther | Panther panther-analysis |
| T1585.001 | [CYFIRMA - Brand Intelligence - Social Media Handle Impersonation Detected High Rule](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A22f49d67-7da7-4809-8d07-89e4478aa6b0) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1585.001 | [CYFIRMA - Brand Intelligence - Executive/People Impersonation High Rule](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A159d26a1-591c-4f70-b1ca-2843c881aaec) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1588.002 | [Hacktool Execution - Imphash](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A24e3e58a-646b-4b50-adef-02ef935b9fc8) | Sigma | SigmaHQ |
| T1588.002 | [Renamed SysInternals DebugView Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acd764533-2e07-40d6-a718-cfeec7f2da7f) | Sigma | SigmaHQ |
| T1657 | [AWS S3 Bucket Enumeration or Brute Force](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A5f0234fd-7f21-42af-8391-511d5fd11d5c) | Elastic | Elastic detection-rules |
| T1657 | [Monitor ransomwarelive for companies of interest on ransowmare data leak sites (DLS)](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=bert-janp-hunting-queries%3A%3A8b9af12a820a) | KQL hunting | Bert-JanP Hunting Queries |

## 9. Plano de emulação e validação

Use num laboratório isolado e autorizado para confirmar que as regras disparam. Os comandos estão nos repositórios oficiais.

| Tática | Técnica | Teste Atomic Red Team | Plataformas |
|---|---|---|---|
| Privilege Escalation | [T1068](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1068/T1068.md) | Scattered Spider BYOVD (CVE-2015-2291 for Intel Ethernet Diagnostics Driver) | windows |
| Privilege Escalation | [T1068](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1068/T1068.md) | Turla Snake Malware Privilege Escalation Through VM Driver | windows |
| Stealth | [T1027.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027.002/T1027.002.md) | Binary simply packed by UPX (linux) | linux |
| Stealth | [T1027.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027.002/T1027.002.md) | Binary packed by UPX, with modified headers (linux) | linux |
| Stealth | [T1036](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036/T1036.md) | System File Copied to Unusual Location | windows |
| Stealth | [T1036](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036/T1036.md) | Malware Masquerading and Execution from Zip File | windows |
| Stealth | [T1036.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.005/T1036.005.md) | Execute a process from a directory masquerading as the current parent directory | linux, macos |
| Stealth | [T1036.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.005/T1036.005.md) | Masquerade as a built-in system executable | windows |
| Discovery | [T1018](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1018/T1018.md) | Remote System Discovery - net | windows |
| Discovery | [T1018](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1018/T1018.md) | Remote System Discovery - net group Domain Computers | windows |
| Impact | [T1486](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1486/T1486.md) | Encrypt files using gpg (FreeBSD/Linux) | linux |
| Impact | [T1486](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1486/T1486.md) | Encrypt files using 7z (FreeBSD/Linux) | linux |

**Logs reais de ataque (EVTX) para testar sem executar nada:**

- T1018 — [ID5145-DNS hosts files access via network share](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1018-Remote%20System%20Discovery/ID5145-DNS%20hosts%20files%20access%20via%20network%20share.evtx) _(explícito)_
- T1036 — [rundll32_hollowing_wermgr_masquerading](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/AutomatedTestingTools/Malware/rundll32_hollowing_wermgr_masquerading.evtx) _(inferido)_
- T1068 — [ID12-13 Mini_Plasma_PoC_AbortHydration_ArbitraryRegKey_EoP](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0004-Privilege%20Escalation/T1068-Exploitation%20for%20Privilege%20Escalation/ID12-13%20Mini_Plasma_PoC_AbortHydration_ArbitraryRegKey_EoP.evtx) _(explícito)_
- T1068 — [ID4673-Privilege SeMachineAccountPrivilege called](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0004-Privilege%20Escalation/T1068-Exploitation%20for%20Privilege%20Escalation/ID4673-Privilege%20SeMachineAccountPrivilege%20called.evtx) _(explícito)_
- T1078 — [ID1149-RDP success logins to multiple hosts](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0001-Initial%20access/T1078-Valid%20accounts/ID1149-RDP%20success%20logins%20to%20multiple%20hosts.evtx) _(explícito)_
- T1078 — [ID33205-SQL Server failed login with disabled SA account](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0001-Initial%20access/T1078-Valid%20accounts/ID33205-SQL%20Server%20failed%20login%20with%20disabled%20SA%20account.evtx) _(explícito)_
- T1486 — [ID 768,775,793,796,817,840-BitLocker encryption activated](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0040-Impact/T1486-Data%20Encrypted%20for%20Impact/ID%20768%2C775%2C793%2C796%2C817%2C840-BitLocker%20encryption%20activated.evtx) _(explícito)_

## 10. Hipóteses de hunting

Se The Gentlemen estiver no seu ambiente, estas são as perguntas a fazer aos seus dados (fontes de log segundo as estratégias de detecção do MITRE ATT&CK).

1. **T1036.001 Invalid Code Signature** — Execution of binaries with invalid digital signatures, where metadata claims code is signed but validation fails. Behavior is often correlated with suspicious parent processes or unexpected execution paths. Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Windows Defender` (Operational log), `WinEventLog:PowerShell` (EventCode=4103, 4104, 4105, 4106).
2. **T1585 Establish Accounts** — Monitor and analyze traffic patterns and packet inspection associated to protocol(s) that do not follow the expected protocol standards and traffic flows (e.g extraneous packets that do not belong to established flows, gratuitous or anomalous traffic… Dados: `Network Traffic` (None), `Persona` (None).
3. **T1219.002 Remote Desktop Software** — Adversary installation or use of RMM software (e.g., TeamViewer, AnyDesk, ScreenConnect) followed by outbound beaconing or remote session establishment Dados: `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Sysmon` (EventCode=3, 22), `WinEventLog:Microsoft-Windows-Windows Firewall With Advanced Security/Firewall` (new rule allowing inbound or outbound connections for remote desktop software).
4. **T1657 Financial Theft** — Monitor for anomalous access to financial applications, browser-based banking sessions, or enterprise ERP systems from Windows endpoints. Detect mass emailing of payment instructions, sudden rule changes in Outlook for financial staff, or use of clipboard… Dados: `WinEventLog:Security` (EventCode=4624, 4648), `WinEventLog:Sysmon` (EventCode=1).
5. **T1486 Data Encrypted for Impact** — High-frequency file write operations using uncommon extensions, followed by ransom note creation, registry tampering, or shadow copy deletion. Often uses CLI tools like vssadmin, wbadmin, cipher, or PowerShell. Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Sysmon` (EventCode=2).
6. **T1036 Masquerading** — Adversary renames LOLBINs or deploys binaries with spoofed file names, internal PE metadata, or misleading icons to appear legitimate. File creation is followed by execution or service registration inconsistent with known usage. Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:System` (EventCode=7045).
7. **T1068 Exploitation for Privilege Escalation** — Detects exploitation attempts targeting vulnerable kernel drivers or OS components, often followed by unusual process or token behavior. Dados: `WinEventLog:Sysmon` (EventCode=6), `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Security` (EventCode=4672).
8. **T1585.001 Social Media Accounts** — Monitor and analyze traffic patterns and packet inspection associated to protocol(s) that do not follow the expected protocol standards and traffic flows (e.g extraneous packets that do not belong to established flows, gratuitous or anomalous traffic… Dados: `Network Traffic` (None), `Persona` (None).
9. **T1027.002 Software Packing** — Detection of unpacking behavior through abnormal memory allocation, followed by executable code injection and execution from non-image sections. Dados: `WinEventLog:Sysmon` (EventCode=10), `WinEventLog:Sysmon` (EventCode=1).
10. **T1018 Remote System Discovery** — Execution of network enumeration utilities (e.g., net.exe, ping.exe, tracert.exe) in short succession, often chained with lateral movement tools or system enumeration commands. Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=3, 22).
11. **T1190 Exploit Public-Facing Application** — Adversary sends crafted HTTP/S (or other service) input to an Internet-facing app (IIS/ASP.NET, API, device portal). Chain: (1) abnormal request patterns to public endpoint → (2) elevated 4xx/5xx or unusual methods/paths → (3) server process (w3wp.exe/other… Dados: `ApplicationLog:IIS` (IIS W3C logs in C:\inetpub\logs\LogFiles\W3SVC* (spikes in 5xx, RCE/SQLi/path traversal/JNDI patterns)), `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=7).
12. **T1583.001 Domains** — Monitor logged domain name system (DNS) data for purchased domains that can be used during targeting. Reputation/category-based detection may be difficult until the categorization is updated. Detection efforts may be focused on related stages of the adversary… Dados: `Domain Name` (None), `Domain Name` (None), `Domain Name` (None).

## 11. OSINT — onde pesquisar

Consultas prontas com todos os nomes conhecidos do grupo:

- Relatórios técnicos: [busca web](https://duckduckgo.com/?q=%28%22The+Gentlemen%22+OR+%22Storm-2697%22+OR+%22GOLD+SHERWOOD%22%29+threat+report) · [PDFs](https://duckduckgo.com/?q=%28%22The+Gentlemen%22+OR+%22Storm-2697%22+OR+%22GOLD+SHERWOOD%22%29+filetype%3Apdf)
- Regras e IOCs publicados: [GitHub](https://github.com/search?type=code&q=%22The+Gentlemen%22+OR+%22Storm-2697%22+OR+%22GOLD+SHERWOOD%22)
- Pulsos de ameaça: [AlienVault OTX](https://otx.alienvault.com/browse/global/pulses?q=The+Gentlemen)
- Família de malware e atores: [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/actors) (busque por The Gentlemen, Storm-2697, GOLD SHERWOOD)
- Cartões de grupo: [ThaiCERT Threat Group Cards](https://apt.etda.or.th/cgi-bin/listgroups.cgi)
- Página oficial: [MITRE ATT&CK G1058](https://attack.mitre.org/groups/G1058/)

## 12. Bibliografia (8 fontes citadas pelo ATT&CK)

- [BradyUnit42_TheGentlemen_July2026](https://unit42.paloaltonetworks.com/the-gentlemen-ransomware/) — Brady, M. (2026, July 10). No Manners Here: The Ruthless Rise of The Gentlemen Ransomware. Retrieved September 18, 2026.
- [CarveyODonnellWelchHuntress_TheGentlemen_May2026](https://www.huntress.com/blog/the-gentlemen-ransomware-defense-evasion-ttps) — Carvey, H., O'Donnell-Welch, L. (2026, May 21). The Gentlemen (Ransomware) in Disguise: Defense Evasion and other TTPs. Retrieved September 18, 2026.
- [CheckPointResearch_TheGentlemen_April2026](https://research.checkpoint.com/2026/dfir-report-the-gentlemen/) — Check Point Research. (2026, April 20). DFIR Report – The Gentlemen & SystemBC: A Sneak Peek Behind the Proxy. Retrieved September 18, 2026.
- [Intel471_TheGentlemen_Aug2026](https://www.intel471.com/blog/threat-hunting-case-study-the-gentlemen) — Intel 471. (2026, August 11). Threat Hunting Case Study: The Gentlemen. Retrieved September 18, 2026.
- [MSTI_GentelmenRansomware_May2026](https://www.microsoft.com/en-us/security/blog/2026/05/28/the-gentlemen-ransomware-dissecting-a-self-propagating-go-encryptor/) — Microsoft Threat Intelligence. (2026, May 28). The Gentlemen ransomware: Dissecting a self-propagating Go encryptor . Retrieved September 18, 2026.
- [Sophos_TheGentlemen_Sept2026](https://www.sophos.com/en-gb/blog/ungentlemanly-behavior-insights-into-a-ransomware-operation) — Sophos Counter Threat Unit Research Team. (2026, September 1). Ungentlemanly behavior: Insights into a ransomware operation. Retrieved September 18, 2026.
- [SoučekESET_Gentlemen_Jun2026](https://www.welivesecurity.com/en/eset-research/killing-me-gently-inside-gentlemens-edr-killer-framework/) — Souček, J. (2026, June 18). Killing me gently: Inside Gentlemen’s EDR killer framework. Retrieved September 18, 2026.
- [TrendAI_TheGentlemen_Sept2025](https://www.trendaisecurity.com/en-us/resources-insights/trendai-security-blog/unmasking-the-gentlemen-ransomware) — Santos, J., et al. (2025, September 9). Unmasking The Gentlemen Ransomware: Tactics, Techniques, and Procedures Revealed . Retrieved September 18, 2026.

## 13. Limites e confiança

- O ATT&CK registra o que foi **relatado publicamente**, não tudo o que o grupo faz. Ausência de uma técnica não prova que o grupo não a usa.
- **Sobreposição de TTP não é atribuição.** Muitas técnicas são compartilhadas entre grupos e com red teams. Use a assinatura comportamental como hipótese, junto com infraestrutura, malware e contexto.
- Cobertura de detecção refere-se ao catálogo público Detection Rules, não ao seu ambiente: confira se a telemetria necessária chega ao seu SIEM.
- Ligações marcadas como _inferidas_ (EVTX por palavra-chave, relatórios por nome) devem ser verificadas.

---
Fontes: MITRE ATT&CK® (uso livre com atribuição, © The MITRE Corporation), APT4ALL (MISP Galaxy CC0/BSD-2, APT Groups & Operations CC BY 4.0, EternalLiberty, APTnotes, Ransomware Tool Matrix CC BY 4.0), Atomic Red Team (Red Canary, MIT), EVTX-to-MITRE-Attack, EVTX-ATTACK-SAMPLES, APT & CyberCriminal Campaign Collections. Gerado por [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules).
