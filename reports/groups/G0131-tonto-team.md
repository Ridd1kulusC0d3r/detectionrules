# Tonto Team (G0131) — Dossiê de inteligência

> **TLP:CLEAR** · gerado em 2026-10-25 a partir de fontes abertas · MITRE ATT&CK v20.0 · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0131) · [ATT&CK](https://attack.mitre.org/groups/G0131/)

**Também conhecido como:** Earth Akhlut, BRONZE HUNTLEY, CactusPete, Karma Panda  
**Registro no ATT&CK:** criado em 2021-05-05, atualizado em 2026-07-31 · referências de 2003 a 2021

## 1. Sumário executivo

- **15 técnicas** atribuídas publicamente, concentradas em **Execution, Credential Access, Discovery**.
- **Arsenal:** 2 malware e 4 ferramentas (ex.: Bisonal, ShadowPad, Mimikatz, LaZagne, NBTscan).
- **Campanhas atribuídas:** 0.
- **Cobertura de detecção pública:** 100% das técnicas têm ao menos uma regra no catálogo; **0 técnicas sem nenhuma regra pública**.
- **Assinatura comportamental** (técnicas raras entre os 178 grupos, as mais úteis para atribuição): T1069.001 Local Groups, T1090.002 External Proxy, T1210 Exploitation of Remote Services, T1003 OS Credential Dumping, T1135 Network Share Discovery.

## 2. Quem é

> Tonto Team is a suspected Chinese state-sponsored cyber espionage threat group that has primarily targeted South Korea, Japan, Taiwan, and the United States since at least 2009; by 2020 they expanded operations to include other Asian as well as Eastern European countries. Tonto Team has targeted government, military, energy, mining, financial, education, healthcare, and technology organizations, including through the Heartbeat Campaign (2009-2012) and Operation Bitter Biscuit (2017).

_Texto original do MITRE ATT&CK, em inglês._

## 3. Perfil TTP por tática (kill chain)

Cada linha: técnica, como o grupo a usou segundo relatos públicos, e o que existe para detectar e testar.

### Initial Access (TA0001) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1566.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1566.001) Spearphishing Attachment | Tonto Team has delivered payloads via spearphishing attachments. | 230 | 2 | — |

### Execution (TA0002) — 5

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1059.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.001) PowerShell | Tonto Team has used PowerShell to download additional payloads. | 1340 | 22 | 15 |
| [T1059.006](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.006) Python | Tonto Team has used Python-based tools for execution. | 122 | — | — |
| [T1203](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1203) Exploitation for Client Execution | Tonto Team has exploited Microsoft vulnerabilities, including CVE-2018-0798, CVE-2018-8174, CVE-2018-0802, CVE-2017-11882, CVE-2019-9489 CVE-2020-8468, and CVE-2018-0798 to enable execution of their delivered malicious payloads. | 202 | — | — |
| [T1204.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1204.002) Malicious File | Tonto Team has relied on user interaction to open their malicious RTF documents. | 259 | 13 | — |
| [T1574.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1574.001) DLL | Tonto Team abuses a legitimate and signed Microsoft executable to launch a malicious DLL. | 455 | 7 | 5 |

### Persistence (TA0003) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1505.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1505.003) Web Shell | Tonto Team has used a first stage web shell after compromising a vulnerable Exchange server. | 210 | 1 | — |

### Privilege Escalation (TA0004) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1068](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1068) Exploitation for Privilege Escalation | Tonto Team has exploited CVE-2019-0803 and MS16-032 to escalate privileges. | 408 | 2 | 2 |

### Stealth (TA0005) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1574.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1574.001) DLL | Tonto Team abuses a legitimate and signed Microsoft executable to launch a malicious DLL. | 455 | 7 | 5 |

### Credential Access (TA0006) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1003) OS Credential Dumping | Tonto Team has used a variety of credential dumping tools. | 399 | 7 | 19 |
| [T1056.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1056.001) Keylogging | Tonto Team has used keylogging tools in their operations. | 40 | 8 | 1 |

### Discovery (TA0007) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1069.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1069.001) Local Groups | Tonto Team has used the ShowLocalGroupDetails command to identify administrator, user, and guest accounts on a compromised host. | 50 | 7 | — |
| [T1135](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1135) Network Share Discovery | Tonto Team has used tools such as NBTscan to enumerate network shares. | 73 | 12 | 3 |

### Lateral Movement (TA0008) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1210](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1210) Exploitation of Remote Services | Tonto Team has used EternalBlue exploits for lateral movement. | 192 | — | 4 |

### Collection (TA0009) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1056.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1056.001) Keylogging | Tonto Team has used keylogging tools in their operations. | 40 | 8 | 1 |

### Command and Control (TA0011) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1090.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1090.002) External Proxy | Tonto Team has routed their traffic through an external server in order to obfuscate their location. | 18 | — | — |
| [T1105](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1105) Ingress Tool Transfer | Tonto Team has downloaded malicious DLLs which served as a ShadowPad loader. | 644 | 39 | — |

## 4. Assinatura comportamental

Técnicas que este grupo usa e que poucos dos 178 grupos do ATT&CK usam. Pesam mais numa atribuição por TTP: ver várias delas juntas é mais informativo do que ver técnicas comuns como PowerShell.

| Técnica | Outros grupos que usam | Peso (raridade) |
|---|---:|---:|
| T1069.001 Local Groups | 6 | 3.11 |
| T1090.002 External Proxy | 10 | 2.70 |
| T1210 Exploitation of Remote Services | 11 | 2.62 |
| T1003 OS Credential Dumping | 12 | 2.55 |
| T1135 Network Share Discovery | 15 | 2.35 |
| T1059.006 Python | 20 | 2.10 |
| T1068 Exploitation for Privilege Escalation | 22 | 2.01 |
| T1056.001 Keylogging | 25 | 1.89 |
| T1505.003 Web Shell | 30 | 1.72 |
| T1574.001 DLL | 35 | 1.58 |

## 5. Arsenal

| Software | Tipo | Técnicas no ATT&CK | Uso relatado (EN) |
|---|---|---:|---|
| [Bisonal](https://attack.mitre.org/software/S0268/) | malware | 34 |  |
| [ShadowPad](https://attack.mitre.org/software/S0596/) | malware | 21 |  |
| [Mimikatz](https://attack.mitre.org/software/S0002/) | ferramenta | 17 |  |
| [LaZagne](https://attack.mitre.org/software/S0349/) | ferramenta | 10 |  |
| [NBTscan](https://attack.mitre.org/software/S0590/) | ferramenta | 5 |  |
| [gsecdump](https://attack.mitre.org/software/S0008/) | ferramenta | 2 |  |

## 6. Campanhas

Nenhuma campanha atribuída no ATT&CK.

## 7. Cobertura defensiva

**15 de 15 técnicas (100%)** têm ao menos uma regra pública no catálogo Detection Rules.

### Regras recomendadas por técnica

Melhor regra disponível por técnica (formato portável e maduro primeiro).

| Técnica | Regra | Formato | Fonte |
|---|---|---|---|
| T1003 | [Antivirus - Password Dumper Signature](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A78cc2dd2-7d20-4d32-93ff-057084c38b93) | Sigma | SigmaHQ |
| T1003 | [HackTool - Rubeus Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A7ec2c172-dceb-4c10-92c9-87c1881b7e18) | Sigma | SigmaHQ |
| T1056.001 | [Linux Keylogging with Pam.d](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A49aae26c-450e-448b-911d-b3c13d178dfc) | Sigma | SigmaHQ |
| T1056.001 | [Linux Keylogging with Pam.d](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A49aae26c-450e-448b-911d-b3c13d178dfc) | Sigma | OpenSearch Security Analytics |
| T1059.001 | [Potential Emotet Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad02e8cf5-6099-48cf-9bfc-1eec2d0c7b18) | Sigma | SigmaHQ |
| T1059.001 | [TropicTrooper Campaign November 2018](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A8c7090c3-e0a0-4944-bd08-08c3a0cecf79) | Sigma | SigmaHQ |
| T1059.006 | [Emotet Loader Execution Via .LNK File](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1f32d820-1d5c-43fe-8fe2-feef0c952eb7) | Sigma | SigmaHQ |
| T1059.006 | [Serpent Backdoor Payload Execution Via Scheduled Task](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad5eb7432-fda4-4bba-a37f-ffa74d9ed639) | Sigma | SigmaHQ |
| T1068 | [Exploiting CVE-2019-1388](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A02e0b2ea-a597-428e-b04a-af6a1a403e5c) | Sigma | SigmaHQ |
| T1068 | [OMIGOD HTTP No Authentication RCE - CVE-2021-38647](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aab6b1a39-a9ee-4ab4-b075-e83acf6e346b) | Sigma | SigmaHQ |
| T1069.001 | [BloodHound Collection Files](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A02773bed-83bf-469f-b7ff-e676e7d78bab) | Sigma | SigmaHQ |
| T1069.001 | [HackTool - Bloodhound/Sharphound Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Af376c8a7-a2d0-4ddc-aa0c-16c17236d962) | Sigma | SigmaHQ |
| T1090.002 | [RDP over Reverse SSH Tunnel WFP](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A5bed80b6-b3e8-428e-a3ae-d3c757589e41) | Sigma | SigmaHQ |
| T1090.002 | [Potential Tunneling via AWS IoT Secure Tunneling Localproxy](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Adeab559f-f3ab-4ce3-b17c-8f70c4169fd6) | Elastic | Elastic detection-rules |
| T1105 | [Greenbug Espionage Group Indicators](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A3711eee4-a808-4849-8a14-faf733da3612) | Sigma | SigmaHQ |
| T1105 | [Pandemic Registry Key](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A47e0852a-cf81-4494-a8e6-31864f8c86ed) | Sigma | SigmaHQ |
| T1135 | [Potential Dridex Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae6eb5a96-9e6f-4a18-9cdd-642cfda21c8e) | Sigma | SigmaHQ |
| T1135 | [Dridex Process Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Ae6eb5a96-9e6f-4a18-9cdd-642cfda21c8e) | Sigma | OpenSearch Security Analytics |
| T1203 | [Droppers Exploiting CVE-2017-11882](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A678eb5f4-8597-4be6-8be7-905e4234b53a) | Sigma | SigmaHQ |
| T1203 | [OMIGOD HTTP No Authentication RCE - CVE-2021-38647](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aab6b1a39-a9ee-4ab4-b075-e83acf6e346b) | Sigma | SigmaHQ |
| T1204.002 | [Ursnif Malware C2 URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A932ac737-33ca-4afd-9869-0d48b391fcc9) | Sigma | SigmaHQ |
| T1204.002 | [Droppers Exploiting CVE-2017-11882](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A678eb5f4-8597-4be6-8be7-905e4234b53a) | Sigma | SigmaHQ |
| T1210 | [OMIGOD HTTP No Authentication RCE - CVE-2021-38647](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aab6b1a39-a9ee-4ab4-b075-e83acf6e346b) | Sigma | SigmaHQ |
| T1210 | [OMIGOD HTTP No Authentication RCE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Aab6b1a39-a9ee-4ab4-b075-e83acf6e346b) | Sigma | OpenSearch Security Analytics |
| T1505.003 | [MOVEit CVE-2023-34362 Exploitation Attempt - Potential Web Shell Request](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A435e41f2-48eb-4c95-8a2b-ed24b50ec30b) | Sigma | SigmaHQ |
| T1505.003 | [Solarwinds SUPERNOVA Webshell Access](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aa2cee20b-eacc-459f-861d-c02e5d12f1db) | Sigma | SigmaHQ |
| T1566.001 | [Ursnif Malware C2 URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A932ac737-33ca-4afd-9869-0d48b391fcc9) | Sigma | SigmaHQ |
| T1566.001 | [Droppers Exploiting CVE-2017-11882](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A678eb5f4-8597-4be6-8be7-905e4234b53a) | Sigma | SigmaHQ |
| T1574.001 | [Winnti Pipemon Characteristics](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A73d70463-75c9-4258-92c6-17500fe972f2) | Sigma | SigmaHQ |
| T1574.001 | [Winnti Pipemon Characteristics](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A73d70463-75c9-4258-92c6-17500fe972f2) | Sigma | OpenSearch Security Analytics |

## 8. Plano de emulação e validação

Use num laboratório isolado e autorizado para confirmar que as regras disparam. Os comandos estão nos repositórios oficiais.

| Tática | Técnica | Teste Atomic Red Team | Plataformas |
|---|---|---|---|
| Initial Access | [T1566.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1566.001/T1566.001.md) | Download Macro-Enabled Phishing Attachment | windows |
| Initial Access | [T1566.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1566.001/T1566.001.md) | Word spawned a command shell and used an IP address in the command line | windows |
| Execution | [T1059.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md) | Mimikatz | windows |
| Execution | [T1059.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md) | Run BloodHound from local disk | windows |
| Execution | [T1204.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1204.002/T1204.002.md) | OSTap Style Macro Execution | windows |
| Execution | [T1204.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1204.002/T1204.002.md) | OSTap Payload Download | windows |
| Persistence | [T1505.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1505.003/T1505.003.md) | Web Shell Written to Disk | windows |
| Privilege Escalation | [T1068](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1068/T1068.md) | Scattered Spider BYOVD (CVE-2015-2291 for Intel Ethernet Diagnostics Driver) | windows |
| Privilege Escalation | [T1068](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1068/T1068.md) | Turla Snake Malware Privilege Escalation Through VM Driver | windows |
| Stealth | [T1574.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1574.001/T1574.001.md) | DLL Search Order Hijacking - amsi.dll | windows |
| Stealth | [T1574.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1574.001/T1574.001.md) | Phantom Dll Hijacking - WinAppXRT.dll | windows |
| Credential Access | [T1003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003/T1003.md) | Gsecdump | windows |
| Credential Access | [T1003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003/T1003.md) | Credential Dumping with NPPSpy | windows |
| Discovery | [T1069.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1069.001/T1069.001.md) | Permission Groups Discovery (Local) | linux, macos |
| Discovery | [T1069.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1069.001/T1069.001.md) | Basic Permission Groups Discovery Windows (Local) | windows |
| Discovery | [T1135](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1135/T1135.md) | Network Share Discovery | macos |
| Discovery | [T1135](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1135/T1135.md) | Network Share Discovery - linux | linux |
| Collection | [T1056.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1056.001/T1056.001.md) | Input Capture | windows |
| Collection | [T1056.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1056.001/T1056.001.md) | Living off the land Terminal Input Capture on Linux with pam.d | linux |
| Command and Control | [T1105](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1105/T1105.md) | rsync remote file copy (push) | linux, macos |
| Command and Control | [T1105](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1105/T1105.md) | rsync remote file copy (pull) | linux, macos |

**Logs reais de ataque (EVTX) para testar sem executar nada:**

- T1003 — [ID1-12-13-Wdigest authentication activation](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0006-Credential%20Access/T1003-Credential%20dumping/ID1-12-13-Wdigest%20authentication%20activation.evtx) _(explícito)_
- T1003 — [ID1-LSASS dump with LSASSY (SYSMON)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0006-Credential%20Access/T1003-Credential%20dumping/ID1-LSASS%20dump%20with%20LSASSY%20%28SYSMON%29.evtx) _(explícito)_
- T1056.001 — [sysmon_13_keylogger_directx](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Credential%20Access/sysmon_13_keylogger_directx.evtx) _(inferido)_
- T1059.001 — [ID4103-4104-Payload download via PowerShell](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1059.001-PowerShell/ID4103-4104-Payload%20download%20via%20PowerShell.evtx) _(explícito)_
- T1059.001 — [ID4688-Encoded PowerShell MSF payload via process execution](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1059.001-PowerShell/ID4688-Encoded%20PowerShell%20MSF%20payload%20via%20process%20execution.evtx) _(explícito)_
- T1068 — [ID12-13 Mini_Plasma_PoC_AbortHydration_ArbitraryRegKey_EoP](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0004-Privilege%20Escalation/T1068-Exploitation%20for%20Privilege%20Escalation/ID12-13%20Mini_Plasma_PoC_AbortHydration_ArbitraryRegKey_EoP.evtx) _(explícito)_
- T1068 — [ID4673-Privilege SeMachineAccountPrivilege called](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0004-Privilege%20Escalation/T1068-Exploitation%20for%20Privilege%20Escalation/ID4673-Privilege%20SeMachineAccountPrivilege%20called.evtx) _(explícito)_
- T1135 — [ID4688-Network share discovery or connection via commandline](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1135.xxx-Network%20Share%20Discovery/ID4688-Network%20share%20discovery%20or%20connection%20via%20commandline.evtx) _(explícito)_
- T1135 — [ID5140-5145-Bloodhound-SharpHound enumeration via SMB](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1135.xxx-Network%20Share%20Discovery/ID5140-5145-Bloodhound-SharpHound%20enumeration%20via%20SMB.evtx) _(explícito)_
- T1210 — [Zerologon_CVE-2020-1472_DFIR_System_NetLogon_Error_EventID_5805](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Credential%20Access/Zerologon_CVE-2020-1472_DFIR_System_NetLogon_Error_EventID_5805.evtx) _(inferido)_
- T1210 — [Zerologon_VoidSec_CVE-2020-1472_4626_LT3_Anonym_follwedby_4742_DC_Anony_DC](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Credential%20Access/Zerologon_VoidSec_CVE-2020-1472_4626_LT3_Anonym_follwedby_4742_DC_Anony_DC.evtx) _(inferido)_
- T1574.001 — [DE_timestomp_and_dll_sideloading_and_RunPersist](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/AutomatedTestingTools/Malware/DE_timestomp_and_dll_sideloading_and_RunPersist.evtx) _(inferido)_
- T1574.001 — [sideloading_injection_persistence_run_key](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/AutomatedTestingTools/Malware/sideloading_injection_persistence_run_key.evtx) _(inferido)_

## 9. Hipóteses de hunting

Se Tonto Team estiver no seu ambiente, estas são as perguntas a fazer aos seus dados (fontes de log segundo as estratégias de detecção do MITRE ATT&CK).

1. **T1069.001 Local Groups** — Detects attempts to enumerate local groups via Net.exe, PowerShell, or native API calls that precede lateral movement or privilege abuse. Dados: `WinEventLog:Security` (EventCode=4688).
2. **T1090.002 External Proxy** — Unusual process (e.g., `rundll32`, `mshta`, `wscript`, or custom payloads) initiates network connection to external IPs/domains that proxy C2 traffic, often over uncommon ports or high entropy HTTP/S connections. Dados: `WinEventLog:Sysmon` (EventCode=3, 22), `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Microsoft-Windows-Windows Defender/Operational` (Unusual external domain access).
3. **T1210 Exploitation of Remote Services** — Correlates inbound network access to remote service ports (e.g., SMB/RPC 445/135, RDP 3389, WinRM 5985/5986) with near-time instability in the target service (crash, abnormal restart), suspicious child process creation under the service, and post-access… Dados: `WinEventLog:System` (EventCode=1000), `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=3, 22).
4. **T1003 OS Credential Dumping** — Processes accessing LSASS memory or SAM registry hives outside of trusted security tools, often followed by file creation or lateral movement. Detects unauthorized access to sensitive OS subsystems for credential extraction. Dados: `WinEventLog:Sysmon` (EventCode=10), `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Security` (EventCode=4663, 4670, 4656).
5. **T1135 Network Share Discovery** — Process or script enumerates network shares via CLI (net view/net share, PowerShell Get-SmbShare/WMI) or OS APIs (NetShareEnum/ srvsvc.NetShareEnumAll RPC) → bursts of outbound SMB/RPC connections (445/139, \\host\IPC$ / srvsvc) to many hosts inside a short… Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=3, 22), `WinEventLog:Sysmon` (EventCode=17).
6. **T1059.006 Python** — Detects Python execution via python.exe or py.exe with anomalous parent lineage (e.g., Office macros, LOLBAS), execution from unusual directories, or chained network/PowerShell/system-level activity. Dados: `WinEventLog:Sysmon` (EventCode=1), `EDR:hunting` (Advanced Hunting: DeviceProcessEvents + DeviceNetworkEvents).
7. **T1068 Exploitation for Privilege Escalation** — Detects exploitation attempts targeting vulnerable kernel drivers or OS components, often followed by unusual process or token behavior. Dados: `WinEventLog:Sysmon` (EventCode=6), `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Security` (EventCode=4672).
8. **T1056.001 Keylogging** — Monitors suspicious usage of Windows API calls like SetWindowsHookEx, GetKeyState, or polling functions within non-UI service processes, combined with Registry or driver modifications. Dados: `WinEventLog:Sysmon` (EventCode=10), `WinEventLog:Security` (EventCode=4663, 4670, 4656), `WinEventLog:System` (EventCode=7045).
9. **T1505.003 Web Shell** — Unexpected file creation in web directories followed by web server processes (e.g., w3wp.exe) spawning command shells or script interpreters (e.g., cmd.exe, powershell.exe) Dados: `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Security` (EventCode=4624, 4648).
10. **T1574.001 DLL** — DLL hijacking behaviors including unexpected DLL loads from non-standard directories, replacement of DLLs, phantom DLL insertion, redirection file creation, and substitution of legitimate DLLs. Defender correlates file system modifications, registry changes,… Dados: `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Sysmon` (EventCode=15), `WinEventLog:Sysmon` (EventCode=7).
11. **T1203 Exploitation for Client Execution** — Cause→effect chain: (1) A client app (browser, Office, PDF/Flash/reader) experiences a crash/abnormal exit or loads from an unusual location, then (2) drops or modifies a file in user-writable paths, and/or (3) spawns an unexpected child (e.g.,… Dados: `WinEventLog:Application` (EventCode=1000), `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Sysmon` (EventCode=1).
12. **T1566.001 Spearphishing Attachment** — Detection of spearphishing attachments by correlating suspicious email delivery with subsequent file creation and abnormal process execution (e.g., Office spawning PowerShell or CMD). Behavior chain includes inbound email metadata → attachment stored on disk… Dados: `m365:unified` (Send/Receive: Inbound emails with attachments from suspicious or spoofed senders), `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Sysmon` (EventCode=1).

## 10. OSINT — onde pesquisar

Consultas prontas com todos os nomes conhecidos do grupo:

- Relatórios técnicos: [busca web](https://duckduckgo.com/?q=%28%22Tonto+Team%22+OR+%22Earth+Akhlut%22+OR+%22BRONZE+HUNTLEY%22+OR+%22CactusPete%22+OR+%22Karma+Panda%22%29+threat+report) · [PDFs](https://duckduckgo.com/?q=%28%22Tonto+Team%22+OR+%22Earth+Akhlut%22+OR+%22BRONZE+HUNTLEY%22+OR+%22CactusPete%22+OR+%22Karma+Panda%22%29+filetype%3Apdf)
- Regras e IOCs publicados: [GitHub](https://github.com/search?type=code&q=%22Tonto+Team%22+OR+%22Earth+Akhlut%22+OR+%22BRONZE+HUNTLEY%22+OR+%22CactusPete%22+OR+%22Karma+Panda%22)
- Pulsos de ameaça: [AlienVault OTX](https://otx.alienvault.com/browse/global/pulses?q=Tonto+Team)
- Família de malware e atores: [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/actors) (busque por Tonto Team, Earth Akhlut, BRONZE HUNTLEY)
- Cartões de grupo: [ThaiCERT Threat Group Cards](https://apt.etda.or.th/cgi-bin/listgroups.cgi)
- Página oficial: [MITRE ATT&CK G0131](https://attack.mitre.org/groups/G0131/)

## 11. Bibliografia (10 fontes citadas pelo ATT&CK)

- [ARS Technica China Hack SK April 2017](https://arstechnica.com/information-technology/2017/04/researchers-claim-china-trying-to-hack-south-korea-missile-defense-efforts/) — Sean Gallagher. (2017, April 21). Researchers claim China trying to hack South Korea missile defense efforts. Retrieved October 17, 2021.
- [CrowdStrike Manufacturing Threat July 2020](https://www.crowdstrike.com/blog/adversaries-targeting-the-manufacturing-industry/) — Falcon OverWatch Team. (2020, July 14). Manufacturing Industry in the Adversaries’ Crosshairs. Retrieved October 17, 2021.
- [ESET Exchange Mar 2021](https://www.welivesecurity.com/2021/03/10/exchange-servers-under-siege-10-apt-groups/) — Faou, M., Tartare, M., Dupuy, T. (2021, March 10). Exchange servers under siege from at least 10 APT groups. Retrieved May 21, 2021.
- [FireEye Chinese Espionage October 2019](https://web.archive.org/web/20210308054208/https://www.fireeye.com/content/dam/fireeye-www/summit/cds-2019/presentations/cds19-executive-s08-achievement-unlocked.pdf) — Nalani Fraser, Kelli Vanderlee. (2019, October 10). Achievement Unlocked - Chinese Cyber Espionage Evolves to Support Higher Level Missions. Retrieved November 17, 2024.
- [Kaspersky CactusPete Aug 2020](https://securelist.com/cactuspete-apt-groups-updated-bisonal-backdoor/97962/) — Zykov, K. (2020, August 13). CactusPete APT group’s updated Bisonal backdoor. Retrieved May 5, 2021.
- [Secureworks BRONZE HUNTLEY ](https://www.secureworks.com/research/threat-profiles/bronze-huntley) — Secureworks. (2021, January 1). BRONZE HUNTLEY Threat Profile. Retrieved May 5, 2021.
- [Talos Bisonal 10 Years March 2020](https://blog.talosintelligence.com/2020/03/bisonal-10-years-of-play.html) — Warren Mercer, Paul Rascagneres, Vitor Ventura. (2020, March 6). Bisonal 10 Years of Play. Retrieved October 17, 2021.
- [Talos Bisonal Mar 2020](https://blog.talosintelligence.com/2020/03/bisonal-10-years-of-play.html) — Mercer, W., et al. (2020, March 5). Bisonal: 10 years of play. Retrieved January 26, 2022.
- [Trend Micro HeartBeat Campaign January 2013](https://www.trendmicro.de/cloud-content/us/pdfs/security-intelligence/white-papers/wp_the-heartbeat-apt-campaign.pdf?) — Roland Dela Paz. (2003, January 3). The HeartBeat APT Campaign. Retrieved October 17, 2021.
- [TrendMicro Tonto Team October 2020](https://vb2020.vblocalhost.com/uploads/VB2020-06.pdf) — Daniel Lughi, Jaromir Horejsi. (2020, October 2). Tonto Team - Exploring the TTPs of an advanced threat actor operating a large infrastructure. Retrieved October 17, 2021.

## 12. Limites e confiança

- O ATT&CK registra o que foi **relatado publicamente**, não tudo o que o grupo faz. Ausência de uma técnica não prova que o grupo não a usa.
- **Sobreposição de TTP não é atribuição.** Muitas técnicas são compartilhadas entre grupos e com red teams. Use a assinatura comportamental como hipótese, junto com infraestrutura, malware e contexto.
- Cobertura de detecção refere-se ao catálogo público Detection Rules, não ao seu ambiente: confira se a telemetria necessária chega ao seu SIEM.
- Ligações marcadas como _inferidas_ (EVTX por palavra-chave, relatórios por nome) devem ser verificadas.

---
Fontes: MITRE ATT&CK® (uso livre com atribuição, © The MITRE Corporation), Atomic Red Team (Red Canary, MIT), EVTX-to-MITRE-Attack, EVTX-ATTACK-SAMPLES, APT & CyberCriminal Campaign Collections. Gerado por [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules).
