# Lotus Blossom (G0030) — Dossiê de inteligência

> **TLP:CLEAR** · gerado em 2026-10-26 a partir de fontes abertas · MITRE ATT&CK v20.0 · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0030) · [ATT&CK](https://attack.mitre.org/groups/G0030/)

**Também conhecido como:** DRAGONFISH, Spring Dragon, RADIUM, Raspberry Typhoon, Bilbug, Thrip  
**Origem atribuída:** China · **Motivação:** espionagem · **Setores-alvo:** Governo, Defesa e militar  
**Registro no ATT&CK:** criado em 2017-05-31, atualizado em 2026-07-31 · referências de 2015 a 2025

## 1. Sumário executivo

- **21 técnicas** atribuídas publicamente, concentradas em **Discovery, Collection, Command and Control**.
- **Arsenal:** 4 malware e 5 ferramentas (ex.: Elise, Sagerunex, Emissary, Impacket, Hannotog).
- **Campanhas atribuídas:** 0.
- **Cobertura de detecção pública:** 100% das técnicas têm ao menos uma regra no catálogo; **0 técnicas sem nenhuma regra pública**.
- **Origem e alvos (APT4ALL):** atribuído a **China**, motivação espionagem; setores Governo, Defesa e militar; 6 países vítimas citados.
- **Onde a cobertura está:** Windows (20 técnicas com regra), EDR / XDR (19 técnicas com regra), Outros / genérico (15 técnicas com regra), Servidores web & aplicações (13 técnicas com regra).
- **Assinatura comportamental** (técnicas raras entre os 178 grupos, as mais úteis para atribuição): T1134 Access Token Manipulation, T1560.003 Archive via Custom Method, T1539 Steal Web Session Cookie, T1090.001 Internal Proxy, T1482 Domain Trust Discovery.

## 2. Quem é

> Lotus Blossom is a long-standing threat group largely targeting various entities in Asia since at least 2009. In addition to government and related targets, Lotus Blossom has also targeted entities such as digital certificate issuers.

_Texto original do MITRE ATT&CK, em inglês._

## 3. Contexto, nomes e alvos

Consolidado pelo [APT4ALL](https://github.com/Ridd1kulusC0d3r/apt4all) a partir de MISP Galaxy, planilha APT Groups & Operations, EternalLiberty e APTnotes. Atribuição é afirmação de quem publicou; confira a fonte.

| Campo | Valor |
|---|---|
| Origem atribuída | China |
| Motivação | espionagem |
| Setores-alvo | Governo, Defesa e militar |
| Vítimas citadas | Hong Kong, Indonesia, Japan, Philippines, Taiwan, Vietnam |
| Alvos (planilha) | — |
| Operações conhecidas | Operation Lotus Blossom |
| Confiança de atribuição (MISP) | 50 |

**Como cada fornecedor chama este grupo** (útil para cruzar relatórios):

| Fornecedor | Nome(s) |
|---|---|
| Kaspersky | Spring Dragon |
| MITRE ATT&CK | G0030 |
| Microsoft | Raspberry Typhoon, RADIUM (antigo · old) |
| Palo Alto Unit 42 | Lotus Blossom |

**Outros nomes no APT4ALL (não listados pelo ATT&CK):** ST Group, Esile, BitterBug, LOTUS PANDA, BRONZE ELGIN, ATK1, Red Salamander, Billbug, G0030/G0076, Bronze Thornwell/Bronze Elgin, CTG-8171, ATK1/ATK78, Thrip/Billbug

## 4. Perfil TTP por tática (kill chain)

Cada linha: técnica, como o grupo a usou segundo relatos públicos, e o que existe para detectar e testar.

### Resource Development (TA0042) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1588.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1588.002) Tool | Lotus Blossom has used publicly-available tools such as a Python-based cookie stealer for Chrome browsers, Impacket, and the Venom proxy tool. | 35 | — | — |

### Execution (TA0002) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1047](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1047) Windows Management Instrumentation | Lotus Blossom has used WMI to enable lateral movement. | 370 | 12 | 11 |

### Persistence (TA0003) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1112](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1112) Modify Registry | Lotus Blossom has installed tools such as Sagerunex by writing them to the Windows registry. | 601 | 92 | 3 |
| [T1543.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1543.003) Windows Service | Lotus Blossom has configured tools such as Sagerunex to run as Windows services. | 1916 | 6 | 19 |

### Privilege Escalation (TA0004) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1134](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1134) Access Token Manipulation | Lotus Blossom has retrieved process tokens for processes to adjust the privileges of the launch process or other items. | 82 | — | 14 |
| [T1543.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1543.003) Windows Service | Lotus Blossom has configured tools such as Sagerunex to run as Windows services. | 1916 | 6 | 19 |

### Stealth (TA0005) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1134](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1134) Access Token Manipulation | Lotus Blossom has retrieved process tokens for processes to adjust the privileges of the launch process or other items. | 82 | — | 14 |

### Defense Impairment (TA0112) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1112](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1112) Modify Registry | Lotus Blossom has installed tools such as Sagerunex by writing them to the Windows registry. | 601 | 92 | 3 |

### Credential Access (TA0006) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1539](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1539) Steal Web Session Cookie | Lotus Blossom has used publicly-available tools to steal cookies from browsers such as Chrome. | 54 | 5 | — |

### Discovery (TA0007) — 10

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1012](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1012) Query Registry | Lotus Blossom has run commands such as `reg query HKLM\SYSTEM\CurrentControlSet\Services\[service name]\Parameters` to verify if installed implants are running as a service. | 92 | 6 | — |
| [T1016](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1016) System Network Configuration Discovery | Lotus Blossom has used commands such as `ipconfig` and `netstat` to gather network information on compromised hosts. | 99 | 10 | 5 |
| [T1016.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1016.001) Internet Connection Discovery | Lotus Blossom has performed checks to determine if a victim machine is able to access the Internet. | 14 | 5 | — |
| [T1018](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1018) Remote System Discovery | Lotus Blossom has used Ping to identify remote systems. | 157 | 23 | 1 |
| [T1046](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1046) Network Service Discovery | Lotus Blossom has used port scanners to enumerate services on remote hosts. | 212 | 13 | 2 |
| [T1049](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1049) System Network Connections Discovery | Lotus Blossom has used commands such as `netstat` to identify system network connections. | 47 | 7 | — |
| [T1083](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1083) File and Directory Discovery | Lotus Blossom has used commands such as `dir` to examine the local filesystem of victim machines. | 137 | 9 | — |
| [T1087.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1087.001) Local Account | Lotus Blossom has used commands such as `net` to profile local system users. | 98 | 11 | — |
| [T1087.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1087.002) Domain Account | Lotus Blossom has used `net` commands and tools such as AdFind to profile domain accounts associated with victim machines and make Active Directory queries. | 180 | 25 | 1 |
| [T1482](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1482) Domain Trust Discovery | Lotus Blossom has used tools such as AdFind to make Active Directory queries. | 158 | 8 | 1 |

### Collection (TA0009) — 3

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1074.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1074.001) Local Data Staging | Lotus Blossom has locally staged compressed and archived data for follow-on exfiltration. | 37 | 3 | — |
| [T1560.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1560.001) Archive via Utility | Lotus Blossom has used WinRAR for compressing data in RAR format. | 76 | 13 | — |
| [T1560.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1560.003) Archive via Custom Method | Lotus Blossom has used custom tools to compress and archive data on victim systems. | 1 | — | — |

### Command and Control (TA0011) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1090.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1090.001) Internal Proxy | Lotus Blossom has used publicly available tools such as the Venom proxy tool to proxy traffic out of victim environments. | 43 | 3 | — |
| [T1090.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1090.003) Multi-hop Proxy | Lotus Blossom has used tools such as the publicly available HTran tool for proxying traffic in victim environments. | 44 | 4 | — |

## 5. Assinatura comportamental

Técnicas que este grupo usa e que poucos dos 178 grupos do ATT&CK usam. Pesam mais numa atribuição por TTP: ver várias delas juntas é mais informativo do que ver técnicas comuns como PowerShell.

| Técnica | Outros grupos que usam | Peso (raridade) |
|---|---:|---:|
| T1134 Access Token Manipulation | 2 | 3.80 |
| T1560.003 Archive via Custom Method | 6 | 3.11 |
| T1539 Steal Web Session Cookie | 7 | 2.99 |
| T1090.001 Internal Proxy | 8 | 2.88 |
| T1482 Domain Trust Discovery | 9 | 2.79 |
| T1016.001 Internet Connection Discovery | 10 | 2.70 |
| T1090.003 Multi-hop Proxy | 12 | 2.55 |
| T1087.001 Local Account | 18 | 2.19 |
| T1012 Query Registry | 19 | 2.14 |
| T1543.003 Windows Service | 25 | 1.89 |

## 6. Arsenal

| Software | Tipo | Técnicas no ATT&CK | Uso relatado (EN) |
|---|---|---:|---|
| [Elise](https://attack.mitre.org/software/S0081/) | malware | 19 | Lotus Blossom has used Elise. |
| [Sagerunex](https://attack.mitre.org/software/S1210/) | malware | 18 | Lotus Blossom is the exclusive user of Sagerunex, and has employed variants of this in operations since 2016. |
| [Emissary](https://attack.mitre.org/software/S0082/) | malware | 15 | Lotus Blossom has used Emissary. |
| [Impacket](https://attack.mitre.org/software/S0357/) | ferramenta | 11 | Lotus Blossom has used Impacket during operations. |
| [Hannotog](https://attack.mitre.org/software/S1211/) | malware | 7 | Hannotog is a backdoor associated with Lotus Blossom operations. |
| [NBTscan](https://attack.mitre.org/software/S0590/) | ferramenta | 5 | Lotus Blossom has used NBTscan during operations. |
| [AdFind](https://attack.mitre.org/software/S0552/) | ferramenta | 5 | Lotus Blossom has used AdFind to query Active Directory in victim environments. |
| [certutil](https://attack.mitre.org/software/S0160/) | ferramenta | 4 | Lotus Blossom has used certutil during operations. |
| [Ping](https://attack.mitre.org/software/S0097/) | ferramenta | 1 | Lotus Blossom has used Ping to verify connectivity to remote hosts. |

**Outras ferramentas e malware relatados (planilha APT Groups & Operations / MISP):** Elise Backdoor, Lstudio, CVE-2017-11882

## 7. Campanhas

Nenhuma campanha atribuída no ATT&CK.

## 8. Cobertura defensiva

**21 de 21 técnicas (100%)** têm ao menos uma regra pública no catálogo Detection Rules.

### Onde procurar — cobertura por tecnologia

Quantas técnicas deste grupo têm ao menos uma regra em cada tecnologia. Comece a caça pelas tecnologias que você tem e que aparecem aqui.

| Tecnologia | Técnicas do grupo com regra |
|---|---:|
| Windows | 20 |
| EDR / XDR | 19 |
| Outros / genérico | 15 |
| Servidores web & aplicações | 13 |
| Linux | 12 |
| macOS | 12 |
| DNS | 12 |
| Active Directory | 11 |
| Firewall & perímetro | 10 |
| IDS / NSM / NDR | 10 |
| Proxy / SWG | 10 |
| IA, LLMs & agentes | 9 |

### Regras recomendadas por técnica

Melhor regra disponível por técnica (formato portável e maduro primeiro).

| Técnica | Regra | Formato | Fonte |
|---|---|---|---|
| T1012 | [Potential Baby Shark Malware Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A2b30fa36-3a18-402f-a22d-bf4ce2189f35) | Sigma | SigmaHQ |
| T1012 | [Operation Wocao Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1cfac73c-be78-4f9a-9b08-5bde0c3953ab) | Sigma | SigmaHQ |
| T1016 | [Potential Pikabot Discovery Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A698d4431-514f-4c82-af4d-cf573872a9f5) | Sigma | SigmaHQ |
| T1016 | [OpenCanary - SNMP OID Request](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae9856028-fd4e-46e6-b3d1-10f7ceb95078) | Sigma | SigmaHQ |
| T1016.001 | [System Public IP Discovery via DNS Query](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A642ce354-4252-4d43-80c9-6603f16571c1) | Elastic | Elastic detection-rules |
| T1016.001 | [Suspicious PDF Reader Child Process](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A53a26770-9cbd-40c5-8b57-61d01a325e14) | Elastic | Elastic detection-rules |
| T1018 | [Chopper Webshell Process Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Afa3c117a-bc0d-416e-a31b-0c0e80653efb) | Sigma | SigmaHQ |
| T1018 | [Webshell Hacking Activity Patterns](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4ebc877f-4612-45cb-b3a5-8e3834db36c9) | Sigma | SigmaHQ |
| T1046 | [HackTool - winPEAS Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A98b53e78-ebaf-46f8-be06-421aafd176d9) | Sigma | SigmaHQ |
| T1046 | [HackTool - WinPwn Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad557dc06-62e8-4468-a8e8-7984124908ce) | Sigma | SigmaHQ |
| T1047 | [HackTool - Potential Impacket Lateral Movement Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A10c14723-61c7-4c75-92ca-9af245723ad2) | Sigma | SigmaHQ |
| T1047 | [CrackMapExec Command Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A058f4380-962d-40a5-afce-50207d36d7e2) | Sigma | OpenSearch Security Analytics |
| T1049 | [Potential Pikabot Discovery Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A698d4431-514f-4c82-af4d-cf573872a9f5) | Sigma | SigmaHQ |
| T1049 | [HackTool - SharpView Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab2317cfa-4a47-4ead-b3ff-297438c0bc2d) | Sigma | SigmaHQ |
| T1074.001 | [Sensitive File Access followed by Compression](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Aa0fbd7a9-1923-4e05-92df-b484168f17bc) | Elastic | Elastic detection-rules |
| T1074.001 | [Folder Compress To Potentially Suspicious Output Via Compress-Archive Cmdlet](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A85a8e5ba-bd03-4bfb-bbfa-a4409a8f8b98+%23+Process+Creation) | Sigma | SigmaHQ |
| T1083 | [Turla Group Lateral Movement](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac601f20d-570a-4cde-a7d6-e17f99cb8e7f) | Sigma | SigmaHQ |
| T1083 | [WannaCry Ransomware Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A41d40bff-377a-43e2-8e1b-2e543069e079) | Sigma | SigmaHQ |
| T1087.001 | [BloodHound Collection Files](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A02773bed-83bf-469f-b7ff-e676e7d78bab) | Sigma | SigmaHQ |
| T1087.001 | [HackTool - Bloodhound/Sharphound Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Af376c8a7-a2d0-4ddc-aa0c-16c17236d962) | Sigma | SigmaHQ |
| T1087.002 | [BloodHound Collection Files](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A02773bed-83bf-469f-b7ff-e676e7d78bab) | Sigma | SigmaHQ |
| T1087.002 | [Suspicious Active Directory Database Snapshot Via ADExplorer](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aef61af62-bc74-4f58-b49b-626448227652) | Sigma | SigmaHQ |
| T1090.001 | [Renamed Cloudflared.EXE Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae0c69ebd-b54f-4aed-8ae3-e3467843f3f0) | Sigma | SigmaHQ |
| T1090.001 | [PUA - Chisel Tunneling Tool Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A8b0e12da-d3c3-49db-bb4f-256703f380e5) | Sigma | SigmaHQ |
| T1090.003 | [Tor Client/Browser Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A62f7c9bf-9135-49b2-8aeb-1e54a6ecc13c) | Sigma | SigmaHQ |
| T1090.003 | [Query Tor Onion Address - DNS Client](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A8384bd26-bde6-4da9-8e5d-4174a7a47ca2) | Sigma | SigmaHQ |
| T1112 | [ShimCache Flush](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab0524451-19af-4efa-a46f-562a977f792e) | Sigma | SigmaHQ |
| T1112 | [ShimCache Flush](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Ab0524451-19af-4efa-a46f-562a977f792e) | Sigma | OpenSearch Security Analytics |
| T1134 | [Suspicious SYSTEM User Process Creation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A2617e7ed-adb7-40ba-b0f3-8f9945fe6c09) | Sigma | SigmaHQ |
| T1134 | [HackTool - NoFilter Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A7b14c76a-c602-4ae6-9717-eff868153fc0) | Sigma | SigmaHQ |
| T1482 | [BloodHound Collection Files](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A02773bed-83bf-469f-b7ff-e676e7d78bab) | Sigma | SigmaHQ |
| T1482 | [HackTool - TruffleSnout Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A69ca006d-b9a9-47f5-80ff-ecd4d25d481a) | Sigma | SigmaHQ |
| T1539 | [SQLite Firefox Profile Data DB Access](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4833155a-4053-4c9c-a997-777fcea0baa7) | Sigma | SigmaHQ |
| T1539 | [SQLite Chromium Profile Data DB Access](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A24c77512-782b-448a-8950-eddb0785fc71) | Sigma | SigmaHQ |
| T1543.003 | [PSExec Lateral Movement](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=hayabusa-native%3A%3A0694c340-3a46-40ac-acfc-c3444ae6572c) | Sigma | Hayabusa (native) |
| T1543.003 | [Suspicious Service Name](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=hayabusa-native%3A%3Acc429813-21db-4019-b520-2f19648e1ef1) | Sigma | Hayabusa (native) |
| T1560.001 | [APT31 Judgement Panda Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A03e2746e-2b31-42f1-ab7a-eb39365b2422) | Sigma | SigmaHQ |
| T1560.001 | [Suspicious Manipulation Of Default Accounts Via Net.EXE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A5b768e71-86f2-4879-b448-81061cbae951) | Sigma | SigmaHQ |
| T1560.003 | [Potential Data Collection in Temporary Directory by Hidden Executable](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-protections-artifacts-behavior%3A%3Aa6994646-d314-4ee0-be1f-1d694dc969e7) | Elastic | Elastic protections-artifacts (behavior) |
| T1588.002 | [Hacktool Execution - Imphash](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A24e3e58a-646b-4b50-adef-02ef935b9fc8) | Sigma | SigmaHQ |
| T1588.002 | [Renamed SysInternals DebugView Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acd764533-2e07-40d6-a718-cfeec7f2da7f) | Sigma | SigmaHQ |

## 9. Plano de emulação e validação

Use num laboratório isolado e autorizado para confirmar que as regras disparam. Os comandos estão nos repositórios oficiais.

| Tática | Técnica | Teste Atomic Red Team | Plataformas |
|---|---|---|---|
| Execution | [T1047](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1047/T1047.md) | WMI Reconnaissance Users | windows |
| Execution | [T1047](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1047/T1047.md) | WMI Reconnaissance Processes | windows |
| Persistence | [T1543.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1543.003/T1543.003.md) | Modify Fax service to run PowerShell | windows |
| Persistence | [T1543.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1543.003/T1543.003.md) | Service Installation CMD | windows |
| Defense Impairment | [T1112](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1112/T1112.md) | Modify Registry of Current User Profile - cmd | windows |
| Defense Impairment | [T1112](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1112/T1112.md) | Modify Registry of Local Machine - cmd | windows |
| Credential Access | [T1539](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1539/T1539.md) | Steal Firefox Cookies (Windows) | windows |
| Credential Access | [T1539](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1539/T1539.md) | Steal Chrome Cookies (Windows) | windows |
| Discovery | [T1012](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1012/T1012.md) | Query Registry | windows |
| Discovery | [T1012](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1012/T1012.md) | Query Registry with Powershell cmdlets | windows |
| Discovery | [T1016](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1016/T1016.md) | System Network Configuration Discovery on Windows | windows |
| Discovery | [T1016](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1016/T1016.md) | List Windows Firewall Rules | windows |
| Discovery | [T1016.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1016.001/T1016.001.md) | Check internet connection using ping Windows | windows |
| Discovery | [T1016.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1016.001/T1016.001.md) | Check internet connection using ping freebsd, linux or macos | linux, macos |
| Discovery | [T1018](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1018/T1018.md) | Remote System Discovery - net | windows |
| Discovery | [T1018](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1018/T1018.md) | Remote System Discovery - net group Domain Computers | windows |
| Discovery | [T1046](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1046/T1046.md) | Port Scan | linux, macos |
| Discovery | [T1046](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1046/T1046.md) | Port Scan Nmap | linux, macos |
| Discovery | [T1049](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1049/T1049.md) | System Network Connections Discovery | windows |
| Discovery | [T1049](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1049/T1049.md) | System Network Connections Discovery with PowerShell | windows |
| Discovery | [T1083](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1083/T1083.md) | File and Directory Discovery (cmd.exe) | windows |
| Discovery | [T1083](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1083/T1083.md) | File and Directory Discovery (PowerShell) | windows |
| Discovery | [T1087.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1087.001/T1087.001.md) | Enumerate all accounts (Local) | linux |
| Discovery | [T1087.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1087.001/T1087.001.md) | View sudoers access | linux, macos |
| Discovery | [T1087.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1087.002/T1087.002.md) | Enumerate all accounts (Domain) | windows |
| Discovery | [T1087.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1087.002/T1087.002.md) | Enumerate all accounts via PowerShell (Domain) | windows |
| Discovery | [T1482](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1482/T1482.md) | Windows - Discover domain trusts with dsquery | windows |
| Discovery | [T1482](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1482/T1482.md) | Windows - Discover domain trusts with nltest | windows |
| Collection | [T1074.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1074.001/T1074.001.md) | Stage data from Discovery.bat | windows |
| Collection | [T1074.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1074.001/T1074.001.md) | Stage data from Discovery.sh | linux, macos |
| Collection | [T1560.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1560.001/T1560.001.md) | Compress Data for Exfiltration With Rar | windows |
| Collection | [T1560.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1560.001/T1560.001.md) | Compress Data and lock with password for Exfiltration with winrar | windows |
| Command and Control | [T1090.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1090.001/T1090.001.md) | Connection Proxy | linux, macos |
| Command and Control | [T1090.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1090.001/T1090.001.md) | Connection Proxy for macOS UI | macos |
| Command and Control | [T1090.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1090.003/T1090.003.md) | Psiphon | windows |
| Command and Control | [T1090.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1090.003/T1090.003.md) | Tor Proxy Usage - Windows | windows |

**Logs reais de ataque (EVTX) para testar sem executar nada:**

- T1016 — [ID4688-Audit policy enumerated](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1016-System%20Network%20Configuration%20Discovery/ID4688-Audit%20policy%20enumerated.evtx) _(explícito)_
- T1016 — [ID4688-Firewall configuration enumerated (command)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1016-System%20Network%20Configuration%20Discovery/ID4688-Firewall%20configuration%20enumerated%20%28command%29.evtx) _(explícito)_
- T1018 — [ID5145-DNS hosts files access via network share](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1018-Remote%20System%20Discovery/ID5145-DNS%20hosts%20files%20access%20via%20network%20share.evtx) _(explícito)_
- T1046 — [ID131-RDP brutforce (no user info)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1046-Network%20Service%20Scanning/ID131-RDP%20brutforce%20%28no%20user%20info%29.evtx) _(explícito)_
- T1046 — [ID4624-Anonymous login with domain specified (DonPapi)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1046-Network%20Service%20Scanning/ID4624-Anonymous%20login%20with%20domain%20specified%20%28DonPapi%29.evtx) _(explícito)_
- T1047 — [ID1-WMI spwaning PowerShell process - WMImplant](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1047-Windows%20Management%20Instrumentation/ID1-WMI%20spwaning%20PowerShell%20process%20-%20WMImplant.evtx) _(explícito)_
- T1047 — [ID1-WMIexec process execution](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1047-Windows%20Management%20Instrumentation/ID1-WMIexec%20process%20execution.evtx) _(explícito)_
- T1087.002 — [discovery_bloodhound](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Discovery/discovery_bloodhound.evtx) _(inferido)_
- T1112 — [ID11,13-SMBexec service registration](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0005-Defense%20Evasion/T1112-Modify%20registry/ID11%2C13-SMBexec%20service%20registration.evtx) _(explícito)_
- T1112 — [ID4624,4670,4688,4674-Registry permission change via WMI (DAMP)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0005-Defense%20Evasion/T1112-Modify%20registry/ID4624%2C4670%2C4688%2C4674-Registry%20permission%20change%20via%20WMI%20%28DAMP%29.evtx) _(explícito)_
- T1134 — [ID4648-4624-RunAsCS login](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0004-Privilege%20Escalation/T1134-Access%20Token%20Manipulation/ID4648-4624-RunAsCS%20login.evtx) _(explícito)_
- T1134 — [ID4688,4624-RottenPotatoNG](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0004-Privilege%20Escalation/T1134-Access%20Token%20Manipulation/ID4688%2C4624-RottenPotatoNG.evtx) _(explícito)_
- T1482 — [ID800,4103,4104-Active Directory Forest PowerShell class](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1482-Domain%20Trust%20Discovery/ID800%2C4103%2C4104-Active%20Directory%20Forest%20PowerShell%20class.evtx) _(explícito)_
- T1543.003 — [ID13-New service for Mimikatz](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0003-Persistence/T1543.003-Create%20or%20Modify%20System%20Process-Windows%20Service/ID13-New%20service%20for%20Mimikatz.evtx) _(explícito)_
- T1543.003 — [ID4688-4697 RDP hijack via service creation](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0003-Persistence/T1543.003-Create%20or%20Modify%20System%20Process-Windows%20Service/ID4688-4697%20RDP%20hijack%20via%20service%20creation.evtx) _(explícito)_

## 10. Hipóteses de hunting

Se Lotus Blossom estiver no seu ambiente, estas são as perguntas a fazer aos seus dados (fontes de log segundo as estratégias de detecção do MITRE ATT&CK).

1. **T1134 Access Token Manipulation** — Detection of suspicious token manipulation chains: use of token-related APIs (e.g., LogonUser, DuplicateTokenEx) or commands (runas) → spawning of a new process under a different security context (e.g., SYSTEM) → mismatched parent-child process lineage or… Dados: `WinEventLog:Security` (EventCode=4672, 4634), `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=10).
2. **T1560.003 Archive via Custom Method** — Detects suspicious custom compression/encryption routines through anomalous script or binary execution that produces high-entropy files without standard archiving utilities. Correlates script execution, memory API usage (bitwise ops, CryptoAPI calls), and… Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Sysmon` (EventCode=10).
3. **T1539 Steal Web Session Cookie** — Detects suspicious access to browser session cookie storage (e.g., Chrome’s `Cookies` SQLite DB) or memory reads of browser processes. Anomalous injection or memory dump utilities targeting browser processes such as `chrome.exe`, `firefox.exe`, or… Dados: `WinEventLog:Sysmon` (EventCode=10), `WinEventLog:Sysmon` (EventCode=2), `WinEventLog:Security` (EventCode=4688).
4. **T1090.001 Internal Proxy** — Anomalous process (e.g., `rundll32`, `svchost`, `cmd`) initiates connections to internal peer hosts not seen in typical communication baselines, used to proxy or forward traffic internally, often using SMB, RPC, or high ports. Dados: `WinEventLog:Sysmon` (EventCode=3, 22), `WinEventLog:Sysmon` (EventCode=1), `Windows Firewall Log` (SMB over high port).
5. **T1482 Domain Trust Discovery** — Adversary uses nltest, PowerShell, or Win32/.NET API to enumerate domain trust relationships (via DSEnumerateDomainTrusts, GetAllTrustRelationships, or LDAP queries), followed by discovery or authentication staging. Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=7), `WinEventLog:Sysmon` (EventCode=10).
6. **T1016.001 Internet Connection Discovery** — Execution of utilities (e.g., ping, tracert, Test-NetConnection) or scripted methods to test Internet connectivity by interacting with external IPs/domains. Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:PowerShell` (EventCode=4103, 4104, 4105, 4106), `WinEventLog:Security` (EventCode=5156, 5157).
7. **T1090.003 Multi-hop Proxy** — Suspicious processes (e.g., Tor clients, relays, unknown binaries) launch with sustained encrypted outbound traffic to known anonymity infrastructure (e.g., Tor, I2P), and may relay to additional internal systems via reverse proxying, ICMP tunneling, or… Dados: `WinEventLog:Sysmon` (EventCode=3, 22), `WinEventLog:Sysmon` (EventCode=1), `dns:query` (Outbound resolution to hidden service domains (e.g., `.onion`)).
8. **T1087.001 Local Account** — Adversary enumeration of local user accounts using Net.exe, WMI, or PowerShell. Dados: `WinEventLog:Sysmon` (EventCode=1).
9. **T1012 Query Registry** — Registry read access associated with suspicious or non-interactive processes querying system config, installed software, or security settings. Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=13, 14), `WinEventLog:PowerShell` (EventCode=4103, 4104, 4105, 4106).
10. **T1543.003 Windows Service** — Detects creation or modification of Windows Services through command-line tools (e.g., `sc.exe`, `powershell.exe`), Registry key changes under `HKLM\System\CurrentControlSet\Services`, and service execution under SYSTEM with unsigned or anomalous binary… Dados: `WinEventLog:Security` (EventCode=4697), `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=13, 14).
11. **T1074.001 Local Data Staging** — Detects file reads across locations followed by writes to temp or staging directories, often compressed or encrypted, indicating local staging behavior. Dados: `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Security` (EventCode=4663, 4670, 4656).
12. **T1112 Modify Registry** — Behavior chain involving abnormal registry modifications via CLI, PowerShell, WMI, or direct API calls, especially targeting persistence, privilege escalation, or defense evasion keys, potentially followed by service restart or process execution. Such as… Dados: `WinEventLog:Sysmon` (EventCode=13, 14), `WinEventLog:Sysmon` (EventCode=1).

## 11. OSINT — onde pesquisar

Consultas prontas com todos os nomes conhecidos do grupo:

- Relatórios técnicos: [busca web](https://duckduckgo.com/?q=%28%22Lotus+Blossom%22+OR+%22DRAGONFISH%22+OR+%22Spring+Dragon%22+OR+%22RADIUM%22+OR+%22Raspberry+Typhoon%22+OR+%22Bilbug%22%29+threat+report) · [PDFs](https://duckduckgo.com/?q=%28%22Lotus+Blossom%22+OR+%22DRAGONFISH%22+OR+%22Spring+Dragon%22+OR+%22RADIUM%22+OR+%22Raspberry+Typhoon%22+OR+%22Bilbug%22%29+filetype%3Apdf)
- Regras e IOCs publicados: [GitHub](https://github.com/search?type=code&q=%22Lotus+Blossom%22+OR+%22DRAGONFISH%22+OR+%22Spring+Dragon%22+OR+%22RADIUM%22+OR+%22Raspberry+Typhoon%22+OR+%22Bilbug%22)
- Pulsos de ameaça: [AlienVault OTX](https://otx.alienvault.com/browse/global/pulses?q=Lotus+Blossom)
- Família de malware e atores: [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/actors) (busque por Lotus Blossom, DRAGONFISH, Spring Dragon)
- Cartões de grupo: [ThaiCERT Threat Group Cards](https://apt.etda.or.th/cgi-bin/listgroups.cgi)
- Página oficial: [MITRE ATT&CK G0030](https://attack.mitre.org/groups/G0030/)

**Relatórios na coleção CyberMonitor** (ligados pelo nome do grupo, conferir antes de citar):

- 2015 — [unit42-operation-lotus-blossom](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2015/2015.06.16.operation-lotus-blossom/unit42-operation-lotus-blossom.pdf) _(via “Lotus Blossom”)_
- 2015 — [attack-on-french-diplomat-linked-to-operation-lotus-blossom](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2015/2015.12.18.Attack_on_Frence_Diplomat_Linked_To_Operation_Lotus_Blossom/attack-on-french-diplomat-linked-to-operation-lotus-blossom.pdf) _(via “Lotus Blossom”)_
- 2016 — [emissary-trojan-changelog-did-operation-lotus-blossom-cause-it-to-evolve](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2016/2016.02.03.Emissary_Trojan_Changelog/emissary-trojan-changelog-did-operation-lotus-blossom-cause-it-to-evolve.pdf) _(via “Lotus Blossom”)_
- 2016 — [the-state-of-the-esilelotus-blossom-campaign](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2016/2016.06.26.The_State_of_the_ESILE_Lotus_Blossom_Campaign/the-state-of-the-esilelotus-blossom-campaign.pdf) _(via “Lotus Blossom”)_
- 2016 — [Emissary Trojan Changelog_ Did Operation Lotus Blossom Cause It to Evolve_ - Palo Alto Networks Blog](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2016/2016.10.31.Emissary_Trojan_Changelog/Emissary%20Trojan%20Changelog_%20Did%20Operation%20Lotus%20Blossom%20Cause%20It%20to%20Evolve_%20-%20Palo%20Alto%20Networks%20Blog.pdf) _(via “Lotus Blossom”)_
- 2016 — [emissary-trojan-changelog-did-operation-lotus-blossom-cause-it-to-evolve](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2016/2016.10.31.Emissary_Trojan_Changelog/emissary-trojan-changelog-did-operation-lotus-blossom-cause-it-to-evolve.pdf) _(via “Lotus Blossom”)_
- 2018 — [Accenture-Security-Dragonfish-Threat-Analysis](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2018/2018.01.27.DRAGONFISH/Accenture-Security-Dragonfish-Threat-Analysis.pdf) _(via “DRAGONFISH”)_
- 2018 — [Lotus Blossom Continues ASEAN Targeting](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2018/2018.02.13.Lotus-Blossom-Continues/Lotus%20Blossom%20Continues%20ASEAN%20Targeting.pdf) _(via “Lotus Blossom”)_
- 2018 — [thrip-hits-satellite-telecoms-defense-targets](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2018/2018.06.20.thrip-hits-satellite-telecoms-defense-targets/thrip-hits-satellite-telecoms-defense-targets.pdf) _(via “Thrip”)_
- 2019 — [Thrip_ Ambitious Attacks Against High Level Targets Continue](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2019/2019.09.09.Thrip/Thrip_%20Ambitious%20Attacks%20Against%20High%20Level%20Targets%20Continue.pdf) _(via “Thrip”)_

**Relatórios públicos ligados pelo APT4ALL** (2 no total, mais recentes primeiro):

- 2016 — [Attack On French Diplomat Linked To Operation Lotus Blossom](https://app.box.com/s/cbxo6pdyf8xua2eg5dn44ni47wbs0le0) _(Palo Alto)_
- 2016 — [Emissary Trojan Changelog: Did Operation Lotus Blossom Cause It To Evolve](https://app.box.com/s/oyqcfzoa1hfq5evuymj5bqfitkqlfp4v) _(Palo Alto)_

## 12. Bibliografia (8 fontes citadas pelo ATT&CK)

- [Accenture Dragonfish Jan 2018](https://web.archive.org/web/20190508165226/https://www.accenture.com/t20180127T003755Z_w_/us-en/_acnmedia/PDF-46/Accenture-Security-Dragonfish-Threat-Analysis.pdf) — Accenture Security. (2018, January 27). DRAGONFISH DELIVERS NEW FORM OF ELISE MALWARE TARGETING ASEAN DEFENCE MINISTERS’ MEETING AND ASSOCIATES. Retrieved November 17, 2024.
- [Cisco LotusBlossom 2025](https://blog.talosintelligence.com/lotus-blossom-espionage-group/) — Joey Chen, Cisco Talos. (2025, February 27). Lotus Blossom espionage group targets multiple industries with different versions of Sagerunex and hacking tools. Retrieved March 15, 2025.
- [Emissary Trojan Feb 2016](http://researchcenter.paloaltonetworks.com/2016/02/emissary-trojan-changelog-did-operation-lotus-blossom-cause-it-to-evolve/) — Falcone, R. and Miller-Osborn, J. (2016, February 3). Emissary Trojan Changelog: Did Operation Lotus Blossom Cause It to Evolve?. Retrieved February 15, 2016.
- [Lotus Blossom Dec 2015](http://researchcenter.paloaltonetworks.com/2015/12/attack-on-french-diplomat-linked-to-operation-lotus-blossom/) — Falcone, R. and Miller-Osborn, J.. (2015, December 18). Attack on French Diplomat Linked to Operation Lotus Blossom. Retrieved February 15, 2016.
- [Lotus Blossom Jun 2015](https://www.paloaltonetworks.com/resources/research/unit42-operation-lotus-blossom.html) — Falcone, R., et al.. (2015, June 16). Operation Lotus Blossom. Retrieved February 15, 2016.
- [Microsoft Threat Actor Naming July 2023](https://learn.microsoft.com/en-us/microsoft-365/security/intelligence/microsoft-threat-actor-naming?view=o365-worldwide) — Microsoft . (2023, July 12). How Microsoft names threat actors. Retrieved November 17, 2023.
- [Spring Dragon Jun 2015](https://securelist.com/the-spring-dragon-apt/70726/) — Baumgartner, K.. (2015, June 17). The Spring Dragon APT. Retrieved February 15, 2016.
- [Symantec Bilbug 2022](https://www.security.com/threat-intelligence/espionage-asia-governments-cert-authority) — Symntec Threat Hunter Team. (2022, November 12). Billbug: State-sponsored Actor Targets Cert Authority, Government Agencies in Multiple Asian Countries. Retrieved March 15, 2025.

## 13. Limites e confiança

- O ATT&CK registra o que foi **relatado publicamente**, não tudo o que o grupo faz. Ausência de uma técnica não prova que o grupo não a usa.
- **Sobreposição de TTP não é atribuição.** Muitas técnicas são compartilhadas entre grupos e com red teams. Use a assinatura comportamental como hipótese, junto com infraestrutura, malware e contexto.
- Cobertura de detecção refere-se ao catálogo público Detection Rules, não ao seu ambiente: confira se a telemetria necessária chega ao seu SIEM.
- Ligações marcadas como _inferidas_ (EVTX por palavra-chave, relatórios por nome) devem ser verificadas.

---
Fontes: MITRE ATT&CK® (uso livre com atribuição, © The MITRE Corporation), APT4ALL (MISP Galaxy CC0/BSD-2, APT Groups & Operations CC BY 4.0, EternalLiberty, APTnotes, Ransomware Tool Matrix CC BY 4.0), Atomic Red Team (Red Canary, MIT), EVTX-to-MITRE-Attack, EVTX-ATTACK-SAMPLES, APT & CyberCriminal Campaign Collections. Gerado por [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules).
