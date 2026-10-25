# Mustard Tempest (G1020) — Dossiê de inteligência

> **TLP:CLEAR** · gerado em 2026-10-25 a partir de fontes abertas · MITRE ATT&CK v20.0 · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1020) · [ATT&CK](https://attack.mitre.org/groups/G1020/)

**Também conhecido como:** DEV-0206, TA569, GOLD PRELUDE, UNC1543  
**Registro no ATT&CK:** criado em 2023-12-06, atualizado em 2026-07-31 · referências de 2022 a 2024

## 1. Sumário executivo

- **12 técnicas** atribuídas publicamente, concentradas em **Resource Development, Initial Access, Stealth**.
- **Arsenal:** 2 malware e 0 ferramentas (ex.: Cobalt Strike, SocGholish).
- **Campanhas atribuídas:** 0.
- **Cobertura de detecção pública:** 67% das técnicas têm ao menos uma regra no catálogo; **4 técnicas sem nenhuma regra pública**.
- **Assinatura comportamental** (técnicas raras entre os 178 grupos, as mais úteis para atribuição): T1583.008 Malvertising, T1608.006 SEO Poisoning, T1584.001 Domains, T1608.004 Drive-by Target, T1583.004 Server.

## 2. Quem é

> Mustard Tempest is an initial access broker that has operated the SocGholish distribution network since at least 2017. Mustard Tempest has partnered with Indrik Spider to provide access for the download of additional malware including LockBit, WastedLocker, and remote access tools.

_Texto original do MITRE ATT&CK, em inglês._

## 3. Perfil TTP por tática (kill chain)

Cada linha: técnica, como o grupo a usou segundo relatos públicos, e o que existe para detectar e testar.

### Resource Development (TA0042) — 6

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1583.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1583.004) Server | Mustard Tempest has acquired servers to host second-stage payloads that remain active for a period of either days, weeks, or months. | **0** | — | — |
| [T1583.008](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1583.008) Malvertising | Mustard Tempest has posted false advertisements including for software packages and browser updates in order to distribute malware. | **0** | — | — |
| [T1584.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1584.001) Domains | Mustard Tempest operates a global network of compromised websites that redirect into a traffic distribution system (TDS) to select victims for a fake browser update page. | 3 | — | — |
| [T1608.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1608.001) Upload Malware | Mustard Tempest has hosted payloads on acquired second-stage servers for periods of either days, weeks, or months. | 3 | — | — |
| [T1608.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1608.004) Drive-by Target | Mustard Tempest has injected malicious JavaScript into compromised websites to infect victims via drive-by download. | **0** | — | — |
| [T1608.006](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1608.006) SEO Poisoning | Mustard Tempest has poisoned search engine results to return fake software updates in order to distribute malware. | **0** | — | — |

### Initial Access (TA0001) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1189](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1189) Drive-by Compromise | Mustard Tempest has used drive-by downloads for initial infection, often using fake browser updates as a lure. | 57 | — | — |
| [T1566.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1566.002) Spearphishing Link | Mustard Tempest has sent victims emails containing links to compromised websites. | 138 | 1 | — |

### Execution (TA0002) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1204.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1204.001) Malicious Link | Mustard Tempest has lured users into downloading malware through malicious links in fake advertisements and spearphishing emails. | 52 | — | — |

### Stealth (TA0005) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1036.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1036.005) Match Legitimate Resource Name or Location | Mustard Tempest has used the filename `AutoUpdater.js` to mimic legitimate update files and has also used the Cyrillic homoglyph characters С `(0xd0a1)` and а `(0xd0b0)`, to produce the filename `Сhrome.Updаte.zip`. | 116 | 4 | — |

### Discovery (TA0007) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1082](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1082) System Information Discovery | Mustard Tempest has used implants to perform system reconnaissance on targeted systems. | 264 | 41 | — |

### Command and Control (TA0011) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1105](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1105) Ingress Tool Transfer | Mustard Tempest has deployed secondary payloads and third stage implants to compromised hosts. | 644 | 39 | — |

## 4. Assinatura comportamental

Técnicas que este grupo usa e que poucos dos 178 grupos do ATT&CK usam. Pesam mais numa atribuição por TTP: ver várias delas juntas é mais informativo do que ver técnicas comuns como PowerShell.

| Técnica | Outros grupos que usam | Peso (raridade) |
|---|---:|---:|
| T1583.008 Malvertising | 0 | 4.49 |
| T1608.006 SEO Poisoning | 1 | 4.09 |
| T1584.001 Domains | 5 | 3.24 |
| T1608.004 Drive-by Target | 7 | 2.99 |
| T1583.004 Server | 8 | 2.88 |
| T1608.001 Upload Malware | 29 | 1.75 |
| T1189 Drive-by Compromise | 30 | 1.72 |
| T1566.002 Spearphishing Link | 47 | 1.30 |
| T1204.001 Malicious Link | 49 | 1.26 |
| T1082 System Information Discovery | 58 | 1.09 |

## 5. Arsenal

| Software | Tipo | Técnicas no ATT&CK | Uso relatado (EN) |
|---|---|---:|---|
| [Cobalt Strike](https://attack.mitre.org/software/S0154/) | malware | 73 |  |
| [SocGholish](https://attack.mitre.org/software/S1124/) | malware | 19 |  |

## 6. Campanhas

Nenhuma campanha atribuída no ATT&CK.

## 7. Cobertura defensiva

**8 de 12 técnicas (67%)** têm ao menos uma regra pública no catálogo Detection Rules.

### Técnicas sem regra pública (prioridade para engenharia de detecção)

- **T1583.008 Malvertising** — Resource Development. Fonte de log sugerida pelo MITRE: `Internet Scan` None
- **T1608.006 SEO Poisoning** — Resource Development. Fonte de log sugerida pelo MITRE: `Internet Scan` None
- **T1608.004 Drive-by Target** — Resource Development. Fonte de log sugerida pelo MITRE: `Internet Scan` None
- **T1583.004 Server** — Resource Development. Fonte de log sugerida pelo MITRE: `Internet Scan` None

### Regras recomendadas por técnica

Melhor regra disponível por técnica (formato portável e maduro primeiro).

| Técnica | Regra | Formato | Fonte |
|---|---|---|---|
| T1036.005 | [Exploit for CVE-2015-1641](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A7993792c-5ce2-4475-a3db-a3a5539827ef) | Sigma | SigmaHQ |
| T1036.005 | [Exploit for CVE-2015-1641](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A7993792c-5ce2-4475-a3db-a3a5539827ef) | Sigma | OpenSearch Security Analytics |
| T1082 | [Potential GobRAT File Discovery Via Grep](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae34cfa0c-0a50-4210-9cb3-5632d08eb041) | Sigma | SigmaHQ |
| T1082 | [System Information Discovery](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A42df45e7-e6e9-43b5-8f26-bec5b39cc239) | Sigma | SigmaHQ |
| T1105 | [Greenbug Espionage Group Indicators](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A3711eee4-a808-4849-8a14-faf733da3612) | Sigma | SigmaHQ |
| T1105 | [Pandemic Registry Key](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A47e0852a-cf81-4494-a8e6-31864f8c86ed) | Sigma | SigmaHQ |
| T1189 | [Flash Player Update from Suspicious Location](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4922a5dd-6743-4fc2-8e81-144374280997) | Sigma | SigmaHQ |
| T1189 | [Cross Site Scripting Strings](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A65354b83-a2ea-4ea6-8414-3ab38be0d409) | Sigma | SigmaHQ |
| T1204.001 | [Google Workspace Object Copied from External Drive with App Consent](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Af33e68a4-bd19-11ed-b02f-f661ea17fbcc) | Elastic | Elastic detection-rules |
| T1204.001 | [Suspicious ClickFix/FileFix Execution Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad487ed4a-fd24-436d-a0b2-f4e95f7b2635) | Sigma | SigmaHQ |
| T1566.002 | [Potential Malicious Usage of CloudTrail System Manager](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A38e7f511-3f74-41d4-836e-f57dfa18eead) | Sigma | SigmaHQ |
| T1566.002 | [Google Workspace Device Registration After OAuth from Suspicious ASN](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A012bfca7-45cb-4507-a3ba-3777167f8b81) | Elastic | Elastic detection-rules |
| T1584.001 | [AWS Route 53 Domain Transferred to Another Account](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A2045567e-b0af-444a-8c0b-0b6e2dae9e13) | Elastic | Elastic detection-rules |
| T1584.001 | [AWS Route 53 Domain Transfer Lock Disabled](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A12051077-0124-4394-9522-8f4f4db1d674) | Elastic | Elastic detection-rules |
| T1608.001 | [M365 OneDrive Malware File Upload](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Abba1b212-b85c-41c6-9b28-be0e5cdfc9b1) | Elastic | Elastic detection-rules |
| T1608.001 | [M365 SharePoint Malware File Detected](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A0e52157a-8e96-4a95-a6e3-5faae5081a74) | Elastic | Elastic detection-rules |

## 8. Plano de emulação e validação

Use num laboratório isolado e autorizado para confirmar que as regras disparam. Os comandos estão nos repositórios oficiais.

| Tática | Técnica | Teste Atomic Red Team | Plataformas |
|---|---|---|---|
| Initial Access | [T1566.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1566.002/T1566.002.md) | Paste and run technique | windows |
| Stealth | [T1036.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.005/T1036.005.md) | Execute a process from a directory masquerading as the current parent directory | linux, macos |
| Stealth | [T1036.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.005/T1036.005.md) | Masquerade as a built-in system executable | windows |
| Discovery | [T1082](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1082/T1082.md) | System Information Discovery | windows |
| Discovery | [T1082](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1082/T1082.md) | System Information Discovery | macos |
| Command and Control | [T1105](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1105/T1105.md) | rsync remote file copy (push) | linux, macos |
| Command and Control | [T1105](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1105/T1105.md) | rsync remote file copy (pull) | linux, macos |

## 9. Hipóteses de hunting

Se Mustard Tempest estiver no seu ambiente, estas são as perguntas a fazer aos seus dados (fontes de log segundo as estratégias de detecção do MITRE ATT&CK).

1. **T1583.008 Malvertising** — If infrastructure or patterns in the malicious web content related to malvertising have been previously identified, internet scanning may uncover when an adversary has staged malicious web content. Much of this activity will take place outside the visibility… Dados: `Internet Scan` (None).
2. **T1608.006 SEO Poisoning** — If infrastructure or patterns in the malicious web content related to SEO poisoning or Drive-by Target have been previously identified, internet scanning may uncover when an adversary has staged web content supporting a strategic web compromise. Much of this… Dados: `Internet Scan` (None).
3. **T1584.001 Domains** — Monitor for logged domain name system (DNS) registry data that may hijack domains and/or subdomains that can be used during targeting. In some cases, abnormal subdomain IP addresses (such as those originating in a different country from the root domain) may… Dados: `Domain Name` (None), `Domain Name` (None), `Domain Name` (None).
4. **T1608.004 Drive-by Target** — If infrastructure or patterns in the malicious web content utilized to deliver a Drive-by Compromise have been previously identified, internet scanning may uncover when an adversary has staged web content for use in a strategic web compromise. Much of this… Dados: `Internet Scan` (None).
5. **T1583.004 Server** — Much of this activity will take place outside the visibility of the target organization, making detection of this behavior difficult. Detection efforts may be focused on related stages of the adversary lifecycle, such as during Command and Control. Once… Dados: `Internet Scan` (None), `Internet Scan` (None).
6. **T1608.001 Upload Malware** — If infrastructure or patterns in malware have been previously identified, internet scanning may uncover when an adversary has staged malware to make it accessible for targeting. Much of this activity will take place outside the visibility of the target… Dados: `Internet Scan` (None).
7. **T1189 Drive-by Compromise** — Correlated evidence of anomalous browser/network behavior (suspicious external resource fetches and script injection patterns) followed by atypical child processes, ephemeral execution contexts, memory modification or process injection, and unexpected file… Dados: `WinEventLog:Security` (EventCode=4624, 4648), `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=3, 22).
8. **T1566.002 Spearphishing Link** — Correlation of inbound emails with embedded links followed by user-driven browser navigation to suspicious or obfuscated domains. Detection chain includes malicious URL in email → user click recorded in Office logs → browser process spawning unusual child… Dados: `m365:unified` (Send/Receive: Inbound emails containing embedded or shortened URLs), `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=3, 22).
9. **T1204.001 Malicious Link** — Behavioral chain: (1) a user-facing app (browser/Office/email client) launches a URL or handles a link, then (2) the same process lineage makes an outbound connection to an untrusted domain/IP, (3) a file is downloaded or unpacked to a user-writable location… Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=3, 22), `WinEventLog:Sysmon` (EventCode=11).
10. **T1082 System Information Discovery** — Detection of processes executing system environment inspection operations followed by access to OS configuration APIs or registry locations that expose OS version, architecture, patch level, or hardware characteristics. Defenders observe process execution… Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:PowerShell` (EventCode=4103, 4104, 4105, 4106), `WinEventLog:Sysmon` (EventCode=1).
11. **T1036.005 Match Legitimate Resource Name or Location** — Detects processes or binaries executed from trusted directories (e.g., System32) or using trusted names (e.g., svchost.exe) where the metadata, hash, or parent process does not align with legitimate activity patterns. Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=11).
12. **T1105 Ingress Tool Transfer** — Unusual or uncommon processes initiate network connections to external destinations followed by file creation (tools downloaded). Dados: `WinEventLog:Sysmon` (EventCode=3, 22), `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Sysmon` (EventCode=1).

## 10. OSINT — onde pesquisar

Consultas prontas com todos os nomes conhecidos do grupo:

- Relatórios técnicos: [busca web](https://duckduckgo.com/?q=%28%22Mustard+Tempest%22+OR+%22DEV-0206%22+OR+%22TA569%22+OR+%22GOLD+PRELUDE%22+OR+%22UNC1543%22%29+threat+report) · [PDFs](https://duckduckgo.com/?q=%28%22Mustard+Tempest%22+OR+%22DEV-0206%22+OR+%22TA569%22+OR+%22GOLD+PRELUDE%22+OR+%22UNC1543%22%29+filetype%3Apdf)
- Regras e IOCs publicados: [GitHub](https://github.com/search?type=code&q=%22Mustard+Tempest%22+OR+%22DEV-0206%22+OR+%22TA569%22+OR+%22GOLD+PRELUDE%22+OR+%22UNC1543%22)
- Pulsos de ameaça: [AlienVault OTX](https://otx.alienvault.com/browse/global/pulses?q=Mustard+Tempest)
- Família de malware e atores: [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/actors) (busque por Mustard Tempest, DEV-0206, TA569)
- Cartões de grupo: [ThaiCERT Threat Group Cards](https://apt.etda.or.th/cgi-bin/listgroups.cgi)
- Página oficial: [MITRE ATT&CK G1020](https://attack.mitre.org/groups/G1020/)

## 11. Bibliografia (6 fontes citadas pelo ATT&CK)

- [Microsoft Ransomware as a Service](https://www.microsoft.com/en-us/security/blog/2022/05/09/ransomware-as-a-service-understanding-the-cybercrime-gig-economy-and-how-to-protect-yourself/) — Microsoft. (2022, May 9). Ransomware as a service: Understanding the cybercrime gig economy and how to protect yourself. Retrieved March 10, 2023.
- [Microsoft Threat Actor Naming July 2023](https://learn.microsoft.com/en-us/microsoft-365/security/intelligence/microsoft-threat-actor-naming?view=o365-worldwide) — Microsoft . (2023, July 12). How Microsoft names threat actors. Retrieved November 17, 2023.
- [Red Canary SocGholish March 2024](https://redcanary.com/threat-detection-report/threats/socgholish/) — Red Canary. (2024, March). Red Canary 2024 Threat Detection Report: SocGholish. Retrieved March 22, 2024.
- [Secureworks Gold Prelude Profile](https://www.secureworks.com/research/threat-profiles/gold-prelude) — Secureworks. (n.d.). GOLD PRELUDE . Retrieved March 22, 2024.
- [SentinelOne SocGholish Infrastructure November 2022](https://www.sentinelone.com/labs/socgholish-diversifies-and-expands-its-malware-staging-infrastructure-to-counter-defenders/) — Milenkoski, A. (2022, November 7). SocGholish Diversifies and Expands Its Malware Staging Infrastructure to Counter Defenders. Retrieved March 22, 2024.
- [SocGholish-update](https://www.proofpoint.com/us/blog/threat-insight/part-1-socgholish-very-real-threat-very-fake-update) — Andrew Northern. (2022, November 22). SocGholish, a very real threat from a very fake update. Retrieved February 13, 2024.

## 12. Limites e confiança

- O ATT&CK registra o que foi **relatado publicamente**, não tudo o que o grupo faz. Ausência de uma técnica não prova que o grupo não a usa.
- **Sobreposição de TTP não é atribuição.** Muitas técnicas são compartilhadas entre grupos e com red teams. Use a assinatura comportamental como hipótese, junto com infraestrutura, malware e contexto.
- Cobertura de detecção refere-se ao catálogo público Detection Rules, não ao seu ambiente: confira se a telemetria necessária chega ao seu SIEM.
- Ligações marcadas como _inferidas_ (EVTX por palavra-chave, relatórios por nome) devem ser verificadas.

---
Fontes: MITRE ATT&CK® (uso livre com atribuição, © The MITRE Corporation), Atomic Red Team (Red Canary, MIT), EVTX-to-MITRE-Attack, EVTX-ATTACK-SAMPLES, APT & CyberCriminal Campaign Collections. Gerado por [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules).
