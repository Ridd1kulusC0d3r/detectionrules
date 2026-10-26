# Cleaver (G0003) — Dossiê de inteligência

> **TLP:CLEAR** · gerado em 2026-10-26 a partir de fontes abertas · MITRE ATT&CK v20.0 · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0003) · [ATT&CK](https://attack.mitre.org/groups/G0003/)

**Também conhecido como:** Threat Group 2889, TG-2889  
**Origem atribuída:** Irã · **Motivação:** espionagem · **Setores-alvo:** Educação e pesquisa, Energia, Governo, Defesa e militar, Setor privado (genérico), Tecnologia  
**Registro no ATT&CK:** criado em 2017-05-31, atualizado em 2026-07-31 · referências de 2014 a 2015

## 1. Sumário executivo

- **5 técnicas** atribuídas publicamente, concentradas em **Resource Development, Credential Access, Collection**.
- **Arsenal:** 2 malware e 2 ferramentas (ex.: Mimikatz, TinyZBot, PsExec, Net Crawler).
- **Campanhas atribuídas:** 0.
- **Cobertura de detecção pública:** 100% das técnicas têm ao menos uma regra no catálogo; **0 técnicas sem nenhuma regra pública**.
- **Origem e alvos (APT4ALL):** atribuído a **Irã**, motivação espionagem; setores Educação e pesquisa, Energia, Governo, Defesa e militar, Setor privado (genérico); 15 países vítimas citados.
- **Onde a cobertura está:** Windows (4 técnicas com regra), Firewall & perímetro (3 técnicas com regra), Outros / genérico (3 técnicas com regra), EDR / XDR (2 técnicas com regra).
- **Assinatura comportamental** (técnicas raras entre os 178 grupos, as mais úteis para atribuição): T1557.002 ARP Cache Poisoning, T1585.001 Social Media Accounts, T1587.001 Malware, T1003.001 LSASS Memory, T1588.002 Tool.

## 2. Quem é

> Cleaver is a threat group that has been attributed to Iranian actors and is responsible for activity tracked as Operation Cleaver. Strong circumstantial evidence suggests Cleaver is linked to Threat Group 2889 (TG-2889).

_Texto original do MITRE ATT&CK, em inglês._

## 3. Contexto, nomes e alvos

Consolidado pelo [APT4ALL](https://github.com/Ridd1kulusC0d3r/apt4all) a partir de MISP Galaxy, planilha APT Groups & Operations, EternalLiberty e APTnotes. Atribuição é afirmação de quem publicou; confira a fonte.

| Campo | Valor |
|---|---|
| Origem atribuída | Irã |
| Motivação | espionagem |
| Setores-alvo | Educação e pesquisa, Energia, Governo, Defesa e militar, Setor privado (genérico), Tecnologia |
| Vítimas citadas | AT&T, BB&T, Bank of America, Canada, Capital One, China, Citigroup, Fifth Third Bank, France, Germany, HSBC, India, Israel, Kuwait, Mexico, NYSE, PNC, Pakistan, Qatar, Saudi Arabia, South Korea, Turkey, US Bancorp, United Kingdom, United States, Wells Fargo |
| Alvos (planilha) | This threat actor targets governments and private sector entities for espionage and sabotage purposes. It is believed to be responsible for compromising U.S. Navy computers at the Navy Marine Corps Intranet in San Diego, the U.S. energy company Calpine Corporation, Saudi Aramco, Pemex, Qatar Airways, and Korean Air |
| Operações conhecidas | Cleaver |
| Confiança de atribuição (MISP) | 50 |

**Como cada fornecedor chama este grupo** (útil para cruzar relatórios):

| Fornecedor | Nome(s) |
|---|---|
| CrowdStrike | Cutting Kitten |
| FireEye | ITSecTeam |
| MITRE ATT&CK | G0003 |

**Outros nomes no APT4ALL (não listados pelo ATT&CK):** Cutting Kitten, Ghambar, alibaba, Tarh andishan, ITSecTeam, Operation Cleaver, Op Cleaver, Cobalt Gypsy

## 4. Perfil TTP por tática (kill chain)

Cada linha: técnica, como o grupo a usou segundo relatos públicos, e o que existe para detectar e testar.

### Resource Development (TA0042) — 3

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1585.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1585.001) Social Media Accounts | Cleaver has created fake LinkedIn profiles that included profile photos, details, and connections. | 4 | — | — |
| [T1587.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1587.001) Malware | Cleaver has created customized tools and payloads for functions including ARP poisoning, encryption, credential dumping, ASP.NET shells, web backdoors, process enumeration, WMI querying, HTTP and SMB communications, network interface sniffing, and keystroke lo… | 43 | — | — |
| [T1588.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1588.002) Tool | Cleaver has obtained and used open-source tools such as PsExec, Windows Credential Editor, and Mimikatz. | 35 | — | — |

### Credential Access (TA0006) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1003.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1003.001) LSASS Memory | Cleaver has been known to dump credentials using Mimikatz and Windows Credential Editor. | 580 | 14 | 10 |
| [T1557.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1557.002) ARP Cache Poisoning | Cleaver has used custom tools to facilitate ARP cache poisoning. | 5 | — | — |

### Collection (TA0009) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1557.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1557.002) ARP Cache Poisoning | Cleaver has used custom tools to facilitate ARP cache poisoning. | 5 | — | — |

## 5. Assinatura comportamental

Técnicas que este grupo usa e que poucos dos 178 grupos do ATT&CK usam. Pesam mais numa atribuição por TTP: ver várias delas juntas é mais informativo do que ver técnicas comuns como PowerShell.

| Técnica | Outros grupos que usam | Peso (raridade) |
|---|---:|---:|
| T1557.002 ARP Cache Poisoning | 1 | 4.09 |
| T1585.001 Social Media Accounts | 22 | 2.01 |
| T1587.001 Malware | 26 | 1.85 |
| T1003.001 LSASS Memory | 43 | 1.38 |
| T1588.002 Tool | 83 | 0.74 |

## 6. Arsenal

| Software | Tipo | Técnicas no ATT&CK | Uso relatado (EN) |
|---|---|---:|---|
| [Mimikatz](https://attack.mitre.org/software/S0002/) | ferramenta | 17 |  |
| [TinyZBot](https://attack.mitre.org/software/S0004/) | malware | 8 |  |
| [PsExec](https://attack.mitre.org/software/S0029/) | ferramenta | 5 |  |
| [Net Crawler](https://attack.mitre.org/software/S0056/) | malware | 4 |  |

**Outras ferramentas e malware relatados (planilha APT Groups & Operations / MISP):** PupyRAT

## 7. Campanhas

Nenhuma campanha atribuída no ATT&CK.

## 8. Cobertura defensiva

**5 de 5 técnicas (100%)** têm ao menos uma regra pública no catálogo Detection Rules.

### Onde procurar — cobertura por tecnologia

Quantas técnicas deste grupo têm ao menos uma regra em cada tecnologia. Comece a caça pelas tecnologias que você tem e que aparecem aqui.

| Tecnologia | Técnicas do grupo com regra |
|---|---:|
| Windows | 4 |
| Firewall & perímetro | 3 |
| Outros / genérico | 3 |
| EDR / XDR | 2 |
| DNS | 2 |
| IA, LLMs & agentes | 2 |
| Linux | 2 |
| Active Directory | 1 |
| Outros IdP / PAM | 1 |
| IDS / NSM / NDR | 1 |
| Proxy / SWG | 1 |
| VPN & acesso remoto | 1 |

### Regras recomendadas por técnica

Melhor regra disponível por técnica (formato portável e maduro primeiro).

| Técnica | Regra | Formato | Fonte |
|---|---|---|---|
| T1003.001 | [Antivirus - Password Dumper Signature](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A78cc2dd2-7d20-4d32-93ff-057084c38b93) | Sigma | SigmaHQ |
| T1003.001 | [Mimikatz through Windows Remote Management](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Aaa35a627-33fb-4d04-a165-d33b4afca3e8) | Sigma | OpenSearch Security Analytics |
| T1557.002 | [Detect Port Security Violation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=splunk-security-content%3A%3A2de3d5b8-a4fa-45c5-8540-6d071c194d24) | Splunk | Splunk security_content |
| T1557.002 | [Detect ARP Poisoning](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=splunk-security-content%3A%3Ab44bebd6-bd39-467b-9321-73971bcd1aac) | Splunk | Splunk security_content |
| T1585.001 | [CYFIRMA - Brand Intelligence - Social Media Handle Impersonation Detected High Rule](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A22f49d67-7da7-4809-8d07-89e4478aa6b0) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1585.001 | [CYFIRMA - Brand Intelligence - Executive/People Impersonation High Rule](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A159d26a1-591c-4f70-b1ca-2843c881aaec) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1587.001 | [Formbook Process Creation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A032f5fb3-d959-41a5-9263-4173c802dc2b) | Sigma | SigmaHQ |
| T1587.001 | [Uncommon File Created In Office Startup Folder](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aa10a2c40-2c4d-49f8-b557-1a946bc55d9d) | Sigma | SigmaHQ |
| T1588.002 | [Hacktool Execution - Imphash](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A24e3e58a-646b-4b50-adef-02ef935b9fc8) | Sigma | SigmaHQ |
| T1588.002 | [Renamed SysInternals DebugView Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acd764533-2e07-40d6-a718-cfeec7f2da7f) | Sigma | SigmaHQ |

## 9. Plano de emulação e validação

Use num laboratório isolado e autorizado para confirmar que as regras disparam. Os comandos estão nos repositórios oficiais.

| Tática | Técnica | Teste Atomic Red Team | Plataformas |
|---|---|---|---|
| Credential Access | [T1003.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/T1003.001.md) | Dump LSASS.exe Memory using ProcDump | windows |
| Credential Access | [T1003.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/T1003.001.md) | Dump LSASS.exe Memory using comsvcs.dll | windows |

**Logs reais de ataque (EVTX) para testar sem executar nada:**

- T1003.001 — [CA_hashdump_4663_4656_lsass_access](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Credential%20Access/CA_hashdump_4663_4656_lsass_access.evtx) _(inferido)_
- T1003.001 — [LsassSilentProcessExit_process_exit_monitor_3001_lsass](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Credential%20Access/LsassSilentProcessExit_process_exit_monitor_3001_lsass.evtx) _(inferido)_

## 10. Hipóteses de hunting

Se Cleaver estiver no seu ambiente, estas são as perguntas a fazer aos seus dados (fontes de log segundo as estratégias de detecção do MITRE ATT&CK).

1. **T1557.002 ARP Cache Poisoning** — Detects anomalous ARP traffic or cache modifications on Windows endpoints that indicate ARP poisoning. Behavioral focus is on multiple IP addresses resolving to a single MAC, or unsolicited ARP replies from unauthorized devices. Dados: `WinEventLog:Sysmon` (EventCode=3, 22), `WinEventLog:Security` (ARP cache modification attempts observed through event tracing or security baselines).
2. **T1585.001 Social Media Accounts** — Monitor and analyze traffic patterns and packet inspection associated to protocol(s) that do not follow the expected protocol standards and traffic flows (e.g extraneous packets that do not belong to established flows, gratuitous or anomalous traffic… Dados: `Network Traffic` (None), `Persona` (None).
3. **T1587.001 Malware** — Consider analyzing malware for features that may be associated with the adversary and/or their developers, such as compiler used, debugging artifacts, or code similarities. Malware repositories can also be used to identify additional samples associated with… Dados: `Malware Repository` (None), `Malware Repository` (None).
4. **T1003.001 LSASS Memory** — A non-privileged or abnormal process attempts to open a handle with full access (0x1F0FFF) to lsass.exe and subsequently invokes memory dump, file creation, or registry modification indicative of credential scraping. This behavior chain reflects staged… Dados: `WinEventLog:Sysmon` (EventCode=10), `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=11).
5. **T1588.002 Tool** — Monitor for contextual data about a malicious payload, such as compilation times, file hashes, as well as watermarks or other identifiable configuration information. In some cases, malware repositories can also be used to identify features of tool use… Dados: `Malware Repository` (None).

## 11. OSINT — onde pesquisar

Consultas prontas com todos os nomes conhecidos do grupo:

- Relatórios técnicos: [busca web](https://duckduckgo.com/?q=%28%22Cleaver%22+OR+%22Threat+Group+2889%22+OR+%22TG-2889%22%29+threat+report) · [PDFs](https://duckduckgo.com/?q=%28%22Cleaver%22+OR+%22Threat+Group+2889%22+OR+%22TG-2889%22%29+filetype%3Apdf)
- Regras e IOCs publicados: [GitHub](https://github.com/search?type=code&q=%22Cleaver%22+OR+%22Threat+Group+2889%22+OR+%22TG-2889%22)
- Pulsos de ameaça: [AlienVault OTX](https://otx.alienvault.com/browse/global/pulses?q=Cleaver)
- Família de malware e atores: [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/actors) (busque por Cleaver, Threat Group 2889, TG-2889)
- Cartões de grupo: [ThaiCERT Threat Group Cards](https://apt.etda.or.th/cgi-bin/listgroups.cgi)
- Página oficial: [MITRE ATT&CK G0003](https://attack.mitre.org/groups/G0003/)

**Relatórios na coleção CyberMonitor** (ligados pelo nome do grupo, conferir antes de citar):

- 2014 — [Cylance_Operation_Cleaver_Report](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2014/2014.12.02.Operation_Cleaver/Cylance_Operation_Cleaver_Report.pdf) _(via “Cleaver”)_
- 2014 — [blogs.blackberry.com-Operation Cleaver The Notepad Files](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2014/2014.12.05.Operation_Cleaver/blogs.blackberry.com-Operation%20Cleaver%20The%20Notepad%20Files.pdf) _(via “Cleaver”)_

**Relatórios públicos ligados pelo APT4ALL** (1 no total, mais recentes primeiro):

- 2014 — [Operation Cleaver: The Notepad Files](https://app.box.com/s/vsret8sjx5qd6xaxzv0rxdw4pocdmjll) _(Cylance)_

## 12. Bibliografia (2 fontes citadas pelo ATT&CK)

- [Cylance Cleaver](https://web.archive.org/web/20200302085133/https://www.cylance.com/content/dam/cylance/pages/operation-cleaver/Cylance_Operation_Cleaver_Report.pdf) — Cylance. (2014, December). Operation Cleaver. Retrieved September 14, 2017.
- [Dell Threat Group 2889](http://www.secureworks.com/cyber-threat-intelligence/threats/suspected-iran-based-hacker-group-creates-network-of-fake-linkedin-profiles/) — Dell SecureWorks. (2015, October 7). Suspected Iran-Based Hacker Group Creates Network of Fake LinkedIn Profiles. Retrieved January 14, 2016.

## 13. Limites e confiança

- O ATT&CK registra o que foi **relatado publicamente**, não tudo o que o grupo faz. Ausência de uma técnica não prova que o grupo não a usa.
- **Sobreposição de TTP não é atribuição.** Muitas técnicas são compartilhadas entre grupos e com red teams. Use a assinatura comportamental como hipótese, junto com infraestrutura, malware e contexto.
- Cobertura de detecção refere-se ao catálogo público Detection Rules, não ao seu ambiente: confira se a telemetria necessária chega ao seu SIEM.
- Ligações marcadas como _inferidas_ (EVTX por palavra-chave, relatórios por nome) devem ser verificadas.

---
Fontes: MITRE ATT&CK® (uso livre com atribuição, © The MITRE Corporation), APT4ALL (MISP Galaxy CC0/BSD-2, APT Groups & Operations CC BY 4.0, EternalLiberty, APTnotes, Ransomware Tool Matrix CC BY 4.0), Atomic Red Team (Red Canary, MIT), EVTX-to-MITRE-Attack, EVTX-ATTACK-SAMPLES, APT & CyberCriminal Campaign Collections. Gerado por [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules).
