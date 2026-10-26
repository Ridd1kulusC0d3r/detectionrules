# Ferocious Kitten (G0137) — Dossiê de inteligência

> **TLP:CLEAR** · gerado em 2026-10-26 a partir de fontes abertas · MITRE ATT&CK v20.0 · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0137) · [ATT&CK](https://attack.mitre.org/groups/G0137/)

**Também conhecido como:** —  
**Origem atribuída:** Irã · **Motivação:** indefinido · **Setores-alvo:** —  
**Registro no ATT&CK:** criado em 2021-09-28, atualizado em 2026-07-31 · referências de 2021 a 2021

## 1. Sumário executivo

- **6 técnicas** atribuídas publicamente, concentradas em **Stealth, Resource Development, Execution**.
- **Arsenal:** 1 malware e 1 ferramentas (ex.: MarkiRAT, BITSAdmin).
- **Campanhas atribuídas:** 0.
- **Cobertura de detecção pública:** 100% das técnicas têm ao menos uma regra no catálogo; **0 técnicas sem nenhuma regra pública**.
- **Origem e alvos (APT4ALL):** atribuído a **Irã**, motivação indefinido.
- **Onde a cobertura está:** Windows (6 técnicas com regra), EDR / XDR (4 técnicas com regra), Microsoft 365 (4 técnicas com regra), Outros / genérico (4 técnicas com regra).
- **Assinatura comportamental** (técnicas raras entre os 178 grupos, as mais úteis para atribuição): T1036.002 Right-to-Left Override, T1583.001 Domains, T1036.005 Match Legitimate Resource Name or Location, T1566.001 Spearphishing Attachment, T1588.002 Tool.

## 2. Quem é

> Ferocious Kitten is a threat group that has primarily targeted Persian-speaking individuals in Iran since at least 2015.

_Texto original do MITRE ATT&CK, em inglês._

## 3. Contexto, nomes e alvos

Consolidado pelo [APT4ALL](https://github.com/Ridd1kulusC0d3r/apt4all) a partir de MISP Galaxy, planilha APT Groups & Operations, EternalLiberty e APTnotes. Atribuição é afirmação de quem publicou; confira a fonte.

| Campo | Valor |
|---|---|
| Origem atribuída | Irã |
| Motivação | indefinido |
| Setores-alvo | — |
| Vítimas citadas | — |
| Alvos (planilha) | — |
| Operações conhecidas | — |
| Confiança de atribuição (MISP) | High |

**Como cada fornecedor chama este grupo** (útil para cruzar relatórios):

| Fornecedor | Nome(s) |
|---|---|
| MITRE ATT&CK | G0137 |

**Outros nomes no APT4ALL (não listados pelo ATT&CK):** Prince of Persia, APT-C-07, Infy/Foudre

## 4. Perfil TTP por tática (kill chain)

Cada linha: técnica, como o grupo a usou segundo relatos públicos, e o que existe para detectar e testar.

### Resource Development (TA0042) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1583.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1583.001) Domains | Ferocious Kitten has acquired domains imitating legitimate sites. | 7 | — | — |
| [T1588.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1588.002) Tool | Ferocious Kitten has obtained open source tools for its operations, including JsonCPP and Psiphon. | 35 | — | — |

### Initial Access (TA0001) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1566.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1566.001) Spearphishing Attachment | Ferocious Kitten has conducted spearphishing campaigns containing malicious documents to lure victims to open the attachments. | 230 | 2 | — |

### Execution (TA0002) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1204.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1204.002) Malicious File | Ferocious Kitten has attempted to convince victims to enable malicious content within a spearphishing email by including an odd decoy message. | 259 | 13 | — |

### Stealth (TA0005) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1036.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1036.002) Right-to-Left Override | Ferocious Kitten has used right-to-left override to reverse executables’ names to make them appear to have different file extensions, rather than their real ones. | 18 | 2 | — |
| [T1036.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1036.005) Match Legitimate Resource Name or Location | Ferocious Kitten has named malicious files update.exe and loaded them into the compromise host's “Public” folder. | 116 | 4 | — |

## 5. Assinatura comportamental

Técnicas que este grupo usa e que poucos dos 178 grupos do ATT&CK usam. Pesam mais numa atribuição por TTP: ver várias delas juntas é mais informativo do que ver técnicas comuns como PowerShell.

| Técnica | Outros grupos que usam | Peso (raridade) |
|---|---:|---:|
| T1036.002 Right-to-Left Override | 4 | 3.40 |
| T1583.001 Domains | 47 | 1.30 |
| T1036.005 Match Legitimate Resource Name or Location | 65 | 0.98 |
| T1566.001 Spearphishing Attachment | 78 | 0.81 |
| T1588.002 Tool | 83 | 0.74 |
| T1204.002 Malicious File | 86 | 0.71 |

## 6. Arsenal

| Software | Tipo | Técnicas no ATT&CK | Uso relatado (EN) |
|---|---|---:|---|
| [MarkiRAT](https://attack.mitre.org/software/S0652/) | malware | 22 |  |
| [BITSAdmin](https://attack.mitre.org/software/S0190/) | ferramenta | 4 |  |

## 7. Campanhas

Nenhuma campanha atribuída no ATT&CK.

## 8. Cobertura defensiva

**6 de 6 técnicas (100%)** têm ao menos uma regra pública no catálogo Detection Rules.

### Onde procurar — cobertura por tecnologia

Quantas técnicas deste grupo têm ao menos uma regra em cada tecnologia. Comece a caça pelas tecnologias que você tem e que aparecem aqui.

| Tecnologia | Técnicas do grupo com regra |
|---|---:|
| Windows | 6 |
| EDR / XDR | 4 |
| Microsoft 365 | 4 |
| Outros / genérico | 4 |
| Linux | 3 |
| macOS | 3 |
| SaaS de negócio | 3 |
| DNS | 3 |
| Proxy / SWG | 3 |
| Servidores web & aplicações | 3 |
| IA, LLMs & agentes | 3 |
| AWS | 3 |

### Regras recomendadas por técnica

Melhor regra disponível por técnica (formato portável e maduro primeiro).

| Técnica | Regra | Formato | Fonte |
|---|---|---|---|
| T1036.002 | [Potential File Extension Spoofing Using Right-to-Left Override](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A979baf41-ca44-4540-9d0c-4fcef3b5a3a4) | Sigma | SigmaHQ |
| T1036.002 | [Potential Defense Evasion Via Right-to-Left Override](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aad691d92-15f2-4181-9aa4-723c74f9ddc3) | Sigma | SigmaHQ |
| T1036.005 | [Exploit for CVE-2015-1641](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A7993792c-5ce2-4475-a3db-a3a5539827ef) | Sigma | SigmaHQ |
| T1036.005 | [Exploit for CVE-2015-1641](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A7993792c-5ce2-4475-a3db-a3a5539827ef) | Sigma | OpenSearch Security Analytics |
| T1204.002 | [Ursnif Malware C2 URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A932ac737-33ca-4afd-9869-0d48b391fcc9) | Sigma | SigmaHQ |
| T1204.002 | [Droppers Exploiting CVE-2017-11882](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A678eb5f4-8597-4be6-8be7-905e4234b53a) | Sigma | SigmaHQ |
| T1566.001 | [Ursnif Malware C2 URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A932ac737-33ca-4afd-9869-0d48b391fcc9) | Sigma | SigmaHQ |
| T1566.001 | [Droppers Exploiting CVE-2017-11882](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A678eb5f4-8597-4be6-8be7-905e4234b53a) | Sigma | SigmaHQ |
| T1583.001 | [AWS Route 53 Private Hosted Zone Associated With a VPC](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ae3c27562-709a-42bd-82f2-3ed926cced19) | Elastic | Elastic detection-rules |
| T1583.001 | [AWS SES Email Identity Verified Then Deleted](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A8e4bde35-125d-4eb3-9a2e-d7e77a053a08) | Elastic | Elastic detection-rules |
| T1588.002 | [Hacktool Execution - Imphash](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A24e3e58a-646b-4b50-adef-02ef935b9fc8) | Sigma | SigmaHQ |
| T1588.002 | [Renamed SysInternals DebugView Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acd764533-2e07-40d6-a718-cfeec7f2da7f) | Sigma | SigmaHQ |

## 9. Plano de emulação e validação

Use num laboratório isolado e autorizado para confirmar que as regras disparam. Os comandos estão nos repositórios oficiais.

| Tática | Técnica | Teste Atomic Red Team | Plataformas |
|---|---|---|---|
| Initial Access | [T1566.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1566.001/T1566.001.md) | Download Macro-Enabled Phishing Attachment | windows |
| Initial Access | [T1566.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1566.001/T1566.001.md) | Word spawned a command shell and used an IP address in the command line | windows |
| Execution | [T1204.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1204.002/T1204.002.md) | OSTap Style Macro Execution | windows |
| Execution | [T1204.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1204.002/T1204.002.md) | OSTap Payload Download | windows |
| Stealth | [T1036.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.002/T1036.002.md) | Masquerading: Right-to-Left Override Batch File Creation and Execution | windows |
| Stealth | [T1036.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.002/T1036.002.md) | Masquerading: RTLO Masqueraded File Download and Execution | windows |
| Stealth | [T1036.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.005/T1036.005.md) | Execute a process from a directory masquerading as the current parent directory | linux, macos |
| Stealth | [T1036.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.005/T1036.005.md) | Masquerade as a built-in system executable | windows |

## 10. Hipóteses de hunting

Se Ferocious Kitten estiver no seu ambiente, estas são as perguntas a fazer aos seus dados (fontes de log segundo as estratégias de detecção do MITRE ATT&CK).

1. **T1036.002 Right-to-Left Override** — Execution of files containing right-to-left override characters (U+202E) to masquerade true file extensions. Often found in phishing payloads or file downloads. Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:PowerShell` (EventCode=4103, 4104, 4105, 4106), `WinEventLog:Windows Defender` (Operational).
2. **T1583.001 Domains** — Monitor logged domain name system (DNS) data for purchased domains that can be used during targeting. Reputation/category-based detection may be difficult until the categorization is updated. Detection efforts may be focused on related stages of the adversary… Dados: `Domain Name` (None), `Domain Name` (None), `Domain Name` (None).
3. **T1036.005 Match Legitimate Resource Name or Location** — Detects processes or binaries executed from trusted directories (e.g., System32) or using trusted names (e.g., svchost.exe) where the metadata, hash, or parent process does not align with legitimate activity patterns. Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=11).
4. **T1566.001 Spearphishing Attachment** — Detection of spearphishing attachments by correlating suspicious email delivery with subsequent file creation and abnormal process execution (e.g., Office spawning PowerShell or CMD). Behavior chain includes inbound email metadata → attachment stored on disk… Dados: `m365:unified` (Send/Receive: Inbound emails with attachments from suspicious or spoofed senders), `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Sysmon` (EventCode=1).
5. **T1588.002 Tool** — Monitor for contextual data about a malicious payload, such as compilation times, file hashes, as well as watermarks or other identifiable configuration information. In some cases, malware repositories can also be used to identify features of tool use… Dados: `Malware Repository` (None).
6. **T1204.002 Malicious File** — User opens a file delivered by email, web, chat, or share. The handler application (Word/PDF reader/archiver) creates a file in user-controlled paths (Downloads, Temp, Desktop) and then spawns a new or unusual child process (e.g., powershell.exe, wscript.exe,… Dados: `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=15).

## 11. OSINT — onde pesquisar

Consultas prontas com todos os nomes conhecidos do grupo:

- Relatórios técnicos: [busca web](https://duckduckgo.com/?q=%28%22Ferocious+Kitten%22%29+threat+report) · [PDFs](https://duckduckgo.com/?q=%28%22Ferocious+Kitten%22%29+filetype%3Apdf)
- Regras e IOCs publicados: [GitHub](https://github.com/search?type=code&q=%22Ferocious+Kitten%22)
- Pulsos de ameaça: [AlienVault OTX](https://otx.alienvault.com/browse/global/pulses?q=Ferocious+Kitten)
- Família de malware e atores: [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/actors) (busque por Ferocious Kitten)
- Cartões de grupo: [ThaiCERT Threat Group Cards](https://apt.etda.or.th/cgi-bin/listgroups.cgi)
- Página oficial: [MITRE ATT&CK G0137](https://attack.mitre.org/groups/G0137/)

**Relatórios na coleção CyberMonitor** (ligados pelo nome do grupo, conferir antes de citar):

- 2021 — [Ferocious Kitten_ 6 years of covert surveillance in Iran _ Securelist](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2021/2021.06.16.Ferocious_Kitten/Ferocious%20Kitten_%206%20years%20of%20covert%20surveillance%20in%20Iran%20_%20Securelist.pdf) _(via “Ferocious Kitten”)_

**Relatórios públicos ligados pelo APT4ALL** (2 no total, mais recentes primeiro):

- 2016 — [Prince of Persia Game Over](https://app.box.com/s/drj4vb73cv87ok5wks21rynlq3236793) _(Palo Alto)_
- 2016 — [Prince of Persia: Infy Malware Active In Decade of Targeted Attacks](https://app.box.com/s/zkjmru7uknf1p90mqn81ycf867le78tn) _(Palo Alto)_

## 12. Bibliografia (1 fontes citadas pelo ATT&CK)

- [Kaspersky Ferocious Kitten Jun 2021](https://securelist.com/ferocious-kitten-6-years-of-covert-surveillance-in-iran/102806/) — GReAT. (2021, June 16). Ferocious Kitten: 6 Years of Covert Surveillance in Iran. Retrieved September 22, 2021.

## 13. Limites e confiança

- O ATT&CK registra o que foi **relatado publicamente**, não tudo o que o grupo faz. Ausência de uma técnica não prova que o grupo não a usa.
- **Sobreposição de TTP não é atribuição.** Muitas técnicas são compartilhadas entre grupos e com red teams. Use a assinatura comportamental como hipótese, junto com infraestrutura, malware e contexto.
- Cobertura de detecção refere-se ao catálogo público Detection Rules, não ao seu ambiente: confira se a telemetria necessária chega ao seu SIEM.
- Ligações marcadas como _inferidas_ (EVTX por palavra-chave, relatórios por nome) devem ser verificadas.

---
Fontes: MITRE ATT&CK® (uso livre com atribuição, © The MITRE Corporation), APT4ALL (MISP Galaxy CC0/BSD-2, APT Groups & Operations CC BY 4.0, EternalLiberty, APTnotes, Ransomware Tool Matrix CC BY 4.0), Atomic Red Team (Red Canary, MIT), EVTX-to-MITRE-Attack, EVTX-ATTACK-SAMPLES, APT & CyberCriminal Campaign Collections. Gerado por [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules).
