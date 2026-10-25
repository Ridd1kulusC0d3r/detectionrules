# Water Galura (G1050) — Dossiê de inteligência

> **TLP:CLEAR** · gerado em 2026-10-25 a partir de fontes abertas · MITRE ATT&CK v20.0 · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1050) · [ATT&CK](https://attack.mitre.org/groups/G1050/)

**Também conhecido como:** GOLD FEATHER  
**Registro no ATT&CK:** criado em 2025-09-29, atualizado em 2026-07-31 · referências de 2024 a 2025

## 1. Sumário executivo

- **3 técnicas** atribuídas publicamente, concentradas em **Impact, Resource Development**.
- **Arsenal:** 1 malware e 1 ferramentas (ex.: Qilin, Tor).
- **Campanhas atribuídas:** 0.
- **Cobertura de detecção pública:** 100% das técnicas têm ao menos uma regra no catálogo; **0 técnicas sem nenhuma regra pública**.
- **Assinatura comportamental** (técnicas raras entre os 178 grupos, as mais úteis para atribuição): T1657 Financial Theft, T1486 Data Encrypted for Impact, T1585.001 Social Media Accounts.

## 2. Quem é

> Water Galura are the operators of the Qilin Ransomware-as-a-Service (RaaS) who handle payload generation, ransom negotiations, and the publication of stolen data for Qilin affilates recruited on Russian cybercrime forums. Water Galura have been active since at least 2022 and use a double extortion model where they demand payment for providing decryption keys and for refraining from publishing the stolen data to their leak site.

_Texto original do MITRE ATT&CK, em inglês._

## 3. Perfil TTP por tática (kill chain)

Cada linha: técnica, como o grupo a usou segundo relatos públicos, e o que existe para detectar e testar.

### Resource Development (TA0042) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1585.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1585.001) Social Media Accounts | Water Galura operates a news channel on Telegram to make announcements for the Qilin RaaS. | 4 | — | — |

### Impact (TA0040) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1486](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1486) Data Encrypted for Impact | Water Galura has encrypted files on victim networks through the generation of Qilin ransomware payloads. | 160 | 10 | 1 |
| [T1657](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1657) Financial Theft | Water Galura has extorted victims for ransomware decryption keys and to prevent publication of data exfiltrated to their Tor data leak site. | 2 | — | — |

## 4. Assinatura comportamental

Técnicas que este grupo usa e que poucos dos 178 grupos do ATT&CK usam. Pesam mais numa atribuição por TTP: ver várias delas juntas é mais informativo do que ver técnicas comuns como PowerShell.

| Técnica | Outros grupos que usam | Peso (raridade) |
|---|---:|---:|
| T1657 Financial Theft | 18 | 2.19 |
| T1486 Data Encrypted for Impact | 19 | 2.14 |
| T1585.001 Social Media Accounts | 22 | 2.01 |

## 5. Arsenal

| Software | Tipo | Técnicas no ATT&CK | Uso relatado (EN) |
|---|---|---:|---|
| [Qilin](https://attack.mitre.org/software/S1242/) | malware | 52 | Water Galura are the operators of the Qilin RaaS. |
| [Tor](https://attack.mitre.org/software/S0183/) | ferramenta | 2 | Water Galura maintains a Tor-hosted data leaks site for Qilin ransomware and affiliates. |

## 6. Campanhas

Nenhuma campanha atribuída no ATT&CK.

## 7. Cobertura defensiva

**3 de 3 técnicas (100%)** têm ao menos uma regra pública no catálogo Detection Rules.

### Regras recomendadas por técnica

Melhor regra disponível por técnica (formato portável e maduro primeiro).

| Técnica | Regra | Formato | Fonte |
|---|---|---|---|
| T1486 | [LockerGoga Ransomware Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A74db3488-fd28-480a-95aa-b7af626de068) | Sigma | SigmaHQ |
| T1486 | [LockerGoga Ransomware](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A74db3488-fd28-480a-95aa-b7af626de068) | Sigma | OpenSearch Security Analytics |
| T1585.001 | [CYFIRMA - Brand Intelligence - Social Media Handle Impersonation Detected High Rule](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A22f49d67-7da7-4809-8d07-89e4478aa6b0) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1585.001 | [CYFIRMA - Brand Intelligence - Executive/People Impersonation High Rule](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A159d26a1-591c-4f70-b1ca-2843c881aaec) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1657 | [AWS S3 Bucket Enumeration or Brute Force](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A5f0234fd-7f21-42af-8391-511d5fd11d5c) | Elastic | Elastic detection-rules |
| T1657 | [Monitor ransomwarelive for companies of interest on ransowmare data leak sites (DLS)](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=bert-janp-hunting-queries%3A%3A8b9af12a820a) | KQL hunting | Bert-JanP Hunting Queries |

## 8. Plano de emulação e validação

Use num laboratório isolado e autorizado para confirmar que as regras disparam. Os comandos estão nos repositórios oficiais.

| Tática | Técnica | Teste Atomic Red Team | Plataformas |
|---|---|---|---|
| Impact | [T1486](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1486/T1486.md) | Encrypt files using gpg (FreeBSD/Linux) | linux |
| Impact | [T1486](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1486/T1486.md) | Encrypt files using 7z (FreeBSD/Linux) | linux |

**Logs reais de ataque (EVTX) para testar sem executar nada:**

- T1486 — [ID 768,775,793,796,817,840-BitLocker encryption activated](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0040-Impact/T1486-Data%20Encrypted%20for%20Impact/ID%20768%2C775%2C793%2C796%2C817%2C840-BitLocker%20encryption%20activated.evtx) _(explícito)_

## 9. Hipóteses de hunting

Se Water Galura estiver no seu ambiente, estas são as perguntas a fazer aos seus dados (fontes de log segundo as estratégias de detecção do MITRE ATT&CK).

1. **T1657 Financial Theft** — Monitor for anomalous access to financial applications, browser-based banking sessions, or enterprise ERP systems from Windows endpoints. Detect mass emailing of payment instructions, sudden rule changes in Outlook for financial staff, or use of clipboard… Dados: `WinEventLog:Security` (EventCode=4624, 4648), `WinEventLog:Sysmon` (EventCode=1).
2. **T1486 Data Encrypted for Impact** — High-frequency file write operations using uncommon extensions, followed by ransom note creation, registry tampering, or shadow copy deletion. Often uses CLI tools like vssadmin, wbadmin, cipher, or PowerShell. Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Sysmon` (EventCode=2).
3. **T1585.001 Social Media Accounts** — Monitor and analyze traffic patterns and packet inspection associated to protocol(s) that do not follow the expected protocol standards and traffic flows (e.g extraneous packets that do not belong to established flows, gratuitous or anomalous traffic… Dados: `Network Traffic` (None), `Persona` (None).

## 10. OSINT — onde pesquisar

Consultas prontas com todos os nomes conhecidos do grupo:

- Relatórios técnicos: [busca web](https://duckduckgo.com/?q=%28%22Water+Galura%22+OR+%22GOLD+FEATHER%22%29+threat+report) · [PDFs](https://duckduckgo.com/?q=%28%22Water+Galura%22+OR+%22GOLD+FEATHER%22%29+filetype%3Apdf)
- Regras e IOCs publicados: [GitHub](https://github.com/search?type=code&q=%22Water+Galura%22+OR+%22GOLD+FEATHER%22)
- Pulsos de ameaça: [AlienVault OTX](https://otx.alienvault.com/browse/global/pulses?q=Water+Galura)
- Família de malware e atores: [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/actors) (busque por Water Galura, GOLD FEATHER)
- Cartões de grupo: [ThaiCERT Threat Group Cards](https://apt.etda.or.th/cgi-bin/listgroups.cgi)
- Página oficial: [MITRE ATT&CK G1050](https://attack.mitre.org/groups/G1050/)

## 11. Bibliografia (3 fontes citadas pelo ATT&CK)

- [BushidoToken Qilin RaaS JUN 2024](https://blog.bushidotoken.net/2024/06/tracking-adversaries-qilin-raas.html) — Thomas, W. (2024, June 12). Tracking Adversaries: The Qilin RaaS. Retrieved September 26, 2025.
- [HC3 Qilin Threat Profile JUN 2024](https://www.aha.org/system/files/media/file/2024/06/tlp-clear-hc3-threat-profile-qilin-aka-agenda-ransomware-6-18-2024.pdf) — Health Sector Cybersecurity Coordination Center. (2024, June 18). Qilin, aka Agenda Ransomware. Retrieved September 26, 2025.
- [Sophos Qilin MSP APR 2025](https://news.sophos.com/en-us/2025/04/01/sophos-mdr-tracks-ongoing-campaign-by-qilin-affiliates-targeting-screenconnect/) — Bradshaw, A. et al. (2025, April 1). Qilin affiliates spear-phish MSP ScreenConnect admin, targeting customers downstream. Retrieved September 26, 2025.

## 12. Limites e confiança

- O ATT&CK registra o que foi **relatado publicamente**, não tudo o que o grupo faz. Ausência de uma técnica não prova que o grupo não a usa.
- **Sobreposição de TTP não é atribuição.** Muitas técnicas são compartilhadas entre grupos e com red teams. Use a assinatura comportamental como hipótese, junto com infraestrutura, malware e contexto.
- Cobertura de detecção refere-se ao catálogo público Detection Rules, não ao seu ambiente: confira se a telemetria necessária chega ao seu SIEM.
- Ligações marcadas como _inferidas_ (EVTX por palavra-chave, relatórios por nome) devem ser verificadas.

---
Fontes: MITRE ATT&CK® (uso livre com atribuição, © The MITRE Corporation), Atomic Red Team (Red Canary, MIT), EVTX-to-MITRE-Attack, EVTX-ATTACK-SAMPLES, APT & CyberCriminal Campaign Collections. Gerado por [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules).
