# AppleJeus (G1049) — Dossiê de inteligência

> **TLP:CLEAR** · gerado em 2026-10-25 a partir de fontes abertas · MITRE ATT&CK v20.0 · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1049) · [ATT&CK](https://attack.mitre.org/groups/G1049/)

**Também conhecido como:** Gleaming Pisces, Citrine Sleet, UNC1720, UNC4736  
**Registro no ATT&CK:** criado em 2025-08-25, atualizado em 2026-07-31 · referências de 2023 a 2025

## 1. Sumário executivo

- **2 técnicas** atribuídas publicamente, concentradas em **Initial Access, Impact**.
- **Arsenal:** 0 malware e 0 ferramentas.
- **Campanhas atribuídas:** 1 (3CX Supply Chain Attack).
- **Cobertura de detecção pública:** 100% das técnicas têm ao menos uma regra no catálogo; **0 técnicas sem nenhuma regra pública**.
- **Assinatura comportamental** (técnicas raras entre os 178 grupos, as mais úteis para atribuição): T1566 Phishing, T1657 Financial Theft.

## 2. Quem é

> AppleJeus is a North Korean state-sponsored threat group attributed to the Reconnaissance General Bureau. Associated with the broader Lazarus Group umbrella of actors, AppleJeus has been active since at least 2018 and is closely aligned in resources with TEMP.hermit, another DPRK-affiliated group under the same umbrella. The group’s primary mission is to generate and launder revenue to provide financial support to the government. AppleJeus primarily targets the cryptocurrency industry and is most notably responsible for the 3CX Supply Chain Attack. The group traditionally deploys malicious cryptocurrency software in combination with Phishing. From these compromised environments, it selectively deploys additional backdoors to enable extended operations against high-value financial targets.

_Texto original do MITRE ATT&CK, em inglês._

## 3. Perfil TTP por tática (kill chain)

Cada linha: técnica, como o grupo a usou segundo relatos públicos, e o que existe para detectar e testar.

### Initial Access (TA0001) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1566](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1566) Phishing | AppleJeus has used spearphishing emails to distribute malicious payloads. | 286 | — | — |

### Impact (TA0040) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1657](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1657) Financial Theft | AppleJeus has targeted the cryptocurrency industry with the goal of stealing digital assets. | 2 | — | — |

## 4. Assinatura comportamental

Técnicas que este grupo usa e que poucos dos 178 grupos do ATT&CK usam. Pesam mais numa atribuição por TTP: ver várias delas juntas é mais informativo do que ver técnicas comuns como PowerShell.

| Técnica | Outros grupos que usam | Peso (raridade) |
|---|---:|---:|
| T1566 Phishing | 7 | 2.99 |
| T1657 Financial Theft | 18 | 2.19 |

## 5. Arsenal

Nenhum software atribuído no ATT&CK.

## 6. Campanhas

| Campanha | Período | Resumo (EN) |
|---|---|---|
| [3CX Supply Chain Attack](https://attack.mitre.org/campaigns/C0057/) | 2022-11 → 2023-03 | The 3CX Supply Chain Attack was the first publicly reported case of one supply chain compromise triggering another, leading to a cascading, two-stage intrusion. The initial supply chain attack began when a 3CX employee d |

## 7. Cobertura defensiva

**2 de 2 técnicas (100%)** têm ao menos uma regra pública no catálogo Detection Rules.

### Regras recomendadas por técnica

Melhor regra disponível por técnica (formato portável e maduro primeiro).

| Técnica | Regra | Formato | Fonte |
|---|---|---|---|
| T1566 | [CVE-2021-31979 CVE-2021-33771 Exploits by Sourgum](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aad7085ac-92e4-4b76-8ce2-276d2c0e68ef) | Sigma | SigmaHQ |
| T1566 | [CVE-2021-31979 CVE-2021-33771 Exploits](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A32b5db62-cb5f-4266-9639-0fa48376ac00) | Sigma | SigmaHQ |
| T1657 | [AWS S3 Bucket Enumeration or Brute Force](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A5f0234fd-7f21-42af-8391-511d5fd11d5c) | Elastic | Elastic detection-rules |
| T1657 | [Monitor ransomwarelive for companies of interest on ransowmare data leak sites (DLS)](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=bert-janp-hunting-queries%3A%3A8b9af12a820a) | KQL hunting | Bert-JanP Hunting Queries |

## 8. Plano de emulação e validação

Use num laboratório isolado e autorizado para confirmar que as regras disparam. Os comandos estão nos repositórios oficiais.


## 9. Hipóteses de hunting

Se AppleJeus estiver no seu ambiente, estas são as perguntas a fazer aos seus dados (fontes de log segundo as estratégias de detecção do MITRE ATT&CK).

1. **T1566 Phishing** — Unusual inbound email activity where attachments or embedded URLs are delivered to users followed by execution of new processes or suspicious document behavior. Detection involves correlating email metadata, file creation, and network activity after a… Dados: `m365:unified` (Send/Receive: Emails with suspicious sender domains, spoofed headers, or anomalous attachment types), `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Sysmon` (EventCode=1).
2. **T1657 Financial Theft** — Monitor for anomalous access to financial applications, browser-based banking sessions, or enterprise ERP systems from Windows endpoints. Detect mass emailing of payment instructions, sudden rule changes in Outlook for financial staff, or use of clipboard… Dados: `WinEventLog:Security` (EventCode=4624, 4648), `WinEventLog:Sysmon` (EventCode=1).

## 10. OSINT — onde pesquisar

Consultas prontas com todos os nomes conhecidos do grupo:

- Relatórios técnicos: [busca web](https://duckduckgo.com/?q=%28%22AppleJeus%22+OR+%22Gleaming+Pisces%22+OR+%22Citrine+Sleet%22+OR+%22UNC1720%22+OR+%22UNC4736%22%29+threat+report) · [PDFs](https://duckduckgo.com/?q=%28%22AppleJeus%22+OR+%22Gleaming+Pisces%22+OR+%22Citrine+Sleet%22+OR+%22UNC1720%22+OR+%22UNC4736%22%29+filetype%3Apdf)
- Regras e IOCs publicados: [GitHub](https://github.com/search?type=code&q=%22AppleJeus%22+OR+%22Gleaming+Pisces%22+OR+%22Citrine+Sleet%22+OR+%22UNC1720%22+OR+%22UNC4736%22)
- Pulsos de ameaça: [AlienVault OTX](https://otx.alienvault.com/browse/global/pulses?q=AppleJeus)
- Família de malware e atores: [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/actors) (busque por AppleJeus, Gleaming Pisces, Citrine Sleet)
- Cartões de grupo: [ThaiCERT Threat Group Cards](https://apt.etda.or.th/cgi-bin/listgroups.cgi)
- Página oficial: [MITRE ATT&CK G1049](https://attack.mitre.org/groups/G1049/)

**Relatórios na coleção CyberMonitor** (ligados pelo nome do grupo, conferir antes de citar):

- 2018 — [Operation_AppleJeus](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2018/2018.08.23.Operation_AppleJeus/Operation_AppleJeus.pdf) _(via “AppleJeus”)_
- 2020 — [Operation AppleJeus Sequel](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2020/2020.01.08_Operation_AppleJeus_Sequel/Operation%20AppleJeus%20Sequel.pdf) _(via “AppleJeus”)_

## 11. Bibliografia (5 fontes citadas pelo ATT&CK)

- [dtex DPRK 2025 structure ITworkers](https://reports.dtexsystems.com/DTEX-Exposing+DPRK+Cyber+Syndicate+and+Hidden+IT+Workforce.pdf) — Michael “Barni” Barnhart, DTEX, and Anonymous SMEs. (2025, May 14). Exposing DPRK's Cyber Syndicate and Hidden IT Workforce. Retrieved September 3, 2025.
- [JPCert Blog Laz Subgroups 2025](https://blogs.jpcert.or.jp/en/2025/03/classifying-lazaruss-subgroup.html) — 佐々木勇人 Hayato Sasaki. (2025, March 25). Tempted to Classifying APT Actors: Practical Challenges of Attribution in the Case of Lazarus’s Subgroup. Retrieved August 25, 2025.
- [Mandiant 3cx UNC4736 2023](https://cloud.google.com/blog/topics/threat-intelligence/3cx-software-supply-chain-compromise/) — Jeff Johnson, Fred Plan, Adrian Sanchez, Renato Fontana, Jake Nicastro, Dimiter Andonov, Marius Fodoreanu, Daniel Scott. (2023, April 20). 3CX Software Supply Chain Compromise Initiated by a Prior Software Supply Chain C
- [Mandiant DPRK Groups 2023](https://cloud.google.com/blog/topics/threat-intelligence/north-korea-cyber-structure-alignment-2023) — Michael Barnhart, Austin Larsen, Jeff Johnson, Taylor Long, Michelle Cantos, Adrian Hernandez. (2023, October 10). Assessed Cyber Structure and Alignments of North Korea in 2023. Retrieved August 25, 2025.
- [Unit42 DPRK Threat Groups 2024](https://unit42.paloaltonetworks.com/threat-assessment-north-korean-threat-groups-2024/) — Unit 42. (2024, September 9). Threat Assessment: North Korean Threat Groups. Retrieved August 25, 2025.

## 12. Limites e confiança

- O ATT&CK registra o que foi **relatado publicamente**, não tudo o que o grupo faz. Ausência de uma técnica não prova que o grupo não a usa.
- **Sobreposição de TTP não é atribuição.** Muitas técnicas são compartilhadas entre grupos e com red teams. Use a assinatura comportamental como hipótese, junto com infraestrutura, malware e contexto.
- Cobertura de detecção refere-se ao catálogo público Detection Rules, não ao seu ambiente: confira se a telemetria necessária chega ao seu SIEM.
- Ligações marcadas como _inferidas_ (EVTX por palavra-chave, relatórios por nome) devem ser verificadas.

---
Fontes: MITRE ATT&CK® (uso livre com atribuição, © The MITRE Corporation), Atomic Red Team (Red Canary, MIT), EVTX-to-MITRE-Attack, EVTX-ATTACK-SAMPLES, APT & CyberCriminal Campaign Collections. Gerado por [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules).
