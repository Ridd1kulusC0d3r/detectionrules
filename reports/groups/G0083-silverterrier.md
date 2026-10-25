# SilverTerrier (G0083) — Dossiê de inteligência

> **TLP:CLEAR** · gerado em 2026-10-25 a partir de fontes abertas · MITRE ATT&CK v20.0 · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0083) · [ATT&CK](https://attack.mitre.org/groups/G0083/)

**Também conhecido como:** —  
**Registro no ATT&CK:** criado em 2019-01-29, atualizado em 2026-07-31 · referências de 2016 a 2016

## 1. Sumário executivo

- **4 técnicas** atribuídas publicamente, concentradas em **Command and Control, Impact**.
- **Arsenal:** 5 malware e 0 ferramentas (ex.: NETWIRE, Agent Tesla, Lokibot, DarkComet, NanoCore).
- **Campanhas atribuídas:** 0.
- **Cobertura de detecção pública:** 100% das técnicas têm ao menos uma regra no catálogo; **0 técnicas sem nenhuma regra pública**.
- **Assinatura comportamental** (técnicas raras entre os 178 grupos, as mais úteis para atribuição): T1071.002 File Transfer Protocols, T1071.003 Mail Protocols, T1657 Financial Theft, T1071.001 Web Protocols.

## 2. Quem é

> SilverTerrier is a Nigerian threat group that has been seen active since 2014. SilverTerrier mainly targets organizations in high technology, higher education, and manufacturing.

_Texto original do MITRE ATT&CK, em inglês._

## 3. Perfil TTP por tática (kill chain)

Cada linha: técnica, como o grupo a usou segundo relatos públicos, e o que existe para detectar e testar.

### Command and Control (TA0011) — 3

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1071.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1071.001) Web Protocols | SilverTerrier uses HTTP for C2 communications. | 228 | 3 | — |
| [T1071.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1071.002) File Transfer Protocols | SilverTerrier uses FTP for C2 communications. | 3 | — | — |
| [T1071.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1071.003) Mail Protocols | SilverTerrier uses SMTP for C2 communications. | 6 | — | — |

### Impact (TA0040) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1657](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1657) Financial Theft | SilverTerrier targets organizations in high technology, higher education, and manufacturing for business email compromise (BEC) campaigns with the goal of financial theft. | 2 | — | — |

## 4. Assinatura comportamental

Técnicas que este grupo usa e que poucos dos 178 grupos do ATT&CK usam. Pesam mais numa atribuição por TTP: ver várias delas juntas é mais informativo do que ver técnicas comuns como PowerShell.

| Técnica | Outros grupos que usam | Peso (raridade) |
|---|---:|---:|
| T1071.002 File Transfer Protocols | 5 | 3.24 |
| T1071.003 Mail Protocols | 5 | 3.24 |
| T1657 Financial Theft | 18 | 2.19 |
| T1071.001 Web Protocols | 57 | 1.11 |

## 5. Arsenal

| Software | Tipo | Técnicas no ATT&CK | Uso relatado (EN) |
|---|---|---:|---|
| [NETWIRE](https://attack.mitre.org/software/S0198/) | malware | 45 |  |
| [Agent Tesla](https://attack.mitre.org/software/S0331/) | malware | 37 |  |
| [Lokibot](https://attack.mitre.org/software/S0447/) | malware | 28 |  |
| [DarkComet](https://attack.mitre.org/software/S0334/) | malware | 18 |  |
| [NanoCore](https://attack.mitre.org/software/S0336/) | malware | 13 |  |

## 6. Campanhas

Nenhuma campanha atribuída no ATT&CK.

## 7. Cobertura defensiva

**4 de 4 técnicas (100%)** têm ao menos uma regra pública no catálogo Detection Rules.

### Regras recomendadas por técnica

Melhor regra disponível por técnica (formato portável e maduro primeiro).

| Técnica | Regra | Formato | Fonte |
|---|---|---|---|
| T1071.001 | [Ursnif Malware Download URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aa36ce77e-30db-4ea0-8795-644d7af5dfb4) | Sigma | SigmaHQ |
| T1071.001 | [Ursnif Malware C2 URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A932ac737-33ca-4afd-9869-0d48b391fcc9) | Sigma | SigmaHQ |
| T1071.002 | [Ubiquiti - Unusual FTP connection to external server](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3Afd200125-9d57-4838-85ca-6430c63e4e5d) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1071.002 | [MS-FTP: Multiple FTP errors from same source.](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=wazuh-ruleset-oficial%3A%3Awazuh-11512) | Wazuh | Wazuh ruleset (oficial) |
| T1071.003 | [SMTP to the Internet on Port 26/TCP](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ad7e62693-aab9-4f66-a21a-3d79ecdd603d) | Elastic | Elastic detection-rules |
| T1071.003 | [CYFIRMA - Brand Intelligence - Domain Impersonation High Rule](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A10bdf525-5b89-4a25-933a-e63e73b915f1) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1657 | [AWS S3 Bucket Enumeration or Brute Force](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A5f0234fd-7f21-42af-8391-511d5fd11d5c) | Elastic | Elastic detection-rules |
| T1657 | [Monitor ransomwarelive for companies of interest on ransowmare data leak sites (DLS)](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=bert-janp-hunting-queries%3A%3A8b9af12a820a) | KQL hunting | Bert-JanP Hunting Queries |

## 8. Plano de emulação e validação

Use num laboratório isolado e autorizado para confirmar que as regras disparam. Os comandos estão nos repositórios oficiais.

| Tática | Técnica | Teste Atomic Red Team | Plataformas |
|---|---|---|---|
| Command and Control | [T1071.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1071.001/T1071.001.md) | Malicious User Agents - Powershell | windows |
| Command and Control | [T1071.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1071.001/T1071.001.md) | Malicious User Agents - CMD | windows |

## 9. Hipóteses de hunting

Se SilverTerrier estiver no seu ambiente, estas são as perguntas a fazer aos seus dados (fontes de log segundo as estratégias de detecção do MITRE ATT&CK).

1. **T1071.002 File Transfer Protocols** — Detects FTP, SMB, or TFTP traffic initiated by suspicious processes like PowerShell, cmd.exe, or rundll32.exe—especially with large outbound file transfers or unbalanced traffic volume. Dados: `WinEventLog:Sysmon` (EventCode=3, 22), `WinEventLog:Sysmon` (EventCode=1), `NSM:Flow` (ftp.log, smb_files.log).
2. **T1071.003 Mail Protocols** — Detects unauthorized use of SMTP/IMAP/POP3 by suspicious binaries (e.g., PowerShell, rundll32) to exfiltrate data or beacon via email, often bypassing proxy or content filters. Dados: `WinEventLog:Sysmon` (EventCode=3, 22), `WinEventLog:Sysmon` (EventCode=1), `NSM:Flow` (smtp.log).
3. **T1657 Financial Theft** — Monitor for anomalous access to financial applications, browser-based banking sessions, or enterprise ERP systems from Windows endpoints. Detect mass emailing of payment instructions, sudden rule changes in Outlook for financial staff, or use of clipboard… Dados: `WinEventLog:Security` (EventCode=4624, 4648), `WinEventLog:Sysmon` (EventCode=1).
4. **T1071.001 Web Protocols** — Detects unexpected or high-volume HTTP/S/WebSocket communication from suspicious processes (e.g., PowerShell, rundll32) using uncommon user agents or mimicking browser traffic to unusual domains or IPs. Dados: `NSM:Flow` (http.log, ssl.log), `WinEventLog:Sysmon` (EventCode=3, 22).

## 10. OSINT — onde pesquisar

Consultas prontas com todos os nomes conhecidos do grupo:

- Relatórios técnicos: [busca web](https://duckduckgo.com/?q=%28%22SilverTerrier%22%29+threat+report) · [PDFs](https://duckduckgo.com/?q=%28%22SilverTerrier%22%29+filetype%3Apdf)
- Regras e IOCs publicados: [GitHub](https://github.com/search?type=code&q=%22SilverTerrier%22)
- Pulsos de ameaça: [AlienVault OTX](https://otx.alienvault.com/browse/global/pulses?q=SilverTerrier)
- Família de malware e atores: [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/actors) (busque por SilverTerrier)
- Cartões de grupo: [ThaiCERT Threat Group Cards](https://apt.etda.or.th/cgi-bin/listgroups.cgi)
- Página oficial: [MITRE ATT&CK G0083](https://attack.mitre.org/groups/G0083/)

## 11. Bibliografia (2 fontes citadas pelo ATT&CK)

- [Unit42 SilverTerrier 2016](https://www.paloaltonetworks.com/content/dam/pan/en_US/assets/pdf/reports/Unit_42/silverterrier-next-evolution-in-nigerian-cybercrime.pdf) — Renals, P., Conant, S. (2016). SILVERTERRIER: The Next Evolution in Nigerian Cybercrime. Retrieved November 13, 2018.
- [Unit42 SilverTerrier 2018](https://www.paloaltonetworks.com/apps/pan/public/downloadResource?pagePath=/content/pan/en_US/resources/whitepapers/unit42-silverterrier-rise-of-nigerian-business-email-compromise) — Unit42. (2016). SILVERTERRIER: THE RISE OF NIGERIAN BUSINESS EMAIL COMPROMISE. Retrieved November 13, 2018.

## 12. Limites e confiança

- O ATT&CK registra o que foi **relatado publicamente**, não tudo o que o grupo faz. Ausência de uma técnica não prova que o grupo não a usa.
- **Sobreposição de TTP não é atribuição.** Muitas técnicas são compartilhadas entre grupos e com red teams. Use a assinatura comportamental como hipótese, junto com infraestrutura, malware e contexto.
- Cobertura de detecção refere-se ao catálogo público Detection Rules, não ao seu ambiente: confira se a telemetria necessária chega ao seu SIEM.
- Ligações marcadas como _inferidas_ (EVTX por palavra-chave, relatórios por nome) devem ser verificadas.

---
Fontes: MITRE ATT&CK® (uso livre com atribuição, © The MITRE Corporation), Atomic Red Team (Red Canary, MIT), EVTX-to-MITRE-Attack, EVTX-ATTACK-SAMPLES, APT & CyberCriminal Campaign Collections. Gerado por [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules).
