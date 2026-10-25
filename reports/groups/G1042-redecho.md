# RedEcho (G1042) — Dossiê de inteligência

> **TLP:CLEAR** · gerado em 2026-10-25 a partir de fontes abertas · MITRE ATT&CK v20.0 · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1042) · [ATT&CK](https://attack.mitre.org/groups/G1042/)

**Também conhecido como:** —  
**Registro no ATT&CK:** criado em 2024-11-21, atualizado em 2026-07-31 · referências de 2021 a 2022

## 1. Sumário executivo

- **5 técnicas** atribuídas publicamente, concentradas em **Command and Control, Resource Development**.
- **Arsenal:** 1 malware e 0 ferramentas (ex.: ShadowPad).
- **Campanhas atribuídas:** 0.
- **Cobertura de detecção pública:** 100% das técnicas têm ao menos uma regra no catálogo; **0 técnicas sem nenhuma regra pública**.
- **Assinatura comportamental** (técnicas raras entre os 178 grupos, as mais úteis para atribuição): T1568 Dynamic Resolution, T1573.002 Asymmetric Cryptography, T1571 Non-Standard Port, T1583.001 Domains, T1071.001 Web Protocols.

## 2. Quem é

> RedEcho is a People’s Republic of China-related threat actor associated with long-running intrusions in Indian critical infrastructure entities. RedEcho overlaps with various other PRC-linked threat groups, such as APT41, and is linked to ShadowPad malware use through shared infrastructure.

_Texto original do MITRE ATT&CK, em inglês._

## 3. Perfil TTP por tática (kill chain)

Cada linha: técnica, como o grupo a usou segundo relatos públicos, e o que existe para detectar e testar.

### Resource Development (TA0042) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1583.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1583.001) Domains | RedEcho has registered domains spoofing Indian critical infrastructure entities. | 7 | — | — |

### Command and Control (TA0011) — 4

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1071.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1071.001) Web Protocols | RedEcho network activity is associated with SSL traffic via TCP 443 and proxied HTTP traffic over non-standard ports. | 228 | 3 | — |
| [T1568](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1568) Dynamic Resolution | RedEcho used dynamic DNS domains associated with malicious infrastructure. | 32 | — | — |
| [T1571](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1571) Non-Standard Port | RedEcho has used non-standard ports such as TCP 8080 for HTTP communication. | 163 | 2 | — |
| [T1573.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1573.002) Asymmetric Cryptography | RedEcho uses SSL for network communication. | 14 | — | — |

## 4. Assinatura comportamental

Técnicas que este grupo usa e que poucos dos 178 grupos do ATT&CK usam. Pesam mais numa atribuição por TTP: ver várias delas juntas é mais informativo do que ver técnicas comuns como PowerShell.

| Técnica | Outros grupos que usam | Peso (raridade) |
|---|---:|---:|
| T1568 Dynamic Resolution | 7 | 2.99 |
| T1573.002 Asymmetric Cryptography | 11 | 2.62 |
| T1571 Non-Standard Port | 18 | 2.19 |
| T1583.001 Domains | 47 | 1.30 |
| T1071.001 Web Protocols | 57 | 1.11 |

## 5. Arsenal

| Software | Tipo | Técnicas no ATT&CK | Uso relatado (EN) |
|---|---|---:|---|
| [ShadowPad](https://attack.mitre.org/software/S0596/) | malware | 21 | RedEcho has used ShadowPad during intrusions. |

## 6. Campanhas

Nenhuma campanha atribuída no ATT&CK.

## 7. Cobertura defensiva

**5 de 5 técnicas (100%)** têm ao menos uma regra pública no catálogo Detection Rules.

### Regras recomendadas por técnica

Melhor regra disponível por técnica (formato portável e maduro primeiro).

| Técnica | Regra | Formato | Fonte |
|---|---|---|---|
| T1071.001 | [Ursnif Malware Download URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aa36ce77e-30db-4ea0-8795-644d7af5dfb4) | Sigma | SigmaHQ |
| T1071.001 | [Ursnif Malware C2 URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A932ac737-33ca-4afd-9869-0d48b391fcc9) | Sigma | SigmaHQ |
| T1568 | [Possible FIN7 DGA Command and Control Behavior](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A4a4e23cf-78a2-449c-bac3-701924c269d3) | Elastic | Elastic detection-rules |
| T1568 | [Cobalt Strike Command and Control Beacon](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Acf53f532-9cc9-445a-9ae7-fced307ec53c) | Elastic | Elastic detection-rules |
| T1571 | [Potentially Suspicious Malware Callback Communication - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Adbfc7c98-04ab-4ab7-aa94-c74d22aa7376) | Sigma | SigmaHQ |
| T1571 | [Potentially Suspicious Malware Callback Communication](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4b89abaa-99fe-4232-afdd-8f9aa4d20382) | Sigma | SigmaHQ |
| T1573.002 | [Potential Self-Signed TLS Certificate Recently Issued on External Connection](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A869fe008-5dd4-4f07-9c2e-aa90c3926fd9) | Elastic | Elastic detection-rules |
| T1573.002 | [Openssl Client or Server Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Aad5a3757-c872-4719-8c72-12d3f08db655) | Elastic | Elastic detection-rules |
| T1583.001 | [AWS Route 53 Private Hosted Zone Associated With a VPC](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ae3c27562-709a-42bd-82f2-3ed926cced19) | Elastic | Elastic detection-rules |
| T1583.001 | [AWS SES Email Identity Verified Then Deleted](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A8e4bde35-125d-4eb3-9a2e-d7e77a053a08) | Elastic | Elastic detection-rules |

## 8. Plano de emulação e validação

Use num laboratório isolado e autorizado para confirmar que as regras disparam. Os comandos estão nos repositórios oficiais.

| Tática | Técnica | Teste Atomic Red Team | Plataformas |
|---|---|---|---|
| Command and Control | [T1071.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1071.001/T1071.001.md) | Malicious User Agents - Powershell | windows |
| Command and Control | [T1071.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1071.001/T1071.001.md) | Malicious User Agents - CMD | windows |
| Command and Control | [T1571](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1571/T1571.md) | Testing usage of uncommonly used port with PowerShell | windows |
| Command and Control | [T1571](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1571/T1571.md) | Testing usage of uncommonly used port | linux, macos |

## 9. Hipóteses de hunting

Se RedEcho estiver no seu ambiente, estas são as perguntas a fazer aos seus dados (fontes de log segundo as estratégias de detecção do MITRE ATT&CK).

1. **T1568 Dynamic Resolution** — Correlate high-frequency or anomalous DNS query activity with processes that do not normally generate network requests (e.g., Office apps, system utilities). Detect pseudo-random or high-entropy domain lookups indicative of domain generation algorithms (DGAs). Dados: `WinEventLog:Sysmon` (EventCode=3, 22), `WinEventLog:Sysmon` (EventCode=1).
2. **T1573.002 Asymmetric Cryptography** — Processes not typically associated with encryption loading asymmetric crypto libraries (e.g., rsaenh.dll, crypt32.dll) and subsequently initiating outbound TLS/SSL connections with abnormal certificate chains or handshakes. Defender correlates process… Dados: `WinEventLog:Sysmon` (EventCode=7), `WinEventLog:Sysmon` (EventCode=3, 22).
3. **T1571 Non-Standard Port** — Processes initiating outbound connections on uncommon ports or using protocols inconsistent with the assigned port. Correlating process creation with subsequent network connections reveals anomalies such as svchost.exe or Office applications using high,… Dados: `WinEventLog:Security` (EventCode=5156, 5157), `WinEventLog:Sysmon` (EventCode=1).
4. **T1583.001 Domains** — Monitor logged domain name system (DNS) data for purchased domains that can be used during targeting. Reputation/category-based detection may be difficult until the categorization is updated. Detection efforts may be focused on related stages of the adversary… Dados: `Domain Name` (None), `Domain Name` (None), `Domain Name` (None).
5. **T1071.001 Web Protocols** — Detects unexpected or high-volume HTTP/S/WebSocket communication from suspicious processes (e.g., PowerShell, rundll32) using uncommon user agents or mimicking browser traffic to unusual domains or IPs. Dados: `NSM:Flow` (http.log, ssl.log), `WinEventLog:Sysmon` (EventCode=3, 22).

## 10. OSINT — onde pesquisar

Consultas prontas com todos os nomes conhecidos do grupo:

- Relatórios técnicos: [busca web](https://duckduckgo.com/?q=%28%22RedEcho%22%29+threat+report) · [PDFs](https://duckduckgo.com/?q=%28%22RedEcho%22%29+filetype%3Apdf)
- Regras e IOCs publicados: [GitHub](https://github.com/search?type=code&q=%22RedEcho%22)
- Pulsos de ameaça: [AlienVault OTX](https://otx.alienvault.com/browse/global/pulses?q=RedEcho)
- Família de malware e atores: [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/actors) (busque por RedEcho)
- Cartões de grupo: [ThaiCERT Threat Group Cards](https://apt.etda.or.th/cgi-bin/listgroups.cgi)
- Página oficial: [MITRE ATT&CK G1042](https://attack.mitre.org/groups/G1042/)

**Relatórios na coleção CyberMonitor** (ligados pelo nome do grupo, conferir antes de citar):

- 2021 — [cta-2021-0228](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2021/2021.02.28.RedEcho_APT/cta-2021-0228.pdf) _(via “RedEcho”)_

## 11. Bibliografia (2 fontes citadas pelo ATT&CK)

- [RecordedFuture RedEcho 2021](https://go.recordedfuture.com/hubfs/reports/cta-2021-0228.pdf) — Recorded Future Insikt Group. (2021, February). China-Linked Group RedEcho Targets the Indian Power Sector Amid Heightened Border Tensions. Retrieved November 21, 2024.
- [RecordedFuture RedEcho 2022](https://go.recordedfuture.com/hubfs/reports/ta-2022-0406.pdf) — Recorded Future Insikt Group. (2022, April 6). Continued Targeting of Indian Power Grid Assets by Chinese State-Sponsored Activity Group. Retrieved November 21, 2024.

## 12. Limites e confiança

- O ATT&CK registra o que foi **relatado publicamente**, não tudo o que o grupo faz. Ausência de uma técnica não prova que o grupo não a usa.
- **Sobreposição de TTP não é atribuição.** Muitas técnicas são compartilhadas entre grupos e com red teams. Use a assinatura comportamental como hipótese, junto com infraestrutura, malware e contexto.
- Cobertura de detecção refere-se ao catálogo público Detection Rules, não ao seu ambiente: confira se a telemetria necessária chega ao seu SIEM.
- Ligações marcadas como _inferidas_ (EVTX por palavra-chave, relatórios por nome) devem ser verificadas.

---
Fontes: MITRE ATT&CK® (uso livre com atribuição, © The MITRE Corporation), Atomic Red Team (Red Canary, MIT), EVTX-to-MITRE-Attack, EVTX-ATTACK-SAMPLES, APT & CyberCriminal Campaign Collections. Gerado por [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules).
