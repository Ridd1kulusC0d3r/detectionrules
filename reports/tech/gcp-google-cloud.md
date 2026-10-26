# Google Cloud — relatório de regras de detecção

> **TLP:CLEAR** · 2026-10-26 · domínio **Nuvem** · plataforma ATT&CK **IaaS** · lente TCEM **Cloud & Multi-Cloud** · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#techno=gcp)

## 1. A história em um parágrafo

O palco é **o projeto Google Cloud — IAM, buckets e cargas na nuvem do Google**. O catálogo reúne **1,006 regras** que olham para cá — 523 de detecção, 303 de hunting, 127 assinaturas e 53 playbooks de resposta. Elas se concentram em **Escalação de privilégio, Persistência, Enfraquecimento de defesas**. Das 104 técnicas do ATT&CK para a plataforma IaaS, **54 (52%)** têm ao menos uma regra aqui e **50 não têm nenhuma** — é onde um atacante passa sem ser visto. Entre os grupos com mais técnicas nesta plataforma estão Scattered Spider, Storm-0501, APT28.

**Lente TCEM — Cloud & Multi-Cloud.** Cloud control planes, workloads, identities, management APIs, cross-cloud trust and SaaS dependencies. Para observar: cloud audit, identity logs, control-plane changes, workload activity. Arquitetura a mapear: control planes, cloud identities, organization hierarchy, workload identities, management APIs.

## 2. Números

| Indicador | Valor |
|---|---:|
| Regras | 1,006 |
| detecção | 523 |
| hunting | 303 |
| assinatura | 127 |
| playbook | 53 |
| Técnicas ATT&CK distintas | 99 |
| Cobertura da plataforma IaaS | 54/104 (52%) |

### Por tática

| Tática | Regras |
|---|---:|
| Reconhecimento | 4 |
| Desenv. de recursos | 8 |
| Acesso inicial | 55 |
| Execução | 40 |
| Persistência | 94 |
| Escalação de privilégio | 124 |
| Furtividade | 44 |
| Enfraquecimento de defesas | 70 |
| Acesso a credenciais | 48 |
| Descoberta | 29 |
| Movimento lateral | 7 |
| Coleta | 25 |
| Comando e controle | 20 |
| Exfiltração | 13 |
| Impacto | 40 |

### Linguagens disponíveis

Em que formato você encontra regra pronta para esta tecnologia.

| Formato | Regras |
|---|---:|
| GCP | 277 |
| YARA-L | 161 |
| Suricata/Snort/Sagan | 127 |
| Panther | 102 |
| Elastic | 97 |
| Wazuh | 77 |
| Playbook | 53 |
| Sigma | 49 |
| Sentinel KQL | 47 |
| Splunk | 16 |

### Padrões de correlação (TCEM)

Como as regras decidem. Muitas de evento único = cobertura ampla mas ruidosa; sequências e novidade = mais contexto, mais exigência de dados.

| Padrão | Regras | O que significa |
|---|---:|---|
| Evento único | 611 | Um evento, sozinho, já tem sinal suficiente para chamar o analista. |
| Novidade / raridade | 109 | Compara com o que é normal: entidade, relação ou valor nunca (ou raramente) visto. |
| Sequência ordenada | 101 | Dois ou mais passos da mesma entidade, na ordem certa, dentro de uma janela. |
| Mudança de estado | 79 | O risco está na transição: algo era seguro e deixou de ser (desligado, rebaixado, alterado). |
| Limiar / acúmulo | 53 | O sinal está na repetição: N eventos por chave em uma janela. |
| Fluxo de resposta | 53 | Não detecta: orquestra o que fazer depois do alerta (SOAR). |

### Fontes que mais contribuem

| Fonte | Regras |
|---|---:|
| GCP security-analytics | 277 |
| Sagan rules (Quadrant) | 127 |
| Panther panther-analysis | 102 |
| Elastic detection-rules | 96 |
| Google SecOps / Chronicle | 83 |
| Chronicle rules (rowham) | 78 |
| Wazuh ruleset (oficial) | 76 |
| Cortex XSOAR (demisto/content) | 50 |
| SigmaHQ | 28 |
| Microsoft Sentinel (Analytic Rules) | 25 |

## 3. Técnicas mais cobertas

| Técnica | Regras nesta tecnologia |
|---|---:|
| [T1685](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1685) Disable or Modify Tools | 46 |
| [T1098](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1098) Account Manipulation | 33 |
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | 28 |
| [T1552](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1552) Unsecured Credentials | 26 |
| [T1078.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.004) Cloud Accounts | 26 |
| [T1548](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1548) Abuse Elevation Control Mechanism | 20 |
| [T1530](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1530) Data from Cloud Storage | 20 |
| [T1611](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1611) Escape to Host | 17 |
| [T1552.007](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1552.007) Container API | 14 |
| [T1531](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1531) Account Access Removal | 12 |
| [T1610](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1610) Deploy Container | 12 |
| [T1685.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1685.002) Disable or Modify Cloud Log | 12 |

## 4. Detecção pela ausência — o que ninguém está olhando (50 técnicas)

Técnicas do ATT&CK para IaaS **sem nenhuma regra nesta tecnologia**, ordenadas pelo número de grupos que as usam. A coluna "regras no catálogo" mostra se existe cobertura em outra tecnologia (ex.: EDR ou rede) que você pode adaptar.

| Técnica | Grupos que usam | Regras no catálogo (todas as tecnologias) |
|---|---:|---:|
| [T1082](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1082) System Information Discovery | 59 | 264 |
| [T1049](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1049) System Network Connections Discovery | 33 | 47 |
| [T1518.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1518.001) Security Software Discovery | 27 | 54 |
| [T1199](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1199) Trusted Relationship | 14 | 18 |
| [T1110.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1110.003) Password Spraying | 12 | 62 |
| [T1518](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1518) Software Discovery | 12 | 112 |
| [T1074.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1074.002) Remote Data Staging | 11 | 5 |
| [T1680](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1680) Local Storage Discovery | 10 | **0** |
| [T1213.006](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1213.006) Databases | 6 | 2 |
| [T1654](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1654) Log Enumeration | 5 | 3 |
| [T1036.010](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1036.010) Masquerade Account Name | 4 | 1 |
| [T1059.009](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.009) Cloud API | 4 | 11 |
| [T1110.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1110.001) Password Guessing | 4 | 63 |
| [T1496.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1496.001) Compute Hijacking | 4 | 2 |
| [T1087](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1087) Account Discovery | 3 | 547 |
| [T1098.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1098.004) SSH Authorized Keys | 3 | 16 |
| [T1201](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1201) Password Policy Discovery | 3 | 43 |
| [T1048](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1048) Exfiltration Over Alternative Protocol | 2 | 229 |
| [T1087.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1087.004) Cloud Account | 2 | 38 |
| [T1211](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1211) Exploitation for Stealth | 2 | 40 |

## 5. Quem mira esta plataforma

Grupos com mais técnicas registradas nesta plataforma e quantas delas você enxerga com as regras desta tecnologia. País atribuído pelo APT4ALL (afirmação de quem publicou).

| Grupo | Origem atribuída | Técnicas na plataforma | Com regra aqui | Exemplos sem regra |
|---|---|---:|---:|---|
| [Scattered Spider](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1015) `G1015` | Sem país atribuído | 22 | 18 | T1082, T1087, T1538, T1556.006 |
| [Storm-0501](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1053) `G1053` | Sem país atribuído | 20 | 15 | T1059.009, T1082, T1087.004, T1518.001 |
| [APT28](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0007) `G0007` | Rússia | 15 | 9 | T1074.002, T1110.001, T1110.003, T1199 |
| [APT29](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0016) `G0016` | Rússia | 15 | 9 | T1059.009, T1087.004, T1110.001, T1110.003 |
| [ShinyHunters](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1057) `G1057` | Sem país atribuído | 15 | 11 | T1059.009, T1082, T1213.006, T1619 |
| [VOID MANTICORE](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1055) `G1055` | Irã | 15 | 12 | T1082, T1110.001, T1199 |
| [Salt Typhoon](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1045) `G1045` | China | 13 | 8 | T1020.001, T1082, T1098.004, T1110.001 |
| [Sandworm Team](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0034) `G0034` | Rússia | 13 | 7 | T1049, T1082, T1199, T1213.006 |
| [TeamTNT](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0139) `G0139` | Sem país atribuído | 13 | 4 | T1048, T1049, T1059.009, T1082 |
| [LAPSUS$](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1004) `G1004` | Sem país atribuído | 12 | 10 | T1199, T1578.003 |
| [Volt Typhoon](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1017) `G1017` | China | 12 | 7 | T1049, T1518, T1614, T1654 |
| [APT38](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0082) `G0082` | Coreia do Norte | 11 | 6 | T1049, T1082, T1213.006, T1518 |
| [APT41](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0096) `G0096` | China | 11 | 8 | T1049, T1082, T1496.001 |
| [Ember Bear](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1003) `G1003` | Rússia | 10 | 7 | T1110.003, T1491.002, T1654 |

## 7. Cenário de referência TCEM

### Cloud Control Plane reference case

**Missão:** Preserve trusted administration of the cloud control plane and production tenancy.

**Privileged cloud session followed by organization-wide policy change** — Detect high-impact control-plane changes performed from privileged administrative context.

1. privileged_cloud_session — T1078 (1265 regras no catálogo)
2. cloud_policy_change — T1098 (831 regras no catálogo)

Contrato de telemetria: fonte **cloud control-plane audit**, campos exigidos actor.id, source.ip, target.resource, action, timestamp; **faltam target.resource** (status partial).
Especificação de detecção: padrão **ordered-sequence**, janela 30m, agrupado por actor.id. Alternativas benignas: approved change with expected authorization context.

## 9. Regras recomendadas para começar

Ranqueadas por portabilidade do formato, maturidade, severidade e por mapearem técnica ATT&CK.

| Regra | Formato | Fonte | Técnicas |
|---|---|---|---|
| [Suspicious Binary Writes Via AnyDesk](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A2d367498-5112-4ae5-a06a-96e7bc33a211) | Sigma | SigmaHQ | T1219.002 |
| [Multiple Cloud Secrets Accessed by Source Address](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A472b4944-d810-43cf-83dc-7d080ae1b8dd) | Elastic | Elastic detection-rules | T1555, T1555.006 |
| [Multi-Cloud CLI Token and Credential Access Commands](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A2b9a3b7a-0891-4a89-abbe-dca753c403cd) | Elastic | Elastic detection-rules | T1528, T1552, T1552.001 |
| [Splunk Enterprise PostgreSQL Recovery Endpoint Injection Artifacts](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A2a7823db-0bc2-48f6-aa2f-e6aef233c6dc) | Elastic | Elastic detection-rules | T1190 |
| [GKE Certificate Signing Request for Privileged Identity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A4159bec9-76ad-4cdc-a797-4a8572073bbe) | Elastic | Elastic detection-rules | T1098, T1098.006 |
| [GKE Pod Exec with Curl or Wget to HTTPS](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A3a68325b-6169-44c1-a5f0-0102ef82b6f1) | Elastic | Elastic detection-rules | T1105, T1609 |
| [GKE Pod Exec Cloud Instance Metadata Access](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ac8bf56cc-c648-4f88-bb4f-9e504d0779d1) | Elastic | Elastic detection-rules | T1552, T1552.005, T1609 |
| [GKE Secret get or list with Suspicious User Agent](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A0c04d82f-6def-4659-aa62-ed6355a51f39) | Elastic | Elastic detection-rules | T1552, T1552.007 |
| [GKE RBAC Wildcard Elevation on Existing Role](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A563a38e9-9790-4a6a-8889-24d26055b832) | Elastic | Elastic detection-rules | T1098, T1098.006 |
| [GCP IAM Custom Role Creation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Aaa8007f0-d1df-49ef-8520-407857594827) | Elastic | Elastic detection-rules | T1078, T1098, T1098.003 |
| [GKE Secrets List from Unusual Source AS Organization](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A4df2e3ae-3553-4194-b22e-3e5a6f71466e) | Elastic | Elastic detection-rules | T1552, T1552.007, T1613 |
| [GKE API Request Impersonating Privileged Identity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A00c2a946-bbe8-4345-941d-9ea13da91600) | Elastic | Elastic detection-rules | T1134 |
| [GKE Pod Exec Potential Reverse Shell](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ab5974c88-d584-451c-8ce3-6b19d7456199) | Elastic | Elastic detection-rules | T1059, T1095, T1609 |
| [GKE Certificate Signing Request API Client Signer Requested](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A1e344fba-a2f7-462b-aaec-d6c8f80d5a28) | Elastic | Elastic detection-rules | T1098, T1098.006 |
| [GKE Rapid Secret GET Activity Against Multiple Objects](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A4780a3d6-e6a7-490c-9afb-9c5fbb220b9a) | Elastic | Elastic detection-rules | T1552, T1552.007 |

## 10. Limites

- A tecnologia de cada regra é inferida por heurística sobre metadados e texto (techmap.py). Regras genéricas podem aparecer em várias tecnologias.
- "Sem regra" quer dizer sem regra pública neste catálogo, não sem detecção possível. Telemetria e contexto do seu ambiente decidem.
- Atribuição de país é afirmação das fontes reunidas pelo APT4ALL, não nossa.

---
Fontes: catálogo [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules), MITRE ATT&CK®, APT4ALL, Ransomware Tool Matrix (CC BY 4.0), TCEM, LLmInjection. Gerado em 2026-10-26.
