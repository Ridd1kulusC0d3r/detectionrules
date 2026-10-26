# ICS / OT — relatório de regras de detecção

> **TLP:CLEAR** · 2026-10-26 · domínio **OT & IoT** · plataforma ATT&CK **ICS** · lente TCEM **ICS / OT** · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#techno=ot)

## 1. A história em um parágrafo

O palco é **o ambiente industrial (ICS/OT) — onde um comando errado vira problema físico**. O catálogo reúne **96 regras** que olham para cá — 23 de detecção, 12 de hunting, 48 assinaturas e 13 playbooks de resposta. Elas se concentram em **Persistência, Acesso inicial, Descoberta**. Das 0 técnicas do ATT&CK para a plataforma ICS, **0 (None%)** têm ao menos uma regra aqui e **0 não têm nenhuma** — é onde um atacante passa sem ser visto. 

**Lente TCEM — ICS / OT.** Industrial control, safety, process availability, engineering access, segmentation and recovery. Para observar: asset inventory, industrial network telemetry, remote access, configuration changes. Arquitetura a mapear: control zones, engineering stations, remote access, safety systems, historians.

## 2. Números

| Indicador | Valor |
|---|---:|
| Regras | 96 |
| assinatura | 48 |
| detecção | 23 |
| playbook | 13 |
| hunting | 12 |
| Técnicas ATT&CK distintas | 11 |
| Cobertura da plataforma ICS | 0/0 (None%) |

### Por tática

| Tática | Regras |
|---|---:|
| Reconhecimento | 2 |
| Acesso inicial | 7 |
| Persistência | 9 |
| Escalação de privilégio | 2 |
| Furtividade | 2 |
| Enfraquecimento de defesas | 2 |
| Acesso a credenciais | 1 |
| Descoberta | 3 |
| Exfiltração | 1 |
| Impacto | 2 |

### Linguagens disponíveis

Em que formato você encontra regra pronta para esta tecnologia.

| Formato | Regras |
|---|---:|
| Suricata/Snort/Sagan | 48 |
| Sentinel KQL | 31 |
| Playbook | 13 |
| YARA-L | 2 |
| Splunk | 2 |

### Padrões de correlação (TCEM)

Como as regras decidem. Muitas de evento único = cobertura ampla mas ruidosa; sequências e novidade = mais contexto, mais exigência de dados.

| Padrão | Regras | O que significa |
|---|---:|---|
| Evento único | 76 | Um evento, sozinho, já tem sinal suficiente para chamar o analista. |
| Fluxo de resposta | 13 | Não detecta: orquestra o que fazer depois do alerta (SOAR). |
| Novidade / raridade | 5 | Compara com o que é normal: entidade, relação ou valor nunca (ou raramente) visto. |
| Limiar / acúmulo | 2 | O sinal está na repetição: N eventos por chave em uma janela. |

### Fontes que mais contribuem

| Fonte | Regras |
|---|---:|
| Sagan rules (Quadrant) | 48 |
| Microsoft Sentinel (Analytic Rules) | 21 |
| Microsoft Sentinel (Hunting Queries) | 10 |
| awesome-playbooks · cisa | 6 |
| Cortex XSOAR (demisto/content) | 4 |
| Splunk analytic stories | 2 |
| awesome-playbooks · ms_azure | 2 |
| Google SecOps / Chronicle | 1 |
| Chronicle rules (rowham) | 1 |
| awesome-playbooks · demisto | 1 |

## 3. Técnicas mais cobertas

| Técnica | Regras nesta tecnologia |
|---|---:|
| [T1133](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1133) External Remote Services | 5 |
| [T1082](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1082) System Information Discovery | 2 |
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | 2 |
| [T1112](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1112) Modify Registry | 2 |
| [T1595](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1595) Active Scanning | 1 |
| [T1135](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1135) Network Share Discovery | 1 |
| [T1020](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1020) Automated Exfiltration | 1 |
| [T1595.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1595.001) Scanning IP Blocks | 1 |
| [T1110.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1110.001) Password Guessing | 1 |
| [T1078.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.001) Default Accounts | 1 |
| [T1499](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1499) Endpoint Denial of Service | 1 |

## 4. Detecção pela ausência — o que ninguém está olhando (0 técnicas)

Técnicas do ATT&CK para ICS **sem nenhuma regra nesta tecnologia**, ordenadas pelo número de grupos que as usam. A coluna "regras no catálogo" mostra se existe cobertura em outra tecnologia (ex.: EDR ou rede) que você pode adaptar.

| Técnica | Grupos que usam | Regras no catálogo (todas as tecnologias) |
|---|---:|---:|

## 7. Cenário de referência TCEM

### ICS OT Resilience reference case

**Missão:** Preserve safe, recoverable industrial control while maintaining visibility of engineering changes.

**Remote engineering access followed by control configuration change** — Detect consequential engineering changes associated with remote administrative context.

1. remote_engineering_session — T1078 (1265 regras no catálogo)
2. control_config_change — T1021 (954 regras no catálogo)

Contrato de telemetria: fonte **industrial engineering audit**, campos exigidos user.id, source.ip, target.resource, action, timestamp (status ready).
Especificação de detecção: padrão **ordered-sequence**, janela 30m, agrupado por user.id. Alternativas benignas: approved change with expected authorization context.

## 9. Regras recomendadas para começar

Ranqueadas por portabilidade do formato, maturidade, severidade e por mapearem técnica ATT&CK.

| Regra | Formato | Fonte | Técnicas |
|---|---|---|---|
| [Oracle - Malicious user agent](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A51d050ee-5740-11ec-bf63-0242ac130002) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) | T1133 |
| [Claroty - Threat detected](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A731e5ac4-7fe1-4b06-9941-532f2e008bb3) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) | T1595 |
| [Claroty - Policy violation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A3b22ac47-e02c-4599-a37a-57f965de17be) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) | T1135 |
| [Claroty - Suspicious file transfer](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A5cf35bad-677f-4c23-8927-1611e7ff6f28) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) | T1020 |
| [Claroty - New Asset](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A6c29b611-ce69-4016-bf99-eca639fee1f5) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) | T1082, T1133 |
| [Claroty - Multiple failed logins to same destinations](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A1c2310ef-19bf-4caf-b2b0-a4c983932fa5) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) | T1133 |
| [Claroty - Login to uncommon location](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3Ae7dbcbc3-b18f-4635-b27c-718195c369f1) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) | T1133 |
| [Claroty - Critical Events](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-hunting-queries%3A%3Aa81f3a44-049c-409d-8b98-b78aa256dacf) | Sentinel KQL | Microsoft Sentinel (Hunting Queries) | T0889 |
| [Claroty - User failed logins](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-hunting-queries%3A%3A917364b7-2925-4c5d-a27c-64137a3b75b5) | Sentinel KQL | Microsoft Sentinel (Hunting Queries) | T1078, T1110.001 |
| [Claroty - PLC logins](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-hunting-queries%3A%3A15569b45-4c34-4693-bf99-841e76b5da65) | Sentinel KQL | Microsoft Sentinel (Hunting Queries) | T1078, T1078.001 |
| [Claroty - Unapproved access](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-hunting-queries%3A%3Ade0fca32-85f3-45df-872e-41e980e5d8d3) | Sentinel KQL | Microsoft Sentinel (Hunting Queries) | T1133 |
| [Claroty - Network scan targets](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-hunting-queries%3A%3A8e70ddf9-32c3-4acd-9cb9-59570344335e) | Sentinel KQL | Microsoft Sentinel (Hunting Queries) | T1595.001 |
| [Claroty - Unresolved alerts](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-hunting-queries%3A%3Afad6cb81-9a05-4acb-9c5b-a7c62af28034) | Sentinel KQL | Microsoft Sentinel (Hunting Queries) | T1082, T1499 |
| [ekanssnake_ransomware_sysmon_detection](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=google-secops-chronicle%3A%3Aca28e1c1bb2a) | YARA-L | Google SecOps / Chronicle | T1112 |

## 10. Limites

- A tecnologia de cada regra é inferida por heurística sobre metadados e texto (techmap.py). Regras genéricas podem aparecer em várias tecnologias.
- "Sem regra" quer dizer sem regra pública neste catálogo, não sem detecção possível. Telemetria e contexto do seu ambiente decidem.
- Atribuição de país é afirmação das fontes reunidas pelo APT4ALL, não nossa.

---
Fontes: catálogo [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules), MITRE ATT&CK®, APT4ALL, Ransomware Tool Matrix (CC BY 4.0), TCEM, LLmInjection. Gerado em 2026-10-26.
