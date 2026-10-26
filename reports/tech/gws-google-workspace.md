# Google Workspace — relatório de regras de detecção

> **TLP:CLEAR** · 2026-10-26 · domínio **SaaS & colaboração** · plataforma ATT&CK **Office Suite** · lente TCEM **Identity & Access** · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#techno=gws)

## 1. A história em um parágrafo

O palco é **o Google Workspace — Gmail, Drive e a identidade Google da empresa**. O catálogo reúne **246 regras** que olham para cá — 196 de detecção, 14 de hunting, 4 assinaturas e 32 playbooks de resposta. Elas se concentram em **Persistência, Escalação de privilégio, Acesso inicial**. Das 79 técnicas do ATT&CK para a plataforma Office Suite, **27 (34%)** têm ao menos uma regra aqui e **52 não têm nenhuma** — é onde um atacante passa sem ser visto. Entre os grupos com mais técnicas nesta plataforma estão Scattered Spider, APT28, APT29.

**Lente TCEM — Identity & Access.** Authentication, authorization, privilege, federation, machine identity and administrative trust. Para observar: sign-in logs, privilege changes, token events, identity administration. Arquitetura a mapear: identity providers, privileged roles, service principals, federation, recovery access.

## 2. Números

| Indicador | Valor |
|---|---:|
| Regras | 246 |
| detecção | 196 |
| playbook | 32 |
| hunting | 14 |
| assinatura | 4 |
| Técnicas ATT&CK distintas | 58 |
| Cobertura da plataforma Office Suite | 27/79 (34%) |

### Por tática

| Tática | Regras |
|---|---:|
| Reconhecimento | 2 |
| Desenv. de recursos | 6 |
| Acesso inicial | 37 |
| Execução | 9 |
| Persistência | 63 |
| Escalação de privilégio | 56 |
| Furtividade | 23 |
| Enfraquecimento de defesas | 17 |
| Acesso a credenciais | 23 |
| Descoberta | 4 |
| Movimento lateral | 6 |
| Coleta | 20 |
| Comando e controle | 4 |
| Exfiltração | 18 |
| Impacto | 10 |

### Linguagens disponíveis

Em que formato você encontra regra pronta para esta tecnologia.

| Formato | Regras |
|---|---:|
| Panther | 61 |
| YARA-L | 47 |
| Elastic | 38 |
| Playbook | 32 |
| Sentinel KQL | 25 |
| Sigma | 23 |
| Splunk | 16 |
| Suricata/Snort/Sagan | 4 |

### Padrões de correlação (TCEM)

Como as regras decidem. Muitas de evento único = cobertura ampla mas ruidosa; sequências e novidade = mais contexto, mais exigência de dados.

| Padrão | Regras | O que significa |
|---|---:|---|
| Evento único | 98 | Um evento, sozinho, já tem sinal suficiente para chamar o analista. |
| Novidade / raridade | 40 | Compara com o que é normal: entidade, relação ou valor nunca (ou raramente) visto. |
| Fluxo de resposta | 32 | Não detecta: orquestra o que fazer depois do alerta (SOAR). |
| Limiar / acúmulo | 28 | O sinal está na repetição: N eventos por chave em uma janela. |
| Mudança de estado | 24 | O risco está na transição: algo era seguro e deixou de ser (desligado, rebaixado, alterado). |
| Sequência ordenada | 24 | Dois ou mais passos da mesma entidade, na ordem certa, dentro de uma janela. |

### Fontes que mais contribuem

| Fonte | Regras |
|---|---:|
| Panther panther-analysis | 61 |
| Elastic detection-rules | 35 |
| Google SecOps / Chronicle | 24 |
| Chronicle rules (rowham) | 23 |
| Cortex XSOAR (demisto/content) | 17 |
| Splunk security_content | 16 |
| Microsoft Sentinel (Hunting Queries) | 14 |
| OpenSearch Security Analytics | 13 |
| Microsoft Sentinel (Analytic Rules) | 11 |
| SigmaHQ | 10 |

## 3. Técnicas mais cobertas

| Técnica | Regras nesta tecnologia |
|---|---:|
| [T1098](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1098) Account Manipulation | 31 |
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | 18 |
| [T1078.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.004) Cloud Accounts | 17 |
| [T1567](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1567) Exfiltration Over Web Service | 17 |
| [T1098.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1098.003) Additional Cloud Roles | 12 |
| [T1685](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1685) Disable or Modify Tools | 9 |
| [T1566](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1566) Phishing | 9 |
| [T1213](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1213) Data from Information Repositories | 7 |
| [T1556](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1556) Modify Authentication Process | 6 |
| [T1484](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1484) Domain or Tenant Policy Modification | 6 |
| [T1586.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1586.003) Cloud Accounts | 6 |
| [T1565](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1565) Data Manipulation | 5 |

## 4. Detecção pela ausência — o que ninguém está olhando (52 técnicas)

Técnicas do ATT&CK para Office Suite **sem nenhuma regra nesta tecnologia**, ordenadas pelo número de grupos que as usam. A coluna "regras no catálogo" mostra se existe cobertura em outra tecnologia (ex.: EDR ou rede) que você pode adaptar.

| Técnica | Grupos que usam | Regras no catálogo (todas as tecnologias) |
|---|---:|---:|
| [T1119](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1119) Automated Collection | 21 | 72 |
| [T1657](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1657) Financial Theft | 19 | 2 |
| [T1684.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1684.001) Impersonation | 18 | 1 |
| [T1199](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1199) Trusted Relationship | 14 | 18 |
| [T1114.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1114.002) Remote Email Collection | 13 | 11 |
| [T1110.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1110.003) Password Spraying | 12 | 62 |
| [T1213.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1213.002) Sharepoint | 8 | 7 |
| [T1539](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1539) Steal Web Session Cookie | 8 | 54 |
| [T1069](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1069) Permission Groups Discovery | 6 | 242 |
| [T1080](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1080) Taint Shared Content | 5 | 12 |
| [T1213.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1213.005) Messaging Applications | 5 | **0** |
| [T1036.010](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1036.010) Masquerade Account Name | 4 | 1 |
| [T1059.009](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.009) Cloud API | 4 | 11 |
| [T1070](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1070) Indicator Removal | 4 | 516 |
| [T1078.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.001) Default Accounts | 4 | 16 |
| [T1087.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1087.003) Email Account | 4 | 1 |
| [T1110.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1110.001) Password Guessing | 4 | 63 |
| [T1110.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1110.002) Password Cracking | 4 | 11 |
| [T1021.007](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1021.007) Cloud Services | 3 | 20 |
| [T1098.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1098.002) Additional Email Delegate Permissions | 3 | 10 |

## 5. Quem mira esta plataforma

Grupos com mais técnicas registradas nesta plataforma e quantas delas você enxerga com as regras desta tecnologia. País atribuído pelo APT4ALL (afirmação de quem publicou).

| Grupo | Origem atribuída | Técnicas na plataforma | Com regra aqui | Exemplos sem regra |
|---|---|---:|---:|---|
| [Scattered Spider](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1015) `G1015` | Sem país atribuído | 20 | 11 | T1021.007, T1069, T1070.008, T1213.005 |
| [APT28](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0007) `G0007` | Rússia | 16 | 7 | T1098.002, T1110.001, T1110.003, T1114.002 |
| [APT29](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0016) `G0016` | Rússia | 16 | 6 | T1021.007, T1059.009, T1087.004, T1098.002 |
| [VOID MANTICORE](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1055) `G1055` | Irã | 13 | 6 | T1110.001, T1114.002, T1119, T1199 |
| [LAPSUS$](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1004) `G1004` | Sem país atribuído | 12 | 7 | T1199, T1213.002, T1213.005, T1552.008 |
| [NIMBUS MANTICORE](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1059) `G1059` | — | 11 | 6 | T1110.003, T1199, T1213.002, T1213.005 |
| [ShinyHunters](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1057) `G1057` | Sem país atribuído | 11 | 7 | T1059.009, T1069.003, T1657, T1684 |
| [Storm-0501](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1053) `G1053` | Sem país atribuído | 10 | 5 | T1021.007, T1059.009, T1087.004, T1526 |
| [HAFNIUM](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0125) `G0125` | China | 9 | 4 | T1110.003, T1114.002, T1119, T1199 |
| [Kimsuky](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0094) `G0094` | Coreia do Norte | 8 | 4 | T1114.002, T1539, T1657, T1684.001 |
| [Magic Hound](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0059) `G0059` | Irã | 8 | 3 | T1036.010, T1078.001, T1087.003, T1098.002 |
| [APT38](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0082) `G0082` | Coreia do Norte | 7 | 4 | T1213.005, T1657, T1684.001 |
| [APT42](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1044) `G1044` | Irã | 7 | 2 | T1070, T1070.008, T1539, T1684.001 |
| [Chimera](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0114) `G0114` | China | 7 | 2 | T1110.003, T1114.002, T1119, T1201 |

## 7. Cenário de referência TCEM

### Enterprise Identity Control Plane

**Missão:** Maintain trusted access to business-critical services and preserve recoverability.

**Trusted administration to enterprise identity control** — Reach the enterprise identity control plane through an existing privileged relationship.

1. Use a privileged account or session — T1078 (1265 regras no catálogo)
2. Modify account or identity configuration — T1098 (831 regras no catálogo)

Contrato de telemetria: fonte **enterprise identity audit telemetry**, campos exigidos user.id, source.ip, target.resource, action, timestamp; **faltam target.resource** (status partial).
Especificação de detecção: padrão **ordered-sequence**, janela 30m, agrupado por user.id. Alternativas benignas: approved administrative change, break-glass recovery with an authorized ticket.

## 9. Regras recomendadas para começar

Ranqueadas por portabilidade do formato, maturidade, severidade e por mapearem técnica ATT&CK.

| Regra | Formato | Fonte | Técnicas |
|---|---|---|---|
| [Google Workspace Impossible Travel Login](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Aaff74d85-5bfa-4ff1-ace2-4e3995a37cfa) | Elastic | Elastic detection-rules | T1078, T1078.004, T1528 |
| [Google Workspace Suspended User Account Renewed](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A00678712-b2df-11ed-afe9-f661ea17fbcc) | Elastic | Elastic detection-rules | T1078, T1078.004, T1098 |
| [Google Workspace Gmail Routing or Forwarding Rule Created or Modified](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A9510add4-3392-11ed-bd01-f661ea17fbce) | Elastic | Elastic detection-rules | T1114, T1114.003 |
| [Google Workspace Role Modified](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A6f435062-b7fc-4af9-acea-5b1ead65c5a5) | Elastic | Elastic detection-rules | T1098 |
| [Google Workspace Device Registration After OAuth from Suspicious ASN](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A012bfca7-45cb-4507-a3ba-3777167f8b81) | Elastic | Elastic detection-rules | T1098, T1098.005, T1566 |
| [Domain Added to Google Workspace Trusted Domains](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Acf549724-c577-4fd6-8f9b-d1b8ec519ec0) | Elastic | Elastic detection-rules | T1484, T1484.002, T1685 |
| [Google Workspace Admin Role Assigned to a User or Group](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A68994a6c-c7ba-4e82-b476-26a26877adf6) | Elastic | Elastic detection-rules | T1098, T1098.003 |
| [Google Workspace Drive Encryption Key(s) Accessed from Anonymous User](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A980b70a0-c820-11ed-8799-f661ea17fbcc) | Elastic | Elastic detection-rules | T1530, T1552, T1552.004 |
| [Google Workspace 2SV Policy Disabled By User](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A5e161522-2545-11ed-ac47-f661ea17fbce) | Elastic | Elastic detection-rules | T1556 |
| [Google Workspace API Access Granted via Domain-Wide Delegation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Aacbc8bb9-2486-49a8-8779-45fb5f9a93ee) | Elastic | Elastic detection-rules | T1098 |
| [Application Added to Google Workspace Domain](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A785a404b-75aa-4ffd-8be5-3334a5a544dd) | Elastic | Elastic detection-rules | T1098, T1098.001 |
| [Google Workspace MFA Enforcement Disabled For Organization](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Acad4500a-abd7-4ef3-b5d3-95524de7cfe1) | Elastic | Elastic detection-rules | T1531, T1556, T1556.006 |
| [Google Workspace Object Copied from External Drive with App Consent](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Af33e68a4-bd19-11ed-b02f-f661ea17fbcc) | Elastic | Elastic detection-rules | T1098, T1098.001, T1204 |
| [Google Workspace Application Access Level Modified](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A22f2fb54-5312-435d-852f-7c74f81684ca) | Sigma | SigmaHQ | T1098.003 |
| [Google Workspace User Granted Admin Privileges](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A2d1b83e4-17c6-4896-a37b-29140b40a788) | Sigma | SigmaHQ | T1098 |

## 10. Limites

- A tecnologia de cada regra é inferida por heurística sobre metadados e texto (techmap.py). Regras genéricas podem aparecer em várias tecnologias.
- "Sem regra" quer dizer sem regra pública neste catálogo, não sem detecção possível. Telemetria e contexto do seu ambiente decidem.
- Atribuição de país é afirmação das fontes reunidas pelo APT4ALL, não nossa.

---
Fontes: catálogo [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules), MITRE ATT&CK®, APT4ALL, Ransomware Tool Matrix (CC BY 4.0), TCEM, LLmInjection. Gerado em 2026-10-26.
