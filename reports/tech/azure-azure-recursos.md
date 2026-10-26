# Azure (recursos) — relatório de regras de detecção

> **TLP:CLEAR** · 2026-10-26 · domínio **Nuvem** · plataforma ATT&CK **IaaS** · lente TCEM **Cloud & Multi-Cloud** · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#techno=azure)

## 1. A história em um parágrafo

O palco é **a assinatura Azure — recursos, cofres de chaves e políticas da nuvem Microsoft**. O catálogo reúne **1,878 regras** que olham para cá — 899 de detecção, 198 de hunting, 208 assinaturas e 573 playbooks de resposta. Elas se concentram em **Persistência, Escalação de privilégio, Acesso inicial**. Das 104 técnicas do ATT&CK para a plataforma IaaS, **70 (67%)** têm ao menos uma regra aqui e **34 não têm nenhuma** — é onde um atacante passa sem ser visto. Entre os grupos com mais técnicas nesta plataforma estão Scattered Spider, Storm-0501, APT28.

**Lente TCEM — Cloud & Multi-Cloud.** Cloud control planes, workloads, identities, management APIs, cross-cloud trust and SaaS dependencies. Para observar: cloud audit, identity logs, control-plane changes, workload activity. Arquitetura a mapear: control planes, cloud identities, organization hierarchy, workload identities, management APIs.

## 2. Números

| Indicador | Valor |
|---|---:|
| Regras | 1,878 |
| detecção | 899 |
| playbook | 573 |
| assinatura | 208 |
| hunting | 198 |
| Técnicas ATT&CK distintas | 161 |
| Cobertura da plataforma IaaS | 70/104 (67%) |

### Por tática

| Tática | Regras |
|---|---:|
| Reconhecimento | 10 |
| Desenv. de recursos | 11 |
| Acesso inicial | 275 |
| Execução | 72 |
| Persistência | 386 |
| Escalação de privilégio | 376 |
| Furtividade | 256 |
| Enfraquecimento de defesas | 103 |
| Acesso a credenciais | 209 |
| Descoberta | 45 |
| Movimento lateral | 53 |
| Coleta | 31 |
| Comando e controle | 47 |
| Exfiltração | 26 |
| Impacto | 70 |

### Linguagens disponíveis

Em que formato você encontra regra pronta para esta tecnologia.

| Formato | Regras |
|---|---:|
| Playbook | 573 |
| Sentinel KQL | 360 |
| Sigma | 352 |
| Suricata/Snort/Sagan | 208 |
| Elastic | 192 |
| Panther | 112 |
| KQL hunting | 37 |
| Splunk | 22 |
| YARA-L | 13 |
| Wazuh | 9 |

### Padrões de correlação (TCEM)

Como as regras decidem. Muitas de evento único = cobertura ampla mas ruidosa; sequências e novidade = mais contexto, mais exigência de dados.

| Padrão | Regras | O que significa |
|---|---:|---|
| Evento único | 810 | Um evento, sozinho, já tem sinal suficiente para chamar o analista. |
| Fluxo de resposta | 573 | Não detecta: orquestra o que fazer depois do alerta (SOAR). |
| Novidade / raridade | 299 | Compara com o que é normal: entidade, relação ou valor nunca (ou raramente) visto. |
| Limiar / acúmulo | 95 | O sinal está na repetição: N eventos por chave em uma janela. |
| Mudança de estado | 72 | O risco está na transição: algo era seguro e deixou de ser (desligado, rebaixado, alterado). |
| Sequência ordenada | 28 | Dois ou mais passos da mesma entidade, na ordem certa, dentro de uma janela. |
| Assinatura de conteúdo | 1 | Casa bytes/strings dentro de arquivo, memória ou pacote, não eventos de log. |

### Fontes que mais contribuem

| Fonte | Regras |
|---|---:|
| awesome-playbooks · ms_azure | 509 |
| OpenSearch Security Analytics | 212 |
| Microsoft Sentinel (Analytic Rules) | 210 |
| Sagan rules (Quadrant) | 207 |
| Elastic detection-rules | 181 |
| Microsoft Sentinel (Hunting Queries) | 150 |
| SigmaHQ | 140 |
| Panther panther-analysis | 112 |
| Cortex XSOAR (demisto/content) | 59 |
| Bert-JanP Hunting Queries | 37 |

## 3. Técnicas mais cobertas

| Técnica | Regras nesta tecnologia |
|---|---:|
| [T1078.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.004) Cloud Accounts | 151 |
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | 139 |
| [T1098](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1098) Account Manipulation | 62 |
| [T1110](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1110) Brute Force | 43 |
| [T1528](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1528) Steal Application Access Token | 39 |
| [T1485](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1485) Data Destruction | 38 |
| [T1552](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1552) Unsecured Credentials | 36 |
| [T1550](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1550) Use Alternate Authentication Material | 33 |
| [T1550.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1550.001) Application Access Token | 32 |
| [T1556](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1556) Modify Authentication Process | 30 |
| [T1098.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1098.003) Additional Cloud Roles | 29 |
| [T1685](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1685) Disable or Modify Tools | 27 |

## 4. Detecção pela ausência — o que ninguém está olhando (34 técnicas)

Técnicas do ATT&CK para IaaS **sem nenhuma regra nesta tecnologia**, ordenadas pelo número de grupos que as usam. A coluna "regras no catálogo" mostra se existe cobertura em outra tecnologia (ex.: EDR ou rede) que você pode adaptar.

| Técnica | Grupos que usam | Regras no catálogo (todas as tecnologias) |
|---|---:|---:|
| [T1049](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1049) System Network Connections Discovery | 33 | 47 |
| [T1518.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1518.001) Security Software Discovery | 27 | 54 |
| [T1119](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1119) Automated Collection | 21 | 72 |
| [T1518](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1518) Software Discovery | 12 | 112 |
| [T1074.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1074.002) Remote Data Staging | 11 | 5 |
| [T1680](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1680) Local Storage Discovery | 10 | **0** |
| [T1213.006](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1213.006) Databases | 6 | 2 |
| [T1074](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1074) Data Staged | 5 | 82 |
| [T1654](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1654) Log Enumeration | 5 | 3 |
| [T1036.010](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1036.010) Masquerade Account Name | 4 | 1 |
| [T1078.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.001) Default Accounts | 4 | 16 |
| [T1496.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1496.001) Compute Hijacking | 4 | 2 |
| [T1098.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1098.004) SSH Authorized Keys | 3 | 16 |
| [T1211](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1211) Exploitation for Stealth | 2 | 40 |
| [T1491.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1491.002) External Defacement | 2 | 1 |
| [T1614](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1614) System Location Discovery | 2 | 31 |
| [T1020.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1020.001) Traffic Duplication | 1 | **0** |
| [T1204.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1204.003) Malicious Image | 1 | 3 |
| [T1538](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1538) Cloud Service Dashboard | 1 | 4 |
| [T1485.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1485.001) Lifecycle-Triggered Deletion | 0 | 3 |

## 5. Quem mira esta plataforma

Grupos com mais técnicas registradas nesta plataforma e quantas delas você enxerga com as regras desta tecnologia. País atribuído pelo APT4ALL (afirmação de quem publicou).

| Grupo | Origem atribuída | Técnicas na plataforma | Com regra aqui | Exemplos sem regra |
|---|---|---:|---:|---|
| [Scattered Spider](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1015) `G1015` | Sem país atribuído | 22 | 20 | T1074, T1538 |
| [Storm-0501](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1053) `G1053` | Sem país atribuído | 20 | 19 | T1518.001 |
| [APT28](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0007) `G0007` | Rússia | 15 | 12 | T1074.002, T1119, T1211 |
| [APT29](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0016) `G0016` | Rússia | 15 | 15 | — |
| [ShinyHunters](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1057) `G1057` | Sem país atribuído | 15 | 14 | T1213.006 |
| [VOID MANTICORE](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1055) `G1055` | Irã | 15 | 13 | T1074, T1119 |
| [Salt Typhoon](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1045) `G1045` | China | 13 | 11 | T1020.001, T1098.004 |
| [Sandworm Team](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0034) `G0034` | Rússia | 13 | 10 | T1049, T1213.006, T1491.002 |
| [TeamTNT](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0139) `G0139` | Sem país atribuído | 13 | 7 | T1049, T1098.004, T1204.003, T1496.001 |
| [LAPSUS$](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1004) `G1004` | Sem país atribuído | 12 | 12 | — |
| [Volt Typhoon](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1017) `G1017` | China | 12 | 6 | T1049, T1074, T1518, T1614 |
| [APT38](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0082) `G0082` | Coreia do Norte | 11 | 7 | T1049, T1213.006, T1518, T1518.001 |
| [APT41](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0096) `G0096` | China | 11 | 9 | T1049, T1496.001 |
| [Ember Bear](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1003) `G1003` | Rússia | 10 | 6 | T1078.001, T1119, T1491.002, T1654 |

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
| [Privilege Role Sign-In Outside Expected Controls](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acf1e5687-84e1-41af-97a9-158094efef53) | Sigma | SigmaHQ | T1078 |
| [OMIGOD SCX RunAsProvider ExecuteShellCommand](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A21541900-27a9-4454-9c4c-3f0a4240344a) | Sigma | SigmaHQ | T1068, T1190, T1203 |
| [Renamed BrowserCore.EXE Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A8a4519e8-e64a-40b6-ae85-ba8ad2177559) | Sigma | SigmaHQ | T1036.003, T1528 |
| [HybridConnectionManager Service Installation - Registry](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aac8866c7-ce44-46fd-8c17-b24acff96ca8) | Sigma | SigmaHQ | T1608 |
| [DNS HybridConnectionManager Service Bus](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A7bd3902d-8b8b-4dd4-838a-c6862d40150d) | Sigma | SigmaHQ | T1554 |
| [Potential MFA Bypass Using Legacy Client Authentication](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A53bb4f7f-48a8-4475-ac30-5a82ddfdf6fc) | Sigma | SigmaHQ | T1078.004, T1110 |
| [Discovery Using AzureHound](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A35b781cc-1a08-4a5a-80af-42fd7c315c6b) | Sigma | SigmaHQ | T1087.004, T1526 |
| [Suspicious SignIns From A Non Registered Device](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A572b12d4-9062-11ed-a1eb-0242ac120002) | Sigma | SigmaHQ | T1078 |
| [Sign-in Failure Due to Conditional Access Requirements Not Met](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab4a6d707-9430-4f5f-af68-0337f52d5c42) | Sigma | SigmaHQ | T1078.004, T1110 |
| [Use of Legacy Authentication Protocols](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A60f6535a-760f-42a9-be3f-c9a0a025906e) | Sigma | SigmaHQ | T1078.004, T1110 |
| [Sign-ins from Non-Compliant Devices](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4f77e1d7-3982-4ee0-8489-abf2d6b75284) | Sigma | SigmaHQ | T1078.004 |
| [Roles Activation Doesn't Require MFA](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A94a66f46-5b64-46ce-80b2-75dcbe627cc0) | Sigma | SigmaHQ | T1078 |
| [Too Many Global Admins](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A7bbc309f-e2b1-4eb1-8369-131a367d67d3) | Sigma | SigmaHQ | T1078 |
| [Stale Accounts In A Privileged Role](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae402c26a-267a-45bd-9615-bd9ceda6da85) | Sigma | SigmaHQ | T1078 |
| [Roles Assigned Outside PIM](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab1bc08d1-8224-4758-a0e6-fbcfc98c73bb) | Sigma | SigmaHQ | T1078 |

## 10. Limites

- A tecnologia de cada regra é inferida por heurística sobre metadados e texto (techmap.py). Regras genéricas podem aparecer em várias tecnologias.
- "Sem regra" quer dizer sem regra pública neste catálogo, não sem detecção possível. Telemetria e contexto do seu ambiente decidem.
- Atribuição de país é afirmação das fontes reunidas pelo APT4ALL, não nossa.

---
Fontes: catálogo [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules), MITRE ATT&CK®, APT4ALL, Ransomware Tool Matrix (CC BY 4.0), TCEM, LLmInjection. Gerado em 2026-10-26.
