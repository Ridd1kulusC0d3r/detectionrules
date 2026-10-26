# Contêineres (Docker/runtime) — relatório de regras de detecção

> **TLP:CLEAR** · 2026-10-26 · domínio **Contêineres** · plataforma ATT&CK **Containers** · lente TCEM **Cloud & Multi-Cloud** · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#techno=containers)

## 1. A história em um parágrafo

O palco é **os contêineres em execução — processos isolados que compartilham o mesmo kernel**. O catálogo reúne **497 regras** que olham para cá — 366 de detecção, 13 de hunting, 5 assinaturas e 113 playbooks de resposta. Elas se concentram em **Execução, Escalação de privilégio, Persistência**. Das 48 técnicas do ATT&CK para a plataforma Containers, **29 (60%)** têm ao menos uma regra aqui e **19 não têm nenhuma** — é onde um atacante passa sem ser visto. Entre os grupos com mais técnicas nesta plataforma estão TeamTNT, APT28, Salt Typhoon.

**Lente TCEM — Cloud & Multi-Cloud.** Cloud control planes, workloads, identities, management APIs, cross-cloud trust and SaaS dependencies. Para observar: cloud audit, identity logs, control-plane changes, workload activity. Arquitetura a mapear: control planes, cloud identities, organization hierarchy, workload identities, management APIs.

## 2. Números

| Indicador | Valor |
|---|---:|
| Regras | 497 |
| detecção | 366 |
| playbook | 113 |
| hunting | 13 |
| assinatura | 5 |
| Técnicas ATT&CK distintas | 125 |
| Cobertura da plataforma Containers | 29/48 (60%) |

### Por tática

| Tática | Regras |
|---|---:|
| Reconhecimento | 3 |
| Acesso inicial | 11 |
| Execução | 102 |
| Persistência | 43 |
| Escalação de privilégio | 90 |
| Furtividade | 33 |
| Enfraquecimento de defesas | 16 |
| Acesso a credenciais | 29 |
| Descoberta | 40 |
| Movimento lateral | 12 |
| Coleta | 13 |
| Comando e controle | 25 |
| Exfiltração | 9 |
| Impacto | 20 |

### Linguagens disponíveis

Em que formato você encontra regra pronta para esta tecnologia.

| Formato | Regras |
|---|---:|
| Elastic | 120 |
| Playbook | 113 |
| Falco | 96 |
| Wazuh | 68 |
| Splunk | 31 |
| Sigma | 30 |
| Panther | 16 |
| Sentinel KQL | 10 |
| YARA-L | 8 |
| Suricata/Snort/Sagan | 5 |

### Padrões de correlação (TCEM)

Como as regras decidem. Muitas de evento único = cobertura ampla mas ruidosa; sequências e novidade = mais contexto, mais exigência de dados.

| Padrão | Regras | O que significa |
|---|---:|---|
| Evento único | 250 | Um evento, sozinho, já tem sinal suficiente para chamar o analista. |
| Fluxo de resposta | 113 | Não detecta: orquestra o que fazer depois do alerta (SOAR). |
| Novidade / raridade | 103 | Compara com o que é normal: entidade, relação ou valor nunca (ou raramente) visto. |
| Mudança de estado | 15 | O risco está na transição: algo era seguro e deixou de ser (desligado, rebaixado, alterado). |
| Sequência ordenada | 15 | Dois ou mais passos da mesma entidade, na ordem certa, dentro de uma janela. |
| Limiar / acúmulo | 1 | O sinal está na repetição: N eventos por chave em uma janela. |

### Fontes que mais contribuem

| Fonte | Regras |
|---|---:|
| Elastic detection-rules | 114 |
| Falco rules | 96 |
| Wazuh ruleset (oficial) | 67 |
| Splunk SOAR / Phantom playbooks | 66 |
| Splunk security_content | 26 |
| awesome-playbooks · splunk | 22 |
| SigmaHQ | 18 |
| Panther panther-analysis | 16 |
| Cortex XSOAR (demisto/content) | 16 |
| OpenSearch Security Analytics | 12 |

## 3. Técnicas mais cobertas

| Técnica | Regras nesta tecnologia |
|---|---:|
| [T1611](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1611) Escape to Host | 52 |
| [T1059](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059) Command and Scripting Interpreter | 45 |
| [T1059.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.004) Unix Shell | 29 |
| [T1610](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1610) Deploy Container | 26 |
| [T1609](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1609) Container Administration Command | 19 |
| [T1613](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1613) Container and Resource Discovery | 19 |
| [T1552](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1552) Unsecured Credentials | 16 |
| [T1552.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1552.001) Credentials In Files | 12 |
| [T1105](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1105) Ingress Tool Transfer | 10 |
| [T1071](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1071) Application Layer Protocol | 10 |
| [T1082](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1082) System Information Discovery | 9 |
| [T1543](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1543) Create or Modify System Process | 9 |

## 4. Detecção pela ausência — o que ninguém está olhando (19 técnicas)

Técnicas do ATT&CK para Containers **sem nenhuma regra nesta tecnologia**, ordenadas pelo número de grupos que as usam. A coluna "regras no catálogo" mostra se existe cobertura em outra tecnologia (ex.: EDR ou rede) que você pode adaptar.

| Técnica | Grupos que usam | Regras no catálogo (todas as tecnologias) |
|---|---:|---:|
| [T1110](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1110) Brute Force | 16 | 552 |
| [T1136.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1136.001) Local Account | 16 | 103 |
| [T1078.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.003) Local Accounts | 14 | 32 |
| [T1110.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1110.003) Password Spraying | 12 | 62 |
| [T1036.010](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1036.010) Masquerade Account Name | 4 | 1 |
| [T1078.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.001) Default Accounts | 4 | 16 |
| [T1110.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1110.001) Password Guessing | 4 | 63 |
| [T1496.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1496.001) Compute Hijacking | 4 | 2 |
| [T1059.013](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.013) Container CLI/API | 3 | **0** |
| [T1136](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1136) Create Account | 3 | 310 |
| [T1110.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1110.004) Credential Stuffing | 2 | 35 |
| [T1204.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1204.003) Malicious Image | 1 | 3 |
| [T1498](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1498) Network Denial of Service | 1 | 81 |
| [T1499](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1499) Endpoint Denial of Service | 1 | 125 |
| [T1543.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1543.005) Container Service | 1 | 2 |
| [T1053.007](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1053.007) Container Orchestration Job | 0 | 4 |
| [T1098.006](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1098.006) Additional Container Cluster Roles | 0 | 34 |
| [T1496.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1496.002) Bandwidth Hijacking | 0 | **0** |
| [T1612](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1612) Build Image on Host | 0 | **0** |

## 5. Quem mira esta plataforma

Grupos com mais técnicas registradas nesta plataforma e quantas delas você enxerga com as regras desta tecnologia. País atribuído pelo APT4ALL (afirmação de quem publicou).

| Grupo | Origem atribuída | Técnicas na plataforma | Com regra aqui | Exemplos sem regra |
|---|---|---:|---:|---|
| [TeamTNT](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0139) `G0139` | Sem país atribuído | 14 | 10 | T1059.013, T1136.001, T1204.003, T1496.001 |
| [APT28](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0007) `G0007` | Rússia | 12 | 8 | T1110, T1110.001, T1110.003, T1498 |
| [Salt Typhoon](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1045) `G1045` | China | 11 | 6 | T1059.013, T1110.001, T1136, T1136.001 |
| [APT41](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0096) `G0096` | China | 10 | 7 | T1110, T1136.001, T1496.001 |
| [Scattered Spider](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1015) `G1015` | Sem país atribuído | 10 | 9 | T1136 |
| [VOID MANTICORE](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1055) `G1055` | Irã | 10 | 7 | T1110, T1110.001, T1110.004 |
| [APT29](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0016) `G0016` | Rússia | 9 | 6 | T1078.003, T1110.001, T1110.003 |
| [Ember Bear](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1003) `G1003` | Rússia | 9 | 6 | T1078.001, T1110, T1110.003 |
| [FIN13](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1016) `G1016` | Rússia | 9 | 7 | T1078.001, T1136.001 |
| [OilRig](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0049) `G0049` | Irã | 9 | 8 | T1110 |
| [TeamPCP](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1056) `G1056` | Sem país atribuído | 9 | 8 | T1059.013 |
| [Fox Kitten](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0117) `G0117` | Irã | 8 | 6 | T1110, T1136.001 |
| [Lazarus Group](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0032) `G0032` | Coreia do Norte | 8 | 7 | T1110.003 |
| [Sandworm Team](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0034) `G0034` | Rússia | 8 | 7 | T1499 |

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
| [Privileged Container Creation with Host Directory Mount](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ad1f310cb-5921-4d37-bbdf-cfdab7a6df9c) | Elastic | Elastic detection-rules | T1059, T1059.004, T1609 |
| [Sensitive Identity File Open by Suspicious Process via Auditd](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ae4c5d6e7-f8a9-4012-b3c4-d5e6f7a80912) | Elastic | Elastic detection-rules | T1552, T1552.001, T1552.007 |
| [Potential Privilege Escalation via Container Misconfiguration](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Aafe6b0eb-dd9d-4922-b08a-1910124d524d) | Elastic | Elastic detection-rules | T1610, T1611 |
| [AWS Credentials Searched For Inside A Container](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A5749282b-7524-4c9d-af9a-e2b3e814e5d4) | Elastic | Elastic detection-rules | T1005, T1083, T1552 |
| [Potential Chroot Container Escape via Mount](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A5ae02ebc-a5de-4eac-afe6-c88de696477d) | Elastic | Elastic detection-rules | T1611 |
| [Potential Privilege Escalation in Container via Runc Init](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Af2a8c4d1-6b3e-4a9f-8c2d-1e5f7a9b0c4d) | Elastic | Elastic detection-rules | T1611 |
| [Sensitive Files Compression Inside A Container](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ad9faf1ba-a216-4c29-b8e0-a05a9d14b027) | Elastic | Elastic detection-rules | T1005, T1552, T1552.001 |
| [Nsenter to PID Namespace via Auditd](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A75f9b95f-370b-4ff3-a84c-66d9ec0b84eb) | Elastic | Elastic detection-rules | T1611 |
| [Chroot Execution in Container Context on Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A9056d577-4da5-47bf-8c94-6c0b1bb3f8a5) | Elastic | Elastic detection-rules | T1611 |
| [Ingress Tool Transfer Followed by Execution and Deletion Detected via Defend for Containers](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A1dc56174-5d02-4ca4-af92-e391f096fb21) | Elastic | Elastic detection-rules | T1059, T1059.004, T1070 |
| [Suspicious Echo or Printf Execution Detected via Defend for Containers](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ad9bfa475-270d-4b07-93cb-b1f49abe13da) | Elastic | Elastic detection-rules | T1037, T1053, T1053.003 |
| [Decoded Payload Piped to Interpreter Detected via Defend for Containers](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A0fb83aa0-3d17-41e9-b09c-56397bf7a7d9) | Elastic | Elastic detection-rules | T1027, T1027.010, T1059 |
| [Potential Direct Kubelet Access via Process Arguments Detected via Defend for Containers](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ab4bd186b-69c6-45ad-8bef-5c35bbadeaef) | Elastic | Elastic detection-rules | T1021, T1059, T1059.004 |
| [Web Server Exploitation Detected via Defend for Containers](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A497a7091-0ebd-44d7-88c4-367ab4d4d852) | Elastic | Elastic detection-rules | T1059, T1059.004, T1071 |
| [Nsenter Execution with Target Flag Inside Container](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A39029450-8e2d-4034-81b0-15af8e4e3a4e) | Elastic | Elastic detection-rules | T1611 |

## 10. Limites

- A tecnologia de cada regra é inferida por heurística sobre metadados e texto (techmap.py). Regras genéricas podem aparecer em várias tecnologias.
- "Sem regra" quer dizer sem regra pública neste catálogo, não sem detecção possível. Telemetria e contexto do seu ambiente decidem.
- Atribuição de país é afirmação das fontes reunidas pelo APT4ALL, não nossa.

---
Fontes: catálogo [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules), MITRE ATT&CK®, APT4ALL, Ransomware Tool Matrix (CC BY 4.0), TCEM, LLmInjection. Gerado em 2026-10-26.
