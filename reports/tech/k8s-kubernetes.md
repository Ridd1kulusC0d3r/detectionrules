# Kubernetes — relatório de regras de detecção

> **TLP:CLEAR** · 2026-10-26 · domínio **Contêineres** · plataforma ATT&CK **Containers** · lente TCEM **Cloud & Multi-Cloud** · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#techno=k8s)

## 1. A história em um parágrafo

O palco é **o cluster Kubernetes — o maestro que decide onde e como cada contêiner roda**. O catálogo reúne **398 regras** que olham para cá — 347 de detecção, 11 de hunting, 30 assinaturas e 10 playbooks de resposta. Elas se concentram em **Escalação de privilégio, Persistência, Execução**. Das 48 técnicas do ATT&CK para a plataforma Containers, **32 (67%)** têm ao menos uma regra aqui e **16 não têm nenhuma** — é onde um atacante passa sem ser visto. Entre os grupos com mais técnicas nesta plataforma estão TeamTNT, APT28, Salt Typhoon.

**Lente TCEM — Cloud & Multi-Cloud.** Cloud control planes, workloads, identities, management APIs, cross-cloud trust and SaaS dependencies. Para observar: cloud audit, identity logs, control-plane changes, workload activity. Arquitetura a mapear: control planes, cloud identities, organization hierarchy, workload identities, management APIs.

## 2. Números

| Indicador | Valor |
|---|---:|
| Regras | 398 |
| detecção | 347 |
| assinatura | 30 |
| hunting | 11 |
| playbook | 10 |
| Técnicas ATT&CK distintas | 98 |
| Cobertura da plataforma Containers | 32/48 (67%) |

### Por tática

| Tática | Regras |
|---|---:|
| Reconhecimento | 6 |
| Acesso inicial | 47 |
| Execução | 84 |
| Persistência | 87 |
| Escalação de privilégio | 124 |
| Furtividade | 55 |
| Enfraquecimento de defesas | 13 |
| Acesso a credenciais | 73 |
| Descoberta | 53 |
| Movimento lateral | 19 |
| Coleta | 7 |
| Comando e controle | 12 |
| Exfiltração | 8 |
| Impacto | 14 |

### Linguagens disponíveis

Em que formato você encontra regra pronta para esta tecnologia.

| Formato | Regras |
|---|---:|
| Elastic | 169 |
| Panther | 74 |
| Sigma | 54 |
| Splunk | 45 |
| Suricata/Snort/Sagan | 30 |
| Playbook | 10 |
| Falco | 7 |
| Sentinel KQL | 5 |
| Wazuh | 4 |

### Padrões de correlação (TCEM)

Como as regras decidem. Muitas de evento único = cobertura ampla mas ruidosa; sequências e novidade = mais contexto, mais exigência de dados.

| Padrão | Regras | O que significa |
|---|---:|---|
| Evento único | 204 | Um evento, sozinho, já tem sinal suficiente para chamar o analista. |
| Novidade / raridade | 149 | Compara com o que é normal: entidade, relação ou valor nunca (ou raramente) visto. |
| Sequência ordenada | 17 | Dois ou mais passos da mesma entidade, na ordem certa, dentro de uma janela. |
| Limiar / acúmulo | 10 | O sinal está na repetição: N eventos por chave em uma janela. |
| Fluxo de resposta | 10 | Não detecta: orquestra o que fazer depois do alerta (SOAR). |
| Mudança de estado | 8 | O risco está na transição: algo era seguro e deixou de ser (desligado, rebaixado, alterado). |

### Fontes que mais contribuem

| Fonte | Regras |
|---|---:|
| Elastic detection-rules | 167 |
| Panther panther-analysis | 74 |
| Splunk security_content | 39 |
| SigmaHQ | 30 |
| Sagan rules (Quadrant) | 30 |
| OpenSearch Security Analytics | 24 |
| Cortex XSOAR (demisto/content) | 10 |
| Falco rules | 7 |
| Splunk analytic stories | 6 |
| Microsoft Sentinel (Hunting Queries) | 4 |

## 3. Técnicas mais cobertas

| Técnica | Regras nesta tecnologia |
|---|---:|
| [T1552](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1552) Unsecured Credentials | 49 |
| [T1613](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1613) Container and Resource Discovery | 43 |
| [T1552.007](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1552.007) Container API | 37 |
| [T1098](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1098) Account Manipulation | 36 |
| [T1609](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1609) Container Administration Command | 33 |
| [T1611](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1611) Escape to Host | 33 |
| [T1610](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1610) Deploy Container | 32 |
| [T1098.006](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1098.006) Additional Container Cluster Roles | 30 |
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | 28 |
| [T1059](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059) Command and Scripting Interpreter | 20 |
| [T1059.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.004) Unix Shell | 11 |
| [T1552.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1552.001) Credentials In Files | 11 |

## 4. Detecção pela ausência — o que ninguém está olhando (16 técnicas)

Técnicas do ATT&CK para Containers **sem nenhuma regra nesta tecnologia**, ordenadas pelo número de grupos que as usam. A coluna "regras no catálogo" mostra se existe cobertura em outra tecnologia (ex.: EDR ou rede) que você pode adaptar.

| Técnica | Grupos que usam | Regras no catálogo (todas as tecnologias) |
|---|---:|---:|
| [T1110](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1110) Brute Force | 16 | 552 |
| [T1136.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1136.001) Local Account | 16 | 103 |
| [T1078.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.003) Local Accounts | 14 | 32 |
| [T1110.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1110.003) Password Spraying | 12 | 62 |
| [T1490](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1490) Inhibit System Recovery | 7 | 188 |
| [T1036.010](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1036.010) Masquerade Account Name | 4 | 1 |
| [T1110.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1110.001) Password Guessing | 4 | 63 |
| [T1496.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1496.001) Compute Hijacking | 4 | 2 |
| [T1059.013](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.013) Container CLI/API | 3 | **0** |
| [T1110.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1110.004) Credential Stuffing | 2 | 35 |
| [T1204](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1204) User Execution | 2 | 673 |
| [T1204.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1204.003) Malicious Image | 1 | 3 |
| [T1498](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1498) Network Denial of Service | 1 | 81 |
| [T1499](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1499) Endpoint Denial of Service | 1 | 125 |
| [T1496.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1496.002) Bandwidth Hijacking | 0 | **0** |
| [T1612](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1612) Build Image on Host | 0 | **0** |

## 5. Quem mira esta plataforma

Grupos com mais técnicas registradas nesta plataforma e quantas delas você enxerga com as regras desta tecnologia. País atribuído pelo APT4ALL (afirmação de quem publicou).

| Grupo | Origem atribuída | Técnicas na plataforma | Com regra aqui | Exemplos sem regra |
|---|---|---:|---:|---|
| [TeamTNT](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0139) `G0139` | Sem país atribuído | 14 | 10 | T1059.013, T1136.001, T1204.003, T1496.001 |
| [APT28](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0007) `G0007` | Rússia | 12 | 8 | T1110, T1110.001, T1110.003, T1498 |
| [Salt Typhoon](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1045) `G1045` | China | 11 | 8 | T1059.013, T1110.001, T1136.001 |
| [APT41](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0096) `G0096` | China | 10 | 7 | T1110, T1136.001, T1496.001 |
| [Scattered Spider](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1015) `G1015` | Sem país atribuído | 10 | 8 | T1204, T1490 |
| [VOID MANTICORE](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1055) `G1055` | Irã | 10 | 6 | T1110, T1110.001, T1110.004, T1490 |
| [APT29](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0016) `G0016` | Rússia | 9 | 6 | T1078.003, T1110.001, T1110.003 |
| [Ember Bear](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1003) `G1003` | Rússia | 9 | 7 | T1110, T1110.003 |
| [FIN13](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1016) `G1016` | Rússia | 9 | 8 | T1136.001 |
| [OilRig](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0049) `G0049` | Irã | 9 | 8 | T1110 |
| [TeamPCP](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1056) `G1056` | Sem país atribuído | 9 | 8 | T1059.013 |
| [Fox Kitten](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0117) `G0117` | Irã | 8 | 6 | T1110, T1136.001 |
| [Lazarus Group](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0032) `G0032` | Coreia do Norte | 8 | 7 | T1110.003 |
| [Sandworm Team](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0034) `G0034` | Rússia | 8 | 6 | T1490, T1499 |

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
| [Multiple Cloud Secrets Accessed by Source Address](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A472b4944-d810-43cf-83dc-7d080ae1b8dd) | Elastic | Elastic detection-rules | T1555, T1555.006 |
| [Kubectl Secrets Enumeration Across All Namespaces](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Aa87d49f0-24ae-4d6e-a0b4-5fd2f6188d6a) | Elastic | Elastic detection-rules | T1552, T1613 |
| [Multi-Cloud CLI Token and Credential Access Commands](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A2b9a3b7a-0891-4a89-abbe-dca753c403cd) | Elastic | Elastic detection-rules | T1528, T1552, T1552.001 |
| [Sensitive Identity File Open by Suspicious Process via Auditd](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ae4c5d6e7-f8a9-4012-b3c4-d5e6f7a80912) | Elastic | Elastic detection-rules | T1552, T1552.001, T1552.007 |
| [Potential Direct Kubelet Access via Process Arguments](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A6aa52f86-18f1-4a5a-a0ac-e2b5db8af589) | Elastic | Elastic detection-rules | T1021, T1059, T1059.004 |
| [Kubernetes and Cloud Credential Path Access via Process Arguments](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A5f0fff18-f340-444b-9a98-c49ade766ff4) | Elastic | Elastic detection-rules | T1528, T1552, T1552.001 |
| [Potential Direct Kubelet Access via Process Arguments Detected via Defend for Containers](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ab4bd186b-69c6-45ad-8bef-5c35bbadeaef) | Elastic | Elastic detection-rules | T1021, T1059, T1059.004 |
| [Potential Kubeletctl Execution Detected via Defend for Containers](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A2572f7e0-7647-4c68-a42b-d3b1973deaae) | Elastic | Elastic detection-rules | T1059, T1059.004, T1609 |
| [GKE Certificate Signing Request for Privileged Identity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A4159bec9-76ad-4cdc-a797-4a8572073bbe) | Elastic | Elastic detection-rules | T1098, T1098.006 |
| [GKE Pod Exec with Curl or Wget to HTTPS](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A3a68325b-6169-44c1-a5f0-0102ef82b6f1) | Elastic | Elastic detection-rules | T1105, T1609 |
| [GKE Pod Exec Cloud Instance Metadata Access](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ac8bf56cc-c648-4f88-bb4f-9e504d0779d1) | Elastic | Elastic detection-rules | T1552, T1552.005, T1609 |
| [GKE Secret get or list with Suspicious User Agent](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A0c04d82f-6def-4659-aa62-ed6355a51f39) | Elastic | Elastic detection-rules | T1552, T1552.007 |
| [GKE RBAC Wildcard Elevation on Existing Role](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A563a38e9-9790-4a6a-8889-24d26055b832) | Elastic | Elastic detection-rules | T1098, T1098.006 |
| [GKE Secrets List from Unusual Source AS Organization](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A4df2e3ae-3553-4194-b22e-3e5a6f71466e) | Elastic | Elastic detection-rules | T1552, T1552.007, T1613 |
| [GKE API Request Impersonating Privileged Identity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A00c2a946-bbe8-4345-941d-9ea13da91600) | Elastic | Elastic detection-rules | T1134 |

## 10. Limites

- A tecnologia de cada regra é inferida por heurística sobre metadados e texto (techmap.py). Regras genéricas podem aparecer em várias tecnologias.
- "Sem regra" quer dizer sem regra pública neste catálogo, não sem detecção possível. Telemetria e contexto do seu ambiente decidem.
- Atribuição de país é afirmação das fontes reunidas pelo APT4ALL, não nossa.

---
Fontes: catálogo [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules), MITRE ATT&CK®, APT4ALL, Ransomware Tool Matrix (CC BY 4.0), TCEM, LLmInjection. Gerado em 2026-10-26.
