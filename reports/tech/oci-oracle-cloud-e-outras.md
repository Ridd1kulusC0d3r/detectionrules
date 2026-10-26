# Oracle Cloud e outras — relatório de regras de detecção

> **TLP:CLEAR** · 2026-10-26 · domínio **Nuvem** · plataforma ATT&CK **IaaS** · lente TCEM **Cloud & Multi-Cloud** · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#techno=oci)

## 1. A história em um parágrafo

O palco é **a nuvem Oracle e outras nuvens — o painel de controle da infraestrutura alugada**. O catálogo reúne **378 regras** que olham para cá — 17 de detecção, 10 de hunting, 351 assinaturas e 0 playbooks de resposta. Elas se concentram em **Persistência, Execução, Furtividade**. Das 104 técnicas do ATT&CK para a plataforma IaaS, **3 (3%)** têm ao menos uma regra aqui e **101 não têm nenhuma** — é onde um atacante passa sem ser visto. Entre os grupos com mais técnicas nesta plataforma estão Scattered Spider, Storm-0501, APT28.

**Lente TCEM — Cloud & Multi-Cloud.** Cloud control planes, workloads, identities, management APIs, cross-cloud trust and SaaS dependencies. Para observar: cloud audit, identity logs, control-plane changes, workload activity. Arquitetura a mapear: control planes, cloud identities, organization hierarchy, workload identities, management APIs.

## 2. Números

| Indicador | Valor |
|---|---:|
| Regras | 378 |
| assinatura | 351 |
| detecção | 17 |
| hunting | 10 |
| Técnicas ATT&CK distintas | 6 |
| Cobertura da plataforma IaaS | 3/104 (3%) |

### Por tática

| Tática | Regras |
|---|---:|
| Execução | 4 |
| Persistência | 5 |
| Furtividade | 4 |
| Enfraquecimento de defesas | 4 |
| Acesso a credenciais | 2 |
| Comando e controle | 1 |

### Linguagens disponíveis

Em que formato você encontra regra pronta para esta tecnologia.

| Formato | Regras |
|---|---:|
| Suricata/Snort/Sagan | 351 |
| Sentinel KQL | 20 |
| Wazuh | 4 |
| Elastic | 2 |
| Sigma | 1 |

### Padrões de correlação (TCEM)

Como as regras decidem. Muitas de evento único = cobertura ampla mas ruidosa; sequências e novidade = mais contexto, mais exigência de dados.

| Padrão | Regras | O que significa |
|---|---:|---|
| Evento único | 366 | Um evento, sozinho, já tem sinal suficiente para chamar o analista. |
| Limiar / acúmulo | 7 | O sinal está na repetição: N eventos por chave em uma janela. |
| Novidade / raridade | 3 | Compara com o que é normal: entidade, relação ou valor nunca (ou raramente) visto. |
| Mudança de estado | 2 | O risco está na transição: algo era seguro e deixou de ser (desligado, rebaixado, alterado). |

### Fontes que mais contribuem

| Fonte | Regras |
|---|---:|
| Sagan rules (Quadrant) | 351 |
| Microsoft Sentinel (Analytic Rules) | 10 |
| Microsoft Sentinel (Hunting Queries) | 10 |
| EVTX-Wazuh-Rules (saifbelaarbi) | 3 |
| Elastic detection-rules | 2 |
| SigmaHQ | 1 |
| SOCFortress Wazuh-Rules | 1 |

## 3. Técnicas mais cobertas

| Técnica | Regras nesta tecnologia |
|---|---:|
| [T1112](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1112) Modify Registry | 4 |
| [T1574.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1574.001) DLL | 4 |
| [T1552.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1552.001) Credentials In Files | 2 |
| [T1528](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1528) Steal Application Access Token | 1 |
| [T1552](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1552) Unsecured Credentials | 1 |
| [T1105](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1105) Ingress Tool Transfer | 1 |

## 4. Detecção pela ausência — o que ninguém está olhando (101 técnicas)

Técnicas do ATT&CK para IaaS **sem nenhuma regra nesta tecnologia**, ordenadas pelo número de grupos que as usam. A coluna "regras no catálogo" mostra se existe cobertura em outra tecnologia (ex.: EDR ou rede) que você pode adaptar.

| Técnica | Grupos que usam | Regras no catálogo (todas as tecnologias) |
|---|---:|---:|
| [T1082](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1082) System Information Discovery | 59 | 264 |
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | 49 | 1265 |
| [T1190](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1190) Exploit Public-Facing Application | 47 | 580 |
| [T1046](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1046) Network Service Discovery | 33 | 212 |
| [T1049](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1049) System Network Connections Discovery | 33 | 47 |
| [T1685](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1685) Disable or Modify Tools | 33 | 1587 |
| [T1518.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1518.001) Security Software Discovery | 27 | 54 |
| [T1119](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1119) Automated Collection | 21 | 72 |
| [T1486](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1486) Data Encrypted for Impact | 20 | 160 |
| [T1059](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059) Command and Scripting Interpreter | 17 | 4085 |
| [T1110](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1110) Brute Force | 16 | 552 |
| [T1078.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.004) Cloud Accounts | 14 | 356 |
| [T1199](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1199) Trusted Relationship | 14 | 18 |
| [T1555](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1555) Credentials from Password Stores | 13 | 292 |
| [T1110.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1110.003) Password Spraying | 12 | 62 |
| [T1518](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1518) Software Discovery | 12 | 112 |
| [T1074.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1074.002) Remote Data Staging | 11 | 5 |
| [T1680](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1680) Local Storage Discovery | 10 | **0** |
| [T1040](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1040) Network Sniffing | 8 | 77 |
| [T1485](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1485) Data Destruction | 8 | 218 |

## 5. Quem mira esta plataforma

Grupos com mais técnicas registradas nesta plataforma e quantas delas você enxerga com as regras desta tecnologia. País atribuído pelo APT4ALL (afirmação de quem publicou).

| Grupo | Origem atribuída | Técnicas na plataforma | Com regra aqui | Exemplos sem regra |
|---|---|---:|---:|---|
| [Scattered Spider](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1015) `G1015` | Sem país atribuído | 22 | 1 | T1021.007, T1069, T1074, T1078 |
| [Storm-0501](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1053) `G1053` | Sem país atribuído | 20 | 0 | T1021.007, T1059.009, T1078.004, T1082 |
| [APT28](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0007) `G0007` | Rússia | 15 | 1 | T1040, T1074.002, T1078, T1078.004 |
| [APT29](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0016) `G0016` | Rússia | 15 | 1 | T1021.007, T1059.009, T1078, T1078.004 |
| [ShinyHunters](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1057) `G1057` | Sem país atribuído | 15 | 2 | T1059.009, T1069.003, T1078, T1078.004 |
| [VOID MANTICORE](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1055) `G1055` | Irã | 15 | 0 | T1074, T1078, T1078.004, T1082 |
| [Salt Typhoon](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1045) `G1045` | China | 13 | 1 | T1020.001, T1040, T1046, T1078 |
| [Sandworm Team](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0034) `G0034` | Rússia | 13 | 0 | T1040, T1049, T1078, T1082 |
| [TeamTNT](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0139) `G0139` | Sem país atribuído | 13 | 1 | T1046, T1048, T1049, T1059.009 |
| [LAPSUS$](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1004) `G1004` | Sem país atribuído | 12 | 0 | T1078, T1078.004, T1098.003, T1136.003 |
| [Volt Typhoon](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1017) `G1017` | China | 12 | 1 | T1046, T1049, T1069, T1074 |
| [APT38](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0082) `G0082` | Coreia do Norte | 11 | 0 | T1049, T1078.004, T1082, T1110 |
| [APT41](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0096) `G0096` | China | 11 | 0 | T1046, T1049, T1069, T1078 |
| [Ember Bear](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1003) `G1003` | Rússia | 10 | 1 | T1021, T1046, T1078.001, T1110 |

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
| [Multi-Cloud CLI Token and Credential Access Commands](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A2b9a3b7a-0891-4a89-abbe-dca753c403cd) | Elastic | Elastic detection-rules | T1528, T1552, T1552.001 |
| [Registry Modification for OCI DLL Redirection](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac0e0bdec-3e3d-47aa-9974-05539c999c89) | Sigma | SigmaHQ | T1112, T1574.001 |
| [Curl or Wget Execution from Container Context](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ae7b2c3d4-5a6b-4e8f-9c0d-1a2b3e4f5a6b) | Elastic | Elastic detection-rules | T1105 |
| [Possible credential discovery attempt: scanning for Oracle Cloud credentials token file](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=socfortress-wazuh-rules%3A%3Awazuh-700098) | Wazuh | SOCFortress Wazuh-Rules | T1552.001 |
| [Sigma: Registry Modification for OCI DLL Redirection](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=evtx-wazuh-rules-saifbelaarbi%3A%3Awazuh-104827) | Wazuh | EVTX-Wazuh-Rules (saifbelaarbi) | T1112, T1574.001 |

## 10. Limites

- A tecnologia de cada regra é inferida por heurística sobre metadados e texto (techmap.py). Regras genéricas podem aparecer em várias tecnologias.
- "Sem regra" quer dizer sem regra pública neste catálogo, não sem detecção possível. Telemetria e contexto do seu ambiente decidem.
- Atribuição de país é afirmação das fontes reunidas pelo APT4ALL, não nossa.

---
Fontes: catálogo [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules), MITRE ATT&CK®, APT4ALL, Ransomware Tool Matrix (CC BY 4.0), TCEM, LLmInjection. Gerado em 2026-10-26.
