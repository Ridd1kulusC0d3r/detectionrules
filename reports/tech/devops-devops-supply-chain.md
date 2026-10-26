# DevOps & supply chain — relatório de regras de detecção

> **TLP:CLEAR** · 2026-10-26 · domínio **SaaS & colaboração** · plataforma ATT&CK **SaaS** · lente TCEM **Software Supply Chain** · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#techno=devops)

## 1. A história em um parágrafo

O palco é **o pipeline de software — repositórios, builds e artefatos que viram produção**. O catálogo reúne **902 regras** que olham para cá — 725 de detecção, 91 de hunting, 54 assinaturas e 32 playbooks de resposta. Elas se concentram em **Acesso inicial, Persistência, Execução**. Das 78 técnicas do ATT&CK para a plataforma SaaS, **40 (51%)** têm ao menos uma regra aqui e **38 não têm nenhuma** — é onde um atacante passa sem ser visto. Entre os grupos com mais técnicas nesta plataforma estão Scattered Spider, APT29, ShinyHunters.

**Lente TCEM — Software Supply Chain.** Source, dependencies, build systems, CI/CD, artifact provenance, release trust and third-party components. Para observar: repository audit, build logs, artifact attestations, dependency changes, release events. Arquitetura a mapear: source repositories, build runners, dependency sources, artifact stores, signing.

## 2. Números

| Indicador | Valor |
|---|---:|
| Regras | 902 |
| detecção | 725 |
| hunting | 91 |
| assinatura | 54 |
| playbook | 32 |
| Técnicas ATT&CK distintas | 123 |
| Cobertura da plataforma SaaS | 40/78 (51%) |

### Por tática

| Tática | Regras |
|---|---:|
| Reconhecimento | 2 |
| Desenv. de recursos | 4 |
| Acesso inicial | 118 |
| Execução | 65 |
| Persistência | 67 |
| Escalação de privilégio | 60 |
| Furtividade | 49 |
| Enfraquecimento de defesas | 56 |
| Acesso a credenciais | 28 |
| Descoberta | 11 |
| Movimento lateral | 19 |
| Coleta | 27 |
| Comando e controle | 34 |
| Exfiltração | 18 |
| Impacto | 18 |

### Linguagens disponíveis

Em que formato você encontra regra pronta para esta tecnologia.

| Formato | Regras |
|---|---:|
| Wazuh | 356 |
| Sentinel KQL | 111 |
| Elastic | 83 |
| Sigma | 78 |
| YARA-L | 67 |
| Panther | 54 |
| Suricata/Snort/Sagan | 54 |
| Splunk | 44 |
| Playbook | 32 |
| KQL hunting | 21 |
| Falco | 1 |
| GCP | 1 |

### Padrões de correlação (TCEM)

Como as regras decidem. Muitas de evento único = cobertura ampla mas ruidosa; sequências e novidade = mais contexto, mais exigência de dados.

| Padrão | Regras | O que significa |
|---|---:|---|
| Evento único | 650 | Um evento, sozinho, já tem sinal suficiente para chamar o analista. |
| Novidade / raridade | 76 | Compara com o que é normal: entidade, relação ou valor nunca (ou raramente) visto. |
| Sequência ordenada | 54 | Dois ou mais passos da mesma entidade, na ordem certa, dentro de uma janela. |
| Mudança de estado | 51 | O risco está na transição: algo era seguro e deixou de ser (desligado, rebaixado, alterado). |
| Fluxo de resposta | 32 | Não detecta: orquestra o que fazer depois do alerta (SOAR). |
| Assinatura de conteúdo | 24 | Casa bytes/strings dentro de arquivo, memória ou pacote, não eventos de log. |
| Limiar / acúmulo | 15 | O sinal está na repetição: N eventos por chave em uma janela. |

### Fontes que mais contribuem

| Fonte | Regras |
|---|---:|
| Wazuh ruleset (oficial) | 352 |
| SigmaHQ | 66 |
| Elastic detection-rules | 57 |
| Microsoft Sentinel (Analytic Rules) | 56 |
| Microsoft Sentinel (Hunting Queries) | 55 |
| Panther panther-analysis | 54 |
| Google SecOps / Chronicle | 35 |
| Chronicle rules (rowham) | 32 |
| Splunk security_content | 30 |
| Sagan rules (Quadrant) | 29 |

## 3. Técnicas mais cobertas

| Técnica | Regras nesta tecnologia |
|---|---:|
| [T1195](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1195) Supply Chain Compromise | 53 |
| [T1685](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1685) Disable or Modify Tools | 48 |
| [T1195.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1195.002) Compromise Software Supply Chain | 42 |
| [T1059](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059) Command and Scripting Interpreter | 27 |
| [T1213.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1213.003) Code Repositories | 20 |
| [T1078.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.004) Cloud Accounts | 19 |
| [T1098](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1098) Account Manipulation | 19 |
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | 19 |
| [T1105](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1105) Ingress Tool Transfer | 18 |
| [T1195.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1195.001) Compromise Software Dependencies and Development Tools | 16 |
| [T1059.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.004) Unix Shell | 13 |
| [T1213](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1213) Data from Information Repositories | 13 |

## 4. Detecção pela ausência — o que ninguém está olhando (38 técnicas)

Técnicas do ATT&CK para SaaS **sem nenhuma regra nesta tecnologia**, ordenadas pelo número de grupos que as usam. A coluna "regras no catálogo" mostra se existe cobertura em outra tecnologia (ex.: EDR ou rede) que você pode adaptar.

| Técnica | Grupos que usam | Regras no catálogo (todas as tecnologias) |
|---|---:|---:|
| [T1566.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1566.002) Spearphishing Link | 48 | 138 |
| [T1684.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1684.001) Impersonation | 18 | 1 |
| [T1539](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1539) Steal Web Session Cookie | 8 | 54 |
| [T1534](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1534) Internal Spearphishing | 7 | 5 |
| [T1213.006](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1213.006) Databases | 6 | 2 |
| [T1080](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1080) Taint Shared Content | 5 | 12 |
| [T1213.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1213.005) Messaging Applications | 5 | **0** |
| [T1036.010](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1036.010) Masquerade Account Name | 4 | 1 |
| [T1059.009](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.009) Cloud API | 4 | 11 |
| [T1078.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.001) Default Accounts | 4 | 16 |
| [T1110.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1110.001) Password Guessing | 4 | 63 |
| [T1021.007](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1021.007) Cloud Services | 3 | 20 |
| [T1201](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1201) Password Policy Discovery | 3 | 43 |
| [T1621](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1621) Multi-Factor Authentication Request Generation | 3 | 27 |
| [T1110.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1110.004) Credential Stuffing | 2 | 35 |
| [T1677](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1677) Poisoned Pipeline Execution | 2 | **0** |
| [T1213.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1213.001) Confluence | 1 | **0** |
| [T1538](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1538) Cloud Service Dashboard | 1 | 4 |
| [T1550.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1550.004) Web Session Cookie | 1 | 4 |
| [T1552.008](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1552.008) Chat Messages | 1 | 2 |

## 5. Quem mira esta plataforma

Grupos com mais técnicas registradas nesta plataforma e quantas delas você enxerga com as regras desta tecnologia. País atribuído pelo APT4ALL (afirmação de quem publicou).

| Grupo | Origem atribuída | Técnicas na plataforma | Com regra aqui | Exemplos sem regra |
|---|---|---:|---:|---|
| [Scattered Spider](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1015) `G1015` | Sem país atribuído | 17 | 10 | T1021.007, T1213.005, T1538, T1539 |
| [APT29](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0016) `G0016` | Rússia | 14 | 8 | T1021.007, T1059.009, T1110.001, T1556.007 |
| [ShinyHunters](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1057) `G1057` | Sem país atribuído | 14 | 11 | T1059.009, T1213.006, T1684 |
| [APT28](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0007) `G0007` | Rússia | 13 | 11 | T1110.001, T1684.001 |
| [LAPSUS$](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1004) `G1004` | Sem país atribuído | 12 | 7 | T1213.001, T1213.005, T1552.008, T1621 |
| [VOID MANTICORE](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1055) `G1055` | Irã | 12 | 9 | T1110.001, T1110.004, T1684.001 |
| [NIMBUS MANTICORE](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1059) `G1059` | — | 11 | 7 | T1213.005, T1534, T1566.002, T1684.001 |
| [Storm-0501](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1053) `G1053` | Sem país atribuído | 11 | 9 | T1021.007, T1059.009 |
| [APT38](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0082) `G0082` | Coreia do Norte | 9 | 4 | T1213.005, T1213.006, T1566.002, T1677 |
| [TeamPCP](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1056) `G1056` | Sem país atribuído | 8 | 6 | T1677, T1684.001 |
| [HAFNIUM](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0125) `G0125` | China | 7 | 7 | — |
| [OilRig](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0049) `G0049` | Irã | 7 | 5 | T1201, T1566.002 |
| [Sandworm Team](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0034) `G0034` | Rússia | 7 | 4 | T1213.006, T1539, T1566.002 |
| [Kimsuky](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0094) `G0094` | Coreia do Norte | 6 | 2 | T1534, T1539, T1566.002, T1684.001 |

## 7. Cenário de referência TCEM

### Software Supply Chain reference case

**Missão:** Preserve the integrity and provenance of software delivered to production.

**Dependency or source change followed by release artifact publication** — Detect release activity whose upstream change context requires review.

1. supply_chain_change — T1195 (187 regras no catálogo)
2. artifact_publish — T1195 (187 regras no catálogo)

Contrato de telemetria: fonte **CI/CD and artifact audit**, campos exigidos pipeline.id, actor.id, target.resource, action, timestamp; **faltam target.resource** (status partial).
Especificação de detecção: padrão **ordered-sequence**, janela 30m, agrupado por pipeline.id. Alternativas benignas: approved change with expected authorization context.

## 9. Regras recomendadas para começar

Ranqueadas por portabilidade do formato, maturidade, severidade e por mapearem técnica ATT&CK.

| Regra | Formato | Fonte | Técnicas |
|---|---|---|---|
| [Potential Suspicious Child Process Of 3CXDesktopApp](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A63f3605b-979f-48c2-b7cc-7f90523fed88) | Sigma | SigmaHQ | T1218 |
| [Potential Compromised 3CXDesktopApp Update Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae7581747-1e44-4d4b-85a6-0db0b4a00f2a) | Sigma | SigmaHQ | T1218 |
| [Potential Compromised 3CXDesktopApp Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A93bbde78-dc86-4e73-9ffc-ff8a384ca89c) | Sigma | SigmaHQ | T1218 |
| [Suspicious VBScript UN2452 Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A20c3f09d-c53d-4e85-8b74-6aa50e2f1b61) | Sigma | SigmaHQ | T1547.001 |
| [Solarwinds SUPERNOVA Webshell Access](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aa2cee20b-eacc-459f-861d-c02e5d12f1db) | Sigma | SigmaHQ | T1505.003 |
| [UNC2452 PowerShell Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab7155193-8a81-4d8f-805d-88de864ca50c) | Sigma | SigmaHQ | T1047, T1059.001 |
| [UNC2452 Process Creation Patterns](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A9be34ad0-b6a7-4fbd-91cf-fc7ec1047f5f) | Sigma | SigmaHQ | T1059.001 |
| [Atlassian Bitbucket Command Injection Via Archive API](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A65c0a0ab-d675-4441-bd6b-d3db226a2685) | Sigma | SigmaHQ | T1190 |
| [REvil Kaseya Incident Malware Patterns](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A5de632bc-7fbd-4c8a-944a-fce55c59eae5) | Sigma | SigmaHQ | T1059 |
| [Antivirus - Web Shell Detection Signature](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Afdf135a2-9241-4f96-a114-bb404948f736) | Sigma | SigmaHQ | T1505.003 |
| [Github Secret Scanning Feature Disabled](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A3883d9a0-fd0f-440f-afbb-445a2a799bb8) | Sigma | SigmaHQ | T1685 |
| [Outdated Dependency Or Vulnerability Alert Disabled](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A34e1c7d4-0cd5-419d-9f1b-1dad3f61018d) | Sigma | SigmaHQ | T1195.001 |
| [Github Push Protection Disabled](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Accd55945-badd-4bae-936b-823a735d37dd) | Sigma | SigmaHQ | T1685 |
| [Github High Risk Configuration Disabled](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A8622c92d-c00e-463c-b09d-fd06166f6794) | Sigma | SigmaHQ | T1556 |
| [Bitbucket Unauthorized Full Data Export Triggered](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A34d81081-03c9-4a7f-91c9-5e46af625cde) | Sigma | SigmaHQ | T1213.003, T1586 |

## 10. Limites

- A tecnologia de cada regra é inferida por heurística sobre metadados e texto (techmap.py). Regras genéricas podem aparecer em várias tecnologias.
- "Sem regra" quer dizer sem regra pública neste catálogo, não sem detecção possível. Telemetria e contexto do seu ambiente decidem.
- Atribuição de país é afirmação das fontes reunidas pelo APT4ALL, não nossa.

---
Fontes: catálogo [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules), MITRE ATT&CK®, APT4ALL, Ransomware Tool Matrix (CC BY 4.0), TCEM, LLmInjection. Gerado em 2026-10-26.
