# Okta — relatório de regras de detecção

> **TLP:CLEAR** · 2026-10-26 · domínio **Identidade** · plataforma ATT&CK **Identity Provider** · lente TCEM **Identity & Access** · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#techno=okta)

## 1. A história em um parágrafo

O palco é **o Okta — a porta única para todos os aplicativos: quem controla o Okta decide quem é quem**. O catálogo reúne **306 regras** que olham para cá — 242 de detecção, 26 de hunting, 16 assinaturas e 22 playbooks de resposta. Elas se concentram em **Persistência, Escalação de privilégio, Acesso a credenciais**. Das 49 técnicas do ATT&CK para a plataforma Identity Provider, **26 (53%)** têm ao menos uma regra aqui e **23 não têm nenhuma** — é onde um atacante passa sem ser visto. Entre os grupos com mais técnicas nesta plataforma estão APT29, Scattered Spider, Storm-0501.

**Lente TCEM — Identity & Access.** Authentication, authorization, privilege, federation, machine identity and administrative trust. Para observar: sign-in logs, privilege changes, token events, identity administration. Arquitetura a mapear: identity providers, privileged roles, service principals, federation, recovery access.

## 2. Números

| Indicador | Valor |
|---|---:|
| Regras | 306 |
| detecção | 242 |
| hunting | 26 |
| playbook | 22 |
| assinatura | 16 |
| Técnicas ATT&CK distintas | 50 |
| Cobertura da plataforma Identity Provider | 26/49 (53%) |

### Por tática

| Tática | Regras |
|---|---:|
| Reconhecimento | 1 |
| Desenv. de recursos | 4 |
| Acesso inicial | 69 |
| Persistência | 95 |
| Escalação de privilégio | 85 |
| Furtividade | 62 |
| Enfraquecimento de defesas | 33 |
| Acesso a credenciais | 78 |
| Descoberta | 1 |
| Movimento lateral | 10 |
| Coleta | 1 |
| Comando e controle | 1 |
| Impacto | 8 |

### Linguagens disponíveis

Em que formato você encontra regra pronta para esta tecnologia.

| Formato | Regras |
|---|---:|
| Elastic | 73 |
| Panther | 58 |
| Sigma | 49 |
| YARA-L | 42 |
| Splunk | 24 |
| Sentinel KQL | 22 |
| Playbook | 22 |
| Suricata/Snort/Sagan | 16 |

### Padrões de correlação (TCEM)

Como as regras decidem. Muitas de evento único = cobertura ampla mas ruidosa; sequências e novidade = mais contexto, mais exigência de dados.

| Padrão | Regras | O que significa |
|---|---:|---|
| Evento único | 97 | Um evento, sozinho, já tem sinal suficiente para chamar o analista. |
| Novidade / raridade | 78 | Compara com o que é normal: entidade, relação ou valor nunca (ou raramente) visto. |
| Limiar / acúmulo | 48 | O sinal está na repetição: N eventos por chave em uma janela. |
| Sequência ordenada | 47 | Dois ou mais passos da mesma entidade, na ordem certa, dentro de uma janela. |
| Fluxo de resposta | 22 | Não detecta: orquestra o que fazer depois do alerta (SOAR). |
| Mudança de estado | 14 | O risco está na transição: algo era seguro e deixou de ser (desligado, rebaixado, alterado). |

### Fontes que mais contribuem

| Fonte | Regras |
|---|---:|
| Elastic detection-rules | 61 |
| Panther panther-analysis | 58 |
| OpenSearch Security Analytics | 25 |
| SigmaHQ | 24 |
| Chronicle rules (rowham) | 22 |
| Splunk security_content | 21 |
| Google SecOps / Chronicle | 20 |
| Sagan rules (Quadrant) | 16 |
| Microsoft Sentinel (Hunting Queries) | 12 |
| Cortex XSOAR (demisto/content) | 12 |

## 3. Técnicas mais cobertas

| Técnica | Regras nesta tecnologia |
|---|---:|
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | 49 |
| [T1110](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1110) Brute Force | 29 |
| [T1078.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.004) Cloud Accounts | 28 |
| [T1556](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1556) Modify Authentication Process | 22 |
| [T1098](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1098) Account Manipulation | 16 |
| [T1621](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1621) Multi-Factor Authentication Request Generation | 11 |
| [T1685](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1685) Disable or Modify Tools | 10 |
| [T1556.006](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1556.006) Multi-Factor Authentication | 10 |
| [T1539](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1539) Steal Web Session Cookie | 9 |
| [T1686.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1686.001) Cloud Firewall | 9 |
| [T1199](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1199) Trusted Relationship | 6 |
| [T1550](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1550) Use Alternate Authentication Material | 6 |

## 4. Detecção pela ausência — o que ninguém está olhando (23 técnicas)

Técnicas do ATT&CK para Identity Provider **sem nenhuma regra nesta tecnologia**, ordenadas pelo número de grupos que as usam. A coluna "regras no catálogo" mostra se existe cobertura em outra tecnologia (ex.: EDR ou rede) que você pode adaptar.

| Técnica | Grupos que usam | Regras no catálogo (todas as tecnologias) |
|---|---:|---:|
| [T1189](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1189) Drive-by Compromise | 31 | 57 |
| [T1059](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059) Command and Scripting Interpreter | 17 | 4085 |
| [T1069](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1069) Permission Groups Discovery | 6 | 242 |
| [T1036.010](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1036.010) Masquerade Account Name | 4 | 1 |
| [T1059.009](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.009) Cloud API | 4 | 11 |
| [T1078.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.001) Default Accounts | 4 | 16 |
| [T1110.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1110.002) Password Cracking | 4 | 11 |
| [T1021.007](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1021.007) Cloud Services | 3 | 20 |
| [T1087](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1087) Account Discovery | 3 | 547 |
| [T1201](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1201) Password Policy Discovery | 3 | 43 |
| [T1087.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1087.004) Cloud Account | 2 | 38 |
| [T1136.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1136.003) Cloud Account | 2 | 53 |
| [T1649](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1649) Steal or Forge Authentication Certificates | 2 | 43 |
| [T1069.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1069.003) Cloud Groups | 1 | 20 |
| [T1098.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1098.005) Device Registration | 1 | 33 |
| [T1212](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1212) Exploitation for Credential Access | 1 | 49 |
| [T1526](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1526) Cloud Service Discovery | 1 | 76 |
| [T1566.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1566.004) Spearphishing Voice | 1 | **0** |
| [T1685.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1685.002) Disable or Modify Cloud Log | 1 | 80 |
| [T1697](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1697) Steal Application Specific Passwords | 1 | **0** |

## 5. Quem mira esta plataforma

Grupos com mais técnicas registradas nesta plataforma e quantas delas você enxerga com as regras desta tecnologia. País atribuído pelo APT4ALL (afirmação de quem publicou).

| Grupo | Origem atribuída | Técnicas na plataforma | Com regra aqui | Exemplos sem regra |
|---|---|---:|---:|---|
| [APT29](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0016) `G0016` | Rússia | 16 | 9 | T1021.007, T1059.009, T1087.004, T1098.005 |
| [Scattered Spider](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1015) `G1015` | Sem país atribuído | 13 | 10 | T1021.007, T1069, T1087 |
| [Storm-0501](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1053) `G1053` | Sem país atribuído | 10 | 6 | T1021.007, T1059.009, T1087.004, T1526 |
| [APT28](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0007) `G0007` | Rússia | 9 | 8 | T1189 |
| [VOID MANTICORE](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1055) `G1055` | Irã | 8 | 8 | — |
| [NIMBUS MANTICORE](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1059) `G1059` | — | 7 | 6 | T1649 |
| [ShinyHunters](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1057) `G1057` | Sem país atribuído | 7 | 5 | T1059.009, T1069.003 |
| [Dragonfly](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0035) `G0035` | Rússia | 6 | 2 | T1036.010, T1059, T1110.002, T1189 |
| [LAPSUS$](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1004) `G1004` | Sem país atribuído | 6 | 5 | T1136.003 |
| [Salt Typhoon](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1045) `G1045` | China | 6 | 5 | T1110.002 |
| [HAFNIUM](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0125) `G0125` | China | 5 | 5 | — |
| [Lazarus Group](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0032) `G0032` | Coreia do Norte | 5 | 4 | T1189 |
| [OilRig](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0049) `G0049` | Irã | 5 | 3 | T1059, T1201 |
| [TeamPCP](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1056) `G1056` | Sem país atribuído | 5 | 5 | — |

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
| [Okta FastPass Phishing Detection](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aee39a9f7-5a79-4b0a-9815-d36b3cf28d3e) | Sigma | SigmaHQ | T1566 |
| [Okta New Admin Console Behaviours](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aa0b38b70-3cb5-484b-a4eb-c4d8e7bcc0a9) | Sigma | SigmaHQ | T1078.004 |
| [Okta User Session Start Via An Anonymising Proxy Service](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Abde30855-5c53-4c18-ae90-1ff79ebc9578) | Sigma | SigmaHQ | T1685 |
| [Okta Suspicious Activity Reported by End-user](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A07e97cc6-aed1-43ae-9081-b3470d2367f1) | Sigma | SigmaHQ | T1586.003 |
| [Potential Okta Password in AlternateID Field](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A91b76b84-8589-47aa-9605-c837583b82a9) | Sigma | SigmaHQ | T1552 |
| [Potentially Successful Okta MFA Bombing via Push Notifications](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A97a8e584-fd3b-421f-9b9d-9c9d9e57e9d7) | Elastic | Elastic detection-rules | T1078, T1078.004, T1621 |
| [Stolen Credentials Used to Login to Okta Account After MFA Reset](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A5610b192-7f18-11ee-825b-f661ea17fbcd) | Elastic | Elastic detection-rules | T1556, T1556.006 |
| [Okta Alerts Following Unusual Proxy Authentication](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Aaf2d8e4c-3b7c-4e91-8f5a-6c9d0e1f2a3b) | Elastic | Elastic detection-rules | T1078, T1078.004 |
| [Okta User Session Impersonation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Acdbebdc1-dc97-43c6-a538-f26a20c0a911) | Elastic | Elastic detection-rules | T1078, T1078.004 |
| [Attempted Bypass of Okta MFA](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A3805c3dc-f82c-4f8d-891e-63c24d3102b0) | Elastic | Elastic detection-rules | T1111 |
| [Okta AiTM Session Cookie Replay](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A9ed5d08f-aad6-4c03-838c-d686da887c2c) | Elastic | Elastic detection-rules | T1539, T1550, T1550.004 |
| [Okta Successful Login After Credential Attack](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A50742e15-c5ef-49c8-9a2d-31221d45af58) | Elastic | Elastic detection-rules | T1078, T1078.004, T1110 |
| [Okta Multiple OS Names Detected for a Single DT Hash](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Afb3ca230-af4e-11f0-900d-f661ea17fbcc) | Elastic | Elastic detection-rules | T1539 |
| [Potential Okta MFA Bombing via Push Notifications](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A8a0fbd26-867f-11ee-947c-f661ea17fbcd) | Elastic | Elastic detection-rules | T1078, T1078.004, T1621 |
| [Okta User Account Locked Out](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A14701da0-4b0f-4ee6-9c95-2ffb4e73bb9a) | Sigma | SigmaHQ | T1531 |

## 10. Limites

- A tecnologia de cada regra é inferida por heurística sobre metadados e texto (techmap.py). Regras genéricas podem aparecer em várias tecnologias.
- "Sem regra" quer dizer sem regra pública neste catálogo, não sem detecção possível. Telemetria e contexto do seu ambiente decidem.
- Atribuição de país é afirmação das fontes reunidas pelo APT4ALL, não nossa.

---
Fontes: catálogo [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules), MITRE ATT&CK®, APT4ALL, Ransomware Tool Matrix (CC BY 4.0), TCEM, LLmInjection. Gerado em 2026-10-26.
