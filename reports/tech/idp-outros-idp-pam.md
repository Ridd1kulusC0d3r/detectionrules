# Outros IdP / PAM — relatório de regras de detecção

> **TLP:CLEAR** · 2026-10-26 · domínio **Identidade** · plataforma ATT&CK **Identity Provider** · lente TCEM **Identity & Access** · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#techno=idp)

## 1. A história em um parágrafo

O palco é **o provedor de identidade e o cofre de senhas privilegiadas**. O catálogo reúne **1,713 regras** que olham para cá — 360 de detecção, 68 de hunting, 1,232 assinaturas e 53 playbooks de resposta. Elas se concentram em **Persistência, Escalação de privilégio, Acesso inicial**. Das 49 técnicas do ATT&CK para a plataforma Identity Provider, **35 (71%)** têm ao menos uma regra aqui e **14 não têm nenhuma** — é onde um atacante passa sem ser visto. Entre os grupos com mais técnicas nesta plataforma estão APT29, Scattered Spider, Storm-0501.

**Lente TCEM — Identity & Access.** Authentication, authorization, privilege, federation, machine identity and administrative trust. Para observar: sign-in logs, privilege changes, token events, identity administration. Arquitetura a mapear: identity providers, privileged roles, service principals, federation, recovery access.

## 2. Números

| Indicador | Valor |
|---|---:|
| Regras | 1,713 |
| assinatura | 1,232 |
| detecção | 360 |
| hunting | 68 |
| playbook | 53 |
| Técnicas ATT&CK distintas | 73 |
| Cobertura da plataforma Identity Provider | 35/49 (71%) |

### Por tática

| Tática | Regras |
|---|---:|
| Desenv. de recursos | 3 |
| Acesso inicial | 84 |
| Execução | 6 |
| Persistência | 123 |
| Escalação de privilégio | 107 |
| Furtividade | 83 |
| Enfraquecimento de defesas | 30 |
| Acesso a credenciais | 62 |
| Descoberta | 7 |
| Movimento lateral | 45 |
| Coleta | 7 |
| Comando e controle | 1 |
| Exfiltração | 3 |
| Impacto | 5 |

### Linguagens disponíveis

Em que formato você encontra regra pronta para esta tecnologia.

| Formato | Regras |
|---|---:|
| Suricata/Snort/Sagan | 1,232 |
| Sentinel KQL | 158 |
| Panther | 105 |
| Elastic | 67 |
| Playbook | 53 |
| Splunk | 34 |
| Sigma | 23 |
| YARA-L | 20 |
| Wazuh | 16 |
| KQL hunting | 5 |

### Padrões de correlação (TCEM)

Como as regras decidem. Muitas de evento único = cobertura ampla mas ruidosa; sequências e novidade = mais contexto, mais exigência de dados.

| Padrão | Regras | O que significa |
|---|---:|---|
| Evento único | 1,389 | Um evento, sozinho, já tem sinal suficiente para chamar o analista. |
| Novidade / raridade | 120 | Compara com o que é normal: entidade, relação ou valor nunca (ou raramente) visto. |
| Limiar / acúmulo | 88 | O sinal está na repetição: N eventos por chave em uma janela. |
| Fluxo de resposta | 53 | Não detecta: orquestra o que fazer depois do alerta (SOAR). |
| Mudança de estado | 41 | O risco está na transição: algo era seguro e deixou de ser (desligado, rebaixado, alterado). |
| Sequência ordenada | 21 | Dois ou mais passos da mesma entidade, na ordem certa, dentro de uma janela. |
| Assinatura de conteúdo | 1 | Casa bytes/strings dentro de arquivo, memória ou pacote, não eventos de log. |

### Fontes que mais contribuem

| Fonte | Regras |
|---|---:|
| Sagan rules (Quadrant) | 1,231 |
| Panther panther-analysis | 105 |
| Microsoft Sentinel (Analytic Rules) | 101 |
| Elastic detection-rules | 62 |
| Microsoft Sentinel (Hunting Queries) | 57 |
| Splunk security_content | 33 |
| Cortex XSOAR (demisto/content) | 24 |
| Wazuh ruleset (oficial) | 15 |
| Google SecOps / Chronicle | 14 |
| SigmaHQ | 12 |

## 3. Técnicas mais cobertas

| Técnica | Regras nesta tecnologia |
|---|---:|
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | 61 |
| [T1078.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.004) Cloud Accounts | 44 |
| [T1550](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1550) Use Alternate Authentication Material | 39 |
| [T1550.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1550.001) Application Access Token | 31 |
| [T1098](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1098) Account Manipulation | 30 |
| [T1566](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1566) Phishing | 24 |
| [T1566.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1566.002) Spearphishing Link | 22 |
| [T1528](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1528) Steal Application Access Token | 22 |
| [T1556](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1556) Modify Authentication Process | 12 |
| [T1685](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1685) Disable or Modify Tools | 10 |
| [T1136](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1136) Create Account | 9 |
| [T1110](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1110) Brute Force | 8 |

## 4. Detecção pela ausência — o que ninguém está olhando (14 técnicas)

Técnicas do ATT&CK para Identity Provider **sem nenhuma regra nesta tecnologia**, ordenadas pelo número de grupos que as usam. A coluna "regras no catálogo" mostra se existe cobertura em outra tecnologia (ex.: EDR ou rede) que você pode adaptar.

| Técnica | Grupos que usam | Regras no catálogo (todas as tecnologias) |
|---|---:|---:|
| [T1189](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1189) Drive-by Compromise | 31 | 57 |
| [T1036.010](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1036.010) Masquerade Account Name | 4 | 1 |
| [T1059.009](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.009) Cloud API | 4 | 11 |
| [T1078.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.001) Default Accounts | 4 | 16 |
| [T1110.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1110.001) Password Guessing | 4 | 63 |
| [T1110.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1110.002) Password Cracking | 4 | 11 |
| [T1201](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1201) Password Policy Discovery | 3 | 43 |
| [T1110.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1110.004) Credential Stuffing | 2 | 35 |
| [T1649](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1649) Steal or Forge Authentication Certificates | 2 | 43 |
| [T1556.007](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1556.007) Hybrid Identity | 1 | 5 |
| [T1566.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1566.004) Spearphishing Voice | 1 | **0** |
| [T1685.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1685.002) Disable or Modify Cloud Log | 1 | 80 |
| [T1697](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1697) Steal Application Specific Passwords | 1 | **0** |
| [T1548.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1548.005) Temporary Elevated Cloud Access | 0 | 8 |

## 5. Quem mira esta plataforma

Grupos com mais técnicas registradas nesta plataforma e quantas delas você enxerga com as regras desta tecnologia. País atribuído pelo APT4ALL (afirmação de quem publicou).

| Grupo | Origem atribuída | Técnicas na plataforma | Com regra aqui | Exemplos sem regra |
|---|---|---:|---:|---|
| [APT29](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0016) `G0016` | Rússia | 16 | 11 | T1059.009, T1110.001, T1556.007, T1649 |
| [Scattered Spider](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1015) `G1015` | Sem país atribuído | 13 | 13 | — |
| [Storm-0501](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1053) `G1053` | Sem país atribuído | 10 | 9 | T1059.009 |
| [APT28](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0007) `G0007` | Rússia | 9 | 7 | T1110.001, T1189 |
| [VOID MANTICORE](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1055) `G1055` | Irã | 8 | 6 | T1110.001, T1110.004 |
| [NIMBUS MANTICORE](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1059) `G1059` | — | 7 | 6 | T1649 |
| [ShinyHunters](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1057) `G1057` | Sem país atribuído | 7 | 6 | T1059.009 |
| [Dragonfly](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0035) `G0035` | Rússia | 6 | 3 | T1036.010, T1110.002, T1189 |
| [LAPSUS$](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1004) `G1004` | Sem país atribuído | 6 | 6 | — |
| [Salt Typhoon](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1045) `G1045` | China | 6 | 4 | T1110.001, T1110.002 |
| [HAFNIUM](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0125) `G0125` | China | 5 | 5 | — |
| [Lazarus Group](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0032) `G0032` | Coreia do Norte | 5 | 4 | T1189 |
| [OilRig](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0049) `G0049` | Irã | 5 | 4 | T1201 |
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
| [AWS Identity Center Identity Provider Change](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad3adb3ef-b7e7-4003-9092-1924c797db35) | Sigma | SigmaHQ | T1556 |
| [Abusing Azure Browser SSO](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A50f852e6-af22-4c78-9ede-42ef36aa3453) | Sigma | OpenSearch Security Analytics | T1574.001 |
| [FortiGate SSO Login Followed by Administrator Account Creation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ae3a7b1c2-5d9f-4e8a-b6c3-2f1d4e5a6b7c) | Elastic | Elastic detection-rules | T1136, T1136.001, T1190 |
| [Google Workspace Device Registration After OAuth from Suspicious ASN](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A012bfca7-45cb-4507-a3ba-3777167f8b81) | Elastic | Elastic detection-rules | T1098, T1098.005, T1566 |
| [Google Workspace API Access Granted via Domain-Wide Delegation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Aacbc8bb9-2486-49a8-8779-45fb5f9a93ee) | Elastic | Elastic detection-rules | T1098 |
| [Application Added to Google Workspace Domain](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A785a404b-75aa-4ffd-8be5-3334a5a544dd) | Elastic | Elastic detection-rules | T1098, T1098.001 |
| [Google Workspace Object Copied from External Drive with App Consent](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Af33e68a4-bd19-11ed-b02f-f661ea17fbcc) | Elastic | Elastic detection-rules | T1098, T1098.001, T1204 |
| [AWS IAM API Calls via Temporary Session Tokens](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ac70d9f0d-8cb6-4cfc-85df-a95c1ccf4eab) | Elastic | Elastic detection-rules | T1078, T1078.004, T1098 |
| [AWS IAM OIDC Provider Created by Rare User](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A47403d72-3ee2-4752-a676-19dc8ff2b9d6) | Elastic | Elastic detection-rules | T1078, T1078.004, T1484 |
| [AWS IAM SAML Provider Created](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Aa80ffc40-a256-475a-a86a-74361930cdb1) | Elastic | Elastic detection-rules | T1078, T1078.004, T1098 |
| [AWS Credentials Used from GitHub Actions and Non-CI/CD Infrastructure](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ab8c7d6e5-f4a3-4b2c-9d8e-7f6a5b4c3d2e) | Elastic | Elastic detection-rules | T1078, T1078.004, T1550 |
| [Stolen Credentials Used to Login to Okta Account After MFA Reset](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A5610b192-7f18-11ee-825b-f661ea17fbcd) | Elastic | Elastic detection-rules | T1556, T1556.006 |
| [CyberArk Privileged Access Security Recommended Monitor](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ac5f81243-56e0-47f9-b5bb-55a5ed89ba57) | Elastic | Elastic detection-rules | T1078, T1098, T1555 |
| [CyberArk Privileged Access Security Error](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A3f0e5410-a4bf-4e8c-bcfc-79d67a285c54) | Elastic | Elastic detection-rules | T1078 |
| [Entra ID OAuth Device Code Flow with Concurrent Sign-ins](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A3db029b3-fbb7-4697-ad07-33cbfd5bd080) | Elastic | Elastic detection-rules | T1078, T1078.004, T1528 |

## 10. Limites

- A tecnologia de cada regra é inferida por heurística sobre metadados e texto (techmap.py). Regras genéricas podem aparecer em várias tecnologias.
- "Sem regra" quer dizer sem regra pública neste catálogo, não sem detecção possível. Telemetria e contexto do seu ambiente decidem.
- Atribuição de país é afirmação das fontes reunidas pelo APT4ALL, não nossa.

---
Fontes: catálogo [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules), MITRE ATT&CK®, APT4ALL, Ransomware Tool Matrix (CC BY 4.0), TCEM, LLmInjection. Gerado em 2026-10-26.
