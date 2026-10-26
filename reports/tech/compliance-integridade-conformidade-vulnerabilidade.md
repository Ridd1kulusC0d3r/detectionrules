# Integridade, conformidade & vulnerabilidade — relatório de regras de detecção

> **TLP:CLEAR** · 2026-10-26 · domínio **Infraestrutura** · lente TCEM **Detection & Validation** · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#techno=compliance)

## 1. A história em um parágrafo

O palco é **a integridade e a postura — arquivos críticos, configuração e vulnerabilidades**. O catálogo reúne **2,932 regras** que olham para cá — 2,184 de detecção, 52 de hunting, 594 assinaturas e 102 playbooks de resposta. Elas se concentram em **Escalação de privilégio, Persistência, Furtividade**. 

**Lente TCEM — Detection & Validation.** Threat-informed telemetry, analytics, validation, retest and analyst-response context. Para observar: sensor health, event quality, normalization, correlation, alert disposition. Arquitetura a mapear: sensors, collection pipelines, SIEM, EDR, correlation, case management.

## 2. Números

| Indicador | Valor |
|---|---:|
| Regras | 2,932 |
| detecção | 2,184 |
| assinatura | 594 |
| playbook | 102 |
| hunting | 52 |
| Técnicas ATT&CK distintas | 149 |

### Por tática

| Tática | Regras |
|---|---:|
| Reconhecimento | 7 |
| Desenv. de recursos | 4 |
| Acesso inicial | 151 |
| Execução | 41 |
| Persistência | 198 |
| Escalação de privilégio | 303 |
| Furtividade | 187 |
| Enfraquecimento de defesas | 160 |
| Acesso a credenciais | 115 |
| Descoberta | 38 |
| Movimento lateral | 26 |
| Coleta | 63 |
| Comando e controle | 30 |
| Exfiltração | 11 |
| Impacto | 111 |

### Linguagens disponíveis

Em que formato você encontra regra pronta para esta tecnologia.

| Formato | Regras |
|---|---:|
| Wazuh | 1,918 |
| Suricata/Snort/Sagan | 594 |
| YARA-L | 117 |
| Playbook | 102 |
| Sentinel KQL | 64 |
| KQL hunting | 37 |
| Elastic | 32 |
| Panther | 26 |
| Splunk | 24 |
| Sigma | 18 |

### Padrões de correlação (TCEM)

Como as regras decidem. Muitas de evento único = cobertura ampla mas ruidosa; sequências e novidade = mais contexto, mais exigência de dados.

| Padrão | Regras | O que significa |
|---|---:|---|
| Evento único | 2,418 | Um evento, sozinho, já tem sinal suficiente para chamar o analista. |
| Limiar / acúmulo | 155 | O sinal está na repetição: N eventos por chave em uma janela. |
| Sequência ordenada | 121 | Dois ou mais passos da mesma entidade, na ordem certa, dentro de uma janela. |
| Fluxo de resposta | 102 | Não detecta: orquestra o que fazer depois do alerta (SOAR). |
| Mudança de estado | 70 | O risco está na transição: algo era seguro e deixou de ser (desligado, rebaixado, alterado). |
| Novidade / raridade | 63 | Compara com o que é normal: entidade, relação ou valor nunca (ou raramente) visto. |
| Assinatura de conteúdo | 3 | Casa bytes/strings dentro de arquivo, memória ou pacote, não eventos de log. |

### Fontes que mais contribuem

| Fonte | Regras |
|---|---:|
| Wazuh ruleset (oficial) | 1,837 |
| Sagan rules (Quadrant) | 591 |
| Cortex XSOAR (demisto/content) | 78 |
| Microsoft Sentinel (Analytic Rules) | 62 |
| Google SecOps / Chronicle | 59 |
| SOCFortress Wazuh-Rules | 59 |
| Chronicle rules (rowham) | 58 |
| Bert-JanP Hunting Queries | 37 |
| Elastic detection-rules | 26 |
| Panther panther-analysis | 26 |

## 3. Técnicas mais cobertas

| Técnica | Regras nesta tecnologia |
|---|---:|
| [T1484](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1484) Domain or Tenant Policy Modification | 103 |
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | 90 |
| [T1110](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1110) Brute Force | 89 |
| [T1499](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1499) Endpoint Denial of Service | 40 |
| [T1114](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1114) Email Collection | 37 |
| [T1055](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1055) Process Injection | 33 |
| [T1133](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1133) External Remote Services | 24 |
| [T1531](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1531) Account Access Removal | 23 |
| [T1190](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1190) Exploit Public-Facing Application | 20 |
| [T1685](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1685) Disable or Modify Tools | 18 |
| [T1098](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1098) Account Manipulation | 15 |
| [T1070.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1070.004) File Deletion | 15 |

## 9. Regras recomendadas para começar

Ranqueadas por portabilidade do formato, maturidade, severidade e por mapearem técnica ATT&CK.

| Regra | Formato | Fonte | Técnicas |
|---|---|---|---|
| [DHCP Callout DLL Installation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A9d3436ef-9476-4c43-acca-90ce06bdf33a) | Sigma | SigmaHQ | T1112, T1574.001 |
| [Invalid PIM License](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A58af08eb-f9e1-43c8-9805-3ad9b0482bd8) | Sigma | SigmaHQ | T1078 |
| [OpenAI ChatGPT Enterprise Codex Prompt Containing Credentials](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ade41effc-9966-4cae-a5bb-2773bf7f641f) | Elastic | Elastic detection-rules | T0055, T1552 |
| [OpenAI ChatGPT Enterprise User Activity From High Number of Countries](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ad7e01c19-4463-4693-bd98-451875737fc8) | Elastic | Elastic detection-rules | T0012, T1078, T1078.004 |
| [OpenAI ChatGPT Enterprise Conversation Message Containing Credentials](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A231c2ade-69c8-4415-b710-0c56f5f07e95) | Elastic | Elastic detection-rules | T0055, T0057, T1552 |
| [Anthropic Compliance API Logging Disabled](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A4890f6d3-709f-440e-9135-d22403516ef7) | Elastic | Elastic detection-rules | T1685, T1685.002 |
| [Anthropic Compliance API Key Created](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ab8c429a1-67f3-448c-a960-951807dd2cd8) | Elastic | Elastic detection-rules | T1098, T1098.001 |
| [Microsoft 365 - User Restricted from Sending Email](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aff246f56-7f24-402a-baca-b86540e3925c) | Sigma | SigmaHQ | T1199 |
| [PST Export Alert Using New-ComplianceSearchAction](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A6897cd82-6664-11ed-9022-0242ac120002) | Sigma | SigmaHQ | T1114 |
| [Web Server Potential Spike in Error Response Codes](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A6fa3abe3-9cd8-41de-951b-51ed8f710523) | Elastic | Elastic detection-rules | T1595, T1595.002, T1595.003 |
| [Potential Spike in Web Server Error Logs](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A6631a759-4559-4c33-a392-13f146c8bcc4) | Elastic | Elastic detection-rules | T1595, T1595.002, T1595.003 |
| [AWS Security Hub Disabled](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ac8a2d4f6-1b3e-4a7c-9d5f-8e0b2c6a4d1e) | Elastic | Elastic detection-rules | T1685 |
| [AWS SSM Inventory Reconnaissance by Rare User](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A1004ad5b-6900-4d28-ab5b-472f02e1fdfb) | Elastic | Elastic detection-rules | T1518, T1538, T1580 |
| [AWS Config Resource Deletion](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A7024e2a0-315d-4334-bb1a-552d604f27bc) | Elastic | Elastic detection-rules | T1685, T1685.002 |
| [Unusual High Word Policy Blocks Detected](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A3216949c-9300-4c53-b57a-221e364c6457) | Elastic | Elastic detection-rules | T0051, T0054 |

## 10. Limites

- A tecnologia de cada regra é inferida por heurística sobre metadados e texto (techmap.py). Regras genéricas podem aparecer em várias tecnologias.
- "Sem regra" quer dizer sem regra pública neste catálogo, não sem detecção possível. Telemetria e contexto do seu ambiente decidem.
- Atribuição de país é afirmação das fontes reunidas pelo APT4ALL, não nossa.

---
Fontes: catálogo [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules), MITRE ATT&CK®, APT4ALL, Ransomware Tool Matrix (CC BY 4.0), TCEM, LLmInjection. Gerado em 2026-10-26.
