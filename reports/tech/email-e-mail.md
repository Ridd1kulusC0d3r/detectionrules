# E-mail — relatório de regras de detecção

> **TLP:CLEAR** · 2026-10-26 · domínio **Rede** · lente TCEM **Identity & Access** · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#techno=email)

## 1. A história em um parágrafo

O palco é **o e-mail — ainda a porta de entrada mais usada**. O catálogo reúne **2,037 regras** que olham para cá — 678 de detecção, 501 de hunting, 455 assinaturas e 403 playbooks de resposta. Elas se concentram em **Acesso inicial, Persistência, Escalação de privilégio**. 

**Lente TCEM — Identity & Access.** Authentication, authorization, privilege, federation, machine identity and administrative trust. Para observar: sign-in logs, privilege changes, token events, identity administration. Arquitetura a mapear: identity providers, privileged roles, service principals, federation, recovery access.

## 2. Números

| Indicador | Valor |
|---|---:|
| Regras | 2,037 |
| detecção | 678 |
| hunting | 501 |
| assinatura | 455 |
| playbook | 403 |
| Técnicas ATT&CK distintas | 157 |

### Por tática

| Tática | Regras |
|---|---:|
| Reconhecimento | 14 |
| Desenv. de recursos | 10 |
| Acesso inicial | 228 |
| Execução | 65 |
| Persistência | 130 |
| Escalação de privilégio | 106 |
| Furtividade | 98 |
| Enfraquecimento de defesas | 23 |
| Acesso a credenciais | 60 |
| Descoberta | 7 |
| Movimento lateral | 34 |
| Coleta | 89 |
| Comando e controle | 32 |
| Exfiltração | 62 |
| Impacto | 42 |

### Linguagens disponíveis

Em que formato você encontra regra pronta para esta tecnologia.

| Formato | Regras |
|---|---:|
| Sentinel KQL | 618 |
| Suricata/Snort/Sagan | 455 |
| Playbook | 403 |
| Elastic | 127 |
| Wazuh | 127 |
| Splunk | 85 |
| Panther | 85 |
| Sigma | 64 |
| YARA-L | 48 |
| KQL hunting | 25 |

### Padrões de correlação (TCEM)

Como as regras decidem. Muitas de evento único = cobertura ampla mas ruidosa; sequências e novidade = mais contexto, mais exigência de dados.

| Padrão | Regras | O que significa |
|---|---:|---|
| Evento único | 1,215 | Um evento, sozinho, já tem sinal suficiente para chamar o analista. |
| Fluxo de resposta | 403 | Não detecta: orquestra o que fazer depois do alerta (SOAR). |
| Novidade / raridade | 212 | Compara com o que é normal: entidade, relação ou valor nunca (ou raramente) visto. |
| Limiar / acúmulo | 112 | O sinal está na repetição: N eventos por chave em uma janela. |
| Sequência ordenada | 47 | Dois ou mais passos da mesma entidade, na ordem certa, dentro de uma janela. |
| Mudança de estado | 41 | O risco está na transição: algo era seguro e deixou de ser (desligado, rebaixado, alterado). |
| Assinatura de conteúdo | 7 | Casa bytes/strings dentro de arquivo, memória ou pacote, não eventos de log. |

### Fontes que mais contribuem

| Fonte | Regras |
|---|---:|
| Sagan rules (Quadrant) | 448 |
| Microsoft Sentinel (Hunting Queries) | 441 |
| Cortex XSOAR (demisto/content) | 189 |
| Microsoft Sentinel (Analytic Rules) | 177 |
| Elastic detection-rules | 103 |
| Wazuh ruleset (oficial) | 94 |
| Panther panther-analysis | 85 |
| Splunk security_content | 55 |
| SigmaHQ | 47 |
| awesome-playbooks · ms_azure | 39 |

## 3. Técnicas mais cobertas

| Técnica | Regras nesta tecnologia |
|---|---:|
| [T1566](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1566) Phishing | 119 |
| [T1566.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1566.002) Spearphishing Link | 68 |
| [T1566.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1566.001) Spearphishing Attachment | 56 |
| [T1114](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1114) Email Collection | 52 |
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | 49 |
| [T1078.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.004) Cloud Accounts | 34 |
| [T1204](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1204) User Execution | 31 |
| [T1098](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1098) Account Manipulation | 30 |
| [T1059](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059) Command and Scripting Interpreter | 24 |
| [T1020](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1020) Automated Exfiltration | 20 |
| [T1071](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1071) Application Layer Protocol | 20 |
| [T1550](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1550) Use Alternate Authentication Material | 20 |

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
| [APT29 2018 Phishing Campaign File Indicators](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A3a3f81ca-652c-482b-adeb-b1c804727f74) | Sigma | SigmaHQ | T1218.011 |
| [APT29 2018 Phishing Campaign CommandLine Indicators](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A7453575c-a747-40b9-839b-125a0aae324b) | Sigma | SigmaHQ | T1218.011 |
| [Suspicious Double Extension File Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1cdd9a09-06c9-4769-99ff-626e2b3991b8) | Sigma | SigmaHQ | T1566.001 |
| [Unidentified Attacker November 2018](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A7453575c-a747-40b9-839b-125a0aae324b) | Sigma | OpenSearch Security Analytics | T1218.011 |
| [Suspicious Double Extension](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A1cdd9a09-06c9-4769-99ff-626e2b3991b8) | Sigma | OpenSearch Security Analytics | T1566.001 |
| [Emotet Loader Execution Via .LNK File](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1f32d820-1d5c-43fe-8fe2-feef0c952eb7) | Sigma | SigmaHQ | T1059.006 |
| [Serpent Backdoor Payload Execution Via Scheduled Task](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad5eb7432-fda4-4bba-a37f-ffa74d9ed639) | Sigma | SigmaHQ | T1053.005, T1059.006 |
| [Okta FastPass Phishing Detection](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aee39a9f7-5a79-4b0a-9815-d36b3cf28d3e) | Sigma | SigmaHQ | T1566 |
| [Potential RipZip Attack on Startup Folder](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aa6976974-ea6f-4e97-818e-ea08625c52cb) | Sigma | SigmaHQ | T1547 |
| [OneNote.EXE Execution of Malicious Embedded Scripts](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A84b1706c-932a-44c4-ae28-892b28a25b94) | Sigma | SigmaHQ | T1218.001 |
| [Phishing Pattern ISO in Archive](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Afcdf69e5-a3d3-452a-9724-26f2308bf2b1) | Sigma | SigmaHQ | T1566 |
| [Suspicious Download from Office Domain](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A00d49ed5-4491-4271-a8db-650a4ef6f8c1) | Sigma | SigmaHQ | T1105, T1608 |
| [Password Protected ZIP File Opened (Email Attachment)](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A571498c8-908e-40b4-910b-d2369159a3da) | Sigma | SigmaHQ | T1027, T1566.001 |
| [AWS SNS Topic Message Publish by Rare User](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A2112ecce-cd34-11ef-873f-f661ea17fbcd) | Elastic | Elastic detection-rules | T1102, T1496, T1496.004 |
| [Okta AiTM Session Cookie Replay](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A9ed5d08f-aad6-4c03-838c-d686da887c2c) | Elastic | Elastic detection-rules | T1539, T1550, T1550.004 |

## 10. Limites

- A tecnologia de cada regra é inferida por heurística sobre metadados e texto (techmap.py). Regras genéricas podem aparecer em várias tecnologias.
- "Sem regra" quer dizer sem regra pública neste catálogo, não sem detecção possível. Telemetria e contexto do seu ambiente decidem.
- Atribuição de país é afirmação das fontes reunidas pelo APT4ALL, não nossa.

---
Fontes: catálogo [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules), MITRE ATT&CK®, APT4ALL, Ransomware Tool Matrix (CC BY 4.0), TCEM, LLmInjection. Gerado em 2026-10-26.
