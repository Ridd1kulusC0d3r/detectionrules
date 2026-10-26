# Bancos de dados — relatório de regras de detecção

> **TLP:CLEAR** · 2026-10-26 · domínio **Web & aplicações** · lente TCEM **Web & API** · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#techno=db)

## 1. A história em um parágrafo

O palco é **os bancos de dados — onde mora o dado que o atacante quer levar**. O catálogo reúne **733 regras** que olham para cá — 454 de detecção, 29 de hunting, 228 assinaturas e 22 playbooks de resposta. Elas se concentram em **Persistência, Acesso a credenciais, Escalação de privilégio**. 

**Lente TCEM — Web & API.** Internet-facing applications, APIs, service trust, sessions, application data and runtime behavior. Para observar: application logs, gateway logs, WAF, authentication, API audit. Arquitetura a mapear: public endpoints, API gateways, sessions, service identities, backend trust.

## 2. Números

| Indicador | Valor |
|---|---:|
| Regras | 733 |
| detecção | 454 |
| assinatura | 228 |
| hunting | 29 |
| playbook | 22 |
| Técnicas ATT&CK distintas | 115 |

### Por tática

| Tática | Regras |
|---|---:|
| Reconhecimento | 2 |
| Acesso inicial | 42 |
| Execução | 30 |
| Persistência | 71 |
| Escalação de privilégio | 69 |
| Furtividade | 28 |
| Enfraquecimento de defesas | 13 |
| Acesso a credenciais | 70 |
| Descoberta | 26 |
| Movimento lateral | 10 |
| Coleta | 40 |
| Comando e controle | 9 |
| Exfiltração | 22 |
| Impacto | 36 |

### Linguagens disponíveis

Em que formato você encontra regra pronta para esta tecnologia.

| Formato | Regras |
|---|---:|
| Suricata/Snort/Sagan | 228 |
| Wazuh | 213 |
| Sigma | 82 |
| Elastic | 58 |
| Sentinel KQL | 58 |
| Splunk | 29 |
| Panther | 26 |
| Playbook | 22 |
| YARA-L | 12 |
| Falco | 3 |
| KQL hunting | 2 |

### Padrões de correlação (TCEM)

Como as regras decidem. Muitas de evento único = cobertura ampla mas ruidosa; sequências e novidade = mais contexto, mais exigência de dados.

| Padrão | Regras | O que significa |
|---|---:|---|
| Evento único | 515 | Um evento, sozinho, já tem sinal suficiente para chamar o analista. |
| Novidade / raridade | 95 | Compara com o que é normal: entidade, relação ou valor nunca (ou raramente) visto. |
| Limiar / acúmulo | 77 | O sinal está na repetição: N eventos por chave em uma janela. |
| Fluxo de resposta | 22 | Não detecta: orquestra o que fazer depois do alerta (SOAR). |
| Mudança de estado | 10 | O risco está na transição: algo era seguro e deixou de ser (desligado, rebaixado, alterado). |
| Sequência ordenada | 9 | Dois ou mais passos da mesma entidade, na ordem certa, dentro de uma janela. |
| Assinatura de conteúdo | 5 | Casa bytes/strings dentro de arquivo, memória ou pacote, não eventos de log. |

### Fontes que mais contribuem

| Fonte | Regras |
|---|---:|
| Sagan rules (Quadrant) | 223 |
| Wazuh ruleset (oficial) | 127 |
| EVTX-Wazuh-Rules (saifbelaarbi) | 81 |
| SigmaHQ | 59 |
| Elastic detection-rules | 39 |
| Microsoft Sentinel (Analytic Rules) | 34 |
| Splunk security_content | 26 |
| Panther panther-analysis | 26 |
| Microsoft Sentinel (Hunting Queries) | 24 |
| OpenSearch Security Analytics | 23 |

## 3. Técnicas mais cobertas

| Técnica | Regras nesta tecnologia |
|---|---:|
| [T1005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1005) Data from Local System | 29 |
| [T1546.011](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1546.011) Application Shimming | 26 |
| [T1190](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1190) Exploit Public-Facing Application | 23 |
| [T1003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1003) OS Credential Dumping | 18 |
| [T1003.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1003.002) Security Account Manager | 16 |
| [T1059](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059) Command and Scripting Interpreter | 15 |
| [T1003.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1003.003) NTDS | 14 |
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | 13 |
| [T1110](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1110) Brute Force | 11 |
| [T1069.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1069.002) Domain Groups | 10 |
| [T1087.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1087.002) Domain Account | 10 |
| [T1482](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1482) Domain Trust Discovery | 10 |

## 9. Regras recomendadas para começar

Ranqueadas por portabilidade do formato, maturidade, severidade e por mapearem técnica ATT&CK.

| Regra | Formato | Fonte | Técnicas |
|---|---|---|---|
| [MSSQL Extended Stored Procedure Backdoor Maggie](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A711ab2fe-c9ba-4746-8840-5228a58c3cb8) | Sigma | SigmaHQ | T1546 |
| [Potential Conti Ransomware Database Dumping Activity Via SQLCmd](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A2f47f1fd-0901-466e-a770-3b7092834a1b) | Sigma | SigmaHQ | T1005 |
| [Suspicious SQL Error Messages](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A8a670c6d-7189-4b1c-8017-a417ca84a086) | Sigma | SigmaHQ | T1190 |
| [OpenCanary - MSSQL Login Attempt Via Windows Authentication](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A6e78f90f-0043-4a01-ac41-f97681613a66) | Sigma | SigmaHQ | T1003, T1213 |
| [OpenCanary - MSSQL Login Attempt Via SQLAuth](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A3ec9a16d-0b4f-4967-9542-ebf38ceac7dd) | Sigma | SigmaHQ | T1003, T1213 |
| [OpenCanary - REDIS Action Command Attempt](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A547dfc53-ebf6-4afe-8d2e-793d9574975d) | Sigma | SigmaHQ | T1003, T1213 |
| [OpenCanary - MySQL Login Attempt](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae7d79a1b-25ed-4956-bd56-bd344fa8fd06) | Sigma | SigmaHQ | T1003, T1213 |
| [NTDS.DIT Creation By Uncommon Process](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A11b1ed55-154d-4e82-8ad7-83739298f720) | Sigma | SigmaHQ | T1003.002, T1003.003 |
| [NTDS.DIT Creation By Uncommon Parent Process](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4e7050dd-e548-483f-b7d6-527ab4fa784d) | Sigma | SigmaHQ | T1003.003 |
| [Potential SAM Database Dump](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4e87b8e2-2ee9-4b2a-a715-4727d297ece0) | Sigma | SigmaHQ | T1003.002 |
| [SQLite Firefox Profile Data DB Access](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4833155a-4053-4c9c-a997-777fcea0baa7) | Sigma | SigmaHQ | T1005, T1539 |
| [HackTool - Pypykatz Credentials Dumping Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aa29808fd-ef50-49ff-9c7a-59a9b040b404) | Sigma | SigmaHQ | T1003.002 |
| [Microsoft IIS Connection Strings Decryption](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A97dbf6e2-e436-44d8-abee-4261b24d3e41) | Sigma | SigmaHQ | T1003 |
| [SQLite Chromium Profile Data DB Access](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A24c77512-782b-448a-8950-eddb0785fc71) | Sigma | SigmaHQ | T1005, T1539, T1555.003 |
| [VeeamBackup Database Credentials Dump Via Sqlcmd.EXE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab57ba453-b384-4ab9-9f40-1038086b4e53) | Sigma | SigmaHQ | T1005 |

## 10. Limites

- A tecnologia de cada regra é inferida por heurística sobre metadados e texto (techmap.py). Regras genéricas podem aparecer em várias tecnologias.
- "Sem regra" quer dizer sem regra pública neste catálogo, não sem detecção possível. Telemetria e contexto do seu ambiente decidem.
- Atribuição de país é afirmação das fontes reunidas pelo APT4ALL, não nossa.

---
Fontes: catálogo [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules), MITRE ATT&CK®, APT4ALL, Ransomware Tool Matrix (CC BY 4.0), TCEM, LLmInjection. Gerado em 2026-10-26.
