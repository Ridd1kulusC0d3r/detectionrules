# Outros / genérico — relatório de regras de detecção

> **TLP:CLEAR** · 2026-10-26 · domínio **Outros** · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#techno=other)

## 1. A história em um parágrafo

O palco é **o ambiente descrito pela fonte do log desta regra**. O catálogo reúne **5,370 regras** que olham para cá — 1,450 de detecção, 274 de hunting, 2,757 assinaturas e 889 playbooks de resposta. Elas se concentram em **Acesso inicial, Persistência, Escalação de privilégio**. 

## 2. Números

| Indicador | Valor |
|---|---:|
| Regras | 5,370 |
| assinatura | 2,757 |
| detecção | 1,450 |
| playbook | 889 |
| hunting | 274 |
| Técnicas ATT&CK distintas | 213 |

### Por tática

| Tática | Regras |
|---|---:|
| Reconhecimento | 30 |
| Desenv. de recursos | 26 |
| Acesso inicial | 157 |
| Execução | 83 |
| Persistência | 145 |
| Escalação de privilégio | 118 |
| Furtividade | 118 |
| Enfraquecimento de defesas | 72 |
| Acesso a credenciais | 92 |
| Descoberta | 96 |
| Movimento lateral | 52 |
| Coleta | 81 |
| Comando e controle | 93 |
| Exfiltração | 60 |
| Impacto | 91 |

### Linguagens disponíveis

Em que formato você encontra regra pronta para esta tecnologia.

| Formato | Regras |
|---|---:|
| Suricata/Snort/Sagan | 2,757 |
| Playbook | 889 |
| Wazuh | 866 |
| Sentinel KQL | 570 |
| Splunk | 91 |
| Panther | 66 |
| KQL hunting | 65 |
| Sigma | 43 |
| Elastic | 22 |
| QRadar AQL | 1 |

### Padrões de correlação (TCEM)

Como as regras decidem. Muitas de evento único = cobertura ampla mas ruidosa; sequências e novidade = mais contexto, mais exigência de dados.

| Padrão | Regras | O que significa |
|---|---:|---|
| Evento único | 3,844 | Um evento, sozinho, já tem sinal suficiente para chamar o analista. |
| Fluxo de resposta | 889 | Não detecta: orquestra o que fazer depois do alerta (SOAR). |
| Limiar / acúmulo | 419 | O sinal está na repetição: N eventos por chave em uma janela. |
| Novidade / raridade | 162 | Compara com o que é normal: entidade, relação ou valor nunca (ou raramente) visto. |
| Mudança de estado | 52 | O risco está na transição: algo era seguro e deixou de ser (desligado, rebaixado, alterado). |
| Sequência ordenada | 4 | Dois ou mais passos da mesma entidade, na ordem certa, dentro de uma janela. |

### Fontes que mais contribuem

| Fonte | Regras |
|---|---:|
| Sagan rules (Quadrant) | 2,757 |
| Wazuh ruleset (oficial) | 589 |
| Cortex XSOAR (demisto/content) | 535 |
| Microsoft Sentinel (Analytic Rules) | 417 |
| SOCFortress Wazuh-Rules | 276 |
| Microsoft Sentinel (Hunting Queries) | 153 |
| awesome-playbooks · resolve | 72 |
| Panther panther-analysis | 66 |
| Bert-JanP Hunting Queries | 65 |
| awesome-playbooks · splunk | 57 |

## 3. Técnicas mais cobertas

| Técnica | Regras nesta tecnologia |
|---|---:|
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | 39 |
| [T1071](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1071) Application Layer Protocol | 36 |
| [T1685](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1685) Disable or Modify Tools | 34 |
| [T1059](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059) Command and Scripting Interpreter | 33 |
| [T1566](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1566) Phishing | 33 |
| [T1133](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1133) External Remote Services | 31 |
| [T1190](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1190) Exploit Public-Facing Application | 28 |
| [T1486](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1486) Data Encrypted for Impact | 27 |
| [T1041](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1041) Exfiltration Over C2 Channel | 24 |
| [T1071.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1071.001) Web Protocols | 24 |
| [T1110](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1110) Brute Force | 21 |
| [T1204](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1204) User Execution | 21 |

## 9. Regras recomendadas para começar

Ranqueadas por portabilidade do formato, maturidade, severidade e por mapearem técnica ATT&CK.

| Regra | Formato | Fonte | Técnicas |
|---|---|---|---|
| [Cisco Crypto Commands](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1f978c6a-4415-47fb-aca5-736a44d7ca3d) | Sigma | SigmaHQ | T1552.004, T1553.004 |
| [Cisco Disabling Logging](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A9e8f6035-88bf-4a63-96b6-b17c0508257e) | Sigma | SigmaHQ | T1685 |
| [Cisco Clear Logs](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aceb407f6-8277-439b-951f-e4210e3ed956) | Sigma | SigmaHQ | T1070.003 |
| [Cisco Local Accounts](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A6d844f0f-1c18-41af-8f19-33e7654edfc3) | Sigma | SigmaHQ | T1098, T1136.001 |
| [OpenCanary - VNC Connection Attempt](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A9db5446c-b44a-4291-8b89-fcab5609c3b3) | Sigma | SigmaHQ | T1021 |
| [OpenCanary - SMB File Open Request](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A22777c9e-873a-4b49-855f-6072ab861a52) | Sigma | SigmaHQ | T1005, T1021 |
| [OpenCanary - FTP Login Attempt](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A6991bc2b-ae2e-447f-bc55-3a1ba04c14e5) | Sigma | SigmaHQ | T1021, T1190 |
| [OpenCanary - NTP Monlist Request](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A7cded4b3-f09e-405a-b96f-24248433ba44) | Sigma | SigmaHQ | T1498 |
| [OpenCanary - SIP Request](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae30de276-68ec-435c-ab99-ef3befec6c61) | Sigma | SigmaHQ | T1123 |
| [OpenCanary - GIT Clone Request](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4fe17521-aef3-4e6a-9d6b-4a7c8de155a8) | Sigma | SigmaHQ | T1213 |
| [OpenCanary - Telnet Login Attempt](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A512cff7a-683a-43ad-afe0-dd398e872f36) | Sigma | SigmaHQ | T1078, T1133 |
| [Potential XXE Exploitation Attempt In JVM Based Application](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac4e06896-e27c-4583-95ac-91ce2279345d) | Sigma | SigmaHQ | T1190 |
| [Python SQL Exceptions](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A19aefed0-ffd4-47dc-a7fc-f8b1425e84f9) | Sigma | SigmaHQ | T1190 |
| [Django Framework Exceptions](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Afd435618-981e-4a7c-81f8-f78ce480d616) | Sigma | SigmaHQ | T1190 |
| [Ruby on Rails Framework Exceptions](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A0d2c3d4c-4b48-4ac3-8f23-ea845746bb1a) | Sigma | SigmaHQ | T1190 |

## 10. Limites

- A tecnologia de cada regra é inferida por heurística sobre metadados e texto (techmap.py). Regras genéricas podem aparecer em várias tecnologias.
- "Sem regra" quer dizer sem regra pública neste catálogo, não sem detecção possível. Telemetria e contexto do seu ambiente decidem.
- Atribuição de país é afirmação das fontes reunidas pelo APT4ALL, não nossa.

---
Fontes: catálogo [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules), MITRE ATT&CK®, APT4ALL, Ransomware Tool Matrix (CC BY 4.0), TCEM, LLmInjection. Gerado em 2026-10-26.
