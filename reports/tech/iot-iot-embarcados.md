# IoT & embarcados — relatório de regras de detecção

> **TLP:CLEAR** · 2026-10-26 · domínio **OT & IoT** · lente TCEM **IoT & Embedded** · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#techno=iot)

## 1. A história em um parágrafo

O palco é **dispositivos IoT e embarcados — câmeras, impressoras, placas de gerência**. O catálogo reúne **172 regras** que olham para cá — 104 de detecção, 15 de hunting, 34 assinaturas e 19 playbooks de resposta. Elas se concentram em **Execução, Furtividade, Acesso inicial**. 

**Lente TCEM — IoT & Embedded.** Devices, firmware, management interfaces, fleet identity, update trust and constrained telemetry. Para observar: device inventory, update events, gateway telemetry, management audit. Arquitetura a mapear: device identity, firmware/update chain, fleet management, gateways.

## 2. Números

| Indicador | Valor |
|---|---:|
| Regras | 172 |
| detecção | 104 |
| assinatura | 34 |
| playbook | 19 |
| hunting | 15 |
| Técnicas ATT&CK distintas | 59 |

### Por tática

| Tática | Regras |
|---|---:|
| Acesso inicial | 12 |
| Execução | 28 |
| Persistência | 10 |
| Escalação de privilégio | 9 |
| Furtividade | 26 |
| Enfraquecimento de defesas | 4 |
| Acesso a credenciais | 7 |
| Descoberta | 5 |
| Movimento lateral | 5 |
| Comando e controle | 9 |
| Exfiltração | 3 |
| Impacto | 2 |

### Linguagens disponíveis

Em que formato você encontra regra pronta para esta tecnologia.

| Formato | Regras |
|---|---:|
| Suricata/Snort/Sagan | 34 |
| Sentinel KQL | 33 |
| Sigma | 29 |
| Elastic | 22 |
| Playbook | 19 |
| Wazuh | 18 |
| Splunk | 15 |
| YARA-L | 2 |

### Padrões de correlação (TCEM)

Como as regras decidem. Muitas de evento único = cobertura ampla mas ruidosa; sequências e novidade = mais contexto, mais exigência de dados.

| Padrão | Regras | O que significa |
|---|---:|---|
| Evento único | 125 | Um evento, sozinho, já tem sinal suficiente para chamar o analista. |
| Fluxo de resposta | 19 | Não detecta: orquestra o que fazer depois do alerta (SOAR). |
| Novidade / raridade | 13 | Compara com o que é normal: entidade, relação ou valor nunca (ou raramente) visto. |
| Sequência ordenada | 9 | Dois ou mais passos da mesma entidade, na ordem certa, dentro de uma janela. |
| Mudança de estado | 4 | O risco está na transição: algo era seguro e deixou de ser (desligado, rebaixado, alterado). |
| Limiar / acúmulo | 2 | O sinal está na repetição: N eventos por chave em uma janela. |

### Fontes que mais contribuem

| Fonte | Regras |
|---|---:|
| Sagan rules (Quadrant) | 34 |
| Microsoft Sentinel (Analytic Rules) | 23 |
| SigmaHQ | 18 |
| Cortex XSOAR (demisto/content) | 16 |
| OpenSearch Security Analytics | 11 |
| Elastic detection-rules | 11 |
| Elastic protections-artifacts (behavior) | 11 |
| Splunk security_content | 10 |
| Microsoft Sentinel (Hunting Queries) | 10 |
| EVTX-Wazuh-Rules (saifbelaarbi) | 9 |

## 3. Técnicas mais cobertas

| Técnica | Regras nesta tecnologia |
|---|---:|
| [T1059](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059) Command and Scripting Interpreter | 9 |
| [T1574](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1574) Hijack Execution Flow | 6 |
| [T1027](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1027) Obfuscated Files or Information | 6 |
| [T1566.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1566.001) Spearphishing Attachment | 6 |
| [T1566](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1566) Phishing | 6 |
| [T1059.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.001) PowerShell | 5 |
| [T1212](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1212) Exploitation for Credential Access | 5 |
| [T1071](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1071) Application Layer Protocol | 5 |
| [T1204](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1204) User Execution | 4 |
| [T1218.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1218.001) Compiled HTML File | 4 |
| [T1068](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1068) Exploitation for Privilege Escalation | 4 |
| [T1203](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1203) Exploitation for Client Execution | 4 |

## 9. Regras recomendadas para começar

Ranqueadas por portabilidade do formato, maturidade, severidade e por mapearem técnica ATT&CK.

| Regra | Formato | Fonte | Técnicas |
|---|---|---|---|
| [Antivirus PrinterNightmare CVE-2021-34527 Exploit Detection](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A6fe1719e-ecdf-4caf-bffe-4f501cb0a561) | Sigma | SigmaHQ | T1055 |
| [Suspicious PrinterPorts Creation (CVE-2020-1048)](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acc08d590-8b90-413a-aff6-31d1a99678d7) | Sigma | SigmaHQ | T1059.001 |
| [CVE-2020-1048 Exploitation Attempt - Suspicious New Printer Ports - Registry](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A7ec912f2-5175-4868-b811-ec13ad0f8567) | Sigma | SigmaHQ | T1112 |
| [PrinterNightmare Mimikatz Driver Name](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aba6b9e43-1d45-4d3c-a504-1043a64c8469) | Sigma | SigmaHQ | T1204 |
| [CVE-2021-1675 Print Spooler Exploitation IPC Access](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A8fe1c584-ee61-444b-be21-e9054b229694) | Sigma | SigmaHQ | T1569 |
| [OneNote.EXE Execution of Malicious Embedded Scripts](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A84b1706c-932a-44c4-ae28-892b28a25b94) | Sigma | SigmaHQ | T1218.001 |
| [Share And Session Enumeration Using Net.EXE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A62510e69-616b-4078-b371-847da438cc03) | Sigma | SigmaHQ | T1018 |
| [Suspicious NTLM Authentication on the Printer Spooler Service](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Abb76d96b-821c-47cf-944b-7ce377864492) | Sigma | SigmaHQ | T1212 |
| [Suspicious Microsoft OneNote Child Process](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac27515df-97a9-4162-8a60-dc0eeb51b775) | Sigma | SigmaHQ | T1566.001 |
| [Suspicious Printer Driver Empty Manufacturer](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae0813366-0407-449a-9869-a2db1119dc41) | Sigma | SigmaHQ | T1574 |
| [SystemNightmare Exploitation Script Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Ac01f7bd6-0c1d-47aa-9c61-187b91273a16) | Sigma | OpenSearch Security Analytics | T1068 |
| [Suspicious New Printer Ports in Registry (CVE-2020-1048)](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A7ec912f2-5175-4868-b811-ec13ad0f8567) | Sigma | OpenSearch Security Analytics | T1112 |
| [Potential Tunneling via AWS IoT Secure Tunneling Localproxy](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Adeab559f-f3ab-4ce3-b17c-8f70c4169fd6) | Elastic | Elastic detection-rules | T1071, T1071.001, T1090 |
| [Printer User (lp) Shell Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Af86cd31c-5c7e-4481-99d7-6875a3e31309) | Elastic | Elastic detection-rules | T1059, T1059.004, T1203 |
| [Suspicious Linux Process Connection to AWS IoT Core MQTT](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A3c92b53d-3376-4c79-86fb-7e785fe8d882) | Elastic | Elastic detection-rules | T1071, T1071.005 |

## 10. Limites

- A tecnologia de cada regra é inferida por heurística sobre metadados e texto (techmap.py). Regras genéricas podem aparecer em várias tecnologias.
- "Sem regra" quer dizer sem regra pública neste catálogo, não sem detecção possível. Telemetria e contexto do seu ambiente decidem.
- Atribuição de país é afirmação das fontes reunidas pelo APT4ALL, não nossa.

---
Fontes: catálogo [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules), MITRE ATT&CK®, APT4ALL, Ransomware Tool Matrix (CC BY 4.0), TCEM, LLmInjection. Gerado em 2026-10-26.
