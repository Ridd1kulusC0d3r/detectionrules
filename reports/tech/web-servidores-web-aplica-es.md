# Servidores web & aplicações — relatório de regras de detecção

> **TLP:CLEAR** · 2026-10-26 · domínio **Web & aplicações** · lente TCEM **Web & API** · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#techno=web)

## 1. A história em um parágrafo

O palco é **aplicações e servidores web expostos — a vitrine que qualquer um na internet pode tocar**. O catálogo reúne **2,424 regras** que olham para cá — 1,100 de detecção, 83 de hunting, 1,118 assinaturas e 123 playbooks de resposta. Elas se concentram em **Acesso inicial, Persistência, Furtividade**. 

**Lente TCEM — Web & API.** Internet-facing applications, APIs, service trust, sessions, application data and runtime behavior. Para observar: application logs, gateway logs, WAF, authentication, API audit. Arquitetura a mapear: public endpoints, API gateways, sessions, service identities, backend trust.

## 2. Números

| Indicador | Valor |
|---|---:|
| Regras | 2,424 |
| assinatura | 1,118 |
| detecção | 1,100 |
| playbook | 123 |
| hunting | 83 |
| Técnicas ATT&CK distintas | 176 |

### Por tática

| Tática | Regras |
|---|---:|
| Reconhecimento | 15 |
| Acesso inicial | 317 |
| Execução | 138 |
| Persistência | 304 |
| Escalação de privilégio | 116 |
| Furtividade | 164 |
| Enfraquecimento de defesas | 59 |
| Acesso a credenciais | 67 |
| Descoberta | 59 |
| Movimento lateral | 75 |
| Coleta | 12 |
| Comando e controle | 115 |
| Exfiltração | 24 |
| Impacto | 26 |

### Linguagens disponíveis

Em que formato você encontra regra pronta para esta tecnologia.

| Formato | Regras |
|---|---:|
| Suricata/Snort/Sagan | 1,118 |
| Wazuh | 319 |
| Sigma | 311 |
| Elastic | 182 |
| Sentinel KQL | 152 |
| Splunk | 137 |
| Playbook | 123 |
| YARA-L | 55 |
| Panther | 15 |
| Falco | 7 |
| KQL hunting | 5 |

### Padrões de correlação (TCEM)

Como as regras decidem. Muitas de evento único = cobertura ampla mas ruidosa; sequências e novidade = mais contexto, mais exigência de dados.

| Padrão | Regras | O que significa |
|---|---:|---|
| Evento único | 1,462 | Um evento, sozinho, já tem sinal suficiente para chamar o analista. |
| Assinatura de conteúdo | 394 | Casa bytes/strings dentro de arquivo, memória ou pacote, não eventos de log. |
| Novidade / raridade | 189 | Compara com o que é normal: entidade, relação ou valor nunca (ou raramente) visto. |
| Limiar / acúmulo | 180 | O sinal está na repetição: N eventos por chave em uma janela. |
| Fluxo de resposta | 123 | Não detecta: orquestra o que fazer depois do alerta (SOAR). |
| Sequência ordenada | 41 | Dois ou mais passos da mesma entidade, na ordem certa, dentro de uma janela. |
| Mudança de estado | 35 | O risco está na transição: algo era seguro e deixou de ser (desligado, rebaixado, alterado). |

### Fontes que mais contribuem

| Fonte | Regras |
|---|---:|
| Sagan rules (Quadrant) | 652 |
| Suricata hunting-rules (travisbgreen) | 466 |
| SigmaHQ | 213 |
| Wazuh ruleset (oficial) | 167 |
| EVTX-Wazuh-Rules (saifbelaarbi) | 126 |
| Splunk security_content | 110 |
| Microsoft Sentinel (Analytic Rules) | 103 |
| Elastic protections-artifacts (behavior) | 100 |
| OpenSearch Security Analytics | 96 |
| Elastic detection-rules | 80 |

## 3. Técnicas mais cobertas

| Técnica | Regras nesta tecnologia |
|---|---:|
| [T1190](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1190) Exploit Public-Facing Application | 231 |
| [T1505.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1505.003) Web Shell | 137 |
| [T1133](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1133) External Remote Services | 71 |
| [T1059](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059) Command and Scripting Interpreter | 69 |
| [T1210](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1210) Exploitation of Remote Services | 66 |
| [T1055](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1055) Process Injection | 60 |
| [T1071](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1071) Application Layer Protocol | 47 |
| [T1505](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1505) Server Software Component | 46 |
| [T1105](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1105) Ingress Tool Transfer | 28 |
| [T1033](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1033) System Owner/User Discovery | 28 |
| [T1059.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.001) PowerShell | 26 |
| [T1059.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.003) Windows Command Shell | 26 |

## 9. Regras recomendadas para começar

Ranqueadas por portabilidade do formato, maturidade, severidade e por mapearem técnica ATT&CK.

| Regra | Formato | Fonte | Técnicas |
|---|---|---|---|
| [Pulse Connect Secure RCE Attack CVE-2021-22893](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A5525edac-f599-4bfd-b926-3fa69860e766) | Sigma | SigmaHQ | T1190 |
| [OMIGOD HTTP No Authentication RCE - CVE-2021-38647](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aab6b1a39-a9ee-4ab4-b075-e83acf6e346b) | Sigma | SigmaHQ | T1021.006, T1068, T1190 |
| [OMIGOD HTTP No Authentication RCE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Aab6b1a39-a9ee-4ab4-b075-e83acf6e346b) | Sigma | OpenSearch Security Analytics | T1021.006, T1068, T1190 |
| [Chafer Malware URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Afb502828-2db0-438e-93e6-801c7548686d) | Sigma | SigmaHQ | T1071.001 |
| [Citrix Netscaler Attack CVE-2019-19781](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aac5a6409-8c89-44c2-8d64-668c29a2d756) | Sigma | SigmaHQ | T1190 |
| [Scanner PoC for CVE-2019-0708 RDP RCE Vuln](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A8400629e-79a9-4737-b387-5db940ab2367) | Sigma | SigmaHQ | T1210 |
| [Pulse Secure Attack CVE-2019-11510](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A2dbc10d7-a797-49a8-8776-49efa6442e60) | Sigma | SigmaHQ | T1190 |
| [CVE-2023-46747 Exploitation Activity - Webserver](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae9928831-ba14-42ea-a4bc-33d352b9929a) | Sigma | SigmaHQ | T1190 |
| [CVE-2023-4966 Exploitation Attempt - Citrix ADC Sensitive Information Disclosure - Webserver](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aa4e068b5-e27c-4f21-85b3-e69e5a4f7ce1) | Sigma | SigmaHQ | T1190 |
| [Potential CVE-2023-23752 Exploitation Attempt](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A0e1ebc5a-15d0-4bf6-8199-b2535397433a) | Sigma | SigmaHQ | T1190 |
| [Potential Exploitation Attempt Of Undocumented WindowsServer RCE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A6d5b8176-d87d-4402-8af4-53aee9db7b5d) | Sigma | SigmaHQ | T1190 |
| [MOVEit CVE-2023-34362 Exploitation Attempt - Potential Web Shell Request](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A435e41f2-48eb-4c95-8a2b-ed24b50ec30b) | Sigma | SigmaHQ | T1505.003 |
| [Potential CVE-2023-27363 Exploitation - HTA File Creation By FoxitPDFReader](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A9cae055f-e1d2-4f81-b8a5-1986a68cdd84) | Sigma | SigmaHQ | T1505.001 |
| [Potential CVE-2023-25717 Exploitation Attempt](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A043c1609-0e32-4462-a6f2-5a0c2da3fafe) | Sigma | SigmaHQ | T1190 |
| [Exploitation Attempt Of CVE-2023-46214 Using Public POC Code](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aba5268de-4dd4-4d5c-8a90-2b5e6dc1aff8) | Sigma | SigmaHQ | T1210 |

## 10. Limites

- A tecnologia de cada regra é inferida por heurística sobre metadados e texto (techmap.py). Regras genéricas podem aparecer em várias tecnologias.
- "Sem regra" quer dizer sem regra pública neste catálogo, não sem detecção possível. Telemetria e contexto do seu ambiente decidem.
- Atribuição de país é afirmação das fontes reunidas pelo APT4ALL, não nossa.

---
Fontes: catálogo [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules), MITRE ATT&CK®, APT4ALL, Ransomware Tool Matrix (CC BY 4.0), TCEM, LLmInjection. Gerado em 2026-10-26.
