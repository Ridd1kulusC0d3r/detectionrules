# DNS — relatório de regras de detecção

> **TLP:CLEAR** · 2026-10-26 · domínio **Rede** · lente TCEM **Web & API** · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#techno=dns)

## 1. A história em um parágrafo

O palco é **o DNS — a lista telefônica que toda conexão consulta antes de acontecer**. O catálogo reúne **1,424 regras** que olham para cá — 921 de detecção, 91 de hunting, 346 assinaturas e 66 playbooks de resposta. Elas se concentram em **Comando e controle, Furtividade, Escalação de privilégio**. 

**Lente TCEM — Web & API.** Internet-facing applications, APIs, service trust, sessions, application data and runtime behavior. Para observar: application logs, gateway logs, WAF, authentication, API audit. Arquitetura a mapear: public endpoints, API gateways, sessions, service identities, backend trust.

## 2. Números

| Indicador | Valor |
|---|---:|
| Regras | 1,424 |
| detecção | 921 |
| assinatura | 346 |
| hunting | 91 |
| playbook | 66 |
| Técnicas ATT&CK distintas | 149 |

### Por tática

| Tática | Regras |
|---|---:|
| Reconhecimento | 12 |
| Desenv. de recursos | 7 |
| Acesso inicial | 43 |
| Execução | 101 |
| Persistência | 65 |
| Escalação de privilégio | 108 |
| Furtividade | 158 |
| Enfraquecimento de defesas | 35 |
| Acesso a credenciais | 63 |
| Descoberta | 18 |
| Movimento lateral | 70 |
| Coleta | 40 |
| Comando e controle | 233 |
| Exfiltração | 74 |
| Impacto | 38 |

### Linguagens disponíveis

Em que formato você encontra regra pronta para esta tecnologia.

| Formato | Regras |
|---|---:|
| Suricata/Snort/Sagan | 346 |
| Wazuh | 338 |
| Sigma | 240 |
| Sentinel KQL | 171 |
| Elastic | 111 |
| Splunk | 80 |
| Playbook | 66 |
| YARA-L | 46 |
| Panther | 16 |
| GCP | 3 |
| QRadar AQL | 3 |
| Falco | 2 |
| KQL hunting | 2 |

### Padrões de correlação (TCEM)

Como as regras decidem. Muitas de evento único = cobertura ampla mas ruidosa; sequências e novidade = mais contexto, mais exigência de dados.

| Padrão | Regras | O que significa |
|---|---:|---|
| Evento único | 995 | Um evento, sozinho, já tem sinal suficiente para chamar o analista. |
| Novidade / raridade | 172 | Compara com o que é normal: entidade, relação ou valor nunca (ou raramente) visto. |
| Limiar / acúmulo | 80 | O sinal está na repetição: N eventos por chave em uma janela. |
| Fluxo de resposta | 66 | Não detecta: orquestra o que fazer depois do alerta (SOAR). |
| Sequência ordenada | 59 | Dois ou mais passos da mesma entidade, na ordem certa, dentro de uma janela. |
| Assinatura de conteúdo | 41 | Casa bytes/strings dentro de arquivo, memória ou pacote, não eventos de log. |
| Mudança de estado | 11 | O risco está na transição: algo era seguro e deixou de ser (desligado, rebaixado, alterado). |

### Fontes que mais contribuem

| Fonte | Regras |
|---|---:|
| Sagan rules (Quadrant) | 280 |
| EVTX-Wazuh-Rules (saifbelaarbi) | 225 |
| SigmaHQ | 143 |
| Microsoft Sentinel (Analytic Rules) | 103 |
| Wazuh ruleset (oficial) | 96 |
| OpenSearch Security Analytics | 81 |
| Elastic detection-rules | 68 |
| Microsoft Sentinel (Hunting Queries) | 68 |
| Splunk security_content | 67 |
| Suricata hunting-rules (travisbgreen) | 66 |

## 3. Técnicas mais cobertas

| Técnica | Regras nesta tecnologia |
|---|---:|
| [T1071.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1071.004) DNS | 83 |
| [T1071](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1071) Application Layer Protocol | 72 |
| [T1055](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1055) Process Injection | 71 |
| [T1021.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1021.002) SMB/Windows Admin Shares | 57 |
| [T1071.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1071.001) Web Protocols | 25 |
| [T1112](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1112) Modify Registry | 25 |
| [T1567.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1567.002) Exfiltration to Cloud Storage | 22 |
| [T1008](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1008) Fallback Channels | 21 |
| [T1569.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1569.002) Service Execution | 20 |
| [T1574.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1574.001) DLL | 19 |
| [T1568](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1568) Dynamic Resolution | 18 |
| [T1187](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1187) Forced Authentication | 18 |

## 9. Regras recomendadas para começar

Ranqueadas por portabilidade do formato, maturidade, severidade e por mapearem técnica ATT&CK.

| Regra | Formato | Fonte | Técnicas |
|---|---|---|---|
| [Monero Crypto Coin Mining Pool Lookup](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab593fd50-7335-4682-a36c-4edcb68e4641) | Sigma | SigmaHQ | T1496, T1567 |
| [Potential SocGholish Second Stage C2 DNS Query](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A70761fe8-6aa2-4f80-98c1-a57049c08e66) | Sigma | SigmaHQ | T1219.002 |
| [IcedID Malware Suspicious Single Digit DLL Execution Via Rundll32](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A2bd8e100-5b3b-4b6a-bbb5-b129d3ddddc5) | Sigma | SigmaHQ | T1218.011 |
| [UNC4841 - SSL Certificate Exfiltration Via Openssl](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A60911c07-f989-4362-84af-c609828ef829) | Sigma | SigmaHQ | T1140 |
| [GALLIUM Artefacts - Builtin](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A3db10f25-2527-4b79-8d4b-471eb900ee29) | Sigma | SigmaHQ | T1071 |
| [DNS RCE CVE-2020-1350](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab5281f31-f9cc-4d0d-95d0-45b91c45b487) | Sigma | SigmaHQ | T1190, T1569.002 |
| [CosmicDuke Service Installation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acb062102-587e-4414-8efa-dbe3c7bf19c6) | Sigma | SigmaHQ | T1543.003, T1569.002 |
| [NotPetya Ransomware Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A79aeeb41-8156-4fac-a0cd-076495ab82a1) | Sigma | SigmaHQ | T1003.001, T1218.011, T1685.005 |
| [Turla Group Named Pipes](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A739915e4-1e70-4778-8b8a-17db02f66db1) | Sigma | SigmaHQ | T1106 |
| [Ps.exe Renamed SysInternals Tool](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A18da1007-3f26-470f-875d-f77faf1cab31) | Sigma | SigmaHQ | T1036.003 |
| [MSSQL Extended Stored Procedure Backdoor Maggie](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A711ab2fe-c9ba-4746-8840-5228a58c3cb8) | Sigma | SigmaHQ | T1546 |
| [Moriya Rootkit File Created](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aa1507d71-0b60-44f6-b17c-bf53220fdd88) | Sigma | SigmaHQ | T1543.003 |
| [APT PRIVATELOG Image Load Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A33a2d1dd-f3b0-40bd-8baf-7974468927cc) | Sigma | SigmaHQ | T1055 |
| [First Time Seen Remote Named Pipe - Zeek](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A021310d9-30a6-480a-84b7-eaa69aeb92bb) | Sigma | SigmaHQ | T1021.002 |
| [DNS Query to External Service Interaction Domains](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aaff715fa-4dd5-497a-8db3-910bea555566) | Sigma | SigmaHQ | T1190, T1595.002 |

## 10. Limites

- A tecnologia de cada regra é inferida por heurística sobre metadados e texto (techmap.py). Regras genéricas podem aparecer em várias tecnologias.
- "Sem regra" quer dizer sem regra pública neste catálogo, não sem detecção possível. Telemetria e contexto do seu ambiente decidem.
- Atribuição de país é afirmação das fontes reunidas pelo APT4ALL, não nossa.

---
Fontes: catálogo [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules), MITRE ATT&CK®, APT4ALL, Ransomware Tool Matrix (CC BY 4.0), TCEM, LLmInjection. Gerado em 2026-10-26.
