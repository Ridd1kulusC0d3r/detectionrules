# WAF / CDN — relatório de regras de detecção

> **TLP:CLEAR** · 2026-10-26 · domínio **Web & aplicações** · lente TCEM **Web & API** · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#techno=waf)

## 1. A história em um parágrafo

O palco é **o WAF/CDN — o filtro na frente das aplicações web**. O catálogo reúne **627 regras** que olham para cá — 227 de detecção, 45 de hunting, 338 assinaturas e 17 playbooks de resposta. Elas se concentram em **Acesso inicial, Persistência, Comando e controle**. 

**Lente TCEM — Web & API.** Internet-facing applications, APIs, service trust, sessions, application data and runtime behavior. Para observar: application logs, gateway logs, WAF, authentication, API audit. Arquitetura a mapear: public endpoints, API gateways, sessions, service identities, backend trust.

## 2. Números

| Indicador | Valor |
|---|---:|
| Regras | 627 |
| assinatura | 338 |
| detecção | 227 |
| hunting | 45 |
| playbook | 17 |
| Técnicas ATT&CK distintas | 44 |

### Por tática

| Tática | Regras |
|---|---:|
| Reconhecimento | 7 |
| Acesso inicial | 102 |
| Execução | 18 |
| Persistência | 53 |
| Escalação de privilégio | 5 |
| Furtividade | 1 |
| Enfraquecimento de defesas | 6 |
| Acesso a credenciais | 4 |
| Descoberta | 8 |
| Movimento lateral | 1 |
| Coleta | 2 |
| Comando e controle | 49 |
| Exfiltração | 6 |
| Impacto | 25 |

### Linguagens disponíveis

Em que formato você encontra regra pronta para esta tecnologia.

| Formato | Regras |
|---|---:|
| Suricata/Snort/Sagan | 338 |
| Wazuh | 116 |
| Sentinel KQL | 91 |
| Sigma | 21 |
| Panther | 20 |
| Playbook | 17 |
| Splunk | 11 |
| Elastic | 7 |
| YARA-L | 5 |
| QRadar AQL | 1 |

### Padrões de correlação (TCEM)

Como as regras decidem. Muitas de evento único = cobertura ampla mas ruidosa; sequências e novidade = mais contexto, mais exigência de dados.

| Padrão | Regras | O que significa |
|---|---:|---|
| Evento único | 530 | Um evento, sozinho, já tem sinal suficiente para chamar o analista. |
| Limiar / acúmulo | 39 | O sinal está na repetição: N eventos por chave em uma janela. |
| Novidade / raridade | 31 | Compara com o que é normal: entidade, relação ou valor nunca (ou raramente) visto. |
| Fluxo de resposta | 17 | Não detecta: orquestra o que fazer depois do alerta (SOAR). |
| Mudança de estado | 6 | O risco está na transição: algo era seguro e deixou de ser (desligado, rebaixado, alterado). |
| Sequência ordenada | 3 | Dois ou mais passos da mesma entidade, na ordem certa, dentro de uma janela. |
| Assinatura de conteúdo | 1 | Casa bytes/strings dentro de arquivo, memória ou pacote, não eventos de log. |

### Fontes que mais contribuem

| Fonte | Regras |
|---|---:|
| Sagan rules (Quadrant) | 337 |
| Wazuh ruleset (oficial) | 80 |
| Microsoft Sentinel (Analytic Rules) | 54 |
| Microsoft Sentinel (Hunting Queries) | 37 |
| EVTX-Wazuh-Rules (saifbelaarbi) | 30 |
| Panther panther-analysis | 20 |
| SigmaHQ | 15 |
| awesome-playbooks · ms_azure | 11 |
| OpenSearch Security Analytics | 6 |
| SOCFortress Wazuh-Rules | 6 |

## 3. Técnicas mais cobertas

| Técnica | Regras nesta tecnologia |
|---|---:|
| [T1133](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1133) External Remote Services | 53 |
| [T1190](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1190) Exploit Public-Facing Application | 45 |
| [T1498](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1498) Network Denial of Service | 23 |
| [T1090.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1090.001) Internal Proxy | 21 |
| [T1572](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1572) Protocol Tunneling | 20 |
| [T1090](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1090) Proxy | 10 |
| [T1203](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1203) Exploitation for Client Execution | 9 |
| [T1102](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1102) Web Service | 8 |
| [T1059](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059) Command and Scripting Interpreter | 8 |
| [T1685](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1685) Disable or Modify Tools | 5 |
| [T1567](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1567) Exfiltration Over Web Service | 4 |
| [T1071.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1071.001) Web Protocols | 4 |

## 9. Regras recomendadas para começar

Ranqueadas por portabilidade do formato, maturidade, severidade e por mapearem técnica ATT&CK.

| Regra | Formato | Fonte | Técnicas |
|---|---|---|---|
| [CVE-2023-46747 Exploitation Activity - Proxy](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Af195b2ff-e542-41bf-8d91-864fb81e5c20) | Sigma | SigmaHQ | T1190 |
| [CVE-2023-46747 Exploitation Activity - Webserver](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae9928831-ba14-42ea-a4bc-33d352b9929a) | Sigma | SigmaHQ | T1190 |
| [CVE-2020-5902 F5 BIG-IP Exploitation Attempt](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A44b53b1c-e60f-4a7b-948e-3435a7918478) | Sigma | SigmaHQ | T1190 |
| [Renamed Cloudflared.EXE Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae0c69ebd-b54f-4aed-8ae3-e3467843f3f0) | Sigma | SigmaHQ | T1090.001 |
| [SQL Injection Strings In URI](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A5513deaf-f49a-46c2-a6c8-3f111b5cb453) | Sigma | OpenSearch Security Analytics | T1190 |
| [Potential TerminalFix Cloudflare Lure in PowerShell](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Aa4071476-76c8-4dc4-a3e2-956148d22aa2) | Elastic | Elastic detection-rules | T1059, T1059.001, T1189 |
| [Potentially Suspicious Azure Front Door Connection](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A8cb4d14e-776e-43c2-8fb9-91e7fcea32b4) | Sigma | SigmaHQ | T1090.004, T1102.002 |
| [F5 BIG-IP iControl Rest API Command Execution - Proxy](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab59c98c6-95e8-4d65-93ee-f594dfb96b17) | Sigma | SigmaHQ | T1190 |
| [F5 BIG-IP iControl Rest API Command Execution - Webserver](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A85254a62-22be-4239-b79c-2ec17e566c37) | Sigma | SigmaHQ | T1190 |
| [Cloudflared Portable Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Afadb84f0-4e84-4f6d-a1ce-9ef2bffb6ccd) | Sigma | SigmaHQ | T1090.001 |
| [Cloudflared Quick Tunnel Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A222129f7-f4dc-4568-b0d2-22440a9639ba) | Sigma | SigmaHQ | T1090.001 |
| [Cloudflared Tunnel Connections Cleanup](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A7050bba1-1aed-454e-8f73-3f46f09ce56a) | Sigma | SigmaHQ | T1090, T1102, T1572 |
| [Cloudflared Tunnel Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A9a019ffc-3580-4c9d-8d87-079f7e8d3fd4) | Sigma | SigmaHQ | T1090, T1102, T1572 |
| [Network Connection Initiated To Cloudflared Tunnels Domains](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A7cd1dcdc-6edf-4896-86dc-d1f19ad64903) | Sigma | SigmaHQ | T1567, T1572 |
| [Cloudflared Tunnels Related DNS Requests](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aa1d9eec5-33b2-4177-8d24-27fe754d0812) | Sigma | SigmaHQ | T1071.001, T1572 |

## 10. Limites

- A tecnologia de cada regra é inferida por heurística sobre metadados e texto (techmap.py). Regras genéricas podem aparecer em várias tecnologias.
- "Sem regra" quer dizer sem regra pública neste catálogo, não sem detecção possível. Telemetria e contexto do seu ambiente decidem.
- Atribuição de país é afirmação das fontes reunidas pelo APT4ALL, não nossa.

---
Fontes: catálogo [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules), MITRE ATT&CK®, APT4ALL, Ransomware Tool Matrix (CC BY 4.0), TCEM, LLmInjection. Gerado em 2026-10-26.
