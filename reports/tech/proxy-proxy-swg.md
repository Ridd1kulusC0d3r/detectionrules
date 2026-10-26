# Proxy / SWG — relatório de regras de detecção

> **TLP:CLEAR** · 2026-10-26 · domínio **Rede** · lente TCEM **Web & API** · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#techno=proxy)

## 1. A história em um parágrafo

O palco é **o proxy web — a janela por onde os usuários saem para a internet**. O catálogo reúne **1,175 regras** que olham para cá — 626 de detecção, 46 de hunting, 415 assinaturas e 88 playbooks de resposta. Elas se concentram em **Comando e controle, Furtividade, Acesso inicial**. 

**Lente TCEM — Web & API.** Internet-facing applications, APIs, service trust, sessions, application data and runtime behavior. Para observar: application logs, gateway logs, WAF, authentication, API audit. Arquitetura a mapear: public endpoints, API gateways, sessions, service identities, backend trust.

## 2. Números

| Indicador | Valor |
|---|---:|
| Regras | 1,175 |
| detecção | 626 |
| assinatura | 415 |
| playbook | 88 |
| hunting | 46 |
| Técnicas ATT&CK distintas | 146 |

### Por tática

| Tática | Regras |
|---|---:|
| Reconhecimento | 2 |
| Desenv. de recursos | 2 |
| Acesso inicial | 83 |
| Execução | 81 |
| Persistência | 63 |
| Escalação de privilégio | 38 |
| Furtividade | 209 |
| Enfraquecimento de defesas | 16 |
| Acesso a credenciais | 25 |
| Descoberta | 25 |
| Movimento lateral | 15 |
| Coleta | 14 |
| Comando e controle | 263 |
| Exfiltração | 16 |
| Impacto | 10 |

### Linguagens disponíveis

Em que formato você encontra regra pronta para esta tecnologia.

| Formato | Regras |
|---|---:|
| Suricata/Snort/Sagan | 415 |
| Sigma | 177 |
| Sentinel KQL | 119 |
| Wazuh | 114 |
| YARA-L | 100 |
| Elastic | 94 |
| Playbook | 88 |
| Splunk | 47 |
| Panther | 17 |
| KQL hunting | 2 |
| Falco | 1 |
| QRadar AQL | 1 |

### Padrões de correlação (TCEM)

Como as regras decidem. Muitas de evento único = cobertura ampla mas ruidosa; sequências e novidade = mais contexto, mais exigência de dados.

| Padrão | Regras | O que significa |
|---|---:|---|
| Evento único | 833 | Um evento, sozinho, já tem sinal suficiente para chamar o analista. |
| Novidade / raridade | 123 | Compara com o que é normal: entidade, relação ou valor nunca (ou raramente) visto. |
| Fluxo de resposta | 88 | Não detecta: orquestra o que fazer depois do alerta (SOAR). |
| Limiar / acúmulo | 87 | O sinal está na repetição: N eventos por chave em uma janela. |
| Sequência ordenada | 33 | Dois ou mais passos da mesma entidade, na ordem certa, dentro de uma janela. |
| Mudança de estado | 11 | O risco está na transição: algo era seguro e deixou de ser (desligado, rebaixado, alterado). |

### Fontes que mais contribuem

| Fonte | Regras |
|---|---:|
| Sagan rules (Quadrant) | 413 |
| SigmaHQ | 121 |
| Microsoft Sentinel (Analytic Rules) | 91 |
| EVTX-Wazuh-Rules (saifbelaarbi) | 75 |
| OpenSearch Security Analytics | 56 |
| Chronicle rules (rowham) | 52 |
| Google SecOps / Chronicle | 48 |
| awesome-playbooks · ms_azure | 48 |
| Elastic protections-artifacts (behavior) | 46 |
| Elastic detection-rules | 44 |

## 3. Técnicas mais cobertas

| Técnica | Regras nesta tecnologia |
|---|---:|
| [T1218](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1218) System Binary Proxy Execution | 117 |
| [T1105](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1105) Ingress Tool Transfer | 88 |
| [T1571](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1571) Non-Standard Port | 85 |
| [T1071.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1071.001) Web Protocols | 53 |
| [T1090](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1090) Proxy | 44 |
| [T1071](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1071) Application Layer Protocol | 43 |
| [T1059](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059) Command and Scripting Interpreter | 30 |
| [T1216](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1216) System Script Proxy Execution | 23 |
| [T1190](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1190) Exploit Public-Facing Application | 22 |
| [T1218.011](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1218.011) Rundll32 | 21 |
| [T1133](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1133) External Remote Services | 20 |
| [T1127](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1127) Trusted Developer Utilities Proxy Execution | 15 |

## 6. Ferramentas de afiliados de ransomware que passam por aqui

Do Ransomware Tool Matrix (via APT4ALL): ferramentas usadas por gangues dentro da rede, nas categorias que esta tecnologia enxerga.

| Ferramenta | Categoria | Gangues que usam | Regras que citam |
|---|---|---:|---:|
| RClone | Exfiltração | 33 | 35 |
| MEGA | Exfiltração | 24 | 74 |
| WinSCP | Exfiltração | 16 | 24 |
| FileZilla | Exfiltração | 9 | 9 |
| Chisel | Túneis e rede | 8 | 10 |
| Sendspace | Exfiltração | 7 | 49 |
| Cloudflared | Túneis e rede | 7 | 45 |
| OpenSSH | Túneis e rede | 7 | 130 |
| Ngrok | Túneis e rede | 6 | 51 |
| Plink | Túneis e rede | 6 | 26 |
| Ligolo | Túneis e rede | 5 | 1 |
| PSCP | Exfiltração | 4 | 7 |
| PrivatLab | Exfiltração | 4 | 48 |
| Proxychains | Túneis e rede | 4 | 9 |
| File[.]io | Exfiltração | 3 | 7 |
| Restic | Exfiltração | 3 | 12 |
| Temp[.]sh | Exfiltração | 3 | 52 |
| PuTTY | Túneis e rede | 3 | 23 |

## 9. Regras recomendadas para começar

Ranqueadas por portabilidade do formato, maturidade, severidade e por mapearem técnica ATT&CK.

| Regra | Formato | Fonte | Técnicas |
|---|---|---|---|
| [Ursnif Malware Download URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aa36ce77e-30db-4ea0-8795-644d7af5dfb4) | Sigma | SigmaHQ | T1071.001 |
| [Ursnif Malware C2 URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A932ac737-33ca-4afd-9869-0d48b391fcc9) | Sigma | SigmaHQ | T1071.001, T1204.002, T1566.001 |
| [Chafer Malware URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Afb502828-2db0-438e-93e6-801c7548686d) | Sigma | SigmaHQ | T1071.001 |
| [APT40 Dropbox Tool User Agent](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A5ba715b6-71b7-44fd-8245-f66893e81b3d) | Sigma | SigmaHQ | T1071.001, T1567.002 |
| [CVE-2023-46747 Exploitation Activity - Proxy](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Af195b2ff-e542-41bf-8d91-864fb81e5c20) | Sigma | SigmaHQ | T1190 |
| [CVE-2023-4966 Exploitation Attempt - Citrix ADC Sensitive Information Disclosure - Proxy](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aaee7681f-b53d-4594-a9de-ac51e6ad3362) | Sigma | SigmaHQ | T1190 |
| [Potential Information Disclosure CVE-2023-43261 Exploitation - Proxy](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Af48f5368-355c-4a1b-8bf5-11c13d589eaa) | Sigma | SigmaHQ | T1190 |
| [ComRAT Network Communication](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A7857f021-007f-4928-8b2c-7aedbe64bb82) | Sigma | SigmaHQ | T1071.001 |
| [Potential OWASSRF Exploitation Attempt - Proxy](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1ddf4596-1908-43c9-add2-1d2c2fcc4797) | Sigma | SigmaHQ | T1190 |
| [OWASSRF Exploitation Attempt Using Public POC - Proxy](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Afdd7e904-7304-4616-a46a-e32f917c4be4) | Sigma | SigmaHQ | T1190 |
| [Okta User Session Start Via An Anonymising Proxy Service](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Abde30855-5c53-4c18-ae90-1ff79ebc9578) | Sigma | SigmaHQ | T1685 |
| [Malware User Agent](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A5c84856b-55a5-45f1-826f-13f37250cf4e) | Sigma | SigmaHQ | T1071.001 |
| [Bitsadmin to Uncommon TLD](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A9eb68894-7476-4cd6-8752-23b51f5883a7) | Sigma | SigmaHQ | T1071.001, T1197 |
| [Exploit Framework User Agent](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Afdd1bfb5-f60b-4a35-910e-f36ed3d0b32f) | Sigma | SigmaHQ | T1071.001 |
| [HackTool - Empire UserAgent URI Combo](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab923f7d6-ac89-4a50-a71a-89fb846b4aa8) | Sigma | SigmaHQ | T1071.001 |

## 10. Limites

- A tecnologia de cada regra é inferida por heurística sobre metadados e texto (techmap.py). Regras genéricas podem aparecer em várias tecnologias.
- "Sem regra" quer dizer sem regra pública neste catálogo, não sem detecção possível. Telemetria e contexto do seu ambiente decidem.
- Atribuição de país é afirmação das fontes reunidas pelo APT4ALL, não nossa.

---
Fontes: catálogo [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules), MITRE ATT&CK®, APT4ALL, Ransomware Tool Matrix (CC BY 4.0), TCEM, LLmInjection. Gerado em 2026-10-26.
