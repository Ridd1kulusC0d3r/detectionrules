# IDS / NSM / NDR — relatório de regras de detecção

> **TLP:CLEAR** · 2026-10-26 · domínio **Rede** · lente TCEM **Detection & Validation** · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#techno=nsm)

## 1. A história em um parágrafo

O palco é **a rede vista por dentro — sensores que leem pacotes e fluxos**. O catálogo reúne **1,912 regras** que olham para cá — 284 de detecção, 15 de hunting, 1,547 assinaturas e 66 playbooks de resposta. Elas se concentram em **Comando e controle, Acesso inicial, Movimento lateral**. 

**Lente TCEM — Detection & Validation.** Threat-informed telemetry, analytics, validation, retest and analyst-response context. Para observar: sensor health, event quality, normalization, correlation, alert disposition. Arquitetura a mapear: sensors, collection pipelines, SIEM, EDR, correlation, case management.

## 2. Números

| Indicador | Valor |
|---|---:|
| Regras | 1,912 |
| assinatura | 1,547 |
| detecção | 284 |
| playbook | 66 |
| hunting | 15 |
| Técnicas ATT&CK distintas | 140 |

### Por tática

| Tática | Regras |
|---|---:|
| Reconhecimento | 13 |
| Desenv. de recursos | 3 |
| Acesso inicial | 116 |
| Execução | 52 |
| Persistência | 48 |
| Escalação de privilégio | 37 |
| Furtividade | 21 |
| Enfraquecimento de defesas | 3 |
| Acesso a credenciais | 74 |
| Descoberta | 89 |
| Movimento lateral | 100 |
| Coleta | 29 |
| Comando e controle | 127 |
| Exfiltração | 44 |
| Impacto | 41 |

### Linguagens disponíveis

Em que formato você encontra regra pronta para esta tecnologia.

| Formato | Regras |
|---|---:|
| Suricata/Snort/Sagan | 1,547 |
| Elastic | 96 |
| Playbook | 66 |
| Sigma | 60 |
| Sentinel KQL | 59 |
| Splunk | 39 |
| Wazuh | 32 |
| YARA-L | 8 |
| Falco | 2 |
| Panther | 2 |
| KQL hunting | 1 |

### Padrões de correlação (TCEM)

Como as regras decidem. Muitas de evento único = cobertura ampla mas ruidosa; sequências e novidade = mais contexto, mais exigência de dados.

| Padrão | Regras | O que significa |
|---|---:|---|
| Evento único | 740 | Um evento, sozinho, já tem sinal suficiente para chamar o analista. |
| Assinatura de conteúdo | 578 | Casa bytes/strings dentro de arquivo, memória ou pacote, não eventos de log. |
| Limiar / acúmulo | 313 | O sinal está na repetição: N eventos por chave em uma janela. |
| Novidade / raridade | 193 | Compara com o que é normal: entidade, relação ou valor nunca (ou raramente) visto. |
| Fluxo de resposta | 66 | Não detecta: orquestra o que fazer depois do alerta (SOAR). |
| Sequência ordenada | 17 | Dois ou mais passos da mesma entidade, na ordem certa, dentro de uma janela. |
| Mudança de estado | 5 | O risco está na transição: algo era seguro e deixou de ser (desligado, rebaixado, alterado). |

### Fontes que mais contribuem

| Fonte | Regras |
|---|---:|
| Sagan rules (Quadrant) | 818 |
| Suricata hunting-rules (travisbgreen) | 719 |
| Elastic detection-rules | 92 |
| Microsoft Sentinel (Analytic Rules) | 48 |
| Cortex XSOAR (demisto/content) | 43 |
| Splunk security_content | 39 |
| SigmaHQ | 33 |
| OpenSearch Security Analytics | 27 |
| SOCFortress Wazuh-Rules | 12 |
| Microsoft Sentinel (Hunting Queries) | 11 |

## 3. Técnicas mais cobertas

| Técnica | Regras nesta tecnologia |
|---|---:|
| [T1190](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1190) Exploit Public-Facing Application | 88 |
| [T1071](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1071) Application Layer Protocol | 72 |
| [T1021](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1021) Remote Services | 50 |
| [T1210](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1210) Exploitation of Remote Services | 38 |
| [T1046](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1046) Network Service Discovery | 32 |
| [T1041](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1041) Exfiltration Over C2 Channel | 29 |
| [T1059](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059) Command and Scripting Interpreter | 24 |
| [T1110](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1110) Brute Force | 20 |
| [T1499](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1499) Endpoint Denial of Service | 19 |
| [T1018](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1018) Remote System Discovery | 16 |
| [T1040](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1040) Network Sniffing | 14 |
| [T1068](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1068) Exploitation for Privilege Escalation | 13 |

## 6. Ferramentas de afiliados de ransomware que passam por aqui

Do Ransomware Tool Matrix (via APT4ALL): ferramentas usadas por gangues dentro da rede, nas categorias que esta tecnologia enxerga.

| Ferramenta | Categoria | Gangues que usam | Regras que citam |
|---|---|---:|---:|
| Cobalt Strike | Ferramentas ofensivas | 43 | 258 |
| Impacket | Ferramentas ofensivas | 20 | 78 |
| Metasploit | Ferramentas ofensivas | 9 | 88 |
| PowerShell Empire | Ferramentas ofensivas | 9 | 9 |
| Chisel | Túneis e rede | 8 | 10 |
| PowerSploit | Ferramentas ofensivas | 8 | 23 |
| Cloudflared | Túneis e rede | 7 | 45 |
| OpenSSH | Túneis e rede | 7 | 130 |
| Ngrok | Túneis e rede | 6 | 51 |
| Plink | Túneis e rede | 6 | 26 |
| Meterpreter | Ferramentas ofensivas | 6 | 51 |
| Rubeus | Ferramentas ofensivas | 6 | 86 |
| Ligolo | Túneis e rede | 5 | 1 |
| NetExec | Ferramentas ofensivas | 5 | 15 |
| Proxychains | Túneis e rede | 4 | 9 |
| Brute Ratel C4 | Ferramentas ofensivas | 4 | 3 |
| PuTTY | Túneis e rede | 3 | 23 |
| CrackMapExec | Ferramentas ofensivas | 3 | 71 |

## 9. Regras recomendadas para começar

Ranqueadas por portabilidade do formato, maturidade, severidade e por mapearem técnica ATT&CK.

| Regra | Formato | Fonte | Técnicas |
|---|---|---|---|
| [OMIGOD HTTP No Authentication RCE - CVE-2021-38647](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aab6b1a39-a9ee-4ab4-b075-e83acf6e346b) | Sigma | SigmaHQ | T1021.006, T1068, T1190 |
| [OMIGOD HTTP No Authentication RCE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Aab6b1a39-a9ee-4ab4-b075-e83acf6e346b) | Sigma | OpenSearch Security Analytics | T1021.006, T1068, T1190 |
| [Publicly Accessible RDP Service](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1fc0809e-06bf-4de3-ad52-25e5263b7623) | Sigma | SigmaHQ | T1021.001 |
| [Suspicious PsExec Execution - Zeek](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Af1b3a22a-45e6-4004-afb5-4291f9c21166) | Sigma | SigmaHQ | T1021.002 |
| [Possible Impacket SecretDump Remote Activity - Zeek](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A92dae1ed-1c9d-4eff-a567-33acbd95b00e) | Sigma | SigmaHQ | T1003.002, T1003.003, T1003.004 |
| [First Time Seen Remote Named Pipe - Zeek](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A021310d9-30a6-480a-84b7-eaa69aeb92bb) | Sigma | SigmaHQ | T1021.002 |
| [Web Server Potential SQL Injection Request](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A7f7a0ee1-7b6f-466a-85b4-110fb105f5e2) | Elastic | Elastic detection-rules | T1059, T1059.004, T1071 |
| [First Seen Network Flow Exporter Followed by Suspicious Source Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A882c8edc-1e39-4a60-80b2-485491b6c91c) | Elastic | Elastic detection-rules | T1685 |
| [ICMP Redirect Message from Internal Host](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A2014ebd8-b847-4cc0-a827-d0d61ec88680) | Elastic | Elastic detection-rules | T1557 |
| [Potential Redis CONFIG SET SSH Authorized Key Injection](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A39ab0f66-efa0-4649-9c9c-8c64682f5fdd) | Elastic | Elastic detection-rules | T1098, T1098.004, T1190 |
| [Potential Redis Lua Use-After-Free RCE Attempt (CVE-2025-49844 / RediShell)](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A9a1ba0ac-aa6f-4c0d-8c80-b7f6ea2efa36) | Elastic | Elastic detection-rules | T1059, T1059.011, T1190 |
| [Potential cPanel WHM CRLF Authentication Bypass (CVE-2026-41940)](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A2449be9d-2fdf-4126-a85b-f05e4058df9f) | Elastic | Elastic detection-rules | T1190 |
| [MySQL User-Defined Function Injection](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ac375532d-069d-41e0-af70-8ca032eb58f5) | Elastic | Elastic detection-rules | T1505, T1505.001 |
| [Potential Redis CONFIG SET Cron Directory Persistence (RedisRaider)](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A29e57265-d358-420a-b1cd-845e8a1fd70d) | Elastic | Elastic detection-rules | T1053, T1053.003, T1496 |
| [React2Shell Network Security Alert](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A1aefed68-eecd-47cc-9044-4a394b60061d) | Elastic | Elastic detection-rules | T1059, T1059.007, T1190 |

## 10. Limites

- A tecnologia de cada regra é inferida por heurística sobre metadados e texto (techmap.py). Regras genéricas podem aparecer em várias tecnologias.
- "Sem regra" quer dizer sem regra pública neste catálogo, não sem detecção possível. Telemetria e contexto do seu ambiente decidem.
- Atribuição de país é afirmação das fontes reunidas pelo APT4ALL, não nossa.

---
Fontes: catálogo [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules), MITRE ATT&CK®, APT4ALL, Ransomware Tool Matrix (CC BY 4.0), TCEM, LLmInjection. Gerado em 2026-10-26.
