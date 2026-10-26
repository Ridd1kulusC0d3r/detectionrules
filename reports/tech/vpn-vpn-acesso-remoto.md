# VPN & acesso remoto — relatório de regras de detecção

> **TLP:CLEAR** · 2026-10-26 · domínio **Rede** · lente TCEM **Identity & Access** · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#techno=vpn)

## 1. A história em um parágrafo

O palco é **o acesso remoto — VPN e ferramentas que deixam alguém de fora operar aqui dentro**. O catálogo reúne **1,364 regras** que olham para cá — 622 de detecção, 266 de hunting, 469 assinaturas e 7 playbooks de resposta. Elas se concentram em **Comando e controle, Persistência, Acesso inicial**. 

**Lente TCEM — Identity & Access.** Authentication, authorization, privilege, federation, machine identity and administrative trust. Para observar: sign-in logs, privilege changes, token events, identity administration. Arquitetura a mapear: identity providers, privileged roles, service principals, federation, recovery access.

## 2. Números

| Indicador | Valor |
|---|---:|
| Regras | 1,364 |
| detecção | 622 |
| assinatura | 469 |
| hunting | 266 |
| playbook | 7 |
| Técnicas ATT&CK distintas | 106 |

### Por tática

| Tática | Regras |
|---|---:|
| Acesso inicial | 141 |
| Execução | 29 |
| Persistência | 153 |
| Escalação de privilégio | 54 |
| Furtividade | 46 |
| Enfraquecimento de defesas | 13 |
| Acesso a credenciais | 32 |
| Descoberta | 9 |
| Movimento lateral | 16 |
| Coleta | 4 |
| Comando e controle | 313 |
| Exfiltração | 23 |
| Impacto | 13 |

### Linguagens disponíveis

Em que formato você encontra regra pronta para esta tecnologia.

| Formato | Regras |
|---|---:|
| Suricata/Snort/Sagan | 469 |
| Wazuh | 300 |
| Sentinel KQL | 283 |
| Sigma | 138 |
| Splunk | 80 |
| Elastic | 61 |
| YARA-L | 17 |
| Playbook | 7 |
| Panther | 6 |
| KQL hunting | 3 |

### Padrões de correlação (TCEM)

Como as regras decidem. Muitas de evento único = cobertura ampla mas ruidosa; sequências e novidade = mais contexto, mais exigência de dados.

| Padrão | Regras | O que significa |
|---|---:|---|
| Evento único | 961 | Um evento, sozinho, já tem sinal suficiente para chamar o analista. |
| Novidade / raridade | 278 | Compara com o que é normal: entidade, relação ou valor nunca (ou raramente) visto. |
| Limiar / acúmulo | 78 | O sinal está na repetição: N eventos por chave em uma janela. |
| Sequência ordenada | 23 | Dois ou mais passos da mesma entidade, na ordem certa, dentro de uma janela. |
| Mudança de estado | 17 | O risco está na transição: algo era seguro e deixou de ser (desligado, rebaixado, alterado). |
| Fluxo de resposta | 7 | Não detecta: orquestra o que fazer depois do alerta (SOAR). |

### Fontes que mais contribuem

| Fonte | Regras |
|---|---:|
| Sagan rules (Quadrant) | 469 |
| Microsoft Sentinel (Hunting Queries) | 229 |
| EVTX-Wazuh-Rules (saifbelaarbi) | 210 |
| SigmaHQ | 99 |
| Wazuh ruleset (oficial) | 84 |
| Microsoft Sentinel (Analytic Rules) | 54 |
| Splunk security_content | 47 |
| Elastic detection-rules | 43 |
| OpenSearch Security Analytics | 39 |
| Splunk analytic stories | 33 |

## 3. Técnicas mais cobertas

| Técnica | Regras nesta tecnologia |
|---|---:|
| [T1219.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1219.002) Remote Desktop Software | 172 |
| [T1133](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1133) External Remote Services | 77 |
| [T1219](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1219) Remote Access Tools | 63 |
| [T1572](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1572) Protocol Tunneling | 49 |
| [T1190](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1190) Exploit Public-Facing Application | 34 |
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | 27 |
| [T1090](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1090) Proxy | 24 |
| [T1090.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1090.001) Internal Proxy | 21 |
| [T1102](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1102) Web Service | 19 |
| [T1567](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1567) Exfiltration Over Web Service | 15 |
| [T1105](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1105) Ingress Tool Transfer | 14 |
| [T1543.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1543.003) Windows Service | 14 |

## 6. Ferramentas de afiliados de ransomware que passam por aqui

Do Ransomware Tool Matrix (via APT4ALL): ferramentas usadas por gangues dentro da rede, nas categorias que esta tecnologia enxerga.

| Ferramenta | Categoria | Gangues que usam | Regras que citam |
|---|---|---:|---:|
| AnyDesk | Acesso remoto (RMM) | 32 | 102 |
| Splashtop | Acesso remoto (RMM) | 13 | 19 |
| Atera | Acesso remoto (RMM) | 12 | 40 |
| ScreenConnect | Acesso remoto (RMM) | 12 | 93 |
| Chisel | Túneis e rede | 8 | 10 |
| TeamViewer | Acesso remoto (RMM) | 7 | 104 |
| Cloudflared | Túneis e rede | 7 | 45 |
| OpenSSH | Túneis e rede | 7 | 130 |
| Ngrok | Túneis e rede | 6 | 51 |
| Plink | Túneis e rede | 6 | 26 |
| Ligolo | Túneis e rede | 5 | 1 |
| LogMeIn | Acesso remoto (RMM) | 4 | 70 |
| MobaXterm | Acesso remoto (RMM) | 4 | 9 |
| NetSupport | Acesso remoto (RMM) | 4 | 49 |
| TightVNC | Acesso remoto (RMM) | 4 | 19 |
| Proxychains | Túneis e rede | 4 | 9 |
| MeshAgent | Acesso remoto (RMM) | 3 | 24 |
| N-Able | Acesso remoto (RMM) | 3 | 40 |

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
| [Pulse Connect Secure RCE Attack CVE-2021-22893](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A5525edac-f599-4bfd-b926-3fa69860e766) | Sigma | SigmaHQ | T1190 |
| [Remote LSASS Process Access Through Windows Remote Management](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aaa35a627-33fb-4d04-a165-d33b4afca3e8) | Sigma | SigmaHQ | T1003.001, T1021.006, T1059.001 |
| [Citrix Netscaler Attack CVE-2019-19781](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aac5a6409-8c89-44c2-8d64-668c29a2d756) | Sigma | SigmaHQ | T1190 |
| [Pulse Secure Attack CVE-2019-11510](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A2dbc10d7-a797-49a8-8776-49efa6442e60) | Sigma | SigmaHQ | T1190 |
| [CVE-2023-4966 Exploitation Attempt - Citrix ADC Sensitive Information Disclosure - Proxy](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aaee7681f-b53d-4594-a9de-ac51e6ad3362) | Sigma | SigmaHQ | T1190 |
| [CVE-2023-4966 Exploitation Attempt - Citrix ADC Sensitive Information Disclosure - Webserver](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aa4e068b5-e27c-4f21-85b3-e69e5a4f7ce1) | Sigma | SigmaHQ | T1190 |
| [Citrix ADS Exploitation CVE-2020-8193 CVE-2020-8195](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A0d0d9a8a-a49e-4e27-b061-7ce4b936cfb7) | Sigma | SigmaHQ | T1190 |
| [Communication To Ngrok Tunneling Service - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A19bf6fdb-7721-4f3d-867f-53467f6a5db6) | Sigma | SigmaHQ | T1090, T1102, T1567 |
| [Suspicious Binary Writes Via AnyDesk](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A2d367498-5112-4ae5-a06a-96e7bc33a211) | Sigma | SigmaHQ | T1219.002 |
| [Remote Access Tool - Anydesk Execution From Suspicious Folder](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A065b00ca-5d5c-4557-ac95-64a6d0b64d86) | Sigma | SigmaHQ | T1219.002 |
| [Renamed Cloudflared.EXE Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae0c69ebd-b54f-4aed-8ae3-e3467843f3f0) | Sigma | SigmaHQ | T1090.001 |
| [PowerShell Web Access Feature Enabled Via DISM](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A7e8f2d3b-9c1a-4f67-b9e8-8d9006e0e51f) | Sigma | SigmaHQ | T1548.002 |
| [Remote Access Tool - AnyDesk Silent Installation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A114e7f1c-f137-48c8-8f54-3088c24ce4b9) | Sigma | SigmaHQ | T1219.002 |
| [Remote Access Tool - ScreenConnect Server Web Shell Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab19146a3-25d4-41b4-928b-1e2a92641b1b) | Sigma | SigmaHQ | T1190 |
| [PUA - Ngrok Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aee37eb7c-a4e7-4cd5-8fa4-efa27f1c3f31) | Sigma | SigmaHQ | T1572 |

## 10. Limites

- A tecnologia de cada regra é inferida por heurística sobre metadados e texto (techmap.py). Regras genéricas podem aparecer em várias tecnologias.
- "Sem regra" quer dizer sem regra pública neste catálogo, não sem detecção possível. Telemetria e contexto do seu ambiente decidem.
- Atribuição de país é afirmação das fontes reunidas pelo APT4ALL, não nossa.

---
Fontes: catálogo [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules), MITRE ATT&CK®, APT4ALL, Ransomware Tool Matrix (CC BY 4.0), TCEM, LLmInjection. Gerado em 2026-10-26.
