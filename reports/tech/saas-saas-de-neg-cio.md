# SaaS de negócio — relatório de regras de detecção

> **TLP:CLEAR** · 2026-10-26 · domínio **SaaS & colaboração** · plataforma ATT&CK **SaaS** · lente TCEM **Identity & Access** · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#techno=saas)

## 1. A história em um parágrafo

O palco é **os SaaS de negócio — onde moram clientes, contratos e dados sensíveis fora do seu datacenter**. O catálogo reúne **648 regras** que olham para cá — 321 de detecção, 64 de hunting, 86 assinaturas e 177 playbooks de resposta. Elas se concentram em **Acesso inicial, Persistência, Escalação de privilégio**. Das 78 técnicas do ATT&CK para a plataforma SaaS, **30 (38%)** têm ao menos uma regra aqui e **48 não têm nenhuma** — é onde um atacante passa sem ser visto. Entre os grupos com mais técnicas nesta plataforma estão Scattered Spider, APT29, ShinyHunters.

**Lente TCEM — Identity & Access.** Authentication, authorization, privilege, federation, machine identity and administrative trust. Para observar: sign-in logs, privilege changes, token events, identity administration. Arquitetura a mapear: identity providers, privileged roles, service principals, federation, recovery access.

## 2. Números

| Indicador | Valor |
|---|---:|
| Regras | 648 |
| detecção | 321 |
| playbook | 177 |
| assinatura | 86 |
| hunting | 64 |
| Técnicas ATT&CK distintas | 92 |
| Cobertura da plataforma SaaS | 30/78 (38%) |

### Por tática

| Tática | Regras |
|---|---:|
| Reconhecimento | 4 |
| Desenv. de recursos | 2 |
| Acesso inicial | 69 |
| Execução | 18 |
| Persistência | 64 |
| Escalação de privilégio | 44 |
| Furtividade | 40 |
| Enfraquecimento de defesas | 13 |
| Acesso a credenciais | 30 |
| Descoberta | 11 |
| Movimento lateral | 9 |
| Coleta | 13 |
| Comando e controle | 11 |
| Exfiltração | 35 |
| Impacto | 12 |

### Linguagens disponíveis

Em que formato você encontra regra pronta para esta tecnologia.

| Formato | Regras |
|---|---:|
| Playbook | 177 |
| Sentinel KQL | 158 |
| Panther | 147 |
| Suricata/Snort/Sagan | 86 |
| Sigma | 32 |
| Splunk | 18 |
| YARA-L | 14 |
| Elastic | 9 |
| Wazuh | 6 |
| KQL hunting | 1 |

### Padrões de correlação (TCEM)

Como as regras decidem. Muitas de evento único = cobertura ampla mas ruidosa; sequências e novidade = mais contexto, mais exigência de dados.

| Padrão | Regras | O que significa |
|---|---:|---|
| Evento único | 283 | Um evento, sozinho, já tem sinal suficiente para chamar o analista. |
| Fluxo de resposta | 177 | Não detecta: orquestra o que fazer depois do alerta (SOAR). |
| Limiar / acúmulo | 99 | O sinal está na repetição: N eventos por chave em uma janela. |
| Novidade / raridade | 51 | Compara com o que é normal: entidade, relação ou valor nunca (ou raramente) visto. |
| Mudança de estado | 25 | O risco está na transição: algo era seguro e deixou de ser (desligado, rebaixado, alterado). |
| Sequência ordenada | 7 | Dois ou mais passos da mesma entidade, na ordem certa, dentro de uma janela. |
| Assinatura de conteúdo | 6 | Casa bytes/strings dentro de arquivo, memória ou pacote, não eventos de log. |

### Fontes que mais contribuem

| Fonte | Regras |
|---|---:|
| Panther panther-analysis | 147 |
| Microsoft Sentinel (Analytic Rules) | 99 |
| Cortex XSOAR (demisto/content) | 81 |
| Sagan rules (Quadrant) | 80 |
| Microsoft Sentinel (Hunting Queries) | 59 |
| awesome-playbooks · tines | 44 |
| SigmaHQ | 24 |
| awesome-playbooks · ms_azure | 22 |
| Splunk security_content | 14 |
| Splunk SOAR / Phantom playbooks | 11 |

## 3. Técnicas mais cobertas

| Técnica | Regras nesta tecnologia |
|---|---:|
| [T1190](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1190) Exploit Public-Facing Application | 33 |
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | 17 |
| [T1567](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1567) Exfiltration Over Web Service | 12 |
| [T1567.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1567.002) Exfiltration to Cloud Storage | 8 |
| [T1059](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059) Command and Scripting Interpreter | 8 |
| [T1110](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1110) Brute Force | 8 |
| [T1041](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1041) Exfiltration Over C2 Channel | 8 |
| [T1133](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1133) External Remote Services | 7 |
| [T1530](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1530) Data from Cloud Storage | 7 |
| [T1078.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.004) Cloud Accounts | 7 |
| [T1098](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1098) Account Manipulation | 7 |
| [T1136](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1136) Create Account | 6 |

## 4. Detecção pela ausência — o que ninguém está olhando (48 técnicas)

Técnicas do ATT&CK para SaaS **sem nenhuma regra nesta tecnologia**, ordenadas pelo número de grupos que as usam. A coluna "regras no catálogo" mostra se existe cobertura em outra tecnologia (ex.: EDR ou rede) que você pode adaptar.

| Técnica | Grupos que usam | Regras no catálogo (todas as tecnologias) |
|---|---:|---:|
| [T1657](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1657) Financial Theft | 19 | 2 |
| [T1684.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1684.001) Impersonation | 18 | 1 |
| [T1072](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1072) Software Deployment Tools | 10 | 59 |
| [T1539](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1539) Steal Web Session Cookie | 8 | 54 |
| [T1069](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1069) Permission Groups Discovery | 6 | 242 |
| [T1213.006](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1213.006) Databases | 6 | 2 |
| [T1080](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1080) Taint Shared Content | 5 | 12 |
| [T1213.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1213.005) Messaging Applications | 5 | **0** |
| [T1036.010](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1036.010) Masquerade Account Name | 4 | 1 |
| [T1059.009](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.009) Cloud API | 4 | 11 |
| [T1110.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1110.001) Password Guessing | 4 | 63 |
| [T1213.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1213.003) Code Repositories | 4 | 21 |
| [T1550.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1550.001) Application Access Token | 4 | 78 |
| [T1021.007](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1021.007) Cloud Services | 3 | 20 |
| [T1195](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1195) Supply Chain Compromise | 3 | 187 |
| [T1201](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1201) Password Policy Discovery | 3 | 43 |
| [T1621](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1621) Multi-Factor Authentication Request Generation | 3 | 27 |
| [T1087.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1087.004) Cloud Account | 2 | 38 |
| [T1110.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1110.004) Credential Stuffing | 2 | 35 |
| [T1211](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1211) Exploitation for Stealth | 2 | 40 |

## 5. Quem mira esta plataforma

Grupos com mais técnicas registradas nesta plataforma e quantas delas você enxerga com as regras desta tecnologia. País atribuído pelo APT4ALL (afirmação de quem publicou).

| Grupo | Origem atribuída | Técnicas na plataforma | Com regra aqui | Exemplos sem regra |
|---|---|---:|---:|---|
| [Scattered Spider](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1015) `G1015` | Sem país atribuído | 17 | 8 | T1021.007, T1069, T1213.003, T1213.005 |
| [APT29](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0016) `G0016` | Rússia | 14 | 8 | T1021.007, T1059.009, T1087.004, T1110.001 |
| [ShinyHunters](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1057) `G1057` | Sem país atribuído | 14 | 6 | T1059.009, T1069.003, T1072, T1213.003 |
| [APT28](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0007) `G0007` | Rússia | 13 | 9 | T1110.001, T1211, T1550.001, T1684.001 |
| [LAPSUS$](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1004) `G1004` | Sem país atribuído | 12 | 7 | T1213.001, T1213.003, T1213.005, T1621 |
| [VOID MANTICORE](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1055) `G1055` | Irã | 12 | 7 | T1072, T1110.001, T1110.004, T1657 |
| [NIMBUS MANTICORE](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1059) `G1059` | — | 11 | 8 | T1072, T1213.005, T1684.001 |
| [Storm-0501](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1053) `G1053` | Sem país atribuído | 11 | 6 | T1021.007, T1059.009, T1087.004, T1098.001 |
| [APT38](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0082) `G0082` | Coreia do Norte | 9 | 4 | T1213.005, T1213.006, T1657, T1677 |
| [TeamPCP](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1056) `G1056` | Sem país atribuído | 8 | 4 | T1550.001, T1657, T1677, T1684.001 |
| [HAFNIUM](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0125) `G0125` | China | 7 | 6 | T1550.001 |
| [OilRig](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0049) `G0049` | Irã | 7 | 5 | T1195, T1201 |
| [Sandworm Team](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0034) `G0034` | Rússia | 7 | 3 | T1072, T1195, T1213.006, T1539 |
| [Kimsuky](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0094) `G0094` | Coreia do Norte | 6 | 3 | T1539, T1657, T1684.001 |

## 6. Ferramentas de afiliados de ransomware que passam por aqui

Do Ransomware Tool Matrix (via APT4ALL): ferramentas usadas por gangues dentro da rede, nas categorias que esta tecnologia enxerga.

| Ferramenta | Categoria | Gangues que usam | Regras que citam |
|---|---|---:|---:|
| RClone | Exfiltração | 33 | 35 |
| MEGA | Exfiltração | 24 | 74 |
| WinSCP | Exfiltração | 16 | 24 |
| FileZilla | Exfiltração | 9 | 9 |
| Sendspace | Exfiltração | 7 | 49 |
| PSCP | Exfiltração | 4 | 7 |
| PrivatLab | Exfiltração | 4 | 48 |
| File[.]io | Exfiltração | 3 | 7 |
| Restic | Exfiltração | 3 | 12 |
| Temp[.]sh | Exfiltração | 3 | 52 |
| AZCopy | Exfiltração | 2 | 4 |
| Anonfiles | Exfiltração | 2 | 61 |
| Dropbox | Exfiltração | 2 | 67 |
| Qaz[.]im | Exfiltração | 2 | 1 |
| UFile | Exfiltração | 2 | 57 |
| pCloud | Exfiltração | 2 | 9 |
| Azure Blob Storage | Exfiltração | 1 | 4 |
| BackBlaze | Exfiltração | 1 | **0** |

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
| [APT40 Dropbox Tool User Agent](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A5ba715b6-71b7-44fd-8245-f66893e81b3d) | Sigma | SigmaHQ | T1071.001, T1567.002 |
| [Confluence Exploitation CVE-2019-3398](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae9bc39ae-978a-4e49-91ab-5bd481fc668b) | Sigma | SigmaHQ | T1190 |
| [CVE-2023-22518 Exploitation Attempt - Suspicious Confluence Child Process (Linux)](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Af8987c03-4290-4c96-870f-55e75ee377f4) | Sigma | SigmaHQ | T1059, T1190 |
| [Atlassian Bitbucket Command Injection Via Archive API](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A65c0a0ab-d675-4441-bd6b-d3db226a2685) | Sigma | SigmaHQ | T1190 |
| [Atlassian Confluence CVE-2022-26134](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A7fb14105-530e-4e2e-8cfb-99f7d8700b66) | Sigma | SigmaHQ | T1059, T1190 |
| [Potential CVE-2021-26084 Exploitation Attempt](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A38825179-3c78-4fed-b222-2e2166b926b1) | Sigma | SigmaHQ | T1190 |
| [Potential Atlassian Confluence CVE-2021-26084 Exploitation Attempt](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A245f92e3-c4da-45f1-9070-bc552e06db11) | Sigma | SigmaHQ | T1059, T1190 |
| [Potential OGNL Injection Exploitation In JVM Based Application](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4d0af518-828e-4a04-a751-a7d03f3046ad) | Sigma | SigmaHQ | T1190 |
| [Suspicious Dropbox API Usage](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A25eabf56-22f0-4915-a1ed-056b8dae0a68) | Sigma | SigmaHQ | T1105, T1567.002 |
| [Suspicious Process Execution by Zoom](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A84b81b96-58dd-4c0d-9b2e-35023ab5ee88) | Elastic | Elastic detection-rules | T1059, T1059.002, T1059.004 |
| [OpenAI ChatGPT Enterprise Conversation Message Containing Credentials](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A231c2ade-69c8-4415-b710-0c56f5f07e95) | Elastic | Elastic detection-rules | T0055, T0057, T1552 |
| [CVE-2023-22518 Exploitation Attempt - Suspicious Confluence Child Process (Windows)](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1ddaa9a4-eb0b-4398-a9fe-7b018f9e23db) | Sigma | SigmaHQ | T1059, T1190 |
| [CVE-2023-22518 Exploitation Attempt - Vulnerable Endpoint Connection (Webserver)](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aa902d249-9b9c-4dc4-8fd0-fbe528ef965c) | Sigma | SigmaHQ | T1190 |
| [CVE-2023-22518 Exploitation Attempt - Vulnerable Endpoint Connection (Proxy)](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A27d2cdde-9778-490e-91ec-9bd0be6e8cc6) | Sigma | SigmaHQ | T1190 |
| [Pnscan Binary Data Transmission Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A97de11cd-4b67-4abf-9a8b-1020e670aa9e) | Sigma | SigmaHQ | T1046 |

## 10. Limites

- A tecnologia de cada regra é inferida por heurística sobre metadados e texto (techmap.py). Regras genéricas podem aparecer em várias tecnologias.
- "Sem regra" quer dizer sem regra pública neste catálogo, não sem detecção possível. Telemetria e contexto do seu ambiente decidem.
- Atribuição de país é afirmação das fontes reunidas pelo APT4ALL, não nossa.

---
Fontes: catálogo [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules), MITRE ATT&CK®, APT4ALL, Ransomware Tool Matrix (CC BY 4.0), TCEM, LLmInjection. Gerado em 2026-10-26.
