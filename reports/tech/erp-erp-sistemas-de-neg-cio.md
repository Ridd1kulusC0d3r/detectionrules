# ERP & sistemas de negócio — relatório de regras de detecção

> **TLP:CLEAR** · 2026-10-26 · domínio **Web & aplicações** · plataforma ATT&CK **SaaS** · lente TCEM **Web & API** · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#techno=erp)

## 1. A história em um parágrafo

O palco é **o ERP — finanças, compras e folha de pagamento**. O catálogo reúne **187 regras** que olham para cá — 180 de detecção, 3 de hunting, 3 assinaturas e 1 playbooks de resposta. Elas se concentram em **Persistência, Escalação de privilégio, Enfraquecimento de defesas**. Das 78 técnicas do ATT&CK para a plataforma SaaS, **16 (21%)** têm ao menos uma regra aqui e **62 não têm nenhuma** — é onde um atacante passa sem ser visto. Entre os grupos com mais técnicas nesta plataforma estão Scattered Spider, APT29, ShinyHunters.

**Lente TCEM — Web & API.** Internet-facing applications, APIs, service trust, sessions, application data and runtime behavior. Para observar: application logs, gateway logs, WAF, authentication, API audit. Arquitetura a mapear: public endpoints, API gateways, sessions, service identities, backend trust.

## 2. Números

| Indicador | Valor |
|---|---:|
| Regras | 187 |
| detecção | 180 |
| hunting | 3 |
| assinatura | 3 |
| playbook | 1 |
| Técnicas ATT&CK distintas | 56 |
| Cobertura da plataforma SaaS | 16/78 (21%) |

### Por tática

| Tática | Regras |
|---|---:|
| Acesso inicial | 21 |
| Execução | 17 |
| Persistência | 56 |
| Escalação de privilégio | 55 |
| Furtividade | 21 |
| Enfraquecimento de defesas | 22 |
| Acesso a credenciais | 7 |
| Descoberta | 3 |
| Movimento lateral | 5 |
| Coleta | 6 |
| Comando e controle | 6 |
| Exfiltração | 7 |
| Impacto | 6 |

### Linguagens disponíveis

Em que formato você encontra regra pronta para esta tecnologia.

| Formato | Regras |
|---|---:|
| Sentinel KQL | 106 |
| YARA-L | 64 |
| Sigma | 7 |
| Suricata/Snort/Sagan | 3 |
| Elastic | 2 |
| Splunk | 2 |
| Wazuh | 2 |
| Playbook | 1 |

### Padrões de correlação (TCEM)

Como as regras decidem. Muitas de evento único = cobertura ampla mas ruidosa; sequências e novidade = mais contexto, mais exigência de dados.

| Padrão | Regras | O que significa |
|---|---:|---|
| Evento único | 81 | Um evento, sozinho, já tem sinal suficiente para chamar o analista. |
| Sequência ordenada | 60 | Dois ou mais passos da mesma entidade, na ordem certa, dentro de uma janela. |
| Novidade / raridade | 21 | Compara com o que é normal: entidade, relação ou valor nunca (ou raramente) visto. |
| Mudança de estado | 16 | O risco está na transição: algo era seguro e deixou de ser (desligado, rebaixado, alterado). |
| Limiar / acúmulo | 8 | O sinal está na repetição: N eventos por chave em uma janela. |
| Fluxo de resposta | 1 | Não detecta: orquestra o que fazer depois do alerta (SOAR). |

### Fontes que mais contribuem

| Fonte | Regras |
|---|---:|
| Microsoft Sentinel (Analytic Rules) | 104 |
| Google SecOps / Chronicle | 63 |
| SigmaHQ | 7 |
| Sagan rules (Quadrant) | 3 |
| Elastic detection-rules | 2 |
| Microsoft Sentinel (Hunting Queries) | 2 |
| SOCFortress Wazuh-Rules | 2 |
| Splunk security_content | 1 |
| Chronicle rules (rowham) | 1 |
| Splunk analytic stories | 1 |

## 3. Técnicas mais cobertas

| Técnica | Regras nesta tecnologia |
|---|---:|
| [T1098](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1098) Account Manipulation | 26 |
| [T1685](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1685) Disable or Modify Tools | 14 |
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | 11 |
| [T1190](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1190) Exploit Public-Facing Application | 9 |
| [T1059](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059) Command and Scripting Interpreter | 9 |
| [T1548](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1548) Abuse Elevation Control Mechanism | 8 |
| [T1059.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.003) Windows Command Shell | 5 |
| [T1505.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1505.003) Web Shell | 4 |
| [T1136](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1136) Create Account | 4 |
| [T1005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1005) Data from Local System | 4 |
| [T1505](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1505) Server Software Component | 3 |
| [T1134](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1134) Access Token Manipulation | 3 |

## 4. Detecção pela ausência — o que ninguém está olhando (62 técnicas)

Técnicas do ATT&CK para SaaS **sem nenhuma regra nesta tecnologia**, ordenadas pelo número de grupos que as usam. A coluna "regras no catálogo" mostra se existe cobertura em outra tecnologia (ex.: EDR ou rede) que você pode adaptar.

| Técnica | Grupos que usam | Regras no catálogo (todas as tecnologias) |
|---|---:|---:|
| [T1566.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1566.002) Spearphishing Link | 48 | 138 |
| [T1119](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1119) Automated Collection | 21 | 72 |
| [T1657](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1657) Financial Theft | 19 | 2 |
| [T1684.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1684.001) Impersonation | 18 | 1 |
| [T1078.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.004) Cloud Accounts | 14 | 356 |
| [T1199](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1199) Trusted Relationship | 14 | 18 |
| [T1110.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1110.003) Password Spraying | 12 | 62 |
| [T1539](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1539) Steal Web Session Cookie | 8 | 54 |
| [T1566](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1566) Phishing | 8 | 662 |
| [T1534](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1534) Internal Spearphishing | 7 | 5 |
| [T1069](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1069) Permission Groups Discovery | 6 | 242 |
| [T1213.006](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1213.006) Databases | 6 | 2 |
| [T1530](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1530) Data from Cloud Storage | 6 | 150 |
| [T1567](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1567) Exfiltration Over Web Service | 6 | 269 |
| [T1080](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1080) Taint Shared Content | 5 | 12 |
| [T1213.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1213.005) Messaging Applications | 5 | **0** |
| [T1036.010](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1036.010) Masquerade Account Name | 4 | 1 |
| [T1059.009](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.009) Cloud API | 4 | 11 |
| [T1078.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.001) Default Accounts | 4 | 16 |
| [T1110.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1110.001) Password Guessing | 4 | 63 |

## 5. Quem mira esta plataforma

Grupos com mais técnicas registradas nesta plataforma e quantas delas você enxerga com as regras desta tecnologia. País atribuído pelo APT4ALL (afirmação de quem publicou).

| Grupo | Origem atribuída | Técnicas na plataforma | Com regra aqui | Exemplos sem regra |
|---|---|---:|---:|---|
| [Scattered Spider](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1015) `G1015` | Sem país atribuído | 17 | 4 | T1021.007, T1069, T1078.004, T1087 |
| [APT29](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0016) `G0016` | Rússia | 14 | 3 | T1021.007, T1059.009, T1078.004, T1087.004 |
| [ShinyHunters](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1057) `G1057` | Sem país atribuído | 14 | 3 | T1059.009, T1069.003, T1078.004, T1213.003 |
| [APT28](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0007) `G0007` | Rússia | 13 | 3 | T1078.004, T1110.001, T1110.003, T1119 |
| [LAPSUS$](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1004) `G1004` | Sem país atribuído | 12 | 3 | T1078.004, T1136.003, T1199, T1213.001 |
| [VOID MANTICORE](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1055) `G1055` | Irã | 12 | 4 | T1078.004, T1110.001, T1110.004, T1119 |
| [NIMBUS MANTICORE](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1059) `G1059` | — | 11 | 3 | T1078.004, T1110.003, T1199, T1213.005 |
| [Storm-0501](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1053) `G1053` | Sem país atribuído | 11 | 4 | T1021.007, T1059.009, T1078.004, T1087.004 |
| [APT38](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0082) `G0082` | Coreia do Norte | 9 | 1 | T1078.004, T1213.005, T1213.006, T1566.002 |
| [TeamPCP](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1056) `G1056` | Sem país atribuído | 8 | 2 | T1078.004, T1528, T1550.001, T1657 |
| [HAFNIUM](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0125) `G0125` | China | 7 | 1 | T1078.004, T1110.003, T1119, T1199 |
| [OilRig](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0049) `G0049` | Irã | 7 | 3 | T1119, T1195, T1201, T1566.002 |
| [Sandworm Team](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0034) `G0034` | Rússia | 7 | 2 | T1195, T1199, T1213.006, T1539 |
| [Kimsuky](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0094) `G0094` | Coreia do Norte | 6 | 0 | T1534, T1539, T1566, T1566.002 |

## 9. Regras recomendadas para começar

Ranqueadas por portabilidade do formato, maturidade, severidade e por mapearem técnica ATT&CK.

| Regra | Formato | Fonte | Técnicas |
|---|---|---|---|
| [Potential CVE-2022-21587 Exploitation Attempt](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad033cb8a-8669-4a8e-a974-48d4185a8503) | Sigma | SigmaHQ | T1190 |
| [Potential SAP NetWeaver Exploitation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A23c53c4c-aa8b-4b07-85c0-fe46a9c8acaf) | Elastic | Elastic detection-rules | T1059, T1059.001, T1059.003 |
| [Potential SAP NetWeaver WebShell Creation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Af7d588ba-e4b0-442e-879d-7ec39fbd69c5) | Elastic | Elastic detection-rules | T1059, T1059.007, T1203 |
| [Potential SAP NetViewer Webshell Command Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A94e12f41-6cb3-45c5-97b1-c783a7bf2e72) | Sigma | SigmaHQ | T1190, T1505.003 |
| [Potential Java WebShell Upload in SAP NetViewer Server](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A639b893f-f93a-4e53-a7c8-f08cf73fe7f7) | Sigma | SigmaHQ | T1505.003 |
| [Suspicious Child Process of SAP NetWeaver - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A69dea60b-2deb-4c9e-a685-ad542f4367f9) | Sigma | SigmaHQ | T1059.003, T1190 |
| [Suspicious Child Process of SAP NetWeaver](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A5b304bcb-ac33-49d0-87af-fa1b3ca94333) | Sigma | SigmaHQ | T1059.003, T1190 |
| [Potential SAP NetWeaver Webshell Creation - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A5b91409c-cb18-4ab6-ac75-c5759f998409) | Sigma | SigmaHQ | T1059.003, T1190 |
| [SAP BTP - Cloud Integration JDBC data source changes](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3Ab2c3d4e5-6f7a-8b9c-0d1e-2f3a4b5c6d7e) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) | T1021 |
| [SAP BTP - Cloud Integration access policy tampering](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A9e6f4b2c-0d3e-5a8f-c9b7-2f5d8a1e4c6b) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) | T1222 |
| [SAP BTP - Cloud Integration artifact deployment](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3Aa1b2c3d4-5e6f-7a8b-9c0d-1e2f3a4b5c6d) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) | T1546 |
| [SAP BTP - User added to Cloud Identity Service privileged Administrators list](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A7d4e9f2a-8b1c-4a5d-9e3f-6c2b1a0d8e7f) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) | T1078 |
| [SAP BTP - Build Work Zone unauthorized access and role tampering](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A8e5f3a2c-9d1b-4c6e-a7f8-3b2d1e0c9a5f) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) | T1070, T1531 |
| [Pathlock TDnR - SAP Instance Profile Changes](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A2a3b4c5d-6e7f-4a0b-8c1d-2e3f4a5b6c64) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) | T1098 |
| [Pathlock TDnR - Critical File Integrity Changes](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A2a3b4c5d-6e7f-4a0b-8c1d-2e3f4a5b6c24) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) | T1036 |

## 10. Limites

- A tecnologia de cada regra é inferida por heurística sobre metadados e texto (techmap.py). Regras genéricas podem aparecer em várias tecnologias.
- "Sem regra" quer dizer sem regra pública neste catálogo, não sem detecção possível. Telemetria e contexto do seu ambiente decidem.
- Atribuição de país é afirmação das fontes reunidas pelo APT4ALL, não nossa.

---
Fontes: catálogo [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules), MITRE ATT&CK®, APT4ALL, Ransomware Tool Matrix (CC BY 4.0), TCEM, LLmInjection. Gerado em 2026-10-26.
