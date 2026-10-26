# Microsoft 365 — relatório de regras de detecção

> **TLP:CLEAR** · 2026-10-26 · domínio **SaaS & colaboração** · plataforma ATT&CK **Office Suite** · lente TCEM **Identity & Access** · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#techno=m365)

## 1. A história em um parágrafo

O palco é **o Microsoft 365 — e-mail, arquivos e conversas da empresa inteira**. O catálogo reúne **3,654 regras** que olham para cá — 1,041 de detecção, 1,115 de hunting, 1,390 assinaturas e 108 playbooks de resposta. Elas se concentram em **Persistência, Acesso inicial, Escalação de privilégio**. Das 79 técnicas do ATT&CK para a plataforma Office Suite, **59 (75%)** têm ao menos uma regra aqui e **20 não têm nenhuma** — é onde um atacante passa sem ser visto. Entre os grupos com mais técnicas nesta plataforma estão Scattered Spider, APT28, APT29.

**Lente TCEM — Identity & Access.** Authentication, authorization, privilege, federation, machine identity and administrative trust. Para observar: sign-in logs, privilege changes, token events, identity administration. Arquitetura a mapear: identity providers, privileged roles, service principals, federation, recovery access.

## 2. Números

| Indicador | Valor |
|---|---:|
| Regras | 3,654 |
| assinatura | 1,390 |
| hunting | 1,115 |
| detecção | 1,041 |
| playbook | 108 |
| Técnicas ATT&CK distintas | 164 |
| Cobertura da plataforma Office Suite | 59/79 (75%) |

### Por tática

| Tática | Regras |
|---|---:|
| Reconhecimento | 2 |
| Desenv. de recursos | 12 |
| Acesso inicial | 179 |
| Execução | 81 |
| Persistência | 265 |
| Escalação de privilégio | 163 |
| Furtividade | 138 |
| Enfraquecimento de defesas | 59 |
| Acesso a credenciais | 88 |
| Descoberta | 54 |
| Movimento lateral | 36 |
| Coleta | 140 |
| Comando e controle | 54 |
| Exfiltração | 48 |
| Impacto | 29 |

### Linguagens disponíveis

Em que formato você encontra regra pronta para esta tecnologia.

| Formato | Regras |
|---|---:|
| Suricata/Snort/Sagan | 1,390 |
| Sentinel KQL | 1,169 |
| Wazuh | 429 |
| Sigma | 180 |
| Splunk | 142 |
| Elastic | 113 |
| Playbook | 108 |
| YARA-L | 80 |
| KQL hunting | 32 |
| Panther | 11 |

### Padrões de correlação (TCEM)

Como as regras decidem. Muitas de evento único = cobertura ampla mas ruidosa; sequências e novidade = mais contexto, mais exigência de dados.

| Padrão | Regras | O que significa |
|---|---:|---|
| Evento único | 2,802 | Um evento, sozinho, já tem sinal suficiente para chamar o analista. |
| Novidade / raridade | 450 | Compara com o que é normal: entidade, relação ou valor nunca (ou raramente) visto. |
| Limiar / acúmulo | 128 | O sinal está na repetição: N eventos por chave em uma janela. |
| Fluxo de resposta | 108 | Não detecta: orquestra o que fazer depois do alerta (SOAR). |
| Mudança de estado | 85 | O risco está na transição: algo era seguro e deixou de ser (desligado, rebaixado, alterado). |
| Sequência ordenada | 81 | Dois ou mais passos da mesma entidade, na ordem certa, dentro de uma janela. |

### Fontes que mais contribuem

| Fonte | Regras |
|---|---:|
| Sagan rules (Quadrant) | 1,390 |
| Microsoft Sentinel (Hunting Queries) | 1,059 |
| SOCFortress Wazuh-Rules | 171 |
| Wazuh ruleset (oficial) | 150 |
| Splunk security_content | 121 |
| Microsoft Sentinel (Analytic Rules) | 110 |
| EVTX-Wazuh-Rules (saifbelaarbi) | 108 |
| SigmaHQ | 104 |
| Elastic detection-rules | 102 |
| OpenSearch Security Analytics | 76 |

## 3. Técnicas mais cobertas

| Técnica | Regras nesta tecnologia |
|---|---:|
| [T1114](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1114) Email Collection | 68 |
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | 57 |
| [T1190](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1190) Exploit Public-Facing Application | 48 |
| [T1505.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1505.003) Web Shell | 44 |
| [T1137](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1137) Office Application Startup | 42 |
| [T1213](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1213) Data from Information Repositories | 39 |
| [T1098](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1098) Account Manipulation | 38 |
| [T1566](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1566) Phishing | 37 |
| [T1528](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1528) Steal Application Access Token | 29 |
| [T1078.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.004) Cloud Accounts | 29 |
| [T1566.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1566.001) Spearphishing Attachment | 28 |
| [T1566.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1566.002) Spearphishing Link | 28 |

## 4. Detecção pela ausência — o que ninguém está olhando (20 técnicas)

Técnicas do ATT&CK para Office Suite **sem nenhuma regra nesta tecnologia**, ordenadas pelo número de grupos que as usam. A coluna "regras no catálogo" mostra se existe cobertura em outra tecnologia (ex.: EDR ou rede) que você pode adaptar.

| Técnica | Grupos que usam | Regras no catálogo (todas as tecnologias) |
|---|---:|---:|
| [T1657](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1657) Financial Theft | 19 | 2 |
| [T1684.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1684.001) Impersonation | 18 | 1 |
| [T1213.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1213.005) Messaging Applications | 5 | **0** |
| [T1036.010](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1036.010) Masquerade Account Name | 4 | 1 |
| [T1059.009](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.009) Cloud API | 4 | 11 |
| [T1078.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.001) Default Accounts | 4 | 16 |
| [T1087.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1087.003) Email Account | 4 | 1 |
| [T1110.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1110.002) Password Cracking | 4 | 11 |
| [T1137.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1137.002) Office Test | 1 | 7 |
| [T1550.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1550.004) Web Session Cookie | 1 | 4 |
| [T1552.008](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1552.008) Chat Messages | 1 | 2 |
| [T1556.007](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1556.007) Hybrid Identity | 1 | 5 |
| [T1667](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1667) Email Bombing | 1 | **0** |
| [T1684](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1684) Social Engineering | 1 | 1 |
| [T1697](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1697) Steal Application Specific Passwords | 1 | **0** |
| [T1548.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1548.005) Temporary Elevated Cloud Access | 0 | 8 |
| [T1567.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1567.004) Exfiltration Over Webhook | 0 | 1 |
| [T1648](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1648) Serverless Execution | 0 | 18 |
| [T1671](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1671) Cloud Application Integration | 0 | 2 |
| [T1684.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1684.002) Email Spoofing | 0 | **0** |

## 5. Quem mira esta plataforma

Grupos com mais técnicas registradas nesta plataforma e quantas delas você enxerga com as regras desta tecnologia. País atribuído pelo APT4ALL (afirmação de quem publicou).

| Grupo | Origem atribuída | Técnicas na plataforma | Com regra aqui | Exemplos sem regra |
|---|---|---:|---:|---|
| [Scattered Spider](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1015) `G1015` | Sem país atribuído | 20 | 17 | T1213.005, T1657, T1684.001 |
| [APT28](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0007) `G0007` | Rússia | 16 | 14 | T1137.002, T1684.001 |
| [APT29](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0016) `G0016` | Rússia | 16 | 14 | T1059.009, T1556.007 |
| [VOID MANTICORE](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1055) `G1055` | Irã | 13 | 11 | T1657, T1684.001 |
| [LAPSUS$](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1004) `G1004` | Sem país atribuído | 12 | 9 | T1213.005, T1552.008, T1684.001 |
| [NIMBUS MANTICORE](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1059) `G1059` | — | 11 | 9 | T1213.005, T1684.001 |
| [ShinyHunters](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1057) `G1057` | Sem país atribuído | 11 | 8 | T1059.009, T1657, T1684 |
| [Storm-0501](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1053) `G1053` | Sem país atribuído | 10 | 8 | T1059.009, T1657 |
| [HAFNIUM](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0125) `G0125` | China | 9 | 9 | — |
| [Kimsuky](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0094) `G0094` | Coreia do Norte | 8 | 6 | T1657, T1684.001 |
| [Magic Hound](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0059) `G0059` | Irã | 8 | 5 | T1036.010, T1078.001, T1087.003 |
| [APT38](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0082) `G0082` | Coreia do Norte | 7 | 4 | T1213.005, T1657, T1684.001 |
| [APT42](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1044) `G1044` | Irã | 7 | 5 | T1684.001, T1697 |
| [Chimera](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0114) `G0114` | China | 7 | 7 | — |

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
| [CVE-2020-0688 Exploitation via Eventlog](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad6266bf5-935e-4661-b477-78772735a7cb) | Sigma | SigmaHQ | T1190 |
| [CVE-2020-0688 Exchange Exploitation via Web Log](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Afce2c2e2-0fb5-41ab-a14c-5391e1fd70a5) | Sigma | SigmaHQ | T1190 |
| [CVE-2020-0688 Exploitation Attempt](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A7c64e577-d72e-4c3d-9d75-8de6d1f9146a) | Sigma | SigmaHQ | T1190 |
| [OWASSRF Exploitation Attempt Using Public POC - Webserver](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A92d78c63-5a5c-4c40-9b60-463810ffb082) | Sigma | SigmaHQ | T1190 |
| [Potential OWASSRF Exploitation Attempt - Proxy](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1ddf4596-1908-43c9-add2-1d2c2fcc4797) | Sigma | SigmaHQ | T1190 |
| [OWASSRF Exploitation Attempt Using Public POC - Proxy](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Afdd7e904-7304-4616-a46a-e32f917c4be4) | Sigma | SigmaHQ | T1190 |
| [Potential OWASSRF Exploitation Attempt - Webserver](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A181f49fa-0b21-4665-a98c-a57025ebb8c7) | Sigma | SigmaHQ | T1190 |
| [Exchange Exploitation Used by HAFNIUM](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A67bce556-312f-4c81-9162-c3c9ff2599b2) | Sigma | SigmaHQ | T1190 |
| [HAFNIUM Exchange Exploitation Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Abbb2dedd-a0e3-46ab-ba6c-6c82ae7a9aa7) | Sigma | SigmaHQ | T1053, T1546 |
| [CVE-2021-33766 Exchange ProxyToken Exploitation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A56973b50-3382-4b56-bdf5-f51a3183797a) | Sigma | SigmaHQ | T1190 |
| [Possible Exploitation of Exchange RCE CVE-2021-42321](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac92f1896-d1d2-43c3-92d5-7a5b35c217bb) | Sigma | SigmaHQ | T1210 |
| [Exchange Exploitation CVE-2021-28480](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aa2a9d722-0acb-4096-bccc-daaf91a5037b) | Sigma | SigmaHQ | T1190 |
| [Exchange ProxyShell Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A23eee45e-933b-49f9-ae1b-df706d2d52ef) | Sigma | SigmaHQ | T1190 |
| [Potential Persistence Via Outlook Form](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac3edc6a5-d9d4-48d8-930e-aab518390917) | Sigma | SigmaHQ | T1137.003 |
| [Suspicious Outlook Macro Created](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A117d3d3a-755c-4a61-b23e-9171146d094c) | Sigma | SigmaHQ | T1008, T1137, T1546 |

## 10. Limites

- A tecnologia de cada regra é inferida por heurística sobre metadados e texto (techmap.py). Regras genéricas podem aparecer em várias tecnologias.
- "Sem regra" quer dizer sem regra pública neste catálogo, não sem detecção possível. Telemetria e contexto do seu ambiente decidem.
- Atribuição de país é afirmação das fontes reunidas pelo APT4ALL, não nossa.

---
Fontes: catálogo [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules), MITRE ATT&CK®, APT4ALL, Ransomware Tool Matrix (CC BY 4.0), TCEM, LLmInjection. Gerado em 2026-10-26.
