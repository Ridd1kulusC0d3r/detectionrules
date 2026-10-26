# AWS — relatório de regras de detecção

> **TLP:CLEAR** · 2026-10-26 · domínio **Nuvem** · plataforma ATT&CK **IaaS** · lente TCEM **Cloud & Multi-Cloud** · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#techno=aws)

## 1. A história em um parágrafo

O palco é **a conta AWS — o painel de controle de servidores, dados e chaves na nuvem**. O catálogo reúne **2,833 regras** que olham para cá — 1,268 de detecção, 99 de hunting, 1,347 assinaturas e 119 playbooks de resposta. Elas se concentram em **Persistência, Escalação de privilégio, Acesso inicial**. Das 104 técnicas do ATT&CK para a plataforma IaaS, **83 (80%)** têm ao menos uma regra aqui e **21 não têm nenhuma** — é onde um atacante passa sem ser visto. Entre os grupos com mais técnicas nesta plataforma estão Scattered Spider, Storm-0501, APT28.

**Lente TCEM — Cloud & Multi-Cloud.** Cloud control planes, workloads, identities, management APIs, cross-cloud trust and SaaS dependencies. Para observar: cloud audit, identity logs, control-plane changes, workload activity. Arquitetura a mapear: control planes, cloud identities, organization hierarchy, workload identities, management APIs.

## 2. Números

| Indicador | Valor |
|---|---:|
| Regras | 2,833 |
| assinatura | 1,347 |
| detecção | 1,268 |
| playbook | 119 |
| hunting | 99 |
| Técnicas ATT&CK distintas | 203 |
| Cobertura da plataforma IaaS | 83/104 (80%) |

### Por tática

| Tática | Regras |
|---|---:|
| Reconhecimento | 19 |
| Desenv. de recursos | 34 |
| Acesso inicial | 249 |
| Execução | 85 |
| Persistência | 369 |
| Escalação de privilégio | 327 |
| Furtividade | 224 |
| Enfraquecimento de defesas | 200 |
| Acesso a credenciais | 141 |
| Descoberta | 101 |
| Movimento lateral | 58 |
| Coleta | 94 |
| Comando e controle | 52 |
| Exfiltração | 87 |
| Impacto | 120 |

### Linguagens disponíveis

Em que formato você encontra regra pronta para esta tecnologia.

| Formato | Regras |
|---|---:|
| Suricata/Snort/Sagan | 1,347 |
| Panther | 349 |
| Elastic | 345 |
| Wazuh | 163 |
| Sentinel KQL | 158 |
| Splunk | 132 |
| Playbook | 119 |
| Sigma | 109 |
| YARA-L | 109 |
| Falco | 2 |

### Padrões de correlação (TCEM)

Como as regras decidem. Muitas de evento único = cobertura ampla mas ruidosa; sequências e novidade = mais contexto, mais exigência de dados.

| Padrão | Regras | O que significa |
|---|---:|---|
| Evento único | 1,981 | Um evento, sozinho, já tem sinal suficiente para chamar o analista. |
| Novidade / raridade | 351 | Compara com o que é normal: entidade, relação ou valor nunca (ou raramente) visto. |
| Limiar / acúmulo | 150 | O sinal está na repetição: N eventos por chave em uma janela. |
| Mudança de estado | 119 | O risco está na transição: algo era seguro e deixou de ser (desligado, rebaixado, alterado). |
| Fluxo de resposta | 119 | Não detecta: orquestra o que fazer depois do alerta (SOAR). |
| Sequência ordenada | 112 | Dois ou mais passos da mesma entidade, na ordem certa, dentro de uma janela. |
| Assinatura de conteúdo | 1 | Casa bytes/strings dentro de arquivo, memória ou pacote, não eventos de log. |

### Fontes que mais contribuem

| Fonte | Regras |
|---|---:|
| Sagan rules (Quadrant) | 1,346 |
| Panther panther-analysis | 349 |
| Elastic detection-rules | 315 |
| Wazuh ruleset (oficial) | 157 |
| Splunk security_content | 118 |
| Microsoft Sentinel (Analytic Rules) | 102 |
| Cortex XSOAR (demisto/content) | 75 |
| SigmaHQ | 63 |
| Google SecOps / Chronicle | 57 |
| Microsoft Sentinel (Hunting Queries) | 56 |

## 3. Técnicas mais cobertas

| Técnica | Regras nesta tecnologia |
|---|---:|
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | 154 |
| [T1685](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1685) Disable or Modify Tools | 122 |
| [T1098](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1098) Account Manipulation | 80 |
| [T1078.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.004) Cloud Accounts | 78 |
| [T1530](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1530) Data from Cloud Storage | 75 |
| [T1485](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1485) Data Destruction | 45 |
| [T1552](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1552) Unsecured Credentials | 44 |
| [T1685.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1685.002) Disable or Modify Cloud Log | 42 |
| [T1005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1005) Data from Local System | 40 |
| [T1110](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1110) Brute Force | 35 |
| [T1098.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1098.003) Additional Cloud Roles | 35 |
| [T1537](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1537) Transfer Data to Cloud Account | 33 |

## 4. Detecção pela ausência — o que ninguém está olhando (21 técnicas)

Técnicas do ATT&CK para IaaS **sem nenhuma regra nesta tecnologia**, ordenadas pelo número de grupos que as usam. A coluna "regras no catálogo" mostra se existe cobertura em outra tecnologia (ex.: EDR ou rede) que você pode adaptar.

| Técnica | Grupos que usam | Regras no catálogo (todas as tecnologias) |
|---|---:|---:|
| [T1049](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1049) System Network Connections Discovery | 33 | 47 |
| [T1518.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1518.001) Security Software Discovery | 27 | 54 |
| [T1199](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1199) Trusted Relationship | 14 | 18 |
| [T1680](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1680) Local Storage Discovery | 10 | **0** |
| [T1654](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1654) Log Enumeration | 5 | 3 |
| [T1036.010](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1036.010) Masquerade Account Name | 4 | 1 |
| [T1496.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1496.001) Compute Hijacking | 4 | 2 |
| [T1211](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1211) Exploitation for Stealth | 2 | 40 |
| [T1578.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1578.003) Delete Cloud Instance | 2 | 4 |
| [T1614](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1614) System Location Discovery | 2 | 31 |
| [T1020.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1020.001) Traffic Duplication | 1 | **0** |
| [T1204.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1204.003) Malicious Image | 1 | 3 |
| [T1550.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1550.004) Web Session Cookie | 1 | 4 |
| [T1556.007](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1556.007) Hybrid Identity | 1 | 5 |
| [T1496.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1496.002) Bandwidth Hijacking | 0 | **0** |
| [T1499.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1499.002) Service Exhaustion Flood | 0 | 2 |
| [T1499.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1499.003) Application Exhaustion Flood | 0 | 2 |
| [T1499.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1499.004) Application or System Exploitation | 0 | 9 |
| [T1606.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1606.001) Web Cookies | 0 | 2 |
| [T1606.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1606.002) SAML Tokens | 0 | 2 |

## 5. Quem mira esta plataforma

Grupos com mais técnicas registradas nesta plataforma e quantas delas você enxerga com as regras desta tecnologia. País atribuído pelo APT4ALL (afirmação de quem publicou).

| Grupo | Origem atribuída | Técnicas na plataforma | Com regra aqui | Exemplos sem regra |
|---|---|---:|---:|---|
| [Scattered Spider](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1015) `G1015` | Sem país atribuído | 22 | 22 | — |
| [Storm-0501](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1053) `G1053` | Sem país atribuído | 20 | 18 | T1518.001, T1578.003 |
| [APT28](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0007) `G0007` | Rússia | 15 | 13 | T1199, T1211 |
| [APT29](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0016) `G0016` | Rússia | 15 | 13 | T1199, T1556.007 |
| [ShinyHunters](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1057) `G1057` | Sem país atribuído | 15 | 15 | — |
| [VOID MANTICORE](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1055) `G1055` | Irã | 15 | 14 | T1199 |
| [Salt Typhoon](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1045) `G1045` | China | 13 | 11 | T1020.001, T1199 |
| [Sandworm Team](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0034) `G0034` | Rússia | 13 | 11 | T1049, T1199 |
| [TeamTNT](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0139) `G0139` | Sem país atribuído | 13 | 8 | T1049, T1204.003, T1496.001, T1518.001 |
| [LAPSUS$](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1004) `G1004` | Sem país atribuído | 12 | 10 | T1199, T1578.003 |
| [Volt Typhoon](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1017) `G1017` | China | 12 | 8 | T1049, T1614, T1654, T1680 |
| [APT38](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0082) `G0082` | Coreia do Norte | 11 | 9 | T1049, T1518.001 |
| [APT41](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0096) `G0096` | China | 11 | 9 | T1049, T1496.001 |
| [Ember Bear](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1003) `G1003` | Rússia | 10 | 9 | T1654 |

## 6. Ferramentas de afiliados de ransomware que passam por aqui

Do Ransomware Tool Matrix (via APT4ALL): ferramentas usadas por gangues dentro da rede, nas categorias que esta tecnologia enxerga.

| Ferramenta | Categoria | Gangues que usam | Regras que citam |
|---|---|---:|---:|
| Mimikatz | Roubo de credenciais | 43 | 253 |
| RClone | Exfiltração | 33 | 35 |
| MEGA | Exfiltração | 24 | 74 |
| WinSCP | Exfiltração | 16 | 24 |
| ProcDump | Roubo de credenciais | 11 | 109 |
| LaZagne | Roubo de credenciais | 10 | 30 |
| FileZilla | Exfiltração | 9 | 9 |
| Sendspace | Exfiltração | 7 | 49 |
| NirSoft WebBrowserPassView | Roubo de credenciais | 6 | 8 |
| Veeam-Get-Creds | Roubo de credenciais | 5 | 12 |
| PSCP | Exfiltração | 4 | 7 |
| PrivatLab | Exfiltração | 4 | 48 |
| NirSoft Dialupass | Roubo de credenciais | 3 | **0** |
| NirSoft IEPassView (iepv) | Roubo de credenciais | 3 | **0** |
| NirSoft MailPassView | Roubo de credenciais | 3 | **0** |
| NirSoft Netpass | Roubo de credenciais | 3 | **0** |
| NirSoft RouterPassView | Roubo de credenciais | 3 | **0** |
| PasswordFox | Roubo de credenciais | 3 | **0** |

## 7. Cenário de referência TCEM

### Cloud Control Plane reference case

**Missão:** Preserve trusted administration of the cloud control plane and production tenancy.

**Privileged cloud session followed by organization-wide policy change** — Detect high-impact control-plane changes performed from privileged administrative context.

1. privileged_cloud_session — T1078 (1265 regras no catálogo)
2. cloud_policy_change — T1098 (831 regras no catálogo)

Contrato de telemetria: fonte **cloud control-plane audit**, campos exigidos actor.id, source.ip, target.resource, action, timestamp; **faltam target.resource** (status partial).
Especificação de detecção: padrão **ordered-sequence**, janela 30m, agrupado por actor.id. Alternativas benignas: approved change with expected authorization context.

## 9. Regras recomendadas para começar

Ranqueadas por portabilidade do formato, maturidade, severidade e por mapearem técnica ATT&CK.

| Regra | Formato | Fonte | Técnicas |
|---|---|---|---|
| [AWS SecurityHub Findings Evasion](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aa607e1fe-74bf-4440-a3ec-b059b9103157) | Sigma | SigmaHQ | T1685 |
| [AWS EC2 Disable EBS Encryption](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A16124c2d-e40b-4fcc-8f2c-5ab7870a2223) | Sigma | SigmaHQ | T1486, T1565 |
| [AWS Identity Center Identity Provider Change](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad3adb3ef-b7e7-4003-9092-1924c797db35) | Sigma | SigmaHQ | T1556 |
| [AWS IAM S3Browser User or AccessKey Creation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Adb014773-d9d9-4792-91e5-133337c0ffee) | Sigma | SigmaHQ | T1059.009, T1078.004 |
| [AWS IAM S3Browser Templated S3 Bucket Policy Creation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Adb014773-7375-4f4e-b83b-133337c0ffee) | Sigma | SigmaHQ | T1059.009, T1078.004 |
| [AWS User Login Profile Was Modified](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A055fb148-60f8-462d-ad16-26926ce050f1) | Sigma | SigmaHQ | T1098 |
| [AWS Config Disabling Channel/Recorder](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A07330162-dba1-4746-8121-a9647d49d297) | Sigma | SigmaHQ | T1685.002 |
| [Restore Public AWS RDS Instance](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac3f265c7-ff03-4056-8ab2-d486227b4599) | Sigma | SigmaHQ | T1020 |
| [Potential Malicious Usage of CloudTrail System Manager](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A38e7f511-3f74-41d4-836e-f57dfa18eead) | Sigma | SigmaHQ | T1566, T1566.002 |
| [AWS IAM S3Browser LoginProfile Creation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Adb014773-b1d3-46bd-ba26-133337c0ffee) | Sigma | SigmaHQ | T1059.009, T1078.004 |
| [AWS EC2 Startup Shell Script Change](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1ab3c5ed-5baf-417b-bb6b-78ca33f6c3df) | Sigma | SigmaHQ | T1059.001, T1059.003, T1059.004 |
| [Malicious Usage Of IMDS Credentials Outside Of AWS Infrastructure](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A352a918a-34d8-4882-8470-44830c507aa3) | Sigma | SigmaHQ | T1078, T1078.002 |
| [AWS GuardDuty Important Change](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A6e61ee20-ce00-4f8d-8aee-bedd8216f7e3) | Sigma | SigmaHQ | T1685 |
| [CobaltStrike Malleable Amazon Browsing Traffic Profile](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A953b895e-5cc9-454b-b183-7f3db555452e) | Sigma | OpenSearch Security Analytics | T1071.001 |
| [Potential Destructive AWS CLI Command Executed by GenAI Agent](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A2635d2ba-51e7-404a-9b17-db413a1351d5) | Elastic | Elastic detection-rules | T0051, T1485, T1531 |

## 10. Limites

- A tecnologia de cada regra é inferida por heurística sobre metadados e texto (techmap.py). Regras genéricas podem aparecer em várias tecnologias.
- "Sem regra" quer dizer sem regra pública neste catálogo, não sem detecção possível. Telemetria e contexto do seu ambiente decidem.
- Atribuição de país é afirmação das fontes reunidas pelo APT4ALL, não nossa.

---
Fontes: catálogo [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules), MITRE ATT&CK®, APT4ALL, Ransomware Tool Matrix (CC BY 4.0), TCEM, LLmInjection. Gerado em 2026-10-26.
