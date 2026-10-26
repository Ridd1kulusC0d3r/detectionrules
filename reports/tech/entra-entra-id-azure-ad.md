# Entra ID (Azure AD) — relatório de regras de detecção

> **TLP:CLEAR** · 2026-10-26 · domínio **Identidade** · plataforma ATT&CK **Identity Provider** · lente TCEM **Identity & Access** · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#techno=entra)

## 1. A história em um parágrafo

O palco é **o Entra ID (Azure AD) — quem é quem para Microsoft 365, Azure e centenas de apps**. O catálogo reúne **977 regras** que olham para cá — 576 de detecção, 249 de hunting, 124 assinaturas e 28 playbooks de resposta. Elas se concentram em **Persistência, Escalação de privilégio, Acesso inicial**. Das 49 técnicas do ATT&CK para a plataforma Identity Provider, **37 (76%)** têm ao menos uma regra aqui e **12 não têm nenhuma** — é onde um atacante passa sem ser visto. Entre os grupos com mais técnicas nesta plataforma estão APT29, Scattered Spider, Storm-0501.

**Lente TCEM — Identity & Access.** Authentication, authorization, privilege, federation, machine identity and administrative trust. Para observar: sign-in logs, privilege changes, token events, identity administration. Arquitetura a mapear: identity providers, privileged roles, service principals, federation, recovery access.

## 2. Números

| Indicador | Valor |
|---|---:|
| Regras | 977 |
| detecção | 576 |
| hunting | 249 |
| assinatura | 124 |
| playbook | 28 |
| Técnicas ATT&CK distintas | 95 |
| Cobertura da plataforma Identity Provider | 37/49 (76%) |

### Por tática

| Tática | Regras |
|---|---:|
| Reconhecimento | 1 |
| Desenv. de recursos | 13 |
| Acesso inicial | 209 |
| Execução | 6 |
| Persistência | 322 |
| Escalação de privilégio | 303 |
| Furtividade | 194 |
| Enfraquecimento de defesas | 48 |
| Acesso a credenciais | 149 |
| Descoberta | 32 |
| Movimento lateral | 46 |
| Coleta | 15 |
| Comando e controle | 16 |
| Exfiltração | 8 |
| Impacto | 14 |

### Linguagens disponíveis

Em que formato você encontra regra pronta para esta tecnologia.

| Formato | Regras |
|---|---:|
| Sentinel KQL | 382 |
| Suricata/Snort/Sagan | 124 |
| Elastic | 120 |
| Sigma | 100 |
| Splunk | 86 |
| KQL hunting | 63 |
| YARA-L | 54 |
| Playbook | 28 |
| Panther | 11 |
| Wazuh | 9 |

### Padrões de correlação (TCEM)

Como as regras decidem. Muitas de evento único = cobertura ampla mas ruidosa; sequências e novidade = mais contexto, mais exigência de dados.

| Padrão | Regras | O que significa |
|---|---:|---|
| Evento único | 424 | Um evento, sozinho, já tem sinal suficiente para chamar o analista. |
| Novidade / raridade | 235 | Compara com o que é normal: entidade, relação ou valor nunca (ou raramente) visto. |
| Mudança de estado | 131 | O risco está na transição: algo era seguro e deixou de ser (desligado, rebaixado, alterado). |
| Sequência ordenada | 82 | Dois ou mais passos da mesma entidade, na ordem certa, dentro de uma janela. |
| Limiar / acúmulo | 77 | O sinal está na repetição: N eventos por chave em uma janela. |
| Fluxo de resposta | 28 | Não detecta: orquestra o que fazer depois do alerta (SOAR). |

### Fontes que mais contribuem

| Fonte | Regras |
|---|---:|
| Microsoft Sentinel (Analytic Rules) | 210 |
| Microsoft Sentinel (Hunting Queries) | 172 |
| Sagan rules (Quadrant) | 124 |
| Elastic detection-rules | 111 |
| Splunk security_content | 80 |
| Bert-JanP Hunting Queries | 63 |
| OpenSearch Security Analytics | 61 |
| Google SecOps / Chronicle | 42 |
| SigmaHQ | 39 |
| awesome-playbooks · ms_azure | 13 |

## 3. Técnicas mais cobertas

| Técnica | Regras nesta tecnologia |
|---|---:|
| [T1078.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.004) Cloud Accounts | 132 |
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | 117 |
| [T1098](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1098) Account Manipulation | 63 |
| [T1110](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1110) Brute Force | 55 |
| [T1550](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1550) Use Alternate Authentication Material | 33 |
| [T1550.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1550.001) Application Access Token | 29 |
| [T1098.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1098.003) Additional Cloud Roles | 28 |
| [T1528](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1528) Steal Application Access Token | 28 |
| [T1556](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1556) Modify Authentication Process | 25 |
| [T1098.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1098.005) Device Registration | 22 |
| [T1087.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1087.004) Cloud Account | 21 |
| [T1566](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1566) Phishing | 21 |

## 4. Detecção pela ausência — o que ninguém está olhando (12 técnicas)

Técnicas do ATT&CK para Identity Provider **sem nenhuma regra nesta tecnologia**, ordenadas pelo número de grupos que as usam. A coluna "regras no catálogo" mostra se existe cobertura em outra tecnologia (ex.: EDR ou rede) que você pode adaptar.

| Técnica | Grupos que usam | Regras no catálogo (todas as tecnologias) |
|---|---:|---:|
| [T1189](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1189) Drive-by Compromise | 31 | 57 |
| [T1036.010](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1036.010) Masquerade Account Name | 4 | 1 |
| [T1059.009](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.009) Cloud API | 4 | 11 |
| [T1078.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.001) Default Accounts | 4 | 16 |
| [T1110.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1110.002) Password Cracking | 4 | 11 |
| [T1649](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1649) Steal or Forge Authentication Certificates | 2 | 43 |
| [T1538](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1538) Cloud Service Dashboard | 1 | 4 |
| [T1566.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1566.004) Spearphishing Voice | 1 | **0** |
| [T1685.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1685.002) Disable or Modify Cloud Log | 1 | 80 |
| [T1697](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1697) Steal Application Specific Passwords | 1 | **0** |
| [T1548.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1548.005) Temporary Elevated Cloud Access | 0 | 8 |
| [T1606.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1606.002) SAML Tokens | 0 | 2 |

## 5. Quem mira esta plataforma

Grupos com mais técnicas registradas nesta plataforma e quantas delas você enxerga com as regras desta tecnologia. País atribuído pelo APT4ALL (afirmação de quem publicou).

| Grupo | Origem atribuída | Técnicas na plataforma | Com regra aqui | Exemplos sem regra |
|---|---|---:|---:|---|
| [APT29](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0016) `G0016` | Rússia | 16 | 13 | T1059.009, T1649, T1685.002 |
| [Scattered Spider](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1015) `G1015` | Sem país atribuído | 13 | 12 | T1538 |
| [Storm-0501](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1053) `G1053` | Sem país atribuído | 10 | 9 | T1059.009 |
| [APT28](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0007) `G0007` | Rússia | 9 | 8 | T1189 |
| [VOID MANTICORE](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1055) `G1055` | Irã | 8 | 8 | — |
| [NIMBUS MANTICORE](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1059) `G1059` | — | 7 | 6 | T1649 |
| [ShinyHunters](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1057) `G1057` | Sem país atribuído | 7 | 6 | T1059.009 |
| [Dragonfly](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0035) `G0035` | Rússia | 6 | 3 | T1036.010, T1110.002, T1189 |
| [LAPSUS$](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1004) `G1004` | Sem país atribuído | 6 | 6 | — |
| [Salt Typhoon](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1045) `G1045` | China | 6 | 5 | T1110.002 |
| [HAFNIUM](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0125) `G0125` | China | 5 | 5 | — |
| [Lazarus Group](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0032) `G0032` | Coreia do Norte | 5 | 4 | T1189 |
| [OilRig](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0049) `G0049` | Irã | 5 | 5 | — |
| [TeamPCP](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1056) `G1056` | Sem país atribuído | 5 | 5 | — |

## 6. Ferramentas de afiliados de ransomware que passam por aqui

Do Ransomware Tool Matrix (via APT4ALL): ferramentas usadas por gangues dentro da rede, nas categorias que esta tecnologia enxerga.

| Ferramenta | Categoria | Gangues que usam | Regras que citam |
|---|---|---:|---:|
| Mimikatz | Roubo de credenciais | 43 | 253 |
| ProcDump | Roubo de credenciais | 11 | 109 |
| LaZagne | Roubo de credenciais | 10 | 30 |
| NirSoft WebBrowserPassView | Roubo de credenciais | 6 | 8 |
| Veeam-Get-Creds | Roubo de credenciais | 5 | 12 |
| NirSoft Dialupass | Roubo de credenciais | 3 | **0** |
| NirSoft IEPassView (iepv) | Roubo de credenciais | 3 | **0** |
| NirSoft MailPassView | Roubo de credenciais | 3 | **0** |
| NirSoft Netpass | Roubo de credenciais | 3 | **0** |
| NirSoft RouterPassView | Roubo de credenciais | 3 | **0** |
| PasswordFox | Roubo de credenciais | 3 | **0** |
| SessionGopher | Roubo de credenciais | 3 | 16 |
| AADInternals | Roubo de credenciais | 2 | 20 |
| DonPAPI | Roubo de credenciais | 2 | **0** |
| GrabFF | Roubo de credenciais | 2 | **0** |
| Invoke-TheHash | Roubo de credenciais | 2 | 1 |
| KeeThief | Roubo de credenciais | 2 | 2 |
| Kerbrute | Roubo de credenciais | 2 | 6 |

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
| [Privilege Role Sign-In Outside Expected Controls](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acf1e5687-84e1-41af-97a9-158094efef53) | Sigma | SigmaHQ | T1078 |
| [Potential MFA Bypass Using Legacy Client Authentication](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A53bb4f7f-48a8-4475-ac30-5a82ddfdf6fc) | Sigma | SigmaHQ | T1078.004, T1110 |
| [Discovery Using AzureHound](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A35b781cc-1a08-4a5a-80af-42fd7c315c6b) | Sigma | SigmaHQ | T1087.004, T1526 |
| [Suspicious SignIns From A Non Registered Device](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A572b12d4-9062-11ed-a1eb-0242ac120002) | Sigma | SigmaHQ | T1078 |
| [Sign-in Failure Due to Conditional Access Requirements Not Met](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab4a6d707-9430-4f5f-af68-0337f52d5c42) | Sigma | SigmaHQ | T1078.004, T1110 |
| [Use of Legacy Authentication Protocols](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A60f6535a-760f-42a9-be3f-c9a0a025906e) | Sigma | SigmaHQ | T1078.004, T1110 |
| [Sign-ins from Non-Compliant Devices](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4f77e1d7-3982-4ee0-8489-abf2d6b75284) | Sigma | SigmaHQ | T1078.004 |
| [Windows LAPS Credential Dump From Entra ID](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aa4b25073-8947-489c-a8dd-93b41c23f26d) | Sigma | SigmaHQ | T1098.005 |
| [M365 or Entra ID Identity Sign-in from a Suspicious Source](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Af0cc239b-67fa-46fc-89d4-f861753a40f5) | Elastic | Elastic detection-rules | T1078 |
| [Entra ID Device with ROADtools Default OS Build (Entity Analytics)](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A10b63b69-9f08-4767-b318-12208f97ad41) | Elastic | Elastic detection-rules | T1098, T1098.005 |
| [Azure Storage Account Deletions by User](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ab2c3d4e5-6f7a-8b9c-0d1e-2f3a4b5c6d7e) | Elastic | Elastic detection-rules | T1485, T1489 |
| [Azure AD Graph Potential Enumeration (ROADrecon)](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A80aa6cca-b343-457b-877e-5877cd71a1f8) | Elastic | Elastic detection-rules | T1069, T1069.003, T1087 |
| [Entra ID Global Administrator Role Assigned](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A04c5a96f-19c5-44fd-9571-a0b033f9086f) | Elastic | Elastic detection-rules | T1098, T1098.003 |
| [Microsoft Entra ID Impossible Travel Sign-in](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Abc9f5144-0ead-476e-ba6e-cef295601195) | Elastic | Elastic detection-rules | T1078, T1078.004, T1528 |
| [Entra ID High Risk Sign-in](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A37994bca-0611-4500-ab67-5588afe73b77) | Elastic | Elastic detection-rules | T1078, T1078.004 |

## 10. Limites

- A tecnologia de cada regra é inferida por heurística sobre metadados e texto (techmap.py). Regras genéricas podem aparecer em várias tecnologias.
- "Sem regra" quer dizer sem regra pública neste catálogo, não sem detecção possível. Telemetria e contexto do seu ambiente decidem.
- Atribuição de país é afirmação das fontes reunidas pelo APT4ALL, não nossa.

---
Fontes: catálogo [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules), MITRE ATT&CK®, APT4ALL, Ransomware Tool Matrix (CC BY 4.0), TCEM, LLmInjection. Gerado em 2026-10-26.
