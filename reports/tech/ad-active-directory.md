# Active Directory — relatório de regras de detecção

> **TLP:CLEAR** · 2026-10-26 · domínio **Identidade** · lente TCEM **Identity & Access** · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#techno=ad)

## 1. A história em um parágrafo

O palco é **o Active Directory — o livro de chaves de toda a rede Windows**. O catálogo reúne **1,899 regras** que olham para cá — 1,211 de detecção, 253 de hunting, 334 assinaturas e 101 playbooks de resposta. Elas se concentram em **Acesso a credenciais, Escalação de privilégio, Persistência**. 

**Lente TCEM — Identity & Access.** Authentication, authorization, privilege, federation, machine identity and administrative trust. Para observar: sign-in logs, privilege changes, token events, identity administration. Arquitetura a mapear: identity providers, privileged roles, service principals, federation, recovery access.

## 2. Números

| Indicador | Valor |
|---|---:|
| Regras | 1,899 |
| detecção | 1,211 |
| assinatura | 334 |
| hunting | 253 |
| playbook | 101 |
| Técnicas ATT&CK distintas | 153 |

### Por tática

| Tática | Regras |
|---|---:|
| Reconhecimento | 3 |
| Desenv. de recursos | 8 |
| Acesso inicial | 88 |
| Execução | 44 |
| Persistência | 191 |
| Escalação de privilégio | 228 |
| Furtividade | 104 |
| Enfraquecimento de defesas | 96 |
| Acesso a credenciais | 339 |
| Descoberta | 188 |
| Movimento lateral | 65 |
| Coleta | 41 |
| Comando e controle | 20 |
| Exfiltração | 7 |
| Impacto | 21 |

### Linguagens disponíveis

Em que formato você encontra regra pronta para esta tecnologia.

| Formato | Regras |
|---|---:|
| Sentinel KQL | 522 |
| Suricata/Snort/Sagan | 334 |
| Wazuh | 282 |
| Sigma | 267 |
| Splunk | 211 |
| Playbook | 101 |
| Elastic | 91 |
| KQL hunting | 52 |
| YARA-L | 37 |
| Panther | 1 |
| QRadar AQL | 1 |

### Padrões de correlação (TCEM)

Como as regras decidem. Muitas de evento único = cobertura ampla mas ruidosa; sequências e novidade = mais contexto, mais exigência de dados.

| Padrão | Regras | O que significa |
|---|---:|---|
| Evento único | 1,237 | Um evento, sozinho, já tem sinal suficiente para chamar o analista. |
| Novidade / raridade | 252 | Compara com o que é normal: entidade, relação ou valor nunca (ou raramente) visto. |
| Mudança de estado | 145 | O risco está na transição: algo era seguro e deixou de ser (desligado, rebaixado, alterado). |
| Limiar / acúmulo | 113 | O sinal está na repetição: N eventos por chave em uma janela. |
| Fluxo de resposta | 101 | Não detecta: orquestra o que fazer depois do alerta (SOAR). |
| Sequência ordenada | 49 | Dois ou mais passos da mesma entidade, na ordem certa, dentro de uma janela. |
| Assinatura de conteúdo | 2 | Casa bytes/strings dentro de arquivo, memória ou pacote, não eventos de log. |

### Fontes que mais contribuem

| Fonte | Regras |
|---|---:|
| Microsoft Sentinel (Analytic Rules) | 348 |
| Sagan rules (Quadrant) | 331 |
| EVTX-Wazuh-Rules (saifbelaarbi) | 242 |
| Splunk security_content | 186 |
| Microsoft Sentinel (Hunting Queries) | 174 |
| SigmaHQ | 156 |
| OpenSearch Security Analytics | 101 |
| Elastic detection-rules | 62 |
| Bert-JanP Hunting Queries | 52 |
| Cortex XSOAR (demisto/content) | 31 |

## 3. Técnicas mais cobertas

| Técnica | Regras nesta tecnologia |
|---|---:|
| [T1087.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1087.002) Domain Account | 91 |
| [T1003.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1003.003) NTDS | 80 |
| [T1482](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1482) Domain Trust Discovery | 68 |
| [T1558.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1558.003) Kerberoasting | 60 |
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | 53 |
| [T1098](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1098) Account Manipulation | 50 |
| [T1069.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1069.002) Domain Groups | 44 |
| [T1087](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1087) Account Discovery | 39 |
| [T1558](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1558) Steal or Forge Kerberos Tickets | 37 |
| [T1003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1003) OS Credential Dumping | 36 |
| [T1087.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1087.001) Local Account | 32 |
| [T1484.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1484.001) Group Policy Modification | 32 |

## 6. Ferramentas de afiliados de ransomware que passam por aqui

Do Ransomware Tool Matrix (via APT4ALL): ferramentas usadas por gangues dentro da rede, nas categorias que esta tecnologia enxerga.

| Ferramenta | Categoria | Gangues que usam | Regras que citam |
|---|---|---:|---:|
| Mimikatz | Roubo de credenciais | 43 | 253 |
| SoftPerfect NetScan | Descoberta | 31 | 10 |
| Advanced IP Scanner | Descoberta | 24 | 22 |
| AdFind | Descoberta | 21 | 68 |
| Advanced Port Scanner | Descoberta | 14 | 16 |
| ProcDump | Roubo de credenciais | 11 | 109 |
| Bloodhound | Descoberta | 10 | 181 |
| LaZagne | Roubo de credenciais | 10 | 30 |
| PowerView | Descoberta | 7 | 74 |
| ADRecon | Descoberta | 6 | 32 |
| SharpShares | Descoberta | 6 | 3 |
| NirSoft WebBrowserPassView | Roubo de credenciais | 6 | 8 |
| Nmap | Descoberta | 5 | 78 |
| ShareFinder | Descoberta | 5 | 18 |
| Veeam-Get-Creds | Roubo de credenciais | 5 | 12 |
| Everything.exe | Descoberta | 4 | 6 |
| PingCastle | Descoberta | 4 | 66 |
| S3 Browser | Descoberta | 3 | 10 |

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
| [Password Change on Directory Service Restore Mode (DSRM) Account](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A53ad8e36-f573-46bf-97e4-15ba5bf4bb51) | Sigma | SigmaHQ | T1098 |
| [User Added To Global Domain Admins Grp](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=hayabusa-native%3A%3A4bb89c86-a138-42a0-baaf-fc2f777a4506) | Sigma | Hayabusa (native) | T1098 |
| [User Added To Local Domain Admins Grp](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=hayabusa-native%3A%3Abc58e432-959f-464d-812e-d60ce5d46fa1) | Sigma | Hayabusa (native) | T1098 |
| [New RDP Connection Initiated From Domain Controller](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Afda34293-718e-4b36-b018-38caab0d1209) | Sigma | SigmaHQ | T1021 |
| [Conti NTDS Exfiltration Command](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aaa92fd02-09f2-48b0-8a93-864813fb8f41) | Sigma | SigmaHQ | T1560 |
| [Suspicious Computer Account Name Change CVE-2021-42287](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A45eb2ae2-9aa2-4c3a-99a5-6e5077655466) | Sigma | SigmaHQ | T1036, T1098 |
| [Potential JNDI Injection Exploitation In JVM Based Application](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Abb0e9cec-d4da-46f5-997f-22efc59f3dca) | Sigma | SigmaHQ | T1190 |
| [SharpHound Recon Sessions](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A6d580420-ff3f-4e0e-b6b0-41b90c787e28) | Sigma | SigmaHQ | T1033 |
| [NTDS Exfiltration Filename Patterns](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A3a8da4e0-36c1-40d2-8b29-b3e890d5172a) | Sigma | SigmaHQ | T1003.003 |
| [NTDS.DIT Creation By Uncommon Process](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A11b1ed55-154d-4e82-8ad7-83739298f720) | Sigma | SigmaHQ | T1003.002, T1003.003 |
| [NTDS.DIT Creation By Uncommon Parent Process](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4e7050dd-e548-483f-b7d6-527ab4fa784d) | Sigma | SigmaHQ | T1003.003 |
| [BloodHound Collection Files](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A02773bed-83bf-469f-b7ff-e676e7d78bab) | Sigma | SigmaHQ | T1059.001, T1069.001, T1069.002 |
| [HackTool - ADCSPwn Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acd8c163e-a19b-402e-bdd5-419ff5859f12) | Sigma | SigmaHQ | T1557.001 |
| [HackTool - KrbRelayUp Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A12827a56-61a4-476a-a9cb-f3068f191073) | Sigma | SigmaHQ | T1550.003, T1558.003 |
| [HackTool - Certipy Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A6938366d-8954-4ddc-baff-c830b3ba8fcd) | Sigma | SigmaHQ | T1649 |

## 10. Limites

- A tecnologia de cada regra é inferida por heurística sobre metadados e texto (techmap.py). Regras genéricas podem aparecer em várias tecnologias.
- "Sem regra" quer dizer sem regra pública neste catálogo, não sem detecção possível. Telemetria e contexto do seu ambiente decidem.
- Atribuição de país é afirmação das fontes reunidas pelo APT4ALL, não nossa.

---
Fontes: catálogo [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules), MITRE ATT&CK®, APT4ALL, Ransomware Tool Matrix (CC BY 4.0), TCEM, LLmInjection. Gerado em 2026-10-26.
