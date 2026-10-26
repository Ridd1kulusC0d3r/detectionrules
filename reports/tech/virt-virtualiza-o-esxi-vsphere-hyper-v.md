# Virtualização (ESXi/vSphere/Hyper-V) — relatório de regras de detecção

> **TLP:CLEAR** · 2026-10-26 · domínio **Infraestrutura** · plataforma ATT&CK **ESXi** · lente TCEM **Cloud & Multi-Cloud** · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#techno=virt)

## 1. A história em um parágrafo

O palco é **o hipervisor (ESXi/vSphere/Hyper-V) — um único ponto que liga e desliga dezenas de servidores**. O catálogo reúne **346 regras** que olham para cá — 215 de detecção, 27 de hunting, 78 assinaturas e 26 playbooks de resposta. Elas se concentram em **Enfraquecimento de defesas, Furtividade, Execução**. Das 117 técnicas do ATT&CK para a plataforma ESXi, **38 (32%)** têm ao menos uma regra aqui e **79 não têm nenhuma** — é onde um atacante passa sem ser visto. Entre os grupos com mais técnicas nesta plataforma estão Lazarus Group, APT38, APT41.

**Lente TCEM — Cloud & Multi-Cloud.** Cloud control planes, workloads, identities, management APIs, cross-cloud trust and SaaS dependencies. Para observar: cloud audit, identity logs, control-plane changes, workload activity. Arquitetura a mapear: control planes, cloud identities, organization hierarchy, workload identities, management APIs.

## 2. Números

| Indicador | Valor |
|---|---:|
| Regras | 346 |
| detecção | 215 |
| assinatura | 78 |
| hunting | 27 |
| playbook | 26 |
| Técnicas ATT&CK distintas | 62 |
| Cobertura da plataforma ESXi | 38/117 (32%) |

### Por tática

| Tática | Regras |
|---|---:|
| Acesso inicial | 22 |
| Execução | 32 |
| Persistência | 30 |
| Escalação de privilégio | 28 |
| Furtividade | 35 |
| Enfraquecimento de defesas | 36 |
| Acesso a credenciais | 5 |
| Descoberta | 24 |
| Movimento lateral | 8 |
| Coleta | 1 |
| Comando e controle | 1 |
| Impacto | 11 |

### Linguagens disponíveis

Em que formato você encontra regra pronta para esta tecnologia.

| Formato | Regras |
|---|---:|
| Suricata/Snort/Sagan | 78 |
| Sentinel KQL | 63 |
| Wazuh | 58 |
| Sigma | 47 |
| Splunk | 40 |
| Elastic | 34 |
| Playbook | 26 |

### Padrões de correlação (TCEM)

Como as regras decidem. Muitas de evento único = cobertura ampla mas ruidosa; sequências e novidade = mais contexto, mais exigência de dados.

| Padrão | Regras | O que significa |
|---|---:|---|
| Evento único | 220 | Um evento, sozinho, já tem sinal suficiente para chamar o analista. |
| Mudança de estado | 40 | O risco está na transição: algo era seguro e deixou de ser (desligado, rebaixado, alterado). |
| Limiar / acúmulo | 26 | O sinal está na repetição: N eventos por chave em uma janela. |
| Fluxo de resposta | 26 | Não detecta: orquestra o que fazer depois do alerta (SOAR). |
| Novidade / raridade | 24 | Compara com o que é normal: entidade, relação ou valor nunca (ou raramente) visto. |
| Sequência ordenada | 10 | Dois ou mais passos da mesma entidade, na ordem certa, dentro de uma janela. |

### Fontes que mais contribuem

| Fonte | Regras |
|---|---:|
| Sagan rules (Quadrant) | 78 |
| Microsoft Sentinel (Analytic Rules) | 44 |
| Elastic detection-rules | 33 |
| Splunk security_content | 32 |
| SigmaHQ | 31 |
| EVTX-Wazuh-Rules (saifbelaarbi) | 27 |
| Wazuh ruleset (oficial) | 24 |
| Microsoft Sentinel (Hunting Queries) | 19 |
| OpenSearch Security Analytics | 15 |
| Cortex XSOAR (demisto/content) | 9 |

## 3. Técnicas mais cobertas

| Técnica | Regras nesta tecnologia |
|---|---:|
| [T1685](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1685) Disable or Modify Tools | 27 |
| [T1190](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1190) Exploit Public-Facing Application | 13 |
| [T1059](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059) Command and Scripting Interpreter | 12 |
| [T1007](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1007) System Service Discovery | 10 |
| [T1033](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1033) System Owner/User Discovery | 10 |
| [T1059.012](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.012) Hypervisor CLI | 9 |
| [T1574.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1574.001) DLL | 8 |
| [T1564.006](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1564.006) Run Virtual Instance | 7 |
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | 6 |
| [T1098](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1098) Account Manipulation | 5 |
| [T1210](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1210) Exploitation of Remote Services | 5 |
| [T1529](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1529) System Shutdown/Reboot | 4 |

## 4. Detecção pela ausência — o que ninguém está olhando (79 técnicas)

Técnicas do ATT&CK para ESXi **sem nenhuma regra nesta tecnologia**, ordenadas pelo número de grupos que as usam. A coluna "regras no catálogo" mostra se existe cobertura em outra tecnologia (ex.: EDR ou rede) que você pode adaptar.

| Técnica | Grupos que usam | Regras no catálogo (todas as tecnologias) |
|---|---:|---:|
| [T1036.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1036.005) Match Legitimate Resource Name or Location | 66 | 116 |
| [T1071.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1071.001) Web Protocols | 58 | 228 |
| [T1016](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1016) System Network Configuration Discovery | 45 | 114 |
| [T1018](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1018) Remote System Discovery | 43 | 157 |
| [T1140](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1140) Deobfuscate/Decode Files or Information | 38 | 173 |
| [T1049](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1049) System Network Connections Discovery | 33 | 47 |
| [T1074.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1074.001) Local Data Staging | 29 | 37 |
| [T1041](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1041) Exfiltration Over C2 Channel | 28 | 135 |
| [T1567.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1567.002) Exfiltration to Cloud Storage | 25 | 85 |
| [T1078.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.002) Domain Accounts | 21 | 36 |
| [T1090](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1090) Proxy | 20 | 268 |
| [T1570](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1570) Lateral Tool Transfer | 19 | 58 |
| [T1571](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1571) Non-Standard Port | 19 | 163 |
| [T1102.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1102.002) Bidirectional Communication | 16 | 27 |
| [T1102](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1102) Web Service | 15 | 149 |
| [T1124](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1124) System Time Discovery | 15 | 18 |
| [T1572](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1572) Protocol Tunneling | 15 | 173 |
| [T1078.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.003) Local Accounts | 14 | 32 |
| [T1573.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1573.001) Symmetric Cryptography | 14 | 5 |
| [T1090.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1090.003) Multi-hop Proxy | 13 | 44 |

## 5. Quem mira esta plataforma

Grupos com mais técnicas registradas nesta plataforma e quantas delas você enxerga com as regras desta tecnologia. País atribuído pelo APT4ALL (afirmação de quem publicou).

| Grupo | Origem atribuída | Técnicas na plataforma | Com regra aqui | Exemplos sem regra |
|---|---|---:|---:|---|
| [Lazarus Group](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0032) `G0032` | Coreia do Norte | 37 | 14 | T1001.003, T1008, T1016, T1036.005 |
| [APT38](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0082) `G0082` | Coreia do Norte | 32 | 16 | T1036.005, T1041, T1048.002, T1049 |
| [APT41](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0096) `G0096` | China | 30 | 14 | T1008, T1016, T1018, T1030 |
| [Kimsuky](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0094) `G0094` | Coreia do Norte | 29 | 14 | T1016, T1036.005, T1041, T1071.001 |
| [Magic Hound](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0059) `G0059` | Irã | 27 | 11 | T1016, T1016.001, T1018, T1036.005 |
| [Salt Typhoon](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1045) `G1045` | China | 27 | 13 | T1016, T1018, T1048.003, T1070.003 |
| [Volt Typhoon](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1017) `G1017` | China | 27 | 10 | T1016, T1016.001, T1018, T1036.005 |
| [APT28](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0007) `G0007` | Rússia | 26 | 12 | T1001.001, T1030, T1036.005, T1048.002 |
| [Mustang Panda](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0129) `G0129` | China | 26 | 10 | T1001.003, T1016, T1018, T1036.005 |
| [Gamaredon Group](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0047) `G0047` | Rússia | 25 | 8 | T1001, T1016.001, T1036.005, T1041 |
| [Sandworm Team](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0034) `G0034` | Rússia | 25 | 12 | T1018, T1036.005, T1041, T1049 |
| [UNC3886](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1048) `G1048` | China | 25 | 14 | T1008, T1037, T1037.004, T1074.001 |
| [Chimera](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0114) `G0114` | China | 24 | 7 | T1016, T1018, T1036.005, T1041 |
| [MuddyWater](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0069) `G0069` | Irã | 24 | 9 | T1016, T1036.005, T1041, T1049 |

## 6. Ferramentas de afiliados de ransomware que passam por aqui

Do Ransomware Tool Matrix (via APT4ALL): ferramentas usadas por gangues dentro da rede, nas categorias que esta tecnologia enxerga.

| Ferramenta | Categoria | Gangues que usam | Regras que citam |
|---|---|---:|---:|
| AnyDesk | Acesso remoto (RMM) | 32 | 102 |
| Splashtop | Acesso remoto (RMM) | 13 | 19 |
| Atera | Acesso remoto (RMM) | 12 | 40 |
| ScreenConnect | Acesso remoto (RMM) | 12 | 93 |
| GMER | Evasão de defesa | 11 | 11 |
| PCHunter | Evasão de defesa | 9 | 13 |
| PowerTool | Evasão de defesa | 8 | 13 |
| ProcessHacker | Evasão de defesa | 7 | 32 |
| TeamViewer | Acesso remoto (RMM) | 7 | 104 |
| Zemana Anti-Rootkit driver | Evasão de defesa | 4 | **0** |
| LogMeIn | Acesso remoto (RMM) | 4 | 70 |
| MobaXterm | Acesso remoto (RMM) | 4 | 9 |
| NetSupport | Acesso remoto (RMM) | 4 | 49 |
| TightVNC | Acesso remoto (RMM) | 4 | 19 |
| Avast Anti-Rootkit driver | Evasão de defesa | 3 | **0** |
| EDRSandBlast | Evasão de defesa | 3 | 1 |
| MeshAgent | Acesso remoto (RMM) | 3 | 24 |
| N-Able | Acesso remoto (RMM) | 3 | 40 |

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
| [CVE-2022-31656 VMware Workspace ONE Access Auth Bypass](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Afcf1101d-07c9-49b2-ad81-7e421ff96d80) | Sigma | SigmaHQ | T1190 |
| [CVE-2021-21978 Exploitation Attempt](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A77586a7f-7ea4-4c41-b19c-820140b84ca9) | Sigma | SigmaHQ | T1190 |
| [Potential CVE-2021-44228 Exploitation Attempt - VMware Horizon](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A3eb91f0a-0060-424a-a676-59f5fdd75610) | Sigma | SigmaHQ | T1190 |
| [CVE-2021-21972 VSphere Exploitation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A179ed852-0f9b-4009-93a7-68475910fd86) | Sigma | SigmaHQ | T1190 |
| [VMware vCenter Server File Upload CVE-2021-22005](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab014ea07-8ea0-4859-b517-50a4e5b7ecec) | Sigma | SigmaHQ | T1190 |
| [ESXi Admin Permission Assigned To Account Via ESXCLI](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A9691f58d-92c1-4416-8bf3-2edd753ec9cf) | Sigma | SigmaHQ | T1059.012, T1098 |
| [Potential Arbitrary Code Execution Via Node.EXE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A6640f31c-01ad-49b5-beb5-83498a5cd8bd) | Sigma | SigmaHQ | T1127 |
| [VMToolsd Suspicious Child Process](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A5687f942-867b-4578-ade7-1e341c46e99a) | Sigma | SigmaHQ | T1059 |
| [Suspicious Persistence Via VMwareToolBoxCmd.EXE VM State Change Script](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A236d8e89-ed95-4789-a982-36f4643738ba) | Sigma | SigmaHQ | T1059 |
| [DLL Sideloading by VMware Xfer Utility](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aebea773c-a8f1-42ad-a856-00cb221966e8) | Sigma | SigmaHQ | T1574.001 |
| [Potential DLL Sideloading Via VMware Xfer](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A9313dc13-d04c-46d8-af4a-a930cc55d93b) | Sigma | SigmaHQ | T1574.001 |
| [Windows Hypervisor Enforced Code Integrity Disabled](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A8b7273a4-ba5d-4d8a-b04f-11f2900d043a) | Sigma | SigmaHQ | T1685 |
| [Hypervisor Enforced Paging Translation Disabled](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A7f2954d2-99c2-4d42-a065-ca36740f187b) | Sigma | SigmaHQ | T1685 |
| [Suspicious Termination of ESXI Process](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A6641a5af-fb7e-487a-adc4-9e6503365318) | Elastic | Elastic detection-rules | T1489 |
| [ESXi Virtual Machine Snapshot Removed](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ae822bf97-933f-58f9-bd14-47a2ac9cd5d3) | Elastic | Elastic detection-rules | T1490 |

## 10. Limites

- A tecnologia de cada regra é inferida por heurística sobre metadados e texto (techmap.py). Regras genéricas podem aparecer em várias tecnologias.
- "Sem regra" quer dizer sem regra pública neste catálogo, não sem detecção possível. Telemetria e contexto do seu ambiente decidem.
- Atribuição de país é afirmação das fontes reunidas pelo APT4ALL, não nossa.

---
Fontes: catálogo [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules), MITRE ATT&CK®, APT4ALL, Ransomware Tool Matrix (CC BY 4.0), TCEM, LLmInjection. Gerado em 2026-10-26.
