# Firewall & perímetro — relatório de regras de detecção

> **TLP:CLEAR** · 2026-10-26 · domínio **Rede** · plataforma ATT&CK **Network Devices** · lente TCEM **Web & API** · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#techno=firewall)

## 1. A história em um parágrafo

O palco é **o perímetro — firewalls que decidem o que entra e o que sai**. O catálogo reúne **3,093 regras** que olham para cá — 765 de detecção, 99 de hunting, 1,675 assinaturas e 554 playbooks de resposta. Elas se concentram em **Enfraquecimento de defesas, Comando e controle, Acesso inicial**. Das 100 técnicas do ATT&CK para a plataforma Network Devices, **50 (50%)** têm ao menos uma regra aqui e **50 não têm nenhuma** — é onde um atacante passa sem ser visto. Entre os grupos com mais técnicas nesta plataforma estão Salt Typhoon, Lazarus Group, APT41.

**Lente TCEM — Web & API.** Internet-facing applications, APIs, service trust, sessions, application data and runtime behavior. Para observar: application logs, gateway logs, WAF, authentication, API audit. Arquitetura a mapear: public endpoints, API gateways, sessions, service identities, backend trust.

## 2. Números

| Indicador | Valor |
|---|---:|
| Regras | 3,093 |
| assinatura | 1,675 |
| detecção | 765 |
| playbook | 554 |
| hunting | 99 |
| Técnicas ATT&CK distintas | 143 |
| Cobertura da plataforma Network Devices | 50/100 (50%) |

### Por tática

| Tática | Regras |
|---|---:|
| Reconhecimento | 16 |
| Desenv. de recursos | 4 |
| Acesso inicial | 116 |
| Execução | 79 |
| Persistência | 107 |
| Escalação de privilégio | 58 |
| Furtividade | 53 |
| Enfraquecimento de defesas | 160 |
| Acesso a credenciais | 39 |
| Descoberta | 49 |
| Movimento lateral | 21 |
| Coleta | 22 |
| Comando e controle | 123 |
| Exfiltração | 32 |
| Impacto | 29 |

### Linguagens disponíveis

Em que formato você encontra regra pronta para esta tecnologia.

| Formato | Regras |
|---|---:|
| Suricata/Snort/Sagan | 1,675 |
| Playbook | 554 |
| Wazuh | 317 |
| Sentinel KQL | 199 |
| Sigma | 133 |
| Splunk | 102 |
| Elastic | 71 |
| YARA-L | 20 |
| Panther | 11 |
| GCP | 7 |
| KQL hunting | 2 |
| QRadar AQL | 2 |

### Padrões de correlação (TCEM)

Como as regras decidem. Muitas de evento único = cobertura ampla mas ruidosa; sequências e novidade = mais contexto, mais exigência de dados.

| Padrão | Regras | O que significa |
|---|---:|---|
| Evento único | 1,985 | Um evento, sozinho, já tem sinal suficiente para chamar o analista. |
| Fluxo de resposta | 554 | Não detecta: orquestra o que fazer depois do alerta (SOAR). |
| Limiar / acúmulo | 259 | O sinal está na repetição: N eventos por chave em uma janela. |
| Novidade / raridade | 181 | Compara com o que é normal: entidade, relação ou valor nunca (ou raramente) visto. |
| Mudança de estado | 87 | O risco está na transição: algo era seguro e deixou de ser (desligado, rebaixado, alterado). |
| Sequência ordenada | 27 | Dois ou mais passos da mesma entidade, na ordem certa, dentro de uma janela. |

### Fontes que mais contribuem

| Fonte | Regras |
|---|---:|
| Sagan rules (Quadrant) | 1,673 |
| Wazuh ruleset (oficial) | 245 |
| Cortex XSOAR (demisto/content) | 228 |
| awesome-playbooks · fortinet | 193 |
| Microsoft Sentinel (Analytic Rules) | 132 |
| Splunk security_content | 83 |
| SigmaHQ | 76 |
| awesome-playbooks · ms_azure | 72 |
| Microsoft Sentinel (Hunting Queries) | 67 |
| Elastic detection-rules | 64 |

## 3. Técnicas mais cobertas

| Técnica | Regras nesta tecnologia |
|---|---:|
| [T1071](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1071) Application Layer Protocol | 61 |
| [T1686.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1686.003) Windows Host Firewall | 60 |
| [T1685](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1685) Disable or Modify Tools | 50 |
| [T1190](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1190) Exploit Public-Facing Application | 46 |
| [T1133](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1133) External Remote Services | 45 |
| [T1686](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1686) Disable or Modify System Firewall | 43 |
| [T1059](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059) Command and Scripting Interpreter | 28 |
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | 27 |
| [T1204](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1204) User Execution | 25 |
| [T1071.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1071.001) Web Protocols | 24 |
| [T1046](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1046) Network Service Discovery | 23 |
| [T1110](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1110) Brute Force | 19 |

## 4. Detecção pela ausência — o que ninguém está olhando (50 técnicas)

Técnicas do ATT&CK para Network Devices **sem nenhuma regra nesta tecnologia**, ordenadas pelo número de grupos que as usam. A coluna "regras no catálogo" mostra se existe cobertura em outra tecnologia (ex.: EDR ou rede) que você pode adaptar.

| Técnica | Grupos que usam | Regras no catálogo (todas as tecnologias) |
|---|---:|---:|
| [T1049](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1049) System Network Connections Discovery | 33 | 47 |
| [T1056.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1056.001) Keylogging | 26 | 40 |
| [T1124](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1124) System Time Discovery | 15 | 18 |
| [T1573.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1573.001) Symmetric Cryptography | 14 | 5 |
| [T1090.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1090.003) Multi-hop Proxy | 13 | 44 |
| [T1070.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1070.003) Clear Command History | 10 | 63 |
| [T1090.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1090.001) Internal Proxy | 9 | 43 |
| [T1040](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1040) Network Sniffing | 8 | 77 |
| [T1552.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1552.004) Private Keys | 8 | 60 |
| [T1020](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1020) Automated Exfiltration | 7 | 69 |
| [T1071.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1071.002) File Transfer Protocols | 6 | 3 |
| [T1561.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1561.002) Disk Structure Wipe | 6 | 2 |
| [T1037](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1037) Boot or Logon Initialization Scripts | 4 | 91 |
| [T1070.007](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1070.007) Clear Network Connection History and Configurations | 4 | **0** |
| [T1078.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.001) Default Accounts | 4 | 16 |
| [T1110.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1110.002) Password Cracking | 4 | 11 |
| [T1529](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1529) System Shutdown/Reboot | 4 | 52 |
| [T1690](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1690) Prevent Command History Logging | 4 | 12 |
| [T1037.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1037.004) RC Scripts | 3 | 13 |
| [T1056](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1056) Input Capture | 3 | 112 |

## 5. Quem mira esta plataforma

Grupos com mais técnicas registradas nesta plataforma e quantas delas você enxerga com as regras desta tecnologia. País atribuído pelo APT4ALL (afirmação de quem publicou).

| Grupo | Origem atribuída | Técnicas na plataforma | Com regra aqui | Exemplos sem regra |
|---|---|---:|---:|---|
| [Salt Typhoon](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1045) `G1045` | China | 33 | 22 | T1020.001, T1040, T1059.008, T1070.003 |
| [Lazarus Group](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0032) `G0032` | Coreia do Norte | 25 | 16 | T1049, T1056.001, T1070.003, T1090.001 |
| [APT41](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0096) `G0096` | China | 24 | 18 | T1037, T1049, T1056.001, T1070.003 |
| [Kimsuky](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0094) `G0094` | Coreia do Norte | 24 | 17 | T1020, T1040, T1056.001, T1071.002 |
| [Volt Typhoon](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1017) `G1017` | China | 23 | 14 | T1006, T1049, T1056.001, T1070.007 |
| [APT38](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0082) `G0082` | Coreia do Norte | 22 | 14 | T1049, T1056.001, T1070.003, T1124 |
| [Magic Hound](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0059) `G0059` | Irã | 21 | 17 | T1049, T1056.001, T1070.003, T1078.001 |
| [Medusa Group](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1051) `G1051` | Sem país atribuído | 21 | 17 | T1070.003, T1090.003, T1529, T1690 |
| [APT28](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0007) `G0007` | Rússia | 19 | 13 | T1040, T1056.001, T1090.003, T1557.004 |
| [Mustang Panda](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0129) `G0129` | China | 19 | 16 | T1049, T1205, T1573.001 |
| [APT39](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0087) `G0087` | Irã | 18 | 15 | T1056, T1056.001, T1090.001 |
| [OilRig](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0049) `G0049` | Irã | 18 | 15 | T1049, T1056.001, T1201 |
| [Sandworm Team](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0034) `G0034` | Rússia | 18 | 14 | T1040, T1049, T1056.001, T1561.002 |
| [Ke3chang](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0004) `G0004` | China | 17 | 14 | T1020, T1049, T1056.001 |

## 6. Ferramentas de afiliados de ransomware que passam por aqui

Do Ransomware Tool Matrix (via APT4ALL): ferramentas usadas por gangues dentro da rede, nas categorias que esta tecnologia enxerga.

| Ferramenta | Categoria | Gangues que usam | Regras que citam |
|---|---|---:|---:|
| Chisel | Túneis e rede | 8 | 10 |
| Cloudflared | Túneis e rede | 7 | 45 |
| OpenSSH | Túneis e rede | 7 | 130 |
| Ngrok | Túneis e rede | 6 | 51 |
| Plink | Túneis e rede | 6 | 26 |
| Ligolo | Túneis e rede | 5 | 1 |
| Proxychains | Túneis e rede | 4 | 9 |
| PuTTY | Túneis e rede | 3 | 23 |
| Catbox[.]moe | Túneis e rede | 2 | 2 |
| Proxifier | Túneis e rede | 2 | **0** |
| Amnezia VPN | Túneis e rede | 1 | **0** |
| Azure Blog Storage | Túneis e rede | 1 | **0** |
| FRP | Túneis e rede | 1 | 13 |
| GOST | Túneis e rede | 1 | 2 |
| IOX | Túneis e rede | 1 | 11 |
| Klink | Túneis e rede | 1 | **0** |
| MinIO | Túneis e rede | 1 | 1 |
| NPS | Túneis e rede | 1 | 18 |

## 9. Regras recomendadas para começar

Ranqueadas por portabilidade do formato, maturidade, severidade e por mapearem técnica ATT&CK.

| Regra | Formato | Fonte | Técnicas |
|---|---|---|---|
| [Fortinet CVE-2018-13379 Exploitation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aa2e97350-4285-43f2-a63f-d0daff291738) | Sigma | SigmaHQ | T1190 |
| [Equation Group C2 Communication](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A881834a4-6659-4773-821e-1c151789d873) | Sigma | SigmaHQ | T1041 |
| [Fortinet CVE-2021-22123 Exploitation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Af425637f-891c-4191-a6c4-3bb1b70513b4) | Sigma | SigmaHQ | T1190 |
| [Disable System Firewall](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A53059bc0-1472-438b-956a-7508a94a91f0) | Sigma | SigmaHQ | T1686 |
| [Remote DCOM/WMI Lateral Movement](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A68050b10-e477-4377-a99b-3721b422d6ef) | Sigma | SigmaHQ | T1021.003, T1047 |
| [Remote Schedule Task Lateral Movement via ATSvc](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A0fcd1c79-4eeb-4746-aba9-1b458f7a79cb) | Sigma | SigmaHQ | T1053, T1053.002 |
| [Remote Schedule Task Lateral Movement via SASec](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aaff229ab-f8cd-447b-b215-084d11e79eb0) | Sigma | SigmaHQ | T1053, T1053.002 |
| [Remote Server Service Abuse for Lateral Movement](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A10018e73-06ec-46ec-8107-9172f1e04ff2) | Sigma | SigmaHQ | T1569.002 |
| [Remote Schedule Task Lateral Movement via ITaskSchedulerService](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aace3ff54-e7fd-46bd-8ea0-74b49a0aca1d) | Sigma | SigmaHQ | T1053, T1053.002 |
| [SharpHound Recon Sessions](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A6d580420-ff3f-4e0e-b6b0-41b90c787e28) | Sigma | SigmaHQ | T1033 |
| [Remote Registry Lateral Movement](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A35c55673-84ca-4e99-8d09-e334f3c29539) | Sigma | SigmaHQ | T1112 |
| [Suspicious Program Location Whitelisted In Firewall Via Netsh.EXE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aa35f5a72-f347-4e36-8895-9869b0d5fc6d) | Sigma | SigmaHQ | T1686.003 |
| [PUA - Fast Reverse Proxy (FRP) Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A32410e29-5f94-4568-b6a3-d91a8adad863) | Sigma | SigmaHQ | T1090 |
| [New Firewall Rule Added In Windows Firewall Exception List For Potential Suspicious Application](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A9e2575e7-2cb9-4da1-adc8-ed94221dca5e) | Sigma | SigmaHQ | T1686.003 |
| [All Rules Have Been Deleted From The Windows Firewall Configuration](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A79609c82-a488-426e-abcf-9f341a39365d) | Sigma | SigmaHQ | T1686.003 |

## 10. Limites

- A tecnologia de cada regra é inferida por heurística sobre metadados e texto (techmap.py). Regras genéricas podem aparecer em várias tecnologias.
- "Sem regra" quer dizer sem regra pública neste catálogo, não sem detecção possível. Telemetria e contexto do seu ambiente decidem.
- Atribuição de país é afirmação das fontes reunidas pelo APT4ALL, não nossa.

---
Fontes: catálogo [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules), MITRE ATT&CK®, APT4ALL, Ransomware Tool Matrix (CC BY 4.0), TCEM, LLmInjection. Gerado em 2026-10-26.
