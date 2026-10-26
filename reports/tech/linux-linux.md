# Linux — relatório de regras de detecção

> **TLP:CLEAR** · 2026-10-26 · domínio **Endpoint** · plataforma ATT&CK **Linux** · lente TCEM **Detection & Validation** · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#techno=linux)

## 1. A história em um parágrafo

O palco é **servidores Linux — onde roda o que a empresa vende: aplicações, bancos, contêineres**. O catálogo reúne **2,739 regras** que olham para cá — 2,152 de detecção, 95 de hunting, 422 assinaturas e 70 playbooks de resposta. Elas se concentram em **Execução, Escalação de privilégio, Furtividade**. Das 356 técnicas do ATT&CK para a plataforma Linux, **222 (62%)** têm ao menos uma regra aqui e **134 não têm nenhuma** — é onde um atacante passa sem ser visto. Entre os grupos com mais técnicas nesta plataforma estão Kimsuky, APT38, Lazarus Group.

**Lente TCEM — Detection & Validation.** Threat-informed telemetry, analytics, validation, retest and analyst-response context. Para observar: sensor health, event quality, normalization, correlation, alert disposition. Arquitetura a mapear: sensors, collection pipelines, SIEM, EDR, correlation, case management.

## 2. Números

| Indicador | Valor |
|---|---:|
| Regras | 2,739 |
| detecção | 2,152 |
| assinatura | 422 |
| hunting | 95 |
| playbook | 70 |
| Técnicas ATT&CK distintas | 286 |
| Cobertura da plataforma Linux | 222/356 (62%) |

### Por tática

| Tática | Regras |
|---|---:|
| Reconhecimento | 15 |
| Desenv. de recursos | 10 |
| Acesso inicial | 146 |
| Execução | 584 |
| Persistência | 396 |
| Escalação de privilégio | 509 |
| Furtividade | 445 |
| Enfraquecimento de defesas | 140 |
| Acesso a credenciais | 179 |
| Descoberta | 195 |
| Movimento lateral | 110 |
| Coleta | 77 |
| Comando e controle | 246 |
| Exfiltração | 42 |
| Impacto | 77 |

### Linguagens disponíveis

Em que formato você encontra regra pronta para esta tecnologia.

| Formato | Regras |
|---|---:|
| Elastic | 894 |
| Sigma | 478 |
| Wazuh | 438 |
| Suricata/Snort/Sagan | 422 |
| Splunk | 243 |
| Falco | 96 |
| Playbook | 70 |
| Sentinel KQL | 47 |
| Panther | 27 |
| YARA-L | 16 |
| KQL hunting | 4 |
| QRadar AQL | 4 |

### Padrões de correlação (TCEM)

Como as regras decidem. Muitas de evento único = cobertura ampla mas ruidosa; sequências e novidade = mais contexto, mais exigência de dados.

| Padrão | Regras | O que significa |
|---|---:|---|
| Evento único | 1,617 | Um evento, sozinho, já tem sinal suficiente para chamar o analista. |
| Novidade / raridade | 594 | Compara com o que é normal: entidade, relação ou valor nunca (ou raramente) visto. |
| Sequência ordenada | 206 | Dois ou mais passos da mesma entidade, na ordem certa, dentro de uma janela. |
| Limiar / acúmulo | 194 | O sinal está na repetição: N eventos por chave em uma janela. |
| Fluxo de resposta | 70 | Não detecta: orquestra o que fazer depois do alerta (SOAR). |
| Mudança de estado | 56 | O risco está na transição: algo era seguro e deixou de ser (desligado, rebaixado, alterado). |
| Assinatura de conteúdo | 2 | Casa bytes/strings dentro de arquivo, memória ou pacote, não eventos de log. |

### Fontes que mais contribuem

| Fonte | Regras |
|---|---:|
| Elastic detection-rules | 564 |
| Sagan rules (Quadrant) | 420 |
| Elastic protections-artifacts (behavior) | 286 |
| SigmaHQ | 285 |
| Splunk security_content | 225 |
| OpenSearch Security Analytics | 193 |
| Wazuh ruleset (oficial) | 185 |
| SOCFortress Wazuh-Rules | 179 |
| Falco rules | 96 |
| Elastic hunting queries | 44 |

## 3. Técnicas mais cobertas

| Técnica | Regras nesta tecnologia |
|---|---:|
| [T1059](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059) Command and Scripting Interpreter | 325 |
| [T1059.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.004) Unix Shell | 275 |
| [T1071](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1071) Application Layer Protocol | 120 |
| [T1068](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1068) Exploitation for Privilege Escalation | 92 |
| [T1548](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1548) Abuse Elevation Control Mechanism | 68 |
| [T1543](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1543) Create or Modify System Process | 66 |
| [T1685](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1685) Disable or Modify Tools | 62 |
| [T1574](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1574) Hijack Execution Flow | 62 |
| [T1190](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1190) Exploit Public-Facing Application | 56 |
| [T1082](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1082) System Information Discovery | 56 |
| [T1021](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1021) Remote Services | 49 |
| [T1021.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1021.004) SSH | 49 |

## 4. Detecção pela ausência — o que ninguém está olhando (134 técnicas)

Técnicas do ATT&CK para Linux **sem nenhuma regra nesta tecnologia**, ordenadas pelo número de grupos que as usam. A coluna "regras no catálogo" mostra se existe cobertura em outra tecnologia (ex.: EDR ou rede) que você pode adaptar.

| Técnica | Grupos que usam | Regras no catálogo (todas as tecnologias) |
|---|---:|---:|
| [T1189](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1189) Drive-by Compromise | 31 | 57 |
| [T1087.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1087.002) Domain Account | 30 | 180 |
| [T1555.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1555.003) Credentials from Web Browsers | 24 | 59 |
| [T1564.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1564.003) Hidden Window | 19 | 51 |
| [T1657](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1657) Financial Theft | 19 | 2 |
| [T1684.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1684.001) Impersonation | 18 | 1 |
| [T1124](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1124) System Time Discovery | 15 | 18 |
| [T1566.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1566.003) Spearphishing via Service | 15 | 8 |
| [T1199](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1199) Trusted Relationship | 14 | 18 |
| [T1573.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1573.001) Symmetric Cryptography | 14 | 5 |
| [T1016.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1016.001) Internet Connection Discovery | 11 | 14 |
| [T1074.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1074.002) Remote Data Staging | 11 | 5 |
| [T1680](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1680) Local Storage Discovery | 10 | **0** |
| [T1039](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1039) Data from Network Shared Drive | 9 | 24 |
| [T1120](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1120) Peripheral Device Discovery | 9 | 11 |
| [T1539](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1539) Steal Web Session Cookie | 8 | 54 |
| [T1027.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1027.005) Indicator Removal from Tools | 7 | 24 |
| [T1027.016](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1027.016) Junk Code Insertion | 7 | **0** |
| [T1217](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1217) Browser Information Discovery | 7 | 19 |
| [T1534](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1534) Internal Spearphishing | 7 | 5 |

## 5. Quem mira esta plataforma

Grupos com mais técnicas registradas nesta plataforma e quantas delas você enxerga com as regras desta tecnologia. País atribuído pelo APT4ALL (afirmação de quem publicou).

| Grupo | Origem atribuída | Técnicas na plataforma | Com regra aqui | Exemplos sem regra |
|---|---|---:|---:|---|
| [Kimsuky](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0094) `G0094` | Coreia do Norte | 83 | 62 | T1027.016, T1056.003, T1071.002, T1071.003 |
| [APT38](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0082) `G0082` | Coreia do Norte | 82 | 62 | T1027.016, T1048.002, T1124, T1189 |
| [Lazarus Group](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0032) `G0032` | Coreia do Norte | 63 | 49 | T1001.003, T1010, T1027.009, T1104 |
| [APT28](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0007) `G0007` | Rússia | 58 | 44 | T1001.001, T1025, T1039, T1048.002 |
| [Mustang Panda](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0129) `G0129` | China | 56 | 46 | T1001.003, T1027.016, T1052.001, T1087.002 |
| [OilRig](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0049) `G0049` | Irã | 55 | 48 | T1003.005, T1025, T1027.005, T1087.002 |
| [APT41](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0096) `G0096` | China | 54 | 48 | T1071.002, T1087.002, T1104, T1480.001 |
| [Volt Typhoon](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1017) `G1017` | China | 54 | 43 | T1010, T1016.001, T1070.007, T1087.002 |
| [Gamaredon Group](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0047) `G0047` | Rússia | 51 | 38 | T1016.001, T1025, T1027.016, T1039 |
| [Sandworm Team](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0034) `G0034` | Rússia | 51 | 44 | T1087.002, T1199, T1213.006, T1491.002 |
| [MuddyWater](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0069) `G0069` | Irã | 49 | 42 | T1003.005, T1087.002, T1104, T1534 |
| [APT32](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0050) `G0050` | Vietnã | 48 | 44 | T1027.016, T1071.003, T1189, T1564.003 |
| [Magic Hound](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0059) `G0059` | Irã | 48 | 40 | T1016.001, T1016.002, T1036.010, T1078.001 |
| [Turla](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0010) `G0010` | Rússia | 48 | 38 | T1016.001, T1025, T1027.005, T1071.003 |

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
| [Linux Crypto Mining Pool Connections](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Aa46c93b7-55ed-4d27-a41b-c259456c4746) | Sigma | OpenSearch Security Analytics | T1496 |
| [Relevant ClamAV Message](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A36aa86ca-fd9d-4456-814e-d3b1b8e1e0bb) | Sigma | SigmaHQ | T1588.001 |
| [Process Discovery](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4e2f5868-08d4-413d-899f-dc2f1508627b) | Sigma | SigmaHQ | T1057 |
| [Sudo Privilege Escalation CVE-2019-14287](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Af74107df-b6c6-4e80-bf00-4170b658162b) | Sigma | SigmaHQ | T1068, T1548.003 |
| [Sudo Privilege Escalation CVE-2019-14287 - Builtin](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A7fcc54cb-f27d-4684-84b7-436af096f858) | Sigma | SigmaHQ | T1068, T1548.003 |
| [UNC4841 - SSL Certificate Exfiltration Via Openssl](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A60911c07-f989-4362-84af-c609828ef829) | Sigma | SigmaHQ | T1140 |
| [UNC4841 - Download Compressed Files From Temp.sh Using Wget](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A60d050c4-e253-4d9a-b673-5ac100cfddfb) | Sigma | SigmaHQ | T1140 |
| [UNC4841 - Download Tar File From Untrusted Direct IP Via Wget](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A23835beb-ec38-4e74-a5d4-b99af6684e91) | Sigma | SigmaHQ | T1140 |
| [CVE-2023-22518 Exploitation Attempt - Suspicious Confluence Child Process (Linux)](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Af8987c03-4290-4c96-870f-55e75ee377f4) | Sigma | SigmaHQ | T1059, T1190 |
| [Potential Centos Web Panel Exploitation Attempt - CVE-2022-44877](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1b2eeb27-949b-4704-8bfa-d8e5cfa045a1) | Sigma | SigmaHQ | T1190 |
| [Apache Spark Shell Command Injection - ProcessCreation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac8a5f584-cdc8-42cc-8cce-0398e4265de3) | Sigma | SigmaHQ | T1190 |
| [Potential Nimbuspwn Exploit CVE-2022-29799 and CVE-2022-27800](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A7ba05b43-adad-4c02-b5e9-c8c35cdf9fa8) | Sigma | SigmaHQ | T1068 |
| [Atlassian Confluence CVE-2022-26134](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A7fb14105-530e-4e2e-8cfb-99f7d8700b66) | Sigma | SigmaHQ | T1059, T1190 |
| [PwnKit Local Privilege Escalation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A0506a799-698b-43b4-85a1-ac4c84c720e9) | Sigma | SigmaHQ | T1548.001 |
| [Suspicious Java Children Processes](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad292e0af-9a18-420c-9525-ec0ac3936892) | Sigma | SigmaHQ | T1059 |

## 10. Limites

- A tecnologia de cada regra é inferida por heurística sobre metadados e texto (techmap.py). Regras genéricas podem aparecer em várias tecnologias.
- "Sem regra" quer dizer sem regra pública neste catálogo, não sem detecção possível. Telemetria e contexto do seu ambiente decidem.
- Atribuição de país é afirmação das fontes reunidas pelo APT4ALL, não nossa.

---
Fontes: catálogo [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules), MITRE ATT&CK®, APT4ALL, Ransomware Tool Matrix (CC BY 4.0), TCEM, LLmInjection. Gerado em 2026-10-26.
