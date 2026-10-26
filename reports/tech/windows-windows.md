# Windows — relatório de regras de detecção

> **TLP:CLEAR** · 2026-10-26 · domínio **Endpoint** · plataforma ATT&CK **Windows** · lente TCEM **Detection & Validation** · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#techno=windows)

## 1. A história em um parágrafo

O palco é **estações e servidores Windows — onde as pessoas trabalham e onde credenciais vivem na memória**. O catálogo reúne **28,043 regras** que olham para cá — 22,035 de detecção, 481 de hunting, 5,443 assinaturas e 84 playbooks de resposta. Elas se concentram em **Furtividade, Escalação de privilégio, Persistência**. Das 479 técnicas do ATT&CK para a plataforma Windows, **382 (80%)** têm ao menos uma regra aqui e **97 não têm nenhuma** — é onde um atacante passa sem ser visto. Entre os grupos com mais técnicas nesta plataforma estão Kimsuky, APT38, Lazarus Group.

**Lente TCEM — Detection & Validation.** Threat-informed telemetry, analytics, validation, retest and analyst-response context. Para observar: sensor health, event quality, normalization, correlation, alert disposition. Arquitetura a mapear: sensors, collection pipelines, SIEM, EDR, correlation, case management.

## 2. Números

| Indicador | Valor |
|---|---:|
| Regras | 28,043 |
| detecção | 22,035 |
| assinatura | 5,443 |
| hunting | 481 |
| playbook | 84 |
| Técnicas ATT&CK distintas | 440 |
| Cobertura da plataforma Windows | 382/479 (80%) |

### Por tática

| Tática | Regras |
|---|---:|
| Reconhecimento | 82 |
| Desenv. de recursos | 120 |
| Acesso inicial | 655 |
| Execução | 4,322 |
| Persistência | 4,622 |
| Escalação de privilégio | 4,831 |
| Furtividade | 5,016 |
| Enfraquecimento de defesas | 1,955 |
| Acesso a credenciais | 1,955 |
| Descoberta | 1,269 |
| Movimento lateral | 868 |
| Coleta | 511 |
| Comando e controle | 1,290 |
| Exfiltração | 237 |
| Impacto | 458 |

### Linguagens disponíveis

Em que formato você encontra regra pronta para esta tecnologia.

| Formato | Regras |
|---|---:|
| Wazuh | 12,665 |
| Suricata/Snort/Sagan | 5,443 |
| Sigma | 5,356 |
| Elastic | 1,508 |
| Splunk | 1,395 |
| YARA-L | 1,058 |
| Sentinel KQL | 473 |
| Playbook | 84 |
| KQL hunting | 31 |
| QRadar AQL | 20 |
| Panther | 10 |

### Padrões de correlação (TCEM)

Como as regras decidem. Muitas de evento único = cobertura ampla mas ruidosa; sequências e novidade = mais contexto, mais exigência de dados.

| Padrão | Regras | O que significa |
|---|---:|---|
| Evento único | 22,620 | Um evento, sozinho, já tem sinal suficiente para chamar o analista. |
| Novidade / raridade | 2,035 | Compara com o que é normal: entidade, relação ou valor nunca (ou raramente) visto. |
| Limiar / acúmulo | 1,631 | O sinal está na repetição: N eventos por chave em uma janela. |
| Mudança de estado | 1,030 | O risco está na transição: algo era seguro e deixou de ser (desligado, rebaixado, alterado). |
| Sequência ordenada | 632 | Dois ou mais passos da mesma entidade, na ordem certa, dentro de uma janela. |
| Fluxo de resposta | 84 | Não detecta: orquestra o que fazer depois do alerta (SOAR). |
| Assinatura de conteúdo | 11 | Casa bytes/strings dentro de arquivo, memória ou pacote, não eventos de log. |

### Fontes que mais contribuem

| Fonte | Regras |
|---|---:|
| EVTX-Wazuh-Rules (saifbelaarbi) | 9,781 |
| Sagan rules (Quadrant) | 5,405 |
| SigmaHQ | 2,922 |
| OpenSearch Security Analytics | 1,608 |
| SOCFortress Wazuh-Rules | 1,450 |
| Wazuh ruleset (oficial) | 1,432 |
| Splunk security_content | 1,283 |
| Elastic protections-artifacts (behavior) | 809 |
| Elastic detection-rules | 665 |
| EVTX-Wazuh-Rules (Sigma export) | 630 |

## 3. Técnicas mais cobertas

| Técnica | Regras nesta tecnologia |
|---|---:|
| [T1543.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1543.003) Windows Service | 1,908 |
| [T1059.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.001) PowerShell | 1,321 |
| [T1218](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1218) System Binary Proxy Execution | 882 |
| [T1059](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059) Command and Scripting Interpreter | 846 |
| [T1685](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1685) Disable or Modify Tools | 817 |
| [T1112](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1112) Modify Registry | 597 |
| [T1003.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1003.001) LSASS Memory | 568 |
| [T1574.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1574.001) DLL | 441 |
| [T1027](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1027) Obfuscated Files or Information | 434 |
| [T1105](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1105) Ingress Tool Transfer | 424 |
| [T1055](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1055) Process Injection | 421 |
| [T1548.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1548.002) Bypass User Account Control | 371 |

## 4. Detecção pela ausência — o que ninguém está olhando (97 técnicas)

Técnicas do ATT&CK para Windows **sem nenhuma regra nesta tecnologia**, ordenadas pelo número de grupos que as usam. A coluna "regras no catálogo" mostra se existe cobertura em outra tecnologia (ex.: EDR ou rede) que você pode adaptar.

| Técnica | Grupos que usam | Regras no catálogo (todas as tecnologias) |
|---|---:|---:|
| [T1657](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1657) Financial Theft | 19 | 2 |
| [T1684.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1684.001) Impersonation | 18 | 1 |
| [T1566.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1566.003) Spearphishing via Service | 15 | 8 |
| [T1573.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1573.001) Symmetric Cryptography | 14 | 5 |
| [T1680](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1680) Local Storage Discovery | 10 | **0** |
| [T1027.016](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1027.016) Junk Code Insertion | 7 | **0** |
| [T1534](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1534) Internal Spearphishing | 7 | 5 |
| [T1560.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1560.003) Archive via Custom Method | 7 | 1 |
| [T1071.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1071.002) File Transfer Protocols | 6 | 3 |
| [T1213.006](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1213.006) Databases | 6 | 2 |
| [T1561.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1561.002) Disk Structure Wipe | 6 | 2 |
| [T1480](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1480) Execution Guardrails | 5 | 2 |
| [T1070.007](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1070.007) Clear Network Connection History and Configurations | 4 | **0** |
| [T1087.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1087.003) Email Account | 4 | 1 |
| [T1111](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1111) Multi-Factor Authentication Interception | 4 | 3 |
| [T1496.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1496.001) Compute Hijacking | 4 | 2 |
| [T1564.011](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1564.011) Ignore Process Interrupts | 4 | **0** |
| [T1678](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1678) Delay Execution | 4 | **0** |
| [T1027.012](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1027.012) LNK Icon Smuggling | 3 | 1 |
| [T1205](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1205) Traffic Signaling | 3 | 7 |

## 5. Quem mira esta plataforma

Grupos com mais técnicas registradas nesta plataforma e quantas delas você enxerga com as regras desta tecnologia. País atribuído pelo APT4ALL (afirmação de quem publicou).

| Grupo | Origem atribuída | Técnicas na plataforma | Com regra aqui | Exemplos sem regra |
|---|---|---:|---:|---|
| [Kimsuky](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0094) `G0094` | Coreia do Norte | 105 | 90 | T1027.012, T1027.016, T1056.003, T1071.002 |
| [APT38](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0082) `G0082` | Coreia do Norte | 90 | 75 | T1027.016, T1213.006, T1480, T1480.002 |
| [Lazarus Group](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0032) `G0032` | Coreia do Norte | 83 | 76 | T1560.003, T1561.001, T1561.002, T1566.003 |
| [APT28](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0007) `G0007` | Rússia | 76 | 72 | T1001.001, T1573.001, T1669, T1684.001 |
| [APT41](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0096) `G0096` | China | 74 | 70 | T1071.002, T1480.001, T1496.001, T1684.001 |
| [Mustang Panda](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0129) `G0129` | China | 73 | 65 | T1027.012, T1027.016, T1176.002, T1205 |
| [OilRig](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0049) `G0049` | Irã | 70 | 69 | T1566.003 |
| [APT32](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0050) `G0050` | Vietnã | 68 | 67 | T1027.016 |
| [Gamaredon Group](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0047) `G0047` | Rússia | 64 | 57 | T1027.012, T1027.016, T1102.003, T1480 |
| [Magic Hound](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0059) `G0059` | Irã | 63 | 61 | T1087.003, T1566.003 |
| [MuddyWater](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0069) `G0069` | Irã | 63 | 60 | T1534, T1573.001, T1684.001 |
| [Volt Typhoon](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1017) `G1017` | China | 62 | 59 | T1070.007, T1573.001, T1680 |
| [Turla](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0010) `G0010` | Rússia | 61 | 59 | T1213.006, T1564.012 |
| [Wizard Spider](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0102) `G0102` | Rússia | 61 | 60 | T1518.002 |

## 6. Ferramentas de afiliados de ransomware que passam por aqui

Do Ransomware Tool Matrix (via APT4ALL): ferramentas usadas por gangues dentro da rede, nas categorias que esta tecnologia enxerga.

| Ferramenta | Categoria | Gangues que usam | Regras que citam |
|---|---|---:|---:|
| Mimikatz | Roubo de credenciais | 43 | 253 |
| PsExec | Binários do próprio sistema | 40 | 260 |
| SoftPerfect NetScan | Descoberta | 31 | 10 |
| Advanced IP Scanner | Descoberta | 24 | 22 |
| AdFind | Descoberta | 21 | 68 |
| Advanced Port Scanner | Descoberta | 14 | 16 |
| WMIC | Binários do próprio sistema | 13 | 543 |
| GMER | Evasão de defesa | 11 | 11 |
| ProcDump | Roubo de credenciais | 11 | 109 |
| LaZagne | Roubo de credenciais | 10 | 30 |
| Bloodhound | Descoberta | 10 | 181 |
| PCHunter | Evasão de defesa | 9 | 13 |
| BCDEdit | Binários do próprio sistema | 8 | 80 |
| PowerTool | Evasão de defesa | 8 | 13 |
| BITSAdmin | Binários do próprio sistema | 7 | 254 |
| ProcessHacker | Evasão de defesa | 7 | 32 |
| PowerView | Descoberta | 7 | 74 |
| Windows Event Utility (wevtutil) | Binários do próprio sistema | 6 | 76 |

## 9. Regras recomendadas para começar

Ranqueadas por portabilidade do formato, maturidade, severidade e por mapearem técnica ATT&CK.

| Regra | Formato | Fonte | Técnicas |
|---|---|---|---|
| [Potential Ryuk Ransomware Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac37510b8-2107-4b78-aa32-72f251e7a844) | Sigma | SigmaHQ | T1547.001 |
| [Potential QBot Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4fcac6eb-0287-4090-8eea-2602e4c20040) | Sigma | SigmaHQ | T1059.005 |
| [Potential Emotet Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad02e8cf5-6099-48cf-9bfc-1eec2d0c7b18) | Sigma | SigmaHQ | T1027, T1059.001 |
| [Potential Snatch Ransomware Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A5325945e-f1f0-406e-97b8-65104d393fff) | Sigma | SigmaHQ | T1204 |
| [Potential Dridex Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae6eb5a96-9e6f-4a18-9cdd-642cfda21c8e) | Sigma | SigmaHQ | T1033, T1055, T1135 |
| [Potential Dtrack RAT Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Af1531fa4-5b84-4342-8f68-9cf3fdbd83d4) | Sigma | SigmaHQ | T1490 |
| [LockerGoga Ransomware Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A74db3488-fd28-480a-95aa-b7af626de068) | Sigma | SigmaHQ | T1486 |
| [Equation Group DLL_U Export Function Load](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad465d1d8-27a2-4cca-9621-a800f37cf72e) | Sigma | SigmaHQ | T1218.011 |
| [Potential Russian APT Credential Theft Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab83f5166-9237-4b5e-9cd4-7b5d52f4d8ee) | Sigma | SigmaHQ | T1003.003, T1552.001 |
| [Exploiting CVE-2019-1388](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A02e0b2ea-a597-428e-b04a-af6a1a403e5c) | Sigma | SigmaHQ | T1068 |
| [Suspicious Call by Ordinal](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Ae79a9e79-eb72-4e78-a628-0e7e8f59e89c) | Sigma | OpenSearch Security Analytics | T1218.011 |
| [Ryuk Ransomware](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Ac37510b8-2107-4b78-aa32-72f251e7a844) | Sigma | OpenSearch Security Analytics | T1547.001 |
| [Password Change on Directory Service Restore Mode (DSRM) Account](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A53ad8e36-f573-46bf-97e4-15ba5bf4bb51) | Sigma | OpenSearch Security Analytics | T1098 |
| [Empire PowerShell UAC Bypass](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A3268b746-88d8-4cd3-bffc-30077d02c787) | Sigma | OpenSearch Security Analytics | T1548.002 |
| [Equation Group DLL_U Load](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Ad465d1d8-27a2-4cca-9621-a800f37cf72e) | Sigma | OpenSearch Security Analytics | T1218.011 |

## 10. Limites

- A tecnologia de cada regra é inferida por heurística sobre metadados e texto (techmap.py). Regras genéricas podem aparecer em várias tecnologias.
- "Sem regra" quer dizer sem regra pública neste catálogo, não sem detecção possível. Telemetria e contexto do seu ambiente decidem.
- Atribuição de país é afirmação das fontes reunidas pelo APT4ALL, não nossa.

---
Fontes: catálogo [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules), MITRE ATT&CK®, APT4ALL, Ransomware Tool Matrix (CC BY 4.0), TCEM, LLmInjection. Gerado em 2026-10-26.
