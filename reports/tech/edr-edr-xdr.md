# EDR / XDR — relatório de regras de detecção

> **TLP:CLEAR** · 2026-10-26 · domínio **Endpoint** · lente TCEM **Detection & Validation** · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#techno=edr)

## 1. A história em um parágrafo

O palco é **a telemetria do EDR/XDR — os olhos instalados dentro de cada máquina**. O catálogo reúne **4,654 regras** que olham para cá — 1,593 de detecção, 1,244 de hunting, 1,456 assinaturas e 361 playbooks de resposta. Elas se concentram em **Furtividade, Execução, Persistência**. 

**Lente TCEM — Detection & Validation.** Threat-informed telemetry, analytics, validation, retest and analyst-response context. Para observar: sensor health, event quality, normalization, correlation, alert disposition. Arquitetura a mapear: sensors, collection pipelines, SIEM, EDR, correlation, case management.

## 2. Números

| Indicador | Valor |
|---|---:|
| Regras | 4,654 |
| detecção | 1,593 |
| assinatura | 1,456 |
| hunting | 1,244 |
| playbook | 361 |
| Técnicas ATT&CK distintas | 351 |

### Por tática

| Tática | Regras |
|---|---:|
| Reconhecimento | 5 |
| Desenv. de recursos | 5 |
| Acesso inicial | 91 |
| Execução | 285 |
| Persistência | 210 |
| Escalação de privilégio | 196 |
| Furtividade | 304 |
| Enfraquecimento de defesas | 150 |
| Acesso a credenciais | 88 |
| Descoberta | 90 |
| Movimento lateral | 71 |
| Coleta | 37 |
| Comando e controle | 118 |
| Exfiltração | 43 |
| Impacto | 35 |

### Linguagens disponíveis

Em que formato você encontra regra pronta para esta tecnologia.

| Formato | Regras |
|---|---:|
| Suricata/Snort/Sagan | 1,456 |
| Sentinel KQL | 1,305 |
| Splunk | 643 |
| Elastic | 580 |
| Playbook | 361 |
| KQL hunting | 137 |
| Wazuh | 74 |
| Panther | 55 |
| Sigma | 35 |
| YARA-L | 8 |

### Padrões de correlação (TCEM)

Como as regras decidem. Muitas de evento único = cobertura ampla mas ruidosa; sequências e novidade = mais contexto, mais exigência de dados.

| Padrão | Regras | O que significa |
|---|---:|---|
| Evento único | 2,917 | Um evento, sozinho, já tem sinal suficiente para chamar o analista. |
| Novidade / raridade | 1,002 | Compara com o que é normal: entidade, relação ou valor nunca (ou raramente) visto. |
| Fluxo de resposta | 361 | Não detecta: orquestra o que fazer depois do alerta (SOAR). |
| Limiar / acúmulo | 199 | O sinal está na repetição: N eventos por chave em uma janela. |
| Mudança de estado | 108 | O risco está na transição: algo era seguro e deixou de ser (desligado, rebaixado, alterado). |
| Sequência ordenada | 67 | Dois ou mais passos da mesma entidade, na ordem certa, dentro de uma janela. |

### Fontes que mais contribuem

| Fonte | Regras |
|---|---:|
| Sagan rules (Quadrant) | 1,456 |
| Microsoft Sentinel (Hunting Queries) | 1,100 |
| Splunk security_content | 636 |
| Elastic detection-rules | 574 |
| Cortex XSOAR (demisto/content) | 258 |
| Microsoft Sentinel (Analytic Rules) | 205 |
| Bert-JanP Hunting Queries | 137 |
| Panther panther-analysis | 55 |
| Wazuh ruleset (oficial) | 38 |
| SigmaHQ | 24 |

## 3. Técnicas mais cobertas

| Técnica | Regras nesta tecnologia |
|---|---:|
| [T1059](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059) Command and Scripting Interpreter | 146 |
| [T1685](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1685) Disable or Modify Tools | 83 |
| [T1218](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1218) System Binary Proxy Execution | 69 |
| [T1059.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.004) Unix Shell | 59 |
| [T1059.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.001) PowerShell | 46 |
| [T1036](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1036) Masquerading | 45 |
| [T1003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1003) OS Credential Dumping | 44 |
| [T1574](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1574) Hijack Execution Flow | 44 |
| [T1112](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1112) Modify Registry | 42 |
| [T1543](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1543) Create or Modify System Process | 40 |
| [T1059.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.003) Windows Command Shell | 37 |
| [T1071](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1071) Application Layer Protocol | 35 |

## 6. Ferramentas de afiliados de ransomware que passam por aqui

Do Ransomware Tool Matrix (via APT4ALL): ferramentas usadas por gangues dentro da rede, nas categorias que esta tecnologia enxerga.

| Ferramenta | Categoria | Gangues que usam | Regras que citam |
|---|---|---:|---:|
| Cobalt Strike | Ferramentas ofensivas | 43 | 258 |
| Impacket | Ferramentas ofensivas | 20 | 78 |
| GMER | Evasão de defesa | 11 | 11 |
| PCHunter | Evasão de defesa | 9 | 13 |
| Metasploit | Ferramentas ofensivas | 9 | 88 |
| PowerShell Empire | Ferramentas ofensivas | 9 | 9 |
| PowerTool | Evasão de defesa | 8 | 13 |
| PowerSploit | Ferramentas ofensivas | 8 | 23 |
| ProcessHacker | Evasão de defesa | 7 | 32 |
| Meterpreter | Ferramentas ofensivas | 6 | 51 |
| Rubeus | Ferramentas ofensivas | 6 | 86 |
| NetExec | Ferramentas ofensivas | 5 | 15 |
| Zemana Anti-Rootkit driver | Evasão de defesa | 4 | **0** |
| Brute Ratel C4 | Ferramentas ofensivas | 4 | 3 |
| Avast Anti-Rootkit driver | Evasão de defesa | 3 | **0** |
| EDRSandBlast | Evasão de defesa | 3 | 1 |
| CrackMapExec | Ferramentas ofensivas | 3 | 71 |
| Koadic | Ferramentas ofensivas | 3 | 13 |

## 9. Regras recomendadas para começar

Ranqueadas por portabilidade do formato, maturidade, severidade e por mapearem técnica ATT&CK.

| Regra | Formato | Fonte | Técnicas |
|---|---|---|---|
| [Potential Russian APT Credential Theft Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab83f5166-9237-4b5e-9cd4-7b5d52f4d8ee) | Sigma | SigmaHQ | T1003.003, T1552.001 |
| [Antivirus - Password Dumper Signature](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A78cc2dd2-7d20-4d32-93ff-057084c38b93) | Sigma | SigmaHQ | T1003, T1003.001, T1003.002 |
| [Antivirus - Exploitation Framework Signature](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A238527ad-3c2c-4e4f-a1f6-92fd63adb864) | Sigma | SigmaHQ | T1203, T1219.002 |
| [Antivirus - Hacktool Signature](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Afa0c05b6-8ad3-468d-8231-c1cbccb64fba) | Sigma | SigmaHQ | T1204 |
| [APT31 Judgement Panda Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A03e2746e-2b31-42f1-ab7a-eb39365b2422) | Sigma | SigmaHQ | T1003.001, T1560.001 |
| [StoneDrill Service Install](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A9e987c6c-4c1e-40d8-bd85-dd26fba8fdd6) | Sigma | SigmaHQ | T1543.003 |
| [Antivirus - Relevant File Paths Alerts Signature](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac9a88268-0047-4824-ba6e-4d81ce0b907c) | Sigma | SigmaHQ | T1588 |
| [Sysinternals PsSuspend Suspicious Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4beb6ae0-f85b-41e2-8f18-8668abc8af78) | Sigma | SigmaHQ | T1685 |
| [Uninstall Crowdstrike Falcon Sensor](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Af0f7be61-9cf5-43be-9836-99d6ef448a18) | Sigma | SigmaHQ | T1685 |
| [HackTool - EDRSilencer Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aeb2d07d4-49cb-4523-801a-da002df36602) | Sigma | SigmaHQ | T1685 |
| [HackTool - EDRSilencer Execution - Filter Added](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A98054878-5eab-434c-85d4-72d4e5a3361b) | Sigma | SigmaHQ | T1685 |
| [Windows Filtering Platform Blocked Connection From EDR Agent Binary](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Abacf58c6-e199-4040-a94f-95dea0f1e45a) | Sigma | SigmaHQ | T1685 |
| [Judgement Panda Exfil Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A03e2746e-2b31-42f1-ab7a-eb39365b2422) | Sigma | OpenSearch Security Analytics | T1003.001, T1560.001 |
| [Judgement Panda Credential Access Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Ab83f5166-9237-4b5e-9cd4-7b5d52f4d8ee) | Sigma | OpenSearch Security Analytics | T1003.003, T1552.001 |
| [Antivirus Exploitation Framework Detection](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A238527ad-3c2c-4e4f-a1f6-92fd63adb864) | Sigma | OpenSearch Security Analytics | T1203, T1219 |

## 10. Limites

- A tecnologia de cada regra é inferida por heurística sobre metadados e texto (techmap.py). Regras genéricas podem aparecer em várias tecnologias.
- "Sem regra" quer dizer sem regra pública neste catálogo, não sem detecção possível. Telemetria e contexto do seu ambiente decidem.
- Atribuição de país é afirmação das fontes reunidas pelo APT4ALL, não nossa.

---
Fontes: catálogo [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules), MITRE ATT&CK®, APT4ALL, Ransomware Tool Matrix (CC BY 4.0), TCEM, LLmInjection. Gerado em 2026-10-26.
