# Backup & armazenamento — relatório de regras de detecção

> **TLP:CLEAR** · 2026-10-26 · domínio **Infraestrutura** · lente TCEM **Detection & Validation** · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#techno=backup)

## 1. A história em um parágrafo

O palco é **os backups — a última linha de recuperação, alvo preferido do ransomware**. O catálogo reúne **716 regras** que olham para cá — 439 de detecção, 16 de hunting, 201 assinaturas e 60 playbooks de resposta. Elas se concentram em **Impacto, Acesso a credenciais, Furtividade**. 

**Lente TCEM — Detection & Validation.** Threat-informed telemetry, analytics, validation, retest and analyst-response context. Para observar: sensor health, event quality, normalization, correlation, alert disposition. Arquitetura a mapear: sensors, collection pipelines, SIEM, EDR, correlation, case management.

## 2. Números

| Indicador | Valor |
|---|---:|
| Regras | 716 |
| detecção | 439 |
| assinatura | 201 |
| playbook | 60 |
| hunting | 16 |
| Técnicas ATT&CK distintas | 69 |

### Por tática

| Tática | Regras |
|---|---:|
| Desenv. de recursos | 2 |
| Acesso inicial | 5 |
| Execução | 16 |
| Persistência | 13 |
| Escalação de privilégio | 16 |
| Furtividade | 27 |
| Enfraquecimento de defesas | 15 |
| Acesso a credenciais | 65 |
| Descoberta | 2 |
| Movimento lateral | 5 |
| Coleta | 20 |
| Comando e controle | 1 |
| Exfiltração | 17 |
| Impacto | 101 |

### Linguagens disponíveis

Em que formato você encontra regra pronta para esta tecnologia.

| Formato | Regras |
|---|---:|
| Suricata/Snort/Sagan | 201 |
| Sentinel KQL | 157 |
| Wazuh | 136 |
| Sigma | 79 |
| Playbook | 60 |
| Elastic | 36 |
| Splunk | 25 |
| Panther | 11 |
| YARA-L | 9 |
| Falco | 1 |
| KQL hunting | 1 |

### Padrões de correlação (TCEM)

Como as regras decidem. Muitas de evento único = cobertura ampla mas ruidosa; sequências e novidade = mais contexto, mais exigência de dados.

| Padrão | Regras | O que significa |
|---|---:|---|
| Evento único | 567 | Um evento, sozinho, já tem sinal suficiente para chamar o analista. |
| Fluxo de resposta | 60 | Não detecta: orquestra o que fazer depois do alerta (SOAR). |
| Novidade / raridade | 44 | Compara com o que é normal: entidade, relação ou valor nunca (ou raramente) visto. |
| Mudança de estado | 27 | O risco está na transição: algo era seguro e deixou de ser (desligado, rebaixado, alterado). |
| Sequência ordenada | 11 | Dois ou mais passos da mesma entidade, na ordem certa, dentro de uma janela. |
| Limiar / acúmulo | 6 | O sinal está na repetição: N eventos por chave em uma janela. |
| Assinatura de conteúdo | 1 | Casa bytes/strings dentro de arquivo, memória ou pacote, não eventos de log. |

### Fontes que mais contribuem

| Fonte | Regras |
|---|---:|
| Sagan rules (Quadrant) | 200 |
| Microsoft Sentinel (Analytic Rules) | 148 |
| EVTX-Wazuh-Rules (saifbelaarbi) | 102 |
| SigmaHQ | 53 |
| Cortex XSOAR (demisto/content) | 42 |
| Elastic detection-rules | 30 |
| Wazuh ruleset (oficial) | 28 |
| OpenSearch Security Analytics | 23 |
| Splunk security_content | 19 |
| awesome-playbooks · resolve | 12 |

## 3. Técnicas mais cobertas

| Técnica | Regras nesta tecnologia |
|---|---:|
| [T1490](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1490) Inhibit System Recovery | 96 |
| [T1003.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1003.003) NTDS | 30 |
| [T1003.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1003.002) Security Account Manager | 24 |
| [T1003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1003) OS Credential Dumping | 18 |
| [T1567.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1567.002) Exfiltration to Cloud Storage | 13 |
| [T1485](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1485) Data Destruction | 13 |
| [T1005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1005) Data from Local System | 12 |
| [T1003.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1003.004) LSA Secrets | 12 |
| [T1048](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1048) Exfiltration Over Alternative Protocol | 11 |
| [T1555](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1555) Credentials from Password Stores | 9 |
| [T1059.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.001) PowerShell | 9 |
| [T1070.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1070.004) File Deletion | 7 |

## 6. Ferramentas de afiliados de ransomware que passam por aqui

Do Ransomware Tool Matrix (via APT4ALL): ferramentas usadas por gangues dentro da rede, nas categorias que esta tecnologia enxerga.

| Ferramenta | Categoria | Gangues que usam | Regras que citam |
|---|---|---:|---:|
| GMER | Evasão de defesa | 11 | 11 |
| PCHunter | Evasão de defesa | 9 | 13 |
| PowerTool | Evasão de defesa | 8 | 13 |
| ProcessHacker | Evasão de defesa | 7 | 32 |
| Zemana Anti-Rootkit driver | Evasão de defesa | 4 | **0** |
| Avast Anti-Rootkit driver | Evasão de defesa | 3 | **0** |
| EDRSandBlast | Evasão de defesa | 3 | 1 |
| Backstab/Process Explorer driver (BYOVD) | Evasão de defesa | 2 | 3 |
| Darkside/TrueSight driver (BYOVD) | Evasão de defesa | 2 | 14 |
| Defender Control | Evasão de defesa | 2 | 1 |
| Eraser | Evasão de defesa | 2 | 1 |
| GIGABYTE Motherboard driver (BYOVD) | Evasão de defesa | 2 | **0** |
| HRSword | Evasão de defesa | 2 | **0** |
| TDSSKiller | Evasão de defesa | 2 | **0** |
| ThreatFire System Monitor driver (BYOVD) | Evasão de defesa | 2 | **0** |
| ThrottleStop driver (BYOVD) | Evasão de defesa | 2 | **0** |
| ADVobfuscator | Evasão de defesa | 1 | **0** |
| Antiy System In-Depth Analysis Toolkit driver (BYOVD) | Evasão de defesa | 1 | **0** |

## 9. Regras recomendadas para começar

Ranqueadas por portabilidade do formato, maturidade, severidade e por mapearem técnica ATT&CK.

| Regra | Formato | Fonte | Técnicas |
|---|---|---|---|
| [Shadow Copies Deletion Using Operating Systems Utilities](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac947b146-0abc-4c87-9c64-b17e9d7274a2) | Sigma | SigmaHQ | T1070, T1490 |
| [VolumeShadowCopy Symlink Creation Via Mklink](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A40b19fa6-d835-400c-b301-41f3a2baacaf) | Sigma | SigmaHQ | T1003.002, T1003.003 |
| [Delete Volume Shadow Copies Via WMI With PowerShell](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A87df9ee1-5416-453a-8a08-e8d4a51e9ce1) | Sigma | SigmaHQ | T1490 |
| [DPAPI Backup Keys And Certificate Export Activity IOC](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A7892ec59-c5bb-496d-8968-e5d210ca3ac4) | Sigma | SigmaHQ | T1552.004, T1555 |
| [Copy From VolumeShadowCopy Via Cmd.EXE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac73124a7-3e89-44a3-bdc1-25fe4df754b1) | Sigma | SigmaHQ | T1490 |
| [Deletion of Volume Shadow Copies via WMI with PowerShell](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A21ff4ca9-f13a-41ad-b828-0077b2af2e40) | Sigma | SigmaHQ | T1490 |
| [PowerShell Base64 Encoded WMI Classes](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1816994b-42e1-4fb1-afd2-134d88184f71) | Sigma | SigmaHQ | T1027, T1059.001 |
| [All Backups Deleted Via Wbadmin.EXE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A639c9081-f482-47d3-a0bd-ddee3d4ecd76) | Sigma | SigmaHQ | T1490 |
| [DSInternals Suspicious PowerShell Cmdlets](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A43d91656-a9b2-4541-b7e2-6a9bd3a13f4e) | Sigma | SigmaHQ | T1059.001 |
| [VeeamBackup Database Credentials Dump Via Sqlcmd.EXE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab57ba453-b384-4ab9-9f40-1038086b4e53) | Sigma | SigmaHQ | T1005 |
| [Sensitive File Dump Via Wbadmin.EXE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A8b93a509-1cb8-42e1-97aa-ee24224cdc15) | Sigma | SigmaHQ | T1003.003 |
| [Sensitive File Access Via Volume Shadow Copy Backup](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Af57f8d16-1f39-4dcb-a604-6c73d9b54b3d) | Sigma | SigmaHQ | T1490 |
| [Suspicious Windows Service Tampering](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ace72ef99-22f1-43d4-8695-419dcb5d9330) | Sigma | SigmaHQ | T1489, T1685 |
| [Sensitive File Recovery From Backup Via Wbadmin.EXE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A84972c80-251c-4c3a-9079-4f00aad93938) | Sigma | SigmaHQ | T1003.003 |
| [Suspicious Volume Shadow Copy VSS_PS.dll Load](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A333cdbe8-27bb-4246-bf82-b41a0dca4b70) | Sigma | SigmaHQ | T1490 |

## 10. Limites

- A tecnologia de cada regra é inferida por heurística sobre metadados e texto (techmap.py). Regras genéricas podem aparecer em várias tecnologias.
- "Sem regra" quer dizer sem regra pública neste catálogo, não sem detecção possível. Telemetria e contexto do seu ambiente decidem.
- Atribuição de país é afirmação das fontes reunidas pelo APT4ALL, não nossa.

---
Fontes: catálogo [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules), MITRE ATT&CK®, APT4ALL, Ransomware Tool Matrix (CC BY 4.0), TCEM, LLmInjection. Gerado em 2026-10-26.
