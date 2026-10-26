# Arquivos & memória (YARA) — relatório de regras de detecção

> **TLP:CLEAR** · 2026-10-26 · domínio **Arquivos & malware** · lente TCEM **Detection & Validation** · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#techno=files)

## 1. A história em um parágrafo

O palco é **arquivos e memória — o próprio artefato do atacante, não o rastro que ele deixa**. O catálogo reúne **22,684 regras** que olham para cá — 0 de detecção, 0 de hunting, 22,684 assinaturas e 0 playbooks de resposta. Elas se concentram em **Furtividade, Acesso a credenciais, Execução**. 

**Lente TCEM — Detection & Validation.** Threat-informed telemetry, analytics, validation, retest and analyst-response context. Para observar: sensor health, event quality, normalization, correlation, alert disposition. Arquitetura a mapear: sensors, collection pipelines, SIEM, EDR, correlation, case management.

## 2. Números

| Indicador | Valor |
|---|---:|
| Regras | 22,684 |
| assinatura | 22,684 |
| Técnicas ATT&CK distintas | 4 |

### Por tática

| Tática | Regras |
|---|---:|
| Execução | 1 |
| Furtividade | 2 |
| Acesso a credenciais | 2 |
| Comando e controle | 1 |

### Linguagens disponíveis

Em que formato você encontra regra pronta para esta tecnologia.

| Formato | Regras |
|---|---:|
| YARA | 22,684 |

### Padrões de correlação (TCEM)

Como as regras decidem. Muitas de evento único = cobertura ampla mas ruidosa; sequências e novidade = mais contexto, mais exigência de dados.

| Padrão | Regras | O que significa |
|---|---:|---|
| Assinatura de conteúdo | 22,684 | Casa bytes/strings dentro de arquivo, memória ou pacote, não eventos de log. |

### Fontes que mais contribuem

| Fonte | Regras |
|---|---:|
| Yara-Rules community | 12,621 |
| Neo23x0 signature-base | 5,755 |
| Elastic protections-artifacts (YARA) | 3,064 |
| ReversingLabs YARA | 1,240 |
| SpiderLabs malware-analysis (YARA) | 4 |

## 3. Técnicas mais cobertas

| Técnica | Regras nesta tecnologia |
|---|---:|
| [T1552](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1552) Unsecured Credentials | 2 |
| [T1221](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1221) Template Injection | 1 |
| [T1574](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1574) Hijack Execution Flow | 1 |
| [T1090](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1090) Proxy | 1 |

## 9. Regras recomendadas para começar

Ranqueadas por portabilidade do formato, maturidade, severidade e por mapearem técnica ATT&CK.

| Regra | Formato | Fonte | Técnicas |
|---|---|---|---|

## 10. Limites

- A tecnologia de cada regra é inferida por heurística sobre metadados e texto (techmap.py). Regras genéricas podem aparecer em várias tecnologias.
- "Sem regra" quer dizer sem regra pública neste catálogo, não sem detecção possível. Telemetria e contexto do seu ambiente decidem.
- Atribuição de país é afirmação das fontes reunidas pelo APT4ALL, não nossa.

---
Fontes: catálogo [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules), MITRE ATT&CK®, APT4ALL, Ransomware Tool Matrix (CC BY 4.0), TCEM, LLmInjection. Gerado em 2026-10-26.
