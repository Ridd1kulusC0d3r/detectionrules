# IA, LLMs & agentes — relatório de regras de detecção

> **TLP:CLEAR** · 2026-10-26 · domínio **IA** · lente TCEM **AI / GenAI** · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#techno=ai)

## 1. A história em um parágrafo

O palco é **IA, LLMs e agentes — modelos, ferramentas e conectores que agem em nome de alguém**. O catálogo reúne **494 regras** que olham para cá — 380 de detecção, 43 de hunting, 38 assinaturas e 33 playbooks de resposta. Elas se concentram em **Persistência, Escalação de privilégio, Furtividade**. 

**Lente TCEM — AI / GenAI.** Models, agents, tool servers, connectors, retrieval, datasets, machine identity, supply chain and AI telemetry. Para observar: model requests, tool calls, policy decisions, retrieval traces, connector activity. Arquitetura a mapear: models, agents, tool servers, connectors, vector stores, datasets, machine identities.

## 2. Números

| Indicador | Valor |
|---|---:|
| Regras | 494 |
| detecção | 380 |
| hunting | 43 |
| assinatura | 38 |
| playbook | 33 |
| Técnicas ATT&CK distintas | 134 |

### Por tática

| Tática | Regras |
|---|---:|
| Desenv. de recursos | 1 |
| Acesso inicial | 33 |
| Execução | 46 |
| Persistência | 73 |
| Escalação de privilégio | 73 |
| Furtividade | 56 |
| Enfraquecimento de defesas | 42 |
| Acesso a credenciais | 40 |
| Descoberta | 19 |
| Movimento lateral | 14 |
| Coleta | 46 |
| Comando e controle | 26 |
| Exfiltração | 28 |
| Impacto | 25 |

### Linguagens disponíveis

Em que formato você encontra regra pronta para esta tecnologia.

| Formato | Regras |
|---|---:|
| Elastic | 185 |
| Sentinel KQL | 83 |
| Splunk | 69 |
| Suricata/Snort/Sagan | 38 |
| Playbook | 33 |
| Panther | 30 |
| Sigma | 28 |
| Wazuh | 19 |
| GCP | 4 |
| YARA-L | 3 |
| KQL hunting | 2 |

### Padrões de correlação (TCEM)

Como as regras decidem. Muitas de evento único = cobertura ampla mas ruidosa; sequências e novidade = mais contexto, mais exigência de dados.

| Padrão | Regras | O que significa |
|---|---:|---|
| Evento único | 236 | Um evento, sozinho, já tem sinal suficiente para chamar o analista. |
| Novidade / raridade | 153 | Compara com o que é normal: entidade, relação ou valor nunca (ou raramente) visto. |
| Fluxo de resposta | 33 | Não detecta: orquestra o que fazer depois do alerta (SOAR). |
| Mudança de estado | 32 | O risco está na transição: algo era seguro e deixou de ser (desligado, rebaixado, alterado). |
| Limiar / acúmulo | 21 | O sinal está na repetição: N eventos por chave em uma janela. |
| Sequência ordenada | 19 | Dois ou mais passos da mesma entidade, na ordem certa, dentro de uma janela. |

### Fontes que mais contribuem

| Fonte | Regras |
|---|---:|
| Elastic detection-rules | 170 |
| Microsoft Sentinel (Analytic Rules) | 63 |
| Splunk security_content | 55 |
| Sagan rules (Quadrant) | 37 |
| Panther panther-analysis | 30 |
| Cortex XSOAR (demisto/content) | 21 |
| Microsoft Sentinel (Hunting Queries) | 20 |
| SigmaHQ | 18 |
| EVTX-Wazuh-Rules (saifbelaarbi) | 15 |
| Splunk analytic stories | 13 |

## 3. Técnicas mais cobertas

| Técnica | Regras nesta tecnologia |
|---|---:|
| [T1685](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1685) Disable or Modify Tools | 32 |
| [T1098](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1098) Account Manipulation | 23 |
| [T1059](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059) Command and Scripting Interpreter | 20 |
| [T1071](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1071) Application Layer Protocol | 19 |
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | 19 |
| [T1078.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.004) Cloud Accounts | 17 |
| [T1119](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1119) Automated Collection | 16 |
| [T1567](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1567) Exfiltration Over Web Service | 11 |
| [T1552](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1552) Unsecured Credentials | 10 |
| [T1105](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1105) Ingress Tool Transfer | 9 |
| [T1059.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.001) PowerShell | 8 |
| [T1213](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1213) Data from Information Repositories | 8 |

## 7. Cenário de referência TCEM

### Enterprise AI Agent reference case

**Missão:** Preserve controlled agent authority, sensitive data access and auditable tool use.

**Agent invokes a sensitive connector after privileged tool authorization** — Correlate privileged agent authorization with consequential tool activity.

1. agent_privileged_authorization — T1078 (1265 regras no catálogo)
2. sensitive_connector_action — T1098 (831 regras no catálogo)

Contrato de telemetria: fonte **AI agent and tool audit**, campos exigidos agent.id, tool.id, target.resource, action, timestamp; **faltam target.resource** (status partial).
Especificação de detecção: padrão **ordered-sequence**, janela 30m, agrupado por agent.id. Alternativas benignas: approved change with expected authorization context.

## 8. Ameaças de IA mapeadas (LLmInjection)

| Técnica | Categoria | ATLAS / OWASP | Especificações de detecção | Testes |
|---|---|---|---:|---:|
| LLMI-T001 Direct Prompt Injection | prompt-context | LLM01:2026, AML.T0051.000 | 2 | 2 |
| LLMI-T002 Indirect Prompt Injection | prompt-context | LLM01:2026, AML.T0051.001 | 2 | 1 |
| LLMI-T003 Jailbreak / Safety Boundary Manipulation | model-behavior | AML.T0054 | 1 | 1 |
| LLMI-T004 Sensitive Information Disclosure | confidentiality | LLM02:2026, AML.T0057 | 1 | 2 |
| LLMI-T005 Model Extraction / Theft | model |  | 2 | 1 |
| LLMI-T006 Data or Model Poisoning | training-data | LLM05:2026, AML.T0020 | 1 | 1 |
| LLMI-T007 RAG Knowledge Poisoning | rag | AML.T0070 | 1 | 1 |
| LLMI-T008 Agent Tool Misuse | agentic | ASI02:2026, AML.T0053 | 3 | 6 |
| LLMI-T009 Memory / Context Poisoning | agentic | ASI06:2026, AML.T0080, AML.T0080.000 | 2 | 1 |
| LLMI-T010 Model Source Tampering | supply-chain | AML.T0010.003 | 3 | 1 |
| LLMI-T011 AI Software Supply Chain Compromise | supply-chain | LLM04:2026, AML.T0010, AML.T0010.001 | 5 | 2 |
| LLMI-T012 Coding-Agent Dependency Manipulation | supply-chain |  | 2 | 2 |
| LLMI-T013 Runtime LLM Command Generation | ai-offensive-enabler | AML.T0102 | 1 | 1 |
| LLMI-T014 AI-Assisted Reconnaissance and Social Engineering | ai-offensive-enabler |  | 1 | 1 |
| LLMI-T015 Agentic Attack Orchestration | ai-autonomous-operator | AML.T0124 | 2 | 1 |
| LLMI-T016 AI Gateway Credential Compromise | supply-chain |  | 1 | 1 |
| LLMI-T017 Prompt Injection Against AI Security Scanners | defense-evasion |  | 2 | 1 |
| LLMI-T018 AI Coding-Assistant Workspace Abuse | agentic-supply-chain | AML.T0081 | 6 | 1 |
| LLMI-T019 Model Distillation Campaign | model-theft |  | 1 | 1 |
| LLMI-T020 Improper Output Handling and Rendering Exfiltration | application | AML.T0077 | 2 | 3 |
| LLMI-T021 Agent Tool Poisoning and Rug Pull | agentic-supply-chain | AML.T0110 | 2 | 1 |
| LLMI-T022 Agentic Resource Consumption and Cost Harvesting | availability | AML.T0034.002 | 2 | 2 |
| LLMI-T023 Crafted AI Assistant Links and Recommendation Poisoning | prompt-context | AML.T0131 | 1 | 1 |
| LLMI-T024 Exposed or Misconfigured AI Services | infrastructure | AML.T0132 | 1 | 1 |
| LLMI-T025 Multimodal Instruction Triggers | prompt-context | AML.T0129 | 1 | 2 |
| LLMI-T026 Inter-Agent Instruction Propagation | agentic |  | 1 | 1 |
| LLMI-T027 Unsanctioned AI Runtime (Shadow AI) | runtime-security |  | 2 | 2 |
| LLMI-T028 AI-Assisted Tooling Development | offensive-enablement |  | 1 | 1 |

## 9. Regras recomendadas para começar

Ranqueadas por portabilidade do formato, maturidade, severidade e por mapearem técnica ATT&CK.

| Regra | Formato | Fonte | Técnicas |
|---|---|---|---|
| [Potential Privilege Escalation Using Symlink Between Osk and Cmd](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae9b61244-893f-427c-b287-3e708f321c6b) | Sigma | SigmaHQ | T1546.008 |
| [PowerShell Credential Prompt](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aca8b77a9-d499-4095-b793-5d5f330d450e) | Sigma | SigmaHQ | T1059.001 |
| [Potential Destructive AWS CLI Command Executed by GenAI Agent](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A2635d2ba-51e7-404a-9b17-db413a1351d5) | Elastic | Elastic detection-rules | T0051, T1485, T1531 |
| [Potential Widespread Malware Infection Across Multiple Hosts](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A28371aa1-14ed-46cf-ab5b-2fc7d1942278) | Elastic | Elastic detection-rules | T1204, T1204.002 |
| [Elastic Defend Alert from GenAI Utility or Descendant](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ad4e5f6a7-b8c9-7d0e-1f2a-3b4c5d6e7f8a) | Elastic | Elastic detection-rules | T0011, T0053, T1059 |
| [GenAI Process Accessing Sensitive Files](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ac0136397-f82a-45e5-9b9f-a3651d77e21a) | Elastic | Elastic detection-rules | T0055, T0085, T0085.001 |
| [Machine Learning Detected a Suspicious Windows Event with a High Malicious Probability Score](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A994e40aa-8c85-43de-825e-15f665375ee8) | Elastic | Elastic detection-rules | T1036, T1036.004 |
| [AWS Bedrock Model Invocation Logging Disabled or Modified](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Afa830742-fd41-4b12-a287-2c57bdf079ef) | Elastic | Elastic detection-rules | T1685, T1685.002 |
| [AWS Bedrock API Key Phantom User Activity Outside Bedrock](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A56788ae8-794b-4ade-affd-534aa5c9e28d) | Elastic | Elastic detection-rules | T0012, T0055, T1078 |
| [AWS IAM Credentials Added to a Bedrock API Key Phantom User](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A71159cad-f8b3-4b3c-ac6e-9cab05594670) | Elastic | Elastic detection-rules | T0012, T1098, T1098.001 |
| [AWS Bedrock API Key Used for Destructive or Anti-Recovery Action](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A89b68231-5134-4499-8eca-20e5d9c90cce) | Elastic | Elastic detection-rules | T0012, T1485, T1685 |
| [AWS Bedrock AgentCore with Public Network Browser or Code Interpreter Sandbox](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A86be0b1b-3984-4b26-bde6-46d33fe7bab1) | Elastic | Elastic detection-rules | T0012, T0103, T1078 |
| [AWS Bedrock Foundation Model Enumeration Followed by Invocation via Long-Term Key](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Aa17f2e5f-de52-49e8-9d86-ccfe91cd54d4) | Elastic | Elastic detection-rules | T0007, T0040, T1078 |
| [AWS Bedrock AgentCore Execution Role Used Outside Its Runtime](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Aee066db8-4f2f-42d3-8ebd-ea25cd9bdc73) | Elastic | Elastic detection-rules | T0012, T0098, T1078 |
| [AWS Bedrock AgentCore Runtime Prompt Targeting Credentials or Instance Metadata](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A9c2f1d6a-4e8b-4c7a-9f3d-2b6e1a0c5d44) | Elastic | Elastic detection-rules | T0054, T0098, T1552 |

## 10. Limites

- A tecnologia de cada regra é inferida por heurística sobre metadados e texto (techmap.py). Regras genéricas podem aparecer em várias tecnologias.
- "Sem regra" quer dizer sem regra pública neste catálogo, não sem detecção possível. Telemetria e contexto do seu ambiente decidem.
- Atribuição de país é afirmação das fontes reunidas pelo APT4ALL, não nossa.

---
Fontes: catálogo [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules), MITRE ATT&CK®, APT4ALL, Ransomware Tool Matrix (CC BY 4.0), TCEM, LLmInjection. Gerado em 2026-10-26.
