# Detection Rules

**Toda regra pública de detecção, explicada até o último campo.**

84.570 regras reais de 48 fontes públicas (Sigma, Elastic, Splunk, Sentinel, Chronicle, OpenSearch, Wazuh, Suricata/Snort/Sagan, YARA, Falco, Panther, QRadar AQL e playbooks SOAR), normalizadas num só esquema. Cada regra responde quatro perguntas: **o que detecta, de quais dados depende, por que disparou e como provar que funciona.**

**Site:** https://ridd1kulusc0d3r.github.io/detectionrules/

| Detecção | Assinaturas | Hunting | Playbooks SOAR |
|---:|---:|---:|---:|
| 34.838 | 42.843 | 3.440 | 3.449 |

## O que o site faz
- **Arsenal:** busca e filtros por tipo, fonte, formato, severidade, tática e técnica ATT&CK. Cada regra abre numa ficha com 7 abas: *Entenda · Veja a lógica · Prepare os dados · Experimente · Adapte · Investigue · Origem & versões*.
- **Experimente:** regras Sigma rodam numa simulação no navegador com eventos que devem e que não devem disparar, mostrando campo a campo por quê.
- **Adapte:** editor com validador por formato e download do **pacote de detecção** (regra + guia + casos de teste).
- **Forja:** você diz o comportamento e os dados que tem; o motor monta a regra e traduz para Sigma, KQL, SPL, EQL, TOML Elastic e Wazuh, explicando cada decisão.
- **Grafo de conhecimento (ATT&CK v20.0):** matriz de cobertura das 706 técnicas, lacunas prioritárias (técnicas usadas por muitos grupos e com poucas regras), 178 grupos APT com o percentual de técnicas que o catálogo público consegue ver, e um grafo de relacionamentos por técnica: grupos, subtécnicas, regras por formato, testes Atomic Red Team, logs EVTX reais, mitigações e softwares.
- **Ficha da regra enriquecida:** contexto ATT&CK na aba *Entenda*, fontes de log recomendadas pelo MITRE na aba *Prepare os dados* e testes Atomic + logs EVTX para provar a detecção na aba *Experimente*.
- **Ferramentas e materiais:** 282 itens da planilha *Malware IR – Tools & Resources*, organizados por fase do trabalho e ligados aos formatos de regra que cada fase produz.
- **Academia:** 8 lições pela técnica de Feynman e o dicionário de campos de cada formato.
- **Playbooks:** resposta separada de detecção, com 5 modelos de triagem e os playbooks reais do catálogo.
- **Progressão:** XP, ranks e conquistas, salvos no navegador.
- **[Manual de Threat Detection](docs/manual-threat-detection.html):** ataques, logs, forense, threat modeling e threat intelligence explicados do zero.

Estados de curadoria explícitos: **importada → explicada → simulada → adaptada**. Explicação e simulação são apoio de estudo; não equivalem a teste no mecanismo real.

## Publicar no GitHub Pages
Em **Settings → Pages → Build and deployment → Source**, escolha **GitHub Actions**. O workflow `Publicar no GitHub Pages` publica a cada push na `main`.

Toda segunda-feira (03:17, horário de Brasília) ele recoleta todas as fontes, reconstrói o catálogo e republica. Para rodar na hora: **Actions → Publicar no GitHub Pages → Run workflow → Recoletar**.

## Rodar localmente
Duplo clique em `ABRIR.bat` (Windows), `ABRIR.command` (macOS) ou `./abrir.sh` (Linux). Requer Python 3; nada sai da sua máquina.

## Reconstruir o catálogo
```bash
./scripts/fetch_sources.sh   # clona as fontes (~1,5 GB, fora do versionamento)
python3 build_catalog.py     # normaliza tudo em catalog.json
python3 make_data.py         # gera data/: índice + blocos de ~3 MB
python3 build_graph.py .     # gera data/graph/: grafo ATT&CK, recursos e exportações
```
Somente biblioteca padrão do Python.

## Grafo e exportações
`build_graph.py` cruza o catálogo com o MITRE ATT&CK v20.0 (STIX oficial), 1.847 testes do Atomic Red Team (só metadados), 483 amostras EVTX (279 organizadas por técnica no EVTX-to-MITRE-Attack, 204 ligadas por palavra-chave no EVTX-ATTACK-SAMPLES), 1528 relatórios APT da coleção CyberMonitor (471 ligados a grupos pelo nome) e a planilha de ferramentas.

| Arquivo | Uso |
|---|---|
| `data/graph/graph.graphml` | Gephi, yEd, Neo4j |
| `data/graph/graph.json` | nós e arestas para qualquer ferramenta |
| `data/graph/navigator-layer.json` | camada de cobertura para o [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) |
| `data/graph/attack.json` | técnicas, grupos, softwares, campanhas, mitigações e estratégias de detecção com cobertura de regras |

IDs antigos citados pelas regras são convertidos pelas revogações oficiais do ATT&CK (ex.: T1562 → T1685 na nova tática *Defense Impairment*, T1086 → T1059.001). Citações de técnicas ICS (`T0xxx`) ficam fora da matriz Enterprise. Ligações marcadas como *inferidas* (EVTX por palavra-chave, relatório por nome do grupo) devem ser conferidas antes de uso formal.

## Desempenho
- Índice de 21 MB servido comprimido (~3,3 MB na rede).
- O texto de cada regra fica em blocos de ~3 MB; o navegador baixa só o bloco da regra aberta.
- Nenhum arquivo acima de 3,5 MB.

## Fontes
| Fonte | Regras |
|---|---:|
| Sagan rules (Quadrant) | 19.430 |
| Yara-Rules community | 12.621 |
| EVTX-Wazuh-Rules (saifbelaarbi) | 9.787 |
| Neo23x0 signature-base | 5.755 |
| Wazuh ruleset (oficial) | 4.481 |
| SigmaHQ | 3.804 |
| Elastic protections-artifacts (YARA) | 3.064 |
| Elastic detection-rules | 2.436 |
| Microsoft Sentinel (Analytic Rules) | 2.429 |
| OpenSearch Security Analytics | 2.326 |
| SOCFortress Wazuh-Rules | 2.211 |
| Splunk security_content | 2.184 |
| Microsoft Sentinel (Hunting Queries) | 2.180 |
| Cortex XSOAR (demisto/content) | 1.675 |
| Elastic protections-artifacts (behavior) | 1.339 |
| ReversingLabs YARA | 1.240 |
| Panther panther-analysis | 1.151 |
| Google SecOps / Chronicle | 948 |
| Chronicle rules (rowham) | 759 |
| Suricata hunting-rules (travisbgreen) | 719 |
| EVTX-Wazuh-Rules (Sigma export) | 630 |
| awesome-playbooks · ms_azure | 509 |
| Bert-JanP Hunting Queries | 443 |
| Splunk analytic stories | 367 |
| GCP security-analytics | 277 |
| Hayabusa (native) | 196 |
| awesome-playbooks · fortinet | 193 |
| Splunk SOAR / Phantom playbooks | 182 |
| awesome-playbooks · splunk | 155 |
| awesome-playbooks · resolve | 149 |
| Elastic hunting queries | 143 |
| awesome-playbooks · xsoar | 131 |
| Falco rules | 96 |
| awesome-playbooks · tines | 87 |
| Splunk security_content playbooks | 86 |
| awesome-playbooks · logichub | 70 |
| wazuh-detection-engineering (Jeremy-Burgos) | 61 |
| awesome-playbooks · demisto | 59 |
| awesome-playbooks · threat_connect | 53 |
| awesome-playbooks · cisa | 51 |
| QRadar AQL (comunidade) | 30 |
| Shuffle workflows | 23 |
| awesome-playbooks · shuffle | 18 |
| Suricata nmap/OPNsense rules | 10 |
| SpiderLabs malware-analysis (YARA) | 4 |
| awesome-playbooks · chronicle | 4 |
| awesome-playbooks · catalyst | 3 |
| awesome-playbooks · oasis_open | 1 |

## Licenças
O código deste repositório é seu para reutilizar. **Cada regra mantém a licença da fonte original**, exibida na aba *Origem & versões* (DRL 1.1, Apache-2.0, MIT, GPLv2, AGPL-3.0, Elastic License v2, BSD-3). Respeite especialmente GPLv2, AGPL-3.0 e Elastic License v2 antes de redistribuir conteúdo derivado.

**Credenciais mascaradas:** alguns playbooks de terceiros (awesome-playbooks, XSOAR, Shuffle) traziam o que parecem credenciais reais: chaves de API, senhas SMTP, webhooks do Slack e chaves AWS. Na geração dos dados, 226 desses valores viram `REDIGIDO-PELO-DETECTIONRULES` e a ficha da regra avisa. Padrões de detecção (como a string `BEGIN PRIVATE KEY` numa regra YARA) e chaves de exemplo da documentação AWS (`…EXAMPLE`) ficam intactos.

Emerging Threats Open e Snort Community oficiais ficam fora do GitHub e não puderam ser coletados; o catálogo inclui mirrors de Suricata/Snort e as regras Sagan.

## Materiais de referência usados no enriquecimento
MITRE ATT&CK (attack-stix-data) · Atomic Red Team (Red Canary) · EVTX-to-MITRE-Attack (mdecrevoisier) · EVTX-ATTACK-SAMPLES (sbousseaden) · APT & CyberCriminal Campaign Collections (CyberMonitor) · planilha *Malware IR – Tools & Resources* (Cyb3rUltron @ShilpeshTrivedi e Harsh Shah @harshsshah), cópia em `sources/`.
