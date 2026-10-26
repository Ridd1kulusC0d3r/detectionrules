# Winnti Group (G0044) — Dossiê de inteligência

> **TLP:CLEAR** · gerado em 2026-10-26 a partir de fontes abertas · MITRE ATT&CK v20.0 · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0044) · [ATT&CK](https://attack.mitre.org/groups/G0044/)

**Também conhecido como:** Blackfly  
**Origem atribuída:** China · **Motivação:** espionagem, financeiro · **Setores-alvo:** Sociedade civil e mídia, Educação e pesquisa, Energia, Financeiro, Governo, Saúde, Infraestrutura crítica, Indústria, Setor privado (genérico), Varejo e hotelaria, Tecnologia, Telecomunicações  
**Registro no ATT&CK:** criado em 2017-05-31, atualizado em 2026-07-31 · referências de 2013 a 2020

## 1. Sumário executivo

- **6 técnicas** atribuídas publicamente, concentradas em **Discovery, Stealth, Command and Control**.
- **Arsenal:** 3 malware e 0 ferramentas (ex.: PlugX, PipeMon, Winnti for Windows).
- **Campanhas atribuídas:** 0.
- **Cobertura de detecção pública:** 100% das técnicas têm ao menos uma regra no catálogo; **0 técnicas sem nenhuma regra pública**.
- **Origem e alvos (APT4ALL):** atribuído a **China**, motivação espionagem, financeiro; setores Sociedade civil e mídia, Educação e pesquisa, Energia, Financeiro, Governo; 16 países vítimas citados.
- **Onde a cobertura está:** Windows (6 técnicas com regra), Outros / genérico (5 técnicas com regra), Linux (4 técnicas com regra), EDR / XDR (4 técnicas com regra).
- **Assinatura comportamental** (técnicas raras entre os 178 grupos, as mais úteis para atribuição): T1014 Rootkit, T1553.002 Code Signing, T1057 Process Discovery, T1583.001 Domains, T1083 File and Directory Discovery.

## 2. Quem é

> Winnti Group is a threat group with Chinese origins that has been active since at least 2010. The group has heavily targeted the gaming industry, but it has also expanded the scope of its targeting. Some reporting suggests a number of other groups, including Axiom, APT17, and Ke3chang, are closely linked to Winnti Group.

_Texto original do MITRE ATT&CK, em inglês._

## 3. Contexto, nomes e alvos

Consolidado pelo [APT4ALL](https://github.com/Ridd1kulusC0d3r/apt4all) a partir de MISP Galaxy, planilha APT Groups & Operations, EternalLiberty e APTnotes. Atribuição é afirmação de quem publicou; confira a fonte.

| Campo | Valor |
|---|---|
| Origem atribuída | China |
| Motivação | espionagem, financeiro |
| Setores-alvo | Sociedade civil e mídia, Educação e pesquisa, Energia, Financeiro, Governo, Saúde, Infraestrutura crítica, Indústria, Setor privado (genérico), Varejo e hotelaria, Tecnologia, Telecomunicações |
| Vítimas citadas | China, France, Hong Kong, India, Italy, Japan, Myanmar, Netherlands, Singapore, South Africa, South Korea, Switzerland, Thailand, Turkey, United Kingdom, United States |
| Alvos (planilha) | ThyssenKrupp, Gameforge, Valve, Teamviewer,Siemens, Sumitomo, BASF, Covestro, Shin-Etsu, Bayer, Roche \| Electronic gaming, multimedia, Internet content industries, technology companies \| Multinational, multi-industry companies, textiles, chemicals, electronics, pharmaceutical companies, manufacturing |
| Operações conhecidas | — |
| Confiança de atribuição (MISP) | High |

**Como cada fornecedor chama este grupo** (útil para cruzar relatórios):

| Fornecedor | Nome(s) |
|---|---|
| CrowdStrike | Wicked Panda |
| MITRE ATT&CK | G0044 |
| Mandiant | APT41 |
| Microsoft | Brass Typhoon, BARIUM (antigo · old) |
| Secureworks | BRONZE ATLAS, TG-2633 |

**Outros nomes no APT4ALL (não listados pelo ATT&CK):** Wicked Panda, BRONZE ATLAS, APT41, Winnti Umbrella, BARIUM, LEAD, RedEcho, Vanadinite, TAG-22, TG-2633, TA415, Grayfly, WICKED SPIDER, BRONZE EXPORT, Red Kelpie, Earth Baku, Amoeba, HOODOO, Brass Typhoon, Winnti, Double Dragon, Leopard Typhoon, SPIRE CASTLE, Wicked Panda/Vault Panda, Barium/Brass Typhoon, G0044/G0096, CTG-2633/TG-2633/TG-3279, Red Kelpie/Red Diablo, Blackfly/Grayfly/Redfly, TAG-28, REF2924

## 4. Perfil TTP por tática (kill chain)

Cada linha: técnica, como o grupo a usou segundo relatos públicos, e o que existe para detectar e testar.

### Resource Development (TA0042) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1583.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1583.001) Domains | Winnti Group has registered domains for C2 that mimicked sites of their intended targets. | 7 | — | — |

### Stealth (TA0005) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1014](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1014) Rootkit | Winnti Group used a rootkit to modify typical server functionality. | 44 | 4 | — |

### Defense Impairment (TA0112) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1553.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1553.002) Code Signing | Winnti Group used stolen certificates to sign its malware. | 11 | — | — |

### Discovery (TA0007) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1057](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1057) Process Discovery | Winnti Group looked for a specific process running on infected servers. | 82 | 10 | — |
| [T1083](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1083) File and Directory Discovery | Winnti Group has used a program named ff.exe to search for specific documents on compromised hosts. | 137 | 9 | — |

### Command and Control (TA0011) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1105](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1105) Ingress Tool Transfer | Winnti Group has downloaded an auxiliary program named ff.exe to infected machines. | 644 | 39 | — |

## 5. Assinatura comportamental

Técnicas que este grupo usa e que poucos dos 178 grupos do ATT&CK usam. Pesam mais numa atribuição por TTP: ver várias delas juntas é mais informativo do que ver técnicas comuns como PowerShell.

| Técnica | Outros grupos que usam | Peso (raridade) |
|---|---:|---:|
| T1014 Rootkit | 5 | 3.24 |
| T1553.002 Code Signing | 27 | 1.82 |
| T1057 Process Discovery | 41 | 1.43 |
| T1583.001 Domains | 47 | 1.30 |
| T1083 File and Directory Discovery | 51 | 1.22 |
| T1105 Ingress Tool Transfer | 89 | 0.68 |

## 6. Arsenal

| Software | Tipo | Técnicas no ATT&CK | Uso relatado (EN) |
|---|---|---:|---|
| [PlugX](https://attack.mitre.org/software/S0013/) | malware | 49 |  |
| [PipeMon](https://attack.mitre.org/software/S0501/) | malware | 23 |  |
| [Winnti for Windows](https://attack.mitre.org/software/S0141/) | malware | 22 |  |

**Outras ferramentas e malware relatados (planilha APT Groups & Operations / MISP):** Winnti, AceHash, Webshells, ZxShell, ShadowPad, LightSpy, Winnti Rootkit malware

## 7. Campanhas

Nenhuma campanha atribuída no ATT&CK.

## 8. Cobertura defensiva

**6 de 6 técnicas (100%)** têm ao menos uma regra pública no catálogo Detection Rules.

### Onde procurar — cobertura por tecnologia

Quantas técnicas deste grupo têm ao menos uma regra em cada tecnologia. Comece a caça pelas tecnologias que você tem e que aparecem aqui.

| Tecnologia | Técnicas do grupo com regra |
|---|---:|
| Windows | 6 |
| Outros / genérico | 5 |
| Linux | 4 |
| EDR / XDR | 4 |
| Firewall & perímetro | 4 |
| Contêineres (Docker/runtime) | 3 |
| Servidores web & aplicações | 3 |
| macOS | 3 |
| Dispositivos de rede | 3 |
| Virtualização (ESXi/vSphere/Hyper-V) | 3 |
| AWS | 3 |
| Microsoft 365 | 3 |

### Regras recomendadas por técnica

Melhor regra disponível por técnica (formato portável e maduro primeiro).

| Técnica | Regra | Formato | Fonte |
|---|---|---|---|
| T1014 | [Triple Cross eBPF Rootkit Install Commands](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A22236d75-d5a0-4287-bf06-c93b1770860f) | Sigma | SigmaHQ |
| T1014 | [Triple Cross eBPF Rootkit Install Commands](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A22236d75-d5a0-4287-bf06-c93b1770860f) | Sigma | OpenSearch Security Analytics |
| T1057 | [Process Discovery](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4e2f5868-08d4-413d-899f-dc2f1508627b) | Sigma | SigmaHQ |
| T1057 | [HackTool - PCHunter Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Afca949cc-79ca-446e-8064-01aa7e52ece5) | Sigma | SigmaHQ |
| T1083 | [Turla Group Lateral Movement](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac601f20d-570a-4cde-a7d6-e17f99cb8e7f) | Sigma | SigmaHQ |
| T1083 | [WannaCry Ransomware Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A41d40bff-377a-43e2-8e1b-2e543069e079) | Sigma | SigmaHQ |
| T1105 | [Greenbug Espionage Group Indicators](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A3711eee4-a808-4849-8a14-faf733da3612) | Sigma | SigmaHQ |
| T1105 | [Pandemic Registry Key](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A47e0852a-cf81-4494-a8e6-31864f8c86ed) | Sigma | SigmaHQ |
| T1553.002 | [Driver Loaded (Invalid Signature)](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=hayabusa-native%3A%3A1f666722-3948-40a2-9d78-d9d374477a90) | Sigma | Hayabusa (native) |
| T1553.002 | [Driver Loaded (Expired/Revoked Cert)](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=hayabusa-native%3A%3Ac837dd6d-0c91-4593-aeab-f6a1f3ca1961) | Sigma | Hayabusa (native) |
| T1583.001 | [AWS Route 53 Private Hosted Zone Associated With a VPC](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ae3c27562-709a-42bd-82f2-3ed926cced19) | Elastic | Elastic detection-rules |
| T1583.001 | [AWS SES Email Identity Verified Then Deleted](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A8e4bde35-125d-4eb3-9a2e-d7e77a053a08) | Elastic | Elastic detection-rules |

## 9. Plano de emulação e validação

Use num laboratório isolado e autorizado para confirmar que as regras disparam. Os comandos estão nos repositórios oficiais.

| Tática | Técnica | Teste Atomic Red Team | Plataformas |
|---|---|---|---|
| Stealth | [T1014](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1014/T1014.md) | Loadable Kernel Module based Rootkit | linux |
| Stealth | [T1014](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1014/T1014.md) | Loadable Kernel Module based Rootkit | linux |
| Discovery | [T1057](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1057/T1057.md) | Process Discovery - ps | linux, macos |
| Discovery | [T1057](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1057/T1057.md) | Process Discovery - tasklist | windows |
| Discovery | [T1083](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1083/T1083.md) | File and Directory Discovery (cmd.exe) | windows |
| Discovery | [T1083](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1083/T1083.md) | File and Directory Discovery (PowerShell) | windows |
| Command and Control | [T1105](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1105/T1105.md) | rsync remote file copy (push) | linux, macos |
| Command and Control | [T1105](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1105/T1105.md) | rsync remote file copy (pull) | linux, macos |

## 10. Hipóteses de hunting

Se Winnti Group estiver no seu ambiente, estas são as perguntas a fazer aos seus dados (fontes de log segundo as estratégias de detecção do MITRE ATT&CK).

1. **T1014 Rootkit** — Unauthorized or anomalous loading of kernel-mode drivers or DLLs, concealed services, or abnormal modification of boot components indicative of rootkit activity. Dados: `WinEventLog:Sysmon` (EventCode=6), `WinEventLog:System` (EventCode=7045), `WinEventLog:Sysmon` (EventCode=11).
2. **T1553.002 Code Signing** — Detects execution of binaries signed with unusual or recently issued certificates, correlation of process execution with abnormal publisher metadata, and mismatched certificate chains. Monitors for revoked or unknown code signing certificates used in… Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=7).
3. **T1057 Process Discovery** — Identifies adversary behavior that launches commands or invokes APIs to enumerate active processes (e.g., tasklist.exe, Get-Process, or CreateToolhelp32Snapshot). Detects execution combined with parent process lineage, network session context, or remote… Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=10).
4. **T1583.001 Domains** — Monitor logged domain name system (DNS) data for purchased domains that can be used during targeting. Reputation/category-based detection may be difficult until the categorization is updated. Detection efforts may be focused on related stages of the adversary… Dados: `Domain Name` (None), `Domain Name` (None), `Domain Name` (None).
5. **T1083 File and Directory Discovery** — Execution of file enumeration commands (e.g., 'dir', 'tree') from non-standard processes or unusual user contexts, followed by recursive directory traversal or access to sensitive locations. Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=11).
6. **T1105 Ingress Tool Transfer** — Unusual or uncommon processes initiate network connections to external destinations followed by file creation (tools downloaded). Dados: `WinEventLog:Sysmon` (EventCode=3, 22), `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Sysmon` (EventCode=1).

## 11. OSINT — onde pesquisar

Consultas prontas com todos os nomes conhecidos do grupo:

- Relatórios técnicos: [busca web](https://duckduckgo.com/?q=%28%22Winnti+Group%22+OR+%22Blackfly%22%29+threat+report) · [PDFs](https://duckduckgo.com/?q=%28%22Winnti+Group%22+OR+%22Blackfly%22%29+filetype%3Apdf)
- Regras e IOCs publicados: [GitHub](https://github.com/search?type=code&q=%22Winnti+Group%22+OR+%22Blackfly%22)
- Pulsos de ameaça: [AlienVault OTX](https://otx.alienvault.com/browse/global/pulses?q=Winnti+Group)
- Família de malware e atores: [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/actors) (busque por Winnti Group, Blackfly)
- Cartões de grupo: [ThaiCERT Threat Group Cards](https://apt.etda.or.th/cgi-bin/listgroups.cgi)
- Página oficial: [MITRE ATT&CK G0044](https://attack.mitre.org/groups/G0044/)

**Relatórios na coleção CyberMonitor** (ligados pelo nome do grupo, conferir antes de citar):

- 2019 — [ESET_Winnti](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2019/2019.10.10.Winnti_Group/ESET_Winnti.pdf) _(via “Winnti Group”)_
- 2020 — [welivesecurity.com-Winnti Group targeting universities in Hong Kong](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2020/2020.01.31.Winnti_universities_in_HK/welivesecurity.com-Winnti%20Group%20targeting%20universities%20in%20Hong%20Kong.pdf) _(via “Winnti Group”)_
- 2020 — [WINNTI GROUP_ Insights From the Past](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2020/2020.04.20_Winnti_from_the_past/WINNTI%20GROUP_%20Insights%20From%20the%20Past.pdf) _(via “Winnti Group”)_
- 2020 — [2020.09.29_ShadowPad - new activity from the Winnti group](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2020/2020.09.29_ShadowPad_-_new_activity_from_the_Winnti_group/2020.09.29_ShadowPad%20-%20new%20activity%20from%20the%20Winnti%20group.pdf) _(via “Winnti Group”)_

**Relatórios públicos ligados pelo APT4ALL** (11 no total, mais recentes primeiro):

- 2023 — [Blackfly: Espionage Group Targets Materials Technology](https://app.box.com/s/haoo75g6usi9rbje6mdi9618lqglo1vz) _(Symantec)_
- 2022 — [A Summary of APT41 Targeting U.S. State Governments](https://app.box.com/s/jtahutqqimavakqi7ynau7sdxrvrsw3s) _(Mandiant)_
- 2021 — [APT41 Resurfaces as Earth Baku With New Cyberespionage Campaign](https://app.box.com/s/qtqlwejty7xz8wj8osz98webycgo5j9x) _(Trend Micro)_
- 2020 — [This Is Not a Test: APT41 Initiates Global Intrusion Campaign Using Multiple Exploits](https://app.box.com/s/fiy6f8qswv4yn57kj40gjd56k324vwli) _(Fireeye)_
- 2019 — [GAME OVER: Detecting and Stopping an APT41 Operation](https://app.box.com/s/tm7vgs6gp84kz44xee2oh8xdqesnnmn5) _(FireEye)_
- 2019 — [APT41: A Dual Espionage and Cyber Crime Operation](https://app.box.com/s/tijt08320isuaywxn1swd2uvbus7v7zl) _(FireEye)_
- 2019 — [APT41: A Dual Espionage and Cyber Crime Operation](https://app.box.com/s/0pvkz8uf1ozvinoec0sufupzzhblkumn) _(FireEye)_
- 2015 — [Games Are Over: Winnti Is Now Targeting Pharmaceutical Companies](https://app.box.com/s/f090ea4pi40hoaxe6otzfw7yl65ylw6y) _(Kaspersky)_
- 2015 — [WINNTI Analysis](https://app.box.com/s/tv5rhy7awdq8ecfrugcrk1d4zcce3xnq) _(Novetta)_
- 2015 — [Backdoor.Winnti Attackers Have A Skeleton In Their Closet?](https://app.box.com/s/89pqnoimwdkrmyhxwqj5pp17jtjm4lmc) _(Symantec)_
- 2013 — [Winnti: More Than Just A Game](https://app.box.com/s/dlzp6f7hv9q3r0kreqvu8yyt36lzdbxw) _(Kaspersky)_

## 12. Bibliografia (6 fontes citadas pelo ATT&CK)

- [401 TRG Winnti Umbrella May 2018](https://401trg.github.io/pages/burning-umbrella.html) — Hegel, T. (2018, May 3). Burning Umbrella: An Intelligence Report on the Winnti Umbrella and Associated State-Sponsored Attackers. Retrieved July 8, 2018.
- [ESET PipeMon May 2020](https://www.welivesecurity.com/2020/05/21/no-game-over-winnti-group/) — Tartare, M. et al. (2020, May 21). No “Game over” for the Winnti Group. Retrieved August 24, 2020.
- [Kaspersky Winnti April 2013](https://securelist.com/winnti-more-than-just-a-game/37029/) — Kaspersky Lab's Global Research and Analysis Team. (2013, April 11). Winnti. More than just a game. Retrieved February 8, 2017.
- [Kaspersky Winnti June 2015](https://securelist.com/games-are-over/70991/) — Tarakanov, D. (2015, June 22). Games are over: Winnti is now targeting pharmaceutical companies. Retrieved January 14, 2016.
- [Novetta Winnti April 2015](https://web.archive.org/web/20150412223949/http://www.novetta.com/wp-content/uploads/2015/04/novetta_winntianalysis.pdf) — Novetta Threat Research Group. (2015, April 7). Winnti Analysis. Retrieved February 8, 2017.
- [Symantec Suckfly March 2016](http://www.symantec.com/connect/blogs/suckfly-revealing-secret-life-your-code-signing-certificates) — DiMaggio, J. (2016, March 15). Suckfly: Revealing the secret life of your code signing certificates. Retrieved August 3, 2016.

## 13. Limites e confiança

- O ATT&CK registra o que foi **relatado publicamente**, não tudo o que o grupo faz. Ausência de uma técnica não prova que o grupo não a usa.
- **Sobreposição de TTP não é atribuição.** Muitas técnicas são compartilhadas entre grupos e com red teams. Use a assinatura comportamental como hipótese, junto com infraestrutura, malware e contexto.
- Cobertura de detecção refere-se ao catálogo público Detection Rules, não ao seu ambiente: confira se a telemetria necessária chega ao seu SIEM.
- Ligações marcadas como _inferidas_ (EVTX por palavra-chave, relatórios por nome) devem ser verificadas.

---
Fontes: MITRE ATT&CK® (uso livre com atribuição, © The MITRE Corporation), APT4ALL (MISP Galaxy CC0/BSD-2, APT Groups & Operations CC BY 4.0, EternalLiberty, APTnotes, Ransomware Tool Matrix CC BY 4.0), Atomic Red Team (Red Canary, MIT), EVTX-to-MITRE-Attack, EVTX-ATTACK-SAMPLES, APT & CyberCriminal Campaign Collections. Gerado por [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules).
