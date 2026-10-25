# BlackOasis (G0063) — Dossiê de inteligência

> **TLP:CLEAR** · gerado em 2026-10-25 a partir de fontes abertas · MITRE ATT&CK v20.0 · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0063) · [ATT&CK](https://attack.mitre.org/groups/G0063/)

**Também conhecido como:** —  
**Registro no ATT&CK:** criado em 2018-04-18, atualizado em 2026-07-31 · referências de 2017 a 2017

## 1. Sumário executivo

- **1 técnicas** atribuídas publicamente, concentradas em **Stealth**.
- **Arsenal:** 0 malware e 0 ferramentas.
- **Campanhas atribuídas:** 0.
- **Cobertura de detecção pública:** 100% das técnicas têm ao menos uma regra no catálogo; **0 técnicas sem nenhuma regra pública**.
- **Assinatura comportamental** (técnicas raras entre os 178 grupos, as mais úteis para atribuição): T1027 Obfuscated Files or Information.

## 2. Quem é

> BlackOasis is a Middle Eastern threat group that is believed to be a customer of Gamma Group. The group has shown interest in prominent figures in the United Nations, as well as opposition bloggers, activists, regional news correspondents, and think tanks. A group known by Microsoft as NEODYMIUM is reportedly associated closely with BlackOasis operations, but evidence that the group names are aliases has not been identified.

_Texto original do MITRE ATT&CK, em inglês._

## 3. Perfil TTP por tática (kill chain)

Cada linha: técnica, como o grupo a usou segundo relatos públicos, e o que existe para detectar e testar.

### Stealth (TA0005) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1027](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1027) Obfuscated Files or Information | BlackOasis's first stage shellcode contains a NOP sled with alternative instructions that was likely designed to bypass antivirus tools. | 520 | 11 | 5 |

## 4. Assinatura comportamental

Técnicas que este grupo usa e que poucos dos 178 grupos do ATT&CK usam. Pesam mais numa atribuição por TTP: ver várias delas juntas é mais informativo do que ver técnicas comuns como PowerShell.

| Técnica | Outros grupos que usam | Peso (raridade) |
|---|---:|---:|
| T1027 Obfuscated Files or Information | 18 | 2.19 |

## 5. Arsenal

Nenhum software atribuído no ATT&CK.

## 6. Campanhas

Nenhuma campanha atribuída no ATT&CK.

## 7. Cobertura defensiva

**1 de 1 técnicas (100%)** têm ao menos uma regra pública no catálogo Detection Rules.

### Regras recomendadas por técnica

Melhor regra disponível por técnica (formato portável e maduro primeiro).

| Técnica | Regra | Formato | Fonte |
|---|---|---|---|
| T1027 | [Potential Emotet Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad02e8cf5-6099-48cf-9bfc-1eec2d0c7b18) | Sigma | SigmaHQ |
| T1027 | [Emotet Process Creation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Ad02e8cf5-6099-48cf-9bfc-1eec2d0c7b18) | Sigma | OpenSearch Security Analytics |

## 8. Plano de emulação e validação

Use num laboratório isolado e autorizado para confirmar que as regras disparam. Os comandos estão nos repositórios oficiais.

| Tática | Técnica | Teste Atomic Red Team | Plataformas |
|---|---|---|---|
| Stealth | [T1027](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027/T1027.md) | Decode base64 Data into Script | linux, macos |
| Stealth | [T1027](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027/T1027.md) | Execute base64-encoded PowerShell | windows |

**Logs reais de ataque (EVTX) para testar sem executar nada:**

- T1027 — [4624,4674,4688- CrackMap Exec SMB mimikatz](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0005-Defense%20Evasion/T1027-Obfuscated%20Files%20or%20Information/4624%2C4674%2C4688-%20CrackMap%20Exec%20SMB%20mimikatz.evtx) _(explícito)_
- T1027 — [ID1-CrackMapExec payload execution](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0005-Defense%20Evasion/T1027-Obfuscated%20Files%20or%20Information/ID1-CrackMapExec%20payload%20execution.evtx) _(explícito)_

## 9. Hipóteses de hunting

Se BlackOasis estiver no seu ambiente, estas são as perguntas a fazer aos seus dados (fontes de log segundo as estratégias de detecção do MITRE ATT&CK).

1. **T1027 Obfuscated Files or Information** — Correlates script execution or suspicious parent processes with creation or modification of encoded, compressed, or encrypted file formats (e.g., .zip, .7z, .enc) and abnormal command-line syntax or PowerShell obfuscation. Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Sysmon` (EventCode=1).

## 10. OSINT — onde pesquisar

Consultas prontas com todos os nomes conhecidos do grupo:

- Relatórios técnicos: [busca web](https://duckduckgo.com/?q=%28%22BlackOasis%22%29+threat+report) · [PDFs](https://duckduckgo.com/?q=%28%22BlackOasis%22%29+filetype%3Apdf)
- Regras e IOCs publicados: [GitHub](https://github.com/search?type=code&q=%22BlackOasis%22)
- Pulsos de ameaça: [AlienVault OTX](https://otx.alienvault.com/browse/global/pulses?q=BlackOasis)
- Família de malware e atores: [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/actors) (busque por BlackOasis)
- Cartões de grupo: [ThaiCERT Threat Group Cards](https://apt.etda.or.th/cgi-bin/listgroups.cgi)
- Página oficial: [MITRE ATT&CK G0063](https://attack.mitre.org/groups/G0063/)

**Relatórios na coleção CyberMonitor** (ligados pelo nome do grupo, conferir antes de citar):

- 2017 — [BlackOasis](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2017/2017.10.16.BlackOasis_APT/BlackOasis.pdf) _(via “BlackOasis”)_

## 11. Bibliografia (3 fontes citadas pelo ATT&CK)

- [CyberScoop BlackOasis Oct 2017](https://www.cyberscoop.com/middle-eastern-hacking-group-using-finfisher-malware-conduct-international-espionage/) — Bing, C. (2017, October 16). Middle Eastern hacking group is using FinFisher malware to conduct international espionage. Retrieved February 15, 2018.
- [Securelist APT Trends Q2 2017](https://securelist.com/apt-trends-report-q2-2017/79332/) — Kaspersky Lab's Global Research & Analysis Team. (2017, August 8). APT Trends report Q2 2017. Retrieved February 15, 2018.
- [Securelist BlackOasis Oct 2017](https://securelist.com/blackoasis-apt-and-new-targeted-attacks-leveraging-zero-day-exploit/82732/) — Kaspersky Lab's Global Research & Analysis Team. (2017, October 16). BlackOasis APT and new targeted attacks leveraging zero-day exploit. Retrieved February 15, 2018.

## 12. Limites e confiança

- O ATT&CK registra o que foi **relatado publicamente**, não tudo o que o grupo faz. Ausência de uma técnica não prova que o grupo não a usa.
- **Sobreposição de TTP não é atribuição.** Muitas técnicas são compartilhadas entre grupos e com red teams. Use a assinatura comportamental como hipótese, junto com infraestrutura, malware e contexto.
- Cobertura de detecção refere-se ao catálogo público Detection Rules, não ao seu ambiente: confira se a telemetria necessária chega ao seu SIEM.
- Ligações marcadas como _inferidas_ (EVTX por palavra-chave, relatórios por nome) devem ser verificadas.

---
Fontes: MITRE ATT&CK® (uso livre com atribuição, © The MITRE Corporation), Atomic Red Team (Red Canary, MIT), EVTX-to-MITRE-Attack, EVTX-ATTACK-SAMPLES, APT & CyberCriminal Campaign Collections. Gerado por [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules).
