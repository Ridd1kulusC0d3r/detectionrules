# DragonOK (G0017) — Dossiê de inteligência

> **TLP:CLEAR** · gerado em 2026-10-26 a partir de fontes abertas · MITRE ATT&CK v20.0 · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0017) · [ATT&CK](https://attack.mitre.org/groups/G0017/)

**Também conhecido como:** —  
**Origem atribuída:** China · **Motivação:** indefinido · **Setores-alvo:** Varejo e hotelaria  
**Registro no ATT&CK:** criado em 2017-05-31, atualizado em 2026-07-31 · referências de 2014 a 2015

## 1. Sumário executivo

- **0 técnicas** atribuídas publicamente, concentradas em **—**.
- **Arsenal:** 2 malware e 0 ferramentas (ex.: PlugX, PoisonIvy).
- **Campanhas atribuídas:** 0.
- **Cobertura de detecção pública:** 0% das técnicas têm ao menos uma regra no catálogo; **0 técnicas sem nenhuma regra pública**.
- **Origem e alvos (APT4ALL):** atribuído a **China**, motivação indefinido; setores Varejo e hotelaria.
- **Assinatura comportamental** (técnicas raras entre os 178 grupos, as mais úteis para atribuição): .

## 2. Quem é

> DragonOK is a threat group that has targeted Japanese organizations with phishing emails. Due to overlapping TTPs, including similar custom tools, DragonOK is thought to have a direct or indirect relationship with the threat group Moafee. It is known to use a variety of malware, including Sysget/HelloBridge, PlugX, PoisonIvy, FormerFirstRat, NFlog, and NewCT.

_Texto original do MITRE ATT&CK, em inglês._

## 3. Contexto, nomes e alvos

Consolidado pelo [APT4ALL](https://github.com/Ridd1kulusC0d3r/apt4all) a partir de MISP Galaxy, planilha APT Groups & Operations, EternalLiberty e APTnotes. Atribuição é afirmação de quem publicou; confira a fonte.

| Campo | Valor |
|---|---|
| Origem atribuída | China |
| Motivação | indefinido |
| Setores-alvo | Varejo e hotelaria |
| Vítimas citadas | — |
| Alvos (planilha) | Japan, SE Asia casino & gaming |
| Operações conhecidas | — |
| Confiança de atribuição (MISP) | — |

**Como cada fornecedor chama este grupo** (útil para cruzar relatórios):

| Fornecedor | Nome(s) |
|---|---|
| FireEye | DragonOK |
| MITRE ATT&CK | G0017 |
| Palo Alto Unit 42 | DragonOK |

**Outros nomes no APT4ALL (não listados pelo ATT&CK):** Dragon Castling

## 4. Perfil TTP por tática (kill chain)

Cada linha: técnica, como o grupo a usou segundo relatos públicos, e o que existe para detectar e testar.

## 5. Assinatura comportamental

Técnicas que este grupo usa e que poucos dos 178 grupos do ATT&CK usam. Pesam mais numa atribuição por TTP: ver várias delas juntas é mais informativo do que ver técnicas comuns como PowerShell.

| Técnica | Outros grupos que usam | Peso (raridade) |
|---|---:|---:|

## 6. Arsenal

| Software | Tipo | Técnicas no ATT&CK | Uso relatado (EN) |
|---|---|---:|---|
| [PlugX](https://attack.mitre.org/software/S0013/) | malware | 49 |  |
| [PoisonIvy](https://attack.mitre.org/software/S0012/) | malware | 15 |  |

**Outras ferramentas e malware relatados (planilha APT Groups & Operations / MISP):** CVE-2015-1641, Sysget, IsSpace, Rambo Backdoor

## 7. Campanhas

Nenhuma campanha atribuída no ATT&CK.

## 8. Cobertura defensiva

**0 de 0 técnicas (0%)** têm ao menos uma regra pública no catálogo Detection Rules.

### Regras recomendadas por técnica

Melhor regra disponível por técnica (formato portável e maduro primeiro).

| Técnica | Regra | Formato | Fonte |
|---|---|---|---|

## 9. Plano de emulação e validação

Use num laboratório isolado e autorizado para confirmar que as regras disparam. Os comandos estão nos repositórios oficiais.


## 10. Hipóteses de hunting

Se DragonOK estiver no seu ambiente, estas são as perguntas a fazer aos seus dados (fontes de log segundo as estratégias de detecção do MITRE ATT&CK).


## 11. OSINT — onde pesquisar

Consultas prontas com todos os nomes conhecidos do grupo:

- Relatórios técnicos: [busca web](https://duckduckgo.com/?q=%28%22DragonOK%22%29+threat+report) · [PDFs](https://duckduckgo.com/?q=%28%22DragonOK%22%29+filetype%3Apdf)
- Regras e IOCs publicados: [GitHub](https://github.com/search?type=code&q=%22DragonOK%22)
- Pulsos de ameaça: [AlienVault OTX](https://otx.alienvault.com/browse/global/pulses?q=DragonOK)
- Família de malware e atores: [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/actors) (busque por DragonOK)
- Cartões de grupo: [ThaiCERT Threat Group Cards](https://apt.etda.or.th/cgi-bin/listgroups.cgi)
- Página oficial: [MITRE ATT&CK G0017](https://attack.mitre.org/groups/G0017/)

**Relatórios na coleção CyberMonitor** (ligados pelo nome do grupo, conferir antes de citar):

- 2017 — [Deep Dive on the DragonOK Rambo Backdoor _ Morphick Cyber Security](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2017/2017.02.15.deep-dive-dragonok-rambo-backdoor/Deep%20Dive%20on%20the%20DragonOK%20Rambo%20Backdoor%20_%20Morphick%20Cyber%20Security.pdf) _(via “DragonOK”)_

**Relatórios públicos ligados pelo APT4ALL** (2 no total, mais recentes primeiro):

- 2022 — [Operation Dragon Castling: APT group targeting betting companies](https://app.box.com/s/xtmf4vkiyrwbnyk9dp0aa3v3aoe7zoc9) _(Avast)_
- 2017 — [DragonOK Updates Toolset and Targets Multiple Geographic Regions](https://app.box.com/s/50tu7yfcrcj3ntj6b894rq6londdps34) _(Palo Alto Networks)_

## 12. Bibliografia (2 fontes citadas pelo ATT&CK)

- [New DragonOK](http://researchcenter.paloaltonetworks.com/2015/04/unit-42-identifies-new-dragonok-backdoor-malware-deployed-against-japanese-targets/) — Miller-Osborn, J., Grunzweig, J.. (2015, April). Unit 42 Identifies New DragonOK Backdoor Malware Deployed Against Japanese Targets. Retrieved November 4, 2015.
- [Operation Quantum Entanglement](https://web.archive.org/web/20210920193513/https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/wp-operation-quantum-entanglement.pdf) — Haq, T., Moran, N., Vashisht, S., Scott, M. (2014, September). OPERATION QUANTUM ENTANGLEMENT. Retrieved November 17, 2024.

## 13. Limites e confiança

- O ATT&CK registra o que foi **relatado publicamente**, não tudo o que o grupo faz. Ausência de uma técnica não prova que o grupo não a usa.
- **Sobreposição de TTP não é atribuição.** Muitas técnicas são compartilhadas entre grupos e com red teams. Use a assinatura comportamental como hipótese, junto com infraestrutura, malware e contexto.
- Cobertura de detecção refere-se ao catálogo público Detection Rules, não ao seu ambiente: confira se a telemetria necessária chega ao seu SIEM.
- Ligações marcadas como _inferidas_ (EVTX por palavra-chave, relatórios por nome) devem ser verificadas.

---
Fontes: MITRE ATT&CK® (uso livre com atribuição, © The MITRE Corporation), APT4ALL (MISP Galaxy CC0/BSD-2, APT Groups & Operations CC BY 4.0, EternalLiberty, APTnotes, Ransomware Tool Matrix CC BY 4.0), Atomic Red Team (Red Canary, MIT), EVTX-to-MITRE-Attack, EVTX-ATTACK-SAMPLES, APT & CyberCriminal Campaign Collections. Gerado por [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules).
