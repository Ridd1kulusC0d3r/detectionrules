# TEMP.Veles (G0088) — Dossiê de inteligência

> **TLP:CLEAR** · gerado em 2026-10-26 a partir de fontes abertas · MITRE ATT&CK v20.0 · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0088) · [ATT&CK](https://attack.mitre.org/groups/G0088/)

**Também conhecido como:** XENOTIME  
**Origem atribuída:** Rússia · **Motivação:** indefinido · **Setores-alvo:** Energia  
**Registro no ATT&CK:** criado em 2019-04-16, atualizado em 2026-07-31 · referências de 2018 a 2019

## 1. Sumário executivo

- **0 técnicas** atribuídas publicamente, concentradas em **—**.
- **Arsenal:** 0 malware e 2 ferramentas (ex.: Mimikatz, PsExec).
- **Campanhas atribuídas:** 2 (C0032, Triton Safety Instrumented System Attack).
- **Cobertura de detecção pública:** 0% das técnicas têm ao menos uma regra no catálogo; **0 técnicas sem nenhuma regra pública**.
- **Origem e alvos (APT4ALL):** atribuído a **Rússia**, motivação indefinido; setores Energia.
- **Assinatura comportamental** (técnicas raras entre os 178 grupos, as mais úteis para atribuição): .

## 2. Quem é

> TEMP.Veles is a Russia-based threat group that has targeted critical infrastructure. The group has been observed utilizing TRITON, a malware framework designed to manipulate industrial safety systems.

_Texto original do MITRE ATT&CK, em inglês._

## 3. Contexto, nomes e alvos

Consolidado pelo [APT4ALL](https://github.com/Ridd1kulusC0d3r/apt4all) a partir de MISP Galaxy, planilha APT Groups & Operations, EternalLiberty e APTnotes. Atribuição é afirmação de quem publicou; confira a fonte.

| Campo | Valor |
|---|---|
| Origem atribuída | Rússia |
| Motivação | indefinido |
| Setores-alvo | Energia |
| Vítimas citadas | — |
| Alvos (planilha) | Oil refinery, other infrastructure |
| Operações conhecidas | — |
| Confiança de atribuição (MISP) | High |

**Como cada fornecedor chama este grupo** (útil para cruzar relatórios):

| Fornecedor | Nome(s) |
|---|---|
| MITRE ATT&CK | G0088 |

**Outros nomes no APT4ALL (não listados pelo ATT&CK):** Triton, TRISIS, ATK91, TRITON Group

## 4. Perfil TTP por tática (kill chain)

Cada linha: técnica, como o grupo a usou segundo relatos públicos, e o que existe para detectar e testar.

## 5. Assinatura comportamental

Técnicas que este grupo usa e que poucos dos 178 grupos do ATT&CK usam. Pesam mais numa atribuição por TTP: ver várias delas juntas é mais informativo do que ver técnicas comuns como PowerShell.

| Técnica | Outros grupos que usam | Peso (raridade) |
|---|---:|---:|

## 6. Arsenal

| Software | Tipo | Técnicas no ATT&CK | Uso relatado (EN) |
|---|---|---:|---|
| [Mimikatz](https://attack.mitre.org/software/S0002/) | ferramenta | 17 |  |
| [PsExec](https://attack.mitre.org/software/S0029/) | ferramenta | 5 |  |

**Outras ferramentas e malware relatados (planilha APT Groups & Operations / MISP):** Triton

## 7. Campanhas

| Campanha | Período | Resumo (EN) |
|---|---|---|
| [C0032](https://attack.mitre.org/campaigns/C0032/) | 2014-10 → 2017-01 | C0032 was an extended campaign suspected to involve the Triton adversaries with related capabilities and techniques focused on gaining a foothold within IT environments. This campaign occurred in 2019 and was distinctly  |
| [Triton Safety Instrumented System Attack](https://attack.mitre.org/campaigns/C0030/) | 2017-06 → 2017-08 | Triton Safety Instrumented System Attack was a campaign employed by TEMP.Veles which leveraged the Triton malware framework against a petrochemical organization. The malware and techniques used within this campaign targe |

## 8. Cobertura defensiva

**0 de 0 técnicas (0%)** têm ao menos uma regra pública no catálogo Detection Rules.

### Regras recomendadas por técnica

Melhor regra disponível por técnica (formato portável e maduro primeiro).

| Técnica | Regra | Formato | Fonte |
|---|---|---|---|

## 9. Plano de emulação e validação

Use num laboratório isolado e autorizado para confirmar que as regras disparam. Os comandos estão nos repositórios oficiais.


## 10. Hipóteses de hunting

Se TEMP.Veles estiver no seu ambiente, estas são as perguntas a fazer aos seus dados (fontes de log segundo as estratégias de detecção do MITRE ATT&CK).


## 11. OSINT — onde pesquisar

Consultas prontas com todos os nomes conhecidos do grupo:

- Relatórios técnicos: [busca web](https://duckduckgo.com/?q=%28%22TEMP.Veles%22+OR+%22XENOTIME%22%29+threat+report) · [PDFs](https://duckduckgo.com/?q=%28%22TEMP.Veles%22+OR+%22XENOTIME%22%29+filetype%3Apdf)
- Regras e IOCs publicados: [GitHub](https://github.com/search?type=code&q=%22TEMP.Veles%22+OR+%22XENOTIME%22)
- Pulsos de ameaça: [AlienVault OTX](https://otx.alienvault.com/browse/global/pulses?q=TEMP.Veles)
- Família de malware e atores: [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/actors) (busque por TEMP.Veles, XENOTIME)
- Cartões de grupo: [ThaiCERT Threat Group Cards](https://apt.etda.or.th/cgi-bin/listgroups.cgi)
- Página oficial: [MITRE ATT&CK G0088](https://attack.mitre.org/groups/G0088/)

**Relatórios públicos ligados pelo APT4ALL** (2 no total, mais recentes primeiro):

- 2017 — [TRISIS Malware](https://app.box.com/s/lczcjm4izqlu3fuve5lf7yof2gpcxn0h) _(Dragos)_
- 2017 — [Attackers Deploy New ICS Attack Framework "TRITON" and Cause Operational Disruption to Critical Infrastructure](https://app.box.com/s/yvlm1esfazyp5ktx6ximkj2l9nkh6sk9) _(FireEye)_

## 12. Bibliografia (5 fontes citadas pelo ATT&CK)

- [Dragos Xenotime 2018](https://dragos.com/resource/xenotime/) — Dragos, Inc.. (n.d.). Xenotime. Retrieved April 16, 2019.
- [FireEye TEMP.Veles 2018](https://www.fireeye.com/blog/threat-research/2018/10/triton-attribution-russian-government-owned-lab-most-likely-built-tools.html) — FireEye Intelligence . (2018, October 23). TRITON Attribution: Russian Government-Owned Lab Most Likely Built Custom Intrusion Tools for TRITON Attackers. Retrieved April 16, 2019.
- [FireEye TEMP.Veles JSON April 2019](https://www.fireeye.com/content/dam/fireeye-www/blog/files/TRITON_Appendix_C.html) — Miller, S., et al. (2019, April 10). TRITON Appendix C. Retrieved April 29, 2019.
- [FireEye TRITON 2019](https://www.fireeye.com/blog/threat-research/2019/04/triton-actor-ttp-profile-custom-attack-tools-detections.html) — Miller, S, et al. (2019, April 10). TRITON Actor TTP Profile, Custom Attack Tools, Detections, and ATT&CK Mapping. Retrieved April 16, 2019.
- [Pylos Xenotime 2019](https://pylos.co/2019/04/12/a-xenotime-to-remember-veles-in-the-wild/) — Slowik, J.. (2019, April 12). A XENOTIME to Remember: Veles in the Wild. Retrieved April 16, 2019.

## 13. Limites e confiança

- O ATT&CK registra o que foi **relatado publicamente**, não tudo o que o grupo faz. Ausência de uma técnica não prova que o grupo não a usa.
- **Sobreposição de TTP não é atribuição.** Muitas técnicas são compartilhadas entre grupos e com red teams. Use a assinatura comportamental como hipótese, junto com infraestrutura, malware e contexto.
- Cobertura de detecção refere-se ao catálogo público Detection Rules, não ao seu ambiente: confira se a telemetria necessária chega ao seu SIEM.
- Ligações marcadas como _inferidas_ (EVTX por palavra-chave, relatórios por nome) devem ser verificadas.

---
Fontes: MITRE ATT&CK® (uso livre com atribuição, © The MITRE Corporation), APT4ALL (MISP Galaxy CC0/BSD-2, APT Groups & Operations CC BY 4.0, EternalLiberty, APTnotes, Ransomware Tool Matrix CC BY 4.0), Atomic Red Team (Red Canary, MIT), EVTX-to-MITRE-Attack, EVTX-ATTACK-SAMPLES, APT & CyberCriminal Campaign Collections. Gerado por [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules).
