# Scarlet Mimic (G0029) — Dossiê de inteligência

> **TLP:CLEAR** · gerado em 2026-10-25 a partir de fontes abertas · MITRE ATT&CK v20.0 · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0029) · [ATT&CK](https://attack.mitre.org/groups/G0029/)

**Também conhecido como:** —  
**Registro no ATT&CK:** criado em 2017-05-31, atualizado em 2026-07-31 · referências de 2016 a 2016

## 1. Sumário executivo

- **1 técnicas** atribuídas publicamente, concentradas em **Stealth**.
- **Arsenal:** 4 malware e 0 ferramentas (ex.: MobileOrder, Psylo, FakeM, CallMe).
- **Campanhas atribuídas:** 0.
- **Cobertura de detecção pública:** 100% das técnicas têm ao menos uma regra no catálogo; **0 técnicas sem nenhuma regra pública**.
- **Assinatura comportamental** (técnicas raras entre os 178 grupos, as mais úteis para atribuição): T1036.002 Right-to-Left Override.

## 2. Quem é

> Scarlet Mimic is a threat group that has targeted minority rights activists. This group has not been directly linked to a government source, but the group's motivations appear to overlap with those of the Chinese government. While there is some overlap between IP addresses used by Scarlet Mimic and Putter Panda, it has not been concluded that the groups are the same.

_Texto original do MITRE ATT&CK, em inglês._

## 3. Perfil TTP por tática (kill chain)

Cada linha: técnica, como o grupo a usou segundo relatos públicos, e o que existe para detectar e testar.

### Stealth (TA0005) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1036.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1036.002) Right-to-Left Override | Scarlet Mimic has used the left-to-right override character in self-extracting RAR archive spearphishing attachment file names. | 18 | 2 | — |

## 4. Assinatura comportamental

Técnicas que este grupo usa e que poucos dos 178 grupos do ATT&CK usam. Pesam mais numa atribuição por TTP: ver várias delas juntas é mais informativo do que ver técnicas comuns como PowerShell.

| Técnica | Outros grupos que usam | Peso (raridade) |
|---|---:|---:|
| T1036.002 Right-to-Left Override | 4 | 3.40 |

## 5. Arsenal

| Software | Tipo | Técnicas no ATT&CK | Uso relatado (EN) |
|---|---|---:|---|
| [MobileOrder](https://attack.mitre.org/software/S0079/) | malware | 7 |  |
| [Psylo](https://attack.mitre.org/software/S0078/) | malware | 5 |  |
| [FakeM](https://attack.mitre.org/software/S0076/) | malware | 4 |  |
| [CallMe](https://attack.mitre.org/software/S0077/) | malware | 4 |  |

## 6. Campanhas

Nenhuma campanha atribuída no ATT&CK.

## 7. Cobertura defensiva

**1 de 1 técnicas (100%)** têm ao menos uma regra pública no catálogo Detection Rules.

### Regras recomendadas por técnica

Melhor regra disponível por técnica (formato portável e maduro primeiro).

| Técnica | Regra | Formato | Fonte |
|---|---|---|---|
| T1036.002 | [Potential File Extension Spoofing Using Right-to-Left Override](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A979baf41-ca44-4540-9d0c-4fcef3b5a3a4) | Sigma | SigmaHQ |
| T1036.002 | [Potential Defense Evasion Via Right-to-Left Override](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aad691d92-15f2-4181-9aa4-723c74f9ddc3) | Sigma | SigmaHQ |

## 8. Plano de emulação e validação

Use num laboratório isolado e autorizado para confirmar que as regras disparam. Os comandos estão nos repositórios oficiais.

| Tática | Técnica | Teste Atomic Red Team | Plataformas |
|---|---|---|---|
| Stealth | [T1036.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.002/T1036.002.md) | Masquerading: Right-to-Left Override Batch File Creation and Execution | windows |
| Stealth | [T1036.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.002/T1036.002.md) | Masquerading: RTLO Masqueraded File Download and Execution | windows |

## 9. Hipóteses de hunting

Se Scarlet Mimic estiver no seu ambiente, estas são as perguntas a fazer aos seus dados (fontes de log segundo as estratégias de detecção do MITRE ATT&CK).

1. **T1036.002 Right-to-Left Override** — Execution of files containing right-to-left override characters (U+202E) to masquerade true file extensions. Often found in phishing payloads or file downloads. Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:PowerShell` (EventCode=4103, 4104, 4105, 4106), `WinEventLog:Windows Defender` (Operational).

## 10. OSINT — onde pesquisar

Consultas prontas com todos os nomes conhecidos do grupo:

- Relatórios técnicos: [busca web](https://duckduckgo.com/?q=%28%22Scarlet+Mimic%22%29+threat+report) · [PDFs](https://duckduckgo.com/?q=%28%22Scarlet+Mimic%22%29+filetype%3Apdf)
- Regras e IOCs publicados: [GitHub](https://github.com/search?type=code&q=%22Scarlet+Mimic%22)
- Pulsos de ameaça: [AlienVault OTX](https://otx.alienvault.com/browse/global/pulses?q=Scarlet+Mimic)
- Família de malware e atores: [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/actors) (busque por Scarlet Mimic)
- Cartões de grupo: [ThaiCERT Threat Group Cards](https://apt.etda.or.th/cgi-bin/listgroups.cgi)
- Página oficial: [MITRE ATT&CK G0029](https://attack.mitre.org/groups/G0029/)

**Relatórios na coleção CyberMonitor** (ligados pelo nome do grupo, conferir antes de citar):

- 2016 — [scarlet-mimic-years-long-espionage-targets-minority-activists](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2016/2016.01.24_Scarlet_Minic/scarlet-mimic-years-long-espionage-targets-minority-activists.pdf) _(via “Scarlet Mimic”)_

## 11. Bibliografia (1 fontes citadas pelo ATT&CK)

- [Scarlet Mimic Jan 2016](http://researchcenter.paloaltonetworks.com/2016/01/scarlet-mimic-years-long-espionage-targets-minority-activists/) — Falcone, R. and Miller-Osborn, J.. (2016, January 24). Scarlet Mimic: Years-Long Espionage Campaign Targets Minority Activists. Retrieved February 10, 2016.

## 12. Limites e confiança

- O ATT&CK registra o que foi **relatado publicamente**, não tudo o que o grupo faz. Ausência de uma técnica não prova que o grupo não a usa.
- **Sobreposição de TTP não é atribuição.** Muitas técnicas são compartilhadas entre grupos e com red teams. Use a assinatura comportamental como hipótese, junto com infraestrutura, malware e contexto.
- Cobertura de detecção refere-se ao catálogo público Detection Rules, não ao seu ambiente: confira se a telemetria necessária chega ao seu SIEM.
- Ligações marcadas como _inferidas_ (EVTX por palavra-chave, relatórios por nome) devem ser verificadas.

---
Fontes: MITRE ATT&CK® (uso livre com atribuição, © The MITRE Corporation), Atomic Red Team (Red Canary, MIT), EVTX-to-MITRE-Attack, EVTX-ATTACK-SAMPLES, APT & CyberCriminal Campaign Collections. Gerado por [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules).
