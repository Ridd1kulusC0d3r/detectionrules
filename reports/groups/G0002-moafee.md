# Moafee (G0002) — Dossiê de inteligência

> **TLP:CLEAR** · gerado em 2026-10-25 a partir de fontes abertas · MITRE ATT&CK v20.0 · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0002) · [ATT&CK](https://attack.mitre.org/groups/G0002/)

**Também conhecido como:** —  
**Registro no ATT&CK:** criado em 2017-05-31, atualizado em 2026-07-31 · referências de 2014 a 2014

## 1. Sumário executivo

- **1 técnicas** atribuídas publicamente, concentradas em **Stealth**.
- **Arsenal:** 1 malware e 0 ferramentas (ex.: PoisonIvy).
- **Campanhas atribuídas:** 0.
- **Cobertura de detecção pública:** 100% das técnicas têm ao menos uma regra no catálogo; **0 técnicas sem nenhuma regra pública**.
- **Assinatura comportamental** (técnicas raras entre os 178 grupos, as mais úteis para atribuição): T1027.001 Binary Padding.

## 2. Quem é

> Moafee is a threat group that appears to operate from the Guandong Province of China. Due to overlapping TTPs, including similar custom tools, Moafee is thought to have a direct or indirect relationship with the threat group DragonOK.

_Texto original do MITRE ATT&CK, em inglês._

## 3. Perfil TTP por tática (kill chain)

Cada linha: técnica, como o grupo a usou segundo relatos públicos, e o que existe para detectar e testar.

### Stealth (TA0005) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1027.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1027.001) Binary Padding | Moafee has been known to employ binary padding. | 13 | 3 | — |

## 4. Assinatura comportamental

Técnicas que este grupo usa e que poucos dos 178 grupos do ATT&CK usam. Pesam mais numa atribuição por TTP: ver várias delas juntas é mais informativo do que ver técnicas comuns como PowerShell.

| Técnica | Outros grupos que usam | Peso (raridade) |
|---|---:|---:|
| T1027.001 Binary Padding | 7 | 2.99 |

## 5. Arsenal

| Software | Tipo | Técnicas no ATT&CK | Uso relatado (EN) |
|---|---|---:|---|
| [PoisonIvy](https://attack.mitre.org/software/S0012/) | malware | 15 |  |

## 6. Campanhas

Nenhuma campanha atribuída no ATT&CK.

## 7. Cobertura defensiva

**1 de 1 técnicas (100%)** têm ao menos uma regra pública no catálogo Detection Rules.

### Regras recomendadas por técnica

Melhor regra disponível por técnica (formato portável e maduro primeiro).

| Técnica | Regra | Formato | Fonte |
|---|---|---|---|
| T1027.001 | [Binary Padding - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac52a914f-3d8b-4b2a-bb75-b3991e75f8ba) | Sigma | SigmaHQ |
| T1027.001 | [Failed Code Integrity Checks](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A470ec5fa-7b4e-4071-b200-4c753100f49b) | Sigma | SigmaHQ |

## 8. Plano de emulação e validação

Use num laboratório isolado e autorizado para confirmar que as regras disparam. Os comandos estão nos repositórios oficiais.

| Tática | Técnica | Teste Atomic Red Team | Plataformas |
|---|---|---|---|
| Stealth | [T1027.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027.001/T1027.001.md) | Pad Binary to Change Hash - Linux/macOS dd | linux, macos |
| Stealth | [T1027.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027.001/T1027.001.md) | Pad Binary to Change Hash using truncate command - Linux/macOS | linux, macos |

## 9. Hipóteses de hunting

Se Moafee estiver no seu ambiente, estas são as perguntas a fazer aos seus dados (fontes de log segundo as estratégias de detecção do MITRE ATT&CK).

1. **T1027.001 Binary Padding** — Detects the creation or execution of padded binary files (e.g., large size but minimal legitimate content) followed by process execution or lateral movement from the host. Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:Security` (EventCode=4663, 4670, 4656), `WinEventLog:Sysmon` (EventCode=11).

## 10. OSINT — onde pesquisar

Consultas prontas com todos os nomes conhecidos do grupo:

- Relatórios técnicos: [busca web](https://duckduckgo.com/?q=%28%22Moafee%22%29+threat+report) · [PDFs](https://duckduckgo.com/?q=%28%22Moafee%22%29+filetype%3Apdf)
- Regras e IOCs publicados: [GitHub](https://github.com/search?type=code&q=%22Moafee%22)
- Pulsos de ameaça: [AlienVault OTX](https://otx.alienvault.com/browse/global/pulses?q=Moafee)
- Família de malware e atores: [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/actors) (busque por Moafee)
- Cartões de grupo: [ThaiCERT Threat Group Cards](https://apt.etda.or.th/cgi-bin/listgroups.cgi)
- Página oficial: [MITRE ATT&CK G0002](https://attack.mitre.org/groups/G0002/)

## 11. Bibliografia (1 fontes citadas pelo ATT&CK)

- [Haq 2014](https://www.fireeye.com/blog/threat-research/2014/09/the-path-to-mass-producing-cyber-attacks.html) — Haq, T., Moran, N., Scott, M., & Vashisht, S. O. (2014, September 10). The Path to Mass-Producing Cyber Attacks &#91;Blog&#93;. Retrieved November 12, 2014.

## 12. Limites e confiança

- O ATT&CK registra o que foi **relatado publicamente**, não tudo o que o grupo faz. Ausência de uma técnica não prova que o grupo não a usa.
- **Sobreposição de TTP não é atribuição.** Muitas técnicas são compartilhadas entre grupos e com red teams. Use a assinatura comportamental como hipótese, junto com infraestrutura, malware e contexto.
- Cobertura de detecção refere-se ao catálogo público Detection Rules, não ao seu ambiente: confira se a telemetria necessária chega ao seu SIEM.
- Ligações marcadas como _inferidas_ (EVTX por palavra-chave, relatórios por nome) devem ser verificadas.

---
Fontes: MITRE ATT&CK® (uso livre com atribuição, © The MITRE Corporation), Atomic Red Team (Red Canary, MIT), EVTX-to-MITRE-Attack, EVTX-ATTACK-SAMPLES, APT & CyberCriminal Campaign Collections. Gerado por [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules).
