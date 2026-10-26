# Equation (G0020) — Dossiê de inteligência

> **TLP:CLEAR** · gerado em 2026-10-26 a partir de fontes abertas · MITRE ATT&CK v20.0 · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0020) · [ATT&CK](https://attack.mitre.org/groups/G0020/)

**Também conhecido como:** —  
**Origem atribuída:** Estados Unidos · **Motivação:** espionagem · **Setores-alvo:** Governo, Defesa e militar  
**Registro no ATT&CK:** criado em 2017-05-31, atualizado em 2026-07-31 · referências de 2012 a 2015

## 1. Sumário executivo

- **4 técnicas** atribuídas publicamente, concentradas em **Stealth, Discovery, Persistence**.
- **Arsenal:** 0 malware e 0 ferramentas.
- **Campanhas atribuídas:** 0.
- **Cobertura de detecção pública:** 25% das técnicas têm ao menos uma regra no catálogo; **3 técnicas sem nenhuma regra pública**.
- **Origem e alvos (APT4ALL):** atribuído a **Estados Unidos**, motivação espionagem; setores Governo, Defesa e militar; 15 países vítimas citados.
- **Onde a cobertura está:** Windows (1 técnicas com regra), EDR / XDR (1 técnicas com regra).
- **Assinatura comportamental** (técnicas raras entre os 178 grupos, as mais úteis para atribuição): T1542.002 Component Firmware, T1480.001 Environmental Keying, T1564.005 Hidden File System, T1120 Peripheral Device Discovery.

## 2. Quem é

> Equation is a sophisticated threat group that employs multiple remote access tools. The group is known to use zero-day exploits and has developed the capability to overwrite the firmware of hard disk drives.

_Texto original do MITRE ATT&CK, em inglês._

## 3. Contexto, nomes e alvos

Consolidado pelo [APT4ALL](https://github.com/Ridd1kulusC0d3r/apt4all) a partir de MISP Galaxy, planilha APT Groups & Operations, EternalLiberty e APTnotes. Atribuição é afirmação de quem publicou; confira a fonte.

| Campo | Valor |
|---|---|
| Origem atribuída | Estados Unidos |
| Motivação | espionagem |
| Setores-alvo | Governo, Defesa e militar |
| Vítimas citadas | Afghanistan, Algeria, China, India, Iran, Kenya, Lebanon, Libya, Mali, Pakistan, Russia, Syria, United Arab Emirates, United Kingdom, Yemen |
| Alvos (planilha) | — |
| Operações conhecidas | — |
| Confiança de atribuição (MISP) | 50 |

**Como cada fornecedor chama este grupo** (útil para cruzar relatórios):

| Fornecedor | Nome(s) |
|---|---|
| MITRE ATT&CK | G0020 |

**Outros nomes no APT4ALL (não listados pelo ATT&CK):** Equation Group, Tilded Team, EQGRP, Longhorn, The Lamberts, Fallow Squall, Platinum Terminal, APT-C-39, Platinum Colony, APT-C-40

## 4. Perfil TTP por tática (kill chain)

Cada linha: técnica, como o grupo a usou segundo relatos públicos, e o que existe para detectar e testar.

### Persistence (TA0003) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1542.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1542.002) Component Firmware | Equation is known to have the capability to overwrite the firmware on hard drives from some manufacturers. | **0** | — | — |

### Stealth (TA0005) — 3

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1480.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1480.001) Environmental Keying | Equation has been observed utilizing environmental keying in payload delivery. | **0** | — | — |
| [T1542.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1542.002) Component Firmware | Equation is known to have the capability to overwrite the firmware on hard drives from some manufacturers. | **0** | — | — |
| [T1564.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1564.005) Hidden File System | Equation has used an encrypted virtual file system stored in the Windows Registry. | **0** | — | — |

### Discovery (TA0007) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1120](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1120) Peripheral Device Discovery | Equation has used tools with the functionality to search for specific information about the attached hard drive that could be used to identify and overwrite the firmware. | 11 | 4 | — |

## 5. Assinatura comportamental

Técnicas que este grupo usa e que poucos dos 178 grupos do ATT&CK usam. Pesam mais numa atribuição por TTP: ver várias delas juntas é mais informativo do que ver técnicas comuns como PowerShell.

| Técnica | Outros grupos que usam | Peso (raridade) |
|---|---:|---:|
| T1542.002 Component Firmware | 0 | 4.49 |
| T1480.001 Environmental Keying | 1 | 4.09 |
| T1564.005 Hidden File System | 1 | 4.09 |
| T1120 Peripheral Device Discovery | 8 | 2.88 |

## 6. Arsenal

Nenhum software atribuído no ATT&CK.

## 7. Campanhas

Nenhuma campanha atribuída no ATT&CK.

## 8. Cobertura defensiva

**1 de 4 técnicas (25%)** têm ao menos uma regra pública no catálogo Detection Rules.

### Técnicas sem regra pública (prioridade para engenharia de detecção)

- **T1542.002 Component Firmware** — Stealth. Fonte de log sugerida pelo MITRE: `WinEventLog:Sysmon` EventCode=6; `auditd:SYSCALL` ioctl/write: Direct firmware update or device memory manipulation syscalls; `macos:unifiedlog` Firmware update events or kernel extension (kext) load
- **T1480.001 Environmental Keying** — Stealth. Fonte de log sugerida pelo MITRE: `WinEventLog:Security` EventCode=4624, 4648; `auditd:SYSCALL` execve syscalls for discovery commands (uname, hostname, id, whoami, ps, netstat, mount) with command-line parameter analysis; `macos:unif
- **T1564.005 Hidden File System** — Stealth. Fonte de log sugerida pelo MITRE: `WinEventLog:Security` EventCode=4663, 4670, 4656; `auditd:SYSCALL` mount or losetup commands creating hidden or encrypted FS; `macos:unifiedlog` Execution of diskutil or hdiutil attaching hidden part

### Onde procurar — cobertura por tecnologia

Quantas técnicas deste grupo têm ao menos uma regra em cada tecnologia. Comece a caça pelas tecnologias que você tem e que aparecem aqui.

| Tecnologia | Técnicas do grupo com regra |
|---|---:|
| Windows | 1 |
| EDR / XDR | 1 |

### Regras recomendadas por técnica

Melhor regra disponível por técnica (formato portável e maduro primeiro).

| Técnica | Regra | Formato | Fonte |
|---|---|---|---|
| T1120 | [PowerShell Suspicious Script with Audio Capture Capabilities](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A2f2f4939-0b34-40c2-a0a3-844eb7889f43) | Elastic | Elastic detection-rules |
| T1120 | [Fsutil Drive Enumeration](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A63de06b9-a385-40b5-8b32-73f2b9ef84b6) | Sigma | SigmaHQ |

## 9. Plano de emulação e validação

Use num laboratório isolado e autorizado para confirmar que as regras disparam. Os comandos estão nos repositórios oficiais.

| Tática | Técnica | Teste Atomic Red Team | Plataformas |
|---|---|---|---|
| Discovery | [T1120](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1120/T1120.md) | Win32_PnPEntity Hardware Inventory | windows |
| Discovery | [T1120](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1120/T1120.md) | WinPwn - printercheck | windows |

## 10. Hipóteses de hunting

Se Equation estiver no seu ambiente, estas são as perguntas a fazer aos seus dados (fontes de log segundo as estratégias de detecção do MITRE ATT&CK).

1. **T1542.002 Component Firmware** — Detection of anomalous driver and firmware interactions, including unsigned or unexpected firmware updates, driver loads linked to hardware components, and suspicious use of privileged APIs to read/write firmware or controller memory. Dados: `WinEventLog:Sysmon` (EventCode=6), `firmware:integrity ` (Firmware integrity verification failures or mismatches against expected UEFI/firmware image baselines).
2. **T1480.001 Environmental Keying** — Windows-specific environmental keying behavioral chain: (1) Rapid system information discovery through multiple techniques (WMI queries, registry enumeration, network share discovery, hostname/domain checks), (2) Target validation through specific… Dados: `WinEventLog:Security` (EventCode=4624, 4648), `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=3, 22).
3. **T1564.005 Hidden File System** — Anomalous creation or mounting of hidden partitions or virtual file systems. Defender view: detection of registry modifications linked to non-standard file systems, suspicious disk I/O patterns, or bootkit-like behavior where hidden volumes are accessed… Dados: `WinEventLog:Security` (EventCode=4663, 4670, 4656), `WinEventLog:Sysmon` (EventCode=13, 14), `etw:Microsoft-Windows-Kernel-Storage` (Raw disk I/O operations bypassing NTFS APIs).
4. **T1120 Peripheral Device Discovery** — Suspicious enumeration of attached peripherals via WMI, PowerShell, or low-level API calls potentially chained with removable device interactions. Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=10).

## 11. OSINT — onde pesquisar

Consultas prontas com todos os nomes conhecidos do grupo:

- Relatórios técnicos: [busca web](https://duckduckgo.com/?q=%28%22Equation%22%29+threat+report) · [PDFs](https://duckduckgo.com/?q=%28%22Equation%22%29+filetype%3Apdf)
- Regras e IOCs publicados: [GitHub](https://github.com/search?type=code&q=%22Equation%22)
- Pulsos de ameaça: [AlienVault OTX](https://otx.alienvault.com/browse/global/pulses?q=Equation)
- Família de malware e atores: [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/actors) (busque por Equation)
- Cartões de grupo: [ThaiCERT Threat Group Cards](https://apt.etda.or.th/cgi-bin/listgroups.cgi)
- Página oficial: [MITRE ATT&CK G0020](https://attack.mitre.org/groups/G0020/)

**Relatórios na coleção CyberMonitor** (ligados pelo nome do grupo, conferir antes de citar):

- 2015 — [Equation_group_questions_and_answers](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2015/2015.02.16.equation-the-death-star/Equation_group_questions_and_answers.pdf) _(via “Equation”)_
- 2015 — [blog_equation-the-death-star](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2015/2015.02.16.equation-the-death-star/blog_equation-the-death-star.pdf) _(via “Equation”)_
- 2015 — [A_Fanny_Equation](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2015/2015.02.17.A_Fanny_Equation/A_Fanny_Equation.pdf) _(via “Equation”)_
- 2019 — [Buckeye_ Espionage Outfit Used Equation Group Tools Prior to Shadow Brokers Leak](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2019/2019.05.07.Buckeye/Buckeye_%20Espionage%20Outfit%20Used%20Equation%20Group%20Tools%20Prior%20to%20Shadow%20Brokers%20Leak.pdf) _(via “Equation”)_
- 2019 — [Multiple Chinese Threat Groups Exploiting CVE-2018-0798 Equation Editor Vulnerability Since Late 2018](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2019/2019.07.03.Chinese_APT_CVE-2018-0798/Multiple%20Chinese%20Threat%20Groups%20Exploiting%20CVE-2018-0798%20Equation%20Editor%20Vulnerability%20Since%20Late%202018.pdf) _(via “Equation”)_
- 2021 — [research.checkpoint.com-The Story of Jian  How APT31 Stole and Used an Unknown Equation Group 0-Day](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2021/2021.02.22.APT31_Equation_Group/research.checkpoint.com-The%20Story%20of%20Jian%20%20How%20APT31%20Stole%20and%20Used%20an%20Unknown%20Equation%20Group%200-Day.pdf) _(via “Equation”)_
- 2022 — [The_Bvp47_a_top-tier_backdoor_of_us_nsa_equation_group.en](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2022/2022.02.23.Bvp47/The_Bvp47_a_top-tier_backdoor_of_us_nsa_equation_group.en.pdf) _(via “Equation”)_

**Relatórios públicos ligados pelo APT4ALL** (2 no total, mais recentes primeiro):

- 2017 — [Longhorn: Tools used by cyberespionage group](https://app.box.com/s/jpmrhxe5hbpjv7l7a8x0hlusep41zo5q) _(Symantec)_
- 2015 — [Equation Group: Questions And Answers](https://app.box.com/s/reidof9i3qnjdq4t0k49o392g8r98tbt) _(Kaspersky)_

## 12. Bibliografia (2 fontes citadas pelo ATT&CK)

- [Kaspersky Equation QA](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/08064459/Equation_group_questions_and_answers.pdf) — Kaspersky Lab's Global Research and Analysis Team. (2015, February). Equation Group: Questions and Answers. Retrieved December 21, 2015.
- [Kaspersky Gauss Whitepaper](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/20134940/kaspersky-lab-gauss.pdf) — Kaspersky Lab. (2012, August). Gauss: Abnormal Distribution. Retrieved January 17, 2019.

## 13. Limites e confiança

- O ATT&CK registra o que foi **relatado publicamente**, não tudo o que o grupo faz. Ausência de uma técnica não prova que o grupo não a usa.
- **Sobreposição de TTP não é atribuição.** Muitas técnicas são compartilhadas entre grupos e com red teams. Use a assinatura comportamental como hipótese, junto com infraestrutura, malware e contexto.
- Cobertura de detecção refere-se ao catálogo público Detection Rules, não ao seu ambiente: confira se a telemetria necessária chega ao seu SIEM.
- Ligações marcadas como _inferidas_ (EVTX por palavra-chave, relatórios por nome) devem ser verificadas.

---
Fontes: MITRE ATT&CK® (uso livre com atribuição, © The MITRE Corporation), APT4ALL (MISP Galaxy CC0/BSD-2, APT Groups & Operations CC BY 4.0, EternalLiberty, APTnotes, Ransomware Tool Matrix CC BY 4.0), Atomic Red Team (Red Canary, MIT), EVTX-to-MITRE-Attack, EVTX-ATTACK-SAMPLES, APT & CyberCriminal Campaign Collections. Gerado por [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules).
