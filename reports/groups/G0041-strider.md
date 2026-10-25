# Strider (G0041) — Dossiê de inteligência

> **TLP:CLEAR** · gerado em 2026-10-25 a partir de fontes abertas · MITRE ATT&CK v20.0 · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0041) · [ATT&CK](https://attack.mitre.org/groups/G0041/)

**Também conhecido como:** ProjectSauron  
**Registro no ATT&CK:** criado em 2017-05-31, atualizado em 2026-07-31 · referências de 2016 a 2016

## 1. Sumário executivo

- **3 técnicas** atribuídas publicamente, concentradas em **Command and Control, Defense Impairment, Persistence**.
- **Arsenal:** 1 malware e 0 ferramentas (ex.: Remsec).
- **Campanhas atribuídas:** 0.
- **Cobertura de detecção pública:** 67% das técnicas têm ao menos uma regra no catálogo; **1 técnicas sem nenhuma regra pública**.
- **Assinatura comportamental** (técnicas raras entre os 178 grupos, as mais úteis para atribuição): T1564.005 Hidden File System, T1556.002 Password Filter DLL, T1090.001 Internal Proxy.

## 2. Quem é

> Strider is a threat group that has been active since at least 2011 and has targeted victims in Russia, China, Sweden, Belgium, Iran, and Rwanda.

_Texto original do MITRE ATT&CK, em inglês._

## 3. Perfil TTP por tática (kill chain)

Cada linha: técnica, como o grupo a usou segundo relatos públicos, e o que existe para detectar e testar.

### Persistence (TA0003) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1556.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1556.002) Password Filter DLL | Strider has registered its persistence module on domain controllers as a Windows LSA (Local System Authority) password filter to acquire credentials any time a domain, local user, or administrator logs in or changes a password. | 16 | 2 | — |

### Stealth (TA0005) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1564.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1564.005) Hidden File System | Strider has used a hidden file system that is stored as a file on disk. | **0** | — | — |

### Defense Impairment (TA0112) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1556.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1556.002) Password Filter DLL | Strider has registered its persistence module on domain controllers as a Windows LSA (Local System Authority) password filter to acquire credentials any time a domain, local user, or administrator logs in or changes a password. | 16 | 2 | — |

### Credential Access (TA0006) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1556.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1556.002) Password Filter DLL | Strider has registered its persistence module on domain controllers as a Windows LSA (Local System Authority) password filter to acquire credentials any time a domain, local user, or administrator logs in or changes a password. | 16 | 2 | — |

### Command and Control (TA0011) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1090.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1090.001) Internal Proxy | Strider has used local servers with both local network and Internet access to act as internal proxy nodes to exfiltrate data from other parts of the network without direct Internet access. | 43 | 3 | — |

## 4. Assinatura comportamental

Técnicas que este grupo usa e que poucos dos 178 grupos do ATT&CK usam. Pesam mais numa atribuição por TTP: ver várias delas juntas é mais informativo do que ver técnicas comuns como PowerShell.

| Técnica | Outros grupos que usam | Peso (raridade) |
|---|---:|---:|
| T1564.005 Hidden File System | 1 | 4.09 |
| T1556.002 Password Filter DLL | 2 | 3.80 |
| T1090.001 Internal Proxy | 8 | 2.88 |

## 5. Arsenal

| Software | Tipo | Técnicas no ATT&CK | Uso relatado (EN) |
|---|---|---:|---|
| [Remsec](https://attack.mitre.org/software/S0125/) | malware | 30 |  |

## 6. Campanhas

Nenhuma campanha atribuída no ATT&CK.

## 7. Cobertura defensiva

**2 de 3 técnicas (67%)** têm ao menos uma regra pública no catálogo Detection Rules.

### Técnicas sem regra pública (prioridade para engenharia de detecção)

- **T1564.005 Hidden File System** — Stealth. Fonte de log sugerida pelo MITRE: `WinEventLog:Security` EventCode=4663, 4670, 4656; `auditd:SYSCALL` mount or losetup commands creating hidden or encrypted FS; `macos:unifiedlog` Execution of diskutil or hdiutil attaching hidden part

### Regras recomendadas por técnica

Melhor regra disponível por técnica (formato portável e maduro primeiro).

| Técnica | Regra | Formato | Fonte |
|---|---|---|---|
| T1090.001 | [Renamed Cloudflared.EXE Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae0c69ebd-b54f-4aed-8ae3-e3467843f3f0) | Sigma | SigmaHQ |
| T1090.001 | [PUA - Chisel Tunneling Tool Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A8b0e12da-d3c3-49db-bb4f-256703f380e5) | Sigma | SigmaHQ |
| T1556.002 | [Powershell Install a DLL in System Directory](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A63bf8794-9917-45bc-88dd-e1b5abc0ecfd) | Sigma | SigmaHQ |
| T1556.002 | [Dropping Of Password Filter DLL](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab7966f4a-b333-455b-8370-8ca53c229762) | Sigma | SigmaHQ |

## 8. Plano de emulação e validação

Use num laboratório isolado e autorizado para confirmar que as regras disparam. Os comandos estão nos repositórios oficiais.

| Tática | Técnica | Teste Atomic Red Team | Plataformas |
|---|---|---|---|
| Defense Impairment | [T1556.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1556.002/T1556.002.md) | Install and Register Password Filter DLL | windows |
| Defense Impairment | [T1556.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1556.002/T1556.002.md) | Install Additional Authentication Packages | windows |
| Command and Control | [T1090.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1090.001/T1090.001.md) | Connection Proxy | linux, macos |
| Command and Control | [T1090.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1090.001/T1090.001.md) | Connection Proxy for macOS UI | macos |

## 9. Hipóteses de hunting

Se Strider estiver no seu ambiente, estas são as perguntas a fazer aos seus dados (fontes de log segundo as estratégias de detecção do MITRE ATT&CK).

1. **T1564.005 Hidden File System** — Anomalous creation or mounting of hidden partitions or virtual file systems. Defender view: detection of registry modifications linked to non-standard file systems, suspicious disk I/O patterns, or bootkit-like behavior where hidden volumes are accessed… Dados: `WinEventLog:Security` (EventCode=4663, 4670, 4656), `WinEventLog:Sysmon` (EventCode=13, 14), `etw:Microsoft-Windows-Kernel-Storage` (Raw disk I/O operations bypassing NTFS APIs).
2. **T1556.002 Password Filter DLL** — Detects suspicious registration of new password filter DLLs into the authentication process. Correlates registry modifications to LSASS Notification Packages with subsequent DLL creation and loading events. Observes anomalous file placement of DLLs in system… Dados: `WinEventLog:Security` (EventCode=4657), `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Sysmon` (EventCode=7).
3. **T1090.001 Internal Proxy** — Anomalous process (e.g., `rundll32`, `svchost`, `cmd`) initiates connections to internal peer hosts not seen in typical communication baselines, used to proxy or forward traffic internally, often using SMB, RPC, or high ports. Dados: `WinEventLog:Sysmon` (EventCode=3, 22), `WinEventLog:Sysmon` (EventCode=1), `Windows Firewall Log` (SMB over high port).

## 10. OSINT — onde pesquisar

Consultas prontas com todos os nomes conhecidos do grupo:

- Relatórios técnicos: [busca web](https://duckduckgo.com/?q=%28%22Strider%22+OR+%22ProjectSauron%22%29+threat+report) · [PDFs](https://duckduckgo.com/?q=%28%22Strider%22+OR+%22ProjectSauron%22%29+filetype%3Apdf)
- Regras e IOCs publicados: [GitHub](https://github.com/search?type=code&q=%22Strider%22+OR+%22ProjectSauron%22)
- Pulsos de ameaça: [AlienVault OTX](https://otx.alienvault.com/browse/global/pulses?q=Strider)
- Família de malware e atores: [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/actors) (busque por Strider, ProjectSauron)
- Cartões de grupo: [ThaiCERT Threat Group Cards](https://apt.etda.or.th/cgi-bin/listgroups.cgi)
- Página oficial: [MITRE ATT&CK G0041](https://attack.mitre.org/groups/G0041/)

**Relatórios na coleção CyberMonitor** (ligados pelo nome do grupo, conferir antes de citar):

- 2016 — [Symantec_Remsec_IOCs](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2016/2016.08.07.Strider_Cyberespionage_group_turns_eye_of_Sauron_on_targets/Symantec_Remsec_IOCs.pdf) _(via “Strider”)_
- 2016 — [strider-cyberespionage-group-turns-eye-sauron-targets](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2016/2016.08.07.Strider_Cyberespionage_group_turns_eye_of_Sauron_on_targets/strider-cyberespionage-group-turns-eye-sauron-targets.pdf) _(via “Strider”)_
- 2016 — [ProjectSauron_ top level cyber-espionage platform covertly extracts encrypted government comms - Securelist](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2016/2016.08.08.ProjectSauron/ProjectSauron_%20top%20level%20cyber-espionage%20platform%20covertly%20extracts%20encrypted%20government%20comms%20-%20Securelist.pdf) _(via “ProjectSauron”)_
- 2016 — [The-ProjectSauron-APT_IOCs_KL](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2016/2016.08.08.ProjectSauron/The-ProjectSauron-APT_IOCs_KL.pdf) _(via “ProjectSauron”)_
- 2016 — [The-ProjectSauron-APT_Technical_Analysis_KL](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2016/2016.08.08.ProjectSauron/The-ProjectSauron-APT_Technical_Analysis_KL.pdf) _(via “ProjectSauron”)_
- 2016 — [The-ProjectSauron-APT_research_KL](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2016/2016.08.08.ProjectSauron/The-ProjectSauron-APT_research_KL.pdf) _(via “ProjectSauron”)_

## 11. Bibliografia (3 fontes citadas pelo ATT&CK)

- [Kaspersky ProjectSauron Blog](https://securelist.com/faq-the-projectsauron-apt/75533/) — Kaspersky Lab's Global Research & Analysis Team. (2016, August 8). ProjectSauron: top level cyber-espionage platform covertly extracts encrypted government comms. Retrieved August 17, 2016.
- [Kaspersky ProjectSauron Full Report](https://securelist.com/files/2016/07/The-ProjectSauron-APT_research_KL.pdf) — Kaspersky Lab's Global Research & Analysis Team. (2016, August 9). The ProjectSauron APT. Retrieved August 17, 2016.
- [Symantec Strider Blog](http://www.symantec.com/connect/blogs/strider-cyberespionage-group-turns-eye-sauron-targets) — Symantec Security Response. (2016, August 7). Strider: Cyberespionage group turns eye of Sauron on targets. Retrieved August 17, 2016.

## 12. Limites e confiança

- O ATT&CK registra o que foi **relatado publicamente**, não tudo o que o grupo faz. Ausência de uma técnica não prova que o grupo não a usa.
- **Sobreposição de TTP não é atribuição.** Muitas técnicas são compartilhadas entre grupos e com red teams. Use a assinatura comportamental como hipótese, junto com infraestrutura, malware e contexto.
- Cobertura de detecção refere-se ao catálogo público Detection Rules, não ao seu ambiente: confira se a telemetria necessária chega ao seu SIEM.
- Ligações marcadas como _inferidas_ (EVTX por palavra-chave, relatórios por nome) devem ser verificadas.

---
Fontes: MITRE ATT&CK® (uso livre com atribuição, © The MITRE Corporation), Atomic Red Team (Red Canary, MIT), EVTX-to-MITRE-Attack, EVTX-ATTACK-SAMPLES, APT & CyberCriminal Campaign Collections. Gerado por [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules).
