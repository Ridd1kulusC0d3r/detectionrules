# Putter Panda (G0024) — Dossiê de inteligência

> **TLP:CLEAR** · gerado em 2026-10-25 a partir de fontes abertas · MITRE ATT&CK v20.0 · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0024) · [ATT&CK](https://attack.mitre.org/groups/G0024/)

**Também conhecido como:** APT2, MSUpdater  
**Registro no ATT&CK:** criado em 2017-05-31, atualizado em 2026-07-31 · referências de 2014 a 2016

## 1. Sumário executivo

- **4 técnicas** atribuídas publicamente, concentradas em **Stealth, Privilege Escalation, Persistence**.
- **Arsenal:** 4 malware e 0 ferramentas (ex.: 4H RAT, 3PARA RAT, pngdowner, httpclient).
- **Campanhas atribuídas:** 0.
- **Cobertura de detecção pública:** 100% das técnicas têm ao menos uma regra no catálogo; **0 técnicas sem nenhuma regra pública**.
- **Assinatura comportamental** (técnicas raras entre os 178 grupos, as mais úteis para atribuição): T1055.001 Dynamic-link Library Injection, T1685 Disable or Modify Tools, T1027.013 Encrypted/Encoded File, T1547.001 Registry Run Keys / Startup Folder.

## 2. Quem é

> Putter Panda is a Chinese threat group that has been attributed to Unit 61486 of the 12th Bureau of the PLA’s 3rd General Staff Department (GSD).

_Texto original do MITRE ATT&CK, em inglês._

## 3. Perfil TTP por tática (kill chain)

Cada linha: técnica, como o grupo a usou segundo relatos públicos, e o que existe para detectar e testar.

### Persistence (TA0003) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1547.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1547.001) Registry Run Keys / Startup Folder | A dropper used by Putter Panda installs itself into the ASEP Registry key HKCU\Software\Microsoft\Windows\CurrentVersion\Run with a value named McUpdate. | 299 | 21 | 2 |

### Privilege Escalation (TA0004) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1055.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1055.001) Dynamic-link Library Injection | An executable dropped onto victims by Putter Panda aims to inject the specified DLL into a process that would normally be accessing the network, including Outlook Express (msinm.exe), Outlook (outlook.exe), Internet Explorer (iexplore.exe), and Firefox (firefo… | 40 | 2 | — |
| [T1547.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1547.001) Registry Run Keys / Startup Folder | A dropper used by Putter Panda installs itself into the ASEP Registry key HKCU\Software\Microsoft\Windows\CurrentVersion\Run with a value named McUpdate. | 299 | 21 | 2 |

### Stealth (TA0005) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1027.013](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1027.013) Encrypted/Encoded File | Droppers used by Putter Panda use RC4 or a 16-byte XOR key consisting of the bytes 0xA0 – 0xAF to obfuscate payloads. | 8 | 4 | — |
| [T1055.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1055.001) Dynamic-link Library Injection | An executable dropped onto victims by Putter Panda aims to inject the specified DLL into a process that would normally be accessing the network, including Outlook Express (msinm.exe), Outlook (outlook.exe), Internet Explorer (iexplore.exe), and Firefox (firefo… | 40 | 2 | — |

### Defense Impairment (TA0112) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1685](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1685) Disable or Modify Tools | Malware used by Putter Panda attempts to terminate processes corresponding to two components of Sophos Anti-Virus (SAVAdminService.exe and SavService.exe). | 1275 | 78 | 19 |

## 4. Assinatura comportamental

Técnicas que este grupo usa e que poucos dos 178 grupos do ATT&CK usam. Pesam mais numa atribuição por TTP: ver várias delas juntas é mais informativo do que ver técnicas comuns como PowerShell.

| Técnica | Outros grupos que usam | Peso (raridade) |
|---|---:|---:|
| T1055.001 Dynamic-link Library Injection | 9 | 2.79 |
| T1685 Disable or Modify Tools | 32 | 1.66 |
| T1027.013 Encrypted/Encoded File | 39 | 1.47 |
| T1547.001 Registry Run Keys / Startup Folder | 58 | 1.09 |

## 5. Arsenal

| Software | Tipo | Técnicas no ATT&CK | Uso relatado (EN) |
|---|---|---:|---|
| [4H RAT](https://attack.mitre.org/software/S0065/) | malware | 6 |  |
| [3PARA RAT](https://attack.mitre.org/software/S0066/) | malware | 4 |  |
| [pngdowner](https://attack.mitre.org/software/S0067/) | malware | 3 |  |
| [httpclient](https://attack.mitre.org/software/S0068/) | malware | 3 |  |

## 6. Campanhas

Nenhuma campanha atribuída no ATT&CK.

## 7. Cobertura defensiva

**4 de 4 técnicas (100%)** têm ao menos uma regra pública no catálogo Detection Rules.

### Regras recomendadas por técnica

Melhor regra disponível por técnica (formato portável e maduro primeiro).

| Técnica | Regra | Formato | Fonte |
|---|---|---|---|
| T1027.013 | [ROT Encoded Python Script Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A5ab49127-b1b3-46e6-8a38-9e8512a2a363) | Elastic | Elastic detection-rules |
| T1027.013 | [Data Encrypted via OpenSSL Utility](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Afeba48f6-40ca-4d04-b41f-5dfa327de865) | Elastic | Elastic detection-rules |
| T1055.001 | [TAIDOOR RAT DLL Load](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad1aa3382-abab-446f-96ea-4de52908210b) | Sigma | SigmaHQ |
| T1055.001 | [Renamed ZOHO Dctask64 Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A340a090b-c4e9-412e-bb36-b4b16fe96f9b) | Sigma | SigmaHQ |
| T1547.001 | [Potential Ryuk Ransomware Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac37510b8-2107-4b78-aa32-72f251e7a844) | Sigma | SigmaHQ |
| T1547.001 | [Ryuk Ransomware](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Ac37510b8-2107-4b78-aa32-72f251e7a844) | Sigma | OpenSearch Security Analytics |
| T1685 | [Windows Defender Configuration Changes](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A801bd44f-ceed-4eb6-887c-11544633c0aa) | Sigma | SigmaHQ |
| T1685 | [Windows Defender Virus Scanning Feature Disabled](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A686c0b4b-9dd3-4847-9077-d6c1bbe36fcb) | Sigma | SigmaHQ |

## 8. Plano de emulação e validação

Use num laboratório isolado e autorizado para confirmar que as regras disparam. Os comandos estão nos repositórios oficiais.

| Tática | Técnica | Teste Atomic Red Team | Plataformas |
|---|---|---|---|
| Persistence | [T1547.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1547.001/T1547.001.md) | Reg Key Run | windows |
| Persistence | [T1547.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1547.001/T1547.001.md) | Reg Key RunOnce | windows |
| Stealth | [T1027.013](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027.013/T1027.013.md) | Decode Eicar File and Write to File | linux, macos, windows |
| Stealth | [T1027.013](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027.013/T1027.013.md) | Decrypt Eicar File and Write to File | linux, macos, windows |
| Stealth | [T1055.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1055.001/T1055.001.md) | Process Injection via mavinject.exe | windows |
| Stealth | [T1055.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1055.001/T1055.001.md) | WinPwn - Get SYSTEM shell - Bind System Shell using UsoClient DLL load technique | windows |
| Defense Impairment | [T1685](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1685/T1685.md) | Windows Disable LSA Protection | windows |
| Defense Impairment | [T1685](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1685/T1685.md) | Disable journal logging via systemctl utility | linux |

**Logs reais de ataque (EVTX) para testar sem executar nada:**

- T1547.001 — [sideloading_injection_persistence_run_key](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/AutomatedTestingTools/Malware/sideloading_injection_persistence_run_key.evtx) _(inferido)_
- T1547.001 — [evasion_persis_hidden_run_keyvalue_sysmon_13](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Persistence/evasion_persis_hidden_run_keyvalue_sysmon_13.evtx) _(inferido)_
- T1685 — [ID1-SYSMON driver unload (FilterManager)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0005-Defense%20Evasion/T1562.001-Impair%20Defenses-Disable%20or%20Modify%20tool/ID1-SYSMON%20driver%20unload%20%28FilterManager%29.evtx) _(explícito)_
- T1685 — [ID13-Defender service configuration disabled](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0005-Defense%20Evasion/T1562.001-Impair%20Defenses-Disable%20or%20Modify%20tool/ID13-Defender%20service%20configuration%20disabled.evtx) _(explícito)_

## 9. Hipóteses de hunting

Se Putter Panda estiver no seu ambiente, estas são as perguntas a fazer aos seus dados (fontes de log segundo as estratégias de detecção do MITRE ATT&CK).

1. **T1055.001 Dynamic-link Library Injection** — Detects DLL injection through correlation of memory allocation and writing to remote process memory (e.g., VirtualAllocEx, WriteProcessMemory), followed by remote thread creation (e.g., CreateRemoteThread) that loads a suspicious or unsigned DLL using… Dados: `WinEventLog:Sysmon` (EventCode=10), `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=7).
2. **T1685 Disable or Modify Tools** — Detection of adversary behavior that disables or modifies security tools, including killing AV/EDR processes, stopping services, altering Sysmon registry keys, or tampering with exclusion lists. Defenders observe process/service termination, registry… Dados: `WinEventLog:System` (EventCode=7045), `WinEventLog:Sysmon` (EventCode=5), `WinEventLog:Sysmon` (EventCode=13, 14).
3. **T1027.013 Encrypted/Encoded File** — Detection of processes that load or decode encrypted/encoded files in memory and subsequently execute or inject them, indicating payload unpacking or memory-resident malware. Dados: `WinEventLog:Sysmon` (EventCode=7), `WinEventLog:Sysmon` (EventCode=10), `WinEventLog:Security` (EventCode=4688).
4. **T1547.001 Registry Run Keys / Startup Folder** — Correlation of Registry key creation/modification events under known Run/Startup keys with new or unusual binary paths or script-based payloads. Multi-event detection includes registry modification followed by process execution from non-standard directories… Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=13, 14), `WinEventLog:Microsoft-Windows-Shell-Core` (New startup folder shortcut or binary placed in Startup directory).

## 10. OSINT — onde pesquisar

Consultas prontas com todos os nomes conhecidos do grupo:

- Relatórios técnicos: [busca web](https://duckduckgo.com/?q=%28%22Putter+Panda%22+OR+%22APT2%22+OR+%22MSUpdater%22%29+threat+report) · [PDFs](https://duckduckgo.com/?q=%28%22Putter+Panda%22+OR+%22APT2%22+OR+%22MSUpdater%22%29+filetype%3Apdf)
- Regras e IOCs publicados: [GitHub](https://github.com/search?type=code&q=%22Putter+Panda%22+OR+%22APT2%22+OR+%22MSUpdater%22)
- Pulsos de ameaça: [AlienVault OTX](https://otx.alienvault.com/browse/global/pulses?q=Putter+Panda)
- Família de malware e atores: [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/actors) (busque por Putter Panda, APT2, MSUpdater)
- Cartões de grupo: [ThaiCERT Threat Group Cards](https://apt.etda.or.th/cgi-bin/listgroups.cgi)
- Página oficial: [MITRE ATT&CK G0024](https://attack.mitre.org/groups/G0024/)

**Relatórios na coleção CyberMonitor** (ligados pelo nome do grupo, conferir antes de citar):

- 2010 — [MSUpdaterTrojanWhitepaper](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2010/2010.09.03.MSUpdater.Trojan/MSUpdaterTrojanWhitepaper.pdf) _(via “MSUpdater”)_
- 2014 — [putter-panda](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2014/2014.06.09.Putter_Panda/putter-panda.pdf) _(via “Putter Panda”)_

## 11. Bibliografia (2 fontes citadas pelo ATT&CK)

- [CrowdStrike Putter Panda](http://cdn0.vox-cdn.com/assets/4589853/crowdstrike-intelligence-report-putter-panda.original.pdf) — Crowdstrike Global Intelligence Team. (2014, June 9). CrowdStrike Intelligence Report: Putter Panda. Retrieved January 22, 2016.
- [Cylance Putter Panda](https://blogs.blackberry.com/en/2016/01/puttering-into-the-future) — Gross, J. and Walter, J.. (2016, January 12). Puttering into the Future.... Retrieved November 17, 2024.

## 12. Limites e confiança

- O ATT&CK registra o que foi **relatado publicamente**, não tudo o que o grupo faz. Ausência de uma técnica não prova que o grupo não a usa.
- **Sobreposição de TTP não é atribuição.** Muitas técnicas são compartilhadas entre grupos e com red teams. Use a assinatura comportamental como hipótese, junto com infraestrutura, malware e contexto.
- Cobertura de detecção refere-se ao catálogo público Detection Rules, não ao seu ambiente: confira se a telemetria necessária chega ao seu SIEM.
- Ligações marcadas como _inferidas_ (EVTX por palavra-chave, relatórios por nome) devem ser verificadas.

---
Fontes: MITRE ATT&CK® (uso livre com atribuição, © The MITRE Corporation), Atomic Red Team (Red Canary, MIT), EVTX-to-MITRE-Attack, EVTX-ATTACK-SAMPLES, APT & CyberCriminal Campaign Collections. Gerado por [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules).
