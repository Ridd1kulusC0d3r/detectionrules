# Orangeworm (G0071) — Dossiê de inteligência

> **TLP:CLEAR** · gerado em 2026-10-25 a partir de fontes abertas · MITRE ATT&CK v20.0 · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0071) · [ATT&CK](https://attack.mitre.org/groups/G0071/)

**Também conhecido como:** —  
**Registro no ATT&CK:** criado em 2018-10-17, atualizado em 2026-07-31 · referências de 2018 a 2022

## 1. Sumário executivo

- **2 técnicas** atribuídas publicamente, concentradas em **Lateral Movement, Command and Control**.
- **Arsenal:** 1 malware e 7 ferramentas (ex.: Kwampirs, Net, cmd, Arp, ipconfig).
- **Campanhas atribuídas:** 0.
- **Cobertura de detecção pública:** 100% das técnicas têm ao menos uma regra no catálogo; **0 técnicas sem nenhuma regra pública**.
- **Assinatura comportamental** (técnicas raras entre os 178 grupos, as mais úteis para atribuição): T1021.002 SMB/Windows Admin Shares, T1071.001 Web Protocols.

## 2. Quem é

> Orangeworm is a group that has targeted organizations in the healthcare sector in the United States, Europe, and Asia since at least 2015, likely for the purpose of corporate espionage. Reverse engineering of Kwampirs, directly associated with Orangeworm activity, indicates significant functional and development overlaps with Shamoon.

_Texto original do MITRE ATT&CK, em inglês._

## 3. Perfil TTP por tática (kill chain)

Cada linha: técnica, como o grupo a usou segundo relatos públicos, e o que existe para detectar e testar.

### Lateral Movement (TA0008) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1021.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1021.002) SMB/Windows Admin Shares | Orangeworm has copied its backdoor across open network shares, including ADMIN$, C$WINDOWS, D$WINDOWS, and E$WINDOWS. | 272 | 4 | 20 |

### Command and Control (TA0011) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1071.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1071.001) Web Protocols | Orangeworm has used HTTP for C2. | 228 | 3 | — |

## 4. Assinatura comportamental

Técnicas que este grupo usa e que poucos dos 178 grupos do ATT&CK usam. Pesam mais numa atribuição por TTP: ver várias delas juntas é mais informativo do que ver técnicas comuns como PowerShell.

| Técnica | Outros grupos que usam | Peso (raridade) |
|---|---:|---:|
| T1021.002 SMB/Windows Admin Shares | 27 | 1.82 |
| T1071.001 Web Protocols | 57 | 1.11 |

## 5. Arsenal

| Software | Tipo | Técnicas no ATT&CK | Uso relatado (EN) |
|---|---|---:|---|
| [Kwampirs](https://attack.mitre.org/software/S0236/) | malware | 22 |  |
| [Net](https://attack.mitre.org/software/S0039/) | ferramenta | 16 |  |
| [cmd](https://attack.mitre.org/software/S0106/) | ferramenta | 6 |  |
| [Arp](https://attack.mitre.org/software/S0099/) | ferramenta | 2 |  |
| [ipconfig](https://attack.mitre.org/software/S0100/) | ferramenta | 1 |  |
| [netstat](https://attack.mitre.org/software/S0104/) | ferramenta | 1 |  |
| [Systeminfo](https://attack.mitre.org/software/S0096/) | ferramenta | 1 |  |
| [route](https://attack.mitre.org/software/S0103/) | ferramenta | 1 |  |

## 6. Campanhas

Nenhuma campanha atribuída no ATT&CK.

## 7. Cobertura defensiva

**2 de 2 técnicas (100%)** têm ao menos uma regra pública no catálogo Detection Rules.

### Regras recomendadas por técnica

Melhor regra disponível por técnica (formato portável e maduro primeiro).

| Técnica | Regra | Formato | Fonte |
|---|---|---|---|
| T1021.002 | [PSExec Lateral Movement](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=hayabusa-native%3A%3A0694c340-3a46-40ac-acfc-c3444ae6572c) | Sigma | Hayabusa (native) |
| T1021.002 | [Turla Group Lateral Movement](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac601f20d-570a-4cde-a7d6-e17f99cb8e7f) | Sigma | SigmaHQ |
| T1071.001 | [Ursnif Malware Download URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aa36ce77e-30db-4ea0-8795-644d7af5dfb4) | Sigma | SigmaHQ |
| T1071.001 | [Ursnif Malware C2 URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A932ac737-33ca-4afd-9869-0d48b391fcc9) | Sigma | SigmaHQ |

## 8. Plano de emulação e validação

Use num laboratório isolado e autorizado para confirmar que as regras disparam. Os comandos estão nos repositórios oficiais.

| Tática | Técnica | Teste Atomic Red Team | Plataformas |
|---|---|---|---|
| Lateral Movement | [T1021.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.002/T1021.002.md) | Map admin share | windows |
| Lateral Movement | [T1021.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.002/T1021.002.md) | Map Admin Share PowerShell | windows |
| Command and Control | [T1071.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1071.001/T1071.001.md) | Malicious User Agents - Powershell | windows |
| Command and Control | [T1071.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1071.001/T1071.001.md) | Malicious User Agents - CMD | windows |

**Logs reais de ataque (EVTX) para testar sem executar nada:**

- T1021.002 — [ID4688,4697,5140-5145 PSexec remote execution + admin share](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0008-Lateral%20Movement/T1021.002-SMB%20Windows%20Admin%20Shares/ID4688%2C4697%2C5140-5145%20PSexec%20remote%20execution%20%2B%20admin%20share.evtx) _(explícito)_
- T1021.002 — [ID4688-4648 Lateral movement with net use](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0008-Lateral%20Movement/T1021.002-SMB%20Windows%20Admin%20Shares/ID4688-4648%20Lateral%20movement%20with%20net%20use.evtx) _(explícito)_

## 9. Hipóteses de hunting

Se Orangeworm estiver no seu ambiente, estas são as perguntas a fazer aos seus dados (fontes de log segundo as estratégias de detecção do MITRE ATT&CK).

1. **T1021.002 SMB/Windows Admin Shares** — An SMB-based remote file share access followed by lateral movement actions such as remote service creation, task scheduling, or suspicious process execution on the target host using ADMIN$ or C$ shares. Dados: `WinEventLog:Security` (EventCode=4624, 4648), `WinEventLog:Sysmon` (EventCode=3, 22), `WinEventLog:Sysmon` (EventCode=1).
2. **T1071.001 Web Protocols** — Detects unexpected or high-volume HTTP/S/WebSocket communication from suspicious processes (e.g., PowerShell, rundll32) using uncommon user agents or mimicking browser traffic to unusual domains or IPs. Dados: `NSM:Flow` (http.log, ssl.log), `WinEventLog:Sysmon` (EventCode=3, 22).

## 10. OSINT — onde pesquisar

Consultas prontas com todos os nomes conhecidos do grupo:

- Relatórios técnicos: [busca web](https://duckduckgo.com/?q=%28%22Orangeworm%22%29+threat+report) · [PDFs](https://duckduckgo.com/?q=%28%22Orangeworm%22%29+filetype%3Apdf)
- Regras e IOCs publicados: [GitHub](https://github.com/search?type=code&q=%22Orangeworm%22)
- Pulsos de ameaça: [AlienVault OTX](https://otx.alienvault.com/browse/global/pulses?q=Orangeworm)
- Família de malware e atores: [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/actors) (busque por Orangeworm)
- Cartões de grupo: [ThaiCERT Threat Group Cards](https://apt.etda.or.th/cgi-bin/listgroups.cgi)
- Página oficial: [MITRE ATT&CK G0071](https://attack.mitre.org/groups/G0071/)

**Relatórios na coleção CyberMonitor** (ligados pelo nome do grupo, conferir antes de citar):

- 2018 — [orangeworm-targets-healthcare-us-europe-asia](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2018/2018.04.23.New_Orangeworm/orangeworm-targets-healthcare-us-europe-asia.pdf) _(via “Orangeworm”)_

## 11. Bibliografia (3 fontes citadas pelo ATT&CK)

- [Cylera Kwampirs 2022](https://resources.cylera.com/hubfs/Cylera%20Labs/Cylera%20Labs%20Kwampirs%20Shamoon%20Technical%20Report.pdf) — Pablo Rincón Crespo. (2022, January). The link between Kwampirs (Orangeworm) and Shamoon APTs. Retrieved February 8, 2024.
- [Symantec Orangeworm April 2018](https://www.symantec.com/blogs/threat-intelligence/orangeworm-targets-healthcare-us-europe-asia) — Symantec Security Response Attack Investigation Team. (2018, April 23). New Orangeworm attack group targets the healthcare sector in the U.S., Europe, and Asia. Retrieved May 8, 2018.
- [Symantec Orangeworm IOCs April 2018](https://symantec-enterprise-blogs.security.com/sites/default/files/2018-04/Orangeworm%20IOCs.pdf) — Symantec Security Response Attack Investigation Team. (2018, April 23). Orangeworm: Indicators of Compromise. Retrieved July 8, 2018.

## 12. Limites e confiança

- O ATT&CK registra o que foi **relatado publicamente**, não tudo o que o grupo faz. Ausência de uma técnica não prova que o grupo não a usa.
- **Sobreposição de TTP não é atribuição.** Muitas técnicas são compartilhadas entre grupos e com red teams. Use a assinatura comportamental como hipótese, junto com infraestrutura, malware e contexto.
- Cobertura de detecção refere-se ao catálogo público Detection Rules, não ao seu ambiente: confira se a telemetria necessária chega ao seu SIEM.
- Ligações marcadas como _inferidas_ (EVTX por palavra-chave, relatórios por nome) devem ser verificadas.

---
Fontes: MITRE ATT&CK® (uso livre com atribuição, © The MITRE Corporation), Atomic Red Team (Red Canary, MIT), EVTX-to-MITRE-Attack, EVTX-ATTACK-SAMPLES, APT & CyberCriminal Campaign Collections. Gerado por [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules).
