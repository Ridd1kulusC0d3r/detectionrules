# Ajax Security Team (G0130) — Dossiê de inteligência

> **TLP:CLEAR** · gerado em 2026-10-25 a partir de fontes abertas · MITRE ATT&CK v20.0 · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0130) · [ATT&CK](https://attack.mitre.org/groups/G0130/)

**Também conhecido como:** Operation Woolen-Goldfish, AjaxTM, Rocket Kitten, Flying Kitten, Operation Saffron Rose  
**Registro no ATT&CK:** criado em 2021-04-14, atualizado em 2026-07-31 · referências de 2013 a 2017

## 1. Sumário executivo

- **6 técnicas** atribuídas publicamente, concentradas em **Credential Access, Initial Access, Collection**.
- **Arsenal:** 0 malware e 2 ferramentas (ex.: sqlmap, Havij).
- **Campanhas atribuídas:** 0.
- **Cobertura de detecção pública:** 100% das técnicas têm ao menos uma regra no catálogo; **0 técnicas sem nenhuma regra pública**.
- **Assinatura comportamental** (técnicas raras entre os 178 grupos, as mais úteis para atribuição): T1566.003 Spearphishing via Service, T1555.003 Credentials from Web Browsers, T1056.001 Keylogging, T1566.001 Spearphishing Attachment, T1204.002 Malicious File.

## 2. Quem é

> Ajax Security Team is a group that has been active since at least 2010 and believed to be operating out of Iran. By 2014 Ajax Security Team transitioned from website defacement operations to malware-based cyber espionage campaigns targeting the US defense industrial base and Iranian users of anti-censorship technologies.

_Texto original do MITRE ATT&CK, em inglês._

## 3. Perfil TTP por tática (kill chain)

Cada linha: técnica, como o grupo a usou segundo relatos públicos, e o que existe para detectar e testar.

### Initial Access (TA0001) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1566.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1566.001) Spearphishing Attachment | Ajax Security Team has used personalized spearphishing attachments. | 230 | 2 | — |
| [T1566.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1566.003) Spearphishing via Service | Ajax Security Team has used various social media channels to spearphish victims. | 8 | — | — |

### Execution (TA0002) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1204.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1204.002) Malicious File | Ajax Security Team has lured victims into executing malicious files. | 259 | 13 | — |

### Credential Access (TA0006) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1056.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1056.001) Keylogging | Ajax Security Team has used CWoolger and MPK, custom-developed malware, which recorded all keystrokes on an infected system. | 40 | 8 | 1 |
| [T1555.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1555.003) Credentials from Web Browsers | Ajax Security Team has used FireMalv custom-developed malware, which collected passwords from the Firefox browser storage. | 59 | 18 | 5 |

### Collection (TA0009) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1056.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1056.001) Keylogging | Ajax Security Team has used CWoolger and MPK, custom-developed malware, which recorded all keystrokes on an infected system. | 40 | 8 | 1 |

### Command and Control (TA0011) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1105](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1105) Ingress Tool Transfer | Ajax Security Team has used Wrapper/Gholee, custom-developed malware, which downloaded additional malware to the infected system. | 644 | 39 | — |

## 4. Assinatura comportamental

Técnicas que este grupo usa e que poucos dos 178 grupos do ATT&CK usam. Pesam mais numa atribuição por TTP: ver várias delas juntas é mais informativo do que ver técnicas comuns como PowerShell.

| Técnica | Outros grupos que usam | Peso (raridade) |
|---|---:|---:|
| T1566.003 Spearphishing via Service | 14 | 2.42 |
| T1555.003 Credentials from Web Browsers | 23 | 1.97 |
| T1056.001 Keylogging | 25 | 1.89 |
| T1566.001 Spearphishing Attachment | 78 | 0.81 |
| T1204.002 Malicious File | 86 | 0.71 |
| T1105 Ingress Tool Transfer | 89 | 0.68 |

## 5. Arsenal

| Software | Tipo | Técnicas no ATT&CK | Uso relatado (EN) |
|---|---|---:|---|
| [sqlmap](https://attack.mitre.org/software/S0225/) | ferramenta | 1 |  |
| [Havij](https://attack.mitre.org/software/S0224/) | ferramenta | 1 |  |

## 6. Campanhas

Nenhuma campanha atribuída no ATT&CK.

## 7. Cobertura defensiva

**6 de 6 técnicas (100%)** têm ao menos uma regra pública no catálogo Detection Rules.

### Regras recomendadas por técnica

Melhor regra disponível por técnica (formato portável e maduro primeiro).

| Técnica | Regra | Formato | Fonte |
|---|---|---|---|
| T1056.001 | [Linux Keylogging with Pam.d](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A49aae26c-450e-448b-911d-b3c13d178dfc) | Sigma | SigmaHQ |
| T1056.001 | [Linux Keylogging with Pam.d](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A49aae26c-450e-448b-911d-b3c13d178dfc) | Sigma | OpenSearch Security Analytics |
| T1105 | [Greenbug Espionage Group Indicators](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A3711eee4-a808-4849-8a14-faf733da3612) | Sigma | SigmaHQ |
| T1105 | [Pandemic Registry Key](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A47e0852a-cf81-4494-a8e6-31864f8c86ed) | Sigma | SigmaHQ |
| T1204.002 | [Ursnif Malware C2 URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A932ac737-33ca-4afd-9869-0d48b391fcc9) | Sigma | SigmaHQ |
| T1204.002 | [Droppers Exploiting CVE-2017-11882](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A678eb5f4-8597-4be6-8be7-905e4234b53a) | Sigma | SigmaHQ |
| T1555.003 | [SQLite Chromium Profile Data DB Access](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A24c77512-782b-448a-8950-eddb0785fc71) | Sigma | SigmaHQ |
| T1555.003 | [HackTool - WinPwn Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad557dc06-62e8-4468-a8e8-7984124908ce) | Sigma | SigmaHQ |
| T1566.001 | [Ursnif Malware C2 URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A932ac737-33ca-4afd-9869-0d48b391fcc9) | Sigma | SigmaHQ |
| T1566.001 | [Droppers Exploiting CVE-2017-11882](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A678eb5f4-8597-4be6-8be7-905e4234b53a) | Sigma | SigmaHQ |
| T1566.003 | [M365 Teams Rogue Help Desk Chat Created](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ae8e7b6b6-78b0-4015-97fe-c2f28468e0d4) | Elastic | Elastic detection-rules |
| T1566.003 | [M365 Azure Monitor Alert Email with Financial or Billing Theme](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Aa6129187-c47b-48ab-a412-67a44836d918) | Elastic | Elastic detection-rules |

## 8. Plano de emulação e validação

Use num laboratório isolado e autorizado para confirmar que as regras disparam. Os comandos estão nos repositórios oficiais.

| Tática | Técnica | Teste Atomic Red Team | Plataformas |
|---|---|---|---|
| Initial Access | [T1566.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1566.001/T1566.001.md) | Download Macro-Enabled Phishing Attachment | windows |
| Initial Access | [T1566.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1566.001/T1566.001.md) | Word spawned a command shell and used an IP address in the command line | windows |
| Execution | [T1204.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1204.002/T1204.002.md) | OSTap Style Macro Execution | windows |
| Execution | [T1204.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1204.002/T1204.002.md) | OSTap Payload Download | windows |
| Credential Access | [T1555.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1555.003/T1555.003.md) | Run Chrome-password Collector | windows |
| Credential Access | [T1555.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1555.003/T1555.003.md) | Search macOS Safari Cookies | macos |
| Collection | [T1056.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1056.001/T1056.001.md) | Input Capture | windows |
| Collection | [T1056.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1056.001/T1056.001.md) | Living off the land Terminal Input Capture on Linux with pam.d | linux |
| Command and Control | [T1105](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1105/T1105.md) | rsync remote file copy (push) | linux, macos |
| Command and Control | [T1105](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1105/T1105.md) | rsync remote file copy (pull) | linux, macos |

**Logs reais de ataque (EVTX) para testar sem executar nada:**

- T1056.001 — [sysmon_13_keylogger_directx](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Credential%20Access/sysmon_13_keylogger_directx.evtx) _(inferido)_
- T1555.003 — [CA_4624_4625_LogonType2_LogonProc_chrome](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Credential%20Access/CA_4624_4625_LogonType2_LogonProc_chrome.evtx) _(inferido)_
- T1555.003 — [CA_chrome_firefox_opera_4663](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Credential%20Access/CA_chrome_firefox_opera_4663.evtx) _(inferido)_

## 9. Hipóteses de hunting

Se Ajax Security Team estiver no seu ambiente, estas são as perguntas a fazer aos seus dados (fontes de log segundo as estratégias de detecção do MITRE ATT&CK).

1. **T1566.003 Spearphishing via Service** — Inbound spearphishing attempts delivered via third-party services (e.g., Gmail, LinkedIn messages) leading to malicious file downloads or browser-initiated script execution. Defender view includes correlation of external service logins, unexpected file write… Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Sysmon` (EventCode=3, 22).
2. **T1555.003 Credentials from Web Browsers** — Detects unauthorized access to web browser credential stores (e.g., Chrome Login Data, Edge Credential Locker) by processes other than the browser itself. Correlates file reads of credential databases with subsequent API calls to `CryptUnprotectData` or… Dados: `WinEventLog:Security` (EventCode=4663, 4670, 4656), `WinEventLog:Sysmon` (EventCode=10), `WinEventLog:Sysmon` (EventCode=1).
3. **T1056.001 Keylogging** — Monitors suspicious usage of Windows API calls like SetWindowsHookEx, GetKeyState, or polling functions within non-UI service processes, combined with Registry or driver modifications. Dados: `WinEventLog:Sysmon` (EventCode=10), `WinEventLog:Security` (EventCode=4663, 4670, 4656), `WinEventLog:System` (EventCode=7045).
4. **T1566.001 Spearphishing Attachment** — Detection of spearphishing attachments by correlating suspicious email delivery with subsequent file creation and abnormal process execution (e.g., Office spawning PowerShell or CMD). Behavior chain includes inbound email metadata → attachment stored on disk… Dados: `m365:unified` (Send/Receive: Inbound emails with attachments from suspicious or spoofed senders), `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Sysmon` (EventCode=1).
5. **T1204.002 Malicious File** — User opens a file delivered by email, web, chat, or share. The handler application (Word/PDF reader/archiver) creates a file in user-controlled paths (Downloads, Temp, Desktop) and then spawns a new or unusual child process (e.g., powershell.exe, wscript.exe,… Dados: `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=15).
6. **T1105 Ingress Tool Transfer** — Unusual or uncommon processes initiate network connections to external destinations followed by file creation (tools downloaded). Dados: `WinEventLog:Sysmon` (EventCode=3, 22), `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Sysmon` (EventCode=1).

## 10. OSINT — onde pesquisar

Consultas prontas com todos os nomes conhecidos do grupo:

- Relatórios técnicos: [busca web](https://duckduckgo.com/?q=%28%22Ajax+Security+Team%22+OR+%22Operation+Woolen-Goldfish%22+OR+%22AjaxTM%22+OR+%22Rocket+Kitten%22+OR+%22Flying+Kitten%22+OR+%22Operation+Saffron+Rose%22%29+threat+report) · [PDFs](https://duckduckgo.com/?q=%28%22Ajax+Security+Team%22+OR+%22Operation+Woolen-Goldfish%22+OR+%22AjaxTM%22+OR+%22Rocket+Kitten%22+OR+%22Flying+Kitten%22+OR+%22Operation+Saffron+Rose%22%29+filetype%3Apdf)
- Regras e IOCs publicados: [GitHub](https://github.com/search?type=code&q=%22Ajax+Security+Team%22+OR+%22Operation+Woolen-Goldfish%22+OR+%22AjaxTM%22+OR+%22Rocket+Kitten%22+OR+%22Flying+Kitten%22+OR+%22Operation+Saffron+Rose%22)
- Pulsos de ameaça: [AlienVault OTX](https://otx.alienvault.com/browse/global/pulses?q=Ajax+Security+Team)
- Família de malware e atores: [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/actors) (busque por Ajax Security Team, Operation Woolen-Goldfish, AjaxTM)
- Cartões de grupo: [ThaiCERT Threat Group Cards](https://apt.etda.or.th/cgi-bin/listgroups.cgi)
- Página oficial: [MITRE ATT&CK G0130](https://attack.mitre.org/groups/G0130/)

**Relatórios na coleção CyberMonitor** (ligados pelo nome do grupo, conferir antes de citar):

- 2013 — [rpt-operation-saffron-rose](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2013/2013.00.00.OPERATION_SAFFRON_ROSE/rpt-operation-saffron-rose.pdf) _(via “Operation Saffron Rose”)_
- 2014 — [CrowdStrike_Flying_Kitten](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2014/2014.05.13.Flying.Kitten/CrowdStrike_Flying_Kitten.pdf) _(via “Flying Kitten”)_
- 2014 — [fireeye-operation-saffron-rose](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2014/2014.05.13.Operation_Saffron_Rose/fireeye-operation-saffron-rose.pdf) _(via “Operation Saffron Rose”)_
- 2014 — [Sayad_Flying_Kitten_analysis](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2014/2014.07.20.Flying_Kitten/Sayad_Flying_Kitten_analysis.pdf) _(via “Flying Kitten”)_
- 2015 — [wp-operation-woolen-goldfish](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2015/2015.03.19.Goldfish_Phishing/wp-operation-woolen-goldfish.pdf) _(via “Operation Woolen-Goldfish”)_
- 2015 — [wp-the-spy-kittens-are-back](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2015/2015.09.01.Rocket_Kitten_2/wp-the-spy-kittens-are-back.pdf) _(via “Rocket Kitten”)_
- 2015 — [rocket-kitten-report](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2015/2015.11.09.Rocket_Kitten_A_Campaign_With_9_Lives/rocket-kitten-report.pdf) _(via “Rocket Kitten”)_

## 11. Bibliografia (5 fontes citadas pelo ATT&CK)

- [Check Point Rocket Kitten](https://blog.checkpoint.com/wp-content/uploads/2015/11/rocket-kitten-report.pdf) — Check Point Software Technologies. (2015). ROCKET KITTEN: A CAMPAIGN WITH 9 LIVES. Retrieved March 16, 2018.
- [CrowdStrike Flying Kitten ](https://www.crowdstrike.com/blog/cat-scratch-fever-crowdstrike-tracks-newly-reported-iranian-actor-flying-kitten/) — Dahl, M.. (2014, May 13). Cat Scratch Fever: CrowdStrike Tracks Newly Reported Iranian Actor as FLYING KITTEN. Retrieved May 27, 2020.
- [FireEye Operation Saffron Rose 2013](https://www.mandiant.com/sites/default/files/2021-09/rpt-operation-saffron-rose.pdf) — Villeneuve, N. et al.. (2013). OPERATION SAFFRON ROSE . Retrieved May 28, 2020.
- [IranThreats Kittens Dec 2017](https://iranthreats.github.io/resources/attribution-flying-rocket-kitten/) — Iran Threats . (2017, December 5). Flying Kitten to Rocket Kitten, A Case of Ambiguity and Shared Code. Retrieved May 28, 2020.
- [TrendMicro Operation Woolen Goldfish March 2015](https://documents.trendmicro.com/assets/wp/wp-operation-woolen-goldfish.pdf) — Cedric Pernet, Kenney Lu. (2015, March 19). Operation Woolen-Goldfish - When Kittens Go phishing. Retrieved April 21, 2021.

## 12. Limites e confiança

- O ATT&CK registra o que foi **relatado publicamente**, não tudo o que o grupo faz. Ausência de uma técnica não prova que o grupo não a usa.
- **Sobreposição de TTP não é atribuição.** Muitas técnicas são compartilhadas entre grupos e com red teams. Use a assinatura comportamental como hipótese, junto com infraestrutura, malware e contexto.
- Cobertura de detecção refere-se ao catálogo público Detection Rules, não ao seu ambiente: confira se a telemetria necessária chega ao seu SIEM.
- Ligações marcadas como _inferidas_ (EVTX por palavra-chave, relatórios por nome) devem ser verificadas.

---
Fontes: MITRE ATT&CK® (uso livre com atribuição, © The MITRE Corporation), Atomic Red Team (Red Canary, MIT), EVTX-to-MITRE-Attack, EVTX-ATTACK-SAMPLES, APT & CyberCriminal Campaign Collections. Gerado por [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules).
