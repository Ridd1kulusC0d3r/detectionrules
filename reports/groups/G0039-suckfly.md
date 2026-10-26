# Suckfly (G0039) — Dossiê de inteligência

> **TLP:CLEAR** · gerado em 2026-10-26 a partir de fontes abertas · MITRE ATT&CK v20.0 · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0039) · [ATT&CK](https://attack.mitre.org/groups/G0039/)

**Também conhecido como:** —  
**Origem atribuída:** China · **Motivação:** indefinido · **Setores-alvo:** —  
**Registro no ATT&CK:** criado em 2017-05-31, atualizado em 2026-07-31 · referências de 2016 a 2016

## 1. Sumário executivo

- **5 técnicas** atribuídas publicamente, concentradas em **Credential Access, Discovery, Execution**.
- **Arsenal:** 1 malware e 0 ferramentas (ex.: Nidiran).
- **Campanhas atribuídas:** 0.
- **Cobertura de detecção pública:** 100% das técnicas têm ao menos uma regra no catálogo; **0 técnicas sem nenhuma regra pública**.
- **Origem e alvos (APT4ALL):** atribuído a **China**, motivação indefinido.
- **Onde a cobertura está:** Windows (5 técnicas com regra), Linux (4 técnicas com regra), macOS (4 técnicas com regra), EDR / XDR (4 técnicas com regra).
- **Assinatura comportamental** (técnicas raras entre os 178 grupos, as mais úteis para atribuição): T1003 OS Credential Dumping, T1553.002 Code Signing, T1046 Network Service Discovery, T1078 Valid Accounts, T1059.003 Windows Command Shell.

## 2. Quem é

> Suckfly is a China-based threat group that has been active since at least 2014.

_Texto original do MITRE ATT&CK, em inglês._

## 3. Contexto, nomes e alvos

Consolidado pelo [APT4ALL](https://github.com/Ridd1kulusC0d3r/apt4all) a partir de MISP Galaxy, planilha APT Groups & Operations, EternalLiberty e APTnotes. Atribuição é afirmação de quem publicou; confira a fonte.

| Campo | Valor |
|---|---|
| Origem atribuída | China |
| Motivação | indefinido |
| Setores-alvo | — |
| Vítimas citadas | — |
| Alvos (planilha) | Indian organisations and Republic of Korea \| South Korea, India |
| Operações conhecidas | — |
| Confiança de atribuição (MISP) | 50 |

**Como cada fornecedor chama este grupo** (útil para cruzar relatórios):

| Fornecedor | Nome(s) |
|---|---|
| MITRE ATT&CK | G0039 |

**Outros nomes no APT4ALL (não listados pelo ATT&CK):** APT22, BRONZE OLIVE, Group 46, Wicked Spider, Bronze Olive/Bronze Export, TG-3279, Barista

## 4. Perfil TTP por tática (kill chain)

Cada linha: técnica, como o grupo a usou segundo relatos públicos, e o que existe para detectar e testar.

### Initial Access (TA0001) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | Suckfly used legitimate account credentials that they dumped to navigate the internal victim network as though they were the legitimate account owner. | 825 | — | 3 |

### Execution (TA0002) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1059.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.003) Windows Command Shell | Several tools used by Suckfly have been command-line driven. | 269 | 6 | 1 |

### Persistence (TA0003) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | Suckfly used legitimate account credentials that they dumped to navigate the internal victim network as though they were the legitimate account owner. | 825 | — | 3 |

### Privilege Escalation (TA0004) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | Suckfly used legitimate account credentials that they dumped to navigate the internal victim network as though they were the legitimate account owner. | 825 | — | 3 |

### Stealth (TA0005) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | Suckfly used legitimate account credentials that they dumped to navigate the internal victim network as though they were the legitimate account owner. | 825 | — | 3 |

### Defense Impairment (TA0112) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1553.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1553.002) Code Signing | Suckfly has used stolen certificates to sign its malware. | 11 | — | — |

### Credential Access (TA0006) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1003) OS Credential Dumping | Suckfly used a signed credential-dumping tool to obtain victim account credentials. | 399 | 7 | 19 |

### Discovery (TA0007) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1046](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1046) Network Service Discovery | Suckfly the victim's internal network for hosts with ports 8080, 5900, and 40 open. | 212 | 13 | 2 |

## 5. Assinatura comportamental

Técnicas que este grupo usa e que poucos dos 178 grupos do ATT&CK usam. Pesam mais numa atribuição por TTP: ver várias delas juntas é mais informativo do que ver técnicas comuns como PowerShell.

| Técnica | Outros grupos que usam | Peso (raridade) |
|---|---:|---:|
| T1003 OS Credential Dumping | 12 | 2.55 |
| T1553.002 Code Signing | 27 | 1.82 |
| T1046 Network Service Discovery | 32 | 1.66 |
| T1078 Valid Accounts | 48 | 1.27 |
| T1059.003 Windows Command Shell | 72 | 0.88 |

## 6. Arsenal

| Software | Tipo | Técnicas no ATT&CK | Uso relatado (EN) |
|---|---|---:|---|
| [Nidiran](https://attack.mitre.org/software/S0118/) | malware | 3 |  |

**Outras ferramentas e malware relatados (planilha APT Groups & Operations / MISP):** Korplug, PlugX, tcpscan, smbscan, wce, gsecdump, credentialdumper

## 7. Campanhas

Nenhuma campanha atribuída no ATT&CK.

## 8. Cobertura defensiva

**5 de 5 técnicas (100%)** têm ao menos uma regra pública no catálogo Detection Rules.

### Onde procurar — cobertura por tecnologia

Quantas técnicas deste grupo têm ao menos uma regra em cada tecnologia. Comece a caça pelas tecnologias que você tem e que aparecem aqui.

| Tecnologia | Técnicas do grupo com regra |
|---|---:|
| Windows | 5 |
| Linux | 4 |
| macOS | 4 |
| EDR / XDR | 4 |
| AWS | 4 |
| Azure (recursos) | 4 |
| DNS | 4 |
| Proxy / SWG | 4 |
| VPN & acesso remoto | 4 |
| Servidores web & aplicações | 4 |
| Bancos de dados | 4 |
| Outros / genérico | 4 |

### Regras recomendadas por técnica

Melhor regra disponível por técnica (formato portável e maduro primeiro).

| Técnica | Regra | Formato | Fonte |
|---|---|---|---|
| T1003 | [Antivirus - Password Dumper Signature](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A78cc2dd2-7d20-4d32-93ff-057084c38b93) | Sigma | SigmaHQ |
| T1003 | [HackTool - Rubeus Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A7ec2c172-dceb-4c10-92c9-87c1881b7e18) | Sigma | SigmaHQ |
| T1046 | [HackTool - winPEAS Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A98b53e78-ebaf-46f8-be06-421aafd176d9) | Sigma | SigmaHQ |
| T1046 | [HackTool - WinPwn Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad557dc06-62e8-4468-a8e8-7984124908ce) | Sigma | SigmaHQ |
| T1059.003 | [HackTool - CrackMapExec Execution Patterns](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A058f4380-962d-40a5-afce-50207d36d7e2) | Sigma | SigmaHQ |
| T1059.003 | [CrackMapExec Command Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A058f4380-962d-40a5-afce-50207d36d7e2) | Sigma | OpenSearch Security Analytics |
| T1078 | [Privilege Role Sign-In Outside Expected Controls](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acf1e5687-84e1-41af-97a9-158094efef53) | Sigma | SigmaHQ |
| T1078 | [OpenCanary - SSH Login Attempt](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aff7139bc-fdb1-4437-92f2-6afefe8884cb) | Sigma | SigmaHQ |
| T1553.002 | [Driver Loaded (Invalid Signature)](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=hayabusa-native%3A%3A1f666722-3948-40a2-9d78-d9d374477a90) | Sigma | Hayabusa (native) |
| T1553.002 | [Driver Loaded (Expired/Revoked Cert)](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=hayabusa-native%3A%3Ac837dd6d-0c91-4593-aeab-f6a1f3ca1961) | Sigma | Hayabusa (native) |

## 9. Plano de emulação e validação

Use num laboratório isolado e autorizado para confirmar que as regras disparam. Os comandos estão nos repositórios oficiais.

| Tática | Técnica | Teste Atomic Red Team | Plataformas |
|---|---|---|---|
| Execution | [T1059.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.003/T1059.003.md) | Create and Execute Batch Script | windows |
| Execution | [T1059.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.003/T1059.003.md) | Writes text to a file and displays it. | windows |
| Credential Access | [T1003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003/T1003.md) | Gsecdump | windows |
| Credential Access | [T1003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003/T1003.md) | Credential Dumping with NPPSpy | windows |
| Discovery | [T1046](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1046/T1046.md) | Port Scan | linux, macos |
| Discovery | [T1046](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1046/T1046.md) | Port Scan Nmap | linux, macos |

**Logs reais de ataque (EVTX) para testar sem executar nada:**

- T1003 — [ID1-12-13-Wdigest authentication activation](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0006-Credential%20Access/T1003-Credential%20dumping/ID1-12-13-Wdigest%20authentication%20activation.evtx) _(explícito)_
- T1003 — [ID1-LSASS dump with LSASSY (SYSMON)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0006-Credential%20Access/T1003-Credential%20dumping/ID1-LSASS%20dump%20with%20LSASSY%20%28SYSMON%29.evtx) _(explícito)_
- T1046 — [ID131-RDP brutforce (no user info)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1046-Network%20Service%20Scanning/ID131-RDP%20brutforce%20%28no%20user%20info%29.evtx) _(explícito)_
- T1046 — [ID4624-Anonymous login with domain specified (DonPapi)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1046-Network%20Service%20Scanning/ID4624-Anonymous%20login%20with%20domain%20specified%20%28DonPapi%29.evtx) _(explícito)_
- T1059.003 — [ID4688-SQL Server payload injectection for reverse shell (MSF)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1059.003-Windows%20Command%20Shell/ID4688-SQL%20Server%20payload%20injectection%20for%20reverse%20shell%20%28MSF%29.evtx) _(explícito)_
- T1078 — [ID1149-RDP success logins to multiple hosts](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0001-Initial%20access/T1078-Valid%20accounts/ID1149-RDP%20success%20logins%20to%20multiple%20hosts.evtx) _(explícito)_
- T1078 — [ID33205-SQL Server failed login with disabled SA account](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0001-Initial%20access/T1078-Valid%20accounts/ID33205-SQL%20Server%20failed%20login%20with%20disabled%20SA%20account.evtx) _(explícito)_

## 10. Hipóteses de hunting

Se Suckfly estiver no seu ambiente, estas são as perguntas a fazer aos seus dados (fontes de log segundo as estratégias de detecção do MITRE ATT&CK).

1. **T1003 OS Credential Dumping** — Processes accessing LSASS memory or SAM registry hives outside of trusted security tools, often followed by file creation or lateral movement. Detects unauthorized access to sensitive OS subsystems for credential extraction. Dados: `WinEventLog:Sysmon` (EventCode=10), `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Security` (EventCode=4663, 4670, 4656).
2. **T1553.002 Code Signing** — Detects execution of binaries signed with unusual or recently issued certificates, correlation of process execution with abnormal publisher metadata, and mismatched certificate chains. Monitors for revoked or unknown code signing certificates used in… Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=7).
3. **T1046 Network Service Discovery** — Detects processes performing network enumeration (e.g., port scans, service probing) by correlating process creation, socket connections, and sequential destination IP probing within a time window. Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=3, 22).
4. **T1078 Valid Accounts** — Detection of compromised or misused valid accounts via anomalous logon patterns, abnormal logon types, and inconsistent geographic or time-based activity across Windows endpoints. Dados: `WinEventLog:Security` (EventCode=4624), `WinEventLog:Security` (EventCode=4776, 4625), `WinEventLog:Sysmon` (EventCode=1).
5. **T1059.003 Windows Command Shell** — Detects interactive or scripted abuse of cmd.exe, batch files, or shell invocation chains. Focuses on parent-child relationships (e.g., cmd.exe launched from unusual parents), anomalous command-line parameters, and chaining with discovery, credential access,… Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=7), `EDR:scriptblock` (Process Tree + Script Block Logging).

## 11. OSINT — onde pesquisar

Consultas prontas com todos os nomes conhecidos do grupo:

- Relatórios técnicos: [busca web](https://duckduckgo.com/?q=%28%22Suckfly%22%29+threat+report) · [PDFs](https://duckduckgo.com/?q=%28%22Suckfly%22%29+filetype%3Apdf)
- Regras e IOCs publicados: [GitHub](https://github.com/search?type=code&q=%22Suckfly%22)
- Pulsos de ameaça: [AlienVault OTX](https://otx.alienvault.com/browse/global/pulses?q=Suckfly)
- Família de malware e atores: [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/actors) (busque por Suckfly)
- Cartões de grupo: [ThaiCERT Threat Group Cards](https://apt.etda.or.th/cgi-bin/listgroups.cgi)
- Página oficial: [MITRE ATT&CK G0039](https://attack.mitre.org/groups/G0039/)

**Relatórios na coleção CyberMonitor** (ligados pelo nome do grupo, conferir antes de citar):

- 2016 — [suckfly-revealing-secret-life-your-code-signing-certificates](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2016/2016.03.15.Suckfly/suckfly-revealing-secret-life-your-code-signing-certificates.pdf) _(via “Suckfly”)_
- 2016 — [indian-organizations-targeted-suckfly-attacks](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2016/2016.05.17.Indian_organizations_targeted_in_Suckfly_attacks/indian-organizations-targeted-suckfly-attacks.pdf) _(via “Suckfly”)_

**Relatórios públicos ligados pelo APT4ALL** (2 no total, mais recentes primeiro):

- 2016 — [Indian organizations targeted in Suckfly attacks](https://app.box.com/s/nekeu5y0v2yk4rdwpuq8y1ahyyuaduen) _(Symantec)_
- 2016 — [Suckfly: Revealing the secret life of your code signing certificates](https://app.box.com/s/p3tmorslyk9q1s3s6eul4xa4148o6fp2) _(Symantec)_

## 12. Bibliografia (2 fontes citadas pelo ATT&CK)

- [Symantec Suckfly March 2016](http://www.symantec.com/connect/blogs/suckfly-revealing-secret-life-your-code-signing-certificates) — DiMaggio, J. (2016, March 15). Suckfly: Revealing the secret life of your code signing certificates. Retrieved August 3, 2016.
- [Symantec Suckfly May 2016](http://www.symantec.com/connect/blogs/indian-organizations-targeted-suckfly-attacks) — DiMaggio, J. (2016, May 17). Indian organizations targeted in Suckfly attacks. Retrieved August 3, 2016.

## 13. Limites e confiança

- O ATT&CK registra o que foi **relatado publicamente**, não tudo o que o grupo faz. Ausência de uma técnica não prova que o grupo não a usa.
- **Sobreposição de TTP não é atribuição.** Muitas técnicas são compartilhadas entre grupos e com red teams. Use a assinatura comportamental como hipótese, junto com infraestrutura, malware e contexto.
- Cobertura de detecção refere-se ao catálogo público Detection Rules, não ao seu ambiente: confira se a telemetria necessária chega ao seu SIEM.
- Ligações marcadas como _inferidas_ (EVTX por palavra-chave, relatórios por nome) devem ser verificadas.

---
Fontes: MITRE ATT&CK® (uso livre com atribuição, © The MITRE Corporation), APT4ALL (MISP Galaxy CC0/BSD-2, APT Groups & Operations CC BY 4.0, EternalLiberty, APTnotes, Ransomware Tool Matrix CC BY 4.0), Atomic Red Team (Red Canary, MIT), EVTX-to-MITRE-Attack, EVTX-ATTACK-SAMPLES, APT & CyberCriminal Campaign Collections. Gerado por [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules).
