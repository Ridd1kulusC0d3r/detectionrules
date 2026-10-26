# Ember Bear (G1003) — Dossiê de inteligência

> **TLP:CLEAR** · gerado em 2026-10-26 a partir de fontes abertas · MITRE ATT&CK v20.0 · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1003) · [ATT&CK](https://attack.mitre.org/groups/G1003/)

**Também conhecido como:** UNC2589, Bleeding Bear, DEV-0586, Cadet Blizzard, Frozenvista, UAC-0056  
**Origem atribuída:** Rússia · **Motivação:** espionagem, financeiro, sabotagem, hacktivismo · **Setores-alvo:** —  
**Registro no ATT&CK:** criado em 2022-06-09, atualizado em 2026-07-31 · referências de 2022 a 2024

## 1. Sumário executivo

- **47 técnicas** atribuídas publicamente, concentradas em **Credential Access, Collection, Persistence**.
- **Arsenal:** 4 malware e 7 ferramentas (ex.: Saint Bot, WhisperGate, CrackMapExec, P.A.S. Webshell, BloodHound).
- **Campanhas atribuídas:** 0.
- **Cobertura de detecção pública:** 96% das técnicas têm ao menos uma regra no catálogo; **2 técnicas sem nenhuma regra pública**.
- **Origem e alvos (APT4ALL):** atribuído a **Rússia**, motivação espionagem, financeiro, sabotagem, hacktivismo; 1 países vítimas citados.
- **Onde a cobertura está:** Windows (40 técnicas com regra), EDR / XDR (38 técnicas com regra), Outros / genérico (35 técnicas com regra), Linux (32 técnicas com regra).
- **Assinatura comportamental** (técnicas raras entre os 178 grupos, as mais úteis para atribuição): T1491.002 External Defacement, T1595.001 Scanning IP Blocks, T1021 Remote Services, T1195 Supply Chain Compromise, T1588.005 Exploits.

## 2. Quem é

> Ember Bear is a Russian state-sponsored cyber espionage group that has been active since at least 2020, linked to Russia's General Staff Main Intelligence Directorate (GRU) 161st Specialist Training Center (Unit 29155). Ember Bear has primarily focused operations against Ukrainian government and telecommunication entities, but has also operated against critical infrastructure entities in Europe and the Americas. Ember Bear conducted the WhisperGate destructive wiper attacks against Ukraine in early 2022. There is some confusion as to whether Ember Bear overlaps with another Russian-linked entity referred to as Saint Bear. At present available evidence strongly suggests these are distinct activities with different behavioral profiles.

_Texto original do MITRE ATT&CK, em inglês._

## 3. Contexto, nomes e alvos

Consolidado pelo [APT4ALL](https://github.com/Ridd1kulusC0d3r/apt4all) a partir de MISP Galaxy, planilha APT Groups & Operations, EternalLiberty e APTnotes. Atribuição é afirmação de quem publicou; confira a fonte.

| Campo | Valor |
|---|---|
| Origem atribuída | Rússia |
| Motivação | espionagem, financeiro, sabotagem, hacktivismo |
| Setores-alvo | — |
| Vítimas citadas | Ukraine |
| Alvos (planilha) | Ukraine, limited evidence to suggest that the group has been involved in attacks on targets in Kyrgyzstan. Third-party reporting has also linked the group to attacks on Georgia. |
| Operações conhecidas | — |
| Confiança de atribuição (MISP) | High |

**Como cada fornecedor chama este grupo** (útil para cruzar relatórios):

| Fornecedor | Nome(s) |
|---|---|
| MITRE ATT&CK | G1003 |

**Outros nomes no APT4ALL (não listados pelo ATT&CK):** Lorec53, Lorec Bear, Saint Bear, TA471, Nascent Ursa, Ruinous Ursa, Nodaria, DEV-0586/Cadet Blizzard

## 4. Perfil TTP por tática (kill chain)

Cada linha: técnica, como o grupo a usou segundo relatos públicos, e o que existe para detectar e testar.

### Reconnaissance (TA0043) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1595.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1595.001) Scanning IP Blocks | Ember Bear has targeted IP ranges for vulnerability scanning related to government and critical infrastructure organizations. | 13 | — | — |
| [T1595.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1595.002) Vulnerability Scanning | Ember Bear has used publicly available tools such as MASSCAN and Acunetix for vulnerability scanning of public-facing infrastructure. | 27 | — | — |

### Resource Development (TA0042) — 5

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1583](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1583) Acquire Infrastructure | Ember Bear uses services such as IVPN, SurfShark, and Tor to add anonymization to operations. | 9 | — | — |
| [T1583.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1583.003) Virtual Private Server | Ember Bear has used virtual private servers (VPSs) to host tools, perform reconnaissance, exploit victim infrastructure, and as a destination for data exfiltration. | **0** | — | — |
| [T1585](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1585) Establish Accounts | Ember Bear has created accounts on dark web forums to obtain various tools and malware. | 1 | — | — |
| [T1588.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1588.001) Malware | Ember Bear has acquired malware and related tools from dark web forums. | 7 | — | — |
| [T1588.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1588.005) Exploits | Ember Bear has obtained exploitation scripts against publicly-disclosed vulnerabilities from public repositories. | **0** | — | — |

### Initial Access (TA0001) — 4

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1078.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.001) Default Accounts | Ember Bear has abused default user names and passwords in externally-accessible IP cameras for initial access. | 16 | 3 | — |
| [T1133](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1133) External Remote Services | Ember Bear have used VPNs both for initial access to victim environments and for persistence within them following compromise. | 361 | 1 | — |
| [T1190](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1190) Exploit Public-Facing Application | Ember Bear gains initial access to victim environments by exploiting external-facing services. Examples include exploitation of CVE-2021-26084 in Confluence servers; CVE-2022-41040, ProxyShell, and other vulnerabilities in Microsoft Exchange; and multiple vuln… | 580 | — | — |
| [T1195](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1195) Supply Chain Compromise | Ember Bear has compromised information technology providers and software developers providing services to targets of interest, building initial access to ultimate victims at least in part through compromise of service providers that work with the victim organi… | 83 | 1 | — |

### Execution (TA0002) — 4

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1047](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1047) Windows Management Instrumentation | Ember Bear has used WMI execution with password hashes for command execution and lateral movement. | 370 | 12 | 11 |
| [T1053.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1053.005) Scheduled Task | Ember Bear uses remotely scheduled tasks to facilitate remote command execution on victim machines. | 248 | 14 | 11 |
| [T1059.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.001) PowerShell | Ember Bear has used PowerShell commands to gather information from compromised systems, such as email servers. | 1340 | 22 | 15 |
| [T1203](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1203) Exploitation for Client Execution | Ember Bear has used exploits to enable follow-on execution of frameworks such as Meterpreter. | 202 | — | — |

### Persistence (TA0003) — 5

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1053.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1053.005) Scheduled Task | Ember Bear uses remotely scheduled tasks to facilitate remote command execution on victim machines. | 248 | 14 | 11 |
| [T1078.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.001) Default Accounts | Ember Bear has abused default user names and passwords in externally-accessible IP cameras for initial access. | 16 | 3 | — |
| [T1112](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1112) Modify Registry | Ember Bear modifies registry values for anti-forensics and defense evasion purposes. | 601 | 92 | 3 |
| [T1133](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1133) External Remote Services | Ember Bear have used VPNs both for initial access to victim environments and for persistence within them following compromise. | 361 | 1 | — |
| [T1505.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1505.003) Web Shell | Ember Bear deploys web shells following initial access for either follow-on command execution or protocol tunneling. Example web shells used by Ember Bear include P0wnyshell, reGeorg, P.A.S. Webshell, and custom variants of publicly-available web shell example… | 210 | 1 | — |

### Privilege Escalation (TA0004) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1053.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1053.005) Scheduled Task | Ember Bear uses remotely scheduled tasks to facilitate remote command execution on victim machines. | 248 | 14 | 11 |
| [T1078.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.001) Default Accounts | Ember Bear has abused default user names and passwords in externally-accessible IP cameras for initial access. | 16 | 3 | — |

### Stealth (TA0005) — 4

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1036](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1036) Masquerading | Ember Bear has renamed the legitimate Sysinternals tool procdump to alternative names such as dump64.exe to evade detection. | 453 | 2 | 1 |
| [T1036.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1036.005) Match Legitimate Resource Name or Location | Ember Bear has renamed tools to match legitimate utilities, such as renaming GOST tunneling instances to `java` in victim environments. | 116 | 4 | — |
| [T1070.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1070.004) File Deletion | Ember Bear deletes files related to lateral movement to avoid detection. | 132 | 11 | — |
| [T1078.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.001) Default Accounts | Ember Bear has abused default user names and passwords in externally-accessible IP cameras for initial access. | 16 | 3 | — |

### Defense Impairment (TA0112) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1112](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1112) Modify Registry | Ember Bear modifies registry values for anti-forensics and defense evasion purposes. | 601 | 92 | 3 |

### Credential Access (TA0006) — 7

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1003) OS Credential Dumping | Ember Bear gathers credential material from target systems, such as SSH keys, to facilitate access to victim environments. | 399 | 7 | 19 |
| [T1003.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1003.001) LSASS Memory | Ember Bear uses legitimate Sysinternals tools such as procdump to dump LSASS memory. | 580 | 14 | 10 |
| [T1003.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1003.002) Security Account Manager | Ember Bear acquires victim credentials by extracting registry hives such as the Security Account Manager through commands such as reg save. | 169 | 8 | — |
| [T1003.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1003.004) LSA Secrets | Ember Bear has used frameworks such as Impacket to dump LSA secrets for credential capture. | 72 | 2 | — |
| [T1110](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1110) Brute Force | Ember Bear used the `su-bruteforce` tool to brute force specific users using the `su` command. | 381 | — | 12 |
| [T1110.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1110.003) Password Spraying | Ember Bear has conducted password spraying against Outlook Web Access (OWA) infrastructure to identify valid user names and passwords. | 62 | 9 | 1 |
| [T1552.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1552.001) Credentials In Files | Ember Bear has dumped configuration settings in accessed IP cameras including plaintext credentials. | 166 | 32 | — |

### Discovery (TA0007) — 3

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1018](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1018) Remote System Discovery | Ember Bear has used tools such as Nmap and MASSCAN for remote service discovery. | 157 | 23 | 1 |
| [T1046](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1046) Network Service Discovery | Ember Bear has used tools such as NMAP for remote system discovery and enumeration in victim environments. | 212 | 13 | 2 |
| [T1654](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1654) Log Enumeration | Ember Bear has enumerated SECURITY and SYSTEM log files during intrusions. | 3 | 2 | — |

### Lateral Movement (TA0008) — 4

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1021](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1021) Remote Services | Ember Bear uses valid network credentials gathered through credential harvesting to move laterally within victim networks, often employing the Impacket framework to do so. | 289 | — | 47 |
| [T1210](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1210) Exploitation of Remote Services | Ember Bear has used exploits for vulnerabilities such as MS17-010, also known as `Eternal Blue`, during operations. | 192 | — | 4 |
| [T1550.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1550.002) Pass the Hash | Ember Bear has used pass-the-hash techniques for lateral movement in victim environments. | 43 | 3 | 1 |
| [T1570](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1570) Lateral Tool Transfer | Ember Bear retrieves follow-on payloads direct from adversary-owned infrastructure for deployment on compromised hosts. | 58 | 2 | — |

### Collection (TA0009) — 5

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1005) Data from Local System | Ember Bear gathers victim system information such as enumerating the volume of a given device or extracting system and security event logs for analysis. | 170 | 3 | — |
| [T1114](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1114) Email Collection | Ember Bear attempts to collect mail from accessed systems and servers. | 119 | — | — |
| [T1119](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1119) Automated Collection | Ember Bear engages in mass collection from compromised systems during intrusions. | 72 | 4 | — |
| [T1125](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1125) Video Capture | Ember Bear has exfiltrated images from compromised IP cameras. | 13 | 1 | 1 |
| [T1560](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1560) Archive Collected Data | Ember Bear has compressed collected data prior to exfiltration. | 53 | 1 | — |

### Command and Control (TA0011) — 5

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1071.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1071.004) DNS | Ember Bear has used DNS tunnelling tools, such as dnscat/2 and Iodine, for C2 purposes. | 117 | 4 | — |
| [T1090.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1090.003) Multi-hop Proxy | Ember Bear has configured multi-hop proxies via ProxyChains within victim environments. | 44 | 4 | — |
| [T1095](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1095) Non-Application Layer Protocol | Ember Bear uses socket-based tunneling utilities for command and control purposes such as NetCat and Go Simple Tunnel (GOST). These tunnels are used to push interactive command prompts over the created sockets. Ember Bear has also used reverse TCP connections … | 72 | 5 | — |
| [T1571](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1571) Non-Standard Port | Ember Bear has used various non-standard ports for C2 communication. | 163 | 2 | — |
| [T1572](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1572) Protocol Tunneling | Ember Bear has used ProxyChains to tunnel protocols to internal networks. | 173 | 9 | 1 |

### Exfiltration (TA0010) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1567.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1567.002) Exfiltration to Cloud Storage | Ember Bear has used tools such as Rclone to exfiltrate information from victim environments to cloud storage such as `mega.nz`. | 85 | 2 | — |

### Impact (TA0040) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1491.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1491.002) External Defacement | Ember Bear is linked to the defacement of several Ukrainian organization websites. | 1 | — | — |
| [T1561.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1561.002) Disk Structure Wipe | Ember Bear conducted destructive operations against victims, including disk structure wiping, via the WhisperGate malware in Ukraine. | 2 | — | — |

## 5. Assinatura comportamental

Técnicas que este grupo usa e que poucos dos 178 grupos do ATT&CK usam. Pesam mais numa atribuição por TTP: ver várias delas juntas é mais informativo do que ver técnicas comuns como PowerShell.

| Técnica | Outros grupos que usam | Peso (raridade) |
|---|---:|---:|
| T1491.002 External Defacement | 1 | 4.09 |
| T1595.001 Scanning IP Blocks | 1 | 4.09 |
| T1021 Remote Services | 2 | 3.80 |
| T1195 Supply Chain Compromise | 2 | 3.80 |
| T1588.005 Exploits | 2 | 3.80 |
| T1078.001 Default Accounts | 3 | 3.58 |
| T1114 Email Collection | 3 | 3.58 |
| T1125 Video Capture | 3 | 3.58 |
| T1654 Log Enumeration | 4 | 3.40 |
| T1561.002 Disk Structure Wipe | 5 | 3.24 |

## 6. Arsenal

| Software | Tipo | Técnicas no ATT&CK | Uso relatado (EN) |
|---|---|---:|---|
| [Saint Bot](https://attack.mitre.org/software/S1018/) | malware | 37 | Ember Bear has used Saint Bot during operations, but is distinct from the threat actor Saint Bear. |
| [WhisperGate](https://attack.mitre.org/software/S0689/) | malware | 28 | Ember Bear is associated with WhisperGate use against multiple victims in Ukraine. |
| [CrackMapExec](https://attack.mitre.org/software/S0488/) | ferramenta | 20 | Ember Bear used CrackMapExec during intrusions. |
| [P.A.S. Webshell](https://attack.mitre.org/software/S0598/) | malware | 15 | Ember Bear has used P.A.S. Webshell during intrusions. |
| [BloodHound](https://attack.mitre.org/software/S0521/) | ferramenta | 11 | Ember Bear has used BloodHound to profile Active Directory environments. |
| [Impacket](https://attack.mitre.org/software/S0357/) | ferramenta | 11 | Ember Bear has used Impacket for lateral movement and process execution in victim environments. |
| [reGeorg](https://attack.mitre.org/software/S1187/) | malware | 10 |  |
| [Rclone](https://attack.mitre.org/software/S1040/) | ferramenta | 6 | Ember Bear has used Rclone to exfiltrate information from victim environments. |
| [ngrok](https://attack.mitre.org/software/S0508/) | ferramenta | 5 | Ember Bear used ngrok during intrusions against Ukrainian victims. |
| [PsExec](https://attack.mitre.org/software/S0029/) | ferramenta | 5 | Ember Bear has used PsExec through frameworks such as Impacket for remote command execution. |
| [Responder](https://attack.mitre.org/software/S0174/) | ferramenta | 2 | Ember Bear has used Responder in intrusions. |

**Outras ferramentas e malware relatados (planilha APT Groups & Operations / MISP):** WhisperGate wiper, Elephant Framework, Graphiron

## 7. Campanhas

Nenhuma campanha atribuída no ATT&CK.

## 8. Cobertura defensiva

**45 de 47 técnicas (96%)** têm ao menos uma regra pública no catálogo Detection Rules.

### Técnicas sem regra pública (prioridade para engenharia de detecção)

- **T1588.005 Exploits** — Resource Development
- **T1583.003 Virtual Private Server** — Resource Development. Fonte de log sugerida pelo MITRE: `Internet Scan` None

### Onde procurar — cobertura por tecnologia

Quantas técnicas deste grupo têm ao menos uma regra em cada tecnologia. Comece a caça pelas tecnologias que você tem e que aparecem aqui.

| Tecnologia | Técnicas do grupo com regra |
|---|---:|
| Windows | 40 |
| EDR / XDR | 38 |
| Outros / genérico | 35 |
| Linux | 32 |
| Servidores web & aplicações | 31 |
| Proxy / SWG | 29 |
| Firewall & perímetro | 28 |
| IDS / NSM / NDR | 27 |
| DNS | 27 |
| Active Directory | 26 |
| AWS | 26 |
| macOS | 24 |

### Regras recomendadas por técnica

Melhor regra disponível por técnica (formato portável e maduro primeiro).

| Técnica | Regra | Formato | Fonte |
|---|---|---|---|
| T1003 | [Antivirus - Password Dumper Signature](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A78cc2dd2-7d20-4d32-93ff-057084c38b93) | Sigma | SigmaHQ |
| T1003 | [HackTool - Rubeus Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A7ec2c172-dceb-4c10-92c9-87c1881b7e18) | Sigma | SigmaHQ |
| T1003.001 | [Antivirus - Password Dumper Signature](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A78cc2dd2-7d20-4d32-93ff-057084c38b93) | Sigma | SigmaHQ |
| T1003.001 | [Mimikatz through Windows Remote Management](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Aaa35a627-33fb-4d04-a165-d33b4afca3e8) | Sigma | OpenSearch Security Analytics |
| T1003.002 | [Antivirus - Password Dumper Signature](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A78cc2dd2-7d20-4d32-93ff-057084c38b93) | Sigma | SigmaHQ |
| T1003.002 | [VolumeShadowCopy Symlink Creation Via Mklink](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A40b19fa6-d835-400c-b301-41f3a2baacaf) | Sigma | SigmaHQ |
| T1003.004 | [Possible Impacket SecretDump Remote Activity - Zeek](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A92dae1ed-1c9d-4eff-a567-33acbd95b00e) | Sigma | SigmaHQ |
| T1003.004 | [Cred Dump Tools Dropped Files](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A8fbf3271-1ef6-4e94-8210-03c2317947f6) | Sigma | SigmaHQ |
| T1005 | [Potential Conti Ransomware Database Dumping Activity Via SQLCmd](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A2f47f1fd-0901-466e-a770-3b7092834a1b) | Sigma | SigmaHQ |
| T1005 | [OpenCanary - SMB File Open Request](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A22777c9e-873a-4b49-855f-6072ab861a52) | Sigma | SigmaHQ |
| T1018 | [Chopper Webshell Process Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Afa3c117a-bc0d-416e-a31b-0c0e80653efb) | Sigma | SigmaHQ |
| T1018 | [Webshell Hacking Activity Patterns](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4ebc877f-4612-45cb-b3a5-8e3834db36c9) | Sigma | SigmaHQ |
| T1021 | [New RDP Connection Initiated From Domain Controller](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Afda34293-718e-4b36-b018-38caab0d1209) | Sigma | SigmaHQ |
| T1021 | [OpenCanary - VNC Connection Attempt](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A9db5446c-b44a-4291-8b89-fcab5609c3b3) | Sigma | SigmaHQ |
| T1036 | [Potential LSASS Process Dump Via Procdump](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A5afee48e-67dd-4e03-a783-f74259dcf998) | Sigma | SigmaHQ |
| T1036 | [Suspicious Use of Procdump on LSASS](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A5afee48e-67dd-4e03-a783-f74259dcf998) | Sigma | OpenSearch Security Analytics |
| T1036.005 | [Exploit for CVE-2015-1641](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A7993792c-5ce2-4475-a3db-a3a5539827ef) | Sigma | SigmaHQ |
| T1036.005 | [Exploit for CVE-2015-1641](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A7993792c-5ce2-4475-a3db-a3a5539827ef) | Sigma | OpenSearch Security Analytics |
| T1046 | [HackTool - winPEAS Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A98b53e78-ebaf-46f8-be06-421aafd176d9) | Sigma | SigmaHQ |
| T1046 | [HackTool - WinPwn Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad557dc06-62e8-4468-a8e8-7984124908ce) | Sigma | SigmaHQ |
| T1047 | [HackTool - Potential Impacket Lateral Movement Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A10c14723-61c7-4c75-92ca-9af245723ad2) | Sigma | SigmaHQ |
| T1047 | [CrackMapExec Command Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A058f4380-962d-40a5-afce-50207d36d7e2) | Sigma | OpenSearch Security Analytics |
| T1053.005 | [Operation Wocao Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1cfac73c-be78-4f9a-9b08-5bde0c3953ab) | Sigma | SigmaHQ |
| T1053.005 | [Operation Wocao Activity - Security](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A74ad4314-482e-4c3e-b237-3f7ed3b9ca8d) | Sigma | SigmaHQ |
| T1059.001 | [Potential Emotet Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad02e8cf5-6099-48cf-9bfc-1eec2d0c7b18) | Sigma | SigmaHQ |
| T1059.001 | [TropicTrooper Campaign November 2018](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A8c7090c3-e0a0-4944-bd08-08c3a0cecf79) | Sigma | SigmaHQ |
| T1070.004 | [File Deletion](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A30aed7b6-d2c1-4eaf-9382-b6bc43e50c57) | Sigma | SigmaHQ |
| T1070.004 | [Prefetch File Deleted](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A0a1f9d29-6465-4776-b091-7f43b26e4c89) | Sigma | SigmaHQ |
| T1071.004 | [OilRig APT Registry Persistence](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A7bdf2a7c-3acc-4091-9581-0a77dad1c5b5) | Sigma | SigmaHQ |
| T1071.004 | [OilRig APT Schedule Task Persistence - Security](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac0580559-a6bd-4ef6-b9b7-83703d98b561) | Sigma | SigmaHQ |
| T1078.001 | [Admin User Remote Logon](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A0f63e1ef-1eb9-4226-9d54-8927ca08520a) | Sigma | SigmaHQ |
| T1078.001 | [Guest Account Enabled Via Sysadminctl](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad7329412-13bd-44ba-a072-3387f804a106) | Sigma | SigmaHQ |
| T1090.003 | [Tor Client/Browser Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A62f7c9bf-9135-49b2-8aeb-1e54a6ecc13c) | Sigma | SigmaHQ |
| T1090.003 | [Query Tor Onion Address - DNS Client](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A8384bd26-bde6-4da9-8e5d-4174a7a47ca2) | Sigma | SigmaHQ |
| T1095 | [PUA - Netcat Suspicious Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae31033fc-33f0-4020-9a16-faf9b31cbf08) | Sigma | SigmaHQ |
| T1095 | [Suspicious React Server Child Process](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Aae3e9625-89ad-4fc3-a7bf-fced5e64f01b) | Elastic | Elastic detection-rules |
| T1110 | [Hack Tool User Agent](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac42a3073-30fb-48ae-8c99-c23ada84b103) | Sigma | SigmaHQ |
| T1110 | [HackTool - CrackMapExec Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A42a993dd-bb3e-48c8-b372-4d6684c4106c) | Sigma | SigmaHQ |
| T1110.003 | [Multiple SonicWall Login Failures Followed by Successful Login](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Aefe7ac71-3b13-41cf-8263-30af68ce3f19) | Elastic | Elastic detection-rules |
| T1110.003 | [Potential Successful SSH Brute Force Attack](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A8cb84371-d053-4f4f-bce0-c74990e28f28) | Elastic | Elastic detection-rules |
| T1112 | [ShimCache Flush](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab0524451-19af-4efa-a46f-562a977f792e) | Sigma | SigmaHQ |
| T1112 | [ShimCache Flush](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Ab0524451-19af-4efa-a46f-562a977f792e) | Sigma | OpenSearch Security Analytics |
| T1114 | [Exchange PowerShell Snap-Ins Usage](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A25676e10-2121-446e-80a4-71ff8506af47) | Sigma | SigmaHQ |
| T1114 | [Hacktool Ruler](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A24549159-ac1b-479c-8175-d42aea947cae) | Sigma | SigmaHQ |
| T1119 | [iOS Implant URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Ae06ac91d-b9e6-443d-8e5b-af749e7aa6b6) | Sigma | OpenSearch Security Analytics |
| T1119 | [Shai-Hulud Malicious GitHub Workflow Creation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A0aba5685-6db6-486f-88ef-29a99c545cfd) | Sigma | SigmaHQ |
| T1125 | [Suspicious Camera and Microphone Access](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A62120148-6b7a-42be-8b91-271c04e281a3) | Sigma | SigmaHQ |
| T1125 | [Suspicious Camera and Microphone Access](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A62120148-6b7a-42be-8b91-271c04e281a3) | Sigma | OpenSearch Security Analytics |
| T1133 | [OpenCanary - SSH Login Attempt](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aff7139bc-fdb1-4437-92f2-6afefe8884cb) | Sigma | SigmaHQ |
| T1133 | [OpenCanary - SSH New Connection Attempt](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acd55f721-5623-4663-bd9b-5229cab5237d) | Sigma | SigmaHQ |
| T1190 | [OMIGOD HTTP No Authentication RCE - CVE-2021-38647](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aab6b1a39-a9ee-4ab4-b075-e83acf6e346b) | Sigma | SigmaHQ |
| T1190 | [Exploited CVE-2020-10189 Zoho ManageEngine](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A846b866e-2a57-46ee-8e16-85fa92759be7) | Sigma | OpenSearch Security Analytics |
| T1195 | [Octopus Scanner Malware](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A805c55d9-31e6-4846-9878-c34c75054fe9) | Sigma | SigmaHQ |
| T1195 | [Elastic Defend Alert from Package Manager Install Ancestry](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A344e6c7d-ceb0-4f20-ba04-7c75569a7e38) | Elastic | Elastic detection-rules |
| T1203 | [Droppers Exploiting CVE-2017-11882](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A678eb5f4-8597-4be6-8be7-905e4234b53a) | Sigma | SigmaHQ |
| T1203 | [OMIGOD HTTP No Authentication RCE - CVE-2021-38647](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aab6b1a39-a9ee-4ab4-b075-e83acf6e346b) | Sigma | SigmaHQ |
| T1210 | [OMIGOD HTTP No Authentication RCE - CVE-2021-38647](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aab6b1a39-a9ee-4ab4-b075-e83acf6e346b) | Sigma | SigmaHQ |
| T1210 | [OMIGOD HTTP No Authentication RCE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Aab6b1a39-a9ee-4ab4-b075-e83acf6e346b) | Sigma | OpenSearch Security Analytics |
| T1491.002 | [AWS S3 Static Site JavaScript File Uploaded](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A16acac42-b2f9-4802-9290-d6c30914db6e) | Elastic | Elastic detection-rules |
| T1505.003 | [MOVEit CVE-2023-34362 Exploitation Attempt - Potential Web Shell Request](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A435e41f2-48eb-4c95-8a2b-ed24b50ec30b) | Sigma | SigmaHQ |
| T1505.003 | [Solarwinds SUPERNOVA Webshell Access](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aa2cee20b-eacc-459f-861d-c02e5d12f1db) | Sigma | SigmaHQ |
| T1550.002 | [Hacktool Ruler](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A24549159-ac1b-479c-8175-d42aea947cae) | Sigma | SigmaHQ |
| T1550.002 | [Pass the Hash Activity 2](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A8eef149c-bd26-49f2-9e5a-9b00e3af499b) | Sigma | SigmaHQ |
| T1552.001 | [Potential Russian APT Credential Theft Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab83f5166-9237-4b5e-9cd4-7b5d52f4d8ee) | Sigma | SigmaHQ |
| T1552.001 | [Copy Passwd Or Shadow From TMP Path](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Afa4aaed5-4fe0-498d-bbc0-08e3346387ba) | Sigma | SigmaHQ |
| T1560 | [Conti NTDS Exfiltration Command](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aaa92fd02-09f2-48b0-8a93-864813fb8f41) | Sigma | SigmaHQ |
| T1560 | [Sensitive Files Compression Inside A Container](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ad9faf1ba-a216-4c29-b8e0-a05a9d14b027) | Elastic | Elastic detection-rules |
| T1561.002 | [Cisco File Deletion](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A71d65515-c436-43c0-841b-236b1f32c21e) | Sigma | SigmaHQ |
| T1561.002 | [Cisco File Deletion](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A71d65515-c436-43c0-841b-236b1f32c21e) | Sigma | OpenSearch Security Analytics |
| T1567.002 | [APT40 Dropbox Tool User Agent](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A5ba715b6-71b7-44fd-8245-f66893e81b3d) | Sigma | SigmaHQ |
| T1567.002 | [PUA - Rclone Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae37db05d-d1f9-49c8-b464-cee1a4b11638) | Sigma | SigmaHQ |
| T1570 | [PSExec Lateral Movement](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=hayabusa-native%3A%3A0694c340-3a46-40ac-acfc-c3444ae6572c) | Sigma | Hayabusa (native) |
| T1570 | [PSEXEC Remote Execution File Artefact](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A304afd73-55a5-4bb9-8c21-0b1fc84ea9e4) | Sigma | SigmaHQ |
| T1571 | [Potentially Suspicious Malware Callback Communication - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Adbfc7c98-04ab-4ab7-aa94-c74d22aa7376) | Sigma | SigmaHQ |
| T1571 | [Potentially Suspicious Malware Callback Communication](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4b89abaa-99fe-4232-afdd-8f9aa4d20382) | Sigma | SigmaHQ |
| T1572 | [Communication To LocaltoNet Tunneling Service Initiated - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac4568f5d-131f-4e78-83d4-45b2da0ec4f1) | Sigma | SigmaHQ |
| T1572 | [Communication To Ngrok Tunneling Service - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A19bf6fdb-7721-4f3d-867f-53467f6a5db6) | Sigma | SigmaHQ |
| T1583 | [AWS Route 53 Private Hosted Zone Associated With a VPC](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ae3c27562-709a-42bd-82f2-3ed926cced19) | Elastic | Elastic detection-rules |
| T1583 | [AWS Service Quota Increase Requested by Rare Identity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A7e1b0654-b6c0-4b1b-ab47-75588533083c) | Elastic | Elastic detection-rules |
| T1585 | [A SAML Connector was created or modified](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=panther-panther-analysis%3A%3ATeleport.SAMLCreated) | Panther | Panther panther-analysis |
| T1588.001 | [Relevant ClamAV Message](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A36aa86ca-fd9d-4456-814e-d3b1b8e1e0bb) | Sigma | SigmaHQ |
| T1588.001 | [Relevant ClamAV Message](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A36aa86ca-fd9d-4456-814e-d3b1b8e1e0bb) | Sigma | OpenSearch Security Analytics |
| T1595.001 | [Grixba Malware Reconnaissance Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aaf688c76-4ce4-4309-bfdd-e896f01acf27) | Sigma | SigmaHQ |
| T1595.001 | [Web Server Suspicious User Agent Requests](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Aa1b7ffa4-bf80-4bf1-86ad-c3f4dc718b35) | Elastic | Elastic detection-rules |
| T1595.002 | [DNS Query to External Service Interaction Domains](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aaff715fa-4dd5-497a-8db3-910bea555566) | Sigma | SigmaHQ |
| T1595.002 | [Web Server Potential SQL Injection Request](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A7f7a0ee1-7b6f-466a-85b4-110fb105f5e2) | Elastic | Elastic detection-rules |
| T1654 | [Sysmon - Event 1: Process creation $(win.eventdata.description)](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=socfortress-wazuh-rules%3A%3Awazuh-100950) | Wazuh | SOCFortress Wazuh-Rules |
| T1654 | [Sysmon - Event 1: Process creation $(win.eventdata.description)](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=socfortress-wazuh-rules%3A%3Awazuh-100951) | Wazuh | SOCFortress Wazuh-Rules |

## 9. Plano de emulação e validação

Use num laboratório isolado e autorizado para confirmar que as regras disparam. Os comandos estão nos repositórios oficiais.

| Tática | Técnica | Teste Atomic Red Team | Plataformas |
|---|---|---|---|
| Initial Access | [T1195](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1195/T1195.md) | Octopus Scanner Malware Open Source Supply Chain | windows |
| Execution | [T1047](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1047/T1047.md) | WMI Reconnaissance Users | windows |
| Execution | [T1047](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1047/T1047.md) | WMI Reconnaissance Processes | windows |
| Execution | [T1053.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1053.005/T1053.005.md) | Scheduled Task Startup Script | windows |
| Execution | [T1053.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1053.005/T1053.005.md) | Scheduled task Local | windows |
| Execution | [T1059.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md) | Mimikatz | windows |
| Execution | [T1059.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md) | Run BloodHound from local disk | windows |
| Persistence | [T1133](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1133/T1133.md) | Running Chrome VPN Extensions via the Registry 2 vpn extension | windows |
| Persistence | [T1505.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1505.003/T1505.003.md) | Web Shell Written to Disk | windows |
| Stealth | [T1036](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036/T1036.md) | System File Copied to Unusual Location | windows |
| Stealth | [T1036](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036/T1036.md) | Malware Masquerading and Execution from Zip File | windows |
| Stealth | [T1036.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.005/T1036.005.md) | Execute a process from a directory masquerading as the current parent directory | linux, macos |
| Stealth | [T1036.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.005/T1036.005.md) | Masquerade as a built-in system executable | windows |
| Stealth | [T1070.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.004/T1070.004.md) | Delete a single file - FreeBSD/Linux/macOS | linux, macos |
| Stealth | [T1070.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.004/T1070.004.md) | Delete an entire folder - FreeBSD/Linux/macOS | linux, macos |
| Stealth | [T1078.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1078.001/T1078.001.md) | Enable Guest account with RDP capability and admin privileges | windows |
| Stealth | [T1078.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1078.001/T1078.001.md) | Activate Guest Account | windows |
| Defense Impairment | [T1112](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1112/T1112.md) | Modify Registry of Current User Profile - cmd | windows |
| Defense Impairment | [T1112](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1112/T1112.md) | Modify Registry of Local Machine - cmd | windows |
| Credential Access | [T1003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003/T1003.md) | Gsecdump | windows |
| Credential Access | [T1003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003/T1003.md) | Credential Dumping with NPPSpy | windows |
| Credential Access | [T1003.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/T1003.001.md) | Dump LSASS.exe Memory using ProcDump | windows |
| Credential Access | [T1003.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/T1003.001.md) | Dump LSASS.exe Memory using comsvcs.dll | windows |
| Credential Access | [T1003.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.002/T1003.002.md) | Registry dump of SAM, creds, and secrets | windows |
| Credential Access | [T1003.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.002/T1003.002.md) | Registry parse with pypykatz | windows |
| Credential Access | [T1003.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.004/T1003.004.md) | Dumping LSA Secrets | windows |
| Credential Access | [T1003.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.004/T1003.004.md) | Dump Kerberos Tickets from LSA using dumper.ps1 | windows |
| Credential Access | [T1110.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1110.003/T1110.003.md) | Password Spray all Domain Users | windows |
| Credential Access | [T1110.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1110.003/T1110.003.md) | Password Spray (DomainPasswordSpray) | windows |
| Credential Access | [T1552.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1552.001/T1552.001.md) | Find AWS credentials | linux, macos |
| Credential Access | [T1552.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1552.001/T1552.001.md) | Extract Browser and System credentials with LaZagne | macos |
| Discovery | [T1018](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1018/T1018.md) | Remote System Discovery - net | windows |
| Discovery | [T1018](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1018/T1018.md) | Remote System Discovery - net group Domain Computers | windows |
| Discovery | [T1046](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1046/T1046.md) | Port Scan | linux, macos |
| Discovery | [T1046](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1046/T1046.md) | Port Scan Nmap | linux, macos |
| Discovery | [T1654](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1654/T1654.md) | Get-EventLog To Enumerate Windows Security Log | windows |
| Discovery | [T1654](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1654/T1654.md) | Enumerate Windows Security Log via WevtUtil | windows |
| Lateral Movement | [T1550.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1550.002/T1550.002.md) | Mimikatz Pass the Hash | windows |
| Lateral Movement | [T1550.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1550.002/T1550.002.md) | crackmapexec Pass the Hash | windows |
| Lateral Movement | [T1570](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1570/T1570.md) | Exfiltration Over SMB over QUIC (New-SmbMapping) | windows |
| Lateral Movement | [T1570](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1570/T1570.md) | Exfiltration Over SMB over QUIC (NET USE) | windows |
| Collection | [T1005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1005/T1005.md) | Search files of interest and save them to a single zip file (Windows) | windows |
| Collection | [T1005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1005/T1005.md) | Find and dump sqlite databases (Linux) | linux |
| Collection | [T1119](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1119/T1119.md) | Automated Collection Command Prompt | windows |
| Collection | [T1119](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1119/T1119.md) | Automated Collection PowerShell | windows |
| Collection | [T1125](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1125/T1125.md) | Registry artefact when application use webcam | windows |
| Collection | [T1560](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1560/T1560.md) | Compress Data for Exfiltration With PowerShell | windows |
| Command and Control | [T1071.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1071.004/T1071.004.md) | DNS Large Query Volume | windows |
| Command and Control | [T1071.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1071.004/T1071.004.md) | DNS Regular Beaconing | windows |
| Command and Control | [T1090.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1090.003/T1090.003.md) | Psiphon | windows |
| Command and Control | [T1090.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1090.003/T1090.003.md) | Tor Proxy Usage - Windows | windows |
| Command and Control | [T1095](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1095/T1095.md) | ICMP C2 | windows |
| Command and Control | [T1095](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1095/T1095.md) | Netcat C2 | windows |
| Command and Control | [T1571](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1571/T1571.md) | Testing usage of uncommonly used port with PowerShell | windows |
| Command and Control | [T1571](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1571/T1571.md) | Testing usage of uncommonly used port | linux, macos |
| Command and Control | [T1572](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1572/T1572.md) | DNS over HTTPS Large Query Volume | windows |
| Command and Control | [T1572](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1572/T1572.md) | DNS over HTTPS Regular Beaconing | windows |
| Exfiltration | [T1567.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1567.002/T1567.002.md) | Exfiltrate data with rclone to cloud Storage - Mega (Windows) | windows |
| Exfiltration | [T1567.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1567.002/T1567.002.md) | Exfiltrate data with rclone to cloud Storage - AWS S3 | linux, macos |

**Logs reais de ataque (EVTX) para testar sem executar nada:**

- T1003 — [ID1-12-13-Wdigest authentication activation](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0006-Credential%20Access/T1003-Credential%20dumping/ID1-12-13-Wdigest%20authentication%20activation.evtx) _(explícito)_
- T1003 — [ID1-LSASS dump with LSASSY (SYSMON)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0006-Credential%20Access/T1003-Credential%20dumping/ID1-LSASS%20dump%20with%20LSASSY%20%28SYSMON%29.evtx) _(explícito)_
- T1003.001 — [CA_hashdump_4663_4656_lsass_access](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Credential%20Access/CA_hashdump_4663_4656_lsass_access.evtx) _(inferido)_
- T1003.001 — [LsassSilentProcessExit_process_exit_monitor_3001_lsass](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Credential%20Access/LsassSilentProcessExit_process_exit_monitor_3001_lsass.evtx) _(inferido)_
- T1018 — [ID5145-DNS hosts files access via network share](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1018-Remote%20System%20Discovery/ID5145-DNS%20hosts%20files%20access%20via%20network%20share.evtx) _(explícito)_
- T1021 — [DFIR_RDP_Client_TimeZone_RdpCoreTs_104_example](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Lateral%20Movement/DFIR_RDP_Client_TimeZone_RdpCoreTs_104_example.evtx) _(inferido)_
- T1021 — [ImpersonateUser-via local Pass The Hash Sysmon and Security](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Lateral%20Movement/ImpersonateUser-via%20local%20Pass%20The%20Hash%20Sysmon%20and%20Security.evtx) _(inferido)_
- T1036 — [rundll32_hollowing_wermgr_masquerading](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/AutomatedTestingTools/Malware/rundll32_hollowing_wermgr_masquerading.evtx) _(inferido)_
- T1046 — [ID131-RDP brutforce (no user info)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1046-Network%20Service%20Scanning/ID131-RDP%20brutforce%20%28no%20user%20info%29.evtx) _(explícito)_
- T1046 — [ID4624-Anonymous login with domain specified (DonPapi)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1046-Network%20Service%20Scanning/ID4624-Anonymous%20login%20with%20domain%20specified%20%28DonPapi%29.evtx) _(explícito)_
- T1047 — [ID1-WMI spwaning PowerShell process - WMImplant](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1047-Windows%20Management%20Instrumentation/ID1-WMI%20spwaning%20PowerShell%20process%20-%20WMImplant.evtx) _(explícito)_
- T1047 — [ID1-WMIexec process execution](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1047-Windows%20Management%20Instrumentation/ID1-WMIexec%20process%20execution.evtx) _(explícito)_
- T1053.005 — [ID4688-4698 Persistent scheduled task with SYSTEM privileges creation](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1053.005-Scheduled%20Task/ID4688-4698%20Persistent%20scheduled%20task%20with%20SYSTEM%20privileges%20creation.evtx) _(explícito)_
- T1053.005 — [ID4688-Interactive shell using AT schedule task](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1053.005-Scheduled%20Task/ID4688-Interactive%20shell%20using%20AT%20schedule%20task.evtx) _(explícito)_
- T1059.001 — [ID4103-4104-Payload download via PowerShell](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1059.001-PowerShell/ID4103-4104-Payload%20download%20via%20PowerShell.evtx) _(explícito)_
- T1059.001 — [ID4688-Encoded PowerShell MSF payload via process execution](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1059.001-PowerShell/ID4688-Encoded%20PowerShell%20MSF%20payload%20via%20process%20execution.evtx) _(explícito)_
- T1110 — [ID 4776,4625-AccountRestore local bruteforce](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0006-Credential%20Access/T1110.xxx-Brut%20force/ID%204776%2C4625-AccountRestore%20local%20bruteforce.evtx) _(explícito)_
- T1110 — [ID18456-SQL Server failed login because only Windows auth](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0006-Credential%20Access/T1110.xxx-Brut%20force/ID18456-SQL%20Server%20failed%20login%20because%20only%20Windows%20auth.evtx) _(explícito)_
- T1110.003 — [kerberos_pwd_spray_4771](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Credential%20Access/kerberos_pwd_spray_4771.evtx) _(inferido)_
- T1112 — [ID11,13-SMBexec service registration](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0005-Defense%20Evasion/T1112-Modify%20registry/ID11%2C13-SMBexec%20service%20registration.evtx) _(explícito)_
- T1112 — [ID4624,4670,4688,4674-Registry permission change via WMI (DAMP)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0005-Defense%20Evasion/T1112-Modify%20registry/ID4624%2C4670%2C4688%2C4674-Registry%20permission%20change%20via%20WMI%20%28DAMP%29.evtx) _(explícito)_
- T1125 — [ID13-RDP shadow session configuration enabled (registry)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0009-Collection/T1125-Video%20capture/ID13-RDP%20shadow%20session%20configuration%20enabled%20%28registry%29.evtx) _(explícito)_
- T1210 — [Zerologon_CVE-2020-1472_DFIR_System_NetLogon_Error_EventID_5805](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Credential%20Access/Zerologon_CVE-2020-1472_DFIR_System_NetLogon_Error_EventID_5805.evtx) _(inferido)_
- T1210 — [Zerologon_VoidSec_CVE-2020-1472_4626_LT3_Anonym_follwedby_4742_DC_Anony_DC](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Credential%20Access/Zerologon_VoidSec_CVE-2020-1472_4626_LT3_Anonym_follwedby_4742_DC_Anony_DC.evtx) _(inferido)_
- T1550.002 — [ImpersonateUser-via local Pass The Hash Sysmon and Security](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Lateral%20Movement/ImpersonateUser-via%20local%20Pass%20The%20Hash%20Sysmon%20and%20Security.evtx) _(inferido)_

## 10. Hipóteses de hunting

Se Ember Bear estiver no seu ambiente, estas são as perguntas a fazer aos seus dados (fontes de log segundo as estratégias de detecção do MITRE ATT&CK).

1. **T1491.002 External Defacement** — Adversary modifies externally-facing web content by accessing and overwriting hosted HTML/JS/CSS files, typically following web shell deployment, credential abuse, or exploitation of web application vulnerabilities. Dados: `WinEventLog:Security` (EventCode=4663, 4670, 4656), `NSM:Connections` (Unusual POST requests to admin or upload endpoints), `WinEventLog:Sysmon` (EventCode=1).
2. **T1595.001 Scanning IP Blocks** — Monitoring the content of network traffic can help detect patterns associated with active scanning activities. This can include identifying repeated connection attempts, unusual scanning behaviors, or probing activity targeting multiple IP addresses across a… Dados: `Network Traffic` (None), `Network Traffic` (None).
3. **T1021 Remote Services** — Logon via RDP or WMI by a user account followed by uncommon command execution, file manipulation, or lateral network connections. Dados: `WinEventLog:Security` (EventCode=4624, 4648), `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=3, 22).
4. **T1195 Supply Chain Compromise** — 1) New or updated software is delivered/installed from atypical sources or with signature/hash mismatches; 2) installer/updater writes binaries to unexpected paths or replaces existing signed files; 3) first run causes unsigned/abnormally signed modules to… Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=7), `WinEventLog:Sysmon` (EventCode=11).
5. **T1078.001 Default Accounts** — Detection of default account usage such as Guest or Administrator performing interactive or remote logons on systems outside of installation or maintenance windows. Dados: `WinEventLog:Security` (EventCode=4624, 4648).
6. **T1114 Email Collection** — Correlates creation of email forwarding rules or header anomalies (e.g., X-MS-Exchange-Organization-AutoForwarded) with suspicious process execution, file access of .pst/.ost files, and network connections to external SMTP servers. Dados: `WinEventLog:Security` (EventCode=5145), `WinEventLog:PowerShell` (EventCode=4103, 4104, 4105, 4106), `WinEventLog:Application` (Exchange logs or header artifacts).
7. **T1125 Video Capture** — A non-standard process (or script-hosted process) loads camera/video-capture libraries (e.g., avicap32.dll, mf.dll, ksproxy.ax), opens the Camera Frame Server/device, writes video/image artifacts (e.g., .mp4/.avi/.yuv) to unusual locations, and optionally… Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=3, 22), `WinEventLog:Sysmon` (EventCode=7).
8. **T1654 Log Enumeration** — Monitor for use of native utilities such as wevtutil.exe or PowerShell cmdlets (Get-WinEvent, Get-EventLog) to enumerate or export logs. Unusual access to security or system event channels, especially by non-administrative users or processes, should be… Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:Security` (EventCode=4663, 4670, 4656).
9. **T1561.002 Disk Structure Wipe** — Processes attempting raw disk access to overwrite sensitive structures such as the MBR or partition table using \\.\PhysicalDrive notation. Detection relies on correlating process creation, privilege escalation, and raw sector writes in Sysmon and Security… Dados: `WinEventLog:Security` (EventCode=4673), `WinEventLog:Sysmon` (Raw write attempts targeting \\.\PhysicalDrive0 or sector 0 (MBR/partition table)), `WinEventLog:Sysmon` (EventCode=6).
10. **T1585 Establish Accounts** — Monitor and analyze traffic patterns and packet inspection associated to protocol(s) that do not follow the expected protocol standards and traffic flows (e.g extraneous packets that do not belong to established flows, gratuitous or anomalous traffic… Dados: `Network Traffic` (None), `Persona` (None).
11. **T1583 Acquire Infrastructure** — Monitor for contextual data about an Internet-facing resource gathered from a scan, such as running services or ports that may buy, lease, or rent infrastructure that can be used during targeting. Detection efforts may be focused on related stages of the… Dados: `Internet Scan` (None), `Internet Scan` (None), `Domain Name` (None).
12. **T1003.004 LSA Secrets** — Detects adversary activity aimed at accessing LSA Secrets, including registry key export of HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets or memory scraping via tools such as Mimikatz or PowerSploit's Invoke-Mimikatz. Dados: `WinEventLog:Security` (EventCode=4663, 4670, 4656), `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=10).

## 11. OSINT — onde pesquisar

Consultas prontas com todos os nomes conhecidos do grupo:

- Relatórios técnicos: [busca web](https://duckduckgo.com/?q=%28%22Ember+Bear%22+OR+%22UNC2589%22+OR+%22Bleeding+Bear%22+OR+%22DEV-0586%22+OR+%22Cadet+Blizzard%22+OR+%22Frozenvista%22%29+threat+report) · [PDFs](https://duckduckgo.com/?q=%28%22Ember+Bear%22+OR+%22UNC2589%22+OR+%22Bleeding+Bear%22+OR+%22DEV-0586%22+OR+%22Cadet+Blizzard%22+OR+%22Frozenvista%22%29+filetype%3Apdf)
- Regras e IOCs publicados: [GitHub](https://github.com/search?type=code&q=%22Ember+Bear%22+OR+%22UNC2589%22+OR+%22Bleeding+Bear%22+OR+%22DEV-0586%22+OR+%22Cadet+Blizzard%22+OR+%22Frozenvista%22)
- Pulsos de ameaça: [AlienVault OTX](https://otx.alienvault.com/browse/global/pulses?q=Ember+Bear)
- Família de malware e atores: [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/actors) (busque por Ember Bear, UNC2589, Bleeding Bear)
- Cartões de grupo: [ThaiCERT Threat Group Cards](https://apt.etda.or.th/cgi-bin/listgroups.cgi)
- Página oficial: [MITRE ATT&CK G1003](https://attack.mitre.org/groups/G1003/)

**Relatórios públicos ligados pelo APT4ALL** (4 no total, mais recentes primeiro):

- 2022 — [UAC-0056 cyberattack on Ukrainian authorities using GraphSteel and GrimPlant malware](https://app.box.com/s/s9jqmfj3eqvzuvbmap8tj673tj37giqd) _(CERT_UA)_
- 2022 — [Threat Actor UAC-0056 Targeting Ukraine with Fake Translation Software](https://app.box.com/s/howogtsvvmqdljp5y4iupj6udhr970mv) _(Sentinelone)_
- 2022 — [APT Group LOREC53 (Lori Bear) Recently Launched A Large-Scale Cyber Attack On Ukraine](https://app.box.com/s/japcw7r6uxnvyenklx06h21veadvdxvy) _(nsfocus)_
- 2022 — [Cyber attack of UAC-0056 group on state organizations of Ukraine using malicious programs SaintBot and OutSteel (CERT-UA #3799)](https://app.box.com/s/gti3fn10hlnanb6c7y50g5n16w8t4cqc) _(CERT-UA)_

## 12. Bibliografia (5 fontes citadas pelo ATT&CK)

- [Cadet Blizzard emerges as novel threat actor](https://www.microsoft.com/en-us/security/blog/2023/06/14/cadet-blizzard-emerges-as-a-novel-and-distinct-russian-threat-actor/) — Microsoft Threat Intelligence. (2023, June 14). Cadet Blizzard emerges as a novel and distinct Russian threat actor. Retrieved July 10, 2023.
- [CISA GRU29155 2024](https://www.cisa.gov/sites/default/files/2024-09/aa24-249a-russian-military-cyber-actors-target-us-and-global-critical-infrastructure.pdf) — US Cybersecurity & Infrastructure Security Agency et al. (2024, September 5). Russian Military Cyber Actors Target U.S. and Global Critical Infrastructure. Retrieved September 6, 2024.
- [CrowdStrike Ember Bear Profile March 2022](https://www.crowdstrike.com/blog/who-is-ember-bear/) — CrowdStrike. (2022, March 30). Who is EMBER BEAR?. Retrieved June 9, 2022.
- [Mandiant UNC2589 March 2022](https://www.mandiant.com/resources/russia-invasion-ukraine-retaliation) — Sadowski, J; Hall, R. (2022, March 4). Responses to Russia's Invasion of Ukraine Likely to Spur Retaliation. Retrieved June 9, 2022.
- [Palo Alto Unit 42 OutSteel SaintBot February 2022 ](https://unit42.paloaltonetworks.com/ukraine-targeted-outsteel-saintbot/) — Unit 42. (2022, February 25). Spear Phishing Attacks Target Organizations in Ukraine, Payloads Include the Document Stealer OutSteel and the Downloader SaintBot. Retrieved June 9, 2022.

## 13. Limites e confiança

- O ATT&CK registra o que foi **relatado publicamente**, não tudo o que o grupo faz. Ausência de uma técnica não prova que o grupo não a usa.
- **Sobreposição de TTP não é atribuição.** Muitas técnicas são compartilhadas entre grupos e com red teams. Use a assinatura comportamental como hipótese, junto com infraestrutura, malware e contexto.
- Cobertura de detecção refere-se ao catálogo público Detection Rules, não ao seu ambiente: confira se a telemetria necessária chega ao seu SIEM.
- Ligações marcadas como _inferidas_ (EVTX por palavra-chave, relatórios por nome) devem ser verificadas.

---
Fontes: MITRE ATT&CK® (uso livre com atribuição, © The MITRE Corporation), APT4ALL (MISP Galaxy CC0/BSD-2, APT Groups & Operations CC BY 4.0, EternalLiberty, APTnotes, Ransomware Tool Matrix CC BY 4.0), Atomic Red Team (Red Canary, MIT), EVTX-to-MITRE-Attack, EVTX-ATTACK-SAMPLES, APT & CyberCriminal Campaign Collections. Gerado por [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules).
