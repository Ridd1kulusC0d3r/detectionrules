# Salt Typhoon (G1045) — Dossiê de inteligência

> **TLP:CLEAR** · gerado em 2026-10-26 a partir de fontes abertas · MITRE ATT&CK v20.0 · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1045) · [ATT&CK](https://attack.mitre.org/groups/G1045/)

**Também conhecido como:** —  
**Origem atribuída:** China · **Motivação:** espionagem · **Setores-alvo:** Governo  
**Registro no ATT&CK:** criado em 2025-02-24, atualizado em 2026-09-23 · referências de 2025 a 2026

## 1. Sumário executivo

- **58 técnicas** atribuídas publicamente, concentradas em **Command and Control, Execution, Resource Development**.
- **Arsenal:** 1 malware e 0 ferramentas (ex.: JumbledPath).
- **Campanhas atribuídas:** 0.
- **Cobertura de detecção pública:** 84% das técnicas têm ao menos uma regra no catálogo; **9 técnicas sem nenhuma regra pública**.
- **Origem e alvos (APT4ALL):** atribuído a **China**, motivação espionagem; setores Governo.
- **Onde a cobertura está:** Linux (41 técnicas com regra), EDR / XDR (40 técnicas com regra), Windows (38 técnicas com regra), Outros / genérico (33 técnicas com regra).
- **Assinatura comportamental** (técnicas raras entre os 178 grupos, as mais úteis para atribuição): T1020.001 Traffic Duplication, T1059.008 Network Device CLI, T1070.009 Clear Persistence, T1543.005 Container Service, T1569 System Services.

## 2. Quem é

> Salt Typhoon is a People's Republic of China (PRC) state-backed actor that has been active since at least 2019 and responsible for numerous compromises of network infrastructure at major U.S. telecommunication and internet service providers (ISP). Salt Typhoon has targeted and leveraged public facing network edge devices to gain access to victim environments. Salt Typhoon has been publicly associated with activities resembling other security industry reported activity groups to include OPERATOR PANDA, RedMike, GhostEmperor, and UNC5807.

_Texto original do MITRE ATT&CK, em inglês._

## 3. Contexto, nomes e alvos

Consolidado pelo [APT4ALL](https://github.com/Ridd1kulusC0d3r/apt4all) a partir de MISP Galaxy, planilha APT Groups & Operations, EternalLiberty e APTnotes. Atribuição é afirmação de quem publicou; confira a fonte.

| Campo | Valor |
|---|---|
| Origem atribuída | China |
| Motivação | espionagem |
| Setores-alvo | Governo |
| Vítimas citadas | — |
| Alvos (planilha) | US Government wiretap system, via Verizon and AT&T. |
| Operações conhecidas | — |
| Confiança de atribuição (MISP) | Mid |

**Como cada fornecedor chama este grupo** (útil para cruzar relatórios):

| Fornecedor | Nome(s) |
|---|---|
| CrowdStrike | Famous Sparrow |
| Kaspersky | GhostEmperor |
| MITRE ATT&CK | G1045 |
| Mandiant | UNC4841 |

**Outros nomes no APT4ALL (não listados pelo ATT&CK):** FamousSparrow, GhostEmperor, UNC4841, SLIME57, UNC2286, RedMike, OPERATOR PANDA, Earth Estries

## 4. Perfil TTP por tática (kill chain)

Cada linha: técnica, como o grupo a usou segundo relatos públicos, e o que existe para detectar e testar.

### Reconnaissance (TA0043) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1590.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1590.004) Network Topology | Salt Typhoon has used configuration files from exploited network devices to help discover upstream and downstream network segments. | **0** | — | — |
| [T1595](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1595) Active Scanning | Salt Typhoon has scanned victim environments for open ports and services. | 99 | — | — |

### Resource Development (TA0042) — 7

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1583.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1583.003) Virtual Private Server | Salt Typhoon has utilized virtual private servers (VPS) for C2 infrastructure. | **0** | — | — |
| [T1584.008](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1584.008) Network Devices | Salt Typhoon has leveraged compromised routers to facilitate operations. | **0** | — | — |
| [T1585.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1585.001) Social Media Accounts | Salt Typhoon members have created and maintained professional accounts on social media to include LinkedIn. | 4 | — | — |
| [T1587](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1587) Develop Capabilities | Salt Typhoon has hosted and attended formal training programs for foreign-made IT products to include Cisco Network Academy. | 22 | — | — |
| [T1587.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1587.001) Malware | Salt Typhoon has used custom tooling including JumbledPath. | 43 | — | — |
| [T1588.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1588.002) Tool | Salt Typhoon has used publicly available tooling to exploit vulnerabilities.  Salt Typhoon has also obtained and utilized open-source tools for creating backdoors and multi-hop proxies to include STOWAWAY. | 35 | — | — |
| [T1588.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1588.005) Exploits | Salt Typhoon has obtained and utilized numerous exploits that target network edge devices to include Cisco IOS, Palo Alto Pan-OS Global Protect, and Ivanti Connect Secure. | **0** | — | — |

### Initial Access (TA0001) — 3

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | Salt Typhoon has used logged into accounts on Cisco devices by cracking weak hashed passwords from configuration files. | 825 | — | 3 |
| [T1190](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1190) Exploit Public-Facing Application | Salt Typhoon has leveraged vulnerabilities in public facing applications and network edge devices including Cisco IOS and IOS XE through CVE-2018-0171, Ivanti Connect Secure through CVE-2023-46805, and Palo Alto Networks GlobalProtect through CVE-2024-3400. | 580 | — | — |
| [T1199](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1199) Trusted Relationship | Salt Typhoon has leveraged compromised devices associated with trusted connections or those associated with private interconnections to include provider-to-provider or provider-to-customer relationships in order to pivot to target networks. | 18 | — | — |

### Execution (TA0002) — 7

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1059.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.004) Unix Shell | Salt Typhoon has utilized a bash shell to execute Linux commands. | 395 | 17 | — |
| [T1059.006](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.006) Python | Salt Typhoon has used Python scripts to execute commands on victim hosts. | 122 | — | — |
| [T1059.008](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.008) Network Device CLI | Salt Typhoon has executed commands on network devices using the native command line interface.   Salt Typhoon has leveraged Tcl scripts on Cisco IOS devices to include `TCLprox.tcl` and `map.tcl` when `tclsh` was available.   Salt Typhoon also leveraged TACACS… | **0** | — | — |
| [T1059.013](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.013) Container CLI/API | Salt Typhoon has leveraged Cisco Guest Shell to interact with a Linux Container on network devices. | **0** | — | — |
| [T1072](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1072) Software Deployment Tools | Salt Typhoon has abused network management tools to include RANCID to facilitate actions in victims’ environments. | 59 | 3 | — |
| [T1569](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1569) System Services | Salt Typhoon has utilized SNMP daemon to execute commands to include SNMPwalk. | 41 | — | — |
| [T1610](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1610) Deploy Container | Salt Typhoon has enabled Linux containers in victim network device environments using `guestshell enable`. | 45 | 1 | — |

### Persistence (TA0003) — 6

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | Salt Typhoon has used logged into accounts on Cisco devices by cracking weak hashed passwords from configuration files. | 825 | — | 3 |
| [T1098.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1098.004) SSH Authorized Keys | Salt Typhoon has added SSH authorized_keys under root or other users at the Linux level on compromised network devices. | 16 | 1 | — |
| [T1136](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1136) Create Account | Salt Typhoon has created Linux-level users on compromised network devices through modification of `/etc/shadow` and `/etc/passwd`. | 127 | — | 11 |
| [T1136.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1136.001) Local Account | Salt Typhoon has created local user accounts to utilize in victim environments.   Salt Typhoon has also created administrative accounts within compromised environments. | 103 | 10 | — |
| [T1543.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1543.005) Container Service | Salt Typhoon has modified container service configurations using `Guest Shell`. | 2 | — | — |
| [T1556](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1556) Modify Authentication Process | Salt Typhoon has modified the Authentication, Authorization, and Accounting (AAA) configurations forcing devices to use less secure authentication methods and to send information to their infrastructure. | 137 | — | — |

### Privilege Escalation (TA0004) — 4

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | Salt Typhoon has used logged into accounts on Cisco devices by cracking weak hashed passwords from configuration files. | 825 | — | 3 |
| [T1098.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1098.004) SSH Authorized Keys | Salt Typhoon has added SSH authorized_keys under root or other users at the Linux level on compromised network devices. | 16 | 1 | — |
| [T1543.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1543.005) Container Service | Salt Typhoon has modified container service configurations using `Guest Shell`. | 2 | — | — |
| [T1548.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1548.003) Sudo and Sudo Caching | Salt Typhoon has elevated privileges of local user accounts by editing `/etc/sudoers` or adding a file under `/etc/sudoers.d/`. | 47 | 6 | — |

### Stealth (TA0005) — 5

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1027.010](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1027.010) Command Obfuscation | Salt Typhoon has obfuscated target pathways with double encoding to bypass security solutions. | 78 | — | — |
| [T1070.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1070.003) Clear Command History | Salt Typhoon has deleted and cleared logs to avoid detection. | 63 | 14 | — |
| [T1070.007](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1070.007) Clear Network Connection History and Configurations | Salt Typhoon has reverted or modified network configuration files to remove traces of activity. | **0** | — | — |
| [T1070.009](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1070.009) Clear Persistence | Salt Typhoon has removed persistence within victim devices through disabling and uninstalling artifacts.  Salt Typhoon has leveraged the commands `guestshell disable` and `guestshell destroy` to deactivate and uninstall Guest Shell containers and return all re… | 2 | — | — |
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | Salt Typhoon has used logged into accounts on Cisco devices by cracking weak hashed passwords from configuration files. | 825 | — | 3 |

### Defense Impairment (TA0112) — 6

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1556](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1556) Modify Authentication Process | Salt Typhoon has modified the Authentication, Authorization, and Accounting (AAA) configurations forcing devices to use less secure authentication methods and to send information to their infrastructure. | 137 | — | — |
| [T1599](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1599) Network Boundary Bridging | Salt Typhoon has abused peer connections to exfiltrate data. | 4 | — | — |
| [T1685](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1685) Disable or Modify Tools | Salt Typhoon has disabled logging and disabled the distribution of logs to log aggregators. | 1275 | 78 | 19 |
| [T1685.006](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1685.006) Clear Linux or Mac System Logs | Salt Typhoon has cleared logs including .bash_history, auth.log, lastlog, wtmp, and btmp. | 23 | 20 | — |
| [T1686](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1686) Disable or Modify System Firewall | Salt Typhoon has made changes to the Access Control List (ACL) and loopback interface address on compromised devices. | 56 | 25 | 6 |
| [T1686.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1686.002) Network Device Firewall | Salt Typhoon has modified the network firewalls access control lists to add IP addresses to bypass security policies and maintain access. | 2 | — | — |

### Credential Access (TA0006) — 5

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1040](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1040) Network Sniffing | Salt Typhoon has used a variety of tools and techniques to capture packet data between network interfaces. | 77 | 16 | 1 |
| [T1110.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1110.001) Password Guessing | Salt Typhoon has used weak credentials to gain access to victim devices. | 63 | 8 | — |
| [T1110.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1110.002) Password Cracking | Salt Typhoon has cracked passwords for accounts with weak encryption obtained from the configuration files of compromised network devices.  Salt Typhoon has cracked weak hashed passwords stolen from configuration files. | 11 | 1 | — |
| [T1552.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1552.001) Credentials In Files | Salt Typhoon has collected credentials stored in configuration files. | 166 | 32 | — |
| [T1556](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1556) Modify Authentication Process | Salt Typhoon has modified the Authentication, Authorization, and Accounting (AAA) configurations forcing devices to use less secure authentication methods and to send information to their infrastructure. | 137 | — | — |

### Discovery (TA0007) — 5

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1016](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1016) System Network Configuration Discovery | Salt Typhoon has discovered and modified network configurations of victim devices. | 99 | 10 | 5 |
| [T1018](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1018) Remote System Discovery | Salt Typhoon has used SNMPwalk to enumerate devices. | 157 | 23 | 1 |
| [T1040](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1040) Network Sniffing | Salt Typhoon has used a variety of tools and techniques to capture packet data between network interfaces. | 77 | 16 | 1 |
| [T1046](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1046) Network Service Discovery | Salt Typhoon has scanned open ports and services within the victim environment. | 212 | 13 | 2 |
| [T1082](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1082) System Information Discovery | Salt Typhoon has discovered system information details utilizing CLI on network devices. | 264 | 41 | — |

### Lateral Movement (TA0008) — 3

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1021.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1021.001) Remote Desktop Protocol | Salt Typhoon has opened and conducted operations utilizing RDP within victim environments. | 139 | 4 | 7 |
| [T1021.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1021.004) SSH | Salt Typhoon has modified the loopback address on compromised switches and used them as the source of SSH connections to additional devices within the target environment, allowing them to bypass access control lists (ACLs). Salt Typhoon has also enabled SSH to… | 60 | 2 | 3 |
| [T1072](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1072) Software Deployment Tools | Salt Typhoon has abused network management tools to include RANCID to facilitate actions in victims’ environments. | 59 | 3 | — |

### Collection (TA0009) — 3

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1005) Data from Local System | Salt Typhoon has gathered data from victim devices. | 170 | 3 | — |
| [T1602.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1602.001) SNMP (MIB Dump) | Salt Typhoon has enumerated device configuration using SNMP and gathered data stored in the Managed Information Base on target devices. | **0** | — | — |
| [T1602.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1602.002) Network Device Configuration Dump | Salt Typhoon has attempted to acquire credentials by dumping network device configurations. Salt Typhoon has also obtained data using RANCID. | 1 | — | — |

### Command and Control (TA0011) — 9

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1071.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1071.001) Web Protocols | Salt Typhoon has utilized HTTP and HTTPS in C2 communications. | 228 | 3 | — |
| [T1071.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1071.002) File Transfer Protocols | Salt Typhoon has leveraged SFTP for C2 communications. | 3 | — | — |
| [T1090](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1090) Proxy | Salt Typhoon has utilized virtual private servers and compromised routers as proxies for malicious communications. | 162 | — | 1 |
| [T1090.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1090.003) Multi-hop Proxy | Salt Typhoon has leveraged multi-hop proxies for command-and-control infrastructure. | 44 | 4 | — |
| [T1095](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1095) Non-Application Layer Protocol | Salt Typhoon has used Generic Routing Encapsulation (GRE) and IPsec tunnels to connect to C2 over non-application layer protocols. | 72 | 5 | — |
| [T1105](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1105) Ingress Tool Transfer | Salt Typhoon has downloaded additional payloads and files to victim devices. | 644 | 39 | — |
| [T1132.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1132.001) Standard Encoding | Salt Typhoon has utilized double encoding with hexadecimals in attempts to obfuscate requested command paths. | 26 | 3 | — |
| [T1571](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1571) Non-Standard Port | Salt Typhoon has leveraged non-standard ports to evade detection by security monitoring. | 163 | 2 | — |
| [T1572](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1572) Protocol Tunneling | Salt Typhoon has modified device configurations to create and use Generic Routing Encapsulation (GRE) tunnels. | 173 | 9 | 1 |

### Exfiltration (TA0010) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1020.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1020.001) Traffic Duplication | Salt Typhoon has enabled traffic mirroring to exfiltrate data. | **0** | — | — |
| [T1048.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1048.003) Exfiltration Over Unencrypted Non-C2 Protocol | Salt Typhoon has exfiltrated configuration files from exploited network devices over FTP and TFTP. | 51 | 8 | — |

## 5. Assinatura comportamental

Técnicas que este grupo usa e que poucos dos 178 grupos do ATT&CK usam. Pesam mais numa atribuição por TTP: ver várias delas juntas é mais informativo do que ver técnicas comuns como PowerShell.

| Técnica | Outros grupos que usam | Peso (raridade) |
|---|---:|---:|
| T1020.001 Traffic Duplication | 0 | 4.49 |
| T1059.008 Network Device CLI | 0 | 4.49 |
| T1070.009 Clear Persistence | 0 | 4.49 |
| T1543.005 Container Service | 0 | 4.49 |
| T1569 System Services | 0 | 4.49 |
| T1595 Active Scanning | 0 | 4.49 |
| T1602.001 SNMP (MIB Dump) | 0 | 4.49 |
| T1602.002 Network Device Configuration Dump | 0 | 4.49 |
| T1548.003 Sudo and Sudo Caching | 1 | 4.09 |
| T1556 Modify Authentication Process | 1 | 4.09 |

## 6. Arsenal

| Software | Tipo | Técnicas no ATT&CK | Uso relatado (EN) |
|---|---|---:|---|
| [JumbledPath](https://attack.mitre.org/software/S1206/) | malware | 6 |  |

## 7. Campanhas

Nenhuma campanha atribuída no ATT&CK.

## 8. Cobertura defensiva

**49 de 58 técnicas (84%)** têm ao menos uma regra pública no catálogo Detection Rules.

### Técnicas sem regra pública (prioridade para engenharia de detecção)

- **T1020.001 Traffic Duplication** — Exfiltration. Fonte de log sugerida pelo MITRE: `AWS:CloudTrail` CreateTrafficMirrorSession or ModifyTrafficMirrorTarget; `networkdevice:syslog` Config change: CLI/NETCONF/SNMP – 'monitor session', 'mirror port'
- **T1059.008 Network Device CLI** — Execution. Fonte de log sugerida pelo MITRE: `networkdevice:syslog` command_exec
- **T1602.001 SNMP (MIB Dump)** — Collection. Fonte de log sugerida pelo MITRE: `networkdevice:syslog` Authentication failures, unexpected community string usage, or unauthorized SNMPv1/v2 requests
- **T1059.013 Container CLI/API** — Execution. Fonte de log sugerida pelo MITRE: `auditd:SYSCALL` execve: Execution of container management CLIs (docker, crictl, kubectl) or interpreted shells (sh, bash, python) within container context
- **T1588.005 Exploits** — Resource Development
- **T1070.007 Clear Network Connection History and Configurations** — Stealth. Fonte de log sugerida pelo MITRE: `WinEventLog:Security` EventCode=4663, 4670, 4656; `auditd:SYSCALL` execve; `macos:unifiedlog` log stream --predicate 'eventMessage contains "loginwindow" or "pfctl"'; `networkdevice:syslog` Command A
- **T1590.004 Network Topology** — Reconnaissance
- **T1584.008 Network Devices** — Resource Development. Fonte de log sugerida pelo MITRE: `Internet Scan` None
- **T1583.003 Virtual Private Server** — Resource Development. Fonte de log sugerida pelo MITRE: `Internet Scan` None

### Onde procurar — cobertura por tecnologia

Quantas técnicas deste grupo têm ao menos uma regra em cada tecnologia. Comece a caça pelas tecnologias que você tem e que aparecem aqui.

| Tecnologia | Técnicas do grupo com regra |
|---|---:|
| Linux | 41 |
| EDR / XDR | 40 |
| Windows | 38 |
| Outros / genérico | 33 |
| Firewall & perímetro | 29 |
| AWS | 28 |
| macOS | 27 |
| Contêineres (Docker/runtime) | 26 |
| Integridade, conformidade & vulnerabilidade | 26 |
| IDS / NSM / NDR | 24 |
| Azure (recursos) | 24 |
| Servidores web & aplicações | 23 |

### Regras recomendadas por técnica

Melhor regra disponível por técnica (formato portável e maduro primeiro).

| Técnica | Regra | Formato | Fonte |
|---|---|---|---|
| T1005 | [Potential Conti Ransomware Database Dumping Activity Via SQLCmd](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A2f47f1fd-0901-466e-a770-3b7092834a1b) | Sigma | SigmaHQ |
| T1005 | [OpenCanary - SMB File Open Request](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A22777c9e-873a-4b49-855f-6072ab861a52) | Sigma | SigmaHQ |
| T1016 | [Potential Pikabot Discovery Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A698d4431-514f-4c82-af4d-cf573872a9f5) | Sigma | SigmaHQ |
| T1016 | [OpenCanary - SNMP OID Request](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae9856028-fd4e-46e6-b3d1-10f7ceb95078) | Sigma | SigmaHQ |
| T1018 | [Chopper Webshell Process Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Afa3c117a-bc0d-416e-a31b-0c0e80653efb) | Sigma | SigmaHQ |
| T1018 | [Webshell Hacking Activity Patterns](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4ebc877f-4612-45cb-b3a5-8e3834db36c9) | Sigma | SigmaHQ |
| T1021.001 | [Hermetic Wiper TG Process Patterns](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A2f974656-6d83-4059-bbdf-68ac5403422f) | Sigma | SigmaHQ |
| T1021.001 | [Publicly Accessible RDP Service](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1fc0809e-06bf-4de3-ad52-25e5263b7623) | Sigma | SigmaHQ |
| T1021.004 | [Potential THC Tool Downloaded](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A2ddc468e-b39b-4f5b-9825-f3dcb0e998ea) | Elastic | Elastic detection-rules |
| T1021.004 | [AWS EC2 CreateKeyPair by New Principal from Non-Cloud AS Organization](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ac8e4f1a2-9b3d-4c5e-a6f7-8b9c0d1e2f3a) | Elastic | Elastic detection-rules |
| T1027.010 | [Decoded Payload Piped to Interpreter Detected via Defend for Containers](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A0fb83aa0-3d17-41e9-b09c-56397bf7a7d9) | Elastic | Elastic detection-rules |
| T1027.010 | [Potential PowerShell Obfuscation via String Concatenation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Af6d8c743-0916-4483-8333-3c6f107e0caa) | Elastic | Elastic detection-rules |
| T1040 | [Cisco Sniffing](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab9e1f193-d236-4451-aaae-2f3d2102120d) | Sigma | SigmaHQ |
| T1040 | [Network Sniffing - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Af4d3748a-65d1-4806-bd23-e25728081d01) | Sigma | SigmaHQ |
| T1046 | [HackTool - winPEAS Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A98b53e78-ebaf-46f8-be06-421aafd176d9) | Sigma | SigmaHQ |
| T1046 | [HackTool - WinPwn Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad557dc06-62e8-4468-a8e8-7984124908ce) | Sigma | SigmaHQ |
| T1048.003 | [Suspicious WebDav Client Execution Via Rundll32.EXE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A982e9f2d-1a85-4d5b-aea4-31f5e97c6555) | Sigma | SigmaHQ |
| T1048.003 | [Possible DNS Tunneling](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A1ec4b281-aa65-46a2-bdae-5fd830ed914e) | Sigma | OpenSearch Security Analytics |
| T1059.004 | [Shell Invocation via Env Command - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Abed978f8-7f3a-432b-82c5-9286a9b3031a) | Sigma | SigmaHQ |
| T1059.004 | [Suspicious Reverse Shell Command Line](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A738d9bcf-6999-4fdb-b4ac-3033037db8ab) | Sigma | SigmaHQ |
| T1059.006 | [Emotet Loader Execution Via .LNK File](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1f32d820-1d5c-43fe-8fe2-feef0c952eb7) | Sigma | SigmaHQ |
| T1059.006 | [Serpent Backdoor Payload Execution Via Scheduled Task](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad5eb7432-fda4-4bba-a37f-ffa74d9ed639) | Sigma | SigmaHQ |
| T1070.003 | [Cisco Clear Logs](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aceb407f6-8277-439b-951f-e4210e3ed956) | Sigma | SigmaHQ |
| T1070.003 | [Linux Command History Tampering](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Afdc88d25-96fb-4b7c-9633-c0e417fdbd4e) | Sigma | SigmaHQ |
| T1070.009 | [Wiz User Created Or Deleted](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=panther-panther-analysis%3A%3AWiz.User.Created.Or.Deleted) | Panther | Panther panther-analysis |
| T1070.009 | [Slack App Removed](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=panther-panther-analysis%3A%3ASlack.AuditLogs.AppRemoved) | Panther | Panther panther-analysis |
| T1071.001 | [Ursnif Malware Download URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aa36ce77e-30db-4ea0-8795-644d7af5dfb4) | Sigma | SigmaHQ |
| T1071.001 | [Ursnif Malware C2 URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A932ac737-33ca-4afd-9869-0d48b391fcc9) | Sigma | SigmaHQ |
| T1071.002 | [Ubiquiti - Unusual FTP connection to external server](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3Afd200125-9d57-4838-85ca-6430c63e4e5d) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1071.002 | [MS-FTP: Multiple FTP errors from same source.](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=wazuh-ruleset-oficial%3A%3Awazuh-11512) | Wazuh | Wazuh ruleset (oficial) |
| T1072 | [Restricted Software Access By SRP](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab4c8da4a-1c12-46b0-8a2b-0a8521d03442) | Sigma | SigmaHQ |
| T1072 | [Suspicious Curl to Jamf Endpoint](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Aa8256685-9736-465b-b159-f25a172d08e8) | Elastic | Elastic detection-rules |
| T1078 | [Privilege Role Sign-In Outside Expected Controls](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acf1e5687-84e1-41af-97a9-158094efef53) | Sigma | SigmaHQ |
| T1078 | [OpenCanary - SSH Login Attempt](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aff7139bc-fdb1-4437-92f2-6afefe8884cb) | Sigma | SigmaHQ |
| T1082 | [Potential GobRAT File Discovery Via Grep](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae34cfa0c-0a50-4210-9cb3-5632d08eb041) | Sigma | SigmaHQ |
| T1082 | [System Information Discovery](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A42df45e7-e6e9-43b5-8f26-bec5b39cc239) | Sigma | SigmaHQ |
| T1090 | [Communication To LocaltoNet Tunneling Service Initiated - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac4568f5d-131f-4e78-83d4-45b2da0ec4f1) | Sigma | SigmaHQ |
| T1090 | [Communication To Ngrok Tunneling Service - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A19bf6fdb-7721-4f3d-867f-53467f6a5db6) | Sigma | SigmaHQ |
| T1090.003 | [Tor Client/Browser Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A62f7c9bf-9135-49b2-8aeb-1e54a6ecc13c) | Sigma | SigmaHQ |
| T1090.003 | [Query Tor Onion Address - DNS Client](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A8384bd26-bde6-4da9-8e5d-4174a7a47ca2) | Sigma | SigmaHQ |
| T1095 | [PUA - Netcat Suspicious Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae31033fc-33f0-4020-9a16-faf9b31cbf08) | Sigma | SigmaHQ |
| T1095 | [Suspicious React Server Child Process](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Aae3e9625-89ad-4fc3-a7bf-fced5e64f01b) | Elastic | Elastic detection-rules |
| T1098.004 | [Potential Redis CONFIG SET SSH Authorized Key Injection](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A39ab0f66-efa0-4649-9c9c-8c64682f5fdd) | Elastic | Elastic detection-rules |
| T1098.004 | [Suspicious Echo or Printf Execution Detected via Defend for Containers](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ad9bfa475-270d-4b07-93cb-b1f49abe13da) | Elastic | Elastic detection-rules |
| T1105 | [Greenbug Espionage Group Indicators](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A3711eee4-a808-4849-8a14-faf733da3612) | Sigma | SigmaHQ |
| T1105 | [Pandemic Registry Key](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A47e0852a-cf81-4494-a8e6-31864f8c86ed) | Sigma | SigmaHQ |
| T1110.001 | [HackTool - Hydra Password Bruteforce Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aaaafa146-074c-11eb-adc1-0242ac120002) | Sigma | SigmaHQ |
| T1110.001 | [Hydra Password Guessing Hack Tool](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Aaaafa146-074c-11eb-adc1-0242ac120002) | Sigma | OpenSearch Security Analytics |
| T1110.002 | [HackTool - Hashcat Password Cracker Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A39b31e81-5f5f-4898-9c0e-2160cfc0f9bf) | Sigma | SigmaHQ |
| T1110.002 | [Password Cracking with Hashcat](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A39b31e81-5f5f-4898-9c0e-2160cfc0f9bf) | Sigma | OpenSearch Security Analytics |
| T1132.001 | [DNS Exfiltration and Tunneling Tools Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A98a96a5a-64a0-4c42-92c5-489da3866cb0) | Sigma | SigmaHQ |
| T1132.001 | [DNS Exfiltration and Tunneling Tools Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A98a96a5a-64a0-4c42-92c5-489da3866cb0) | Sigma | OpenSearch Security Analytics |
| T1136 | [FortiGate SSO Login Followed by Administrator Account Creation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ae3a7b1c2-5d9f-4e8a-b6c3-2f1d4e5a6b7c) | Elastic | Elastic detection-rules |
| T1136 | [Potential Linux Backdoor User Account Creation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A494ebba4-ecb7-4be4-8c6f-654c686549ad) | Elastic | Elastic detection-rules |
| T1136.001 | [DarkGate - User Created Via Net.EXE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Abf906d7b-7070-4642-8383-e404cf26eba5) | Sigma | SigmaHQ |
| T1136.001 | [Serv-U Exploitation CVE-2021-35211 by DEV-0322](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A75578840-9526-4b2a-9462-af469a45e767) | Sigma | SigmaHQ |
| T1190 | [OMIGOD HTTP No Authentication RCE - CVE-2021-38647](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aab6b1a39-a9ee-4ab4-b075-e83acf6e346b) | Sigma | SigmaHQ |
| T1190 | [Exploited CVE-2020-10189 Zoho ManageEngine](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A846b866e-2a57-46ee-8e16-85fa92759be7) | Sigma | OpenSearch Security Analytics |
| T1199 | [Microsoft 365 - User Restricted from Sending Email](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aff246f56-7f24-402a-baca-b86540e3925c) | Sigma | SigmaHQ |
| T1199 | [Microsoft 365 - User Restricted from Sending Email](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Aff246f56-7f24-402a-baca-b86540e3925c) | Sigma | OpenSearch Security Analytics |
| T1543.005 | [Kubernetes Sensitive Configuration File Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A0fe2290a-2664-4c9c-8263-b88904f12f0d) | Elastic | Elastic detection-rules |
| T1543.005 | [Kubernetes Static Pod Manifest File Access](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Aa698a653-e144-4e40-bade-35135935be45) | Elastic | Elastic detection-rules |
| T1548.003 | [Sudo Privilege Escalation CVE-2019-14287](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Af74107df-b6c6-4e80-bf00-4170b658162b) | Sigma | SigmaHQ |
| T1548.003 | [Sudo Privilege Escalation CVE-2019-14287 - Builtin](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A7fcc54cb-f27d-4684-84b7-436af096f858) | Sigma | SigmaHQ |
| T1552.001 | [Potential Russian APT Credential Theft Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab83f5166-9237-4b5e-9cd4-7b5d52f4d8ee) | Sigma | SigmaHQ |
| T1552.001 | [Copy Passwd Or Shadow From TMP Path](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Afa4aaed5-4fe0-498d-bbc0-08e3346387ba) | Sigma | SigmaHQ |
| T1556 | [Github High Risk Configuration Disabled](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A8622c92d-c00e-463c-b09d-fd06166f6794) | Sigma | SigmaHQ |
| T1556 | [Possible Shadow Credentials Added](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Af598ea0c-c25a-4f72-a219-50c44411c791) | Sigma | SigmaHQ |
| T1569 | [Possible CVE-2021-1675 Print Spooler Exploitation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4e64668a-4da1-49f5-a8df-9e2d5b866718) | Sigma | SigmaHQ |
| T1569 | [CVE-2021-1675 Print Spooler Exploitation IPC Access](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A8fe1c584-ee61-444b-be21-e9054b229694) | Sigma | SigmaHQ |
| T1571 | [Potentially Suspicious Malware Callback Communication - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Adbfc7c98-04ab-4ab7-aa94-c74d22aa7376) | Sigma | SigmaHQ |
| T1571 | [Potentially Suspicious Malware Callback Communication](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4b89abaa-99fe-4232-afdd-8f9aa4d20382) | Sigma | SigmaHQ |
| T1572 | [Communication To LocaltoNet Tunneling Service Initiated - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac4568f5d-131f-4e78-83d4-45b2da0ec4f1) | Sigma | SigmaHQ |
| T1572 | [Communication To Ngrok Tunneling Service - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A19bf6fdb-7721-4f3d-867f-53467f6a5db6) | Sigma | SigmaHQ |
| T1585.001 | [CYFIRMA - Brand Intelligence - Social Media Handle Impersonation Detected High Rule](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A22f49d67-7da7-4809-8d07-89e4478aa6b0) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1585.001 | [CYFIRMA - Brand Intelligence - Executive/People Impersonation High Rule](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A159d26a1-591c-4f70-b1ca-2843c881aaec) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1587 | [FoggyWeb Backdoor DLL Loading](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A640dc51c-7713-4faa-8a0e-e7c0d9d4654c) | Sigma | SigmaHQ |
| T1587 | [CVE-2021-1675 Print Spooler Exploitation Filename Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A2131cfb3-8c12-45e8-8fa0-31f5924e9f07) | Sigma | SigmaHQ |
| T1587.001 | [Formbook Process Creation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A032f5fb3-d959-41a5-9263-4173c802dc2b) | Sigma | SigmaHQ |
| T1587.001 | [Uncommon File Created In Office Startup Folder](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aa10a2c40-2c4d-49f8-b557-1a946bc55d9d) | Sigma | SigmaHQ |
| T1588.002 | [Hacktool Execution - Imphash](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A24e3e58a-646b-4b50-adef-02ef935b9fc8) | Sigma | SigmaHQ |
| T1588.002 | [Renamed SysInternals DebugView Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acd764533-2e07-40d6-a718-cfeec7f2da7f) | Sigma | SigmaHQ |
| T1595 | [PUA - PingCastle Execution From Potentially Suspicious Parent](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab37998de-a70b-4f33-b219-ec36bf433dc0) | Sigma | SigmaHQ |
| T1595 | [Web Server Potential SQL Injection Request](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A7f7a0ee1-7b6f-466a-85b4-110fb105f5e2) | Elastic | Elastic detection-rules |
| T1599 | [External Principal Accessing AWS Resources Via VPC Endpoint](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=panther-panther-analysis%3A%3AAWS.CloudTrail.VPCE.ExternalPrincipal) | Panther | Panther panther-analysis |
| T1599 | [VPC Endpoint Access Denied](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=panther-panther-analysis%3A%3AAWS.CloudTrail.VPCE.AccessDenied) | Panther | Panther panther-analysis |
| T1602.002 | [FortiGate Configuration File Downloaded](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ab7e2a04d-4f8a-4e12-8c9a-1d5e6f7a8b9c) | Elastic | Elastic detection-rules |
| T1610 | [Privileged Container Creation with Host Directory Mount](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ad1f310cb-5921-4d37-bbdf-cfdab7a6df9c) | Elastic | Elastic detection-rules |
| T1610 | [Potential Privilege Escalation via Container Misconfiguration](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Aafe6b0eb-dd9d-4922-b08a-1910124d524d) | Elastic | Elastic detection-rules |
| T1685 | [Windows Defender Configuration Changes](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A801bd44f-ceed-4eb6-887c-11544633c0aa) | Sigma | SigmaHQ |
| T1685 | [Windows Defender Virus Scanning Feature Disabled](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A686c0b4b-9dd3-4847-9077-d6c1bbe36fcb) | Sigma | SigmaHQ |
| T1685.006 | [Syslog Clearing or Removal Via System Utilities](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A3fcc9b35-39e4-44c0-a2ad-9e82b6902b31) | Sigma | SigmaHQ |
| T1685.006 | [Linux Logs Clearing Attempts](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A80915f59-9b56-4616-9de0-fd0dea6c12fe) | Sigma | SigmaHQ |
| T1686 | [Disable System Firewall](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A53059bc0-1472-438b-956a-7508a94a91f0) | Sigma | SigmaHQ |
| T1686 | [Netsh RDP Port Opening](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A01aeb693-138d-49d2-9403-c4f52d7d3d62) | Sigma | OpenSearch Security Analytics |
| T1686.002 | [FortiGate - New Firewall Policy Added](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Af24ab7a8-f09a-4319-82c1-915586aa642b) | Sigma | SigmaHQ |
| T1686.002 | [FortiGate - Firewall Address Object Added](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A5c8d7b41-3812-432f-a0bb-4cfb7c31827e) | Sigma | SigmaHQ |

## 9. Plano de emulação e validação

Use num laboratório isolado e autorizado para confirmar que as regras disparam. Os comandos estão nos repositórios oficiais.

| Tática | Técnica | Teste Atomic Red Team | Plataformas |
|---|---|---|---|
| Execution | [T1059.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.004/T1059.004.md) | Create and Execute Bash Shell Script | linux, macos |
| Execution | [T1059.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.004/T1059.004.md) | Command-Line Interface | linux, macos |
| Execution | [T1072](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1072/T1072.md) | Radmin Viewer Utility | windows |
| Execution | [T1072](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1072/T1072.md) | PDQ Deploy RAT | windows |
| Execution | [T1610](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1610/T1610.md) | Deploy Docker container | containers |
| Persistence | [T1098.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1098.004/T1098.004.md) | Modify SSH Authorized Keys | linux, macos |
| Persistence | [T1136.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1136.001/T1136.001.md) | Create a user account on a Linux system | linux |
| Persistence | [T1136.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1136.001/T1136.001.md) | Create a user account on a FreeBSD system | linux |
| Privilege Escalation | [T1548.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1548.003/T1548.003.md) | Sudo usage | linux, macos |
| Privilege Escalation | [T1548.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1548.003/T1548.003.md) | Sudo usage (freebsd) | linux |
| Stealth | [T1070.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.003/T1070.003.md) | Clear Bash history (rm) |  |
| Stealth | [T1070.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.003/T1070.003.md) | Clear Bash history (echo) |  |
| Defense Impairment | [T1685](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1685/T1685.md) | Windows Disable LSA Protection | windows |
| Defense Impairment | [T1685](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1685/T1685.md) | Disable journal logging via systemctl utility | linux |
| Defense Impairment | [T1685.006](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1685.006/T1685.006.md) | rm -rf | linux, macos |
| Defense Impairment | [T1685.006](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1685.006/T1685.006.md) | rm -rf | linux |
| Defense Impairment | [T1686](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1686/T1686.md) | Disable Microsoft Defender Firewall | windows |
| Defense Impairment | [T1686](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1686/T1686.md) | Disable Microsoft Defender Firewall via Registry | windows |
| Credential Access | [T1040](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1040/T1040.md) | Packet Capture Linux using tshark or tcpdump | linux |
| Credential Access | [T1040](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1040/T1040.md) | Packet Capture FreeBSD using tshark or tcpdump | linux |
| Credential Access | [T1110.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1110.001/T1110.001.md) | Brute Force Credentials of single Active Directory domain users via SMB | windows |
| Credential Access | [T1110.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1110.001/T1110.001.md) | Brute Force Credentials of single Active Directory domain user via LDAP against domain controller (NTLM or Kerberos) | windows |
| Credential Access | [T1110.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1110.002/T1110.002.md) | Password Cracking with Hashcat | windows |
| Credential Access | [T1552.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1552.001/T1552.001.md) | Find AWS credentials | linux, macos |
| Credential Access | [T1552.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1552.001/T1552.001.md) | Extract Browser and System credentials with LaZagne | macos |
| Discovery | [T1016](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1016/T1016.md) | System Network Configuration Discovery on Windows | windows |
| Discovery | [T1016](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1016/T1016.md) | List Windows Firewall Rules | windows |
| Discovery | [T1018](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1018/T1018.md) | Remote System Discovery - net | windows |
| Discovery | [T1018](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1018/T1018.md) | Remote System Discovery - net group Domain Computers | windows |
| Discovery | [T1046](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1046/T1046.md) | Port Scan | linux, macos |
| Discovery | [T1046](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1046/T1046.md) | Port Scan Nmap | linux, macos |
| Discovery | [T1082](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1082/T1082.md) | System Information Discovery | windows |
| Discovery | [T1082](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1082/T1082.md) | System Information Discovery | macos |
| Lateral Movement | [T1021.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.001/T1021.001.md) | RDP to Remote Host | windows |
| Lateral Movement | [T1021.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.001/T1021.001.md) | Changing RDP Port to Non Standard Port via Powershell | windows |
| Lateral Movement | [T1021.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.004/T1021.004.md) | ESXi - Enable SSH via PowerCLI | windows |
| Lateral Movement | [T1021.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.004/T1021.004.md) | ESXi - Enable SSH via VIM-CMD | windows |
| Collection | [T1005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1005/T1005.md) | Search files of interest and save them to a single zip file (Windows) | windows |
| Collection | [T1005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1005/T1005.md) | Find and dump sqlite databases (Linux) | linux |
| Command and Control | [T1071.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1071.001/T1071.001.md) | Malicious User Agents - Powershell | windows |
| Command and Control | [T1071.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1071.001/T1071.001.md) | Malicious User Agents - CMD | windows |
| Command and Control | [T1090.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1090.003/T1090.003.md) | Psiphon | windows |
| Command and Control | [T1090.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1090.003/T1090.003.md) | Tor Proxy Usage - Windows | windows |
| Command and Control | [T1095](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1095/T1095.md) | ICMP C2 | windows |
| Command and Control | [T1095](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1095/T1095.md) | Netcat C2 | windows |
| Command and Control | [T1105](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1105/T1105.md) | rsync remote file copy (push) | linux, macos |
| Command and Control | [T1105](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1105/T1105.md) | rsync remote file copy (pull) | linux, macos |
| Command and Control | [T1132.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1132.001/T1132.001.md) | Base64 Encoded data. | linux, macos |
| Command and Control | [T1132.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1132.001/T1132.001.md) | Base64 Encoded data (freebsd) | linux |
| Command and Control | [T1571](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1571/T1571.md) | Testing usage of uncommonly used port with PowerShell | windows |
| Command and Control | [T1571](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1571/T1571.md) | Testing usage of uncommonly used port | linux, macos |
| Command and Control | [T1572](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1572/T1572.md) | DNS over HTTPS Large Query Volume | windows |
| Command and Control | [T1572](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1572/T1572.md) | DNS over HTTPS Regular Beaconing | windows |
| Exfiltration | [T1048.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1048.003/T1048.003.md) | Exfiltration Over Alternative Protocol - HTTP | linux, macos |
| Exfiltration | [T1048.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1048.003/T1048.003.md) | Exfiltration Over Alternative Protocol - ICMP | windows |

**Logs reais de ataque (EVTX) para testar sem executar nada:**

- T1016 — [ID4688-Audit policy enumerated](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1016-System%20Network%20Configuration%20Discovery/ID4688-Audit%20policy%20enumerated.evtx) _(explícito)_
- T1016 — [ID4688-Firewall configuration enumerated (command)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1016-System%20Network%20Configuration%20Discovery/ID4688-Firewall%20configuration%20enumerated%20%28command%29.evtx) _(explícito)_
- T1018 — [ID5145-DNS hosts files access via network share](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1018-Remote%20System%20Discovery/ID5145-DNS%20hosts%20files%20access%20via%20network%20share.evtx) _(explícito)_
- T1021.001 — [ID4688,4778,4779 RDP hijack direct](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0008-Lateral%20Movement/T1021.001-Remote%20Desktop%20Protocol/ID4688%2C4778%2C4779%20RDP%20hijack%20direct.evtx) _(explícito)_
- T1021.001 — [ID4688-4778 RDP hijack command execution](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0008-Lateral%20Movement/T1021.001-Remote%20Desktop%20Protocol/ID4688-4778%20RDP%20hijack%20command%20execution.evtx) _(explícito)_
- T1021.004 — [ID4-OpenSSH server listening](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0008-Lateral%20Movement/T1021.004-Remote%20Service%20SSH/ID4-OpenSSH%20server%20listening.evtx) _(explícito)_
- T1021.004 — [ID4103-4104-OpenSSH server activation and config](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0008-Lateral%20Movement/T1021.004-Remote%20Service%20SSH/ID4103-4104-OpenSSH%20server%20activation%20and%20config.evtx) _(explícito)_
- T1040 — [ID-4688 Native Windows sniffer Pktmon usage](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0006-Credential%20Access/T1040-Traffic%20sniffing/ID-4688%20Native%20Windows%20sniffer%20Pktmon%20usage.evtx) _(explícito)_
- T1046 — [ID131-RDP brutforce (no user info)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1046-Network%20Service%20Scanning/ID131-RDP%20brutforce%20%28no%20user%20info%29.evtx) _(explícito)_
- T1046 — [ID4624-Anonymous login with domain specified (DonPapi)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1046-Network%20Service%20Scanning/ID4624-Anonymous%20login%20with%20domain%20specified%20%28DonPapi%29.evtx) _(explícito)_
- T1078 — [ID1149-RDP success logins to multiple hosts](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0001-Initial%20access/T1078-Valid%20accounts/ID1149-RDP%20success%20logins%20to%20multiple%20hosts.evtx) _(explícito)_
- T1078 — [ID33205-SQL Server failed login with disabled SA account](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0001-Initial%20access/T1078-Valid%20accounts/ID33205-SQL%20Server%20failed%20login%20with%20disabled%20SA%20account.evtx) _(explícito)_
- T1090 — [ID5600-proxy configuration changed](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0011-Command%20and%20Control/T1090-Proxy/ID5600-proxy%20configuration%20changed.evtx) _(explícito)_
- T1136 — [ID33205-SQL Server Disabled SA user activated](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0003-Persistence/T1136-Create%20account/ID33205-SQL%20Server%20Disabled%20SA%20user%20activated.evtx) _(explícito)_
- T1136 — [ID33205-SQL Server local user created](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0003-Persistence/T1136-Create%20account/ID33205-SQL%20Server%20local%20user%20created.evtx) _(explícito)_
- T1572 — [ID4688-netsh RDP port forwarding abuse](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0011-Command%20and%20Control/T1572-Protocol%20tunneling/ID4688-netsh%20RDP%20port%20forwarding%20abuse.evtx) _(explícito)_
- T1685 — [ID1-SYSMON driver unload (FilterManager)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0005-Defense%20Evasion/T1562.001-Impair%20Defenses-Disable%20or%20Modify%20tool/ID1-SYSMON%20driver%20unload%20%28FilterManager%29.evtx) _(explícito)_
- T1685 — [ID13-Defender service configuration disabled](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0005-Defense%20Evasion/T1562.001-Impair%20Defenses-Disable%20or%20Modify%20tool/ID13-Defender%20service%20configuration%20disabled.evtx) _(explícito)_
- T1686 — [ID2003-4950-Firewall disabled](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0005-Defense%20Evasion/T1562.004-Impair%20Defenses-Disable%20or%20Modify%20System%20Firewall/ID2003-4950-Firewall%20disabled.evtx) _(explícito)_
- T1686 — [ID2004-Any any firewall rule created](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0005-Defense%20Evasion/T1562.004-Impair%20Defenses-Disable%20or%20Modify%20System%20Firewall/ID2004-Any%20any%20firewall%20rule%20created.evtx) _(explícito)_

## 10. Hipóteses de hunting

Se Salt Typhoon estiver no seu ambiente, estas são as perguntas a fazer aos seus dados (fontes de log segundo as estratégias de detecção do MITRE ATT&CK).

1. **T1020.001 Traffic Duplication** — Configuration changes to virtual TAP/mirror policies that forward traffic to unapproved destinations. Detection correlates management plane API calls with mirrored traffic observation. Dados: `AWS:CloudTrail` (CreateTrafficMirrorSession or ModifyTrafficMirrorTarget), `AWS:VPCFlowLogs` (Traffic observed on mirror destination instance).
2. **T1059.008 Network Device CLI** — Detects unauthorized or anomalous use of command-line interfaces (CLI) on network devices. Focuses on remote access sessions (e.g., SSH/Telnet), privilege escalation within CLI sessions, execution of high-risk commands (e.g., config replace, terminal monitor,… Dados: `networkdevice:syslog` (command_exec), `NSM:Flow` (remote CLI session detection), `networkdevice:syslog` (authorization/accounting logs).
3. **T1070.009 Clear Persistence** — Detects adversary activity that removes persistence artifacts such as services, registry keys, scheduled tasks, user accounts, and binaries through commands like `sc delete`, `schtasks /delete`, or `reg delete`. Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Security` (EventCode=4726, 4657), `WinEventLog:TaskScheduler` (EventCode=106).
4. **T1543.005 Container Service** — Correlate the creation or modification of containers using restart policies (e.g., 'always') or DaemonSets with elevated host access, service account misuse, or privileged container contexts. Watch for manipulation of systemd units involving containers or pod… Dados: `auditd:SYSCALL` (execve), `systemd:unit` (container run with restart policy set to 'always' or 'unless-stopped'), `kubernetes:audit` (create).
5. **T1569 System Services** — Monitor for abnormal creation or modification of Windows services (e.g., via sc.exe, PowerShell, or API calls) that load non-standard executables. Correlate registry changes in service keys with service creation events and process execution to detect service… Dados: `WinEventLog:Security` (EventCode=4697), `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=13, 14).
6. **T1595 Active Scanning** — Monitor network data for uncommon data flows. Processes utilizing the network that do not normally have network communication or have never been seen before are suspicious. Monitor and analyze traffic patterns and packet inspection associated to protocol(s)… Dados: `Network Traffic` (None), `Network Traffic` (None).
7. **T1602.001 SNMP (MIB Dump)** — Defenders may observe suspicious SNMP MIB enumeration through abnormal queries for large sets of OIDs, repeated SNMP GETBULK/GETNEXT requests, or queries originating from non-administrative IP addresses. Anomalous use of community strings, authentication… Dados: `networkdevice:syslog` (Authentication failures, unexpected community string usage, or unauthorized SNMPv1/v2 requests), `NSM:Flow` (High-volume or repeated SNMP GETBULK/GETNEXT queries from untrusted or external IPs), `networkdevice:audit` (SNMP configuration changes, such as enabling read/write access or modifying community strings).
8. **T1602.002 Network Device Configuration Dump** — Defenders may observe adversary attempts to collect or export full device configurations by detecting unusual SNMP queries, Smart Install (SMI) activity, or CLI/API commands that request running or startup configuration dumps. Correlated behaviors include… Dados: `networkdevice:syslog` (Failed and successful logins to network devices outside approved admin IP ranges), `networkdevice:cli` (Execution of commands like 'show running-config', 'copy running-config', or 'export config'), `NSM:Flow` (Outbound SCP, TFTP, or FTP sessions carrying configuration file content).
9. **T1548.003 Sudo and Sudo Caching** — Correlate command executions involving 'sudo' with elevated effective user ID (euid=0), especially when tty_tickets is disabled or timestamp_timeout is actively abused. Dados: `auditd:SYSCALL` (execve call for sudo where euid != uid), `auditd:SYSCALL` (execve call for modification of /etc/sudoers or writing to /var/db/sudo).
10. **T1556 Modify Authentication Process** — Detects modification of LSASS and authentication DLLs, suspicious registry changes to password filter packages, and abnormal process access to lsass.exe. Correlates registry modifications, DLL loads, and process handle access events. Dados: `WinEventLog:Security` (EventCode=4657), `WinEventLog:Sysmon` (EventCode=10), `WinEventLog:Sysmon` (EventCode=7).
11. **T1599 Network Boundary Bridging** — From a defender’s perspective, suspicious bridging is observed when network devices begin allowing traffic that contradicts existing segmentation or access policies. Observable behaviors include sudden modifications to ACLs or firewall rules, unusual… Dados: `NSM:Flow` (Unexpected flows between segmented networks or prohibited ports), `networkdevice:syslog` (ACL/Firewall rule modification or new route injection).
12. **T1686.002 Network Device Firewall** — Defender observes configuration changes on firewall/network appliance involving rule creation, modification, or deletion from abnormal management IPs or non-console channels (e.g., remote CLI, API). These are often correlated with a spike in previously… Dados: `networkdevice:Firewall` (update_rule: Access control or NAT rule modified or disabled outside maintenance window), `networkdevice:Firewall` (Login from untrusted IP, or new admin account accessing firewall console/API), `networkdevice:Firewall` (Audit trail or CLI/API access indicating commands like no access-list, delete rule-set, clear config).

## 11. OSINT — onde pesquisar

Consultas prontas com todos os nomes conhecidos do grupo:

- Relatórios técnicos: [busca web](https://duckduckgo.com/?q=%28%22Salt+Typhoon%22%29+threat+report) · [PDFs](https://duckduckgo.com/?q=%28%22Salt+Typhoon%22%29+filetype%3Apdf)
- Regras e IOCs publicados: [GitHub](https://github.com/search?type=code&q=%22Salt+Typhoon%22)
- Pulsos de ameaça: [AlienVault OTX](https://otx.alienvault.com/browse/global/pulses?q=Salt+Typhoon)
- Família de malware e atores: [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/actors) (busque por Salt Typhoon)
- Cartões de grupo: [ThaiCERT Threat Group Cards](https://apt.etda.or.th/cgi-bin/listgroups.cgi)
- Página oficial: [MITRE ATT&CK G1045](https://attack.mitre.org/groups/G1045/)

## 12. Bibliografia (8 fontes citadas pelo ATT&CK)

- [CarySentinelLabs_CiscoSaltTyphoon_Dec2025](https://www.sentinelone.com/labs/malicious-apprentice-how-two-hackers-went-from-cisco-academy-to-cisco-cves/) — Cary, D. (2025, December 10). Malicious Apprentice | How Two Hackers Went From Cisco Academy to Cisco CVEs. Retrieved September 22, 2026.
- [CISA_AA25-239ASaltTyphoon_Sept2025](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-239a) — CISA. (2025, September 3). Countering Chinese State-Sponsored Actors Compromise of Networks Worldwide to Feed Global Espionage System. Retrieved September 22, 2026.
- [Cisco Salt Typhoon FEB 2025](https://blog.talosintelligence.com/salt-typhoon-analysis/) — Cisco Talos. (2025, February 20). Weathering the storm: In the midst of a Typhoon. Retrieved February 24, 2025.
- [CrowdStrike_OperatorPanda_NoDate](https://www.crowdstrike.com/en-us/adversaries/operator-panda/) — CrowdStrike. (n.d.). Operator Panda. Retrieved September 22, 2026.
- [Mandiant_M-Trends2026_Mar2026](https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2026) — Kutscher, J. (2026, March 23). M-Trends 2026: Data, Insights, and Strategies From the Frontlines. Retrieved September 22, 2026.
- [Microsoft_ThreatActorNaming_NoDate](https://learn.microsoft.com/en-us/unified-secops/microsoft-threat-actor-naming) — Microsoft. (n.d.). How Microsoft names threat actors. Retrieved September 22, 2026.
- [RF_SaltTyphoon_Feb2025](https://www.recordedfuture.com/research/redmike-salt-typhoon-exploits-vulnerable-devices) — Insikt Group. (2025, February 13). RedMike (Salt Typhoon) Exploits Cisco Vulnerabilities for Cyber Espionage. Retrieved September 22, 2026.
- [US Dept. of Treasury Salt Typhoon JAN 2025](https://home.treasury.gov/news/press-releases/jy2792) — US Department of Treasury. (2025, January 17). Treasury Sanctions Company Associated with Salt Typhoon and Hacker Associated with Treasury Compromise. Retrieved February 24, 2025.

## 13. Limites e confiança

- O ATT&CK registra o que foi **relatado publicamente**, não tudo o que o grupo faz. Ausência de uma técnica não prova que o grupo não a usa.
- **Sobreposição de TTP não é atribuição.** Muitas técnicas são compartilhadas entre grupos e com red teams. Use a assinatura comportamental como hipótese, junto com infraestrutura, malware e contexto.
- Cobertura de detecção refere-se ao catálogo público Detection Rules, não ao seu ambiente: confira se a telemetria necessária chega ao seu SIEM.
- Ligações marcadas como _inferidas_ (EVTX por palavra-chave, relatórios por nome) devem ser verificadas.

---
Fontes: MITRE ATT&CK® (uso livre com atribuição, © The MITRE Corporation), APT4ALL (MISP Galaxy CC0/BSD-2, APT Groups & Operations CC BY 4.0, EternalLiberty, APTnotes, Ransomware Tool Matrix CC BY 4.0), Atomic Red Team (Red Canary, MIT), EVTX-to-MITRE-Attack, EVTX-ATTACK-SAMPLES, APT & CyberCriminal Campaign Collections. Gerado por [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules).
