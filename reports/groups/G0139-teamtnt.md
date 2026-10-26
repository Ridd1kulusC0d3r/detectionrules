# TeamTNT (G0139) — Dossiê de inteligência

> **TLP:CLEAR** · gerado em 2026-10-26 a partir de fontes abertas · MITRE ATT&CK v20.0 · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0139) · [ATT&CK](https://attack.mitre.org/groups/G0139/)

**Também conhecido como:** —  
**Origem atribuída:** Sem país atribuído · **Motivação:** financeiro · **Setores-alvo:** —  
**Registro no ATT&CK:** criado em 2021-10-01, atualizado em 2026-07-31 · referências de 2020 a 2022

## 1. Sumário executivo

- **56 técnicas** atribuídas publicamente, concentradas em **Discovery, Execution, Stealth**.
- **Arsenal:** 1 malware e 3 ferramentas (ex.: Hildegard, Peirates, LaZagne, MimiPenguin).
- **Campanhas atribuídas:** 0.
- **Cobertura de detecção pública:** 95% das técnicas têm ao menos uma regra no catálogo; **3 técnicas sem nenhuma regra pública**.
- **Origem e alvos (APT4ALL):** atribuído a **Sem país atribuído**, motivação financeiro.
- **Onde a cobertura está:** EDR / XDR (49 técnicas com regra), Linux (47 técnicas com regra), Windows (44 técnicas com regra), Outros / genérico (37 técnicas com regra).
- **Assinatura comportamental** (técnicas raras entre os 178 grupos, as mais úteis para atribuição): T1204.003 Malicious Image, T1552.005 Cloud Instance Metadata API, T1569.003 Systemctl, T1609 Container Administration Command, T1611 Escape to Host.

## 2. Quem é

> TeamTNT is a threat group that has primarily targeted cloud and containerized environments. The group as been active since at least October 2019 and has mainly focused its efforts on leveraging cloud and container resources to deploy cryptocurrency miners in victim environments.

_Texto original do MITRE ATT&CK, em inglês._

## 3. Contexto, nomes e alvos

Consolidado pelo [APT4ALL](https://github.com/Ridd1kulusC0d3r/apt4all) a partir de MISP Galaxy, planilha APT Groups & Operations, EternalLiberty e APTnotes. Atribuição é afirmação de quem publicou; confira a fonte.

| Campo | Valor |
|---|---|
| Origem atribuída | Sem país atribuído |
| Motivação | financeiro |
| Setores-alvo | — |
| Vítimas citadas | — |
| Alvos (planilha) | — |
| Operações conhecidas | — |
| Confiança de atribuição (MISP) | High |

**Como cada fornecedor chama este grupo** (útil para cruzar relatórios):

| Fornecedor | Nome(s) |
|---|---|
| MITRE ATT&CK | G0139 |

**Outros nomes no APT4ALL (não listados pelo ATT&CK):** Adept Libra

## 4. Perfil TTP por tática (kill chain)

Cada linha: técnica, como o grupo a usou segundo relatos públicos, e o que existe para detectar e testar.

### Reconnaissance (TA0043) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1595.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1595.001) Scanning IP Blocks | TeamTNT has scanned specific lists of target IP addresses. | 13 | — | — |
| [T1595.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1595.002) Vulnerability Scanning | TeamTNT has scanned for vulnerabilities in IoT devices and other related resources such as the Docker API. | 27 | — | — |

### Resource Development (TA0042) — 3

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1583.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1583.001) Domains | TeamTNT has obtained domains to host their payloads. | 7 | — | — |
| [T1587.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1587.001) Malware | TeamTNT has developed custom malware such as Hildegard. | 43 | — | — |
| [T1608.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1608.001) Upload Malware | TeamTNT has uploaded backdoored Docker images to Docker Hub. | 3 | — | — |

### Initial Access (TA0001) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1133](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1133) External Remote Services | TeamTNT has used open-source tools such as Weave Scope to target exposed Docker API ports and gain initial access to victim environments. TeamTNT has also targeted exposed kubelets for Kubernetes environments. | 361 | 1 | — |

### Execution (TA0002) — 9

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1059.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.001) PowerShell | TeamTNT has executed PowerShell commands in batch scripts. | 1340 | 22 | 15 |
| [T1059.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.003) Windows Command Shell | TeamTNT has used batch scripts to download tools and executing cryptocurrency miners. | 269 | 6 | 1 |
| [T1059.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.004) Unix Shell | TeamTNT has used shell scripts for execution. | 395 | 17 | — |
| [T1059.009](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.009) Cloud API | TeamTNT has leveraged AWS CLI to enumerate cloud environments with compromised credentials. | 11 | — | — |
| [T1059.013](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.013) Container CLI/API | TeamTNT targeted misconfigured containers and used container CLI tools. | **0** | — | — |
| [T1204.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1204.003) Malicious Image | TeamTNT has relied on users to download and execute malicious Docker images. | 3 | 1 | — |
| [T1569.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1569.003) Systemctl | TeamTNT has created system services to execute cryptocurrency mining software. | **0** | — | — |
| [T1609](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1609) Container Administration Command | TeamTNT executed Hildegard through the kubelet API run command and by executing commands on running containers. | 42 | 2 | — |
| [T1610](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1610) Deploy Container | TeamTNT has deployed different types of containers into victim environments to facilitate execution. TeamTNT has also transferred cryptocurrency mining software to Kubernetes clusters discovered within local IP address ranges. | 45 | 1 | — |

### Persistence (TA0003) — 6

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1098.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1098.004) SSH Authorized Keys | TeamTNT has added RSA keys in authorized_keys. | 16 | 1 | — |
| [T1133](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1133) External Remote Services | TeamTNT has used open-source tools such as Weave Scope to target exposed Docker API ports and gain initial access to victim environments. TeamTNT has also targeted exposed kubelets for Kubernetes environments. | 361 | 1 | — |
| [T1136.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1136.001) Local Account | TeamTNT has created local privileged users on victim machines. | 103 | 10 | — |
| [T1543.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1543.002) Systemd Service | TeamTNT has established persistence through the creation of a cryptocurrency mining system service using systemctl. | 23 | 4 | — |
| [T1543.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1543.003) Windows Service | TeamTNT has used malware that adds cryptocurrency miners as a service. | 1916 | 6 | 19 |
| [T1547.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1547.001) Registry Run Keys / Startup Folder | TeamTNT has added batch scripts to the startup folder. | 299 | 21 | 2 |

### Privilege Escalation (TA0004) — 5

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1098.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1098.004) SSH Authorized Keys | TeamTNT has added RSA keys in authorized_keys. | 16 | 1 | — |
| [T1543.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1543.002) Systemd Service | TeamTNT has established persistence through the creation of a cryptocurrency mining system service using systemctl. | 23 | 4 | — |
| [T1543.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1543.003) Windows Service | TeamTNT has used malware that adds cryptocurrency miners as a service. | 1916 | 6 | 19 |
| [T1547.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1547.001) Registry Run Keys / Startup Folder | TeamTNT has added batch scripts to the startup folder. | 299 | 21 | 2 |
| [T1611](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1611) Escape to Host | TeamTNT has deployed privileged containers that mount the filesystem of victim machine. | 74 | 3 | — |

### Stealth (TA0005) — 8

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1014](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1014) Rootkit | TeamTNT has used rootkits such as the open-source Diamorphine rootkit and their custom bots to hide cryptocurrency mining activities on the machine. | 44 | 4 | — |
| [T1027.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1027.002) Software Packing | TeamTNT has used UPX and Ezuri packer to pack its binaries. | 12 | 4 | — |
| [T1027.013](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1027.013) Encrypted/Encoded File | TeamTNT has encrypted its binaries via AES and encoded files using Base64. | 8 | 4 | — |
| [T1036](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1036) Masquerading | TeamTNT has disguised their scripts with docker-related file names. | 453 | 2 | 1 |
| [T1036.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1036.005) Match Legitimate Resource Name or Location | TeamTNT has replaced .dockerd and .dockerenv with their own scripts and cryptocurrency mining software. | 116 | 4 | — |
| [T1070.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1070.003) Clear Command History | TeamTNT has cleared command history with history -c. | 63 | 14 | — |
| [T1070.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1070.004) File Deletion | TeamTNT has used a payload that removes itself after running. TeamTNT also has deleted locally staged files for collecting credentials or scan results for local IP addresses after exfiltrating them. | 132 | 11 | — |
| [T1140](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1140) Deobfuscate/Decode Files or Information | TeamTNT has used a script that decodes a Base64-encoded version of WeaveWorks Scope. | 173 | 11 | 1 |

### Defense Impairment (TA0112) — 4

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1222.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1222.002) Linux and Mac Permissions | TeamTNT has modified the permissions on binaries with chattr. | 34 | 14 | — |
| [T1685](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1685) Disable or Modify Tools | TeamTNT has disabled and uninstalled security tools such as Alibaba, Tencent, and BMC cloud monitoring agents on cloud-based infrastructure. | 1275 | 78 | 19 |
| [T1685.006](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1685.006) Clear Linux or Mac System Logs | TeamTNT has removed system logs from /var/log/syslog. | 23 | 20 | — |
| [T1686](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1686) Disable or Modify System Firewall | TeamTNT has disabled iptables. | 56 | 25 | 6 |

### Credential Access (TA0006) — 3

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1552.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1552.001) Credentials In Files | TeamTNT has searched for unsecured AWS credentials and Docker API credentials. | 166 | 32 | — |
| [T1552.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1552.004) Private Keys | TeamTNT has searched for unsecured SSH keys. | 60 | 17 | 1 |
| [T1552.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1552.005) Cloud Instance Metadata API | TeamTNT has queried the AWS instance metadata service for credentials. | 25 | 3 | — |

### Discovery (TA0007) — 11

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1007](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1007) System Service Discovery | TeamTNT has searched for services such as Alibaba Cloud Security's aliyun service and BMC Helix Cloud Security's bmc-agent service in order to disable them. | 37 | 8 | — |
| [T1016](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1016) System Network Configuration Discovery | TeamTNT has enumerated the host machine’s IP address. | 99 | 10 | 5 |
| [T1046](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1046) Network Service Discovery | TeamTNT has used masscan to search for open Docker API ports and Kubernetes clusters. TeamTNT has also used malware that utilizes zmap and zgrab to search for vulnerable services in cloud environments. | 212 | 13 | 2 |
| [T1049](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1049) System Network Connections Discovery | TeamTNT has run netstat -anp to search for rival malware connections. TeamTNT has also used `libprocesshider` to modify /etc/ld.so.preload. | 47 | 7 | — |
| [T1057](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1057) Process Discovery | TeamTNT has searched for rival malware and removes it if found. TeamTNT has also searched for running processes containing the strings aliyun or liyun to identify machines running Alibaba Cloud Security tools. | 82 | 10 | — |
| [T1082](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1082) System Information Discovery | TeamTNT has searched for system version, architecture, and hostname information. | 264 | 41 | — |
| [T1083](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1083) File and Directory Discovery | TeamTNT has used a script that checks `/proc/*/environ` for environment variables related to AWS. | 137 | 9 | — |
| [T1120](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1120) Peripheral Device Discovery | TeamTNT has searched for attached VGA devices using lspci. | 11 | 4 | — |
| [T1518.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1518.001) Security Software Discovery | TeamTNT has searched for security products on infected machines. | 54 | 12 | — |
| [T1613](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1613) Container and Resource Discovery | TeamTNT has checked for running containers with docker ps and for specific container names with docker inspect. TeamTNT has also searched for Kubernetes pods running in a local network. | 62 | 2 | — |
| [T1680](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1680) Local Storage Discovery | TeamTNT has searched for disk partition and logical volume information. | **0** | — | — |

### Lateral Movement (TA0008) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1021.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1021.004) SSH | TeamTNT has used SSH to connect back to victim machines. TeamTNT has also used SSH to transfer tools and payloads onto victim hosts and execute them. | 60 | 2 | 3 |

### Collection (TA0009) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1074.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1074.001) Local Data Staging | TeamTNT has aggregated collected credentials in text files before exfiltrating. | 37 | 3 | — |

### Command and Control (TA0011) — 5

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1071](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1071) Application Layer Protocol | TeamTNT has used an IRC bot for C2 communications. | 511 | 1 | — |
| [T1071.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1071.001) Web Protocols | TeamTNT has the `curl` command to send credentials over HTTP and the `curl` and `wget` commands to download new software. TeamTNT has also used a custom user agent HTTP header in shell scripts. | 228 | 3 | — |
| [T1102](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1102) Web Service | TeamTNT has leveraged iplogger.org to send collected data back to C2. | 98 | — | — |
| [T1105](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1105) Ingress Tool Transfer | TeamTNT has the curl and wget commands as well as batch scripts to download new tools. | 644 | 39 | — |
| [T1219](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1219) Remote Access Tools | TeamTNT has established tmate sessions for C2 communications. | 119 | 15 | — |

### Exfiltration (TA0010) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1048](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1048) Exfiltration Over Alternative Protocol | TeamTNT has sent locally staged files with collected credentials to C2 servers using cURL. | 151 | 4 | — |

### Impact (TA0040) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1496.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1496.001) Compute Hijacking | TeamTNT has deployed XMRig Docker images to mine cryptocurrency. TeamTNT has also infected Docker containers and Kubernetes clusters with XMRig, and used RainbowMiner and lolMiner for mining cryptocurrency. | 2 | — | — |

## 5. Assinatura comportamental

Técnicas que este grupo usa e que poucos dos 178 grupos do ATT&CK usam. Pesam mais numa atribuição por TTP: ver várias delas juntas é mais informativo do que ver técnicas comuns como PowerShell.

| Técnica | Outros grupos que usam | Peso (raridade) |
|---|---:|---:|
| T1204.003 Malicious Image | 0 | 4.49 |
| T1552.005 Cloud Instance Metadata API | 0 | 4.49 |
| T1569.003 Systemctl | 0 | 4.49 |
| T1609 Container Administration Command | 0 | 4.49 |
| T1611 Escape to Host | 0 | 4.49 |
| T1613 Container and Resource Discovery | 0 | 4.49 |
| T1048 Exfiltration Over Alternative Protocol | 1 | 4.09 |
| T1595.001 Scanning IP Blocks | 1 | 4.09 |
| T1059.013 Container CLI/API | 2 | 3.80 |
| T1098.004 SSH Authorized Keys | 2 | 3.80 |

## 6. Arsenal

| Software | Tipo | Técnicas no ATT&CK | Uso relatado (EN) |
|---|---|---:|---|
| [Hildegard](https://attack.mitre.org/software/S0601/) | malware | 27 |  |
| [Peirates](https://attack.mitre.org/software/S0683/) | ferramenta | 12 |  |
| [LaZagne](https://attack.mitre.org/software/S0349/) | ferramenta | 10 |  |
| [MimiPenguin](https://attack.mitre.org/software/S0179/) | ferramenta | 1 |  |

## 7. Campanhas

Nenhuma campanha atribuída no ATT&CK.

## 8. Cobertura defensiva

**53 de 56 técnicas (95%)** têm ao menos uma regra pública no catálogo Detection Rules.

### Técnicas sem regra pública (prioridade para engenharia de detecção)

- **T1569.003 Systemctl** — Execution. Fonte de log sugerida pelo MITRE: `auditd:EXECVE` execution of systemctl with subcommands start, stop, enable, disable
- **T1059.013 Container CLI/API** — Execution. Fonte de log sugerida pelo MITRE: `auditd:SYSCALL` execve: Execution of container management CLIs (docker, crictl, kubectl) or interpreted shells (sh, bash, python) within container context
- **T1680 Local Storage Discovery** — Discovery. Fonte de log sugerida pelo MITRE: `WinEventLog:Sysmon` EventCode=1; `auditd:SYSCALL` execve call with argv matching known disk enumeration commands (lsblk, parted, fdisk); `macos:unifiedlog` process launch of diskutil or system_profil

### Onde procurar — cobertura por tecnologia

Quantas técnicas deste grupo têm ao menos uma regra em cada tecnologia. Comece a caça pelas tecnologias que você tem e que aparecem aqui.

| Tecnologia | Técnicas do grupo com regra |
|---|---:|
| EDR / XDR | 49 |
| Linux | 47 |
| Windows | 44 |
| Outros / genérico | 37 |
| macOS | 35 |
| Contêineres (Docker/runtime) | 29 |
| AWS | 29 |
| Servidores web & aplicações | 28 |
| DNS | 28 |
| Firewall & perímetro | 27 |
| Azure (recursos) | 26 |
| Integridade, conformidade & vulnerabilidade | 25 |

### Regras recomendadas por técnica

Melhor regra disponível por técnica (formato portável e maduro primeiro).

| Técnica | Regra | Formato | Fonte |
|---|---|---|---|
| T1007 | [HackTool - PCHunter Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Afca949cc-79ca-446e-8064-01aa7e52ece5) | Sigma | SigmaHQ |
| T1007 | [SC.EXE Query Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A57712d7a-679c-4a41-a913-87e7175ae429) | Sigma | SigmaHQ |
| T1014 | [Triple Cross eBPF Rootkit Install Commands](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A22236d75-d5a0-4287-bf06-c93b1770860f) | Sigma | SigmaHQ |
| T1014 | [Triple Cross eBPF Rootkit Install Commands](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A22236d75-d5a0-4287-bf06-c93b1770860f) | Sigma | OpenSearch Security Analytics |
| T1016 | [Potential Pikabot Discovery Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A698d4431-514f-4c82-af4d-cf573872a9f5) | Sigma | SigmaHQ |
| T1016 | [OpenCanary - SNMP OID Request](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae9856028-fd4e-46e6-b3d1-10f7ceb95078) | Sigma | SigmaHQ |
| T1021.004 | [Potential THC Tool Downloaded](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A2ddc468e-b39b-4f5b-9825-f3dcb0e998ea) | Elastic | Elastic detection-rules |
| T1021.004 | [AWS EC2 CreateKeyPair by New Principal from Non-Cloud AS Organization](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ac8e4f1a2-9b3d-4c5e-a6f7-8b9c0d1e2f3a) | Elastic | Elastic detection-rules |
| T1027.002 | [Python Image Load By Non-Python Process](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acbb56d62-4060-40f7-9466-d8aaf3123f83) | Sigma | SigmaHQ |
| T1027.002 | [Python Py2Exe Image Load](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Acbb56d62-4060-40f7-9466-d8aaf3123f83) | Sigma | OpenSearch Security Analytics |
| T1027.013 | [ROT Encoded Python Script Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A5ab49127-b1b3-46e6-8a38-9e8512a2a363) | Elastic | Elastic detection-rules |
| T1027.013 | [Data Encrypted via OpenSSL Utility](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Afeba48f6-40ca-4d04-b41f-5dfa327de865) | Elastic | Elastic detection-rules |
| T1036 | [Potential LSASS Process Dump Via Procdump](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A5afee48e-67dd-4e03-a783-f74259dcf998) | Sigma | SigmaHQ |
| T1036 | [Suspicious Use of Procdump on LSASS](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A5afee48e-67dd-4e03-a783-f74259dcf998) | Sigma | OpenSearch Security Analytics |
| T1036.005 | [Exploit for CVE-2015-1641](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A7993792c-5ce2-4475-a3db-a3a5539827ef) | Sigma | SigmaHQ |
| T1036.005 | [Exploit for CVE-2015-1641](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A7993792c-5ce2-4475-a3db-a3a5539827ef) | Sigma | OpenSearch Security Analytics |
| T1046 | [HackTool - winPEAS Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A98b53e78-ebaf-46f8-be06-421aafd176d9) | Sigma | SigmaHQ |
| T1046 | [HackTool - WinPwn Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad557dc06-62e8-4468-a8e8-7984124908ce) | Sigma | SigmaHQ |
| T1048 | [Suspicious Redirection to Local Admin Share](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aab9e3b40-0c85-4ba1-aede-455d226fd124) | Sigma | SigmaHQ |
| T1048 | [Powershell DNSExfiltration](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad59d7842-9a21-4bc6-ba98-64bfe0091355) | Sigma | SigmaHQ |
| T1049 | [Potential Pikabot Discovery Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A698d4431-514f-4c82-af4d-cf573872a9f5) | Sigma | SigmaHQ |
| T1049 | [HackTool - SharpView Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab2317cfa-4a47-4ead-b3ff-297438c0bc2d) | Sigma | SigmaHQ |
| T1057 | [Process Discovery](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4e2f5868-08d4-413d-899f-dc2f1508627b) | Sigma | SigmaHQ |
| T1057 | [HackTool - PCHunter Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Afca949cc-79ca-446e-8064-01aa7e52ece5) | Sigma | SigmaHQ |
| T1059.001 | [Potential Emotet Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad02e8cf5-6099-48cf-9bfc-1eec2d0c7b18) | Sigma | SigmaHQ |
| T1059.001 | [TropicTrooper Campaign November 2018](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A8c7090c3-e0a0-4944-bd08-08c3a0cecf79) | Sigma | SigmaHQ |
| T1059.003 | [HackTool - CrackMapExec Execution Patterns](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A058f4380-962d-40a5-afce-50207d36d7e2) | Sigma | SigmaHQ |
| T1059.003 | [CrackMapExec Command Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A058f4380-962d-40a5-afce-50207d36d7e2) | Sigma | OpenSearch Security Analytics |
| T1059.004 | [Shell Invocation via Env Command - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Abed978f8-7f3a-432b-82c5-9286a9b3031a) | Sigma | SigmaHQ |
| T1059.004 | [Suspicious Reverse Shell Command Line](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A738d9bcf-6999-4fdb-b4ac-3033037db8ab) | Sigma | SigmaHQ |
| T1059.009 | [AWS IAM S3Browser User or AccessKey Creation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Adb014773-d9d9-4792-91e5-133337c0ffee) | Sigma | SigmaHQ |
| T1059.009 | [AWS IAM S3Browser Templated S3 Bucket Policy Creation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Adb014773-7375-4f4e-b83b-133337c0ffee) | Sigma | SigmaHQ |
| T1070.003 | [Cisco Clear Logs](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aceb407f6-8277-439b-951f-e4210e3ed956) | Sigma | SigmaHQ |
| T1070.003 | [Linux Command History Tampering](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Afdc88d25-96fb-4b7c-9633-c0e417fdbd4e) | Sigma | SigmaHQ |
| T1070.004 | [File Deletion](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A30aed7b6-d2c1-4eaf-9382-b6bc43e50c57) | Sigma | SigmaHQ |
| T1070.004 | [Prefetch File Deleted](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A0a1f9d29-6465-4776-b091-7f43b26e4c89) | Sigma | SigmaHQ |
| T1071 | [GALLIUM IOCs](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A440a56bf-7873-4439-940a-1c8a671073c2) | Sigma | SigmaHQ |
| T1071 | [GALLIUM Artefacts - Builtin](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A3db10f25-2527-4b79-8d4b-471eb900ee29) | Sigma | SigmaHQ |
| T1071.001 | [Ursnif Malware Download URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aa36ce77e-30db-4ea0-8795-644d7af5dfb4) | Sigma | SigmaHQ |
| T1071.001 | [Ursnif Malware C2 URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A932ac737-33ca-4afd-9869-0d48b391fcc9) | Sigma | SigmaHQ |
| T1074.001 | [Sensitive File Access followed by Compression](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Aa0fbd7a9-1923-4e05-92df-b484168f17bc) | Elastic | Elastic detection-rules |
| T1074.001 | [Folder Compress To Potentially Suspicious Output Via Compress-Archive Cmdlet](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A85a8e5ba-bd03-4bfb-bbfa-a4409a8f8b98+%23+Process+Creation) | Sigma | SigmaHQ |
| T1082 | [Potential GobRAT File Discovery Via Grep](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae34cfa0c-0a50-4210-9cb3-5632d08eb041) | Sigma | SigmaHQ |
| T1082 | [System Information Discovery](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A42df45e7-e6e9-43b5-8f26-bec5b39cc239) | Sigma | SigmaHQ |
| T1083 | [Turla Group Lateral Movement](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac601f20d-570a-4cde-a7d6-e17f99cb8e7f) | Sigma | SigmaHQ |
| T1083 | [WannaCry Ransomware Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A41d40bff-377a-43e2-8e1b-2e543069e079) | Sigma | SigmaHQ |
| T1098.004 | [Potential Redis CONFIG SET SSH Authorized Key Injection](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A39ab0f66-efa0-4649-9c9c-8c64682f5fdd) | Elastic | Elastic detection-rules |
| T1098.004 | [Suspicious Echo or Printf Execution Detected via Defend for Containers](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ad9bfa475-270d-4b07-93cb-b1f49abe13da) | Elastic | Elastic detection-rules |
| T1102 | [Communication To LocaltoNet Tunneling Service Initiated - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac4568f5d-131f-4e78-83d4-45b2da0ec4f1) | Sigma | SigmaHQ |
| T1102 | [Communication To Ngrok Tunneling Service - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A19bf6fdb-7721-4f3d-867f-53467f6a5db6) | Sigma | SigmaHQ |
| T1105 | [Greenbug Espionage Group Indicators](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A3711eee4-a808-4849-8a14-faf733da3612) | Sigma | SigmaHQ |
| T1105 | [Pandemic Registry Key](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A47e0852a-cf81-4494-a8e6-31864f8c86ed) | Sigma | SigmaHQ |
| T1120 | [PowerShell Suspicious Script with Audio Capture Capabilities](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A2f2f4939-0b34-40c2-a0a3-844eb7889f43) | Elastic | Elastic detection-rules |
| T1120 | [Fsutil Drive Enumeration](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A63de06b9-a385-40b5-8b32-73f2b9ef84b6) | Sigma | SigmaHQ |
| T1133 | [OpenCanary - SSH Login Attempt](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aff7139bc-fdb1-4437-92f2-6afefe8884cb) | Sigma | SigmaHQ |
| T1133 | [OpenCanary - SSH New Connection Attempt](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acd55f721-5623-4663-bd9b-5229cab5237d) | Sigma | SigmaHQ |
| T1136.001 | [DarkGate - User Created Via Net.EXE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Abf906d7b-7070-4642-8383-e404cf26eba5) | Sigma | SigmaHQ |
| T1136.001 | [Serv-U Exploitation CVE-2021-35211 by DEV-0322](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A75578840-9526-4b2a-9462-af469a45e767) | Sigma | SigmaHQ |
| T1140 | [UNC4841 - SSL Certificate Exfiltration Via Openssl](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A60911c07-f989-4362-84af-c609828ef829) | Sigma | SigmaHQ |
| T1140 | [UNC4841 - Download Compressed Files From Temp.sh Using Wget](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A60d050c4-e253-4d9a-b673-5ac100cfddfb) | Sigma | SigmaHQ |
| T1204.003 | [MS Graph message: Indicators that the system is potentially infected with malware have been detected. Check th](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=wazuh-ruleset-oficial%3A%3Awazuh-99532) | Wazuh | Wazuh ruleset (oficial) |
| T1204.003 | [MS Graph message: Indicators that the system is infected with malware have been detected.](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=wazuh-ruleset-oficial%3A%3Awazuh-99591) | Wazuh | Wazuh ruleset (oficial) |
| T1219 | [Renamed Visual Studio Code Tunnel Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A2cf29f11-e356-4f61-98c0-1bdb9393d6da) | Sigma | SigmaHQ |
| T1219 | [Hijack Legit RDP Session to Move Laterally](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A52753ea4-b3a0-4365-910d-36cff487b789) | Sigma | OpenSearch Security Analytics |
| T1222.002 | [File Permission Modification in Writable Directory](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A9f9a2a82-93a8-4b1a-8778-1780895626d4) | Elastic | Elastic detection-rules |
| T1222.002 | [Chmod Targeting Sensitive Directories](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A6419afd1-3742-47a5-a7e6-b50386cd15f8) | Sigma | SigmaHQ |
| T1496.001 | [Newly Observed Process Exhibiting High CPU Usage](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Af9de0949-94d8-441d-ae9a-8eb1e040acf2) | Elastic | Elastic detection-rules |
| T1496.001 | [Memory Swap Modification](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A5e4023e7-6357-4061-ae1c-9df33e78c674) | Elastic | Elastic detection-rules |
| T1518.001 | [Sysmon Discovery Via Default Driver Altitude Using Findstr.EXE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A37db85d1-b089-490a-a59a-c7b6f984f480) | Sigma | SigmaHQ |
| T1518.001 | [Local Firewall Rules Enumeration Via NetFirewallRule Cmdlet](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aea207a23-b441-4a17-9f76-ad5be47d51d3) | Sigma | SigmaHQ |
| T1543.002 | [LiteLLM / TeamPCP Supply Chain Attack Indicators](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A36603778-030c-43c4-8cbb-cd3c1d1a80c7) | Sigma | SigmaHQ |
| T1543.002 | [TeamPCP LiteLLM Supply Chain Attack Persistence Indicators](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A81c0b7f5-81c9-435e-a291-bc32fc2b72cd) | Sigma | SigmaHQ |
| T1543.003 | [PSExec Lateral Movement](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=hayabusa-native%3A%3A0694c340-3a46-40ac-acfc-c3444ae6572c) | Sigma | Hayabusa (native) |
| T1543.003 | [Suspicious Service Name](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=hayabusa-native%3A%3Acc429813-21db-4019-b520-2f19648e1ef1) | Sigma | Hayabusa (native) |
| T1547.001 | [Potential Ryuk Ransomware Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac37510b8-2107-4b78-aa32-72f251e7a844) | Sigma | SigmaHQ |
| T1547.001 | [Ryuk Ransomware](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Ac37510b8-2107-4b78-aa32-72f251e7a844) | Sigma | OpenSearch Security Analytics |
| T1552.001 | [Potential Russian APT Credential Theft Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab83f5166-9237-4b5e-9cd4-7b5d52f4d8ee) | Sigma | SigmaHQ |
| T1552.001 | [Copy Passwd Or Shadow From TMP Path](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Afa4aaed5-4fe0-498d-bbc0-08e3346387ba) | Sigma | SigmaHQ |
| T1552.004 | [Cisco Crypto Commands](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1f978c6a-4415-47fb-aca5-736a44d7ca3d) | Sigma | SigmaHQ |
| T1552.004 | [DPAPI Backup Keys And Certificate Export Activity IOC](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A7892ec59-c5bb-496d-8968-e5d210ca3ac4) | Sigma | SigmaHQ |
| T1552.005 | [GKE Pod Exec Cloud Instance Metadata Access](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ac8bf56cc-c648-4f88-bb4f-9e504d0779d1) | Elastic | Elastic detection-rules |
| T1552.005 | [AWS EC2 Instance Console Login via Assumed Role](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ad1e5e410-3e34-412e-9b1f-dd500b3b55cd) | Elastic | Elastic detection-rules |
| T1583.001 | [AWS Route 53 Private Hosted Zone Associated With a VPC](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ae3c27562-709a-42bd-82f2-3ed926cced19) | Elastic | Elastic detection-rules |
| T1583.001 | [AWS SES Email Identity Verified Then Deleted](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A8e4bde35-125d-4eb3-9a2e-d7e77a053a08) | Elastic | Elastic detection-rules |
| T1587.001 | [Formbook Process Creation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A032f5fb3-d959-41a5-9263-4173c802dc2b) | Sigma | SigmaHQ |
| T1587.001 | [Uncommon File Created In Office Startup Folder](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aa10a2c40-2c4d-49f8-b557-1a946bc55d9d) | Sigma | SigmaHQ |
| T1595.001 | [Grixba Malware Reconnaissance Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aaf688c76-4ce4-4309-bfdd-e896f01acf27) | Sigma | SigmaHQ |
| T1595.001 | [Web Server Suspicious User Agent Requests](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Aa1b7ffa4-bf80-4bf1-86ad-c3f4dc718b35) | Elastic | Elastic detection-rules |
| T1595.002 | [DNS Query to External Service Interaction Domains](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aaff715fa-4dd5-497a-8db3-910bea555566) | Sigma | SigmaHQ |
| T1595.002 | [Web Server Potential SQL Injection Request](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A7f7a0ee1-7b6f-466a-85b4-110fb105f5e2) | Elastic | Elastic detection-rules |
| T1608.001 | [M365 OneDrive Malware File Upload](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Abba1b212-b85c-41c6-9b28-be0e5cdfc9b1) | Elastic | Elastic detection-rules |
| T1608.001 | [M365 SharePoint Malware File Detected](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A0e52157a-8e96-4a95-a6e3-5faae5081a74) | Elastic | Elastic detection-rules |
| T1609 | [Privileged Container Creation with Host Directory Mount](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ad1f310cb-5921-4d37-bbdf-cfdab7a6df9c) | Elastic | Elastic detection-rules |
| T1609 | [Potential Kubeletctl Execution Detected via Defend for Containers](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A2572f7e0-7647-4c68-a42b-d3b1973deaae) | Elastic | Elastic detection-rules |
| T1610 | [Privileged Container Creation with Host Directory Mount](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ad1f310cb-5921-4d37-bbdf-cfdab7a6df9c) | Elastic | Elastic detection-rules |
| T1610 | [Potential Privilege Escalation via Container Misconfiguration](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Aafe6b0eb-dd9d-4922-b08a-1910124d524d) | Elastic | Elastic detection-rules |
| T1611 | [Privileged Container Creation with Host Directory Mount](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ad1f310cb-5921-4d37-bbdf-cfdab7a6df9c) | Elastic | Elastic detection-rules |
| T1611 | [Potential Privilege Escalation via Container Misconfiguration](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Aafe6b0eb-dd9d-4922-b08a-1910124d524d) | Elastic | Elastic detection-rules |
| T1613 | [Kubectl Secrets Enumeration Across All Namespaces](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Aa87d49f0-24ae-4d6e-a0b4-5fd2f6188d6a) | Elastic | Elastic detection-rules |
| T1613 | [Potential Direct Kubelet Access via Process Arguments](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A6aa52f86-18f1-4a5a-a0ac-e2b5db8af589) | Elastic | Elastic detection-rules |
| T1685 | [Windows Defender Configuration Changes](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A801bd44f-ceed-4eb6-887c-11544633c0aa) | Sigma | SigmaHQ |
| T1685 | [Windows Defender Virus Scanning Feature Disabled](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A686c0b4b-9dd3-4847-9077-d6c1bbe36fcb) | Sigma | SigmaHQ |
| T1685.006 | [Syslog Clearing or Removal Via System Utilities](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A3fcc9b35-39e4-44c0-a2ad-9e82b6902b31) | Sigma | SigmaHQ |
| T1685.006 | [Linux Logs Clearing Attempts](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A80915f59-9b56-4616-9de0-fd0dea6c12fe) | Sigma | SigmaHQ |
| T1686 | [Disable System Firewall](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A53059bc0-1472-438b-956a-7508a94a91f0) | Sigma | SigmaHQ |
| T1686 | [Netsh RDP Port Opening](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A01aeb693-138d-49d2-9403-c4f52d7d3d62) | Sigma | OpenSearch Security Analytics |

## 9. Plano de emulação e validação

Use num laboratório isolado e autorizado para confirmar que as regras disparam. Os comandos estão nos repositórios oficiais.

| Tática | Técnica | Teste Atomic Red Team | Plataformas |
|---|---|---|---|
| Execution | [T1059.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md) | Mimikatz | windows |
| Execution | [T1059.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md) | Run BloodHound from local disk | windows |
| Execution | [T1059.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.003/T1059.003.md) | Create and Execute Batch Script | windows |
| Execution | [T1059.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.003/T1059.003.md) | Writes text to a file and displays it. | windows |
| Execution | [T1059.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.004/T1059.004.md) | Create and Execute Bash Shell Script | linux, macos |
| Execution | [T1059.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.004/T1059.004.md) | Command-Line Interface | linux, macos |
| Execution | [T1204.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1204.003/T1204.003.md) | Malicious Execution from Mounted ISO Image | windows |
| Execution | [T1609](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1609/T1609.md) | ExecIntoContainer | containers |
| Execution | [T1609](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1609/T1609.md) | Docker Exec Into Container | containers |
| Execution | [T1610](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1610/T1610.md) | Deploy Docker container | containers |
| Persistence | [T1098.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1098.004/T1098.004.md) | Modify SSH Authorized Keys | linux, macos |
| Persistence | [T1133](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1133/T1133.md) | Running Chrome VPN Extensions via the Registry 2 vpn extension | windows |
| Persistence | [T1136.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1136.001/T1136.001.md) | Create a user account on a Linux system | linux |
| Persistence | [T1136.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1136.001/T1136.001.md) | Create a user account on a FreeBSD system | linux |
| Persistence | [T1543.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1543.002/T1543.002.md) | Create Systemd Service | linux |
| Persistence | [T1543.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1543.002/T1543.002.md) | Create SysV Service | linux |
| Persistence | [T1543.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1543.003/T1543.003.md) | Modify Fax service to run PowerShell | windows |
| Persistence | [T1543.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1543.003/T1543.003.md) | Service Installation CMD | windows |
| Persistence | [T1547.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1547.001/T1547.001.md) | Reg Key Run | windows |
| Persistence | [T1547.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1547.001/T1547.001.md) | Reg Key RunOnce | windows |
| Privilege Escalation | [T1611](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1611/T1611.md) | Deploy container using nsenter container escape | containers |
| Privilege Escalation | [T1611](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1611/T1611.md) | Mount host filesystem to escape privileged Docker container | containers |
| Stealth | [T1014](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1014/T1014.md) | Loadable Kernel Module based Rootkit | linux |
| Stealth | [T1014](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1014/T1014.md) | Loadable Kernel Module based Rootkit | linux |
| Stealth | [T1027.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027.002/T1027.002.md) | Binary simply packed by UPX (linux) | linux |
| Stealth | [T1027.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027.002/T1027.002.md) | Binary packed by UPX, with modified headers (linux) | linux |
| Stealth | [T1027.013](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027.013/T1027.013.md) | Decode Eicar File and Write to File | linux, macos, windows |
| Stealth | [T1027.013](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027.013/T1027.013.md) | Decrypt Eicar File and Write to File | linux, macos, windows |
| Stealth | [T1036](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036/T1036.md) | System File Copied to Unusual Location | windows |
| Stealth | [T1036](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036/T1036.md) | Malware Masquerading and Execution from Zip File | windows |
| Stealth | [T1036.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.005/T1036.005.md) | Execute a process from a directory masquerading as the current parent directory | linux, macos |
| Stealth | [T1036.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.005/T1036.005.md) | Masquerade as a built-in system executable | windows |
| Stealth | [T1070.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.003/T1070.003.md) | Clear Bash history (rm) |  |
| Stealth | [T1070.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.003/T1070.003.md) | Clear Bash history (echo) |  |
| Stealth | [T1070.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.004/T1070.004.md) | Delete a single file - FreeBSD/Linux/macOS | linux, macos |
| Stealth | [T1070.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.004/T1070.004.md) | Delete an entire folder - FreeBSD/Linux/macOS | linux, macos |
| Stealth | [T1140](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1140/T1140.md) | Deobfuscate/Decode Files Or Information | windows |
| Stealth | [T1140](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1140/T1140.md) | Certutil Rename and Decode | windows |
| Defense Impairment | [T1222.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1222.002/T1222.002.md) | chmod - Change file or folder mode (numeric mode) | linux, macos |
| Defense Impairment | [T1222.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1222.002/T1222.002.md) | chmod - Change file or folder mode (symbolic mode) | linux, macos |
| Defense Impairment | [T1685](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1685/T1685.md) | Windows Disable LSA Protection | windows |
| Defense Impairment | [T1685](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1685/T1685.md) | Disable journal logging via systemctl utility | linux |
| Defense Impairment | [T1685.006](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1685.006/T1685.006.md) | rm -rf | linux, macos |
| Defense Impairment | [T1685.006](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1685.006/T1685.006.md) | rm -rf | linux |
| Defense Impairment | [T1686](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1686/T1686.md) | Disable Microsoft Defender Firewall | windows |
| Defense Impairment | [T1686](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1686/T1686.md) | Disable Microsoft Defender Firewall via Registry | windows |
| Credential Access | [T1552.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1552.001/T1552.001.md) | Find AWS credentials | linux, macos |
| Credential Access | [T1552.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1552.001/T1552.001.md) | Extract Browser and System credentials with LaZagne | macos |
| Credential Access | [T1552.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1552.004/T1552.004.md) | Private Keys | windows |
| Credential Access | [T1552.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1552.004/T1552.004.md) | Discover Private SSH Keys | linux, macos |
| Credential Access | [T1552.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1552.005/T1552.005.md) | Azure - Search Azure AD User Attributes for Passwords | azure-ad |
| Credential Access | [T1552.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1552.005/T1552.005.md) | Azure - Dump Azure Instance Metadata from Virtual Machines | iaas:azure |
| Discovery | [T1007](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1007/T1007.md) | System Service Discovery | windows |
| Discovery | [T1007](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1007/T1007.md) | System Service Discovery - net.exe | windows |
| Discovery | [T1016](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1016/T1016.md) | System Network Configuration Discovery on Windows | windows |
| Discovery | [T1016](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1016/T1016.md) | List Windows Firewall Rules | windows |
| Discovery | [T1046](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1046/T1046.md) | Port Scan | linux, macos |
| Discovery | [T1046](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1046/T1046.md) | Port Scan Nmap | linux, macos |
| Discovery | [T1049](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1049/T1049.md) | System Network Connections Discovery | windows |
| Discovery | [T1049](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1049/T1049.md) | System Network Connections Discovery with PowerShell | windows |
| Discovery | [T1057](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1057/T1057.md) | Process Discovery - ps | linux, macos |
| Discovery | [T1057](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1057/T1057.md) | Process Discovery - tasklist | windows |
| Discovery | [T1082](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1082/T1082.md) | System Information Discovery | windows |
| Discovery | [T1082](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1082/T1082.md) | System Information Discovery | macos |
| Discovery | [T1083](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1083/T1083.md) | File and Directory Discovery (cmd.exe) | windows |
| Discovery | [T1083](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1083/T1083.md) | File and Directory Discovery (PowerShell) | windows |
| Discovery | [T1120](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1120/T1120.md) | Win32_PnPEntity Hardware Inventory | windows |
| Discovery | [T1120](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1120/T1120.md) | WinPwn - printercheck | windows |
| Discovery | [T1518.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1518.001/T1518.001.md) | Security Software Discovery | windows |
| Discovery | [T1518.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1518.001/T1518.001.md) | Security Software Discovery - powershell | windows |
| Discovery | [T1613](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1613/T1613.md) | Docker Container and Resource Discovery | containers |
| Discovery | [T1613](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1613/T1613.md) | Podman Container and Resource Discovery | containers |
| Lateral Movement | [T1021.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.004/T1021.004.md) | ESXi - Enable SSH via PowerCLI | windows |
| Lateral Movement | [T1021.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.004/T1021.004.md) | ESXi - Enable SSH via VIM-CMD | windows |
| Collection | [T1074.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1074.001/T1074.001.md) | Stage data from Discovery.bat | windows |
| Collection | [T1074.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1074.001/T1074.001.md) | Stage data from Discovery.sh | linux, macos |
| Command and Control | [T1071](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1071/T1071.md) | Telnet C2 | windows |
| Command and Control | [T1071.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1071.001/T1071.001.md) | Malicious User Agents - Powershell | windows |
| Command and Control | [T1071.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1071.001/T1071.001.md) | Malicious User Agents - CMD | windows |
| Command and Control | [T1105](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1105/T1105.md) | rsync remote file copy (push) | linux, macos |
| Command and Control | [T1105](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1105/T1105.md) | rsync remote file copy (pull) | linux, macos |
| Command and Control | [T1219](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1219/T1219.md) | TeamViewer Files Detected Test on Windows | windows |
| Command and Control | [T1219](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1219/T1219.md) | AnyDesk Files Detected Test on Windows | windows |
| Exfiltration | [T1048](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1048/T1048.md) | Exfiltration Over Alternative Protocol - SSH | linux, macos |
| Exfiltration | [T1048](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1048/T1048.md) | Exfiltration Over Alternative Protocol - SSH | linux, macos |

**Logs reais de ataque (EVTX) para testar sem executar nada:**

- T1016 — [ID4688-Audit policy enumerated](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1016-System%20Network%20Configuration%20Discovery/ID4688-Audit%20policy%20enumerated.evtx) _(explícito)_
- T1016 — [ID4688-Firewall configuration enumerated (command)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1016-System%20Network%20Configuration%20Discovery/ID4688-Firewall%20configuration%20enumerated%20%28command%29.evtx) _(explícito)_
- T1021.004 — [ID4-OpenSSH server listening](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0008-Lateral%20Movement/T1021.004-Remote%20Service%20SSH/ID4-OpenSSH%20server%20listening.evtx) _(explícito)_
- T1021.004 — [ID4103-4104-OpenSSH server activation and config](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0008-Lateral%20Movement/T1021.004-Remote%20Service%20SSH/ID4103-4104-OpenSSH%20server%20activation%20and%20config.evtx) _(explícito)_
- T1036 — [rundll32_hollowing_wermgr_masquerading](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/AutomatedTestingTools/Malware/rundll32_hollowing_wermgr_masquerading.evtx) _(inferido)_
- T1046 — [ID131-RDP brutforce (no user info)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1046-Network%20Service%20Scanning/ID131-RDP%20brutforce%20%28no%20user%20info%29.evtx) _(explícito)_
- T1046 — [ID4624-Anonymous login with domain specified (DonPapi)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1046-Network%20Service%20Scanning/ID4624-Anonymous%20login%20with%20domain%20specified%20%28DonPapi%29.evtx) _(explícito)_
- T1059.001 — [ID4103-4104-Payload download via PowerShell](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1059.001-PowerShell/ID4103-4104-Payload%20download%20via%20PowerShell.evtx) _(explícito)_
- T1059.001 — [ID4688-Encoded PowerShell MSF payload via process execution](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1059.001-PowerShell/ID4688-Encoded%20PowerShell%20MSF%20payload%20via%20process%20execution.evtx) _(explícito)_
- T1059.003 — [ID4688-SQL Server payload injectection for reverse shell (MSF)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1059.003-Windows%20Command%20Shell/ID4688-SQL%20Server%20payload%20injectection%20for%20reverse%20shell%20%28MSF%29.evtx) _(explícito)_
- T1140 — [ID4688-Certutil download](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0005-Defense%20Evasion/T1140-Deobfuscate-Decode%20Files%20or%20Information/ID4688-Certutil%20download.evtx) _(explícito)_
- T1543.003 — [ID13-New service for Mimikatz](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0003-Persistence/T1543.003-Create%20or%20Modify%20System%20Process-Windows%20Service/ID13-New%20service%20for%20Mimikatz.evtx) _(explícito)_
- T1543.003 — [ID4688-4697 RDP hijack via service creation](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0003-Persistence/T1543.003-Create%20or%20Modify%20System%20Process-Windows%20Service/ID4688-4697%20RDP%20hijack%20via%20service%20creation.evtx) _(explícito)_
- T1547.001 — [sideloading_injection_persistence_run_key](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/AutomatedTestingTools/Malware/sideloading_injection_persistence_run_key.evtx) _(inferido)_
- T1547.001 — [evasion_persis_hidden_run_keyvalue_sysmon_13](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Persistence/evasion_persis_hidden_run_keyvalue_sysmon_13.evtx) _(inferido)_
- T1552.004 — [ID70-CAPI-Private key accessed Mimikatz](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0006-Credential%20Access/T1552.004-Unsecured%20Credentials-Private%20Keys/ID70-CAPI-Private%20key%20accessed%20Mimikatz.evtx) _(explícito)_
- T1685 — [ID1-SYSMON driver unload (FilterManager)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0005-Defense%20Evasion/T1562.001-Impair%20Defenses-Disable%20or%20Modify%20tool/ID1-SYSMON%20driver%20unload%20%28FilterManager%29.evtx) _(explícito)_
- T1685 — [ID13-Defender service configuration disabled](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0005-Defense%20Evasion/T1562.001-Impair%20Defenses-Disable%20or%20Modify%20tool/ID13-Defender%20service%20configuration%20disabled.evtx) _(explícito)_
- T1686 — [ID2003-4950-Firewall disabled](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0005-Defense%20Evasion/T1562.004-Impair%20Defenses-Disable%20or%20Modify%20System%20Firewall/ID2003-4950-Firewall%20disabled.evtx) _(explícito)_
- T1686 — [ID2004-Any any firewall rule created](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0005-Defense%20Evasion/T1562.004-Impair%20Defenses-Disable%20or%20Modify%20System%20Firewall/ID2004-Any%20any%20firewall%20rule%20created.evtx) _(explícito)_

## 10. Hipóteses de hunting

Se TeamTNT estiver no seu ambiente, estas são as perguntas a fazer aos seus dados (fontes de log segundo as estratégias de detecção do MITRE ATT&CK).

1. **T1204.003 Malicious Image** — CONTAINERS (Docker/K8s/containerd): A user pulls an untrusted image from a public/unknown registry and then creates/starts a container from that image. Shortly after start, the container spawns unexpected utilities (e.g., curl/wget/bash/python), or makes… Dados: `containerd:events` (Image pull from untrusted registry (name NOT IN allowlist) or new digest never seen before), `kubernetes:audit` (create: Pod/Container created with image tag 'latest' or mutable tag; imagePullPolicy=Always; noDigest=true), `kubernetes:events` (start: ContainerStarted or Pulling image → Started container).
2. **T1552.005 Cloud Instance Metadata API** — Detects access attempts to cloud instance metadata endpoints (e.g., 169.254.169.254) from virtual machines or containerized workloads. This includes both direct access and SSRF exploitation patterns. Dados: `AWS:VPCFlowLogs` (Outbound connection to 169.254.169.254 from EC2 workload), `AWS:CloudTrail` (GetInstanceIdentityDocument), `ebpf:syscalls` (Process within container accesses link-local address 169.254.169.254).
3. **T1569.003 Systemctl** — Abuse of systemctl to execute commands or manage systemd services. Defender perspective: correlate suspicious service creation or modification with execution of systemctl subcommands such as start, enable, or status. Detect cases where systemctl is used to… Dados: `auditd:EXECVE` (execution of systemctl with subcommands start, stop, enable, disable), `auditd:SYSCALL` (open/write of .service unit files), `auditd:EXECVE` (systemctl spawning managed processes).
4. **T1609 Container Administration Command** — Defenders may detect abuse of container administration commands by observing anomalous use of management utilities (`docker exec`, `kubectl exec`, or API calls to kubelet) correlated with unexpected process creation inside containers. Behavioral chains… Dados: `docker:daemon` (docker exec or docker run with unexpected command/entrypoint), `kubernetes:apiserver` (kubectl exec or kubelet API calls targeting running pods).
5. **T1611 Escape to Host** — Detection of container escape attempts via bind mounts, privileged containers, or abuse of docker.sock. Defenders may observe anomalous volume mount configurations (e.g., hostPath to / or /proc), unexpected privileged container launches, or use of container… Dados: `docker:daemon` (container create/start with privileged flag or host volume mount), `kubernetes:apiserver` (Pod spec with hostPath or privileged securityContext).
6. **T1613 Container and Resource Discovery** — Detection of adversary attempts to enumerate containers, pods, nodes, and related resources within containerized environments. Defenders may observe anomalous API calls to Docker or Kubernetes (e.g., 'docker ps', 'kubectl get pods', 'kubectl get nodes'),… Dados: `kubernetes:apiserver` (list or get requests against pods, deployments, or nodes), `docker:daemon` (docker ps, docker inspect, or docker images commands).
7. **T1048 Exfiltration Over Alternative Protocol** — Detects unusual outbound file transfer behavior using protocols like FTP, SMB, SMTP, or DNS, involving non-standard processes, off-hour activity, or uncommonly high volume. Dados: `WinEventLog:Sysmon` (EventCode=3, 22), `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Security` (EventCode=4688).
8. **T1595.001 Scanning IP Blocks** — Monitoring the content of network traffic can help detect patterns associated with active scanning activities. This can include identifying repeated connection attempts, unusual scanning behaviors, or probing activity targeting multiple IP addresses across a… Dados: `Network Traffic` (None), `Network Traffic` (None).
9. **T1059.013 Container CLI/API** — Execution of container orchestration commands (e.g., `docker exec`, `kubectl exec`) or API-driven interactions with running containers from unauthorized hosts or non-standard user contexts. Defender sees programmatic or interactive command execution within… Dados: `auditd:SYSCALL` (execve: Execution of container management CLIs (docker, crictl, kubectl) or interpreted shells (sh, bash, python) within container context), `docker:events` (exec_create: docker exec events targeting running containers from non-CI sources), `kubernetes:apiserver` (create/exec: Kubernetes API calls to exec into containers or create pods from curl, kubectl, or SDK clients).
10. **T1098.004 SSH Authorized Keys** — Adversary attempts to gain persistence by modifying ~/.ssh/authorized_keys via shell, text editor, echo or redirected output. Dados: `auditd:SYSCALL` (write | PATH=/home/*/.ssh/authorized_keys), `auditd:SYSCALL` (execve).
11. **T1610 Deploy Container** — Remote/API driven creation **and** start of a container whose image is not on an allow‑list (or is tagged `latest`), executed by a non-admin principal, and/or started with risky runtime attributes (e.g., `--privileged`, host PID/NET namespaces, sensitive host… Dados: `docker:daemon` (container_create,container_start), `containerd:runtime` (CRI CreateContainer/StartContainer with privileged=true OR added capabilities OR host* namespaces), `ebpf:syscalls` (process execution or network connect from just-created container PID namespace).
12. **T1059.009 Cloud API** — Detects adversarial use of cloud APIs for command execution, resource control, or reconnaissance. Focuses on CLI/SDK/scripting language abuse via stolen credentials or in-browser Cloud Shells. Monitors for anomalous API calls chained with authentication… Dados: `AWS:CloudTrail` (eventName: RunInstances, CreateUser, PutRolePolicy, InvokeCommand), `azure:activity` (operationName: Write, Access Review, RoleAssignment), `Okta:SystemLog` (eventType: user.authentication.sso, app.oauth2.token.grant).

## 11. OSINT — onde pesquisar

Consultas prontas com todos os nomes conhecidos do grupo:

- Relatórios técnicos: [busca web](https://duckduckgo.com/?q=%28%22TeamTNT%22%29+threat+report) · [PDFs](https://duckduckgo.com/?q=%28%22TeamTNT%22%29+filetype%3Apdf)
- Regras e IOCs publicados: [GitHub](https://github.com/search?type=code&q=%22TeamTNT%22)
- Pulsos de ameaça: [AlienVault OTX](https://otx.alienvault.com/browse/global/pulses?q=TeamTNT)
- Família de malware e atores: [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/actors) (busque por TeamTNT)
- Cartões de grupo: [ThaiCERT Threat Group Cards](https://apt.etda.or.th/cgi-bin/listgroups.cgi)
- Página oficial: [MITRE ATT&CK G0139](https://attack.mitre.org/groups/G0139/)

**Relatórios na coleção CyberMonitor** (ligados pelo nome do grupo, conferir antes de citar):

- 2020 — [TeamTNT activity targets Weave Scope deployments - Microsoft Tech Community - 1645968](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2020/2020.09.08.TeamTNT_Weave-Scope/TeamTNT%20activity%20targets%20Weave%20Scope%20deployments%20-%20Microsoft%20Tech%20Community%20-%201645968.pdf) _(via “TeamTNT”)_
- 2021 — [Hildegard_ New TeamTNT Malware Targeting Kubernetes](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2021/2021.02.03.Hildegard/Hildegard_%20New%20TeamTNT%20Malware%20Targeting%20Kubernetes.pdf) _(via “TeamTNT”)_
- 2021 — [wp-tracking-the-activities-of-teamTNT](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2021/2021.07.20.Tracking.TeamTNT/wp-tracking-the-activities-of-teamTNT.pdf) _(via “TeamTNT”)_

## 12. Bibliografia (13 fontes citadas pelo ATT&CK)

- [Aqua TeamTNT August 2020](https://blog.aquasec.com/container-security-tnt-container-attack) — Kol, Roi. Morag, A. (2020, August 25). Deep Analysis of TeamTNT Techniques Using Container Images to Attack. Retrieved September 22, 2021.
- [ATT TeamTNT Chimaera September 2020](https://cybersecurity.att.com/blogs/labs-research/teamtnt-with-new-campaign-aka-chimaera) — AT&T Alien Labs. (2021, September 8). TeamTNT with new campaign aka Chimaera. Retrieved September 22, 2021.
- [Cado Security TeamTNT Worm August 2020](https://www.cadosecurity.com/team-tnt-the-first-crypto-mining-worm-to-steal-aws-credentials/) — Cado Security. (2020, August 16). Team TNT – The First Crypto-Mining Worm to Steal AWS Credentials. Retrieved September 22, 2021.
- [Cisco Talos Blog](https://blog.talosintelligence.com/teamtnt-targeting-aws-alibaba-2/) — Jaeson Schultz, Darin Smith. (2022, April 21). TeamTNT Targeting AWS, Alibaba. Retrieved June 15, 2025.
- [Cisco Talos Intelligence Group](https://blog.talosintelligence.com/teamtnt-targeting-aws-alibaba-2/) — Darin Smith. (2022, April 21). TeamTNT targeting AWS, Alibaba. Retrieved August 4, 2022.
- [Intezer TeamTNT Explosion September 2021](https://www.intezer.com/wp-content/uploads/2021/09/TeamTNT-Cryptomining-Explosion.pdf) — Intezer. (2021, September 1). TeamTNT Cryptomining Explosion. Retrieved October 15, 2021.
- [Intezer TeamTNT September 2020](https://www.intezer.com/blog/cloud-security/attackers-abusing-legitimate-cloud-monitoring-tools-to-conduct-cyber-attacks/) — Fishbein, N. (2020, September 8). Attackers Abusing Legitimate Cloud Monitoring Tools to Conduct Cyber Attacks. Retrieved September 22, 2021.
- [Lacework TeamTNT May 2021](https://www.lacework.com/blog/taking-teamtnt-docker-images-offline) — Stroud, J. (2021, May 25). Taking TeamTNT's Docker Images Offline. Retrieved September 16, 2024.
- [Palo Alto Black-T October 2020](https://unit42.paloaltonetworks.com/black-t-cryptojacking-variant/) — Quist, N. (2020, October 5). Black-T: New Cryptojacking Variant from TeamTNT. Retrieved September 22, 2021.
- [Talos TeamTNT](https://blog.talosintelligence.com/2022/04/teamtnt-targeting-aws-alibaba.html) — Darin Smith. (2022, April 21). TeamTNT targeting AWS, Alibaba. Retrieved July 8, 2022.
- [TeamTNT Cloud Enumeration](https://unit42.paloaltonetworks.com/teamtnt-operations-cloud-environments) — Nathaniel Quist. (2021, June 4). TeamTNT Actively Enumerating Cloud Environments to Infiltrate Organizations. Retrieved February 8, 2022.
- [Trend Micro TeamTNT](https://documents.trendmicro.com/assets/white_papers/wp-tracking-the-activities-of-teamTNT.pdf) — Fiser, D. Oliveira, A. (n.d.). Tracking the Activities of TeamTNT A Closer Look at a Cloud-Focused Malicious Actor Group. Retrieved September 22, 2021.
- [Unit 42 Hildegard Malware](https://unit42.paloaltonetworks.com/hildegard-malware-teamtnt/) — Chen, J. et al. (2021, February 3). Hildegard: New TeamTNT Cryptojacking Malware Targeting Kubernetes. Retrieved April 5, 2021.

## 13. Limites e confiança

- O ATT&CK registra o que foi **relatado publicamente**, não tudo o que o grupo faz. Ausência de uma técnica não prova que o grupo não a usa.
- **Sobreposição de TTP não é atribuição.** Muitas técnicas são compartilhadas entre grupos e com red teams. Use a assinatura comportamental como hipótese, junto com infraestrutura, malware e contexto.
- Cobertura de detecção refere-se ao catálogo público Detection Rules, não ao seu ambiente: confira se a telemetria necessária chega ao seu SIEM.
- Ligações marcadas como _inferidas_ (EVTX por palavra-chave, relatórios por nome) devem ser verificadas.

---
Fontes: MITRE ATT&CK® (uso livre com atribuição, © The MITRE Corporation), APT4ALL (MISP Galaxy CC0/BSD-2, APT Groups & Operations CC BY 4.0, EternalLiberty, APTnotes, Ransomware Tool Matrix CC BY 4.0), Atomic Red Team (Red Canary, MIT), EVTX-to-MITRE-Attack, EVTX-ATTACK-SAMPLES, APT & CyberCriminal Campaign Collections. Gerado por [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules).
