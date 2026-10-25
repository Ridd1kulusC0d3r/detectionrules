# Rocke (G0106) — Dossiê de inteligência

> **TLP:CLEAR** · gerado em 2026-10-25 a partir de fontes abertas · MITRE ATT&CK v20.0 · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0106) · [ATT&CK](https://attack.mitre.org/groups/G0106/)

**Também conhecido como:** —  
**Registro no ATT&CK:** criado em 2020-05-26, atualizado em 2026-07-31 · referências de 2018 a 2019

## 1. Sumário executivo

- **36 técnicas** atribuídas publicamente, concentradas em **Stealth, Command and Control, Discovery**.
- **Arsenal:** 0 malware e 0 ferramentas.
- **Campanhas atribuídas:** 0.
- **Cobertura de detecção pública:** 100% das técnicas têm ao menos uma regra no catálogo; **0 técnicas sem nenhuma regra pública**.
- **Assinatura comportamental** (técnicas raras entre os 178 grupos, as mais úteis para atribuição): T1055.002 Portable Executable Injection, T1053.003 Cron, T1574.006 Dynamic Linker Hijacking, T1027.004 Compile After Delivery, T1037 Boot or Logon Initialization Scripts.

## 2. Quem é

> Rocke is an alleged Chinese-speaking adversary whose primary objective appeared to be cryptojacking, or stealing victim system resources for the purposes of mining cryptocurrency. The name Rocke comes from the email address "rocke@live.cn" used to create the wallet which held collected cryptocurrency. Researchers have detected overlaps between Rocke and the Iron Cybercrime Group, though this attribution has not been confirmed.

_Texto original do MITRE ATT&CK, em inglês._

## 3. Perfil TTP por tática (kill chain)

Cada linha: técnica, como o grupo a usou segundo relatos públicos, e o que existe para detectar e testar.

### Initial Access (TA0001) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1190](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1190) Exploit Public-Facing Application | Rocke exploited Apache Struts, Oracle WebLogic (CVE-2017-10271), and Adobe ColdFusion (CVE-2017-3066) vulnerabilities to deliver malware. | 580 | — | — |

### Execution (TA0002) — 4

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1053.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1053.003) Cron | Rocke installed a cron job that downloaded and executed files from the C2. | 48 | 4 | — |
| [T1059.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.004) Unix Shell | Rocke used shell scripts to run commands which would obtain persistence and execute the cryptocurrency mining malware. | 395 | 17 | — |
| [T1059.006](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.006) Python | Rocke has used Python-based malware to install and spread their coinminer. | 122 | — | — |
| [T1574.006](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1574.006) Dynamic Linker Hijacking | Rocke has modified /etc/ld.so.preload to hook libc functions in order to hide the installed dropper and mining software in process lists. | 29 | 3 | — |

### Persistence (TA0003) — 4

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1037](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1037) Boot or Logon Initialization Scripts | Rocke has installed an "init.d" startup script to maintain persistence. | 60 | — | — |
| [T1053.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1053.003) Cron | Rocke installed a cron job that downloaded and executed files from the C2. | 48 | 4 | — |
| [T1543.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1543.002) Systemd Service | Rocke has installed a systemd service script to maintain persistence. | 23 | 4 | — |
| [T1547.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1547.001) Registry Run Keys / Startup Folder | Rocke's miner has created UPX-packed files in the Windows Start Menu Folder. | 299 | 21 | 2 |

### Privilege Escalation (TA0004) — 5

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1037](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1037) Boot or Logon Initialization Scripts | Rocke has installed an "init.d" startup script to maintain persistence. | 60 | — | — |
| [T1053.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1053.003) Cron | Rocke installed a cron job that downloaded and executed files from the C2. | 48 | 4 | — |
| [T1055.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1055.002) Portable Executable Injection | Rocke's miner, "TermsHost.exe", evaded defenses by injecting itself into Windows processes, including Notepad.exe. | 3 | 1 | — |
| [T1543.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1543.002) Systemd Service | Rocke has installed a systemd service script to maintain persistence. | 23 | 4 | — |
| [T1547.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1547.001) Registry Run Keys / Startup Folder | Rocke's miner has created UPX-packed files in the Windows Start Menu Folder. | 299 | 21 | 2 |

### Stealth (TA0005) — 11

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1014](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1014) Rootkit | Rocke has modified /etc/ld.so.preload to hook libc functions in order to hide the installed dropper and mining software in process lists. | 44 | 4 | — |
| [T1027](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1027) Obfuscated Files or Information | Rocke has modified UPX headers after packing files to break unpackers. | 520 | 11 | 5 |
| [T1027.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1027.002) Software Packing | Rocke's miner has created UPX-packed files in the Windows Start Menu Folder. | 12 | 4 | — |
| [T1027.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1027.004) Compile After Delivery | Rocke has compiled malware, delivered to victims as .c files, with the GNU Compiler Collection (GCC). | 32 | 5 | — |
| [T1036.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1036.005) Match Legitimate Resource Name or Location | Rocke has used shell scripts which download mining executables and saves them with the filename "java". | 116 | 4 | — |
| [T1055.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1055.002) Portable Executable Injection | Rocke's miner, "TermsHost.exe", evaded defenses by injecting itself into Windows processes, including Notepad.exe. | 3 | 1 | — |
| [T1070.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1070.004) File Deletion | Rocke has deleted files on infected machines. | 132 | 11 | — |
| [T1070.006](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1070.006) Timestomp | Rocke has changed the time stamp of certain files. | 28 | 10 | 3 |
| [T1140](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1140) Deobfuscate/Decode Files or Information | Rocke has extracted tar.gz files after downloading them from a C2 server. | 173 | 11 | 1 |
| [T1564.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1564.001) Hidden Files and Directories | Rocke downloaded a file "libprocesshider", which could hide files on the target system. | 76 | 10 | — |
| [T1574.006](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1574.006) Dynamic Linker Hijacking | Rocke has modified /etc/ld.so.preload to hook libc functions in order to hide the installed dropper and mining software in process lists. | 29 | 3 | — |

### Defense Impairment (TA0112) — 4

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1222.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1222.002) Linux and Mac Permissions | Rocke has changed file permissions of files so they could not be modified. | 34 | 14 | — |
| [T1685](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1685) Disable or Modify Tools | Rocke used scripts which detected and uninstalled antivirus software. | 1275 | 78 | 19 |
| [T1685.006](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1685.006) Clear Linux or Mac System Logs | Rocke has cleared log files within the /var/log/ folder. | 23 | 20 | — |
| [T1686](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1686) Disable or Modify System Firewall | Rocke used scripts which killed processes and added firewall rules to block traffic related to other cryptominers. | 56 | 25 | 6 |

### Credential Access (TA0006) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1552.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1552.004) Private Keys | Rocke has used SSH private keys on the infected machine to spread its coinminer throughout a network. | 60 | 17 | 1 |

### Discovery (TA0007) — 5

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1018](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1018) Remote System Discovery | Rocke has looked for IP addresses in the known_hosts file on the infected system and attempted to SSH into them. | 157 | 23 | 1 |
| [T1046](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1046) Network Service Discovery | Rocke conducted scanning for exposed TCP port 7001 as well as SSH and Redis servers. | 212 | 13 | 2 |
| [T1057](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1057) Process Discovery | Rocke can detect a running process's PID on the infected machine. | 82 | 10 | — |
| [T1082](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1082) System Information Discovery | Rocke has used uname -m to collect the name and information about the infected system's kernel. | 264 | 41 | — |
| [T1518.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1518.001) Security Software Discovery | Rocke used scripts which detected and uninstalled antivirus software. | 54 | 12 | — |

### Lateral Movement (TA0008) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1021.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1021.004) SSH | Rocke has spread its coinminer via SSH. | 60 | 2 | 3 |

### Command and Control (TA0011) — 6

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1071](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1071) Application Layer Protocol | Rocke issued wget requests from infected systems to the C2. | 511 | 1 | — |
| [T1071.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1071.001) Web Protocols | Rocke has executed wget and curl commands to Pastebin over the HTTPS protocol. | 228 | 3 | — |
| [T1102](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1102) Web Service | Rocke has used Pastebin, Gitee, and GitLab for Command and Control. | 98 | — | — |
| [T1102.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1102.001) Dead Drop Resolver | Rocke has used Pastebin to check the version of beaconing malware and redirect to another Pastebin hosting updated malware. | 18 | — | — |
| [T1105](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1105) Ingress Tool Transfer | Rocke used malware to download additional malicious files to the target system. | 644 | 39 | — |
| [T1571](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1571) Non-Standard Port | Rocke's miner connects to a C2 server using port 51640. | 163 | 2 | — |

### Impact (TA0040) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1496.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1496.001) Compute Hijacking | Rocke has distributed cryptomining malware. | 2 | — | — |

## 4. Assinatura comportamental

Técnicas que este grupo usa e que poucos dos 178 grupos do ATT&CK usam. Pesam mais numa atribuição por TTP: ver várias delas juntas é mais informativo do que ver técnicas comuns como PowerShell.

| Técnica | Outros grupos que usam | Peso (raridade) |
|---|---:|---:|
| T1055.002 Portable Executable Injection | 1 | 4.09 |
| T1053.003 Cron | 2 | 3.80 |
| T1574.006 Dynamic Linker Hijacking | 2 | 3.80 |
| T1027.004 Compile After Delivery | 3 | 3.58 |
| T1037 Boot or Logon Initialization Scripts | 3 | 3.58 |
| T1222.002 Linux and Mac Permissions | 3 | 3.58 |
| T1496.001 Compute Hijacking | 3 | 3.58 |
| T1543.002 Systemd Service | 3 | 3.58 |
| T1685.006 Clear Linux or Mac System Logs | 3 | 3.58 |
| T1014 Rootkit | 5 | 3.24 |

## 5. Arsenal

Nenhum software atribuído no ATT&CK.

## 6. Campanhas

Nenhuma campanha atribuída no ATT&CK.

## 7. Cobertura defensiva

**36 de 36 técnicas (100%)** têm ao menos uma regra pública no catálogo Detection Rules.

### Regras recomendadas por técnica

Melhor regra disponível por técnica (formato portável e maduro primeiro).

| Técnica | Regra | Formato | Fonte |
|---|---|---|---|
| T1014 | [Triple Cross eBPF Rootkit Install Commands](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A22236d75-d5a0-4287-bf06-c93b1770860f) | Sigma | SigmaHQ |
| T1014 | [Triple Cross eBPF Rootkit Install Commands](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A22236d75-d5a0-4287-bf06-c93b1770860f) | Sigma | OpenSearch Security Analytics |
| T1018 | [Chopper Webshell Process Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Afa3c117a-bc0d-416e-a31b-0c0e80653efb) | Sigma | SigmaHQ |
| T1018 | [Webshell Hacking Activity Patterns](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4ebc877f-4612-45cb-b3a5-8e3834db36c9) | Sigma | SigmaHQ |
| T1021.004 | [Potential THC Tool Downloaded](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A2ddc468e-b39b-4f5b-9825-f3dcb0e998ea) | Elastic | Elastic detection-rules |
| T1021.004 | [AWS EC2 CreateKeyPair by New Principal from Non-Cloud AS Organization](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ac8e4f1a2-9b3d-4c5e-a6f7-8b9c0d1e2f3a) | Elastic | Elastic detection-rules |
| T1027 | [Potential Emotet Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad02e8cf5-6099-48cf-9bfc-1eec2d0c7b18) | Sigma | SigmaHQ |
| T1027 | [Emotet Process Creation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Ad02e8cf5-6099-48cf-9bfc-1eec2d0c7b18) | Sigma | OpenSearch Security Analytics |
| T1027.002 | [Python Image Load By Non-Python Process](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acbb56d62-4060-40f7-9466-d8aaf3123f83) | Sigma | SigmaHQ |
| T1027.002 | [Python Py2Exe Image Load](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Acbb56d62-4060-40f7-9466-d8aaf3123f83) | Sigma | OpenSearch Security Analytics |
| T1027.004 | [Visual Basic Command Line Compiler Usage](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A7b10f171-7f04-47c7-9fa2-5be43c76e535) | Sigma | SigmaHQ |
| T1027.004 | [Csc.EXE Execution Form Potentially Suspicious Parent](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab730a276-6b63-41b8-bcf8-55930c8fc6ee) | Sigma | SigmaHQ |
| T1036.005 | [Exploit for CVE-2015-1641](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A7993792c-5ce2-4475-a3db-a3a5539827ef) | Sigma | SigmaHQ |
| T1036.005 | [Exploit for CVE-2015-1641](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A7993792c-5ce2-4475-a3db-a3a5539827ef) | Sigma | OpenSearch Security Analytics |
| T1037 | [GenAI Process Accessing Sensitive Files](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ac0136397-f82a-45e5-9b9f-a3651d77e21a) | Elastic | Elastic detection-rules |
| T1037 | [Process Spawned from Message-of-the-Day (MOTD)](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A4ec47004-b34a-42e6-8003-376a123ea447) | Elastic | Elastic detection-rules |
| T1046 | [HackTool - winPEAS Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A98b53e78-ebaf-46f8-be06-421aafd176d9) | Sigma | SigmaHQ |
| T1046 | [HackTool - WinPwn Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad557dc06-62e8-4468-a8e8-7984124908ce) | Sigma | SigmaHQ |
| T1053.003 | [Triple Cross eBPF Rootkit Default Persistence](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1a2ea919-d11d-4d1e-8535-06cda13be20f) | Sigma | SigmaHQ |
| T1053.003 | [Triple Cross eBPF Rootkit Default Persistence](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A1a2ea919-d11d-4d1e-8535-06cda13be20f) | Sigma | OpenSearch Security Analytics |
| T1055.002 | [Potential Process Injection via PowerShell](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A2e29e96a-b67c-455a-afe4-de6183431d0d) | Elastic | Elastic detection-rules |
| T1055.002 | [Suspicious .NET Reflection via PowerShell](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ae26f042e-c590-4e82-8e05-41e81bd822ad) | Elastic | Elastic detection-rules |
| T1057 | [Process Discovery](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4e2f5868-08d4-413d-899f-dc2f1508627b) | Sigma | SigmaHQ |
| T1057 | [HackTool - PCHunter Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Afca949cc-79ca-446e-8064-01aa7e52ece5) | Sigma | SigmaHQ |
| T1059.004 | [Shell Invocation via Env Command - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Abed978f8-7f3a-432b-82c5-9286a9b3031a) | Sigma | SigmaHQ |
| T1059.004 | [Suspicious Reverse Shell Command Line](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A738d9bcf-6999-4fdb-b4ac-3033037db8ab) | Sigma | SigmaHQ |
| T1059.006 | [Emotet Loader Execution Via .LNK File](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1f32d820-1d5c-43fe-8fe2-feef0c952eb7) | Sigma | SigmaHQ |
| T1059.006 | [Serpent Backdoor Payload Execution Via Scheduled Task](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad5eb7432-fda4-4bba-a37f-ffa74d9ed639) | Sigma | SigmaHQ |
| T1070.004 | [File Deletion](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A30aed7b6-d2c1-4eaf-9382-b6bc43e50c57) | Sigma | SigmaHQ |
| T1070.004 | [Prefetch File Deleted](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A0a1f9d29-6465-4776-b091-7f43b26e4c89) | Sigma | SigmaHQ |
| T1070.006 | [File Creation Date Changed to Another Year](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A558eebe5-f2ba-4104-b339-36f7902bcc1a) | Sigma | SigmaHQ |
| T1070.006 | [Touch Suspicious Service File](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A31545105-3444-4584-bebf-c466353230d2) | Sigma | SigmaHQ |
| T1071 | [GALLIUM IOCs](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A440a56bf-7873-4439-940a-1c8a671073c2) | Sigma | SigmaHQ |
| T1071 | [GALLIUM Artefacts - Builtin](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A3db10f25-2527-4b79-8d4b-471eb900ee29) | Sigma | SigmaHQ |
| T1071.001 | [Ursnif Malware Download URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aa36ce77e-30db-4ea0-8795-644d7af5dfb4) | Sigma | SigmaHQ |
| T1071.001 | [Ursnif Malware C2 URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A932ac737-33ca-4afd-9869-0d48b391fcc9) | Sigma | SigmaHQ |
| T1082 | [Potential GobRAT File Discovery Via Grep](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae34cfa0c-0a50-4210-9cb3-5632d08eb041) | Sigma | SigmaHQ |
| T1082 | [System Information Discovery](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A42df45e7-e6e9-43b5-8f26-bec5b39cc239) | Sigma | SigmaHQ |
| T1102 | [Communication To LocaltoNet Tunneling Service Initiated - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac4568f5d-131f-4e78-83d4-45b2da0ec4f1) | Sigma | SigmaHQ |
| T1102 | [Communication To Ngrok Tunneling Service - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A19bf6fdb-7721-4f3d-867f-53467f6a5db6) | Sigma | SigmaHQ |
| T1102.001 | [Raw Paste Service Access](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A5468045b-4fcc-4d1a-973c-c9c9578edacb) | Sigma | SigmaHQ |
| T1102.001 | [PwnDrp Access](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A2b1ee7e4-89b6-4739-b7bb-b811b6607e5e) | Sigma | SigmaHQ |
| T1105 | [Greenbug Espionage Group Indicators](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A3711eee4-a808-4849-8a14-faf733da3612) | Sigma | SigmaHQ |
| T1105 | [Pandemic Registry Key](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A47e0852a-cf81-4494-a8e6-31864f8c86ed) | Sigma | SigmaHQ |
| T1140 | [UNC4841 - SSL Certificate Exfiltration Via Openssl](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A60911c07-f989-4362-84af-c609828ef829) | Sigma | SigmaHQ |
| T1140 | [UNC4841 - Download Compressed Files From Temp.sh Using Wget](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A60d050c4-e253-4d9a-b673-5ac100cfddfb) | Sigma | SigmaHQ |
| T1190 | [OMIGOD HTTP No Authentication RCE - CVE-2021-38647](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aab6b1a39-a9ee-4ab4-b075-e83acf6e346b) | Sigma | SigmaHQ |
| T1190 | [Exploited CVE-2020-10189 Zoho ManageEngine](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A846b866e-2a57-46ee-8e16-85fa92759be7) | Sigma | OpenSearch Security Analytics |
| T1222.002 | [File Permission Modification in Writable Directory](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A9f9a2a82-93a8-4b1a-8778-1780895626d4) | Elastic | Elastic detection-rules |
| T1222.002 | [Chmod Targeting Sensitive Directories](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A6419afd1-3742-47a5-a7e6-b50386cd15f8) | Sigma | SigmaHQ |
| T1496.001 | [Newly Observed Process Exhibiting High CPU Usage](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Af9de0949-94d8-441d-ae9a-8eb1e040acf2) | Elastic | Elastic detection-rules |
| T1496.001 | [Memory Swap Modification](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A5e4023e7-6357-4061-ae1c-9df33e78c674) | Elastic | Elastic detection-rules |
| T1518.001 | [Sysmon Discovery Via Default Driver Altitude Using Findstr.EXE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A37db85d1-b089-490a-a59a-c7b6f984f480) | Sigma | SigmaHQ |
| T1518.001 | [Local Firewall Rules Enumeration Via NetFirewallRule Cmdlet](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aea207a23-b441-4a17-9f76-ad5be47d51d3) | Sigma | SigmaHQ |
| T1543.002 | [LiteLLM / TeamPCP Supply Chain Attack Indicators](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A36603778-030c-43c4-8cbb-cd3c1d1a80c7) | Sigma | SigmaHQ |
| T1543.002 | [TeamPCP LiteLLM Supply Chain Attack Persistence Indicators](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A81c0b7f5-81c9-435e-a291-bc32fc2b72cd) | Sigma | SigmaHQ |
| T1547.001 | [Potential Ryuk Ransomware Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac37510b8-2107-4b78-aa32-72f251e7a844) | Sigma | SigmaHQ |
| T1547.001 | [Ryuk Ransomware](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Ac37510b8-2107-4b78-aa32-72f251e7a844) | Sigma | OpenSearch Security Analytics |
| T1552.004 | [Cisco Crypto Commands](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1f978c6a-4415-47fb-aca5-736a44d7ca3d) | Sigma | SigmaHQ |
| T1552.004 | [DPAPI Backup Keys And Certificate Export Activity IOC](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A7892ec59-c5bb-496d-8968-e5d210ca3ac4) | Sigma | SigmaHQ |
| T1564.001 | [Set Suspicious Files as System Files Using Attrib.EXE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aefec536f-72e8-4656-8960-5e85d091345b) | Sigma | SigmaHQ |
| T1564.001 | [PowerShell Logging Disabled Via Registry Key Tampering](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Afecfd1a1-cc78-4313-a1ea-2ee2e8ec27a7) | Sigma | SigmaHQ |
| T1571 | [Potentially Suspicious Malware Callback Communication - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Adbfc7c98-04ab-4ab7-aa94-c74d22aa7376) | Sigma | SigmaHQ |
| T1571 | [Potentially Suspicious Malware Callback Communication](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4b89abaa-99fe-4232-afdd-8f9aa4d20382) | Sigma | SigmaHQ |
| T1574.006 | [Code Injection by ld.so Preload](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A7e3c4651-c347-40c4-b1d4-d48590fdf684) | Sigma | SigmaHQ |
| T1574.006 | [Modification of ld.so.preload](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4b3cb710-5e83-4715-8c45-8b2b5b3e5751) | Sigma | SigmaHQ |
| T1685 | [Windows Defender Configuration Changes](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A801bd44f-ceed-4eb6-887c-11544633c0aa) | Sigma | SigmaHQ |
| T1685 | [Windows Defender Virus Scanning Feature Disabled](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A686c0b4b-9dd3-4847-9077-d6c1bbe36fcb) | Sigma | SigmaHQ |
| T1685.006 | [Syslog Clearing or Removal Via System Utilities](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A3fcc9b35-39e4-44c0-a2ad-9e82b6902b31) | Sigma | SigmaHQ |
| T1685.006 | [Linux Logs Clearing Attempts](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A80915f59-9b56-4616-9de0-fd0dea6c12fe) | Sigma | SigmaHQ |
| T1686 | [Disable System Firewall](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A53059bc0-1472-438b-956a-7508a94a91f0) | Sigma | SigmaHQ |
| T1686 | [Netsh RDP Port Opening](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A01aeb693-138d-49d2-9403-c4f52d7d3d62) | Sigma | OpenSearch Security Analytics |

## 8. Plano de emulação e validação

Use num laboratório isolado e autorizado para confirmar que as regras disparam. Os comandos estão nos repositórios oficiais.

| Tática | Técnica | Teste Atomic Red Team | Plataformas |
|---|---|---|---|
| Execution | [T1053.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1053.003/T1053.003.md) | Cron - Replace crontab with referenced file | linux, macos |
| Execution | [T1053.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1053.003/T1053.003.md) | Cron - Add script to all cron subfolders | linux, macos |
| Execution | [T1059.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.004/T1059.004.md) | Create and Execute Bash Shell Script | linux, macos |
| Execution | [T1059.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.004/T1059.004.md) | Command-Line Interface | linux, macos |
| Persistence | [T1543.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1543.002/T1543.002.md) | Create Systemd Service | linux |
| Persistence | [T1543.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1543.002/T1543.002.md) | Create SysV Service | linux |
| Persistence | [T1547.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1547.001/T1547.001.md) | Reg Key Run | windows |
| Persistence | [T1547.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1547.001/T1547.001.md) | Reg Key RunOnce | windows |
| Stealth | [T1014](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1014/T1014.md) | Loadable Kernel Module based Rootkit | linux |
| Stealth | [T1014](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1014/T1014.md) | Loadable Kernel Module based Rootkit | linux |
| Stealth | [T1027](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027/T1027.md) | Decode base64 Data into Script | linux, macos |
| Stealth | [T1027](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027/T1027.md) | Execute base64-encoded PowerShell | windows |
| Stealth | [T1027.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027.002/T1027.002.md) | Binary simply packed by UPX (linux) | linux |
| Stealth | [T1027.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027.002/T1027.002.md) | Binary packed by UPX, with modified headers (linux) | linux |
| Stealth | [T1027.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027.004/T1027.004.md) | Compile After Delivery using csc.exe | windows |
| Stealth | [T1027.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027.004/T1027.004.md) | Dynamic C# Compile | windows |
| Stealth | [T1036.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.005/T1036.005.md) | Execute a process from a directory masquerading as the current parent directory | linux, macos |
| Stealth | [T1036.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.005/T1036.005.md) | Masquerade as a built-in system executable | windows |
| Stealth | [T1055.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1055.002/T1055.002.md) | Portable Executable Injection | windows |
| Stealth | [T1070.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.004/T1070.004.md) | Delete a single file - FreeBSD/Linux/macOS | linux, macos |
| Stealth | [T1070.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.004/T1070.004.md) | Delete an entire folder - FreeBSD/Linux/macOS | linux, macos |
| Stealth | [T1070.006](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.006/T1070.006.md) | Set a file's access timestamp | linux, macos |
| Stealth | [T1070.006](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.006/T1070.006.md) | Set a file's modification timestamp | linux, macos |
| Stealth | [T1140](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1140/T1140.md) | Deobfuscate/Decode Files Or Information | windows |
| Stealth | [T1140](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1140/T1140.md) | Certutil Rename and Decode | windows |
| Stealth | [T1564.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1564.001/T1564.001.md) | Create a hidden file in a hidden directory | linux, macos |
| Stealth | [T1564.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1564.001/T1564.001.md) | Mac Hidden file | macos |
| Stealth | [T1574.006](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1574.006/T1574.006.md) | Shared Library Injection via /etc/ld.so.preload | linux |
| Stealth | [T1574.006](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1574.006/T1574.006.md) | Shared Library Injection via LD_PRELOAD | linux |
| Defense Impairment | [T1222.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1222.002/T1222.002.md) | chmod - Change file or folder mode (numeric mode) | linux, macos |
| Defense Impairment | [T1222.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1222.002/T1222.002.md) | chmod - Change file or folder mode (symbolic mode) | linux, macos |
| Defense Impairment | [T1685](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1685/T1685.md) | Windows Disable LSA Protection | windows |
| Defense Impairment | [T1685](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1685/T1685.md) | Disable journal logging via systemctl utility | linux |
| Defense Impairment | [T1685.006](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1685.006/T1685.006.md) | rm -rf | linux, macos |
| Defense Impairment | [T1685.006](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1685.006/T1685.006.md) | rm -rf | linux |
| Defense Impairment | [T1686](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1686/T1686.md) | Disable Microsoft Defender Firewall | windows |
| Defense Impairment | [T1686](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1686/T1686.md) | Disable Microsoft Defender Firewall via Registry | windows |
| Credential Access | [T1552.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1552.004/T1552.004.md) | Private Keys | windows |
| Credential Access | [T1552.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1552.004/T1552.004.md) | Discover Private SSH Keys | linux, macos |
| Discovery | [T1018](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1018/T1018.md) | Remote System Discovery - net | windows |
| Discovery | [T1018](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1018/T1018.md) | Remote System Discovery - net group Domain Computers | windows |
| Discovery | [T1046](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1046/T1046.md) | Port Scan | linux, macos |
| Discovery | [T1046](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1046/T1046.md) | Port Scan Nmap | linux, macos |
| Discovery | [T1057](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1057/T1057.md) | Process Discovery - ps | linux, macos |
| Discovery | [T1057](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1057/T1057.md) | Process Discovery - tasklist | windows |
| Discovery | [T1082](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1082/T1082.md) | System Information Discovery | windows |
| Discovery | [T1082](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1082/T1082.md) | System Information Discovery | macos |
| Discovery | [T1518.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1518.001/T1518.001.md) | Security Software Discovery | windows |
| Discovery | [T1518.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1518.001/T1518.001.md) | Security Software Discovery - powershell | windows |
| Lateral Movement | [T1021.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.004/T1021.004.md) | ESXi - Enable SSH via PowerCLI | windows |
| Lateral Movement | [T1021.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.004/T1021.004.md) | ESXi - Enable SSH via VIM-CMD | windows |
| Command and Control | [T1071](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1071/T1071.md) | Telnet C2 | windows |
| Command and Control | [T1071.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1071.001/T1071.001.md) | Malicious User Agents - Powershell | windows |
| Command and Control | [T1071.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1071.001/T1071.001.md) | Malicious User Agents - CMD | windows |
| Command and Control | [T1105](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1105/T1105.md) | rsync remote file copy (push) | linux, macos |
| Command and Control | [T1105](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1105/T1105.md) | rsync remote file copy (pull) | linux, macos |
| Command and Control | [T1571](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1571/T1571.md) | Testing usage of uncommonly used port with PowerShell | windows |
| Command and Control | [T1571](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1571/T1571.md) | Testing usage of uncommonly used port | linux, macos |

**Logs reais de ataque (EVTX) para testar sem executar nada:**

- T1018 — [ID5145-DNS hosts files access via network share](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1018-Remote%20System%20Discovery/ID5145-DNS%20hosts%20files%20access%20via%20network%20share.evtx) _(explícito)_
- T1021.004 — [ID4-OpenSSH server listening](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0008-Lateral%20Movement/T1021.004-Remote%20Service%20SSH/ID4-OpenSSH%20server%20listening.evtx) _(explícito)_
- T1021.004 — [ID4103-4104-OpenSSH server activation and config](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0008-Lateral%20Movement/T1021.004-Remote%20Service%20SSH/ID4103-4104-OpenSSH%20server%20activation%20and%20config.evtx) _(explícito)_
- T1027 — [4624,4674,4688- CrackMap Exec SMB mimikatz](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0005-Defense%20Evasion/T1027-Obfuscated%20Files%20or%20Information/4624%2C4674%2C4688-%20CrackMap%20Exec%20SMB%20mimikatz.evtx) _(explícito)_
- T1027 — [ID1-CrackMapExec payload execution](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0005-Defense%20Evasion/T1027-Obfuscated%20Files%20or%20Information/ID1-CrackMapExec%20payload%20execution.evtx) _(explícito)_
- T1046 — [ID131-RDP brutforce (no user info)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1046-Network%20Service%20Scanning/ID131-RDP%20brutforce%20%28no%20user%20info%29.evtx) _(explícito)_
- T1046 — [ID4624-Anonymous login with domain specified (DonPapi)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1046-Network%20Service%20Scanning/ID4624-Anonymous%20login%20with%20domain%20specified%20%28DonPapi%29.evtx) _(explícito)_
- T1070.006 — [ID4616-system time changed](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0005-Defense%20Evasion/T1070.006-Timestomp/ID4616-system%20time%20changed.evtx) _(explícito)_
- T1070.006 — [DE_timestomp_and_dll_sideloading_and_RunPersist](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/AutomatedTestingTools/Malware/DE_timestomp_and_dll_sideloading_and_RunPersist.evtx) _(inferido)_
- T1140 — [ID4688-Certutil download](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0005-Defense%20Evasion/T1140-Deobfuscate-Decode%20Files%20or%20Information/ID4688-Certutil%20download.evtx) _(explícito)_
- T1547.001 — [sideloading_injection_persistence_run_key](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/AutomatedTestingTools/Malware/sideloading_injection_persistence_run_key.evtx) _(inferido)_
- T1547.001 — [evasion_persis_hidden_run_keyvalue_sysmon_13](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Persistence/evasion_persis_hidden_run_keyvalue_sysmon_13.evtx) _(inferido)_
- T1552.004 — [ID70-CAPI-Private key accessed Mimikatz](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0006-Credential%20Access/T1552.004-Unsecured%20Credentials-Private%20Keys/ID70-CAPI-Private%20key%20accessed%20Mimikatz.evtx) _(explícito)_
- T1685 — [ID1-SYSMON driver unload (FilterManager)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0005-Defense%20Evasion/T1562.001-Impair%20Defenses-Disable%20or%20Modify%20tool/ID1-SYSMON%20driver%20unload%20%28FilterManager%29.evtx) _(explícito)_
- T1685 — [ID13-Defender service configuration disabled](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0005-Defense%20Evasion/T1562.001-Impair%20Defenses-Disable%20or%20Modify%20tool/ID13-Defender%20service%20configuration%20disabled.evtx) _(explícito)_
- T1686 — [ID2003-4950-Firewall disabled](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0005-Defense%20Evasion/T1562.004-Impair%20Defenses-Disable%20or%20Modify%20System%20Firewall/ID2003-4950-Firewall%20disabled.evtx) _(explícito)_
- T1686 — [ID2004-Any any firewall rule created](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0005-Defense%20Evasion/T1562.004-Impair%20Defenses-Disable%20or%20Modify%20System%20Firewall/ID2004-Any%20any%20firewall%20rule%20created.evtx) _(explícito)_

## 9. Hipóteses de hunting

Se Rocke estiver no seu ambiente, estas são as perguntas a fazer aos seus dados (fontes de log segundo as estratégias de detecção do MITRE ATT&CK).

1. **T1055.002 Portable Executable Injection** — Detects PE injection through a behavioral sequence where one process opens (OpenProcess) a handle to another, allocates remote memory (VirtualAllocEx), writes a PE header (MZ) or shellcode (WriteProcessMemory), then initiates a new thread (CreateRemoteThread… Dados: `WinEventLog:Sysmon` (EventCode=10), `WinEventLog:Sysmon` (EventCode=8), `WinEventLog:Sysmon` (EventCode=1).
2. **T1053.003 Cron** — Detects creation or modification of crontab entries by non-root users or from abnormal parent processes, followed by the execution of uncommon binaries at scheduled intervals. Dados: `auditd:SYSCALL` (write), `auditd:SYSCALL` (execve).
3. **T1574.006 Dynamic Linker Hijacking** — Detection focuses on identifying abuse of LD_PRELOAD and related linker variables. Defender perspective: monitor unexpected setting or modification of LD_PRELOAD in shell initialization scripts or environment exports, file creation of suspicious shared… Dados: `auditd:SYSCALL` (execve with LD_PRELOAD or linker-related environment variables set), `auditd:PATH` (creation of .so files in non-standard directories (e.g., /tmp, /home/*)), `linux:osquery` (process environment variables containing LD_PRELOAD).
4. **T1027.004 Compile After Delivery** — Detects compilation activity using csc.exe, ilasm.exe, or msbuild.exe initiated by user-space processes outside typical development environments, followed by execution or network activity from newly written binaries. Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Sysmon` (EventCode=3, 22).
5. **T1037 Boot or Logon Initialization Scripts** — Monitoring modification and execution of user or system logon scripts such as in registry Run keys or startup folders. Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:Security` (EventCode=4657), `WinEventLog:TaskScheduler` (EventCode=106).
6. **T1222.002 Linux and Mac Permissions** — Linux permission escalation behavioral chain: (1) Process creation of permission modification utilities (chmod, chown, chgrp, setfacl) with suspicious parameters indicating privilege escalation intent, (2) System call analysis revealing direct file metadata… Dados: `auditd:SYSCALL` (syscall in (chmod, fchmod, fchmodat, chown, fchown, fchownat, lchown, setxattr, lsetxattr, fsetxattr, removexattr, lremovexattr, fremovexattr)), `auditd:PROCTITLE` (proctitle contains chmod, chown, chgrp, setfacl, or attr with suspicious parameters (777, 755, +x, -R)), `linux:osquery` (process execution events for permission modification utilities with command-line analysis).
7. **T1496.001 Compute Hijacking** — Sustained execution of resource-intensive processes (e.g., cryptocurrency miners), often launched via scheduled tasks, WMI, or PowerShell. These processes frequently establish persistent external connections and attempt to evade detection using masqueraded or… Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=3, 22), `WinEventLog:Security` (EventCode=4698).
8. **T1543.002 Systemd Service** — Detects the creation or modification of `.service` unit files in system/user-level directories, combined with execution of `systemctl`, `service`, or dynamically created drop-ins via systemd generators. Detects persistence by analyzing the `ExecStart` path,… Dados: `auditd:SYSCALL` (write, open, or rename to /etc/systemd/system/*.service), `auditd:SYSCALL` (modification of existing .service file), `auditd:SYSCALL` (execution of systemctl or service with enable/start parameters).
9. **T1685.006 Clear Linux or Mac System Logs** — Detects log-clearing behavior by correlating suspicious command execution targeting log files under /var/log/, anomalous deletions or truncations of system logs, and unusual child processes (e.g., shell pipelines or redirections). Dados: `auditd:SYSCALL` (execve), `auditd:SYSCALL` (PATH).
10. **T1014 Rootkit** — Unauthorized or anomalous loading of kernel-mode drivers or DLLs, concealed services, or abnormal modification of boot components indicative of rootkit activity. Dados: `WinEventLog:Sysmon` (EventCode=6), `WinEventLog:System` (EventCode=7045), `WinEventLog:Sysmon` (EventCode=11).
11. **T1071 Application Layer Protocol** — Detects suspicious usage of common application-layer protocols (e.g., HTTP, HTTPS, DNS, SMB) by abnormal processes, with high outbound byte counts or irregular ports, possibly indicating command and control or data exfiltration. Dados: `NSM:Flow` (http, dns, smb, ssl logs), `WinEventLog:Sysmon` (EventCode=3, 22).
12. **T1102.001 Dead Drop Resolver** — Detection of a process or script that accesses a common web service to retrieve content containing obfuscated indicators of a secondary C2 server (dead drop resolver behavior). Dados: `WinEventLog:Sysmon` (EventCode=3, 22), `etw:Microsoft-Windows-NDIS-PacketCapture` (TLS Handshake/Network Flow).

## 10. OSINT — onde pesquisar

Consultas prontas com todos os nomes conhecidos do grupo:

- Relatórios técnicos: [busca web](https://duckduckgo.com/?q=%28%22Rocke%22%29+threat+report) · [PDFs](https://duckduckgo.com/?q=%28%22Rocke%22%29+filetype%3Apdf)
- Regras e IOCs publicados: [GitHub](https://github.com/search?type=code&q=%22Rocke%22)
- Pulsos de ameaça: [AlienVault OTX](https://otx.alienvault.com/browse/global/pulses?q=Rocke)
- Família de malware e atores: [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/actors) (busque por Rocke)
- Cartões de grupo: [ThaiCERT Threat Group Cards](https://apt.etda.or.th/cgi-bin/listgroups.cgi)
- Página oficial: [MITRE ATT&CK G0106](https://attack.mitre.org/groups/G0106/)

**Relatórios na coleção CyberMonitor** (ligados pelo nome do grupo, conferir antes de citar):

- 2019 — [Malware Used by Rocke Group Evolves to Evade Detection by Cloud Security Products](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2019/2019.01.17.Rocke_Group/Malware%20Used%20by%20Rocke%20Group%20Evolves%20to%20Evade%20Detection%20by%20Cloud%20Security%20Products.pdf) _(via “Rocke”)_

## 11. Bibliografia (3 fontes citadas pelo ATT&CK)

- [Anomali Rocke March 2019](https://www.anomali.com/blog/rocke-evolves-its-arsenal-with-a-new-malware-family-written-in-golang) — Anomali Labs. (2019, March 15). Rocke Evolves Its Arsenal With a New Malware Family Written in Golang. Retrieved April 24, 2019.
- [Talos Rocke August 2018](https://blog.talosintelligence.com/2018/08/rocke-champion-of-monero-miners.html) — Liebenberg, D.. (2018, August 30). Rocke: The Champion of Monero Miners. Retrieved May 26, 2020.
- [Unit 42 Rocke January 2019](https://unit42.paloaltonetworks.com/malware-used-by-rocke-group-evolves-to-evade-detection-by-cloud-security-products/) — Xingyu, J.. (2019, January 17). Malware Used by Rocke Group Evolves to Evade Detection by Cloud Security Products. Retrieved May 26, 2020.

## 12. Limites e confiança

- O ATT&CK registra o que foi **relatado publicamente**, não tudo o que o grupo faz. Ausência de uma técnica não prova que o grupo não a usa.
- **Sobreposição de TTP não é atribuição.** Muitas técnicas são compartilhadas entre grupos e com red teams. Use a assinatura comportamental como hipótese, junto com infraestrutura, malware e contexto.
- Cobertura de detecção refere-se ao catálogo público Detection Rules, não ao seu ambiente: confira se a telemetria necessária chega ao seu SIEM.
- Ligações marcadas como _inferidas_ (EVTX por palavra-chave, relatórios por nome) devem ser verificadas.

---
Fontes: MITRE ATT&CK® (uso livre com atribuição, © The MITRE Corporation), Atomic Red Team (Red Canary, MIT), EVTX-to-MITRE-Attack, EVTX-ATTACK-SAMPLES, APT & CyberCriminal Campaign Collections. Gerado por [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules).
