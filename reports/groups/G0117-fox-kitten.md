# Fox Kitten (G0117) — Dossiê de inteligência

> **TLP:CLEAR** · gerado em 2026-10-25 a partir de fontes abertas · MITRE ATT&CK v20.0 · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0117) · [ATT&CK](https://attack.mitre.org/groups/G0117/)

**Também conhecido como:** UNC757, Parisite, Pioneer Kitten, RUBIDIUM, Lemon Sandstorm  
**Registro no ATT&CK:** criado em 2020-12-21, atualizado em 2026-07-31 · referências de 2020 a 2025

## 1. Sumário executivo

- **41 técnicas** atribuídas publicamente, concentradas em **Discovery, Credential Access, Collection**.
- **Arsenal:** 3 malware e 2 ferramentas (ex.: SystemBC, China Chopper, Pay2Key, ngrok, PsExec).
- **Campanhas atribuídas:** 0.
- **Cobertura de detecção pública:** 98% das técnicas têm ao menos uma regra no catálogo; **1 técnicas sem nenhuma regra pública**.
- **Assinatura comportamental** (técnicas raras entre os 178 grupos, as mais úteis para atribuição): T1021.005 VNC, T1213.005 Messaging Applications, T1530 Data from Cloud Storage, T1546.008 Accessibility Features, T1585 Establish Accounts.

## 2. Quem é

> Fox Kitten is threat actor with a suspected nexus to the Iranian government that has been active since at least 2017 against entities in the Middle East, North Africa, Europe, Australia, and North America. Fox Kitten has targeted multiple industrial verticals including oil and gas, technology, government, defense, healthcare, manufacturing, and engineering.

_Texto original do MITRE ATT&CK, em inglês._

## 3. Perfil TTP por tática (kill chain)

Cada linha: técnica, como o grupo a usou segundo relatos públicos, e o que existe para detectar e testar.

### Resource Development (TA0042) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1585](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1585) Establish Accounts | Fox Kitten has created KeyBase accounts to communicate with ransomware victims. | 1 | — | — |
| [T1585.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1585.001) Social Media Accounts | Fox Kitten has used a Twitter account to communicate with ransomware victims. | 4 | — | — |

### Initial Access (TA0001) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | Fox Kitten has used valid credentials with various services during lateral movement. | 825 | — | 3 |
| [T1190](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1190) Exploit Public-Facing Application | Fox Kitten has exploited known vulnerabilities in Fortinet, PulseSecure, and Palo Alto VPN appliances. | 580 | — | — |

### Execution (TA0002) — 4

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1053.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1053.005) Scheduled Task | Fox Kitten has used Scheduled Tasks for persistence and to load and execute a reverse proxy binary. | 248 | 14 | 11 |
| [T1059](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059) Command and Scripting Interpreter | Fox Kitten has used a Perl reverse shell to communicate with C2. | 1467 | 1 | — |
| [T1059.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.001) PowerShell | Fox Kitten has used PowerShell scripts to access credential data. | 1340 | 22 | 15 |
| [T1059.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.003) Windows Command Shell | Fox Kitten has used cmd.exe likely as a password changing mechanism. | 269 | 6 | 1 |

### Persistence (TA0003) — 5

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1053.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1053.005) Scheduled Task | Fox Kitten has used Scheduled Tasks for persistence and to load and execute a reverse proxy binary. | 248 | 14 | 11 |
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | Fox Kitten has used valid credentials with various services during lateral movement. | 825 | — | 3 |
| [T1136.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1136.001) Local Account | Fox Kitten has created a local user account with administrator privileges. | 103 | 10 | — |
| [T1505.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1505.003) Web Shell | Fox Kitten has installed web shells on compromised hosts to maintain access. | 210 | 1 | — |
| [T1546.008](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1546.008) Accessibility Features | Fox Kitten has used sticky keys to launch a command prompt. | 40 | 10 | — |

### Privilege Escalation (TA0004) — 3

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1053.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1053.005) Scheduled Task | Fox Kitten has used Scheduled Tasks for persistence and to load and execute a reverse proxy binary. | 248 | 14 | 11 |
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | Fox Kitten has used valid credentials with various services during lateral movement. | 825 | — | 3 |
| [T1546.008](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1546.008) Accessibility Features | Fox Kitten has used sticky keys to launch a command prompt. | 40 | 10 | — |

### Stealth (TA0005) — 5

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1027.010](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1027.010) Command Obfuscation | Fox Kitten has base64 encoded scripts to avoid detection. | 78 | — | — |
| [T1027.013](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1027.013) Encrypted/Encoded File | Fox Kitten has base64 encoded payloads to avoid detection. | 8 | 4 | — |
| [T1036.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1036.004) Masquerade Task or Service | Fox Kitten has named the task for a reverse proxy lpupdate to appear legitimate. | 31 | 4 | — |
| [T1036.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1036.005) Match Legitimate Resource Name or Location | Fox Kitten has named binaries and configuration files svhost and dllhost respectively to appear legitimate. | 116 | 4 | — |
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | Fox Kitten has used valid credentials with various services during lateral movement. | 825 | — | 3 |

### Credential Access (TA0006) — 5

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1003.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1003.001) LSASS Memory | Fox Kitten has used prodump to dump credentials from LSASS. | 580 | 14 | 10 |
| [T1003.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1003.003) NTDS | Fox Kitten has used Volume Shadow Copy to access credential information from NTDS. | 157 | 11 | 2 |
| [T1110](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1110) Brute Force | Fox Kitten has brute forced RDP credentials. | 381 | — | 12 |
| [T1552.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1552.001) Credentials In Files | Fox Kitten has accessed files to gain valid credentials. | 166 | 32 | — |
| [T1555.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1555.005) Password Managers | Fox Kitten has used scripts to access credential information from the KeePass database. | 6 | — | — |

### Discovery (TA0007) — 7

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1012](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1012) Query Registry | Fox Kitten has accessed Registry hives ntuser.dat and UserClass.dat. | 92 | 6 | — |
| [T1018](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1018) Remote System Discovery | Fox Kitten has used Angry IP Scanner to detect remote systems. | 157 | 23 | 1 |
| [T1046](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1046) Network Service Discovery | Fox Kitten has used tools including NMAP to conduct broad scanning to identify open ports. | 212 | 13 | 2 |
| [T1083](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1083) File and Directory Discovery | Fox Kitten has used WizTree to obtain network files and directory listings. | 137 | 9 | — |
| [T1087.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1087.001) Local Account | Fox Kitten has accessed ntuser.dat and UserClass.dat on compromised hosts. | 98 | 11 | — |
| [T1087.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1087.002) Domain Account | Fox Kitten has used the Softerra LDAP browser to browse documentation on service accounts. | 180 | 25 | 1 |
| [T1217](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1217) Browser Information Discovery | Fox Kitten has used Google Chrome bookmarks to identify internal resources and assets. | 19 | 11 | — |

### Lateral Movement (TA0008) — 5

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1021.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1021.001) Remote Desktop Protocol | Fox Kitten has used RDP to log in and move laterally in the target environment. | 139 | 4 | 7 |
| [T1021.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1021.002) SMB/Windows Admin Shares | Fox Kitten has used valid accounts to access SMB shares. | 272 | 4 | 20 |
| [T1021.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1021.004) SSH | Fox Kitten has used the PuTTY and Plink tools for lateral movement. | 60 | 2 | 3 |
| [T1021.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1021.005) VNC | Fox Kitten has installed TightVNC server and client on compromised servers and endpoints for lateral movement. | 7 | 1 | — |
| [T1210](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1210) Exploitation of Remote Services | Fox Kitten has exploited known vulnerabilities in remote services including RDP. | 192 | — | 4 |

### Collection (TA0009) — 5

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1005) Data from Local System | Fox Kitten has searched local system resources to access sensitive documents. | 170 | 3 | — |
| [T1039](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1039) Data from Network Shared Drive | Fox Kitten has searched network shares to access sensitive documents. | 24 | 2 | — |
| [T1213.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1213.005) Messaging Applications | Fox Kitten has accessed victim security and IT environments and Microsoft Teams to mine valuable information. | **0** | — | — |
| [T1530](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1530) Data from Cloud Storage | Fox Kitten has obtained files from the victim's cloud storage instances. | 150 | 2 | — |
| [T1560.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1560.001) Archive via Utility | Fox Kitten has used 7-Zip to archive data. | 76 | 13 | — |

### Command and Control (TA0011) — 4

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1090](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1090) Proxy | Fox Kitten has used the open source reverse proxy tools including FRPC and Go Proxy to establish connections from C2 to local servers. | 162 | — | 1 |
| [T1102](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1102) Web Service | Fox Kitten has used Amazon Web Services to host C2. | 98 | — | — |
| [T1105](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1105) Ingress Tool Transfer | Fox Kitten has downloaded additional tools including PsExec directly to endpoints. | 644 | 39 | — |
| [T1572](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1572) Protocol Tunneling | Fox Kitten has used protocol tunneling for communication and RDP activity on compromised hosts through the use of open source tools such as ngrok and custom tool SSHMinion. | 173 | 9 | 1 |

## 4. Assinatura comportamental

Técnicas que este grupo usa e que poucos dos 178 grupos do ATT&CK usam. Pesam mais numa atribuição por TTP: ver várias delas juntas é mais informativo do que ver técnicas comuns como PowerShell.

| Técnica | Outros grupos que usam | Peso (raridade) |
|---|---:|---:|
| T1021.005 VNC | 3 | 3.58 |
| T1213.005 Messaging Applications | 4 | 3.40 |
| T1530 Data from Cloud Storage | 5 | 3.24 |
| T1546.008 Accessibility Features | 5 | 3.24 |
| T1585 Establish Accounts | 5 | 3.24 |
| T1217 Browser Information Discovery | 6 | 3.11 |
| T1555.005 Password Managers | 6 | 3.11 |
| T1039 Data from Network Shared Drive | 8 | 2.88 |
| T1210 Exploitation of Remote Services | 11 | 2.62 |
| T1102 Web Service | 14 | 2.42 |

## 5. Arsenal

| Software | Tipo | Técnicas no ATT&CK | Uso relatado (EN) |
|---|---|---:|---|
| [SystemBC](https://attack.mitre.org/software/S9001/) | malware | 21 |  |
| [China Chopper](https://attack.mitre.org/software/S0020/) | malware | 10 |  |
| [Pay2Key](https://attack.mitre.org/software/S0556/) | malware | 8 |  |
| [ngrok](https://attack.mitre.org/software/S0508/) | ferramenta | 5 |  |
| [PsExec](https://attack.mitre.org/software/S0029/) | ferramenta | 5 |  |

## 6. Campanhas

Nenhuma campanha atribuída no ATT&CK.

## 7. Cobertura defensiva

**40 de 41 técnicas (98%)** têm ao menos uma regra pública no catálogo Detection Rules.

### Técnicas sem regra pública (prioridade para engenharia de detecção)

- **T1213.005 Messaging Applications** — Collection. Fonte de log sugerida pelo MITRE: `saas:slack` conversations.history, files.list, users.info, audit_logs; `m365:unified` TeamsMessagesAccessedViaEDiscovery, TeamsGraphMessageExport

### Regras recomendadas por técnica

Melhor regra disponível por técnica (formato portável e maduro primeiro).

| Técnica | Regra | Formato | Fonte |
|---|---|---|---|
| T1003.001 | [Antivirus - Password Dumper Signature](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A78cc2dd2-7d20-4d32-93ff-057084c38b93) | Sigma | SigmaHQ |
| T1003.001 | [Mimikatz through Windows Remote Management](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Aaa35a627-33fb-4d04-a165-d33b4afca3e8) | Sigma | OpenSearch Security Analytics |
| T1003.003 | [Potential Russian APT Credential Theft Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab83f5166-9237-4b5e-9cd4-7b5d52f4d8ee) | Sigma | SigmaHQ |
| T1003.003 | [VolumeShadowCopy Symlink Creation Via Mklink](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A40b19fa6-d835-400c-b301-41f3a2baacaf) | Sigma | SigmaHQ |
| T1005 | [Potential Conti Ransomware Database Dumping Activity Via SQLCmd](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A2f47f1fd-0901-466e-a770-3b7092834a1b) | Sigma | SigmaHQ |
| T1005 | [OpenCanary - SMB File Open Request](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A22777c9e-873a-4b49-855f-6072ab861a52) | Sigma | SigmaHQ |
| T1012 | [Potential Baby Shark Malware Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A2b30fa36-3a18-402f-a22d-bf4ce2189f35) | Sigma | SigmaHQ |
| T1012 | [Operation Wocao Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1cfac73c-be78-4f9a-9b08-5bde0c3953ab) | Sigma | SigmaHQ |
| T1018 | [Chopper Webshell Process Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Afa3c117a-bc0d-416e-a31b-0c0e80653efb) | Sigma | SigmaHQ |
| T1018 | [Webshell Hacking Activity Patterns](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4ebc877f-4612-45cb-b3a5-8e3834db36c9) | Sigma | SigmaHQ |
| T1021.001 | [Hermetic Wiper TG Process Patterns](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A2f974656-6d83-4059-bbdf-68ac5403422f) | Sigma | SigmaHQ |
| T1021.001 | [Publicly Accessible RDP Service](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1fc0809e-06bf-4de3-ad52-25e5263b7623) | Sigma | SigmaHQ |
| T1021.002 | [PSExec Lateral Movement](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=hayabusa-native%3A%3A0694c340-3a46-40ac-acfc-c3444ae6572c) | Sigma | Hayabusa (native) |
| T1021.002 | [Turla Group Lateral Movement](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac601f20d-570a-4cde-a7d6-e17f99cb8e7f) | Sigma | SigmaHQ |
| T1021.004 | [Potential THC Tool Downloaded](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A2ddc468e-b39b-4f5b-9825-f3dcb0e998ea) | Elastic | Elastic detection-rules |
| T1021.004 | [AWS EC2 CreateKeyPair by New Principal from Non-Cloud AS Organization](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ac8e4f1a2-9b3d-4c5e-a6f7-8b9c0d1e2f3a) | Elastic | Elastic detection-rules |
| T1021.005 | [Suspicious UltraVNC Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A871b9555-69ca-4993-99d3-35a59f9f3599) | Sigma | SigmaHQ |
| T1021.005 | [Suspicious UltraVNC Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A871b9555-69ca-4993-99d3-35a59f9f3599) | Sigma | OpenSearch Security Analytics |
| T1027.010 | [Decoded Payload Piped to Interpreter Detected via Defend for Containers](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A0fb83aa0-3d17-41e9-b09c-56397bf7a7d9) | Elastic | Elastic detection-rules |
| T1027.010 | [Potential PowerShell Obfuscation via String Concatenation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Af6d8c743-0916-4483-8333-3c6f107e0caa) | Elastic | Elastic detection-rules |
| T1027.013 | [ROT Encoded Python Script Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A5ab49127-b1b3-46e6-8a38-9e8512a2a363) | Elastic | Elastic detection-rules |
| T1027.013 | [Data Encrypted via OpenSSL Utility](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Afeba48f6-40ca-4d04-b41f-5dfa327de865) | Elastic | Elastic detection-rules |
| T1036.004 | [Operation Wocao Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1cfac73c-be78-4f9a-9b08-5bde0c3953ab) | Sigma | SigmaHQ |
| T1036.004 | [Operation Wocao Activity - Security](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A74ad4314-482e-4c3e-b237-3f7ed3b9ca8d) | Sigma | SigmaHQ |
| T1036.005 | [Exploit for CVE-2015-1641](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A7993792c-5ce2-4475-a3db-a3a5539827ef) | Sigma | SigmaHQ |
| T1036.005 | [Exploit for CVE-2015-1641](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A7993792c-5ce2-4475-a3db-a3a5539827ef) | Sigma | OpenSearch Security Analytics |
| T1039 | [Copy from Admin Share](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A855bc8b5-2ae8-402e-a9ed-b889e6df1900) | Sigma | OpenSearch Security Analytics |
| T1039 | [PowerShell Share Enumeration Script](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A4c59cff1-b78a-41b8-a9f1-4231984d1fb6) | Elastic | Elastic detection-rules |
| T1046 | [HackTool - winPEAS Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A98b53e78-ebaf-46f8-be06-421aafd176d9) | Sigma | SigmaHQ |
| T1046 | [HackTool - WinPwn Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad557dc06-62e8-4468-a8e8-7984124908ce) | Sigma | SigmaHQ |
| T1053.005 | [Operation Wocao Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1cfac73c-be78-4f9a-9b08-5bde0c3953ab) | Sigma | SigmaHQ |
| T1053.005 | [Operation Wocao Activity - Security](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A74ad4314-482e-4c3e-b237-3f7ed3b9ca8d) | Sigma | SigmaHQ |
| T1059 | [Windows Defender Threat Detected](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A57b649ef-ff42-4fb0-8bf6-62da243a1708) | Sigma | OpenSearch Security Analytics |
| T1059 | [Windows Defender AMSI Trigger Detected](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Aea9bf0fa-edec-4fb8-8b78-b119f2528186) | Sigma | OpenSearch Security Analytics |
| T1059.001 | [Potential Emotet Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad02e8cf5-6099-48cf-9bfc-1eec2d0c7b18) | Sigma | SigmaHQ |
| T1059.001 | [TropicTrooper Campaign November 2018](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A8c7090c3-e0a0-4944-bd08-08c3a0cecf79) | Sigma | SigmaHQ |
| T1059.003 | [HackTool - CrackMapExec Execution Patterns](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A058f4380-962d-40a5-afce-50207d36d7e2) | Sigma | SigmaHQ |
| T1059.003 | [CrackMapExec Command Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A058f4380-962d-40a5-afce-50207d36d7e2) | Sigma | OpenSearch Security Analytics |
| T1078 | [Privilege Role Sign-In Outside Expected Controls](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acf1e5687-84e1-41af-97a9-158094efef53) | Sigma | SigmaHQ |
| T1078 | [OpenCanary - SSH Login Attempt](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aff7139bc-fdb1-4437-92f2-6afefe8884cb) | Sigma | SigmaHQ |
| T1083 | [Turla Group Lateral Movement](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac601f20d-570a-4cde-a7d6-e17f99cb8e7f) | Sigma | SigmaHQ |
| T1083 | [WannaCry Ransomware Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A41d40bff-377a-43e2-8e1b-2e543069e079) | Sigma | SigmaHQ |
| T1087.001 | [BloodHound Collection Files](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A02773bed-83bf-469f-b7ff-e676e7d78bab) | Sigma | SigmaHQ |
| T1087.001 | [HackTool - Bloodhound/Sharphound Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Af376c8a7-a2d0-4ddc-aa0c-16c17236d962) | Sigma | SigmaHQ |
| T1087.002 | [BloodHound Collection Files](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A02773bed-83bf-469f-b7ff-e676e7d78bab) | Sigma | SigmaHQ |
| T1087.002 | [Suspicious Active Directory Database Snapshot Via ADExplorer](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aef61af62-bc74-4f58-b49b-626448227652) | Sigma | SigmaHQ |
| T1090 | [Communication To LocaltoNet Tunneling Service Initiated - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac4568f5d-131f-4e78-83d4-45b2da0ec4f1) | Sigma | SigmaHQ |
| T1090 | [Communication To Ngrok Tunneling Service - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A19bf6fdb-7721-4f3d-867f-53467f6a5db6) | Sigma | SigmaHQ |
| T1102 | [Communication To LocaltoNet Tunneling Service Initiated - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac4568f5d-131f-4e78-83d4-45b2da0ec4f1) | Sigma | SigmaHQ |
| T1102 | [Communication To Ngrok Tunneling Service - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A19bf6fdb-7721-4f3d-867f-53467f6a5db6) | Sigma | SigmaHQ |
| T1105 | [Greenbug Espionage Group Indicators](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A3711eee4-a808-4849-8a14-faf733da3612) | Sigma | SigmaHQ |
| T1105 | [Pandemic Registry Key](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A47e0852a-cf81-4494-a8e6-31864f8c86ed) | Sigma | SigmaHQ |
| T1110 | [Hack Tool User Agent](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac42a3073-30fb-48ae-8c99-c23ada84b103) | Sigma | SigmaHQ |
| T1110 | [HackTool - CrackMapExec Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A42a993dd-bb3e-48c8-b372-4d6684c4106c) | Sigma | SigmaHQ |
| T1136.001 | [DarkGate - User Created Via Net.EXE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Abf906d7b-7070-4642-8383-e404cf26eba5) | Sigma | SigmaHQ |
| T1136.001 | [Serv-U Exploitation CVE-2021-35211 by DEV-0322](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A75578840-9526-4b2a-9462-af469a45e767) | Sigma | SigmaHQ |
| T1190 | [OMIGOD HTTP No Authentication RCE - CVE-2021-38647](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aab6b1a39-a9ee-4ab4-b075-e83acf6e346b) | Sigma | SigmaHQ |
| T1190 | [Exploited CVE-2020-10189 Zoho ManageEngine](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A846b866e-2a57-46ee-8e16-85fa92759be7) | Sigma | OpenSearch Security Analytics |
| T1210 | [OMIGOD HTTP No Authentication RCE - CVE-2021-38647](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aab6b1a39-a9ee-4ab4-b075-e83acf6e346b) | Sigma | SigmaHQ |
| T1210 | [OMIGOD HTTP No Authentication RCE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Aab6b1a39-a9ee-4ab4-b075-e83acf6e346b) | Sigma | OpenSearch Security Analytics |
| T1217 | [File And SubFolder Enumeration Via Dir Command](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A7c9340a9-e2ee-4e43-94c5-c54ebbea1006) | Sigma | SigmaHQ |
| T1217 | [Suspicious Where Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A725a9768-0f5e-4cb3-aec2-bc5719c6831a) | Sigma | SigmaHQ |
| T1505.003 | [MOVEit CVE-2023-34362 Exploitation Attempt - Potential Web Shell Request](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A435e41f2-48eb-4c95-8a2b-ed24b50ec30b) | Sigma | SigmaHQ |
| T1505.003 | [Solarwinds SUPERNOVA Webshell Access](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aa2cee20b-eacc-459f-861d-c02e5d12f1db) | Sigma | SigmaHQ |
| T1530 | [Google Workspace Drive Encryption Key(s) Accessed from Anonymous User](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A980b70a0-c820-11ed-8799-f661ea17fbcc) | Elastic | Elastic detection-rules |
| T1530 | [AWS CloudTrail Log Updated](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A3e002465-876f-4f04-b016-84ef48ce7e5d) | Elastic | Elastic detection-rules |
| T1546.008 | [Suspicious Debugger Registration Cmdline](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aae215552-081e-44c7-805f-be16f975c8a2) | Sigma | SigmaHQ |
| T1546.008 | [Sticky Key Like Backdoor Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A2fdefcb3-dbda-401e-ae23-f0db027628bc) | Sigma | SigmaHQ |
| T1552.001 | [Potential Russian APT Credential Theft Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab83f5166-9237-4b5e-9cd4-7b5d52f4d8ee) | Sigma | SigmaHQ |
| T1552.001 | [Copy Passwd Or Shadow From TMP Path](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Afa4aaed5-4fe0-498d-bbc0-08e3346387ba) | Sigma | SigmaHQ |
| T1555.005 | [Remote Thread Created In KeePass.EXE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A77564cc2-7382-438b-a7f6-395c2ae53b9a) | Sigma | SigmaHQ |
| T1555.005 | [KeePass Password Dumping](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A77564cc2-7382-438b-a7f6-395c2ae53b9a) | Sigma | OpenSearch Security Analytics |
| T1560.001 | [APT31 Judgement Panda Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A03e2746e-2b31-42f1-ab7a-eb39365b2422) | Sigma | SigmaHQ |
| T1560.001 | [Suspicious Manipulation Of Default Accounts Via Net.EXE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A5b768e71-86f2-4879-b448-81061cbae951) | Sigma | SigmaHQ |
| T1572 | [Communication To LocaltoNet Tunneling Service Initiated - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac4568f5d-131f-4e78-83d4-45b2da0ec4f1) | Sigma | SigmaHQ |
| T1572 | [Communication To Ngrok Tunneling Service - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A19bf6fdb-7721-4f3d-867f-53467f6a5db6) | Sigma | SigmaHQ |
| T1585 | [A SAML Connector was created or modified](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=panther-panther-analysis%3A%3ATeleport.SAMLCreated) | Panther | Panther panther-analysis |
| T1585.001 | [CYFIRMA - Brand Intelligence - Social Media Handle Impersonation Detected High Rule](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A22f49d67-7da7-4809-8d07-89e4478aa6b0) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1585.001 | [CYFIRMA - Brand Intelligence - Executive/People Impersonation High Rule](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A159d26a1-591c-4f70-b1ca-2843c881aaec) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |

## 8. Plano de emulação e validação

Use num laboratório isolado e autorizado para confirmar que as regras disparam. Os comandos estão nos repositórios oficiais.

| Tática | Técnica | Teste Atomic Red Team | Plataformas |
|---|---|---|---|
| Execution | [T1053.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1053.005/T1053.005.md) | Scheduled Task Startup Script | windows |
| Execution | [T1053.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1053.005/T1053.005.md) | Scheduled task Local | windows |
| Execution | [T1059](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059/T1059.md) | AutoIt Script Execution | windows |
| Execution | [T1059.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md) | Mimikatz | windows |
| Execution | [T1059.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md) | Run BloodHound from local disk | windows |
| Execution | [T1059.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.003/T1059.003.md) | Create and Execute Batch Script | windows |
| Execution | [T1059.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.003/T1059.003.md) | Writes text to a file and displays it. | windows |
| Persistence | [T1136.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1136.001/T1136.001.md) | Create a user account on a Linux system | linux |
| Persistence | [T1136.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1136.001/T1136.001.md) | Create a user account on a FreeBSD system | linux |
| Persistence | [T1505.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1505.003/T1505.003.md) | Web Shell Written to Disk | windows |
| Privilege Escalation | [T1546.008](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1546.008/T1546.008.md) | Attaches Command Prompt as a Debugger to a List of Target Processes | windows |
| Privilege Escalation | [T1546.008](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1546.008/T1546.008.md) | Replace binary of sticky keys | windows |
| Stealth | [T1027.013](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027.013/T1027.013.md) | Decode Eicar File and Write to File | linux, macos, windows |
| Stealth | [T1027.013](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027.013/T1027.013.md) | Decrypt Eicar File and Write to File | linux, macos, windows |
| Stealth | [T1036.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.004/T1036.004.md) | Creating W32Time similar named service using schtasks | windows |
| Stealth | [T1036.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.004/T1036.004.md) | Creating W32Time similar named service using sc | windows |
| Stealth | [T1036.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.005/T1036.005.md) | Execute a process from a directory masquerading as the current parent directory | linux, macos |
| Stealth | [T1036.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.005/T1036.005.md) | Masquerade as a built-in system executable | windows |
| Credential Access | [T1003.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/T1003.001.md) | Dump LSASS.exe Memory using ProcDump | windows |
| Credential Access | [T1003.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/T1003.001.md) | Dump LSASS.exe Memory using comsvcs.dll | windows |
| Credential Access | [T1003.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.003/T1003.003.md) | Create Volume Shadow Copy with vssadmin | windows |
| Credential Access | [T1003.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.003/T1003.003.md) | Copy NTDS.dit from Volume Shadow Copy | windows |
| Credential Access | [T1552.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1552.001/T1552.001.md) | Find AWS credentials | linux, macos |
| Credential Access | [T1552.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1552.001/T1552.001.md) | Extract Browser and System credentials with LaZagne | macos |
| Discovery | [T1012](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1012/T1012.md) | Query Registry | windows |
| Discovery | [T1012](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1012/T1012.md) | Query Registry with Powershell cmdlets | windows |
| Discovery | [T1018](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1018/T1018.md) | Remote System Discovery - net | windows |
| Discovery | [T1018](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1018/T1018.md) | Remote System Discovery - net group Domain Computers | windows |
| Discovery | [T1046](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1046/T1046.md) | Port Scan | linux, macos |
| Discovery | [T1046](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1046/T1046.md) | Port Scan Nmap | linux, macos |
| Discovery | [T1083](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1083/T1083.md) | File and Directory Discovery (cmd.exe) | windows |
| Discovery | [T1083](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1083/T1083.md) | File and Directory Discovery (PowerShell) | windows |
| Discovery | [T1087.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1087.001/T1087.001.md) | Enumerate all accounts (Local) | linux |
| Discovery | [T1087.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1087.001/T1087.001.md) | View sudoers access | linux, macos |
| Discovery | [T1087.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1087.002/T1087.002.md) | Enumerate all accounts (Domain) | windows |
| Discovery | [T1087.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1087.002/T1087.002.md) | Enumerate all accounts via PowerShell (Domain) | windows |
| Discovery | [T1217](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1217/T1217.md) | List Mozilla Firefox Bookmark Database Files on FreeBSD/Linux | linux |
| Discovery | [T1217](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1217/T1217.md) | List Mozilla Firefox Bookmark Database Files on macOS | macos |
| Lateral Movement | [T1021.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.001/T1021.001.md) | RDP to Remote Host | windows |
| Lateral Movement | [T1021.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.001/T1021.001.md) | Changing RDP Port to Non Standard Port via Powershell | windows |
| Lateral Movement | [T1021.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.002/T1021.002.md) | Map admin share | windows |
| Lateral Movement | [T1021.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.002/T1021.002.md) | Map Admin Share PowerShell | windows |
| Lateral Movement | [T1021.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.004/T1021.004.md) | ESXi - Enable SSH via PowerCLI | windows |
| Lateral Movement | [T1021.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.004/T1021.004.md) | ESXi - Enable SSH via VIM-CMD | windows |
| Lateral Movement | [T1021.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.005/T1021.005.md) | Enable Apple Remote Desktop Agent | macos |
| Collection | [T1005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1005/T1005.md) | Search files of interest and save them to a single zip file (Windows) | windows |
| Collection | [T1005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1005/T1005.md) | Find and dump sqlite databases (Linux) | linux |
| Collection | [T1039](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1039/T1039.md) | Copy a sensitive File over Administrative share with copy | windows |
| Collection | [T1039](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1039/T1039.md) | Copy a sensitive File over Administrative share with Powershell | windows |
| Collection | [T1530](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1530/T1530.md) | AWS - Scan for Anonymous Access to S3 | iaas:aws |
| Collection | [T1530](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1530/T1530.md) | Azure - Dump Azure Storage Account Objects via Azure CLI | iaas:azure |
| Collection | [T1560.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1560.001/T1560.001.md) | Compress Data for Exfiltration With Rar | windows |
| Collection | [T1560.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1560.001/T1560.001.md) | Compress Data and lock with password for Exfiltration with winrar | windows |
| Command and Control | [T1105](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1105/T1105.md) | rsync remote file copy (push) | linux, macos |
| Command and Control | [T1105](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1105/T1105.md) | rsync remote file copy (pull) | linux, macos |
| Command and Control | [T1572](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1572/T1572.md) | DNS over HTTPS Large Query Volume | windows |
| Command and Control | [T1572](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1572/T1572.md) | DNS over HTTPS Regular Beaconing | windows |

**Logs reais de ataque (EVTX) para testar sem executar nada:**

- T1003.001 — [CA_hashdump_4663_4656_lsass_access](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Credential%20Access/CA_hashdump_4663_4656_lsass_access.evtx) _(inferido)_
- T1003.001 — [LsassSilentProcessExit_process_exit_monitor_3001_lsass](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Credential%20Access/LsassSilentProcessExit_process_exit_monitor_3001_lsass.evtx) _(inferido)_
- T1003.003 — [dc_applog_ntdsutil_dfir_325_326_327](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Credential%20Access/dc_applog_ntdsutil_dfir_325_326_327.evtx) _(inferido)_
- T1003.003 — [LM_regsvc_DirectoryServiceExtPt_Lsass_NTDS_AdamXpn](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Lateral%20Movement/LM_regsvc_DirectoryServiceExtPt_Lsass_NTDS_AdamXpn.evtx) _(inferido)_
- T1018 — [ID5145-DNS hosts files access via network share](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1018-Remote%20System%20Discovery/ID5145-DNS%20hosts%20files%20access%20via%20network%20share.evtx) _(explícito)_
- T1021.001 — [ID4688,4778,4779 RDP hijack direct](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0008-Lateral%20Movement/T1021.001-Remote%20Desktop%20Protocol/ID4688%2C4778%2C4779%20RDP%20hijack%20direct.evtx) _(explícito)_
- T1021.001 — [ID4688-4778 RDP hijack command execution](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0008-Lateral%20Movement/T1021.001-Remote%20Desktop%20Protocol/ID4688-4778%20RDP%20hijack%20command%20execution.evtx) _(explícito)_
- T1021.002 — [ID4688,4697,5140-5145 PSexec remote execution + admin share](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0008-Lateral%20Movement/T1021.002-SMB%20Windows%20Admin%20Shares/ID4688%2C4697%2C5140-5145%20PSexec%20remote%20execution%20%2B%20admin%20share.evtx) _(explícito)_
- T1021.002 — [ID4688-4648 Lateral movement with net use](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0008-Lateral%20Movement/T1021.002-SMB%20Windows%20Admin%20Shares/ID4688-4648%20Lateral%20movement%20with%20net%20use.evtx) _(explícito)_
- T1021.004 — [ID4-OpenSSH server listening](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0008-Lateral%20Movement/T1021.004-Remote%20Service%20SSH/ID4-OpenSSH%20server%20listening.evtx) _(explícito)_
- T1021.004 — [ID4103-4104-OpenSSH server activation and config](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0008-Lateral%20Movement/T1021.004-Remote%20Service%20SSH/ID4103-4104-OpenSSH%20server%20activation%20and%20config.evtx) _(explícito)_
- T1046 — [ID131-RDP brutforce (no user info)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1046-Network%20Service%20Scanning/ID131-RDP%20brutforce%20%28no%20user%20info%29.evtx) _(explícito)_
- T1046 — [ID4624-Anonymous login with domain specified (DonPapi)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1046-Network%20Service%20Scanning/ID4624-Anonymous%20login%20with%20domain%20specified%20%28DonPapi%29.evtx) _(explícito)_
- T1053.005 — [ID4688-4698 Persistent scheduled task with SYSTEM privileges creation](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1053.005-Scheduled%20Task/ID4688-4698%20Persistent%20scheduled%20task%20with%20SYSTEM%20privileges%20creation.evtx) _(explícito)_
- T1053.005 — [ID4688-Interactive shell using AT schedule task](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1053.005-Scheduled%20Task/ID4688-Interactive%20shell%20using%20AT%20schedule%20task.evtx) _(explícito)_
- T1059.001 — [ID4103-4104-Payload download via PowerShell](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1059.001-PowerShell/ID4103-4104-Payload%20download%20via%20PowerShell.evtx) _(explícito)_
- T1059.001 — [ID4688-Encoded PowerShell MSF payload via process execution](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1059.001-PowerShell/ID4688-Encoded%20PowerShell%20MSF%20payload%20via%20process%20execution.evtx) _(explícito)_
- T1059.003 — [ID4688-SQL Server payload injectection for reverse shell (MSF)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1059.003-Windows%20Command%20Shell/ID4688-SQL%20Server%20payload%20injectection%20for%20reverse%20shell%20%28MSF%29.evtx) _(explícito)_
- T1078 — [ID1149-RDP success logins to multiple hosts](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0001-Initial%20access/T1078-Valid%20accounts/ID1149-RDP%20success%20logins%20to%20multiple%20hosts.evtx) _(explícito)_
- T1078 — [ID33205-SQL Server failed login with disabled SA account](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0001-Initial%20access/T1078-Valid%20accounts/ID33205-SQL%20Server%20failed%20login%20with%20disabled%20SA%20account.evtx) _(explícito)_
- T1087.002 — [discovery_bloodhound](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Discovery/discovery_bloodhound.evtx) _(inferido)_
- T1090 — [ID5600-proxy configuration changed](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0011-Command%20and%20Control/T1090-Proxy/ID5600-proxy%20configuration%20changed.evtx) _(explícito)_
- T1110 — [ID 4776,4625-AccountRestore local bruteforce](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0006-Credential%20Access/T1110.xxx-Brut%20force/ID%204776%2C4625-AccountRestore%20local%20bruteforce.evtx) _(explícito)_
- T1110 — [ID18456-SQL Server failed login because only Windows auth](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0006-Credential%20Access/T1110.xxx-Brut%20force/ID18456-SQL%20Server%20failed%20login%20because%20only%20Windows%20auth.evtx) _(explícito)_
- T1210 — [Zerologon_CVE-2020-1472_DFIR_System_NetLogon_Error_EventID_5805](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Credential%20Access/Zerologon_CVE-2020-1472_DFIR_System_NetLogon_Error_EventID_5805.evtx) _(inferido)_

## 9. Hipóteses de hunting

Se Fox Kitten estiver no seu ambiente, estas são as perguntas a fazer aos seus dados (fontes de log segundo as estratégias de detecção do MITRE ATT&CK).

1. **T1021.005 VNC** — Detection of VNC service or executable starting unexpectedly, followed by user session creation and interactive desktop activity (mouse/keyboard simulation). Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Security` (EventCode=4624, 4648), `NSM:Flow` (port 5900 inbound).
2. **T1213.005 Messaging Applications** — Atypical access to Slack or Teams conversations via APIs, automation tokens, or bulk message export functionality, particularly after an account takeover or rare sign-in pattern. Often includes mass retrieval of chat history, download of message content, or… Dados: `saas:slack` (conversations.history, files.list, users.info, audit_logs), `m365:signinlogs` (UserLoggedIn).
3. **T1530 Data from Cloud Storage** — Spike in object access from new IAM user or role followed by data exfiltration to external IPs Dados: `AWS:CloudTrail` (GetObject, CopyObject), `AWS:CloudTrail` (AssumeRole), `AWS:VPCFlowLogs` (Unusual volume of data transferred from S3 storage endpoints to non-corporate IPs).
4. **T1546.008 Accessibility Features** — Defenders can observe suspicious replacement or tampering of system accessibility binaries (e.g., utilman.exe, sethc.exe, osk.exe) and anomalous modifications to registry keys used to redirect accessibility programs (such as IFEO keys). Additionally,… Dados: `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=13, 14).
5. **T1585 Establish Accounts** — Monitor and analyze traffic patterns and packet inspection associated to protocol(s) that do not follow the expected protocol standards and traffic flows (e.g extraneous packets that do not belong to established flows, gratuitous or anomalous traffic… Dados: `Network Traffic` (None), `Persona` (None).
6. **T1217 Browser Information Discovery** — Access to browser artifact locations (e.g., Chrome, Edge, Firefox) by processes like PowerShell, cmd.exe, or unknown tools, followed by file reads, decoding, or export operations indicating enumeration of bookmarks, autofill, or history databases. Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:PowerShell` (EventCode=4103, 4104, 4105, 4106).
7. **T1555.005 Password Managers** — Detection of suspicious access to password manager processes (KeePass, 1Password, LastPass, Bitwarden) through abnormal process injection, memory reads, or command-line usage of vault-related DLLs. Correlates process creation with OS API calls and file access… Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=10), `WinEventLog:Sysmon` (EventCode=15).
8. **T1039 Data from Network Shared Drive** — Monitoring of file access to network shares (e.g., C$, Admin$) followed by unusual read or copy operations by processes not typically associated with such activity (e.g., PowerShell, certutil). Dados: `WinEventLog:Security` (EventCode=5145), `WinEventLog:Sysmon` (EventCode=11).
9. **T1210 Exploitation of Remote Services** — Correlates inbound network access to remote service ports (e.g., SMB/RPC 445/135, RDP 3389, WinRM 5985/5986) with near-time instability in the target service (crash, abnormal restart), suspicious child process creation under the service, and post-access… Dados: `WinEventLog:System` (EventCode=1000), `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=3, 22).
10. **T1102 Web Service** — Detects unusual outbound connections to web services from uncommon processes using SSL/TLS, particularly those exhibiting high outbound data volume or persistence. Dados: `WinEventLog:Sysmon` (EventCode=3, 22), `NSM:Flow` (SSL/TLS Inspection or PCAP).
11. **T1572 Protocol Tunneling** — Processes such as plink.exe, ssh.exe, or netsh.exe establishing outbound network connections where traffic patterns show encapsulated protocols (e.g., RDP over SSH). Defender observations include anomalous process-to-network relationships, large asymmetric… Dados: `WinEventLog:Sysmon` (EventCode=3, 22), `WinEventLog:Sysmon` (EventCode=1).
12. **T1110 Brute Force** — High volume of failed logon attempts followed by a successful one from a suspicious user, host, or timeframe Dados: `WinEventLog:Security` (EventCode=4776, 4625).

## 10. OSINT — onde pesquisar

Consultas prontas com todos os nomes conhecidos do grupo:

- Relatórios técnicos: [busca web](https://duckduckgo.com/?q=%28%22Fox+Kitten%22+OR+%22UNC757%22+OR+%22Parisite%22+OR+%22Pioneer+Kitten%22+OR+%22RUBIDIUM%22+OR+%22Lemon+Sandstorm%22%29+threat+report) · [PDFs](https://duckduckgo.com/?q=%28%22Fox+Kitten%22+OR+%22UNC757%22+OR+%22Parisite%22+OR+%22Pioneer+Kitten%22+OR+%22RUBIDIUM%22+OR+%22Lemon+Sandstorm%22%29+filetype%3Apdf)
- Regras e IOCs publicados: [GitHub](https://github.com/search?type=code&q=%22Fox+Kitten%22+OR+%22UNC757%22+OR+%22Parisite%22+OR+%22Pioneer+Kitten%22+OR+%22RUBIDIUM%22+OR+%22Lemon+Sandstorm%22)
- Pulsos de ameaça: [AlienVault OTX](https://otx.alienvault.com/browse/global/pulses?q=Fox+Kitten)
- Família de malware e atores: [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/actors) (busque por Fox Kitten, UNC757, Parisite)
- Cartões de grupo: [ThaiCERT Threat Group Cards](https://apt.etda.or.th/cgi-bin/listgroups.cgi)
- Página oficial: [MITRE ATT&CK G0117](https://attack.mitre.org/groups/G0117/)

**Relatórios na coleção CyberMonitor** (ligados pelo nome do grupo, conferir antes de citar):

- 2020 — [ClearSky-Fox-Kitten-Campaign-v1](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2020/2020.02.17_Fox_Kitten_Campaign/ClearSky-Fox-Kitten-Campaign-v1.pdf) _(via “Fox Kitten”)_

## 11. Bibliografia (8 fontes citadas pelo ATT&CK)

- [Check Point Pay2Key November 2020](https://research.checkpoint.com/2020/ransomware-alert-pay2key/) — Check Point. (2020, November 6). Ransomware Alert: Pay2Key. Retrieved January 4, 2021.
- [CISA AA20-259A Iran-Based Actor September 2020](https://us-cert.cisa.gov/ncas/alerts/aa20-259a) — CISA. (2020, September 15). Iran-Based Threat Actor Exploits VPN Vulnerabilities. Retrieved December 21, 2020.
- [ClearkSky Fox Kitten February 2020](https://www.clearskysec.com/fox-kitten/) — ClearSky. (2020, February 16). Fox Kitten – Widespread Iranian Espionage-Offensive Campaign. Retrieved December 21, 2020.
- [ClearSky Pay2Kitten December 2020](https://www.clearskysec.com/wp-content/uploads/2020/12/Pay2Kitten.pdf) — ClearSky. (2020, December 17). Pay2Key Ransomware – A New Campaign by Fox Kitten. Retrieved December 21, 2020.
- [CrowdStrike PIONEER KITTEN August 2020](https://www.crowdstrike.com/blog/who-is-pioneer-kitten/) — Orleans, A. (2020, August 31). Who Is PIONEER KITTEN?. Retrieved December 21, 2020.
- [Dragos PARISITE ](https://www.dragos.com/threat/parisite/) — Dragos. (n.d.). PARISITE. Retrieved December 21, 2020.
- [FortinetEtAl_IranianIntrusion_Mar2025](https://www.fortinet.com/content/dam/fortinet/assets/reports/report-incident-response-middle-east.pdf) — Robson, M., et al. (2025, March 7). Investigating Iranian Intrusion into Strategic Middle East Critical Infrastructure. Retrieved June 18, 2025.
- [Microsoft Threat Actor Naming July 2023](https://learn.microsoft.com/en-us/microsoft-365/security/intelligence/microsoft-threat-actor-naming?view=o365-worldwide) — Microsoft . (2023, July 12). How Microsoft names threat actors. Retrieved November 17, 2023.

## 12. Limites e confiança

- O ATT&CK registra o que foi **relatado publicamente**, não tudo o que o grupo faz. Ausência de uma técnica não prova que o grupo não a usa.
- **Sobreposição de TTP não é atribuição.** Muitas técnicas são compartilhadas entre grupos e com red teams. Use a assinatura comportamental como hipótese, junto com infraestrutura, malware e contexto.
- Cobertura de detecção refere-se ao catálogo público Detection Rules, não ao seu ambiente: confira se a telemetria necessária chega ao seu SIEM.
- Ligações marcadas como _inferidas_ (EVTX por palavra-chave, relatórios por nome) devem ser verificadas.

---
Fontes: MITRE ATT&CK® (uso livre com atribuição, © The MITRE Corporation), Atomic Red Team (Red Canary, MIT), EVTX-to-MITRE-Attack, EVTX-ATTACK-SAMPLES, APT & CyberCriminal Campaign Collections. Gerado por [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules).
