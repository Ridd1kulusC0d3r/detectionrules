# ShinyHunters (G1057) — Dossiê de inteligência

> **TLP:CLEAR** · gerado em 2026-10-25 a partir de fontes abertas · MITRE ATT&CK v20.0 · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1057) · [ATT&CK](https://attack.mitre.org/groups/G1057/)

**Também conhecido como:** UNC6240, Bling Libra  
**Registro no ATT&CK:** criado em 2026-07-29, atualizado em 2026-07-31 · referências de 2021 a 2026

## 1. Sumário executivo

- **46 técnicas** atribuídas publicamente, concentradas em **Discovery, Resource Development, Stealth**.
- **Arsenal:** 0 malware e 1 ferramentas (ex.: Tor).
- **Campanhas atribuídas:** 0.
- **Cobertura de detecção pública:** 89% das técnicas têm ao menos uma regra no catálogo; **5 técnicas sem nenhuma regra pública**.
- **Assinatura comportamental** (técnicas raras entre os 178 grupos, as mais úteis para atribuição): T1069.003 Cloud Groups, T1619 Cloud Storage Object Discovery, T1684 Social Engineering, T1195.001 Compromise Software Dependencies and Development Tools, T1560.002 Archive via Library.

## 2. Quem é

> ShinyHunters is a cyber criminal collective that has been active since at least 2019 operating under the ShinyCorp persona. ShinyHunters has targeted multiple industries and geographic regions gathering legitimate credentials and personally identifiable information (PII) for resale or extortion of victims. ShinyHunters has been associated with the broader collective called The Community, also known as The Com whose members have also included Scattered Spider and LAPSUS$. Public reporting has mentioned a variety of names for operations ShinyHunters members have reportedly conducted with members of other groups, including “Scattered Lapsus Hunters,” “Scattered Lapsus Shiny Hunters,” and “SLSH.”

_Texto original do MITRE ATT&CK, em inglês._

## 3. Perfil TTP por tática (kill chain)

Cada linha: técnica, como o grupo a usou segundo relatos públicos, e o que existe para detectar e testar.

### Reconnaissance (TA0043) — 5

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1589.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1589.001) Credentials | ShinyHunters has collected credentials containing PII, ultimately selling the information on their DLS. | 2 | — | — |
| [T1593.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1593.003) Code Repositories | ShinyHunters has searched through target companies’ GitHub repositories for login credentials or API keys. | 6 | — | — |
| [T1595.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1595.002) Vulnerability Scanning | ShinyHunters has searched through victim companies’ GitHub repositories for vulnerabilities. | 27 | — | — |
| [T1598](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1598) Phishing for Information | ShinyHunters has sent phishing emails to Microsoft Office 365 corporate users in order to steal credentials. | 4 | — | — |
| [T1598.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1598.003) Spearphishing Link | ShinyHunters has used spearphishing emails with malicious links to gain initial access and credentials. | **0** | — | — |

### Resource Development (TA0042) — 6

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1583.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1583.001) Domains | ShinyHunters has established clearnet and Tor data leak sites (DLS) including one named “SHINYHUNTERS” for the exfiltration and posting of stolen data. Additionally, ShinyHunters has registered domains that mimic legitimate Microsoft Azure NetApp Files endpoin… | 7 | — | — |
| [T1583.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1583.004) Server | ShinyHunters has used five IP addresses to host Python SimpleHTTP servers on port 8888, which exposed staging materials, customized agents, and .bash_history files. | **0** | — | — |
| [T1585.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1585.002) Email Accounts | ShinyHunters has established multiple email accounts, such as shinycorp@tutonota[.]com, for use in extortion activities. | **0** | — | — |
| [T1587.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1587.004) Exploits | ShinyHunters has exploited zero-day vulnerability CVE-2026-35273 against Oracle PeopleSoft application infrastructure. | 4 | — | — |
| [T1588.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1588.002) Tool | ShinyHunters has obtained MeshCentral to deploy agents masquerading as legitimate cloud endpoints. ShinyHunters has obtained WinSCP to gather information on S3 bucket configurations. ShinyHunters has obtained ConnectWise and other RMM tools to gain initial acc… | 35 | — | — |
| [T1588.007](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1588.007) Artificial Intelligence | ShinyHunters has used Bland AI to create conversational pathways tailored to specific scenarios during voice phishing attacks. | **0** | — | — |

### Initial Access (TA0001) — 5

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | ShinyHunters has used valid high-privileged SSO users as leverage during negotiations. | 825 | — | 3 |
| [T1078.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.002) Domain Accounts | ShinyHunters has used valid domain accounts to gain initial access or to escalate privileges within environments. | 36 | — | 1 |
| [T1078.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.004) Cloud Accounts | ShinyHunters has used valid cloud accounts to gain initial access or to escalate privileges within cloud environments. Additionally, ShinyHunters has also used valid credentials from public repositories to include access keys to gain access to the victim organ… | 356 | 3 | — |
| [T1190](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1190) Exploit Public-Facing Application | ShinyHunters has exploited CVE-2026-35273 against Oracle PeopleSoft application infrastructure. ShinyHunters has exploited known vulnerabilities in internet-facing servers. | 580 | — | — |
| [T1195.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1195.001) Compromise Software Dependencies and Development Tools | ShinyHunters has compromised CI/CD pipelines by gaining access to high privilege engineering accounts on Git version control, BrowserStack, JFrog and other cloud project management platforms. | 30 | — | — |

### Execution (TA0002) — 4

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1059.007](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.007) JavaScript | ShinyHunters has used the MeshCentral command-line interface utility meshctrl.js and npm to interact with compromised systems. Specifically for npm, ShinyHunters has checked for the authenticode tool using the command `npm list global authenticode`. Additional… | 205 | 5 | — |
| [T1059.009](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.009) Cloud API | ShinyHunters has used the AWS Command Line Interface (CLI) for operations to include a variety of API calls, such as `ListBuckets`, `CreateBucket` and `DeleteBucket`. | 11 | — | — |
| [T1072](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1072) Software Deployment Tools | ShinyHunters has abused software deployment tools for lateral movement. | 59 | 3 | — |
| [T1203](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1203) Exploitation for Client Execution | ShinyHunters has exploited vulnerabilities in the target company’s GitHub repository source code to enable more complex follow-on third-party or supply chain attacks. | 202 | — | — |

### Persistence (TA0003) — 3

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | ShinyHunters has used valid high-privileged SSO users as leverage during negotiations. | 825 | — | 3 |
| [T1078.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.002) Domain Accounts | ShinyHunters has used valid domain accounts to gain initial access or to escalate privileges within environments. | 36 | — | 1 |
| [T1078.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.004) Cloud Accounts | ShinyHunters has used valid cloud accounts to gain initial access or to escalate privileges within cloud environments. Additionally, ShinyHunters has also used valid credentials from public repositories to include access keys to gain access to the victim organ… | 356 | 3 | — |

### Privilege Escalation (TA0004) — 3

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | ShinyHunters has used valid high-privileged SSO users as leverage during negotiations. | 825 | — | 3 |
| [T1078.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.002) Domain Accounts | ShinyHunters has used valid domain accounts to gain initial access or to escalate privileges within environments. | 36 | — | 1 |
| [T1078.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.004) Cloud Accounts | ShinyHunters has used valid cloud accounts to gain initial access or to escalate privileges within cloud environments. Additionally, ShinyHunters has also used valid credentials from public repositories to include access keys to gain access to the victim organ… | 356 | 3 | — |

### Stealth (TA0005) — 5

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1036.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1036.005) Match Legitimate Resource Name or Location | ShinyHunters has disguised MeshCentral agent binaries as Microsoft Azure services, e.g. meshagent32-azure-ops.exe, meshagent64-azure-ops.exe, and meshagent64-v2.exe. | 116 | 4 | — |
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | ShinyHunters has used valid high-privileged SSO users as leverage during negotiations. | 825 | — | 3 |
| [T1078.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.002) Domain Accounts | ShinyHunters has used valid domain accounts to gain initial access or to escalate privileges within environments. | 36 | — | 1 |
| [T1078.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.004) Cloud Accounts | ShinyHunters has used valid cloud accounts to gain initial access or to escalate privileges within cloud environments. Additionally, ShinyHunters has also used valid credentials from public repositories to include access keys to gain access to the victim organ… | 356 | 3 | — |
| [T1684](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1684) Social Engineering | ShinyHunters has used social engineering to demand payment from victims. | **0** | — | — |

### Credential Access (TA0006) — 3

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1110](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1110) Brute Force | ShinyHunters has performed brute force attacks against edge devices, such as VPNs or firewall solutions. | 381 | — | 12 |
| [T1528](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1528) Steal Application Access Token | ShinyHunters has stolen valid OAuth credentials from DevOps personnel or a company GitHub repository. Additionally, ShinyHunters has stolen application access tokens to access cloud services and to bypass authentication mechanisms. | 105 | 2 | — |
| [T1552.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1552.001) Credentials In Files | ShinyHunters has gathered PII from database infrastructure. | 166 | 32 | — |

### Discovery (TA0007) — 7

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1016](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1016) System Network Configuration Discovery | ShinyHunters has collected machine names and IP addresses by parsing the process scheduler configuration file psappsrv.cfg. | 99 | 10 | 5 |
| [T1018](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1018) Remote System Discovery | ShinyHunters has enumerated the internal subnet using ` cat /etc/hosts \| grep -E "[redacted_victim_string]"`. | 157 | 23 | 1 |
| [T1069.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1069.003) Cloud Groups | ShinyHunters has executed API calls to enumerate permissions for compromised AWS accounts. | 20 | — | — |
| [T1082](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1082) System Information Discovery | ShinyHunters has used the MeshCentral command-line utility meshctrl.js to collect hostnames and IDs of compromised systems. | 264 | 41 | — |
| [T1083](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1083) File and Directory Discovery | ShinyHunters has checked mount points for Oracle PeopleSoft configurations and has checked the process scheduler configuration file psappsrv.cfg. Additionally, ShinyHunters has read WebLogic server XML configurations files (config.xml). | 137 | 9 | — |
| [T1580](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1580) Cloud Infrastructure Discovery | ShinyHunters has used Amazon Simple Storage Service (S3) Browser and WinSCP to collect information on S3 bucket configurations. | 48 | 2 | — |
| [T1619](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1619) Cloud Storage Object Discovery | ShinyHunters has used Amazon Simple Storage Service (S3) Browser and WinSCP to access S3 objects. | 12 | 4 | — |

### Lateral Movement (TA0008) — 3

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1072](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1072) Software Deployment Tools | ShinyHunters has abused software deployment tools for lateral movement. | 59 | 3 | — |
| [T1210](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1210) Exploitation of Remote Services | ShinyHunters has exploited vulnerabilities in remote services for lateral movement. | 192 | — | 4 |
| [T1550.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1550.001) Application Access Token | ShinyHunters has used stolen OAuth keys to access cloud infrastructure and to bypass two-factor authentication. | 78 | — | — |

### Collection (TA0009) — 4

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1213.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1213.003) Code Repositories | ShinyHunters has gathered information from and has searched for vulnerabilities in the target company’s GitHub repository source code. | 21 | — | — |
| [T1213.006](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1213.006) Databases | ShinyHunters has collected Salesforce datasets from victims in the airline and retail sectors. | 2 | — | — |
| [T1530](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1530) Data from Cloud Storage | ShinyHunters has collected data from insecure cloud buckets. | 150 | 2 | — |
| [T1560.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1560.002) Archive via Library | ShinyHunters has used the following command to compress collected data: ` pv -s "$(du -sb exfil \| awk '{print $1}')" \| zstd -3 -T0 -o exfil.tar.zst `. | 6 | 4 | — |

### Command and Control (TA0011) — 4

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1090.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1090.003) Multi-hop Proxy | ShinyHunters has used Tor to host their DLS. | 44 | 4 | — |
| [T1105](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1105) Ingress Tool Transfer | ShinyHunters has deployed custom scripts to targeted systems from customized MeshAgents in their staging environment. | 644 | 39 | — |
| [T1219](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1219) Remote Access Tools | ShinyHunters has used MeshCentral and ConnectWise to gain initial access, to run administrative command queries and to deploy the custom lateral movement and defacement script [victim_abbreviation]_fanout.sh. | 119 | 15 | — |
| [T1573.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1573.002) Asymmetric Cryptography | ShinyHunters has established a connection between the staging host and the C2 using SSH. | 14 | — | — |

### Exfiltration (TA0010) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1567](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1567) Exfiltration Over Web Service | ShinyHunters has used compromised Salesforce CRM (Customer Relationship Management) dashboards to exfiltrate bulk data. Additionally, ShinyHunters has used LimeWire, a file-sharing service, to showcase samples of stolen data. | 162 | — | — |

### Impact (TA0040) — 3

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1485](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1485) Data Destruction | ShinyHunters has executed the `DeleteBucket` API call to delete buckets. | 215 | 5 | — |
| [T1491.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1491.001) Internal Defacement | ShinyHunters has left ransom notes titled README-IF-YOU-SEE-THIS-YOUVE-BEEN-HACKED.TXT. | 18 | 4 | — |
| [T1657](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1657) Financial Theft | ShinyHunters has called or sent text messages or emails to employees of victim organizations to demand payment in Bitcoin within 72 hours. Email addresses used in extortion activities include shinycorp@tuta[.]com, shinygroup@tuta[.]com, shinycorp@tutanota[.]co… | 2 | — | — |

## 4. Assinatura comportamental

Técnicas que este grupo usa e que poucos dos 178 grupos do ATT&CK usam. Pesam mais numa atribuição por TTP: ver várias delas juntas é mais informativo do que ver técnicas comuns como PowerShell.

| Técnica | Outros grupos que usam | Peso (raridade) |
|---|---:|---:|
| T1069.003 Cloud Groups | 0 | 4.49 |
| T1619 Cloud Storage Object Discovery | 0 | 4.49 |
| T1684 Social Engineering | 0 | 4.49 |
| T1195.001 Compromise Software Dependencies and Development Tools | 2 | 3.80 |
| T1560.002 Archive via Library | 2 | 3.80 |
| T1580 Cloud Infrastructure Discovery | 2 | 3.80 |
| T1059.009 Cloud API | 3 | 3.58 |
| T1213.003 Code Repositories | 3 | 3.58 |
| T1491.001 Internal Defacement | 3 | 3.58 |
| T1528 Steal Application Access Token | 3 | 3.58 |

## 5. Arsenal

| Software | Tipo | Técnicas no ATT&CK | Uso relatado (EN) |
|---|---|---:|---|
| [Tor](https://attack.mitre.org/software/S0183/) | ferramenta | 2 | ShinyHunters has used Tor for their DLS. |

## 6. Campanhas

Nenhuma campanha atribuída no ATT&CK.

## 7. Cobertura defensiva

**41 de 46 técnicas (89%)** têm ao menos uma regra pública no catálogo Detection Rules.

### Técnicas sem regra pública (prioridade para engenharia de detecção)

- **T1684 Social Engineering** — Stealth. Fonte de log sugerida pelo MITRE: `NSM:Connections` Outbound connection after script or installer launch; `WinEventLog:Sysmon` EventCode=1; `saas:okta` user.account.reset_password; user.mfa.factor.activate; app.oauth2.authorize; `m365
- **T1588.007 Artificial Intelligence** — Resource Development
- **T1583.004 Server** — Resource Development. Fonte de log sugerida pelo MITRE: `Internet Scan` None
- **T1598.003 Spearphishing Link** — Reconnaissance. Fonte de log sugerida pelo MITRE: `Application Log` None
- **T1585.002 Email Accounts** — Resource Development

### Regras recomendadas por técnica

Melhor regra disponível por técnica (formato portável e maduro primeiro).

| Técnica | Regra | Formato | Fonte |
|---|---|---|---|
| T1016 | [Potential Pikabot Discovery Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A698d4431-514f-4c82-af4d-cf573872a9f5) | Sigma | SigmaHQ |
| T1016 | [OpenCanary - SNMP OID Request](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae9856028-fd4e-46e6-b3d1-10f7ceb95078) | Sigma | SigmaHQ |
| T1018 | [Chopper Webshell Process Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Afa3c117a-bc0d-416e-a31b-0c0e80653efb) | Sigma | SigmaHQ |
| T1018 | [Webshell Hacking Activity Patterns](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4ebc877f-4612-45cb-b3a5-8e3834db36c9) | Sigma | SigmaHQ |
| T1036.005 | [Exploit for CVE-2015-1641](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A7993792c-5ce2-4475-a3db-a3a5539827ef) | Sigma | SigmaHQ |
| T1036.005 | [Exploit for CVE-2015-1641](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A7993792c-5ce2-4475-a3db-a3a5539827ef) | Sigma | OpenSearch Security Analytics |
| T1059.007 | [Adwind RAT / JRAT](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1fac1481-2dbc-48b2-9096-753c49b4ec71) | Sigma | SigmaHQ |
| T1059.007 | [WScript or CScript Dropper - File](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A002bdb95-0cf1-46a6-9e08-d38c128a6127) | Sigma | SigmaHQ |
| T1059.009 | [AWS IAM S3Browser User or AccessKey Creation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Adb014773-d9d9-4792-91e5-133337c0ffee) | Sigma | SigmaHQ |
| T1059.009 | [AWS IAM S3Browser Templated S3 Bucket Policy Creation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Adb014773-7375-4f4e-b83b-133337c0ffee) | Sigma | SigmaHQ |
| T1069.003 | [Azure AD Graph Potential Enumeration (ROADrecon)](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A80aa6cca-b343-457b-877e-5877cd71a1f8) | Elastic | Elastic detection-rules |
| T1069.003 | [Azure AD Graph Access with Suspicious User-Agent](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A3aec394d-ed2a-4f3e-8ed3-4a2adea39f05) | Elastic | Elastic detection-rules |
| T1072 | [Restricted Software Access By SRP](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab4c8da4a-1c12-46b0-8a2b-0a8521d03442) | Sigma | SigmaHQ |
| T1072 | [Suspicious Curl to Jamf Endpoint](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Aa8256685-9736-465b-b159-f25a172d08e8) | Elastic | Elastic detection-rules |
| T1078 | [Privilege Role Sign-In Outside Expected Controls](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acf1e5687-84e1-41af-97a9-158094efef53) | Sigma | SigmaHQ |
| T1078 | [OpenCanary - SSH Login Attempt](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aff7139bc-fdb1-4437-92f2-6afefe8884cb) | Sigma | SigmaHQ |
| T1078.002 | [Malicious Usage Of IMDS Credentials Outside Of AWS Infrastructure](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A352a918a-34d8-4882-8470-44830c507aa3) | Sigma | SigmaHQ |
| T1078.002 | [AdminSDHolder SDProp Exclusion Added](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A61d29caf-6c15-4d1e-9ccb-7ad12ccc0bc7) | Elastic | Elastic detection-rules |
| T1078.004 | [Okta New Admin Console Behaviours](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aa0b38b70-3cb5-484b-a4eb-c4d8e7bcc0a9) | Sigma | SigmaHQ |
| T1078.004 | [AWS IAM S3Browser User or AccessKey Creation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Adb014773-d9d9-4792-91e5-133337c0ffee) | Sigma | SigmaHQ |
| T1082 | [Potential GobRAT File Discovery Via Grep](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae34cfa0c-0a50-4210-9cb3-5632d08eb041) | Sigma | SigmaHQ |
| T1082 | [System Information Discovery](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A42df45e7-e6e9-43b5-8f26-bec5b39cc239) | Sigma | SigmaHQ |
| T1083 | [Turla Group Lateral Movement](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac601f20d-570a-4cde-a7d6-e17f99cb8e7f) | Sigma | SigmaHQ |
| T1083 | [WannaCry Ransomware Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A41d40bff-377a-43e2-8e1b-2e543069e079) | Sigma | SigmaHQ |
| T1090.003 | [Tor Client/Browser Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A62f7c9bf-9135-49b2-8aeb-1e54a6ecc13c) | Sigma | SigmaHQ |
| T1090.003 | [Query Tor Onion Address - DNS Client](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A8384bd26-bde6-4da9-8e5d-4174a7a47ca2) | Sigma | SigmaHQ |
| T1105 | [Greenbug Espionage Group Indicators](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A3711eee4-a808-4849-8a14-faf733da3612) | Sigma | SigmaHQ |
| T1105 | [Pandemic Registry Key](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A47e0852a-cf81-4494-a8e6-31864f8c86ed) | Sigma | SigmaHQ |
| T1110 | [Hack Tool User Agent](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac42a3073-30fb-48ae-8c99-c23ada84b103) | Sigma | SigmaHQ |
| T1110 | [HackTool - CrackMapExec Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A42a993dd-bb3e-48c8-b372-4d6684c4106c) | Sigma | SigmaHQ |
| T1190 | [OMIGOD HTTP No Authentication RCE - CVE-2021-38647](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aab6b1a39-a9ee-4ab4-b075-e83acf6e346b) | Sigma | SigmaHQ |
| T1190 | [Exploited CVE-2020-10189 Zoho ManageEngine](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A846b866e-2a57-46ee-8e16-85fa92759be7) | Sigma | OpenSearch Security Analytics |
| T1195.001 | [Outdated Dependency Or Vulnerability Alert Disabled](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A34e1c7d4-0cd5-419d-9f1b-1dad3f61018d) | Sigma | SigmaHQ |
| T1195.001 | [Octopus Scanner Malware](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A805c55d9-31e6-4846-9878-c34c75054fe9) | Sigma | SigmaHQ |
| T1203 | [Droppers Exploiting CVE-2017-11882](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A678eb5f4-8597-4be6-8be7-905e4234b53a) | Sigma | SigmaHQ |
| T1203 | [OMIGOD HTTP No Authentication RCE - CVE-2021-38647](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aab6b1a39-a9ee-4ab4-b075-e83acf6e346b) | Sigma | SigmaHQ |
| T1210 | [OMIGOD HTTP No Authentication RCE - CVE-2021-38647](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aab6b1a39-a9ee-4ab4-b075-e83acf6e346b) | Sigma | SigmaHQ |
| T1210 | [OMIGOD HTTP No Authentication RCE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Aab6b1a39-a9ee-4ab4-b075-e83acf6e346b) | Sigma | OpenSearch Security Analytics |
| T1213.003 | [Bitbucket Unauthorized Full Data Export Triggered](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A34d81081-03c9-4a7f-91c9-5e46af625cde) | Sigma | SigmaHQ |
| T1213.003 | [Bitbucket Full Data Export Triggered](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A195e1b9d-bfc2-4ffa-ab4e-35aef69815f8) | Sigma | SigmaHQ |
| T1213.006 | [AWS RDS Snapshot Export](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A119c8877-8613-416d-a98a-96b6664ee73a) | Elastic | Elastic detection-rules |
| T1213.006 | [AWS Secrets Manager Rapid Secrets Retrieval](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A185c782e-f86a-11ee-9d9f-f661ea17fbce) | Elastic | Elastic detection-rules |
| T1219 | [Renamed Visual Studio Code Tunnel Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A2cf29f11-e356-4f61-98c0-1bdb9393d6da) | Sigma | SigmaHQ |
| T1219 | [Hijack Legit RDP Session to Move Laterally](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A52753ea4-b3a0-4365-910d-36cff487b789) | Sigma | OpenSearch Security Analytics |
| T1485 | [Fsutil Suspicious Invocation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aadd64136-62e5-48ea-807e-88638d02df1e) | Sigma | SigmaHQ |
| T1485 | [Potential BlackByte Ransomware Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A999e8307-a775-4d5f-addc-4855632335be) | Sigma | SigmaHQ |
| T1491.001 | [Potential Ransomware Activity Using LegalNotice Message](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A8b9606c9-28be-4a38-b146-0e313cc232c1) | Sigma | SigmaHQ |
| T1491.001 | [Potentially Suspicious Desktop Background Change Using Reg.EXE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A8cbc9475-8d05-4e27-9c32-df960716c701) | Sigma | SigmaHQ |
| T1528 | [Renamed BrowserCore.EXE Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A8a4519e8-e64a-40b6-ae85-ba8ad2177559) | Sigma | SigmaHQ |
| T1528 | [HackTool - Koh Default Named Pipe](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A0adc67e0-a68f-4ffd-9c43-28905aad5d6a) | Sigma | SigmaHQ |
| T1530 | [Google Workspace Drive Encryption Key(s) Accessed from Anonymous User](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A980b70a0-c820-11ed-8799-f661ea17fbcc) | Elastic | Elastic detection-rules |
| T1530 | [AWS CloudTrail Log Updated](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A3e002465-876f-4f04-b016-84ef48ce7e5d) | Elastic | Elastic detection-rules |
| T1550.001 | [AWS EC2 Instance Console Login via Assumed Role](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ad1e5e410-3e34-412e-9b1f-dd500b3b55cd) | Elastic | Elastic detection-rules |
| T1550.001 | [AWS First Occurrence of STS GetFederationToken Request by User](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A7a5cc9a8-5ea3-11ef-beec-f661ea17fbce) | Elastic | Elastic detection-rules |
| T1552.001 | [Potential Russian APT Credential Theft Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab83f5166-9237-4b5e-9cd4-7b5d52f4d8ee) | Sigma | SigmaHQ |
| T1552.001 | [Copy Passwd Or Shadow From TMP Path](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Afa4aaed5-4fe0-498d-bbc0-08e3346387ba) | Sigma | SigmaHQ |
| T1560.002 | [GenAI Process Performing Encoding/Chunking Prior to Network Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ac3d4e5f6-a7b8-9012-cdef-123456789abc) | Elastic | Elastic detection-rules |
| T1560.002 | [PowerShell Script with Archive Compression Capabilities](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A27071ea3-e806-4697-8abc-e22c92aa4293) | Elastic | Elastic detection-rules |
| T1567 | [Monero Crypto Coin Mining Pool Lookup](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab593fd50-7335-4682-a36c-4edcb68e4641) | Sigma | SigmaHQ |
| T1567 | [Monero Crypto Coin Mining Pool Lookup](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Ab593fd50-7335-4682-a36c-4edcb68e4641) | Sigma | OpenSearch Security Analytics |
| T1573.002 | [Potential Self-Signed TLS Certificate Recently Issued on External Connection](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A869fe008-5dd4-4f07-9c2e-aa90c3926fd9) | Elastic | Elastic detection-rules |
| T1573.002 | [Openssl Client or Server Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Aad5a3757-c872-4719-8c72-12d3f08db655) | Elastic | Elastic detection-rules |
| T1580 | [AWS Discovery API Calls from VPN ASN for the First Time by Identity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ae3c7a891-4b2d-4e8c-a1f0-9d8e7c6b5a4d) | Elastic | Elastic detection-rules |
| T1580 | [Entra ID Sign-in BloodHound Suite User-Agent Detected](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ac28750fa-4092-11f0-aca6-f661ea17fbcd) | Elastic | Elastic detection-rules |
| T1583.001 | [AWS Route 53 Private Hosted Zone Associated With a VPC](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ae3c27562-709a-42bd-82f2-3ed926cced19) | Elastic | Elastic detection-rules |
| T1583.001 | [AWS SES Email Identity Verified Then Deleted](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A8e4bde35-125d-4eb3-9a2e-d7e77a053a08) | Elastic | Elastic detection-rules |
| T1587.004 | [MS Graph message: Indicators of vulnerability exploitation on the system have been detected. However, this ale](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=wazuh-ruleset-oficial%3A%3Awazuh-99549) | Wazuh | Wazuh ruleset (oficial) |
| T1587.004 | [MS Graph message: Indicators of vulnerability exploitation on the system have been detected. This alert may be](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=wazuh-ruleset-oficial%3A%3Awazuh-99568) | Wazuh | Wazuh ruleset (oficial) |
| T1588.002 | [Hacktool Execution - Imphash](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A24e3e58a-646b-4b50-adef-02ef935b9fc8) | Sigma | SigmaHQ |
| T1588.002 | [Renamed SysInternals DebugView Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acd764533-2e07-40d6-a718-cfeec7f2da7f) | Sigma | SigmaHQ |
| T1589.001 | [Linux Medusa Rootkit](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=splunk-security-content%3A%3A7add8520-71d5-43aa-b262-ee082b1f0238) | Splunk | Splunk security_content |
| T1589.001 | [MS Graph message: A user's credentials were compromised or stolen. This is a true positive alert.](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=wazuh-ruleset-oficial%3A%3Awazuh-99612) | Wazuh | Wazuh ruleset (oficial) |
| T1593.003 | [Suspicious Git Clone - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acfec9d29-64ec-4a0f-9ffe-0fdb856d5446) | Sigma | SigmaHQ |
| T1593.003 | [Suspicious Git Clone](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aaef9d1f1-7396-4e92-a927-4567c7a495c1) | Sigma | SigmaHQ |
| T1595.002 | [DNS Query to External Service Interaction Domains](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aaff715fa-4dd5-497a-8db3-910bea555566) | Sigma | SigmaHQ |
| T1595.002 | [Web Server Potential SQL Injection Request](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A7f7a0ee1-7b6f-466a-85b4-110fb105f5e2) | Elastic | Elastic detection-rules |
| T1598 | [CyberBlindSpot - Any Issue Detected](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3Aabe1a662-d00d-482e-aa68-9394622ae02e) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1598 | [Proofpoint Phishing Email Detected](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=panther-panther-analysis%3A%3AProofpoint.PhishingDetected) | Panther | Panther panther-analysis |
| T1619 | [Potential Bucket Enumeration on AWS](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Af305fd62-beca-47da-ad95-7690a0620084) | Sigma | SigmaHQ |
| T1619 | [AWS S3 Rapid Bucket Posture API Calls from a Single Principal](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Aa7577205-88a1-4a08-85d4-7b72a9a2e969) | Elastic | Elastic detection-rules |
| T1657 | [AWS S3 Bucket Enumeration or Brute Force](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A5f0234fd-7f21-42af-8391-511d5fd11d5c) | Elastic | Elastic detection-rules |
| T1657 | [Monitor ransomwarelive for companies of interest on ransowmare data leak sites (DLS)](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=bert-janp-hunting-queries%3A%3A8b9af12a820a) | KQL hunting | Bert-JanP Hunting Queries |

## 8. Plano de emulação e validação

Use num laboratório isolado e autorizado para confirmar que as regras disparam. Os comandos estão nos repositórios oficiais.

| Tática | Técnica | Teste Atomic Red Team | Plataformas |
|---|---|---|---|
| Execution | [T1059.007](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.007/T1059.007.md) | JScript execution to gather local computer information via cscript | windows |
| Execution | [T1059.007](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.007/T1059.007.md) | JScript execution to gather local computer information via wscript | windows |
| Execution | [T1072](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1072/T1072.md) | Radmin Viewer Utility | windows |
| Execution | [T1072](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1072/T1072.md) | PDQ Deploy RAT | windows |
| Stealth | [T1036.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.005/T1036.005.md) | Execute a process from a directory masquerading as the current parent directory | linux, macos |
| Stealth | [T1036.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.005/T1036.005.md) | Masquerade as a built-in system executable | windows |
| Stealth | [T1078.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1078.004/T1078.004.md) | Creating GCP Service Account and Service Account Key | google-workspace, iaas:gcp |
| Stealth | [T1078.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1078.004/T1078.004.md) | Azure Persistence Automation Runbook Created or Modified | iaas:azure |
| Credential Access | [T1528](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1528/T1528.md) | Azure - Functions code upload - Functions code injection via Blob upload | iaas:azure |
| Credential Access | [T1528](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1528/T1528.md) | Azure - Functions code upload - Functions code injection via File Share modification to retrieve the Functions identity  | iaas:azure |
| Credential Access | [T1552.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1552.001/T1552.001.md) | Find AWS credentials | linux, macos |
| Credential Access | [T1552.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1552.001/T1552.001.md) | Extract Browser and System credentials with LaZagne | macos |
| Discovery | [T1016](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1016/T1016.md) | System Network Configuration Discovery on Windows | windows |
| Discovery | [T1016](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1016/T1016.md) | List Windows Firewall Rules | windows |
| Discovery | [T1018](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1018/T1018.md) | Remote System Discovery - net | windows |
| Discovery | [T1018](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1018/T1018.md) | Remote System Discovery - net group Domain Computers | windows |
| Discovery | [T1082](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1082/T1082.md) | System Information Discovery | windows |
| Discovery | [T1082](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1082/T1082.md) | System Information Discovery | macos |
| Discovery | [T1083](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1083/T1083.md) | File and Directory Discovery (cmd.exe) | windows |
| Discovery | [T1083](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1083/T1083.md) | File and Directory Discovery (PowerShell) | windows |
| Discovery | [T1580](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1580/T1580.md) | AWS - EC2 Enumeration from Cloud Instance | iaas:aws, linux, macos |
| Discovery | [T1580](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1580/T1580.md) | AWS - EC2 Security Group Enumeration | iaas:aws |
| Discovery | [T1619](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1619/T1619.md) | AWS S3 Enumeration | iaas:aws |
| Discovery | [T1619](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1619/T1619.md) | Azure - Enumerate Storage Account Objects via Shared Key authorization using Azure CLI | iaas:azure |
| Collection | [T1530](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1530/T1530.md) | AWS - Scan for Anonymous Access to S3 | iaas:aws |
| Collection | [T1530](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1530/T1530.md) | Azure - Dump Azure Storage Account Objects via Azure CLI | iaas:azure |
| Collection | [T1560.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1560.002/T1560.002.md) | Compressing data using GZip in Python (FreeBSD/Linux) | linux |
| Collection | [T1560.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1560.002/T1560.002.md) | Compressing data using bz2 in Python (FreeBSD/Linux) | linux |
| Command and Control | [T1090.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1090.003/T1090.003.md) | Psiphon | windows |
| Command and Control | [T1090.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1090.003/T1090.003.md) | Tor Proxy Usage - Windows | windows |
| Command and Control | [T1105](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1105/T1105.md) | rsync remote file copy (push) | linux, macos |
| Command and Control | [T1105](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1105/T1105.md) | rsync remote file copy (pull) | linux, macos |
| Command and Control | [T1219](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1219/T1219.md) | TeamViewer Files Detected Test on Windows | windows |
| Command and Control | [T1219](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1219/T1219.md) | AnyDesk Files Detected Test on Windows | windows |
| Impact | [T1485](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1485/T1485.md) | Windows - Overwrite file with SysInternals SDelete | windows |
| Impact | [T1485](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1485/T1485.md) | FreeBSD/macOS/Linux - Overwrite file with DD | linux, macos |
| Impact | [T1491.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1491.001/T1491.001.md) | Replace Desktop Wallpaper | windows |
| Impact | [T1491.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1491.001/T1491.001.md) | Configure LegalNoticeCaption and LegalNoticeText registry keys to display ransom message | windows |

**Logs reais de ataque (EVTX) para testar sem executar nada:**

- T1016 — [ID4688-Audit policy enumerated](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1016-System%20Network%20Configuration%20Discovery/ID4688-Audit%20policy%20enumerated.evtx) _(explícito)_
- T1016 — [ID4688-Firewall configuration enumerated (command)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1016-System%20Network%20Configuration%20Discovery/ID4688-Firewall%20configuration%20enumerated%20%28command%29.evtx) _(explícito)_
- T1018 — [ID5145-DNS hosts files access via network share](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1018-Remote%20System%20Discovery/ID5145-DNS%20hosts%20files%20access%20via%20network%20share.evtx) _(explícito)_
- T1078 — [ID1149-RDP success logins to multiple hosts](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0001-Initial%20access/T1078-Valid%20accounts/ID1149-RDP%20success%20logins%20to%20multiple%20hosts.evtx) _(explícito)_
- T1078 — [ID33205-SQL Server failed login with disabled SA account](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0001-Initial%20access/T1078-Valid%20accounts/ID33205-SQL%20Server%20failed%20login%20with%20disabled%20SA%20account.evtx) _(explícito)_
- T1078.002 — [ID4964-Login of a member of a special group](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0005-Defense%20Evasion/T1078.002-Valid%20accounts-Domain%20accounts/ID4964-Login%20of%20a%20member%20of%20a%20special%20group.evtx) _(explícito)_
- T1110 — [ID 4776,4625-AccountRestore local bruteforce](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0006-Credential%20Access/T1110.xxx-Brut%20force/ID%204776%2C4625-AccountRestore%20local%20bruteforce.evtx) _(explícito)_
- T1110 — [ID18456-SQL Server failed login because only Windows auth](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0006-Credential%20Access/T1110.xxx-Brut%20force/ID18456-SQL%20Server%20failed%20login%20because%20only%20Windows%20auth.evtx) _(explícito)_
- T1210 — [Zerologon_CVE-2020-1472_DFIR_System_NetLogon_Error_EventID_5805](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Credential%20Access/Zerologon_CVE-2020-1472_DFIR_System_NetLogon_Error_EventID_5805.evtx) _(inferido)_
- T1210 — [Zerologon_VoidSec_CVE-2020-1472_4626_LT3_Anonym_follwedby_4742_DC_Anony_DC](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Credential%20Access/Zerologon_VoidSec_CVE-2020-1472_4626_LT3_Anonym_follwedby_4742_DC_Anony_DC.evtx) _(inferido)_

## 9. Hipóteses de hunting

Se ShinyHunters estiver no seu ambiente, estas são as perguntas a fazer aos seus dados (fontes de log segundo as estratégias de detecção do MITRE ATT&CK).

1. **T1069.003 Cloud Groups** — Detects adversarial use of cloud-native APIs (e.g., AWS IAM, Azure RBAC, GCP Identity) to enumerate cloud group memberships or policy mappings via unauthorized sessions or scripts. Dados: `AWS:CloudTrail` (ListGroups, ListAttachedRolePolicies).
2. **T1619 Cloud Storage Object Discovery** — Detection of suspicious enumeration of cloud storage objects via API calls such as AWS S3 ListObjectsV2, Azure List Blobs, or GCP ListObjects. Correlate access with account role, user context, and prior authentication activity to identify anomalous usage… Dados: `AWS:CloudTrail` (ListObjectsV2), `AWS:CloudTrail` (GetObject, CopyObject).
3. **T1684 Social Engineering** — Detects users executing commands copied from chats, tickets, or emails, including curl|bash patterns, shell script launches from temp directories, credential changes, or SSH key additions shortly after communication events. Dados: `NSM:Connections` (Outbound connection after script or installer launch), `auditd:EXECVE` (execve of curl,wget,bash,sh,python with piped or remote content), `auditd:PATH` (odification of ~/.ssh/authorized_keys or credential files).
4. **T1195.001 Compromise Software Dependencies and Development Tools** — Adversary manipulates dependencies/dev tools used by developers or CI: a package manager (npm/yarn/pnpm, pip/pipenv, nuget/dotnet, chocolatey/winget, maven/gradle) or a compiler/IDE downloads or restores content; files are written under project paths and… Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=7), `WinEventLog:Sysmon` (EventCode=11).
5. **T1560.002 Archive via Library** — Detects adversarial archiving using libraries (zlib, zip APIs) invoked by scripts or binaries. Correlates process executions of Python, PowerShell, or custom .NET binaries with DLL/module loads linked to compression libraries, followed by archive file… Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=7), `WinEventLog:Sysmon` (EventCode=11).
6. **T1580 Cloud Infrastructure Discovery** — Defenders should monitor for suspicious enumeration of cloud infrastructure components via APIs or CLI tools. Observable behaviors include repeated listing or description operations for compute instances, snapshots, storage buckets, and volumes. From a… Dados: `AWS:CloudTrail` (DescribeInstances), `AWS:CloudTrail` (ListBuckets), `AWS:CloudTrail` (DescribeDBInstances).
7. **T1059.009 Cloud API** — Detects adversarial use of cloud APIs for command execution, resource control, or reconnaissance. Focuses on CLI/SDK/scripting language abuse via stolen credentials or in-browser Cloud Shells. Monitors for anomalous API calls chained with authentication… Dados: `AWS:CloudTrail` (eventName: RunInstances, CreateUser, PutRolePolicy, InvokeCommand), `azure:activity` (operationName: Write, Access Review, RoleAssignment), `Okta:SystemLog` (eventType: user.authentication.sso, app.oauth2.token.grant).
8. **T1213.003 Code Repositories** — Anomalous or bulk download activity from private or restricted repositories by non-developer or privileged accounts, often preceded by unusual login behavior (e.g., unfamiliar geo, OAuth token use, elevated API rate). Dados: `saas:github` (repo.download, repo.clone, oauth.authorize, repo.getContent), `saas:github` (Login from unusual IP, device fingerprint, or location; access token creation from new client), `saas:github` (Bulk access to multiple files or large volume of repo requests within short time window).
9. **T1491.001 Internal Defacement** — Adversary modifies internal UI messages (e.g., login banners, desktop wallpapers) or hosted intranet web pages by creating or altering content files using scripts or unauthorized access. Often preceded by privilege escalation or web shell deployment. Dados: `WinEventLog:Security` (EventCode=4663, 4670, 4656), `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Sysmon` (EventCode=2).
10. **T1528 Steal Application Access Token** — Access and retrieval of container service account tokens followed by unauthorized API requests using those tokens to interact with the Kubernetes API server or internal services. Dados: `kubernetes:audit` (GET or LIST requests to /var/run/secrets/kubernetes.io/serviceaccount/ followed by access to the Kubernetes API server).
11. **T1550.001 Application Access Token** — Use of AWS STS or GCP IAM APIs to request temporary tokens or federation sessions inconsistent with normal account activity, including from unexpected principals or regions. Dados: `AWS:CloudTrail` (AssumeRole, GetFederationToken, GetSessionToken), `AWS:CloudTrail` (sts:GetFederationToken).
12. **T1213.006 Databases** — Unusual database command-line access (e.g., `psql`, `mysql`, `mongo`) from non-admin users, occurring outside typical automation windows or without known service context. Often followed by data dumps to .sql/.csv files or outbound data transfers. Defender… Dados: `auditd:SYSCALL` (execve: Execution of CLI tools like psql, mysql, mongo, sqlite3), `auditd:PATH` (Creation of files with extensions .sql, .csv, .sqlite, especially in user directories), `NSM:Flow` (http::post: Outbound HTTP POST from host shortly after DB export activity).

## 10. OSINT — onde pesquisar

Consultas prontas com todos os nomes conhecidos do grupo:

- Relatórios técnicos: [busca web](https://duckduckgo.com/?q=%28%22ShinyHunters%22+OR+%22UNC6240%22+OR+%22Bling+Libra%22%29+threat+report) · [PDFs](https://duckduckgo.com/?q=%28%22ShinyHunters%22+OR+%22UNC6240%22+OR+%22Bling+Libra%22%29+filetype%3Apdf)
- Regras e IOCs publicados: [GitHub](https://github.com/search?type=code&q=%22ShinyHunters%22+OR+%22UNC6240%22+OR+%22Bling+Libra%22)
- Pulsos de ameaça: [AlienVault OTX](https://otx.alienvault.com/browse/global/pulses?q=ShinyHunters)
- Família de malware e atores: [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/actors) (busque por ShinyHunters, UNC6240, Bling Libra)
- Cartões de grupo: [ThaiCERT Threat Group Cards](https://apt.etda.or.th/cgi-bin/listgroups.cgi)
- Página oficial: [MITRE ATT&CK G1057](https://attack.mitre.org/groups/G1057/)

## 11. Bibliografia (8 fontes citadas pelo ATT&CK)

- [ElecticIQ Buyukkaya_ShinyHunters_Sept2025](https://blog.eclecticiq.com/shinyhunters-calling-financially-motivated-data-extortion-group-targeting-enterprise-cloud-applications) — Büyükkaya, A. (2025, September 22). ShinyHunters Calling: Financially Motivated Data Extortion Group Targeting Enterprise Cloud Applications. Retrieved May 18, 2026.
- [FBI_SHLMS_May2026](https://www.ic3.gov/PSA/2026/PSA260515) — Federal Bureau of Investigation. (2026, May 15). ShinyHunters: Cyber Criminal Group Attacks Learning Management System. Retrieved July 1, 2026.
- [Google Salesforce JUN 2025](https://cloud.google.com/blog/topics/threat-intelligence/voice-phishing-data-extortion) — Google Threat Intelligence Group. (2025, June 4). The Cost of a Call: From Voice Phishing to Data Extortion. Retrieved October 22, 2025.
- [Google_SHOracle_Jun2026](https://cloud.google.com/blog/topics/threat-intelligence/shinyhunters-targets-education-sector-oracle-exploit) — Mandiant, Google Threat Intelligence Group. (2026, June 11). ShinyHunters Targets Education Sector with Oracle PeopleSoft Exploit. Retrieved June 11, 2026.
- [Intel471_SH_Aug2021](https://www.intel471.com/blog/shinyhunters-data-breach-mitre-attack) — Intel 471. (2021, August 23). Here’s how to guard your enterprise against ShinyHunters. Retrieved July 29, 2026.
- [Mandiant_SHDataTheft_Jan2026](https://cloud.google.com/blog/topics/threat-intelligence/expansion-shinyhunters-saas-data-theft) — Mandiant. (2026, January 30). Vishing for Access: Tracking the Expansion of ShinyHunters-Branded SaaS Data Theft. Retrieved June 16, 2026.
- [SOCRadar_ShinyHunters_Mar2024](https://socradar.io/dark-web-profile-shinyhunters/) — SOCRadar. (2024, March 18). Dark Web Profile: ShinyHunters. Retrieved May 18, 2026.
- [Unit42KelleyVaya_BlingLibra_Aug2024](https://unit42.paloaltonetworks.com/shinyhunters-ransomware-extortion/) — Kelley, M., Vaya, C. (2024, August 23). Bling Libra’s Tactical Evolution: The Threat Actor Group Behind ShinyHunters Ransomware. Retrieved May 18, 2026.

## 12. Limites e confiança

- O ATT&CK registra o que foi **relatado publicamente**, não tudo o que o grupo faz. Ausência de uma técnica não prova que o grupo não a usa.
- **Sobreposição de TTP não é atribuição.** Muitas técnicas são compartilhadas entre grupos e com red teams. Use a assinatura comportamental como hipótese, junto com infraestrutura, malware e contexto.
- Cobertura de detecção refere-se ao catálogo público Detection Rules, não ao seu ambiente: confira se a telemetria necessária chega ao seu SIEM.
- Ligações marcadas como _inferidas_ (EVTX por palavra-chave, relatórios por nome) devem ser verificadas.

---
Fontes: MITRE ATT&CK® (uso livre com atribuição, © The MITRE Corporation), Atomic Red Team (Red Canary, MIT), EVTX-to-MITRE-Attack, EVTX-ATTACK-SAMPLES, APT & CyberCriminal Campaign Collections. Gerado por [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules).
