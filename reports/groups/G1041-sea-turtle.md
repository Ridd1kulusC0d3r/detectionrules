# Sea Turtle (G1041) — Dossiê de inteligência

> **TLP:CLEAR** · gerado em 2026-10-25 a partir de fontes abertas · MITRE ATT&CK v20.0 · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1041) · [ATT&CK](https://attack.mitre.org/groups/G1041/)

**Também conhecido como:** Teal Kurma, Marbled Dust, Cosmic Wolf, SILICON  
**Registro no ATT&CK:** criado em 2024-11-20, atualizado em 2026-07-31 · referências de 2019 a 2024

## 1. Sumário executivo

- **27 técnicas** atribuídas publicamente, concentradas em **Resource Development, Initial Access, Collection**.
- **Arsenal:** 1 malware e 0 ferramentas (ex.: SnappyTCP).
- **Campanhas atribuídas:** 0.
- **Cobertura de detecção pública:** 89% das técnicas têm ao menos uma regra no catálogo; **3 técnicas sem nenhuma regra pública**.
- **Assinatura comportamental** (técnicas raras entre os 178 grupos, as mais úteis para atribuição): T1608.003 Install Digital Certificate, T1584.002 DNS Server, T1557 Adversary-in-the-Middle, T1583.002 DNS Server, T1027.004 Compile After Delivery.

## 2. Quem é

> Sea Turtle is a Türkiye-linked threat actor active since at least 2017 performing espionage and service provider compromise operations against victims in Asia, Europe, and North America. Sea Turtle is notable for targeting registrars managing ccTLDs and complex DNS-based intrusions where the threat actor compromised DNS providers to hijack DNS resolution for ultimate victims, enabling Sea Turtle to spoof log in portals and other applications for credential collection.

_Texto original do MITRE ATT&CK, em inglês._

## 3. Perfil TTP por tática (kill chain)

Cada linha: técnica, como o grupo a usou segundo relatos públicos, e o que existe para detectar e testar.

### Resource Development (TA0042) — 8

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1583](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1583) Acquire Infrastructure | Sea Turtle accessed victim networks from VPN service provider networks. | 9 | — | — |
| [T1583.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1583.001) Domains | Sea Turtle registered domains for authoritative name servers used in DNS hijacking activity and for command and control servers. | 7 | — | — |
| [T1583.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1583.002) DNS Server | Sea Turtle built adversary-in-the-middle DNS servers to impersonate legitimate services that were later used to capture credentials. | **0** | — | — |
| [T1583.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1583.003) Virtual Private Server | Sea Turtle created adversary-in-the-middle servers to impersonate legitimate services and enable credential capture. | **0** | — | — |
| [T1584.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1584.002) DNS Server | Sea Turtle modified Name Server (NS) items to refer to Sea Turtle-controlled DNS servers to provide responses for all DNS lookups. | 4 | — | — |
| [T1588.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1588.002) Tool | Sea Turtle has used tools such as Adminer during intrusions. | 35 | — | — |
| [T1588.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1588.004) Digital Certificates | Sea Turtle created new certificates using a technique called the actors performed "certificate impersonation," a technique in which Sea Turtle obtained a certificate authority-signed X.509 certificate from another provider for the same domain imitating the one… | 1 | — | — |
| [T1608.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1608.003) Install Digital Certificate | Sea Turtle captured legitimate SSL certificates from victim organizations and installed these on Sea Turtle-controlled infrastructure to enable subsequent adversary-in-the-middle operations. | 1 | — | — |

### Initial Access (TA0001) — 6

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | Sea Turtle used compromised credentials to maintain long-term access to victim environments. | 825 | — | 3 |
| [T1078.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.003) Local Accounts | Sea Turtle compromised cPanel accounts in victim environments. | 32 | 13 | — |
| [T1133](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1133) External Remote Services | Sea Turtle has used external-facing SSH to achieve initial access to the IT environments of victim organizations. | 361 | 1 | — |
| [T1190](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1190) Exploit Public-Facing Application | Sea Turtle gained access to victim environments by exploiting multiple known vulnerabilities over several campaigns. | 580 | — | — |
| [T1199](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1199) Trusted Relationship | Sea Turtle targeted third-party entities in trusted relationships with primary targets to ultimately achieve access at primary targets. Entities targeted included DNS registrars, telecommunication companies, and internet service providers. | 18 | — | — |
| [T1566](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1566) Phishing | Sea Turtle used spear phishing to gain initial access to victims. | 286 | — | — |

### Execution (TA0002) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1059.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.004) Unix Shell | Sea Turtle used shell scripts for post-exploitation execution in victim environments. | 395 | 17 | — |
| [T1203](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1203) Exploitation for Client Execution | Sea Turtle has used exploits for vulnerabilities such as CVE-2021-44228, CVE-2021-21974, and CVE-2022-0847 to achieve client code execution. | 202 | — | — |

### Persistence (TA0003) — 4

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | Sea Turtle used compromised credentials to maintain long-term access to victim environments. | 825 | — | 3 |
| [T1078.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.003) Local Accounts | Sea Turtle compromised cPanel accounts in victim environments. | 32 | 13 | — |
| [T1133](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1133) External Remote Services | Sea Turtle has used external-facing SSH to achieve initial access to the IT environments of victim organizations. | 361 | 1 | — |
| [T1505.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1505.003) Web Shell | Sea Turtle deployed the SnappyTCP web shell during intrusion operations. | 210 | 1 | — |

### Privilege Escalation (TA0004) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | Sea Turtle used compromised credentials to maintain long-term access to victim environments. | 825 | — | 3 |
| [T1078.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.003) Local Accounts | Sea Turtle compromised cPanel accounts in victim environments. | 32 | 13 | — |

### Stealth (TA0005) — 4

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1027.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1027.004) Compile After Delivery | Sea Turtle downloaded source code files from remote addresses then compiled them locally via GCC in victim environments. | 32 | 5 | — |
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | Sea Turtle used compromised credentials to maintain long-term access to victim environments. | 825 | — | 3 |
| [T1078.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.003) Local Accounts | Sea Turtle compromised cPanel accounts in victim environments. | 32 | 13 | — |
| [T1564.011](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1564.011) Ignore Process Interrupts | Sea Turtle executed SnappyTCP using the tool NoHup, which keeps the malware running on a system after exiting the shell or terminal. | **0** | — | — |

### Defense Impairment (TA0112) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1685.006](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1685.006) Clear Linux or Mac System Logs | Sea Turtle has overwritten Linux system logs and unsets the Bash history file (effectively removing logging) during intrusions. | 23 | 20 | — |
| [T1690](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1690) Prevent Command History Logging | Sea Turtle unset the Bash and MySQL history files on victim systems. | 12 | 12 | — |

### Credential Access (TA0006) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1557](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1557) Adversary-in-the-Middle | Sea Turtle modified DNS records at service providers to redirect traffic from legitimate resources to Sea Turtle-controlled servers to enable adversary-in-the-middle attacks for credential capture. | 67 | — | 2 |

### Collection (TA0009) — 5

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1074.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1074.002) Remote Data Staging | Sea Turtle staged collected email archives in the public web directory of a website that was accessible from the internet. | 5 | — | — |
| [T1114.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1114.001) Local Email Collection | Sea Turtle collected email archives from victim environments. | 15 | 1 | — |
| [T1213.006](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1213.006) Databases | Sea Turtle used the tool Adminer to remotely logon to the MySQL service of victim machines. | 2 | — | — |
| [T1557](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1557) Adversary-in-the-Middle | Sea Turtle modified DNS records at service providers to redirect traffic from legitimate resources to Sea Turtle-controlled servers to enable adversary-in-the-middle attacks for credential capture. | 67 | — | 2 |
| [T1560.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1560.001) Archive via Utility | Sea Turtle used the tar utility to create a local archive of email data on a victim system. | 76 | 13 | — |

### Command and Control (TA0011) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1071.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1071.001) Web Protocols | Sea Turtle connected over TCP using HTTP to establish command and control channels. | 228 | 3 | — |

## 4. Assinatura comportamental

Técnicas que este grupo usa e que poucos dos 178 grupos do ATT&CK usam. Pesam mais numa atribuição por TTP: ver várias delas juntas é mais informativo do que ver técnicas comuns como PowerShell.

| Técnica | Outros grupos que usam | Peso (raridade) |
|---|---:|---:|
| T1608.003 Install Digital Certificate | 0 | 4.49 |
| T1584.002 DNS Server | 1 | 4.09 |
| T1557 Adversary-in-the-Middle | 2 | 3.80 |
| T1583.002 DNS Server | 2 | 3.80 |
| T1027.004 Compile After Delivery | 3 | 3.58 |
| T1564.011 Ignore Process Interrupts | 3 | 3.58 |
| T1685.006 Clear Linux or Mac System Logs | 3 | 3.58 |
| T1690 Prevent Command History Logging | 3 | 3.58 |
| T1213.006 Databases | 5 | 3.24 |
| T1588.004 Digital Certificates | 6 | 3.11 |

## 5. Arsenal

| Software | Tipo | Técnicas no ATT&CK | Uso relatado (EN) |
|---|---|---:|---|
| [SnappyTCP](https://attack.mitre.org/software/S1163/) | malware | 5 | Sea Turtle used SnappyTCP following initial access in intrusions from 2021 to 2023. |

## 6. Campanhas

Nenhuma campanha atribuída no ATT&CK.

## 7. Cobertura defensiva

**24 de 27 técnicas (89%)** têm ao menos uma regra pública no catálogo Detection Rules.

### Técnicas sem regra pública (prioridade para engenharia de detecção)

- **T1583.002 DNS Server** — Resource Development
- **T1564.011 Ignore Process Interrupts** — Stealth. Fonte de log sugerida pelo MITRE: `auditd:SYSCALL` execve call including 'nohup' or trailing '&'; `WinEventLog:PowerShell` EventCode=4103, 4104, 4105, 4106; `macos:unifiedlog` nohup, disown, or osascript execution patterns
- **T1583.003 Virtual Private Server** — Resource Development. Fonte de log sugerida pelo MITRE: `Internet Scan` None

### Regras recomendadas por técnica

Melhor regra disponível por técnica (formato portável e maduro primeiro).

| Técnica | Regra | Formato | Fonte |
|---|---|---|---|
| T1027.004 | [Visual Basic Command Line Compiler Usage](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A7b10f171-7f04-47c7-9fa2-5be43c76e535) | Sigma | SigmaHQ |
| T1027.004 | [Csc.EXE Execution Form Potentially Suspicious Parent](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab730a276-6b63-41b8-bcf8-55930c8fc6ee) | Sigma | SigmaHQ |
| T1059.004 | [Shell Invocation via Env Command - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Abed978f8-7f3a-432b-82c5-9286a9b3031a) | Sigma | SigmaHQ |
| T1059.004 | [Suspicious Reverse Shell Command Line](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A738d9bcf-6999-4fdb-b4ac-3033037db8ab) | Sigma | SigmaHQ |
| T1071.001 | [Ursnif Malware Download URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aa36ce77e-30db-4ea0-8795-644d7af5dfb4) | Sigma | SigmaHQ |
| T1071.001 | [Ursnif Malware C2 URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A932ac737-33ca-4afd-9869-0d48b391fcc9) | Sigma | SigmaHQ |
| T1074.002 | [Google Workspace Drive Data Transfer or Takeout Export Initiated](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A07b5f85a-240f-11ed-b3d9-f661ea17fbce) | Elastic | Elastic detection-rules |
| T1074.002 | [AWS RDS DB Instance Restored](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Abf1073bf-ce26-4607-b405-ba1ed8e9e204) | Elastic | Elastic detection-rules |
| T1078 | [Privilege Role Sign-In Outside Expected Controls](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acf1e5687-84e1-41af-97a9-158094efef53) | Sigma | SigmaHQ |
| T1078 | [OpenCanary - SSH Login Attempt](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aff7139bc-fdb1-4437-92f2-6afefe8884cb) | Sigma | SigmaHQ |
| T1078.003 | [Potential Successful SSH Brute Force Attack via macOS Security Events](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Af5898b1e-3071-4597-b066-43d298c7b415) | Elastic | Elastic detection-rules |
| T1078.003 | [Admin User Remote Logon](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A0f63e1ef-1eb9-4226-9d54-8927ca08520a) | Sigma | SigmaHQ |
| T1114.001 | [Powershell Local Email Collection](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A2837e152-93c8-43d2-85ba-c3cd3c2ae614) | Sigma | SigmaHQ |
| T1114.001 | [Exporting Exchange Mailbox via PowerShell](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A6aace640-e631-4870-ba8e-5fdda09325db) | Elastic | Elastic detection-rules |
| T1133 | [OpenCanary - SSH Login Attempt](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aff7139bc-fdb1-4437-92f2-6afefe8884cb) | Sigma | SigmaHQ |
| T1133 | [OpenCanary - SSH New Connection Attempt](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acd55f721-5623-4663-bd9b-5229cab5237d) | Sigma | SigmaHQ |
| T1190 | [OMIGOD HTTP No Authentication RCE - CVE-2021-38647](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aab6b1a39-a9ee-4ab4-b075-e83acf6e346b) | Sigma | SigmaHQ |
| T1190 | [Exploited CVE-2020-10189 Zoho ManageEngine](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A846b866e-2a57-46ee-8e16-85fa92759be7) | Sigma | OpenSearch Security Analytics |
| T1199 | [Microsoft 365 - User Restricted from Sending Email](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aff246f56-7f24-402a-baca-b86540e3925c) | Sigma | SigmaHQ |
| T1199 | [Microsoft 365 - User Restricted from Sending Email](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Aff246f56-7f24-402a-baca-b86540e3925c) | Sigma | OpenSearch Security Analytics |
| T1203 | [Droppers Exploiting CVE-2017-11882](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A678eb5f4-8597-4be6-8be7-905e4234b53a) | Sigma | SigmaHQ |
| T1203 | [OMIGOD HTTP No Authentication RCE - CVE-2021-38647](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aab6b1a39-a9ee-4ab4-b075-e83acf6e346b) | Sigma | SigmaHQ |
| T1213.006 | [AWS RDS Snapshot Export](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A119c8877-8613-416d-a98a-96b6664ee73a) | Elastic | Elastic detection-rules |
| T1213.006 | [AWS Secrets Manager Rapid Secrets Retrieval](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A185c782e-f86a-11ee-9d9f-f661ea17fbce) | Elastic | Elastic detection-rules |
| T1505.003 | [MOVEit CVE-2023-34362 Exploitation Attempt - Potential Web Shell Request](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A435e41f2-48eb-4c95-8a2b-ed24b50ec30b) | Sigma | SigmaHQ |
| T1505.003 | [Solarwinds SUPERNOVA Webshell Access](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aa2cee20b-eacc-459f-861d-c02e5d12f1db) | Sigma | SigmaHQ |
| T1557 | [ICMP Redirect Message from Internal Host](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A2014ebd8-b847-4cc0-a827-d0d61ec88680) | Elastic | Elastic detection-rules |
| T1557 | [Multiple DHCP Servers Responding to the Same Transaction](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A44b8d933-8fed-485d-a0af-bd97d0093439) | Elastic | Elastic detection-rules |
| T1560.001 | [APT31 Judgement Panda Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A03e2746e-2b31-42f1-ab7a-eb39365b2422) | Sigma | SigmaHQ |
| T1560.001 | [Suspicious Manipulation Of Default Accounts Via Net.EXE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A5b768e71-86f2-4879-b448-81061cbae951) | Sigma | SigmaHQ |
| T1566 | [CVE-2021-31979 CVE-2021-33771 Exploits by Sourgum](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aad7085ac-92e4-4b76-8ce2-276d2c0e68ef) | Sigma | SigmaHQ |
| T1566 | [CVE-2021-31979 CVE-2021-33771 Exploits](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A32b5db62-cb5f-4266-9639-0fa48376ac00) | Sigma | SigmaHQ |
| T1583 | [AWS Route 53 Private Hosted Zone Associated With a VPC](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ae3c27562-709a-42bd-82f2-3ed926cced19) | Elastic | Elastic detection-rules |
| T1583 | [AWS Service Quota Increase Requested by Rare Identity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A7e1b0654-b6c0-4b1b-ab47-75588533083c) | Elastic | Elastic detection-rules |
| T1583.001 | [AWS Route 53 Private Hosted Zone Associated With a VPC](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ae3c27562-709a-42bd-82f2-3ed926cced19) | Elastic | Elastic detection-rules |
| T1583.001 | [AWS SES Email Identity Verified Then Deleted](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A8e4bde35-125d-4eb3-9a2e-d7e77a053a08) | Elastic | Elastic detection-rules |
| T1584.002 | [GCP Audit Logs - DNSSEC Disabled on Managed DNS Zone](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A9129a43e-e204-4a9a-969e-d8861ce3437c) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1584.002 | [Amazon Security Lake - Route 53 - Succsessful DNS request [$(query.type)] "$(query.hostname)" from $(src_endpo](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=wazuh-ruleset-oficial%3A%3Awazuh-99080) | Wazuh | Wazuh ruleset (oficial) |
| T1588.002 | [Hacktool Execution - Imphash](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A24e3e58a-646b-4b50-adef-02ef935b9fc8) | Sigma | SigmaHQ |
| T1588.002 | [Renamed SysInternals DebugView Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acd764533-2e07-40d6-a718-cfeec7f2da7f) | Sigma | SigmaHQ |
| T1588.004 | [Cisco Secure Firewall - Blacklisted SSL Certificate Fingerprint](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=splunk-security-content%3A%3Ac43f7b49-2dab-4e76-892e-7f971c2f20f1) | Splunk | Splunk security_content |
| T1608.003 | [AWS KMS Imported Key Material Usage](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1279262f-1464-422f-ac0d-5b545320c526) | Sigma | SigmaHQ |
| T1685.006 | [Syslog Clearing or Removal Via System Utilities](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A3fcc9b35-39e4-44c0-a2ad-9e82b6902b31) | Sigma | SigmaHQ |
| T1685.006 | [Linux Logs Clearing Attempts](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A80915f59-9b56-4616-9de0-fd0dea6c12fe) | Sigma | SigmaHQ |
| T1690 | [ESXi Syslog Configuration Change Via ESXCLI](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A38eb1dbb-011f-40b1-a126-cf03a0210563) | Sigma | SigmaHQ |
| T1690 | [ESXi Syslog Configuration Change Via ESXCLI](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A38eb1dbb-011f-40b1-a126-cf03a0210563) | Sigma | OpenSearch Security Analytics |

## 8. Plano de emulação e validação

Use num laboratório isolado e autorizado para confirmar que as regras disparam. Os comandos estão nos repositórios oficiais.

| Tática | Técnica | Teste Atomic Red Team | Plataformas |
|---|---|---|---|
| Execution | [T1059.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.004/T1059.004.md) | Create and Execute Bash Shell Script | linux, macos |
| Execution | [T1059.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.004/T1059.004.md) | Command-Line Interface | linux, macos |
| Persistence | [T1133](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1133/T1133.md) | Running Chrome VPN Extensions via the Registry 2 vpn extension | windows |
| Persistence | [T1505.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1505.003/T1505.003.md) | Web Shell Written to Disk | windows |
| Stealth | [T1027.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027.004/T1027.004.md) | Compile After Delivery using csc.exe | windows |
| Stealth | [T1027.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027.004/T1027.004.md) | Dynamic C# Compile | windows |
| Stealth | [T1078.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1078.003/T1078.003.md) | Create local account with admin privileges | windows |
| Stealth | [T1078.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1078.003/T1078.003.md) | Create local account with admin privileges - MacOS | macos |
| Defense Impairment | [T1685.006](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1685.006/T1685.006.md) | rm -rf | linux, macos |
| Defense Impairment | [T1685.006](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1685.006/T1685.006.md) | rm -rf | linux |
| Defense Impairment | [T1690](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1690/T1690.md) | Disable history collection | linux, macos |
| Defense Impairment | [T1690](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1690/T1690.md) | Disable history collection (freebsd) | linux |
| Collection | [T1114.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1114.001/T1114.001.md) | Email Collection with PowerShell Get-Inbox | windows |
| Collection | [T1560.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1560.001/T1560.001.md) | Compress Data for Exfiltration With Rar | windows |
| Collection | [T1560.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1560.001/T1560.001.md) | Compress Data and lock with password for Exfiltration with winrar | windows |
| Command and Control | [T1071.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1071.001/T1071.001.md) | Malicious User Agents - Powershell | windows |
| Command and Control | [T1071.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1071.001/T1071.001.md) | Malicious User Agents - CMD | windows |

**Logs reais de ataque (EVTX) para testar sem executar nada:**

- T1078 — [ID1149-RDP success logins to multiple hosts](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0001-Initial%20access/T1078-Valid%20accounts/ID1149-RDP%20success%20logins%20to%20multiple%20hosts.evtx) _(explícito)_
- T1078 — [ID33205-SQL Server failed login with disabled SA account](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0001-Initial%20access/T1078-Valid%20accounts/ID33205-SQL%20Server%20failed%20login%20with%20disabled%20SA%20account.evtx) _(explícito)_
- T1557 — [ID5145-Print spooler bug abuse](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0006-Credential%20Access/T1557-Man%20in%20the%20middle/ID5145-Print%20spooler%20bug%20abuse.evtx) _(explícito)_
- T1557 — [ID515-DNS entry created with wildcard](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0006-Credential%20Access/T1557-Man%20in%20the%20middle/ID515-DNS%20entry%20created%20with%20wildcard.evtx) _(explícito)_

## 9. Hipóteses de hunting

Se Sea Turtle estiver no seu ambiente, estas são as perguntas a fazer aos seus dados (fontes de log segundo as estratégias de detecção do MITRE ATT&CK).

1. **T1608.003 Install Digital Certificate** — Consider use of services that may aid in the tracking of certificates in use on sites across the Internet. In some cases it may be possible to pivot on known pieces of certificate information to uncover other adversary infrastructure. Detection efforts may be… Dados: `Internet Scan` (None).
2. **T1584.002 DNS Server** — Monitor for queried domain name system (DNS) registry data that may compromise third-party DNS servers that can be used during targeting. Much of this activity will take place outside the visibility of the target organization, making detection of this… Dados: `Domain Name` (None), `Domain Name` (None).
3. **T1557 Adversary-in-the-Middle** — Detects suspicious DNS/ARP poisoning attempts, unauthorized modifications to registry/network configuration, or abnormal TLS downgrade activity. Correlates changes in system configuration with subsequent unusual network flows or authentication events. Dados: `WinEventLog:Security` (EventCode=4663, 4670, 4656), `WinEventLog:Sysmon` (EventCode=3, 22).
4. **T1027.004 Compile After Delivery** — Detects compilation activity using csc.exe, ilasm.exe, or msbuild.exe initiated by user-space processes outside typical development environments, followed by execution or network activity from newly written binaries. Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Sysmon` (EventCode=3, 22).
5. **T1564.011 Ignore Process Interrupts** — Execution of processes using nohup or shell redirection to ignore SIGHUP and continue running after session termination. Defender perspective: correlation between commands including nohup, disowned jobs, or `&` suffix with continued process execution after… Dados: `auditd:SYSCALL` (execve call including 'nohup' or trailing '&'), `auditd:SYSCALL` (process persists beyond parent shell termination).
6. **T1685.006 Clear Linux or Mac System Logs** — Detects log-clearing behavior by correlating suspicious command execution targeting log files under /var/log/, anomalous deletions or truncations of system logs, and unusual child processes (e.g., shell pipelines or redirections). Dados: `auditd:SYSCALL` (execve), `auditd:SYSCALL` (PATH).
7. **T1690 Prevent Command History Logging** — Detection of environment variable tampering (HISTFILE, HISTCONTROL, HISTFILESIZE) and absence of expected bash history writes. Correlation of unset or zeroed history variables with active shell sessions is indicative of adversarial evasion. Dados: `auditd:SYSCALL` (execve calls modifying HISTFILE or HISTCONTROL via unset/export), `linux:osquery` (processes modifying environment variables related to history logging).
8. **T1213.006 Databases** — Unusual database command-line access (e.g., `psql`, `mysql`, `mongo`) from non-admin users, occurring outside typical automation windows or without known service context. Often followed by data dumps to .sql/.csv files or outbound data transfers. Defender… Dados: `auditd:SYSCALL` (execve: Execution of CLI tools like psql, mysql, mongo, sqlite3), `auditd:PATH` (Creation of files with extensions .sql, .csv, .sqlite, especially in user directories), `NSM:Flow` (http::post: Outbound HTTP POST from host shortly after DB export activity).
9. **T1588.004 Digital Certificates** — Consider use of services that may aid in the tracking of newly issued certificates and/or certificates in use on sites across the Internet. In some cases it may be possible to pivot on known pieces of certificate information to uncover other adversary… Dados: `Certificate` (None), `Internet Scan` (None).
10. **T1566 Phishing** — Unusual inbound email activity where attachments or embedded URLs are delivered to users followed by execution of new processes or suspicious document behavior. Detection involves correlating email metadata, file creation, and network activity after a… Dados: `m365:unified` (Send/Receive: Emails with suspicious sender domains, spoofed headers, or anomalous attachment types), `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Sysmon` (EventCode=1).
11. **T1114.001 Local Email Collection** — Detection focuses on processes that attempt to locate, access, or exfiltrate local Outlook data files (.pst/.ost) using file system access, native Windows utilities (e.g., PowerShell, WMI), or remote access tools with file browsing capabilities. The behavior… Dados: `WinEventLog:Security` (EventCode=4663, 4670, 4656), `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=11).
12. **T1583 Acquire Infrastructure** — Monitor for contextual data about an Internet-facing resource gathered from a scan, such as running services or ports that may buy, lease, or rent infrastructure that can be used during targeting. Detection efforts may be focused on related stages of the… Dados: `Internet Scan` (None), `Internet Scan` (None), `Domain Name` (None).

## 10. OSINT — onde pesquisar

Consultas prontas com todos os nomes conhecidos do grupo:

- Relatórios técnicos: [busca web](https://duckduckgo.com/?q=%28%22Sea+Turtle%22+OR+%22Teal+Kurma%22+OR+%22Marbled+Dust%22+OR+%22Cosmic+Wolf%22+OR+%22SILICON%22%29+threat+report) · [PDFs](https://duckduckgo.com/?q=%28%22Sea+Turtle%22+OR+%22Teal+Kurma%22+OR+%22Marbled+Dust%22+OR+%22Cosmic+Wolf%22+OR+%22SILICON%22%29+filetype%3Apdf)
- Regras e IOCs publicados: [GitHub](https://github.com/search?type=code&q=%22Sea+Turtle%22+OR+%22Teal+Kurma%22+OR+%22Marbled+Dust%22+OR+%22Cosmic+Wolf%22+OR+%22SILICON%22)
- Pulsos de ameaça: [AlienVault OTX](https://otx.alienvault.com/browse/global/pulses?q=Sea+Turtle)
- Família de malware e atores: [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/actors) (busque por Sea Turtle, Teal Kurma, Marbled Dust)
- Cartões de grupo: [ThaiCERT Threat Group Cards](https://apt.etda.or.th/cgi-bin/listgroups.cgi)
- Página oficial: [MITRE ATT&CK G1041](https://attack.mitre.org/groups/G1041/)

**Relatórios na coleção CyberMonitor** (ligados pelo nome do grupo, conferir antes de citar):

- 2019 — [DNS Hijacking Abuses Trust In Core Internet Service](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2019/2019.04.17.Operation_Sea_Turtle/DNS%20Hijacking%20Abuses%20Trust%20In%20Core%20Internet%20Service.pdf) _(via “Sea Turtle”)_
- 2019 — [Sea Turtle keeps on swimming, finds new victims, DNS hijacking techniques](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2019/2019.07.09.SeaTurtle_swimming/Sea%20Turtle%20keeps%20on%20swimming%2C%20finds%20new%20victims%2C%20DNS%20hijacking%20techniques.pdf) _(via “Sea Turtle”)_

## 11. Bibliografia (5 fontes citadas pelo ATT&CK)

- [Hunt Sea Turtle 2024](https://www.huntandhackett.com/blog/turkish-espionage-campaigns) — Hunt & Hackett Research Team. (2024, January 5). Turkish espionage campaigns in the Netherlands. Retrieved November 20, 2024.
- [Microsoft Digital Defense 2021](https://query.prod.cms.rt.microsoft.com/cms/api/am/binary/RWMFIi?id=101738) — Microsoft. (2021, October). Microsoft Digital Defense Report. Retrieved November 20, 2024.
- [PWC Sea Turtle 2023](https://www.pwc.com/gx/en/issues/cybersecurity/cyber-threat-intelligence/tortoise-and-malwahare.html) — PwC Threat Intelligence. (2023, December 5). The Tortoise and The Malware. Retrieved November 20, 2024.
- [Talos Sea Turtle 2019](https://blog.talosintelligence.com/seaturtle/) — Cisco Talos. (2019, April 17). Sea Turtle: DNS Hijacking Abuses Trust In Core Internet Service. Retrieved November 20, 2024.
- [Talos Sea Turtle 2019_2](https://blog.talosintelligence.com/sea-turtle-keeps-on-swimming/) — Paul Rascagneres. (2019, July 9). Sea Turtle keeps on swimming, finds new victims, DNS hijacking techniques. Retrieved November 20, 2024.

## 12. Limites e confiança

- O ATT&CK registra o que foi **relatado publicamente**, não tudo o que o grupo faz. Ausência de uma técnica não prova que o grupo não a usa.
- **Sobreposição de TTP não é atribuição.** Muitas técnicas são compartilhadas entre grupos e com red teams. Use a assinatura comportamental como hipótese, junto com infraestrutura, malware e contexto.
- Cobertura de detecção refere-se ao catálogo público Detection Rules, não ao seu ambiente: confira se a telemetria necessária chega ao seu SIEM.
- Ligações marcadas como _inferidas_ (EVTX por palavra-chave, relatórios por nome) devem ser verificadas.

---
Fontes: MITRE ATT&CK® (uso livre com atribuição, © The MITRE Corporation), Atomic Red Team (Red Canary, MIT), EVTX-to-MITRE-Attack, EVTX-ATTACK-SAMPLES, APT & CyberCriminal Campaign Collections. Gerado por [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules).
