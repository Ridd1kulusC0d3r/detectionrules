# Star Blizzard (G1033) — Dossiê de inteligência

> **TLP:CLEAR** · gerado em 2026-10-25 a partir de fontes abertas · MITRE ATT&CK v20.0 · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1033) · [ATT&CK](https://attack.mitre.org/groups/G1033/)

**Também conhecido como:** SEABORGIUM, Callisto Group, TA446, COLDRIVER  
**Registro no ATT&CK:** criado em 2024-06-14, atualizado em 2026-07-31 · referências de 2022 a 2024

## 1. Sumário executivo

- **20 técnicas** atribuídas publicamente, concentradas em **Resource Development, Reconnaissance, Execution**.
- **Arsenal:** 1 malware e 0 ferramentas (ex.: Spica).
- **Campanhas atribuídas:** 0.
- **Cobertura de detecção pública:** 85% das técnicas têm ao menos uma regra no catálogo; **3 técnicas sem nenhuma regra pública**.
- **Assinatura comportamental** (técnicas raras entre os 178 grupos, as mais úteis para atribuição): T1550.004 Web Session Cookie, T1598.002 Spearphishing Attachment, T1114.003 Email Forwarding Rule, T1593 Search Open Websites/Domains, T1539 Steal Web Session Cookie.

## 2. Quem é

> Star Blizzard is a cyber espionage and influence group originating in Russia that has been active since at least 2019. Star Blizzard campaigns align closely with Russian state interests and have included persistent phishing and credential theft against academic, defense, government, NGO, and think tank organizations in NATO countries, particularly the US and the UK.

_Texto original do MITRE ATT&CK, em inglês._

## 3. Perfil TTP por tática (kill chain)

Cada linha: técnica, como o grupo a usou segundo relatos públicos, e o que existe para detectar e testar.

### Reconnaissance (TA0043) — 4

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1589](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1589) Gather Victim Identity Information | Star Blizzard has identified ways to engage targets by researching potential victims' interests and social or professional contacts. | 11 | — | — |
| [T1593](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1593) Search Open Websites/Domains | Star Blizzard has used open-source research to identify information about victims to use in targeting. | 8 | — | — |
| [T1598.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1598.002) Spearphishing Attachment | Star Blizzard has sent emails to establish rapport with targets eventually sending messages with attachments containing links to credential-stealing sites. | **0** | — | — |
| [T1598.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1598.003) Spearphishing Link | Star Blizzard has sent emails to establish rapport with targets eventually sending messages with links to credential-stealing sites. | **0** | — | — |

### Resource Development (TA0042) — 7

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1583](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1583) Acquire Infrastructure | Star Blizzard has used HubSpot and MailerLite marketing platform services to hide the true sender of phishing emails. | 9 | — | — |
| [T1583.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1583.001) Domains | Star Blizzard has registered domains using randomized words and with names resembling legitimate organizations. | 7 | — | — |
| [T1585.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1585.001) Social Media Accounts | Star Blizzard has established fraudulent profiles on professional networking sites to conduct reconnaissance. | 4 | — | — |
| [T1585.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1585.002) Email Accounts | Star Blizzard has registered impersonation email accounts to spoof experts in a particular field or individuals and organizations affiliated with the intended target. | **0** | — | — |
| [T1586.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1586.002) Email Accounts | Star Blizzard has used compromised email accounts to conduct spearphishing against  contacts of the original victim. | 3 | — | — |
| [T1588.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1588.002) Tool | Star Blizzard has incorporated the open-source EvilGinx framework into their spearphishing activity. | 35 | — | — |
| [T1608.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1608.001) Upload Malware | Star Blizzard has uploaded malicious payloads to cloud storage sites. | 3 | — | — |

### Initial Access (TA0001) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | Star Blizzard has used stolen credentials to sign into victim email accounts. | 825 | — | 3 |
| [T1566.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1566.001) Spearphishing Attachment | Star Blizzard has sent emails with malicious .pdf files to spread malware. | 230 | 2 | — |

### Execution (TA0002) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1059.007](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.007) JavaScript | Star Blizzard has used JavaScript to redirect victim traffic from an adversary controlled server to a server hosting the Evilginx phishing framework. | 205 | 5 | — |
| [T1204.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1204.002) Malicious File | Star Blizzard has lured targets into opening malicious .pdf files to deliver malware. | 259 | 13 | — |

### Persistence (TA0003) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | Star Blizzard has used stolen credentials to sign into victim email accounts. | 825 | — | 3 |

### Privilege Escalation (TA0004) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | Star Blizzard has used stolen credentials to sign into victim email accounts. | 825 | — | 3 |

### Stealth (TA0005) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | Star Blizzard has used stolen credentials to sign into victim email accounts. | 825 | — | 3 |
| [T1684.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1684.001) Impersonation | Star Blizzard has registered impersonation email accounts to spoof experts in a particular field or individuals and organizations affiliated with the intended target. | 1 | — | — |

### Credential Access (TA0006) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1539](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1539) Steal Web Session Cookie | Star Blizzard has used EvilGinx to steal the session cookies of victims directed to  phishing domains. | 54 | 5 | — |

### Lateral Movement (TA0008) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1550.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1550.004) Web Session Cookie | Star Blizzard has bypassed multi-factor authentication on victim email accounts by using session cookies stolen using EvilGinx. | 4 | — | — |

### Collection (TA0009) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1114.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1114.002) Remote Email Collection | Star Blizzard has remotely accessed victims' email accounts to steal messages and attachments. | 11 | 1 | — |
| [T1114.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1114.003) Email Forwarding Rule | Star Blizzard has abused email forwarding rules to monitor the activities of a victim, steal information, and maintain persistent access after compromised credentials are reset. | 10 | 1 | — |

## 4. Assinatura comportamental

Técnicas que este grupo usa e que poucos dos 178 grupos do ATT&CK usam. Pesam mais numa atribuição por TTP: ver várias delas juntas é mais informativo do que ver técnicas comuns como PowerShell.

| Técnica | Outros grupos que usam | Peso (raridade) |
|---|---:|---:|
| T1550.004 Web Session Cookie | 0 | 4.49 |
| T1598.002 Spearphishing Attachment | 3 | 3.58 |
| T1114.003 Email Forwarding Rule | 4 | 3.40 |
| T1593 Search Open Websites/Domains | 5 | 3.24 |
| T1539 Steal Web Session Cookie | 7 | 2.99 |
| T1583 Acquire Infrastructure | 8 | 2.88 |
| T1589 Gather Victim Identity Information | 9 | 2.79 |
| T1114.002 Remote Email Collection | 12 | 2.55 |
| T1586.002 Email Accounts | 13 | 2.48 |
| T1598.003 Spearphishing Link | 15 | 2.35 |

## 5. Arsenal

| Software | Tipo | Técnicas no ATT&CK | Uso relatado (EN) |
|---|---|---:|---|
| [Spica](https://attack.mitre.org/software/S1140/) | malware | 9 |  |

## 6. Campanhas

Nenhuma campanha atribuída no ATT&CK.

## 7. Cobertura defensiva

**17 de 20 técnicas (85%)** têm ao menos uma regra pública no catálogo Detection Rules.

### Técnicas sem regra pública (prioridade para engenharia de detecção)

- **T1598.002 Spearphishing Attachment** — Reconnaissance. Fonte de log sugerida pelo MITRE: `Network Traffic` None
- **T1598.003 Spearphishing Link** — Reconnaissance. Fonte de log sugerida pelo MITRE: `Application Log` None
- **T1585.002 Email Accounts** — Resource Development

### Regras recomendadas por técnica

Melhor regra disponível por técnica (formato portável e maduro primeiro).

| Técnica | Regra | Formato | Fonte |
|---|---|---|---|
| T1059.007 | [Adwind RAT / JRAT](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1fac1481-2dbc-48b2-9096-753c49b4ec71) | Sigma | SigmaHQ |
| T1059.007 | [WScript or CScript Dropper - File](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A002bdb95-0cf1-46a6-9e08-d38c128a6127) | Sigma | SigmaHQ |
| T1078 | [Privilege Role Sign-In Outside Expected Controls](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acf1e5687-84e1-41af-97a9-158094efef53) | Sigma | SigmaHQ |
| T1078 | [OpenCanary - SSH Login Attempt](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aff7139bc-fdb1-4437-92f2-6afefe8884cb) | Sigma | SigmaHQ |
| T1114.002 | [Microsoft Graph Email Access by Unusual User and Client](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ae882e934-2aaa-11f0-8272-f661ea17fbcc) | Elastic | Elastic detection-rules |
| T1114.002 | [M365 Exchange Mailbox Accessed by Unusual Client](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A48819484-9826-4083-9eba-1da74cd0eaf2) | Elastic | Elastic detection-rules |
| T1114.003 | [Google Workspace Gmail Routing or Forwarding Rule Created or Modified](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A9510add4-3392-11ed-bd01-f661ea17fbce) | Elastic | Elastic detection-rules |
| T1114.003 | [Mail Forwarding/Redirecting Activity In O365](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac726e007-2cd0-4a55-abfb-79730fbedee5) | Sigma | SigmaHQ |
| T1204.002 | [Ursnif Malware C2 URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A932ac737-33ca-4afd-9869-0d48b391fcc9) | Sigma | SigmaHQ |
| T1204.002 | [Droppers Exploiting CVE-2017-11882](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A678eb5f4-8597-4be6-8be7-905e4234b53a) | Sigma | SigmaHQ |
| T1539 | [SQLite Firefox Profile Data DB Access](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4833155a-4053-4c9c-a997-777fcea0baa7) | Sigma | SigmaHQ |
| T1539 | [SQLite Chromium Profile Data DB Access](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A24c77512-782b-448a-8950-eddb0785fc71) | Sigma | SigmaHQ |
| T1550.004 | [Okta AiTM Session Cookie Replay](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A9ed5d08f-aad6-4c03-838c-d686da887c2c) | Elastic | Elastic detection-rules |
| T1550.004 | [Multiple Device Token Hashes for Single Okta Session](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Acc382a2e-7e52-11ee-9aac-f661ea17fbcd) | Elastic | Elastic detection-rules |
| T1566.001 | [Ursnif Malware C2 URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A932ac737-33ca-4afd-9869-0d48b391fcc9) | Sigma | SigmaHQ |
| T1566.001 | [Droppers Exploiting CVE-2017-11882](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A678eb5f4-8597-4be6-8be7-905e4234b53a) | Sigma | SigmaHQ |
| T1583 | [AWS Route 53 Private Hosted Zone Associated With a VPC](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ae3c27562-709a-42bd-82f2-3ed926cced19) | Elastic | Elastic detection-rules |
| T1583 | [AWS Service Quota Increase Requested by Rare Identity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A7e1b0654-b6c0-4b1b-ab47-75588533083c) | Elastic | Elastic detection-rules |
| T1583.001 | [AWS Route 53 Private Hosted Zone Associated With a VPC](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ae3c27562-709a-42bd-82f2-3ed926cced19) | Elastic | Elastic detection-rules |
| T1583.001 | [AWS SES Email Identity Verified Then Deleted](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A8e4bde35-125d-4eb3-9a2e-d7e77a053a08) | Elastic | Elastic detection-rules |
| T1585.001 | [CYFIRMA - Brand Intelligence - Social Media Handle Impersonation Detected High Rule](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A22f49d67-7da7-4809-8d07-89e4478aa6b0) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1585.001 | [CYFIRMA - Brand Intelligence - Executive/People Impersonation High Rule](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A159d26a1-591c-4f70-b1ca-2843c881aaec) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1586.002 | [CYFIRMA - Brand Intelligence - Domain Impersonation High Rule](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A10bdf525-5b89-4a25-933a-e63e73b915f1) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1586.002 | [CYFIRMA - Brand Intelligence - Domain Impersonation Medium Rule](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A8f97ddbe-ab66-4f6c-b675-73b5eeb07259) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1588.002 | [Hacktool Execution - Imphash](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A24e3e58a-646b-4b50-adef-02ef935b9fc8) | Sigma | SigmaHQ |
| T1588.002 | [Renamed SysInternals DebugView Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acd764533-2e07-40d6-a718-cfeec7f2da7f) | Sigma | SigmaHQ |
| T1589 | [SSHD Error Message CVE-2018-15473](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4c9d903d-4939-4094-ade0-3cb748f4d7da) | Sigma | SigmaHQ |
| T1589 | [SSHD Error Message CVE-2018-15473](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A4c9d903d-4939-4094-ade0-3cb748f4d7da) | Sigma | OpenSearch Security Analytics |
| T1593 | [CYFIRMA - Social and Public Exposure -  Social Media Threats  Activity Detected Rule](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A4fe04459-13f1-4ff7-9b7c-f9be0c2aad6d) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1593 | [CYFIRMA - Social and Public Exposure - Confidential Files Information Exposure Rule](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A67e9c4aa-a2fa-4e4e-9272-1a8da41475c6) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1608.001 | [M365 OneDrive Malware File Upload](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Abba1b212-b85c-41c6-9b28-be0e5cdfc9b1) | Elastic | Elastic detection-rules |
| T1608.001 | [M365 SharePoint Malware File Detected](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A0e52157a-8e96-4a95-a6e3-5faae5081a74) | Elastic | Elastic detection-rules |
| T1684.001 | [Entra ID OAuth user_impersonation Scope for Unusual User and Client](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A9563dace-5822-11f0-b1d3-f661ea17fbcd) | Elastic | Elastic detection-rules |

## 8. Plano de emulação e validação

Use num laboratório isolado e autorizado para confirmar que as regras disparam. Os comandos estão nos repositórios oficiais.

| Tática | Técnica | Teste Atomic Red Team | Plataformas |
|---|---|---|---|
| Initial Access | [T1566.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1566.001/T1566.001.md) | Download Macro-Enabled Phishing Attachment | windows |
| Initial Access | [T1566.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1566.001/T1566.001.md) | Word spawned a command shell and used an IP address in the command line | windows |
| Execution | [T1059.007](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.007/T1059.007.md) | JScript execution to gather local computer information via cscript | windows |
| Execution | [T1059.007](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.007/T1059.007.md) | JScript execution to gather local computer information via wscript | windows |
| Execution | [T1204.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1204.002/T1204.002.md) | OSTap Style Macro Execution | windows |
| Execution | [T1204.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1204.002/T1204.002.md) | OSTap Payload Download | windows |
| Credential Access | [T1539](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1539/T1539.md) | Steal Firefox Cookies (Windows) | windows |
| Credential Access | [T1539](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1539/T1539.md) | Steal Chrome Cookies (Windows) | windows |
| Collection | [T1114.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1114.002/T1114.002.md) | Office365 - Remote Mail Collected | office-365 |
| Collection | [T1114.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1114.003/T1114.003.md) | Office365 - Email Forwarding | office-365 |

**Logs reais de ataque (EVTX) para testar sem executar nada:**

- T1078 — [ID1149-RDP success logins to multiple hosts](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0001-Initial%20access/T1078-Valid%20accounts/ID1149-RDP%20success%20logins%20to%20multiple%20hosts.evtx) _(explícito)_
- T1078 — [ID33205-SQL Server failed login with disabled SA account](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0001-Initial%20access/T1078-Valid%20accounts/ID33205-SQL%20Server%20failed%20login%20with%20disabled%20SA%20account.evtx) _(explícito)_

## 9. Hipóteses de hunting

Se Star Blizzard estiver no seu ambiente, estas são as perguntas a fazer aos seus dados (fontes de log segundo as estratégias de detecção do MITRE ATT&CK).

1. **T1550.004 Web Session Cookie** — Anomalous access to cloud web applications using session tokens without corresponding MFA/credential validation, often from unusual locations or device fingerprints. Dados: `AWS:CloudTrail` (SessionToken used without preceding MFA or login event), `AWS:CloudTrail` (ConsoleLogin).
2. **T1598.002 Spearphishing Attachment** — Monitor network data for uncommon data flows. Processes utilizing the network that do not normally have network communication or have never been seen before are suspicious. Monitor for suspicious email activity, such as numerous accounts receiving messages… Dados: `Network Traffic` (None), `Application Log` (None), `Network Traffic` (None).
3. **T1114.003 Email Forwarding Rule** — Creation of inbox rules via PowerShell (New-InboxRule) or transport rules using Exchange cmdlets. Correlates user behavior, cmdlet usage, and rule properties. Dados: `WinEventLog:PowerShell` (EventCode=4103, 4104, 4105, 4106), `WinEventLog:Security` (EventCode=4688), `m365:exchange` (Cmdlet - New-InboxRule).
4. **T1539 Steal Web Session Cookie** — Detects suspicious access to browser session cookie storage (e.g., Chrome’s `Cookies` SQLite DB) or memory reads of browser processes. Anomalous injection or memory dump utilities targeting browser processes such as `chrome.exe`, `firefox.exe`, or… Dados: `WinEventLog:Sysmon` (EventCode=10), `WinEventLog:Sysmon` (EventCode=2), `WinEventLog:Security` (EventCode=4688).
5. **T1583 Acquire Infrastructure** — Monitor for contextual data about an Internet-facing resource gathered from a scan, such as running services or ports that may buy, lease, or rent infrastructure that can be used during targeting. Detection efforts may be focused on related stages of the… Dados: `Internet Scan` (None), `Internet Scan` (None), `Domain Name` (None).
6. **T1589 Gather Victim Identity Information** — Monitor for suspicious network traffic that could be indicative of probing for user information, such as large/iterative quantities of authentication requests originating from a single source (especially if the source is known to be associated with an… Dados: `Network Traffic` (None).
7. **T1114.002 Remote Email Collection** — Detects adversaries accessing remote mail systems (e.g., Exchange Online, O365) using stolen credentials or OAuth tokens, followed by scripted access to mailbox contents via PowerShell, AADInternals, or unattended API queries. Detection focuses on abnormal… Dados: `azure:signinlogs` (Abnormal sign-in from scripting tools (PowerShell, AADInternals)), `m365:purview` (MailItemsAccessed & Exchange Audit), `WinEventLog:PowerShell` (EventCode=4103, 4104, 4105, 4106).
8. **T1598.003 Spearphishing Link** — Monitor for suspicious email activity, such as numerous accounts receiving messages from a single unusual/unknown sender. Filtering based on DKIM+SPF or header analysis can help detect when the email sender is spoofed. Monitor for references to uncategorized… Dados: `Application Log` (None), `Network Traffic` (None), `Network Traffic` (None).
9. **T1684.001 Impersonation** — Monitor for anomalous email activity originating from Windows-hosted applications (e.g., Outlook) where the sending account name or display name does not match the underlying SMTP address. Detect abnormal volume of outbound messages containing sensitive… Dados: `WinEventLog:Security` (EventCode=4624, 4648), `m365:unified` (SendOnBehalf/SendAs: Emails sent where the sending identity mismatches account ownership).
10. **T1585.001 Social Media Accounts** — Monitor and analyze traffic patterns and packet inspection associated to protocol(s) that do not follow the expected protocol standards and traffic flows (e.g extraneous packets that do not belong to established flows, gratuitous or anomalous traffic… Dados: `Network Traffic` (None), `Persona` (None).
11. **T1059.007 JavaScript** — Detects JavaScript execution through WSH (wscript.exe, cscript.exe) or HTA (mshta.exe), particularly when spawned from Office macros, web browsers, or abnormal user paths. Correlates script execution with outbound network activity or system modification. Dados: `WinEventLog:Sysmon` (EventCode=1), `m365:defender` (ScriptBlockLogging + AMSI), `WinEventLog:Sysmon` (EventCode=7).
12. **T1608.001 Upload Malware** — If infrastructure or patterns in malware have been previously identified, internet scanning may uncover when an adversary has staged malware to make it accessible for targeting. Much of this activity will take place outside the visibility of the target… Dados: `Internet Scan` (None).

## 10. OSINT — onde pesquisar

Consultas prontas com todos os nomes conhecidos do grupo:

- Relatórios técnicos: [busca web](https://duckduckgo.com/?q=%28%22Star+Blizzard%22+OR+%22SEABORGIUM%22+OR+%22Callisto+Group%22+OR+%22TA446%22+OR+%22COLDRIVER%22%29+threat+report) · [PDFs](https://duckduckgo.com/?q=%28%22Star+Blizzard%22+OR+%22SEABORGIUM%22+OR+%22Callisto+Group%22+OR+%22TA446%22+OR+%22COLDRIVER%22%29+filetype%3Apdf)
- Regras e IOCs publicados: [GitHub](https://github.com/search?type=code&q=%22Star+Blizzard%22+OR+%22SEABORGIUM%22+OR+%22Callisto+Group%22+OR+%22TA446%22+OR+%22COLDRIVER%22)
- Pulsos de ameaça: [AlienVault OTX](https://otx.alienvault.com/browse/global/pulses?q=Star+Blizzard)
- Família de malware e atores: [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/actors) (busque por Star Blizzard, SEABORGIUM, Callisto Group)
- Cartões de grupo: [ThaiCERT Threat Group Cards](https://apt.etda.or.th/cgi-bin/listgroups.cgi)
- Página oficial: [MITRE ATT&CK G1033](https://attack.mitre.org/groups/G1033/)

**Relatórios na coleção CyberMonitor** (ligados pelo nome do grupo, conferir antes de citar):

- 2017 — [callisto-group](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2017/2017.04.13.callisto-group/callisto-group.pdf) _(via “Callisto Group”)_

## 11. Bibliografia (4 fontes citadas pelo ATT&CK)

- [CISA Star Blizzard Advisory December 2023](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-341a) — CISA, et al. (2023, December 7). Russian FSB Cyber Actor Star Blizzard Continues Worldwide Spear-phishing Campaigns. Retrieved June 13, 2024.
- [Google TAG COLDRIVER January 2024](https://blog.google/threat-analysis-group/google-tag-coldriver-russian-phishing-malware/) — Shields, W. (2024, January 18). Russian threat group COLDRIVER expands its targeting of Western officials to include the use of malware. Retrieved June 13, 2024.
- [Microsoft Star Blizzard August 2022](https://www.microsoft.com/en-us/security/blog/2022/08/15/disrupting-seaborgiums-ongoing-phishing-operations/) — Microsoft Threat Intelligence. (2022, August 15). Disrupting SEABORGIUM’s ongoing phishing operations. Retrieved June 13, 2024.
- [StarBlizzard](https://www.microsoft.com/en-us/security/blog/2023/12/07/star-blizzard-increases-sophistication-and-evasion-in-ongoing-attacks/) — Microsoft Threat Intelligence. (2023, December 7). Star Blizzard increases sophistication and evasion in ongoing attacks. Retrieved February 13, 2024.

## 12. Limites e confiança

- O ATT&CK registra o que foi **relatado publicamente**, não tudo o que o grupo faz. Ausência de uma técnica não prova que o grupo não a usa.
- **Sobreposição de TTP não é atribuição.** Muitas técnicas são compartilhadas entre grupos e com red teams. Use a assinatura comportamental como hipótese, junto com infraestrutura, malware e contexto.
- Cobertura de detecção refere-se ao catálogo público Detection Rules, não ao seu ambiente: confira se a telemetria necessária chega ao seu SIEM.
- Ligações marcadas como _inferidas_ (EVTX por palavra-chave, relatórios por nome) devem ser verificadas.

---
Fontes: MITRE ATT&CK® (uso livre com atribuição, © The MITRE Corporation), Atomic Red Team (Red Canary, MIT), EVTX-to-MITRE-Attack, EVTX-ATTACK-SAMPLES, APT & CyberCriminal Campaign Collections. Gerado por [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules).
