# Silent Librarian (G0122) — Dossiê de inteligência

> **TLP:CLEAR** · gerado em 2026-10-25 a partir de fontes abertas · MITRE ATT&CK v20.0 · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0122) · [ATT&CK](https://attack.mitre.org/groups/G0122/)

**Também conhecido como:** TA407, COBALT DICKENS  
**Registro no ATT&CK:** criado em 2021-02-03, atualizado em 2026-07-31 · referências de 2018 a 2020

## 1. Sumário executivo

- **13 técnicas** atribuídas publicamente, concentradas em **Resource Development, Reconnaissance, Collection**.
- **Arsenal:** 0 malware e 0 ferramentas.
- **Campanhas atribuídas:** 0.
- **Cobertura de detecção pública:** 69% das técnicas têm ao menos uma regra no catálogo; **4 técnicas sem nenhuma regra pública**.
- **Assinatura comportamental** (técnicas raras entre os 178 grupos, as mais úteis para atribuição): T1589.003 Employee Names, T1114 Email Collection, T1608.005 Link Target, T1114.003 Email Forwarding Rule, T1594 Search Victim-Owned Websites.

## 2. Quem é

> Silent Librarian is a group that has targeted research and proprietary data at universities, government agencies, and private sector companies worldwide since at least 2013. Members of Silent Librarian are known to have been affiliated with the Iran-based Mabna Institute which has conducted cyber intrusions at the behest of the government of Iran, specifically the Islamic Revolutionary Guard Corps (IRGC).

_Texto original do MITRE ATT&CK, em inglês._

## 3. Perfil TTP por tática (kill chain)

Cada linha: técnica, como o grupo a usou segundo relatos públicos, e o que existe para detectar e testar.

### Reconnaissance (TA0043) — 4

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1589.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1589.002) Email Addresses | Silent Librarian has collected e-mail addresses from targeted organizations from open Internet searches. | 5 | — | — |
| [T1589.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1589.003) Employee Names | Silent Librarian has collected lists of names for individuals from targeted organizations. | 1 | — | — |
| [T1594](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1594) Search Victim-Owned Websites | Silent Librarian has searched victim's websites to identify the interests and academic areas of targeted individuals and to scrape source code, branding, and organizational contact information for phishing pages. | **0** | — | — |
| [T1598.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1598.003) Spearphishing Link | Silent Librarian has used links in e-mails to direct victims to credential harvesting websites designed to appear like the targeted organization's login page. | **0** | — | — |

### Resource Development (TA0042) — 5

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1583.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1583.001) Domains | Silent Librarian has acquired domains to establish credential harvesting pages, often spoofing the target organization and using free top level domains .TK, .ML, .GA, .CF, and .GQ. | 7 | — | — |
| [T1585.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1585.002) Email Accounts | Silent Librarian has established e-mail accounts to receive e-mails forwarded from compromised accounts. | **0** | — | — |
| [T1588.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1588.002) Tool | Silent Librarian has obtained free and publicly available tools including SingleFile and HTTrack to copy login pages of targeted organizations. | 35 | — | — |
| [T1588.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1588.004) Digital Certificates | Silent Librarian has obtained free Let's Encrypt SSL certificates for use on their phishing pages. | 1 | — | — |
| [T1608.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1608.005) Link Target | Silent Librarian has cloned victim organization login pages and staged them for later use in credential harvesting campaigns. Silent Librarian has also made use of a variety of URL shorteners for these staged websites. | **0** | — | — |

### Initial Access (TA0001) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | Silent Librarian has used compromised credentials to obtain unauthorized access to online accounts. | 825 | — | 3 |

### Persistence (TA0003) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | Silent Librarian has used compromised credentials to obtain unauthorized access to online accounts. | 825 | — | 3 |

### Privilege Escalation (TA0004) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | Silent Librarian has used compromised credentials to obtain unauthorized access to online accounts. | 825 | — | 3 |

### Stealth (TA0005) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | Silent Librarian has used compromised credentials to obtain unauthorized access to online accounts. | 825 | — | 3 |

### Credential Access (TA0006) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1110.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1110.003) Password Spraying | Silent Librarian has used collected lists of names and e-mail accounts to use in password spraying attacks against private sector targets. | 62 | 9 | 1 |

### Collection (TA0009) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1114](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1114) Email Collection | Silent Librarian has exfiltrated entire mailboxes from compromised accounts. | 119 | — | — |
| [T1114.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1114.003) Email Forwarding Rule | Silent Librarian has set up auto forwarding rules on compromised e-mail accounts. | 10 | 1 | — |

## 4. Assinatura comportamental

Técnicas que este grupo usa e que poucos dos 178 grupos do ATT&CK usam. Pesam mais numa atribuição por TTP: ver várias delas juntas é mais informativo do que ver técnicas comuns como PowerShell.

| Técnica | Outros grupos que usam | Peso (raridade) |
|---|---:|---:|
| T1589.003 Employee Names | 2 | 3.80 |
| T1114 Email Collection | 3 | 3.58 |
| T1608.005 Link Target | 3 | 3.58 |
| T1114.003 Email Forwarding Rule | 4 | 3.40 |
| T1594 Search Victim-Owned Websites | 5 | 3.24 |
| T1588.004 Digital Certificates | 6 | 3.11 |
| T1110.003 Password Spraying | 11 | 2.62 |
| T1589.002 Email Addresses | 13 | 2.48 |
| T1598.003 Spearphishing Link | 15 | 2.35 |
| T1585.002 Email Accounts | 20 | 2.10 |

## 5. Arsenal

Nenhum software atribuído no ATT&CK.

## 6. Campanhas

Nenhuma campanha atribuída no ATT&CK.

## 7. Cobertura defensiva

**9 de 13 técnicas (69%)** têm ao menos uma regra pública no catálogo Detection Rules.

### Técnicas sem regra pública (prioridade para engenharia de detecção)

- **T1608.005 Link Target** — Resource Development. Fonte de log sugerida pelo MITRE: `Internet Scan` None
- **T1594 Search Victim-Owned Websites** — Reconnaissance. Fonte de log sugerida pelo MITRE: `Application Log` None
- **T1598.003 Spearphishing Link** — Reconnaissance. Fonte de log sugerida pelo MITRE: `Application Log` None
- **T1585.002 Email Accounts** — Resource Development

### Regras recomendadas por técnica

Melhor regra disponível por técnica (formato portável e maduro primeiro).

| Técnica | Regra | Formato | Fonte |
|---|---|---|---|
| T1078 | [Privilege Role Sign-In Outside Expected Controls](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acf1e5687-84e1-41af-97a9-158094efef53) | Sigma | SigmaHQ |
| T1078 | [OpenCanary - SSH Login Attempt](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aff7139bc-fdb1-4437-92f2-6afefe8884cb) | Sigma | SigmaHQ |
| T1110.003 | [Multiple SonicWall Login Failures Followed by Successful Login](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Aefe7ac71-3b13-41cf-8263-30af68ce3f19) | Elastic | Elastic detection-rules |
| T1110.003 | [Potential Successful SSH Brute Force Attack](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A8cb84371-d053-4f4f-bce0-c74990e28f28) | Elastic | Elastic detection-rules |
| T1114 | [Exchange PowerShell Snap-Ins Usage](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A25676e10-2121-446e-80a4-71ff8506af47) | Sigma | SigmaHQ |
| T1114 | [Hacktool Ruler](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A24549159-ac1b-479c-8175-d42aea947cae) | Sigma | SigmaHQ |
| T1114.003 | [Google Workspace Gmail Routing or Forwarding Rule Created or Modified](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A9510add4-3392-11ed-bd01-f661ea17fbce) | Elastic | Elastic detection-rules |
| T1114.003 | [Mail Forwarding/Redirecting Activity In O365](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac726e007-2cd0-4a55-abfb-79730fbedee5) | Sigma | SigmaHQ |
| T1583.001 | [AWS Route 53 Private Hosted Zone Associated With a VPC](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ae3c27562-709a-42bd-82f2-3ed926cced19) | Elastic | Elastic detection-rules |
| T1583.001 | [AWS SES Email Identity Verified Then Deleted](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A8e4bde35-125d-4eb3-9a2e-d7e77a053a08) | Elastic | Elastic detection-rules |
| T1588.002 | [Hacktool Execution - Imphash](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A24e3e58a-646b-4b50-adef-02ef935b9fc8) | Sigma | SigmaHQ |
| T1588.002 | [Renamed SysInternals DebugView Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acd764533-2e07-40d6-a718-cfeec7f2da7f) | Sigma | SigmaHQ |
| T1588.004 | [Cisco Secure Firewall - Blacklisted SSL Certificate Fingerprint](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=splunk-security-content%3A%3Ac43f7b49-2dab-4e76-892e-7f971c2f20f1) | Splunk | Splunk security_content |
| T1589.002 | [Potential Unconstrained Delegation Discovery Via Get-ADComputer - ScriptBlock](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acdfa73b6-3c9d-4bb8-97f8-ddbd8921f5c5) | Sigma | SigmaHQ |
| T1589.002 | [AWSCloudTrail - Suspicious AWS CLI Command Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A8c2dc344-9352-4ca1-8863-b1b7a5e09e59) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1589.003 | [AWSCloudTrail - Suspicious AWS CLI Command Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A8c2dc344-9352-4ca1-8863-b1b7a5e09e59) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |

## 8. Plano de emulação e validação

Use num laboratório isolado e autorizado para confirmar que as regras disparam. Os comandos estão nos repositórios oficiais.

| Tática | Técnica | Teste Atomic Red Team | Plataformas |
|---|---|---|---|
| Credential Access | [T1110.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1110.003/T1110.003.md) | Password Spray all Domain Users | windows |
| Credential Access | [T1110.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1110.003/T1110.003.md) | Password Spray (DomainPasswordSpray) | windows |
| Collection | [T1114.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1114.003/T1114.003.md) | Office365 - Email Forwarding | office-365 |

**Logs reais de ataque (EVTX) para testar sem executar nada:**

- T1078 — [ID1149-RDP success logins to multiple hosts](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0001-Initial%20access/T1078-Valid%20accounts/ID1149-RDP%20success%20logins%20to%20multiple%20hosts.evtx) _(explícito)_
- T1078 — [ID33205-SQL Server failed login with disabled SA account](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0001-Initial%20access/T1078-Valid%20accounts/ID33205-SQL%20Server%20failed%20login%20with%20disabled%20SA%20account.evtx) _(explícito)_
- T1110.003 — [kerberos_pwd_spray_4771](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Credential%20Access/kerberos_pwd_spray_4771.evtx) _(inferido)_

## 9. Hipóteses de hunting

Se Silent Librarian estiver no seu ambiente, estas são as perguntas a fazer aos seus dados (fontes de log segundo as estratégias de detecção do MITRE ATT&CK).

1. **T1114 Email Collection** — Correlates creation of email forwarding rules or header anomalies (e.g., X-MS-Exchange-Organization-AutoForwarded) with suspicious process execution, file access of .pst/.ost files, and network connections to external SMTP servers. Dados: `WinEventLog:Security` (EventCode=5145), `WinEventLog:PowerShell` (EventCode=4103, 4104, 4105, 4106), `WinEventLog:Application` (Exchange logs or header artifacts).
2. **T1608.005 Link Target** — If infrastructure or patterns in malicious web content have been previously identified, internet scanning may uncover when an adversary has staged web content to make it accessible for targeting. Much of this activity will take place outside the visibility of… Dados: `Internet Scan` (None).
3. **T1114.003 Email Forwarding Rule** — Creation of inbox rules via PowerShell (New-InboxRule) or transport rules using Exchange cmdlets. Correlates user behavior, cmdlet usage, and rule properties. Dados: `WinEventLog:PowerShell` (EventCode=4103, 4104, 4105, 4106), `WinEventLog:Security` (EventCode=4688), `m365:exchange` (Cmdlet - New-InboxRule).
4. **T1594 Search Victim-Owned Websites** — Monitor for suspicious network traffic that could be indicative of adversary reconnaissance, such as rapid successions of requests indicative of web crawling and/or large quantities of requests originating from a single source (especially if the source is… Dados: `Application Log` (None).
5. **T1588.004 Digital Certificates** — Consider use of services that may aid in the tracking of newly issued certificates and/or certificates in use on sites across the Internet. In some cases it may be possible to pivot on known pieces of certificate information to uncover other adversary… Dados: `Certificate` (None), `Internet Scan` (None).
6. **T1110.003 Password Spraying** — A high volume of authentication failures using a single password (or small set) across many different user accounts within a defined time window Dados: `WinEventLog:Security` (EventCode=4625, 4771, 4648).
7. **T1589.002 Email Addresses** — Monitor for suspicious network traffic that could be indicative of probing for email addresses and/or usernames, such as large/iterative quantities of authentication requests originating from a single source (especially if the source is known to be associated… Dados: `Network Traffic` (None).
8. **T1598.003 Spearphishing Link** — Monitor for suspicious email activity, such as numerous accounts receiving messages from a single unusual/unknown sender. Filtering based on DKIM+SPF or header analysis can help detect when the email sender is spoofed. Monitor for references to uncategorized… Dados: `Application Log` (None), `Network Traffic` (None), `Network Traffic` (None).
9. **T1583.001 Domains** — Monitor logged domain name system (DNS) data for purchased domains that can be used during targeting. Reputation/category-based detection may be difficult until the categorization is updated. Detection efforts may be focused on related stages of the adversary… Dados: `Domain Name` (None), `Domain Name` (None), `Domain Name` (None).
10. **T1078 Valid Accounts** — Detection of compromised or misused valid accounts via anomalous logon patterns, abnormal logon types, and inconsistent geographic or time-based activity across Windows endpoints. Dados: `WinEventLog:Security` (EventCode=4624), `WinEventLog:Security` (EventCode=4776, 4625), `WinEventLog:Sysmon` (EventCode=1).
11. **T1588.002 Tool** — Monitor for contextual data about a malicious payload, such as compilation times, file hashes, as well as watermarks or other identifiable configuration information. In some cases, malware repositories can also be used to identify features of tool use… Dados: `Malware Repository` (None).

## 10. OSINT — onde pesquisar

Consultas prontas com todos os nomes conhecidos do grupo:

- Relatórios técnicos: [busca web](https://duckduckgo.com/?q=%28%22Silent+Librarian%22+OR+%22TA407%22+OR+%22COBALT+DICKENS%22%29+threat+report) · [PDFs](https://duckduckgo.com/?q=%28%22Silent+Librarian%22+OR+%22TA407%22+OR+%22COBALT+DICKENS%22%29+filetype%3Apdf)
- Regras e IOCs publicados: [GitHub](https://github.com/search?type=code&q=%22Silent+Librarian%22+OR+%22TA407%22+OR+%22COBALT+DICKENS%22)
- Pulsos de ameaça: [AlienVault OTX](https://otx.alienvault.com/browse/global/pulses?q=Silent+Librarian)
- Família de malware e atores: [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/actors) (busque por Silent Librarian, TA407, COBALT DICKENS)
- Cartões de grupo: [ThaiCERT Threat Group Cards](https://apt.etda.or.th/cgi-bin/listgroups.cgi)
- Página oficial: [MITRE ATT&CK G0122](https://attack.mitre.org/groups/G0122/)

**Relatórios na coleção CyberMonitor** (ligados pelo nome do grupo, conferir antes de citar):

- 2020 — [Silent Librarian APT right on schedule for 20_21 academic year - Malwarebytes Labs _ Malwarebytes Labs](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2020/2020.10.14.Silent_Librarian_APT/Silent%20Librarian%20APT%20right%20on%20schedule%20for%2020_21%20academic%20year%20-%20Malwarebytes%20Labs%20_%20Malwarebytes%20Labs.pdf) _(via “Silent Librarian”)_

## 11. Bibliografia (6 fontes citadas pelo ATT&CK)

- [DOJ Iran Indictments March 2018](https://www.justice.gov/usao-sdny/press-release/file/1045781/download) — DOJ. (2018, March 23). U.S. v. Rafatnejad et al . Retrieved February 3, 2021.
- [Malwarebytes Silent Librarian October 2020](https://blog.malwarebytes.com/malwarebytes-news/2020/10/silent-librarian-apt-phishing-attack/) — Malwarebytes Threat Intelligence Team. (2020, October 14). Silent Librarian APT right on schedule for 20/21 academic year. Retrieved February 3, 2021.
- [Phish Labs Silent Librarian](https://info.phishlabs.com/blog/silent-librarian-more-to-the-story-of-the-iranian-mabna-institute-indictment) — Hassold, Crane. (2018, March 26). Silent Librarian: More to the Story of the Iranian Mabna Institute Indictment. Retrieved February 3, 2021.
- [Proofpoint TA407 September 2019](https://www.proofpoint.com/us/threat-insight/post/threat-actor-profile-ta407-silent-librarian) — Proofpoint Threat Insight Team. (2019, September 5). Threat Actor Profile: TA407, the Silent Librarian. Retrieved February 3, 2021.
- [Secureworks COBALT DICKENS August 2018](https://www.secureworks.com/blog/back-to-school-cobalt-dickens-targets-universities) — Counter Threat Unit Research Team. (2018, August 24). Back to School: COBALT DICKENS Targets Universities. Retrieved February 3, 2021.
- [Secureworks COBALT DICKENS September 2019](https://www.secureworks.com/blog/cobalt-dickens-goes-back-to-school-again) — Counter Threat Unit Research Team. (2019, September 11). COBALT DICKENS Goes Back to School…Again. Retrieved February 3, 2021.

## 12. Limites e confiança

- O ATT&CK registra o que foi **relatado publicamente**, não tudo o que o grupo faz. Ausência de uma técnica não prova que o grupo não a usa.
- **Sobreposição de TTP não é atribuição.** Muitas técnicas são compartilhadas entre grupos e com red teams. Use a assinatura comportamental como hipótese, junto com infraestrutura, malware e contexto.
- Cobertura de detecção refere-se ao catálogo público Detection Rules, não ao seu ambiente: confira se a telemetria necessária chega ao seu SIEM.
- Ligações marcadas como _inferidas_ (EVTX por palavra-chave, relatórios por nome) devem ser verificadas.

---
Fontes: MITRE ATT&CK® (uso livre com atribuição, © The MITRE Corporation), Atomic Red Team (Red Canary, MIT), EVTX-to-MITRE-Attack, EVTX-ATTACK-SAMPLES, APT & CyberCriminal Campaign Collections. Gerado por [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules).
