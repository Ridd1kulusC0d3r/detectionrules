# LAPSUS$ (G1004) — Dossiê de inteligência

> **TLP:CLEAR** · gerado em 2026-10-26 a partir de fontes abertas · MITRE ATT&CK v20.0 · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1004) · [ATT&CK](https://attack.mitre.org/groups/G1004/)

**Também conhecido como:** DEV-0537, Strawberry Tempest  
**Origem atribuída:** Sem país atribuído · **Motivação:** financeiro, sabotagem · **Setores-alvo:** —  
**Registro no ATT&CK:** criado em 2022-06-09, atualizado em 2026-07-31 · referências de 2022 a 2023

## 1. Sumário executivo

- **43 técnicas** atribuídas publicamente, concentradas em **Reconnaissance, Credential Access, Collection**.
- **Arsenal:** 0 malware e 1 ferramentas (ex.: Mimikatz).
- **Campanhas atribuídas:** 0.
- **Cobertura de detecção pública:** 88% das técnicas têm ao menos uma regra no catálogo; **5 técnicas sem nenhuma regra pública**.
- **Origem e alvos (APT4ALL):** atribuído a **Sem país atribuído**, motivação financeiro, sabotagem.
- **Onde a cobertura está:** Windows (24 técnicas com regra), Outros / genérico (20 técnicas com regra), Azure (recursos) (19 técnicas com regra), E-mail (18 técnicas com regra).
- **Assinatura comportamental** (técnicas raras entre os 178 grupos, as mais úteis para atribuição): T1213.001 Confluence, T1552.008 Chat Messages, T1597.002 Purchase Technical Data, T1136.003 Cloud Account, T1204 User Execution.

## 2. Quem é

> LAPSUS$ is cyber criminal threat group that has been active since at least mid-2021. LAPSUS$ specializes in large-scale social engineering and extortion operations, including destructive attacks without the use of ransomware. The group has targeted organizations globally, including in the government, manufacturing, higher education, energy, healthcare, technology, telecommunications, and media sectors.

_Texto original do MITRE ATT&CK, em inglês._

## 3. Contexto, nomes e alvos

Consolidado pelo [APT4ALL](https://github.com/Ridd1kulusC0d3r/apt4all) a partir de MISP Galaxy, planilha APT Groups & Operations, EternalLiberty e APTnotes. Atribuição é afirmação de quem publicou; confira a fonte.

| Campo | Valor |
|---|---|
| Origem atribuída | Sem país atribuído |
| Motivação | financeiro, sabotagem |
| Setores-alvo | — |
| Vítimas citadas | — |
| Alvos (planilha) | — |
| Operações conhecidas | — |
| Confiança de atribuição (MISP) | High |

**Como cada fornecedor chama este grupo** (útil para cruzar relatórios):

| Fornecedor | Nome(s) |
|---|---|
| MITRE ATT&CK | G1004 |
| Microsoft | Strawberry Tempest, DEV-0537 (antigo · old) |

**Outros nomes no APT4ALL (não listados pelo ATT&CK):** SLIPPY SPIDER, UNC3661, DEV-0537/Strawberry Tempest, Gold Rainforest, White Dev 111

## 4. Perfil TTP por tática (kill chain)

Cada linha: técnica, como o grupo a usou segundo relatos públicos, e o que existe para detectar e testar.

### Reconnaissance (TA0043) — 8

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1589](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1589) Gather Victim Identity Information | LAPSUS$ has gathered detailed information of target employees to enhance their social engineering lures. | 11 | — | — |
| [T1589.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1589.001) Credentials | LAPSUS$ has gathered user identities and credentials to gain initial access to a victim's organization; the group has also called an organization's help desk to reset a target's credentials. | 2 | — | — |
| [T1589.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1589.002) Email Addresses | LAPSUS$ has gathered employee email addresses, including personal accounts, for social engineering and initial access efforts. | 5 | — | — |
| [T1591.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1591.002) Business Relationships | LAPSUS$ has gathered detailed knowledge of an organization's supply chain relationships. | 2 | — | — |
| [T1591.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1591.004) Identify Roles | LAPSUS$ has gathered detailed knowledge of team structures within a target organization. | 2 | — | — |
| [T1593.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1593.003) Code Repositories | LAPSUS$ has searched public code repositories for exposed credentials. | 6 | — | — |
| [T1597.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1597.002) Purchase Technical Data | LAPSUS$ has purchased credentials and session tokens from criminal underground forums. | **0** | — | — |
| [T1598.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1598.004) Spearphishing Voice | LAPSUS$ has called victims' help desk to convince the support personnel to reset a privileged account’s credentials. | **0** | — | — |

### Resource Development (TA0042) — 5

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1583.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1583.003) Virtual Private Server | LAPSUS$ has used VPS hosting providers for infrastructure. | **0** | — | — |
| [T1584.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1584.002) DNS Server | LAPSUS$ has reconfigured a victim's DNS records to actor-controlled domains and websites. | 4 | — | — |
| [T1586.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1586.002) Email Accounts | LAPSUS$ has payed employees, suppliers, and business partners of target organizations for credentials. | 3 | — | — |
| [T1588.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1588.001) Malware | LAPSUS$ acquired and used the Redline password stealer in their operations. | 7 | — | — |
| [T1588.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1588.002) Tool | LAPSUS$ has obtained tools such as RVTools and AD Explorer for their operations. | 35 | — | — |

### Initial Access (TA0001) — 4

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | LAPSUS$ has used compromised credentials and/or session tokens to gain access into a victim's VPN, VDI, RDP, and IAMs. | 825 | — | 3 |
| [T1078.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.004) Cloud Accounts | LAPSUS$ has used compromised credentials to access cloud assets within a target organization. | 356 | 3 | — |
| [T1133](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1133) External Remote Services | LAPSUS$ has gained access to internet-facing systems and applications, including virtual private network (VPN), remote desktop protocol (RDP), and virtual desktop infrastructure (VDI) including Citrix. | 361 | 1 | — |
| [T1199](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1199) Trusted Relationship | LAPSUS$ has accessed internet-facing identity providers such as Azure Active Directory and Okta to target specific organizations. | 18 | — | — |

### Execution (TA0002) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1204](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1204) User Execution | LAPSUS$ has recruited target organization employees or contractors who provide credentials and approve an associated MFA prompt, or install remote management software onto a corporate workstation, allowing LAPSUS$ to take control of an authenticated system. | 326 | — | 1 |

### Persistence (TA0003) — 5

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | LAPSUS$ has used compromised credentials and/or session tokens to gain access into a victim's VPN, VDI, RDP, and IAMs. | 825 | — | 3 |
| [T1078.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.004) Cloud Accounts | LAPSUS$ has used compromised credentials to access cloud assets within a target organization. | 356 | 3 | — |
| [T1098.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1098.003) Additional Cloud Roles | LAPSUS$ has added the global admin role to accounts they have created in the targeted organization's cloud instances. | 122 | 2 | — |
| [T1133](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1133) External Remote Services | LAPSUS$ has gained access to internet-facing systems and applications, including virtual private network (VPN), remote desktop protocol (RDP), and virtual desktop infrastructure (VDI) including Citrix. | 361 | 1 | — |
| [T1136.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1136.003) Cloud Account | LAPSUS$ has created global admin accounts in the targeted organization's cloud instances to gain persistence. | 53 | 3 | — |

### Privilege Escalation (TA0004) — 4

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1068](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1068) Exploitation for Privilege Escalation | LAPSUS$ has exploited unpatched vulnerabilities on internally accessible servers including JIRA, GitLab, and Confluence for privilege escalation. | 408 | 2 | 2 |
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | LAPSUS$ has used compromised credentials and/or session tokens to gain access into a victim's VPN, VDI, RDP, and IAMs. | 825 | — | 3 |
| [T1078.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.004) Cloud Accounts | LAPSUS$ has used compromised credentials to access cloud assets within a target organization. | 356 | 3 | — |
| [T1098.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1098.003) Additional Cloud Roles | LAPSUS$ has added the global admin role to accounts they have created in the targeted organization's cloud instances. | 122 | 2 | — |

### Stealth (TA0005) — 3

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | LAPSUS$ has used compromised credentials and/or session tokens to gain access into a victim's VPN, VDI, RDP, and IAMs. | 825 | — | 3 |
| [T1078.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.004) Cloud Accounts | LAPSUS$ has used compromised credentials to access cloud assets within a target organization. | 356 | 3 | — |
| [T1684.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1684.001) Impersonation | LAPSUS$ has called victims' help desk and impersonated legitimate users with previously gathered information in order to gain access to privileged accounts. | 1 | — | — |

### Defense Impairment (TA0112) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1578.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1578.002) Create Cloud Instance | LAPSUS$ has created new virtual machines within the target's cloud environment after leveraging credential access to cloud assets. | 6 | — | — |
| [T1578.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1578.003) Delete Cloud Instance | LAPSUS$ has deleted the target's systems and resources in the cloud to trigger the organization's incident and crisis response process. | 4 | — | — |

### Credential Access (TA0006) — 7

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1003.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1003.003) NTDS | LAPSUS$ has used Windows built-in tool `ntdsutil` to extract the Active Directory (AD) database. | 157 | 11 | 2 |
| [T1003.006](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1003.006) DCSync | LAPSUS$ has used DCSync attacks to gather credentials for privilege escalation routines. | 33 | 2 | 2 |
| [T1111](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1111) Multi-Factor Authentication Interception | LAPSUS$ has replayed stolen session token and passwords to trigger simple-approval MFA prompts in hope of the legitimate user will grant necessary approval. | 3 | — | — |
| [T1552.008](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1552.008) Chat Messages | LAPSUS$ has targeted various collaboration tools like Slack, Teams, JIRA, Confluence, and others to hunt for exposed credentials to support privilege escalation and lateral movement. | 2 | — | — |
| [T1555.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1555.003) Credentials from Web Browsers | LAPSUS$ has obtained passwords and session tokens with the use of the Redline password stealer. | 59 | 18 | 5 |
| [T1555.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1555.005) Password Managers | LAPSUS$ has accessed local password managers and databases to obtain further credentials from a compromised network. | 6 | — | — |
| [T1621](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1621) Multi-Factor Authentication Request Generation | LAPSUS$ has spammed target users with MFA prompts in the hope that the legitimate user will grant necessary approval. | 27 | — | — |

### Discovery (TA0007) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1069.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1069.002) Domain Groups | LAPSUS$ has used the AD Explorer tool to enumerate groups on a victim's network. | 91 | 15 | — |
| [T1087.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1087.002) Domain Account | LAPSUS$ has used the AD Explorer tool to enumerate users on a victim's network. | 180 | 25 | 1 |

### Collection (TA0009) — 6

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1005) Data from Local System | LAPSUS$ uploaded sensitive files, information, and credentials from a targeted organization for extortion or public release. | 170 | 3 | — |
| [T1114.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1114.003) Email Forwarding Rule | LAPSUS$ has set an Office 365 tenant level mail transport rule to send all mail in and out of the targeted organization to the newly created account. | 10 | 1 | — |
| [T1213.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1213.001) Confluence | LAPSUS$ has searched a victim's network for collaboration platforms like Confluence and JIRA to discover further high-privilege account credentials. | **0** | — | — |
| [T1213.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1213.002) Sharepoint | LAPSUS$ has searched a victim's network for collaboration platforms like SharePoint to discover further high-privilege account credentials. | 7 | — | — |
| [T1213.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1213.003) Code Repositories | LAPSUS$ has searched a victim's network for code repositories like GitLab and GitHub to discover further high-privilege account credentials. | 21 | — | — |
| [T1213.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1213.005) Messaging Applications | LAPSUS$ has searched a victim's network for organization collaboration channels like MS Teams or Slack to discover further high-privilege account credentials. | **0** | — | — |

### Command and Control (TA0011) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1090](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1090) Proxy | LAPSUS$ has leverage NordVPN for its egress points when targeting intended victims. | 162 | — | 1 |

### Impact (TA0040) — 3

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1485](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1485) Data Destruction | LAPSUS$ has deleted the target's systems and resources both on-premises and in the cloud. | 215 | 5 | — |
| [T1489](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1489) Service Stop | LAPSUS$ has shut down virtual machines from within a victim's on-premise VMware ESXi infrastructure. | 112 | 9 | — |
| [T1531](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1531) Account Access Removal | LAPSUS$ has removed a targeted organization's global admin accounts to lock the organization out of all access. | 101 | 8 | — |

## 5. Assinatura comportamental

Técnicas que este grupo usa e que poucos dos 178 grupos do ATT&CK usam. Pesam mais numa atribuição por TTP: ver várias delas juntas é mais informativo do que ver técnicas comuns como PowerShell.

| Técnica | Outros grupos que usam | Peso (raridade) |
|---|---:|---:|
| T1213.001 Confluence | 0 | 4.49 |
| T1552.008 Chat Messages | 0 | 4.49 |
| T1597.002 Purchase Technical Data | 0 | 4.49 |
| T1136.003 Cloud Account | 1 | 4.09 |
| T1204 User Execution | 1 | 4.09 |
| T1531 Account Access Removal | 1 | 4.09 |
| T1578.002 Create Cloud Instance | 1 | 4.09 |
| T1578.003 Delete Cloud Instance | 1 | 4.09 |
| T1584.002 DNS Server | 1 | 4.09 |
| T1598.004 Spearphishing Voice | 1 | 4.09 |

## 6. Arsenal

| Software | Tipo | Técnicas no ATT&CK | Uso relatado (EN) |
|---|---|---:|---|
| [Mimikatz](https://attack.mitre.org/software/S0002/) | ferramenta | 17 |  |

### Ferramentas observadas em intrusões (Lapsus$) — Ransomware Tool Matrix

Ferramentas legítimas e ofensivas que afiliados usam dentro da rede. Cada uma é um ponto de detecção: veja quantas regras do catálogo a citam.

| Ferramenta | Categoria | Regras que citam |
|---|---|---:|
| Mimikatz | credenciais | 253 |
| AnyDesk | rmm | 102 |
| NTDS Utility (ntdsutil) | lolbas | 51 |
| ADExplorer | descoberta | 32 |

## 7. Campanhas

Nenhuma campanha atribuída no ATT&CK.

## 8. Cobertura defensiva

**38 de 43 técnicas (88%)** têm ao menos uma regra pública no catálogo Detection Rules.

### Técnicas sem regra pública (prioridade para engenharia de detecção)

- **T1213.001 Confluence** — Collection. Fonte de log sugerida pelo MITRE: `saas:confluence` access.content
- **T1597.002 Purchase Technical Data** — Reconnaissance
- **T1598.004 Spearphishing Voice** — Reconnaissance. Fonte de log sugerida pelo MITRE: `Application Log` None
- **T1213.005 Messaging Applications** — Collection. Fonte de log sugerida pelo MITRE: `saas:slack` conversations.history, files.list, users.info, audit_logs; `m365:unified` TeamsMessagesAccessedViaEDiscovery, TeamsGraphMessageExport
- **T1583.003 Virtual Private Server** — Resource Development. Fonte de log sugerida pelo MITRE: `Internet Scan` None

### Onde procurar — cobertura por tecnologia

Quantas técnicas deste grupo têm ao menos uma regra em cada tecnologia. Comece a caça pelas tecnologias que você tem e que aparecem aqui.

| Tecnologia | Técnicas do grupo com regra |
|---|---:|
| Windows | 24 |
| Outros / genérico | 20 |
| Azure (recursos) | 19 |
| E-mail | 18 |
| Integridade, conformidade & vulnerabilidade | 18 |
| EDR / XDR | 17 |
| Linux | 17 |
| AWS | 17 |
| Active Directory | 16 |
| Entra ID (Azure AD) | 16 |
| Microsoft 365 | 16 |
| Bancos de dados | 14 |

### Regras recomendadas por técnica

Melhor regra disponível por técnica (formato portável e maduro primeiro).

| Técnica | Regra | Formato | Fonte |
|---|---|---|---|
| T1003.003 | [Potential Russian APT Credential Theft Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab83f5166-9237-4b5e-9cd4-7b5d52f4d8ee) | Sigma | SigmaHQ |
| T1003.003 | [VolumeShadowCopy Symlink Creation Via Mklink](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A40b19fa6-d835-400c-b301-41f3a2baacaf) | Sigma | SigmaHQ |
| T1003.006 | [HackTool - Mimikatz Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aa642964e-bead-4bed-8910-1bb4d63e3b4d) | Sigma | SigmaHQ |
| T1003.006 | [Mimikatz Use](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A06d71506-7beb-4f22-8888-e2e5e2ca7fd8) | Sigma | SigmaHQ |
| T1005 | [Potential Conti Ransomware Database Dumping Activity Via SQLCmd](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A2f47f1fd-0901-466e-a770-3b7092834a1b) | Sigma | SigmaHQ |
| T1005 | [OpenCanary - SMB File Open Request](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A22777c9e-873a-4b49-855f-6072ab861a52) | Sigma | SigmaHQ |
| T1068 | [Exploiting CVE-2019-1388](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A02e0b2ea-a597-428e-b04a-af6a1a403e5c) | Sigma | SigmaHQ |
| T1068 | [OMIGOD HTTP No Authentication RCE - CVE-2021-38647](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aab6b1a39-a9ee-4ab4-b075-e83acf6e346b) | Sigma | SigmaHQ |
| T1069.002 | [BloodHound Collection Files](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A02773bed-83bf-469f-b7ff-e676e7d78bab) | Sigma | SigmaHQ |
| T1069.002 | [HackTool - SharpView Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab2317cfa-4a47-4ead-b3ff-297438c0bc2d) | Sigma | SigmaHQ |
| T1078 | [Privilege Role Sign-In Outside Expected Controls](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acf1e5687-84e1-41af-97a9-158094efef53) | Sigma | SigmaHQ |
| T1078 | [OpenCanary - SSH Login Attempt](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aff7139bc-fdb1-4437-92f2-6afefe8884cb) | Sigma | SigmaHQ |
| T1078.004 | [Okta New Admin Console Behaviours](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aa0b38b70-3cb5-484b-a4eb-c4d8e7bcc0a9) | Sigma | SigmaHQ |
| T1078.004 | [AWS IAM S3Browser User or AccessKey Creation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Adb014773-d9d9-4792-91e5-133337c0ffee) | Sigma | SigmaHQ |
| T1087.002 | [BloodHound Collection Files](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A02773bed-83bf-469f-b7ff-e676e7d78bab) | Sigma | SigmaHQ |
| T1087.002 | [Suspicious Active Directory Database Snapshot Via ADExplorer](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aef61af62-bc74-4f58-b49b-626448227652) | Sigma | SigmaHQ |
| T1090 | [Communication To LocaltoNet Tunneling Service Initiated - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac4568f5d-131f-4e78-83d4-45b2da0ec4f1) | Sigma | SigmaHQ |
| T1090 | [Communication To Ngrok Tunneling Service - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A19bf6fdb-7721-4f3d-867f-53467f6a5db6) | Sigma | SigmaHQ |
| T1098.003 | [App Granted Privileged Delegated Or App Permissions](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A5aecf3d5-f8a0-48e7-99be-3a759df7358f) | Sigma | SigmaHQ |
| T1098.003 | [App Granted Privileged Delegated Or App Permissions](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A5aecf3d5-f8a0-48e7-99be-3a759df7358f) | Sigma | OpenSearch Security Analytics |
| T1111 | [Attempted Bypass of Okta MFA](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A3805c3dc-f82c-4f8d-891e-63c24d3102b0) | Elastic | Elastic detection-rules |
| T1111 | [Possible AiTM Phishing Attempt Against Microsoft Entra ID](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A16daa67c-b137-48dc-8eb7-76598a44791a) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1114.003 | [Google Workspace Gmail Routing or Forwarding Rule Created or Modified](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A9510add4-3392-11ed-bd01-f661ea17fbce) | Elastic | Elastic detection-rules |
| T1114.003 | [Mail Forwarding/Redirecting Activity In O365](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac726e007-2cd0-4a55-abfb-79730fbedee5) | Sigma | SigmaHQ |
| T1133 | [OpenCanary - SSH Login Attempt](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aff7139bc-fdb1-4437-92f2-6afefe8884cb) | Sigma | SigmaHQ |
| T1133 | [OpenCanary - SSH New Connection Attempt](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acd55f721-5623-4663-bd9b-5229cab5237d) | Sigma | SigmaHQ |
| T1136.003 | [AWS IAM Sensitive Operations via Lambda Execution Role](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Aa8f3c2e1-4d5b-4e6f-8a9b-0c1d2e3f4a5b) | Elastic | Elastic detection-rules |
| T1136.003 | [AWS IAM Create User via Assumed Role on EC2 Instance](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Af7a1c536-9ac0-11ef-9911-f661ea17fbcd) | Elastic | Elastic detection-rules |
| T1199 | [Microsoft 365 - User Restricted from Sending Email](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aff246f56-7f24-402a-baca-b86540e3925c) | Sigma | SigmaHQ |
| T1199 | [Microsoft 365 - User Restricted from Sending Email](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Aff246f56-7f24-402a-baca-b86540e3925c) | Sigma | OpenSearch Security Analytics |
| T1204 | [Potential Snatch Ransomware Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A5325945e-f1f0-406e-97b8-65104d393fff) | Sigma | SigmaHQ |
| T1204 | [Antivirus - Hacktool Signature](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Afa0c05b6-8ad3-468d-8231-c1cbccb64fba) | Sigma | SigmaHQ |
| T1213.002 | [M365 SharePoint/OneDrive File Access via PowerShell](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A491651da-125b-11f1-af7d-f661ea17fbce) | Elastic | Elastic detection-rules |
| T1213.002 | [Entra ID Sharepoint or OneDrive Accessed by Unusual Client](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Aa3cc60d8-2701-11f0-accf-f661ea17fbcd) | Elastic | Elastic detection-rules |
| T1213.003 | [Bitbucket Unauthorized Full Data Export Triggered](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A34d81081-03c9-4a7f-91c9-5e46af625cde) | Sigma | SigmaHQ |
| T1213.003 | [Bitbucket Full Data Export Triggered](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A195e1b9d-bfc2-4ffa-ab4e-35aef69815f8) | Sigma | SigmaHQ |
| T1485 | [Fsutil Suspicious Invocation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aadd64136-62e5-48ea-807e-88638d02df1e) | Sigma | SigmaHQ |
| T1485 | [Potential BlackByte Ransomware Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A999e8307-a775-4d5f-addc-4855632335be) | Sigma | SigmaHQ |
| T1489 | [Delete Important Scheduled Task](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Adbc1f800-0fe0-4bc0-9c66-292c2abe3f78) | Sigma | SigmaHQ |
| T1489 | [Suspicious Windows Service Tampering](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ace72ef99-22f1-43d4-8695-419dcb5d9330) | Sigma | SigmaHQ |
| T1531 | [Potential Destructive AWS CLI Command Executed by GenAI Agent](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A2635d2ba-51e7-404a-9b17-db413a1351d5) | Elastic | Elastic detection-rules |
| T1531 | [Google Workspace MFA Enforcement Disabled For Organization](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Acad4500a-abd7-4ef3-b5d3-95524de7cfe1) | Elastic | Elastic detection-rules |
| T1552.008 | [Slack Workspace Files Accessed by Osascript](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-protections-artifacts-behavior%3A%3A0e99bc1e-caeb-4a6e-b5ca-5d0d1ee6916c) | Elastic | Elastic protections-artifacts (behavior) |
| T1552.008 | [Slack Workspace Files Accessed by Unsigned or Untrusted Process](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-protections-artifacts-behavior%3A%3A2f1ca71e-536b-4721-9aa8-06bc019541de) | Elastic | Elastic protections-artifacts (behavior) |
| T1555.003 | [SQLite Chromium Profile Data DB Access](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A24c77512-782b-448a-8950-eddb0785fc71) | Sigma | SigmaHQ |
| T1555.003 | [HackTool - WinPwn Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad557dc06-62e8-4468-a8e8-7984124908ce) | Sigma | SigmaHQ |
| T1555.005 | [Remote Thread Created In KeePass.EXE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A77564cc2-7382-438b-a7f6-395c2ae53b9a) | Sigma | SigmaHQ |
| T1555.005 | [KeePass Password Dumping](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A77564cc2-7382-438b-a7f6-395c2ae53b9a) | Sigma | OpenSearch Security Analytics |
| T1578.002 | [AWS RDS DB Instance Restored](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Abf1073bf-ce26-4607-b405-ba1ed8e9e204) | Elastic | Elastic detection-rules |
| T1578.002 | [Azure VM Extension Deployment by User](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ae842d39d-ead1-48c6-97f1-6b055476c2f3) | Elastic | Elastic detection-rules |
| T1578.003 | [Azure Active Directory Hybrid Health AD FS Service Delete](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A48739819-8230-4ee3-a8ea-e0289d1fb0ff) | Sigma | SigmaHQ |
| T1578.003 | [Azure Active Directory Hybrid Health AD FS Service Delete](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A48739819-8230-4ee3-a8ea-e0289d1fb0ff-2d1a19373b08) | Sigma | OpenSearch Security Analytics |
| T1584.002 | [GCP Audit Logs - DNSSEC Disabled on Managed DNS Zone](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A9129a43e-e204-4a9a-969e-d8861ce3437c) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1584.002 | [Amazon Security Lake - Route 53 - Succsessful DNS request [$(query.type)] "$(query.hostname)" from $(src_endpo](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=wazuh-ruleset-oficial%3A%3Awazuh-99080) | Wazuh | Wazuh ruleset (oficial) |
| T1586.002 | [CYFIRMA - Brand Intelligence - Domain Impersonation High Rule](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A10bdf525-5b89-4a25-933a-e63e73b915f1) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1586.002 | [CYFIRMA - Brand Intelligence - Domain Impersonation Medium Rule](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A8f97ddbe-ab66-4f6c-b675-73b5eeb07259) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1588.001 | [Relevant ClamAV Message](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A36aa86ca-fd9d-4456-814e-d3b1b8e1e0bb) | Sigma | SigmaHQ |
| T1588.001 | [Relevant ClamAV Message](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A36aa86ca-fd9d-4456-814e-d3b1b8e1e0bb) | Sigma | OpenSearch Security Analytics |
| T1588.002 | [Hacktool Execution - Imphash](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A24e3e58a-646b-4b50-adef-02ef935b9fc8) | Sigma | SigmaHQ |
| T1588.002 | [Renamed SysInternals DebugView Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acd764533-2e07-40d6-a718-cfeec7f2da7f) | Sigma | SigmaHQ |
| T1589 | [SSHD Error Message CVE-2018-15473](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4c9d903d-4939-4094-ade0-3cb748f4d7da) | Sigma | SigmaHQ |
| T1589 | [SSHD Error Message CVE-2018-15473](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A4c9d903d-4939-4094-ade0-3cb748f4d7da) | Sigma | OpenSearch Security Analytics |
| T1589.001 | [Linux Medusa Rootkit](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=splunk-security-content%3A%3A7add8520-71d5-43aa-b262-ee082b1f0238) | Splunk | Splunk security_content |
| T1589.001 | [MS Graph message: A user's credentials were compromised or stolen. This is a true positive alert.](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=wazuh-ruleset-oficial%3A%3Awazuh-99612) | Wazuh | Wazuh ruleset (oficial) |
| T1589.002 | [Potential Unconstrained Delegation Discovery Via Get-ADComputer - ScriptBlock](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acdfa73b6-3c9d-4bb8-97f8-ddbd8921f5c5) | Sigma | SigmaHQ |
| T1589.002 | [AWSCloudTrail - Suspicious AWS CLI Command Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A8c2dc344-9352-4ca1-8863-b1b7a5e09e59) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1591.002 | [CYFIRMA - Brand Intelligence - Social Media Handle Impersonation Detected High Rule](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A22f49d67-7da7-4809-8d07-89e4478aa6b0) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1591.002 | [CYFIRMA - Brand Intelligence - Social Media Handle Impersonation Detected Medium Rule](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A710f4755-490d-4fa7-aef0-43b5a66edc7b) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1591.004 | [Bitbucket User Permissions Export Attempt](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A87cc6698-3e07-4ba2-9b43-a85a73e151e2) | Sigma | SigmaHQ |
| T1591.004 | [Bitbucket User Details Export Attempt Detected](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A5259cbf2-0a75-48bf-b57a-c54d6fabaef3) | Sigma | SigmaHQ |
| T1593.003 | [Suspicious Git Clone - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acfec9d29-64ec-4a0f-9ffe-0fdb856d5446) | Sigma | SigmaHQ |
| T1593.003 | [Suspicious Git Clone](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aaef9d1f1-7396-4e92-a927-4567c7a495c1) | Sigma | SigmaHQ |
| T1621 | [Potentially Successful Okta MFA Bombing via Push Notifications](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A97a8e584-fd3b-421f-9b9d-9c9d9e57e9d7) | Elastic | Elastic detection-rules |
| T1621 | [Potential Okta MFA Bombing via Push Notifications](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A8a0fbd26-867f-11ee-947c-f661ea17fbcd) | Elastic | Elastic detection-rules |
| T1684.001 | [Entra ID OAuth user_impersonation Scope for Unusual User and Client](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A9563dace-5822-11f0-b1d3-f661ea17fbcd) | Elastic | Elastic detection-rules |

## 9. Plano de emulação e validação

Use num laboratório isolado e autorizado para confirmar que as regras disparam. Os comandos estão nos repositórios oficiais.

| Tática | Técnica | Teste Atomic Red Team | Plataformas |
|---|---|---|---|
| Persistence | [T1098.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1098.003/T1098.003.md) | Azure AD - Add Company Administrator Role to a user | azure-ad |
| Persistence | [T1098.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1098.003/T1098.003.md) | Simulate - Post BEC persistence via user password reset followed by user added to company administrator role | azure-ad |
| Persistence | [T1133](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1133/T1133.md) | Running Chrome VPN Extensions via the Registry 2 vpn extension | windows |
| Persistence | [T1136.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1136.003/T1136.003.md) | AWS - Create a new IAM user | iaas:aws |
| Persistence | [T1136.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1136.003/T1136.003.md) | Azure AD - Create a new user | azure-ad |
| Privilege Escalation | [T1068](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1068/T1068.md) | Scattered Spider BYOVD (CVE-2015-2291 for Intel Ethernet Diagnostics Driver) | windows |
| Privilege Escalation | [T1068](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1068/T1068.md) | Turla Snake Malware Privilege Escalation Through VM Driver | windows |
| Stealth | [T1078.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1078.004/T1078.004.md) | Creating GCP Service Account and Service Account Key | google-workspace, iaas:gcp |
| Stealth | [T1078.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1078.004/T1078.004.md) | Azure Persistence Automation Runbook Created or Modified | iaas:azure |
| Credential Access | [T1003.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.003/T1003.003.md) | Create Volume Shadow Copy with vssadmin | windows |
| Credential Access | [T1003.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.003/T1003.003.md) | Copy NTDS.dit from Volume Shadow Copy | windows |
| Credential Access | [T1003.006](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.006/T1003.006.md) | DCSync (Active Directory) | windows |
| Credential Access | [T1003.006](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.006/T1003.006.md) | Run DSInternals Get-ADReplAccount | windows |
| Credential Access | [T1555.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1555.003/T1555.003.md) | Run Chrome-password Collector | windows |
| Credential Access | [T1555.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1555.003/T1555.003.md) | Search macOS Safari Cookies | macos |
| Discovery | [T1069.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1069.002/T1069.002.md) | Basic Permission Groups Discovery Windows (Domain) | windows |
| Discovery | [T1069.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1069.002/T1069.002.md) | Permission Groups Discovery PowerShell (Domain) | windows |
| Discovery | [T1087.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1087.002/T1087.002.md) | Enumerate all accounts (Domain) | windows |
| Discovery | [T1087.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1087.002/T1087.002.md) | Enumerate all accounts via PowerShell (Domain) | windows |
| Collection | [T1005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1005/T1005.md) | Search files of interest and save them to a single zip file (Windows) | windows |
| Collection | [T1005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1005/T1005.md) | Find and dump sqlite databases (Linux) | linux |
| Collection | [T1114.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1114.003/T1114.003.md) | Office365 - Email Forwarding | office-365 |
| Impact | [T1485](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1485/T1485.md) | Windows - Overwrite file with SysInternals SDelete | windows |
| Impact | [T1485](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1485/T1485.md) | FreeBSD/macOS/Linux - Overwrite file with DD | linux, macos |
| Impact | [T1489](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1489/T1489.md) | Windows - Stop service using Service Controller | windows |
| Impact | [T1489](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1489/T1489.md) | Windows - Stop service using net.exe | windows |
| Impact | [T1531](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1531/T1531.md) | Change User Password - Windows | windows |
| Impact | [T1531](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1531/T1531.md) | Delete User - Windows | windows |

**Logs reais de ataque (EVTX) para testar sem executar nada:**

- T1003.003 — [dc_applog_ntdsutil_dfir_325_326_327](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Credential%20Access/dc_applog_ntdsutil_dfir_325_326_327.evtx) _(inferido)_
- T1003.003 — [LM_regsvc_DirectoryServiceExtPt_Lsass_NTDS_AdamXpn](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Lateral%20Movement/LM_regsvc_DirectoryServiceExtPt_Lsass_NTDS_AdamXpn.evtx) _(inferido)_
- T1003.006 — [CA_DCSync_4662](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Credential%20Access/CA_DCSync_4662.evtx) _(inferido)_
- T1003.006 — [DACL_DCSync_Right_Powerview_ Add-DomainObjectAcl](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Persistence/DACL_DCSync_Right_Powerview_%20Add-DomainObjectAcl.evtx) _(inferido)_
- T1068 — [ID12-13 Mini_Plasma_PoC_AbortHydration_ArbitraryRegKey_EoP](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0004-Privilege%20Escalation/T1068-Exploitation%20for%20Privilege%20Escalation/ID12-13%20Mini_Plasma_PoC_AbortHydration_ArbitraryRegKey_EoP.evtx) _(explícito)_
- T1068 — [ID4673-Privilege SeMachineAccountPrivilege called](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0004-Privilege%20Escalation/T1068-Exploitation%20for%20Privilege%20Escalation/ID4673-Privilege%20SeMachineAccountPrivilege%20called.evtx) _(explícito)_
- T1078 — [ID1149-RDP success logins to multiple hosts](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0001-Initial%20access/T1078-Valid%20accounts/ID1149-RDP%20success%20logins%20to%20multiple%20hosts.evtx) _(explícito)_
- T1078 — [ID33205-SQL Server failed login with disabled SA account](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0001-Initial%20access/T1078-Valid%20accounts/ID33205-SQL%20Server%20failed%20login%20with%20disabled%20SA%20account.evtx) _(explícito)_
- T1087.002 — [discovery_bloodhound](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Discovery/discovery_bloodhound.evtx) _(inferido)_
- T1090 — [ID5600-proxy configuration changed](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0011-Command%20and%20Control/T1090-Proxy/ID5600-proxy%20configuration%20changed.evtx) _(explícito)_
- T1204 — [ID4688-Edge payload download via command](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1204-User%20execution/ID4688-Edge%20payload%20download%20via%20command.evtx) _(explícito)_
- T1555.003 — [CA_4624_4625_LogonType2_LogonProc_chrome](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Credential%20Access/CA_4624_4625_LogonType2_LogonProc_chrome.evtx) _(inferido)_
- T1555.003 — [CA_chrome_firefox_opera_4663](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Credential%20Access/CA_chrome_firefox_opera_4663.evtx) _(inferido)_

## 10. Hipóteses de hunting

Se LAPSUS$ estiver no seu ambiente, estas são as perguntas a fazer aos seus dados (fontes de log segundo as estratégias de detecção do MITRE ATT&CK).

1. **T1213.001 Confluence** — Detection of excessive or programmatic access to Confluence spaces or pages, particularly by privileged users, through a combination of access logs, API usage, and identity context. Correlates logon sessions, user roles, and abnormal document viewing or… Dados: `saas:confluence` (access.content), `saas:confluence` (logon), `saas:confluence` (REST API access from non-browser agents).
2. **T1552.008 Chat Messages** — Detection correlates message events in email and collaboration tools (e.g., Outlook, Teams) that contain regex-like patterns resembling credentials, API keys, or tokens. Anomalous forwarding or bulk copy activity of chat/email content containing secrets is… Dados: `m365:unified` (MessageSend, MessageRead, or FileAttached events containing credential-like patterns).
3. **T1136.003 Cloud Account** — Adversaries create user accounts via identity provider APIs or admin portals (e.g., Azure AD, Okta). These accounts may be assigned elevated privileges or used in chained authentication. Detection monitors Add User activity from suspicious IPs or automation… Dados: `azure:audit` (Add user), `azure:audit` (Add member to role), `azure:signinlogs` (Login from newly created account).
4. **T1204 User Execution** — Cause→effect chain: (1) User-facing app (Office/PDF/archiver/browser) records an open/click or abnormal event, then (2) a downloaded file is created in a user-writable path and/or decompressed, (3) the parent user app spawns a living-off-the-land binary… Dados: `WinEventLog:Application` (EventCode=1000), `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Security` (EventCode=4688).
5. **T1531 Account Access Removal** — Correlated user account modification (reset, disable, deletion) events with anomalous process lineage (e.g., PowerShell or net.exe from an interactive session), especially outside of IT admin change windows or by non-admin users. Dados: `WinEventLog:Security` (EventCode=4723, 4724, 4740), `WinEventLog:Sysmon` (EventCode=1).
6. **T1578.002 Create Cloud Instance** — Detection focuses on abnormal or unauthorized cloud instance creation events. From a defender’s perspective, suspicious behavior includes VM/instance creation by rarely used or newly created accounts, creation events from unusual geolocations, or rapid… Dados: `AWS:CloudTrail` (RunInstances), `AWS:CloudTrail` (DescribeInstances), `azure:activity` (MICROSOFT.COMPUTE/VIRTUALMACHINES/WRITE).
7. **T1578.003 Delete Cloud Instance** — Defenders can detect suspicious cloud instance deletions by correlating events across authentication, instance lifecycle, and account activity. From a defender’s perspective, behaviors of interest include instances deleted shortly after creation, deletions… Dados: `AWS:CloudTrail` (TerminateInstances), `AWS:CloudTrail` (DescribeInstances), `azure:activity` (MICROSOFT.COMPUTE/VIRTUALMACHINES/DELETE).
8. **T1584.002 DNS Server** — Monitor for queried domain name system (DNS) registry data that may compromise third-party DNS servers that can be used during targeting. Much of this activity will take place outside the visibility of the target organization, making detection of this… Dados: `Domain Name` (None), `Domain Name` (None).
9. **T1598.004 Spearphishing Voice** — Monitor call logs from corporate devices to identify patterns of potential voice phishing, such as calls to/from known malicious phone numbers. Dados: `Application Log` (None).
10. **T1098.003 Additional Cloud Roles** — Detection of new IAM roles or policies attached to a user/service in AWS/GCP/Azure outside normal patterns or hours, often following account compromise. Dados: `AWS:CloudTrail` (AttachUserPolicy, CreatePolicyVersion, PutRolePolicy).
11. **T1621 Multi-Factor Authentication Request Generation** — Monitor for excessive or anomalous MFA push notifications or token requests, especially when login attempts originate from unusual IPs or geolocations and do not correspond to legitimate user-initiated sessions. Dados: `azure:signinlogs` (Multiple MFA challenge requests without successful primary login), `NSM:Connections` (PushNotificationSent).
12. **T1111 Multi-Factor Authentication Interception** — Behavior chain involving unexpected API calls to capture keyboard input, driver loads for keyloggers, or remote use of smart card authentication via logon sessions not initiated by local user interaction Dados: `WinEventLog:Sysmon` (EventCode=10), `WinEventLog:Security` (EventCode=4624, 4648), `WinEventLog:Sysmon` (EventCode=13, 14).

## 11. OSINT — onde pesquisar

Consultas prontas com todos os nomes conhecidos do grupo:

- Relatórios técnicos: [busca web](https://duckduckgo.com/?q=%28%22LAPSUS%24%22+OR+%22DEV-0537%22+OR+%22Strawberry+Tempest%22%29+threat+report) · [PDFs](https://duckduckgo.com/?q=%28%22LAPSUS%24%22+OR+%22DEV-0537%22+OR+%22Strawberry+Tempest%22%29+filetype%3Apdf)
- Regras e IOCs publicados: [GitHub](https://github.com/search?type=code&q=%22LAPSUS%24%22+OR+%22DEV-0537%22+OR+%22Strawberry+Tempest%22)
- Pulsos de ameaça: [AlienVault OTX](https://otx.alienvault.com/browse/global/pulses?q=LAPSUS%24)
- Família de malware e atores: [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/actors) (busque por LAPSUS$, DEV-0537, Strawberry Tempest)
- Cartões de grupo: [ThaiCERT Threat Group Cards](https://apt.etda.or.th/cgi-bin/listgroups.cgi)
- Página oficial: [MITRE ATT&CK G1004](https://attack.mitre.org/groups/G1004/)

## 12. Bibliografia (5 fontes citadas pelo ATT&CK)

- [BBC LAPSUS Apr 2022](https://www.bbc.com/news/technology-60953527) — BBC. (2022, April 1). LAPSUS: Two UK Teenagers Charged with Hacking for Gang. Retrieved June 9, 2022.
- [Microsoft Threat Actor Naming July 2023](https://learn.microsoft.com/en-us/microsoft-365/security/intelligence/microsoft-threat-actor-naming?view=o365-worldwide) — Microsoft . (2023, July 12). How Microsoft names threat actors. Retrieved November 17, 2023.
- [MSTIC DEV-0537 Mar 2022](https://www.microsoft.com/security/blog/2022/03/22/dev-0537-criminal-actor-targeting-organizations-for-data-exfiltration-and-destruction/) — MSTIC, DART, M365 Defender. (2022, March 24). DEV-0537 Criminal Actor Targeting Organizations for Data Exfiltration and Destruction. Retrieved May 17, 2022.
- [NCC Group LAPSUS Apr 2022](https://www.nccgroup.com/research-blog/lapsus-recent-techniques-tactics-and-procedures/) — Brown, D., et al. (2022, April 28). LAPSUS$: Recent techniques, tactics and procedures. Retrieved December 22, 2022.
- [UNIT 42 LAPSUS Mar 2022](https://unit42.paloaltonetworks.com/lapsus-group/) — UNIT 42. (2022, March 24). Threat Brief: Lapsus$ Group. Retrieved May 17, 2022.

## 13. Limites e confiança

- O ATT&CK registra o que foi **relatado publicamente**, não tudo o que o grupo faz. Ausência de uma técnica não prova que o grupo não a usa.
- **Sobreposição de TTP não é atribuição.** Muitas técnicas são compartilhadas entre grupos e com red teams. Use a assinatura comportamental como hipótese, junto com infraestrutura, malware e contexto.
- Cobertura de detecção refere-se ao catálogo público Detection Rules, não ao seu ambiente: confira se a telemetria necessária chega ao seu SIEM.
- Ligações marcadas como _inferidas_ (EVTX por palavra-chave, relatórios por nome) devem ser verificadas.

---
Fontes: MITRE ATT&CK® (uso livre com atribuição, © The MITRE Corporation), APT4ALL (MISP Galaxy CC0/BSD-2, APT Groups & Operations CC BY 4.0, EternalLiberty, APTnotes, Ransomware Tool Matrix CC BY 4.0), Atomic Red Team (Red Canary, MIT), EVTX-to-MITRE-Attack, EVTX-ATTACK-SAMPLES, APT & CyberCriminal Campaign Collections. Gerado por [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules).
