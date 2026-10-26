# TeamPCP (G1056) — Dossiê de inteligência

> **TLP:CLEAR** · gerado em 2026-10-26 a partir de fontes abertas · MITRE ATT&CK v20.0 · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1056) · [ATT&CK](https://attack.mitre.org/groups/G1056/)

**Também conhecido como:** PCPCat, ShellForce, DeadCatx3, SHADOW-WATER-058, UNC6780  
**Origem atribuída:** Sem país atribuído · **Motivação:** financeiro · **Setores-alvo:** —  
**Registro no ATT&CK:** criado em 2026-07-16, atualizado em 2026-09-02 · referências de 2026 a 2026

## 1. Sumário executivo

- **37 técnicas** atribuídas publicamente, concentradas em **Resource Development, Persistence, Stealth**.
- **Arsenal:** 3 malware e 0 ferramentas (ex.: Mini Shai-Hulud, TeamPCP Cloud Stealer, CanisterWorm).
- **Campanhas atribuídas:** 0.
- **Cobertura de detecção pública:** 86% das técnicas têm ao menos uma regra no catálogo; **5 técnicas sem nenhuma regra pública**.
- **Origem e alvos (APT4ALL):** atribuído a **Sem país atribuído**, motivação financeiro.
- **Onde a cobertura está:** Windows (23 técnicas com regra), Linux (23 técnicas com regra), EDR / XDR (22 técnicas com regra), DevOps & supply chain (21 técnicas com regra).
- **Assinatura comportamental** (técnicas raras entre os 178 grupos, as mais úteis para atribuição): T1176.002 IDE Extensions, T1546.016 Installer Packages, T1677 Poisoned Pipeline Execution, T1059.013 Container CLI/API, T1195.001 Compromise Software Dependencies and Development Tools.

## 2. Quem é

> TeamPCP is a financially-motivated, cloud-native threat group that has been active since at least September 2025. Initially focused on ransomware and cryptocurrency theft, TeamPCP shifted in early 2026 to systematic, worm-driven credential theft and software supply chain attacks targeting Continuous Integration and Continuous Delivery (CI/CD) workflows. TeamPCP has monetized access through extortion and through partnerships with ransomware actors including Vect and CipherForce.

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
| Confiança de atribuição (MISP) | — |

**Como cada fornecedor chama este grupo** (útil para cruzar relatórios):

| Fornecedor | Nome(s) |
|---|---|
| MITRE ATT&CK | G1056 |

**Outros nomes no APT4ALL (não listados pelo ATT&CK):** Altered Spider, CanisterWorm

## 4. Perfil TTP por tática (kill chain)

Cada linha: técnica, como o grupo a usou segundo relatos públicos, e o que existe para detectar e testar.

### Resource Development (TA0042) — 8

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1583](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1583) Acquire Infrastructure | In May 2026 TeamPCP announced co-ownership of the BreachForums cybercriminal forum claiming responsibility for platform operations, dispute resolution, personnel vetting, and hosting monetary contests. | 9 | — | — |
| [T1583.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1583.001) Domains | TeamPCP has registered domains resembling legitimate victim sites such as scan.aquasecurtiy[.]org, checkmarx[.]zone, and git-tanstack[.]com to mask C2 and exfiltration endpoints. TeamPCP has also set up a dark web leak site to post stolen data. | 7 | — | — |
| [T1583.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1583.004) Server | TeamPCP has leased infrastructure specifically for offensive operations including Google assets in AS396982. | **0** | — | — |
| [T1583.006](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1583.006) Web Services | TeamPCP has set up Clouflare Tunnels for malware C2. TeamPCP has also used the session messenger network for decentralized, encrypted exfiltration via  *.getsession[.]org to recipient  ID `05f9e609d79eed391015e11380dee4b5c9ead0b6e2e7f0134e6e51767a87323026`. | 2 | — | — |
| [T1585.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1585.001) Social Media Accounts | TeamPCP has used its own Telegram channel and X accounts @pcpcats and @xploitrsturtle2 for external communications. | 4 | — | — |
| [T1587.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1587.001) Malware | TeamPCP has developed and deployed custom malware including TeamPCP Cloud Stealer, CanisterWorm, and Mini Shai-Hulud. | 43 | — | — |
| [T1608.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1608.001) Upload Malware | TeamPCP has pushed GitHub commits that modified the actions/checkout to reference an imposter commit that downloaded malicious files from attacker-controlled C2 domains. | 3 | — | — |
| [T1683.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1683.001) Written Content | TeamPCP has created Dune-themed GitHub repositories using stolen tokens. | **0** | — | — |

### Initial Access (TA0001) — 4

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | TeamPCP has compromised credentials associated with open source security scanning tools and used them to push malicious code to all the resources the tools had access to. | 825 | — | 3 |
| [T1078.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.004) Cloud Accounts | TeamPCP has used compromised credentials for GitHub and software package repositories, including privileged service accounts, to inject malicious code into CI/CD pipelines. | 356 | 3 | — |
| [T1190](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1190) Exploit Public-Facing Application | TeamPCP has exploited misconfigurations in GitHub Actions and vulnerabilities such as CVE-2026-33634 in the Aqua Security Trivy scanner and CVE-2025-55182 (React2Shell) against vulnerable cloud endpoints. | 580 | — | — |
| [T1195.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1195.001) Compromise Software Dependencies and Development Tools | TeamPCP has conducted coordinated supply chain attacks targeting open-source developer infrastructure including the NPM, VS Code, Docker, and PyPi ecosystems to compromise multiple software packages. | 30 | — | — |

### Execution (TA0002) — 6

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1059.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.004) Unix Shell | TeamPCP has leveraged malware capable of execution via the Linux CLI. | 395 | 17 | — |
| [T1059.006](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.006) Python | TeamPCP has poisoned PyPi packages with malicious code and has used a 13 file modular Python framework for data collection. | 122 | — | — |
| [T1059.007](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.007) JavaScript | TeamPCP has used the JavaScript runtime for malware delivery and injected malicious JavaScript into OpenVSX extensions. | 205 | 5 | — |
| [T1059.013](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.013) Container CLI/API | TeamPCP has queried the Kubernetes API for local service account tokens and has used `kubectl` for lateral movement. | **0** | — | — |
| [T1610](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1610) Deploy Container | TeamPCP has deployed privileged DaemonSets to delete files on targeted Kubernetes clusters. | 45 | 1 | — |
| [T1677](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1677) Poisoned Pipeline Execution | TeamPCP has compromised trusted CI/CD pipelines by injecting credential-stealing payloads into legitimate workflows and software packages including open-source security tools Trivy and KICS, and AI gateway LiteLLM. | **0** | — | — |

### Persistence (TA0003) — 7

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | TeamPCP has compromised credentials associated with open source security scanning tools and used them to push malicious code to all the resources the tools had access to. | 825 | — | 3 |
| [T1078.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.004) Cloud Accounts | TeamPCP has used compromised credentials for GitHub and software package repositories, including privileged service accounts, to inject malicious code into CI/CD pipelines. | 356 | 3 | — |
| [T1098](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1098) Account Manipulation | TeamPCP has modified settings to publish private Aqua Security repositories to GitHub as public. | 535 | 17 | 30 |
| [T1176.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1176.002) IDE Extensions | TeamPCP has compromised VS Code and Open VSX IDE extensions. | **0** | — | — |
| [T1543.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1543.002) Systemd Service | TeamPCP has used the systemd user service for malware persistence in targeted environments. | 23 | 4 | — |
| [T1546.016](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1546.016) Installer Packages | TeamPCP has modified software packages with preinstall scripts to download and execute malicious payloads. | 16 | — | — |
| [T1547.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1547.001) Registry Run Keys / Startup Folder | TeamPCP has dropped malware into the Windows Startup folder to establish persistence. | 299 | 21 | 2 |

### Privilege Escalation (TA0004) — 6

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | TeamPCP has compromised credentials associated with open source security scanning tools and used them to push malicious code to all the resources the tools had access to. | 825 | — | 3 |
| [T1078.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.004) Cloud Accounts | TeamPCP has used compromised credentials for GitHub and software package repositories, including privileged service accounts, to inject malicious code into CI/CD pipelines. | 356 | 3 | — |
| [T1098](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1098) Account Manipulation | TeamPCP has modified settings to publish private Aqua Security repositories to GitHub as public. | 535 | 17 | 30 |
| [T1543.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1543.002) Systemd Service | TeamPCP has used the systemd user service for malware persistence in targeted environments. | 23 | 4 | — |
| [T1546.016](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1546.016) Installer Packages | TeamPCP has modified software packages with preinstall scripts to download and execute malicious payloads. | 16 | — | — |
| [T1547.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1547.001) Registry Run Keys / Startup Folder | TeamPCP has dropped malware into the Windows Startup folder to establish persistence. | 299 | 21 | 2 |

### Stealth (TA0005) — 6

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1027.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1027.003) Steganography | TeamPCP has hidden malicious payloads in the frame data of WAV audio files. | 13 | — | — |
| [T1036.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1036.005) Match Legitimate Resource Name or Location | TeamPCP has cloned GitHub commit metadata including the author name, email, committer, and timestamps to use for impostor commits. TeamPCP has also used legitimate file names such as msbuild.exe and ringtone.wav to mask malicious payloads. | 116 | 4 | — |
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | TeamPCP has compromised credentials associated with open source security scanning tools and used them to push malicious code to all the resources the tools had access to. | 825 | — | 3 |
| [T1078.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.004) Cloud Accounts | TeamPCP has used compromised credentials for GitHub and software package repositories, including privileged service accounts, to inject malicious code into CI/CD pipelines. | 356 | 3 | — |
| [T1564.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1564.001) Hidden Files and Directories | TeamPCP has used a hidden .lock file to establish a 12 hour cooldown period between re-drops for installed malware. | 76 | 10 | — |
| [T1684.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1684.001) Impersonation | TeamPCP impersonated legitimate maintainers to push imposter commits to the Aquasecurity Trivy scanner GitHub repository. | 1 | — | — |

### Defense Impairment (TA0112) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1553.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1553.002) Code Signing | TeamPCP has compromised legitimate software release workflows resulting in malicious packages receiving legitimate project cryptographic signing. | 11 | — | — |

### Credential Access (TA0006) — 3

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1528](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1528) Steal Application Access Token | TeamPCP has used malware to steal access tokens from targeted cloud and developer environments. | 105 | 2 | — |
| [T1552.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1552.004) Private Keys | TeamPCP has used malware to extract SSH and GPG keys from victim environments. | 60 | 17 | 1 |
| [T1555.006](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1555.006) Cloud Secrets Management Stores | TeamPCP has used malware to exfiltrate cloud secrets from targeted environments including AWS, GCP, and Azure. | 11 | 1 | — |

### Lateral Movement (TA0008) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1550.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1550.001) Application Access Token | TeamPCP has used stolen access tokens to inject malicious code into CI/CD workflows and to exfiltrate sensitive data from cloud, developer, and container environments. | 78 | — | — |

### Collection (TA0009) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1005) Data from Local System | TeamPCP has stolen source code from victim environments including Mistral AI. | 170 | 3 | — |

### Command and Control (TA0011) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1105](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1105) Ingress Tool Transfer | TeamPCP has modified legitimate software binaries to retrieve secondary payloads from C2. | 644 | 39 | — |

### Impact (TA0040) — 3

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1485](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1485) Data Destruction | TeamPCP has deployed privileged DaemonSets to delete files on Kubernetes clusters and has executed recursive file deletions on non-containerized hosts. | 215 | 5 | — |
| [T1486](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1486) Data Encrypted for Impact | TeamPCP has deployed ransomware and has announced partnerships with ransomware groups including Vect and CipherForce in online criminal forums. | 160 | 10 | 1 |
| [T1657](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1657) Financial Theft | TeamPCP has engaged in cryptocurrency mining and theft. TeamPCP has also partnered with ransomware and data theft extortion groups, sold leaked code, and crowdsourced supply chain compromises by open-sourcing their Mini Shai-Hulud malware. | 2 | — | — |

## 5. Assinatura comportamental

Técnicas que este grupo usa e que poucos dos 178 grupos do ATT&CK usam. Pesam mais numa atribuição por TTP: ver várias delas juntas é mais informativo do que ver técnicas comuns como PowerShell.

| Técnica | Outros grupos que usam | Peso (raridade) |
|---|---:|---:|
| T1176.002 IDE Extensions | 1 | 4.09 |
| T1546.016 Installer Packages | 1 | 4.09 |
| T1677 Poisoned Pipeline Execution | 1 | 4.09 |
| T1059.013 Container CLI/API | 2 | 3.80 |
| T1195.001 Compromise Software Dependencies and Development Tools | 2 | 3.80 |
| T1555.006 Cloud Secrets Management Stores | 2 | 3.80 |
| T1610 Deploy Container | 2 | 3.80 |
| T1528 Steal Application Access Token | 3 | 3.58 |
| T1543.002 Systemd Service | 3 | 3.58 |
| T1550.001 Application Access Token | 3 | 3.58 |

## 6. Arsenal

| Software | Tipo | Técnicas no ATT&CK | Uso relatado (EN) |
|---|---|---:|---|
| [Mini Shai-Hulud](https://attack.mitre.org/software/S9043/) | malware | 55 | TeamPCP has used Mini Shai-Hulud in supply chain campaigns targeting CI/CD workflows. |
| [TeamPCP Cloud Stealer](https://attack.mitre.org/software/S9041/) | malware | 48 | TeamPCP has used TeamPCP Cloud Stealer in credential harvesting and exfiltration. |
| [CanisterWorm](https://attack.mitre.org/software/S9042/) | malware | 32 | TeamPCP has used CanisterWorm in credential harvesting and software supply chain campaigns since at least 2026. |

## 7. Campanhas

Nenhuma campanha atribuída no ATT&CK.

## 8. Cobertura defensiva

**32 de 37 técnicas (86%)** têm ao menos uma regra pública no catálogo Detection Rules.

### Técnicas sem regra pública (prioridade para engenharia de detecção)

- **T1176.002 IDE Extensions** — Persistence. Fonte de log sugerida pelo MITRE: `WinEventLog:Security` EventCode=4688; `auditd:SYSCALL` execve; `macos:unifiedlog` Execution of Code.app, idea, JetBrainsToolbox, eclipse with install/extension flags
- **T1677 Poisoned Pipeline Execution** — Execution. Fonte de log sugerida pelo MITRE: `saas:github` Workflow triggered via pull_request_target from forked repo
- **T1059.013 Container CLI/API** — Execution. Fonte de log sugerida pelo MITRE: `auditd:SYSCALL` execve: Execution of container management CLIs (docker, crictl, kubectl) or interpreted shells (sh, bash, python) within container context
- **T1683.001 Written Content** — Resource Development
- **T1583.004 Server** — Resource Development. Fonte de log sugerida pelo MITRE: `Internet Scan` None

### Onde procurar — cobertura por tecnologia

Quantas técnicas deste grupo têm ao menos uma regra em cada tecnologia. Comece a caça pelas tecnologias que você tem e que aparecem aqui.

| Tecnologia | Técnicas do grupo com regra |
|---|---:|
| Windows | 23 |
| Linux | 23 |
| EDR / XDR | 22 |
| DevOps & supply chain | 21 |
| AWS | 20 |
| Outros / genérico | 19 |
| macOS | 18 |
| Microsoft 365 | 18 |
| E-mail | 18 |
| IA, LLMs & agentes | 16 |
| Kubernetes | 15 |
| Contêineres (Docker/runtime) | 15 |

### Regras recomendadas por técnica

Melhor regra disponível por técnica (formato portável e maduro primeiro).

| Técnica | Regra | Formato | Fonte |
|---|---|---|---|
| T1005 | [Potential Conti Ransomware Database Dumping Activity Via SQLCmd](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A2f47f1fd-0901-466e-a770-3b7092834a1b) | Sigma | SigmaHQ |
| T1005 | [OpenCanary - SMB File Open Request](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A22777c9e-873a-4b49-855f-6072ab861a52) | Sigma | SigmaHQ |
| T1027.003 | [Steganography Hide Files with Steghide](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ace446a9e-30b9-4483-8e38-d2c9ad0a2280) | Sigma | SigmaHQ |
| T1027.003 | [Steganography Unzip Hidden Information From Picture File](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aedd595d7-7895-4fa7-acb3-85a18a8772ca) | Sigma | SigmaHQ |
| T1036.005 | [Exploit for CVE-2015-1641](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A7993792c-5ce2-4475-a3db-a3a5539827ef) | Sigma | SigmaHQ |
| T1036.005 | [Exploit for CVE-2015-1641](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A7993792c-5ce2-4475-a3db-a3a5539827ef) | Sigma | OpenSearch Security Analytics |
| T1059.004 | [Shell Invocation via Env Command - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Abed978f8-7f3a-432b-82c5-9286a9b3031a) | Sigma | SigmaHQ |
| T1059.004 | [Suspicious Reverse Shell Command Line](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A738d9bcf-6999-4fdb-b4ac-3033037db8ab) | Sigma | SigmaHQ |
| T1059.006 | [Emotet Loader Execution Via .LNK File](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1f32d820-1d5c-43fe-8fe2-feef0c952eb7) | Sigma | SigmaHQ |
| T1059.006 | [Serpent Backdoor Payload Execution Via Scheduled Task](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad5eb7432-fda4-4bba-a37f-ffa74d9ed639) | Sigma | SigmaHQ |
| T1059.007 | [Adwind RAT / JRAT](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1fac1481-2dbc-48b2-9096-753c49b4ec71) | Sigma | SigmaHQ |
| T1059.007 | [WScript or CScript Dropper - File](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A002bdb95-0cf1-46a6-9e08-d38c128a6127) | Sigma | SigmaHQ |
| T1078 | [Privilege Role Sign-In Outside Expected Controls](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acf1e5687-84e1-41af-97a9-158094efef53) | Sigma | SigmaHQ |
| T1078 | [OpenCanary - SSH Login Attempt](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aff7139bc-fdb1-4437-92f2-6afefe8884cb) | Sigma | SigmaHQ |
| T1078.004 | [Okta New Admin Console Behaviours](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aa0b38b70-3cb5-484b-a4eb-c4d8e7bcc0a9) | Sigma | SigmaHQ |
| T1078.004 | [AWS IAM S3Browser User or AccessKey Creation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Adb014773-d9d9-4792-91e5-133337c0ffee) | Sigma | SigmaHQ |
| T1098 | [Password Change on Directory Service Restore Mode (DSRM) Account](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A53ad8e36-f573-46bf-97e4-15ba5bf4bb51) | Sigma | SigmaHQ |
| T1098 | [User Added To Global Domain Admins Grp](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=hayabusa-native%3A%3A4bb89c86-a138-42a0-baaf-fc2f777a4506) | Sigma | Hayabusa (native) |
| T1105 | [Greenbug Espionage Group Indicators](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A3711eee4-a808-4849-8a14-faf733da3612) | Sigma | SigmaHQ |
| T1105 | [Pandemic Registry Key](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A47e0852a-cf81-4494-a8e6-31864f8c86ed) | Sigma | SigmaHQ |
| T1190 | [OMIGOD HTTP No Authentication RCE - CVE-2021-38647](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aab6b1a39-a9ee-4ab4-b075-e83acf6e346b) | Sigma | SigmaHQ |
| T1190 | [Exploited CVE-2020-10189 Zoho ManageEngine](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A846b866e-2a57-46ee-8e16-85fa92759be7) | Sigma | OpenSearch Security Analytics |
| T1195.001 | [Outdated Dependency Or Vulnerability Alert Disabled](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A34e1c7d4-0cd5-419d-9f1b-1dad3f61018d) | Sigma | SigmaHQ |
| T1195.001 | [Octopus Scanner Malware](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A805c55d9-31e6-4846-9878-c34c75054fe9) | Sigma | SigmaHQ |
| T1485 | [Fsutil Suspicious Invocation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aadd64136-62e5-48ea-807e-88638d02df1e) | Sigma | SigmaHQ |
| T1485 | [Potential BlackByte Ransomware Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A999e8307-a775-4d5f-addc-4855632335be) | Sigma | SigmaHQ |
| T1486 | [LockerGoga Ransomware Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A74db3488-fd28-480a-95aa-b7af626de068) | Sigma | SigmaHQ |
| T1486 | [LockerGoga Ransomware](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A74db3488-fd28-480a-95aa-b7af626de068) | Sigma | OpenSearch Security Analytics |
| T1528 | [Renamed BrowserCore.EXE Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A8a4519e8-e64a-40b6-ae85-ba8ad2177559) | Sigma | SigmaHQ |
| T1528 | [HackTool - Koh Default Named Pipe](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A0adc67e0-a68f-4ffd-9c43-28905aad5d6a) | Sigma | SigmaHQ |
| T1543.002 | [LiteLLM / TeamPCP Supply Chain Attack Indicators](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A36603778-030c-43c4-8cbb-cd3c1d1a80c7) | Sigma | SigmaHQ |
| T1543.002 | [TeamPCP LiteLLM Supply Chain Attack Persistence Indicators](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A81c0b7f5-81c9-435e-a291-bc32fc2b72cd) | Sigma | SigmaHQ |
| T1546.016 | [Suspicious File Creation via Pkg Install Script](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A1955e925-6679-4535-9c1b-28ebf369f35f) | Elastic | Elastic detection-rules |
| T1546.016 | [Unusual DPKG Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ad6241c90-99f2-44db-b50f-299b6ebd7ee9) | Elastic | Elastic detection-rules |
| T1547.001 | [Potential Ryuk Ransomware Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac37510b8-2107-4b78-aa32-72f251e7a844) | Sigma | SigmaHQ |
| T1547.001 | [Ryuk Ransomware](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Ac37510b8-2107-4b78-aa32-72f251e7a844) | Sigma | OpenSearch Security Analytics |
| T1550.001 | [AWS EC2 Instance Console Login via Assumed Role](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ad1e5e410-3e34-412e-9b1f-dd500b3b55cd) | Elastic | Elastic detection-rules |
| T1550.001 | [AWS First Occurrence of STS GetFederationToken Request by User](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A7a5cc9a8-5ea3-11ef-beec-f661ea17fbce) | Elastic | Elastic detection-rules |
| T1552.004 | [Cisco Crypto Commands](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1f978c6a-4415-47fb-aca5-736a44d7ca3d) | Sigma | SigmaHQ |
| T1552.004 | [DPAPI Backup Keys And Certificate Export Activity IOC](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A7892ec59-c5bb-496d-8968-e5d210ca3ac4) | Sigma | SigmaHQ |
| T1553.002 | [Driver Loaded (Invalid Signature)](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=hayabusa-native%3A%3A1f666722-3948-40a2-9d78-d9d374477a90) | Sigma | Hayabusa (native) |
| T1553.002 | [Driver Loaded (Expired/Revoked Cert)](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=hayabusa-native%3A%3Ac837dd6d-0c91-4593-aeab-f6a1f3ca1961) | Sigma | Hayabusa (native) |
| T1555.006 | [Multiple Cloud Secrets Accessed by Source Address](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A472b4944-d810-43cf-83dc-7d080ae1b8dd) | Elastic | Elastic detection-rules |
| T1555.006 | [AWS Lateral Movement from Kubernetes SA via AssumeRoleWithWebIdentity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Aa1b2c3d4-e5f6-4789-a0b1-c2d3e4f5a6b7) | Elastic | Elastic detection-rules |
| T1564.001 | [Set Suspicious Files as System Files Using Attrib.EXE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aefec536f-72e8-4656-8960-5e85d091345b) | Sigma | SigmaHQ |
| T1564.001 | [PowerShell Logging Disabled Via Registry Key Tampering](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Afecfd1a1-cc78-4313-a1ea-2ee2e8ec27a7) | Sigma | SigmaHQ |
| T1583 | [AWS Route 53 Private Hosted Zone Associated With a VPC](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ae3c27562-709a-42bd-82f2-3ed926cced19) | Elastic | Elastic detection-rules |
| T1583 | [AWS Service Quota Increase Requested by Rare Identity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A7e1b0654-b6c0-4b1b-ab47-75588533083c) | Elastic | Elastic detection-rules |
| T1583.001 | [AWS Route 53 Private Hosted Zone Associated With a VPC](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ae3c27562-709a-42bd-82f2-3ed926cced19) | Elastic | Elastic detection-rules |
| T1583.001 | [AWS SES Email Identity Verified Then Deleted](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A8e4bde35-125d-4eb3-9a2e-d7e77a053a08) | Elastic | Elastic detection-rules |
| T1583.006 | [GitHub Repo Created](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A6cea88e4-6ce2-4238-9981-a54c140d6336) | Elastic | Elastic detection-rules |
| T1583.006 | [Cisco Secure Firewall - Rare Snort Rule Triggered](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=splunk-security-content%3A%3Ae20313d2-7d63-4fcf-b2d9-d6e12c6c7bd7) | Splunk | Splunk security_content |
| T1585.001 | [CYFIRMA - Brand Intelligence - Social Media Handle Impersonation Detected High Rule](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A22f49d67-7da7-4809-8d07-89e4478aa6b0) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1585.001 | [CYFIRMA - Brand Intelligence - Executive/People Impersonation High Rule](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A159d26a1-591c-4f70-b1ca-2843c881aaec) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1587.001 | [Formbook Process Creation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A032f5fb3-d959-41a5-9263-4173c802dc2b) | Sigma | SigmaHQ |
| T1587.001 | [Uncommon File Created In Office Startup Folder](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aa10a2c40-2c4d-49f8-b557-1a946bc55d9d) | Sigma | SigmaHQ |
| T1608.001 | [M365 OneDrive Malware File Upload](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Abba1b212-b85c-41c6-9b28-be0e5cdfc9b1) | Elastic | Elastic detection-rules |
| T1608.001 | [M365 SharePoint Malware File Detected](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A0e52157a-8e96-4a95-a6e3-5faae5081a74) | Elastic | Elastic detection-rules |
| T1610 | [Privileged Container Creation with Host Directory Mount](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ad1f310cb-5921-4d37-bbdf-cfdab7a6df9c) | Elastic | Elastic detection-rules |
| T1610 | [Potential Privilege Escalation via Container Misconfiguration](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Aafe6b0eb-dd9d-4922-b08a-1910124d524d) | Elastic | Elastic detection-rules |
| T1657 | [AWS S3 Bucket Enumeration or Brute Force](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A5f0234fd-7f21-42af-8391-511d5fd11d5c) | Elastic | Elastic detection-rules |
| T1657 | [Monitor ransomwarelive for companies of interest on ransowmare data leak sites (DLS)](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=bert-janp-hunting-queries%3A%3A8b9af12a820a) | KQL hunting | Bert-JanP Hunting Queries |
| T1684.001 | [Entra ID OAuth user_impersonation Scope for Unusual User and Client](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A9563dace-5822-11f0-b1d3-f661ea17fbcd) | Elastic | Elastic detection-rules |

## 9. Plano de emulação e validação

Use num laboratório isolado e autorizado para confirmar que as regras disparam. Os comandos estão nos repositórios oficiais.

| Tática | Técnica | Teste Atomic Red Team | Plataformas |
|---|---|---|---|
| Execution | [T1059.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.004/T1059.004.md) | Create and Execute Bash Shell Script | linux, macos |
| Execution | [T1059.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.004/T1059.004.md) | Command-Line Interface | linux, macos |
| Execution | [T1059.007](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.007/T1059.007.md) | JScript execution to gather local computer information via cscript | windows |
| Execution | [T1059.007](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.007/T1059.007.md) | JScript execution to gather local computer information via wscript | windows |
| Execution | [T1610](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1610/T1610.md) | Deploy Docker container | containers |
| Persistence | [T1098](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1098/T1098.md) | Admin Account Manipulate | windows |
| Persistence | [T1098](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1098/T1098.md) | Domain Account and Group Manipulate | windows |
| Persistence | [T1543.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1543.002/T1543.002.md) | Create Systemd Service | linux |
| Persistence | [T1543.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1543.002/T1543.002.md) | Create SysV Service | linux |
| Persistence | [T1547.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1547.001/T1547.001.md) | Reg Key Run | windows |
| Persistence | [T1547.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1547.001/T1547.001.md) | Reg Key RunOnce | windows |
| Stealth | [T1036.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.005/T1036.005.md) | Execute a process from a directory masquerading as the current parent directory | linux, macos |
| Stealth | [T1036.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.005/T1036.005.md) | Masquerade as a built-in system executable | windows |
| Stealth | [T1078.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1078.004/T1078.004.md) | Creating GCP Service Account and Service Account Key | google-workspace, iaas:gcp |
| Stealth | [T1078.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1078.004/T1078.004.md) | Azure Persistence Automation Runbook Created or Modified | iaas:azure |
| Stealth | [T1564.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1564.001/T1564.001.md) | Create a hidden file in a hidden directory | linux, macos |
| Stealth | [T1564.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1564.001/T1564.001.md) | Mac Hidden file | macos |
| Credential Access | [T1528](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1528/T1528.md) | Azure - Functions code upload - Functions code injection via Blob upload | iaas:azure |
| Credential Access | [T1528](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1528/T1528.md) | Azure - Functions code upload - Functions code injection via File Share modification to retrieve the Functions identity  | iaas:azure |
| Credential Access | [T1552.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1552.004/T1552.004.md) | Private Keys | windows |
| Credential Access | [T1552.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1552.004/T1552.004.md) | Discover Private SSH Keys | linux, macos |
| Credential Access | [T1555.006](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1555.006/T1555.006.md) | Azure - Dump All Azure Key Vaults with Microburst | iaas:azure |
| Collection | [T1005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1005/T1005.md) | Search files of interest and save them to a single zip file (Windows) | windows |
| Collection | [T1005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1005/T1005.md) | Find and dump sqlite databases (Linux) | linux |
| Command and Control | [T1105](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1105/T1105.md) | rsync remote file copy (push) | linux, macos |
| Command and Control | [T1105](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1105/T1105.md) | rsync remote file copy (pull) | linux, macos |
| Impact | [T1485](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1485/T1485.md) | Windows - Overwrite file with SysInternals SDelete | windows |
| Impact | [T1485](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1485/T1485.md) | FreeBSD/macOS/Linux - Overwrite file with DD | linux, macos |
| Impact | [T1486](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1486/T1486.md) | Encrypt files using gpg (FreeBSD/Linux) | linux |
| Impact | [T1486](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1486/T1486.md) | Encrypt files using 7z (FreeBSD/Linux) | linux |

**Logs reais de ataque (EVTX) para testar sem executar nada:**

- T1078 — [ID1149-RDP success logins to multiple hosts](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0001-Initial%20access/T1078-Valid%20accounts/ID1149-RDP%20success%20logins%20to%20multiple%20hosts.evtx) _(explícito)_
- T1078 — [ID33205-SQL Server failed login with disabled SA account](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0001-Initial%20access/T1078-Valid%20accounts/ID33205-SQL%20Server%20failed%20login%20with%20disabled%20SA%20account.evtx) _(explícito)_
- T1098 — [ID33205-SQL Server member added to database role](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0003-Persistence/T1098.xxx-Account%20manipulation/ID33205-SQL%20Server%20member%20added%20to%20database%20role.evtx) _(explícito)_
- T1098 — [ID33205-SQL Server member added to server role](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0003-Persistence/T1098.xxx-Account%20manipulation/ID33205-SQL%20Server%20member%20added%20to%20server%20role.evtx) _(explícito)_
- T1486 — [ID 768,775,793,796,817,840-BitLocker encryption activated](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0040-Impact/T1486-Data%20Encrypted%20for%20Impact/ID%20768%2C775%2C793%2C796%2C817%2C840-BitLocker%20encryption%20activated.evtx) _(explícito)_
- T1547.001 — [sideloading_injection_persistence_run_key](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/AutomatedTestingTools/Malware/sideloading_injection_persistence_run_key.evtx) _(inferido)_
- T1547.001 — [evasion_persis_hidden_run_keyvalue_sysmon_13](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Persistence/evasion_persis_hidden_run_keyvalue_sysmon_13.evtx) _(inferido)_
- T1552.004 — [ID70-CAPI-Private key accessed Mimikatz](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0006-Credential%20Access/T1552.004-Unsecured%20Credentials-Private%20Keys/ID70-CAPI-Private%20key%20accessed%20Mimikatz.evtx) _(explícito)_

## 10. Hipóteses de hunting

Se TeamPCP estiver no seu ambiente, estas são as perguntas a fazer aos seus dados (fontes de log segundo as estratégias de detecção do MITRE ATT&CK).

1. **T1176.002 IDE Extensions** — Adversary installs or side-loads an IDE extension (VS Code, IntelliJ/JetBrains, Eclipse) or enables IDE tunneling. Chain: (1) IDE binary starts on a non-developer endpoint or server, often with install/force/tunnel flags → (2) extension files/registrations… Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=3, 22), `WinEventLog:Sysmon` (EventCode=11).
2. **T1546.016 Installer Packages** — Correlation of package install event with execution of postinstall scripts containing unknown binaries or abnormal CLI usage. Look for `/usr/sbin/installer` execution followed by child processes originating from postinstall script. Dados: `macos:unifiedlog` (Execution of /usr/sbin/installer spawning child process from within /private/tmp or package contents), `macos:unifiedlog` (Creation or modification of postinstall scripts within .pkg or .mpkg contents).
3. **T1677 Poisoned Pipeline Execution** — Detects anomalous CI/CD workflow execution originating from forked repositories, with pull request (PR) metadata or commit messages containing suspicious patterns (e.g., encoded payloads), coupled with the use of insecure pipeline triggers like… Dados: `saas:github` (Workflow triggered via pull_request_target from forked repo), `saas:github` (CI/CD secret accessed or exported), `saas:github` (Artifact generated includes base64/encoded exfil payload or URL).
4. **T1059.013 Container CLI/API** — Execution of container orchestration commands (e.g., `docker exec`, `kubectl exec`) or API-driven interactions with running containers from unauthorized hosts or non-standard user contexts. Defender sees programmatic or interactive command execution within… Dados: `auditd:SYSCALL` (execve: Execution of container management CLIs (docker, crictl, kubectl) or interpreted shells (sh, bash, python) within container context), `docker:events` (exec_create: docker exec events targeting running containers from non-CI sources), `kubernetes:apiserver` (create/exec: Kubernetes API calls to exec into containers or create pods from curl, kubectl, or SDK clients).
5. **T1195.001 Compromise Software Dependencies and Development Tools** — Adversary manipulates dependencies/dev tools used by developers or CI: a package manager (npm/yarn/pnpm, pip/pipenv, nuget/dotnet, chocolatey/winget, maven/gradle) or a compiler/IDE downloads or restores content; files are written under project paths and… Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=7), `WinEventLog:Sysmon` (EventCode=11).
6. **T1555.006 Cloud Secrets Management Stores** — Detection of suspicious access to cloud-native secret management systems (AWS Secrets Manager, GCP Secret Manager, Azure Key Vault, HashiCorp Vault). Focuses on abnormal secret retrieval activity, such as secrets being accessed by unusual identities, from… Dados: `AWS:CloudTrail` (GetSecretValue).
7. **T1610 Deploy Container** — Remote/API driven creation **and** start of a container whose image is not on an allow‑list (or is tagged `latest`), executed by a non-admin principal, and/or started with risky runtime attributes (e.g., `--privileged`, host PID/NET namespaces, sensitive host… Dados: `docker:daemon` (container_create,container_start), `containerd:runtime` (CRI CreateContainer/StartContainer with privileged=true OR added capabilities OR host* namespaces), `ebpf:syscalls` (process execution or network connect from just-created container PID namespace).
8. **T1528 Steal Application Access Token** — Access and retrieval of container service account tokens followed by unauthorized API requests using those tokens to interact with the Kubernetes API server or internal services. Dados: `kubernetes:audit` (GET or LIST requests to /var/run/secrets/kubernetes.io/serviceaccount/ followed by access to the Kubernetes API server).
9. **T1543.002 Systemd Service** — Detects the creation or modification of `.service` unit files in system/user-level directories, combined with execution of `systemctl`, `service`, or dynamically created drop-ins via systemd generators. Detects persistence by analyzing the `ExecStart` path,… Dados: `auditd:SYSCALL` (write, open, or rename to /etc/systemd/system/*.service), `auditd:SYSCALL` (modification of existing .service file), `auditd:SYSCALL` (execution of systemctl or service with enable/start parameters).
10. **T1550.001 Application Access Token** — Use of AWS STS or GCP IAM APIs to request temporary tokens or federation sessions inconsistent with normal account activity, including from unexpected principals or regions. Dados: `AWS:CloudTrail` (AssumeRole, GetFederationToken, GetSessionToken), `AWS:CloudTrail` (sts:GetFederationToken).
11. **T1098 Account Manipulation** — Account attribute changes (e.g., password set, group membership, servicePrincipalName, logon hours) correlated with unusual process lineage or timing, indicating privilege escalation or persistence via valid accounts. Dados: `WinEventLog:Security` (EventCode=4738, 4728, 4670), `WinEventLog:Sysmon` (EventCode=1).
12. **T1485 Data Destruction** — Adversary spawns command-line tools (e.g., del, cipher /w, SDelete) or scripts to recursively delete or overwrite user/system files. This may be correlated with abnormal file IO activity, registry writes, or tampering in critical system directories. Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Sysmon` (EventCode=23).

## 11. OSINT — onde pesquisar

Consultas prontas com todos os nomes conhecidos do grupo:

- Relatórios técnicos: [busca web](https://duckduckgo.com/?q=%28%22TeamPCP%22+OR+%22PCPCat%22+OR+%22ShellForce%22+OR+%22DeadCatx3%22+OR+%22SHADOW-WATER-058%22+OR+%22UNC6780%22%29+threat+report) · [PDFs](https://duckduckgo.com/?q=%28%22TeamPCP%22+OR+%22PCPCat%22+OR+%22ShellForce%22+OR+%22DeadCatx3%22+OR+%22SHADOW-WATER-058%22+OR+%22UNC6780%22%29+filetype%3Apdf)
- Regras e IOCs publicados: [GitHub](https://github.com/search?type=code&q=%22TeamPCP%22+OR+%22PCPCat%22+OR+%22ShellForce%22+OR+%22DeadCatx3%22+OR+%22SHADOW-WATER-058%22+OR+%22UNC6780%22)
- Pulsos de ameaça: [AlienVault OTX](https://otx.alienvault.com/browse/global/pulses?q=TeamPCP)
- Família de malware e atores: [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/actors) (busque por TeamPCP, PCPCat, ShellForce)
- Cartões de grupo: [ThaiCERT Threat Group Cards](https://apt.etda.or.th/cgi-bin/listgroups.cgi)
- Página oficial: [MITRE ATT&CK G1056](https://attack.mitre.org/groups/G1056/)

## 12. Bibliografia (17 fontes citadas pelo ATT&CK)

- [Aikido CanisterWorm MAR 2026](https://www.aikido.dev/blog/teampcp-stage-payload-canisterworm-iran) — Eriksen, C. (2026, March 22). CanisterWorm Gets Teeth: TeamPCP's Kubernetes Wiper Targets Iran. Retrieved July 27, 2026.
- [Aikido TeamPCP Telnyx MAR 2026](https://www.aikido.dev/blog/telnyx-pypi-compromised-teampcp-canisterworm) — Eriksen, C. (2026, March 27). Popular telnyx package compromised on PyPI by TeamPCP. Retrieved July 16, 2026.
- [Aikido TeamPCP Trivy MAR 2026](https://www.aikido.dev/blog/teampcp-deploys-worm-npm-trivy-compromise) — Eriksen, C. (2026, March 20). TeamPCP deploys CanisterWorm on NPM following Trivy compromise. Retrieved July 27, 2026.
- [Aqua Security Blog Trivy Compromise APR 2026](https://www.aquasec.com/blog/trivy-supply-chain-attack-what-you-need-to-know) — Aqua Team. (2026, April 1). Update: Ongoing Investigation and Continued Remediation. Retrieved July 1, 2026.
- [Aqua Security Trivy Compromise MAR 2026](https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23) — Aqua Security . (2026, March 21). Trivy ecosystem supply chain temporarily compromised. Retrieved July 1, 2026.
- [FBI TeamPCP JUL 2026](https://www.ic3.gov/CSA/2026/260702.pdf) — FBI. (2026, July 2). Cyber Criminal Group TeamPCP. Retrieved July 7, 2026.
- [Flashpoint Mini Shai-Hulud MAY 2026](https://flashpoint.io/blog/mini-shai-hulud-worm-new-era-ci-cd-exploitation/) — Flashpoint. (2026, May 28). The Mini Shai-Hulud Worm and the New Era of CI/CD Exploitation. Retrieved July 16, 2026.
- [Google AI Threat Tracker MAY 2026](https://cloud.google.com/blog/topics/threat-intelligence/ai-vulnerability-exploitation-initial-access) — Google Threat Intelligence Group. (2026, May 11). GTIG AI Threat Tracker: Adversaries Leverage AI for Vulnerability Exploitation, Augmented Operations, and Initial Access. Retrieved July 7, 2026.
- [Hunt.io TeamPCP Toolkit MAY 2026](https://hunt.io/blog/teampcp-python-toolkit-firescale-github-c2-takedown) — Hunt.io. (2026, May 14). How TeamPCP's Python Toolkit Survives a C2 Takedown: FIRESCALE, GitHub, and the Victim's Own Account. Retrieved July 16, 2026.
- [Palo Alto TeamPCP MAR 2026](https://unit42.paloaltonetworks.com/teampcp-supply-chain-attacks/) — Unit 42. (2026, March 31). Weaponizing the Protectors: TeamPCP’s Multi-Stage Supply Chain Attack on Security Infrastructure. Retrieved July 1, 2026.
- [Phoenix TeamPCP 20 MAY 2026](https://phoenix.security/teampcp-github-breach-durabletask-pypi-supply-chain-wave-four-2026/) — Webb, M. (2026, May 20). TeamPCP Wave Four: GitHub Breach via Poisoned VS Code Extension, durabletask PyPI Worm, and ~4,000 Internal Repositories Exfiltrated. Retrieved July 16, 2026.
- [Sysdig TeamPCP MAR 2026](https://www.sysdig.com/blog/teampcp-expands-supply-chain-compromise-spreads-from-trivy-to-checkmarx-github-actions) — Sysdig Threat Research Team. (2026, March 23). TeamPCP expands: Supply chain compromise spreads from Trivy to Checkmarx GitHub Actions. Retrieved July 1, 2026.
- [Trend Micro TeamPCP MAY 2026](https://www.trendmicro.com/en_us/research/26/e/analyzing-teampcp-supply-chain-attacks.html) — Santos, J. and Navato, J.R. (2026, May 13). Analyzing TeamPCP’s Supply Chain Attacks: Checkmarx KICS and elementary-data in CI/CD Credential Theft. Retrieved July 16, 2026.
- [Wiz Mini Shai-Hulud MAY 2026](https://www.wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised) — McCarthy, R., Cohen, A., and Read, B. (2026, May 12). Mini Shai-Hulud Strikes Again: TanStack + more npm Packages Compromised. Retrieved July 16, 2026.
- [Wiz TeamPCP KICS MAR 2026](https://www.wiz.io/blog/teampcp-attack-kics-github-action) — McCarthy, R., Haughom, J., Read, B. (2026, March 23). KICS GitHub Action Compromised: TeamPCP Strikes Again in Supply Chain Attack. Retrieved July 1, 2026.
- [Wiz TeamPCP Profile MAY 2026](https://threats.wiz.io/all-actors/teampcp) — Wiz. (2026, May 20). TeamPCP. Retrieved July 16, 2026.
- [Wiz Trivy Compromise MAR 2026](https://www.wiz.io/blog/trivy-compromised-teampcp-supply-chain-attack) — McCarthy, R. (2026, March 20). Trivy Compromised: Everything You Need to Know about the Latest Supply Chain Attack. Retrieved July 1, 2026.

## 13. Limites e confiança

- O ATT&CK registra o que foi **relatado publicamente**, não tudo o que o grupo faz. Ausência de uma técnica não prova que o grupo não a usa.
- **Sobreposição de TTP não é atribuição.** Muitas técnicas são compartilhadas entre grupos e com red teams. Use a assinatura comportamental como hipótese, junto com infraestrutura, malware e contexto.
- Cobertura de detecção refere-se ao catálogo público Detection Rules, não ao seu ambiente: confira se a telemetria necessária chega ao seu SIEM.
- Ligações marcadas como _inferidas_ (EVTX por palavra-chave, relatórios por nome) devem ser verificadas.

---
Fontes: MITRE ATT&CK® (uso livre com atribuição, © The MITRE Corporation), APT4ALL (MISP Galaxy CC0/BSD-2, APT Groups & Operations CC BY 4.0, EternalLiberty, APTnotes, Ransomware Tool Matrix CC BY 4.0), Atomic Red Team (Red Canary, MIT), EVTX-to-MITRE-Attack, EVTX-ATTACK-SAMPLES, APT & CyberCriminal Campaign Collections. Gerado por [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules).
