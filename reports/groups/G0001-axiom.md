# Axiom (G0001) — Dossiê de inteligência

> **TLP:CLEAR** · gerado em 2026-10-25 a partir de fontes abertas · MITRE ATT&CK v20.0 · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0001) · [ATT&CK](https://attack.mitre.org/groups/G0001/)

**Também conhecido como:** Group 72  
**Registro no ATT&CK:** criado em 2017-05-31, atualizado em 2026-07-31 · referências de 2013 a 2015

## 1. Sumário executivo

- **16 técnicas** atribuídas publicamente, concentradas em **Initial Access, Resource Development, Collection**.
- **Arsenal:** 8 malware e 0 ferramentas (ex.: PlugX, ZxShell, gh0st RAT, Hydraq, Derusbi).
- **Campanhas atribuídas:** 0.
- **Cobertura de detecção pública:** 81% das técnicas têm ao menos uma regra no catálogo; **3 técnicas sem nenhuma regra pública**.
- **Assinatura comportamental** (técnicas raras entre os 178 grupos, as mais úteis para atribuição): T1001.002 Steganography, T1553 Subvert Trust Controls, T1563.002 RDP Hijacking, T1583.002 DNS Server, T1584.005 Botnet.

## 2. Quem é

> Axiom is a suspected Chinese cyber espionage group that has targeted the aerospace, defense, government, manufacturing, and media sectors since at least 2008. Some reporting suggests a degree of overlap between Axiom and Winnti Group but the two groups appear to be distinct based on differences in reporting on TTPs and targeting.

_Texto original do MITRE ATT&CK, em inglês._

## 3. Perfil TTP por tática (kill chain)

Cada linha: técnica, como o grupo a usou segundo relatos públicos, e o que existe para detectar e testar.

### Resource Development (TA0042) — 3

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1583.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1583.002) DNS Server | Axiom has acquired dynamic DNS services for use in the targeting of intended victims. | **0** | — | — |
| [T1583.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1583.003) Virtual Private Server | Axiom has used VPS hosting providers in targeting of intended victims. | **0** | — | — |
| [T1584.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1584.005) Botnet | Axiom has used large groups of compromised machines for use as proxy nodes. | **0** | — | — |

### Initial Access (TA0001) — 4

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | Axiom has used previously compromised administrative accounts to escalate privileges. | 825 | — | 3 |
| [T1189](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1189) Drive-by Compromise | Axiom has used watering hole attacks to gain access. | 57 | — | — |
| [T1190](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1190) Exploit Public-Facing Application | Axiom has been observed using SQL injection to gain access to systems. | 580 | — | — |
| [T1566](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1566) Phishing | Axiom has used spear phishing to initially compromise victims. | 286 | — | — |

### Execution (TA0002) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1203](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1203) Exploitation for Client Execution | Axiom has used exploits for multiple vulnerabilities including CVE-2014-0322, CVE-2012-4792, CVE-2012-1889, and CVE-2013-3893. | 202 | — | — |

### Persistence (TA0003) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | Axiom has used previously compromised administrative accounts to escalate privileges. | 825 | — | 3 |
| [T1546.008](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1546.008) Accessibility Features | Axiom actors have been known to use the Sticky Keys replacement within RDP sessions to obtain persistence. | 40 | 10 | — |

### Privilege Escalation (TA0004) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | Axiom has used previously compromised administrative accounts to escalate privileges. | 825 | — | 3 |
| [T1546.008](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1546.008) Accessibility Features | Axiom actors have been known to use the Sticky Keys replacement within RDP sessions to obtain persistence. | 40 | 10 | — |

### Stealth (TA0005) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | Axiom has used previously compromised administrative accounts to escalate privileges. | 825 | — | 3 |

### Defense Impairment (TA0112) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1553](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1553) Subvert Trust Controls | Axiom has used digital certificates to deliver malware. | 55 | — | 1 |

### Credential Access (TA0006) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1003) OS Credential Dumping | Axiom has been known to dump credentials. | 399 | 7 | 19 |

### Lateral Movement (TA0008) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1021.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1021.001) Remote Desktop Protocol | Axiom has used RDP during operations. | 139 | 4 | 7 |
| [T1563.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1563.002) RDP Hijacking | Axiom has targeted victims with remote administration tools including RDP. | 16 | 1 | — |

### Collection (TA0009) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1005) Data from Local System | Axiom has collected data from a compromised network. | 170 | 3 | — |
| [T1560](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1560) Archive Collected Data | Axiom has compressed and encrypted data prior to exfiltration. | 53 | 1 | — |

### Command and Control (TA0011) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1001.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1001.002) Steganography | Axiom has used steganography to hide its C2 communications. | 4 | — | — |

## 4. Assinatura comportamental

Técnicas que este grupo usa e que poucos dos 178 grupos do ATT&CK usam. Pesam mais numa atribuição por TTP: ver várias delas juntas é mais informativo do que ver técnicas comuns como PowerShell.

| Técnica | Outros grupos que usam | Peso (raridade) |
|---|---:|---:|
| T1001.002 Steganography | 0 | 4.49 |
| T1553 Subvert Trust Controls | 0 | 4.49 |
| T1563.002 RDP Hijacking | 1 | 4.09 |
| T1583.002 DNS Server | 2 | 3.80 |
| T1584.005 Botnet | 4 | 3.40 |
| T1546.008 Accessibility Features | 5 | 3.24 |
| T1566 Phishing | 7 | 2.99 |
| T1003 OS Credential Dumping | 12 | 2.55 |
| T1560 Archive Collected Data | 12 | 2.55 |
| T1583.003 Virtual Private Server | 18 | 2.19 |

## 5. Arsenal

| Software | Tipo | Técnicas no ATT&CK | Uso relatado (EN) |
|---|---|---:|---|
| [PlugX](https://attack.mitre.org/software/S0013/) | malware | 49 |  |
| [ZxShell](https://attack.mitre.org/software/S0412/) | malware | 34 |  |
| [gh0st RAT](https://attack.mitre.org/software/S0032/) | malware | 24 |  |
| [Hydraq](https://attack.mitre.org/software/S0203/) | malware | 19 |  |
| [Derusbi](https://attack.mitre.org/software/S0021/) | malware | 18 |  |
| [PoisonIvy](https://attack.mitre.org/software/S0012/) | malware | 15 |  |
| [Hikit](https://attack.mitre.org/software/S0009/) | malware | 11 |  |
| [Zox](https://attack.mitre.org/software/S0672/) | malware | 9 |  |

## 6. Campanhas

Nenhuma campanha atribuída no ATT&CK.

## 7. Cobertura defensiva

**13 de 16 técnicas (81%)** têm ao menos uma regra pública no catálogo Detection Rules.

### Técnicas sem regra pública (prioridade para engenharia de detecção)

- **T1583.002 DNS Server** — Resource Development
- **T1584.005 Botnet** — Resource Development
- **T1583.003 Virtual Private Server** — Resource Development. Fonte de log sugerida pelo MITRE: `Internet Scan` None

### Regras recomendadas por técnica

Melhor regra disponível por técnica (formato portável e maduro primeiro).

| Técnica | Regra | Formato | Fonte |
|---|---|---|---|
| T1001.002 | [Suspicious command used in possible steganographic payload delivery (T1001.002)](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=socfortress-wazuh-rules%3A%3Awazuh-700064) | Wazuh | SOCFortress Wazuh-Rules |
| T1001.002 | [Script executed from hidden payload likely appended to image (Stego + Execution)](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=socfortress-wazuh-rules%3A%3Awazuh-700065) | Wazuh | SOCFortress Wazuh-Rules |
| T1003 | [Antivirus - Password Dumper Signature](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A78cc2dd2-7d20-4d32-93ff-057084c38b93) | Sigma | SigmaHQ |
| T1003 | [HackTool - Rubeus Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A7ec2c172-dceb-4c10-92c9-87c1881b7e18) | Sigma | SigmaHQ |
| T1005 | [Potential Conti Ransomware Database Dumping Activity Via SQLCmd](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A2f47f1fd-0901-466e-a770-3b7092834a1b) | Sigma | SigmaHQ |
| T1005 | [OpenCanary - SMB File Open Request](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A22777c9e-873a-4b49-855f-6072ab861a52) | Sigma | SigmaHQ |
| T1021.001 | [Hermetic Wiper TG Process Patterns](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A2f974656-6d83-4059-bbdf-68ac5403422f) | Sigma | SigmaHQ |
| T1021.001 | [Publicly Accessible RDP Service](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1fc0809e-06bf-4de3-ad52-25e5263b7623) | Sigma | SigmaHQ |
| T1078 | [Privilege Role Sign-In Outside Expected Controls](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acf1e5687-84e1-41af-97a9-158094efef53) | Sigma | SigmaHQ |
| T1078 | [OpenCanary - SSH Login Attempt](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aff7139bc-fdb1-4437-92f2-6afefe8884cb) | Sigma | SigmaHQ |
| T1189 | [Flash Player Update from Suspicious Location](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4922a5dd-6743-4fc2-8e81-144374280997) | Sigma | SigmaHQ |
| T1189 | [Cross Site Scripting Strings](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A65354b83-a2ea-4ea6-8414-3ab38be0d409) | Sigma | SigmaHQ |
| T1190 | [OMIGOD HTTP No Authentication RCE - CVE-2021-38647](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aab6b1a39-a9ee-4ab4-b075-e83acf6e346b) | Sigma | SigmaHQ |
| T1190 | [Exploited CVE-2020-10189 Zoho ManageEngine](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A846b866e-2a57-46ee-8e16-85fa92759be7) | Sigma | OpenSearch Security Analytics |
| T1203 | [Droppers Exploiting CVE-2017-11882](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A678eb5f4-8597-4be6-8be7-905e4234b53a) | Sigma | SigmaHQ |
| T1203 | [OMIGOD HTTP No Authentication RCE - CVE-2021-38647](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aab6b1a39-a9ee-4ab4-b075-e83acf6e346b) | Sigma | SigmaHQ |
| T1546.008 | [Suspicious Debugger Registration Cmdline](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aae215552-081e-44c7-805f-be16f975c8a2) | Sigma | SigmaHQ |
| T1546.008 | [Sticky Key Like Backdoor Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A2fdefcb3-dbda-401e-ae23-f0db027628bc) | Sigma | SigmaHQ |
| T1553 | [Suspicious RazerInstaller Explorer Subprocess](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aa4eaf250-7dc1-4842-862a-5e71cd59a167) | Sigma | SigmaHQ |
| T1553 | [ESXi Host Prepared for an Unsigned Install](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A12c56e4a-8d36-5dab-a5b6-5322db31c901) | Elastic | Elastic detection-rules |
| T1560 | [Conti NTDS Exfiltration Command](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aaa92fd02-09f2-48b0-8a93-864813fb8f41) | Sigma | SigmaHQ |
| T1560 | [Sensitive Files Compression Inside A Container](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ad9faf1ba-a216-4c29-b8e0-a05a9d14b027) | Elastic | Elastic detection-rules |
| T1563.002 | [Suspicious RDP Redirect Using TSCON](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Af72aa3e8-49f9-4c7d-bd74-f8ab84ff9bbb) | Sigma | SigmaHQ |
| T1563.002 | [Potential MSTSC Shadowing Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A6ba5a05f-b095-4f0a-8654-b825f4f16334) | Sigma | SigmaHQ |
| T1566 | [CVE-2021-31979 CVE-2021-33771 Exploits by Sourgum](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aad7085ac-92e4-4b76-8ce2-276d2c0e68ef) | Sigma | SigmaHQ |
| T1566 | [CVE-2021-31979 CVE-2021-33771 Exploits](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A32b5db62-cb5f-4266-9639-0fa48376ac00) | Sigma | SigmaHQ |

## 8. Plano de emulação e validação

Use num laboratório isolado e autorizado para confirmar que as regras disparam. Os comandos estão nos repositórios oficiais.

| Tática | Técnica | Teste Atomic Red Team | Plataformas |
|---|---|---|---|
| Privilege Escalation | [T1546.008](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1546.008/T1546.008.md) | Attaches Command Prompt as a Debugger to a List of Target Processes | windows |
| Privilege Escalation | [T1546.008](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1546.008/T1546.008.md) | Replace binary of sticky keys | windows |
| Credential Access | [T1003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003/T1003.md) | Gsecdump | windows |
| Credential Access | [T1003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003/T1003.md) | Credential Dumping with NPPSpy | windows |
| Lateral Movement | [T1021.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.001/T1021.001.md) | RDP to Remote Host | windows |
| Lateral Movement | [T1021.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.001/T1021.001.md) | Changing RDP Port to Non Standard Port via Powershell | windows |
| Lateral Movement | [T1563.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1563.002/T1563.002.md) | RDP hijacking | windows |
| Collection | [T1005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1005/T1005.md) | Search files of interest and save them to a single zip file (Windows) | windows |
| Collection | [T1005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1005/T1005.md) | Find and dump sqlite databases (Linux) | linux |
| Collection | [T1560](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1560/T1560.md) | Compress Data for Exfiltration With PowerShell | windows |

**Logs reais de ataque (EVTX) para testar sem executar nada:**

- T1003 — [ID1-12-13-Wdigest authentication activation](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0006-Credential%20Access/T1003-Credential%20dumping/ID1-12-13-Wdigest%20authentication%20activation.evtx) _(explícito)_
- T1003 — [ID1-LSASS dump with LSASSY (SYSMON)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0006-Credential%20Access/T1003-Credential%20dumping/ID1-LSASS%20dump%20with%20LSASSY%20%28SYSMON%29.evtx) _(explícito)_
- T1021.001 — [ID4688,4778,4779 RDP hijack direct](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0008-Lateral%20Movement/T1021.001-Remote%20Desktop%20Protocol/ID4688%2C4778%2C4779%20RDP%20hijack%20direct.evtx) _(explícito)_
- T1021.001 — [ID4688-4778 RDP hijack command execution](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0008-Lateral%20Movement/T1021.001-Remote%20Desktop%20Protocol/ID4688-4778%20RDP%20hijack%20command%20execution.evtx) _(explícito)_
- T1078 — [ID1149-RDP success logins to multiple hosts](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0001-Initial%20access/T1078-Valid%20accounts/ID1149-RDP%20success%20logins%20to%20multiple%20hosts.evtx) _(explícito)_
- T1078 — [ID33205-SQL Server failed login with disabled SA account](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0001-Initial%20access/T1078-Valid%20accounts/ID33205-SQL%20Server%20failed%20login%20with%20disabled%20SA%20account.evtx) _(explícito)_
- T1553 — [ID12-13 SIP provider registration](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0005-Defense%20Evasion/T1553-%20Subvert%20Trust%20Controls/ID12-13%20SIP%20provider%20registration.evtx) _(explícito)_

## 9. Hipóteses de hunting

Se Axiom estiver no seu ambiente, estas são as perguntas a fazer aos seus dados (fontes de log segundo as estratégias de detecção do MITRE ATT&CK).

1. **T1001.002 Steganography** — Detect the creation or modification of common media file formats (e.g., .jpg, .png, .wav) following suspicious process activity like compression or encryption, especially when paired with lateral movement or exfiltration behavior. Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Sysmon` (EventCode=3, 22).
2. **T1553 Subvert Trust Controls** — Detection correlates abnormal installation or modification of root or code-signing certificates, creation/modification of suspicious registry keys for trust providers, and unusual module loads from non-standard locations. Identifies unsigned or improperly… Dados: `WinEventLog:Security` (EventCode=4657), `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Sysmon` (EventCode=1).
3. **T1563.002 RDP Hijacking** — Detection of suspicious use of `tscon.exe` or equivalent methods to hijack legitimate RDP sessions. Defenders can observe anomalies such as session reassignments without corresponding authentication, processes spawned in the context of hijacked sessions, or… Dados: `WinEventLog:Security` (EventCode=4624, 4648), `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=3, 22).
4. **T1546.008 Accessibility Features** — Defenders can observe suspicious replacement or tampering of system accessibility binaries (e.g., utilman.exe, sethc.exe, osk.exe) and anomalous modifications to registry keys used to redirect accessibility programs (such as IFEO keys). Additionally,… Dados: `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=13, 14).
5. **T1566 Phishing** — Unusual inbound email activity where attachments or embedded URLs are delivered to users followed by execution of new processes or suspicious document behavior. Detection involves correlating email metadata, file creation, and network activity after a… Dados: `m365:unified` (Send/Receive: Emails with suspicious sender domains, spoofed headers, or anomalous attachment types), `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Sysmon` (EventCode=1).
6. **T1003 OS Credential Dumping** — Processes accessing LSASS memory or SAM registry hives outside of trusted security tools, often followed by file creation or lateral movement. Detects unauthorized access to sensitive OS subsystems for credential extraction. Dados: `WinEventLog:Sysmon` (EventCode=10), `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Security` (EventCode=4663, 4670, 4656).
7. **T1560 Archive Collected Data** — Detects adversarial archiving of files prior to exfiltration by correlating execution of compression/encryption utilities (e.g., makecab.exe, rar.exe, 7z.exe, powershell Compress-Archive) with subsequent creation of large compressed or encrypted files.… Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Sysmon` (EventCode=7).
8. **T1583.003 Virtual Private Server** — Once adversaries have provisioned a VPS (ex: for use as a command and control server), internet scans may reveal servers that adversaries have acquired. Consider looking for identifiable patterns such as services listening, certificates in use, SSL/TLS… Dados: `Internet Scan` (None), `Internet Scan` (None).
9. **T1189 Drive-by Compromise** — Correlated evidence of anomalous browser/network behavior (suspicious external resource fetches and script injection patterns) followed by atypical child processes, ephemeral execution contexts, memory modification or process injection, and unexpected file… Dados: `WinEventLog:Security` (EventCode=4624, 4648), `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=3, 22).
10. **T1021.001 Remote Desktop Protocol** — Remote Desktop (RDP) logon by a user followed by unusual process execution, file access, or lateral movement activity within a short timeframe. Dados: `WinEventLog:Security` (EventCode=4624, 4648), `WinEventLog:Security` (EventCode=4778, EventCode=4779), `WinEventLog:Sysmon` (EventCode=3, 22).
11. **T1203 Exploitation for Client Execution** — Cause→effect chain: (1) A client app (browser, Office, PDF/Flash/reader) experiences a crash/abnormal exit or loads from an unusual location, then (2) drops or modifies a file in user-writable paths, and/or (3) spawns an unexpected child (e.g.,… Dados: `WinEventLog:Application` (EventCode=1000), `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Sysmon` (EventCode=1).
12. **T1005 Data from Local System** — Adversaries collecting local files via PowerShell, WMI, or direct file API calls often include recursive file listings, targeted file reads, and temporary file staging. Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=11).

## 10. OSINT — onde pesquisar

Consultas prontas com todos os nomes conhecidos do grupo:

- Relatórios técnicos: [busca web](https://duckduckgo.com/?q=%28%22Axiom%22+OR+%22Group+72%22%29+threat+report) · [PDFs](https://duckduckgo.com/?q=%28%22Axiom%22+OR+%22Group+72%22%29+filetype%3Apdf)
- Regras e IOCs publicados: [GitHub](https://github.com/search?type=code&q=%22Axiom%22+OR+%22Group+72%22)
- Pulsos de ameaça: [AlienVault OTX](https://otx.alienvault.com/browse/global/pulses?q=Axiom)
- Família de malware e atores: [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/actors) (busque por Axiom, Group 72)
- Cartões de grupo: [ThaiCERT Threat Group Cards](https://apt.etda.or.th/cgi-bin/listgroups.cgi)
- Página oficial: [MITRE ATT&CK G0001](https://attack.mitre.org/groups/G0001/)

**Relatórios na coleção CyberMonitor** (ligados pelo nome do grupo, conferir antes de citar):

- 2014 — [Group_72](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2014/2014.10.14.Group_72/Group_72.pdf) _(via “Group 72”)_
- 2014 — [Group72_Opening_ZxShell](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2014/2014.10.28.Group_72_ZxShell/Group72_Opening_ZxShell.pdf) _(via “Group 72”)_

## 11. Bibliografia (6 fontes citadas pelo ATT&CK)

- [Cisco Group 72](http://blogs.cisco.com/security/talos/threat-spotlight-group-72) — Esler, J., Lee, M., and Williams, C. (2014, October 14). Threat Spotlight: Group 72. Retrieved January 14, 2016.
- [Kaspersky Winnti April 2013](https://securelist.com/winnti-more-than-just-a-game/37029/) — Kaspersky Lab's Global Research and Analysis Team. (2013, April 11). Winnti. More than just a game. Retrieved February 8, 2017.
- [Kaspersky Winnti June 2015](https://securelist.com/games-are-over/70991/) — Tarakanov, D. (2015, June 22). Games are over: Winnti is now targeting pharmaceutical companies. Retrieved January 14, 2016.
- [Novetta Winnti April 2015](https://web.archive.org/web/20150412223949/http://www.novetta.com/wp-content/uploads/2015/04/novetta_winntianalysis.pdf) — Novetta Threat Research Group. (2015, April 7). Winnti Analysis. Retrieved February 8, 2017.
- [Novetta-Axiom](https://web.archive.org/web/20230115144216/http://www.novetta.com/wp-content/uploads/2014/11/Executive_Summary-Final_1.pdf) — Novetta. (n.d.). Operation SMN: Axiom Threat Actor Group Report. Retrieved November 12, 2014.
- [Talos ZxShell Oct 2014](https://blogs.cisco.com/security/talos/opening-zxshell) — Allievi, A., et al. (2014, October 28). Threat Spotlight: Group 72, Opening the ZxShell. Retrieved September 24, 2019.

## 12. Limites e confiança

- O ATT&CK registra o que foi **relatado publicamente**, não tudo o que o grupo faz. Ausência de uma técnica não prova que o grupo não a usa.
- **Sobreposição de TTP não é atribuição.** Muitas técnicas são compartilhadas entre grupos e com red teams. Use a assinatura comportamental como hipótese, junto com infraestrutura, malware e contexto.
- Cobertura de detecção refere-se ao catálogo público Detection Rules, não ao seu ambiente: confira se a telemetria necessária chega ao seu SIEM.
- Ligações marcadas como _inferidas_ (EVTX por palavra-chave, relatórios por nome) devem ser verificadas.

---
Fontes: MITRE ATT&CK® (uso livre com atribuição, © The MITRE Corporation), Atomic Red Team (Red Canary, MIT), EVTX-to-MITRE-Attack, EVTX-ATTACK-SAMPLES, APT & CyberCriminal Campaign Collections. Gerado por [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules).
