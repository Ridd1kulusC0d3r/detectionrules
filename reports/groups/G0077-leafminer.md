# Leafminer (G0077) — Dossiê de inteligência

> **TLP:CLEAR** · gerado em 2026-10-26 a partir de fontes abertas · MITRE ATT&CK v20.0 · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0077) · [ATT&CK](https://attack.mitre.org/groups/G0077/)

**Também conhecido como:** Raspite  
**Origem atribuída:** Irã · **Motivação:** indefinido · **Setores-alvo:** Energia  
**Registro no ATT&CK:** criado em 2018-10-17, atualizado em 2026-07-31 · referências de 2018 a 2018

## 1. Sumário executivo

- **17 técnicas** atribuídas publicamente, concentradas em **Credential Access, Discovery, Stealth**.
- **Arsenal:** 0 malware e 4 ferramentas (ex.: Mimikatz, LaZagne, PsExec, MailSniper).
- **Campanhas atribuídas:** 0.
- **Cobertura de detecção pública:** 100% das técnicas têm ao menos uma regra no catálogo; **0 técnicas sem nenhuma regra pública**.
- **Origem e alvos (APT4ALL):** atribuído a **Irã**, motivação indefinido; setores Energia.
- **Onde a cobertura está:** Windows (17 técnicas com regra), EDR / XDR (14 técnicas com regra), Active Directory (11 técnicas com regra), Firewall & perímetro (11 técnicas com regra).
- **Assinatura comportamental** (técnicas raras entre os 178 grupos, as mais úteis para atribuição): T1055.013 Process Doppelgänging, T1003.005 Cached Domain Credentials, T1003.004 LSA Secrets, T1110.003 Password Spraying, T1114.002 Remote Email Collection.

## 2. Quem é

> Leafminer is an Iranian threat group that has targeted government organizations and business entities in the Middle East since at least early 2017.

_Texto original do MITRE ATT&CK, em inglês._

## 3. Contexto, nomes e alvos

Consolidado pelo [APT4ALL](https://github.com/Ridd1kulusC0d3r/apt4all) a partir de MISP Galaxy, planilha APT Groups & Operations, EternalLiberty e APTnotes. Atribuição é afirmação de quem publicou; confira a fonte.

| Campo | Valor |
|---|---|
| Origem atribuída | Irã |
| Motivação | indefinido |
| Setores-alvo | Energia |
| Vítimas citadas | — |
| Alvos (planilha) | MENA Region |
| Operações conhecidas | — |
| Confiança de atribuição (MISP) | High |

**Como cada fornecedor chama este grupo** (útil para cruzar relatórios):

| Fornecedor | Nome(s) |
|---|---|
| CrowdStrike | Flash Kitten |
| MITRE ATT&CK | G0077 |

**Outros nomes no APT4ALL (não listados pelo ATT&CK):** Flash Kitten

## 4. Perfil TTP por tática (kill chain)

Cada linha: técnica, como o grupo a usou segundo relatos públicos, e o que existe para detectar e testar.

### Resource Development (TA0042) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1588.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1588.002) Tool | Leafminer has obtained and used tools such as LaZagne, Mimikatz, PsExec, and MailSniper. | 35 | — | — |

### Initial Access (TA0001) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1189](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1189) Drive-by Compromise | Leafminer has infected victims using watering holes. | 57 | — | — |

### Execution (TA0002) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1059.007](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.007) JavaScript | Leafminer infected victims using JavaScript code. | 205 | 5 | — |

### Persistence (TA0003) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1136.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1136.001) Local Account | Leafminer used a tool called Imecab to set up a persistent remote access account on the victim machine. | 103 | 10 | — |

### Privilege Escalation (TA0004) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1055.013](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1055.013) Process Doppelgänging | Leafminer has used Process Doppelgänging to evade security software while deploying tools on compromised systems. | 2 | — | — |

### Stealth (TA0005) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1027.010](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1027.010) Command Obfuscation | Leafminer obfuscated scripts that were used on victim machines. | 78 | — | — |
| [T1055.013](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1055.013) Process Doppelgänging | Leafminer has used Process Doppelgänging to evade security software while deploying tools on compromised systems. | 2 | — | — |

### Credential Access (TA0006) — 7

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1003.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1003.001) LSASS Memory | Leafminer used several tools for retrieving login and password information, including LaZagne and Mimikatz. | 580 | 14 | 10 |
| [T1003.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1003.004) LSA Secrets | Leafminer used several tools for retrieving login and password information, including LaZagne. | 72 | 2 | — |
| [T1003.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1003.005) Cached Domain Credentials | Leafminer used several tools for retrieving login and password information, including LaZagne. | 32 | 1 | — |
| [T1110.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1110.003) Password Spraying | Leafminer used a tool called Total SMB BruteForcer to perform internal password spraying. | 62 | 9 | 1 |
| [T1552.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1552.001) Credentials In Files | Leafminer used several tools for retrieving login and password information, including LaZagne. | 166 | 32 | — |
| [T1555](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1555) Credentials from Password Stores | Leafminer used several tools for retrieving login and password information, including LaZagne. | 160 | 9 | 2 |
| [T1555.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1555.003) Credentials from Web Browsers | Leafminer used several tools for retrieving login and password information, including LaZagne. | 59 | 18 | 5 |

### Discovery (TA0007) — 3

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1018](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1018) Remote System Discovery | Leafminer used Microsoft’s Sysinternals tools to gather detailed information about remote systems. | 157 | 23 | 1 |
| [T1046](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1046) Network Service Discovery | Leafminer scanned network services to search for vulnerabilities in the victim system. | 212 | 13 | 2 |
| [T1083](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1083) File and Directory Discovery | Leafminer used a tool called MailSniper to search for files on the desktop and another utility called Sobolsoft to extract attachments from EML files. | 137 | 9 | — |

### Collection (TA0009) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1114.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1114.002) Remote Email Collection | Leafminer used a tool called MailSniper to search through the Exchange server mailboxes for keywords. | 11 | 1 | — |

## 5. Assinatura comportamental

Técnicas que este grupo usa e que poucos dos 178 grupos do ATT&CK usam. Pesam mais numa atribuição por TTP: ver várias delas juntas é mais informativo do que ver técnicas comuns como PowerShell.

| Técnica | Outros grupos que usam | Peso (raridade) |
|---|---:|---:|
| T1055.013 Process Doppelgänging | 0 | 4.49 |
| T1003.005 Cached Domain Credentials | 3 | 3.58 |
| T1003.004 LSA Secrets | 9 | 2.79 |
| T1110.003 Password Spraying | 11 | 2.62 |
| T1114.002 Remote Email Collection | 12 | 2.55 |
| T1555 Credentials from Password Stores | 12 | 2.55 |
| T1136.001 Local Account | 15 | 2.35 |
| T1552.001 Credentials In Files | 15 | 2.35 |
| T1555.003 Credentials from Web Browsers | 23 | 1.97 |
| T1059.007 JavaScript | 29 | 1.75 |

## 6. Arsenal

| Software | Tipo | Técnicas no ATT&CK | Uso relatado (EN) |
|---|---|---:|---|
| [Mimikatz](https://attack.mitre.org/software/S0002/) | ferramenta | 17 |  |
| [LaZagne](https://attack.mitre.org/software/S0349/) | ferramenta | 10 |  |
| [PsExec](https://attack.mitre.org/software/S0029/) | ferramenta | 5 |  |
| [MailSniper](https://attack.mitre.org/software/S0413/) | ferramenta | 3 |  |

**Outras ferramentas e malware relatados (planilha APT Groups & Operations / MISP):** Sorgu, guester, Trojan.Imecab

## 7. Campanhas

Nenhuma campanha atribuída no ATT&CK.

## 8. Cobertura defensiva

**17 de 17 técnicas (100%)** têm ao menos uma regra pública no catálogo Detection Rules.

### Onde procurar — cobertura por tecnologia

Quantas técnicas deste grupo têm ao menos uma regra em cada tecnologia. Comece a caça pelas tecnologias que você tem e que aparecem aqui.

| Tecnologia | Técnicas do grupo com regra |
|---|---:|
| Windows | 17 |
| EDR / XDR | 14 |
| Active Directory | 11 |
| Firewall & perímetro | 11 |
| VPN & acesso remoto | 10 |
| macOS | 10 |
| DNS | 9 |
| Servidores web & aplicações | 9 |
| Bancos de dados | 9 |
| Outros / genérico | 9 |
| Linux | 9 |
| E-mail | 9 |

### Regras recomendadas por técnica

Melhor regra disponível por técnica (formato portável e maduro primeiro).

| Técnica | Regra | Formato | Fonte |
|---|---|---|---|
| T1003.001 | [Antivirus - Password Dumper Signature](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A78cc2dd2-7d20-4d32-93ff-057084c38b93) | Sigma | SigmaHQ |
| T1003.001 | [Mimikatz through Windows Remote Management](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Aaa35a627-33fb-4d04-a165-d33b4afca3e8) | Sigma | OpenSearch Security Analytics |
| T1003.004 | [Possible Impacket SecretDump Remote Activity - Zeek](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A92dae1ed-1c9d-4eff-a567-33acbd95b00e) | Sigma | SigmaHQ |
| T1003.004 | [Cred Dump Tools Dropped Files](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A8fbf3271-1ef6-4e94-8210-03c2317947f6) | Sigma | SigmaHQ |
| T1003.005 | [Cred Dump Tools Dropped Files](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A8fbf3271-1ef6-4e94-8210-03c2317947f6) | Sigma | SigmaHQ |
| T1003.005 | [Potential Reconnaissance For Cached Credentials Via Cmdkey.EXE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A07f8bdc2-c9b3-472a-9817-5a670b872f53) | Sigma | SigmaHQ |
| T1018 | [Chopper Webshell Process Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Afa3c117a-bc0d-416e-a31b-0c0e80653efb) | Sigma | SigmaHQ |
| T1018 | [Webshell Hacking Activity Patterns](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4ebc877f-4612-45cb-b3a5-8e3834db36c9) | Sigma | SigmaHQ |
| T1027.010 | [Decoded Payload Piped to Interpreter Detected via Defend for Containers](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A0fb83aa0-3d17-41e9-b09c-56397bf7a7d9) | Elastic | Elastic detection-rules |
| T1027.010 | [Potential PowerShell Obfuscation via String Concatenation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Af6d8c743-0916-4483-8333-3c6f107e0caa) | Elastic | Elastic detection-rules |
| T1046 | [HackTool - winPEAS Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A98b53e78-ebaf-46f8-be06-421aafd176d9) | Sigma | SigmaHQ |
| T1046 | [HackTool - WinPwn Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad557dc06-62e8-4468-a8e8-7984124908ce) | Sigma | SigmaHQ |
| T1055.013 | [PowerShell PInvoke Process Injection API Chain](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=splunk-security-content%3A%3A3f1a2b4c-d5e6-7890-abcd-ef1234567890) | Splunk | Splunk security_content |
| T1055.013 | [Process Executable Image Tampering Attempt](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-protections-artifacts-behavior%3A%3A905f4c30-a8c5-40a5-80e3-a50c6714632f) | Elastic | Elastic protections-artifacts (behavior) |
| T1059.007 | [Adwind RAT / JRAT](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1fac1481-2dbc-48b2-9096-753c49b4ec71) | Sigma | SigmaHQ |
| T1059.007 | [WScript or CScript Dropper - File](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A002bdb95-0cf1-46a6-9e08-d38c128a6127) | Sigma | SigmaHQ |
| T1083 | [Turla Group Lateral Movement](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac601f20d-570a-4cde-a7d6-e17f99cb8e7f) | Sigma | SigmaHQ |
| T1083 | [WannaCry Ransomware Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A41d40bff-377a-43e2-8e1b-2e543069e079) | Sigma | SigmaHQ |
| T1110.003 | [Multiple SonicWall Login Failures Followed by Successful Login](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Aefe7ac71-3b13-41cf-8263-30af68ce3f19) | Elastic | Elastic detection-rules |
| T1110.003 | [Potential Successful SSH Brute Force Attack](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A8cb84371-d053-4f4f-bce0-c74990e28f28) | Elastic | Elastic detection-rules |
| T1114.002 | [Microsoft Graph Email Access by Unusual User and Client](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ae882e934-2aaa-11f0-8272-f661ea17fbcc) | Elastic | Elastic detection-rules |
| T1114.002 | [M365 Exchange Mailbox Accessed by Unusual Client](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A48819484-9826-4083-9eba-1da74cd0eaf2) | Elastic | Elastic detection-rules |
| T1136.001 | [DarkGate - User Created Via Net.EXE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Abf906d7b-7070-4642-8383-e404cf26eba5) | Sigma | SigmaHQ |
| T1136.001 | [Serv-U Exploitation CVE-2021-35211 by DEV-0322](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A75578840-9526-4b2a-9462-af469a45e767) | Sigma | SigmaHQ |
| T1189 | [Flash Player Update from Suspicious Location](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4922a5dd-6743-4fc2-8e81-144374280997) | Sigma | SigmaHQ |
| T1189 | [Cross Site Scripting Strings](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A65354b83-a2ea-4ea6-8414-3ab38be0d409) | Sigma | SigmaHQ |
| T1552.001 | [Potential Russian APT Credential Theft Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab83f5166-9237-4b5e-9cd4-7b5d52f4d8ee) | Sigma | SigmaHQ |
| T1552.001 | [Copy Passwd Or Shadow From TMP Path](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Afa4aaed5-4fe0-498d-bbc0-08e3346387ba) | Sigma | SigmaHQ |
| T1555 | [HackTool - SecurityXploded Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A7679d464-4f74-45e2-9e01-ac66c5eb041a) | Sigma | SigmaHQ |
| T1555 | [SecurityXploded Tool](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A7679d464-4f74-45e2-9e01-ac66c5eb041a) | Sigma | OpenSearch Security Analytics |
| T1555.003 | [SQLite Chromium Profile Data DB Access](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A24c77512-782b-448a-8950-eddb0785fc71) | Sigma | SigmaHQ |
| T1555.003 | [HackTool - WinPwn Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad557dc06-62e8-4468-a8e8-7984124908ce) | Sigma | SigmaHQ |
| T1588.002 | [Hacktool Execution - Imphash](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A24e3e58a-646b-4b50-adef-02ef935b9fc8) | Sigma | SigmaHQ |
| T1588.002 | [Renamed SysInternals DebugView Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acd764533-2e07-40d6-a718-cfeec7f2da7f) | Sigma | SigmaHQ |

## 9. Plano de emulação e validação

Use num laboratório isolado e autorizado para confirmar que as regras disparam. Os comandos estão nos repositórios oficiais.

| Tática | Técnica | Teste Atomic Red Team | Plataformas |
|---|---|---|---|
| Execution | [T1059.007](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.007/T1059.007.md) | JScript execution to gather local computer information via cscript | windows |
| Execution | [T1059.007](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.007/T1059.007.md) | JScript execution to gather local computer information via wscript | windows |
| Persistence | [T1136.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1136.001/T1136.001.md) | Create a user account on a Linux system | linux |
| Persistence | [T1136.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1136.001/T1136.001.md) | Create a user account on a FreeBSD system | linux |
| Credential Access | [T1003.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/T1003.001.md) | Dump LSASS.exe Memory using ProcDump | windows |
| Credential Access | [T1003.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/T1003.001.md) | Dump LSASS.exe Memory using comsvcs.dll | windows |
| Credential Access | [T1003.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.004/T1003.004.md) | Dumping LSA Secrets | windows |
| Credential Access | [T1003.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.004/T1003.004.md) | Dump Kerberos Tickets from LSA using dumper.ps1 | windows |
| Credential Access | [T1003.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.005/T1003.005.md) | Cached Credential Dump via Cmdkey | windows |
| Credential Access | [T1110.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1110.003/T1110.003.md) | Password Spray all Domain Users | windows |
| Credential Access | [T1110.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1110.003/T1110.003.md) | Password Spray (DomainPasswordSpray) | windows |
| Credential Access | [T1552.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1552.001/T1552.001.md) | Find AWS credentials | linux, macos |
| Credential Access | [T1552.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1552.001/T1552.001.md) | Extract Browser and System credentials with LaZagne | macos |
| Credential Access | [T1555](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1555/T1555.md) | Extract Windows Credential Manager via VBA | windows |
| Credential Access | [T1555](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1555/T1555.md) | Dump credentials from Windows Credential Manager With PowerShell [windows Credentials] | windows |
| Credential Access | [T1555.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1555.003/T1555.003.md) | Run Chrome-password Collector | windows |
| Credential Access | [T1555.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1555.003/T1555.003.md) | Search macOS Safari Cookies | macos |
| Discovery | [T1018](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1018/T1018.md) | Remote System Discovery - net | windows |
| Discovery | [T1018](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1018/T1018.md) | Remote System Discovery - net group Domain Computers | windows |
| Discovery | [T1046](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1046/T1046.md) | Port Scan | linux, macos |
| Discovery | [T1046](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1046/T1046.md) | Port Scan Nmap | linux, macos |
| Discovery | [T1083](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1083/T1083.md) | File and Directory Discovery (cmd.exe) | windows |
| Discovery | [T1083](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1083/T1083.md) | File and Directory Discovery (PowerShell) | windows |
| Collection | [T1114.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1114.002/T1114.002.md) | Office365 - Remote Mail Collected | office-365 |

**Logs reais de ataque (EVTX) para testar sem executar nada:**

- T1003.001 — [CA_hashdump_4663_4656_lsass_access](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Credential%20Access/CA_hashdump_4663_4656_lsass_access.evtx) _(inferido)_
- T1003.001 — [LsassSilentProcessExit_process_exit_monitor_3001_lsass](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Credential%20Access/LsassSilentProcessExit_process_exit_monitor_3001_lsass.evtx) _(inferido)_
- T1018 — [ID5145-DNS hosts files access via network share](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1018-Remote%20System%20Discovery/ID5145-DNS%20hosts%20files%20access%20via%20network%20share.evtx) _(explícito)_
- T1046 — [ID131-RDP brutforce (no user info)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1046-Network%20Service%20Scanning/ID131-RDP%20brutforce%20%28no%20user%20info%29.evtx) _(explícito)_
- T1046 — [ID4624-Anonymous login with domain specified (DonPapi)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1046-Network%20Service%20Scanning/ID4624-Anonymous%20login%20with%20domain%20specified%20%28DonPapi%29.evtx) _(explícito)_
- T1110.003 — [kerberos_pwd_spray_4771](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Credential%20Access/kerberos_pwd_spray_4771.evtx) _(inferido)_
- T1555 — [ID4662-Sensitve DPAPI attributes accessed](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0006-Credential%20Access/T1555-Credentials%20from%20Password%20Stores/ID4662-Sensitve%20DPAPI%20attributes%20accessed.evtx) _(explícito)_
- T1555 — [ID5145-user file-credentials-browser dump via network share](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0006-Credential%20Access/T1555-Credentials%20from%20Password%20Stores/ID5145-user%20file-credentials-browser%20dump%20via%20network%20share.evtx) _(explícito)_
- T1555.003 — [CA_4624_4625_LogonType2_LogonProc_chrome](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Credential%20Access/CA_4624_4625_LogonType2_LogonProc_chrome.evtx) _(inferido)_
- T1555.003 — [CA_chrome_firefox_opera_4663](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Credential%20Access/CA_chrome_firefox_opera_4663.evtx) _(inferido)_

## 10. Hipóteses de hunting

Se Leafminer estiver no seu ambiente, estas são as perguntas a fazer aos seus dados (fontes de log segundo as estratégias de detecção do MITRE ATT&CK).

1. **T1055.013 Process Doppelgänging** — Detects adversary abuse of Transactional NTFS (TxF) and undocumented process loading mechanisms (e.g., NtCreateProcessEx) to create a hollowed process from an uncommitted, maliciously tainted file image in memory, later executed via NtCreateThreadEx. Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=10), `WinEventLog:Sysmon` (EventCode=11).
2. **T1003.005 Cached Domain Credentials** — Detects adversary behavior accessing Windows cached domain credential files using tools like Mimikatz, reg.exe, or PowerShell, often combined with registry exports or LSASS memory scraping. Dados: `WinEventLog:Security` (EventCode=4663, 4670, 4656), `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=10).
3. **T1003.004 LSA Secrets** — Detects adversary activity aimed at accessing LSA Secrets, including registry key export of HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets or memory scraping via tools such as Mimikatz or PowerSploit's Invoke-Mimikatz. Dados: `WinEventLog:Security` (EventCode=4663, 4670, 4656), `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=10).
4. **T1110.003 Password Spraying** — A high volume of authentication failures using a single password (or small set) across many different user accounts within a defined time window Dados: `WinEventLog:Security` (EventCode=4625, 4771, 4648).
5. **T1114.002 Remote Email Collection** — Detects adversaries accessing remote mail systems (e.g., Exchange Online, O365) using stolen credentials or OAuth tokens, followed by scripted access to mailbox contents via PowerShell, AADInternals, or unattended API queries. Detection focuses on abnormal… Dados: `azure:signinlogs` (Abnormal sign-in from scripting tools (PowerShell, AADInternals)), `m365:purview` (MailItemsAccessed & Exchange Audit), `WinEventLog:PowerShell` (EventCode=4103, 4104, 4105, 4106).
6. **T1555 Credentials from Password Stores** — Monitors suspicious access to password stores such as LSASS, DPAPI, Windows Credential Manager, or browser credential databases. Detects anomalous process-to-process access (e.g., Mimikatz accessing LSASS) and correlation of credential store file reads with… Dados: `WinEventLog:Sysmon` (EventCode=10), `WinEventLog:Security` (EventCode=4663, 4670, 4656), `WinEventLog:Sysmon` (EventCode=1).
7. **T1136.001 Local Account** — Adversary uses built-in tools like 'net user /add', PowerShell, or WMI to create a local user. Sequence: Account creation event (4720) follows process creation of a suspicious executable (e.g., powershell.exe or net.exe). Dados: `WinEventLog:Security` (EventCode=4720), `WinEventLog:Sysmon` (EventCode=1).
8. **T1552.001 Credentials In Files** — Correlated file access to insecure credential files (e.g., *.env, *.xml, *.ps1) followed by suspicious process execution or authentication using retrieved credentials. Detected through Sysmon logs and Windows Security Event logs. Dados: `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Security` (EventCode=4624, 4648).
9. **T1555.003 Credentials from Web Browsers** — Detects unauthorized access to web browser credential stores (e.g., Chrome Login Data, Edge Credential Locker) by processes other than the browser itself. Correlates file reads of credential databases with subsequent API calls to `CryptUnprotectData` or… Dados: `WinEventLog:Security` (EventCode=4663, 4670, 4656), `WinEventLog:Sysmon` (EventCode=10), `WinEventLog:Sysmon` (EventCode=1).
10. **T1059.007 JavaScript** — Detects JavaScript execution through WSH (wscript.exe, cscript.exe) or HTA (mshta.exe), particularly when spawned from Office macros, web browsers, or abnormal user paths. Correlates script execution with outbound network activity or system modification. Dados: `WinEventLog:Sysmon` (EventCode=1), `m365:defender` (ScriptBlockLogging + AMSI), `WinEventLog:Sysmon` (EventCode=7).
11. **T1027.010 Command Obfuscation** — Detection of command-line activity exhibiting syntactic obfuscation patterns, such as excessive escape characters, base64 encoding, command concatenation, or outlier command length and entropy. Dados: `WinEventLog:Security` (EventCode=4688).
12. **T1189 Drive-by Compromise** — Correlated evidence of anomalous browser/network behavior (suspicious external resource fetches and script injection patterns) followed by atypical child processes, ephemeral execution contexts, memory modification or process injection, and unexpected file… Dados: `WinEventLog:Security` (EventCode=4624, 4648), `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=3, 22).

## 11. OSINT — onde pesquisar

Consultas prontas com todos os nomes conhecidos do grupo:

- Relatórios técnicos: [busca web](https://duckduckgo.com/?q=%28%22Leafminer%22+OR+%22Raspite%22%29+threat+report) · [PDFs](https://duckduckgo.com/?q=%28%22Leafminer%22+OR+%22Raspite%22%29+filetype%3Apdf)
- Regras e IOCs publicados: [GitHub](https://github.com/search?type=code&q=%22Leafminer%22+OR+%22Raspite%22)
- Pulsos de ameaça: [AlienVault OTX](https://otx.alienvault.com/browse/global/pulses?q=Leafminer)
- Família de malware e atores: [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/actors) (busque por Leafminer, Raspite)
- Cartões de grupo: [ThaiCERT Threat Group Cards](https://apt.etda.or.th/cgi-bin/listgroups.cgi)
- Página oficial: [MITRE ATT&CK G0077](https://attack.mitre.org/groups/G0077/)

## 12. Bibliografia (2 fontes citadas pelo ATT&CK)

- [Dragos Raspite Aug 2018](https://www.dragos.com/blog/20180802Raspite.html) — Dragos, Inc. (2018, August 2). RASPITE. Retrieved November 26, 2018.
- [Symantec Leafminer July 2018](https://www.symantec.com/blogs/threat-intelligence/leafminer-espionage-middle-east) — Symantec Security Response. (2018, July 25). Leafminer: New Espionage Campaigns Targeting Middle Eastern Regions. Retrieved August 28, 2018.

## 13. Limites e confiança

- O ATT&CK registra o que foi **relatado publicamente**, não tudo o que o grupo faz. Ausência de uma técnica não prova que o grupo não a usa.
- **Sobreposição de TTP não é atribuição.** Muitas técnicas são compartilhadas entre grupos e com red teams. Use a assinatura comportamental como hipótese, junto com infraestrutura, malware e contexto.
- Cobertura de detecção refere-se ao catálogo público Detection Rules, não ao seu ambiente: confira se a telemetria necessária chega ao seu SIEM.
- Ligações marcadas como _inferidas_ (EVTX por palavra-chave, relatórios por nome) devem ser verificadas.

---
Fontes: MITRE ATT&CK® (uso livre com atribuição, © The MITRE Corporation), APT4ALL (MISP Galaxy CC0/BSD-2, APT Groups & Operations CC BY 4.0, EternalLiberty, APTnotes, Ransomware Tool Matrix CC BY 4.0), Atomic Red Team (Red Canary, MIT), EVTX-to-MITRE-Attack, EVTX-ATTACK-SAMPLES, APT & CyberCriminal Campaign Collections. Gerado por [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules).
