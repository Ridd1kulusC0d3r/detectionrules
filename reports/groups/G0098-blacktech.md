# BlackTech (G0098) — Dossiê de inteligência

> **TLP:CLEAR** · gerado em 2026-10-26 a partir de fontes abertas · MITRE ATT&CK v20.0 · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0098) · [ATT&CK](https://attack.mitre.org/groups/G0098/)

**Também conhecido como:** Palmerworm  
**Origem atribuída:** China · **Motivação:** espionagem · **Setores-alvo:** —  
**Registro no ATT&CK:** criado em 2020-05-05, atualizado em 2026-07-31 · referências de 2017 a 2021

## 1. Sumário executivo

- **14 técnicas** atribuídas publicamente, concentradas em **Execution, Initial Access, Resource Development**.
- **Arsenal:** 5 malware e 1 ferramentas (ex.: Flagpro, PLEAD, Waterbear, TSCookie, Kivars).
- **Campanhas atribuídas:** 0.
- **Cobertura de detecção pública:** 100% das técnicas têm ao menos uma regra no catálogo; **0 técnicas sem nenhuma regra pública**.
- **Origem e alvos (APT4ALL):** atribuído a **China**, motivação espionagem.
- **Onde a cobertura está:** Windows (12 técnicas com regra), EDR / XDR (12 técnicas com regra), Linux (10 técnicas com regra), macOS (9 técnicas com regra).
- **Assinatura comportamental** (técnicas raras entre os 178 grupos, as mais úteis para atribuição): T1036.002 Right-to-Left Override, T1588.004 Digital Certificates, T1588.003 Code Signing Certificates, T1021.004 SSH, T1106 Native API.

## 2. Quem é

> BlackTech is a suspected Chinese cyber espionage group that has primarily targeted organizations in East Asia--particularly Taiwan, Japan, and Hong Kong--and the US since at least 2013. BlackTech has used a combination of custom malware, dual-use tools, and living off the land tactics to compromise media, construction, engineering, electronics, and financial company networks.

_Texto original do MITRE ATT&CK, em inglês._

## 3. Contexto, nomes e alvos

Consolidado pelo [APT4ALL](https://github.com/Ridd1kulusC0d3r/apt4all) a partir de MISP Galaxy, planilha APT Groups & Operations, EternalLiberty e APTnotes. Atribuição é afirmação de quem publicou; confira a fonte.

| Campo | Valor |
|---|---|
| Origem atribuída | China |
| Motivação | espionagem |
| Setores-alvo | — |
| Vítimas citadas | — |
| Alvos (planilha) | targets in East Asia, particularly Taiwan, and occasionally, Japan and Hong Kong |
| Operações conhecidas | PLEAD, Shrouded Crossbow, Waterbear |
| Confiança de atribuição (MISP) | High |

**Como cada fornecedor chama este grupo** (útil para cruzar relatórios):

| Fornecedor | Nome(s) |
|---|---|
| MITRE ATT&CK | G0098 |

**Outros nomes no APT4ALL (não listados pelo ATT&CK):** Phantom of Routers, CIRCUIT PANDA, Temp.Overboard, HUAPI, T-APT-03, Manga Taurus, Red Djinn, Earth Hundun, Canary Typhoon, Mobwork, CAVERN CASTLE, Circuit Panda/Radio Panda, Bronze Canal, CTG-6177, Shrouded Crossbow, BendyBear/Manga Taurus

## 4. Perfil TTP por tática (kill chain)

Cada linha: técnica, como o grupo a usou segundo relatos públicos, e o que existe para detectar e testar.

### Resource Development (TA0042) — 3

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1588.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1588.002) Tool | BlackTech has obtained and used tools such as Putty, SNScan, and PsExec for its operations. | 35 | — | — |
| [T1588.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1588.003) Code Signing Certificates | BlackTech has used stolen code-signing certificates for its malicious payloads. | 1 | — | — |
| [T1588.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1588.004) Digital Certificates | BlackTech has used valid, stolen digital certificates for some of their malware and tools. | 1 | — | — |

### Initial Access (TA0001) — 3

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1190](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1190) Exploit Public-Facing Application | BlackTech has exploited a buffer overflow vulnerability in Microsoft Internet Information Services (IIS) 6.0, CVE-2017-7269, in order to establish a new HTTP or command and control (C2) server. | 580 | — | — |
| [T1566.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1566.001) Spearphishing Attachment | BlackTech has used spearphishing e-mails with malicious password-protected archived files (ZIP or RAR) to deliver malware. | 230 | 2 | — |
| [T1566.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1566.002) Spearphishing Link | BlackTech has used spearphishing e-mails with links to cloud services to deliver malware. | 138 | 1 | — |

### Execution (TA0002) — 5

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1106](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1106) Native API | BlackTech has used built-in API functions. | 118 | 5 | — |
| [T1203](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1203) Exploitation for Client Execution | BlackTech has exploited multiple vulnerabilities for execution, including Microsoft Office vulnerabilities CVE-2012-0158, CVE-2014-6352, CVE-2017-0199, and Adobe Flash CVE-2015-5119. | 202 | — | — |
| [T1204.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1204.001) Malicious Link | BlackTech has used e-mails with malicious links to lure victims into installing malware. | 52 | — | — |
| [T1204.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1204.002) Malicious File | BlackTech has used e-mails with malicious documents to lure victims into installing malware. | 259 | 13 | — |
| [T1574.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1574.001) DLL | BlackTech has used DLL side loading by giving DLLs hardcoded names and placing them in searched directories. | 455 | 7 | 5 |

### Stealth (TA0005) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1036.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1036.002) Right-to-Left Override | BlackTech has used right-to-left-override to obfuscate the filenames of malicious e-mail attachments. | 18 | 2 | — |
| [T1574.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1574.001) DLL | BlackTech has used DLL side loading by giving DLLs hardcoded names and placing them in searched directories. | 455 | 7 | 5 |

### Discovery (TA0007) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1046](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1046) Network Service Discovery | BlackTech has used the SNScan tool to find other potential targets on victim networks. | 212 | 13 | 2 |

### Lateral Movement (TA0008) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1021.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1021.004) SSH | BlackTech has used Putty for remote access. | 60 | 2 | 3 |

## 5. Assinatura comportamental

Técnicas que este grupo usa e que poucos dos 178 grupos do ATT&CK usam. Pesam mais numa atribuição por TTP: ver várias delas juntas é mais informativo do que ver técnicas comuns como PowerShell.

| Técnica | Outros grupos que usam | Peso (raridade) |
|---|---:|---:|
| T1036.002 Right-to-Left Override | 4 | 3.40 |
| T1588.004 Digital Certificates | 6 | 3.11 |
| T1588.003 Code Signing Certificates | 7 | 2.99 |
| T1021.004 SSH | 18 | 2.19 |
| T1106 Native API | 20 | 2.10 |
| T1046 Network Service Discovery | 32 | 1.66 |
| T1574.001 DLL | 35 | 1.58 |
| T1203 Exploitation for Client Execution | 41 | 1.43 |
| T1190 Exploit Public-Facing Application | 46 | 1.32 |
| T1566.002 Spearphishing Link | 47 | 1.30 |

## 6. Arsenal

| Software | Tipo | Técnicas no ATT&CK | Uso relatado (EN) |
|---|---|---:|---|
| [Flagpro](https://attack.mitre.org/software/S0696/) | malware | 24 |  |
| [PLEAD](https://attack.mitre.org/software/S0435/) | malware | 15 |  |
| [Waterbear](https://attack.mitre.org/software/S0579/) | malware | 14 |  |
| [TSCookie](https://attack.mitre.org/software/S0436/) | malware | 13 |  |
| [Kivars](https://attack.mitre.org/software/S0437/) | malware | 7 |  |
| [PsExec](https://attack.mitre.org/software/S0029/) | ferramenta | 5 |  |

**Outras ferramentas e malware relatados (planilha APT Groups & Operations / MISP):** BendyBear

## 7. Campanhas

Nenhuma campanha atribuída no ATT&CK.

## 8. Cobertura defensiva

**14 de 14 técnicas (100%)** têm ao menos uma regra pública no catálogo Detection Rules.

### Onde procurar — cobertura por tecnologia

Quantas técnicas deste grupo têm ao menos uma regra em cada tecnologia. Comece a caça pelas tecnologias que você tem e que aparecem aqui.

| Tecnologia | Técnicas do grupo com regra |
|---|---:|
| Windows | 12 |
| EDR / XDR | 12 |
| Linux | 10 |
| macOS | 9 |
| Servidores web & aplicações | 9 |
| AWS | 8 |
| Proxy / SWG | 8 |
| Integridade, conformidade & vulnerabilidade | 8 |
| Outros / genérico | 8 |
| Microsoft 365 | 8 |
| Contêineres (Docker/runtime) | 7 |
| SaaS de negócio | 7 |

### Regras recomendadas por técnica

Melhor regra disponível por técnica (formato portável e maduro primeiro).

| Técnica | Regra | Formato | Fonte |
|---|---|---|---|
| T1021.004 | [Potential THC Tool Downloaded](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A2ddc468e-b39b-4f5b-9825-f3dcb0e998ea) | Elastic | Elastic detection-rules |
| T1021.004 | [AWS EC2 CreateKeyPair by New Principal from Non-Cloud AS Organization](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ac8e4f1a2-9b3d-4c5e-a6f7-8b9c0d1e2f3a) | Elastic | Elastic detection-rules |
| T1036.002 | [Potential File Extension Spoofing Using Right-to-Left Override](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A979baf41-ca44-4540-9d0c-4fcef3b5a3a4) | Sigma | SigmaHQ |
| T1036.002 | [Potential Defense Evasion Via Right-to-Left Override](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aad691d92-15f2-4181-9aa4-723c74f9ddc3) | Sigma | SigmaHQ |
| T1046 | [HackTool - winPEAS Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A98b53e78-ebaf-46f8-be06-421aafd176d9) | Sigma | SigmaHQ |
| T1046 | [HackTool - WinPwn Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad557dc06-62e8-4468-a8e8-7984124908ce) | Sigma | SigmaHQ |
| T1106 | [Turla Group Named Pipes](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A739915e4-1e70-4778-8b8a-17db02f66db1) | Sigma | SigmaHQ |
| T1106 | [BPFDoor Abnormal Process ID or Lock File Accessed](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A808146b2-9332-4d78-9416-d7e47012d83d) | Sigma | SigmaHQ |
| T1190 | [OMIGOD HTTP No Authentication RCE - CVE-2021-38647](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aab6b1a39-a9ee-4ab4-b075-e83acf6e346b) | Sigma | SigmaHQ |
| T1190 | [Exploited CVE-2020-10189 Zoho ManageEngine](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A846b866e-2a57-46ee-8e16-85fa92759be7) | Sigma | OpenSearch Security Analytics |
| T1203 | [Droppers Exploiting CVE-2017-11882](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A678eb5f4-8597-4be6-8be7-905e4234b53a) | Sigma | SigmaHQ |
| T1203 | [OMIGOD HTTP No Authentication RCE - CVE-2021-38647](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aab6b1a39-a9ee-4ab4-b075-e83acf6e346b) | Sigma | SigmaHQ |
| T1204.001 | [Google Workspace Object Copied from External Drive with App Consent](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Af33e68a4-bd19-11ed-b02f-f661ea17fbcc) | Elastic | Elastic detection-rules |
| T1204.001 | [Suspicious ClickFix/FileFix Execution Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad487ed4a-fd24-436d-a0b2-f4e95f7b2635) | Sigma | SigmaHQ |
| T1204.002 | [Ursnif Malware C2 URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A932ac737-33ca-4afd-9869-0d48b391fcc9) | Sigma | SigmaHQ |
| T1204.002 | [Droppers Exploiting CVE-2017-11882](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A678eb5f4-8597-4be6-8be7-905e4234b53a) | Sigma | SigmaHQ |
| T1566.001 | [Ursnif Malware C2 URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A932ac737-33ca-4afd-9869-0d48b391fcc9) | Sigma | SigmaHQ |
| T1566.001 | [Droppers Exploiting CVE-2017-11882](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A678eb5f4-8597-4be6-8be7-905e4234b53a) | Sigma | SigmaHQ |
| T1566.002 | [Potential Malicious Usage of CloudTrail System Manager](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A38e7f511-3f74-41d4-836e-f57dfa18eead) | Sigma | SigmaHQ |
| T1566.002 | [Google Workspace Device Registration After OAuth from Suspicious ASN](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A012bfca7-45cb-4507-a3ba-3777167f8b81) | Elastic | Elastic detection-rules |
| T1574.001 | [Winnti Pipemon Characteristics](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A73d70463-75c9-4258-92c6-17500fe972f2) | Sigma | SigmaHQ |
| T1574.001 | [Winnti Pipemon Characteristics](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A73d70463-75c9-4258-92c6-17500fe972f2) | Sigma | OpenSearch Security Analytics |
| T1588.002 | [Hacktool Execution - Imphash](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A24e3e58a-646b-4b50-adef-02ef935b9fc8) | Sigma | SigmaHQ |
| T1588.002 | [Renamed SysInternals DebugView Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acd764533-2e07-40d6-a718-cfeec7f2da7f) | Sigma | SigmaHQ |
| T1588.003 | [Short-lived ephemeral code signing certificates](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-hunting-queries%3A%3Ae920899f-edf0-446c-bb13-effbaf61b27b) | Sentinel KQL | Microsoft Sentinel (Hunting Queries) |
| T1588.004 | [Cisco Secure Firewall - Blacklisted SSL Certificate Fingerprint](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=splunk-security-content%3A%3Ac43f7b49-2dab-4e76-892e-7f971c2f20f1) | Splunk | Splunk security_content |

## 9. Plano de emulação e validação

Use num laboratório isolado e autorizado para confirmar que as regras disparam. Os comandos estão nos repositórios oficiais.

| Tática | Técnica | Teste Atomic Red Team | Plataformas |
|---|---|---|---|
| Initial Access | [T1566.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1566.001/T1566.001.md) | Download Macro-Enabled Phishing Attachment | windows |
| Initial Access | [T1566.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1566.001/T1566.001.md) | Word spawned a command shell and used an IP address in the command line | windows |
| Initial Access | [T1566.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1566.002/T1566.002.md) | Paste and run technique | windows |
| Execution | [T1106](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1106/T1106.md) | Execution through API - CreateProcess | windows |
| Execution | [T1106](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1106/T1106.md) | WinPwn - Get SYSTEM shell - Pop System Shell using CreateProcess technique | windows |
| Execution | [T1204.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1204.002/T1204.002.md) | OSTap Style Macro Execution | windows |
| Execution | [T1204.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1204.002/T1204.002.md) | OSTap Payload Download | windows |
| Stealth | [T1036.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.002/T1036.002.md) | Masquerading: Right-to-Left Override Batch File Creation and Execution | windows |
| Stealth | [T1036.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.002/T1036.002.md) | Masquerading: RTLO Masqueraded File Download and Execution | windows |
| Stealth | [T1574.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1574.001/T1574.001.md) | DLL Search Order Hijacking - amsi.dll | windows |
| Stealth | [T1574.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1574.001/T1574.001.md) | Phantom Dll Hijacking - WinAppXRT.dll | windows |
| Discovery | [T1046](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1046/T1046.md) | Port Scan | linux, macos |
| Discovery | [T1046](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1046/T1046.md) | Port Scan Nmap | linux, macos |
| Lateral Movement | [T1021.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.004/T1021.004.md) | ESXi - Enable SSH via PowerCLI | windows |
| Lateral Movement | [T1021.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.004/T1021.004.md) | ESXi - Enable SSH via VIM-CMD | windows |

**Logs reais de ataque (EVTX) para testar sem executar nada:**

- T1021.004 — [ID4-OpenSSH server listening](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0008-Lateral%20Movement/T1021.004-Remote%20Service%20SSH/ID4-OpenSSH%20server%20listening.evtx) _(explícito)_
- T1021.004 — [ID4103-4104-OpenSSH server activation and config](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0008-Lateral%20Movement/T1021.004-Remote%20Service%20SSH/ID4103-4104-OpenSSH%20server%20activation%20and%20config.evtx) _(explícito)_
- T1046 — [ID131-RDP brutforce (no user info)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1046-Network%20Service%20Scanning/ID131-RDP%20brutforce%20%28no%20user%20info%29.evtx) _(explícito)_
- T1046 — [ID4624-Anonymous login with domain specified (DonPapi)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1046-Network%20Service%20Scanning/ID4624-Anonymous%20login%20with%20domain%20specified%20%28DonPapi%29.evtx) _(explícito)_
- T1574.001 — [DE_timestomp_and_dll_sideloading_and_RunPersist](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/AutomatedTestingTools/Malware/DE_timestomp_and_dll_sideloading_and_RunPersist.evtx) _(inferido)_
- T1574.001 — [sideloading_injection_persistence_run_key](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/AutomatedTestingTools/Malware/sideloading_injection_persistence_run_key.evtx) _(inferido)_

## 10. Hipóteses de hunting

Se BlackTech estiver no seu ambiente, estas são as perguntas a fazer aos seus dados (fontes de log segundo as estratégias de detecção do MITRE ATT&CK).

1. **T1036.002 Right-to-Left Override** — Execution of files containing right-to-left override characters (U+202E) to masquerade true file extensions. Often found in phishing payloads or file downloads. Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:PowerShell` (EventCode=4103, 4104, 4105, 4106), `WinEventLog:Windows Defender` (Operational).
2. **T1588.004 Digital Certificates** — Consider use of services that may aid in the tracking of newly issued certificates and/or certificates in use on sites across the Internet. In some cases it may be possible to pivot on known pieces of certificate information to uncover other adversary… Dados: `Certificate` (None), `Internet Scan` (None).
3. **T1588.003 Code Signing Certificates** — Consider analyzing code signing certificates for features that may be associated with the adversary and/or their developers, such as the thumbprint, algorithm used, validity period, common name, and certificate authority. Malware repositories can also be used… Dados: `Malware Repository` (None).
4. **T1021.004 SSH** — SSH login from a remote system (via sshd), followed by user context execution of suspicious binaries or privilege escalation behavior. Dados: `auditd:EXECVE` (EXECVE), `linux:syslog` (None), `NSM:Flow` (TCP port 22 traffic).
5. **T1106 Native API** — Unusual or suspicious processes loading critical native API DLLs (e.g., ntdll.dll, kernel32.dll) followed by direct syscall behavior, memory manipulation, or hollowing. Dados: `WinEventLog:Sysmon` (EventCode=7), `WinEventLog:Sysmon` (EventCode=10), `WinEventLog:Sysmon` (EventCode=1).
6. **T1046 Network Service Discovery** — Detects processes performing network enumeration (e.g., port scans, service probing) by correlating process creation, socket connections, and sequential destination IP probing within a time window. Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=3, 22).
7. **T1574.001 DLL** — DLL hijacking behaviors including unexpected DLL loads from non-standard directories, replacement of DLLs, phantom DLL insertion, redirection file creation, and substitution of legitimate DLLs. Defender correlates file system modifications, registry changes,… Dados: `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Sysmon` (EventCode=15), `WinEventLog:Sysmon` (EventCode=7).
8. **T1203 Exploitation for Client Execution** — Cause→effect chain: (1) A client app (browser, Office, PDF/Flash/reader) experiences a crash/abnormal exit or loads from an unusual location, then (2) drops or modifies a file in user-writable paths, and/or (3) spawns an unexpected child (e.g.,… Dados: `WinEventLog:Application` (EventCode=1000), `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Sysmon` (EventCode=1).
9. **T1190 Exploit Public-Facing Application** — Adversary sends crafted HTTP/S (or other service) input to an Internet-facing app (IIS/ASP.NET, API, device portal). Chain: (1) abnormal request patterns to public endpoint → (2) elevated 4xx/5xx or unusual methods/paths → (3) server process (w3wp.exe/other… Dados: `ApplicationLog:IIS` (IIS W3C logs in C:\inetpub\logs\LogFiles\W3SVC* (spikes in 5xx, RCE/SQLi/path traversal/JNDI patterns)), `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=7).
10. **T1566.002 Spearphishing Link** — Correlation of inbound emails with embedded links followed by user-driven browser navigation to suspicious or obfuscated domains. Detection chain includes malicious URL in email → user click recorded in Office logs → browser process spawning unusual child… Dados: `m365:unified` (Send/Receive: Inbound emails containing embedded or shortened URLs), `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=3, 22).
11. **T1204.001 Malicious Link** — Behavioral chain: (1) a user-facing app (browser/Office/email client) launches a URL or handles a link, then (2) the same process lineage makes an outbound connection to an untrusted domain/IP, (3) a file is downloaded or unpacked to a user-writable location… Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=3, 22), `WinEventLog:Sysmon` (EventCode=11).
12. **T1566.001 Spearphishing Attachment** — Detection of spearphishing attachments by correlating suspicious email delivery with subsequent file creation and abnormal process execution (e.g., Office spawning PowerShell or CMD). Behavior chain includes inbound email metadata → attachment stored on disk… Dados: `m365:unified` (Send/Receive: Inbound emails with attachments from suspicious or spoofed senders), `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Sysmon` (EventCode=1).

## 11. OSINT — onde pesquisar

Consultas prontas com todos os nomes conhecidos do grupo:

- Relatórios técnicos: [busca web](https://duckduckgo.com/?q=%28%22BlackTech%22+OR+%22Palmerworm%22%29+threat+report) · [PDFs](https://duckduckgo.com/?q=%28%22BlackTech%22+OR+%22Palmerworm%22%29+filetype%3Apdf)
- Regras e IOCs publicados: [GitHub](https://github.com/search?type=code&q=%22BlackTech%22+OR+%22Palmerworm%22)
- Pulsos de ameaça: [AlienVault OTX](https://otx.alienvault.com/browse/global/pulses?q=BlackTech)
- Família de malware e atores: [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/actors) (busque por BlackTech, Palmerworm)
- Cartões de grupo: [ThaiCERT Threat Group Cards](https://apt.etda.or.th/cgi-bin/listgroups.cgi)
- Página oficial: [MITRE ATT&CK G0098](https://attack.mitre.org/groups/G0098/)

**Relatórios na coleção CyberMonitor** (ligados pelo nome do grupo, conferir antes de citar):

- 2017 — [following-trail-blacktech-cyber-espionage-campaigns](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2017/2017.06.22.following-trail-blacktech-cyber-espionage-campaigns/following-trail-blacktech-cyber-espionage-campaigns.pdf) _(via “BlackTech”)_
- 2020 — [Palmerworm_ Espionage Gang Targets the Media, Finance, and Other Sectors _ Symantec Blogs](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2020/2020.09.29.Palmerworm/Palmerworm_%20Espionage%20Gang%20Targets%20the%20Media%2C%20Finance%2C%20and%20Other%20Sectors%20_%20Symantec%20Blogs.pdf) _(via “Palmerworm”)_
- 2021 — [unit42.paloaltonetworks.com-BendyBear Novel Chinese Shellcode Linked With Cyber Espionage Group BlackTech](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2021/2021.02.09.BendyBear/unit42.paloaltonetworks.com-BendyBear%20Novel%20Chinese%20Shellcode%20Linked%20With%20Cyber%20Espionage%20Group%20BlackTech.pdf) _(via “BlackTech”)_
- 2021 — [Malware Gh0stTimes Used by BlackTech - JPCERT_CC Eyes _ JPCERT Coordination Center official Blog](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2021/2021.10.04.Gh0stTimes_BlackTech/Malware%20Gh0stTimes%20Used%20by%20BlackTech%20-%20JPCERT_CC%20Eyes%20_%20JPCERT%20Coordination%20Center%20official%20Blog.pdf) _(via “BlackTech”)_
- 2021 — [EN-BlackTech_2021](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2021/2021.12.19.BlackTech_APT/EN-BlackTech_2021.pdf) _(via “BlackTech”)_

## 12. Bibliografia (9 fontes citadas pelo ATT&CK)

- [ESET PLEAD Malware July 2018](https://www.welivesecurity.com/2018/07/09/certificates-stolen-taiwanese-tech-companies-plead-malware-campaign/) — Cherepanov, A.. (2018, July 9). Certificates stolen from Taiwanese tech‑companies misused in Plead malware campaign. Retrieved May 6, 2020.
- [IronNet BlackTech Oct 2021](https://www.ironnet.com/blog/china-cyber-attacks-the-current-threat-landscape) — Demboski, M., et al. (2021, October 26). China cyber attacks: the current threat landscape. Retrieved March 25, 2022.
- [JPCert PLEAD Downloader June 2018](https://blogs.jpcert.or.jp/en/2018/03/malware-tscooki-7aa0.html) — Tomonaga, S. (2018, June 8). PLEAD Downloader Used by BlackTech. Retrieved May 6, 2020.
- [JPCert TSCookie March 2018](https://blogs.jpcert.or.jp/en/2018/03/malware-tscooki-7aa0.html) — Tomonaga, S. (2018, March 6). Malware “TSCookie”. Retrieved May 6, 2020.
- [NTT Security Flagpro new December 2021](https://insight-jp.nttsecurity.com/post/102hf3q/flagpro-the-new-malware-used-by-blacktech) — Hada, H. (2021, December 28). Flagpro The new malware used by BlackTech. Retrieved March 25, 2022.
- [Reuters Taiwan BlackTech August 2020](https://www.reuters.com/article/us-taiwan-cyber-china/taiwan-says-china-behind-cyberattacks-on-government-agencies-emails-idUSKCN25F0JK) — Lee, Y. (2020, August 19). Taiwan says China behind cyberattacks on government agencies, emails. Retrieved April 6, 2022.
- [Symantec Palmerworm Sep 2020](https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/palmerworm-blacktech-espionage-apt) — Threat Intelligence. (2020, September 29). Palmerworm: Espionage Gang Targets the Media, Finance, and Other Sectors. Retrieved March 25, 2022.
- [Trend Micro Waterbear December 2019](https://www.trendmicro.com/en_us/research/19/l/waterbear-is-back-uses-api-hooking-to-evade-security-product-detection.html) — Su, V. et al. (2019, December 11). Waterbear Returns, Uses API Hooking to Evade Security. Retrieved February 22, 2021.
- [TrendMicro BlackTech June 2017](https://blog.trendmicro.com/trendlabs-security-intelligence/following-trail-blacktech-cyber-espionage-campaigns/) — Bermejo, L., et al. (2017, June 22). Following the Trail of BlackTech’s Cyber Espionage Campaigns. Retrieved May 5, 2020.

## 13. Limites e confiança

- O ATT&CK registra o que foi **relatado publicamente**, não tudo o que o grupo faz. Ausência de uma técnica não prova que o grupo não a usa.
- **Sobreposição de TTP não é atribuição.** Muitas técnicas são compartilhadas entre grupos e com red teams. Use a assinatura comportamental como hipótese, junto com infraestrutura, malware e contexto.
- Cobertura de detecção refere-se ao catálogo público Detection Rules, não ao seu ambiente: confira se a telemetria necessária chega ao seu SIEM.
- Ligações marcadas como _inferidas_ (EVTX por palavra-chave, relatórios por nome) devem ser verificadas.

---
Fontes: MITRE ATT&CK® (uso livre com atribuição, © The MITRE Corporation), APT4ALL (MISP Galaxy CC0/BSD-2, APT Groups & Operations CC BY 4.0, EternalLiberty, APTnotes, Ransomware Tool Matrix CC BY 4.0), Atomic Red Team (Red Canary, MIT), EVTX-to-MITRE-Attack, EVTX-ATTACK-SAMPLES, APT & CyberCriminal Campaign Collections. Gerado por [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules).
