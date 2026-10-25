# Earth Lusca (G1006) — Dossiê de inteligência

> **TLP:CLEAR** · gerado em 2026-10-25 a partir de fontes abertas · MITRE ATT&CK v20.0 · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1006) · [ATT&CK](https://attack.mitre.org/groups/G1006/)

**Também conhecido como:** TAG-22, Charcoal Typhoon, CHROMIUM, ControlX  
**Registro no ATT&CK:** criado em 2022-07-01, atualizado em 2026-07-31 · referências de 2021 a 2023

## 1. Sumário executivo

- **44 técnicas** atribuídas publicamente, concentradas em **Execution, Resource Development, Discovery**.
- **Arsenal:** 3 malware e 6 ferramentas (ex.: Cobalt Strike, PowerSploit, ShadowPad, Mimikatz, Winnti for Linux).
- **Campanhas atribuídas:** 0.
- **Cobertura de detecção pública:** 95% das técnicas têm ao menos uma regra no catálogo; **2 técnicas sem nenhuma regra pública**.
- **Assinatura comportamental** (técnicas raras entre os 178 grupos, as mais úteis para atribuição): T1547.012 Print Processors, T1098.004 SSH Authorized Keys, T1584.006 Web Services, T1003.006 DCSync, T1583.004 Server.

## 2. Quem é

> Earth Lusca is a suspected China-based cyber espionage group that has been active since at least April 2019. Earth Lusca has targeted organizations in Australia, China, Hong Kong, Mongolia, Nepal, the Philippines, Taiwan, Thailand, Vietnam, the United Arab Emirates, Nigeria, Germany, France, and the United States. Targets included government institutions, news media outlets, gambling companies, educational institutions, COVID-19 research organizations, telecommunications companies, religious movements banned in China, and cryptocurrency trading platforms; security researchers assess some Earth Lusca operations may be financially motivated.
> 
> Earth Lusca has used malware commonly used by other Chinese threat groups, including APT41 and the Winnti Group cluster, however security researchers assess Earth Lusca's techniques and infrastructure are separate.

_Texto original do MITRE ATT&CK, em inglês._

## 3. Perfil TTP por tática (kill chain)

Cada linha: técnica, como o grupo a usou segundo relatos públicos, e o que existe para detectar e testar.

### Reconnaissance (TA0043) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1595.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1595.002) Vulnerability Scanning | Earth Lusca has scanned for vulnerabilities in the public-facing servers of their targets. | 27 | — | — |

### Resource Development (TA0042) — 8

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1583.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1583.001) Domains | Earth Lusca has registered domains, intended to look like legitimate target domains, that have been used in watering hole attacks. | 7 | — | — |
| [T1583.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1583.004) Server | Earth Lusca has acquired multiple servers for some of their operations, using each server for a different role. | **0** | — | — |
| [T1583.006](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1583.006) Web Services | Earth Lusca has established GitHub accounts to host their malware. | 2 | — | — |
| [T1584.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1584.004) Server | Earth Lusca has used compromised web servers as part of their operational infrastructure. | **0** | — | — |
| [T1584.006](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1584.006) Web Services | Earth Lusca has compromised Google Drive repositories. | 1 | — | — |
| [T1588.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1588.001) Malware | Earth Lusca has acquired and used a variety of malware, including Cobalt Strike. | 7 | — | — |
| [T1588.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1588.002) Tool | Earth Lusca has acquired and used a variety of open source tools. | 35 | — | — |
| [T1608.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1608.001) Upload Malware | Earth Lusca has staged malware and malicious files on compromised web servers, GitHub, and Google Drive. | 3 | — | — |

### Initial Access (TA0001) — 3

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1189](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1189) Drive-by Compromise | Earth Lusca has performed watering hole attacks. | 57 | — | — |
| [T1190](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1190) Exploit Public-Facing Application | Earth Lusca has compromised victims by directly exploiting vulnerabilities of public-facing servers, including those associated with Microsoft Exchange and Oracle GlassFish. | 580 | — | — |
| [T1566.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1566.002) Spearphishing Link | Earth Lusca has sent spearphishing emails to potential targets that contained a malicious link. | 138 | 1 | — |

### Execution (TA0002) — 9

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1047](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1047) Windows Management Instrumentation | Earth Lusca used a VBA script to execute WMI. | 370 | 12 | 11 |
| [T1053.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1053.005) Scheduled Task | Earth Lusca used the command schtasks /Create /SC ONLOgon /TN WindowsUpdateCheck /TR “[file path]” /ru system for persistence. | 248 | 14 | 11 |
| [T1059.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.001) PowerShell | Earth Lusca has used PowerShell to execute commands. | 1340 | 22 | 15 |
| [T1059.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.005) Visual Basic | Earth Lusca used VBA scripts. | 192 | 3 | — |
| [T1059.006](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.006) Python | Earth Lusca used Python scripts for port scanning or building reverse shells. | 122 | — | — |
| [T1059.007](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.007) JavaScript | Earth Lusca has manipulated legitimate websites to inject malicious JavaScript code as part of their watering hole operations. | 205 | 5 | — |
| [T1204.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1204.001) Malicious Link | Earth Lusca has sent spearphishing emails that required the user to click on a malicious link and subsequently open a decoy document with a malicious loader. | 52 | — | — |
| [T1204.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1204.002) Malicious File | Earth Lusca required users to click on a malicious file for the loader to activate. | 259 | 13 | — |
| [T1574.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1574.001) DLL | Earth Lusca has placed a malicious payload in `%WINDIR%\SYSTEM32\oci.dll` so it would be sideloaded by the MSDTC service. | 455 | 7 | 5 |

### Persistence (TA0003) — 5

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1053.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1053.005) Scheduled Task | Earth Lusca used the command schtasks /Create /SC ONLOgon /TN WindowsUpdateCheck /TR “[file path]” /ru system for persistence. | 248 | 14 | 11 |
| [T1098.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1098.004) SSH Authorized Keys | Earth Lusca has dropped an SSH-authorized key in the `/root/.ssh` folder in order to access a compromised server with SSH. | 16 | 1 | — |
| [T1112](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1112) Modify Registry | Earth Lusca modified the registry using the command reg add “HKEY_CURRENT_USER\Environment” /v UserInitMprLogonScript /t REG_SZ /d “[file path]” for persistence. | 601 | 92 | 3 |
| [T1543.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1543.003) Windows Service | Earth Lusca created a service using the command sc create “SysUpdate” binpath= “cmd /c start “[file path]””&&sc config “SysUpdate” start= auto&&net start SysUpdate for persistence. | 1916 | 6 | 19 |
| [T1547.012](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1547.012) Print Processors | Earth Lusca has added the Registry key `HKLM\SYSTEM\ControlSet001\Control\Print\Environments\Windows x64\Print Processors\UDPrint” /v Driver /d “spool.dll /f` to load malware as a Print Processor. | 4 | 1 | — |

### Privilege Escalation (TA0004) — 5

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1053.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1053.005) Scheduled Task | Earth Lusca used the command schtasks /Create /SC ONLOgon /TN WindowsUpdateCheck /TR “[file path]” /ru system for persistence. | 248 | 14 | 11 |
| [T1098.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1098.004) SSH Authorized Keys | Earth Lusca has dropped an SSH-authorized key in the `/root/.ssh` folder in order to access a compromised server with SSH. | 16 | 1 | — |
| [T1543.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1543.003) Windows Service | Earth Lusca created a service using the command sc create “SysUpdate” binpath= “cmd /c start “[file path]””&&sc config “SysUpdate” start= auto&&net start SysUpdate for persistence. | 1916 | 6 | 19 |
| [T1547.012](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1547.012) Print Processors | Earth Lusca has added the Registry key `HKLM\SYSTEM\ControlSet001\Control\Print\Environments\Windows x64\Print Processors\UDPrint” /v Driver /d “spool.dll /f` to load malware as a Print Processor. | 4 | 1 | — |
| [T1548.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1548.002) Bypass User Account Control | Earth Lusca has used the Fodhelper UAC bypass technique to gain elevated privileges. | 379 | 28 | 14 |

### Stealth (TA0005) — 6

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1027](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1027) Obfuscated Files or Information | Earth Lusca used Base64 to encode strings. | 520 | 11 | 5 |
| [T1027.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1027.003) Steganography | Earth Lusca has used steganography to hide shellcode in a BMP image file. | 13 | — | — |
| [T1036.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1036.005) Match Legitimate Resource Name or Location | Earth Lusca used the command `move [file path] c:\windows\system32\spool\prtprocs\x64\spool.dll` to move and register a malicious DLL name as a Windows print processor, which eventually was loaded by the Print Spooler service. | 116 | 4 | — |
| [T1140](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1140) Deobfuscate/Decode Files or Information | Earth Lusca has used certutil to decode a string into a cabinet file. | 173 | 11 | 1 |
| [T1218.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1218.005) Mshta | Earth Lusca has used `mshta.exe` to load an HTA script within a malicious .LNK file. | 130 | 10 | 4 |
| [T1574.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1574.001) DLL | Earth Lusca has placed a malicious payload in `%WINDIR%\SYSTEM32\oci.dll` so it would be sideloaded by the MSDTC service. | 455 | 7 | 5 |

### Defense Impairment (TA0112) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1112](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1112) Modify Registry | Earth Lusca modified the registry using the command reg add “HKEY_CURRENT_USER\Environment” /v UserInitMprLogonScript /t REG_SZ /d “[file path]” for persistence. | 601 | 92 | 3 |

### Credential Access (TA0006) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1003.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1003.001) LSASS Memory | Earth Lusca has used ProcDump to obtain the hashes of credentials by dumping the memory of the LSASS process. | 580 | 14 | 10 |
| [T1003.006](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1003.006) DCSync | Earth Lusca has used a DCSync command with Mimikatz to retrieve credentials from an exploited controller. | 33 | 2 | 2 |

### Discovery (TA0007) — 7

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1007](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1007) System Service Discovery | Earth Lusca has used Tasklist to obtain information from a compromised host. | 37 | 8 | — |
| [T1016](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1016) System Network Configuration Discovery | Earth Lusca used the command ipconfig to obtain information about network configurations. | 99 | 10 | 5 |
| [T1018](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1018) Remote System Discovery | Earth Lusca used the command powershell “Get-EventLog -LogName security -Newest 500 \| where {$_.EventID -eq 4624} \| format-list - property * \| findstr “Address”” to find the network information of successfully logged-in accounts to discovery addresses of other… | 157 | 23 | 1 |
| [T1033](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1033) System Owner/User Discovery | Earth Lusca collected information on user accounts via the whoami command. | 181 | 8 | — |
| [T1049](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1049) System Network Connections Discovery | Earth Lusca employed a PowerShell script called RDPConnectionParser to read and filter the Windows event log “Microsoft-Windows-TerminalServices-RDPClient/Operational” (Event ID 1024) to obtain network information from RDP connections. Earth Lusca has also use… | 47 | 7 | — |
| [T1057](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1057) Process Discovery | Earth Lusca has used Tasklist to obtain information from a compromised host. | 82 | 10 | — |
| [T1482](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1482) Domain Trust Discovery | Earth Lusca has used Nltest to obtain information about domain controllers. | 158 | 8 | 1 |

### Lateral Movement (TA0008) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1210](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1210) Exploitation of Remote Services | Earth Lusca has used Mimikatz to exploit a domain controller via the ZeroLogon exploit (CVE-2020-1472). | 192 | — | 4 |

### Collection (TA0009) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1560.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1560.001) Archive via Utility | Earth Lusca has used WinRAR to compress stolen files into an archive prior to exfiltration. | 76 | 13 | — |

### Command and Control (TA0011) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1090](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1090) Proxy | Earth Lusca adopted Cloudflare as a proxy for compromised servers. | 162 | — | 1 |

### Exfiltration (TA0010) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1567.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1567.002) Exfiltration to Cloud Storage | Earth Lusca has used the megacmd tool to upload stolen files from a victim network to MEGA. | 85 | 2 | — |

## 4. Assinatura comportamental

Técnicas que este grupo usa e que poucos dos 178 grupos do ATT&CK usam. Pesam mais numa atribuição por TTP: ver várias delas juntas é mais informativo do que ver técnicas comuns como PowerShell.

| Técnica | Outros grupos que usam | Peso (raridade) |
|---|---:|---:|
| T1547.012 Print Processors | 0 | 4.49 |
| T1098.004 SSH Authorized Keys | 2 | 3.80 |
| T1584.006 Web Services | 3 | 3.58 |
| T1003.006 DCSync | 4 | 3.40 |
| T1583.004 Server | 8 | 2.88 |
| T1027.003 Steganography | 9 | 2.79 |
| T1482 Domain Trust Discovery | 9 | 2.79 |
| T1584.004 Server | 9 | 2.79 |
| T1548.002 Bypass User Account Control | 10 | 2.70 |
| T1210 Exploitation of Remote Services | 11 | 2.62 |

## 5. Arsenal

| Software | Tipo | Técnicas no ATT&CK | Uso relatado (EN) |
|---|---|---:|---|
| [Cobalt Strike](https://attack.mitre.org/software/S0154/) | malware | 73 |  |
| [PowerSploit](https://attack.mitre.org/software/S0194/) | ferramenta | 28 |  |
| [ShadowPad](https://attack.mitre.org/software/S0596/) | malware | 21 |  |
| [Mimikatz](https://attack.mitre.org/software/S0002/) | ferramenta | 17 |  |
| [Winnti for Linux](https://attack.mitre.org/software/S0430/) | malware | 8 |  |
| [NBTscan](https://attack.mitre.org/software/S0590/) | ferramenta | 5 |  |
| [certutil](https://attack.mitre.org/software/S0160/) | ferramenta | 4 |  |
| [Tasklist](https://attack.mitre.org/software/S0057/) | ferramenta | 3 |  |
| [Nltest](https://attack.mitre.org/software/S0359/) | ferramenta | 3 |  |

## 6. Campanhas

Nenhuma campanha atribuída no ATT&CK.

## 7. Cobertura defensiva

**42 de 44 técnicas (95%)** têm ao menos uma regra pública no catálogo Detection Rules.

### Técnicas sem regra pública (prioridade para engenharia de detecção)

- **T1583.004 Server** — Resource Development. Fonte de log sugerida pelo MITRE: `Internet Scan` None
- **T1584.004 Server** — Resource Development. Fonte de log sugerida pelo MITRE: `Internet Scan` None

### Regras recomendadas por técnica

Melhor regra disponível por técnica (formato portável e maduro primeiro).

| Técnica | Regra | Formato | Fonte |
|---|---|---|---|
| T1003.001 | [Antivirus - Password Dumper Signature](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A78cc2dd2-7d20-4d32-93ff-057084c38b93) | Sigma | SigmaHQ |
| T1003.001 | [Mimikatz through Windows Remote Management](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Aaa35a627-33fb-4d04-a165-d33b4afca3e8) | Sigma | OpenSearch Security Analytics |
| T1003.006 | [HackTool - Mimikatz Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aa642964e-bead-4bed-8910-1bb4d63e3b4d) | Sigma | SigmaHQ |
| T1003.006 | [Mimikatz Use](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A06d71506-7beb-4f22-8888-e2e5e2ca7fd8) | Sigma | SigmaHQ |
| T1007 | [HackTool - PCHunter Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Afca949cc-79ca-446e-8064-01aa7e52ece5) | Sigma | SigmaHQ |
| T1007 | [SC.EXE Query Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A57712d7a-679c-4a41-a913-87e7175ae429) | Sigma | SigmaHQ |
| T1016 | [Potential Pikabot Discovery Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A698d4431-514f-4c82-af4d-cf573872a9f5) | Sigma | SigmaHQ |
| T1016 | [OpenCanary - SNMP OID Request](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae9856028-fd4e-46e6-b3d1-10f7ceb95078) | Sigma | SigmaHQ |
| T1018 | [Chopper Webshell Process Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Afa3c117a-bc0d-416e-a31b-0c0e80653efb) | Sigma | SigmaHQ |
| T1018 | [Webshell Hacking Activity Patterns](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4ebc877f-4612-45cb-b3a5-8e3834db36c9) | Sigma | SigmaHQ |
| T1027 | [Potential Emotet Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad02e8cf5-6099-48cf-9bfc-1eec2d0c7b18) | Sigma | SigmaHQ |
| T1027 | [Emotet Process Creation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Ad02e8cf5-6099-48cf-9bfc-1eec2d0c7b18) | Sigma | OpenSearch Security Analytics |
| T1027.003 | [Steganography Hide Files with Steghide](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ace446a9e-30b9-4483-8e38-d2c9ad0a2280) | Sigma | SigmaHQ |
| T1027.003 | [Steganography Unzip Hidden Information From Picture File](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aedd595d7-7895-4fa7-acb3-85a18a8772ca) | Sigma | SigmaHQ |
| T1033 | [Potential Dridex Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae6eb5a96-9e6f-4a18-9cdd-642cfda21c8e) | Sigma | SigmaHQ |
| T1033 | [Dridex Process Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Ae6eb5a96-9e6f-4a18-9cdd-642cfda21c8e) | Sigma | OpenSearch Security Analytics |
| T1036.005 | [Exploit for CVE-2015-1641](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A7993792c-5ce2-4475-a3db-a3a5539827ef) | Sigma | SigmaHQ |
| T1036.005 | [Exploit for CVE-2015-1641](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A7993792c-5ce2-4475-a3db-a3a5539827ef) | Sigma | OpenSearch Security Analytics |
| T1047 | [HackTool - Potential Impacket Lateral Movement Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A10c14723-61c7-4c75-92ca-9af245723ad2) | Sigma | SigmaHQ |
| T1047 | [CrackMapExec Command Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A058f4380-962d-40a5-afce-50207d36d7e2) | Sigma | OpenSearch Security Analytics |
| T1049 | [Potential Pikabot Discovery Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A698d4431-514f-4c82-af4d-cf573872a9f5) | Sigma | SigmaHQ |
| T1049 | [HackTool - SharpView Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab2317cfa-4a47-4ead-b3ff-297438c0bc2d) | Sigma | SigmaHQ |
| T1053.005 | [Operation Wocao Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1cfac73c-be78-4f9a-9b08-5bde0c3953ab) | Sigma | SigmaHQ |
| T1053.005 | [Operation Wocao Activity - Security](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A74ad4314-482e-4c3e-b237-3f7ed3b9ca8d) | Sigma | SigmaHQ |
| T1057 | [Process Discovery](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4e2f5868-08d4-413d-899f-dc2f1508627b) | Sigma | SigmaHQ |
| T1057 | [HackTool - PCHunter Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Afca949cc-79ca-446e-8064-01aa7e52ece5) | Sigma | SigmaHQ |
| T1059.001 | [Potential Emotet Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad02e8cf5-6099-48cf-9bfc-1eec2d0c7b18) | Sigma | SigmaHQ |
| T1059.001 | [TropicTrooper Campaign November 2018](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A8c7090c3-e0a0-4944-bd08-08c3a0cecf79) | Sigma | SigmaHQ |
| T1059.005 | [Potential QBot Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4fcac6eb-0287-4090-8eea-2602e4c20040) | Sigma | SigmaHQ |
| T1059.005 | [QBot Process Creation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A4fcac6eb-0287-4090-8eea-2602e4c20040) | Sigma | OpenSearch Security Analytics |
| T1059.006 | [Emotet Loader Execution Via .LNK File](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1f32d820-1d5c-43fe-8fe2-feef0c952eb7) | Sigma | SigmaHQ |
| T1059.006 | [Serpent Backdoor Payload Execution Via Scheduled Task](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad5eb7432-fda4-4bba-a37f-ffa74d9ed639) | Sigma | SigmaHQ |
| T1059.007 | [Adwind RAT / JRAT](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1fac1481-2dbc-48b2-9096-753c49b4ec71) | Sigma | SigmaHQ |
| T1059.007 | [WScript or CScript Dropper - File](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A002bdb95-0cf1-46a6-9e08-d38c128a6127) | Sigma | SigmaHQ |
| T1090 | [Communication To LocaltoNet Tunneling Service Initiated - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac4568f5d-131f-4e78-83d4-45b2da0ec4f1) | Sigma | SigmaHQ |
| T1090 | [Communication To Ngrok Tunneling Service - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A19bf6fdb-7721-4f3d-867f-53467f6a5db6) | Sigma | SigmaHQ |
| T1098.004 | [Potential Redis CONFIG SET SSH Authorized Key Injection](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A39ab0f66-efa0-4649-9c9c-8c64682f5fdd) | Elastic | Elastic detection-rules |
| T1098.004 | [Suspicious Echo or Printf Execution Detected via Defend for Containers](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ad9bfa475-270d-4b07-93cb-b1f49abe13da) | Elastic | Elastic detection-rules |
| T1112 | [ShimCache Flush](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab0524451-19af-4efa-a46f-562a977f792e) | Sigma | SigmaHQ |
| T1112 | [ShimCache Flush](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Ab0524451-19af-4efa-a46f-562a977f792e) | Sigma | OpenSearch Security Analytics |
| T1140 | [UNC4841 - SSL Certificate Exfiltration Via Openssl](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A60911c07-f989-4362-84af-c609828ef829) | Sigma | SigmaHQ |
| T1140 | [UNC4841 - Download Compressed Files From Temp.sh Using Wget](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A60d050c4-e253-4d9a-b673-5ac100cfddfb) | Sigma | SigmaHQ |
| T1189 | [Flash Player Update from Suspicious Location](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4922a5dd-6743-4fc2-8e81-144374280997) | Sigma | SigmaHQ |
| T1189 | [Cross Site Scripting Strings](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A65354b83-a2ea-4ea6-8414-3ab38be0d409) | Sigma | SigmaHQ |
| T1190 | [OMIGOD HTTP No Authentication RCE - CVE-2021-38647](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aab6b1a39-a9ee-4ab4-b075-e83acf6e346b) | Sigma | SigmaHQ |
| T1190 | [Exploited CVE-2020-10189 Zoho ManageEngine](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A846b866e-2a57-46ee-8e16-85fa92759be7) | Sigma | OpenSearch Security Analytics |
| T1204.001 | [Google Workspace Object Copied from External Drive with App Consent](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Af33e68a4-bd19-11ed-b02f-f661ea17fbcc) | Elastic | Elastic detection-rules |
| T1204.001 | [Suspicious ClickFix/FileFix Execution Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad487ed4a-fd24-436d-a0b2-f4e95f7b2635) | Sigma | SigmaHQ |
| T1204.002 | [Ursnif Malware C2 URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A932ac737-33ca-4afd-9869-0d48b391fcc9) | Sigma | SigmaHQ |
| T1204.002 | [Droppers Exploiting CVE-2017-11882](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A678eb5f4-8597-4be6-8be7-905e4234b53a) | Sigma | SigmaHQ |
| T1210 | [OMIGOD HTTP No Authentication RCE - CVE-2021-38647](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aab6b1a39-a9ee-4ab4-b075-e83acf6e346b) | Sigma | SigmaHQ |
| T1210 | [OMIGOD HTTP No Authentication RCE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Aab6b1a39-a9ee-4ab4-b075-e83acf6e346b) | Sigma | OpenSearch Security Analytics |
| T1218.005 | [Potential Baby Shark Malware Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A2b30fa36-3a18-402f-a22d-bf4ce2189f35) | Sigma | SigmaHQ |
| T1218.005 | [Remotely Hosted HTA File Executed Via Mshta.EXE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab98d0db6-511d-45de-ad02-e82a98729620) | Sigma | SigmaHQ |
| T1482 | [BloodHound Collection Files](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A02773bed-83bf-469f-b7ff-e676e7d78bab) | Sigma | SigmaHQ |
| T1482 | [HackTool - TruffleSnout Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A69ca006d-b9a9-47f5-80ff-ecd4d25d481a) | Sigma | SigmaHQ |
| T1543.003 | [PSExec Lateral Movement](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=hayabusa-native%3A%3A0694c340-3a46-40ac-acfc-c3444ae6572c) | Sigma | Hayabusa (native) |
| T1543.003 | [Suspicious Service Name](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=hayabusa-native%3A%3Acc429813-21db-4019-b520-2f19648e1ef1) | Sigma | Hayabusa (native) |
| T1547.012 | [Potential Port Monitor or Print Processor Registration Abuse](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A8f3e91c7-d791-4704-80a1-42c160d7aa27) | Elastic | Elastic detection-rules |
| T1547.012 | [Printer driver failed to load, possible remote code execution using PrinterNightmare exploit: CVE-2021-34527.](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=wazuh-ruleset-oficial%3A%3Awazuh-92655) | Wazuh | Wazuh ruleset (oficial) |
| T1548.002 | [CMSTP UAC Bypass via COM Object Access](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4b60e6f2-bf39-47b4-b4ea-398e33cfe253) | Sigma | SigmaHQ |
| T1548.002 | [HackTool - Empire PowerShell UAC Bypass](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A3268b746-88d8-4cd3-bffc-30077d02c787) | Sigma | SigmaHQ |
| T1560.001 | [APT31 Judgement Panda Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A03e2746e-2b31-42f1-ab7a-eb39365b2422) | Sigma | SigmaHQ |
| T1560.001 | [Suspicious Manipulation Of Default Accounts Via Net.EXE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A5b768e71-86f2-4879-b448-81061cbae951) | Sigma | SigmaHQ |
| T1566.002 | [Potential Malicious Usage of CloudTrail System Manager](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A38e7f511-3f74-41d4-836e-f57dfa18eead) | Sigma | SigmaHQ |
| T1566.002 | [Google Workspace Device Registration After OAuth from Suspicious ASN](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A012bfca7-45cb-4507-a3ba-3777167f8b81) | Elastic | Elastic detection-rules |
| T1567.002 | [APT40 Dropbox Tool User Agent](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A5ba715b6-71b7-44fd-8245-f66893e81b3d) | Sigma | SigmaHQ |
| T1567.002 | [PUA - Rclone Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae37db05d-d1f9-49c8-b464-cee1a4b11638) | Sigma | SigmaHQ |
| T1574.001 | [Winnti Pipemon Characteristics](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A73d70463-75c9-4258-92c6-17500fe972f2) | Sigma | SigmaHQ |
| T1574.001 | [Winnti Pipemon Characteristics](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A73d70463-75c9-4258-92c6-17500fe972f2) | Sigma | OpenSearch Security Analytics |
| T1583.001 | [AWS Route 53 Private Hosted Zone Associated With a VPC](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ae3c27562-709a-42bd-82f2-3ed926cced19) | Elastic | Elastic detection-rules |
| T1583.001 | [AWS SES Email Identity Verified Then Deleted](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A8e4bde35-125d-4eb3-9a2e-d7e77a053a08) | Elastic | Elastic detection-rules |
| T1583.006 | [GitHub Repo Created](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A6cea88e4-6ce2-4238-9981-a54c140d6336) | Elastic | Elastic detection-rules |
| T1583.006 | [Cisco Secure Firewall - Rare Snort Rule Triggered](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=splunk-security-content%3A%3Ae20313d2-7d63-4fcf-b2d9-d6e12c6c7bd7) | Splunk | Splunk security_content |
| T1584.006 | [Suspicious PowerShell Mailbox Export to Share](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A889719ef-dd62-43df-86c3-768fb08dc7c0) | Sigma | OpenSearch Security Analytics |
| T1588.001 | [Relevant ClamAV Message](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A36aa86ca-fd9d-4456-814e-d3b1b8e1e0bb) | Sigma | SigmaHQ |
| T1588.001 | [Relevant ClamAV Message](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A36aa86ca-fd9d-4456-814e-d3b1b8e1e0bb) | Sigma | OpenSearch Security Analytics |
| T1588.002 | [Hacktool Execution - Imphash](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A24e3e58a-646b-4b50-adef-02ef935b9fc8) | Sigma | SigmaHQ |
| T1588.002 | [Renamed SysInternals DebugView Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acd764533-2e07-40d6-a718-cfeec7f2da7f) | Sigma | SigmaHQ |
| T1595.002 | [DNS Query to External Service Interaction Domains](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aaff715fa-4dd5-497a-8db3-910bea555566) | Sigma | SigmaHQ |
| T1595.002 | [Web Server Potential SQL Injection Request](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A7f7a0ee1-7b6f-466a-85b4-110fb105f5e2) | Elastic | Elastic detection-rules |
| T1608.001 | [M365 OneDrive Malware File Upload](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Abba1b212-b85c-41c6-9b28-be0e5cdfc9b1) | Elastic | Elastic detection-rules |
| T1608.001 | [M365 SharePoint Malware File Detected](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A0e52157a-8e96-4a95-a6e3-5faae5081a74) | Elastic | Elastic detection-rules |

## 8. Plano de emulação e validação

Use num laboratório isolado e autorizado para confirmar que as regras disparam. Os comandos estão nos repositórios oficiais.

| Tática | Técnica | Teste Atomic Red Team | Plataformas |
|---|---|---|---|
| Initial Access | [T1566.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1566.002/T1566.002.md) | Paste and run technique | windows |
| Execution | [T1047](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1047/T1047.md) | WMI Reconnaissance Users | windows |
| Execution | [T1047](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1047/T1047.md) | WMI Reconnaissance Processes | windows |
| Execution | [T1053.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1053.005/T1053.005.md) | Scheduled Task Startup Script | windows |
| Execution | [T1053.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1053.005/T1053.005.md) | Scheduled task Local | windows |
| Execution | [T1059.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md) | Mimikatz | windows |
| Execution | [T1059.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md) | Run BloodHound from local disk | windows |
| Execution | [T1059.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.005/T1059.005.md) | Visual Basic script execution to gather local computer information | windows |
| Execution | [T1059.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.005/T1059.005.md) | Encoded VBS code execution | windows |
| Execution | [T1059.007](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.007/T1059.007.md) | JScript execution to gather local computer information via cscript | windows |
| Execution | [T1059.007](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.007/T1059.007.md) | JScript execution to gather local computer information via wscript | windows |
| Execution | [T1204.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1204.002/T1204.002.md) | OSTap Style Macro Execution | windows |
| Execution | [T1204.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1204.002/T1204.002.md) | OSTap Payload Download | windows |
| Persistence | [T1098.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1098.004/T1098.004.md) | Modify SSH Authorized Keys | linux, macos |
| Persistence | [T1543.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1543.003/T1543.003.md) | Modify Fax service to run PowerShell | windows |
| Persistence | [T1543.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1543.003/T1543.003.md) | Service Installation CMD | windows |
| Persistence | [T1547.012](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1547.012/T1547.012.md) | Print Processors | windows |
| Privilege Escalation | [T1548.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1548.002/T1548.002.md) | Bypass UAC using Event Viewer (cmd) | windows |
| Privilege Escalation | [T1548.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1548.002/T1548.002.md) | Bypass UAC using Event Viewer (PowerShell) | windows |
| Stealth | [T1027](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027/T1027.md) | Decode base64 Data into Script | linux, macos |
| Stealth | [T1027](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027/T1027.md) | Execute base64-encoded PowerShell | windows |
| Stealth | [T1036.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.005/T1036.005.md) | Execute a process from a directory masquerading as the current parent directory | linux, macos |
| Stealth | [T1036.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.005/T1036.005.md) | Masquerade as a built-in system executable | windows |
| Stealth | [T1140](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1140/T1140.md) | Deobfuscate/Decode Files Or Information | windows |
| Stealth | [T1140](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1140/T1140.md) | Certutil Rename and Decode | windows |
| Stealth | [T1218.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.005/T1218.005.md) | Mshta executes JavaScript Scheme Fetch Remote Payload With GetObject | windows |
| Stealth | [T1218.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.005/T1218.005.md) | Mshta executes VBScript to execute malicious command | windows |
| Stealth | [T1574.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1574.001/T1574.001.md) | DLL Search Order Hijacking - amsi.dll | windows |
| Stealth | [T1574.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1574.001/T1574.001.md) | Phantom Dll Hijacking - WinAppXRT.dll | windows |
| Defense Impairment | [T1112](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1112/T1112.md) | Modify Registry of Current User Profile - cmd | windows |
| Defense Impairment | [T1112](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1112/T1112.md) | Modify Registry of Local Machine - cmd | windows |
| Credential Access | [T1003.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/T1003.001.md) | Dump LSASS.exe Memory using ProcDump | windows |
| Credential Access | [T1003.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/T1003.001.md) | Dump LSASS.exe Memory using comsvcs.dll | windows |
| Credential Access | [T1003.006](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.006/T1003.006.md) | DCSync (Active Directory) | windows |
| Credential Access | [T1003.006](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.006/T1003.006.md) | Run DSInternals Get-ADReplAccount | windows |
| Discovery | [T1007](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1007/T1007.md) | System Service Discovery | windows |
| Discovery | [T1007](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1007/T1007.md) | System Service Discovery - net.exe | windows |
| Discovery | [T1016](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1016/T1016.md) | System Network Configuration Discovery on Windows | windows |
| Discovery | [T1016](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1016/T1016.md) | List Windows Firewall Rules | windows |
| Discovery | [T1018](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1018/T1018.md) | Remote System Discovery - net | windows |
| Discovery | [T1018](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1018/T1018.md) | Remote System Discovery - net group Domain Computers | windows |
| Discovery | [T1033](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1033/T1033.md) | System Owner/User Discovery | windows |
| Discovery | [T1033](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1033/T1033.md) | System Owner/User Discovery | linux, macos |
| Discovery | [T1049](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1049/T1049.md) | System Network Connections Discovery | windows |
| Discovery | [T1049](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1049/T1049.md) | System Network Connections Discovery with PowerShell | windows |
| Discovery | [T1057](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1057/T1057.md) | Process Discovery - ps | linux, macos |
| Discovery | [T1057](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1057/T1057.md) | Process Discovery - tasklist | windows |
| Discovery | [T1482](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1482/T1482.md) | Windows - Discover domain trusts with dsquery | windows |
| Discovery | [T1482](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1482/T1482.md) | Windows - Discover domain trusts with nltest | windows |
| Collection | [T1560.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1560.001/T1560.001.md) | Compress Data for Exfiltration With Rar | windows |
| Collection | [T1560.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1560.001/T1560.001.md) | Compress Data and lock with password for Exfiltration with winrar | windows |
| Exfiltration | [T1567.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1567.002/T1567.002.md) | Exfiltrate data with rclone to cloud Storage - Mega (Windows) | windows |
| Exfiltration | [T1567.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1567.002/T1567.002.md) | Exfiltrate data with rclone to cloud Storage - AWS S3 | linux, macos |

**Logs reais de ataque (EVTX) para testar sem executar nada:**

- T1003.001 — [CA_hashdump_4663_4656_lsass_access](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Credential%20Access/CA_hashdump_4663_4656_lsass_access.evtx) _(inferido)_
- T1003.001 — [LsassSilentProcessExit_process_exit_monitor_3001_lsass](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Credential%20Access/LsassSilentProcessExit_process_exit_monitor_3001_lsass.evtx) _(inferido)_
- T1003.006 — [CA_DCSync_4662](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Credential%20Access/CA_DCSync_4662.evtx) _(inferido)_
- T1003.006 — [DACL_DCSync_Right_Powerview_ Add-DomainObjectAcl](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Persistence/DACL_DCSync_Right_Powerview_%20Add-DomainObjectAcl.evtx) _(inferido)_
- T1016 — [ID4688-Audit policy enumerated](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1016-System%20Network%20Configuration%20Discovery/ID4688-Audit%20policy%20enumerated.evtx) _(explícito)_
- T1016 — [ID4688-Firewall configuration enumerated (command)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1016-System%20Network%20Configuration%20Discovery/ID4688-Firewall%20configuration%20enumerated%20%28command%29.evtx) _(explícito)_
- T1018 — [ID5145-DNS hosts files access via network share](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1018-Remote%20System%20Discovery/ID5145-DNS%20hosts%20files%20access%20via%20network%20share.evtx) _(explícito)_
- T1027 — [4624,4674,4688- CrackMap Exec SMB mimikatz](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0005-Defense%20Evasion/T1027-Obfuscated%20Files%20or%20Information/4624%2C4674%2C4688-%20CrackMap%20Exec%20SMB%20mimikatz.evtx) _(explícito)_
- T1027 — [ID1-CrackMapExec payload execution](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0005-Defense%20Evasion/T1027-Obfuscated%20Files%20or%20Information/ID1-CrackMapExec%20payload%20execution.evtx) _(explícito)_
- T1047 — [ID1-WMI spwaning PowerShell process - WMImplant](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1047-Windows%20Management%20Instrumentation/ID1-WMI%20spwaning%20PowerShell%20process%20-%20WMImplant.evtx) _(explícito)_
- T1047 — [ID1-WMIexec process execution](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1047-Windows%20Management%20Instrumentation/ID1-WMIexec%20process%20execution.evtx) _(explícito)_
- T1053.005 — [ID4688-4698 Persistent scheduled task with SYSTEM privileges creation](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1053.005-Scheduled%20Task/ID4688-4698%20Persistent%20scheduled%20task%20with%20SYSTEM%20privileges%20creation.evtx) _(explícito)_
- T1053.005 — [ID4688-Interactive shell using AT schedule task](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1053.005-Scheduled%20Task/ID4688-Interactive%20shell%20using%20AT%20schedule%20task.evtx) _(explícito)_
- T1059.001 — [ID4103-4104-Payload download via PowerShell](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1059.001-PowerShell/ID4103-4104-Payload%20download%20via%20PowerShell.evtx) _(explícito)_
- T1059.001 — [ID4688-Encoded PowerShell MSF payload via process execution](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1059.001-PowerShell/ID4688-Encoded%20PowerShell%20MSF%20payload%20via%20process%20execution.evtx) _(explícito)_
- T1090 — [ID5600-proxy configuration changed](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0011-Command%20and%20Control/T1090-Proxy/ID5600-proxy%20configuration%20changed.evtx) _(explícito)_
- T1112 — [ID11,13-SMBexec service registration](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0005-Defense%20Evasion/T1112-Modify%20registry/ID11%2C13-SMBexec%20service%20registration.evtx) _(explícito)_
- T1112 — [ID4624,4670,4688,4674-Registry permission change via WMI (DAMP)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0005-Defense%20Evasion/T1112-Modify%20registry/ID4624%2C4670%2C4688%2C4674-Registry%20permission%20change%20via%20WMI%20%28DAMP%29.evtx) _(explícito)_
- T1140 — [ID4688-Certutil download](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0005-Defense%20Evasion/T1140-Deobfuscate-Decode%20Files%20or%20Information/ID4688-Certutil%20download.evtx) _(explícito)_
- T1210 — [Zerologon_CVE-2020-1472_DFIR_System_NetLogon_Error_EventID_5805](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Credential%20Access/Zerologon_CVE-2020-1472_DFIR_System_NetLogon_Error_EventID_5805.evtx) _(inferido)_
- T1210 — [Zerologon_VoidSec_CVE-2020-1472_4626_LT3_Anonym_follwedby_4742_DC_Anony_DC](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Credential%20Access/Zerologon_VoidSec_CVE-2020-1472_4626_LT3_Anonym_follwedby_4742_DC_Anony_DC.evtx) _(inferido)_
- T1218.005 — [exec_persist_rundll32_mshta_scheduledtask_sysmon_1_3_11](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Execution/exec_persist_rundll32_mshta_scheduledtask_sysmon_1_3_11.evtx) _(inferido)_
- T1218.005 — [sysmon_mshta_sharpshooter_stageless_meterpreter](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Execution/sysmon_mshta_sharpshooter_stageless_meterpreter.evtx) _(inferido)_
- T1482 — [ID800,4103,4104-Active Directory Forest PowerShell class](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1482-Domain%20Trust%20Discovery/ID800%2C4103%2C4104-Active%20Directory%20Forest%20PowerShell%20class.evtx) _(explícito)_
- T1543.003 — [ID13-New service for Mimikatz](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0003-Persistence/T1543.003-Create%20or%20Modify%20System%20Process-Windows%20Service/ID13-New%20service%20for%20Mimikatz.evtx) _(explícito)_

## 9. Hipóteses de hunting

Se Earth Lusca estiver no seu ambiente, estas são as perguntas a fazer aos seus dados (fontes de log segundo as estratégias de detecção do MITRE ATT&CK).

1. **T1547.012 Print Processors** — Correlated registry modifications under Print Processors path, followed by DLL file creation within the system print processor directory, and DLL load by spoolsv.exe. Malicious execution often occurs during service restart or system boot, with SYSTEM-level… Dados: `WinEventLog:Sysmon` (EventCode=13, 14), `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Sysmon` (EventCode=7).
2. **T1098.004 SSH Authorized Keys** — Adversary attempts to gain persistence by modifying ~/.ssh/authorized_keys via shell, text editor, echo or redirected output. Dados: `auditd:SYSCALL` (write | PATH=/home/*/.ssh/authorized_keys), `auditd:SYSCALL` (execve).
3. **T1584.006 Web Services** — Once adversaries leverage the abused web service as infrastructure (ex: for command and control), it may be possible to look for unique characteristics associated with adversary software, if known. Much of this activity will take place outside the visibility… Dados: `Internet Scan` (None).
4. **T1003.006 DCSync** — Detects unauthorized invocation of replication operations (DCSync) via Directory Replication Service (DRS), often executed by threat actors using Mimikatz or similar tools from non-DC endpoints. Dados: `WinEventLog:Security` (EventCode=4662), `WinEventLog:Security` (EventCode=4929), `NSM:Content` (Traffic on RPC DRSUAPI).
5. **T1583.004 Server** — Much of this activity will take place outside the visibility of the target organization, making detection of this behavior difficult. Detection efforts may be focused on related stages of the adversary lifecycle, such as during Command and Control. Once… Dados: `Internet Scan` (None), `Internet Scan` (None).
6. **T1027.003 Steganography** — Detects execution of image viewers or PowerShell scripts accessing or decoding files with mismatched MIME headers or embedded script-like byte patterns; often correlated with suspicious parent-child process lineage and outbound connections. Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=3, 22), `WinEventLog:Security` (EventCode=4663, 4670, 4656).
7. **T1482 Domain Trust Discovery** — Adversary uses nltest, PowerShell, or Win32/.NET API to enumerate domain trust relationships (via DSEnumerateDomainTrusts, GetAllTrustRelationships, or LDAP queries), followed by discovery or authentication staging. Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=7), `WinEventLog:Sysmon` (EventCode=10).
8. **T1584.004 Server** — Once adversaries have provisioned software on a compromised server (ex: for use as a command and control server), internet scans may reveal servers that adversaries have compromised. Consider looking for identifiable patterns such as services listening,… Dados: `Internet Scan` (None), `Internet Scan` (None).
9. **T1548.002 Bypass User Account Control** — Detects a multi-event behavior chain involving UAC bypass attempts via known auto-elevated binaries (e.g., eventvwr.exe, sdclt.exe), unauthorized Registry changes to UAC-related keys, and anomalous process execution with elevated privileges but lacking… Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:Security` (EventCode=4672), `WinEventLog:Sysmon` (EventCode=13, 14).
10. **T1210 Exploitation of Remote Services** — Correlates inbound network access to remote service ports (e.g., SMB/RPC 445/135, RDP 3389, WinRM 5985/5986) with near-time instability in the target service (crash, abnormal restart), suspicious child process creation under the service, and post-access… Dados: `WinEventLog:System` (EventCode=1000), `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=3, 22).
11. **T1595.002 Vulnerability Scanning** — Monitor and analyze traffic patterns and packet inspection associated to protocol(s) that do not follow the expected protocol standards and traffic flows (e.g extraneous packets that do not belong to established flows, gratuitous or anomalous traffic… Dados: `Network Traffic` (None), `Network Traffic` (None).
12. **T1007 System Service Discovery** — Enumeration of services via native CLI tools (e.g., `sc query`, `tasklist /svc`, `net start`) or API calls via PowerShell and WMI. Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:PowerShell` (EventCode=4103, 4104, 4105, 4106).

## 10. OSINT — onde pesquisar

Consultas prontas com todos os nomes conhecidos do grupo:

- Relatórios técnicos: [busca web](https://duckduckgo.com/?q=%28%22Earth+Lusca%22+OR+%22TAG-22%22+OR+%22Charcoal+Typhoon%22+OR+%22CHROMIUM%22+OR+%22ControlX%22%29+threat+report) · [PDFs](https://duckduckgo.com/?q=%28%22Earth+Lusca%22+OR+%22TAG-22%22+OR+%22Charcoal+Typhoon%22+OR+%22CHROMIUM%22+OR+%22ControlX%22%29+filetype%3Apdf)
- Regras e IOCs publicados: [GitHub](https://github.com/search?type=code&q=%22Earth+Lusca%22+OR+%22TAG-22%22+OR+%22Charcoal+Typhoon%22+OR+%22CHROMIUM%22+OR+%22ControlX%22)
- Pulsos de ameaça: [AlienVault OTX](https://otx.alienvault.com/browse/global/pulses?q=Earth+Lusca)
- Família de malware e atores: [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/actors) (busque por Earth Lusca, TAG-22, Charcoal Typhoon)
- Cartões de grupo: [ThaiCERT Threat Group Cards](https://apt.etda.or.th/cgi-bin/listgroups.cgi)
- Página oficial: [MITRE ATT&CK G1006](https://attack.mitre.org/groups/G1006/)

**Relatórios na coleção CyberMonitor** (ligados pelo nome do grupo, conferir antes de citar):

- 2022 — [technical-brief-delving-deep-an-analysis-of-earth-lusca-operations](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2022/2022.01.17.Earth_Lucsa/technical-brief-delving-deep-an-analysis-of-earth-lusca-operations.pdf) _(via “Earth Lusca”)_
- 2024 — [earth-lusca-uses-geopolitical-lure-to-target-taiwan](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2024/2024.02.26.Earth_Lusca_Uses_Geopolitical_Lure_to_Target_Taiwan_Before_Elections/earth-lusca-uses-geopolitical-lure-to-target-taiwan.pdf) _(via “Earth Lusca”)_

## 11. Bibliografia (4 fontes citadas pelo ATT&CK)

- [Microsoft Threat Actor Naming July 2023](https://learn.microsoft.com/en-us/microsoft-365/security/intelligence/microsoft-threat-actor-naming?view=o365-worldwide) — Microsoft . (2023, July 12). How Microsoft names threat actors. Retrieved November 17, 2023.
- [Recorded Future RedHotel August 2023](https://go.recordedfuture.com/hubfs/reports/cta-2023-0808.pdf) — Insikt Group. (2023, August 8). RedHotel: A Prolific, Chinese State-Sponsored Group Operating at a Global Scale. Retrieved March 11, 2024.
- [Recorded Future TAG-22 July 2021](https://www.recordedfuture.com/research/chinese-group-tag-22-targets-nepal-philippines-taiwan) — INSIKT GROUP. (2021, July 8). Chinese State-Sponsored Activity Group TAG-22 Targets Nepal, the Philippines, and Taiwan Using Winnti and Other Tooling. Retrieved September 16, 2024.
- [TrendMicro EarthLusca 2022](https://www.trendmicro.com/content/dam/trendmicro/global/en/research/22/a/earth-lusca-employs-sophisticated-infrastructure-varied-tools-and-techniques/technical-brief-delving-deep-an-analysis-of-earth-lusca-operations.pdf) — Chen, J., et al. (2022). Delving Deep: An Analysis of Earth Lusca’s Operations. Retrieved July 1, 2022.

## 12. Limites e confiança

- O ATT&CK registra o que foi **relatado publicamente**, não tudo o que o grupo faz. Ausência de uma técnica não prova que o grupo não a usa.
- **Sobreposição de TTP não é atribuição.** Muitas técnicas são compartilhadas entre grupos e com red teams. Use a assinatura comportamental como hipótese, junto com infraestrutura, malware e contexto.
- Cobertura de detecção refere-se ao catálogo público Detection Rules, não ao seu ambiente: confira se a telemetria necessária chega ao seu SIEM.
- Ligações marcadas como _inferidas_ (EVTX por palavra-chave, relatórios por nome) devem ser verificadas.

---
Fontes: MITRE ATT&CK® (uso livre com atribuição, © The MITRE Corporation), Atomic Red Team (Red Canary, MIT), EVTX-to-MITRE-Attack, EVTX-ATTACK-SAMPLES, APT & CyberCriminal Campaign Collections. Gerado por [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules).
