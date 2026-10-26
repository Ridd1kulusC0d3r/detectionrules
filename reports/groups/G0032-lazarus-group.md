# Lazarus Group (G0032) — Dossiê de inteligência

> **TLP:CLEAR** · gerado em 2026-10-26 a partir de fontes abertas · MITRE ATT&CK v20.0 · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0032) · [ATT&CK](https://attack.mitre.org/groups/G0032/)

**Também conhecido como:** Labyrinth Chollima, HIDDEN COBRA, Guardians of Peace, ZINC, NICKEL ACADEMY, Diamond Sleet  
**Origem atribuída:** Coreia do Norte · **Motivação:** espionagem, sabotagem · **Setores-alvo:** Financeiro, Governo, Indústria, Tecnologia  
**Registro no ATT&CK:** criado em 2017-05-31, atualizado em 2026-07-31 · referências de 2016 a 2025

## 1. Sumário executivo

- **93 técnicas** atribuídas publicamente, concentradas em **Stealth, Command and Control, Discovery**.
- **Arsenal:** 22 malware e 4 ferramentas (ex.: Bankshot, Dtrack, BLINDINGCAN, HOPLIGHT, HotCroissant).
- **Campanhas atribuídas:** 1 (Operation Dream Job).
- **Cobertura de detecção pública:** 97% das técnicas têm ao menos uma regra no catálogo; **3 técnicas sem nenhuma regra pública**.
- **Origem e alvos (APT4ALL):** atribuído a **Coreia do Norte**, motivação espionagem, sabotagem; setores Financeiro, Governo, Indústria, Tecnologia.
- **Onde a cobertura está:** Windows (80 técnicas com regra), EDR / XDR (65 técnicas com regra), Linux (61 técnicas com regra), Outros / genérico (59 técnicas com regra).
- **Assinatura comportamental** (técnicas raras entre os 178 grupos, as mais úteis para atribuição): T1574.013 KernelCallbackTable, T1134.002 Create Process with Token, T1202 Indirect Command Execution, T1218 System Binary Proxy Execution, T1557.001 Name Resolution Poisoning and SMB Relay.

## 2. Quem é

> Lazarus Group is a North Korean state-sponsored cyber threat group attributed to the Reconnaissance General Bureau (RGB). Lazarus Group has been active since at least 2009 and is reportedly responsible for the November 2014 destructive wiper attack on Sony Pictures Entertainment, identified by Novetta as part of Operation Blockbuster. Malware used by Lazarus Group correlates to other reported campaigns, including Operation Flame, Operation 1Mission, Operation Troy, DarkSeoul, and Ten Days of Rain.
> 
> North Korea’s cyber operations have shown a consistent pattern of adaptation, forming and reorganizing units as national priorities shift. These units frequently share personnel, infrastructure, malware, and tradecraft, making it difficult to attribute specific operations with high confidence. Public reporting often uses “Lazarus Group” as an umbrella term for multiple North Korean cyber operators conducting espionage, destructive attacks, and financially motivated campaigns.

_Texto original do MITRE ATT&CK, em inglês._

## 3. Contexto, nomes e alvos

Consolidado pelo [APT4ALL](https://github.com/Ridd1kulusC0d3r/apt4all) a partir de MISP Galaxy, planilha APT Groups & Operations, EternalLiberty e APTnotes. Atribuição é afirmação de quem publicou; confira a fonte.

| Campo | Valor |
|---|---|
| Origem atribuída | Coreia do Norte |
| Motivação | espionagem, sabotagem |
| Setores-alvo | Financeiro, Governo, Indústria, Tecnologia |
| Vítimas citadas | — |
| Alvos (planilha) | Believed to be responsible for Dark Seoul, Ten Days of Rain, the Sony Pictures Entertainment attack, the SWIFT-related bank heists, and WannaCry. Known to the U.S. government as Hidden Cobra. Targeting also BitCoin Exchanges, financial sector, technology/engineering sector |
| Operações conhecidas | Troy, Blockbuster, Dark Seoul, Applejeus, Inception, NorthStar, Dream Job, KuCoin Hack, ThreatNeedle |
| Confiança de atribuição (MISP) | — |

**Como cada fornecedor chama este grupo** (útil para cruzar relatórios):

| Fornecedor | Nome(s) |
|---|---|
| Cisco Talos | Group 77 |
| CrowdStrike | Labyrinth Chollima |
| MITRE ATT&CK | G0032 |
| Microsoft | Diamond Sleet, ZINC (antigo · old) |
| Secureworks | Hastati Group |

**Outros nomes no APT4ALL (não listados pelo ATT&CK):** Group 77, Hastati Group, Bureau 121, BeagleBoyzBureau121, BeagleBoyz, Unit 121, Whois Hacking Team, WHOis Team, NewRomanic Cyber Army Team, APT-C-26, UNC2970, UNC577, UNC4736, Appleworm, NICKEL GLADSTONE, COVELLITE, ATK3, Black Artemis, LolZarus

## 4. Perfil TTP por tática (kill chain)

Cada linha: técnica, como o grupo a usou segundo relatos públicos, e o que existe para detectar e testar.

### Reconnaissance (TA0043) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1589.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1589.002) Email Addresses | Lazarus Group collected email addresses belonging to various departments of a targeted organization which were used in follow-on phishing campaigns. | 5 | — | — |
| [T1591](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1591) Gather Victim Org Information | Lazarus Group has studied publicly available information about a targeted organization to tailor spearphishing efforts against specific departments and/or individuals. | 2 | — | — |

### Resource Development (TA0042) — 8

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1583.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1583.001) Domains | Lazarus Group has acquired domains related to their campaigns to act as distribution points and C2 channels. | 7 | — | — |
| [T1583.006](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1583.006) Web Services | Lazarus Group has hosted malicious downloads on Github. | 2 | — | — |
| [T1584.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1584.004) Server | Lazarus Group has compromised servers to stage malicious tools. | **0** | — | — |
| [T1585.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1585.001) Social Media Accounts | Lazarus Group has created new Twitter accounts to conduct social engineering against potential victims. | 4 | — | — |
| [T1585.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1585.002) Email Accounts | Lazarus Group has created new email accounts for spearphishing operations. | **0** | — | — |
| [T1587.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1587.001) Malware | Lazarus Group has developed custom malware for use in their operations. | 43 | — | — |
| [T1588.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1588.002) Tool | Lazarus Group has obtained a variety of tools for their operations, including Responder and PuTTy PSCP. | 35 | — | — |
| [T1588.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1588.004) Digital Certificates | Lazarus Group has obtained SSL certificates for their C2 domains. | 1 | — | — |

### Initial Access (TA0001) — 5

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | Lazarus Group has used administrator credentials to gain access to restricted network segments. | 825 | — | 3 |
| [T1189](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1189) Drive-by Compromise | Lazarus Group delivered RATANKBA and other malicious code to victims via a compromised legitimate website. | 57 | — | — |
| [T1566.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1566.001) Spearphishing Attachment | Lazarus Group has targeted victims with spearphishing emails containing malicious Microsoft Word documents. | 230 | 2 | — |
| [T1566.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1566.002) Spearphishing Link | Lazarus Group has sent malicious links to victims via email. | 138 | 1 | — |
| [T1566.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1566.003) Spearphishing via Service | Lazarus Group has used social media platforms, including LinkedIn and Twitter, to send spearphishing messages. | 8 | — | — |

### Execution (TA0002) — 10

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1047](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1047) Windows Management Instrumentation | Lazarus Group has used WMIC for discovery as well as to execute payloads for persistence and lateral movement. | 370 | 12 | 11 |
| [T1053.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1053.005) Scheduled Task | Lazarus Group has used schtasks for persistence including through the periodic execution of a remote XSL script or a dropped VBS payload. | 248 | 14 | 11 |
| [T1059.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.001) PowerShell | Lazarus Group has used PowerShell to execute commands and malicious code. | 1340 | 22 | 15 |
| [T1059.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.003) Windows Command Shell | Lazarus Group malware uses cmd.exe to execute commands on a compromised host. A Destover-like variant used by Lazarus Group uses a batch file mechanism to delete its binaries from the system. | 269 | 6 | 1 |
| [T1059.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.005) Visual Basic | Lazarus Group has used VBA and embedded macros in Word documents to execute malicious code. | 192 | 3 | — |
| [T1106](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1106) Native API | Lazarus Group has used the Windows API ObtainUserAgentString to obtain the User-Agent from a compromised host to connect to a C2 server. Lazarus Group has also used various, often lesser known, functions to perform various types of Discovery and Process Inject… | 118 | 5 | — |
| [T1203](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1203) Exploitation for Client Execution | Lazarus Group has exploited Adobe Flash vulnerability CVE-2018-4878 for execution. | 202 | — | — |
| [T1204.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1204.002) Malicious File | Lazarus Group has attempted to get users to launch a malicious Microsoft Word attachment delivered via a spearphishing email. | 259 | 13 | — |
| [T1574.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1574.001) DLL | Lazarus Group has replaced `win_fw.dll`, an internal component that is executed during IDA Pro installation, with a malicious DLL to download and execute a payload. Lazarus Group utilized DLL side-loading to execute malicious payloads through abuse of the legi… | 455 | 7 | 5 |
| [T1574.013](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1574.013) KernelCallbackTable | Lazarus Group has abused the KernelCallbackTable to hijack process control flow and execute shellcode. | 2 | — | — |

### Persistence (TA0003) — 7

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1053.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1053.005) Scheduled Task | Lazarus Group has used schtasks for persistence including through the periodic execution of a remote XSL script or a dropped VBS payload. | 248 | 14 | 11 |
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | Lazarus Group has used administrator credentials to gain access to restricted network segments. | 825 | — | 3 |
| [T1098](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1098) Account Manipulation | Lazarus Group malware WhiskeyDelta-Two contains a function that attempts to rename the administrator’s account. | 535 | 17 | 30 |
| [T1542.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1542.003) Bootkit | Lazarus Group malware WhiskeyAlfa-Three modifies sector 0 of the Master Boot Record (MBR) to ensure that the malware will persist even if a victim machine shuts down. | 9 | — | — |
| [T1543.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1543.003) Windows Service | Several Lazarus Group malware families install themselves as new services. | 1916 | 6 | 19 |
| [T1547.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1547.001) Registry Run Keys / Startup Folder | Lazarus Group has maintained persistence by loading malicious code into a startup folder or by adding a Registry Run key. | 299 | 21 | 2 |
| [T1547.009](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1547.009) Shortcut Modification | Lazarus Group malware has maintained persistence on a system by creating a LNK shortcut in the user’s Startup folder. | 28 | 2 | — |

### Privilege Escalation (TA0004) — 8

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1053.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1053.005) Scheduled Task | Lazarus Group has used schtasks for persistence including through the periodic execution of a remote XSL script or a dropped VBS payload. | 248 | 14 | 11 |
| [T1055.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1055.001) Dynamic-link Library Injection | A Lazarus Group malware sample performs reflective DLL injection. | 40 | 2 | — |
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | Lazarus Group has used administrator credentials to gain access to restricted network segments. | 825 | — | 3 |
| [T1098](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1098) Account Manipulation | Lazarus Group malware WhiskeyDelta-Two contains a function that attempts to rename the administrator’s account. | 535 | 17 | 30 |
| [T1134.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1134.002) Create Process with Token | Lazarus Group keylogger KiloAlfa obtains user tokens from interactive sessions to execute itself with API call CreateProcessAsUserA under that user's context. | 60 | 2 | — |
| [T1543.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1543.003) Windows Service | Several Lazarus Group malware families install themselves as new services. | 1916 | 6 | 19 |
| [T1547.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1547.001) Registry Run Keys / Startup Folder | Lazarus Group has maintained persistence by loading malicious code into a startup folder or by adding a Registry Run key. | 299 | 21 | 2 |
| [T1547.009](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1547.009) Shortcut Modification | Lazarus Group malware has maintained persistence on a system by creating a LNK shortcut in the user’s Startup folder. | 28 | 2 | — |

### Stealth (TA0005) — 23

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1027.007](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1027.007) Dynamic API Resolution | Lazarus Group has used a custom hashing method to resolve APIs used in shellcode. | 2 | 1 | — |
| [T1027.009](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1027.009) Embedded Payloads | Lazarus Group has distributed malicious payloads embedded in PNG files. | 4 | — | — |
| [T1027.013](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1027.013) Encrypted/Encoded File | Lazarus Group has used multiple types of encryption and encoding for their payloads, including AES, Caracachs, RC4, XOR, Base64, and other tricks such as creating aliases in code for Native API function names. | 8 | 4 | — |
| [T1036.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1036.003) Rename Legitimate Utilities | Lazarus Group has renamed system utilities such as wscript.exe and mshta.exe. | 165 | 8 | — |
| [T1036.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1036.004) Masquerade Task or Service | Lazarus Group has used a scheduled task named `SRCheck` to mask the execution of a malicious .dll. | 31 | 4 | — |
| [T1036.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1036.005) Match Legitimate Resource Name or Location | Lazarus Group has renamed malicious code to disguise it as Microsoft's narrator and other legitimate files. | 116 | 4 | — |
| [T1055.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1055.001) Dynamic-link Library Injection | A Lazarus Group malware sample performs reflective DLL injection. | 40 | 2 | — |
| [T1070](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1070) Indicator Removal | Lazarus Group has restored malicious KernelCallbackTable code to its original state after the process execution flow has been hijacked. | 263 | 2 | — |
| [T1070.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1070.003) Clear Command History | Lazarus Group has routinely deleted log files on a compromised router, including automatic log deletion through the use of the logrotate utility. | 63 | 14 | — |
| [T1070.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1070.004) File Deletion | Lazarus Group malware has deleted files in various ways, including "suicide scripts" to delete malware binaries from the victim. Lazarus Group also uses secure file deletion to delete files from the victim. | 132 | 11 | — |
| [T1070.006](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1070.006) Timestomp | Several Lazarus Group malware families use timestomping, including modifying the last write timestamp of a specified Registry key to a random date, as well as copying the timestamp for legitimate .exe files (such as calc.exe or mspaint.exe) to its dropped file… | 28 | 10 | 3 |
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | Lazarus Group has used administrator credentials to gain access to restricted network segments. | 825 | — | 3 |
| [T1134.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1134.002) Create Process with Token | Lazarus Group keylogger KiloAlfa obtains user tokens from interactive sessions to execute itself with API call CreateProcessAsUserA under that user's context. | 60 | 2 | — |
| [T1140](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1140) Deobfuscate/Decode Files or Information | Lazarus Group has used shellcode within macros to decrypt and manually map DLLs and shellcode into memory at runtime. | 173 | 11 | 1 |
| [T1202](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1202) Indirect Command Execution | Lazarus Group persistence mechanisms have used forfiles.exe to execute .htm files. | 221 | 5 | 1 |
| [T1218](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1218) System Binary Proxy Execution | Lazarus Group lnk files used for persistence have abused the Windows Update Client (wuauclt.exe) to execute a malicious DLL. | 920 | 16 | — |
| [T1218.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1218.005) Mshta | Lazarus Group has used mshta.exe to execute HTML pages downloaded by initial access documents. | 130 | 10 | 4 |
| [T1218.011](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1218.011) Rundll32 | Lazarus Group has used rundll32 to execute malicious payloads on a compromised host. | 274 | 16 | 12 |
| [T1542.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1542.003) Bootkit | Lazarus Group malware WhiskeyAlfa-Three modifies sector 0 of the Master Boot Record (MBR) to ensure that the malware will persist even if a victim machine shuts down. | 9 | — | — |
| [T1564.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1564.001) Hidden Files and Directories | Lazarus Group has used a VBA Macro to set its file attributes to System and Hidden and has named files with a dot prefix to hide them from the Finder application. | 76 | 10 | — |
| [T1574.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1574.001) DLL | Lazarus Group has replaced `win_fw.dll`, an internal component that is executed during IDA Pro installation, with a malicious DLL to download and execute a payload. Lazarus Group utilized DLL side-loading to execute malicious payloads through abuse of the legi… | 455 | 7 | 5 |
| [T1574.013](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1574.013) KernelCallbackTable | Lazarus Group has abused the KernelCallbackTable to hijack process control flow and execute shellcode. | 2 | — | — |
| [T1620](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1620) Reflective Code Loading | Lazarus Group has changed memory protection permissions then overwritten in memory DLL function code with shellcode, which was later executed via KernelCallbackTable hijacking. Lazarus Group has also used shellcode within macros to decrypt and manually map DLL… | 54 | 3 | — |

### Defense Impairment (TA0112) — 3

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1553.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1553.002) Code Signing | Lazarus Group has digitally signed malware and utilities to evade detection. | 11 | — | — |
| [T1685](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1685) Disable or Modify Tools | Lazarus Group malware TangoDelta attempts to terminate various processes associated with McAfee. Additionally, Lazarus Group malware SHARPKNOT disables the Microsoft Windows System Event Notification and Alerter services.. | 1275 | 78 | 19 |
| [T1686.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1686.003) Windows Host Firewall | Various Lazarus Group malware modifies the Windows firewall to allow incoming connections or disable it entirely using netsh. | 64 | 2 | — |

### Credential Access (TA0006) — 3

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1056.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1056.001) Keylogging | Lazarus Group malware KiloAlfa contains keylogging functionality. | 40 | 8 | 1 |
| [T1110.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1110.003) Password Spraying | Lazarus Group malware attempts to connect to Windows shares for lateral movement by using a generated list of usernames, which center around permutations of the username Administrator, and weak passwords. | 62 | 9 | 1 |
| [T1557.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1557.001) Name Resolution Poisoning and SMB Relay | Lazarus Group executed Responder using the command [Responder file path] -i [IP address] -rPv on a compromised host to harvest credentials and move laterally. | 68 | 1 | — |

### Discovery (TA0007) — 11

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1010](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1010) Application Window Discovery | Lazarus Group malware IndiaIndia obtains and sends to its C2 server the title of the window for each running process. The KilaAlfa keylogger also reports the title of the window in the foreground. | 6 | 1 | — |
| [T1012](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1012) Query Registry | Lazarus Group malware IndiaIndia checks Registry keys within HKCU and HKLM to determine if certain applications are present, including SecureCRT, Terminal Services, RealVNC, TightVNC, UltraVNC, Radmin, mRemote, TeamViewer, FileZilla, pcAnyware, and Remote Desk… | 92 | 6 | — |
| [T1016](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1016) System Network Configuration Discovery | Lazarus Group malware IndiaIndia obtains and sends to its C2 server information about the first network interface card’s configuration, including IP address, gateways, subnet mask, DHCP information, and whether WINS is available. | 99 | 10 | 5 |
| [T1033](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1033) System Owner/User Discovery | Various Lazarus Group malware enumerates logged-on users. | 181 | 8 | — |
| [T1046](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1046) Network Service Discovery | Lazarus Group has used nmap from a router VM to scan ports on systems within the restricted segment of an enterprise network. | 212 | 13 | 2 |
| [T1049](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1049) System Network Connections Discovery | Lazarus Group has used net use to identify and establish a network connection with a remote host. | 47 | 7 | — |
| [T1057](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1057) Process Discovery | Several Lazarus Group malware families gather a list of running processes on a victim system and send it to their C2 server. A Destover-like variant used by Lazarus Group also gathers process times. | 82 | 10 | — |
| [T1082](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1082) System Information Discovery | Several Lazarus Group malware families collect information on the type and version of the victim OS, as well as the victim computer name and CPU information. | 264 | 41 | — |
| [T1083](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1083) File and Directory Discovery | Lazarus Group malware can use a common function to identify target files by their extension, and some also enumerate files and directories, including a Destover-like variant that lists files and gathers information for all drives. | 137 | 9 | — |
| [T1124](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1124) System Time Discovery | A Destover-like implant used by Lazarus Group can obtain the current system time and send it to the C2 server. | 18 | 6 | — |
| [T1680](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1680) Local Storage Discovery | A Destover-like variant used by Lazarus Group collects disk space information and sends it to its C2 server. | **0** | — | — |

### Lateral Movement (TA0008) — 3

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1021.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1021.001) Remote Desktop Protocol | Lazarus Group malware SierraCharlie uses RDP for propagation. | 139 | 4 | 7 |
| [T1021.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1021.002) SMB/Windows Admin Shares | Lazarus Group malware SierraAlfa accesses the ADMIN$ share via SMB to conduct lateral movement. | 272 | 4 | 20 |
| [T1021.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1021.004) SSH | Lazarus Group used SSH and the PuTTy PSCP utility to gain access to a restricted segment of a compromised network. | 60 | 2 | 3 |

### Collection (TA0009) — 7

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1005) Data from Local System | Lazarus Group has collected data and files from compromised networks. | 170 | 3 | — |
| [T1056.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1056.001) Keylogging | Lazarus Group malware KiloAlfa contains keylogging functionality. | 40 | 8 | 1 |
| [T1074.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1074.001) Local Data Staging | Lazarus Group malware IndiaIndia saves information gathered about the victim to a file that is saved in the %TEMP% directory, then compressed, encrypted, and uploaded to a C2 server. | 37 | 3 | — |
| [T1557.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1557.001) Name Resolution Poisoning and SMB Relay | Lazarus Group executed Responder using the command [Responder file path] -i [IP address] -rPv on a compromised host to harvest credentials and move laterally. | 68 | 1 | — |
| [T1560](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1560) Archive Collected Data | Lazarus Group has compressed exfiltrated data with RAR and used RomeoDelta malware to archive specified directories in .zip format, encrypt the .zip file, and upload it to C2. | 53 | 1 | — |
| [T1560.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1560.002) Archive via Library | Lazarus Group malware IndiaIndia saves information gathered about the victim to a file that is compressed with Zlib, encrypted, and uploaded to a C2 server. | 6 | 4 | — |
| [T1560.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1560.003) Archive via Custom Method | A Lazarus Group malware sample encrypts data using a simple byte based XOR operation prior to exfiltration. | 1 | — | — |

### Command and Control (TA0011) — 11

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1001.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1001.003) Protocol or Service Impersonation | Lazarus Group malware also uses a unique form of communication encryption known as FakeTLS that mimics TLS but uses a different encryption method, potentially evading SSL traffic inspection/decryption. | 7 | — | — |
| [T1008](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1008) Fallback Channels | Lazarus Group malware SierraAlfa sends data to one of the hard-coded C2 servers chosen at random, and if the transmission fails, chooses a new C2 server to attempt the transmission again. | 55 | — | — |
| [T1071.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1071.001) Web Protocols | Lazarus Group has conducted C2 over HTTP and HTTPS. | 228 | 3 | — |
| [T1090.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1090.001) Internal Proxy | Lazarus Group has used a compromised router to serve as a proxy between a victim network's corporate and restricted segments. | 43 | 3 | — |
| [T1090.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1090.002) External Proxy | Lazarus Group has used multiple proxies to obfuscate network traffic from victims. | 18 | — | — |
| [T1102.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1102.002) Bidirectional Communication | Lazarus Group has used GitHub as C2, pulling hosted image payloads then committing command execution output to files in specific directories. | 27 | — | — |
| [T1104](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1104) Multi-Stage Channels | Lazarus Group has used multi-stage malware components that inject later stages into separate processes. | 1 | — | — |
| [T1105](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1105) Ingress Tool Transfer | Lazarus Group has downloaded files, malware, and tools from its C2 onto a compromised host. | 644 | 39 | — |
| [T1132.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1132.001) Standard Encoding | A Lazarus Group malware sample encodes data with base64. | 26 | 3 | — |
| [T1571](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1571) Non-Standard Port | Some Lazarus Group malware uses a list of ordered port numbers to choose a port for C2 traffic, creating port-protocol mismatches. | 163 | 2 | — |
| [T1573.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1573.001) Symmetric Cryptography | Several Lazarus Group malware families encrypt C2 traffic using custom code that uses XOR with an ADD operation and XOR with a SUB operation. Another Lazarus Group malware sample XORs C2 traffic. Other Lazarus Group malware uses Caracachs encryption to encrypt… | 5 | — | — |

### Exfiltration (TA0010) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1041](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1041) Exfiltration Over C2 Channel | Lazarus Group has exfiltrated data and files over a C2 channel through its various tools and malware. | 135 | 2 | — |
| [T1048.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1048.003) Exfiltration Over Unencrypted Non-C2 Protocol | Lazarus Group malware SierraBravo-Two generates an email message via SMTP containing information about newly infected victims. | 51 | 8 | — |

### Impact (TA0040) — 6

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1485](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1485) Data Destruction | Lazarus Group has used a custom secure delete function to overwrite file contents with data from heap memory. | 215 | 5 | — |
| [T1489](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1489) Service Stop | Lazarus Group has stopped the MSExchangeIS service to render Exchange contents inaccessible to users. | 112 | 9 | — |
| [T1491.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1491.001) Internal Defacement | Lazarus Group replaced the background wallpaper of systems with a threatening image after rendering the system unbootable with a Disk Structure Wipe. | 18 | 4 | — |
| [T1529](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1529) System Shutdown/Reboot | Lazarus Group has rebooted systems after destroying files and wiping the MBR on infected systems. | 52 | 16 | — |
| [T1561.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1561.001) Disk Content Wipe | Lazarus Group has used malware like WhiskeyAlfa to overwrite the first 64MB of every drive with a mix of static and random buffers. A similar process is then used to wipe content in logical drives and, finally, attempt to wipe every byte of every sector on eve… | 6 | — | — |
| [T1561.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1561.002) Disk Structure Wipe | Lazarus Group malware SHARPKNOT overwrites and deletes the Master Boot Record (MBR) on the victim's machine and has possessed MBR wiper malware since at least 2009. | 2 | — | — |

## 5. Assinatura comportamental

Técnicas que este grupo usa e que poucos dos 178 grupos do ATT&CK usam. Pesam mais numa atribuição por TTP: ver várias delas juntas é mais informativo do que ver técnicas comuns como PowerShell.

| Técnica | Outros grupos que usam | Peso (raridade) |
|---|---:|---:|
| T1574.013 KernelCallbackTable | 0 | 4.49 |
| T1134.002 Create Process with Token | 1 | 4.09 |
| T1202 Indirect Command Execution | 1 | 4.09 |
| T1218 System Binary Proxy Execution | 1 | 4.09 |
| T1557.001 Name Resolution Poisoning and SMB Relay | 1 | 4.09 |
| T1001.003 Protocol or Service Impersonation | 2 | 3.80 |
| T1010 Application Window Discovery | 2 | 3.80 |
| T1027.007 Dynamic API Resolution | 2 | 3.80 |
| T1027.009 Embedded Payloads | 2 | 3.80 |
| T1542.003 Bootkit | 2 | 3.80 |

## 6. Arsenal

| Software | Tipo | Técnicas no ATT&CK | Uso relatado (EN) |
|---|---|---:|---|
| [Bankshot](https://attack.mitre.org/software/S0239/) | malware | 25 |  |
| [Dtrack](https://attack.mitre.org/software/S0567/) | malware | 23 |  |
| [BLINDINGCAN](https://attack.mitre.org/software/S0520/) | malware | 22 |  |
| [HOPLIGHT](https://attack.mitre.org/software/S0376/) | malware | 21 |  |
| [HotCroissant](https://attack.mitre.org/software/S0431/) | malware | 20 |  |
| [AppleJeus](https://attack.mitre.org/software/S0584/) | malware | 20 |  |
| [Volgmer](https://attack.mitre.org/software/S0180/) | malware | 19 |  |
| [WannaCry](https://attack.mitre.org/software/S0366/) | malware | 16 |  |
| [TAINTEDSCRIBE](https://attack.mitre.org/software/S0586/) | malware | 16 |  |
| [Proxysvc](https://attack.mitre.org/software/S0238/) | malware | 15 |  |
| [TYPEFRAME](https://attack.mitre.org/software/S0263/) | malware | 15 |  |
| [RATANKBA](https://attack.mitre.org/software/S0241/) | malware | 15 |  |
| [ThreatNeedle](https://attack.mitre.org/software/S0665/) | malware | 14 |  |
| [MagicRAT](https://attack.mitre.org/software/S1182/) | malware | 13 | MagicRAT is exclusively associated with Lazarus Group operations in 2022. |
| [KEYMARBLE](https://attack.mitre.org/software/S0271/) | malware | 11 |  |
| [AuditCred](https://attack.mitre.org/software/S0347/) | malware | 9 |  |
| [Dacls](https://attack.mitre.org/software/S0497/) | malware | 9 |  |
| [FALLCHILL](https://attack.mitre.org/software/S0181/) | malware | 9 |  |
| [BADCALL](https://attack.mitre.org/software/S0245/) | malware | 8 |  |
| [Cryptoistic](https://attack.mitre.org/software/S0498/) | malware | 7 |  |
| [ECCENTRICBANDWAGON](https://attack.mitre.org/software/S0593/) | malware | 6 |  |
| [HARDRAIN](https://attack.mitre.org/software/S0246/) | malware | 5 |  |
| [netsh](https://attack.mitre.org/software/S0108/) | ferramenta | 4 |  |
| [RawDisk](https://attack.mitre.org/software/S0364/) | ferramenta | 3 |  |
| [Responder](https://attack.mitre.org/software/S0174/) | ferramenta | 2 |  |
| [route](https://attack.mitre.org/software/S0103/) | ferramenta | 1 |  |

**Outras ferramentas e malware relatados (planilha APT Groups & Operations / MISP):** Tdrop, Tdrop2, Troy, Destover, FallChill RAT, Hawup, Manuscrypt, WolfRAT, SheepRAT, HtDnDownLoader, Whois Wiper

## 7. Campanhas

| Campanha | Período | Resumo (EN) |
|---|---|---|
| [Operation Dream Job](https://attack.mitre.org/campaigns/C0022/) | 2019-09 → 2020-08 | Operation Dream Job was a cyber espionage operation likely conducted by Lazarus Group that targeted the defense, aerospace, government, and other sectors in the United States, Israel, Australia, Russia, and India. In at  |

## 8. Cobertura defensiva

**90 de 93 técnicas (97%)** têm ao menos uma regra pública no catálogo Detection Rules.

### Técnicas sem regra pública (prioridade para engenharia de detecção)

- **T1584.004 Server** — Resource Development. Fonte de log sugerida pelo MITRE: `Internet Scan` None
- **T1680 Local Storage Discovery** — Discovery. Fonte de log sugerida pelo MITRE: `WinEventLog:Sysmon` EventCode=1; `auditd:SYSCALL` execve call with argv matching known disk enumeration commands (lsblk, parted, fdisk); `macos:unifiedlog` process launch of diskutil or system_profil
- **T1585.002 Email Accounts** — Resource Development

### Onde procurar — cobertura por tecnologia

Quantas técnicas deste grupo têm ao menos uma regra em cada tecnologia. Comece a caça pelas tecnologias que você tem e que aparecem aqui.

| Tecnologia | Técnicas do grupo com regra |
|---|---:|
| Windows | 80 |
| EDR / XDR | 65 |
| Linux | 61 |
| Outros / genérico | 59 |
| macOS | 51 |
| Servidores web & aplicações | 46 |
| Firewall & perímetro | 42 |
| DNS | 39 |
| Proxy / SWG | 39 |
| AWS | 35 |
| IDS / NSM / NDR | 35 |
| Microsoft 365 | 34 |

### Regras recomendadas por técnica

Melhor regra disponível por técnica (formato portável e maduro primeiro).

| Técnica | Regra | Formato | Fonte |
|---|---|---|---|
| T1001.003 | [DNSCat2 Powershell Implementation Detection Via Process Creation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Ab11d75d6-d7c1-11ea-87d0-0242ac130003) | Sigma | OpenSearch Security Analytics |
| T1001.003 | [Sigma: Suspicious LDAP-Attributes Used](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=evtx-wazuh-rules-saifbelaarbi%3A%3Awazuh-110011) | Wazuh | EVTX-Wazuh-Rules (saifbelaarbi) |
| T1005 | [Potential Conti Ransomware Database Dumping Activity Via SQLCmd](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A2f47f1fd-0901-466e-a770-3b7092834a1b) | Sigma | SigmaHQ |
| T1005 | [OpenCanary - SMB File Open Request](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A22777c9e-873a-4b49-855f-6072ab861a52) | Sigma | SigmaHQ |
| T1008 | [Suspicious Outlook Macro Created](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A117d3d3a-755c-4a61-b23e-9171146d094c) | Sigma | SigmaHQ |
| T1008 | [Outlook Macro Execution Without Warning Setting Enabled](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae3b50fa5-3c3f-444e-937b-0a99d33731cd) | Sigma | SigmaHQ |
| T1010 | [SCM Database Handle Failure](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A13addce7-47b2-4ca0-a98f-1de964d1d669) | Sigma | SigmaHQ |
| T1010 | [SCM Database Handle Failure](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A13addce7-47b2-4ca0-a98f-1de964d1d669) | Sigma | OpenSearch Security Analytics |
| T1012 | [Potential Baby Shark Malware Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A2b30fa36-3a18-402f-a22d-bf4ce2189f35) | Sigma | SigmaHQ |
| T1012 | [Operation Wocao Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1cfac73c-be78-4f9a-9b08-5bde0c3953ab) | Sigma | SigmaHQ |
| T1016 | [Potential Pikabot Discovery Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A698d4431-514f-4c82-af4d-cf573872a9f5) | Sigma | SigmaHQ |
| T1016 | [OpenCanary - SNMP OID Request](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae9856028-fd4e-46e6-b3d1-10f7ceb95078) | Sigma | SigmaHQ |
| T1021.001 | [Hermetic Wiper TG Process Patterns](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A2f974656-6d83-4059-bbdf-68ac5403422f) | Sigma | SigmaHQ |
| T1021.001 | [Publicly Accessible RDP Service](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1fc0809e-06bf-4de3-ad52-25e5263b7623) | Sigma | SigmaHQ |
| T1021.002 | [PSExec Lateral Movement](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=hayabusa-native%3A%3A0694c340-3a46-40ac-acfc-c3444ae6572c) | Sigma | Hayabusa (native) |
| T1021.002 | [Turla Group Lateral Movement](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac601f20d-570a-4cde-a7d6-e17f99cb8e7f) | Sigma | SigmaHQ |
| T1021.004 | [Potential THC Tool Downloaded](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A2ddc468e-b39b-4f5b-9825-f3dcb0e998ea) | Elastic | Elastic detection-rules |
| T1021.004 | [AWS EC2 CreateKeyPair by New Principal from Non-Cloud AS Organization](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ac8e4f1a2-9b3d-4c5e-a6f7-8b9c0d1e2f3a) | Elastic | Elastic detection-rules |
| T1027.007 | [Sysmon - Event 1: Process creation $(win.eventdata.description)](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=socfortress-wazuh-rules%3A%3Awazuh-101142) | Wazuh | SOCFortress Wazuh-Rules |
| T1027.007 | [Sysmon - Event 7: Image loaded by $(win.eventdata.image)](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=socfortress-wazuh-rules%3A%3Awazuh-106131) | Wazuh | SOCFortress Wazuh-Rules |
| T1027.009 | [Powershell Token Obfuscation - Process Creation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Adeb9b646-a508-44ee-b7c9-d8965921c6b6) | Sigma | SigmaHQ |
| T1027.009 | [Powershell Token Obfuscation - Powershell](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Af3a98ce4-6164-4dd4-867c-4d83de7eca51) | Sigma | SigmaHQ |
| T1027.013 | [ROT Encoded Python Script Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A5ab49127-b1b3-46e6-8a38-9e8512a2a363) | Elastic | Elastic detection-rules |
| T1027.013 | [Data Encrypted via OpenSSL Utility](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Afeba48f6-40ca-4d04-b41f-5dfa327de865) | Elastic | Elastic detection-rules |
| T1033 | [Potential Dridex Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae6eb5a96-9e6f-4a18-9cdd-642cfda21c8e) | Sigma | SigmaHQ |
| T1033 | [Dridex Process Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Ae6eb5a96-9e6f-4a18-9cdd-642cfda21c8e) | Sigma | OpenSearch Security Analytics |
| T1036.003 | [Ps.exe Renamed SysInternals Tool](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A18da1007-3f26-470f-875d-f77faf1cab31) | Sigma | SigmaHQ |
| T1036.003 | [Renamed ProcDump Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4a0b2c7e-7cb2-495d-8b63-5f268e7bfd67) | Sigma | SigmaHQ |
| T1036.004 | [Operation Wocao Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1cfac73c-be78-4f9a-9b08-5bde0c3953ab) | Sigma | SigmaHQ |
| T1036.004 | [Operation Wocao Activity - Security](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A74ad4314-482e-4c3e-b237-3f7ed3b9ca8d) | Sigma | SigmaHQ |
| T1036.005 | [Exploit for CVE-2015-1641](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A7993792c-5ce2-4475-a3db-a3a5539827ef) | Sigma | SigmaHQ |
| T1036.005 | [Exploit for CVE-2015-1641](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A7993792c-5ce2-4475-a3db-a3a5539827ef) | Sigma | OpenSearch Security Analytics |
| T1041 | [Equation Group C2 Communication](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A881834a4-6659-4773-821e-1c151789d873) | Sigma | SigmaHQ |
| T1041 | [OpenCanary - TFTP Request](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab4e6b016-a2ac-4759-ad85-8000b300d61e) | Sigma | SigmaHQ |
| T1046 | [HackTool - winPEAS Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A98b53e78-ebaf-46f8-be06-421aafd176d9) | Sigma | SigmaHQ |
| T1046 | [HackTool - WinPwn Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad557dc06-62e8-4468-a8e8-7984124908ce) | Sigma | SigmaHQ |
| T1047 | [HackTool - Potential Impacket Lateral Movement Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A10c14723-61c7-4c75-92ca-9af245723ad2) | Sigma | SigmaHQ |
| T1047 | [CrackMapExec Command Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A058f4380-962d-40a5-afce-50207d36d7e2) | Sigma | OpenSearch Security Analytics |
| T1048.003 | [Suspicious WebDav Client Execution Via Rundll32.EXE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A982e9f2d-1a85-4d5b-aea4-31f5e97c6555) | Sigma | SigmaHQ |
| T1048.003 | [Possible DNS Tunneling](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A1ec4b281-aa65-46a2-bdae-5fd830ed914e) | Sigma | OpenSearch Security Analytics |
| T1049 | [Potential Pikabot Discovery Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A698d4431-514f-4c82-af4d-cf573872a9f5) | Sigma | SigmaHQ |
| T1049 | [HackTool - SharpView Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab2317cfa-4a47-4ead-b3ff-297438c0bc2d) | Sigma | SigmaHQ |
| T1053.005 | [Operation Wocao Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1cfac73c-be78-4f9a-9b08-5bde0c3953ab) | Sigma | SigmaHQ |
| T1053.005 | [Operation Wocao Activity - Security](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A74ad4314-482e-4c3e-b237-3f7ed3b9ca8d) | Sigma | SigmaHQ |
| T1055.001 | [TAIDOOR RAT DLL Load](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad1aa3382-abab-446f-96ea-4de52908210b) | Sigma | SigmaHQ |
| T1055.001 | [Renamed ZOHO Dctask64 Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A340a090b-c4e9-412e-bb36-b4b16fe96f9b) | Sigma | SigmaHQ |
| T1056.001 | [Linux Keylogging with Pam.d](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A49aae26c-450e-448b-911d-b3c13d178dfc) | Sigma | SigmaHQ |
| T1056.001 | [Linux Keylogging with Pam.d](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A49aae26c-450e-448b-911d-b3c13d178dfc) | Sigma | OpenSearch Security Analytics |
| T1057 | [Process Discovery](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4e2f5868-08d4-413d-899f-dc2f1508627b) | Sigma | SigmaHQ |
| T1057 | [HackTool - PCHunter Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Afca949cc-79ca-446e-8064-01aa7e52ece5) | Sigma | SigmaHQ |
| T1059.001 | [Potential Emotet Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad02e8cf5-6099-48cf-9bfc-1eec2d0c7b18) | Sigma | SigmaHQ |
| T1059.001 | [TropicTrooper Campaign November 2018](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A8c7090c3-e0a0-4944-bd08-08c3a0cecf79) | Sigma | SigmaHQ |
| T1059.003 | [HackTool - CrackMapExec Execution Patterns](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A058f4380-962d-40a5-afce-50207d36d7e2) | Sigma | SigmaHQ |
| T1059.003 | [CrackMapExec Command Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A058f4380-962d-40a5-afce-50207d36d7e2) | Sigma | OpenSearch Security Analytics |
| T1059.005 | [Potential QBot Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4fcac6eb-0287-4090-8eea-2602e4c20040) | Sigma | SigmaHQ |
| T1059.005 | [QBot Process Creation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A4fcac6eb-0287-4090-8eea-2602e4c20040) | Sigma | OpenSearch Security Analytics |
| T1070 | [Shadow Copies Deletion Using Operating Systems Utilities](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac947b146-0abc-4c87-9c64-b17e9d7274a2) | Sigma | SigmaHQ |
| T1070 | [Fsutil Suspicious Invocation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aadd64136-62e5-48ea-807e-88638d02df1e) | Sigma | SigmaHQ |
| T1070.003 | [Cisco Clear Logs](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aceb407f6-8277-439b-951f-e4210e3ed956) | Sigma | SigmaHQ |
| T1070.003 | [Linux Command History Tampering](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Afdc88d25-96fb-4b7c-9633-c0e417fdbd4e) | Sigma | SigmaHQ |
| T1070.004 | [File Deletion](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A30aed7b6-d2c1-4eaf-9382-b6bc43e50c57) | Sigma | SigmaHQ |
| T1070.004 | [Prefetch File Deleted](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A0a1f9d29-6465-4776-b091-7f43b26e4c89) | Sigma | SigmaHQ |
| T1070.006 | [File Creation Date Changed to Another Year](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A558eebe5-f2ba-4104-b339-36f7902bcc1a) | Sigma | SigmaHQ |
| T1070.006 | [Touch Suspicious Service File](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A31545105-3444-4584-bebf-c466353230d2) | Sigma | SigmaHQ |
| T1071.001 | [Ursnif Malware Download URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aa36ce77e-30db-4ea0-8795-644d7af5dfb4) | Sigma | SigmaHQ |
| T1071.001 | [Ursnif Malware C2 URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A932ac737-33ca-4afd-9869-0d48b391fcc9) | Sigma | SigmaHQ |
| T1074.001 | [Sensitive File Access followed by Compression](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Aa0fbd7a9-1923-4e05-92df-b484168f17bc) | Elastic | Elastic detection-rules |
| T1074.001 | [Folder Compress To Potentially Suspicious Output Via Compress-Archive Cmdlet](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A85a8e5ba-bd03-4bfb-bbfa-a4409a8f8b98+%23+Process+Creation) | Sigma | SigmaHQ |
| T1078 | [Privilege Role Sign-In Outside Expected Controls](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acf1e5687-84e1-41af-97a9-158094efef53) | Sigma | SigmaHQ |
| T1078 | [OpenCanary - SSH Login Attempt](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aff7139bc-fdb1-4437-92f2-6afefe8884cb) | Sigma | SigmaHQ |
| T1082 | [Potential GobRAT File Discovery Via Grep](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae34cfa0c-0a50-4210-9cb3-5632d08eb041) | Sigma | SigmaHQ |
| T1082 | [System Information Discovery](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A42df45e7-e6e9-43b5-8f26-bec5b39cc239) | Sigma | SigmaHQ |
| T1083 | [Turla Group Lateral Movement](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac601f20d-570a-4cde-a7d6-e17f99cb8e7f) | Sigma | SigmaHQ |
| T1083 | [WannaCry Ransomware Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A41d40bff-377a-43e2-8e1b-2e543069e079) | Sigma | SigmaHQ |
| T1090.001 | [Renamed Cloudflared.EXE Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae0c69ebd-b54f-4aed-8ae3-e3467843f3f0) | Sigma | SigmaHQ |
| T1090.001 | [PUA - Chisel Tunneling Tool Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A8b0e12da-d3c3-49db-bb4f-256703f380e5) | Sigma | SigmaHQ |
| T1090.002 | [RDP over Reverse SSH Tunnel WFP](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A5bed80b6-b3e8-428e-a3ae-d3c757589e41) | Sigma | SigmaHQ |
| T1090.002 | [Potential Tunneling via AWS IoT Secure Tunneling Localproxy](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Adeab559f-f3ab-4ce3-b17c-8f70c4169fd6) | Elastic | Elastic detection-rules |
| T1098 | [Password Change on Directory Service Restore Mode (DSRM) Account](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A53ad8e36-f573-46bf-97e4-15ba5bf4bb51) | Sigma | SigmaHQ |
| T1098 | [User Added To Global Domain Admins Grp](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=hayabusa-native%3A%3A4bb89c86-a138-42a0-baaf-fc2f777a4506) | Sigma | Hayabusa (native) |
| T1102.002 | [Potential Etherhiding C2 via Blockchain Connection](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Abba8c7d1-172b-435d-9034-02ed9289c628) | Elastic | Elastic detection-rules |
| T1102.002 | [Google Calendar C2 via Script Interpreter](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Aabc7a2be-479e-428b-b0b3-1d22bda46dd9) | Elastic | Elastic detection-rules |
| T1104 | [PowerShell DownloadFile](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A8f70ac5f-1f6f-4f8e-b454-db19561216c5) | Sigma | OpenSearch Security Analytics |
| T1105 | [Greenbug Espionage Group Indicators](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A3711eee4-a808-4849-8a14-faf733da3612) | Sigma | SigmaHQ |
| T1105 | [Pandemic Registry Key](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A47e0852a-cf81-4494-a8e6-31864f8c86ed) | Sigma | SigmaHQ |
| T1106 | [Turla Group Named Pipes](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A739915e4-1e70-4778-8b8a-17db02f66db1) | Sigma | SigmaHQ |
| T1106 | [BPFDoor Abnormal Process ID or Lock File Accessed](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A808146b2-9332-4d78-9416-d7e47012d83d) | Sigma | SigmaHQ |
| T1110.003 | [Multiple SonicWall Login Failures Followed by Successful Login](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Aefe7ac71-3b13-41cf-8263-30af68ce3f19) | Elastic | Elastic detection-rules |
| T1110.003 | [Potential Successful SSH Brute Force Attack](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A8cb84371-d053-4f4f-bce0-c74990e28f28) | Elastic | Elastic detection-rules |
| T1124 | [Use of W32tm as Timer](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A6da2c9f5-7c53-401b-aacb-92c040ce1215) | Sigma | SigmaHQ |
| T1124 | [Cisco Discovery](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A9705a6a1-6db6-4a16-a987-15b7151e299b) | Sigma | SigmaHQ |
| T1132.001 | [DNS Exfiltration and Tunneling Tools Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A98a96a5a-64a0-4c42-92c5-489da3866cb0) | Sigma | SigmaHQ |
| T1132.001 | [DNS Exfiltration and Tunneling Tools Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A98a96a5a-64a0-4c42-92c5-489da3866cb0) | Sigma | OpenSearch Security Analytics |
| T1134.002 | [Suspicious Child Process Created as System](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A590a5f4c-6c8c-4f10-8307-89afe9453a9d) | Sigma | SigmaHQ |
| T1134.002 | [PUA - AdvancedRun Suspicious Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Afa00b701-44c6-4679-994d-5a18afa8a707) | Sigma | SigmaHQ |
| T1140 | [UNC4841 - SSL Certificate Exfiltration Via Openssl](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A60911c07-f989-4362-84af-c609828ef829) | Sigma | SigmaHQ |
| T1140 | [UNC4841 - Download Compressed Files From Temp.sh Using Wget](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A60d050c4-e253-4d9a-b673-5ac100cfddfb) | Sigma | SigmaHQ |
| T1189 | [Flash Player Update from Suspicious Location](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4922a5dd-6743-4fc2-8e81-144374280997) | Sigma | SigmaHQ |
| T1189 | [Cross Site Scripting Strings](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A65354b83-a2ea-4ea6-8414-3ab38be0d409) | Sigma | SigmaHQ |
| T1202 | [Suspicious Child Process Of BgInfo.EXE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A811f459f-9231-45d4-959a-0266c6311987) | Sigma | SigmaHQ |
| T1202 | [Suspicious Splwow64 Without Params](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1f1a8509-2cbb-44f5-8751-8e1571518ce2) | Sigma | SigmaHQ |
| T1203 | [Droppers Exploiting CVE-2017-11882](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A678eb5f4-8597-4be6-8be7-905e4234b53a) | Sigma | SigmaHQ |
| T1203 | [OMIGOD HTTP No Authentication RCE - CVE-2021-38647](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aab6b1a39-a9ee-4ab4-b075-e83acf6e346b) | Sigma | SigmaHQ |
| T1204.002 | [Ursnif Malware C2 URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A932ac737-33ca-4afd-9869-0d48b391fcc9) | Sigma | SigmaHQ |
| T1204.002 | [Droppers Exploiting CVE-2017-11882](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A678eb5f4-8597-4be6-8be7-905e4234b53a) | Sigma | SigmaHQ |
| T1218 | [MavInject Process Injection](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A17eb8e57-9983-420d-ad8a-2c4976c22eb8) | Sigma | OpenSearch Security Analytics |
| T1218 | [Potential Suspicious Child Process Of 3CXDesktopApp](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A63f3605b-979f-48c2-b7cc-7f90523fed88) | Sigma | SigmaHQ |
| T1218.005 | [Potential Baby Shark Malware Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A2b30fa36-3a18-402f-a22d-bf4ce2189f35) | Sigma | SigmaHQ |
| T1218.005 | [Remotely Hosted HTA File Executed Via Mshta.EXE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab98d0db6-511d-45de-ad02-e82a98729620) | Sigma | SigmaHQ |
| T1218.011 | [Equation Group DLL_U Export Function Load](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad465d1d8-27a2-4cca-9621-a800f37cf72e) | Sigma | SigmaHQ |
| T1218.011 | [APT29 2018 Phishing Campaign File Indicators](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A3a3f81ca-652c-482b-adeb-b1c804727f74) | Sigma | SigmaHQ |
| T1485 | [Fsutil Suspicious Invocation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aadd64136-62e5-48ea-807e-88638d02df1e) | Sigma | SigmaHQ |
| T1485 | [Potential BlackByte Ransomware Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A999e8307-a775-4d5f-addc-4855632335be) | Sigma | SigmaHQ |
| T1489 | [Delete Important Scheduled Task](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Adbc1f800-0fe0-4bc0-9c66-292c2abe3f78) | Sigma | SigmaHQ |
| T1489 | [Suspicious Windows Service Tampering](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ace72ef99-22f1-43d4-8695-419dcb5d9330) | Sigma | SigmaHQ |
| T1491.001 | [Potential Ransomware Activity Using LegalNotice Message](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A8b9606c9-28be-4a38-b146-0e313cc232c1) | Sigma | SigmaHQ |
| T1491.001 | [Potentially Suspicious Desktop Background Change Using Reg.EXE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A8cbc9475-8d05-4e27-9c32-df960716c701) | Sigma | SigmaHQ |
| T1529 | [Silence.EDA Detection](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A3ceb2083-a27f-449a-be33-14ec1b7cc973) | Sigma | SigmaHQ |
| T1529 | [Silence.EDA Detection](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A3ceb2083-a27f-449a-be33-14ec1b7cc973) | Sigma | OpenSearch Security Analytics |
| T1542.003 | [Potential Ransomware or Unauthorized MBR Tampering Via Bcdedit.EXE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac9fbe8e9-119d-40a6-9b59-dd58a5d84429) | Sigma | SigmaHQ |
| T1542.003 | [Initramfs Unpacking via unmkinitramfs](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ac5fc788c-7576-4a02-b3d6-d2c016eb85a6) | Elastic | Elastic detection-rules |
| T1543.003 | [PSExec Lateral Movement](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=hayabusa-native%3A%3A0694c340-3a46-40ac-acfc-c3444ae6572c) | Sigma | Hayabusa (native) |
| T1543.003 | [Suspicious Service Name](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=hayabusa-native%3A%3Acc429813-21db-4019-b520-2f19648e1ef1) | Sigma | Hayabusa (native) |
| T1547.001 | [Potential Ryuk Ransomware Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac37510b8-2107-4b78-aa32-72f251e7a844) | Sigma | SigmaHQ |
| T1547.001 | [Ryuk Ransomware](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Ac37510b8-2107-4b78-aa32-72f251e7a844) | Sigma | OpenSearch Security Analytics |
| T1547.009 | [Creation Exe for Service with Unquoted Path](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A8c3c76ca-8f8b-4b1d-aaf3-81aebcd367c9) | Sigma | SigmaHQ |
| T1547.009 | [New Custom Shim Database Created](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aee63c85c-6d51-4d12-ad09-04e25877a947) | Sigma | SigmaHQ |
| T1553.002 | [Driver Loaded (Invalid Signature)](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=hayabusa-native%3A%3A1f666722-3948-40a2-9d78-d9d374477a90) | Sigma | Hayabusa (native) |
| T1553.002 | [Driver Loaded (Expired/Revoked Cert)](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=hayabusa-native%3A%3Ac837dd6d-0c91-4593-aeab-f6a1f3ca1961) | Sigma | Hayabusa (native) |
| T1557.001 | [HackTool - Impacket Tools Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4627c6ae-6899-46e2-aa0c-6ebcb1becd19) | Sigma | SigmaHQ |
| T1557.001 | [HackTool - ADCSPwn Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acd8c163e-a19b-402e-bdd5-419ff5859f12) | Sigma | SigmaHQ |
| T1560 | [Conti NTDS Exfiltration Command](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aaa92fd02-09f2-48b0-8a93-864813fb8f41) | Sigma | SigmaHQ |
| T1560 | [Sensitive Files Compression Inside A Container](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ad9faf1ba-a216-4c29-b8e0-a05a9d14b027) | Elastic | Elastic detection-rules |
| T1560.002 | [GenAI Process Performing Encoding/Chunking Prior to Network Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ac3d4e5f6-a7b8-9012-cdef-123456789abc) | Elastic | Elastic detection-rules |
| T1560.002 | [PowerShell Script with Archive Compression Capabilities](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A27071ea3-e806-4697-8abc-e22c92aa4293) | Elastic | Elastic detection-rules |
| T1560.003 | [Potential Data Collection in Temporary Directory by Hidden Executable](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-protections-artifacts-behavior%3A%3Aa6994646-d314-4ee0-be1f-1d694dc969e7) | Elastic | Elastic protections-artifacts (behavior) |
| T1561.001 | [Cisco File Deletion](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A71d65515-c436-43c0-841b-236b1f32c21e) | Sigma | SigmaHQ |
| T1561.001 | [Cisco File Deletion](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A71d65515-c436-43c0-841b-236b1f32c21e) | Sigma | OpenSearch Security Analytics |
| T1561.002 | [Cisco File Deletion](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A71d65515-c436-43c0-841b-236b1f32c21e) | Sigma | SigmaHQ |
| T1561.002 | [Cisco File Deletion](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A71d65515-c436-43c0-841b-236b1f32c21e) | Sigma | OpenSearch Security Analytics |
| T1564.001 | [Set Suspicious Files as System Files Using Attrib.EXE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aefec536f-72e8-4656-8960-5e85d091345b) | Sigma | SigmaHQ |
| T1564.001 | [PowerShell Logging Disabled Via Registry Key Tampering](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Afecfd1a1-cc78-4313-a1ea-2ee2e8ec27a7) | Sigma | SigmaHQ |
| T1566.001 | [Ursnif Malware C2 URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A932ac737-33ca-4afd-9869-0d48b391fcc9) | Sigma | SigmaHQ |
| T1566.001 | [Droppers Exploiting CVE-2017-11882](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A678eb5f4-8597-4be6-8be7-905e4234b53a) | Sigma | SigmaHQ |
| T1566.002 | [Potential Malicious Usage of CloudTrail System Manager](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A38e7f511-3f74-41d4-836e-f57dfa18eead) | Sigma | SigmaHQ |
| T1566.002 | [Google Workspace Device Registration After OAuth from Suspicious ASN](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A012bfca7-45cb-4507-a3ba-3777167f8b81) | Elastic | Elastic detection-rules |
| T1566.003 | [M365 Teams Rogue Help Desk Chat Created](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ae8e7b6b6-78b0-4015-97fe-c2f28468e0d4) | Elastic | Elastic detection-rules |
| T1566.003 | [M365 Azure Monitor Alert Email with Financial or Billing Theme](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Aa6129187-c47b-48ab-a412-67a44836d918) | Elastic | Elastic detection-rules |
| T1571 | [Potentially Suspicious Malware Callback Communication - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Adbfc7c98-04ab-4ab7-aa94-c74d22aa7376) | Sigma | SigmaHQ |
| T1571 | [Potentially Suspicious Malware Callback Communication](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4b89abaa-99fe-4232-afdd-8f9aa4d20382) | Sigma | SigmaHQ |
| T1573.001 | [CYFIRMA - High severity Command & Control Network Indicators with Monitor Recommendation Rule](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A6d8fb3fe-2501-4103-8137-34261fa3a596) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1573.001 | [CYFIRMA - High severity Command & Control Network Indicators with Block Recommendation Rule](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A6b61b716-afd9-4f6c-ad00-965d5987cafd) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1574.001 | [Winnti Pipemon Characteristics](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A73d70463-75c9-4258-92c6-17500fe972f2) | Sigma | SigmaHQ |
| T1574.001 | [Winnti Pipemon Characteristics](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A73d70463-75c9-4258-92c6-17500fe972f2) | Sigma | OpenSearch Security Analytics |
| T1574.013 | [UID Elevation from Previously Unknown Executable](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A7787362c-90ff-4b1a-b313-8808b1020e64) | Elastic | Elastic detection-rules |
| T1574.013 | [Suspicious Kworker UID Elevation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A7dfaaa17-425c-4fe7-bd36-83705fde7c2b) | Elastic | Elastic detection-rules |
| T1583.001 | [AWS Route 53 Private Hosted Zone Associated With a VPC](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ae3c27562-709a-42bd-82f2-3ed926cced19) | Elastic | Elastic detection-rules |
| T1583.001 | [AWS SES Email Identity Verified Then Deleted](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A8e4bde35-125d-4eb3-9a2e-d7e77a053a08) | Elastic | Elastic detection-rules |
| T1583.006 | [GitHub Repo Created](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A6cea88e4-6ce2-4238-9981-a54c140d6336) | Elastic | Elastic detection-rules |
| T1583.006 | [Cisco Secure Firewall - Rare Snort Rule Triggered](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=splunk-security-content%3A%3Ae20313d2-7d63-4fcf-b2d9-d6e12c6c7bd7) | Splunk | Splunk security_content |
| T1585.001 | [CYFIRMA - Brand Intelligence - Social Media Handle Impersonation Detected High Rule](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A22f49d67-7da7-4809-8d07-89e4478aa6b0) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1585.001 | [CYFIRMA - Brand Intelligence - Executive/People Impersonation High Rule](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A159d26a1-591c-4f70-b1ca-2843c881aaec) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1587.001 | [Formbook Process Creation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A032f5fb3-d959-41a5-9263-4173c802dc2b) | Sigma | SigmaHQ |
| T1587.001 | [Uncommon File Created In Office Startup Folder](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aa10a2c40-2c4d-49f8-b557-1a946bc55d9d) | Sigma | SigmaHQ |
| T1588.002 | [Hacktool Execution - Imphash](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A24e3e58a-646b-4b50-adef-02ef935b9fc8) | Sigma | SigmaHQ |
| T1588.002 | [Renamed SysInternals DebugView Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acd764533-2e07-40d6-a718-cfeec7f2da7f) | Sigma | SigmaHQ |
| T1588.004 | [Cisco Secure Firewall - Blacklisted SSL Certificate Fingerprint](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=splunk-security-content%3A%3Ac43f7b49-2dab-4e76-892e-7f971c2f20f1) | Splunk | Splunk security_content |
| T1589.002 | [Potential Unconstrained Delegation Discovery Via Get-ADComputer - ScriptBlock](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acdfa73b6-3c9d-4bb8-97f8-ddbd8921f5c5) | Sigma | SigmaHQ |
| T1589.002 | [AWSCloudTrail - Suspicious AWS CLI Command Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A8c2dc344-9352-4ca1-8863-b1b7a5e09e59) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1591 | [AWSCloudTrail - Suspicious AWS CLI Command Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A8c2dc344-9352-4ca1-8863-b1b7a5e09e59) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1591 | [MailGuard 365 - Malware Threats](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-hunting-queries%3A%3Adaaae6ad-1fd0-4efa-b571-116689e67a20) | Sentinel KQL | Microsoft Sentinel (Hunting Queries) |
| T1620 | [PowerShell Base64 Encoded Reflective Assembly Load](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A62b7ccc9-23b4-471e-aa15-6da3663c4d59) | Sigma | SigmaHQ |
| T1620 | [Potential WinAPI Calls Via PowerShell Scripts](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A03d83090-8cba-44a0-b02f-0b756a050306) | Sigma | SigmaHQ |
| T1685 | [Windows Defender Configuration Changes](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A801bd44f-ceed-4eb6-887c-11544633c0aa) | Sigma | SigmaHQ |
| T1685 | [Windows Defender Virus Scanning Feature Disabled](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A686c0b4b-9dd3-4847-9077-d6c1bbe36fcb) | Sigma | SigmaHQ |
| T1686.003 | [Suspicious Program Location Whitelisted In Firewall Via Netsh.EXE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aa35f5a72-f347-4e36-8895-9869b0d5fc6d) | Sigma | SigmaHQ |
| T1686.003 | [RDP Connection Allowed Via Netsh.EXE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A01aeb693-138d-49d2-9403-c4f52d7d3d62) | Sigma | SigmaHQ |

## 9. Plano de emulação e validação

Use num laboratório isolado e autorizado para confirmar que as regras disparam. Os comandos estão nos repositórios oficiais.

| Tática | Técnica | Teste Atomic Red Team | Plataformas |
|---|---|---|---|
| Initial Access | [T1566.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1566.001/T1566.001.md) | Download Macro-Enabled Phishing Attachment | windows |
| Initial Access | [T1566.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1566.001/T1566.001.md) | Word spawned a command shell and used an IP address in the command line | windows |
| Initial Access | [T1566.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1566.002/T1566.002.md) | Paste and run technique | windows |
| Execution | [T1047](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1047/T1047.md) | WMI Reconnaissance Users | windows |
| Execution | [T1047](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1047/T1047.md) | WMI Reconnaissance Processes | windows |
| Execution | [T1053.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1053.005/T1053.005.md) | Scheduled Task Startup Script | windows |
| Execution | [T1053.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1053.005/T1053.005.md) | Scheduled task Local | windows |
| Execution | [T1059.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md) | Mimikatz | windows |
| Execution | [T1059.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md) | Run BloodHound from local disk | windows |
| Execution | [T1059.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.003/T1059.003.md) | Create and Execute Batch Script | windows |
| Execution | [T1059.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.003/T1059.003.md) | Writes text to a file and displays it. | windows |
| Execution | [T1059.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.005/T1059.005.md) | Visual Basic script execution to gather local computer information | windows |
| Execution | [T1059.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.005/T1059.005.md) | Encoded VBS code execution | windows |
| Execution | [T1106](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1106/T1106.md) | Execution through API - CreateProcess | windows |
| Execution | [T1106](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1106/T1106.md) | WinPwn - Get SYSTEM shell - Pop System Shell using CreateProcess technique | windows |
| Execution | [T1204.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1204.002/T1204.002.md) | OSTap Style Macro Execution | windows |
| Execution | [T1204.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1204.002/T1204.002.md) | OSTap Payload Download | windows |
| Persistence | [T1098](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1098/T1098.md) | Admin Account Manipulate | windows |
| Persistence | [T1098](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1098/T1098.md) | Domain Account and Group Manipulate | windows |
| Persistence | [T1543.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1543.003/T1543.003.md) | Modify Fax service to run PowerShell | windows |
| Persistence | [T1543.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1543.003/T1543.003.md) | Service Installation CMD | windows |
| Persistence | [T1547.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1547.001/T1547.001.md) | Reg Key Run | windows |
| Persistence | [T1547.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1547.001/T1547.001.md) | Reg Key RunOnce | windows |
| Persistence | [T1547.009](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1547.009/T1547.009.md) | Shortcut Modification | windows |
| Persistence | [T1547.009](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1547.009/T1547.009.md) | Create shortcut to cmd in startup folders | windows |
| Stealth | [T1027.007](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027.007/T1027.007.md) | Dynamic API Resolution-Ninja-syscall | windows |
| Stealth | [T1027.013](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027.013/T1027.013.md) | Decode Eicar File and Write to File | linux, macos, windows |
| Stealth | [T1027.013](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027.013/T1027.013.md) | Decrypt Eicar File and Write to File | linux, macos, windows |
| Stealth | [T1036.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.003/T1036.003.md) | Masquerading as Windows LSASS process | windows |
| Stealth | [T1036.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.003/T1036.003.md) | Masquerading as FreeBSD or Linux crond process. | linux |
| Stealth | [T1036.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.004/T1036.004.md) | Creating W32Time similar named service using schtasks | windows |
| Stealth | [T1036.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.004/T1036.004.md) | Creating W32Time similar named service using sc | windows |
| Stealth | [T1036.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.005/T1036.005.md) | Execute a process from a directory masquerading as the current parent directory | linux, macos |
| Stealth | [T1036.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.005/T1036.005.md) | Masquerade as a built-in system executable | windows |
| Stealth | [T1055.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1055.001/T1055.001.md) | Process Injection via mavinject.exe | windows |
| Stealth | [T1055.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1055.001/T1055.001.md) | WinPwn - Get SYSTEM shell - Bind System Shell using UsoClient DLL load technique | windows |
| Stealth | [T1070](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070/T1070.md) | Indicator Removal using FSUtil | windows |
| Stealth | [T1070](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070/T1070.md) | Indicator Manipulation using FSUtil | windows |
| Stealth | [T1070.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.003/T1070.003.md) | Clear Bash history (rm) |  |
| Stealth | [T1070.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.003/T1070.003.md) | Clear Bash history (echo) |  |
| Stealth | [T1070.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.004/T1070.004.md) | Delete a single file - FreeBSD/Linux/macOS | linux, macos |
| Stealth | [T1070.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.004/T1070.004.md) | Delete an entire folder - FreeBSD/Linux/macOS | linux, macos |
| Stealth | [T1070.006](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.006/T1070.006.md) | Set a file's access timestamp | linux, macos |
| Stealth | [T1070.006](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.006/T1070.006.md) | Set a file's modification timestamp | linux, macos |
| Stealth | [T1134.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1134.002/T1134.002.md) | Access Token Manipulation | windows |
| Stealth | [T1134.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1134.002/T1134.002.md) | WinPwn - Get SYSTEM shell - Pop System Shell using Token Manipulation technique | windows |
| Stealth | [T1140](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1140/T1140.md) | Deobfuscate/Decode Files Or Information | windows |
| Stealth | [T1140](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1140/T1140.md) | Certutil Rename and Decode | windows |
| Stealth | [T1202](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1202/T1202.md) | Indirect Command Execution - pcalua.exe | windows |
| Stealth | [T1202](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1202/T1202.md) | Indirect Command Execution - forfiles.exe | windows |
| Stealth | [T1218](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218/T1218.md) | mavinject - Inject DLL into running process | windows |
| Stealth | [T1218](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218/T1218.md) | Register-CimProvider - Execute evil dll | windows |
| Stealth | [T1218.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.005/T1218.005.md) | Mshta executes JavaScript Scheme Fetch Remote Payload With GetObject | windows |
| Stealth | [T1218.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.005/T1218.005.md) | Mshta executes VBScript to execute malicious command | windows |
| Stealth | [T1218.011](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.011/T1218.011.md) | Rundll32 execute JavaScript Remote Payload With GetObject | windows |
| Stealth | [T1218.011](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.011/T1218.011.md) | Rundll32 execute VBscript command | windows |
| Stealth | [T1564.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1564.001/T1564.001.md) | Create a hidden file in a hidden directory | linux, macos |
| Stealth | [T1564.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1564.001/T1564.001.md) | Mac Hidden file | macos |
| Stealth | [T1574.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1574.001/T1574.001.md) | DLL Search Order Hijacking - amsi.dll | windows |
| Stealth | [T1574.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1574.001/T1574.001.md) | Phantom Dll Hijacking - WinAppXRT.dll | windows |
| Stealth | [T1620](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1620/T1620.md) | WinPwn - Reflectively load Mimik@tz into memory | windows |
| Stealth | [T1620](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1620/T1620.md) | Reflective PE Injection via PowerSploit | windows |
| Defense Impairment | [T1685](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1685/T1685.md) | Windows Disable LSA Protection | windows |
| Defense Impairment | [T1685](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1685/T1685.md) | Disable journal logging via systemctl utility | linux |
| Defense Impairment | [T1686.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1686.003/T1686.003.md) | Enable Firewall Rule Group via COM Object (HNetCfg.FwPolicy2) | windows |
| Defense Impairment | [T1686.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1686.003/T1686.003.md) | Set All Network Profiles to Private via Registry | windows |
| Credential Access | [T1110.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1110.003/T1110.003.md) | Password Spray all Domain Users | windows |
| Credential Access | [T1110.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1110.003/T1110.003.md) | Password Spray (DomainPasswordSpray) | windows |
| Credential Access | [T1557.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1557.001/T1557.001.md) | LLMNR Poisoning with Inveigh (PowerShell) | windows |
| Discovery | [T1010](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1010/T1010.md) | List Process Main Windows - C# .NET | windows |
| Discovery | [T1012](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1012/T1012.md) | Query Registry | windows |
| Discovery | [T1012](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1012/T1012.md) | Query Registry with Powershell cmdlets | windows |
| Discovery | [T1016](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1016/T1016.md) | System Network Configuration Discovery on Windows | windows |
| Discovery | [T1016](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1016/T1016.md) | List Windows Firewall Rules | windows |
| Discovery | [T1033](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1033/T1033.md) | System Owner/User Discovery | windows |
| Discovery | [T1033](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1033/T1033.md) | System Owner/User Discovery | linux, macos |
| Discovery | [T1046](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1046/T1046.md) | Port Scan | linux, macos |
| Discovery | [T1046](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1046/T1046.md) | Port Scan Nmap | linux, macos |
| Discovery | [T1049](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1049/T1049.md) | System Network Connections Discovery | windows |
| Discovery | [T1049](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1049/T1049.md) | System Network Connections Discovery with PowerShell | windows |
| Discovery | [T1057](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1057/T1057.md) | Process Discovery - ps | linux, macos |
| Discovery | [T1057](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1057/T1057.md) | Process Discovery - tasklist | windows |
| Discovery | [T1082](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1082/T1082.md) | System Information Discovery | windows |
| Discovery | [T1082](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1082/T1082.md) | System Information Discovery | macos |
| Discovery | [T1083](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1083/T1083.md) | File and Directory Discovery (cmd.exe) | windows |
| Discovery | [T1083](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1083/T1083.md) | File and Directory Discovery (PowerShell) | windows |
| Discovery | [T1124](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1124/T1124.md) | System Time Discovery | windows |
| Discovery | [T1124](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1124/T1124.md) | System Time Discovery - PowerShell | windows |
| Lateral Movement | [T1021.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.001/T1021.001.md) | RDP to Remote Host | windows |
| Lateral Movement | [T1021.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.001/T1021.001.md) | Changing RDP Port to Non Standard Port via Powershell | windows |
| Lateral Movement | [T1021.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.002/T1021.002.md) | Map admin share | windows |
| Lateral Movement | [T1021.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.002/T1021.002.md) | Map Admin Share PowerShell | windows |
| Lateral Movement | [T1021.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.004/T1021.004.md) | ESXi - Enable SSH via PowerCLI | windows |
| Lateral Movement | [T1021.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.004/T1021.004.md) | ESXi - Enable SSH via VIM-CMD | windows |
| Collection | [T1005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1005/T1005.md) | Search files of interest and save them to a single zip file (Windows) | windows |
| Collection | [T1005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1005/T1005.md) | Find and dump sqlite databases (Linux) | linux |
| Collection | [T1056.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1056.001/T1056.001.md) | Input Capture | windows |
| Collection | [T1056.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1056.001/T1056.001.md) | Living off the land Terminal Input Capture on Linux with pam.d | linux |
| Collection | [T1074.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1074.001/T1074.001.md) | Stage data from Discovery.bat | windows |
| Collection | [T1074.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1074.001/T1074.001.md) | Stage data from Discovery.sh | linux, macos |
| Collection | [T1560](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1560/T1560.md) | Compress Data for Exfiltration With PowerShell | windows |
| Collection | [T1560.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1560.002/T1560.002.md) | Compressing data using GZip in Python (FreeBSD/Linux) | linux |
| Collection | [T1560.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1560.002/T1560.002.md) | Compressing data using bz2 in Python (FreeBSD/Linux) | linux |
| Command and Control | [T1071.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1071.001/T1071.001.md) | Malicious User Agents - Powershell | windows |
| Command and Control | [T1071.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1071.001/T1071.001.md) | Malicious User Agents - CMD | windows |
| Command and Control | [T1090.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1090.001/T1090.001.md) | Connection Proxy | linux, macos |
| Command and Control | [T1090.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1090.001/T1090.001.md) | Connection Proxy for macOS UI | macos |
| Command and Control | [T1105](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1105/T1105.md) | rsync remote file copy (push) | linux, macos |
| Command and Control | [T1105](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1105/T1105.md) | rsync remote file copy (pull) | linux, macos |
| Command and Control | [T1132.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1132.001/T1132.001.md) | Base64 Encoded data. | linux, macos |
| Command and Control | [T1132.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1132.001/T1132.001.md) | Base64 Encoded data (freebsd) | linux |
| Command and Control | [T1571](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1571/T1571.md) | Testing usage of uncommonly used port with PowerShell | windows |
| Command and Control | [T1571](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1571/T1571.md) | Testing usage of uncommonly used port | linux, macos |
| Exfiltration | [T1041](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1041/T1041.md) | C2 Data Exfiltration | windows |
| Exfiltration | [T1041](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1041/T1041.md) | Text Based Data Exfiltration using DNS subdomains | windows |
| Exfiltration | [T1048.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1048.003/T1048.003.md) | Exfiltration Over Alternative Protocol - HTTP | linux, macos |
| Exfiltration | [T1048.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1048.003/T1048.003.md) | Exfiltration Over Alternative Protocol - ICMP | windows |
| Impact | [T1485](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1485/T1485.md) | Windows - Overwrite file with SysInternals SDelete | windows |
| Impact | [T1485](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1485/T1485.md) | FreeBSD/macOS/Linux - Overwrite file with DD | linux, macos |
| Impact | [T1489](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1489/T1489.md) | Windows - Stop service using Service Controller | windows |
| Impact | [T1489](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1489/T1489.md) | Windows - Stop service using net.exe | windows |
| Impact | [T1491.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1491.001/T1491.001.md) | Replace Desktop Wallpaper | windows |
| Impact | [T1491.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1491.001/T1491.001.md) | Configure LegalNoticeCaption and LegalNoticeText registry keys to display ransom message | windows |
| Impact | [T1529](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1529/T1529.md) | Shutdown System - Windows | windows |
| Impact | [T1529](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1529/T1529.md) | Restart System - Windows | windows |

**Logs reais de ataque (EVTX) para testar sem executar nada:**

- T1016 — [ID4688-Audit policy enumerated](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1016-System%20Network%20Configuration%20Discovery/ID4688-Audit%20policy%20enumerated.evtx) _(explícito)_
- T1016 — [ID4688-Firewall configuration enumerated (command)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1016-System%20Network%20Configuration%20Discovery/ID4688-Firewall%20configuration%20enumerated%20%28command%29.evtx) _(explícito)_
- T1021.001 — [ID4688,4778,4779 RDP hijack direct](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0008-Lateral%20Movement/T1021.001-Remote%20Desktop%20Protocol/ID4688%2C4778%2C4779%20RDP%20hijack%20direct.evtx) _(explícito)_
- T1021.001 — [ID4688-4778 RDP hijack command execution](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0008-Lateral%20Movement/T1021.001-Remote%20Desktop%20Protocol/ID4688-4778%20RDP%20hijack%20command%20execution.evtx) _(explícito)_
- T1021.002 — [ID4688,4697,5140-5145 PSexec remote execution + admin share](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0008-Lateral%20Movement/T1021.002-SMB%20Windows%20Admin%20Shares/ID4688%2C4697%2C5140-5145%20PSexec%20remote%20execution%20%2B%20admin%20share.evtx) _(explícito)_
- T1021.002 — [ID4688-4648 Lateral movement with net use](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0008-Lateral%20Movement/T1021.002-SMB%20Windows%20Admin%20Shares/ID4688-4648%20Lateral%20movement%20with%20net%20use.evtx) _(explícito)_
- T1021.004 — [ID4-OpenSSH server listening](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0008-Lateral%20Movement/T1021.004-Remote%20Service%20SSH/ID4-OpenSSH%20server%20listening.evtx) _(explícito)_
- T1021.004 — [ID4103-4104-OpenSSH server activation and config](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0008-Lateral%20Movement/T1021.004-Remote%20Service%20SSH/ID4103-4104-OpenSSH%20server%20activation%20and%20config.evtx) _(explícito)_
- T1046 — [ID131-RDP brutforce (no user info)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1046-Network%20Service%20Scanning/ID131-RDP%20brutforce%20%28no%20user%20info%29.evtx) _(explícito)_
- T1046 — [ID4624-Anonymous login with domain specified (DonPapi)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1046-Network%20Service%20Scanning/ID4624-Anonymous%20login%20with%20domain%20specified%20%28DonPapi%29.evtx) _(explícito)_
- T1047 — [ID1-WMI spwaning PowerShell process - WMImplant](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1047-Windows%20Management%20Instrumentation/ID1-WMI%20spwaning%20PowerShell%20process%20-%20WMImplant.evtx) _(explícito)_
- T1047 — [ID1-WMIexec process execution](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1047-Windows%20Management%20Instrumentation/ID1-WMIexec%20process%20execution.evtx) _(explícito)_
- T1053.005 — [ID4688-4698 Persistent scheduled task with SYSTEM privileges creation](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1053.005-Scheduled%20Task/ID4688-4698%20Persistent%20scheduled%20task%20with%20SYSTEM%20privileges%20creation.evtx) _(explícito)_
- T1053.005 — [ID4688-Interactive shell using AT schedule task](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1053.005-Scheduled%20Task/ID4688-Interactive%20shell%20using%20AT%20schedule%20task.evtx) _(explícito)_
- T1056.001 — [sysmon_13_keylogger_directx](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Credential%20Access/sysmon_13_keylogger_directx.evtx) _(inferido)_
- T1059.001 — [ID4103-4104-Payload download via PowerShell](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1059.001-PowerShell/ID4103-4104-Payload%20download%20via%20PowerShell.evtx) _(explícito)_
- T1059.001 — [ID4688-Encoded PowerShell MSF payload via process execution](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1059.001-PowerShell/ID4688-Encoded%20PowerShell%20MSF%20payload%20via%20process%20execution.evtx) _(explícito)_
- T1059.003 — [ID4688-SQL Server payload injectection for reverse shell (MSF)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1059.003-Windows%20Command%20Shell/ID4688-SQL%20Server%20payload%20injectection%20for%20reverse%20shell%20%28MSF%29.evtx) _(explícito)_
- T1070.006 — [ID4616-system time changed](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0005-Defense%20Evasion/T1070.006-Timestomp/ID4616-system%20time%20changed.evtx) _(explícito)_
- T1070.006 — [DE_timestomp_and_dll_sideloading_and_RunPersist](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/AutomatedTestingTools/Malware/DE_timestomp_and_dll_sideloading_and_RunPersist.evtx) _(inferido)_
- T1078 — [ID1149-RDP success logins to multiple hosts](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0001-Initial%20access/T1078-Valid%20accounts/ID1149-RDP%20success%20logins%20to%20multiple%20hosts.evtx) _(explícito)_
- T1078 — [ID33205-SQL Server failed login with disabled SA account](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0001-Initial%20access/T1078-Valid%20accounts/ID33205-SQL%20Server%20failed%20login%20with%20disabled%20SA%20account.evtx) _(explícito)_
- T1098 — [ID33205-SQL Server member added to database role](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0003-Persistence/T1098.xxx-Account%20manipulation/ID33205-SQL%20Server%20member%20added%20to%20database%20role.evtx) _(explícito)_
- T1098 — [ID33205-SQL Server member added to server role](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0003-Persistence/T1098.xxx-Account%20manipulation/ID33205-SQL%20Server%20member%20added%20to%20server%20role.evtx) _(explícito)_
- T1110.003 — [kerberos_pwd_spray_4771](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Credential%20Access/kerberos_pwd_spray_4771.evtx) _(inferido)_

## 10. Hipóteses de hunting

Se Lazarus Group estiver no seu ambiente, estas são as perguntas a fazer aos seus dados (fontes de log segundo as estratégias de detecção do MITRE ATT&CK).

1. **T1574.013 KernelCallbackTable** — Unexpected modification of the KernelCallbackTable in a process’s PEB followed by invocation of modified callback functions (e.g., fnCOPYDATA) through Windows messages. Defender observes suspicious API call chains such as NtQueryInformationProcess →… Dados: `WinEventLog:Sysmon` (EventCode=10), `WinEventLog:Sysmon` (EventCode=1), `etw:Microsoft-Windows-Kernel-Process` (WriteProcessMemory: WriteProcessMemory targeting regions containing KernelCallbackTable addresses).
2. **T1134.002 Create Process with Token** — A process (often after stealing/creating a token) calls CreateProcessWithTokenW/CreateProcessAsUserW or uses runas to spawn a **new** process whose security context (SID/LogonId/IntegrityLevel) differs from its parent. Chain: (1) suspicious command/API → (2)… Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=10), `ETW:ProcThread` (api_call: CreateProcessWithTokenW, CreateProcessAsUserW).
3. **T1202 Indirect Command Execution** — Cause→effect chain: (1) A user or service launches an indirection utility (e.g., forfiles.exe, pcalua.exe, wsl.exe, scriptrunner.exe, ssh.exe with -o ProxyCommand/LocalCommand). (2) That utility spawns a secondary program/command (PowerShell, cmd, msiexec,… Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=3, 22), `WinEventLog:Sysmon` (EventCode=11).
4. **T1218 System Binary Proxy Execution** — Execution of trusted, Microsoft-signed binaries such as `rundll32.exe`, `msiexec.exe`, or `regsvr32.exe` used to execute externally hosted, unsigned, or suspicious payloads through command-line parameters or network retrieval. Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=3, 22), `WinEventLog:Sysmon` (EventCode=7).
5. **T1557.001 Name Resolution Poisoning and SMB Relay** — Detects anomalous network traffic on UDP 5355 (LLMNR) and UDP 137 (NBT-NS) combined with unauthorized SMB relay attempts, registry modifications re-enabling multicast name resolution, or suspicious service creation indicative of adversary-in-the-middle… Dados: `WinEventLog:Security` (EventCode=4697), `WinEventLog:Security` (Registry key modification HKLM\Software\Policies\Microsoft\Windows NT\DNSClient\EnableMulticast), `NSM:Flow` (Unusual responses to LLMNR (UDP 5355) or NBT-NS (UDP 137) queries from unauthorized hosts).
6. **T1001.003 Protocol or Service Impersonation** — Untrusted processes creating outbound TLS/HTTPS connections with malformed certificates or header fields, often mismatched with target service behavior. Detects protocol impersonation attempts via traffic metadata analysis and host process lineage. Dados: `WinEventLog:Sysmon` (EventCode=3, 22), `NSM:Flow` (SSL/TLS Handshake Analysis).
7. **T1010 Application Window Discovery** — Processes using Win32 API calls (e.g., EnumWindows, GetForegroundWindow) or scripting tools (e.g., PowerShell, VBScript) to enumerate open windows. These often appear with reconnaissance or data collection TTPs. Dados: `WinEventLog:Sysmon` (EventCode=10), `WinEventLog:PowerShell` (EventCode=4103, 4104, 4105, 4106).
8. **T1027.007 Dynamic API Resolution** — Behavioral chain involving suspicious use of GetProcAddress and LoadLibrary following memory allocation and manual mapping, often paired with low entropy strings, abnormal API use without static import tables, or delayed module load behaviors. Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=7), `etw:Microsoft-Windows-Kernel-Process` (API tracing / stack tracing via ETW or telemetry-based EDR).
9. **T1027.009 Embedded Payloads** — Detection of executables or scripts containing hidden embedded resources or secondary payloads, often with anomalies in file size vs. functionality or dropped child binaries. Dados: `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Sysmon` (EventCode=1), `EDR:file` (File Metadata Analysis (PE overlays, entropy)).
10. **T1542.003 Bootkit** — Detection of raw access to physical drives, modification of boot records (MBR/VBR), and suspicious file creation or alteration within the EFI System Partition (ESP). Correlates privileged process execution with low-level disk modification and unexpected… Dados: `WinEventLog:Sysmon` (EventCode=9), `WinEventLog:Sysmon` (EventCode=11).
11. **T1560.002 Archive via Library** — Detects adversarial archiving using libraries (zlib, zip APIs) invoked by scripts or binaries. Correlates process executions of Python, PowerShell, or custom .NET binaries with DLL/module loads linked to compression libraries, followed by archive file… Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=7), `WinEventLog:Sysmon` (EventCode=11).
12. **T1561.001 Disk Content Wipe** — Processes attempting raw disk access via \\.\PhysicalDrive paths, abnormal file I/O to MBR/boot sectors, or loading of third-party drivers (e.g., RawDisk) that enable disk overwrite. Correlate process creation, privilege usage, and disk modification events… Dados: `WinEventLog:Security` (EventCode=4673), `WinEventLog:Sysmon` (Raw disk writes targeting \\.\PhysicalDrive* or MBR locations), `WinEventLog:Sysmon` (EventCode=6).

## 11. OSINT — onde pesquisar

Consultas prontas com todos os nomes conhecidos do grupo:

- Relatórios técnicos: [busca web](https://duckduckgo.com/?q=%28%22Lazarus+Group%22+OR+%22Labyrinth+Chollima%22+OR+%22HIDDEN+COBRA%22+OR+%22Guardians+of+Peace%22+OR+%22ZINC%22+OR+%22NICKEL+ACADEMY%22%29+threat+report) · [PDFs](https://duckduckgo.com/?q=%28%22Lazarus+Group%22+OR+%22Labyrinth+Chollima%22+OR+%22HIDDEN+COBRA%22+OR+%22Guardians+of+Peace%22+OR+%22ZINC%22+OR+%22NICKEL+ACADEMY%22%29+filetype%3Apdf)
- Regras e IOCs publicados: [GitHub](https://github.com/search?type=code&q=%22Lazarus+Group%22+OR+%22Labyrinth+Chollima%22+OR+%22HIDDEN+COBRA%22+OR+%22Guardians+of+Peace%22+OR+%22ZINC%22+OR+%22NICKEL+ACADEMY%22)
- Pulsos de ameaça: [AlienVault OTX](https://otx.alienvault.com/browse/global/pulses?q=Lazarus+Group)
- Família de malware e atores: [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/actors) (busque por Lazarus Group, Labyrinth Chollima, HIDDEN COBRA)
- Cartões de grupo: [ThaiCERT Threat Group Cards](https://apt.etda.or.th/cgi-bin/listgroups.cgi)
- Página oficial: [MITRE ATT&CK G0032](https://attack.mitre.org/groups/G0032/)

**Relatórios na coleção CyberMonitor** (ligados pelo nome do grupo, conferir antes de citar):

- 2017 — [TA17-164A](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2017/2017.06.13.HIDDEN_COBRA/TA17-164A.pdf) _(via “HIDDEN COBRA”)_
- 2018 — [hidden-cobra-targets-turkish-financial-sector-new-bankshot-implant](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2018/2018.03.08.hidden-cobra-targets-turkish-financial/hidden-cobra-targets-turkish-financial-sector-new-bankshot-implant.pdf) _(via “HIDDEN COBRA”)_
- 2018 — [FASTCash How the Lazarus Group is Emptying Millions from ATMs](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2018/2018.11.08.FASTCash/FASTCash%20How%20the%20Lazarus%20Group%20is%20Emptying%20Millions%20from%20ATMs.pdf) _(via “Lazarus Group”)_
- 2019 — [LAZARUS GROUP DIRECTED TO ORGANIZATIONS IN RUSSIA_google_translate](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2019/2019.02.20.LAZARUS_to_RUSSIA/LAZARUS%20GROUP%20DIRECTED%20TO%20ORGANIZATIONS%20IN%20RUSSIA_google_translate.pdf) _(via “Lazarus Group”)_
- 2020 — [Weaponizing a Lazarus Group Implant](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2020/2020.02.22_Lazarus_Group_Weaponizing/Weaponizing%20a%20Lazarus%20Group%20Implant.pdf) _(via “Lazarus Group”)_
- 2020 — [f-secureLABS-tlp-white-lazarus-threat-intel-report2](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2020/2020.08.18.LAZARUS_GROUP/f-secureLABS-tlp-white-lazarus-threat-intel-report2.pdf) _(via “Lazarus Group”)_
- 2021 — [Lazarus Group Recruitment_ Threat Hunters vs Head Hunters](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2021/2021.04.27.Lazarus_Group_Recruitment/Lazarus%20Group%20Recruitment_%20Threat%20Hunters%20vs%20Head%20Hunters.pdf) _(via “Lazarus Group”)_
- 2024 — [JSAC2024_1_6_dongwook-kim_seulgi-lee_en](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2024/2024.01.25.Lazarus_Group/JSAC2024_1_6_dongwook-kim_seulgi-lee_en.pdf) _(via “Lazarus Group”)_

**Relatórios públicos ligados pelo APT4ALL** (4 no total, mais recentes primeiro):

- 2023 — [Stealing the LIGHTSHOW (Part One) - North Korea's UNC2970](https://app.box.com/s/t1wj2s9hwf71dh65w5re5est9yhvh0mu) _(Mandiant)_
- 2023 — [Lazarus group using public certificate vulnerability](https://app.box.com/s/ovpepub4io3zuwkn65viaoxcn18ifunk) _(Ahnlab)_
- 2018 — [Lazarus Group Targets More Cryptocurrency Exchanges and FinTech Companies](https://app.box.com/s/yepeditzh0t0upifbucv99utoretbbzl) _(Intezer)_
- 2018 — [Hidden Cobra Targets Turkish Financial Sector With New Bankshot Implant](https://app.box.com/s/a5yxk9ttke0l3wg054ub6tgb54hwp35a) _(McAfee)_

## 12. Bibliografia (51 fontes citadas pelo ATT&CK)

- [ASEC Lazarus 2022](https://asec.ahnlab.com/en/39828/) — AhnLab ASEC. (2022, October 6). Lazarus Group Uses the DLL Side-Loading Technique (mi.dll). Retrieved January 7, 2025.
- [CISA AppleJeus Feb 2021](https://us-cert.cisa.gov/ncas/alerts/aa21-048a) — Cybersecurity and Infrastructure Security Agency. (2021, February 21). AppleJeus: Analysis of North Korea’s Cryptocurrency Malware. Retrieved March 1, 2021.
- [CISA EB Aug 2020](https://us-cert.cisa.gov/ncas/analysis-reports/ar20-239a) — Cybersecurity and Infrastructure Security Agency. (2020, August 26). MAR-10301706-1.v1 - North Korean Remote Access Tool: ECCENTRICBANDWAGON. Retrieved March 18, 2021.
- [CISA MAR-10288834-2.v1  TAINTEDSCRIBE MAY 2020](https://us-cert.cisa.gov/ncas/analysis-reports/ar20-133b) — USG. (2020, May 12). MAR-10288834-2.v1 – North Korean Trojan: TAINTEDSCRIBE. Retrieved March 5, 2021.
- [Cisco MagicRAT 2022](https://blog.talosintelligence.com/lazarus-magicrat/) — Asheer Malhotra, Vitor Ventura & Jungsoo An, Cisco Talos. (2022, September 7). MagicRAT: Lazarus’ latest gateway into victim networks. Retrieved December 30, 2024.
- [ClearSky Lazarus Aug 2020](https://www.clearskysec.com/wp-content/uploads/2020/08/Dream-Job-Campaign.pdf) — ClearSky Research Team. (2020, August 13). Operation 'Dream Job' Widespread North Korean Espionage Campaign. Retrieved December 20, 2021.
- [CrowdStrike Labyrinth Chollima Feb 2022](https://web.archive.org/web/20210723190317/https://adversary.crowdstrike.com/en-US/adversary/labyrinth-chollima/) — CrowdStrike. (2022, February 1). CrowdStrike Adversary Labyrinth Chollima. Retrieved February 1, 2022.
- [ESET Twitter Ida Pro Nov 2021](https://x.com/ESETresearch/status/1458438155149922312) — Cherepanov, Anton. (2019, November 10). ESETresearch discovered a trojanized IDA Pro installer. Retrieved September 12, 2024.
- [FireEye APT38 Oct 2018](https://services.google.com/fh/files/misc/apt38-un-usual-suspects.pdf) — FireEye. (2018, October 03). APT38: Un-usual Suspects. Retrieved November 17, 2024.
- [FireEye WannaCry 2017](https://www.fireeye.com/blog/threat-research/2017/05/wannacry-malware-profile.html) — Berry, A., Homan, J., and Eitzman, R. (2017, May 23). WannaCry Malware Profile. Retrieved March 15, 2019.
- [Google TAG Lazarus Jan 2021](https://blog.google/threat-analysis-group/new-campaign-targeting-security-researchers/) — Weidemann, A. (2021, January 25). New campaign targeting security researchers. Retrieved December 20, 2021.
- [JPCert Blog Laz Subgroups 2025](https://blogs.jpcert.or.jp/en/2025/03/classifying-lazaruss-subgroup.html) — 佐々木勇人 Hayato Sasaki. (2025, March 25). Tempted to Classifying APT Actors: Practical Challenges of Attribution in the Case of Lazarus’s Subgroup. Retrieved August 25, 2025.
- [Kaspersky Dtrack](https://usa.kaspersky.com/about/press-releases/2019_dtrack-previously-unknown-spy-tool-hits-financial-institutions-and-research-centers) — Kaspersky Global Research and Analysis Team. (2019, September 23). DTrack: previously unknown spy-tool by Lazarus hits financial institutions and research centers. Retrieved January 20, 2021.
- [Kaspersky ThreatNeedle Feb 2021](https://securelist.com/lazarus-threatneedle/100803/) — Vyacheslav Kopeytsev and Seongsu Park. (2021, February 25). Lazarus targets defense industry with ThreatNeedle. Retrieved October 27, 2021.
- [Lazarus APT January 2022](https://blog.malwarebytes.com/threat-intelligence/2022/01/north-koreas-lazarus-apt-leverages-windows-update-client-github-in-latest-campaign/) — Saini, A. and Hossein, J. (2022, January 27). North Korea’s Lazarus APT leverages Windows Update client, GitHub in latest campaign. Retrieved January 27, 2022.
- [Lazarus RATANKBA](https://blog.trendmicro.com/trendlabs-security-intelligence/lazarus-campaign-targeting-cryptocurrencies-reveals-remote-controller-tool-evolved-ratankba/) — Lei, C., et al. (2018, January 24). Lazarus Campaign Targeting Cryptocurrencies Reveals Remote Controller Tool, an Evolved RATANKBA, and More. Retrieved May 22, 2018.
- [LogRhythm WannaCry](https://web.archive.org/web/20230522041200/https://logrhythm.com/blog/a-technical-analysis-of-wannacry-ransomware/) — Noerenberg, E., Costis, A., and Quist, N. (2017, May 16). A Technical Analysis of WannaCry Ransomware. Retrieved December 8, 2024.
- [Mandiant DPRK Groups 2023](https://cloud.google.com/blog/topics/threat-intelligence/north-korea-cyber-structure-alignment-2023) — Michael Barnhart, Austin Larsen, Jeff Johnson, Taylor Long, Michelle Cantos, Adrian Hernandez. (2023, October 10). Assessed Cyber Structure and Alignments of North Korea in 2023. Retrieved August 25, 2025.
- [Mandiant DPRK Laz Org Breakdown 2022](https://cloud.google.com/blog/topics/threat-intelligence/mapping-dprk-groups-to-government/) — Michael Barnhart, Michelle Cantos, Jeffery Johnson, Elias fox, Gary Freas, Dan Scott. (2022, March 23). Not So Lazarus: Mapping DPRK Cyber Threat Groups to Government Organizations. Retrieved September 9, 2025.
- [McAfee Bankshot](https://securingtomorrow.mcafee.com/mcafee-labs/hidden-cobra-targets-turkish-financial-sector-new-bankshot-implant/) — Sherstobitoff, R. (2018, March 08). Hidden Cobra Targets Turkish Financial Sector With New Bankshot Implant. Retrieved May 18, 2018.
- [McAfee GhostSecret](https://securingtomorrow.mcafee.com/mcafee-labs/analyzing-operation-ghostsecret-attack-seeks-to-steal-data-worldwide/) — Sherstobitoff, R., Malhotra, A. (2018, April 24). Analyzing Operation GhostSecret: Attack Seeks to Steal Data Worldwide. Retrieved May 16, 2018.
- [McAfee Lazarus Jul 2020](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/operation-north-star-a-job-offer-thats-too-good-to-be-true/?hilite=%27Operation%27%2C%27North%27%2C%27Star%27) — Cashman, M. (2020, July 29). Operation North Star Campaign. Retrieved December 20, 2021.
- [McAfee Lazarus Resurfaces Feb 2018](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/lazarus-resurfaces-targets-global-banks-bitcoin-users/) — Sherstobitoff, R. (2018, February 12). Lazarus Resurfaces, Targets Global Banks and Bitcoin Users. Retrieved February 19, 2018.
- [McAfee-GhostSecret-fixurl](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/analyzing-operation-ghostsecret-attack-seeks-to-steal-data-worldwide/) — Ryan Sherstobitoff. (2018, April 24). Analyzing Operation GhostSecret: Attack Seeks to Steal Data Worldwide. Retrieved August 15, 2024.
- [Microsoft DiamondSleet 2023](https://www.microsoft.com/en-us/security/blog/2023/11/22/diamond-sleet-supply-chain-compromise-distributes-a-modified-cyberlink-installer/) — Microsoft Threat Intelligence. (2023, November 22). Diamond Sleet supply chain compromise distributes a modified CyberLink installer. Retrieved March 28, 2025.
- [Microsoft Threat Actor Naming July 2023](https://learn.microsoft.com/en-us/microsoft-365/security/intelligence/microsoft-threat-actor-naming?view=o365-worldwide) — Microsoft . (2023, July 12). How Microsoft names threat actors. Retrieved November 17, 2023.
- [Microsoft ZINC disruption Dec 2017](https://blogs.microsoft.com/on-the-issues/2017/12/19/microsoft-facebook-disrupt-zinc-malware-attack-protect-customers-internet-ongoing-cyberthreats/) — Smith, B. (2017, December 19). Microsoft and Facebook disrupt ZINC malware attack to protect customers and the internet from ongoing cyberthreats. Retrieved December 20, 2017.
- [Novetta Blockbuster](https://web.archive.org/web/20160226161828/https://www.operationblockbuster.com/wp-content/uploads/2016/02/Operation-Blockbuster-Report.pdf) — Novetta Threat Research Group. (2016, February 24). Operation Blockbuster: Unraveling the Long Thread of the Sony Attack. Retrieved February 25, 2016.
- [Novetta Blockbuster Destructive Malware](https://web.archive.org/web/20160303200515/https:/operationblockbuster.com/wp-content/uploads/2016/02/Operation-Blockbuster-Destructive-Malware-Report.pdf) — Novetta Threat Research Group. (2016, February 24). Operation Blockbuster: Destructive Malware Report. Retrieved November 17, 2024.
- [Novetta Blockbuster Loaders](https://web.archive.org/web/20190508165631/https://operationblockbuster.com/wp-content/uploads/2016/02/Operation-Blockbuster-Loaders-Installers-and-Uninstallers-Report.pdf) — Novetta Threat Research Group. (2016, February 24). Operation Blockbuster: Loaders, Installers and Uninstallers Report. Retrieved November 17, 2024.
- [Novetta Blockbuster RATs](https://web.archive.org/web/20220608001455/https://www.operationblockbuster.com/wp-content/uploads/2016/02/Operation-Blockbuster-RAT-and-Staging-Report.pdf) — Novetta Threat Research Group. (2016, February 24). Operation Blockbuster: Remote Administration Tools & Content Staging Malware Report. Retrieved March 16, 2016.
- [Novetta Blockbuster Tools](https://web.archive.org/web/20220425194457/https://operationblockbuster.com/wp-content/uploads/2016/02/Operation-Blockbuster-Tools-Report.pdf) — Novetta Threat Research Group. (2016, February 24). Operation Blockbuster: Tools Report. Retrieved March 10, 2016.
- [Qualys LolZarus](https://blog.qualys.com/vulnerabilities-threat-research/2022/02/08/lolzarus-lazarus-group-incorporating-lolbins-into-campaigns) — Pradhan, A. (2022, February 8). LolZarus: Lazarus Group Incorporating Lolbins into Campaigns. Retrieved March 22, 2022.
- [RATANKBA](https://www.trendmicro.com/en_us/research/17/b/ratankba-watering-holes-against-enterprises.html) — Trend Micro. (2017, February 27). RATANKBA: Delving into Large-scale Watering Holes against Enterprises. Retrieved May 22, 2018.
- [Secureworks NICKEL ACADEMY Dec 2017](https://www.secureworks.com/about/press/media-alert-secureworks-discovers-north-korean-cyber-threat-group-lazarus-spearphishing) — Secureworks. (2017, December 15). Media Alert - Secureworks Discovers North Korean Cyber Threat Group, Lazarus, Spearphishing Financial Executives of Cryptocurrency Companies. Retrieved December 27, 2017.
- [SecureWorks WannaCry Analysis](https://www.secureworks.com/research/wcry-ransomware-analysis) — Counter Threat Unit Research Team. (2017, May 18). WCry Ransomware Analysis. Retrieved March 26, 2019.
- [SentinelOne Lazarus macOS July 2020](https://www.sentinelone.com/blog/four-distinct-families-of-lazarus-malware-target-apples-macos-platform/) — Stokes, P. (2020, July 27). Four Distinct Families of Lazarus Malware Target Apple’s macOS Platform. Retrieved August 7, 2020.
- [Treasury North Korean Cyber Groups September 2019](https://home.treasury.gov/news/press-releases/sm774) — US Treasury . (2019, September 13). Treasury Sanctions North Korean State-Sponsored Malicious Cyber Groups. Retrieved September 29, 2021.
- [TrendMicro Lazarus Nov 2018](https://blog.trendmicro.com/trendlabs-security-intelligence/lazarus-continues-heists-mounts-attacks-on-financial-organizations-in-latin-america/) — Trend Micro. (2018, November 20). Lazarus Continues Heists, Mounts Attacks on Financial Organizations in Latin America. Retrieved December 3, 2018.
- [TrendMicro macOS Dacls May 2020](https://blog.trendmicro.com/trendlabs-security-intelligence/new-macos-dacls-rat-backdoor-show-lazarus-multi-platform-attack-capability/) — Mabutas, G. (2020, May 11). New MacOS Dacls RAT Backdoor Shows Lazarus’ Multi-Platform Attack Capability. Retrieved August 10, 2020.
- [US-CERT BADCALL](https://www.us-cert.gov/sites/default/files/publications/MAR-10135536-G.PDF) — US-CERT. (2018, February 06). Malware Analysis Report (MAR) - 10135536-G. Retrieved June 7, 2018.
- [US-CERT BLINDINGCAN Aug 2020](https://us-cert.cisa.gov/ncas/analysis-reports/ar20-232a) — US-CERT. (2020, August 19). MAR-10295134-1.v1 – North Korean Remote Access Trojan: BLINDINGCAN. Retrieved August 19, 2020.
- [US-CERT FALLCHILL Nov 2017](https://www.us-cert.gov/ncas/alerts/TA17-318A) — US-CERT. (2017, November 22). Alert (TA17-318A): HIDDEN COBRA – North Korean Remote Administration Tool: FALLCHILL. Retrieved December 7, 2017.
- [US-CERT HARDRAIN March 2018](https://www.us-cert.gov/sites/default/files/publications/MAR-10135536-F.pdf) — US-CERT. (2018, February 05). Malware Analysis Report (MAR) - 10135536-F. Retrieved June 11, 2018.
- [US-CERT HIDDEN COBRA June 2017](https://www.us-cert.gov/ncas/alerts/TA17-164A) — US-CERT. (2017, June 13). Alert (TA17-164A) HIDDEN COBRA – North Korea’s DDoS Botnet Infrastructure. Retrieved July 13, 2017.
- [US-CERT HOPLIGHT Apr 2019](https://www.us-cert.gov/ncas/analysis-reports/AR19-100A) — US-CERT. (2019, April 10). MAR-10135536-8 – North Korean Trojan: HOPLIGHT. Retrieved April 19, 2019.
- [US-CERT HOTCROISSANT February 2020](https://www.us-cert.gov/ncas/analysis-reports/ar20-045d) — US-CERT. (2020, February 20). MAR-10271944-1.v1 – North Korean Trojan: HOTCROISSANT. Retrieved May 1, 2020.
- [US-CERT KEYMARBLE Aug 2018](https://www.us-cert.gov/ncas/analysis-reports/AR18-221A) — US-CERT. (2018, August 09). MAR-10135536-17 – North Korean Trojan: KEYMARBLE. Retrieved August 16, 2018.
- [US-CERT SHARPKNOT June 2018](https://www.us-cert.gov/sites/default/files/publications/MAR-10135536.11.WHITE.pdf) — US-CERT. (2018, March 09). Malware Analysis Report (MAR) - 10135536.11.WHITE. Retrieved June 13, 2018.
- [US-CERT TYPEFRAME June 2018](https://www.us-cert.gov/ncas/analysis-reports/AR18-165A) — US-CERT. (2018, June 14). MAR-10135536-12 – North Korean Trojan: TYPEFRAME. Retrieved July 13, 2018.
- [US-CERT Volgmer Nov 2017](https://www.us-cert.gov/ncas/alerts/TA17-318B) — US-CERT. (2017, November 22). Alert (TA17-318B): HIDDEN COBRA – North Korean Trojan: Volgmer. Retrieved December 7, 2017.

## 13. Limites e confiança

- O ATT&CK registra o que foi **relatado publicamente**, não tudo o que o grupo faz. Ausência de uma técnica não prova que o grupo não a usa.
- **Sobreposição de TTP não é atribuição.** Muitas técnicas são compartilhadas entre grupos e com red teams. Use a assinatura comportamental como hipótese, junto com infraestrutura, malware e contexto.
- Cobertura de detecção refere-se ao catálogo público Detection Rules, não ao seu ambiente: confira se a telemetria necessária chega ao seu SIEM.
- Ligações marcadas como _inferidas_ (EVTX por palavra-chave, relatórios por nome) devem ser verificadas.

---
Fontes: MITRE ATT&CK® (uso livre com atribuição, © The MITRE Corporation), APT4ALL (MISP Galaxy CC0/BSD-2, APT Groups & Operations CC BY 4.0, EternalLiberty, APTnotes, Ransomware Tool Matrix CC BY 4.0), Atomic Red Team (Red Canary, MIT), EVTX-to-MITRE-Attack, EVTX-ATTACK-SAMPLES, APT & CyberCriminal Campaign Collections. Gerado por [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules).
