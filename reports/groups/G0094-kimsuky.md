# Kimsuky (G0094) — Dossiê de inteligência

> **TLP:CLEAR** · gerado em 2026-10-26 a partir de fontes abertas · MITRE ATT&CK v20.0 · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0094) · [ATT&CK](https://attack.mitre.org/groups/G0094/)

**Também conhecido como:** Black Banshee, Velvet Chollima, Emerald Sleet, THALLIUM, APT43, TA427, Springtail, Earth Kumiho, PatheticSlug  
**Origem atribuída:** Coreia do Norte · **Motivação:** espionagem, financeiro · **Setores-alvo:** Sociedade civil e mídia, Educação e pesquisa, Energia, Governo, Indústria, Defesa e militar, Setor privado (genérico)  
**Registro no ATT&CK:** criado em 2019-08-26, atualizado em 2026-07-31 · referências de 2013 a 2026

## 1. Sumário executivo

- **130 técnicas** atribuídas publicamente, concentradas em **Stealth, Resource Development, Discovery**.
- **Arsenal:** 13 malware e 6 ferramentas (ex.: AppleSeed, QuasarRAT, gh0st RAT, Troll Stealer, KGH_SPY).
- **Campanhas atribuídas:** 0.
- **Cobertura de detecção pública:** 88% das técnicas têm ao menos uma regra no catálogo; **15 técnicas sem nenhuma regra pública**.
- **Origem e alvos (APT4ALL):** atribuído a **Coreia do Norte**, motivação espionagem, financeiro; setores Sociedade civil e mídia, Educação e pesquisa, Energia, Governo, Indústria; 9 países vítimas citados.
- **Onde a cobertura está:** Windows (96 técnicas com regra), EDR / XDR (83 técnicas com regra), Linux (72 técnicas com regra), Outros / genérico (65 técnicas com regra).
- **Assinatura comportamental** (técnicas raras entre os 178 grupos, as mais úteis para atribuição): T1132.002 Non-Standard Encoding, T1176.001 Browser Extensions, T1185 Browser Session Hijacking, T1546.001 Change Default File Association, T1593.002 Search Engines.

## 2. Quem é

> Kimsuky is a Democratic People's Republic of Korea (DPRK)-based cyber espionage group that has been active since at least 2012. The group initially targeted South Korean government agencies, think tanks, and subject-matter experts in various fields. Its operations expanded to include the United Nations and organizations in the government, education, business services, and manufacturing sectors across the United States, Japan, Russia, and Europe. Kimsuky has focused collection on foreign policy and national security issues tied to the Korean Peninsula, nuclear policy, and sanctions. Kimsuky operations have overlapped with those of other North Korean state-sponsored cyber espionage actors as a result of ad hoc collaborations or other limited resource sharing. 
> 
> Kimsuky was assessed to be responsible for the 2014 Korea Hydro & Nuclear Power Co. compromise; other notable campaigns include Operation STOLEN PENCIL (2018), Operation Kabar Cobra (2019), and Operation Smoke Screen (2019). In 2023, Kimsuky was observed using commercial large language models (LLMs) to assist with vulnerability research, scripting, social engineering and reconnaissance.
> 
> DPRK threat actor cluster boundaries overlap in open source reporting, with some security researchers consolidating all attributed North Korean state-sponsored cyber activity under Lazarus Group, rather than tracking operationally distinct subgroups.

_Texto original do MITRE ATT&CK, em inglês._

## 3. Contexto, nomes e alvos

Consolidado pelo [APT4ALL](https://github.com/Ridd1kulusC0d3r/apt4all) a partir de MISP Galaxy, planilha APT Groups & Operations, EternalLiberty e APTnotes. Atribuição é afirmação de quem publicou; confira a fonte.

| Campo | Valor |
|---|---|
| Origem atribuída | Coreia do Norte |
| Motivação | espionagem, financeiro |
| Setores-alvo | Sociedade civil e mídia, Educação e pesquisa, Energia, Governo, Indústria, Defesa e militar, Setor privado (genérico) |
| Vítimas citadas | China, France, Germany, India, Japan, Korea Institute for Defense Analyses, Ministry of Unification, North America, Russia, Sejong Institute, South Africa, South Korea, United Kingdom |
| Alvos (planilha) | This threat actor targets South Korean think tanks, industry, nuclear power operators, and the Ministry of Unification for espionage purposes. |
| Operações conhecidas | Campaign Rifle, Honeybee |
| Confiança de atribuição (MISP) | 50 |

**Como cada fornecedor chama este grupo** (útil para cruzar relatórios):

| Fornecedor | Nome(s) |
|---|---|
| CrowdStrike | Velvet Chollima, Archipelago |
| MITRE ATT&CK | G0094 |
| Microsoft | Emerald Sleet, THALLIUM (antigo · old) |

**Outros nomes no APT4ALL (não listados pelo ATT&CK):** Kimsuki, TA408, TAG-115, CloudDragon, TA406, SharpTongue, Crooked Pisces, Osmium, Cerium, Archipelago, Ruby Sleet, Operation Stolen Pencil, Sparkling Pisces, Opal Sleet, Konni, Vedalia, Osmium/Opal Sleet, Nickel Juniper, UNC1130/UNC3782/UNC4469/APT43, TA406/TA427, Thallium/Cerium/Ruby Sleet/Emerald Sleet, ITG16, Nickel Kimball, APT-C-55, Larva-24005, UAT-5394

## 4. Perfil TTP por tática (kill chain)

Cada linha: técnica, como o grupo a usou segundo relatos públicos, e o que existe para detectar e testar.

### Reconnaissance (TA0043) — 10

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1589.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1589.002) Email Addresses | Kimsuky has collected valid email addresses including personal accounts that were subsequently used for spearphishing and other forms of social engineering. | 5 | — | — |
| [T1589.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1589.003) Employee Names | Kimsuky has collected victim employee name information. | 1 | — | — |
| [T1591](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1591) Gather Victim Org Information | Kimsuky has collected victim organization information including but not limited to organization hierarchy, functions, press releases, and others. Kimsuky has also used large language models (LLMs) to gather information about potential targets of interest. | 2 | — | — |
| [T1593.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1593.001) Social Media | Kimsuky has used Twitter to monitor potential victims and to prepare targeted phishing e-mails. | **0** | — | — |
| [T1593.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1593.002) Search Engines | Kimsuky has searched for vulnerabilities, tools, and geopolitical trends on Google to target victims. | **0** | — | — |
| [T1594](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1594) Search Victim-Owned Websites | Kimsuky has searched for information on the target company's website. | **0** | — | — |
| [T1596](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1596) Search Open Technical Databases | Kimsuky has used LLMs to better understand publicly reported vulnerabilities. | 1 | — | — |
| [T1598](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1598) Phishing for Information | Kimsuky has used tailored spearphishing emails to gather victim information including contat lists to identify additional targets. | 4 | — | — |
| [T1598.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1598.003) Spearphishing Link | Kimsuky has used links in e-mail to steal account information including web beacons for target profiling. Kimsuky has also utilized QR codes (also known as Quishing) to direct victims to malicious links through the reliance of a mobile device to scan a code wi… | **0** | — | — |
| [T1682](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1682) Query Public AI Services | Kimsuky has used LLMs to identify think tanks, government organizations, and experts to inform targeting for spearphishing campaigns. | **0** | — | — |

### Resource Development (TA0042) — 15

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1583](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1583) Acquire Infrastructure | Kimsuky has used funds from stolen and laundered cryptocurrency to acquire operational infrastructure. | 9 | — | — |
| [T1583.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1583.001) Domains | Kimsuky has registered domains to spoof targeted organizations and trusted third parties including search engines, web platforms, and cryptocurrency exchanges. | 7 | — | — |
| [T1583.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1583.004) Server | Kimsuky has purchased hosting servers with virtual currency and prepaid cards. | **0** | — | — |
| [T1583.006](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1583.006) Web Services | Kimsuky has hosted content used for targeting efforts via web services such as Blogspot. Kimsuky has also leveraged Dropbox for hosting payloads and uploading victim system information. | 2 | — | — |
| [T1584.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1584.001) Domains | Kimsuky has compromised legitimate sites and used them to distribute malware. | 3 | — | — |
| [T1585](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1585) Establish Accounts | Kimsuky has leveraged stolen PII to create accounts. | 1 | — | — |
| [T1585.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1585.001) Social Media Accounts | Kimsuky has created social media accounts to monitor news and security trends as well as potential targets. | 4 | — | — |
| [T1585.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1585.002) Email Accounts | Kimsuky has created email accounts for phishing operations. | **0** | — | — |
| [T1586.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1586.002) Email Accounts | Kimsuky has compromised email accounts to send spearphishing e-mails. | 3 | — | — |
| [T1587](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1587) Develop Capabilities | Kimsuky created and used a mailing toolkit to use in spearphishing attacks. | 22 | — | — |
| [T1587.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1587.001) Malware | Kimsuky has developed its own unique malware such as MailFetch.py for use in operations. | 43 | — | — |
| [T1588.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1588.002) Tool | Kimsuky has obtained and used tools such as Nirsoft WebBrowserPassVIew, Mimikatz, and PsExec. | 35 | — | — |
| [T1588.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1588.003) Code Signing Certificates | Kimsuky has stolen a valid certificate that is used to sign the malware and the dropper. | 1 | — | — |
| [T1588.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1588.005) Exploits | Kimsuky has obtained exploit code for various CVEs. | **0** | — | — |
| [T1608.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1608.001) Upload Malware | Kimsuky has used compromised and acquired infrastructure to host and deliver malware including Blogspot to host beacons, file exfiltrators, and implants. Kimsuky has also hosted malicious payloads on Dropbox. | 3 | — | — |

### Initial Access (TA0001) — 6

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1078.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.003) Local Accounts | Kimsuky has used a tool called GREASE to add a Windows admin account in order to allow them continued access via RDP. | 32 | 13 | — |
| [T1133](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1133) External Remote Services | Kimsuky has used RDP to establish persistence. | 361 | 1 | — |
| [T1190](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1190) Exploit Public-Facing Application | Kimsuky has exploited various vulnerabilities for initial access, including Microsoft Exchange vulnerability CVE-2020-0688. | 580 | — | — |
| [T1566](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1566) Phishing | Kimsuky has used spearphishing to gain initial access and intelligence. | 286 | — | — |
| [T1566.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1566.001) Spearphishing Attachment | Kimsuky has used emails containing Word, Excel and/or HWP (Hangul Word Processor) documents in their spearphishing campaigns. Kimsuky has also distributed emails with attached compressed zip files that contained malicious .LNK files masquerading as legitimate … | 230 | 2 | — |
| [T1566.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1566.002) Spearphishing Link | Kimsuky has sent spearphishing emails containing a link to a document that contained malicious macros or took the victim to an actor-controlled domain. | 138 | 1 | — |

### Execution (TA0002) — 11

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1053.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1053.005) Scheduled Task | Kimsuky has downloaded additional malware with scheduled tasks. Kimsuky has established persistence by creating a scheduled task named “ChromeUpdateTaskMachine” through the PowerShell cmdlet `Register-ScheduleTask` which was set to execute another PowerShell s… | 248 | 14 | 11 |
| [T1059.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.001) PowerShell | Kimsuky has executed a variety of PowerShell scripts including Invoke-Mimikatz. Kimsuky has also utilized PowerShell scripts for execution, persistence, and defense evasion. Kimsuky has leveraged PowerShell’s cmdlet `Expand-Archive` to extract contents of zip … | 1340 | 22 | 15 |
| [T1059.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.003) Windows Command Shell | Kimsuky has executed Windows commands by using `cmd` and running batch scripts. Kimsuky has also used `cmd.exe` to automatically open downloaded decoy pdf documents with the system’s default PDF viewer. Kimsuky has utilized malicious payloads to create reverse… | 269 | 6 | 1 |
| [T1059.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.005) Visual Basic | Kimsuky has used Visual Basic to download malicious payloads. Kimsuky has also used malicious VBA macros within maldocs disguised as forms that trigger when a victim types any content into the lure. Kimsuky has also leveraged VBScript (VBS) scripts to execute … | 192 | 3 | — |
| [T1059.006](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.006) Python | Kimsuky has used a macOS Python implant to gather data as well as MailFetcher.py code to automatically collect email data. | 122 | — | — |
| [T1059.007](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.007) JavaScript | Kimsuky has used JScript for logging and downloading additional tools. Kimsuky has used TRANSLATEXT, which contained four Javascript files for bypassing defenses, collecting sensitive information and screenshots, and exfiltrating data. | 205 | 5 | — |
| [T1106](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1106) Native API | Kimsuky has utilized Native APIs to collect data from victim hosts and facilitate execution of malicious scripts. | 118 | 5 | — |
| [T1204.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1204.001) Malicious Link | Kimsuky has lured victims into clicking malicious links. | 52 | — | — |
| [T1204.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1204.002) Malicious File | Kimsuky has used spearphishing attachments to entice victims into opening malicious files, including LNK files disguised with tailored filenames and fake extensions. Kimsuky has also delivered malicious payloads within archive files (e.g., ZIP), which display … | 259 | 13 | — |
| [T1204.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1204.004) Malicious Copy and Paste | Kimsuky has leveraged ClickFix type tactics enticing victims to copy and paste malicious code. | 32 | — | — |
| [T1559.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1559.001) Component Object Model | Kimsuky has leveraged Component Object Model (COM) to create scheduled tasks to include using naming conventions that mimic legitimate applications. Kimsuky has leveraged obfuscation VBScript to form a string in `WScript.Shell` which has downloaded a malicious… | 35 | — | — |

### Persistence (TA0003) — 12

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1053.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1053.005) Scheduled Task | Kimsuky has downloaded additional malware with scheduled tasks. Kimsuky has established persistence by creating a scheduled task named “ChromeUpdateTaskMachine” through the PowerShell cmdlet `Register-ScheduleTask` which was set to execute another PowerShell s… | 248 | 14 | 11 |
| [T1078.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.003) Local Accounts | Kimsuky has used a tool called GREASE to add a Windows admin account in order to allow them continued access via RDP. | 32 | 13 | — |
| [T1098.007](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1098.007) Additional Local or Domain Groups | Kimsuky has added accounts to specific groups with net localgroup. | 10 | — | — |
| [T1112](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1112) Modify Registry | Kimsuky has modified Registry settings for default file associations to enable all macros and for persistence. Kimsuky has also modified the registry entry for `HKCU:\Software\Microsoft\Windows\CurrentVersion\Run` registry key for persistence with the name Win… | 601 | 92 | 3 |
| [T1133](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1133) External Remote Services | Kimsuky has used RDP to establish persistence. | 361 | 1 | — |
| [T1136.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1136.001) Local Account | Kimsuky has created accounts with net user. | 103 | 10 | — |
| [T1176.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1176.001) Browser Extensions | Kimsuky has used Google Chrome browser extensions to infect victims and to steal passwords and cookies. | 15 | — | — |
| [T1205](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1205) Traffic Signaling | Kimsuky has used TRANSLATEXT to redirect clients to legitimate Gmail, Naver or Kakao pages if the clients connect with no parameters. | 4 | — | — |
| [T1505.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1505.003) Web Shell | Kimsuky has used modified versions of open source PHP web shells to maintain access, often adding "Dinosaur" references within the code. | 210 | 1 | — |
| [T1543.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1543.003) Windows Service | Kimsuky has created new services for persistence. | 1916 | 6 | 19 |
| [T1546.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1546.001) Change Default File Association | Kimsuky has a HWP document stealer module which changes the default program association in the registry to open HWP documents. | 27 | 1 | — |
| [T1547.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1547.001) Registry Run Keys / Startup Folder | Kimsuky has placed scripts in the startup folder for persistence and modified the `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce` Registry key. | 299 | 21 | 2 |

### Privilege Escalation (TA0004) — 9

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1053.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1053.005) Scheduled Task | Kimsuky has downloaded additional malware with scheduled tasks. Kimsuky has established persistence by creating a scheduled task named “ChromeUpdateTaskMachine” through the PowerShell cmdlet `Register-ScheduleTask` which was set to execute another PowerShell s… | 248 | 14 | 11 |
| [T1055](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1055) Process Injection | Kimsuky has used Win7Elevate to inject malicious code into explorer.exe. | 481 | 13 | 4 |
| [T1055.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1055.001) Dynamic-link Library Injection | Kimsuky has the ability to load DLLs via reflective injection by allocating memory using `VirtualAllocEx()`, then decrypting a DLL with `WriteProcessMemory()` and invoking execution through `CreateRemoteThread()`. | 40 | 2 | — |
| [T1055.012](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1055.012) Process Hollowing | Kimsuky has used a file injector DLL to spawn a benign process on the victim's system and inject the malicious payload into it via process hollowing. | 29 | 4 | 2 |
| [T1078.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.003) Local Accounts | Kimsuky has used a tool called GREASE to add a Windows admin account in order to allow them continued access via RDP. | 32 | 13 | — |
| [T1098.007](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1098.007) Additional Local or Domain Groups | Kimsuky has added accounts to specific groups with net localgroup. | 10 | — | — |
| [T1543.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1543.003) Windows Service | Kimsuky has created new services for persistence. | 1916 | 6 | 19 |
| [T1546.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1546.001) Change Default File Association | Kimsuky has a HWP document stealer module which changes the default program association in the registry to open HWP documents. | 27 | 1 | — |
| [T1547.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1547.001) Registry Run Keys / Startup Folder | Kimsuky has placed scripts in the startup folder for persistence and modified the `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce` Registry key. | 299 | 21 | 2 |

### Stealth (TA0005) — 31

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1027](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1027) Obfuscated Files or Information | Kimsuky has obfuscated binary strings including the use of XOR encryption and Base64 encoding. Kimsuky has also modified the first byte of DLL implants targeting victims to prevent recognition of the executable file format. Kimsuky has obfuscated strings using… | 520 | 11 | 5 |
| [T1027.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1027.001) Binary Padding | Kimsuky has performed padding of PowerShell command line code with over 100 spaces. | 13 | 3 | — |
| [T1027.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1027.002) Software Packing | Kimsuky has packed malware with UPX. | 12 | 4 | — |
| [T1027.007](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1027.007) Dynamic API Resolution | Kimsuky has leveraged dynamic API resolution using custom hashing techniques. | 2 | 1 | — |
| [T1027.010](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1027.010) Command Obfuscation | Kimsuky has encoded malicious PowerShell scripts using Base64. | 78 | — | — |
| [T1027.012](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1027.012) LNK Icon Smuggling | Kimsuky has used the LNK icon location to execute malicious scripts. Kimsuky has also padded the LNK target field properties with extra spaces to obscure the script. | 1 | — | — |
| [T1027.013](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1027.013) Encrypted/Encoded File | Kimsuky has obfuscated code within files by converting hexadecimal strings to decimal numbers using the `CLng function` in combination with processing arithmetic operations and leveraging the `Chr function` to generate readable characters. Kimsuky has also enc… | 8 | 4 | — |
| [T1027.015](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1027.015) Compression | Kimsuky has delivered malicious payloads within Zip archives. | 3 | — | — |
| [T1027.016](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1027.016) Junk Code Insertion | Kimsuky has obfuscated code by filling scripts with junk code and concatenating strings to hamper analysis and detection. | **0** | — | — |
| [T1036.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1036.004) Masquerade Task or Service | Kimsuky has disguised services to appear as benign software or related to operating system functions. | 31 | 4 | — |
| [T1036.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1036.005) Match Legitimate Resource Name or Location | Kimsuky has renamed malware to legitimate names such as ESTCommon.dll or patch.dll. Kimsuky has also disguised payloads using legitimate file names including a PowerShell payload named chrome.ps1. Kimsuky has also used a malicious QR code that masqueraded as a… | 116 | 4 | — |
| [T1036.007](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1036.007) Double File Extension | Kimsuky has used an additional filename extension to hide the true file type. Kimsuky has also masqueraded malicious LNK files as PDF objects using the double extension .pdf.lnk. | 25 | — | — |
| [T1055](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1055) Process Injection | Kimsuky has used Win7Elevate to inject malicious code into explorer.exe. | 481 | 13 | 4 |
| [T1055.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1055.001) Dynamic-link Library Injection | Kimsuky has the ability to load DLLs via reflective injection by allocating memory using `VirtualAllocEx()`, then decrypting a DLL with `WriteProcessMemory()` and invoking execution through `CreateRemoteThread()`. | 40 | 2 | — |
| [T1055.012](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1055.012) Process Hollowing | Kimsuky has used a file injector DLL to spawn a benign process on the victim's system and inject the malicious payload into it via process hollowing. | 29 | 4 | 2 |
| [T1070.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1070.004) File Deletion | Kimsuky has deleted the exfiltrated data on disk after transmission. Kimsuky has also used an instrumentor script to terminate browser processes running on an infected system and then delete the cookie files on disk. Kimsuky has deleted files using the `Remove… | 132 | 11 | — |
| [T1070.006](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1070.006) Timestomp | Kimsuky has manipulated timestamps for creation or compilation dates to defeat anti-forensics. | 28 | 10 | 3 |
| [T1078.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.003) Local Accounts | Kimsuky has used a tool called GREASE to add a Windows admin account in order to allow them continued access via RDP. | 32 | 13 | — |
| [T1140](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1140) Deobfuscate/Decode Files or Information | Kimsuky has decoded malicious VBScripts using Base64. Kimsuky has also decoded malicious PowerShell scripts using Base64. Kimsuky has decoded RC4 obfuscated files prior to downloading files from their infrastructure. | 173 | 11 | 1 |
| [T1205](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1205) Traffic Signaling | Kimsuky has used TRANSLATEXT to redirect clients to legitimate Gmail, Naver or Kakao pages if the clients connect with no parameters. | 4 | — | — |
| [T1218.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1218.005) Mshta | Kimsuky has used mshta.exe to run malicious scripts on the system. | 130 | 10 | 4 |
| [T1218.010](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1218.010) Regsvr32 | Kimsuky has executed malware with regsvr32s. | 150 | 5 | 2 |
| [T1218.011](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1218.011) Rundll32 | Kimsuky has used `rundll32.exe` to execute malicious scripts and malware on a victim's network. | 274 | 16 | 12 |
| [T1480.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1480.002) Mutual Exclusion | Kimsuky has utilized a mutex to detect whether its malware is actively running on the victim host. Kimsuky has leveraged PowerShell to store the Process ID (PID) of the currently running malicious PowerShell script into a file named pid.txt which is saved loca… | **0** | — | — |
| [T1497.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1497.001) System Checks | Kimsuky has detected and killed virtual environments by using the PowerShell cmdlet `Get-CimInstance` that searches the classname of the computer system manufacturer through an if statement of `if($computerSystem.Manufacturer -match "VMware" -or $computerSyste… | 16 | 9 | — |
| [T1564.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1564.002) Hidden Users | Kimsuky has run reg add ‘HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList’ /v to hide a newly created user. | 20 | 3 | — |
| [T1564.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1564.003) Hidden Window | Kimsuky has used an information gathering module that will hide an AV software window from the victim. Kimsuky has also been known to use `-WindowStyle Hidden` to conceal PowerShell windows. | 51 | 3 | — |
| [T1564.011](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1564.011) Ignore Process Interrupts | Kimsuky has leveraged the PowerShell `-ErrorAction SilentlyContinue` command to continue execution through system events. | **0** | — | — |
| [T1620](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1620) Reflective Code Loading | Kimsuky has used the Invoke-Mimikatz PowerShell script to reflectively load a Mimikatz credential stealing DLL into memory. Kimsuky has also used reflective loading through .NET assembly using `[System.Reflection.Assembly]::Load`. | 54 | 3 | — |
| [T1678](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1678) Delay Execution | Kimsuky has utilized the Sleep function to ensure execution of scripts. | **0** | — | — |
| [T1684.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1684.001) Impersonation | Kimsuky has also impersonated legitimate people, such as a foreign advisor, an embassy employee, and a think tank employee. Kimsuky has also purported to be a Japanese diplomat to communicate with the victims. | 1 | — | — |

### Defense Impairment (TA0112) — 4

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1112](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1112) Modify Registry | Kimsuky has modified Registry settings for default file associations to enable all macros and for persistence. Kimsuky has also modified the registry entry for `HKCU:\Software\Microsoft\Windows\CurrentVersion\Run` registry key for persistence with the name Win… | 601 | 92 | 3 |
| [T1553.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1553.002) Code Signing | Kimsuky has signed files with the name EGIS CO,. Ltd. and has stolen a valid certificate that is used to sign the malware and the dropper. | 11 | — | — |
| [T1685](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1685) Disable or Modify Tools | Kimsuky has been observed turning off Windows Security Center and can hide the AV software window from the view of the infected user. | 1275 | 78 | 19 |
| [T1686](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1686) Disable or Modify System Firewall | Kimsuky has been observed disabling the system firewall. | 56 | 25 | 6 |

### Credential Access (TA0006) — 10

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1003.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1003.001) LSASS Memory | Kimsuky has gathered credentials using Mimikatz and ProcDump. | 580 | 14 | 10 |
| [T1040](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1040) Network Sniffing | Kimsuky has used the Nirsoft SniffPass network sniffer to obtain passwords sent over non-secure protocols. | 77 | 16 | 1 |
| [T1056.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1056.001) Keylogging | Kimsuky has used a PowerShell-based keylogger as well as a tool called MECHANICAL to log keystrokes. Kimsuky has also leveraged Native Windows API functions such as `GetAsyncKeyState()` along with others to capture keystrokes every 50 milliseconds and stores d… | 40 | 8 | 1 |
| [T1056.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1056.003) Web Portal Capture | Kimsuky has collected credentials from a fake Google account login page. | **0** | — | — |
| [T1111](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1111) Multi-Factor Authentication Interception | Kimsuky has used a proprietary tool to intercept one time passwords required for two-factor authentication. | 3 | — | — |
| [T1539](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1539) Steal Web Session Cookie | Kimsuky has used malware, such as TRANSLATEXT, to steal and exfiltrate browser cookies. | 54 | 5 | — |
| [T1552.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1552.001) Credentials In Files | Kimsuky has used tools that are capable of obtaining credentials from saved mail. | 166 | 32 | — |
| [T1552.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1552.004) Private Keys | Kimsuky has accessed a Local State files associated with Chromium-based browsers that contain the AES key used to encrypt passwords stored in the browser to include `app_bound_encrypted_key`. | 60 | 17 | 1 |
| [T1555.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1555.003) Credentials from Web Browsers | Kimsuky has used browser extensions including Google Chrome to steal passwords and cookies from browsers. Kimsuky has also used Nirsoft's WebBrowserPassView tool to dump the passwords obtained from victims. | 59 | 18 | 5 |
| [T1557](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1557) Adversary-in-the-Middle | Kimsuky has used modified versions of PHProxy to examine web traffic between the victim and the accessed website. | 67 | — | 2 |

### Discovery (TA0007) — 13

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1007](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1007) System Service Discovery | Kimsuky has used an instrumentor script to gather the names of all services running on a victim's system. | 37 | 8 | — |
| [T1012](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1012) Query Registry | Kimsuky has obtained specific Registry keys and values on a compromised host. | 92 | 6 | — |
| [T1016](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1016) System Network Configuration Discovery | Kimsuky has used `ipconfig/all` and web beacons sent via email to gather network configuration information. Kimsuky has also identified Host IP addresses leveraging the WMI class `Win32_NetworkAdapterConfiguration`. | 99 | 10 | 5 |
| [T1033](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1033) System Owner/User Discovery | Kimsuky has gathered the identity of the user by querying `System.Security.Principal` namespace using the `GetCurrent()` method. | 181 | 8 | — |
| [T1040](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1040) Network Sniffing | Kimsuky has used the Nirsoft SniffPass network sniffer to obtain passwords sent over non-secure protocols. | 77 | 16 | 1 |
| [T1057](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1057) Process Discovery | Kimsuky can gather a list of all processes running on a victim's machine. Kimsuky has also obtained running processes on the victim device utilizing PowerShell cmdlet `Get-Process`. | 82 | 10 | — |
| [T1082](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1082) System Information Discovery | Kimsuky has enumerated OS type, OS version, and other information using a script or the "systeminfo" command. Kimsuky has also obtained system information such as OS type, OS version, and system type through querying various Windows Management Instrumentation … | 264 | 41 | — |
| [T1083](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1083) File and Directory Discovery | Kimsuky has the ability to enumerate all files and directories on an infected system. Kimsuky has used a custom script with a function called CreateFileList() that can scan all filesystem drives, prioritizing C:\Users, to locate files and file extensions of in… | 137 | 9 | — |
| [T1124](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1124) System Time Discovery | Kimsuky has gathered the system time of the device using the PowerShell cmdlet `Get-Date`. | 18 | 6 | — |
| [T1217](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1217) Browser Information Discovery | Kimsuky has collected sensitive browser data using the function `GetBrowserData()` to include login credentials, bookmarks, cookies, and encryption keys. | 19 | 11 | — |
| [T1497.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1497.001) System Checks | Kimsuky has detected and killed virtual environments by using the PowerShell cmdlet `Get-CimInstance` that searches the classname of the computer system manufacturer through an if statement of `if($computerSystem.Manufacturer -match "VMware" -or $computerSyste… | 16 | 9 | — |
| [T1518.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1518.001) Security Software Discovery | Kimsuky has checked for the presence of antivirus software with powershell Get-CimInstance -Namespace root/securityCenter2 – classname antivirusproduct. Kimsuky has also obtained details on antivirus software through WMI queries using `Win32_OperatingSystem` a… | 54 | 12 | — |
| [T1680](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1680) Local Storage Discovery | Kimsuky has enumerated drives. | **0** | — | — |

### Lateral Movement (TA0008) — 3

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1021.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1021.001) Remote Desktop Protocol | Kimsuky has used RDP for direct remote point-and-click access. | 139 | 4 | 7 |
| [T1534](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1534) Internal Spearphishing | Kimsuky has sent internal spearphishing emails for lateral movement after stealing victim information. | 5 | — | — |
| [T1550.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1550.002) Pass the Hash | Kimsuky has used pass the hash for authentication to remote access software used in C2. | 43 | 3 | 1 |

### Collection (TA0009) — 12

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1005) Data from Local System | Kimsuky has collected Office, PDF, and HWP documents from its victims. Kimsuky has also harvested victim files through the use of the `RecentFiles()` function that collects paths of recently accessed files by parsing .lnk shortcuts from `%APPDATA%\Microsoft\Wi… | 170 | 3 | — |
| [T1056.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1056.001) Keylogging | Kimsuky has used a PowerShell-based keylogger as well as a tool called MECHANICAL to log keystrokes. Kimsuky has also leveraged Native Windows API functions such as `GetAsyncKeyState()` along with others to capture keystrokes every 50 milliseconds and stores d… | 40 | 8 | 1 |
| [T1056.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1056.003) Web Portal Capture | Kimsuky has collected credentials from a fake Google account login page. | **0** | — | — |
| [T1074.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1074.001) Local Data Staging | Kimsuky has staged collected data files under C:\Program Files\Common Files\System\Ole DB\. Kimsuky has also gathered data in structured directories prior to exfiltration under the %TEMP% environment variable. | 37 | 3 | — |
| [T1113](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1113) Screen Capture | Kimsuky has captured browser screenshots using TRANSLATEXT. Kimsuky has also obtained screen captures with custom malware. | 60 | 10 | — |
| [T1114.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1114.002) Remote Email Collection | Kimsuky has used tools such as the MailFetch mail crawler to collect victim emails (excluding spam) from online services via IMAP. | 11 | 1 | — |
| [T1114.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1114.003) Email Forwarding Rule | Kimsuky has set auto-forward rules on victim's e-mail accounts. | 10 | 1 | — |
| [T1115](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1115) Clipboard Data | Kimsuky has the ability to steal data from the clipboard. | 33 | 5 | — |
| [T1185](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1185) Browser Session Hijacking | Kimsuky has the ability to use form-grabbing to extract emails and passwords from web data forms. | 13 | — | — |
| [T1557](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1557) Adversary-in-the-Middle | Kimsuky has used modified versions of PHProxy to examine web traffic between the victim and the accessed website. | 67 | — | 2 |
| [T1560.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1560.001) Archive via Utility | Kimsuky has used QuickZip to archive stolen files before exfiltration. Kimsuky has used the Send() function to compress all collected data into a zip file named init,.zip, then renames it to init.dat, before exfiltration. | 76 | 13 | — |
| [T1560.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1560.003) Archive via Custom Method | Kimsuky has used RC4 encryption before exfil. | 1 | — | — |

### Command and Control (TA0011) — 10

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1071.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1071.001) Web Protocols | Kimsuky has used HTTP GET and POST requests for C2. | 228 | 3 | — |
| [T1071.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1071.002) File Transfer Protocols | Kimsuky has used FTP to download additional malware to the target machine. | 3 | — | — |
| [T1071.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1071.003) Mail Protocols | Kimsuky has used e-mail to send exfiltrated data to C2 servers. | 6 | — | — |
| [T1102.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1102.001) Dead Drop Resolver | Kimsuky has used TRANSLATEXT and a dead drop resolver to retrieve configurations and commands from a public blog site. | 18 | — | — |
| [T1102.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1102.002) Bidirectional Communication | Kimsuky has used Blogspot pages and a Github repository for C2. Kimsuky has also leveraged Dropbox for downloading payloads and uploading victim system information. | 27 | — | — |
| [T1105](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1105) Ingress Tool Transfer | Kimsuky has downloaded additional scripts, tools, and malware onto victim systems. | 644 | 39 | — |
| [T1132.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1132.002) Non-Standard Encoding | Kimsuky has obfuscated HTTP Post request communications utilizing XOR with a designated key, followed by Base64 encoding. | **0** | — | — |
| [T1205](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1205) Traffic Signaling | Kimsuky has used TRANSLATEXT to redirect clients to legitimate Gmail, Naver or Kakao pages if the clients connect with no parameters. | 4 | — | — |
| [T1219.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1219.002) Remote Desktop Software | Kimsuky has used a modified TeamViewer client as a command and control channel. | 221 | — | — |
| [T1568](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1568) Dynamic Resolution | Kimsuky has used Dynamic DNS (DDNS) services, such as FreeDNS or No-IP DDNS, to include servers located in South Korea. | 32 | — | — |

### Exfiltration (TA0010) — 3

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1020](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1020) Automated Exfiltration | Kimsuky has exfiltrated data to C2 servers using an automated script that executes every 10 minutes and after successful checks for the presence of pre-designated staged filenames. | 69 | 2 | — |
| [T1041](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1041) Exfiltration Over C2 Channel | Kimsuky has exfiltrated data over its C2 channel. | 135 | 2 | — |
| [T1567.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1567.002) Exfiltration to Cloud Storage | Kimsuky has exfiltrated stolen files and data to actor-controlled Blogspot accounts. Kimsuky has also leveraged Dropbox for uploading victim system information. | 85 | 2 | — |

### Impact (TA0040) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1489](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1489) Service Stop | Kimsuky has disabled actively running virtual environments using the `KillMe` function to include VMware, Microsoft Hypervisors, and VirtualBox. | 112 | 9 | — |
| [T1657](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1657) Financial Theft | Kimsuky has stolen and laundered cryptocurrency to self-fund operations including the acquisition of infrastructure. | 2 | — | — |

## 5. Assinatura comportamental

Técnicas que este grupo usa e que poucos dos 178 grupos do ATT&CK usam. Pesam mais numa atribuição por TTP: ver várias delas juntas é mais informativo do que ver técnicas comuns como PowerShell.

| Técnica | Outros grupos que usam | Peso (raridade) |
|---|---:|---:|
| T1132.002 Non-Standard Encoding | 0 | 4.49 |
| T1176.001 Browser Extensions | 0 | 4.49 |
| T1185 Browser Session Hijacking | 0 | 4.49 |
| T1546.001 Change Default File Association | 0 | 4.49 |
| T1593.002 Search Engines | 0 | 4.49 |
| T1036.007 Double File Extension | 1 | 4.09 |
| T1056.003 Web Portal Capture | 1 | 4.09 |
| T1480.002 Mutual Exclusion | 1 | 4.09 |
| T1564.002 Hidden Users | 1 | 4.09 |
| T1596 Search Open Technical Databases | 1 | 4.09 |

## 6. Arsenal

| Software | Tipo | Técnicas no ATT&CK | Uso relatado (EN) |
|---|---|---:|---|
| [AppleSeed](https://attack.mitre.org/software/S0622/) | malware | 32 |  |
| [QuasarRAT](https://attack.mitre.org/software/S0262/) | ferramenta | 25 |  |
| [gh0st RAT](https://attack.mitre.org/software/S0032/) | malware | 24 |  |
| [Troll Stealer](https://attack.mitre.org/software/S1196/) | malware | 22 | Troll Stealer is exclusively linked to Kimsuky operations. |
| [KGH_SPY](https://attack.mitre.org/software/S0526/) | malware | 20 |  |
| [Amadey](https://attack.mitre.org/software/S1025/) | malware | 17 |  |
| [Mimikatz](https://attack.mitre.org/software/S0002/) | ferramenta | 17 |  |
| [NOKKI](https://attack.mitre.org/software/S0353/) | malware | 16 |  |
| [BabyShark](https://attack.mitre.org/software/S0414/) | malware | 16 |  |
| [TRANSLATEXT](https://attack.mitre.org/software/S1201/) | malware | 15 |  |
| [Gomir](https://attack.mitre.org/software/S1198/) | malware | 14 | Gomir is uniquely associated with Kimsuky operations. |
| [Gold Dragon](https://attack.mitre.org/software/S0249/) | malware | 14 |  |
| [HTTPTroy](https://attack.mitre.org/software/S9007/) | malware | 13 |  |
| [CSPY Downloader](https://attack.mitre.org/software/S0527/) | ferramenta | 12 |  |
| [Brave Prince](https://attack.mitre.org/software/S0252/) | malware | 7 |  |
| [PsExec](https://attack.mitre.org/software/S0029/) | ferramenta | 5 |  |
| [certutil](https://attack.mitre.org/software/S0160/) | ferramenta | 4 | Kimsuky has utilized certutil to decode a malicious payload. |
| [GoBear](https://attack.mitre.org/software/S1197/) | malware | 3 | GoBear is exclusively linked to Kimsuky operations. |
| [schtasks](https://attack.mitre.org/software/S0111/) | ferramenta | 1 |  |

**Outras ferramentas e malware relatados (planilha APT Groups & Operations / MISP):** KPortScan, Procdump, Eternal suite of exploits, Mechanical, Grease

## 7. Campanhas

Nenhuma campanha atribuída no ATT&CK.

## 8. Cobertura defensiva

**115 de 130 técnicas (88%)** têm ao menos uma regra pública no catálogo Detection Rules.

### Técnicas sem regra pública (prioridade para engenharia de detecção)

- **T1132.002 Non-Standard Encoding** — Command and Control. Fonte de log sugerida pelo MITRE: `WinEventLog:Security` EventCode=4688; `auditd:SYSCALL` execve of interpreters (python, perl), custom binaries, or shell utilities with long arguments containing non-standard tokens; `macos:endpointse
- **T1593.002 Search Engines** — Reconnaissance
- **T1056.003 Web Portal Capture** — Collection. Fonte de log sugerida pelo MITRE: `auditd:SYSCALL` write; `WinEventLog:Sysmon` EventCode=11; `fs:fsusage` Filesystem Access Logging
- **T1480.002 Mutual Exclusion** — Stealth. Fonte de log sugerida pelo MITRE: `WinEventLog:Sysmon` EventCode=1; `auditd:SYSCALL` open, flock, fcntl, unlink; `macos:unifiedlog` flock|NSDistributedLock|FileHandle.*lockForWriting
- **T1682 Query Public AI Services** — Reconnaissance
- **T1588.005 Exploits** — Resource Development
- **T1593.001 Social Media** — Reconnaissance
- **T1564.011 Ignore Process Interrupts** — Stealth. Fonte de log sugerida pelo MITRE: `auditd:SYSCALL` execve call including 'nohup' or trailing '&'; `WinEventLog:PowerShell` EventCode=4103, 4104, 4105, 4106; `macos:unifiedlog` nohup, disown, or osascript execution patterns
- **T1678 Delay Execution** — Stealth. Fonte de log sugerida pelo MITRE: `WinEventLog:Sysmon` EventCode=1; `auditd:SYSCALL` execve or nanosleep with no stdout/stderr I/O; `macos:unifiedlog` launchd or osascript spawns process with delay command
- **T1594 Search Victim-Owned Websites** — Reconnaissance. Fonte de log sugerida pelo MITRE: `Application Log` None
- **T1027.016 Junk Code Insertion** — Stealth. Fonte de log sugerida pelo MITRE: `WinEventLog:Sysmon` EventCode=11; `auditd:SYSCALL` write; `macos:endpointsecurity` ES_EVENT_TYPE_NOTIFY_EXEC
- **T1583.004 Server** — Resource Development. Fonte de log sugerida pelo MITRE: `Internet Scan` None
- **T1680 Local Storage Discovery** — Discovery. Fonte de log sugerida pelo MITRE: `WinEventLog:Sysmon` EventCode=1; `auditd:SYSCALL` execve call with argv matching known disk enumeration commands (lsblk, parted, fdisk); `macos:unifiedlog` process launch of diskutil or system_profil
- **T1598.003 Spearphishing Link** — Reconnaissance. Fonte de log sugerida pelo MITRE: `Application Log` None
- **T1585.002 Email Accounts** — Resource Development

### Onde procurar — cobertura por tecnologia

Quantas técnicas deste grupo têm ao menos uma regra em cada tecnologia. Comece a caça pelas tecnologias que você tem e que aparecem aqui.

| Tecnologia | Técnicas do grupo com regra |
|---|---:|
| Windows | 96 |
| EDR / XDR | 83 |
| Linux | 72 |
| Outros / genérico | 65 |
| macOS | 61 |
| Servidores web & aplicações | 53 |
| E-mail | 48 |
| Firewall & perímetro | 46 |
| Microsoft 365 | 46 |
| DNS | 43 |
| AWS | 43 |
| IA, LLMs & agentes | 42 |

### Regras recomendadas por técnica

Melhor regra disponível por técnica (formato portável e maduro primeiro).

| Técnica | Regra | Formato | Fonte |
|---|---|---|---|
| T1003.001 | [Antivirus - Password Dumper Signature](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A78cc2dd2-7d20-4d32-93ff-057084c38b93) | Sigma | SigmaHQ |
| T1003.001 | [Mimikatz through Windows Remote Management](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Aaa35a627-33fb-4d04-a165-d33b4afca3e8) | Sigma | OpenSearch Security Analytics |
| T1005 | [Potential Conti Ransomware Database Dumping Activity Via SQLCmd](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A2f47f1fd-0901-466e-a770-3b7092834a1b) | Sigma | SigmaHQ |
| T1005 | [OpenCanary - SMB File Open Request](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A22777c9e-873a-4b49-855f-6072ab861a52) | Sigma | SigmaHQ |
| T1007 | [HackTool - PCHunter Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Afca949cc-79ca-446e-8064-01aa7e52ece5) | Sigma | SigmaHQ |
| T1007 | [SC.EXE Query Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A57712d7a-679c-4a41-a913-87e7175ae429) | Sigma | SigmaHQ |
| T1012 | [Potential Baby Shark Malware Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A2b30fa36-3a18-402f-a22d-bf4ce2189f35) | Sigma | SigmaHQ |
| T1012 | [Operation Wocao Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1cfac73c-be78-4f9a-9b08-5bde0c3953ab) | Sigma | SigmaHQ |
| T1016 | [Potential Pikabot Discovery Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A698d4431-514f-4c82-af4d-cf573872a9f5) | Sigma | SigmaHQ |
| T1016 | [OpenCanary - SNMP OID Request](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae9856028-fd4e-46e6-b3d1-10f7ceb95078) | Sigma | SigmaHQ |
| T1020 | [Restore Public AWS RDS Instance](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac3f265c7-ff03-4056-8ab2-d486227b4599) | Sigma | SigmaHQ |
| T1020 | [Restore Public AWS RDS Instance](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Ac3f265c7-ff03-4056-8ab2-d486227b4599) | Sigma | OpenSearch Security Analytics |
| T1021.001 | [Hermetic Wiper TG Process Patterns](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A2f974656-6d83-4059-bbdf-68ac5403422f) | Sigma | SigmaHQ |
| T1021.001 | [Publicly Accessible RDP Service](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1fc0809e-06bf-4de3-ad52-25e5263b7623) | Sigma | SigmaHQ |
| T1027 | [Potential Emotet Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad02e8cf5-6099-48cf-9bfc-1eec2d0c7b18) | Sigma | SigmaHQ |
| T1027 | [Emotet Process Creation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Ad02e8cf5-6099-48cf-9bfc-1eec2d0c7b18) | Sigma | OpenSearch Security Analytics |
| T1027.001 | [Binary Padding - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac52a914f-3d8b-4b2a-bb75-b3991e75f8ba) | Sigma | SigmaHQ |
| T1027.001 | [Failed Code Integrity Checks](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A470ec5fa-7b4e-4071-b200-4c753100f49b) | Sigma | SigmaHQ |
| T1027.002 | [Python Image Load By Non-Python Process](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acbb56d62-4060-40f7-9466-d8aaf3123f83) | Sigma | SigmaHQ |
| T1027.002 | [Python Py2Exe Image Load](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Acbb56d62-4060-40f7-9466-d8aaf3123f83) | Sigma | OpenSearch Security Analytics |
| T1027.007 | [Sysmon - Event 1: Process creation $(win.eventdata.description)](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=socfortress-wazuh-rules%3A%3Awazuh-101142) | Wazuh | SOCFortress Wazuh-Rules |
| T1027.007 | [Sysmon - Event 7: Image loaded by $(win.eventdata.image)](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=socfortress-wazuh-rules%3A%3Awazuh-106131) | Wazuh | SOCFortress Wazuh-Rules |
| T1027.010 | [Decoded Payload Piped to Interpreter Detected via Defend for Containers](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A0fb83aa0-3d17-41e9-b09c-56397bf7a7d9) | Elastic | Elastic detection-rules |
| T1027.010 | [Potential PowerShell Obfuscation via String Concatenation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Af6d8c743-0916-4483-8333-3c6f107e0caa) | Elastic | Elastic detection-rules |
| T1027.012 | [Rare .lnk File Created on Desktop](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=bert-janp-hunting-queries%3A%3A64f8f89949bb) | KQL hunting | Bert-JanP Hunting Queries |
| T1027.013 | [ROT Encoded Python Script Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A5ab49127-b1b3-46e6-8a38-9e8512a2a363) | Elastic | Elastic detection-rules |
| T1027.013 | [Data Encrypted via OpenSSL Utility](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Afeba48f6-40ca-4d04-b41f-5dfa327de865) | Elastic | Elastic detection-rules |
| T1027.015 | [PowerShell Suspicious Payload Encoded and Compressed](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A81fe9dc6-a2d7-4192-a2d8-eed98afc766a) | Elastic | Elastic detection-rules |
| T1027.015 | [Suspicious Content Extracted or Decompressed via Funzip](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Adc0b7782-0df0-47ff-8337-db0d678bdb66) | Elastic | Elastic detection-rules |
| T1033 | [Potential Dridex Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae6eb5a96-9e6f-4a18-9cdd-642cfda21c8e) | Sigma | SigmaHQ |
| T1033 | [Dridex Process Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Ae6eb5a96-9e6f-4a18-9cdd-642cfda21c8e) | Sigma | OpenSearch Security Analytics |
| T1036.004 | [Operation Wocao Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1cfac73c-be78-4f9a-9b08-5bde0c3953ab) | Sigma | SigmaHQ |
| T1036.004 | [Operation Wocao Activity - Security](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A74ad4314-482e-4c3e-b237-3f7ed3b9ca8d) | Sigma | SigmaHQ |
| T1036.005 | [Exploit for CVE-2015-1641](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A7993792c-5ce2-4475-a3db-a3a5539827ef) | Sigma | SigmaHQ |
| T1036.005 | [Exploit for CVE-2015-1641](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A7993792c-5ce2-4475-a3db-a3a5539827ef) | Sigma | OpenSearch Security Analytics |
| T1036.007 | [Suspicious Double Extension Files](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab4926b47-a9d7-434c-b3a0-adc3fa0bd13e) | Sigma | SigmaHQ |
| T1036.007 | [Suspicious Parent Double Extension File Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A5e6a80c8-2d45-4633-9ef4-fa2671a39c5c) | Sigma | SigmaHQ |
| T1040 | [Cisco Sniffing](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab9e1f193-d236-4451-aaae-2f3d2102120d) | Sigma | SigmaHQ |
| T1040 | [Network Sniffing - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Af4d3748a-65d1-4806-bd23-e25728081d01) | Sigma | SigmaHQ |
| T1041 | [Equation Group C2 Communication](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A881834a4-6659-4773-821e-1c151789d873) | Sigma | SigmaHQ |
| T1041 | [OpenCanary - TFTP Request](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab4e6b016-a2ac-4759-ad85-8000b300d61e) | Sigma | SigmaHQ |
| T1053.005 | [Operation Wocao Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1cfac73c-be78-4f9a-9b08-5bde0c3953ab) | Sigma | SigmaHQ |
| T1053.005 | [Operation Wocao Activity - Security](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A74ad4314-482e-4c3e-b237-3f7ed3b9ca8d) | Sigma | SigmaHQ |
| T1055 | [Potential Dridex Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae6eb5a96-9e6f-4a18-9cdd-642cfda21c8e) | Sigma | SigmaHQ |
| T1055 | [Antivirus PrinterNightmare CVE-2021-34527 Exploit Detection](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A6fe1719e-ecdf-4caf-bffe-4f501cb0a561) | Sigma | SigmaHQ |
| T1055.001 | [TAIDOOR RAT DLL Load](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad1aa3382-abab-446f-96ea-4de52908210b) | Sigma | SigmaHQ |
| T1055.001 | [Renamed ZOHO Dctask64 Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A340a090b-c4e9-412e-bb36-b4b16fe96f9b) | Sigma | SigmaHQ |
| T1055.012 | [Potential Pikabot Hollowing Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad8937fe7-42d5-4b4d-8178-e089c908f63f) | Sigma | SigmaHQ |
| T1055.012 | [HackTool - CACTUSTORCH Remote Thread Creation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A2e4e488a-6164-4811-9ea1-f960c7359c40) | Sigma | SigmaHQ |
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
| T1059.006 | [Emotet Loader Execution Via .LNK File](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1f32d820-1d5c-43fe-8fe2-feef0c952eb7) | Sigma | SigmaHQ |
| T1059.006 | [Serpent Backdoor Payload Execution Via Scheduled Task](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad5eb7432-fda4-4bba-a37f-ffa74d9ed639) | Sigma | SigmaHQ |
| T1059.007 | [Adwind RAT / JRAT](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1fac1481-2dbc-48b2-9096-753c49b4ec71) | Sigma | SigmaHQ |
| T1059.007 | [WScript or CScript Dropper - File](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A002bdb95-0cf1-46a6-9e08-d38c128a6127) | Sigma | SigmaHQ |
| T1070.004 | [File Deletion](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A30aed7b6-d2c1-4eaf-9382-b6bc43e50c57) | Sigma | SigmaHQ |
| T1070.004 | [Prefetch File Deleted](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A0a1f9d29-6465-4776-b091-7f43b26e4c89) | Sigma | SigmaHQ |
| T1070.006 | [File Creation Date Changed to Another Year](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A558eebe5-f2ba-4104-b339-36f7902bcc1a) | Sigma | SigmaHQ |
| T1070.006 | [Touch Suspicious Service File](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A31545105-3444-4584-bebf-c466353230d2) | Sigma | SigmaHQ |
| T1071.001 | [Ursnif Malware Download URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aa36ce77e-30db-4ea0-8795-644d7af5dfb4) | Sigma | SigmaHQ |
| T1071.001 | [Ursnif Malware C2 URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A932ac737-33ca-4afd-9869-0d48b391fcc9) | Sigma | SigmaHQ |
| T1071.002 | [Ubiquiti - Unusual FTP connection to external server](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3Afd200125-9d57-4838-85ca-6430c63e4e5d) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1071.002 | [MS-FTP: Multiple FTP errors from same source.](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=wazuh-ruleset-oficial%3A%3Awazuh-11512) | Wazuh | Wazuh ruleset (oficial) |
| T1071.003 | [SMTP to the Internet on Port 26/TCP](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ad7e62693-aab9-4f66-a21a-3d79ecdd603d) | Elastic | Elastic detection-rules |
| T1071.003 | [CYFIRMA - Brand Intelligence - Domain Impersonation High Rule](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A10bdf525-5b89-4a25-933a-e63e73b915f1) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1074.001 | [Sensitive File Access followed by Compression](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Aa0fbd7a9-1923-4e05-92df-b484168f17bc) | Elastic | Elastic detection-rules |
| T1074.001 | [Folder Compress To Potentially Suspicious Output Via Compress-Archive Cmdlet](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A85a8e5ba-bd03-4bfb-bbfa-a4409a8f8b98+%23+Process+Creation) | Sigma | SigmaHQ |
| T1078.003 | [Potential Successful SSH Brute Force Attack via macOS Security Events](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Af5898b1e-3071-4597-b066-43d298c7b415) | Elastic | Elastic detection-rules |
| T1078.003 | [Admin User Remote Logon](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A0f63e1ef-1eb9-4226-9d54-8927ca08520a) | Sigma | SigmaHQ |
| T1082 | [Potential GobRAT File Discovery Via Grep](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae34cfa0c-0a50-4210-9cb3-5632d08eb041) | Sigma | SigmaHQ |
| T1082 | [System Information Discovery](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A42df45e7-e6e9-43b5-8f26-bec5b39cc239) | Sigma | SigmaHQ |
| T1083 | [Turla Group Lateral Movement](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac601f20d-570a-4cde-a7d6-e17f99cb8e7f) | Sigma | SigmaHQ |
| T1083 | [WannaCry Ransomware Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A41d40bff-377a-43e2-8e1b-2e543069e079) | Sigma | SigmaHQ |
| T1098.007 | [User or Group Creation/Modification](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Afcf733d5-7801-4eb0-92ac-8ffacf3658f2) | Elastic | Elastic detection-rules |
| T1098.007 | [Linux User Added to Privileged Group](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A43d6ec12-2b1c-47b5-8f35-e9de65551d3b) | Elastic | Elastic detection-rules |
| T1102.001 | [Raw Paste Service Access](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A5468045b-4fcc-4d1a-973c-c9c9578edacb) | Sigma | SigmaHQ |
| T1102.001 | [PwnDrp Access](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A2b1ee7e4-89b6-4739-b7bb-b811b6607e5e) | Sigma | SigmaHQ |
| T1102.002 | [Potential Etherhiding C2 via Blockchain Connection](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Abba8c7d1-172b-435d-9034-02ed9289c628) | Elastic | Elastic detection-rules |
| T1102.002 | [Google Calendar C2 via Script Interpreter](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Aabc7a2be-479e-428b-b0b3-1d22bda46dd9) | Elastic | Elastic detection-rules |
| T1105 | [Greenbug Espionage Group Indicators](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A3711eee4-a808-4849-8a14-faf733da3612) | Sigma | SigmaHQ |
| T1105 | [Pandemic Registry Key](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A47e0852a-cf81-4494-a8e6-31864f8c86ed) | Sigma | SigmaHQ |
| T1106 | [Turla Group Named Pipes](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A739915e4-1e70-4778-8b8a-17db02f66db1) | Sigma | SigmaHQ |
| T1106 | [BPFDoor Abnormal Process ID or Lock File Accessed](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A808146b2-9332-4d78-9416-d7e47012d83d) | Sigma | SigmaHQ |
| T1111 | [Attempted Bypass of Okta MFA](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A3805c3dc-f82c-4f8d-891e-63c24d3102b0) | Elastic | Elastic detection-rules |
| T1111 | [Possible AiTM Phishing Attempt Against Microsoft Entra ID](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A16daa67c-b137-48dc-8eb7-76598a44791a) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1112 | [ShimCache Flush](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab0524451-19af-4efa-a46f-562a977f792e) | Sigma | SigmaHQ |
| T1112 | [ShimCache Flush](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Ab0524451-19af-4efa-a46f-562a977f792e) | Sigma | OpenSearch Security Analytics |
| T1113 | [PowerShell Suspicious Script with Screenshot Capabilities](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A959a7353-1129-4aa7-9084-30746b256a70) | Elastic | Elastic detection-rules |
| T1113 | [Potential Remote Desktop Shadowing Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ac57f8579-e2a5-4804-847f-f2732edc5156) | Elastic | Elastic detection-rules |
| T1114.002 | [Microsoft Graph Email Access by Unusual User and Client](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ae882e934-2aaa-11f0-8272-f661ea17fbcc) | Elastic | Elastic detection-rules |
| T1114.002 | [M365 Exchange Mailbox Accessed by Unusual Client](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A48819484-9826-4083-9eba-1da74cd0eaf2) | Elastic | Elastic detection-rules |
| T1114.003 | [Google Workspace Gmail Routing or Forwarding Rule Created or Modified](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A9510add4-3392-11ed-bd01-f661ea17fbce) | Elastic | Elastic detection-rules |
| T1114.003 | [Mail Forwarding/Redirecting Activity In O365](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac726e007-2cd0-4a55-abfb-79730fbedee5) | Sigma | SigmaHQ |
| T1115 | [Pbpaste Execution via Unusual Parent Process](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ad7182e12-df8f-4ecf-b8f8-7cc0adcec425) | Elastic | Elastic detection-rules |
| T1115 | [Clipboard Data Collection Via Pbpaste](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad8af0da1-2959-40f9-a3e4-37a6aa1228b7) | Sigma | SigmaHQ |
| T1124 | [Use of W32tm as Timer](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A6da2c9f5-7c53-401b-aacb-92c040ce1215) | Sigma | SigmaHQ |
| T1124 | [Cisco Discovery](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A9705a6a1-6db6-4a16-a987-15b7151e299b) | Sigma | SigmaHQ |
| T1133 | [OpenCanary - SSH Login Attempt](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aff7139bc-fdb1-4437-92f2-6afefe8884cb) | Sigma | SigmaHQ |
| T1133 | [OpenCanary - SSH New Connection Attempt](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acd55f721-5623-4663-bd9b-5229cab5237d) | Sigma | SigmaHQ |
| T1136.001 | [DarkGate - User Created Via Net.EXE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Abf906d7b-7070-4642-8383-e404cf26eba5) | Sigma | SigmaHQ |
| T1136.001 | [Serv-U Exploitation CVE-2021-35211 by DEV-0322](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A75578840-9526-4b2a-9462-af469a45e767) | Sigma | SigmaHQ |
| T1140 | [UNC4841 - SSL Certificate Exfiltration Via Openssl](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A60911c07-f989-4362-84af-c609828ef829) | Sigma | SigmaHQ |
| T1140 | [UNC4841 - Download Compressed Files From Temp.sh Using Wget](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A60d050c4-e253-4d9a-b673-5ac100cfddfb) | Sigma | SigmaHQ |
| T1176.001 | [Suspicious Chromium Browser Instance Executed With Custom Extension](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A27ba3207-dd30-4812-abbf-5d20c57d474e) | Sigma | SigmaHQ |
| T1176.001 | [Manual Loading of a Suspicious Chromium Extension](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Af1f3070e-045c-4e03-ae58-d11d43d2ee51) | Elastic | Elastic detection-rules |
| T1185 | [Potential Data Stealing Via Chromium Headless Debugging](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A3e8207c5-fcd2-4ea6-9418-15d45b4890e4) | Sigma | SigmaHQ |
| T1185 | [Browser Process Spawned from an Unusual Parent](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A46b01bb5-cff2-4a00-9f87-c041d9eab554) | Elastic | Elastic detection-rules |
| T1190 | [OMIGOD HTTP No Authentication RCE - CVE-2021-38647](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aab6b1a39-a9ee-4ab4-b075-e83acf6e346b) | Sigma | SigmaHQ |
| T1190 | [Exploited CVE-2020-10189 Zoho ManageEngine](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A846b866e-2a57-46ee-8e16-85fa92759be7) | Sigma | OpenSearch Security Analytics |
| T1204.001 | [Google Workspace Object Copied from External Drive with App Consent](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Af33e68a4-bd19-11ed-b02f-f661ea17fbcc) | Elastic | Elastic detection-rules |
| T1204.001 | [Suspicious ClickFix/FileFix Execution Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad487ed4a-fd24-436d-a0b2-f4e95f7b2635) | Sigma | SigmaHQ |
| T1204.002 | [Ursnif Malware C2 URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A932ac737-33ca-4afd-9869-0d48b391fcc9) | Sigma | SigmaHQ |
| T1204.002 | [Droppers Exploiting CVE-2017-11882](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A678eb5f4-8597-4be6-8be7-905e4234b53a) | Sigma | SigmaHQ |
| T1204.004 | [Potential TerminalFix Cloudflare Lure in PowerShell](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Aa4071476-76c8-4dc4-a3e2-956148d22aa2) | Elastic | Elastic detection-rules |
| T1204.004 | [Potential Fake CAPTCHA Phishing Attack](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Afbad57ec-4442-48db-a34f-5ee907b44a22) | Elastic | Elastic detection-rules |
| T1205 | [Unusual Linux Network Port Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A3c7e32e6-6104-46d9-a06e-da0f8b5795a0) | Elastic | Elastic detection-rules |
| T1205 | [Potential rootkit activity: insmod command executed](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=socfortress-wazuh-rules%3A%3Awazuh-700003) | Wazuh | SOCFortress Wazuh-Rules |
| T1217 | [File And SubFolder Enumeration Via Dir Command](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A7c9340a9-e2ee-4e43-94c5-c54ebbea1006) | Sigma | SigmaHQ |
| T1217 | [Suspicious Where Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A725a9768-0f5e-4cb3-aec2-bc5719c6831a) | Sigma | SigmaHQ |
| T1218.005 | [Potential Baby Shark Malware Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A2b30fa36-3a18-402f-a22d-bf4ce2189f35) | Sigma | SigmaHQ |
| T1218.005 | [Remotely Hosted HTA File Executed Via Mshta.EXE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab98d0db6-511d-45de-ad02-e82a98729620) | Sigma | SigmaHQ |
| T1218.010 | [Potential EmpireMonkey Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A10152a7b-b566-438f-a33c-390b607d1c8d) | Sigma | SigmaHQ |
| T1218.010 | [Suspicious Microsoft Office Child Process](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A438025f9-5856-4663-83f7-52f878a70a50) | Sigma | SigmaHQ |
| T1218.011 | [Equation Group DLL_U Export Function Load](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad465d1d8-27a2-4cca-9621-a800f37cf72e) | Sigma | SigmaHQ |
| T1218.011 | [APT29 2018 Phishing Campaign File Indicators](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A3a3f81ca-652c-482b-adeb-b1c804727f74) | Sigma | SigmaHQ |
| T1219.002 | [Antivirus - Exploitation Framework Signature](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A238527ad-3c2c-4e4f-a1f6-92fd63adb864) | Sigma | SigmaHQ |
| T1219.002 | [Potential SocGholish Second Stage C2 DNS Query](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A70761fe8-6aa2-4f80-98c1-a57049c08e66) | Sigma | SigmaHQ |
| T1489 | [Delete Important Scheduled Task](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Adbc1f800-0fe0-4bc0-9c66-292c2abe3f78) | Sigma | SigmaHQ |
| T1489 | [Suspicious Windows Service Tampering](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ace72ef99-22f1-43d4-8695-419dcb5d9330) | Sigma | SigmaHQ |
| T1497.001 | [Virtual Machine Fingerprinting](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A5b03c9fb-9945-4d2f-9568-fd690fee3fba) | Elastic | Elastic detection-rules |
| T1497.001 | [Powershell Detect Virtualization Environment](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad93129cd-1ee0-479f-bc03-ca6f129882e3) | Sigma | SigmaHQ |
| T1505.003 | [MOVEit CVE-2023-34362 Exploitation Attempt - Potential Web Shell Request](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A435e41f2-48eb-4c95-8a2b-ed24b50ec30b) | Sigma | SigmaHQ |
| T1505.003 | [Solarwinds SUPERNOVA Webshell Access](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aa2cee20b-eacc-459f-861d-c02e5d12f1db) | Sigma | SigmaHQ |
| T1518.001 | [Sysmon Discovery Via Default Driver Altitude Using Findstr.EXE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A37db85d1-b089-490a-a59a-c7b6f984f480) | Sigma | SigmaHQ |
| T1518.001 | [Local Firewall Rules Enumeration Via NetFirewallRule Cmdlet](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aea207a23-b441-4a17-9f76-ad5be47d51d3) | Sigma | SigmaHQ |
| T1534 | [AWS SNS Topic Message Publish by Rare User](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A2112ecce-cd34-11ef-873f-f661ea17fbcd) | Elastic | Elastic detection-rules |
| T1534 | [OpenAI ChatGPT Enterprise Gmail Message Sent via Connector](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A7184e35d-5605-4283-badf-435e1974e488) | Elastic | Elastic detection-rules |
| T1539 | [SQLite Firefox Profile Data DB Access](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4833155a-4053-4c9c-a997-777fcea0baa7) | Sigma | SigmaHQ |
| T1539 | [SQLite Chromium Profile Data DB Access](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A24c77512-782b-448a-8950-eddb0785fc71) | Sigma | SigmaHQ |
| T1543.003 | [PSExec Lateral Movement](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=hayabusa-native%3A%3A0694c340-3a46-40ac-acfc-c3444ae6572c) | Sigma | Hayabusa (native) |
| T1543.003 | [Suspicious Service Name](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=hayabusa-native%3A%3Acc429813-21db-4019-b520-2f19648e1ef1) | Sigma | Hayabusa (native) |
| T1546.001 | [Change Default File Association To Executable Via Assoc](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aae6f14e6-14de-45b0-9f44-c0986f50dc89) | Sigma | SigmaHQ |
| T1546.001 | [Shell Open Registry Keys Manipulation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A152f3630-77c1-4284-bcc0-4cc68ab2f6e7) | Sigma | SigmaHQ |
| T1547.001 | [Potential Ryuk Ransomware Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac37510b8-2107-4b78-aa32-72f251e7a844) | Sigma | SigmaHQ |
| T1547.001 | [Ryuk Ransomware](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3Ac37510b8-2107-4b78-aa32-72f251e7a844) | Sigma | OpenSearch Security Analytics |
| T1550.002 | [Hacktool Ruler](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A24549159-ac1b-479c-8175-d42aea947cae) | Sigma | SigmaHQ |
| T1550.002 | [Pass the Hash Activity 2](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A8eef149c-bd26-49f2-9e5a-9b00e3af499b) | Sigma | SigmaHQ |
| T1552.001 | [Potential Russian APT Credential Theft Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab83f5166-9237-4b5e-9cd4-7b5d52f4d8ee) | Sigma | SigmaHQ |
| T1552.001 | [Copy Passwd Or Shadow From TMP Path](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Afa4aaed5-4fe0-498d-bbc0-08e3346387ba) | Sigma | SigmaHQ |
| T1552.004 | [Cisco Crypto Commands](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A1f978c6a-4415-47fb-aca5-736a44d7ca3d) | Sigma | SigmaHQ |
| T1552.004 | [DPAPI Backup Keys And Certificate Export Activity IOC](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A7892ec59-c5bb-496d-8968-e5d210ca3ac4) | Sigma | SigmaHQ |
| T1553.002 | [Driver Loaded (Invalid Signature)](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=hayabusa-native%3A%3A1f666722-3948-40a2-9d78-d9d374477a90) | Sigma | Hayabusa (native) |
| T1553.002 | [Driver Loaded (Expired/Revoked Cert)](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=hayabusa-native%3A%3Ac837dd6d-0c91-4593-aeab-f6a1f3ca1961) | Sigma | Hayabusa (native) |
| T1555.003 | [SQLite Chromium Profile Data DB Access](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A24c77512-782b-448a-8950-eddb0785fc71) | Sigma | SigmaHQ |
| T1555.003 | [HackTool - WinPwn Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ad557dc06-62e8-4468-a8e8-7984124908ce) | Sigma | SigmaHQ |
| T1557 | [ICMP Redirect Message from Internal Host](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A2014ebd8-b847-4cc0-a827-d0d61ec88680) | Elastic | Elastic detection-rules |
| T1557 | [Multiple DHCP Servers Responding to the Same Transaction](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A44b8d933-8fed-485d-a0af-bd97d0093439) | Elastic | Elastic detection-rules |
| T1559.001 | [CMSTP Execution Process Access](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A3b4b232a-af90-427c-a22f-30b0c0837b95) | Sigma | SigmaHQ |
| T1559.001 | [CMSTP Execution Process Access](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A3b4b232a-af90-427c-a22f-30b0c0837b95) | Sigma | OpenSearch Security Analytics |
| T1560.001 | [APT31 Judgement Panda Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A03e2746e-2b31-42f1-ab7a-eb39365b2422) | Sigma | SigmaHQ |
| T1560.001 | [Suspicious Manipulation Of Default Accounts Via Net.EXE](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A5b768e71-86f2-4879-b448-81061cbae951) | Sigma | SigmaHQ |
| T1560.003 | [Potential Data Collection in Temporary Directory by Hidden Executable](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-protections-artifacts-behavior%3A%3Aa6994646-d314-4ee0-be1f-1d694dc969e7) | Elastic | Elastic protections-artifacts (behavior) |
| T1564.002 | [Hiding User Account Via SpecialAccounts Registry Key](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Af8aebc67-a56d-4ec9-9fbe-7b0e8b7b4efd) | Sigma | SigmaHQ |
| T1564.002 | [Creation of a Hidden Local User Account](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A2edc8076-291e-41e9-81e4-e3fcbc97ae5e) | Elastic | Elastic detection-rules |
| T1564.003 | [Potential Data Stealing Via Chromium Headless Debugging](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A3e8207c5-fcd2-4ea6-9418-15d45b4890e4) | Sigma | SigmaHQ |
| T1564.003 | [HackTool - Covenant PowerShell Launcher](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac260b6db-48ba-4b4a-a76f-2f67644e99d2) | Sigma | SigmaHQ |
| T1566 | [CVE-2021-31979 CVE-2021-33771 Exploits by Sourgum](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aad7085ac-92e4-4b76-8ce2-276d2c0e68ef) | Sigma | SigmaHQ |
| T1566 | [CVE-2021-31979 CVE-2021-33771 Exploits](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A32b5db62-cb5f-4266-9639-0fa48376ac00) | Sigma | SigmaHQ |
| T1566.001 | [Ursnif Malware C2 URL Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A932ac737-33ca-4afd-9869-0d48b391fcc9) | Sigma | SigmaHQ |
| T1566.001 | [Droppers Exploiting CVE-2017-11882](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A678eb5f4-8597-4be6-8be7-905e4234b53a) | Sigma | SigmaHQ |
| T1566.002 | [Potential Malicious Usage of CloudTrail System Manager](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A38e7f511-3f74-41d4-836e-f57dfa18eead) | Sigma | SigmaHQ |
| T1566.002 | [Google Workspace Device Registration After OAuth from Suspicious ASN](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A012bfca7-45cb-4507-a3ba-3777167f8b81) | Elastic | Elastic detection-rules |
| T1567.002 | [APT40 Dropbox Tool User Agent](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A5ba715b6-71b7-44fd-8245-f66893e81b3d) | Sigma | SigmaHQ |
| T1567.002 | [PUA - Rclone Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae37db05d-d1f9-49c8-b464-cee1a4b11638) | Sigma | SigmaHQ |
| T1568 | [Possible FIN7 DGA Command and Control Behavior](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A4a4e23cf-78a2-449c-bac3-701924c269d3) | Elastic | Elastic detection-rules |
| T1568 | [Cobalt Strike Command and Control Beacon](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Acf53f532-9cc9-445a-9ae7-fced307ec53c) | Elastic | Elastic detection-rules |
| T1583 | [AWS Route 53 Private Hosted Zone Associated With a VPC](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ae3c27562-709a-42bd-82f2-3ed926cced19) | Elastic | Elastic detection-rules |
| T1583 | [AWS Service Quota Increase Requested by Rare Identity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A7e1b0654-b6c0-4b1b-ab47-75588533083c) | Elastic | Elastic detection-rules |
| T1583.001 | [AWS Route 53 Private Hosted Zone Associated With a VPC](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ae3c27562-709a-42bd-82f2-3ed926cced19) | Elastic | Elastic detection-rules |
| T1583.001 | [AWS SES Email Identity Verified Then Deleted](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A8e4bde35-125d-4eb3-9a2e-d7e77a053a08) | Elastic | Elastic detection-rules |
| T1583.006 | [GitHub Repo Created](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A6cea88e4-6ce2-4238-9981-a54c140d6336) | Elastic | Elastic detection-rules |
| T1583.006 | [Cisco Secure Firewall - Rare Snort Rule Triggered](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=splunk-security-content%3A%3Ae20313d2-7d63-4fcf-b2d9-d6e12c6c7bd7) | Splunk | Splunk security_content |
| T1584.001 | [AWS Route 53 Domain Transferred to Another Account](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A2045567e-b0af-444a-8c0b-0b6e2dae9e13) | Elastic | Elastic detection-rules |
| T1584.001 | [AWS Route 53 Domain Transfer Lock Disabled](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A12051077-0124-4394-9522-8f4f4db1d674) | Elastic | Elastic detection-rules |
| T1585 | [A SAML Connector was created or modified](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=panther-panther-analysis%3A%3ATeleport.SAMLCreated) | Panther | Panther panther-analysis |
| T1585.001 | [CYFIRMA - Brand Intelligence - Social Media Handle Impersonation Detected High Rule](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A22f49d67-7da7-4809-8d07-89e4478aa6b0) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1585.001 | [CYFIRMA - Brand Intelligence - Executive/People Impersonation High Rule](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A159d26a1-591c-4f70-b1ca-2843c881aaec) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1586.002 | [CYFIRMA - Brand Intelligence - Domain Impersonation High Rule](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A10bdf525-5b89-4a25-933a-e63e73b915f1) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1586.002 | [CYFIRMA - Brand Intelligence - Domain Impersonation Medium Rule](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A8f97ddbe-ab66-4f6c-b675-73b5eeb07259) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1587 | [FoggyWeb Backdoor DLL Loading](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A640dc51c-7713-4faa-8a0e-e7c0d9d4654c) | Sigma | SigmaHQ |
| T1587 | [CVE-2021-1675 Print Spooler Exploitation Filename Pattern](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A2131cfb3-8c12-45e8-8fa0-31f5924e9f07) | Sigma | SigmaHQ |
| T1587.001 | [Formbook Process Creation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A032f5fb3-d959-41a5-9263-4173c802dc2b) | Sigma | SigmaHQ |
| T1587.001 | [Uncommon File Created In Office Startup Folder](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aa10a2c40-2c4d-49f8-b557-1a946bc55d9d) | Sigma | SigmaHQ |
| T1588.002 | [Hacktool Execution - Imphash](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A24e3e58a-646b-4b50-adef-02ef935b9fc8) | Sigma | SigmaHQ |
| T1588.002 | [Renamed SysInternals DebugView Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acd764533-2e07-40d6-a718-cfeec7f2da7f) | Sigma | SigmaHQ |
| T1588.003 | [Short-lived ephemeral code signing certificates](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-hunting-queries%3A%3Ae920899f-edf0-446c-bb13-effbaf61b27b) | Sentinel KQL | Microsoft Sentinel (Hunting Queries) |
| T1589.002 | [Potential Unconstrained Delegation Discovery Via Get-ADComputer - ScriptBlock](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acdfa73b6-3c9d-4bb8-97f8-ddbd8921f5c5) | Sigma | SigmaHQ |
| T1589.002 | [AWSCloudTrail - Suspicious AWS CLI Command Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A8c2dc344-9352-4ca1-8863-b1b7a5e09e59) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1589.003 | [AWSCloudTrail - Suspicious AWS CLI Command Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A8c2dc344-9352-4ca1-8863-b1b7a5e09e59) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1591 | [AWSCloudTrail - Suspicious AWS CLI Command Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A8c2dc344-9352-4ca1-8863-b1b7a5e09e59) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1591 | [MailGuard 365 - Malware Threats](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-hunting-queries%3A%3Adaaae6ad-1fd0-4efa-b571-116689e67a20) | Sentinel KQL | Microsoft Sentinel (Hunting Queries) |
| T1596 | [AWSCloudTrail - Suspicious AWS CLI Command Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3A8c2dc344-9352-4ca1-8863-b1b7a5e09e59) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1598 | [CyberBlindSpot - Any Issue Detected](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=microsoft-sentinel-analytic-rules%3A%3Aabe1a662-d00d-482e-aa68-9394622ae02e) | Sentinel KQL | Microsoft Sentinel (Analytic Rules) |
| T1598 | [Proofpoint Phishing Email Detected](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=panther-panther-analysis%3A%3AProofpoint.PhishingDetected) | Panther | Panther panther-analysis |
| T1608.001 | [M365 OneDrive Malware File Upload](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Abba1b212-b85c-41c6-9b28-be0e5cdfc9b1) | Elastic | Elastic detection-rules |
| T1608.001 | [M365 SharePoint Malware File Detected](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A0e52157a-8e96-4a95-a6e3-5faae5081a74) | Elastic | Elastic detection-rules |
| T1620 | [PowerShell Base64 Encoded Reflective Assembly Load](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A62b7ccc9-23b4-471e-aa15-6da3663c4d59) | Sigma | SigmaHQ |
| T1620 | [Potential WinAPI Calls Via PowerShell Scripts](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A03d83090-8cba-44a0-b02f-0b756a050306) | Sigma | SigmaHQ |
| T1657 | [AWS S3 Bucket Enumeration or Brute Force](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A5f0234fd-7f21-42af-8391-511d5fd11d5c) | Elastic | Elastic detection-rules |
| T1657 | [Monitor ransomwarelive for companies of interest on ransowmare data leak sites (DLS)](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=bert-janp-hunting-queries%3A%3A8b9af12a820a) | KQL hunting | Bert-JanP Hunting Queries |
| T1684.001 | [Entra ID OAuth user_impersonation Scope for Unusual User and Client](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A9563dace-5822-11f0-b1d3-f661ea17fbcd) | Elastic | Elastic detection-rules |
| T1685 | [Windows Defender Configuration Changes](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A801bd44f-ceed-4eb6-887c-11544633c0aa) | Sigma | SigmaHQ |
| T1685 | [Windows Defender Virus Scanning Feature Disabled](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A686c0b4b-9dd3-4847-9077-d6c1bbe36fcb) | Sigma | SigmaHQ |
| T1686 | [Disable System Firewall](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A53059bc0-1472-438b-956a-7508a94a91f0) | Sigma | SigmaHQ |
| T1686 | [Netsh RDP Port Opening](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A01aeb693-138d-49d2-9403-c4f52d7d3d62) | Sigma | OpenSearch Security Analytics |

## 9. Plano de emulação e validação

Use num laboratório isolado e autorizado para confirmar que as regras disparam. Os comandos estão nos repositórios oficiais.

| Tática | Técnica | Teste Atomic Red Team | Plataformas |
|---|---|---|---|
| Initial Access | [T1566.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1566.001/T1566.001.md) | Download Macro-Enabled Phishing Attachment | windows |
| Initial Access | [T1566.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1566.001/T1566.001.md) | Word spawned a command shell and used an IP address in the command line | windows |
| Initial Access | [T1566.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1566.002/T1566.002.md) | Paste and run technique | windows |
| Execution | [T1053.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1053.005/T1053.005.md) | Scheduled Task Startup Script | windows |
| Execution | [T1053.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1053.005/T1053.005.md) | Scheduled task Local | windows |
| Execution | [T1059.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md) | Mimikatz | windows |
| Execution | [T1059.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md) | Run BloodHound from local disk | windows |
| Execution | [T1059.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.003/T1059.003.md) | Create and Execute Batch Script | windows |
| Execution | [T1059.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.003/T1059.003.md) | Writes text to a file and displays it. | windows |
| Execution | [T1059.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.005/T1059.005.md) | Visual Basic script execution to gather local computer information | windows |
| Execution | [T1059.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.005/T1059.005.md) | Encoded VBS code execution | windows |
| Execution | [T1059.007](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.007/T1059.007.md) | JScript execution to gather local computer information via cscript | windows |
| Execution | [T1059.007](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.007/T1059.007.md) | JScript execution to gather local computer information via wscript | windows |
| Execution | [T1106](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1106/T1106.md) | Execution through API - CreateProcess | windows |
| Execution | [T1106](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1106/T1106.md) | WinPwn - Get SYSTEM shell - Pop System Shell using CreateProcess technique | windows |
| Execution | [T1204.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1204.002/T1204.002.md) | OSTap Style Macro Execution | windows |
| Execution | [T1204.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1204.002/T1204.002.md) | OSTap Payload Download | windows |
| Persistence | [T1133](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1133/T1133.md) | Running Chrome VPN Extensions via the Registry 2 vpn extension | windows |
| Persistence | [T1136.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1136.001/T1136.001.md) | Create a user account on a Linux system | linux |
| Persistence | [T1136.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1136.001/T1136.001.md) | Create a user account on a FreeBSD system | linux |
| Persistence | [T1505.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1505.003/T1505.003.md) | Web Shell Written to Disk | windows |
| Persistence | [T1543.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1543.003/T1543.003.md) | Modify Fax service to run PowerShell | windows |
| Persistence | [T1543.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1543.003/T1543.003.md) | Service Installation CMD | windows |
| Persistence | [T1547.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1547.001/T1547.001.md) | Reg Key Run | windows |
| Persistence | [T1547.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1547.001/T1547.001.md) | Reg Key RunOnce | windows |
| Privilege Escalation | [T1546.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1546.001/T1546.001.md) | Change Default File Association | windows |
| Stealth | [T1027](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027/T1027.md) | Decode base64 Data into Script | linux, macos |
| Stealth | [T1027](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027/T1027.md) | Execute base64-encoded PowerShell | windows |
| Stealth | [T1027.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027.001/T1027.001.md) | Pad Binary to Change Hash - Linux/macOS dd | linux, macos |
| Stealth | [T1027.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027.001/T1027.001.md) | Pad Binary to Change Hash using truncate command - Linux/macOS | linux, macos |
| Stealth | [T1027.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027.002/T1027.002.md) | Binary simply packed by UPX (linux) | linux |
| Stealth | [T1027.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027.002/T1027.002.md) | Binary packed by UPX, with modified headers (linux) | linux |
| Stealth | [T1027.007](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027.007/T1027.007.md) | Dynamic API Resolution-Ninja-syscall | windows |
| Stealth | [T1027.013](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027.013/T1027.013.md) | Decode Eicar File and Write to File | linux, macos, windows |
| Stealth | [T1027.013](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027.013/T1027.013.md) | Decrypt Eicar File and Write to File | linux, macos, windows |
| Stealth | [T1036.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.004/T1036.004.md) | Creating W32Time similar named service using schtasks | windows |
| Stealth | [T1036.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.004/T1036.004.md) | Creating W32Time similar named service using sc | windows |
| Stealth | [T1036.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.005/T1036.005.md) | Execute a process from a directory masquerading as the current parent directory | linux, macos |
| Stealth | [T1036.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.005/T1036.005.md) | Masquerade as a built-in system executable | windows |
| Stealth | [T1055](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1055/T1055.md) | Shellcode execution via VBA | windows |
| Stealth | [T1055](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1055/T1055.md) | Remote Process Injection in LSASS via mimikatz | windows |
| Stealth | [T1055.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1055.001/T1055.001.md) | Process Injection via mavinject.exe | windows |
| Stealth | [T1055.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1055.001/T1055.001.md) | WinPwn - Get SYSTEM shell - Bind System Shell using UsoClient DLL load technique | windows |
| Stealth | [T1055.012](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1055.012/T1055.012.md) | Process Hollowing using PowerShell | windows |
| Stealth | [T1055.012](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1055.012/T1055.012.md) | RunPE via VBA | windows |
| Stealth | [T1070.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.004/T1070.004.md) | Delete a single file - FreeBSD/Linux/macOS | linux, macos |
| Stealth | [T1070.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.004/T1070.004.md) | Delete an entire folder - FreeBSD/Linux/macOS | linux, macos |
| Stealth | [T1070.006](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.006/T1070.006.md) | Set a file's access timestamp | linux, macos |
| Stealth | [T1070.006](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.006/T1070.006.md) | Set a file's modification timestamp | linux, macos |
| Stealth | [T1078.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1078.003/T1078.003.md) | Create local account with admin privileges | windows |
| Stealth | [T1078.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1078.003/T1078.003.md) | Create local account with admin privileges - MacOS | macos |
| Stealth | [T1140](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1140/T1140.md) | Deobfuscate/Decode Files Or Information | windows |
| Stealth | [T1140](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1140/T1140.md) | Certutil Rename and Decode | windows |
| Stealth | [T1218.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.005/T1218.005.md) | Mshta executes JavaScript Scheme Fetch Remote Payload With GetObject | windows |
| Stealth | [T1218.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.005/T1218.005.md) | Mshta executes VBScript to execute malicious command | windows |
| Stealth | [T1218.010](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.010/T1218.010.md) | Regsvr32 local COM scriptlet execution | windows |
| Stealth | [T1218.010](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.010/T1218.010.md) | Regsvr32 remote COM scriptlet execution | windows |
| Stealth | [T1218.011](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.011/T1218.011.md) | Rundll32 execute JavaScript Remote Payload With GetObject | windows |
| Stealth | [T1218.011](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.011/T1218.011.md) | Rundll32 execute VBscript command | windows |
| Stealth | [T1497.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1497.001/T1497.001.md) | Detect Virtualization Environment (Linux) | linux |
| Stealth | [T1497.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1497.001/T1497.001.md) | Detect Virtualization Environment (FreeBSD) | linux |
| Stealth | [T1564.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1564.002/T1564.002.md) | Create Hidden User using UniqueID < 500 | macos |
| Stealth | [T1564.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1564.002/T1564.002.md) | Create Hidden User using IsHidden option | macos |
| Stealth | [T1564.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1564.003/T1564.003.md) | Hidden Window | windows |
| Stealth | [T1564.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1564.003/T1564.003.md) | Headless Browser Accessing Mockbin | windows |
| Stealth | [T1620](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1620/T1620.md) | WinPwn - Reflectively load Mimik@tz into memory | windows |
| Stealth | [T1620](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1620/T1620.md) | Reflective PE Injection via PowerSploit | windows |
| Defense Impairment | [T1112](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1112/T1112.md) | Modify Registry of Current User Profile - cmd | windows |
| Defense Impairment | [T1112](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1112/T1112.md) | Modify Registry of Local Machine - cmd | windows |
| Defense Impairment | [T1685](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1685/T1685.md) | Windows Disable LSA Protection | windows |
| Defense Impairment | [T1685](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1685/T1685.md) | Disable journal logging via systemctl utility | linux |
| Defense Impairment | [T1686](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1686/T1686.md) | Disable Microsoft Defender Firewall | windows |
| Defense Impairment | [T1686](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1686/T1686.md) | Disable Microsoft Defender Firewall via Registry | windows |
| Credential Access | [T1003.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/T1003.001.md) | Dump LSASS.exe Memory using ProcDump | windows |
| Credential Access | [T1003.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/T1003.001.md) | Dump LSASS.exe Memory using comsvcs.dll | windows |
| Credential Access | [T1040](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1040/T1040.md) | Packet Capture Linux using tshark or tcpdump | linux |
| Credential Access | [T1040](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1040/T1040.md) | Packet Capture FreeBSD using tshark or tcpdump | linux |
| Credential Access | [T1539](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1539/T1539.md) | Steal Firefox Cookies (Windows) | windows |
| Credential Access | [T1539](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1539/T1539.md) | Steal Chrome Cookies (Windows) | windows |
| Credential Access | [T1552.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1552.001/T1552.001.md) | Find AWS credentials | linux, macos |
| Credential Access | [T1552.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1552.001/T1552.001.md) | Extract Browser and System credentials with LaZagne | macos |
| Credential Access | [T1552.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1552.004/T1552.004.md) | Private Keys | windows |
| Credential Access | [T1552.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1552.004/T1552.004.md) | Discover Private SSH Keys | linux, macos |
| Credential Access | [T1555.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1555.003/T1555.003.md) | Run Chrome-password Collector | windows |
| Credential Access | [T1555.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1555.003/T1555.003.md) | Search macOS Safari Cookies | macos |
| Discovery | [T1007](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1007/T1007.md) | System Service Discovery | windows |
| Discovery | [T1007](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1007/T1007.md) | System Service Discovery - net.exe | windows |
| Discovery | [T1012](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1012/T1012.md) | Query Registry | windows |
| Discovery | [T1012](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1012/T1012.md) | Query Registry with Powershell cmdlets | windows |
| Discovery | [T1016](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1016/T1016.md) | System Network Configuration Discovery on Windows | windows |
| Discovery | [T1016](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1016/T1016.md) | List Windows Firewall Rules | windows |
| Discovery | [T1033](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1033/T1033.md) | System Owner/User Discovery | windows |
| Discovery | [T1033](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1033/T1033.md) | System Owner/User Discovery | linux, macos |
| Discovery | [T1057](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1057/T1057.md) | Process Discovery - ps | linux, macos |
| Discovery | [T1057](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1057/T1057.md) | Process Discovery - tasklist | windows |
| Discovery | [T1082](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1082/T1082.md) | System Information Discovery | windows |
| Discovery | [T1082](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1082/T1082.md) | System Information Discovery | macos |
| Discovery | [T1083](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1083/T1083.md) | File and Directory Discovery (cmd.exe) | windows |
| Discovery | [T1083](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1083/T1083.md) | File and Directory Discovery (PowerShell) | windows |
| Discovery | [T1124](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1124/T1124.md) | System Time Discovery | windows |
| Discovery | [T1124](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1124/T1124.md) | System Time Discovery - PowerShell | windows |
| Discovery | [T1217](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1217/T1217.md) | List Mozilla Firefox Bookmark Database Files on FreeBSD/Linux | linux |
| Discovery | [T1217](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1217/T1217.md) | List Mozilla Firefox Bookmark Database Files on macOS | macos |
| Discovery | [T1518.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1518.001/T1518.001.md) | Security Software Discovery | windows |
| Discovery | [T1518.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1518.001/T1518.001.md) | Security Software Discovery - powershell | windows |
| Lateral Movement | [T1021.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.001/T1021.001.md) | RDP to Remote Host | windows |
| Lateral Movement | [T1021.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.001/T1021.001.md) | Changing RDP Port to Non Standard Port via Powershell | windows |
| Lateral Movement | [T1550.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1550.002/T1550.002.md) | Mimikatz Pass the Hash | windows |
| Lateral Movement | [T1550.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1550.002/T1550.002.md) | crackmapexec Pass the Hash | windows |
| Collection | [T1005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1005/T1005.md) | Search files of interest and save them to a single zip file (Windows) | windows |
| Collection | [T1005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1005/T1005.md) | Find and dump sqlite databases (Linux) | linux |
| Collection | [T1056.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1056.001/T1056.001.md) | Input Capture | windows |
| Collection | [T1056.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1056.001/T1056.001.md) | Living off the land Terminal Input Capture on Linux with pam.d | linux |
| Collection | [T1074.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1074.001/T1074.001.md) | Stage data from Discovery.bat | windows |
| Collection | [T1074.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1074.001/T1074.001.md) | Stage data from Discovery.sh | linux, macos |
| Collection | [T1113](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1113/T1113.md) | Screencapture | macos |
| Collection | [T1113](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1113/T1113.md) | Screencapture (silent) | macos |
| Collection | [T1114.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1114.002/T1114.002.md) | Office365 - Remote Mail Collected | office-365 |
| Collection | [T1114.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1114.003/T1114.003.md) | Office365 - Email Forwarding | office-365 |
| Collection | [T1115](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1115/T1115.md) | Utilize Clipboard to store or execute commands from | windows |
| Collection | [T1115](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1115/T1115.md) | Execute Commands from Clipboard using PowerShell | windows |
| Collection | [T1560.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1560.001/T1560.001.md) | Compress Data for Exfiltration With Rar | windows |
| Collection | [T1560.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1560.001/T1560.001.md) | Compress Data and lock with password for Exfiltration with winrar | windows |
| Command and Control | [T1071.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1071.001/T1071.001.md) | Malicious User Agents - Powershell | windows |
| Command and Control | [T1071.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1071.001/T1071.001.md) | Malicious User Agents - CMD | windows |
| Command and Control | [T1105](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1105/T1105.md) | rsync remote file copy (push) | linux, macos |
| Command and Control | [T1105](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1105/T1105.md) | rsync remote file copy (pull) | linux, macos |
| Exfiltration | [T1020](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1020/T1020.md) | IcedID Botnet HTTP PUT | windows |
| Exfiltration | [T1020](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1020/T1020.md) | Exfiltration via Encrypted FTP | windows |
| Exfiltration | [T1041](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1041/T1041.md) | C2 Data Exfiltration | windows |
| Exfiltration | [T1041](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1041/T1041.md) | Text Based Data Exfiltration using DNS subdomains | windows |
| Exfiltration | [T1567.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1567.002/T1567.002.md) | Exfiltrate data with rclone to cloud Storage - Mega (Windows) | windows |
| Exfiltration | [T1567.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1567.002/T1567.002.md) | Exfiltrate data with rclone to cloud Storage - AWS S3 | linux, macos |
| Impact | [T1489](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1489/T1489.md) | Windows - Stop service using Service Controller | windows |
| Impact | [T1489](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1489/T1489.md) | Windows - Stop service using net.exe | windows |

**Logs reais de ataque (EVTX) para testar sem executar nada:**

- T1003.001 — [CA_hashdump_4663_4656_lsass_access](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Credential%20Access/CA_hashdump_4663_4656_lsass_access.evtx) _(inferido)_
- T1003.001 — [LsassSilentProcessExit_process_exit_monitor_3001_lsass](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Credential%20Access/LsassSilentProcessExit_process_exit_monitor_3001_lsass.evtx) _(inferido)_
- T1016 — [ID4688-Audit policy enumerated](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1016-System%20Network%20Configuration%20Discovery/ID4688-Audit%20policy%20enumerated.evtx) _(explícito)_
- T1016 — [ID4688-Firewall configuration enumerated (command)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0007-Discovery/T1016-System%20Network%20Configuration%20Discovery/ID4688-Firewall%20configuration%20enumerated%20%28command%29.evtx) _(explícito)_
- T1021.001 — [ID4688,4778,4779 RDP hijack direct](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0008-Lateral%20Movement/T1021.001-Remote%20Desktop%20Protocol/ID4688%2C4778%2C4779%20RDP%20hijack%20direct.evtx) _(explícito)_
- T1021.001 — [ID4688-4778 RDP hijack command execution](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0008-Lateral%20Movement/T1021.001-Remote%20Desktop%20Protocol/ID4688-4778%20RDP%20hijack%20command%20execution.evtx) _(explícito)_
- T1027 — [4624,4674,4688- CrackMap Exec SMB mimikatz](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0005-Defense%20Evasion/T1027-Obfuscated%20Files%20or%20Information/4624%2C4674%2C4688-%20CrackMap%20Exec%20SMB%20mimikatz.evtx) _(explícito)_
- T1027 — [ID1-CrackMapExec payload execution](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0005-Defense%20Evasion/T1027-Obfuscated%20Files%20or%20Information/ID1-CrackMapExec%20payload%20execution.evtx) _(explícito)_
- T1040 — [ID-4688 Native Windows sniffer Pktmon usage](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0006-Credential%20Access/T1040-Traffic%20sniffing/ID-4688%20Native%20Windows%20sniffer%20Pktmon%20usage.evtx) _(explícito)_
- T1053.005 — [ID4688-4698 Persistent scheduled task with SYSTEM privileges creation](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1053.005-Scheduled%20Task/ID4688-4698%20Persistent%20scheduled%20task%20with%20SYSTEM%20privileges%20creation.evtx) _(explícito)_
- T1053.005 — [ID4688-Interactive shell using AT schedule task](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1053.005-Scheduled%20Task/ID4688-Interactive%20shell%20using%20AT%20schedule%20task.evtx) _(explícito)_
- T1055 — [sideloading_injection_persistence_run_key](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/AutomatedTestingTools/Malware/sideloading_injection_persistence_run_key.evtx) _(inferido)_
- T1055 — [sideloading_uacbypass_rundll32_injection_c2](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/AutomatedTestingTools/Malware/sideloading_uacbypass_rundll32_injection_c2.evtx) _(inferido)_
- T1055.012 — [rundll32_hollowing_wermgr_masquerading](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/AutomatedTestingTools/Malware/rundll32_hollowing_wermgr_masquerading.evtx) _(inferido)_
- T1055.012 — [apt10_jjs_sideloading_prochollowing_persist_as_service_sysmon_1_7_8_13](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Defense%20Evasion/apt10_jjs_sideloading_prochollowing_persist_as_service_sysmon_1_7_8_13.evtx) _(inferido)_
- T1056.001 — [sysmon_13_keylogger_directx](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Credential%20Access/sysmon_13_keylogger_directx.evtx) _(inferido)_
- T1059.001 — [ID4103-4104-Payload download via PowerShell](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1059.001-PowerShell/ID4103-4104-Payload%20download%20via%20PowerShell.evtx) _(explícito)_
- T1059.001 — [ID4688-Encoded PowerShell MSF payload via process execution](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1059.001-PowerShell/ID4688-Encoded%20PowerShell%20MSF%20payload%20via%20process%20execution.evtx) _(explícito)_
- T1059.003 — [ID4688-SQL Server payload injectection for reverse shell (MSF)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1059.003-Windows%20Command%20Shell/ID4688-SQL%20Server%20payload%20injectection%20for%20reverse%20shell%20%28MSF%29.evtx) _(explícito)_
- T1070.006 — [ID4616-system time changed](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0005-Defense%20Evasion/T1070.006-Timestomp/ID4616-system%20time%20changed.evtx) _(explícito)_
- T1070.006 — [DE_timestomp_and_dll_sideloading_and_RunPersist](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/AutomatedTestingTools/Malware/DE_timestomp_and_dll_sideloading_and_RunPersist.evtx) _(inferido)_
- T1112 — [ID11,13-SMBexec service registration](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0005-Defense%20Evasion/T1112-Modify%20registry/ID11%2C13-SMBexec%20service%20registration.evtx) _(explícito)_
- T1112 — [ID4624,4670,4688,4674-Registry permission change via WMI (DAMP)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0005-Defense%20Evasion/T1112-Modify%20registry/ID4624%2C4670%2C4688%2C4674-Registry%20permission%20change%20via%20WMI%20%28DAMP%29.evtx) _(explícito)_
- T1140 — [ID4688-Certutil download](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0005-Defense%20Evasion/T1140-Deobfuscate-Decode%20Files%20or%20Information/ID4688-Certutil%20download.evtx) _(explícito)_
- T1218.005 — [exec_persist_rundll32_mshta_scheduledtask_sysmon_1_3_11](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Execution/exec_persist_rundll32_mshta_scheduledtask_sysmon_1_3_11.evtx) _(inferido)_

## 10. Hipóteses de hunting

Se Kimsuky estiver no seu ambiente, estas são as perguntas a fazer aos seus dados (fontes de log segundo as estratégias de detecção do MITRE ATT&CK).

1. **T1132.002 Non-Standard Encoding** — A process/script constructs or references a custom/alphabet translation table (e.g., 64/85/32+ arbitrary chars, XOR/base-N loops) or emits long high-entropy strings that do NOT validate as standard Base64/Hex → shortly after, the same process (or its child)… Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=3, 22), `WinEventLog:PowerShell` (EventCode=4103, 4104, 4105, 4106).
2. **T1176.001 Browser Extensions** — Installation of a new browser extension followed by suspicious file writes or outbound network connections to untrusted domains by the browser process. Dados: `WinEventLog:Sysmon` (EventCode=11), `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=3, 22).
3. **T1185 Browser Session Hijacking** — Adversary gains high integrity or special privileges (e.g., SeDebugPrivilege), locates a running browser process, opens it with write/inject rights, and modifies it (e.g., CreateRemoteThread / DLL load) to inherit cookies/tokens or establish a browser pivot.… Dados: `WinEventLog:Security` (EventCode=4672), `WinEventLog:Security` (EventCode=4673), `WinEventLog:Security` (EventCode=4624, 4648).
4. **T1546.001 Change Default File Association** — Detects modification of registry keys used for default file handlers, followed by anomalous process execution from user-initiated file opens. This includes tracking changes under HKCU and HKCR for file extension mappings, and correlating them with new or… Dados: `WinEventLog:Sysmon` (EventCode=13, 14), `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Security` (EventCode=4672).
5. **T1036.007 Double File Extension** — Detects adversary behavior where a file with a benign-looking first extension (e.g., .txt, .jpg) ends with a dangerous second extension (e.g., .exe, .scr), and is subsequently executed. The behavior chain includes file creation with misleading naming and user… Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=11).
6. **T1056.003 Web Portal Capture** — Detects unauthorized modifications to login-facing web server files (e.g., index.php, login.js) typically tied to VPN, SSO, or intranet portals. Correlates suspicious file changes with remote access artifacts or web shell behavior. Dados: `auditd:SYSCALL` (write), `NSM:Flow` (HTTP Request Logging).
7. **T1480.002 Mutual Exclusion** — Adversary-created named mutex using system APIs (e.g., CreateMutexW) followed by conditional process termination or alternate code path indicating malware avoiding reinfection. Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=11).
8. **T1564.002 Hidden Users** — Registry modifications to HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList setting user visibility to 0, or creation of user accounts not shown on login screen. Defender view: correlation of account creation with registry… Dados: `WinEventLog:Security` (EventCode=4720), `WinEventLog:Sysmon` (EventCode=13, 14).
9. **T1027.007 Dynamic API Resolution** — Behavioral chain involving suspicious use of GetProcAddress and LoadLibrary following memory allocation and manual mapping, often paired with low entropy strings, abnormal API use without static import tables, or delayed module load behaviors. Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=7), `etw:Microsoft-Windows-Kernel-Process` (API tracing / stack tracing via ETW or telemetry-based EDR).
10. **T1027.012 LNK Icon Smuggling** — Correlates LNK file execution with embedded resource extraction or suspicious network activity following initial launch, often leading to payload delivery via disguised icons. Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=15), `WinEventLog:Sysmon` (EventCode=3, 22).
11. **T1204.004 Malicious Copy and Paste** — A user is socially engineered (web page, email, document) to open Run/PowerShell/CMD and paste an obfuscated one-liner. The chain is: (1) user context active in a browser/email/office app → (2) process creation of a command interpreter with suspicious… Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:PowerShell` (EventCode=4103, 4104, 4105, 4106), `WinEventLog:Sysmon` (EventCode=11).
12. **T1205 Traffic Signaling** — A remote host sends a short sequence of failed connection attempts (RST/ICMP unreachable) to a set of closed ports. Within a brief window the endpoint (a) adds/enables a firewall rule or (b) a sniffer-backed process begins listening or opens a new socket,… Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=3, 22), `WinEventLog:Microsoft-Windows-Windows Firewall With Advanced Security/Firewall` (EventCode=2004, 2005, 2006).

## 11. OSINT — onde pesquisar

Consultas prontas com todos os nomes conhecidos do grupo:

- Relatórios técnicos: [busca web](https://duckduckgo.com/?q=%28%22Kimsuky%22+OR+%22Black+Banshee%22+OR+%22Velvet+Chollima%22+OR+%22Emerald+Sleet%22+OR+%22THALLIUM%22+OR+%22APT43%22%29+threat+report) · [PDFs](https://duckduckgo.com/?q=%28%22Kimsuky%22+OR+%22Black+Banshee%22+OR+%22Velvet+Chollima%22+OR+%22Emerald+Sleet%22+OR+%22THALLIUM%22+OR+%22APT43%22%29+filetype%3Apdf)
- Regras e IOCs publicados: [GitHub](https://github.com/search?type=code&q=%22Kimsuky%22+OR+%22Black+Banshee%22+OR+%22Velvet+Chollima%22+OR+%22Emerald+Sleet%22+OR+%22THALLIUM%22+OR+%22APT43%22)
- Pulsos de ameaça: [AlienVault OTX](https://otx.alienvault.com/browse/global/pulses?q=Kimsuky)
- Família de malware e atores: [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/actors) (busque por Kimsuky, Black Banshee, Velvet Chollima)
- Cartões de grupo: [ThaiCERT Threat Group Cards](https://apt.etda.or.th/cgi-bin/listgroups.cgi)
- Página oficial: [MITRE ATT&CK G0094](https://attack.mitre.org/groups/G0094/)

**Relatórios na coleção CyberMonitor** (ligados pelo nome do grupo, conferir antes de citar):

- 2013 — [Kimsuky](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2013/2013.09.11.Kimsuky_Operation/Kimsuky.pdf) _(via “Kimsuky”)_
- 2020 — [The North Korean Kimsuky APT keeps threatening South Korea evolving its TTPs](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2020/2020.03.03_Kimsuky_APT/The%20North%20Korean%20Kimsuky%20APT%20keeps%20threatening%20South%20Korea%20evolving%20its%20TTPs.pdf) _(via “Kimsuky”)_
- 2020 — [TLP-WHITE_AA20-301A_North_Korean_APT_Focus_Kimsuky](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2020/2020.10.27_AA20-301A.North_Korean_APT/TLP-WHITE_AA20-301A_North_Korean_APT_Focus_Kimsuky.pdf) _(via “Kimsuky”)_
- 2024 — [(3) Kimsuky is targeting an arms manufacturer in Europe. _ LinkedIn](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2024/2024.06.10.Kimsuky_Europe/%283%29%20Kimsuky%20is%20targeting%20an%20arms%20manufacturer%20in%20Europe.%20_%20LinkedIn.pdf) _(via “Kimsuky”)_

**Relatórios públicos ligados pelo APT4ALL** (4 no total, mais recentes primeiro):

- 2023 — [Kimsuky Group Uses AutoIt to Create Malware (RftRAT, Amadey)](https://app.box.com/s/xs2z8yf59q58ph1qn5sqr92sj2g6zefo) _(Ahnlab)_
- 2022 — [Kimsuky Group's APT Attacks (AppleSeed, PebbleDash)](https://app.box.com/s/iygnjm6cv5mwzlry3ct3dtor049ci6pk) _(Ahnlab)_
- 2021 — [Kimsuky Espionage Campaign](https://app.box.com/s/t7evyuuhbdiqo9q3mtowy9exwn9flner) _(Inquest)_
- 2013 — [The "Kimsuky" Operation: A North Korean Apt?](https://app.box.com/s/bel4s8xubunn5gxjvorgm7qg2v0e9kgt) _(Kaspersky)_

## 12. Bibliografia (33 fontes citadas pelo ATT&CK)

- [AhnLab Kimsuky Kabar Cobra Feb 2019](https://global.ahnlab.com/global/upload/download/techreport/%5BAnalysis_Report%5DOperation%20Kabar%20Cobra.pdf) — AhnLab. (2019, February 28). Operation Kabar Cobra - Tenacious cyber-espionage campaign by Kimsuky Group. Retrieved September 29, 2021.
- [Aryaka Kimsuky July 2025](https://www.aryaka.com/docs/reports/aryaka-kimsuky-apt-operational-blueprint.pdf) — Varadharajan Krishnasamy, Aditya K Sood. (2025, July 29). From Reconnaissance to Control: The Operational Blueprint of Kimsuky APT for Cyber Espionage. Retrieved April 18, 2026.
- [ASEC Troll Stealer 2024](https://asec.ahnlab.com/en/61934/) — AhnLab ASEC. (2024, February 16). TrollAgent That Infects Systems Upon Security Program Installation Process (Kimsuky Group). Retrieved January 17, 2025.
- [CISA AA20-301A Kimsuky](https://us-cert.cisa.gov/ncas/alerts/aa20-301a) — CISA, FBI, CNMF. (2020, October 27). https://us-cert.cisa.gov/ncas/alerts/aa20-301a. Retrieved November 4, 2020.
- [Cloudflare 2026 Threat Report New Threat Actors March 2026](https://blog.cloudflare.com/2026-threat-report/) — Cloudflare. (2026, March 3). Introducing the 2026 Cloudflare Threat Report. Retrieved April 18, 2026.
- [Crowdstrike GTR2020 Mar 2020](https://go.crowdstrike.com/rs/281-OBQ-266/images/Report2020CrowdStrikeGlobalThreatReport.pdf) — Crowdstrike. (2020, March 2). 2020 Global Threat Report. Retrieved December 11, 2020.
- [Cybereason Kimsuky November 2020](https://www.cybereason.com/blog/back-to-the-future-inside-the-kimsuky-kgh-spyware-suite) — Dahan, A. et al. (2020, November 2). Back to the Future: Inside the Kimsuky KGH Spyware Suite. Retrieved November 6, 2020.
- [EnkiWhiteHat_KimsukyDOCSWAP_Dec2025](https://www.enki.co.kr/en/media-center/blog/kimsuky-distributing-malicious-mobile-app-via-qr-code) — EnkiWhiteHat. (2025, December 16). Kimsuky Distributing Malicious Mobile App via QR Code. Retrieved January 8, 2026.
- [EST Kimsuky April 2019](https://blog.alyac.co.kr/2234) — Alyac. (2019, April 3). Kimsuky Organization Steals Operation Stealth Power. Retrieved August 13, 2019.
- [EST Kimsuky SmokeScreen April 2019](https://blog.alyac.co.kr/attachment/cfile5.uf@99A0CD415CB67E210DCEB3.pdf) — ESTSecurity. (2019, April 17). Analysis of the APT Campaign ‘Smoke Screen’ targeting to Korea and US 출처: https://blog.alyac.co.kr/2243 [이스트시큐리티 알약 블로그]. Retrieved September 29, 2021.
- [FBI_KimsukyQR_Jan2026](https://www.ic3.gov/CSA/2026/260108.pdf) — FBI. (2026, January 8). FBI Flash AC-000001-MW North Korean Kimsuky Actors Leverage Malicious QR Codes in Spearphishing Campaigns Targeting U.S. Entities. Retrieved April 18, 2026.
- [Gen Digital Kimsuky HTTPTroy October 2025](https://www.gendigital.com/blog/insights/research/dprk-kimsuky-lazarus-analysis) — Alexndru-Cristian Bardas. (2025, October 30). DPRK’s Playbook: Kimsuky’s HttpTroy and Lazarus’s New BLINDINGCAN Variant. Retrieved April 8, 2026.
- [Kimsuky Malwarebytes](https://www.malwarebytes.com/blog/threat-intelligence/2021/06/kimsuky-apt-continues-to-target-south-korean-government-using-appleseed-backdoor) — Hossein Jazi. (2021, June 1). Kimsuky APT continues to target South Korean government using AppleSeed backdoor. Retrieved January 10, 2024.
- [KISA Operation Muzabi](https://web.archive.org/web/20220328121326/https://boho.or.kr/filedownload.do?attach_file_seq=2695&attach_file_id=EpF2695.pdf) — KISA. (2021). Phishing Target Reconnaissance and Attack Resource Analysis Operation Muzabi. Retrieved March 8, 2024.
- [Malwarebytes Kimsuky June 2021](https://blog.malwarebytes.com/threat-analysis/2021/06/kimsuky-apt-continues-to-target-south-korean-government-using-appleseed-backdoor/) — Jazi, H. (2021, June 1). Kimsuky APT continues to target South Korean government using AppleSeed backdoor. Retrieved June 10, 2021.
- [Mandiant APT43 March 2024](https://services.google.com/fh/files/misc/apt43-report-en.pdf) — Mandiant. (2024, March 14). APT43: North Korean Group Uses Cybercrime to Fund Espionage Operations. Retrieved May 3, 2024.
- [Microsoft Threat Actor Naming July 2023](https://learn.microsoft.com/en-us/microsoft-365/security/intelligence/microsoft-threat-actor-naming?view=o365-worldwide) — Microsoft . (2023, July 12). How Microsoft names threat actors. Retrieved November 17, 2023.
- [MSFT-AI](https://www.microsoft.com/en-us/security/blog/2024/02/14/staying-ahead-of-threat-actors-in-the-age-of-ai/) — Microsoft Threat Intelligence. (2024, February 14). Staying ahead of threat actors in the age of AI. Retrieved March 11, 2024.
- [NaumaanProofpoint_GlobalClickFix_April2025](https://www.proofpoint.com/us/blog/threat-insight/around-world-90-days-state-sponsored-actors-try-clickfix) — Naumaan, S., et al. (2025, April 17). Around the World in 90 Days: State-Sponsored Actors Try ClickFix . Retrieved January 21, 2026.
- [Netscout Stolen Pencil Dec 2018](https://asert.arbornetworks.com/stolen-pencil-campaign-targets-academia/) — ASERT team. (2018, December 5). STOLEN PENCIL Campaign Targets Academia. Retrieved February 5, 2019.
- [OpenAI-CTI](https://openai.com/index/disrupting-malicious-uses-of-ai-by-state-affiliated-threat-actors/) — OpenAI. (2024, February 14). Disrupting malicious uses of AI by state-affiliated threat actors. Retrieved September 12, 2024.
- [Proofpoint TA427 April 2024](https://www.proofpoint.com/us/blog/threat-insight/social-engineering-dmarc-abuse-ta427s-art-information-gathering) — Lesnewich, G. et al. (2024, April 16). From Social Engineering to DMARC Abuse: TA427’s Art of Information Gathering. Retrieved May 3, 2024.
- [Rapid7 Threat Landscape Actors March 2026](https://www.rapid7.com/cdn/assets/bltc1ddd6561ab54a26/69ba67de50ca691edcd3f5b7/rapid7-threat-landscape-report-2026.pdf) — Rapid7. (2026, March 18). 2026 GLOBAL THREAT LANDSCAPE REPORT: Decoding the Accelerated Cyber Attack Cycle. Retrieved April 18, 2026.
- [S2W Troll Stealer 2024](https://medium.com/s2wblog/kimsuky-disguised-as-a-korean-company-signed-with-a-valid-certificate-to-distribute-troll-stealer-cfa5d54314e2) — Jiho Kim & Sebin Lee, S2W. (2024, February 7). Kimsuky disguised as a Korean company signed with a valid certificate to distribute Troll Stealer (English ver.). Retrieved January 17, 2025.
- [Securelist Kimsuky Sept 2013](https://securelist.com/the-kimsuky-operation-a-north-korean-apt/57915/) — Tarakanov , D.. (2013, September 11). The “Kimsuky” Operation: A North Korean APT?. Retrieved August 13, 2019.
- [Securonix Kimsuky February 2025](https://www.securonix.com/blog/analyzing-deepdrive-north-korean-threat-actors-observed-exploiting-trusted-platforms-for-targeted-attacks/) — Den Iuzvyk, Tim Peck. (2025, February 13). Analyzing DEEP#DRIVE: North Korean Threat Actors Observed Exploiting Trusted Platforms for Targeted Attacks. Retrieved August 19, 2025.
- [Symantec Troll Stealer 2024](https://www.security.com/threat-intelligence/springtail-kimsuky-backdoor-espionage) — Symantec Threat Hunter Team. (2024, May 16). Springtail: New Linux Backdoor Added to Toolkit. Retrieved January 17, 2025.
- [Talos Kimsuky Nov 2021](https://blog.talosintelligence.com/2021/11/kimsuky-abuses-blogs-delivers-malware.html) — An, J and Malhotra, A. (2021, November 10). North Korean attackers use malicious blogs to deliver malware to high-profile South Korean targets. Retrieved December 29, 2021.
- [ThreatConnect Kimsuky September 2020](https://threatconnect.com/blog/kimsuky-phishing-operations-putting-in-work/) — ThreatConnect. (2020, September 28). Kimsuky Phishing Operations Putting In Work. Retrieved October 30, 2020.
- [VirusBulletin Kimsuky October 2019](https://www.virusbulletin.com/virusbulletin/2020/03/vb2019-paper-kimsuky-group-tracking-king-spearphishing/) — Kim, J. et al. (2019, October). KIMSUKY GROUP: TRACKING THE KING OF THE SPEAR PHISHING. Retrieved November 2, 2020.
- [Zdnet Kimsuky Dec 2018](https://www.zdnet.com/article/cyber-espionage-group-uses-chrome-extension-to-infect-victims/) — Cimpanu, C.. (2018, December 5). Cyber-espionage group uses Chrome extension to infect victims. Retrieved August 26, 2019.
- [Zdnet Kimsuky Group September 2020](https://www.zdnet.com/article/north-korea-has-tried-to-hack-11-officials-of-the-un-security-council/) — Cimpanu, C. (2020, September 30). North Korea has tried to hack 11 officials of the UN Security Council. Retrieved November 4, 2020.
- [Zscaler Kimsuky TRANSLATEXT](https://www.zscaler.com/blogs/security-research/kimsuky-deploys-translatext-target-south-korean-academia#technical-analysis) — Park, S. (2024, June 27). Kimsuky deploys TRANSLATEXT to target South Korean academia. Retrieved October 14, 2024.

## 13. Limites e confiança

- O ATT&CK registra o que foi **relatado publicamente**, não tudo o que o grupo faz. Ausência de uma técnica não prova que o grupo não a usa.
- **Sobreposição de TTP não é atribuição.** Muitas técnicas são compartilhadas entre grupos e com red teams. Use a assinatura comportamental como hipótese, junto com infraestrutura, malware e contexto.
- Cobertura de detecção refere-se ao catálogo público Detection Rules, não ao seu ambiente: confira se a telemetria necessária chega ao seu SIEM.
- Ligações marcadas como _inferidas_ (EVTX por palavra-chave, relatórios por nome) devem ser verificadas.

---
Fontes: MITRE ATT&CK® (uso livre com atribuição, © The MITRE Corporation), APT4ALL (MISP Galaxy CC0/BSD-2, APT Groups & Operations CC BY 4.0, EternalLiberty, APTnotes, Ransomware Tool Matrix CC BY 4.0), Atomic Red Team (Red Canary, MIT), EVTX-to-MITRE-Attack, EVTX-ATTACK-SAMPLES, APT & CyberCriminal Campaign Collections. Gerado por [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules).
