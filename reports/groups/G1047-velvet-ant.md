# Velvet Ant (G1047) — Dossiê de inteligência

> **TLP:CLEAR** · gerado em 2026-10-25 a partir de fontes abertas · MITRE ATT&CK v20.0 · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1047) · [ATT&CK](https://attack.mitre.org/groups/G1047/)

**Também conhecido como:** —  
**Registro no ATT&CK:** criado em 2025-03-14, atualizado em 2026-07-31 · referências de 2024 a 2024

## 1. Sumário executivo

- **22 técnicas** atribuídas publicamente, concentradas em **Stealth, Command and Control, Execution**.
- **Arsenal:** 1 malware e 1 ferramentas (ex.: PlugX, Impacket).
- **Campanhas atribuídas:** 0.
- **Cobertura de detecção pública:** 100% das técnicas têm ao menos uma regra no catálogo; **0 técnicas sem nenhuma regra pública**.
- **Assinatura comportamental** (técnicas raras entre os 178 grupos, as mais úteis para atribuição): T1132 Data Encoding, T1211 Exploitation for Stealth, T1037.004 RC Scripts, T1071 Application Layer Protocol, T1040 Network Sniffing.

## 2. Quem é

> Velvet Ant is a threat actor operating since at least 2021. Velvet Ant is associated with complex persistence mechanisms, the targeting of network devices and appliances during operations, and the use of zero day exploits.

_Texto original do MITRE ATT&CK, em inglês._

## 3. Perfil TTP por tática (kill chain)

Cada linha: técnica, como o grupo a usou segundo relatos públicos, e o que existe para detectar e testar.

### Initial Access (TA0001) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1078.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.003) Local Accounts | Velvet Ant accessed vulnerable Cisco switch devices using accounts with administrator privileges. | 32 | 13 | — |
| [T1133](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1133) External Remote Services | Velvet Ant has leveraged access to internet-facing remote services to compromise and retain access to victim environments. | 361 | 1 | — |

### Execution (TA0002) — 4

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1047](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1047) Windows Management Instrumentation | Velvet Ant used the `wmiexec.py` tool within Impacket for remote process execution via WMI. | 370 | 12 | 11 |
| [T1059.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.004) Unix Shell | Velvet Ant used a custom tool, VELVETSTING, to parse encoded inbound commands to compromised F5 BIG-IP devices and then execute them via the Unix shell. | 395 | 17 | — |
| [T1569.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1569.002) Service Execution | Velvet Ant executed and installed PlugX as a Windows service. | 230 | 8 | 8 |
| [T1574.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1574.001) DLL | Velvet Ant has used malicious DLLs executed via legitimate EXE files through DLL search order hijacking to launch follow-on payloads such as PlugX. | 455 | 7 | 5 |

### Persistence (TA0003) — 3

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1037.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1037.004) RC Scripts | Velvet Ant used a modified `/etc/rc.local` file on compromised F5 BIG-IP devices to maintain persistence. | 13 | 3 | — |
| [T1078.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.003) Local Accounts | Velvet Ant accessed vulnerable Cisco switch devices using accounts with administrator privileges. | 32 | 13 | — |
| [T1133](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1133) External Remote Services | Velvet Ant has leveraged access to internet-facing remote services to compromise and retain access to victim environments. | 361 | 1 | — |

### Privilege Escalation (TA0004) — 3

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1037.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1037.004) RC Scripts | Velvet Ant used a modified `/etc/rc.local` file on compromised F5 BIG-IP devices to maintain persistence. | 13 | 3 | — |
| [T1055](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1055) Process Injection | Velvet Ant initial execution included launching multiple `svchost` processes and injecting code into them. | 481 | 13 | 4 |
| [T1078.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.003) Local Accounts | Velvet Ant accessed vulnerable Cisco switch devices using accounts with administrator privileges. | 32 | 13 | — |

### Stealth (TA0005) — 5

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1036.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1036.005) Match Legitimate Resource Name or Location | Velvet Ant used a malicious DLL, `iviewers.dll`, that mimics the legitimate "OLE/COM Object Viewer" within Windows. | 116 | 4 | — |
| [T1055](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1055) Process Injection | Velvet Ant initial execution included launching multiple `svchost` processes and injecting code into them. | 481 | 13 | 4 |
| [T1078.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.003) Local Accounts | Velvet Ant accessed vulnerable Cisco switch devices using accounts with administrator privileges. | 32 | 13 | — |
| [T1211](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1211) Exploitation for Stealth | Velvet Ant exploited CVE-2024-20399 in Cisco Switches to which the threat actor was already able to authenticate in order to escape the NX-OS command line interface and gain access to the underlying operating system for arbitrary command execution. | 40 | — | — |
| [T1574.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1574.001) DLL | Velvet Ant has used malicious DLLs executed via legitimate EXE files through DLL search order hijacking to launch follow-on payloads such as PlugX. | 455 | 7 | 5 |

### Defense Impairment (TA0112) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1685](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1685) Disable or Modify Tools | Velvet Ant attempted to disable local security tools and endpoint detection and response (EDR) software during operations. | 1275 | 78 | 19 |
| [T1686](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1686) Disable or Modify System Firewall | Velvet Ant modified system firewall settings during PlugX installation using `netsh.exe` to open a listening, random high number port on victim devices. | 56 | 25 | 6 |

### Credential Access (TA0006) — 1

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1040](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1040) Network Sniffing | Velvet Ant has used a custom tool, "VELVETTAP", to perform packet capture from compromised F5 BIG-IP devices. | 77 | 16 | 1 |

### Discovery (TA0007) — 3

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1040](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1040) Network Sniffing | Velvet Ant has used a custom tool, "VELVETTAP", to perform packet capture from compromised F5 BIG-IP devices. | 77 | 16 | 1 |
| [T1049](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1049) System Network Connections Discovery | Velvet Ant has enumerated existing network connections on victim devices. | 47 | 7 | — |
| [T1083](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1083) File and Directory Discovery | Velvet Ant has enumerated local files and folders on victim devices. | 137 | 9 | — |

### Lateral Movement (TA0008) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1021.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1021.002) SMB/Windows Admin Shares | Velvet Ant has transferred tools within victim environments using SMB. | 272 | 4 | 20 |
| [T1570](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1570) Lateral Tool Transfer | Velvet Ant transferred files laterally within victim networks through the Impacket toolkit. | 58 | 2 | — |

### Command and Control (TA0011) — 5

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1071](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1071) Application Layer Protocol | Velvet Ant has used reverse SSH tunnels to communicate to victim devices. | 511 | 1 | — |
| [T1090.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1090.001) Internal Proxy | Velvet Ant has tunneled traffic from victims through an internal, compromised host to proxy communications to command and control nodes. | 43 | 3 | — |
| [T1132](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1132) Data Encoding | Velvet Ant sent commands to compromised F5 BIG-IP devices in an encoded format requiring a passkey before interpretation and execution. | 8 | — | — |
| [T1571](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1571) Non-Standard Port | Velvet Ant has used random high number ports for PlugX listeners on victim devices. | 163 | 2 | — |
| [T1573.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1573.002) Asymmetric Cryptography | Velvet Ant has used a reverse SSH shell to securely communicate with victim devices. | 14 | — | — |

## 4. Assinatura comportamental

Técnicas que este grupo usa e que poucos dos 178 grupos do ATT&CK usam. Pesam mais numa atribuição por TTP: ver várias delas juntas é mais informativo do que ver técnicas comuns como PowerShell.

| Técnica | Outros grupos que usam | Peso (raridade) |
|---|---:|---:|
| T1132 Data Encoding | 0 | 4.49 |
| T1211 Exploitation for Stealth | 1 | 4.09 |
| T1037.004 RC Scripts | 2 | 3.80 |
| T1071 Application Layer Protocol | 5 | 3.24 |
| T1040 Network Sniffing | 7 | 2.99 |
| T1090.001 Internal Proxy | 8 | 2.88 |
| T1573.002 Asymmetric Cryptography | 11 | 2.62 |
| T1059.004 Unix Shell | 12 | 2.55 |
| T1686 Disable or Modify System Firewall | 12 | 2.55 |
| T1078.003 Local Accounts | 13 | 2.48 |

## 5. Arsenal

| Software | Tipo | Técnicas no ATT&CK | Uso relatado (EN) |
|---|---|---:|---|
| [PlugX](https://attack.mitre.org/software/S0013/) | malware | 49 | Velvet Ant heavily relies on variants of PlugX for various phases of operations. |
| [Impacket](https://attack.mitre.org/software/S0357/) | ferramenta | 11 | Velvet Ant used Impacket for lateral tool transfer and remote process execution. |

## 6. Campanhas

Nenhuma campanha atribuída no ATT&CK.

## 7. Cobertura defensiva

**22 de 22 técnicas (100%)** têm ao menos uma regra pública no catálogo Detection Rules.

### Regras recomendadas por técnica

Melhor regra disponível por técnica (formato portável e maduro primeiro).

| Técnica | Regra | Formato | Fonte |
|---|---|---|---|
| T1021.002 | [PSExec Lateral Movement](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=hayabusa-native%3A%3A0694c340-3a46-40ac-acfc-c3444ae6572c) | Sigma | Hayabusa (native) |
| T1021.002 | [Turla Group Lateral Movement](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac601f20d-570a-4cde-a7d6-e17f99cb8e7f) | Sigma | SigmaHQ |
| T1036.005 | [Exploit for CVE-2015-1641](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A7993792c-5ce2-4475-a3db-a3a5539827ef) | Sigma | SigmaHQ |
| T1036.005 | [Exploit for CVE-2015-1641](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A7993792c-5ce2-4475-a3db-a3a5539827ef) | Sigma | OpenSearch Security Analytics |
| T1037.004 | [GenAI Process Accessing Sensitive Files](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ac0136397-f82a-45e5-9b9f-a3651d77e21a) | Elastic | Elastic detection-rules |
| T1037.004 | [rc.local/rc.common File Creation](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A0f4d35e4-925e-4959-ab24-911be207ee6f) | Elastic | Elastic detection-rules |
| T1040 | [Cisco Sniffing](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab9e1f193-d236-4451-aaae-2f3d2102120d) | Sigma | SigmaHQ |
| T1040 | [Network Sniffing - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Af4d3748a-65d1-4806-bd23-e25728081d01) | Sigma | SigmaHQ |
| T1047 | [HackTool - Potential Impacket Lateral Movement Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A10c14723-61c7-4c75-92ca-9af245723ad2) | Sigma | SigmaHQ |
| T1047 | [CrackMapExec Command Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A058f4380-962d-40a5-afce-50207d36d7e2) | Sigma | OpenSearch Security Analytics |
| T1049 | [Potential Pikabot Discovery Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A698d4431-514f-4c82-af4d-cf573872a9f5) | Sigma | SigmaHQ |
| T1049 | [HackTool - SharpView Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab2317cfa-4a47-4ead-b3ff-297438c0bc2d) | Sigma | SigmaHQ |
| T1055 | [Potential Dridex Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae6eb5a96-9e6f-4a18-9cdd-642cfda21c8e) | Sigma | SigmaHQ |
| T1055 | [Antivirus PrinterNightmare CVE-2021-34527 Exploit Detection](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A6fe1719e-ecdf-4caf-bffe-4f501cb0a561) | Sigma | SigmaHQ |
| T1059.004 | [Shell Invocation via Env Command - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Abed978f8-7f3a-432b-82c5-9286a9b3031a) | Sigma | SigmaHQ |
| T1059.004 | [Suspicious Reverse Shell Command Line](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A738d9bcf-6999-4fdb-b4ac-3033037db8ab) | Sigma | SigmaHQ |
| T1071 | [GALLIUM IOCs](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A440a56bf-7873-4439-940a-1c8a671073c2) | Sigma | SigmaHQ |
| T1071 | [GALLIUM Artefacts - Builtin](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A3db10f25-2527-4b79-8d4b-471eb900ee29) | Sigma | SigmaHQ |
| T1078.003 | [Potential Successful SSH Brute Force Attack via macOS Security Events](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Af5898b1e-3071-4597-b066-43d298c7b415) | Elastic | Elastic detection-rules |
| T1078.003 | [Admin User Remote Logon](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A0f63e1ef-1eb9-4226-9d54-8927ca08520a) | Sigma | SigmaHQ |
| T1083 | [Turla Group Lateral Movement](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac601f20d-570a-4cde-a7d6-e17f99cb8e7f) | Sigma | SigmaHQ |
| T1083 | [WannaCry Ransomware Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A41d40bff-377a-43e2-8e1b-2e543069e079) | Sigma | SigmaHQ |
| T1090.001 | [Renamed Cloudflared.EXE Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae0c69ebd-b54f-4aed-8ae3-e3467843f3f0) | Sigma | SigmaHQ |
| T1090.001 | [PUA - Chisel Tunneling Tool Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A8b0e12da-d3c3-49db-bb4f-256703f380e5) | Sigma | SigmaHQ |
| T1132 | [Base16 or Base32 Encoding/Decoding Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Adebff20a-46bc-4a4d-bae5-5cdd14222795) | Elastic | Elastic detection-rules |
| T1132 | [File Compressed or Archived into Common Format by Unsigned Process](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A79124edf-30a8-4d48-95c4-11522cad94b1) | Elastic | Elastic detection-rules |
| T1133 | [OpenCanary - SSH Login Attempt](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aff7139bc-fdb1-4437-92f2-6afefe8884cb) | Sigma | SigmaHQ |
| T1133 | [OpenCanary - SSH New Connection Attempt](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Acd55f721-5623-4663-bd9b-5229cab5237d) | Sigma | SigmaHQ |
| T1211 | [Microsoft Malware Protection Engine Crash](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A545a5da6-f103-4919-a519-e9aec1026ee4) | Sigma | SigmaHQ |
| T1211 | [Audit CVE Event](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A48d91a3a-2363-43ba-a456-ca71ac3da5c2) | Sigma | SigmaHQ |
| T1569.002 | [PSExec Lateral Movement](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=hayabusa-native%3A%3A0694c340-3a46-40ac-acfc-c3444ae6572c) | Sigma | Hayabusa (native) |
| T1569.002 | [DNS RCE CVE-2020-1350](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab5281f31-f9cc-4d0d-95d0-45b91c45b487) | Sigma | SigmaHQ |
| T1570 | [PSExec Lateral Movement](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=hayabusa-native%3A%3A0694c340-3a46-40ac-acfc-c3444ae6572c) | Sigma | Hayabusa (native) |
| T1570 | [PSEXEC Remote Execution File Artefact](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A304afd73-55a5-4bb9-8c21-0b1fc84ea9e4) | Sigma | SigmaHQ |
| T1571 | [Potentially Suspicious Malware Callback Communication - Linux](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Adbfc7c98-04ab-4ab7-aa94-c74d22aa7376) | Sigma | SigmaHQ |
| T1571 | [Potentially Suspicious Malware Callback Communication](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A4b89abaa-99fe-4232-afdd-8f9aa4d20382) | Sigma | SigmaHQ |
| T1573.002 | [Potential Self-Signed TLS Certificate Recently Issued on External Connection](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A869fe008-5dd4-4f07-9c2e-aa90c3926fd9) | Elastic | Elastic detection-rules |
| T1573.002 | [Openssl Client or Server Activity](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Aad5a3757-c872-4719-8c72-12d3f08db655) | Elastic | Elastic detection-rules |
| T1574.001 | [Winnti Pipemon Characteristics](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A73d70463-75c9-4258-92c6-17500fe972f2) | Sigma | SigmaHQ |
| T1574.001 | [Winnti Pipemon Characteristics](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A73d70463-75c9-4258-92c6-17500fe972f2) | Sigma | OpenSearch Security Analytics |
| T1685 | [Windows Defender Configuration Changes](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A801bd44f-ceed-4eb6-887c-11544633c0aa) | Sigma | SigmaHQ |
| T1685 | [Windows Defender Virus Scanning Feature Disabled](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A686c0b4b-9dd3-4847-9077-d6c1bbe36fcb) | Sigma | SigmaHQ |
| T1686 | [Disable System Firewall](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A53059bc0-1472-438b-956a-7508a94a91f0) | Sigma | SigmaHQ |
| T1686 | [Netsh RDP Port Opening](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A01aeb693-138d-49d2-9403-c4f52d7d3d62) | Sigma | OpenSearch Security Analytics |

## 8. Plano de emulação e validação

Use num laboratório isolado e autorizado para confirmar que as regras disparam. Os comandos estão nos repositórios oficiais.

| Tática | Técnica | Teste Atomic Red Team | Plataformas |
|---|---|---|---|
| Execution | [T1047](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1047/T1047.md) | WMI Reconnaissance Users | windows |
| Execution | [T1047](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1047/T1047.md) | WMI Reconnaissance Processes | windows |
| Execution | [T1059.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.004/T1059.004.md) | Create and Execute Bash Shell Script | linux, macos |
| Execution | [T1059.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.004/T1059.004.md) | Command-Line Interface | linux, macos |
| Execution | [T1569.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1569.002/T1569.002.md) | Execute a Command as a Service | windows |
| Execution | [T1569.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1569.002/T1569.002.md) | Use PsExec to execute a command on a remote host | windows |
| Persistence | [T1037.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1037.004/T1037.004.md) | rc.common | macos |
| Persistence | [T1037.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1037.004/T1037.004.md) | rc.common | linux |
| Persistence | [T1133](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1133/T1133.md) | Running Chrome VPN Extensions via the Registry 2 vpn extension | windows |
| Stealth | [T1036.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.005/T1036.005.md) | Execute a process from a directory masquerading as the current parent directory | linux, macos |
| Stealth | [T1036.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1036.005/T1036.005.md) | Masquerade as a built-in system executable | windows |
| Stealth | [T1055](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1055/T1055.md) | Shellcode execution via VBA | windows |
| Stealth | [T1055](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1055/T1055.md) | Remote Process Injection in LSASS via mimikatz | windows |
| Stealth | [T1078.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1078.003/T1078.003.md) | Create local account with admin privileges | windows |
| Stealth | [T1078.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1078.003/T1078.003.md) | Create local account with admin privileges - MacOS | macos |
| Stealth | [T1574.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1574.001/T1574.001.md) | DLL Search Order Hijacking - amsi.dll | windows |
| Stealth | [T1574.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1574.001/T1574.001.md) | Phantom Dll Hijacking - WinAppXRT.dll | windows |
| Defense Impairment | [T1685](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1685/T1685.md) | Windows Disable LSA Protection | windows |
| Defense Impairment | [T1685](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1685/T1685.md) | Disable journal logging via systemctl utility | linux |
| Defense Impairment | [T1686](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1686/T1686.md) | Disable Microsoft Defender Firewall | windows |
| Defense Impairment | [T1686](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1686/T1686.md) | Disable Microsoft Defender Firewall via Registry | windows |
| Credential Access | [T1040](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1040/T1040.md) | Packet Capture Linux using tshark or tcpdump | linux |
| Credential Access | [T1040](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1040/T1040.md) | Packet Capture FreeBSD using tshark or tcpdump | linux |
| Discovery | [T1049](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1049/T1049.md) | System Network Connections Discovery | windows |
| Discovery | [T1049](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1049/T1049.md) | System Network Connections Discovery with PowerShell | windows |
| Discovery | [T1083](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1083/T1083.md) | File and Directory Discovery (cmd.exe) | windows |
| Discovery | [T1083](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1083/T1083.md) | File and Directory Discovery (PowerShell) | windows |
| Lateral Movement | [T1021.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.002/T1021.002.md) | Map admin share | windows |
| Lateral Movement | [T1021.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.002/T1021.002.md) | Map Admin Share PowerShell | windows |
| Lateral Movement | [T1570](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1570/T1570.md) | Exfiltration Over SMB over QUIC (New-SmbMapping) | windows |
| Lateral Movement | [T1570](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1570/T1570.md) | Exfiltration Over SMB over QUIC (NET USE) | windows |
| Command and Control | [T1071](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1071/T1071.md) | Telnet C2 | windows |
| Command and Control | [T1090.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1090.001/T1090.001.md) | Connection Proxy | linux, macos |
| Command and Control | [T1090.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1090.001/T1090.001.md) | Connection Proxy for macOS UI | macos |
| Command and Control | [T1571](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1571/T1571.md) | Testing usage of uncommonly used port with PowerShell | windows |
| Command and Control | [T1571](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1571/T1571.md) | Testing usage of uncommonly used port | linux, macos |

**Logs reais de ataque (EVTX) para testar sem executar nada:**

- T1021.002 — [ID4688,4697,5140-5145 PSexec remote execution + admin share](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0008-Lateral%20Movement/T1021.002-SMB%20Windows%20Admin%20Shares/ID4688%2C4697%2C5140-5145%20PSexec%20remote%20execution%20%2B%20admin%20share.evtx) _(explícito)_
- T1021.002 — [ID4688-4648 Lateral movement with net use](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0008-Lateral%20Movement/T1021.002-SMB%20Windows%20Admin%20Shares/ID4688-4648%20Lateral%20movement%20with%20net%20use.evtx) _(explícito)_
- T1040 — [ID-4688 Native Windows sniffer Pktmon usage](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0006-Credential%20Access/T1040-Traffic%20sniffing/ID-4688%20Native%20Windows%20sniffer%20Pktmon%20usage.evtx) _(explícito)_
- T1047 — [ID1-WMI spwaning PowerShell process - WMImplant](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1047-Windows%20Management%20Instrumentation/ID1-WMI%20spwaning%20PowerShell%20process%20-%20WMImplant.evtx) _(explícito)_
- T1047 — [ID1-WMIexec process execution](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1047-Windows%20Management%20Instrumentation/ID1-WMIexec%20process%20execution.evtx) _(explícito)_
- T1055 — [sideloading_injection_persistence_run_key](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/AutomatedTestingTools/Malware/sideloading_injection_persistence_run_key.evtx) _(inferido)_
- T1055 — [sideloading_uacbypass_rundll32_injection_c2](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/AutomatedTestingTools/Malware/sideloading_uacbypass_rundll32_injection_c2.evtx) _(inferido)_
- T1569.002 — [ID5145-remote service creation over SMB](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1569.002-Service%20execution/ID5145-remote%20service%20creation%20over%20SMB.evtx) _(explícito)_
- T1569.002 — [ID5145-service massive remote creation via named pipe - Tchopper](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0002-Execution/T1569.002-Service%20execution/ID5145-service%20massive%20remote%20creation%20via%20named%20pipe%20-%20Tchopper.evtx) _(explícito)_
- T1574.001 — [DE_timestomp_and_dll_sideloading_and_RunPersist](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/AutomatedTestingTools/Malware/DE_timestomp_and_dll_sideloading_and_RunPersist.evtx) _(inferido)_
- T1574.001 — [sideloading_injection_persistence_run_key](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/AutomatedTestingTools/Malware/sideloading_injection_persistence_run_key.evtx) _(inferido)_
- T1685 — [ID1-SYSMON driver unload (FilterManager)](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0005-Defense%20Evasion/T1562.001-Impair%20Defenses-Disable%20or%20Modify%20tool/ID1-SYSMON%20driver%20unload%20%28FilterManager%29.evtx) _(explícito)_
- T1685 — [ID13-Defender service configuration disabled](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0005-Defense%20Evasion/T1562.001-Impair%20Defenses-Disable%20or%20Modify%20tool/ID13-Defender%20service%20configuration%20disabled.evtx) _(explícito)_
- T1686 — [ID2003-4950-Firewall disabled](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0005-Defense%20Evasion/T1562.004-Impair%20Defenses-Disable%20or%20Modify%20System%20Firewall/ID2003-4950-Firewall%20disabled.evtx) _(explícito)_
- T1686 — [ID2004-Any any firewall rule created](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0005-Defense%20Evasion/T1562.004-Impair%20Defenses-Disable%20or%20Modify%20System%20Firewall/ID2004-Any%20any%20firewall%20rule%20created.evtx) _(explícito)_

## 9. Hipóteses de hunting

Se Velvet Ant estiver no seu ambiente, estas são as perguntas a fazer aos seus dados (fontes de log segundo as estratégias de detecção do MITRE ATT&CK).

1. **T1132 Data Encoding** — Atypical processes (e.g., powershell.exe, regsvr32.exe) encode large outbound traffic using Base64 or other character encodings; this traffic is sent over uncommon ports or embedded in protocol fields (e.g., HTTP cookies or headers). Dados: `WinEventLog:Sysmon` (EventCode=3, 22), `WinEventLog:Sysmon` (EventCode=1), `NSM:Flow` (Unusual Base64-encoded content in URI, headers, or POST body).
2. **T1211 Exploitation for Stealth** — Detects exploitation attempts targeting defensive security software or OS services. Defender observation includes abnormal process behavior (e.g., AV or EDR crashing unexpectedly), unsigned/untrusted modules loaded into defensive processes, or privilege… Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=7).
3. **T1037.004 RC Scripts** — Detection of modified or newly created /etc/rc.local or /etc/init.d scripts followed by suspicious execution during system startup. Dados: `auditd:SYSCALL` (execve), `linux:syslog` (boot logs).
4. **T1071 Application Layer Protocol** — Detects suspicious usage of common application-layer protocols (e.g., HTTP, HTTPS, DNS, SMB) by abnormal processes, with high outbound byte counts or irregular ports, possibly indicating command and control or data exfiltration. Dados: `NSM:Flow` (http, dns, smb, ssl logs), `WinEventLog:Sysmon` (EventCode=3, 22).
5. **T1040 Network Sniffing** — Detects suspicious execution of network monitoring tools (e.g., Wireshark, tshark, Microsoft Message Analyzer), driver loading indicative of promiscuous mode, or non-admin user privilege escalation to access NICs for capture. Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:System` (EventCode=7045).
6. **T1090.001 Internal Proxy** — Anomalous process (e.g., `rundll32`, `svchost`, `cmd`) initiates connections to internal peer hosts not seen in typical communication baselines, used to proxy or forward traffic internally, often using SMB, RPC, or high ports. Dados: `WinEventLog:Sysmon` (EventCode=3, 22), `WinEventLog:Sysmon` (EventCode=1), `Windows Firewall Log` (SMB over high port).
7. **T1573.002 Asymmetric Cryptography** — Processes not typically associated with encryption loading asymmetric crypto libraries (e.g., rsaenh.dll, crypt32.dll) and subsequently initiating outbound TLS/SSL connections with abnormal certificate chains or handshakes. Defender correlates process… Dados: `WinEventLog:Sysmon` (EventCode=7), `WinEventLog:Sysmon` (EventCode=3, 22).
8. **T1059.004 Unix Shell** — Detects bash, sh, zsh, or BusyBox shell execution initiated via remote sessions, unauthorized users, or embedded within secondary script interpreters. Focus is on chained behavior: shell > suspicious commands > network discovery or persistence indicators. Dados: `auditd:SYSCALL` (execve), `linux:osquery` (socket_events), `linux:syslog` (auth.log / secure.log).
9. **T1686 Disable or Modify System Firewall** — Detection of firewall tampering by monitoring processes executing netsh, PowerShell Set-NetFirewallProfile, or sc stop mpssvc. Registry modifications under HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy also indicate adversarial… Dados: `WinEventLog:Security` (EventCode=4688), `WinEventLog:Sysmon` (EventCode=13, 14).
10. **T1078.003 Local Accounts** — Detects anomalous usage of local accounts to log into a system, especially accounts not typically used interactively or outside business hours. Dados: `WinEventLog:Security` (EventCode=4624, 4648), `WinEventLog:Security` (EventCode=4672).
11. **T1055 Process Injection** — Detects process injection by correlating memory manipulation API calls (e.g., VirtualAllocEx, WriteProcessMemory), suspicious thread creation (e.g., CreateRemoteThread), and unusual DLL loads within another process's context. Dados: `WinEventLog:Sysmon` (EventCode=10), `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=7).
12. **T1569.002 Service Execution** — Detection focuses on abnormal service executions initiated via service control manager APIs, sc.exe, net.exe, or PsExec creating temporary services. Defenders observe process creation of services.exe spawning non-standard binaries, registry changes in service… Dados: `WinEventLog:Security` (EventCode=4697), `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Sysmon` (EventCode=13, 14).

## 10. OSINT — onde pesquisar

Consultas prontas com todos os nomes conhecidos do grupo:

- Relatórios técnicos: [busca web](https://duckduckgo.com/?q=%28%22Velvet+Ant%22%29+threat+report) · [PDFs](https://duckduckgo.com/?q=%28%22Velvet+Ant%22%29+filetype%3Apdf)
- Regras e IOCs publicados: [GitHub](https://github.com/search?type=code&q=%22Velvet+Ant%22)
- Pulsos de ameaça: [AlienVault OTX](https://otx.alienvault.com/browse/global/pulses?q=Velvet+Ant)
- Família de malware e atores: [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/actors) (busque por Velvet Ant)
- Cartões de grupo: [ThaiCERT Threat Group Cards](https://apt.etda.or.th/cgi-bin/listgroups.cgi)
- Página oficial: [MITRE ATT&CK G1047](https://attack.mitre.org/groups/G1047/)

**Relatórios na coleção CyberMonitor** (ligados pelo nome do grupo, conferir antes de citar):

- 2024 — [In-Depth Analysis_ Velvet Ant's Prolonged Cyber Attack on a Large Organization](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/blob/master/2024/2024.06.16.velvet-ant/In-Depth%20Analysis_%20Velvet%20Ant%27s%20Prolonged%20Cyber%20Attack%20on%20a%20Large%20Organization.pdf) _(via “Velvet Ant”)_

## 11. Bibliografia (2 fontes citadas pelo ATT&CK)

- [Sygnia VelvetAnt 2024A](https://www.sygnia.co/blog/china-nexus-threat-group-velvet-ant/) — Sygnia Team. (2024, June 3). China-Nexus Threat Group ‘Velvet Ant’ Abuses F5 Load Balancers for Persistence. Retrieved March 14, 2025.
- [Sygnia VelvetAnt 2024B](https://www.sygnia.co/threat-reports-and-advisories/china-nexus-threat-group-velvet-ant-exploits-cisco-0-day/) — Sygnia Team. (2024, July 1). China-Nexus Threat Group ‘Velvet Ant’ Exploits Cisco Zero-Day (CVE-2024-20399) to Compromise Nexus Switch Devices – Advisory for Mitigation and Response. Retrieved March 14, 2025.

## 12. Limites e confiança

- O ATT&CK registra o que foi **relatado publicamente**, não tudo o que o grupo faz. Ausência de uma técnica não prova que o grupo não a usa.
- **Sobreposição de TTP não é atribuição.** Muitas técnicas são compartilhadas entre grupos e com red teams. Use a assinatura comportamental como hipótese, junto com infraestrutura, malware e contexto.
- Cobertura de detecção refere-se ao catálogo público Detection Rules, não ao seu ambiente: confira se a telemetria necessária chega ao seu SIEM.
- Ligações marcadas como _inferidas_ (EVTX por palavra-chave, relatórios por nome) devem ser verificadas.

---
Fontes: MITRE ATT&CK® (uso livre com atribuição, © The MITRE Corporation), Atomic Red Team (Red Canary, MIT), EVTX-to-MITRE-Attack, EVTX-ATTACK-SAMPLES, APT & CyberCriminal Campaign Collections. Gerado por [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules).
