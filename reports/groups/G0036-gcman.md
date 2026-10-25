# GCMAN (G0036) — Dossiê de inteligência

> **TLP:CLEAR** · gerado em 2026-10-25 a partir de fontes abertas · MITRE ATT&CK v20.0 · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0036) · [ATT&CK](https://attack.mitre.org/groups/G0036/)

**Também conhecido como:** —  
**Registro no ATT&CK:** criado em 2017-05-31, atualizado em 2026-07-31 · referências de 2016 a 2016

## 1. Sumário executivo

- **2 técnicas** atribuídas publicamente, concentradas em **Lateral Movement**.
- **Arsenal:** 0 malware e 0 ferramentas.
- **Campanhas atribuídas:** 0.
- **Cobertura de detecção pública:** 100% das técnicas têm ao menos uma regra no catálogo; **0 técnicas sem nenhuma regra pública**.
- **Assinatura comportamental** (técnicas raras entre os 178 grupos, as mais úteis para atribuição): T1021.005 VNC, T1021.004 SSH.

## 2. Quem é

> GCMAN is a threat group that focuses on targeting banks for the purpose of transferring money to e-currency services.

_Texto original do MITRE ATT&CK, em inglês._

## 3. Perfil TTP por tática (kill chain)

Cada linha: técnica, como o grupo a usou segundo relatos públicos, e o que existe para detectar e testar.

### Lateral Movement (TA0008) — 2

| Técnica | Procedimento observado (EN) | Regras | Atomic | EVTX |
|---|---|---:|---:|---:|
| [T1021.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1021.004) SSH | GCMAN uses Putty for lateral movement. | 60 | 2 | 3 |
| [T1021.005](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1021.005) VNC | GCMAN uses VNC for lateral movement. | 7 | 1 | — |

## 4. Assinatura comportamental

Técnicas que este grupo usa e que poucos dos 178 grupos do ATT&CK usam. Pesam mais numa atribuição por TTP: ver várias delas juntas é mais informativo do que ver técnicas comuns como PowerShell.

| Técnica | Outros grupos que usam | Peso (raridade) |
|---|---:|---:|
| T1021.005 VNC | 3 | 3.58 |
| T1021.004 SSH | 18 | 2.19 |

## 5. Arsenal

Nenhum software atribuído no ATT&CK.

## 6. Campanhas

Nenhuma campanha atribuída no ATT&CK.

## 7. Cobertura defensiva

**2 de 2 técnicas (100%)** têm ao menos uma regra pública no catálogo Detection Rules.

### Regras recomendadas por técnica

Melhor regra disponível por técnica (formato portável e maduro primeiro).

| Técnica | Regra | Formato | Fonte |
|---|---|---|---|
| T1021.004 | [Potential THC Tool Downloaded](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A2ddc468e-b39b-4f5b-9825-f3dcb0e998ea) | Elastic | Elastic detection-rules |
| T1021.004 | [AWS EC2 CreateKeyPair by New Principal from Non-Cloud AS Organization](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ac8e4f1a2-9b3d-4c5e-a6f7-8b9c0d1e2f3a) | Elastic | Elastic detection-rules |
| T1021.005 | [Suspicious UltraVNC Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A871b9555-69ca-4993-99d3-35a59f9f3599) | Sigma | SigmaHQ |
| T1021.005 | [Suspicious UltraVNC Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A871b9555-69ca-4993-99d3-35a59f9f3599) | Sigma | OpenSearch Security Analytics |

## 8. Plano de emulação e validação

Use num laboratório isolado e autorizado para confirmar que as regras disparam. Os comandos estão nos repositórios oficiais.

| Tática | Técnica | Teste Atomic Red Team | Plataformas |
|---|---|---|---|
| Lateral Movement | [T1021.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.004/T1021.004.md) | ESXi - Enable SSH via PowerCLI | windows |
| Lateral Movement | [T1021.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.004/T1021.004.md) | ESXi - Enable SSH via VIM-CMD | windows |
| Lateral Movement | [T1021.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.005/T1021.005.md) | Enable Apple Remote Desktop Agent | macos |

**Logs reais de ataque (EVTX) para testar sem executar nada:**

- T1021.004 — [ID4-OpenSSH server listening](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0008-Lateral%20Movement/T1021.004-Remote%20Service%20SSH/ID4-OpenSSH%20server%20listening.evtx) _(explícito)_
- T1021.004 — [ID4103-4104-OpenSSH server activation and config](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack/blob/master/TA0008-Lateral%20Movement/T1021.004-Remote%20Service%20SSH/ID4103-4104-OpenSSH%20server%20activation%20and%20config.evtx) _(explícito)_

## 9. Hipóteses de hunting

Se GCMAN estiver no seu ambiente, estas são as perguntas a fazer aos seus dados (fontes de log segundo as estratégias de detecção do MITRE ATT&CK).

1. **T1021.005 VNC** — Detection of VNC service or executable starting unexpectedly, followed by user session creation and interactive desktop activity (mouse/keyboard simulation). Dados: `WinEventLog:Sysmon` (EventCode=1), `WinEventLog:Security` (EventCode=4624, 4648), `NSM:Flow` (port 5900 inbound).
2. **T1021.004 SSH** — SSH login from a remote system (via sshd), followed by user context execution of suspicious binaries or privilege escalation behavior. Dados: `auditd:EXECVE` (EXECVE), `linux:syslog` (None), `NSM:Flow` (TCP port 22 traffic).

## 10. OSINT — onde pesquisar

Consultas prontas com todos os nomes conhecidos do grupo:

- Relatórios técnicos: [busca web](https://duckduckgo.com/?q=%28%22GCMAN%22%29+threat+report) · [PDFs](https://duckduckgo.com/?q=%28%22GCMAN%22%29+filetype%3Apdf)
- Regras e IOCs publicados: [GitHub](https://github.com/search?type=code&q=%22GCMAN%22)
- Pulsos de ameaça: [AlienVault OTX](https://otx.alienvault.com/browse/global/pulses?q=GCMAN)
- Família de malware e atores: [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/actors) (busque por GCMAN)
- Cartões de grupo: [ThaiCERT Threat Group Cards](https://apt.etda.or.th/cgi-bin/listgroups.cgi)
- Página oficial: [MITRE ATT&CK G0036](https://attack.mitre.org/groups/G0036/)

## 11. Bibliografia (1 fontes citadas pelo ATT&CK)

- [Securelist GCMAN](https://securelist.com/apt-style-bank-robberies-increase-with-metel-gcman-and-carbanak-2-0-attacks/73638/) — Kaspersky Lab's Global Research & Analysis Team. (2016, February 8). APT-style bank robberies increase with Metel, GCMAN and Carbanak 2.0 attacks. Retrieved April 20, 2016.

## 12. Limites e confiança

- O ATT&CK registra o que foi **relatado publicamente**, não tudo o que o grupo faz. Ausência de uma técnica não prova que o grupo não a usa.
- **Sobreposição de TTP não é atribuição.** Muitas técnicas são compartilhadas entre grupos e com red teams. Use a assinatura comportamental como hipótese, junto com infraestrutura, malware e contexto.
- Cobertura de detecção refere-se ao catálogo público Detection Rules, não ao seu ambiente: confira se a telemetria necessária chega ao seu SIEM.
- Ligações marcadas como _inferidas_ (EVTX por palavra-chave, relatórios por nome) devem ser verificadas.

---
Fontes: MITRE ATT&CK® (uso livre com atribuição, © The MITRE Corporation), Atomic Red Team (Red Canary, MIT), EVTX-to-MITRE-Attack, EVTX-ATTACK-SAMPLES, APT & CyberCriminal Campaign Collections. Gerado por [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules).
