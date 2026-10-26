# macOS — relatório de regras de detecção

> **TLP:CLEAR** · 2026-10-26 · domínio **Endpoint** · plataforma ATT&CK **macOS** · lente TCEM **Detection & Validation** · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#techno=macos)

## 1. A história em um parágrafo

O palco é **Macs de desenvolvedores e executivos — poucos, mas com acessos valiosos**. O catálogo reúne **771 regras** que olham para cá — 635 de detecção, 31 de hunting, 100 assinaturas e 5 playbooks de resposta. Elas se concentram em **Execução, Escalação de privilégio, Persistência**. Das 357 técnicas do ATT&CK para a plataforma macOS, **171 (48%)** têm ao menos uma regra aqui e **186 não têm nenhuma** — é onde um atacante passa sem ser visto. Entre os grupos com mais técnicas nesta plataforma estão APT38, Kimsuky, Lazarus Group.

**Lente TCEM — Detection & Validation.** Threat-informed telemetry, analytics, validation, retest and analyst-response context. Para observar: sensor health, event quality, normalization, correlation, alert disposition. Arquitetura a mapear: sensors, collection pipelines, SIEM, EDR, correlation, case management.

## 2. Números

| Indicador | Valor |
|---|---:|
| Regras | 771 |
| detecção | 635 |
| assinatura | 100 |
| hunting | 31 |
| playbook | 5 |
| Técnicas ATT&CK distintas | 195 |
| Cobertura da plataforma macOS | 171/357 (48%) |

### Por tática

| Tática | Regras |
|---|---:|
| Desenv. de recursos | 1 |
| Acesso inicial | 51 |
| Execução | 242 |
| Persistência | 115 |
| Escalação de privilégio | 123 |
| Furtividade | 114 |
| Enfraquecimento de defesas | 51 |
| Acesso a credenciais | 76 |
| Descoberta | 46 |
| Movimento lateral | 9 |
| Coleta | 35 |
| Comando e controle | 100 |
| Exfiltração | 9 |
| Impacto | 7 |

### Linguagens disponíveis

Em que formato você encontra regra pronta para esta tecnologia.

| Formato | Regras |
|---|---:|
| Elastic | 436 |
| Sigma | 105 |
| Suricata/Snort/Sagan | 100 |
| Wazuh | 57 |
| Splunk | 33 |
| Panther | 13 |
| Sentinel KQL | 12 |
| YARA-L | 10 |
| Playbook | 5 |

### Padrões de correlação (TCEM)

Como as regras decidem. Muitas de evento único = cobertura ampla mas ruidosa; sequências e novidade = mais contexto, mais exigência de dados.

| Padrão | Regras | O que significa |
|---|---:|---|
| Evento único | 483 | Um evento, sozinho, já tem sinal suficiente para chamar o analista. |
| Sequência ordenada | 147 | Dois ou mais passos da mesma entidade, na ordem certa, dentro de uma janela. |
| Novidade / raridade | 109 | Compara com o que é normal: entidade, relação ou valor nunca (ou raramente) visto. |
| Mudança de estado | 15 | O risco está na transição: algo era seguro e deixou de ser (desligado, rebaixado, alterado). |
| Limiar / acúmulo | 11 | O sinal está na repetição: N eventos por chave em uma janela. |
| Fluxo de resposta | 5 | Não detecta: orquestra o que fazer depois do alerta (SOAR). |
| Assinatura de conteúdo | 1 | Casa bytes/strings dentro de arquivo, memória ou pacote, não eventos de log. |

### Fontes que mais contribuem

| Fonte | Regras |
|---|---:|
| Elastic protections-artifacts (behavior) | 305 |
| Elastic detection-rules | 116 |
| Sagan rules (Quadrant) | 99 |
| SigmaHQ | 75 |
| OpenSearch Security Analytics | 30 |
| wazuh-detection-engineering (Jeremy-Burgos) | 29 |
| Wazuh ruleset (oficial) | 28 |
| Splunk security_content | 25 |
| Elastic hunting queries | 15 |
| Panther panther-analysis | 13 |

## 3. Técnicas mais cobertas

| Técnica | Regras nesta tecnologia |
|---|---:|
| [T1059](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059) Command and Scripting Interpreter | 168 |
| [T1059.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.004) Unix Shell | 84 |
| [T1105](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1105) Ingress Tool Transfer | 67 |
| [T1059.006](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.006) Python | 50 |
| [T1059.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.002) AppleScript | 46 |
| [T1059.007](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1059.007) JavaScript | 31 |
| [T1071](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1071) Application Layer Protocol | 24 |
| [T1204](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1204) User Execution | 23 |
| [T1555](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1555) Credentials from Password Stores | 23 |
| [T1552.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1552.001) Credentials In Files | 22 |
| [T1027](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1027) Obfuscated Files or Information | 21 |
| [T1543](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1543) Create or Modify System Process | 21 |

## 4. Detecção pela ausência — o que ninguém está olhando (186 técnicas)

Técnicas do ATT&CK para macOS **sem nenhuma regra nesta tecnologia**, ordenadas pelo número de grupos que as usam. A coluna "regras no catálogo" mostra se existe cobertura em outra tecnologia (ex.: EDR ou rede) que você pode adaptar.

| Técnica | Grupos que usam | Regras no catálogo (todas as tecnologias) |
|---|---:|---:|
| [T1027.010](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1027.010) Command Obfuscation | 31 | 78 |
| [T1505.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1505.003) Web Shell | 31 | 210 |
| [T1041](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1041) Exfiltration Over C2 Channel | 28 | 135 |
| [T1553.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1553.002) Code Signing | 28 | 11 |
| [T1056.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1056.001) Keylogging | 26 | 40 |
| [T1027.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1027.002) Software Packing | 24 | 12 |
| [T1078.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078.002) Domain Accounts | 21 | 36 |
| [T1090](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1090) Proxy | 20 | 268 |
| [T1570](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1570) Lateral Tool Transfer | 19 | 58 |
| [T1657](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1657) Financial Theft | 19 | 2 |
| [T1684.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1684.001) Impersonation | 18 | 1 |
| [T1007](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1007) System Service Discovery | 16 | 37 |
| [T1135](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1135) Network Share Discovery | 16 | 73 |
| [T1124](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1124) System Time Discovery | 15 | 18 |
| [T1566.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1566.003) Spearphishing via Service | 15 | 8 |
| [T1572](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1572) Protocol Tunneling | 15 | 173 |
| [T1199](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1199) Trusted Relationship | 14 | 18 |
| [T1573.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1573.001) Symmetric Cryptography | 14 | 5 |
| [T1090.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1090.003) Multi-hop Proxy | 13 | 44 |
| [T1095](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1095) Non-Application Layer Protocol | 13 | 72 |

## 5. Quem mira esta plataforma

Grupos com mais técnicas registradas nesta plataforma e quantas delas você enxerga com as regras desta tecnologia. País atribuído pelo APT4ALL (afirmação de quem publicou).

| Grupo | Origem atribuída | Técnicas na plataforma | Com regra aqui | Exemplos sem regra |
|---|---|---:|---:|---|
| [APT38](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0082) `G0082` | Coreia do Norte | 86 | 58 | T1027.002, T1027.010, T1027.015, T1027.016 |
| [Kimsuky](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0094) `G0094` | Coreia do Norte | 84 | 56 | T1007, T1020, T1027.002, T1027.010 |
| [Lazarus Group](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0032) `G0032` | Coreia do Norte | 63 | 45 | T1001.003, T1010, T1041, T1048.003 |
| [APT28](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0007) `G0007` | Rússia | 57 | 38 | T1001.001, T1014, T1025, T1039 |
| [Mustang Panda](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0129) `G0129` | China | 57 | 40 | T1001.003, T1027.016, T1036.008, T1041 |
| [OilRig](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0049) `G0049` | Irã | 55 | 42 | T1007, T1025, T1027.005, T1048.003 |
| [APT41](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0096) `G0096` | China | 54 | 41 | T1014, T1027.002, T1056.001, T1071.002 |
| [Volt Typhoon](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1017) `G1017` | China | 54 | 35 | T1007, T1010, T1027.002, T1036.008 |
| [Gamaredon Group](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0047) `G0047` | Rússia | 51 | 29 | T1001, T1020, T1021.005, T1025 |
| [Sandworm Team](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0034) `G0034` | Rússia | 51 | 38 | T1027.010, T1041, T1056.001, T1078.002 |
| [Magic Hound](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0059) `G0059` | Irã | 48 | 36 | T1016.002, T1027.010, T1036.010, T1056.001 |
| [MuddyWater](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0069) `G0069` | Irã | 48 | 37 | T1027.003, T1027.004, T1027.010, T1041 |
| [Turla](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0010) `G0010` | Rússia | 48 | 35 | T1007, T1025, T1027.005, T1027.010 |
| [APT32](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0050) `G0050` | Vietnã | 47 | 39 | T1027.010, T1027.016, T1041, T1048.003 |

## 9. Regras recomendadas para começar

Ranqueadas por portabilidade do formato, maturidade, severidade e por mapearem técnica ATT&CK.

| Regra | Formato | Fonte | Técnicas |
|---|---|---|---|
| [JXA In-memory Execution Via OSAScript](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Af1408a58-0e94-4165-b80a-da9f96cf6fc3) | Sigma | SigmaHQ | T1059.007 |
| [Binary Padding - MacOS](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A95361ce5-c891-4b0a-87ca-e24607884a96) | Sigma | SigmaHQ | T1027.001 |
| [Credentials In Files](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A53b1b378-9b06-4992-b972-dde6e423d2b4) | Sigma | SigmaHQ | T1552.001 |
| [Potential Base64 Decoded From Images](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A09a910bf-f71f-4737-9c40-88880ba5913d) | Sigma | SigmaHQ | T1140 |
| [Potential Persistence Via PlistBuddy](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A65d506d3-fcfe-4071-b4b2-bcefe721bbbb) | Sigma | SigmaHQ | T1543.001, T1543.004 |
| [Suspicious Microsoft Office Child Process - MacOS](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A69483748-1525-4a6c-95ca-90dc8d431b68) | Sigma | SigmaHQ | T1059.002, T1137.002, T1204.002 |
| [Binary Padding](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A95361ce5-c891-4b0a-87ca-e24607884a96) | Sigma | OpenSearch Security Analytics | T1027.001 |
| [Potential Credential Discovery via Recursive Grep](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Ab8e4c2a1-7f3d-4e9b-8c5a-1d0e6f2a4b8c) | Elastic | Elastic detection-rules | T1083, T1552, T1552.001 |
| [Suspicious Process Execution by Zoom](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A84b81b96-58dd-4c0d-9b2e-35023ab5ee88) | Elastic | Elastic detection-rules | T1059, T1059.002, T1059.004 |
| [Long Base64 Encoded Command via Scripting Interpreter](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A74d31cb7-4a2c-44fe-9d1d-f375b9f3cb61) | Elastic | Elastic detection-rules | T1027, T1059, T1059.001 |
| [Potential Successful SSH Brute Force Attack via macOS Security Events](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Af5898b1e-3071-4597-b066-43d298c7b415) | Elastic | Elastic detection-rules | T1078, T1078.003, T1110 |
| [Curl Execution via Shell Profile](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Aafdca1e0-0f8a-4fcf-9e1e-95e09791e3cd) | Elastic | Elastic detection-rules | T1059, T1059.004, T1105 |
| [Suspicious Curl to Jamf Endpoint](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Aa8256685-9736-465b-b159-f25a172d08e8) | Elastic | Elastic detection-rules | T1059, T1059.002, T1059.006 |
| [Privilege Escalation via Parallels Appliance Extract Argument Injection](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A448dbe05-07b1-46bb-b3e3-ac9790387948) | Elastic | Elastic detection-rules | T1068, T1202 |
| [Keychain Password Retrieval via Command Line](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A9092cd6c-650f-4fa3-8a8a-28256c7489c9) | Elastic | Elastic detection-rules | T1555, T1555.001, T1555.003 |

## 10. Limites

- A tecnologia de cada regra é inferida por heurística sobre metadados e texto (techmap.py). Regras genéricas podem aparecer em várias tecnologias.
- "Sem regra" quer dizer sem regra pública neste catálogo, não sem detecção possível. Telemetria e contexto do seu ambiente decidem.
- Atribuição de país é afirmação das fontes reunidas pelo APT4ALL, não nossa.

---
Fontes: catálogo [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules), MITRE ATT&CK®, APT4ALL, Ransomware Tool Matrix (CC BY 4.0), TCEM, LLmInjection. Gerado em 2026-10-26.
