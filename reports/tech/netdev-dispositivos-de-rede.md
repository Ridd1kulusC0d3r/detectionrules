# Dispositivos de rede — relatório de regras de detecção

> **TLP:CLEAR** · 2026-10-26 · domínio **Rede** · plataforma ATT&CK **Network Devices** · lente TCEM **IoT & Embedded** · [abrir no site](https://ridd1kulusc0d3r.github.io/detectionrules/#techno=netdev)

## 1. A história em um parágrafo

O palco é **roteadores e switches — a infraestrutura que quase ninguém monitora**. O catálogo reúne **557 regras** que olham para cá — 156 de detecção, 30 de hunting, 351 assinaturas e 20 playbooks de resposta. Elas se concentram em **Acesso inicial, Furtividade, Persistência**. Das 100 técnicas do ATT&CK para a plataforma Network Devices, **36 (36%)** têm ao menos uma regra aqui e **64 não têm nenhuma** — é onde um atacante passa sem ser visto. Entre os grupos com mais técnicas nesta plataforma estão Salt Typhoon, Lazarus Group, APT41.

**Lente TCEM — IoT & Embedded.** Devices, firmware, management interfaces, fleet identity, update trust and constrained telemetry. Para observar: device inventory, update events, gateway telemetry, management audit. Arquitetura a mapear: device identity, firmware/update chain, fleet management, gateways.

## 2. Números

| Indicador | Valor |
|---|---:|
| Regras | 557 |
| assinatura | 351 |
| detecção | 156 |
| hunting | 30 |
| playbook | 20 |
| Técnicas ATT&CK distintas | 65 |
| Cobertura da plataforma Network Devices | 36/100 (36%) |

### Por tática

| Tática | Regras |
|---|---:|
| Reconhecimento | 1 |
| Acesso inicial | 22 |
| Execução | 5 |
| Persistência | 16 |
| Escalação de privilégio | 14 |
| Furtividade | 18 |
| Enfraquecimento de defesas | 6 |
| Acesso a credenciais | 12 |
| Descoberta | 7 |
| Movimento lateral | 8 |
| Coleta | 13 |
| Comando e controle | 15 |
| Exfiltração | 7 |
| Impacto | 15 |

### Linguagens disponíveis

Em que formato você encontra regra pronta para esta tecnologia.

| Formato | Regras |
|---|---:|
| Suricata/Snort/Sagan | 351 |
| Sentinel KQL | 66 |
| Splunk | 51 |
| Wazuh | 31 |
| Sigma | 23 |
| Playbook | 20 |
| Elastic | 10 |
| YARA-L | 4 |
| KQL hunting | 1 |

### Padrões de correlação (TCEM)

Como as regras decidem. Muitas de evento único = cobertura ampla mas ruidosa; sequências e novidade = mais contexto, mais exigência de dados.

| Padrão | Regras | O que significa |
|---|---:|---|
| Evento único | 425 | Um evento, sozinho, já tem sinal suficiente para chamar o analista. |
| Novidade / raridade | 51 | Compara com o que é normal: entidade, relação ou valor nunca (ou raramente) visto. |
| Limiar / acúmulo | 45 | O sinal está na repetição: N eventos por chave em uma janela. |
| Fluxo de resposta | 20 | Não detecta: orquestra o que fazer depois do alerta (SOAR). |
| Mudança de estado | 9 | O risco está na transição: algo era seguro e deixou de ser (desligado, rebaixado, alterado). |
| Sequência ordenada | 7 | Dois ou mais passos da mesma entidade, na ordem certa, dentro de uma janela. |

### Fontes que mais contribuem

| Fonte | Regras |
|---|---:|
| Sagan rules (Quadrant) | 351 |
| Microsoft Sentinel (Analytic Rules) | 45 |
| Splunk security_content | 43 |
| Wazuh ruleset (oficial) | 25 |
| Microsoft Sentinel (Hunting Queries) | 21 |
| SigmaHQ | 15 |
| Elastic detection-rules | 10 |
| OpenSearch Security Analytics | 8 |
| Splunk analytic stories | 8 |
| Cortex XSOAR (demisto/content) | 8 |

## 3. Técnicas mais cobertas

| Técnica | Regras nesta tecnologia |
|---|---:|
| [T1190](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1190) Exploit Public-Facing Application | 10 |
| [T1078](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1078) Valid Accounts | 7 |
| [T1041](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1041) Exfiltration Over C2 Channel | 6 |
| [T1557](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1557) Adversary-in-the-Middle | 6 |
| [T1071](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1071) Application Layer Protocol | 6 |
| [T1498](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1498) Network Denial of Service | 5 |
| [T1499](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1499) Endpoint Denial of Service | 5 |
| [T1572](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1572) Protocol Tunneling | 5 |
| [T1571](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1571) Non-Standard Port | 5 |
| [T1016](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1016) System Network Configuration Discovery | 4 |
| [T1036](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1036) Masquerading | 4 |
| [T1565.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1565.002) Transmitted Data Manipulation | 4 |

## 4. Detecção pela ausência — o que ninguém está olhando (64 técnicas)

Técnicas do ATT&CK para Network Devices **sem nenhuma regra nesta tecnologia**, ordenadas pelo número de grupos que as usam. A coluna "regras no catálogo" mostra se existe cobertura em outra tecnologia (ex.: EDR ou rede) que você pode adaptar.

| Técnica | Grupos que usam | Regras no catálogo (todas as tecnologias) |
|---|---:|---:|
| [T1071.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1071.001) Web Protocols | 58 | 228 |
| [T1056.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1056.001) Keylogging | 26 | 40 |
| [T1110](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1110) Brute Force | 16 | 552 |
| [T1136.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1136.001) Local Account | 16 | 103 |
| [T1573.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1573.001) Symmetric Cryptography | 14 | 5 |
| [T1090.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1090.003) Multi-hop Proxy | 13 | 44 |
| [T1686](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1686) Disable or Modify System Firewall | 13 | 191 |
| [T1110.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1110.003) Password Spraying | 12 | 62 |
| [T1573.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1573.002) Asymmetric Cryptography | 12 | 14 |
| [T1071.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1071.004) DNS | 11 | 117 |
| [T1090.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1090.002) External Proxy | 11 | 18 |
| [T1070.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1070.003) Clear Command History | 10 | 63 |
| [T1072](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1072) Software Deployment Tools | 10 | 59 |
| [T1090.001](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1090.001) Internal Proxy | 9 | 43 |
| [T1552.004](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1552.004) Private Keys | 8 | 60 |
| [T1020](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1020) Automated Exfiltration | 7 | 69 |
| [T1490](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1490) Inhibit System Recovery | 7 | 188 |
| [T1071.003](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1071.003) Mail Protocols | 6 | 6 |
| [T1561.002](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1561.002) Disk Structure Wipe | 6 | 2 |
| [T1037](https://ridd1kulusc0d3r.github.io/detectionrules/#tech=T1037) Boot or Logon Initialization Scripts | 4 | 91 |

## 5. Quem mira esta plataforma

Grupos com mais técnicas registradas nesta plataforma e quantas delas você enxerga com as regras desta tecnologia. País atribuído pelo APT4ALL (afirmação de quem publicou).

| Grupo | Origem atribuída | Técnicas na plataforma | Com regra aqui | Exemplos sem regra |
|---|---|---:|---:|---|
| [Salt Typhoon](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1045) `G1045` | China | 33 | 17 | T1020.001, T1059.008, T1070.003, T1070.007 |
| [Lazarus Group](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0032) `G0032` | Coreia do Norte | 25 | 14 | T1056.001, T1070, T1070.003, T1071.001 |
| [APT41](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0096) `G0096` | China | 24 | 16 | T1037, T1056.001, T1070.003, T1071.001 |
| [Kimsuky](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0094) `G0094` | Coreia do Norte | 24 | 16 | T1020, T1056.001, T1071.001, T1071.003 |
| [Volt Typhoon](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1017) `G1017` | China | 23 | 16 | T1006, T1056.001, T1070.007, T1090.001 |
| [APT38](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0082) `G0082` | Coreia do Norte | 22 | 12 | T1056.001, T1070.003, T1071.001, T1110 |
| [Magic Hound](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0059) `G0059` | Irã | 21 | 15 | T1056.001, T1070.003, T1071.001, T1078.001 |
| [Medusa Group](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G1051) `G1051` | Sem país atribuído | 21 | 12 | T1070.003, T1071.001, T1072, T1090.003 |
| [APT28](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0007) `G0007` | Rússia | 19 | 8 | T1056.001, T1071.001, T1071.003, T1090.002 |
| [Mustang Panda](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0129) `G0129` | China | 19 | 14 | T1070, T1071.001, T1072, T1205 |
| [APT39](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0087) `G0087` | Irã | 18 | 10 | T1056, T1056.001, T1071.001, T1071.004 |
| [OilRig](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0049) `G0049` | Irã | 18 | 13 | T1056.001, T1071.001, T1071.004, T1110 |
| [Sandworm Team](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0034) `G0034` | Rússia | 18 | 13 | T1056.001, T1071.001, T1072, T1490 |
| [Ke3chang](https://ridd1kulusc0d3r.github.io/detectionrules/#group=G0004) `G0004` | China | 17 | 13 | T1020, T1056.001, T1071.001, T1071.004 |

## 9. Regras recomendadas para começar

Ranqueadas por portabilidade do formato, maturidade, severidade e por mapearem técnica ATT&CK.

| Regra | Formato | Fonte | Técnicas |
|---|---|---|---|
| [Potential Information Disclosure CVE-2023-43261 Exploitation - Proxy](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Af48f5368-355c-4a1b-8bf5-11c13d589eaa) | Sigma | SigmaHQ | T1190 |
| [Potential Information Disclosure CVE-2023-43261 Exploitation - Web](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Aa2bcca38-9f3a-4d5e-b603-0c587e8569d7) | Sigma | SigmaHQ | T1190 |
| [Arcadyan Router Exploitations](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Af0500377-bc70-425d-ac8c-e956cd906871) | Sigma | SigmaHQ | T1190 |
| [OpenCanary - TFTP Request](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ab4e6b016-a2ac-4759-ad85-8000b300d61e) | Sigma | SigmaHQ | T1041 |
| [OpenCanary - SNMP OID Request](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ae9856028-fd4e-46e6-b3d1-10f7ceb95078) | Sigma | SigmaHQ | T1016, T1021 |
| [WMIC Loading Scripting Libraries](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A06ce37c2-61ab-4f05-9ff5-b1a96d18ae32) | Sigma | OpenSearch Security Analytics | T1220 |
| [ICMP Redirect Message from Internal Host](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A2014ebd8-b847-4cc0-a827-d0d61ec88680) | Elastic | Elastic detection-rules | T1557 |
| [Zimbra Swatchdog SNMP Command Injection Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A1fa1a434-75a7-4c58-9bef-331d62bf3f82) | Elastic | Elastic detection-rules | T1059, T1059.004, T1190 |
| [Cisco Discovery](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A9705a6a1-6db6-4a16-a987-15b7151e299b) | Sigma | SigmaHQ | T1016, T1018, T1033 |
| [Cisco Stage Data](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3A5e51acb2-bcbe-435b-99c6-0e3cd5e2aa59) | Sigma | SigmaHQ | T1074, T1105, T1560.001 |
| [Suspicious CodePage Switch Via CHCP](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=sigmahq%3A%3Ac7942406-33dd-4377-a564-0f62db0593a3) | Sigma | SigmaHQ | T1036 |
| [Winword.exe Loads Suspicious DLL](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=opensearch-security-analytics%3A%3A2621b3a6-3840-4810-ac14-a02426086171) | Sigma | OpenSearch Security Analytics | T1202 |
| [Potential Third-Party Cloud Storage Client Execution](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3Aab05c807-e12b-4ec1-8380-844a65c9fef1) | Elastic | Elastic detection-rules | T1530, T1537, T1567 |
| [M365 Identity OAuth ROPC Grant via Legacy Authentication Client](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A3d753eb2-68c4-404a-9279-91a3ad490765) | Elastic | Elastic detection-rules | T1078, T1078.004 |
| [Potential Persistence via Time Provider Modification](https://ridd1kulusc0d3r.github.io/detectionrules/#rule=elastic-detection-rules%3A%3A14ed1aa9-ebfd-4cf9-a463-0ac59ec55204) | Elastic | Elastic detection-rules | T1547, T1547.003 |

## 10. Limites

- A tecnologia de cada regra é inferida por heurística sobre metadados e texto (techmap.py). Regras genéricas podem aparecer em várias tecnologias.
- "Sem regra" quer dizer sem regra pública neste catálogo, não sem detecção possível. Telemetria e contexto do seu ambiente decidem.
- Atribuição de país é afirmação das fontes reunidas pelo APT4ALL, não nossa.

---
Fontes: catálogo [Detection Rules](https://github.com/Ridd1kulusC0d3r/detectionrules), MITRE ATT&CK®, APT4ALL, Ransomware Tool Matrix (CC BY 4.0), TCEM, LLmInjection. Gerado em 2026-10-26.
