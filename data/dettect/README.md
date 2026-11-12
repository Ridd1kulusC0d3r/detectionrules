# Arquivos para o DeTT&CT

Gerados por [`build_dettect.py`](../../build_dettect.py) a partir do catálogo. A ideia vem do
[Dettectinator](https://github.com/siriussecurity/dettectinator): produzir os YAML do
[DeTT&CT](https://github.com/rabobank-cdc/DeTTECT) a partir das regras, em vez de preencher a mão.

| Arquivo | Tipo DeTT&CT | Conteúdo |
|---|---|---|
| `techniques-all.yaml` | technique-administration | Todas as linguagens. Em cada técnica, uma linha por fonte com a contagem de regras. |
| `techniques-<formato>.yaml` | technique-administration | Uma linguagem só (sigma, elastic, splunk, sentinel, kql-md, yaral, wazuh, suricata, panther, falco, gcp, yara, aql). Em cada técnica, até 20 nomes de regra. |
| `data-sources-sysmon.yaml` | data-source-administration | Componentes de dados que o Sysmon registra, com o EventID de cada um. |
| `data-sources-windows-security.yaml` | data-source-administration | O mesmo para o Windows Security Auditing. |
| `data-sources-defender-endpoint.yaml` | data-source-administration | O mesmo para as tabelas e ActionTypes do Defender for Endpoint. |
| `index.json` | | Lista dos arquivos com contagens. |

## Como usar

1. Abra o [DeTT&CT Editor](https://rabobank-cdc.github.io/dettect-editor) e carregue o arquivo da linguagem do seu SIEM.
2. Apague as técnicas cujas regras você não implantou e ajuste a nota das que implantou e testou.
3. Gere a camada do ATT&CK Navigator: `python dettect.py d -ft techniques-sigma.yaml -l`.

## Leia antes de confiar

- **É uma linha de base, não a sua cobertura.** Toda técnica sai com nota de detecção 1 ("regra pública disponível, ainda não validada"). A nota real depende de você implantar, alimentar com os logs certos e testar.
- **Visibilidade fica em 0.** O catálogo não sabe quais logs você coleta. Use os `data-sources-*.yaml` como ponto de partida e preencha `date_connected` e `data_quality`.
- **Os `data-sources-*.yaml` são modelos.** Listam o que a fonte é capaz de registrar segundo o [OSSEM-DM](https://github.com/OTRF/OSSEM-DM) (MIT), não o que está ligado no seu ambiente.
- **Versão do ATT&CK.** Os IDs seguem a versão usada pelo catálogo (veja o cabeçalho de cada arquivo). Um DeTT&CT com versão mais antiga ignora as técnicas que não conhece.
- Playbooks SOAR ficam de fora: respondem, não detectam.
