#!/usr/bin/env bash
# Clona (shallow) todas as fontes do catálogo na raiz do repo. Usado pelo GitHub Actions e localmente.
set -u
cd "$(dirname "$0")/.."
clone(){ # owner/repo destino
  [ -d "$2" ] && { echo "= $2 (já existe)"; return; }
  timeout 600 git clone -q --depth 1 "https://github.com/$1.git" "$2" && echo "OK $1" || echo "FALHOU $1"
}
sparse(){ # owner/repo destino [--branch X] -- padrões...
  local repo=$1 dest=$2; shift 2; local br=""
  if [ "${1:-}" = "--branch" ]; then br="--branch $2"; shift 2; fi
  [ -d "$dest" ] && { echo "= $dest (já existe)"; return; }
  timeout 900 git clone -q --depth 1 $br --filter=blob:none --sparse "https://github.com/$repo.git" "$dest" \
    && (cd "$dest" && git sparse-checkout set --no-cone "$@" >/dev/null 2>&1) && echo "OK $repo (sparse)" || echo "FALHOU $repo"
}
clone SigmaHQ/sigma sigma &
clone elastic/detection-rules elastic_detection-rules &
clone splunk/security_content splunk_security_content &
clone chronicle/detection-rules chronicle_detection-rules &
clone Yamato-Security/hayabusa-rules Yamato-Security_hayabusa-rules &
clone falcosecurity/rules falcosecurity_rules &
clone Neo23x0/signature-base Neo23x0_signature-base &
clone Yara-Rules/rules Yara-Rules_rules &
clone reversinglabs/reversinglabs-yara-rules reversinglabs_reversinglabs-yara-rules &
clone socfortress/Wazuh-Rules socfortress_Wazuh-Rules &
clone FalconForceTeam/FalconFriday FalconForceTeam_FalconFriday &
clone Bert-JanP/Hunting-Queries-Detection-Rules Bert-JanP_Hunting-Queries-Detection-Rules &
clone panther-labs/panther-analysis panther-labs_panther-analysis &
clone GoogleCloudPlatform/security-analytics gcp_secanalytics &
clone System-CTL/QRadar-AQL-Queries System-CTL_QRadar-AQL-Queries &
clone Cyb3rSn0rlax/QRadar-AQLQueries Cyb3rSn0rlax_QRadar-AQLQueries &
clone saifbelaarbi/evtx-wazuh-rules saifbelaarbi_evtx-wazuh-rules &
clone Jeremy-Burgos/wazuh-detection-engineering Jeremy-Burgos_wazuh-detection-engineering &
clone rowham/chronicle-detection-rules rowham_chronicle-detection-rules &
clone luduslibrum/awesome-playbooks luduslibrum_awesome-playbooks &
clone phantomcyber/playbooks phantomcyber_playbooks &
clone Shuffle/workflows Shuffle_workflows &
clone elastic/protections-artifacts elastic_protections-artifacts &
clone travisbgreen/hunting-rules mir_hunting-rules &
clone quadrantsec/sagan-rules mir_sagan-rules &
clone aleksibovellan/opnsense-suricata-nmaps mir_opnsense-suricata-nmaps &
clone SpiderLabs/malware-analysis spiderlabs_ma &
# índices (sem baixar binários): amostras EVTX e relatórios APT
noblob(){ [ -d "$2" ] && return; timeout 600 git clone -q --depth 1 --filter=blob:none --no-checkout "https://github.com/$1.git" "$2" && echo "OK $1 (índice)" || echo "FALHOU $1"; }
noblob mdecrevoisier/EVTX-to-MITRE-Attack evtx_mitre &
noblob sbousseaden/EVTX-ATTACK-SAMPLES evtx_samples &
noblob CyberMonitor/APT_CyberCriminal_Campagin_Collections apt_collections &
wait
sparse wazuh/wazuh wazuh_wazuh --branch v4.9.2 '/ruleset/rules/*' '/ruleset/decoders/*' &
sparse Azure/Azure-Sentinel azure_sentinel '/Detections/**/*.yaml' '/Hunting Queries/**/*.yaml' '/Solutions/*/Analytic Rules/*.yaml' '/Solutions/*/Hunting Queries/*.yaml' &
sparse opensearch-project/security-analytics os_secanalytics '/src/main/config/rules/**' &
sparse demisto/content demisto_content '/Packs/*/Playbooks/*.yml' &
sparse mitre-attack/attack-stix-data attack_stix '/enterprise-attack/enterprise-attack.json' &
sparse redcanaryco/atomic-red-team atomic '/atomics/T*/T*.yaml' &
wait
echo "coleta concluída"
