#!/usr/bin/env python3
"""Taxonomia de TECNOLOGIA e de PADRÃO DE CORRELAÇÃO das regras. stdlib-only.

Por que existe: o catálogo nasceu organizado por FONTE (de qual repositório a regra veio).
Quem defende um ambiente pensa por TECNOLOGIA ("o que eu tenho para Okta? e para ESXi?").
Este módulo reclassifica cada regra pelo que ela observa, a partir de metadados e texto:
produto/categoria/serviço do logsource, caminho do arquivo, título, descrição e início da lógica.

Classificação heurística (regex), transparente e auditável: cada tecnologia lista o padrão
que a aciona. Uma regra pode tocar várias tecnologias (ex.: Entra ID + Microsoft 365).

Padrões de correlação seguem o catálogo do TCEM (Ridd1kulusC0d3r/Cyber-Threat-Context-Modeling,
src/tce/data/detection-correlation-patterns.yaml) + dois rótulos para o que não é correlação de
eventos: assinatura de conteúdo (YARA) e fluxo de resposta (playbooks).
"""
import re

# (id, nome, domínio, plataforma ATT&CK, lente TCEM, regex)
TECHS = [
 # ---- Endpoint
 ("windows","Windows","Endpoint","Windows","purple-detection",
  r"\bwindows\b|\bwin_|/windows/|sysmon|wineventlog|winevtlog|\bevtx\b|powershell|securityevents?\b|windowsevent|\bwmi\b|\bmsiexec|\brundll32|\bregsvr32|\bcmd\.exe|\blsass|\bregistry\b|registry_|\bntlm\b|\.exe\b"),
 ("linux","Linux","Endpoint","Linux","purple-detection",
  r"\blinux\b|/linux/|auditd|\bsshd?\b|\bsudo\b|\bpam\b|/etc/|systemd|crontab|\bcron\b|\bbash\b|journald|ubuntu|red ?hat|debian|centos|\bselinux|\bapparmor|ld_preload|\bkernel module"),
 ("macos","macOS","Endpoint","macOS","purple-detection",
  r"macos|\bosx\b|mac os|darwin|\bjamf|launchd|launchagent|launchdaemon|\bplist\b|unified ?log|\bxprotect|gatekeeper|tcc\.db"),
 ("edr","EDR / XDR","Endpoint","","purple-detection",
  r"\bedr\b|\bxdr\b|crowdstrike|\bfalcon\b(?!ry)|sentinel.?one|sentinel_one|microsoftthreatprotection|m365_defender|defender for endpoint|\bmde\b|deviceprocessevents|devicenetworkevents|devicefileevents|deviceregistryevents|deviceevents|deviceimageload|devicelogonevents|carbon ?black|cortex xdr|cylance|ciscosecureendpoint|trend ?micro|\beset\b|kaspersky|bitdefender|symantec|mcafee|trellix|sophos|elastic endpoint|endpoint security|antivirus|\bendpoint\b"),
 # ---- Identidade
 ("ad","Active Directory","Identidade","","identity-access",
  r"active.?directory|\bkerberos|kerberoast|\bldap\b|bloodhound|dcsync|\bntds|\bgpo\b|group policy|\badcs\b|certificate services|certipy|domain controller|\bsamaccount|\bspn\b|golden ticket|silver ticket|\bdsrm\b|pass.the.(hash|ticket)|\bdomain admins?\b|\btgt\b|\btgs\b|\bad cs\b|adexplorer|adrecon|sharphound"),
 ("entra","Entra ID (Azure AD)","Identidade","Identity Provider","identity-access",
  r"azure ?active ?directory|azureactivedirectory|azure_?ad\b|azuread|\bentra\b|\baad\b|signinlogs|aadnoninteractive|aadserviceprincipal|\bservice principal|conditional access|microsoft identity|graph api|\bmsgraph|identityinfo|azure\.signinlogs|azure\.auditlogs"),
 ("okta","Okta","Identidade","Identity Provider","identity-access", r"\bokta"),
 ("idp","Outros IdP / PAM","Identidade","Identity Provider","identity-access",
  r"\bduo\b|ping ?(identity|federate|one)|onelogin|\bauth0|cyberark|silverfort|jumpcloud|keycloak|beyondtrust|delinea|thycotic|hashicorp vault|\bsaml\b|\boauth|\boidc\b|\bsso\b|authomize|\bpam(?: |_)?(vault|privileged)"),
 # ---- Nuvem
 ("aws","AWS","Nuvem","IaaS","cloud-multicloud",
  r"\baws\b|aws[._]|amazon|cloudtrail|guardduty|\bs3\b|\bec2\b|\blambda\b|route ?53|\biam (role|user|policy)|\bsts\b|assumerole|securityhub|\beks\b|\bbedrock"),
 ("azure","Azure (recursos)","Nuvem","IaaS","cloud-multicloud",
  r"azureactivity|azure\.activitylogs|azure\.monitor|azure resource|azure ?(subscription|key ?vault|storage|vm|function|automation|monitor|policy|firewall|diagnostics)|keyvault|azurediagnostics|defender for cloud|\barm template|\bazure\b(?! ?ad| ?active)"),
 ("gcp","Google Cloud","Nuvem","IaaS","cloud-multicloud",
  r"\bgcp\b|gcp\.|google cloud|gcloud|bigquery|cloud logging|cloud audit|\bgke\b|stackdriver|google_cloud|cloudaudit\.googleapis"),
 ("oci","Oracle Cloud e outras","Nuvem","IaaS","cloud-multicloud",
  r"oracle ?cloud|\boci\b|alibaba ?cloud|digitalocean|ibm ?cloud|oraclecloud"),
 # ---- Contêineres
 ("k8s","Kubernetes","Contêineres","Containers","cloud-multicloud",
  r"kubernetes|\bk8s|kubectl|kube-?(apiserver|system|audit)|\bopenshift|\baks\b|kubelet|\bpod(s)? (exec|create)|clusterrole"),
 ("containers","Contêineres (Docker/runtime)","Contêineres","Containers","cloud-multicloud",
  r"container|docker|containerd|\bcri-o|podman|linux/containers|\bfalco\b|runc\b"),
 # ---- SaaS e colaboração
 ("m365","Microsoft 365","SaaS & colaboração","Office Suite","identity-access",
  r"office ?365|\bo365\b|\bm365\b|microsoft 365|\bexchange\b|sharepoint|onedrive|\bteams\b|officeactivity|\boutlook\b|emailevents|emailurlinfo|cloudappevents|purview|mailbox|\bowa\b|microsoft365"),
 ("gws","Google Workspace","SaaS & colaboração","Office Suite","identity-access",
  r"google ?workspace|g ?suite|\bgmail\b|google drive|googleworkspace|google_workspace|admin\.google"),
 ("devops","DevOps & supply chain","SaaS & colaboração","SaaS","software-supply-chain",
  r"github|gitlab|bitbucket|azure devops|jenkins|circleci|terraform|\bci/cd|\bcicd\b|argocd|jfrog|artifactory|\bnpm\b|\bpypi\b|supply.?chain|code ?signing|\bsbom\b"),
 ("saas","SaaS de negócio","SaaS & colaboração","SaaS","identity-access",
  r"\bslack|\bzoom\b|webex|\bbox(dataconnector|\.com| api)|dropbox|\bjira|confluence|atlassian|\bnotion\b|salesforce|servicenow|workday|snowflake|zendesk|1password|lastpass|docusign|hubspot|\bsaas\b|dataverse|power ?platform|powerapps|dynamics 365"),
 # ---- Rede
 ("firewall","Firewall & perímetro","Rede","Network Devices","web-api",
  r"firewall|palo ?alto|pan-?os|paloalto|fortinet|fortigate|checkpoint|check point|cisco ?asa|\basa\b|sonicwall|pfsense|opnsense|iptables|netfilter|juniper|watchguard|meraki|\bufw\b|rpc_firewall"),
 ("nsm","IDS / NSM / NDR","Rede","","purple-detection",
  r"suricata|\bsnort|\bzeek|\bbro\b|corelight|network_traffic|netflow|\bpcap|\bndr\b|darktrace|extrahop|vectra|\bjarm|\bja3|\bnmap"),
 ("dns","DNS","Rede","","web-api",
  r"\bdns\b|dnsevents|dns_query|umbrella|infoblox|bind9|\bnamed\b|\bdoh\b|dns over https|dga\b|dnsdataconnector"),
 ("proxy","Proxy / SWG","Rede","","web-api",
  r"\bproxy\b|squid|zscaler|bluecoat|web ?gateway|\bswg\b|netskope|forcepoint|url filtering|webproxy"),
 ("vpn","VPN & acesso remoto","Rede","","identity-access",
  r"\bvpn\b|globalprotect|anyconnect|pulse ?secure|ivanti connect|openvpn|wireguard|tailscale|zerotier|netscaler|citrix ?(adc|gateway)|remote access|\brmm\b|anydesk|teamviewer|screenconnect|connectwise|splashtop|\batera\b|rustdesk|ngrok|cloudflared"),
 ("email","E-mail","Rede","","identity-access",
  r"\be-?mail|mail ?gateway|proofpoint|mimecast|\bsmtp|postfix|sendmail|\bexim\b|dmarc|\bspf\b|phish|attachment|\.eml\b"),
 ("netdev","Dispositivos de rede","Rede","Network Devices","iot-embedded",
  r"\brouter|\bswitch(es)?\b|cisco ?ios|ios-?xe|junos|mikrotik|ubiquiti|unifi|\bsnmp|network device|arista|\btftp"),
 # ---- Web e aplicações
 ("web","Servidores web & aplicações","Web & aplicações","","web-api",
  r"webserver|web server|\bapache|\bnginx|\biis\b|tomcat|\bhttp(s)?\b|accesslog|access\.log|\bw3c|webshell|web shell|\bphp\b|\.aspx?\b|\bjsp\b|\bcgi\b|sql injection|\bxss\b|\blfi\b|\brce\b|path traversal|\bapi\b|graphql"),
 ("waf","WAF / CDN","Web & aplicações","","web-api",
  r"\bwaf\b|modsecurity|imperva|akamai|cloudflare|\bf5\b|big-?ip|front ?door|incapsula"),
 ("db","Bancos de dados","Web & aplicações","","web-api",
  r"sql ?server|\bmssql|mysql|postgres|oracle (db|database)|mongodb|\bredis\b|\bdatabase\b|\bdb2\b|azuresql|elasticsearch|cassandra|mariadb|sqlite|\bxp_cmdshell"),
 ("erp","ERP & sistemas de negócio","Web & aplicações","SaaS","web-api",
  r"\bsap\b|sapbtp|\berp\b|pathlock|oracle ebs|peoplesoft|\bsap ?(hana|netweaver|s4)"),
 # ---- Infraestrutura
 ("virt","Virtualização (ESXi/vSphere/Hyper-V)","Infraestrutura","ESXi","cloud-multicloud",
  r"vmware|vsphere|vcenter|\besxi|hyper-?v|proxmox|nutanix|xenserver|virtualbox|\bvmx\b"),
 ("backup","Backup & armazenamento","Infraestrutura","","purple-detection",
  r"veeam|\bbackup|commvault|rubrik|cohesity|netapp|synology|\bnas\b|shadow ?cop|vssadmin|\bwbadmin"),
 ("compliance","Integridade, conformidade & vulnerabilidade","Infraestrutura","","purple-detection",
  r"vulnerability (scan|management|assessment)|vuln(erability)? scanner|qualys|tenable|nessus|rapid7|insightvm|openvas|osquery|\bfim\b|syscheck|file integrity|rootcheck|\bsca\b|\bcis\b|compliance|\bpci\b|\bgdpr|\bhipaa|nist_800|\bciscat|policy_monitoring"),
 # ---- OT / IoT
 ("ot","ICS / OT","OT & IoT","ICS","ics-ot",
  r"\bics\b|scada|modbus|\bdnp3|\bplc\b|\bhmi\b|industrial|claroty|nozomi|dragos|s7comm|iec ?104|iec-?61850|bacnet|\bopc[ -]?ua|ot/ics|ics/ot"),
 ("iot","IoT & embarcados","OT & IoT","","iot-embedded",
  r"\biot\b|\bcctv|ip camera|\bprinter|embedded|firmware|\bbmc\b|\bipmi"),
 # ---- IA
 ("ai","IA, LLMs & agentes","IA","","ai-genai",
  r"\bai\b|\bllms?\b|genai|gen ai|openai|chatgpt|openai_chatgpt|anthropic|\bclaude\b|bedrock|\bcopilot|gemini|vertex ?ai|azure openai|hugging ?face|ollama|\bmcp\b|model context protocol|prompt injection|\bprompt\b|aishield|boschaishield|langchain|\bagentic|ai agent|ai assistant|machine learning model|llminjection"),
 # ---- Arquivos
 ("files","Arquivos & memória (YARA)","Arquivos & malware","","purple-detection", r"arquivo/memória"),
]

# o que está em jogo em cada tecnologia — usado na narrativa das regras e nos relatórios
STAGE = {
 'windows': 'estações e servidores Windows — onde as pessoas trabalham e onde credenciais vivem na memória',
 'linux': 'servidores Linux — onde roda o que a empresa vende: aplicações, bancos, contêineres',
 'macos': 'Macs de desenvolvedores e executivos — poucos, mas com acessos valiosos',
 'edr': 'a telemetria do EDR/XDR — os olhos instalados dentro de cada máquina',
 'ad': 'o Active Directory — o livro de chaves de toda a rede Windows',
 'entra': 'o Entra ID (Azure AD) — quem é quem para Microsoft 365, Azure e centenas de apps',
 'okta': 'o Okta — a porta única para todos os aplicativos: quem controla o Okta decide quem é quem',
 'idp': 'o provedor de identidade e o cofre de senhas privilegiadas',
 'aws': 'a conta AWS — o painel de controle de servidores, dados e chaves na nuvem',
 'azure': 'a assinatura Azure — recursos, cofres de chaves e políticas da nuvem Microsoft',
 'gcp': 'o projeto Google Cloud — IAM, buckets e cargas na nuvem do Google',
 'oci': 'a nuvem Oracle e outras nuvens — o painel de controle da infraestrutura alugada',
 'k8s': 'o cluster Kubernetes — o maestro que decide onde e como cada contêiner roda',
 'containers': 'os contêineres em execução — processos isolados que compartilham o mesmo kernel',
 'm365': 'o Microsoft 365 — e-mail, arquivos e conversas da empresa inteira',
 'gws': 'o Google Workspace — Gmail, Drive e a identidade Google da empresa',
 'devops': 'o pipeline de software — repositórios, builds e artefatos que viram produção',
 'saas': 'os SaaS de negócio — onde moram clientes, contratos e dados sensíveis fora do seu datacenter',
 'firewall': 'o perímetro — firewalls que decidem o que entra e o que sai',
 'nsm': 'a rede vista por dentro — sensores que leem pacotes e fluxos',
 'dns': 'o DNS — a lista telefônica que toda conexão consulta antes de acontecer',
 'proxy': 'o proxy web — a janela por onde os usuários saem para a internet',
 'vpn': 'o acesso remoto — VPN e ferramentas que deixam alguém de fora operar aqui dentro',
 'email': 'o e-mail — ainda a porta de entrada mais usada',
 'netdev': 'roteadores e switches — a infraestrutura que quase ninguém monitora',
 'web': 'aplicações e servidores web expostos — a vitrine que qualquer um na internet pode tocar',
 'waf': 'o WAF/CDN — o filtro na frente das aplicações web',
 'db': 'os bancos de dados — onde mora o dado que o atacante quer levar',
 'erp': 'o ERP — finanças, compras e folha de pagamento',
 'virt': 'o hipervisor (ESXi/vSphere/Hyper-V) — um único ponto que liga e desliga dezenas de servidores',
 'backup': 'os backups — a última linha de recuperação, alvo preferido do ransomware',
 'compliance': 'a integridade e a postura — arquivos críticos, configuração e vulnerabilidades',
 'ot': 'o ambiente industrial (ICS/OT) — onde um comando errado vira problema físico',
 'iot': 'dispositivos IoT e embarcados — câmeras, impressoras, placas de gerência',
 'ai': 'IA, LLMs e agentes — modelos, ferramentas e conectores que agem em nome de alguém',
 'files': 'arquivos e memória — o próprio artefato do atacante, não o rastro que ele deixa',
 'other': 'o ambiente descrito pela fonte do log desta regra',
}
TECH_IDS=[t[0] for t in TECHS]
TECH_BY={t[0]:t for t in TECHS}
DOMAINS=[]
for t in TECHS:
    if t[2] not in DOMAINS: DOMAINS.append(t[2])
_RX=[(t[0],re.compile(t[5],re.I)) for t in TECHS]

def _text(r):
    ls=r.get("logsource") or {}
    if isinstance(ls,str): ls={}
    parts=[str(ls.get(k) or "") for k in ("product","category","service")]
    p=(r.get("path") or "")
    # o 1º segmento é a pasta do clone (ex.: azure_sentinel/, mir_sagan-rules/) e diz a FONTE, não a tecnologia
    p="/".join(p.split("/")[1:]) if "/" in p else p
    p=re.sub(r"(?i)\b(database|exports?|detections?|rules|src/main/config|by_technique)/","",p)
    # nome do arquivo e pastas dizem muito (rules/windows/…, Solutions/Okta/…, 0095-sshd_rules.xml)
    desc=re.sub(r"^Assinatura [^:]{0,80}:\s*","",(r.get("description") or "")[:300])   # boilerplate do parser (ex.: "Assinatura Sagan (log IDS, sintaxe Snort):")
    parts+= [p.replace("_"," ").replace("-"," "), p, r.get("title") or "", desc]
    # URLs citadas (github.com/autor, docs da Microsoft…) dizem de onde veio a pesquisa, não o que a regra observa
    return re.sub(r"https?://\S+|\b[\w.-]+\.(com|io|org|net)/\S*", " ", " | ".join(parts))

def classify(r):
    """Lista de ids de tecnologia (ordenada pela ordem da taxonomia)."""
    fmt=r.get("format")
    if fmt=="yara": return ["files"]
    t=_text(r)
    q=((r.get("query") or r.get("raw") or "")[:1500])
    out=[tid for tid,rx in _RX if tid!="files" and (rx.search(t))]
    if not out:
        out=[tid for tid,rx in _RX if tid not in ("files","web","edr") and rx.search(q)]
    if fmt=="falco" and "containers" not in out: out.append("containers")
    # Sagan usa sintaxe Snort, mas lê LOGS (syslog), não pacotes: não é NSM por definição
    if fmt=="suricata" and "nsm" not in out and "sagan" not in (r.get("source") or "").lower(): out.append("nsm")
    # EDR só quando não há SO mais específico OU quando a fonte é tabela de EDR
    if "edr" in out and len(out)>1 and not re.search(r"crowdstrike|sentinel.?one|microsoftthreatprotection|m365_defender|device\w+events|carbon ?black|cortex|cylance|trend ?micro|edr|xdr",t,re.I):
        out.remove("edr")
    # 'web' é amplo; se já há tecnologia de identidade/nuvem/SaaS, ele vira ruído
    if "web" in out and len(out)>1 and any(x in out for x in ("okta","entra","aws","gcp","azure","m365","gws","saas","devops","k8s","ai")):
        out.remove("web")
    order={k:i for i,k in enumerate(TECH_IDS)}
    return sorted(set(out),key=order.get) or ["other"]

# ---------------- padrões de correlação (TCEM) ----------------
PATTERNS=[
 ("single-event","Evento único","Um evento, sozinho, já tem sinal suficiente para chamar o analista."),
 ("ordered-sequence","Sequência ordenada","Dois ou mais passos da mesma entidade, na ordem certa, dentro de uma janela."),
 ("threshold","Limiar / acúmulo","O sinal está na repetição: N eventos por chave em uma janela."),
 ("new-entity","Novidade / raridade","Compara com o que é normal: entidade, relação ou valor nunca (ou raramente) visto."),
 ("state-transition","Mudança de estado","O risco está na transição: algo era seguro e deixou de ser (desligado, rebaixado, alterado)."),
 ("content-signature","Assinatura de conteúdo","Casa bytes/strings dentro de arquivo, memória ou pacote, não eventos de log."),
 ("response-flow","Fluxo de resposta","Não detecta: orquestra o que fazer depois do alerta (SOAR)."),
]
PAT_IDS=[p[0] for p in PATTERNS]
RX_SEQ=re.compile(r"\bsequence\s+(by|with)\b|\|\s*transaction\b|<if_matched_(sid|group)>|temporal_ordered|type:\s*temporal\b|followed by|\bmaxspan\b|\$e\d?\.\S+\s*=\s*\$\w+.*\n.*\$\w+\d?\.\S+|\bmatch:\s*\n\s*\$\w+.*over\b",re.I)
RX_THR=re.compile(r"frequency=\"?\d|\[rule\.threshold\]|type\s*=\s*\"threshold\"|type:\s*event_count|value_count|\|\s*where\s+\w*(count|cnt|total|num)\w*\s*[><]=?\s*\d|(summarize|stats|tstats|eventstats)\b[^|\n]{0,200}\b(count|dc|dcount|distinct_count)\b[^\n]{0,400}\|\s*where|#\w+\s*[>]=?\s*\d|having\s+count|count\(\*\)\s*>|\bthreshold\b|detection_filter|\bbrute.?force",re.I)
RX_NEW=re.compile(r"new_terms|type\s*=\s*\"new_terms\"|first.?seen|firstseen|never.?seen|\brare\b|\bbaseline|isnull\(prev|outlier|anomal|machine_learning|ml_job|\bunusual\b|least common|not\s+in\s*\(\s*known|\bprevalence|uncommon",re.I)
RX_STATE=re.compile(r"old_?value|new_?value|previous_?(state|value)|modifiedproperties|oldvalue|newvalue|\bdisabl(ed|ing)\b|turned off|\bdowngrad|tamper|\bstopped\b|set to\b|was (changed|modified|removed|deleted)|policy (change|modif)|(changed|modified) (from|to)\b",re.I)

def pattern(r):
    fmt=r.get("format"); ct=r.get("ctype")
    if ct=="playbook" or fmt=="playbook": return "response-flow"
    if fmt=="yara": return "content-signature"
    q=((r.get("raw") or "")[:30000])+"\n"+((r.get("query") or "")[:8000])
    if fmt=="wazuh" and re.search(r"frequency=",q):
        return "ordered-sequence" if re.search(r"<if_matched_(sid|group)>",q) and not re.search(r"<same_",q) else "threshold"
    if RX_SEQ.search(q): return "ordered-sequence"
    if RX_NEW.search(q) or RX_NEW.search(r.get("title") or ""): return "new-entity"
    if RX_THR.search(q): return "threshold"
    if fmt=="suricata" and "sagan" not in (r.get("source") or "").lower(): return "content-signature"
    if RX_STATE.search((r.get("title") or "")+" "+(r.get("description") or "")[:300]) or RX_STATE.search(q[:2000]): return "state-transition"
    return "single-event"

if __name__=="__main__":
    import json,sys,collections
    R=json.load(open(sys.argv[1] if len(sys.argv)>1 else "catalog.json",encoding="utf-8"))
    c=collections.Counter(); p=collections.Counter(); multi=0
    for r in R:
        t=classify(r); c.update(t); p[pattern(r)]+=1; multi+=len(t)>1
    for k,v in c.most_common(): print(f"{v:7d}  {k:11s} {TECH_BY.get(k,('','Outros/genérico'))[1]}")
    print("multi-tecnologia:",multi); print(p.most_common())
