// ─── Knowledge Base para AI Consultant ───────────────────────────────────────
export const scenarios = [
  {
    id: 'phishing',
    keywords: ['email', 'e-mail', 'phishing', 'link', 'suspeito', 'spoofing', 'spam', 'mensagem', 'anexo', 'header', 'cabecalho', 'cabeçalho', 'remetente', 'spear', 'recebi', 'clicou', 'cliquei', 'usuario clicou', 'abriu o link'],
    weightedKeywords: ['phishing', 'spear phishing', 'spoofing', 'email suspeito', 'e-mail suspeito', 'anexo malicioso', 'clicou no link', 'cliquei no link', 'recebi email suspeito'],
    title: 'E-mail Suspeito / Phishing',
    severity: 'high',
    ttps: ['T1566.001', 'T1566.002', 'T1598', 'T1078', 'T1204.001'],
    summary: 'Phishing é o principal vetor de ataque inicial. E-mails fraudulentos podem conter links para credential harvesting, anexos com malware (macros, LNK, ISO) ou usar spoofing para parecerem legítimos. Ação imediata evita comprometimento.',
    steps: [
      { priority: 1, action: 'NÃO clique em links nem abra anexos — isole o e-mail primeiro', tool: 'Quarentena no gateway de e-mail', link: null, category: '🔴 CRÍTICO' },
      { priority: 2, action: 'Analisar cabeçalho completo (SPF/DKIM/DMARC/Received)', tool: 'Email Header Analyzer', link: '/email-header', category: 'Análise' },
      { priority: 3, action: 'Verificar IP de origem e domínio do remetente', tool: 'IOC Lookup (VirusTotal + AbuseIPDB)', link: '/lookup', category: 'Consulta' },
      { priority: 4, action: 'Se houver link: verificar URL em sandbox without clicking (VirusTotal / URLScan.io)', tool: 'IOC Lookup', link: '/lookup', category: 'Consulta' },
      { priority: 5, action: 'Se houver anexo: calcular hash SHA256 e verificar (certutil -hashfile arquivo SHA256)', tool: 'Hybrid Analysis / VirusTotal', link: '/lookup', category: 'Análise' },
      { priority: 6, action: 'Verificar quantos usuários receberam o mesmo e-mail (busca por assunto/remetente)', tool: 'M365 Defender / Mimecast / Proofpoint', link: null, category: 'Investigação' },
      { priority: 7, action: 'Se usuário já clicou/abriu: iniciar investigação de endpoint', tool: 'EDR — ver cenário de Execução Suspeita', link: null, category: 'Escalada' },
      { priority: 8, action: 'Bloquear domínio/IP remetente no gateway de e-mail e proxy', tool: 'Gateway de e-mail + Firewall', link: null, category: 'Contenção' },
    ],
    mitigations: ['M1017 - User Training', 'M1054 - Software Configuration (SPF/DKIM/DMARC)', 'M1021 - Restrict Web-Based Content'],
    references: ['https://attack.mitre.org/techniques/T1566/', 'https://mxtoolbox.com/EmailHeaders.aspx'],
  },
  {
    id: 'script_exec',
    keywords: ['powershell', 'cmd', 'wscript', 'cscript', 'terminal', 'script', 'shell', 'execucao', 'execução', 'comando', 'processo', 'lolbin', 'mshta', 'wmic', 'rundll32', 'regsvr32', 'encoded', 'base64', 'invoke', 'iex', 'downloadstring', 'executa', 'rodando', 'bat', 'vbs', 'linha de comando'],
    weightedKeywords: ['powershell suspeito', 'script malicioso', '-encodedcommand', 'invoke-expression', 'downloadstring', 'lolbin', 'wscript suspeito', 'processo suspeito'],
    title: 'Execução Suspeita de Script / Linha de Comando',
    severity: 'critical',
    ttps: ['T1059.001', 'T1059.003', 'T1027', 'T1140', 'T1055', 'T1218'],
    summary: 'PowerShell, cmd.exe, WScript e LOLBins são usados em Living off the Land (LotL) attacks. PowerShell com -EncodedCommand ou IEX (Invoke-Expression) é red flag imediato de execução in-memory.',
    steps: [
      { priority: 1, action: 'Capturar linha de comando completa via EventID 4688 (com Process Command Line habilitado) ou Sysmon EventID 1', tool: 'EDR / Windows Event Log', link: null, category: 'Coleta' },
      { priority: 2, action: 'Verificar processo pai — word.exe → powershell.exe = macro maliciosa; wscript.exe → powershell.exe = JS/VBS dropper', tool: 'EDR (Process Tree)', link: null, category: 'Análise' },
      { priority: 3, action: 'Decodificar base64 se houver -EncodedCommand: [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String("..."))', tool: 'PowerShell local / CyberChef online', link: null, category: 'Análise' },
      { priority: 4, action: 'Extrair hash do executável e verificar reputação', tool: 'IOC Lookup (VirusTotal + Hybrid Analysis)', link: '/lookup', category: 'Consulta' },
      { priority: 5, action: 'Verificar conexões de rede abertas pelo processo: netstat -anop | findstr PID', tool: 'EDR / netstat', link: null, category: 'Investigação' },
      { priority: 6, action: 'Verificar escrita de arquivo em disco (dropper?): Sysmon EventID 11 (FileCreate)', tool: 'Sysmon / EDR', link: null, category: 'Investigação' },
      { priority: 7, action: 'Isolar endpoint se comportamento malicioso confirmado', tool: 'EDR — isolamento de host', link: null, category: 'Contenção' },
    ],
    mitigations: ['M1038 - Execution Prevention', 'M1042 - Disable or Remove Feature', 'M1049 - Antivirus/Antimalware'],
    references: ['https://attack.mitre.org/techniques/T1059/001/', 'https://lolbas-project.github.io/'],
  },
  {
    id: 'c2_network',
    keywords: ['ip', 'conexao', 'conexão', 'trafego', 'tráfego', 'rede', 'porta', 'outbound', 'c2', 'beacon', 'beaconing', 'controle', 'comunicacao estranha', 'comunicação estranha', 'firewall', 'proxy', 'exfil', 'saindo', 'conectando'],
    weightedKeywords: ['c2', 'beaconing', 'comando e controle', 'conexão suspeita', 'tráfego suspeito', 'ip malicioso', 'host conectando periodicamente'],
    title: 'IP / Conexão de Rede Suspeita (C2)',
    severity: 'high',
    ttps: ['T1071', 'T1095', 'T1571', 'T1572', 'T1041'],
    summary: 'Conexões periódicas para IPs externos desconhecidos indicam beaconing — malware se comunicando com C2. Quanto mais regular o intervalo, mais suspeito. Identifique o processo responsável e bloqueie na fonte.',
    steps: [
      { priority: 1, action: 'Verificar reputação do IP em threat intel', tool: 'IOC Lookup (VirusTotal + AbuseIPDB + IBM X-Force)', link: '/lookup', category: 'Consulta' },
      { priority: 2, action: 'Identificar processo fazendo a conexão: netstat -anop (anote PID) → tasklist /fi "PID eq X"', tool: 'EDR / netstat', link: null, category: 'Investigação' },
      { priority: 3, action: 'Analisar frequência: conexões a cada X segundos regulares = beaconing típico de malware', tool: 'Firewall Logs / NDR / Zeek', link: null, category: 'Análise' },
      { priority: 4, action: 'Verificar volume: muito upload vs download indica exfiltração de dados', tool: 'SIEM / Firewall flow logs', link: null, category: 'Análise' },
      { priority: 5, action: 'Verificar domínio/PTR do IP e JA3 fingerprint TLS', tool: 'IOC Lookup / Shodan', link: '/lookup', category: 'Consulta' },
      { priority: 6, action: 'Bloquear IP no firewall e isolar host se C2 confirmado', tool: 'Firewall / EDR', link: null, category: 'Contenção' },
    ],
    mitigations: ['M1031 - Network Intrusion Prevention', 'M1037 - Filter Network Traffic', 'M1020 - SSL/TLS Inspection'],
    references: ['https://attack.mitre.org/techniques/T1071/', 'https://www.abuseipdb.com/'],
  },
  {
    id: 'malware',
    keywords: ['hash', 'arquivo', 'executavel', 'executável', 'malware', 'virus', 'vírus', 'trojan', 'worm', 'dll', 'exe', 'binario', 'binário', 'sample', 'dropper', 'stager', 'payload', 'macro', 'office', 'doc', 'xls', 'pe file', 'spyware', 'cryptominer', 'miner'],
    weightedKeywords: ['arquivo malicioso', 'executável suspeito', 'malware detectado', 'trojan', 'dropper', 'payload malicioso', 'sample de malware', 'este exe é malicioso'],
    title: 'Arquivo Suspeito / Análise de Malware',
    severity: 'critical',
    ttps: ['T1204.002', 'T1105', 'T1027', 'T1055', 'T1036'],
    summary: 'Arquivo suspeito detectado. Calcule o hash e verifique ANTES de executar. Nunca analise malware em produção — use sandbox isolada. Hash limpo no VirusTotal não é garantia 100% de segurança (malware novo).',
    steps: [
      { priority: 1, action: 'NÃO execute o arquivo — colocar em quarentena imediatamente', tool: 'EDR / AV', link: null, category: '🔴 CRÍTICO' },
      { priority: 2, action: 'Calcular hash SHA256: certutil -hashfile arquivo.exe SHA256 (Win) | sha256sum arquivo (Linux)', tool: 'CertUtil / sha256sum / PowerShell Get-FileHash', link: null, category: 'Coleta' },
      { priority: 3, action: 'Verificar hash em 70+ engines antivírus e bases de malware', tool: 'IOC Lookup (VirusTotal + Hybrid Analysis)', link: '/lookup', category: 'Consulta' },
      { priority: 4, action: 'Detonar em sandbox para análise comportamental (sem risco)', tool: 'Hybrid Analysis / Any.run', link: '/lookup', category: 'Análise' },
      { priority: 5, action: 'Análise estática: verificar strings, imports de DLL, seções PE', tool: 'CFF Explorer / PE-bear / strings', link: null, category: 'Análise Estática' },
      { priority: 6, action: 'Verificar assinatura digital: publisher confiável e certificado válido?', tool: 'Sigcheck (Sysinternals) / Windows Properties', link: null, category: 'Verificação' },
      { priority: 7, action: 'Se malicioso confirmado: quarentena, extração de IoCs e bloqueio no EDR', tool: 'EDR / SIEM', link: null, category: 'Contenção' },
    ],
    mitigations: ['M1049 - Antivirus/Antimalware', 'M1038 - Execution Prevention', 'M1045 - Code Signing'],
    references: ['https://www.virustotal.com/', 'https://www.hybrid-analysis.com/'],
  },
  {
    id: 'credentials',
    keywords: ['usuario', 'usuário', 'conta', 'login', 'senha', 'credencial', 'acesso', 'autenticacao', 'autenticação', 'comprometida', 'vazamento', 'breach', 'dump', 'password', 'mfa', 'multifator', 'token', 'session', 'cookie roubado', 'account', 'acessando indevidamente', 'login suspeito'],
    weightedKeywords: ['conta comprometida', 'credencial vazada', 'senha comprometida', 'mfa bypass', 'session hijacking', 'cookie roubado', 'login suspeito', 'acesso indevido'],
    title: 'Conta / Credencial Comprometida',
    severity: 'high',
    ttps: ['T1078', 'T1110', 'T1552', 'T1555', 'T1003', 'T1539'],
    summary: 'Credenciais comprometidas são o vetor mais comum de acesso inicial atualmente. Revogar sessões rapidamente é crítico — cada minuto com acesso ativo aumenta o raio de impacto. Assuma que o atacante já coletou dados.',
    steps: [
      { priority: 1, action: 'Revogar TODAS as sessões ativas da conta imediatamente', tool: 'Azure AD / Okta / Active Directory', link: null, category: '🔴 CRÍTICO' },
      { priority: 2, action: 'Revisar histórico de logins: IPs, países, horários e dispositivos incomuns', tool: 'Azure AD Sign-In Logs / IDP Audit Logs', link: null, category: 'Investigação' },
      { priority: 3, action: 'Verificar Impossible Travel (login SP→Rússia em 10 min = fisicamente impossível)', tool: 'Azure AD Identity Protection / UEBA', link: null, category: 'Análise' },
      { priority: 4, action: 'Verificar IPs dos logins suspeitos em threat intel', tool: 'IOC Lookup (AbuseIPDB)', link: '/lookup', category: 'Consulta' },
      { priority: 5, action: 'Forçar reset de senha e re-enrolar MFA', tool: 'Active Directory / IDP', link: null, category: 'Remediação' },
      { priority: 6, action: 'Auditar ações das últimas 72h: arquivos acessados, e-mails enviados, regras de inbox criadas', tool: 'SIEM / M365 Compliance / Audit Logs', link: null, category: 'Investigação' },
      { priority: 7, action: 'Verificar criação de novas contas ou escalada de privilégios (EventID 4720, 4728)', tool: 'Active Directory Security Log / SIEM', link: null, category: 'Investigação' },
    ],
    mitigations: ['M1032 - Multi-factor Authentication', 'M1027 - Password Policies', 'M1036 - Account Use Policies'],
    references: ['https://attack.mitre.org/techniques/T1078/', 'https://haveibeenpwned.com/'],
  },
  {
    id: 'domain_url',
    keywords: ['dns', 'dominio', 'domínio', 'domain', 'url', 'site', 'whois', 'typosquatting', 'lookalike', 'redirect', 'encurtado', 'curto', 'subdominio', 'dga', 'link malicioso', 'endereço suspeito'],
    weightedKeywords: ['domínio suspeito', 'url maliciosa', 'typosquatting', 'lookalike domain', 'dga domain', 'domínio recém-registrado', 'site suspeito'],
    title: 'Domínio / URL Suspeita',
    severity: 'medium',
    ttps: ['T1583.001', 'T1189', 'T1566.002', 'T1071.004'],
    summary: 'Domínios maliciosos são usados em phishing, C2 e drive-by downloads. Domínios recém-registrados (< 30 dias), com nomes semelhantes a marcas conhecidas são especialmente suspeitos.',
    steps: [
      { priority: 1, action: 'Verificar reputação do domínio/URL em bases de threat intel', tool: 'IOC Lookup (VirusTotal + IBM X-Force)', link: '/lookup', category: 'Consulta' },
      { priority: 2, action: 'Verificar data de registro WHOIS — domínio < 30 dias = alto risco', tool: 'IOC Lookup / WHOIS', link: '/lookup', category: 'Consulta' },
      { priority: 3, action: 'Verificar IP que o domínio resolve e sua reputação', tool: 'IOC Lookup', link: '/lookup', category: 'Consulta' },
      { priority: 4, action: 'Expandir URLs encurtadas ANTES de clicar: curl -IL URL | unshorten.me', tool: 'unshorten.me / curl -L', link: null, category: 'Análise' },
      { priority: 5, action: 'Visualizar site via URLScan.io (screenshot + análise sem você acessar)', tool: 'urlscan.io', link: null, category: 'Análise Segura' },
      { priority: 6, action: 'Se typosquatting confirmado: notificar marca impersonada e registrador', tool: 'Relatório formal', link: null, category: 'Ação' },
    ],
    mitigations: ['M1021 - Restrict Web-Based Content', 'M1037 - Filter Network Traffic'],
    references: ['https://urlscan.io/', 'https://www.virustotal.com/'],
  },
  {
    id: 'cve_vuln',
    keywords: ['cve', 'vulnerabilidade', 'exploit', 'patch', 'atualizacao', 'atualização', 'zero-day', 'zeroday', 'rce', 'sqli', 'xss', 'ssrf', 'lfi', 'rfi', 'injection', 'deserialization', 'log4j', 'log4shell', 'brecha', 'falha', 'poc', 'metasploit', 'exploit-db'],
    weightedKeywords: ['cve-', 'zero-day', 'log4shell', 'rce', 'sql injection', 'command injection', 'exploit disponível', 'poc público', 'vulnerabilidade crítica'],
    title: 'Vulnerabilidade / CVE / Exploit',
    severity: 'high',
    ttps: ['T1190', 'T1203', 'T1211', 'T1068', 'T1210'],
    summary: 'CVEs com exploits públicos representam risco imediato. Verifique primeiro o catálogo KEV da CISA (exploração ativa confirmada). Sistemas expostos à internet devem ser priorizados no patch.',
    steps: [
      { priority: 1, action: 'Buscar detalhes do CVE e score CVSS 3.1 no NIST NVD', tool: 'IOC Lookup (CVE Search)', link: '/lookup', category: 'Consulta' },
      { priority: 2, action: 'Verificar se está no catálogo KEV da CISA (exploração ativa confirmada)', tool: 'cisa.gov/known-exploited-vulnerabilities-catalog', link: null, category: 'Consulta' },
      { priority: 3, action: 'Verificar se há PoC/exploit público no GitHub, Exploit-DB ou Metasploit', tool: 'GitHub search / Exploit-DB', link: null, category: 'Consulta' },
      { priority: 4, action: 'Inventariar sistemas afetados no ambiente (expostos à internet = prioridade máxima)', tool: 'Vulnerability Scanner (Tenable / Qualys)', link: null, category: 'Investigação' },
      { priority: 5, action: 'Verificar logs/alertas por sinais de exploração já ocorrida', tool: 'SIEM / WAF Logs / IDS Alerts', link: null, category: 'Investigação' },
      { priority: 6, action: 'Aplicar patch emergencial ou workaround (WAF rule, desabilitar funcionalidade)', tool: 'Patch Management / WAF', link: null, category: 'Remediação' },
    ],
    mitigations: ['M1051 - Update Software', 'M1016 - Vulnerability Scanning', 'M1050 - Exploit Protection'],
    references: ['https://nvd.nist.gov/', 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog'],
  },
  {
    id: 'ransomware',
    keywords: ['ransomware', 'criptografado', 'encrypted', 'ransom', 'note', 'pagamento', 'bitcoin', 'sequestro', 'lockbit', 'blackcat', 'alphv', 'arquivos bloqueados', 'extensao estranha', 'extensão estranha', 'vssadmin', 'shadow', 'arquivos inacessiveis', 'resgate'],
    weightedKeywords: ['ransomware', 'arquivos criptografados', 'nota de resgate', 'ransom note', 'vssadmin delete shadows', 'lockbit', 'blackcat', 'alphv', 'ransomhub'],
    title: '🚨 Ransomware — Resposta de Emergência',
    severity: 'critical',
    ttps: ['T1486', 'T1490', 'T1489', 'T1562', 'T1070'],
    summary: 'SITUAÇÃO CRÍTICA. Isole AGORA para evitar propagação. Não desligue — RAM pode ter a chave. NÃO pague sem especialista jurídico. Tempo entre infecção e criptografia total pode ser de minutos.',
    steps: [
      { priority: 1, action: '⚡ AGORA: Isolar host(s) afetados da rede — desconectar cabo/Wi-Fi ou usar isolamento EDR', tool: 'EDR / Switch / Wi-Fi off', link: null, category: '🔴 CRÍTICO' },
      { priority: 2, action: '⚡ AGORA: Desabilitar compartilhamentos SMB e drives mapeados', tool: 'GPO / cmd: net share * /delete', link: null, category: '🔴 CRÍTICO' },
      { priority: 3, action: 'Identificar variante pela nota de resgate e extensão dos arquivos', tool: 'nomoreransom.org/crypto-sheriff', link: null, category: 'Identificação' },
      { priority: 4, action: 'Verificar shadow copies: cmd > vssadmin list shadows — foram deletadas?', tool: 'CMD (vssadmin)', link: null, category: 'Investigação' },
      { priority: 5, action: 'Verificar IoCs do ransomware (hashes, IPs C2) em threat intel', tool: 'IOC Lookup', link: '/lookup', category: 'Consulta' },
      { priority: 6, action: 'NÃO pague sem consultar autoridades e especialistas legais (pode ser crime)', tool: 'CERT.br / Polícia Federal / Advogado especializado', link: null, category: 'Legal' },
      { priority: 7, action: 'Verificar nomoreransom.org — pode haver decryptor GRATUITO disponível', tool: 'nomoreransom.org', link: null, category: 'Recuperação' },
      { priority: 8, action: 'Restaurar SOMENTE de backups offline verificados, após limpeza completa do ambiente', tool: 'Backup / DR Plan', link: null, category: 'Recuperação' },
    ],
    mitigations: ['M1053 - Data Backup', 'M1040 - Behavior Prevention on Endpoint', 'M1028 - Operating System Configuration'],
    references: ['https://www.nomoreransom.org/', 'https://attack.mitre.org/techniques/T1486/'],
  },
  {
    id: 'ad_attack',
    keywords: ['active directory', 'kerberoasting', 'kerberos', 'golden ticket', 'silver ticket', 'pass the hash', 'pass-the-hash', 'pth', 'dcsync', 'mimikatz', 'bloodhound', 'domain controller', 'ntlm', 'lsass', 'sam database', 'ntds', 'krbtgt', 'gpo', 'ad comprometido'],
    weightedKeywords: ['kerberoasting', 'golden ticket', 'pass-the-hash', 'dcsync', 'mimikatz', 'bloodhound', 'domain admin comprometido', 'lsass dump', 'ntds.dit'],
    title: 'Ataque ao Active Directory',
    severity: 'critical',
    ttps: ['T1003', 'T1558.003', 'T1550.002', 'T1550.003', 'T1087.002', 'T1482'],
    summary: 'Ataques ao AD visam o Domain Controller e contas privilegiadas. AD comprometido = rede inteira comprometida. Kerberoasting, DCSync e Pass-the-Hash são as técnicas mais comuns e mais destrutivas.',
    steps: [
      { priority: 1, action: 'Verificar acesso suspeito ao LSASS: EventID 4656 com Object lsass.exe | Sysmon EventID 10 (Process Access)', tool: 'SIEM / Sysmon', link: null, category: 'Análise' },
      { priority: 2, action: 'Verificar DCSync: EventID 4662 com propriedade "DS-Replication-Get-Changes"', tool: 'Windows Security Log / SIEM', link: null, category: 'Análise' },
      { priority: 3, action: 'Verificar Kerberoasting: EventID 4769 com ticket encryption type 0x17 (RC4)', tool: 'Windows Security Log', link: null, category: 'Análise' },
      { priority: 4, action: 'Mapear contas de serviço com SPN (alvos de Kerberoasting): Get-ADUser -Filter {ServicePrincipalName -ne "$null"}', tool: 'PowerShell AD / BloodHound', link: null, category: 'Investigação' },
      { priority: 5, action: 'Resetar senha do KRBTGT duas vezes (invalida Golden Tickets existentes)', tool: 'PowerShell: reset-KrbtgtKeys.ps1', link: null, category: 'Contenção' },
      { priority: 6, action: 'Resetar senhas de Domain Admins, Enterprise Admins e Schema Admins', tool: 'Active Directory', link: null, category: 'Remediação' },
      { priority: 7, action: 'Executar BloodHound para identificar caminhos de ataque remanescentes', tool: 'BloodHound Community Edition', link: null, category: 'Investigação' },
    ],
    mitigations: ['M1032 - MFA', 'M1026 - Privileged Account Management', 'M1043 - Credential Access Protection'],
    references: ['https://attack.mitre.org/techniques/T1558/003/', 'https://bloodhound.readthedocs.io/'],
  },
  {
    id: 'lateral_movement',
    keywords: ['movimento lateral', 'lateral movement', 'rdp', 'ssh', 'smb', 'winrm', 'psexec', 'wmi', 'propagando', 'espalhando', 'hosts comprometidos', 'pivoting', 'maquinas afetadas', 'máquinas afetadas', 'pulando de maquina', 'se espalhando'],
    weightedKeywords: ['movimento lateral', 'rdp suspeito', 'smb lateral', 'psexec suspeito', 'wmi execução remota', 'pivoting', 'se espalhando pela rede', 'saltando de host'],
    title: 'Movimento Lateral na Rede',
    severity: 'critical',
    ttps: ['T1021.001', 'T1021.002', 'T1021.006', 'T1550.002', 'T1570'],
    summary: 'Movimento lateral indica que o atacante está dentro da rede e se deslocando entre sistemas. Identificar o "patient zero" e todos os hosts já comprometidos é urgente para conter a progressão.',
    steps: [
      { priority: 1, action: 'Mapear de qual host partiram as conexões suspeitas: SIEM — correlacionar EventID 4624 LogonType 3 e 10', tool: 'SIEM', link: null, category: 'Investigação' },
      { priority: 2, action: 'Identificar o "patient zero" — host com menor timestamp de atividade maliciosa', tool: 'EDR / SIEM timeline', link: null, category: 'Investigação' },
      { priority: 3, action: 'Verificar quais credenciais foram usadas no movimento (EventID 4624 Account Name)', tool: 'Windows Security Log', link: null, category: 'Análise' },
      { priority: 4, action: 'Isolar hosts comprometidos: segmentar VLANs ou usar isolamento via EDR', tool: 'EDR / Switch VLAN / Firewall interno', link: null, category: 'Contenção' },
      { priority: 5, action: 'Verificar Pass-the-Hash: EventID 4624 LogonType 3 com NtLmSsp para múltiplos hosts', tool: 'SIEM', link: null, category: 'Análise' },
      { priority: 6, action: 'Verificar ferramentas copiadas via ADMIN$ nos hosts de destino', tool: 'EDR / Sysmon EventID 11 (FileCreate em ADMIN$)', link: null, category: 'Investigação' },
    ],
    mitigations: ['M1035 - Limit Access Over Network', 'M1032 - MFA', 'M1030 - Network Segmentation'],
    references: ['https://attack.mitre.org/techniques/T1021/'],
  },
  {
    id: 'cloud_incident',
    keywords: ['cloud', 'nuvem', 'azure', 'aws', 'gcp', 'google cloud', 'm365', 'microsoft 365', 'sharepoint', 'teams', 'onedrive', 'bucket', 's3', 'storage', 'iam', 'role', 'entra id', 'aad', 'office 365', 'tenant'],
    weightedKeywords: ['azure comprometido', 'aws comprometido', 'bucket s3 exposto', 'iam privilege escalation', 'azure ad breach', 'm365 comprometido', 'cloud attack'],
    title: 'Incidente em Cloud (Azure/AWS/M365)',
    severity: 'high',
    ttps: ['T1078.004', 'T1530', 'T1567.002', 'T1136.003', 'T1098.001'],
    summary: 'Incidentes cloud têm escopo potencialmente enorme — um IAM comprometido pode dar acesso a toda a infraestrutura. Revogue credenciais imediatamente e audite CloudTrail/Azure Monitor.',
    steps: [
      { priority: 1, action: 'Revogar/rotacionar chaves de API e tokens comprometidos imediatamente', tool: 'Azure Portal / AWS IAM / GCP Console', link: null, category: '🔴 CRÍTICO' },
      { priority: 2, action: 'Analisar logs de autenticação cloud (Azure Sign-In / CloudTrail / GCP Audit)', tool: 'Azure Monitor / AWS CloudTrail / GCP Audit Log', link: null, category: 'Investigação' },
      { priority: 3, action: 'Verificar criação de novos usuários/roles/permissões na timeline do incidente', tool: 'Azure AD Audit / IAM Access Advisor', link: null, category: 'Investigação' },
      { priority: 4, action: 'Verificar dados acessados/exfiltrados: downloads de storage, e-mails lidos', tool: 'DLP / CloudTrail Data Events / M365 Compliance', link: null, category: 'Análise' },
      { priority: 5, action: 'Verificar criação de recursos (VMs, buckets) — possível uso para mineração', tool: 'Azure Cost Analysis / AWS Resource Explorer', link: null, category: 'Investigação' },
      { priority: 6, action: 'Implementar MFA e revisar permissões IAM pelo princípio do mínimo privilégio', tool: 'Azure AD / AWS IAM Access Analyzer', link: null, category: 'Remediação' },
    ],
    mitigations: ['M1032 - MFA', 'M1018 - User Account Management', 'M1047 - Audit'],
    references: ['https://attack.mitre.org/techniques/T1078/004/'],
  },
  {
    id: 'web_attack',
    keywords: ['aplicacao web', 'aplicação web', 'webapp', 'web app', 'sql', 'injection', 'xss', 'cross site', 'ssrf', 'rce', 'webshell', 'web shell', 'upload', 'nginx', 'apache', 'iis', 'tomcat', 'api', 'endpoint', 'waf', 'payload no campo'],
    weightedKeywords: ['sql injection', 'xss', 'ssrf', 'web shell instalado', 'rce na aplicação', 'upload malicioso', 'payload injetado'],
    title: 'Ataque em Aplicação Web',
    severity: 'high',
    ttps: ['T1190', 'T1059.007', 'T1505.003', 'T1078', 'T1136'],
    summary: 'Ataques web exploram SQLi, XSS, SSRF e RCE. Após exploração, atacantes instalam web shells para acesso persistente. Logs do WAF e servidor web são as fontes primárias de evidência.',
    steps: [
      { priority: 1, action: 'Analisar logs WAF e servidor web por payloads: SQL (single quote, union), path traversal (../), JNDI (${jndi:)', tool: 'WAF Logs / Apache/Nginx access.log / IIS logs', link: null, category: 'Investigação' },
      { priority: 2, action: 'Verificar processos filhos do servidor web lançando shell: w3wp.exe → cmd.exe = web shell', tool: 'EDR / Sysmon EventID 1', link: null, category: 'Análise' },
      { priority: 3, action: 'Buscar web shells: find /var/www -name "*.php" -newer index.php (Linux) | dir /s *.asp (Windows)', tool: 'CLI / EDR file monitoring', link: null, category: 'Investigação' },
      { priority: 4, action: 'Verificar queries SQL anômalas nos logs de banco de dados', tool: 'DB Activity Monitoring / DB Logs', link: null, category: 'Análise' },
      { priority: 5, action: 'Avaliar quais dados foram acessados/exfiltrados (impacto LGPD)', tool: 'DLP / WAF / Proxy Logs', link: null, category: 'Análise' },
      { priority: 6, action: 'Aplicar patch da vulnerabilidade e remover web shells identificados', tool: 'Patch + remoção manual auditada', link: null, category: 'Remediação' },
    ],
    mitigations: ['M1051 - Update Software', 'M1042 - Disable or Remove Feature', 'M1050 - Exploit Protection'],
    references: ['https://owasp.org/www-project-top-ten/', 'https://attack.mitre.org/techniques/T1190/'],
  },
  {
    id: 'privilege_escalation',
    keywords: ['escalacao', 'escalação', 'escalada', 'privilegio', 'privilégio', 'admin', 'root', 'system', 'uac bypass', 'sudo', 'setuid', 'kernel exploit', 'token', 'impersonation', 'virei admin', 'tenho system', 'conseguiu root'],
    weightedKeywords: ['escalada de privilégios', 'uac bypass', 'kernel exploit', 'token impersonation', 'virou domain admin', 'conseguiu root', 'explorou para elevar'],
    title: 'Escalada de Privilégios',
    severity: 'critical',
    ttps: ['T1068', 'T1548.002', 'T1055', 'T1134', 'T1484'],
    summary: 'Escalada permite obter SYSTEM/root/Domain Admin. Normalmente ocorre após acesso inicial e antecede movimento lateral massivo. Identificar a técnica usada é fundamental para remediar.',
    steps: [
      { priority: 1, action: 'Identificar processo que elevou privilégios: EventID 4672 (special privileges assigned)', tool: 'Windows Security Log / SIEM', link: null, category: 'Análise' },
      { priority: 2, action: 'Verificar técnica usada: UAC bypass (fodhelper.exe, eventvwr.exe), token impersonation (SeImpersonatePrivilege)?', tool: 'EDR / Sysmon', link: null, category: 'Análise' },
      { priority: 3, action: 'Verificar carregamento de driver suspeito (BYOVD): Sysmon EventID 6 — driver não assinado ou vulnerável', tool: 'Sysmon EventID 6 / EDR', link: null, category: 'Análise' },
      { priority: 4, action: 'Verificar ações executadas após a elevação de privilégio', tool: 'EDR / Windows Security Log EventID 4688', link: null, category: 'Investigação' },
      { priority: 5, action: 'Isolar host e revogar chaves/tokens comprometidos', tool: 'EDR / Active Directory', link: null, category: 'Contenção' },
    ],
    mitigations: ['M1026 - Privileged Account Management', 'M1051 - Update Software', 'M1040 - Behavior Prevention'],
    references: ['https://attack.mitre.org/techniques/T1068/', 'https://attack.mitre.org/techniques/T1548/002/'],
  },
  {
    id: 'data_exfiltration',
    keywords: ['exfiltracao', 'exfiltração', 'exfiltration', 'vazamento', 'dados saindo', 'upload suspeito', 'transferencia', 'transferência', 'copiando', 'dados enviados', 'dataleak', 'data loss', 'dlp', 'dns tunneling', 'icmp', 'muito trafego de saida'],
    weightedKeywords: ['exfiltração de dados', 'dados vazando', 'upload suspeito grande', 'dns tunneling', 'icmp tunneling', 'muito tráfego de saída', 'dados sendo copiados'],
    title: 'Exfiltração de Dados',
    severity: 'critical',
    ttps: ['T1041', 'T1048', 'T1567', 'T1020', 'T1030'],
    summary: 'Dados sensíveis estão deixando a organização. LGPD exige notificação à ANPD em 72h se dados pessoais foram afetados. Detectar e conter rapidamente é crítico — cada GB exfiltrado aumenta o impacto regulatório.',
    steps: [
      { priority: 1, action: 'Estimar volume de dados transferidos e identificar o destino (IP/domínio)', tool: 'Firewall Flow Logs / NetFlow / DLP Alerts', link: null, category: 'Análise' },
      { priority: 2, action: 'Identificar protocolo: HTTP upload, DNS queries anômalas, SMTP, FTP, SFTP?', tool: 'Proxy Logs / DNS Logs / Firewall', link: null, category: 'Análise' },
      { priority: 3, action: 'Verificar IP/domínio de destino em threat intel', tool: 'IOC Lookup (VirusTotal + AbuseIPDB)', link: '/lookup', category: 'Consulta' },
      { priority: 4, action: 'Identificar quais dados foram acessados antes da exfiltração', tool: 'DLP / File Access Audit Logs / SIEM', link: null, category: 'Investigação' },
      { priority: 5, action: 'Bloquear destino no firewall/proxy e interromper a transferência em curso', tool: 'Firewall / Proxy / DLP', link: null, category: 'Contenção' },
      { priority: 6, action: 'Avaliar obrigação LGPD — dados pessoais afetados? Prazo: 72h para notificar ANPD', tool: 'DPO / Consultoria Jurídica', link: null, category: 'Legal' },
    ],
    mitigations: ['M1057 - Data Loss Prevention', 'M1031 - Network Intrusion Prevention', 'M1037 - Filter Network Traffic'],
    references: ['https://attack.mitre.org/techniques/T1041/', 'https://www.anpd.gov.br/'],
  },
  {
    id: 'insider_threat',
    keywords: ['funcionario', 'funcionário', 'insider', 'colaborador', 'interno', 'demitido', 'acesso indevido', 'acessando dados', 'copiando', 'sabotagem', 'ex-funcionario', 'desligado', 'download em massa', 'suspeita de funcionario'],
    weightedKeywords: ['insider threat', 'funcionário suspeito', 'ex-funcionário acessando', 'colaborador copiando dados', 'sabotagem interna', 'download em massa'],
    title: 'Ameaça Interna (Insider Threat)',
    severity: 'high',
    ttps: ['T1078', 'T1213', 'T1048', 'T1485', 'T1070'],
    summary: 'Insiders têm acesso legítimo — detecção depende de baselining comportamental. Foque em anomalias: acessos fora do horário, volumes anormais de download, acesso a dados fora do escopo do cargo.',
    steps: [
      { priority: 1, action: 'Revisar logs de acesso do usuário: horário, sistemas acessados, volume de dados manipulados', tool: 'SIEM / DLP / File Audit Logs', link: null, category: 'Investigação' },
      { priority: 2, action: 'Comparar volume de downloads/acessos recentes vs. baseline histórico do mesmo usuário', tool: 'UEBA / DLP / File Access Logs', link: null, category: 'Análise' },
      { priority: 3, action: 'Verificar uso de USB/CD, uploads para Google Drive/Dropbox pessoal, e-mails para conta pessoal', tool: 'DLP / Proxy Logs / Email DLP', link: null, category: 'Análise' },
      { priority: 4, action: 'Preservar evidências ANTES de confrontar — manter cadeia de custódia para possível ação judicial', tool: 'Coleta forense / Documentação formal', link: null, category: '🔴 Legal' },
      { priority: 5, action: 'Suspender acesso do colaborador imediatamente se confirmado', tool: 'Active Directory / IDP / Badge system', link: null, category: 'Contenção' },
      { priority: 6, action: 'Envolver RH, Jurídico e DPO no processo — não agir unilateralmente', tool: 'Equipes internas', link: null, category: 'Legal' },
    ],
    mitigations: ['M1018 - User Account Management', 'M1057 - Data Loss Prevention', 'M1047 - Audit'],
    references: ['https://www.cisa.gov/topics/physical-security/insider-threat-mitigation'],
  },
  {
    id: 'ddos',
    keywords: ['ddos', 'dos', 'ataque volumetrico', 'ataque volumétrico', 'fora do ar', 'indisponivel', 'indisponível', 'sobrecarga', 'flood', 'syn flood', 'amplificacao', 'amplificação', 'slowloris', 'servico caiu', 'site caiu', 'site fora', 'lento demais'],
    weightedKeywords: ['ddos', 'ataque volumétrico', 'syn flood', 'amplificação dns', 'site caiu por ataque', 'serviço indisponível por ataque'],
    title: 'Ataque DDoS / Negação de Serviço',
    severity: 'high',
    ttps: ['T1498', 'T1499'],
    summary: 'DDoS torna serviços indisponíveis por sobrecarga. Atenção: DDoS frequentemente é usado como distração para outro ataque simultâneo — não desvie toda a atenção para o DDoS.',
    steps: [
      { priority: 1, action: 'Confirmar que é ataque (não problema de infra): checar status.azure.com / status.aws.amazon.com / isitdown.us', tool: 'Status pages dos provedores', link: null, category: 'Triagem' },
      { priority: 2, action: 'Identificar tipo: volumétrico (Gbps), protocolo (SYN flood) ou aplicação (HTTP flood)?', tool: 'Firewall Stats / NetFlow / IDS', link: null, category: 'Análise' },
      { priority: 3, action: 'Ativar proteção anti-DDoS no CDN: Cloudflare "Under Attack Mode" / AWS Shield / Azure DDoS', tool: 'CDN / Cloud DDoS Protection', link: null, category: 'Contenção' },
      { priority: 4, action: 'Rate limiting e bloqueio de ASNs/países de origem suspeitos no WAF', tool: 'WAF / Load Balancer / Firewall', link: null, category: 'Contenção' },
      { priority: 5, action: 'Contatar ISP para upstream scrubbing se ataque volumétrico ultrapassar capacidade', tool: 'ISP NOC / Cloudflare Magic Transit', link: null, category: 'Escalada' },
      { priority: 6, action: '⚠️ Monitorar outros alertas de segurança — DDoS pode ser distração para ataque maior', tool: 'SIEM — não desviar atenção completamente', link: null, category: 'Investigação' },
    ],
    mitigations: ['M1037 - Filter Network Traffic', 'M1035 - Limit Access to Resource'],
    references: ['https://attack.mitre.org/techniques/T1498/', 'https://www.cloudflare.com/ddos/'],
  },
  {
    id: 'persistence',
    keywords: ['persistencia', 'persistência', 'persistence', 'startup', 'inicializacao', 'inicialização', 'registro', 'registry', 'tarefa agendada', 'scheduled task', 'cron', 'servico novo', 'serviço novo', 'backdoor', 'implante', 'volta sempre', 'voltou depois de reiniciar', 'run key'],
    weightedKeywords: ['backdoor instalado', 'persistência detectada', 'tarefa agendada suspeita', 'serviço novo suspeito', 'chave run suspeita', 'volta após reiniciar', 'mecanismo de persistência'],
    title: 'Mecanismo de Persistência Detectado',
    severity: 'high',
    ttps: ['T1547.001', 'T1053.005', 'T1543.003', 'T1505.003', 'T1136'],
    summary: 'Persistência garante acesso mesmo após reinicializações. Remover TODOS os mecanismos é crucial antes de declarar o incidente encerrado — backdoors esquecidos causam reinfecção garantida.',
    steps: [
      { priority: 1, action: 'Verificar chaves Run/RunOnce no registro: HKCU e HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run', tool: 'regedit / Autoruns (Sysinternals) — gratuito', link: null, category: 'Investigação' },
      { priority: 2, action: 'Verificar tarefas agendadas: schtasks /query /fo LIST /v (ou aba Scheduled Tasks no Autoruns)', tool: 'CMD / Autoruns', link: null, category: 'Investigação' },
      { priority: 3, action: 'Verificar serviços novos instalados: EventID 7045 / sc query type= all state= all', tool: 'Windows Event Log / Autoruns (aba Services)', link: null, category: 'Investigação' },
      { priority: 4, action: 'Verificar pasta Startup: shell:startup (usuário) e shell:common startup (todos)', tool: 'Autoruns / Windows Explorer', link: null, category: 'Investigação' },
      { priority: 5, action: 'Verificar hash dos executáveis suspeitos encontrados em qualquer dos métodos acima', tool: 'IOC Lookup (VirusTotal)', link: '/lookup', category: 'Consulta' },
      { priority: 6, action: 'Remover mecanismos e verificar reincidência após reinicialização controlada e monitorada', tool: 'EDR / Remoção manual + reboot', link: null, category: 'Remediação' },
    ],
    mitigations: ['M1018 - User Account Management', 'M1022 - Restrict File and Directory Permissions', 'M1024 - Restrict Registry Permissions'],
    references: ['https://attack.mitre.org/tactics/TA0003/'],
  },
  {
    id: 'brute_force',
    keywords: ['forca bruta', 'força bruta', 'brute force', 'password spray', 'spraying', 'tentativas de login', 'falhas de autenticacao', 'falhas de autenticação', 'lockout', 'bloqueio de conta', 'tentativas', 'tentando senhas', 'credential stuffing', 'muitas tentativas'],
    weightedKeywords: ['brute force', 'password spraying', 'credential stuffing', 'muitas tentativas de login', 'conta bloqueada', 'tentativa de login em massa'],
    title: 'Força Bruta / Password Spray',
    severity: 'medium',
    ttps: ['T1110.001', 'T1110.003', 'T1110.004'],
    summary: 'Password Spraying (1 senha para N contas) evita lockout e é difícil de detectar. Se alguma tentativa teve SUCESSO, trate como conta comprometida imediatamente e inicie o cenário de Credenciais.',
    steps: [
      { priority: 1, action: 'Identificar padrão: brute force (muitas falhas 1 conta) ou spraying (poucas falhas N contas)?', tool: 'SIEM — EventID 4625 agrupado por conta vs por IP de origem', link: null, category: 'Análise' },
      { priority: 2, action: 'Verificar IP de origem em threat intel (VPN? Tor? Data center suspeito?)', tool: 'IOC Lookup (AbuseIPDB)', link: '/lookup', category: 'Consulta' },
      { priority: 3, action: '⚠️ CRÍTICO: Verificar se algum login teve sucesso após as falhas (EventID 4624)', tool: 'SIEM — correlacionar EventID 4625 + 4624 do mesmo IP/conta', link: null, category: 'Análise' },
      { priority: 4, action: 'Bloquear IP de origem no firewall/gateway de autenticação', tool: 'Firewall / Azure AD Identity Protection / Okta ThreatInsight', link: null, category: 'Contenção' },
      { priority: 5, action: 'Habilitar MFA para todas as contas expostas à internet', tool: 'Active Directory / IDP', link: null, category: 'Remediação' },
      { priority: 6, action: 'Se login bem-sucedido confirmado: iniciar resposta de conta comprometida (revogar sessões, reset senha)', tool: 'Azure AD / IDP — ver cenário de Credenciais', link: null, category: 'Escalada' },
    ],
    mitigations: ['M1032 - Multi-factor Authentication', 'M1036 - Account Use Policies', 'M1027 - Password Policies'],
    references: ['https://attack.mitre.org/techniques/T1110/003/'],
  },
  {
    id: 'forensics',
    keywords: ['forense', 'forensics', 'evidencia', 'evidência', 'log', 'investigar', 'analisar', 'timeline', 'o que aconteceu', 'quando aconteceu', 'memoria', 'memória', 'dump', 'artefato', 'historico', 'reconstituir', 'investigacao', 'coleta de evidencias'],
    weightedKeywords: ['análise forense', 'coletar evidências', 'timeline do ataque', 'dump de memória', 'reconstruir o ataque', 'investigação forense', 'forense digital'],
    title: 'Investigação Forense Digital',
    severity: 'medium',
    ttps: ['T1070', 'T1006', 'T1485'],
    summary: 'Forense reconstrói o que aconteceu, como e quando. Respeite a ordem de volatilidade: colete RAM e conexões ANTES de desligar. Documente a cadeia de custódia para possível ação judicial.',
    steps: [
      { priority: 1, action: 'ANTES de desligar: coletar imagem da memória RAM (mais volátil — perde ao desligar)', tool: 'DumpIt / WinPmem / FTK Imager Live', link: null, category: 'Coleta Volátil' },
      { priority: 2, action: 'Registrar conexões abertas: netstat -anob (Win) | ss -tulpn (Linux)', tool: 'CLI / EDR', link: null, category: 'Coleta Volátil' },
      { priority: 3, action: 'Coletar imagem forense do disco (bit-a-bit, write blocker, preservar hash)', tool: 'FTK Imager / dc3dd / dcfldd', link: null, category: 'Coleta Disco' },
      { priority: 4, action: 'Exportar Windows Event Logs: wevtutil epl Security security.evtx | wevtutil epl System system.evtx', tool: 'wevtutil / SIEM', link: null, category: 'Coleta Logs' },
      { priority: 5, action: 'Construir timeline correlacionando todas as fontes de log', tool: 'Plaso (log2timeline) / Velociraptor / Volatility', link: null, category: 'Análise' },
      { priority: 6, action: 'Documentar cadeia de custódia: hash SHA256 das evidências + quem coletou + quando', tool: 'Documento formal assinado', link: null, category: 'Legal' },
    ],
    mitigations: [],
    references: ['https://www.volatilityfoundation.org/', 'https://docs.velociraptor.app/'],
  },
];

export const defaultScenario = {
  title: 'Consulta Geral de Segurança',
  severity: 'info',
  ttps: [],
  summary: 'Não identifiquei um cenário específico para sua pergunta. Tente descrever com mais detalhes: o que você viu, em qual sistema, qual ferramenta gerou o alerta e qual é o comportamento suspeito.',
  steps: [
    { priority: 1, action: 'Dica: Inclua mais contexto — ex: "powershell executando comando estranho" ou "usuário logando de IP russo de madrugada"', tool: null, link: null, category: 'Dica' },
    { priority: 2, action: 'Para verificar IPs, hashes, domínios ou CVEs suspeitos', tool: 'IOC Lookup', link: '/lookup', category: 'Consulta' },
    { priority: 3, action: 'Para analisar e-mail suspeito com headers completos', tool: 'Email Header Analyzer', link: '/email-header', category: 'Análise' },
    { priority: 4, action: 'Para consultar táticas e técnicas de atacantes', tool: 'MITRE Explorer', link: '/mitre', category: 'Referência' },
  ],
  mitigations: [],
  references: [],
};

// ─── Técnicas MITRE ATT&CK (subset das principais) ────────────────────────────
export const mitreTactics = [
    { id: 'TA0043', name: 'Reconnaissance', namePT: 'Reconhecimento', color: '#6366f1', icon: '🔍' },
    { id: 'TA0042', name: 'Resource Development', namePT: 'Desenvolv. de Recursos', color: '#8b5cf6', icon: '🛠️' },
    { id: 'TA0001', name: 'Initial Access', nameWT: 'Acesso Inicial', nameP: 'Acesso Inicial', color: '#ec4899', icon: '🚪' },
    { id: 'TA0002', name: 'Execution', nameWT: 'Execução', nameP: 'Execução', color: '#ef4444', icon: '▶️' },
    { id: 'TA0003', name: 'Persistence', nameWT: 'Persistência', nameP: 'Persistência', color: '#f97316', icon: '🔒' },
    { id: 'TA0004', name: 'Privilege Escalation', nameWT: 'Escalada de Privilégios', nameP: 'Escal. Privilégios', color: '#eab308', icon: '⬆️' },
    { id: 'TA0005', name: 'Defense Evasion', nameWT: 'Evasão de Defesas', nameP: 'Evasão de Defesas', color: '#84cc16', icon: '🛡️' },
    { id: 'TA0006', name: 'Credential Access', nameWT: 'Acesso a Credenciais', nameP: 'Acesso Credenciais', color: '#22c55e', icon: '🔑' },
    { id: 'TA0007', name: 'Discovery', nameWT: 'Descoberta', nameP: 'Descoberta', color: '#10b981', icon: '🗺️' },
    { id: 'TA0008', name: 'Lateral Movement', nameWT: 'Movimento Lateral', nameP: 'Movim. Lateral', color: '#06b6d4', icon: '↔️' },
    { id: 'TA0009', name: 'Collection', nameWT: 'Coleta', nameP: 'Coleta', color: '#3b82f6', icon: '📦' },
    { id: 'TA0011', name: 'Command and Control', nameWT: 'Comando e Controle', nameP: 'C2', color: '#6366f1', icon: '📡' },
    { id: 'TA0010', name: 'Exfiltration', nameWT: 'Exfiltração', nameP: 'Exfiltração', color: '#8b5cf6', icon: '📤' },
    { id: 'TA0040', name: 'Impact', nameWT: 'Impacto', nameP: 'Impacto', color: '#ef4444', icon: '💥' },
];

export const mitreTechniques = [
    // Reconnaissance (TA0043)
    { id: 'T1595', tacticId: 'TA0043', name: 'Active Scanning', desc: 'Atacantes realizam varreduras ativas para identificar sistemas, serviços e vulnerabilidades em redes alvo.', subtecnicas: ['T1595.001 - Vulnerability Scanning', 'T1595.002 - Wordlist Scanning'], platforms: ['Network'], mitigations: ['M1031 - Network Intrusion Prevention'], detections: ['IDS/IPS alerts for scanning', 'Unusual network traffic patterns'], severity: 'low' },
    { id: 'T1598', tacticId: 'TA0043', name: 'Phishing for Information', desc: 'Envio de e-mails ou mensagens para coletar informações sobre a organização ou indivíduos, sem necessariamente entregar malware.', subtecnicas: ['T1598.001 - Spearphishing for Information', 'T1598.002 - Whaling for Information'], platforms: ['Email', 'Social Media'], mitigations: ['M1017 - User Training'], detections: ['User reports of suspicious emails', 'Email gateway logs'], severity: 'medium' },
    { id: 'T1590', tacticId: 'TA0043', name: 'Gather Victim Network Information', desc: 'Coleta de informações sobre a rede da vítima, como topologia, endereços IP, domínios e serviços, a partir de fontes públicas ou acessíveis.', subtecnicas: ['T1590.001 - DNS', 'T1590.002 - Network Topology', 'T1590.003 - IP Addresses'], platforms: ['Network'], mitigations: ['M1054 - Software Configuration'], detections: ['Monitoring public data sources for company info'], severity: 'low' },

    // Resource Development (TA0042)
    { id: 'T1583', tacticId: 'TA0042', name: 'Acquire Infrastructure', desc: 'Atacantes adquirem infraestrutura como domínios, servidores, certificados SSL para hospedar operações maliciosas.', subtecnicas: ['T1583.001 - Domains', 'T1583.003 - Virtual Private Server', 'T1583.006 - Web Services'], platforms: ['Cloud', 'Network'], mitigations: ['M1021 - Restrict Web-Based Content'], detections: ['Monitoring new domain registrations related to brand'], severity: 'medium' },
    { id: 'T1608', tacticId: 'TA0042', name: 'Stage Capabilities', desc: 'Preparação de capacidades (malware, exploits) em infraestrutura controlada pelo atacante antes de um ataque.', subtecnicas: ['T1608.001 - Upload Tool', 'T1608.003 - Drive-by Target'], platforms: ['Cloud', 'Network'], mitigations: ['M1037 - Filter Network Traffic'], detections: ['Threat intelligence feeds for new malware samples'], severity: 'medium' },

    // Initial Access (TA0001)
    { id: 'T1566', tacticId: 'TA0001', name: 'Phishing', desc: 'Envio de mensagens fraudulentas para coletar informações ou instalar malware. Inclui spear phishing por e-mail, link e via serviços de terceiros.', subtecnicas: ['T1566.001 - Spearphishing Attachment', 'T1566.002 - Spearphishing Link', 'T1566.003 - Spearphishing via Service'], platforms: ['Windows', 'macOS', 'Linux'], mitigations: ['M1017 - User Training', 'M1054 - Software Configuration'], detections: ['Monitor incoming email for suspicious attachments/links', 'Email gateway logs'], severity: 'high' },
    { id: 'T1190', tacticId: 'TA0001', name: 'Exploit Public-Facing Application', desc: 'Exploração de vulnerabilidades em aplicações expostas publicamente para obter acesso inicial ao sistema.', subtecnicas: [], platforms: ['Windows', 'Linux', 'macOS', 'Containers'], mitigations: ['M1051 - Update Software', 'M1050 - Exploit Protection', 'M1048 - Application Isolation'], detections: ['Web application firewall alerts', 'Anomalous network traffic patterns'], severity: 'critical' },
    { id: 'T1078', tacticId: 'TA0001', name: 'Valid Accounts', desc: 'Uso de credenciais legítimas de contas para obter acesso inicial, manter persistência e escalar privilégios. Inclui contas padrão, de domínio, cloud e locais.', subtecnicas: ['T1078.001 - Default Accounts', 'T1078.002 - Domain Accounts', 'T1078.003 - Local Accounts', 'T1078.004 - Cloud Accounts'], platforms: ['Windows', 'Azure', 'Linux', 'macOS'], mitigations: ['M1032 - Multi-factor Authentication', 'M1027 - Password Policies'], detections: ['Impossible travel', 'Logins fora do horário', 'MFA push bombing'], severity: 'high' },
    { id: 'T1133', tacticId: 'TA0001', name: 'External Remote Services', desc: 'Acesso inicial através de serviços remotos legítimos (VPN, Citrix, RDP) que são expostos à internet e podem ser comprometidos.', subtecnicas: [], platforms: ['Windows', 'Linux', 'macOS'], mitigations: ['M1032 - Multi-factor Authentication', 'M1035 - Limit Access to Resource Over Network'], detections: ['Unusual VPN/RDP logins', 'Brute force attempts on remote services'], severity: 'high' },
    { id: 'T1189', tacticId: 'TA0001', name: 'Drive-by Compromise', desc: 'Comprometimento de sistemas através de visitas a sites maliciosos ou comprometidos que exploram vulnerabilidades no navegador ou plugins.', subtecnicas: [], platforms: ['Windows', 'macOS', 'Linux'], mitigations: ['M1021 - Restrict Web-Based Content', 'M1051 - Update Software'], detections: ['Browser exploit alerts', 'Unusual web traffic to known malicious sites'], severity: 'high' },

    // Execution (TA0002)
    { id: 'T1059', tacticId: 'TA0002', name: 'Command and Scripting Interpreter', desc: 'Uso de interpreters de comandos e scripts (PowerShell, bash, Python, etc.) para executar código malicioso.', subtecnicas: ['T1059.001 - PowerShell', 'T1059.003 - Windows Command Shell', 'T1059.004 - Unix Shell', 'T1059.006 - Python', 'T1059.007 - JavaScript'], platforms: ['Windows', 'macOS', 'Linux'], mitigations: ['M1038 - Execution Prevention', 'M1049 - Antivirus/Antimalware'], detections: ['Command line logging (EventID 4688)', 'Script block logging', 'PowerShell transcript'], severity: 'high' },
    { id: 'T1204', tacticId: 'TA0002', name: 'User Execution', desc: 'Engenharia social para induzir usuário a executar arquivo ou clicar em link malicioso. Frequentemente parte de campanhas de phishing.', subtecnicas: ['T1204.001 - Malicious Link', 'T1204.002 - Malicious File', 'T1204.003 - Malicious Image'], platforms: ['Windows', 'macOS', 'Linux'], mitigations: ['M1017 - User Training', 'M1038 - Execution Prevention'], detections: ['Process launches from user downloads/email', 'Office macro execution'], severity: 'medium' },
    { id: 'T1053', tacticId: 'TA0002', name: 'Scheduled Task/Job', desc: 'Criação de tarefas agendadas para executar código malicioso em intervalos regulares ou em eventos específicos do sistema.', subtecnicas: ['T1053.002 - At', 'T1053.003 - Cron', 'T1053.005 - Scheduled Task'], platforms: ['Windows', 'Linux', 'macOS'], mitigations: ['M1028 - Operating System Configuration', 'M1047 - Audit'], detections: ['EventID 4698 (Task created)', 'schtasks.exe command line monitoring'], severity: 'medium' },
    { id: 'T1569', tacticId: 'TA0002', name: 'System Services', desc: 'Criação ou modificação de serviços do sistema para executar código malicioso com privilégios elevados.', subtecnicas: ['T1569.002 - Service Execution'], platforms: ['Windows', 'Linux'], mitigations: ['M1028 - Operating System Configuration', 'M1047 - Audit'], detections: ['EventID 7045 (Service created)', 'Service control manager logs'], severity: 'high' },
    { id: 'T1106', tacticId: 'TA0002', name: 'Native API', desc: 'Uso direto de chamadas de API nativas do sistema operacional para executar funções maliciosas, contornando mecanismos de segurança de alto nível.', subtecnicas: [], platforms: ['Windows', 'macOS', 'Linux'], mitigations: ['M1040 - Behavior Prevention on Endpoint'], detections: ['Unusual API calls by processes', 'Hooking detection'], severity: 'high' },

    // Persistence (TA0003)
    { id: 'T1547', tacticId: 'TA0003', name: 'Boot or Logon Autostart Execution', desc: 'Configuração de chaves de registro, pastas de startup ou serviços para executar malware automaticamente na inicialização.', subtecnicas: ['T1547.001 - Registry Run Keys', 'T1547.004 - Winlogon Helper DLL', 'T1547.009 - Shortcut Modification'], platforms: ['Windows', 'macOS', 'Linux'], mitigations: ['M1018 - User Account Management', 'M1022 - Restrict File and Directory Permissions'], detections: ['Registry monitoring (Run keys)', 'Startup folder changes'], severity: 'high' },
    { id: 'T1543', tacticId: 'TA0003', name: 'Create or Modify System Process', desc: 'Criação ou modificação de processos do sistema, como serviços ou daemons, para manter a persistência.', subtecnicas: ['T1543.003 - Windows Service'], platforms: ['Windows', 'Linux', 'macOS'], mitigations: ['M1028 - Operating System Configuration', 'M1047 - Audit'], detections: ['New service creation (EventID 7045)', 'Unusual process parent-child relationships'], severity: 'high' },
    { id: 'T1574', tacticId: 'TA0003', name: 'Hijack Execution Flow', desc: 'Modificação do fluxo de execução de programas legítimos para carregar e executar código malicioso (ex: DLL Sideloading).', subtecnicas: ['T1574.001 - DLL Search Order Hijacking', 'T1574.002 - DLL Side-Loading'], platforms: ['Windows', 'Linux', 'macOS'], mitigations: ['M1042 - Disable or Remove Feature or Program', 'M1040 - Behavior Prevention on Endpoint'], detections: ['Unusual DLL loads', 'Process monitoring for module loads'], severity: 'high' },
    { id: 'T1098', tacticId: 'TA0003', name: 'Account Manipulation', desc: 'Criação ou modificação de contas de usuário para manter acesso persistente.', subtecnicas: ['T1098.002 - Additional Cloud Roles', 'T1098.003 - Additional Cloud Credentials'], platforms: ['Windows', 'Linux', 'macOS', 'Cloud'], mitigations: ['M1018 - User Account Management', 'M1032 - Multi-factor Authentication'], detections: ['New user account creation (EventID 4720)', 'Privilege changes on accounts'], severity: 'high' },

    // Privilege Escalation (TA0004)
    { id: 'T1068', tacticId: 'TA0004', name: 'Exploitation for Privilege Escalation', desc: 'Exploração de vulnerabilidades de software para elevar privilégios no sistema local.', subtecnicas: [], platforms: ['Windows', 'Linux', 'macOS'], mitigations: ['M1051 - Update Software', 'M1050 - Exploit Protection'], detections: ['Anomalous process spawning with elevated privileges', 'Vulnerability scanner alerts'], severity: 'critical' },
    { id: 'T1548', tacticId: 'TA0004', name: 'Abuse Elevation Control Mechanism', desc: 'Abuso de mecanismos de controle de elevação de privilégios (UAC, sudo) para executar código com privilégios mais altos.', subtecnicas: ['T1548.002 - Bypass User Account Control'], platforms: ['Windows', 'Linux', 'macOS'], mitigations: ['M1028 - Operating System Configuration', 'M1042 - Disable or Remove Feature or Program'], detections: ['UAC bypass attempts', 'Sudo log monitoring'], severity: 'high' },
    { id: 'T1134', tacticId: 'TA0004', name: 'Access Token Manipulation', desc: 'Manipulação de tokens de acesso para assumir a identidade de outro usuário ou processo com privilégios mais altos.', subtecnicas: ['T1134.001 - Token Impersonation/Theft', 'T1134.002 - Create Process with Token'], platforms: ['Windows'], mitigations: ['M1025 - Privileged Process Integrity'], detections: ['Process access to tokens', 'Unusual process creation with elevated tokens'], severity: 'critical' },
    { id: 'T1484', tacticId: 'TA0004', name: 'Group Policy Modification', desc: 'Modificação de políticas de grupo para conceder privilégios adicionais ou desabilitar controles de segurança.', subtecnicas: ['T1484.001 - Group Policy Modification'], platforms: ['Windows'], mitigations: ['M1018 - User Account Management', 'M1047 - Audit'], detections: ['Group Policy changes (EventID 5136)', 'Unusual GPO modifications'], severity: 'high' },

    // Defense Evasion (TA0005)
    { id: 'T1027', tacticId: 'TA0005', name: 'Obfuscated Files or Information', desc: 'Ofuscação de arquivos, scripts ou comunicações para dificultar detecção e análise por ferramentas de segurança.', subtecnicas: ['T1027.001 - Binary Padding', 'T1027.002 - Software Packing', 'T1027.004 - Compile After Delivery', 'T1027.010 - Command Obfuscation'], platforms: ['Windows', 'macOS', 'Linux'], mitigations: ['M1049 - Antivirus/Antimalware', 'M1040 - Behavior Prevention'], detections: ['High entropy strings', 'Base64 in command lines', 'AMSI alerts'], severity: 'high' },
    { id: 'T1562', tacticId: 'TA0005', name: 'Impair Defenses', desc: 'Desabilitação ou modificação de ferramentas de segurança, logs e mecanismos de defesa para evitar detecção.', subtecnicas: ['T1562.001 - Disable or Modify Tools', 'T1562.002 - Disable Windows Event Logging', 'T1562.004 - Disable or Modify System Firewall'], platforms: ['Windows', 'macOS', 'Linux'], mitigations: ['M1022 - Restrict File and Directory Permissions', 'M1047 - Audit'], detections: ['EventID 7045/7036 (service changes)', 'AV/EDR disabled alerts'], severity: 'critical' },
    { id: 'T1070', tacticId: 'TA0005', name: 'Indicator Removal on Host', desc: 'Remoção de logs, arquivos ou outros indicadores de comprometimento para cobrir rastros.', subtecnicas: ['T1070.001 - Clear Windows Event Logs', 'T1070.003 - Clear Command History', 'T1070.004 - File Deletion'], platforms: ['Windows', 'macOS', 'Linux'], mitigations: ['M1047 - Audit', 'M1028 - Operating System Configuration'], detections: ['Event log clearing (EventID 1102)', 'Unusual file deletions'], severity: 'high' },
    { id: 'T1036', tacticId: 'TA0005', name: 'Masquerading', desc: 'Atacantes tentam se passar por programas ou arquivos legítimos para evitar detecção.', subtecnicas: ['T1036.003 - Rename System Utilities', 'T1036.004 - Masquerade as Legitimate File'], platforms: ['Windows', 'macOS', 'Linux'], mitigations: ['M1040 - Behavior Prevention on Endpoint', 'M1045 - Code Signing'], detections: ['Unusual process names', 'Files with double extensions'], severity: 'medium' },
    { id: 'T1140', tacticId: 'TA0005', name: 'Deobfuscate/Decode Files or Information', desc: 'Desofuscação ou decodificação de dados para torná-los executáveis ou legíveis após a evasão inicial.', subtecnicas: [], platforms: ['Windows', 'macOS', 'Linux'], mitigations: ['M1040 - Behavior Prevention on Endpoint'], detections: ['Execution of deobfuscation tools', 'High CPU usage during script execution'], severity: 'medium' },

    // Credential Access (TA0006)
    { id: 'T1003', tacticId: 'TA0006', name: 'OS Credential Dumping', desc: 'Extração de credenciais e hashes de autenticação de sistemas operacionais e aplicações (ex: Mimikatz no LSASS).', subtecnicas: ['T1003.001 - LSASS Memory', 'T1003.002 - Security Account Manager', 'T1003.003 - NTDS', 'T1003.006 - DCSync'], platforms: ['Windows', 'Linux', 'macOS'], mitigations: ['M1043 - Credential Access Protection', 'M1025 - Privileged Process Integrity'], detections: ['Process access to LSASS (EventID 4656)', 'Mimikatz signatures', 'SAM/NTDS access'], severity: 'critical' },
    { id: 'T1110', tacticId: 'TA0006', name: 'Brute Force', desc: 'Tentativas sistemáticas de adivinhar credenciais por força bruta, password spraying ou credential stuffing.', subtecnicas: ['T1110.001 - Password Guessing', 'T1110.002 - Password Cracking', 'T1110.003 - Password Spraying', 'T1110.004 - Credential Stuffing'], platforms: ['Windows', 'Azure', 'Linux', 'Containers'], mitigations: ['M1036 - Account Use Policies', 'M1032 - Multi-factor Authentication'], detections: ['Multiple failed logins (EventID 4625)', 'Account lockout patterns'], severity: 'medium' },
    { id: 'T1555', tacticId: 'TA0006', name: 'Credentials from Password Stores', desc: 'Coleta de credenciais armazenadas em navegadores, gerenciadores de senhas ou outros arquivos locais.', subtecnicas: ['T1555.003 - Web Browsers', 'T1555.004 - Keychain'], platforms: ['Windows', 'macOS', 'Linux'], mitigations: ['M1043 - Credential Access Protection', 'M1027 - Password Policies'], detections: ['Access to browser credential stores', 'Execution of credential dumping tools'], severity: 'high' },
    { id: 'T1552', tacticId: 'TA0006', name: 'Unsecured Credentials', desc: 'Descoberta e uso de credenciais armazenadas de forma insegura em arquivos, variáveis de ambiente ou código.', subtecnicas: ['T1552.001 - Credentials in Files', 'T1552.002 - Credentials in Registry'], platforms: ['Windows', 'macOS', 'Linux'], mitigations: ['M1022 - Restrict File and Directory Permissions', 'M1027 - Password Policies'], detections: ['Scanning for credential files', 'Access to sensitive registry keys'], severity: 'high' },
    { id: 'T1606', tacticId: 'TA0006', name: 'Forge Web Credentials', desc: 'Criação de tokens de sessão ou cookies falsificados para autenticação em aplicações web.', subtecnicas: ['T1606.002 - SAML Tokens'], platforms: ['Web'], mitigations: ['M1032 - Multi-factor Authentication', 'M1047 - Audit'], detections: ['Unusual session token usage', 'SAML token validation failures'], severity: 'high' },

    // Discovery (TA0007)
    { id: 'T1046', tacticId: 'TA0007', name: 'Network Service Discovery', desc: 'Enumeração de serviços e portas abertas na rede para identificar alvos adicionais e planejar movimentos laterais.', subtecnicas: [], platforms: ['Windows', 'macOS', 'Linux', 'Containers'], mitigations: ['M1031 - Network Intrusion Prevention', 'M1030 - Network Segmentation'], detections: ['Network scanning patterns (IDS/IPS)', 'High volume SYN packets'], severity: 'medium' },
    { id: 'T1087', tacticId: 'TA0007', name: 'Account Discovery', desc: 'Enumeração de contas de usuário e grupos para identificar alvos de interesse e privilégios.', subtecnicas: ['T1087.001 - Local Account', 'T1087.002 - Domain Account', 'T1087.004 - Cloud Account'], platforms: ['Windows', 'macOS', 'Linux', 'Cloud'], mitigations: ['M1018 - User Account Management', 'M1047 - Audit'], detections: ['Execution of "net user" or "get-aduser"', 'Unusual LDAP queries'], severity: 'medium' },
    { id: 'T1057', tacticId: 'TA0007', name: 'Process Discovery', desc: 'Listagem de processos em execução para identificar software de segurança, aplicações sensíveis ou outros processos de interesse.', subtecnicas: [], platforms: ['Windows', 'macOS', 'Linux'], mitigations: ['M1047 - Audit'], detections: ['Execution of "tasklist" or "ps"', 'Unusual process enumeration'], severity: 'medium' },
    { id: 'T1083', tacticId: 'TA0007', name: 'File and Directory Discovery', desc: 'Busca por arquivos e diretórios sensíveis, como documentos, backups, configurações ou credenciais.', subtecnicas: [], platforms: ['Windows', 'macOS', 'Linux'], mitigations: ['M1022 - Restrict File and Directory Permissions'], detections: ['Unusual file access patterns', 'Execution of "dir" or "find"'], severity: 'medium' },
    { id: 'T1016', tacticId: 'TA0007', name: 'System Network Configuration Discovery', desc: 'Coleta de informações sobre a configuração de rede do sistema, como interfaces, rotas e configurações de firewall.', subtecnicas: [], platforms: ['Windows', 'macOS', 'Linux'], mitigations: ['M1047 - Audit'], detections: ['Execution of "ipconfig" or "ifconfig"', 'Unusual network configuration queries'], severity: 'medium' },
    { id: 'T1033', tacticId: 'TA0007', name: 'System Owner/User Discovery', desc: 'Identificação do proprietário ou usuários do sistema para entender o contexto e planejar ataques direcionados.', subtecnicas: [], platforms: ['Windows', 'macOS', 'Linux'], mitigations: ['M1018 - User Account Management'], detections: ['Execution of "whoami" or "id"', 'Unusual queries for user information'], severity: 'low' },
    { id: 'T1049', tacticId: 'TA0007', name: 'System Network Connections Discovery', desc: 'Listagem de conexões de rede ativas para identificar comunicações existentes e potenciais alvos de movimento lateral.', subtecnicas: [], platforms: ['Windows', 'macOS', 'Linux'], mitigations: ['M1047 - Audit'], detections: ['Execution of "netstat"', 'Unusual network connection enumeration'], severity: 'medium' },

    // Lateral Movement (TA0008)
    { id: 'T1021', tacticId: 'TA0008', name: 'Remote Services', desc: 'Uso de serviços remotos legítimos (RDP, SSH, SMB, WinRM) para mover-se lateralmente entre sistemas na rede.', subtecnicas: ['T1021.001 - Remote Desktop Protocol', 'T1021.002 - SMB/Windows Admin Shares', 'T1021.004 - SSH', 'T1021.006 - Windows Remote Management'], platforms: ['Windows', 'Linux', 'macOS'], mitigations: ['M1035 - Limit Access to Resource Over Network', 'M1032 - Multi-factor Authentication'], detections: ['Unusual RDP/SSH connections', 'Admin share access from unexpected hosts'], severity: 'high' },
    { id: 'T1570', tacticId: 'TA0008', name: 'Lateral Tool Transfer', desc: 'Transferência de ferramentas e malware para outros sistemas na rede para facilitar o movimento lateral.', subtecnicas: [], platforms: ['Windows', 'Linux', 'macOS'], mitigations: ['M1038 - Execution Prevention', 'M1049 - Antivirus/Antimalware'], detections: ['Unusual file transfers between hosts', 'Execution of remote copy commands'], severity: 'high' },
    { id: 'T1076', tacticId: 'TA0008', name: 'Remote Services Session Hijacking', desc: 'Sequestro de sessões de serviços remotos existentes para obter acesso a outros sistemas sem novas credenciais.', subtecnicas: [], platforms: ['Windows', 'Linux', 'macOS'], mitigations: ['M1035 - Limit Access to Resource Over Network'], detections: ['Unusual session activity', 'Session takeover alerts'], severity: 'high' },
    { id: 'T1550', tacticId: 'TA0008', name: 'Use Alternate Authentication Material', desc: 'Uso de material de autenticação alternativo (tickets Kerberos, hashes NTLM) para autenticar em outros sistemas.', subtecnicas: ['T1550.002 - Pass the Hash', 'T1550.003 - Pass the Ticket'], platforms: ['Windows'], mitigations: ['M1043 - Credential Access Protection', 'M1025 - Privileged Process Integrity'], detections: ['Kerberos ticket usage anomalies', 'NTLM hash usage'], severity: 'critical' },

    // Collection (TA0009)
    { id: 'T1005', tacticId: 'TA0009', name: 'Data from Local System', desc: 'Coleta de dados sensíveis diretamente do sistema local, como documentos, bancos de dados ou arquivos de configuração.', subtecnicas: [], platforms: ['Windows', 'macOS', 'Linux'], mitigations: ['M1022 - Restrict File and Directory Permissions', 'M1057 - Data Loss Prevention'], detections: ['Unusual access to sensitive files', 'Large file transfers from local system'], severity: 'high' },
    { id: 'T1039', tacticId: 'TA0009', name: 'Data from Network Shared Drive', desc: 'Coleta de dados de compartilhamentos de rede acessíveis, como pastas compartilhadas ou drives mapeados.', subtecnicas: [], platforms: ['Windows', 'macOS', 'Linux'], mitigations: ['M1022 - Restrict File and Directory Permissions', 'M1030 - Network Segmentation'], detections: ['Unusual access to network shares', 'Large file transfers from network drives'], severity: 'high' },
    { id: 'T1119', tacticId: 'TA0009', name: 'Automated Collection', desc: 'Uso de scripts ou ferramentas para automatizar a coleta de dados de múltiplos locais ou sistemas.', subtecnicas: [], platforms: ['Windows', 'macOS', 'Linux'], mitigations: ['M1040 - Behavior Prevention on Endpoint', 'M1057 - Data Loss Prevention'], detections: ['Execution of collection scripts', 'Rapid data access across multiple directories'], severity: 'high' },
    { id: 'T1530', tacticId: 'TA0009', name: 'Data from Cloud Storage', desc: 'Coleta de dados de serviços de armazenamento em nuvem, como S3 buckets, Azure Blob Storage ou Google Cloud Storage.', subtecnicas: [], platforms: ['Cloud'], mitigations: ['M1047 - Audit', 'M1022 - Restrict File and Directory Permissions'], detections: ['Unusual access to cloud storage', 'Large downloads from cloud storage'], severity: 'high' },
    { id: 'T1560', tacticId: 'TA0009', name: 'Archive Collected Data', desc: 'Compactação e/ou criptografia de dados coletados para facilitar a exfiltração e evitar detecção.', subtecnicas: ['T1560.001 - Archive via Utility', 'T1560.002 - Archive via Custom Method'], platforms: ['Windows', 'macOS', 'Linux'], mitigations: ['M1057 - Data Loss Prevention'], detections: ['Execution of archiving tools (zip, rar)', 'Creation of large encrypted archives'], severity: 'medium' },

    // Command and Control (TA0011)
    { id: 'T1071', tacticId: 'TA0011', name: 'Application Layer Protocol', desc: 'Uso de protocolos legítimos de camada de aplicação (HTTP/S, DNS, SMTP) para comunicação de C2 e exfiltração.', subtecnicas: ['T1071.001 - Web Protocols', 'T1071.004 - DNS', 'T1071.003 - Mail Protocols'], platforms: ['Windows', 'macOS', 'Linux'], mitigations: ['M1031 - Network Intrusion Prevention', 'M1037 - Filter Network Traffic'], detections: ['Anomalous DNS query volumes', 'Periodic beaconing patterns', 'Unusual HTTPS destinations'], severity: 'high' },
    { id: 'T1090', tacticId: 'TA0011', name: 'Proxy', desc: 'Uso de proxies, VPNs ou Tor para mascarar a origem do tráfego C2 e dificultar a rastreabilidade.', subtecnicas: ['T1090.002 - External Proxy', 'T1090.003 - Internal Proxy', 'T1090.004 - Tor'], platforms: ['Windows', 'macOS', 'Linux'], mitigations: ['M1037 - Filter Network Traffic', 'M1031 - Network Intrusion Prevention'], detections: ['Connections to known proxy/Tor exit nodes', 'Unusual proxy configurations'], severity: 'high' },
    { id: 'T1573', tacticId: 'TA0011', name: 'Encrypted Channel', desc: 'Uso de canais de comunicação criptografados (SSL/TLS, SSH) para proteger o tráfego C2 de inspeção.', subtecnicas: ['T1573.001 - Symmetric Cryptography', 'T1573.002 - Asymmetric Cryptography'], platforms: ['Windows', 'macOS', 'Linux'], mitigations: ['M1020 - SSL/TLS Inspection', 'M1031 - Network Intrusion Prevention'], detections: ['Unusual SSL/TLS certificates', 'Encrypted traffic to suspicious destinations'], severity: 'medium' },
    { id: 'T1105', tacticId: 'TA0011', name: 'Ingress Tool Transfer', desc: 'Transferência de ferramentas e malware para o sistema comprometido para uso posterior.', subtecnicas: [], platforms: ['Windows', 'macOS', 'Linux'], mitigations: ['M1038 - Execution Prevention', 'M1049 - Antivirus/Antimalware'], detections: ['Unusual file downloads', 'Execution of download utilities (curl, wget)'], severity: 'high' },
    { id: 'T1572', tacticId: 'TA0011', name: 'Protocol Tunneling', desc: 'Encapsulamento de um protocolo dentro de outro (ex: DNS tunneling, ICMP tunneling) para evadir detecção e firewalls.', subtecnicas: [], platforms: ['Windows', 'macOS', 'Linux'], mitigations: ['M1031 - Network Intrusion Prevention', 'M1037 - Filter Network Traffic'], detections: ['Anomalous DNS/ICMP traffic patterns', 'High volume of small packets'], severity: 'high' },

    // Exfiltration (TA0010)
    { id: 'T1048', tacticId: 'TA0010', name: 'Exfiltration Over Alternative Protocol', desc: 'Exfiltração de dados usando protocolos alternativos como DNS, ICMP ou outros canais para contornar controles de DLP.', subtecnicas: ['T1048.001 - Exfiltration Over Symmetric Encrypted Non-C2 Protocol', 'T1048.003 - Exfiltration Over Unencrypted Non-C2 Protocol'], platforms: ['Windows', 'macOS', 'Linux'], mitigations: ['M1031 - Network Intrusion Prevention', 'M1057 - Data Loss Prevention'], detections: ['High volume DNS queries', 'ICMP tunneling patterns', 'Large outbound transfers'], severity: 'critical' },
    { id: 'T1041', tacticId: 'TA0010', name: 'Exfiltration Over C2 Channel', desc: 'Exfiltração de dados através do mesmo canal de Comando e Controle estabelecido pelo atacante.', subtecnicas: [], platforms: ['Windows', 'macOS', 'Linux'], mitigations: ['M1057 - Data Loss Prevention', 'M1031 - Network Intrusion Prevention'], detections: ['Large data transfers over C2 channels', 'Unusual C2 traffic volume'], severity: 'high' },
    { id: 'T1567', tacticId: 'TA0010', name: 'Exfiltration Over Web Service', desc: 'Exfiltração de dados para serviços web externos, como armazenamento em nuvem (Dropbox, Google Drive) ou sites de pastebin.', subtecnicas: ['T1567.002 - Exfiltration to Cloud Storage'], platforms: ['Windows', 'macOS', 'Linux'], mitigations: ['M1057 - Data Loss Prevention', 'M1021 - Restrict Web-Based Content'], detections: ['Unusual uploads to cloud storage', 'Access to pastebin sites'], severity: 'high' },
    { id: 'T1020', tacticId: 'TA0010', name: 'Automated Exfiltration', desc: 'Uso de scripts ou ferramentas para automatizar a exfiltração de dados em massa ou em intervalos regulares.', subtecnicas: [], platforms: ['Windows', 'macOS', 'Linux'], mitigations: ['M1057 - Data Loss Prevention', 'M1040 - Behavior Prevention on Endpoint'], detections: ['Scheduled tasks for data transfer', 'High volume outbound traffic'], severity: 'high' },

    // Impact (TA0040)
    { id: 'T1486', tacticId: 'TA0040', name: 'Data Encrypted for Impact', desc: 'Criptografia de dados em sistemas para impedir acesso e extorquir resgate (Ransomware). Técnica de impacto de alta gravidade.', subtecnicas: [], platforms: ['Windows', 'macOS', 'Linux'], mitigations: ['M1053 - Data Backup', 'M1040 - Behavior Prevention on Endpoint'], detections: ['Mass file modification', 'Ransom note creation', 'Shadow copy deletion (vssadmin)'], severity: 'critical' },
    { id: 'T1490', tacticId: 'TA0040', name: 'Inhibit System Recovery', desc: 'Exclusão ou modificação de backups, shadow copies e mecanismos de recuperação para dificultar restauração após ataque.', subtecnicas: [], platforms: ['Windows', 'macOS', 'Linux'], mitigations: ['M1053 - Data Backup', 'M1028 - Operating System Configuration'], detections: ['vssadmin delete shadows', 'bcdedit modifications', 'wbadmin delete catalog'], severity: 'critical' },
    { id: 'T1499', tacticId: 'TA0040', name: 'Endpoint Denial of Service', desc: 'Ataques que visam tornar um endpoint indisponível, como desligamento, reinicialização ou sobrecarga de recursos.', subtecnicas: ['T1499.001 - OS Shutdown', 'T1499.002 - Resource Exhaustion'], platforms: ['Windows', 'macOS', 'Linux'], mitigations: ['M1028 - Operating System Configuration', 'M1040 - Behavior Prevention on Endpoint'], detections: ['System shutdowns/reboots', 'High CPU/memory usage'], severity: 'high' },
    { id: 'T1489', tacticId: 'TA0040', name: 'Service Stop', desc: 'Parada de serviços críticos do sistema ou de segurança para interromper operações ou evadir detecção.', subtecnicas: [], platforms: ['Windows', 'macOS', 'Linux'], mitigations: ['M1028 - Operating System Configuration', 'M1047 - Audit'], detections: ['Service stop events (EventID 7036)', 'Unusual service terminations'], severity: 'high' },
    { id: 'T1529', tacticId: 'TA0040', name: 'System Shutdown/Reboot', desc: 'Desligamento ou reinicialização de sistemas para causar interrupção ou dificultar a resposta a incidentes.', subtecnicas: [], platforms: ['Windows', 'macOS', 'Linux'], mitigations: ['M1028 - Operating System Configuration'], detections: ['System shutdown/reboot events', 'Unusual power-off commands'], severity: 'high' },
    { id: 'T1491', tacticId: 'TA0040', name: 'Defacement', desc: 'Modificação de conteúdo de sites ou sistemas para exibir mensagens do atacante, geralmente para fins de propaganda ou intimidação.', subtecnicas: ['T1491.001 - Internal Defacement', 'T1491.002 - External Defacement'], platforms: ['Web'], mitigations: ['M1022 - Restrict File and Directory Permissions', 'M1053 - Data Backup'], detections: ['Website content changes', 'Integrity monitoring alerts'], severity: 'medium' },
    { id: 'T1496', tacticId: 'TA0040', name: 'Resource Hijacking', desc: 'Uso de recursos do sistema comprometido (CPU, GPU, largura de banda) para atividades maliciosas, como mineração de criptomoedas.', subtecnicas: [], platforms: ['Windows', 'macOS', 'Linux'], mitigations: ['M1028 - Operating System Configuration', 'M1040 - Behavior Prevention on Endpoint'], detections: ['Unusual high resource usage', 'Connections to crypto mining pools'], severity: 'medium' },
];

// ─── Dados de exemplo de headers de e-mail ────────────────────────────────────
export const exampleEmailHeaders = {
    phishing: `Delivered-To: analista@empresa.com.br
Received: by 2002:a05:6402:1501:0:0:0:0 with SMTP id e1csp1234567iol;
        Mon, 01 Mar 2024 07:12:44 -0800 (PST)
Received: from mail-sor-f41.google.com (mail-sor-f41.google.com. [209.85.220.41])
        by mx.google.com with SMTPS id y23sor1234567pjq.61.2024.03.01.07.12.43
Received: from [185.220.101.47] (unknown [185.220.101.47])
        by smtp.mailgun.org (Postfix) with ESMTP id 4A3B2C;
        Mon, 01 Mar 2024 07:12:42 -0800 (PST)
From: "Banco Bradesco" <seguranca@bradesc0-online.ru>
To: analista@empresa.com.br
Reply-To: no-reply@bradesc0-online.ru
Subject: [URGENTE] Sua conta foi suspensa - Verifique agora
Date: Mon, 01 Mar 2024 10:12:41 -0500
Message-ID: <20240301101241.A1B2C3D4E5F6@bradesc0-online.ru>
MIME-Version: 1.0
Content-Type: text/html; charset=UTF-8
X-Mailer: PHPMailer 6.5.0
X-Originating-IP: 185.220.101.47
Authentication-Results: mx.google.com;
       spf=fail (google.com: domain of seguranca@bradesc0-online.ru does not designate 209.85.220.41 as permitted sender) smtp.mailfrom=seguranca@bradesc0-online.ru;
       dkim=none;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=bradesc0-online.ru`,
    legitimate: `Delivered-To: analista@empresa.com.br
Received: by 2002:a05:6402:1501:0:0:0:0 with SMTP id e1csp4567890iol;
        Mon, 01 Mar 2024 09:30:00 -0800 (PST)
Received: from mail-pj1-f53.google.com (mail-pj1-f53.google.com. [209.85.216.53])
        by mx.google.com with SMTPS id s1sor123456pjq.22.2024.03.01.09.29.59
From: "Microsoft 365" <noreply@microsoft.com>
To: analista@empresa.com.br
Subject: Seu resumo mensal do Microsoft 365
Date: Mon, 01 Mar 2024 17:30:00 +0000
Message-ID: <20240301173000.B1C2D3E4F5G6@microsoft.com>
MIME-Version: 1.0
Content-Type: text/html; charset=UTF-8
Authentication-Results: mx.google.com;
       spf=pass (google.com: domain of noreply@microsoft.com designates 209.85.216.53 as permitted sender) smtp.mailfrom=noreply@microsoft.com;
       dkim=pass header.i=@microsoft.com header.s=selector1 header.b=AbCdEfGh;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=microsoft.com`,
};

// ─── Dados mock de IoCs ──────────────────────────────────────────────────────
export const iocDatabase = {
    ips: {
        '185.220.101.47': {
            reputation: 'malicious',
            country: 'Rússia', countryCode: 'RU', city: 'Moscow',
            asn: 'AS4224', asnName: 'Tor Project',
            vtScore: 58, vtTotal: 73,
            abuseConfidence: 98, abuseReports: 234,
            ibmRisk: 9.8, ibmCategories: ['C2', 'Malware', 'Botnet'],
            hybridVerdict: null,
            reverseDns: 'tor-exit-relay.node.ru',
            openPorts: [443, 80, 22, 9001],
            tags: ['Tor Exit Node', 'C2', 'Botnet', 'Blacklisted', 'Threat Actor'],
            firstSeen: '2019-03-12',
            lastSeen: '2024-03-01',
            relatedMalware: ['Cobalt Strike', 'AsyncRAT', 'Agent Tesla'],
            summary: 'IP pertencente à infraestrutura Tor, classificado como nó de saída (Exit Node). Amplamente documentado como ponto de C2 para múltiplas campanhas de malware. Presente em listas de bloqueio de todos os principais feeds de threat intelligence. Nenhum uso legítimo esperado desta faixa.',
        },
        '8.8.8.8': {
            reputation: 'clean',
            country: 'Estados Unidos', countryCode: 'US', city: 'Mountain View',
            asn: 'AS15169', asnName: 'Google LLC',
            vtScore: 0, vtTotal: 73,
            abuseConfidence: 0, abuseReports: 0,
            ibmRisk: 0.1, ibmCategories: ['DNS', 'Legitimate'],
            hybridVerdict: null,
            reverseDns: 'dns.google',
            openPorts: [53],
            tags: ['Google', 'DNS', 'Público', 'Legítimo'],
            firstSeen: '2009-01-01',
            lastSeen: '2024-03-01',
            relatedMalware: [],
            summary: 'DNS público do Google. IP amplamente reconhecido como legítimo. Nenhum histórico de atividade maliciosa. Usado como servidor DNS público por milhões de usuários.',
        },
        '89.187.190.42': {
            reputation: 'suspicious',
            country: 'Reino Unido', countryCode: 'GB', city: 'London',
            asn: 'AS47583', asnName: 'Hostinger Ltd',
            vtScore: 8, vtTotal: 73,
            abuseConfidence: 45, abuseReports: 12,
            ibmRisk: 5.2, ibmCategories: ['Hosting', 'Proxy'],
            hybridVerdict: null,
            reverseDns: 'server.hostinger.com',
            openPorts: [80, 443, 22],
            tags: ['VPN', 'Datacenter', 'Hosting', 'Suspeito'],
            firstSeen: '2022-11-05',
            lastSeen: '2024-03-01',
            relatedMalware: [],
            summary: 'IP de datacenter de hosting compartilhado. Alguns reportes de abuso registrados. Pode ser VPN comercial ou servidor de aplicação. Contexto adicional necessário para classificação definitiva.',
        },
    },
    hashes: {
        '44d88612fea8a8f36de82e1278abb02f': {
            reputation: 'malicious',
            type: 'MD5',
            filename: 'eicar_test.exe',
            filesize: '68 bytes',
            filetype: 'Win32 EXE',
            vtScore: 68, vtTotal: 72,
            hybridVerdict: 'malicious',
            hybridThreat: 100,
            hybridFamily: 'EICAR-Test-File',
            hybridTags: ['Test', 'Anti-Malware', 'EICAR'],
            hybridNetworkActivity: 'Nenhuma',
            hybridRegistryChanges: 0,
            ibmRisk: 9.5,
            tags: ['EICAR', 'Test File', 'AV Test'],
            firstSeen: '2002-01-01',
            malwareFamilies: ['EICAR-Test-File'],
            summary: 'Hash do arquivo de teste EICAR — padrão da indústria para testar se antivírus está funcionando. Este arquivo não é malware real, mas é detectado por todos os AVs como teste.',
        },
        'a7f3e2b1c9d48f2e0b4c6d8e1a3f5b7d': {
            reputation: 'malicious',
            type: 'SHA256',
            filename: 'invoice_march2024.docm',
            filesize: '245 KB',
            filetype: 'MS Office Word Macro',
            vtScore: 45, vtTotal: 70,
            hybridVerdict: 'malicious',
            hybridThreat: 95,
            hybridFamily: 'Emotet',
            hybridTags: ['Emotet', 'Macro', 'Dropper', 'Banking Trojan'],
            hybridNetworkActivity: 'Conexão para 185.220.101.47:443 (C2)',
            hybridRegistryChanges: 12,
            ibmRisk: 9.1,
            tags: ['Emotet', 'Macro Malware', 'Dropper', 'Phishing'],
            firstSeen: '2024-02-28',
            malwareFamilies: ['Emotet', 'IcedID'],
            summary: 'Documento Word com macro maliciosa associada ao Emotet — um dos trojans bancários mais difundidos. Tipicamente distribuído via e-mail de phishing como fatura ou NF falsa. Estabelece conexão C2 e age como dropper para cargas secundárias.',
        },
    },
    domains: {
        'bradesc0-online.ru': {
            reputation: 'malicious',
            vtScore: 38, vtTotal: 70,
            ibmRisk: 9.4, ibmCategories: ['Phishing', 'Fraud'],
            whoisCreated: '2024-02-29',
            whoisRegistrar: 'NameCheap, Inc.',
            whoisCountry: 'Rússia',
            resolvedIp: '185.220.101.47',
            ssl: false,
            tags: ['Typosquatting', 'Phishing', 'Brand Abuse', 'Novo Domínio'],
            summary: 'Domínio registrado há 1 dia, usando typosquatting de "Bradesco" (bradesc0 com zero). Claro indicativo de phishing. Resolve para IP malicioso classificado como Tor Exit Node. Não possui certificado SSL válido.',
        },
        'microsoft.com': {
            reputation: 'clean',
            vtScore: 0, vtTotal: 70,
            ibmRisk: 0.1, ibmCategories: ['Technology', 'Legitimate'],
            whoisCreated: '1991-05-02',
            whoisRegistrar: 'MarkMonitor Inc.',
            whoisCountry: 'EUA',
            resolvedIp: '20.76.201.171',
            ssl: true,
            tags: ['Legítimo', 'Microsoft', 'Confiável'],
            summary: 'Domínio oficial da Microsoft Corporation registrado desde 1991. Amplamente verificado como legítimo em todas as bases de threat intelligence.',
        },
    },
    cves: {
        'CVE-2024-21887': {
            description: 'Vulnerabilidade de injeção de comando no Ivanti Connect Secure e Policy Secure que permite execução remota de código por atacante autenticado.',
            cvss: 9.1, severity: 'critical',
            vendors: ['Ivanti'],
            products: ['Connect Secure', 'Policy Secure'],
            publishedDate: '2024-01-10',
            exploitPublic: true,
            cisaKev: true,
            patch: 'Disponível — Patch ICS 22.x - Jan 2024',
            references: ['CVE-2024-21887 NVD', 'Ivanti Advisory Jan 2024'],
            summary: 'CVE crítico com exploit público disponível. Está no catálogo KEV da CISA (exploração ativa confirmada). Aplique o patch imediatamente. CVSSv3: 9.1 (Crítico).',
        },
    },
};
