// ─── Detalhes ricos das técnicas MITRE ATT&CK ─────────────────────────────────
// Cada entry pode ter:
//   fullDesc:          Descrição completa e contextualizada
//   investigationSteps: Passos para investigar quando a técnica é detectada
//   procedureExamples: Exemplos reais de grupos/malware que usaram a técnica
//   responseActions:  O que fazer para conter/remediar
//   huntingQueries:   Queries/comandos para threat hunting

export const techniqueDetails = {
    //─── T1566 — Phishing ────────────────────────────────────────────────────────
    T1566: {
        fullDesc: `Phishing é o vetor de ataque mais comum em incidentes de segurança. O atacante envia mensagens fraudulentas via e-mail, SMS ou plataformas de mensageria para enganar o usuário e fazê-lo: (1) clicar em link malicioso, (2) abrir anexo com malware, ou (3) fornecer credenciais em página falsa. A efetividade vem da engenharia social — o e-mail frequentemente imita comunicados de banco, TI interna, RH ou fornecedores conhecidos.`,
        investigationSteps: [
            { step: 1, title: 'Coletar e isolar o e-mail', desc: 'Obtenha o e-mail completo com headers. Não clique em nenhum link. Use "Mostrar original" no Gmail ou "Propriedades" no Outlook.' },
            { step: 2, title: 'Analisar headers (SPF/DKIM/DMARC)', desc: 'Use a ferramenta "Análise de E-mail Headers" desta plataforma. Verifique se SPF falhou, se o domínio do From ≠ Reply-To (spoofing) e o IP de origem.' },
            { step: 3, title: 'Verificar remetente e domínio', desc: 'Cheque o domínio do remetente no IOC Lookup (VirusTotal + IBM X-Force). Atenção a typosquatting: bradesco.com.br vs bradesc0.com.br.' },
            { step: 4, title: 'Analisar links', desc: 'Se houver URLs: expanda encurtadores (unshorten.me), verifique no VirusTotal URL scanner. Nunca acesse o link diretamente — use sandbox (any.run, urlscan.io).' },
            { step: 5, title: 'Analisar anexos', desc: 'Se houver arquivos: calcule o hash MD5/SHA256 (certutil -hashfile arquivo SHA256) e verifique no IOC Lookup. Envie para sandbox no Hybrid Analysis.' },
            { step: 6, title: 'Verificar impacto — quantos usuários receberam?', desc: 'Busque no gateway de e-mail (Microsoft 365 Defender, Mimecast, Proofpoint) por todos os recebimentos do mesmo remetente ou assunto nas últimas 24h.' },
            { step: 7, title: 'Verificar se algum usuário clicou/abriu', desc: 'Verifique logs de proxy web para acessos ao domínio malicioso. Verifique logs de sandbox corporativo. Se alguém clicou, escale para investigação de endpoint.' },
        ],
        procedureExamples: [
            { actor: 'APT29 (Cozy Bear)', desc: 'Campanha direcionada a organizações governamentais usando e-mails de spear phishing com anexos ZIP contendo LNK maliciosos que executavam payloads Cobalt Strike.' },
            { actor: 'Emotet / TA542', desc: 'Botnets enviawam e-mails em massa fingindo ser faturas, NFs e comunicados de bancos. Anexo era documento Word com macro (CVE-2017-11882). Era o dropper mais distribuído do mundo.' },
            { actor: 'FIN7', desc: 'Grupo de crime financeiro usava e-mails de "reclamações de clientes" com documentos Word maliciosos para comprometer redes de restaurantes e varejistas e roubar dados de cartão.' },
        ],
        responseActions: [
            'Marcar o e-mail como phishing no gateway e solicitar remoção em massa de todas as caixas de entrada',
            'Bloquear o domínio e IP do remetente no gateway de e-mail e no firewall/proxy',
            'Se usuário clicou em link: iniciar investigação de endpoint (ver T1204)',
            'Se usuário forneceu credenciais: resetar senha imediatamente e revogar sessões (ver T1078)',
            'Notificar outros usuários que possam ter recebido o mesmo e-mail',
            'Reportar o domínio phishing ao registrador e ao Google Safe Browsing',
        ],
        huntingQueries: [
            'Microsoft 365 Defender: DeviceNetworkEvents | where RemoteUrl contains "dominio-malicioso.com"',
            'Splunk: index=email sourcetype=mimecast sender_domain="dominio-malicioso.com"',
            'KQL (Sentinel): EmailEvents | where SenderMailFromDomain == "dominio.ru" | summarize count() by RecipientEmailAddress',
        ],
    },

    //─── T1059 — Command and Scripting Interpreter ───────────────────────────────
    T1059: {
        fullDesc: `Attackers abusam de interpreters de linha de comando e scripting (PowerShell, cmd.exe, bash, Python, WScript) para executar código malicioso. Essa técnica é chamada de "Living off the Land" (LotL) quando usa ferramentas nativas do SO, pois dificulta a detecção — o mesmo executável é usado por administradores legítimos. PowerShell é o mais abusado em ambientes Windows por sua integração com o SO e capacidade de baixar e executar código diretamente da memória.`,
        investigationSteps: [
            { step: 1, title: 'Capturar linha de comando completa', desc: 'Windows EventID 4688 (com Process Command Line habilitado em GPO) ou logs do Sysmon Event 1 mostram a linha de comando completa. Verifique o EDR para árvore de processos.' },
            { step: 2, title: 'Verificar processo pai', desc: 'PowerShell sendo lançado por winword.exe, excel.exe ou outlook.exe é red flag (macro maliciosa). PowerShell lançado por wscript.exe ou mshta.exe indica LOLBin abuse.' },
            { step: 3, title: 'Decodificar parâmetros ofuscados', desc: 'PowerShell com -EncodedCommand: copie o base64 e decodifique: [System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String("BASE64_AQUI")). Verifique PSDecode online.' },
            { step: 4, title: 'Verificar downloads na memória', desc: 'Padrão "IEX (New-Object Net.WebClient).DownloadString(\'url\')" indica download e execução em memória. Recupere a URL e verifique no IOC Lookup.' },
            { step: 5, title: 'Verificar conexões de rede do processo', desc: 'Netstat -anop ou EDR: qual IP o processo conectou? Verifique a reputação do IP no IOC Lookup.' },
            { step: 6, title: 'Extrair e verificar hash do processo', desc: 'Calcule hash do executável: Get-FileHash -Algorithm SHA256 powershell.exe. Um powershell.exe legítimo tem hash específico por versão — hash diferente indica manipulação.' },
        ],
        procedureExamples: [
            { actor: 'Cobalt Strike / Threat Actors', desc: 'Uso massivo de PowerShell com -EncodedCommand e IEX (Invoke-Expression) para baixar e executar shellcode diretamente na memória, evitando gravar arquivo em disco.' },
            { actor: 'Lazarus Group (APT38)', desc: 'Scripts PowerShell usados para reconhecimento interno, coleta de dados financeiros e movimentação lateral em ataques contra instituições bancárias.' },
            { actor: 'SocGholish / FakeUpdates', desc: 'Websites comprometidos entregavam "fake updates" que executavam arquivos JS via WScript.exe, que por sua vez lançavam PowerShell para baixar Cobalt Strike.' },
        ],
        responseActions: [
            'Isolar o endpoint imediatamente se dropper foi identificado',
            'Coletar dump de memória do processo para análise forense (ProcDump -ma PID)',
            'Verificar todos os processos filhos e conexões de rede abertas pelo processo suspeito',
            'Habilitar Script Block Logging e Module Logging do PowerShell se ainda não estiver ativo',
            'Revogar execução de scripts não assinados: Set-ExecutionPolicy AllSigned via GPO',
            'Considerar AppLocker ou WDAC para bloquear execução de scripts não autorizados',
        ],
        huntingQueries: [
            'Sysmon: EventID 1, Image contains powershell, CommandLine contains "-enc" OR "IEX" OR "DownloadString"',
            'Splunk: index=wineventlog EventCode=4688 New_Process_Name="*powershell*" Process_Command_Line="*-enc*"',
            'KQL: ProcessEvents | where FileName =~ "powershell.exe" | where ProcessCommandLine has_any ("-EncodedCommand", "IEX", "Invoke-Expression", "DownloadString")',
        ],
    },

    //─── T1078 — Valid Accounts ───────────────────────────────────────────────────
    T1078: {
        fullDesc: `O uso de credenciais legítimas é uma das técnicas de acesso inicial mais difíceis de detectar, pois o comportamento aparece como uso "normal" do sistema. As credenciais podem ter sido obtidas por phishing, vazamento de dados (Have I Been Pwned), compra no dark web, ou força bruta. Inclui contas locais, de domínio (AD), cloud (Azure AD, AWS IAM) e contas de serviço/sistema.`,
        investigationSteps: [
            { step: 1, title: 'Revisar histórico de logins da conta', desc: 'Azure AD Sign-in Logs / Active Directory EventID 4624 (logon) e 4625 (falha). Verifique: IP de origem, horário, localização geográfica, dispositivo usado e método de autenticação.' },
            { step: 2, title: 'Detectar Impossible Travel', desc: 'Login em São Paulo às 09:00 e login em Moscou às 09:15 é impossível fisicamente. Azure AD tem detecção nativa. Calcule distância e tempo entre logins consecutivos.' },
            { step: 3, title: 'Verificar IP dos logins', desc: 'Verifique os IPs de origem no IOC Lookup (AbuseIPDB + IBM X-Force). IPs de VPN comercial, Tor ou DCs desconhecidos são suspeitos.' },
            { step: 4, title: 'Auditar ações recentes da conta', desc: 'Quais arquivos foram acessados, movidos, deletados? Quais sistemas foram acessados via RDP/SSH? Foram criados novos usuários ou alteradas permissões? Logs de auditoria do AD (EventID 4720, 4728, 4732).' },
            { step: 5, title: 'Verificar MFA bypass', desc: 'Atacantes usam "MFA Fatigue" (bombardear com push até o usuário aceitar) ou roubam tokens de sessão (bypass MFA). Verifique se há aprovações de MFA anômalas nos logs de autenticação.' },
            { step: 6, title: 'Verificar se há persistência instalada', desc: 'A conta comprometida pode ter sido usada para instalar backdoors. Verifique tarefas agendadas criadas, serviços instalados, chaves de registro Run e contas adicionais criadas.' },
        ],
        procedureExamples: [
            { actor: 'LAPSUS$ Group', desc: 'Comprou credenciais de funcionários e prestadores de serviço no dark web e usou acesso legítimo ao VPN/SSO para comprometer Nvidia, Samsung, Microsoft e Okta em 2022.' },
            { actor: 'APT29 / Midnight Blizzard', desc: 'Comprometeu contas da Microsoft em jan/2024 via password spraying em conta de teste sem MFA, acessando e-mails de líderes executivos.' },
            { actor: 'SolarWinds (Nobelium)', desc: 'Após comprometer o build do SolarWinds Orion, usou tokens SAML forjados para acessar e-mails e serviços cloud de vítimas sem precisar de senha.' },
        ],
        responseActions: [
            'Revogar TODAS as sessões ativas da conta imediatamente (Azure: Revogar tokens / AD: Forçar kerberos ticket reset)',
            'Resetar a senha da conta e de qualquer conta que ela possa ter acessado',
            'Re-enrolar e reforçar MFA (desabilitar opções mais fracas como SMS se possível)',
            'Verificar e revogar regras de encaminhamento de e-mail criadas pela conta comprometida',
            'Auditar permissões — a conta ganhou novos grupos ou roles?',
            'Investigar todos os sistemas acessados pela conta nas últimas 72 horas',
        ],
        huntingQueries: [
            'KQL (Azure): SigninLogs | where ResultType == 0 | summarize locations=make_set(Location) by UserPrincipalName | where array_length(locations) > 2',
            'Splunk: index=azure sourcetype=azure:aad:signin ResultDescription="Success" | stats dc(location_city) as cities by user | where cities > 2',
            'EventID 4624 | filter Source_IP not in whitelist | correlate with 4625 failures on same account',
        ],
    },

    //─── T1003 — OS Credential Dumping ───────────────────────────────────────────
    T1003: {
        fullDesc: `Credential Dumping é a extração de senhas, hashes NTLM e tickets Kerberos diretamente do sistema operacional. A ferramenta mais conhecida é o Mimikatz, que pode ler credenciais diretamente do processo LSASS (Local Security Authority Subsystem Service). Hashes NTLM podem ser usados em ataques Pass-the-Hash sem precisar conhecer a senha em texto claro. Tickets Kerberos podem ser usados em Pass-the-Ticket ou Golden/Silver Ticket.`,
        investigationSteps: [
            { step: 1, title: 'Verificar acesso ao processo LSASS', desc: 'EventID 4656 (acesso a objeto) no Security log, com Object Name "\\Device\\HarddiskVolume...\\lsass.exe" e AccessMask 0x1FFFFF ou 0x1010. Também Sysmon EventID 10 (Process Access) com TargetImage contendo lsass.' },
            { step: 2, title: 'Verificar criação de dump do LSASS', desc: 'Ferramentas como Task Manager, ProcDump ou comsvcs.dll criam lsass.dmp. Sysmon EventID 11 (FileCreate) para arquivos .dmp. Também: "C:\\Windows\\Temp\\lsass.dmp" ou variações.' },
            { step: 3, title: 'Identificar o processo que fez o acesso', desc: 'Qual processo acessou o LSASS? powershell.exe, cmd.exe, rundll32.exe são suspeitos. Processos com SeDebugPrivilege habilitado merecem investigação.' },
            { step: 4, title: 'Verificar comandos DCSync', desc: 'DCSync: EventID 4662 com "DS-Replication-Get-Changes" e "DS-Replication-Get-Changes-All". Indica que conta perguntou replicação do AD — padrão do Mimikatz dcsync.' },
            { step: 5, title: 'Verificar acesso à chave SAM no registro', desc: 'reg save HKLM\\SAM dump_sam.hiv — EventID 4656 para chave SAM. Permite dump de hashes de contas locais.' },
            { step: 6, title: 'Verificar uso dos hashes coletados', desc: 'Após credential dumping, o atacante usa os hashes. Monitore EventID 4624 com LogonType 3 (rede) para logins NTLM em múltiplos hosts em curto espaço de tempo a partir do mesmo host comprometido.' },
        ],
        procedureExamples: [
            { actor: 'Mimikatz (genérico)', desc: 'Comando: sekurlsa::logonpasswords — extrai hashes e senhas em texto claro de todos os usuários com sessão ativa no LSASS. Requer privilégios de SYSTEM ou SeDebugPrivilege.' },
            { actor: 'Conti Ransomware', desc: 'Usava Mimikatz e outros dumpers para obter credenciais de Domain Admin rapidamente após acesso inicial, viabilizando disseminação do ransomware em toda a rede em minutos.' },
            { actor: 'APT41', desc: 'Usou a técnica DCSync para extrair credenciais do AD de forma silenciosa sem precisar acessar diretamente o LSASS dos DCs, apenas simulando um controlador de domínio.' },
        ],
        responseActions: [
            'Isolar o host comprometido IMEDIATAMENTE — hashes coletados podem ser usados em lateral movement em segundos',
            'Assumir que TODAS as credenciais logadas naquele host estão comprometidas — resetar senhas',
            'Se houve DCSync: todas as senhas do domínio devem ser tratadas como comprometidas — planejar rotação em massa',
            'Habilitar Credential Guard (Windows 10+) para proteger o LSASS com virtualização',
            'Considerar habilitar RunAsPPL para o LSASS: HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa: RunAsPPL = 1',
            'Implementar LAPS (Local Administrator Password Solution) para randomizar senhas locais',
        ],
        huntingQueries: [
            'Sysmon EventID 10: TargetImage LIKE "%lsass%" AND GrantedAccess IN (0x1010, 0x1FFFFF, 0x143A)',
            'KQL: SecurityEvent | where EventID == 4656 | where ObjectName contains "lsass"',
            'KQL (DCSync): SecurityEvent | where EventID == 4662 | where Properties contains "Replicating Directory Changes"',
        ],
    },

    //─── T1110 — Brute Force ─────────────────────────────────────────────────────
    T1110: {
        fullDesc: `Ataques de força bruta tentam adivinhar credenciais de forma sistemática. Password Spraying é a variante mais perigosa: em vez de tentar muitas senhas para uma conta (que causaria lockout), tenta uma senha comum (ex: Verão@2024!) para centenas de contas — evitando bloqueio. Credential Stuffing usa listas de credenciais vazadas de outros serviços (reutilização de senha). São frequentemente direcionados a serviços expostos: VPN, RDP, OWA, Microsoft 365.`,
        investigationSteps: [
            { step: 1, title: 'Identificar padrão do ataque', desc: 'Força bruta: muitas falhas (4625) para uma conta. Password Spraying: poucas falhas para muitas contas diferentes, em intervalos regulares (~30min para evitar lockout). Credential Stuffing: fonte com lista variada.' },
            { step: 2, title: 'Identificar o IP de origem', desc: 'Verifique o IP no IOC Lookup (AbuseIPDB). Se for IP de VPN/proxy/Tor ou de país fora do padrão da org, bloqueie no firewall/gateway imediatamente.' },
            { step: 3, title: 'Verificar se alguma autenticação teve sucesso', desc: 'Após as falhas, houve um EventID 4624 (sucesso)? Para quais contas? Investigue as sessões abertas por essas contas imediatamente.' },
            { step: 4, title: 'Mapear contas visadas', desc: 'Quais contas foram alvo? Contas privilegiadas (admin, service accounts) são alvo prioritário. Contas sem MFA são vulneráveis a esses ataques.' },
            { step: 5, title: 'Verificar se há enumeração de usuários', desc: 'LDAP queries com filtros para enumerar contas (EventID 4661) podem preceder o brute force. Quem fez a enumeração?' },
        ],
        procedureExamples: [
            { actor: 'APT29 / Midnight Blizzard', desc: 'Realizou password spraying em conta de teste Microsoft sem MFA, obtendo acesso ao tenant em jan/2024. Usou senhas simples em larga escala para não disparar alertas.' },
            { actor: 'Grupos de eCrime (genérico)', desc: 'Credential stuffing massivo contra serviços de streaming, bancos e e-commerce usando listas de bilhões de credenciais vazadas. Taxa de sucesso de 1-2% já é lucrativa em escala.' },
        ],
        responseActions: [
            'Bloquear IP de origem no firewall/WAF imediatamente se ainda em andamento',
            'Verificar e remediar qualquer autenticação bem-sucedida (reset de senha, revogação de sessão)',
            'Habilitar MFA para TODAS as contas, especialmente as expostas à internet',
            'Implementar CAPTCHA ou rate limiting nos serviços de autenticação',
            'Configurar política de lockout inteligente (lockout após N falhas em X minutos)',
            'Usar Azure AD Identity Protection ou Okta ThreatInsight para bloqueio automático de IPs suspeitos',
        ],
        huntingQueries: [
            'KQL: SecurityEvent | where EventID == 4625 | summarize Falhas=count() by IpAddress, TargetUserName | where Falhas > 10',
            'Password Spray KQL: SecurityEvent | where EventID == 4625 | summarize Contas=dcount(TargetUserName) by IpAddress | where Contas > 20',
            'Splunk: index=wineventlog EventCode=4625 | stats count by Source_Network_Address | where count > 50',
        ],
    },

    //─── T1486 — Data Encrypted for Impact (Ransomware) ─────────────────────────
    T1486: {
        fullDesc: `Ransomware é o uso de criptografia para tornar dados inacessíveis e extorquir resgate. Operações modernas de ransomware usam modelo "dupla extorsão": além de criptografar, exfiltram dados e ameaçam publicá-los se o resgate não for pago. Grupos como LockBit, Cl0p, BlackCat/ALPHV e RansomHub são exemplos ativos. O impacto pode ser catastrófico para organizações sem backups adequados, chegando a causar falência ou interrupção de serviços críticos por semanas.`,
        investigationSteps: [
            { step: 1, title: '⚡ IMEDIATO: Isolar o sistema da rede', desc: 'Execute imediatamente: desconectar o cabo de rede, desabilitar Wi-Fi e Bluetooth. Se possível, usar a função de isolamento do EDR. NÃO desligue o computador — a memória pode conter a chave de criptografia.' },
            { step: 2, title: '⚡ IMEDIATO: Identificar e isolar outros sistemas afetados', desc: 'O ransomware provavelmente se espalhou. Identificar outros hosts com modificações em massa de arquivos. Isolar segmentos de rede afetados via VLAN ou ACLs.' },
            { step: 3, title: 'Identificar a variante do ransomware', desc: 'Acesse nomoreransom.org/crypto-sheriff.aspx com amostras dos arquivos criptografados e a nota de resgate. Pode indicar ferramentas específicas de decriptação disponíveis.' },
            { step: 4, title: 'Preservar evidências forenses', desc: 'Capture imagem da memória RAM (DumpIt, WinPmem) antes de desligar. Tirar snapshot de VM se aplicável. Não execute nenhuma ferramenta de limpeza antes de forense completo.' },
            { step: 5, title: 'Determinar vetor de entrada', desc: 'Como o ransomware entrou? Phishing, RDP exposto, VPN comprometida? Windows logs (EventID 4624, 4625, 4688), proxy logs, e-mail gateway. Isso é crítico para evitar reinfecção.' },
            { step: 6, title: 'Verificar backups', desc: 'Existem backups offline/out-of-band não afetados? NUNCA restaure sem primeiro garantir que o ambiente está limpo. Vssadmin list shadows no host pode mostrar se shadow copies foram deletadas.' },
        ],
        procedureExamples: [
            { actor: 'LockBit 3.0', desc: 'Um dos grupos mais ativos. Modelo RaaS (Ransomware-as-a-Service). Usa credential stuffing e exploração de VPN para acesso inicial, Cobalt Strike para C2, e criptografia rápida (pode criptografar 50GB em minutos).' },
            { actor: 'Cl0p / TA505', desc: 'Responsável por ataques massivos via exploração de vulnerabilidade zero-day no GoAnywhere MFT (2023) e MOVEit Transfer (2023), afetando centenas de organizações com exfiltração antes da criptografia.' },
            { actor: 'RansomHub', desc: 'Grupo emergente (2024) com afiliados de alto nível. Atacou infraestrutura crítica incluindo hospitais. Usa double extorsion e publica dados no site .onion em 90 dias se não pago.' },
        ],
        responseActions: [
            'NÃO PAGUE o resgate sem consultar especialistas jurídicos e autoridades — pagamento não garante decriptação e pode violar sanções',
            'Contate CERT nacional (CISA nos EUA, CERT.br no Brasil) e autoridades policiais (Polícia Federal)',
            'Ativar plano de continuidade de negócios — quais serviços/processos podem funcionar manualmente?',
            'Verificar nomoreransom.org — alguns ransomwares têm decriptadores gratuitos disponíveis',
            'Restaurar apenas de backups offline verificados, após completa limpeza do ambiente',
            'Após recuperação: implementar segmentação de rede, MFA, backup 3-2-1 e EDR em todos os endpoints',
        ],
        huntingQueries: [
            'Sysmon EventID 11: FileCreate com extensões desconhecidas em massa (> 100 arquivos/min por processo)',
            'KQL: DeviceFileEvents | where FileName endswith ".locked" or FileName endswith ".enc" or FileName == "README_DECRYPT.txt"',
            'Sysmon/EDR: vssadmin.exe com argumento "delete shadows" — indica destruição de backups antes de criptografar',
        ],
    },

    //─── T1190 — Exploit Public-Facing Application ───────────────────────────────
    T1190: {
        fullDesc: `Exploração de vulnerabilidades em aplicações web, APIs, VPNs ou serviços de e-mail expostos à internet. Inclui SQL Injection, Remote Code Execution (RCE), deserialização insegura e buffer overflow. CVEs como Log4Shell (CVE-2021-44228), ProxyLogon (Exchange) e Citrix Bleed têm sido massivamente explorados. Atacantes varreram a internet em horas após publicação de PoCs públicos.`,
        investigationSteps: [
            { step: 1, title: 'Identificar a vulnerabilidade explorada', desc: 'Analise logs do WAF, servidor web e IDS/IPS por padrões de exploit (payloads, user-agents incomuns). Systems como Shodan podem mostrar se sua infra estava exposta.' },
            { step: 2, title: 'Verificar se houve execução de código', desc: 'Após exploração bem-sucedida, geralmente há execução de comandos ou download de ferramentas. Verifique processos filhos do processo web (tomcat, w3wp.exe, nginx): qualquer shell ou powershell é red flag.' },
            { step: 3, title: 'Verificar instalação de web shell', desc: 'Arquivos .jsp, .php, .aspx criados em diretórios web após a exploração são web shells. Faça hash de todos os arquivos web e compare com baseline ou verifique no VirusTotal.' },
            { step: 4, title: 'Avaliar dados acessados', desc: 'O exploit deu acesso a quais dados? Banco de dados, arquivos de configuração com credenciais, diretórios de upload? Avalie o impacto de privacidade e cumprimento regulatório (LGPD).' },
            { step: 5, title: 'Aplicar o patch imediatamente', desc: 'Identifique a versão vulnerável e o CVE. Aplique o patch do fornecedor ou, se não disponível, aplique workaround temporário (desabilitar o recurso vulnerável, bloquear no WAF).' },
        ],
        procedureExamples: [
            { actor: 'Log4Shell (CVE-2021-44228)', desc: 'Vulnerabilidade no Apache Log4j 2 permitia RCE via JNDI lookup em strings de log. Atacantes enviavam payloads em user-agents, usernames, qualquer campo logado. Afetou milhares de produtos.' },
            { actor: 'ProxyLogon (Exchange)', desc: 'Chain de 4 CVEs (CVE-2021-26855, etc.) permitia RCE sem autenticação no Exchange Server. Grupos como HAFNIUM instalaram web shells em minutos após a publicação do PoC.' },
        ],
        responseActions: [
            'Isolar o sistema comprometido da rede interna imediatamanete',
            'Aplicar patch do fornecedor ou workaround de emergência (WAF rule, desabilitar funcionalidade)',
            'Realizar varredura de web shells em todos os diretórios da aplicação',
            'Revogar credenciais que possam ter sido expostas na aplicação',
            'Contratar forensics se houver suspeita de exfiltração de dados (obrigação LGPD em 72h)',
        ],
        huntingQueries: [
            'Log4Shell: grep -r "${jndi:" /var/log/ (ou buscar em logs de aplicação)',
            'Web shell: find /var/www -name "*.php" -newer /var/www/index.php -exec ls -la {} \\;',
            'KQL: DeviceProcessEvents | where InitiatingProcessFileName =~ "w3wp.exe" | where FileName in~ ("cmd.exe", "powershell.exe", "wscript.exe")',
        ],
    },

    //─── T1021 — Remote Services ─────────────────────────────────────────────────
    T1021: {
        fullDesc: `Uso de serviços remotos legítimos (RDP, SSH, SMB, WinRM, VNC) com credenciais válidas para movimento lateral — acesso de um sistema comprometido para outros sistemas na mesma rede. Por usar protocolos legítimos com credenciais válidas, é difícil de detectar sem contexto comportamental. RDP é o mais visual (sessão gráfica). SMB Admin Shares (ADMIN$, C$, IPC$) permitem execução remota de comandos. WinRM/PowerShell remoto é muito usado por ferramentas como Cobalt Strike.`,
        investigationSteps: [
            { step: 1, title: 'Mapear de quais hosts as conexões partiram', desc: 'EventID 4624 com LogonType 10 (RemoteInteractive = RDP) ou LogonType 3 (Network). Source IP deve ser investigado: é um host legítimo? Faz sentido esse host acessar esse servidor?' },
            { step: 2, title: 'Verificar timeline de lateral movement', desc: 'Correlacione logins remotos em múltiplos hosts em curto espaço de tempo. "Patient zero" → Host A → Host B → DC é padrão clássico de escalada para Domain Controller.' },
            { step: 3, title: 'Verificar credenciais usadas', desc: 'Que conta foi usada? Se foi conta local de administrador com a mesma senha em vários hosts (sem LAPS), o atacante usou pass-the-hash ou same password. Se foi conta de domínio comprometida, revogar.' },
            { step: 4, title: 'Verificar o que foi executado nas sessões remotas', desc: 'EventID 4688 no host de destino durante a sessão. O que o atacante fez? Instalou serviço? Criou conta? Executou scripts? Alterou arquivos?' },
            { step: 5, title: 'Verificar se ferramentas foram transferidas', desc: 'SMB/Admin shares podem ter sido usadas para copiar ferramentas (Cobalt Strike, Mimikatz). Verificar criação de arquivos suspeitos em C$\\Windows\\Temp no host de destino.' },
        ],
        procedureExamples: [
            { actor: 'Cobalt Strike / Threat Actors', desc: 'Usa WinRM (PowerShell remoto) e SMB para movimento lateral a partir de beacons. O "Jump psexec" do Cobalt Strike copia um serviço para o ADMIN$ e o executa remotamente.' },
            { actor: 'RDP como vetor primário', desc: 'Grupos de ransomware compram acesso RDP exposto à internet em fóruns de crime. Após acesso, usam o mesmo RDP para moverem lateralmente para servidores de backup e domínio.' },
        ],
        responseActions: [
            'Desabilitar RDP/SMB desnecessário via GPO (especialmente de workstations para workstations)',
            'Implementar LAPS — senhas únicas para cada máquina eliminam pass-the-hash lateral',
            'Segmentar a rede: workstations não devem acessar diretamente servidores sem proxy/jump host',
            'Habilitar Windows Defender Credential Guard para mitigar pass-the-hash',
            'Auditar grupos "Administradores locais" regularmente — princípio do mínimo privilégio',
        ],
        huntingQueries: [
            'KQL: SecurityEvent | where EventID == 4624 | where LogonType == 10 | summarize count() by SourceIP, DestinationHost | where count > 5',
            'Lateral movement: correlacionar EventID 4624 LogonType 3 em múltiplos hosts dentro de 1 hora',
            'Sysmon: EventID 3 (Network Connect) de processos de admin (cmd, powershell) para porta 445 (SMB) ou 3389 (RDP)',
        ],
    },

    //─── T1562 — Impair Defenses ─────────────────────────────────────────────────
    T1562: {
        fullDesc: `Atacantes desabilitam ou modificam ferramentas de segurança (antivírus, EDR, firewall, event logging) para operar sem detecção. É frequentemente um dos primeiros passos após acesso inicial e antes de ações de impacto. Ferramentas modernas de EDR detectam tentativas de desabilitar proteções em tempo real, mas atacantes com privilégios SYSTEM podem contornar isso através de drivers maliciosos (BYOVD — Bring Your Own Vulnerable Driver).`,
        investigationSteps: [
            { step: 1, title: 'Verificar gaps nos logs de segurança', desc: 'Se os logs do Windows têm um período sem eventos (especialmente EventID 4688), o logging pode ter sido desabilitado. EventID 1102 indica que o log foi limpo. Correlacione com SIEM.' },
            { step: 2, title: 'Verificar status de serviços de segurança', desc: 'EventID 7036 (serviço parou) ou 7045 (novo serviço instalado) para serviços de AV/EDR. Verificar Get-Service | Where-Object {$_.Status -eq "Stopped"} para serviços de segurança.' },
            { step: 3, title: 'Verificar modificações de firewall', desc: 'EventID 4950 (regra de firewall removida) e 4951 (regra modificada). Também: netsh advfirewall show currentprofile — está ativado? Tem regras inbound suspeitas?' },
            { step: 4, title: 'Verificar carregamento de drivers suspeitos (BYOVD)', desc: 'EventID 6 (Sysmon — Driver loaded) ou EventID 6422/6423. Drivers como mhyprot2.sys, gdrv.sys (do anticheat de jogos) foram usados para desabilitar EDRs.' },
            { step: 5, title: 'Verificar modificações de registro de AV', desc: 'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender — DisableAntiSpyware = 1 indica que Defender foi desabilitado via política. Também: Get-MpComputerStatus | select AMServiceEnabled.' },
        ],
        procedureExamples: [
            { actor: 'BlackCat/ALPHV Ransomware', desc: 'Usou o driver gdrv.sys (driver vulnerável do GIGABYTE) para encerrar processos de EDR com privilégios de kernel, contornando proteções que normalmente detectariam o ransomware.' },
            { actor: 'Babuk / Clop', desc: 'Scripts de batch que percorriam lista de serviços de segurança conhecidos (Sophos, Kaspersky, MalwareBytes, etc.) e os encerravam via net stop e sc delete antes de criptografar.' },
        ],
        responseActions: [
            'Verificar e restaurar serviços de segurança desabilitados imediatamente',
            'Se BYOVD: o driver vulnerável deve ser bloqueado via hash (Microsoft HVCI/WDAC)',
            'Verificar integridade dos logs — se houve gap, assumir que atividade maliciosa ocorreu no período',
            'Proteger serviços de segurança contra encerramento: tamper protection do Defender, PPL (Protected Process Light)',
            'Centralizar logs em SIEM imutável (não depender apenas de logs locais que podem ser apagados)',
        ],
        huntingQueries: [
            'KQL: SecurityEvent | where EventID == 7036 | where Message contains_any ("Windows Defender", "Antivirus", "CrowdStrike")',
            'EventID 1102 (Security Log Cleared): deve gerar alerta imediato em qualquer SIEM',
            'Sysmon EventID 6: ImageLoaded WHERE NOT SIS (Signed) AND Signer NOT IN "Microsoft, WHQL approved"',
        ],
    },

    //─── T1071 — Application Layer Protocol (C2) ─────────────────────────────────
    T1071: {
        fullDesc: `Uso de protocolos de rede legítimos (HTTP/HTTPS, DNS, SMTP) para comunicação de Comando e Controle (C2), misturando tráfego malicioso com tráfego legítimo. Por usar protocolos permitidos e frequentemente HTTPS (que encripta o payload), é difícil de bloquear sem inspeção de SSL. Beaconing é o padrão: o agente malicioso faz check-ins periódicos ao servidor C2 para receber comandos.`,
        investigationSteps: [
            { step: 1, title: 'Identificar padrões de beaconing', desc: 'Beaconing é comunicação periódica regular. Procure por conexões que ocorrem a cada X segundos/minutos para o mesmo IP externo. Ferramentas: Zeek network logs, Rita (Real Intelligence Threat Analytics).' },
            { step: 2, title: 'Verificar o IP/domínio de destino', desc: 'Verifique o IP/domínio no IOC Lookup (VirusTotal + IBM X-Force + AbuseIPDB). IPs de datacenter em países incomuns, domínios gerados algoritmicamente (DGA) ou recém-registrados são suspeitos.' },
            { step: 3, title: 'Analisar JA3/JA3S fingerprint (HTTPS)', desc: 'O JA3 fingerprint do TLS handshake identifica o cliente TLS. Cobalt Strike e outros C2s têm JA3 conhecidos. Ferramentas de NDR/IDS como Suricata, Zeek e Darktrace fazem essa análise.' },
            { step: 4, title: 'Verificar DNS tunelado', desc: 'DNS C2 usa queries DNS anormalmente longas ou frequentes para subdomínios de um domínio controlado pelo atacante. Analise volume de queries DNS por domínio — mais de 100 queries para um domínio desconhecido é suspeito.' },
            { step: 5, title: 'Identificar o processo fazendo a conexão', desc: 'Sysmon EventID 3 (Network Connect): qual processo está fazendo as conexões periódicas? svchost.exe fazendo beaconing pode ser serviço malicioso. Proceso inesperado conectando a internet deve ser investigado.' },
        ],
        procedureExamples: [
            { actor: 'Cobalt Strike', desc: 'Framework de C2 mais usado por grupos de crime e APTs. Suporta HTTP/HTTPS, DNS e SMB listeners. "Malleable C2 profiles" permitem que o tráfego imite Amazon, Google, Microsoft.' },
            { actor: 'APT29 / WellMess', desc: 'Malware que usava HTTPS com certificados Let\'s Encrypt legítimos para se misturar ao tráfego HTTPS normal. Alvejou institutos de pesquisa de vacinas COVID-19 em 2020.' },
        ],
        responseActions: [
            'Bloquear o IP/domínio do C2 no firewall e no proxy corporativo imediatamente',
            'Isolar o host afetado que está fazendo beaconing',
            'Implementar inspeção de SSL/TLS no proxy para identificar C2 sobre HTTPS (requer implantacão de CA corporativa)',
            'Configurar RPZ (Response Policy Zone) no DNS para bloquear domínios maliciosos automaticamente',
            'Implementar solução de NDR (Network Detection and Response) para detecção automática de beaconing',
        ],
        huntingQueries: [
            'Rita (FOSS): beacon detection baseado em frequência e tamanho de pacotes',
            'KQL: DeviceNetworkEvents | summarize count() by RemoteIP, DeviceName | where count > 100 and count < 500 (beaconing típico)',
            'DNS: index=dns | stats count by query | where count > 50 AND NOT query matches known_domains',
        ],
    },
};

// Retorna detalhes de uma técnica pelo ID
export function getTechniqueDetails(id) {
    // Tenta pelo ID completo primeiro (T1059.001), depois pela base (T1059)
    return techniqueDetails[id] || techniqueDetails[id.split('.')[0]] || null;
}
