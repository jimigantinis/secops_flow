import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Search, Globe, Hash, Mail, Map, Bot, ExternalLink, ArrowRight, Shield, Zap } from 'lucide-react';

const quickTools = [
    { path: '/lookup', icon: Search, label: 'IOC Lookup', desc: 'IP, Hash, Domínio, URL, CVE', color: '#06b6d4', gradient: 'linear-gradient(135deg, rgba(6,182,212,0.12), rgba(59,130,246,0.08))' },
    { path: '/email-header', icon: Mail, label: 'Análise de E-mail', desc: 'SPF · DKIM · DMARC · Spoofing', color: '#f97316', gradient: 'linear-gradient(135deg, rgba(249,115,22,0.12), rgba(234,179,8,0.08))' },
    { path: '/mitre', icon: Map, label: 'MITRE ATT&CK', desc: 'Táticas · Técnicas · Mitigações', color: '#a78bfa', gradient: 'linear-gradient(135deg, rgba(167,139,250,0.12), rgba(99,102,241,0.08))' },
    { path: '/consultor', icon: Bot, label: 'AI Consultor', desc: 'Descreva o incidente, receba orientação', color: '#22c55e', gradient: 'linear-gradient(135deg, rgba(34,197,94,0.12), rgba(16,185,129,0.08))' },
];

const externalTools = [
    { name: 'VirusTotal', url: 'https://www.virustotal.com/gui/home/search', desc: 'Arquivos, URLs, IPs, domínios', color: '#3b82f6' },
    { name: 'AbuseIPDB', url: 'https://www.abuseipdb.com/', desc: 'Reputação e reportes de IPs', color: '#ef4444' },
    { name: 'IBM X-Force', url: 'https://exchange.xforce.ibmcloud.com/', desc: 'Threat Intelligence global', color: '#06b6d4' },
    { name: 'Hybrid Analysis', url: 'https://www.hybrid-analysis.com/', desc: 'Sandbox de análise de malware', color: '#f97316' },
    { name: 'MXToolbox', url: 'https://mxtoolbox.com/EmailHeaders.aspx', desc: 'Análise de e-mail headers', color: '#22c55e' },
    { name: 'URLScan.io', url: 'https://urlscan.io/', desc: 'Scanner de URLs e domínios', color: '#eab308' },
    { name: 'Shodan', url: 'https://www.shodan.io/', desc: 'Busca de dispositivos expostos', color: '#a78bfa' },
    { name: 'NIST NVD', url: 'https://nvd.nist.gov/vuln/search', desc: 'Base de CVEs e vulnerabilidades', color: '#94a3b8' },
];

function detectType(value) {
    const v = value.trim();
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(v)) return 'ip';
    if (/^[a-f0-9]{32}$/i.test(v)) return 'hash-md5';
    if (/^[a-f0-9]{40}$/i.test(v)) return 'hash-sha1';
    if (/^[a-f0-9]{64}$/i.test(v)) return 'hash-sha256';
    if (/^CVE-\d{4}-\d{4,}$/i.test(v)) return 'cve';
    if (/^https?:\/\//i.test(v)) return 'url';
    if (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(v)) return 'domain';
    return 'unknown';
}

const typeLabel = { ip: '🌐 Endereço IP', 'hash-md5': '# Hash MD5', 'hash-sha1': '# Hash SHA1', 'hash-sha256': '# Hash SHA256', cve: '⚠️ CVE', url: '🔗 URL', domain: '🌍 Domínio', unknown: '❓ Desconhecido' };

export default function Home() {
    const [query, setQuery] = useState('');
    const [detectedType, setDetectedType] = useState(null);
    const navigate = useNavigate();

    const handleInput = (e) => {
        const v = e.target.value;
        setQuery(v);
        if (v.trim().length > 4) setDetectedType(detectType(v));
        else setDetectedType(null);
    };

    const handleSearch = (e) => {
        e.preventDefault();
        if (query.trim()) navigate(`/lookup?q=${encodeURIComponent(query.trim())}`);
    };

    return (
        <div className="animate-fade-in">
            {/* Hero */}
            <div style={{ textAlign: 'center', padding: '32px 0 40px' }}>
                <div style={{ display: 'flex', justifyContent: 'center', marginBottom: 16 }}>
                    <div style={{ width: 56, height: 56, borderRadius: 16, background: 'linear-gradient(135deg, #06b6d4, #3b82f6)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                        <Shield size={28} color="white" />
                    </div>
                </div>
                <h1 style={{ fontSize: 28, fontWeight: 900, letterSpacing: -0.8, color: '#f8fafc', marginBottom: 8 }}>
                    SecOps <span className="gradient-text">Flow</span>
                </h1>
                <p style={{ fontSize: 14, color: '#64748b', maxWidth: 480, margin: '0 auto' }}>
                    Plataforma unificada de análise para analistas de segurança. Verifique IoCs, analise e-mails suspeitos, explore MITRE ATT&CK e consulte a IA — tudo em um lugar.
                </p>

                {/* Search bar */}
                <form onSubmit={handleSearch} style={{ maxWidth: 580, margin: '28px auto 0', position: 'relative' }}>
                    <div style={{ position: 'relative' }}>
                        <Search size={18} style={{ position: 'absolute', left: 16, top: '50%', transform: 'translateY(-50%)', color: '#64748b', zIndex: 2 }} />
                        <input
                            style={{
                                width: '100%', padding: '14px 120px 14px 48px',
                                background: '#1e293b', border: '1px solid rgba(255,255,255,0.1)',
                                borderRadius: 12, color: '#f8fafc', fontSize: 15,
                                outline: 'none', transition: 'all 0.2s',
                                boxShadow: '0 4px 24px rgba(0,0,0,0.2)',
                            }}
                            onFocus={e => { e.target.style.borderColor = 'rgba(6,182,212,0.5)'; e.target.style.boxShadow = '0 0 0 3px rgba(6,182,212,0.1), 0 4px 24px rgba(0,0,0,0.2)'; }}
                            onBlur={e => { e.target.style.borderColor = 'rgba(255,255,255,0.1)'; e.target.style.boxShadow = '0 4px 24px rgba(0,0,0,0.2)'; }}
                            placeholder="Digite um IP, hash MD5/SHA, domínio, URL ou CVE..."
                            value={query}
                            onChange={handleInput}
                        />
                        <button type="submit" className="btn-primary" style={{ position: 'absolute', right: 8, top: '50%', transform: 'translateY(-50%)', padding: '8px 16px' }}>
                            Analisar <ArrowRight size={14} />
                        </button>
                    </div>
                    {/* Type detection hint */}
                    {detectedType && (
                        <div style={{ marginTop: 8, textAlign: 'left', paddingLeft: 4 }}>
                            <span style={{ fontSize: 12, color: '#06b6d4' }}>
                                <Zap size={11} style={{ display: 'inline', marginRight: 4 }} />
                                Detectado: <strong>{typeLabel[detectedType]}</strong> — será analisado no IOC Lookup
                            </span>
                        </div>
                    )}
                </form>

                {/* Example quick searches */}
                <div style={{ display: 'flex', gap: 8, justifyContent: 'center', marginTop: 14, flexWrap: 'wrap' }}>
                    <span style={{ fontSize: 12, color: '#475569' }}>Exemplos:</span>
                    {['185.220.101.47', '44d88612fea8a8f36de82e1278abb02f', 'bradesc0-online.ru', 'CVE-2024-21887'].map(ex => (
                        <button key={ex} onClick={() => { setQuery(ex); setDetectedType(detectType(ex)); }}
                            style={{ fontSize: 11, fontFamily: "'Fira Code', monospace", background: 'rgba(255,255,255,0.04)', color: '#94a3b8', border: '1px solid rgba(255,255,255,0.07)', borderRadius: 6, padding: '3px 10px', cursor: 'pointer', transition: 'all 0.15s' }}
                            onMouseEnter={e => e.target.style.color = '#06b6d4'}
                            onMouseLeave={e => e.target.style.color = '#94a3b8'}
                        >{ex}</button>
                    ))}
                </div>
            </div>

            {/* Main tools */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 14, marginBottom: 28 }}>
                {quickTools.map(({ path, icon: Icon, label, desc, color, gradient }) => (
                    <button key={path} onClick={() => navigate(path)}
                        style={{
                            background: gradient, border: `1px solid ${color}25`,
                            borderRadius: 14, padding: '20px 18px', cursor: 'pointer',
                            textAlign: 'left', transition: 'all 0.2s', color: 'inherit'
                        }}
                        onMouseEnter={e => { e.currentTarget.style.transform = 'translateY(-2px)'; e.currentTarget.style.boxShadow = `0 8px 24px ${color}20`; e.currentTarget.style.borderColor = `${color}50`; }}
                        onMouseLeave={e => { e.currentTarget.style.transform = 'translateY(0)'; e.currentTarget.style.boxShadow = 'none'; e.currentTarget.style.borderColor = `${color}25`; }}
                    >
                        <div style={{ width: 40, height: 40, borderRadius: 10, background: `${color}18`, display: 'flex', alignItems: 'center', justifyContent: 'center', marginBottom: 14 }}>
                            <Icon size={20} color={color} />
                        </div>
                        <div style={{ fontSize: 14, fontWeight: 700, color: '#f8fafc', marginBottom: 4 }}>{label}</div>
                        <div style={{ fontSize: 12, color: '#64748b' }}>{desc}</div>
                    </button>
                ))}
            </div>

            {/* External tools */}
            <div>
                <div style={{ fontSize: 13, fontWeight: 700, color: '#f8fafc', marginBottom: 12 }}>
                    Links Rápidos — Ferramentas Externas
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 10 }}>
                    {externalTools.map(({ name, url, desc, color }) => (
                        <a key={name} href={url} target="_blank" rel="noopener noreferrer"
                            style={{
                                display: 'flex', alignItems: 'center', gap: 10,
                                background: '#1e293b', border: '1px solid rgba(255,255,255,0.07)',
                                borderRadius: 10, padding: '12px 14px', textDecoration: 'none',
                                transition: 'all 0.2s', cursor: 'pointer'
                            }}
                            onMouseEnter={e => { e.currentTarget.style.background = '#263550'; e.currentTarget.style.borderColor = `${color}40`; }}
                            onMouseLeave={e => { e.currentTarget.style.background = '#1e293b'; e.currentTarget.style.borderColor = 'rgba(255,255,255,0.07)'; }}
                        >
                            <div style={{ width: 8, height: 8, borderRadius: '50%', background: color, flexShrink: 0 }} />
                            <div>
                                <div style={{ fontSize: 13, fontWeight: 600, color: '#f8fafc' }}>{name}</div>
                                <div style={{ fontSize: 11, color: '#64748b' }}>{desc}</div>
                            </div>
                            <ExternalLink size={12} color="#475569" style={{ marginLeft: 'auto', flexShrink: 0 }} />
                        </a>
                    ))}
                </div>
            </div>
        </div>
    );
}
