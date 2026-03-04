import React, { useState, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import { Search, Globe, Hash, Link2, AlertTriangle, CheckCircle2, Clock, ExternalLink, Bot } from 'lucide-react';

const exampleResults = {
    '185.220.101.47': {
        type: 'ip',
        value: '185.220.101.47',
        reputation: 'malicious',
        vtScore: '58/73',
        country: 'Rússia',
        asn: 'AS4224 - Tor Project',
        tags: ['Tor Exit Node', 'C2 servidor', 'Blacklisted', 'Cryptominer'],
        firstSeen: '2019-03-12',
        lastSeen: '01/03/2024',
        reverseDns: 'tor-exit.node.ru',
        relatedIncidents: ['INC-2024-0891'],
        abuseConfidence: 98,
        summary: 'IP pertencente à rede Tor, frequentemente utilizado como ponto de saída para ataques de Comando e Controle (C2). Aparece em múltiplas blacklists internacionais. Nenhum tráfego legítimo esperado.'
    }
};

export default function ThreatIntel() {
    const [searchParams] = useSearchParams();
    const [query, setQuery] = useState(searchParams.get('q') || '');
    const [result, setResult] = useState(null);
    const [loading, setLoading] = useState(false);

    useEffect(() => {
        const q = searchParams.get('q');
        if (q) { setQuery(q); simulateSearch(q); }
    }, [searchParams]);

    const simulateSearch = (q) => {
        setLoading(true);
        setTimeout(() => {
            setResult(exampleResults[q] || {
                type: 'unknown',
                value: q,
                reputation: 'clean',
                summary: `Nenhum indicador de comprometimento encontrado para "${q}" nas bases de dados consultadas.`,
                tags: [],
                vtScore: '0/73',
            });
            setLoading(false);
        }, 1200);
    };

    const handleSearch = (e) => {
        e.preventDefault();
        if (query.trim()) simulateSearch(query.trim());
    };

    return (
        <div className="animate-fade-in">
            <div style={{ marginBottom: 24 }}>
                <h1 style={{ fontSize: 22, fontWeight: 800, color: '#f8fafc', letterSpacing: -0.5 }}>Threat Intelligence</h1>
                <p style={{ fontSize: 13, color: '#64748b', marginTop: 4 }}>Busca unificada de IPs, hashes, domínios e usuários</p>
            </div>

            <form onSubmit={handleSearch} style={{ display: 'flex', gap: 10, marginBottom: 28, maxWidth: 600 }}>
                <div style={{ position: 'relative', flex: 1 }}>
                    <Search size={16} style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', color: '#64748b' }} />
                    <input
                        className="search-input"
                        style={{ width: '100%', paddingLeft: 40, fontSize: 14 }}
                        placeholder="Buscar: 185.220.101.47, a7f3e2b1..., malware.cc"
                        value={query}
                        onChange={e => setQuery(e.target.value)}
                    />
                </div>
                <button type="submit" className="btn-primary">Investigar</button>
            </form>

            {/* Example badges */}
            <div style={{ display: 'flex', gap: 8, marginBottom: 24, flexWrap: 'wrap' }}>
                <span style={{ fontSize: 11, color: '#64748b' }}>Exemplos rápidos:</span>
                {['185.220.101.47', 'a7f3e2b1c9d4...', 'update-sync.ru', 'j.silva'].map(ex => (
                    <button
                        key={ex}
                        onClick={() => { setQuery(ex); simulateSearch(ex); }}
                        style={{
                            fontSize: 11, fontFamily: "'Fira Code', monospace",
                            background: 'rgba(255,255,255,0.05)', color: '#94a3b8',
                            border: '1px solid rgba(255,255,255,0.07)', borderRadius: 6,
                            padding: '3px 10px', cursor: 'pointer', transition: 'all 0.2s'
                        }}
                        onMouseEnter={e => e.target.style.color = '#06b6d4'}
                        onMouseLeave={e => e.target.style.color = '#94a3b8'}
                    >{ex}</button>
                ))}
            </div>

            {loading && (
                <div style={{ textAlign: 'center', padding: 60 }}>
                    <div style={{ display: 'inline-flex', flexDirection: 'column', alignItems: 'center', gap: 12 }}>
                        <Bot size={32} color="#06b6d4" style={{ animation: 'pulse 1s ease-in-out infinite alternate' }} />
                        <div style={{ fontSize: 14, color: '#94a3b8' }}>Consultando VirusTotal, MISP, AbuseIPDB...</div>
                    </div>
                </div>
            )}

            {result && !loading && (
                <div className="animate-slide-in-up">
                    <div className="card" style={{ maxWidth: 700 }}>
                        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 12, marginBottom: 20 }}>
                            <div>
                                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
                                    {result.type === 'ip' ? <Globe size={16} color="#06b6d4" /> : <Hash size={16} color="#06b6d4" />}
                                    <span style={{ fontSize: 20, fontWeight: 800, fontFamily: "'Fira Code', monospace", color: '#f8fafc' }}>
                                        {result.value}
                                    </span>
                                </div>
                                <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                                    {result.tags?.map(tag => (
                                        <span key={tag} style={{
                                            fontSize: 11, background: 'rgba(239,68,68,0.1)', color: '#f87171',
                                            border: '1px solid rgba(239,68,68,0.2)', borderRadius: 4, padding: '2px 8px'
                                        }}>{tag}</span>
                                    ))}
                                </div>
                            </div>
                            <div style={{ textAlign: 'center', flexShrink: 0 }}>
                                <div style={{
                                    fontSize: 28, fontWeight: 900,
                                    color: result.reputation === 'malicious' ? '#ef4444' : result.reputation === 'suspicious' ? '#f97316' : '#22c55e'
                                }}>
                                    {result.vtScore || '0/73'}
                                </div>
                                <div style={{ fontSize: 11, color: '#64748b' }}>VirusTotal</div>
                            </div>
                        </div>

                        <div className="divider" style={{ marginBottom: 16 }} />

                        <div style={{ marginBottom: 16, background: 'rgba(239,68,68,0.05)', border: '1px solid rgba(239,68,68,0.15)', borderRadius: 8, padding: 12 }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 6 }}>
                                <Bot size={13} color="#06b6d4" />
                                <span style={{ fontSize: 11, fontWeight: 700, color: '#06b6d4' }}>Análise IA</span>
                            </div>
                            <p style={{ fontSize: 12.5, color: '#cbd5e1', lineHeight: 1.7 }}>{result.summary}</p>
                        </div>

                        {result.country && (
                            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
                                {[
                                    { label: 'País', value: result.country },
                                    { label: 'ASN', value: result.asn },
                                    { label: 'Primeiro visto', value: result.firstSeen },
                                    { label: 'Último visto', value: result.lastSeen },
                                    { label: 'DNS Reverso', value: result.reverseDns },
                                    { label: 'Confiança de Abuso', value: `${result.abuseConfidence}%` },
                                ].filter(r => r.value).map(({ label, value }) => (
                                    <div key={label} style={{ background: 'rgba(255,255,255,0.03)', borderRadius: 6, padding: '8px 12px' }}>
                                        <div style={{ fontSize: 10, color: '#64748b', marginBottom: 2 }}>{label}</div>
                                        <div style={{ fontSize: 12, fontWeight: 600, color: '#94a3b8', fontFamily: "'Fira Code', monospace" }}>{value}</div>
                                    </div>
                                ))}
                            </div>
                        )}
                    </div>
                </div>
            )}

            {!result && !loading && (
                <div style={{ textAlign: 'center', padding: '60px 20px' }}>
                    <Bot size={48} color="#1e293b" style={{ marginBottom: 12 }} />
                    <div style={{ fontSize: 15, fontWeight: 600, color: '#334155', marginBottom: 6 }}>
                        Busca Unificada de Threat Intelligence
                    </div>
                    <div style={{ fontSize: 13, color: '#1e293b' }}>
                        Consulta simultânea: VirusTotal · MISP · AbuseIPDB · Shodan · Active Directory
                    </div>
                </div>
            )}
        </div>
    );
}
