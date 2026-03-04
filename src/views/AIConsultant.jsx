import React, { useState, useRef, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
    Bot, Send, User, ArrowRight, ExternalLink, ChevronRight,
    AlertTriangle, CheckCircle2, RefreshCw, Lightbulb, Shield, Map
} from 'lucide-react';
import { scenarios, defaultScenario } from '../data/knowledgeBase';

const SUGGESTIONS = [
    'Recebi um e-mail suspeito com link. O que devo verificar?',
    'Encontrei um processo PowerShell rodando com -EncodedCommand estranho.',
    'Um host está fazendo conexões periódicas para um IP externo desconhecido.',
    'Usuário clicou em link de phishing. Quais são os próximos passos?',
    'Encontrei executável suspeito no servidor. Como analisar o hash?',
    'Servidor criptografando arquivos — possível ransomware em andamento.',
    'Detectei possível Kerberoasting no Active Directory. Como investigar?',
    'Um funcionário está copiando dados em massa antes de ser demitido.',
    'Sistema web está lento e WAF disparou alertas de SQL injection.',
    'Há tentativas de login massivas nas contas do Azure AD.',
    'Detectei movimento lateral via RDP entre máquinas internas.',
    'Detectamos um CVE crítico em produção com exploit público disponível.',
    'Arquivo novo criado em pasta de inicialização suspeito — é persistência?',
    'Preciso investigar o que aconteceu ontem neste servidor (forense).',
    'Nossa infraestrutura AWS teve permissões IAM criadas de forma suspeita.',
];

const severityColor = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#3b82f6', info: '#06b6d4' };
const categoryColor = {
    '🔴 CRÍTICO': '#ef4444', 'Coleta': '#06b6d4', 'Análise': '#a78bfa',
    'Consulta': '#3b82f6', 'Investigação': '#f97316', 'Análise Estática': '#8b5cf6',
    'Verificação': '#22c55e', 'Forense': '#94a3b8', 'Contenção': '#ef4444',
    'Remediação': '#22c55e', 'Referência': '#a78bfa', 'Análise Segura': '#06b6d4',
    'Mitigação Temporária': '#eab308', 'Orientação Legal': '#64748b',
};

// Normaliza texto: minúsculas + remove acentos + remove pontuação extra
function normalize(text) {
    return text
        .toLowerCase()
        .normalize('NFD')
        .replace(/[\u0300-\u036f]/g, '')  // remove acentos
        .replace(/[^a-z0-9\s\-\.]/g, ' ')  // remove pontuação especial
        .replace(/\s+/g, ' ')
        .trim();
}

// Extrai artefatos da pergunta (IPs, hashes, CVEs, domínios)
function extractArtifacts(text) {
    const artifacts = [];
    const ipMatch = text.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g);
    const hashMatch = text.match(/\b[a-fA-F0-9]{32,64}\b/g);
    const cveMatch = text.match(/CVE-\d{4}-\d{4,7}/gi);
    const domainMatch = text.match(/\b(?:[a-z0-9\-]+\.)+(?:com|net|org|io|br|xyz|ru|cn|top|info)\b/gi);
    if (ipMatch) artifacts.push(...ipMatch.map(v => ({ type: 'IP', value: v })));
    if (hashMatch) artifacts.push(...hashMatch.map(v => ({ type: 'Hash', value: v })));
    if (cveMatch) artifacts.push(...cveMatch.map(v => ({ type: 'CVE', value: v })));
    if (domainMatch) artifacts.push(...domainMatch.slice(0, 3).map(v => ({ type: 'Domínio', value: v })));
    return artifacts;
}

// Engine de matching com pontuação ponderada
function matchScenario(text) {
    const norm = normalize(text);
    const orig = text.toLowerCase();
    let best = null;
    let bestScore = 0;

    for (const scenario of scenarios) {
        let score = 0;

        // Keywords simples: 1 ponto por match (match parcial)
        for (const kw of scenario.keywords) {
            if (norm.includes(normalize(kw))) score += 1;
        }

        // Frases-chave ponderadas: 3 pontos por match (mais específicas)
        if (scenario.weightedKeywords) {
            for (const wkw of scenario.weightedKeywords) {
                if (norm.includes(normalize(wkw)) || orig.includes(wkw.toLowerCase())) {
                    score += 3;
                }
            }
        }

        // Bonus: ID do cenário mencionado diretamente (ex: "ransomware", "kerberoasting")
        if (scenario.id && norm.includes(scenario.id)) score += 5;

        if (score > bestScore) { bestScore = score; best = scenario; }
    }

    // Requer score mínimo de 2 para evitar falsos positivos
    return bestScore >= 2 ? { scenario: best, score: bestScore } : null;
}

function AnalysisResponse({ scenario, navigate }) {
    const sev = scenario.severity;
    const sevCfg = severityColor[sev] || '#94a3b8';

    return (
        <div className="animate-slide-in-up" style={{ maxWidth: 720 }}>
            {/* Scenario header */}
            <div style={{
                background: 'linear-gradient(135deg, rgba(6,182,212,0.06), rgba(59,130,246,0.04))',
                border: '1px solid rgba(6,182,212,0.2)',
                borderRadius: 12, padding: '14px 18px', marginBottom: 14, position: 'relative', overflow: 'hidden'
            }}>
                <div style={{ position: 'absolute', top: 0, left: 0, right: 0, height: 2, background: `linear-gradient(90deg, ${sevCfg}, transparent)` }} />
                <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
                    <Bot size={16} color="#06b6d4" />
                    <span style={{ fontSize: 13, fontWeight: 700, color: '#06b6d4' }}>AI Consultor · Cenário identificado:</span>
                    <span style={{ fontSize: 12, fontWeight: 700, color: sevCfg, background: `${sevCfg}18`, border: `1px solid ${sevCfg}35`, borderRadius: 5, padding: '1px 8px' }}>
                        {sev.charAt(0).toUpperCase() + sev.slice(1)}
                    </span>
                </div>
                <div style={{ fontSize: 16, fontWeight: 800, color: '#f8fafc', marginBottom: 8 }}>{scenario.title}</div>
                <p style={{ fontSize: 13, color: '#94a3b8', lineHeight: 1.7 }}>{scenario.summary}</p>
            </div>

            {/* TTPs */}
            {scenario.ttps?.length > 0 && (
                <div style={{ marginBottom: 14 }}>
                    <div style={{ fontSize: 11, fontWeight: 700, color: '#a78bfa', marginBottom: 8, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                        🗺️ TTPs MITRE ATT&CK Relacionados
                    </div>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                        {scenario.ttps.map(t => (
                            <button key={t} onClick={() => navigate('/mitre')} className="mitre-tag" style={{ cursor: 'pointer' }}>
                                {t}
                            </button>
                        ))}
                    </div>
                </div>
            )}

            {/* Checklist */}
            <div style={{ marginBottom: 14 }}>
                <div style={{ fontSize: 11, fontWeight: 700, color: '#f8fafc', marginBottom: 10, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                    ✅ Checklist de Ações — Siga esta ordem:
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                    {scenario.steps.map((step, i) => {
                        const catColor = categoryColor[step.category] || '#64748b';
                        return (
                            <div key={i} style={{
                                display: 'flex', alignItems: 'flex-start', gap: 12,
                                background: step.category === '🔴 CRÍTICO' ? 'rgba(239,68,68,0.06)' : 'rgba(255,255,255,0.03)',
                                border: `1px solid ${step.category === '🔴 CRÍTICO' ? 'rgba(239,68,68,0.2)' : 'rgba(255,255,255,0.06)'}`,
                                borderRadius: 8, padding: '10px 14px'
                            }}>
                                <div style={{
                                    width: 22, height: 22, borderRadius: '50%', background: `${catColor}18`,
                                    border: `1px solid ${catColor}30`, display: 'flex', alignItems: 'center',
                                    justifyContent: 'center', fontSize: 11, fontWeight: 800, color: catColor, flexShrink: 0
                                }}>{step.priority}</div>
                                <div style={{ flex: 1 }}>
                                    <div style={{ fontSize: 13, fontWeight: 600, color: '#f8fafc', marginBottom: 2 }}>{step.action}</div>
                                    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                                        <span style={{ fontSize: 10, background: `${catColor}12`, color: catColor, border: `1px solid ${catColor}25`, borderRadius: 4, padding: '1px 6px' }}>
                                            {step.category}
                                        </span>
                                        <span style={{ fontSize: 11, color: '#64748b' }}>{step.tool}</span>
                                    </div>
                                </div>
                                {step.link && (
                                    <button onClick={() => navigate(step.link)} className="btn-ghost" style={{ fontSize: 11, padding: '5px 10px', flexShrink: 0 }}>
                                        Abrir <ArrowRight size={11} />
                                    </button>
                                )}
                            </div>
                        );
                    })}
                </div>
            </div>

            {/* Mitigations & References */}
            {scenario.mitigations?.length > 0 && (
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                    <div className="card-sm">
                        <div style={{ fontSize: 11, fontWeight: 700, color: '#22c55e', marginBottom: 8 }}>🛡️ Mitigações (MITRE)</div>
                        {scenario.mitigations.map(m => (
                            <div key={m} style={{ fontSize: 11, color: '#94a3b8', padding: '3px 0', borderBottom: '1px solid rgba(255,255,255,0.05)' }}>{m}</div>
                        ))}
                    </div>
                    {scenario.references?.length > 0 && (
                        <div className="card-sm">
                            <div style={{ fontSize: 11, fontWeight: 700, color: '#06b6d4', marginBottom: 8 }}>🔗 Referências</div>
                            {scenario.references.map(r => (
                                <a key={r} href={r} target="_blank" rel="noopener noreferrer"
                                    style={{ display: 'block', fontSize: 11, color: '#06b6d4', padding: '3px 0', borderBottom: '1px solid rgba(255,255,255,0.05)', textDecoration: 'none', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                                    {r.replace('https://', '').split('/')[0]} <ExternalLink size={9} style={{ display: 'inline' }} />
                                </a>
                            ))}
                        </div>
                    )}
                </div>
            )}
        </div>
    );
}

export default function AIConsultant() {
    const navigate = useNavigate();
    const [messages, setMessages] = useState([
        {
            role: 'assistant',
            type: 'welcome',
            content: 'Olá! Sou o AI Consultor do SecOps Flow. Descreva o problema de segurança que está investigando e vou orientar você com base no MITRE ATT&CK, indicando as ações recomendadas, TTPs relacionados e ferramentas para a investigação.',
        }
    ]);
    const [input, setInput] = useState('');
    const [loading, setLoading] = useState(false);
    const endRef = useRef(null);

    useEffect(() => { endRef.current?.scrollIntoView({ behavior: 'smooth' }); }, [messages]);

    const send = (text) => {
        if (!text?.trim()) return;
        const userMsg = { role: 'user', content: text };
        setMessages(prev => [...prev, userMsg]);
        setInput('');
        setLoading(true);

        setTimeout(() => {
            const result = matchScenario(text);
            const artifacts = extractArtifacts(text);
            const scenario = result ? result.scenario : defaultScenario;
            const confidence = result ? result.score : 0;
            setMessages(prev => [...prev, { role: 'assistant', type: 'analysis', scenario, artifacts, confidence }]);
            setLoading(false);
        }, 900);
    };

    const startNew = () => {
        setMessages([{
            role: 'assistant', type: 'welcome',
            content: 'Nova consulta iniciada. Descreva o problema de segurança que está investigando.'
        }]);
        setInput('');
    };

    return (
        <div className="animate-fade-in" style={{ height: 'calc(100vh - 108px)', display: 'flex', flexDirection: 'column' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 16, flexShrink: 0 }}>
                <div>
                    <h1 style={{ fontSize: 22, fontWeight: 800, color: '#f8fafc', letterSpacing: -0.5 }}>AI Consultor</h1>
                    <p style={{ fontSize: 13, color: '#64748b', marginTop: 4 }}>Descreva o incidente e receba orientação baseada no MITRE ATT&CK</p>
                </div>
                <button onClick={startNew} className="btn-ghost" style={{ fontSize: 12 }}>
                    <RefreshCw size={13} /> Nova Consulta
                </button>
            </div>

            {/* Suggestions */}
            {messages.length <= 1 && (
                <div style={{ marginBottom: 14, flexShrink: 0 }}>
                    <div style={{ fontSize: 11, fontWeight: 600, color: '#475569', marginBottom: 8, display: 'flex', alignItems: 'center', gap: 6 }}>
                        <Lightbulb size={12} /> Sugestões rápidas
                    </div>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                        {SUGGESTIONS.map(s => (
                            <button key={s} onClick={() => send(s)}
                                style={{ fontSize: 12, background: 'rgba(255,255,255,0.04)', color: '#94a3b8', border: '1px solid rgba(255,255,255,0.07)', borderRadius: 8, padding: '5px 12px', cursor: 'pointer', transition: 'all 0.15s', textAlign: 'left' }}
                                onMouseEnter={e => { e.currentTarget.style.background = 'rgba(6,182,212,0.08)'; e.currentTarget.style.color = '#06b6d4'; e.currentTarget.style.borderColor = 'rgba(6,182,212,0.3)'; }}
                                onMouseLeave={e => { e.currentTarget.style.background = 'rgba(255,255,255,0.04)'; e.currentTarget.style.color = '#94a3b8'; e.currentTarget.style.borderColor = 'rgba(255,255,255,0.07)'; }}
                            >{s}</button>
                        ))}
                    </div>
                </div>
            )}

            {/* Messages */}
            <div style={{ flex: 1, overflowY: 'auto', paddingRight: 4, display: 'flex', flexDirection: 'column', gap: 14 }}>
                {messages.map((msg, i) => (
                    <div key={i} style={{ display: 'flex', gap: 10, flexDirection: msg.role === 'user' ? 'row-reverse' : 'row' }}>
                        {/* Avatar */}
                        <div style={{
                            width: 32, height: 32, borderRadius: 8, flexShrink: 0,
                            background: msg.role === 'user' ? 'linear-gradient(135deg, #3b82f6, #06b6d4)' : 'linear-gradient(135deg, #06b6d4, #a78bfa)',
                            display: 'flex', alignItems: 'center', justifyContent: 'center'
                        }}>
                            {msg.role === 'user' ? <User size={16} color="white" /> : <Bot size={16} color="white" />}
                        </div>

                        {/* Content */}
                        <div style={{ maxWidth: '85%' }}>
                            {msg.role === 'user' ? (
                                <div style={{ background: 'rgba(59,130,246,0.12)', border: '1px solid rgba(59,130,246,0.25)', borderRadius: '12px 12px 2px 12px', padding: '10px 14px' }}>
                                    <p style={{ fontSize: 13, color: '#f8fafc', margin: 0, lineHeight: 1.6 }}>{msg.content}</p>
                                </div>
                            ) : msg.type === 'welcome' ? (
                                <div className="copilot-box">
                                    <p style={{ fontSize: 13, color: '#cbd5e1', lineHeight: 1.7, margin: 0 }}>{msg.content}</p>
                                </div>
                            ) : (
                                <div>
                                    {/* Artefatos detectados na pergunta */}
                                    {msg.artifacts?.length > 0 && (
                                        <div style={{ background: 'rgba(6,182,212,0.06)', border: '1px solid rgba(6,182,212,0.2)', borderRadius: 8, padding: '8px 12px', marginBottom: 10, display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                                            <span style={{ fontSize: 11, color: '#64748b', fontWeight: 600 }}>🔍 Artefatos detectados:</span>
                                            {msg.artifacts.map((a, idx) => (
                                                <button key={idx} onClick={() => navigate('/lookup')}
                                                    style={{ fontSize: 11, fontFamily: "'Fira Code', monospace", background: 'rgba(6,182,212,0.1)', color: '#06b6d4', border: '1px solid rgba(6,182,212,0.25)', borderRadius: 4, padding: '2px 8px', cursor: 'pointer' }}>
                                                    {a.type}: {a.value}
                                                </button>
                                            ))}
                                            <span style={{ fontSize: 10, color: '#475569' }}>→ verificar no IOC Lookup</span>
                                        </div>
                                    )}
                                    <AnalysisResponse scenario={msg.scenario} navigate={navigate} confidence={msg.confidence} />
                                </div>
                            )}
                        </div>
                    </div>
                ))}

                {loading && (
                    <div style={{ display: 'flex', gap: 10 }}>
                        <div style={{ width: 32, height: 32, borderRadius: 8, background: 'linear-gradient(135deg, #06b6d4, #a78bfa)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                            <Bot size={16} color="white" />
                        </div>
                        <div className="copilot-box">
                            <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                                {[0, 1, 2].map(i => (
                                    <div key={i} style={{ width: 7, height: 7, borderRadius: '50%', background: '#06b6d4', animation: `blink 1.2s ease-in-out ${i * 0.2}s infinite` }} />
                                ))}
                                <span style={{ fontSize: 12, color: '#64748b', marginLeft: 4 }}>Consultando base de conhecimento MITRE...</span>
                            </div>
                        </div>
                    </div>
                )}
                <div ref={endRef} />
            </div>

            {/* Input */}
            <div style={{ borderTop: '1px solid rgba(255,255,255,0.07)', paddingTop: 14, flexShrink: 0 }}>
                <div style={{ display: 'flex', gap: 10 }}>
                    <textarea
                        value={input}
                        onChange={e => setInput(e.target.value)}
                        onKeyDown={e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send(input); } }}
                        placeholder="Descreva o problema de segurança... (Ex: recebi e-mail suspeito, encontrei processo estranho, IP malicioso detectado...)"
                        style={{
                            flex: 1, background: '#1e293b', border: '1px solid rgba(255,255,255,0.1)',
                            borderRadius: 10, color: '#f8fafc', padding: '10px 14px',
                            fontFamily: 'Inter, sans-serif', fontSize: 13, lineHeight: 1.6,
                            outline: 'none', resize: 'none', minHeight: 44, maxHeight: 120,
                            transition: 'border-color 0.2s'
                        }}
                        onFocus={e => e.target.style.borderColor = 'rgba(6,182,212,0.4)'}
                        onBlur={e => e.target.style.borderColor = 'rgba(255,255,255,0.1)'}
                        rows={1}
                        disabled={loading}
                    />
                    <button
                        onClick={() => send(input)}
                        className="btn-primary"
                        disabled={loading || !input.trim()}
                        style={{ padding: '10px 16px', alignSelf: 'flex-end', opacity: !input.trim() ? 0.5 : 1 }}
                    >
                        <Send size={15} />
                    </button>
                </div>
                <div style={{ fontSize: 11, color: '#334155', marginTop: 6, textAlign: 'center' }}>
                    Enter para enviar · Shift+Enter para nova linha · Respostas baseadas em MITRE ATT&CK (local, sem API externa)
                </div>
            </div>
        </div>
    );
}
