import React, { useState } from 'react';
import { Mail, Play, CheckCircle2, AlertTriangle, XCircle, Info, Globe, ExternalLink, ArrowRight, Copy } from 'lucide-react';
import { exampleEmailHeaders } from '../data/knowledgeBase';

function parseHeaders(raw) {
    const lines = raw.split('\n');
    const headers = {};
    let currentKey = null;
    lines.forEach(line => {
        const match = line.match(/^([A-Za-z0-9\-_]+):\s?(.*)/);
        if (match) { currentKey = match[1].toLowerCase(); headers[currentKey] = match[2].trim(); }
        else if (currentKey && line.startsWith(' ')) { headers[currentKey] += ' ' + line.trim(); }
    });
    return headers;
}

function extractIPs(raw) {
    const ips = [...new Set((raw.match(/\b(\d{1,3}\.){3}\d{1,3}\b/g) || []))];
    return ips.filter(ip => {
        const parts = ip.split('.').map(Number);
        if (parts[0] === 127 || parts[0] === 10) return false;
        if (parts[0] === 192 && parts[1] === 168) return false;
        if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return false;
        return true;
    });
}

function analyzeHeaders(raw) {
    const headers = parseHeaders(raw);
    const text = raw.toLowerCase();

    const spfLine = raw.match(/spf=(\w+)/i);
    const dkimLine = raw.match(/dkim=(\w+)/i);
    const dmarcLine = raw.match(/dmarc=(\w+)/i);

    const spf = spfLine?.[1]?.toLowerCase() || 'none';
    const dkim = dkimLine?.[1]?.toLowerCase() || 'none';
    const dmarc = dmarcLine?.[1]?.toLowerCase() || 'none';

    const from = headers['from'] || '';
    const replyTo = headers['reply-to'] || '';
    const returnPath = headers['return-path'] || '';

    const fromDomain = from.match(/@([\w.-]+)/)?.[1]?.toLowerCase();
    const replyToDomain = replyTo.match(/@([\w.-]+)/)?.[1]?.toLowerCase();
    const returnDomain = returnPath.match(/@([\w.-]+)/)?.[1]?.toLowerCase();

    const originatingIp = headers['x-originating-ip'] || null;
    const mailer = headers['x-mailer'] || null;

    const isSpoofed = fromDomain && replyToDomain && fromDomain !== replyToDomain;
    const domainMismatch = fromDomain && returnDomain && fromDomain !== returnDomain;

    const issues = [];
    if (spf === 'fail' || spf === 'softfail') issues.push({ level: 'critical', msg: `SPF ${spf.toUpperCase()}: O servidor remetente não está autorizado a enviar e-mails por este domínio.` });
    if (dkim === 'none' || dkim === 'fail') issues.push({ level: dkim === 'none' ? 'warn' : 'critical', msg: `DKIM ${dkim.toUpperCase()}: ${dkim === 'none' ? 'Assinatura DKIM ausente — e-mail não verificado criptograficamente.' : 'Assinatura DKIM inválida — e-mail pode ter sido alterado em trânsito.'}` });
    if (dmarc === 'fail' || dmarc === 'none') issues.push({ level: dmarc === 'none' ? 'warn' : 'critical', msg: `DMARC ${dmarc.toUpperCase()}: ${dmarc === 'none' ? 'Política DMARC ausente — sem proteção anti-spoofing.' : 'DMARC falhou — e-mail não passou nas verificações de autenticação.'}` });
    if (isSpoofed) issues.push({ level: 'critical', msg: `Possível SPOOFING: Domínio no "From" (${fromDomain}) é diferente do "Reply-To" (${replyToDomain}). Resposta será enviada para domínio diferente do remetente aparente.` });
    if (domainMismatch) issues.push({ level: 'warn', msg: `Domínio do "From" (${fromDomain}) difere do "Return-Path" (${returnDomain}) — indica possível mismatch de remetentes.` });
    if (mailer && mailer.toLowerCase().includes('phpmailer')) issues.push({ level: 'warn', msg: `Enviado via PHPMailer — software comum em campanhas de phishing automatizado.` });

    const hasCritical = issues.some(i => i.level === 'critical');
    const hasWarn = issues.some(i => i.level === 'warn');
    const verdict = hasCritical ? 'malicious' : hasWarn ? 'suspicious' : 'clean';

    const ips = extractIPs(raw);

    return { spf, dkim, dmarc, from, replyTo, returnPath, fromDomain, replyToDomain, returnDomain, originatingIp, mailer, isSpoofed, domainMismatch, issues, verdict, ips, headers };
}

function StatusBadge({ value, label }) {
    const cfg = {
        pass: { icon: <CheckCircle2 size={14} />, color: '#22c55e', bg: 'rgba(34,197,94,0.1)', text: 'PASS' },
        fail: { icon: <XCircle size={14} />, color: '#ef4444', bg: 'rgba(239,68,68,0.1)', text: 'FAIL' },
        softfail: { icon: <AlertTriangle size={14} />, color: '#f97316', bg: 'rgba(249,115,22,0.1)', text: 'SOFTFAIL' },
        none: { icon: <Info size={14} />, color: '#64748b', bg: 'rgba(100,116,139,0.1)', text: 'NONE' },
    }[value?.toLowerCase()] || { icon: <Info size={14} />, color: '#64748b', bg: 'rgba(100,116,139,0.1)', text: value?.toUpperCase() };

    return (
        <div style={{ background: cfg.bg, border: `1px solid ${cfg.color}40`, borderRadius: 8, padding: '8px 14px', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 4, minWidth: 90 }}>
            <div style={{ color: cfg.color }}>{cfg.icon}</div>
            <div style={{ fontSize: 13, fontWeight: 800, color: cfg.color }}>{cfg.text}</div>
            <div style={{ fontSize: 10, color: '#64748b' }}>{label}</div>
        </div>
    );
}

export default function EmailHeaderAnalyzer() {
    const [raw, setRaw] = useState('');
    const [result, setResult] = useState(null);
    const [loading, setLoading] = useState(false);

    const analyze = () => {
        if (!raw.trim()) return;
        setLoading(true);
        setTimeout(() => { setResult(analyzeHeaders(raw)); setLoading(false); }, 700);
    };

    const loadExample = (key) => { setRaw(exampleEmailHeaders[key]); setResult(null); };

    const verdictCfg = {
        malicious: { label: '🔴 Suspeito / Provável Phishing', color: '#ef4444', bg: 'rgba(239,68,68,0.08)' },
        suspicious: { label: '🟡 Atenção — Verificar Manualmente', color: '#f97316', bg: 'rgba(249,115,22,0.08)' },
        clean: { label: '🟢 Headers Aparentemente Legítimos', color: '#22c55e', bg: 'rgba(34,197,94,0.08)' },
    };

    return (
        <div className="animate-fade-in">
            <div style={{ marginBottom: 20 }}>
                <h1 style={{ fontSize: 22, fontWeight: 800, color: '#f8fafc', letterSpacing: -0.5 }}>Analisador de E-mail Headers</h1>
                <p style={{ fontSize: 13, color: '#64748b', marginTop: 4 }}>Cole os cabeçalhos do e-mail para análise de SPF, DKIM, DMARC, spoofing e IPs</p>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: result ? '1fr 1fr' : '1fr', gap: 16 }}>
                {/* Input */}
                <div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                        <div style={{ display: 'flex', gap: 6 }}>
                            <button onClick={() => loadExample('phishing')} className="btn-ghost" style={{ fontSize: 11 }}>
                                <Mail size={12} /> Exemplo: Phishing
                            </button>
                            <button onClick={() => loadExample('legitimate')} className="btn-ghost" style={{ fontSize: 11 }}>
                                <Mail size={12} /> Exemplo: Legítimo
                            </button>
                        </div>
                        <button onClick={() => { setRaw(''); setResult(null); }} className="btn-ghost" style={{ fontSize: 11 }}>Limpar</button>
                    </div>
                    <textarea
                        value={raw}
                        onChange={e => setRaw(e.target.value)}
                        placeholder={'Cole aqui os headers do e-mail...\n\nExemplo:\nReceived: from mail.example.com...\nFrom: "Nome" <email@dominio.com>\nAuthentication-Results: spf=pass...'}
                        style={{
                            width: '100%', minHeight: 320, maxHeight: 480,
                            background: '#0f172a', border: '1px solid rgba(255,255,255,0.1)',
                            borderRadius: 10, color: '#a5f3fc', padding: 14,
                            fontFamily: "'Fira Code', monospace", fontSize: 11, lineHeight: 1.7,
                            outline: 'none', resize: 'vertical', boxSizing: 'border-box',
                            transition: 'border-color 0.2s'
                        }}
                        onFocus={e => e.target.style.borderColor = 'rgba(6,182,212,0.4)'}
                        onBlur={e => e.target.style.borderColor = 'rgba(255,255,255,0.1)'}
                    />
                    <button
                        onClick={analyze}
                        className="btn-primary"
                        style={{ width: '100%', justifyContent: 'center', marginTop: 10, padding: 12, fontSize: 14 }}
                        disabled={loading || !raw.trim()}
                    >
                        {loading ? 'Analisando...' : <><Play size={14} /> Analisar Headers</>}
                    </button>

                    <div style={{ marginTop: 14 }}>
                        <div style={{ fontSize: 11, fontWeight: 700, color: '#475569', marginBottom: 8, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                            Onde encontrar os headers?
                        </div>
                        {[
                            { client: 'Gmail', steps: 'Abrir e-mail → ⋮ (menu) → "Mostrar original"' },
                            { client: 'Outlook', steps: 'Abrir e-mail → Arquivo → Propriedades → Cabeçalhos' },
                            { client: 'Apple Mail', steps: 'Abrir e-mail → Exibização → Cabeçalhos → Todos' },
                            { client: 'Thunderbird', steps: 'Ctrl+U ou Exibição → Código-fonte da mensagem' },
                        ].map(({ client, steps }) => (
                            <div key={client} style={{ display: 'flex', gap: 8, marginBottom: 5 }}>
                                <span style={{ fontSize: 11, fontWeight: 600, color: '#06b6d4', minWidth: 70 }}>{client}</span>
                                <span style={{ fontSize: 11, color: '#64748b' }}>{steps}</span>
                            </div>
                        ))}
                    </div>
                </div>

                {/* Results */}
                {result && (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                        {/* Verdict */}
                        <div style={{ background: verdictCfg[result.verdict].bg, border: `1px solid ${verdictCfg[result.verdict].color}30`, borderRadius: 12, padding: '14px 18px' }}>
                            <div style={{ fontSize: 16, fontWeight: 800, color: verdictCfg[result.verdict].color }}>
                                {verdictCfg[result.verdict].label}
                            </div>
                        </div>

                        {/* Auth results */}
                        <div className="card">
                            <div style={{ fontSize: 12, fontWeight: 700, color: '#f8fafc', marginBottom: 12 }}>Autenticação de E-mail</div>
                            <div style={{ display: 'flex', gap: 10, marginBottom: 12 }}>
                                <StatusBadge value={result.spf} label="SPF" />
                                <StatusBadge value={result.dkim} label="DKIM" />
                                <StatusBadge value={result.dmarc} label="DMARC" />
                            </div>
                            <div style={{ fontSize: 11, color: '#475569', lineHeight: 1.7 }}>
                                <strong style={{ color: '#64748b' }}>SPF</strong> verifica se o servidor tem permissão de envio ·{' '}
                                <strong style={{ color: '#64748b' }}>DKIM</strong> garante integridade do conteúdo ·{' '}
                                <strong style={{ color: '#64748b' }}>DMARC</strong> define a política de verificação
                            </div>
                        </div>

                        {/* Issues */}
                        {result.issues.length > 0 && (
                            <div className="card">
                                <div style={{ fontSize: 12, fontWeight: 700, color: '#f8fafc', marginBottom: 10 }}>
                                    ⚠️ Problemas Detectados ({result.issues.length})
                                </div>
                                {result.issues.map((issue, i) => (
                                    <div key={i} style={{
                                        display: 'flex', gap: 10, padding: '8px 12px', borderRadius: 8, marginBottom: 6,
                                        background: issue.level === 'critical' ? 'rgba(239,68,68,0.07)' : 'rgba(249,115,22,0.07)',
                                        border: `1px solid ${issue.level === 'critical' ? 'rgba(239,68,68,0.2)' : 'rgba(249,115,22,0.2)'}`
                                    }}>
                                        {issue.level === 'critical'
                                            ? <XCircle size={14} color="#ef4444" style={{ flexShrink: 0, marginTop: 1 }} />
                                            : <AlertTriangle size={14} color="#f97316" style={{ flexShrink: 0, marginTop: 1 }} />}
                                        <span style={{ fontSize: 12, color: '#cbd5e1', lineHeight: 1.6 }}>{issue.msg}</span>
                                    </div>
                                ))}
                            </div>
                        )}

                        {/* Header details */}
                        <div className="card">
                            <div style={{ fontSize: 12, fontWeight: 700, color: '#f8fafc', marginBottom: 10 }}>Campos Principais</div>
                            {[
                                { label: 'From', value: result.from },
                                { label: 'Reply-To', value: result.replyTo || '(igual ao From)' },
                                { label: 'Return-Path', value: result.returnPath || '(não especificado)' },
                                { label: 'X-Originating-IP', value: result.originatingIp || '(não presente)' },
                                { label: 'X-Mailer', value: result.mailer || '(não especificado)' },
                            ].map(({ label, value }) => (
                                <div key={label} style={{ display: 'flex', gap: 8, padding: '6px 0', borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
                                    <span style={{ fontSize: 11, fontWeight: 600, color: '#64748b', minWidth: 120, flexShrink: 0 }}>{label}</span>
                                    <span style={{ fontSize: 11, fontFamily: "'Fira Code', monospace", color: '#94a3b8', wordBreak: 'break-all' }}>{value}</span>
                                </div>
                            ))}
                        </div>

                        {/* IPs found */}
                        {result.ips.length > 0 && (
                            <div className="card">
                                <div style={{ fontSize: 12, fontWeight: 700, color: '#f8fafc', marginBottom: 10 }}>
                                    IPs Extraídos da Rota ({result.ips.length})
                                </div>
                                {result.ips.map(ip => (
                                    <div key={ip} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '8px 0', borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
                                        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                                            <Globe size={12} color="#64748b" />
                                            <span style={{ fontSize: 12, fontFamily: "'Fira Code', monospace", color: '#06b6d4' }}>{ip}</span>
                                        </div>
                                        <div style={{ display: 'flex', gap: 6 }}>
                                            <a href={`https://www.virustotal.com/gui/ip-address/${ip}`} target="_blank" rel="noopener noreferrer" className="btn-ghost" style={{ fontSize: 11, padding: '3px 8px' }}>VT<ExternalLink size={10} /></a>
                                            <a href={`https://www.abuseipdb.com/check/${ip}`} target="_blank" rel="noopener noreferrer" className="btn-ghost" style={{ fontSize: 11, padding: '3px 8px' }}>Abuse<ExternalLink size={10} /></a>
                                        </div>
                                    </div>
                                ))}
                            </div>
                        )}
                    </div>
                )}
            </div>
        </div>
    );
}
