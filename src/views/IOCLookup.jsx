import React, { useState, useEffect, useCallback } from 'react';
import { useSearchParams } from 'react-router-dom';
import {
    Search, Globe, Hash, Link2, ExternalLink, RefreshCw,
    Copy, Shield, Settings, X, Eye, EyeOff, AlertTriangle,
    CheckCircle2, HelpCircle, Loader
} from 'lucide-react';
import {
    loadApiKeys, saveApiKeys,
    fetchIPInfo, fetchAbuseIPDB, fetchVirusTotalIP, fetchVirusTotalHash,
    fetchVirusTotalDomain, fetchNVDCve, calcVerdict
} from '../services/threatIntelApi';

// ─── Helpers ─────────────────────────────────────────────────────────────────
function detectType(v) {
    if (!v) return null;
    const val = v.trim();
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(val)) return 'ip';
    if (/^[a-f0-9]{32}$/i.test(val)) return 'hash';
    if (/^[a-f0-9]{40}$/i.test(val)) return 'hash';
    if (/^[a-f0-9]{64}$/i.test(val)) return 'hash';
    if (/^CVE-\d{4}-\d{4,}/i.test(val)) return 'cve';
    if (/^https?:\/\//i.test(val)) return 'url';
    if (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(val)) return 'domain';
    return null;
}

function fmt(n) { return n === undefined || n === null ? '—' : String(n); }

// ─── API Settings Modal ───────────────────────────────────────────────────────
function SettingsModal({ onClose }) {
    const [keys, setKeys] = useState(loadApiKeys);
    const [show, setShow] = useState({});

    const save = () => { saveApiKeys(keys); onClose(); };

    const fields = [
        { id: 'abuseipdb', label: 'AbuseIPDB', hint: 'abuseipdb.com → Account → API', free: true },
        { id: 'virustotal', label: 'VirusTotal', hint: 'virustotal.com → Profile → API Key', free: true },
    ];

    return (
        <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.7)', zIndex: 1000, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <div style={{ background: '#0f172a', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 16, width: 480, padding: 28, maxWidth: '95vw' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
                    <div>
                        <div style={{ fontSize: 16, fontWeight: 800, color: '#f8fafc' }}>🔑 Configurar API Keys</div>
                        <div style={{ fontSize: 12, color: '#64748b', marginTop: 4 }}>Chaves salvas localmente (localStorage). Nunca enviadas a nenhum servidor.</div>
                    </div>
                    <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#64748b' }}><X size={18} /></button>
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: 16, marginBottom: 24 }}>
                    {fields.map(f => (
                        <div key={f.id}>
                            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
                                <label style={{ fontSize: 13, fontWeight: 600, color: '#cbd5e1' }}>{f.label}</label>
                                {f.free && <span style={{ fontSize: 10, background: 'rgba(34,197,94,0.1)', color: '#22c55e', border: '1px solid rgba(34,197,94,0.2)', borderRadius: 4, padding: '1px 6px' }}>GRÁTIS</span>}
                            </div>
                            <div style={{ position: 'relative' }}>
                                <input
                                    type={show[f.id] ? 'text' : 'password'}
                                    value={keys[f.id] || ''}
                                    onChange={e => setKeys(k => ({ ...k, [f.id]: e.target.value }))}
                                    placeholder={`Cole sua API Key do ${f.label}...`}
                                    style={{ width: '100%', background: '#1e293b', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 8, color: '#f8fafc', padding: '9px 40px 9px 12px', fontSize: 12, fontFamily: "'Fira Code', monospace", outline: 'none', boxSizing: 'border-box' }}
                                />
                                <button onClick={() => setShow(s => ({ ...s, [f.id]: !s[f.id] }))}
                                    style={{ position: 'absolute', right: 10, top: '50%', transform: 'translateY(-50%)', background: 'none', border: 'none', cursor: 'pointer', color: '#64748b' }}>
                                    {show[f.id] ? <EyeOff size={14} /> : <Eye size={14} />}
                                </button>
                            </div>
                            <div style={{ fontSize: 11, color: '#475569', marginTop: 4 }}>👉 {f.hint}</div>
                        </div>
                    ))}
                </div>

                <div style={{ background: 'rgba(6,182,212,0.06)', border: '1px solid rgba(6,182,212,0.15)', borderRadius: 8, padding: '10px 14px', marginBottom: 20, fontSize: 12, color: '#94a3b8', lineHeight: 1.6 }}>
                    💡 Sem chaves: o IOC Lookup mostra geolocalização gratuita (ipinfo.io) e links externos.<br />
                    Com chaves: busca em tempo real com dados completos de cada plataforma.
                </div>

                <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end' }}>
                    <button onClick={onClose} className="btn-ghost" style={{ fontSize: 13 }}>Cancelar</button>
                    <button onClick={save} className="btn-primary" style={{ fontSize: 13 }}>Salvar Chaves</button>
                </div>
            </div>
        </div>
    );
}

// ─── Service Card ─────────────────────────────────────────────────────────────
function ServiceCard({ name, icon, status, data, linkUrl, children, loading }) {
    const statusCfg = {
        ok: { color: '#22c55e', label: 'Dados obtidos' },
        no_key: { color: '#64748b', label: 'API Key não configurada' },
        error: { color: '#f97316', label: 'Erro na consulta' },
        cors_error: { color: '#f97316', label: 'CORS bloqueado' },
        not_found: { color: '#94a3b8', label: 'Não encontrado' },
        loading: { color: '#06b6d4', label: 'Consultando...' },
    }[loading ? 'loading' : status] || { color: '#64748b', label: status };

    return (
        <div style={{ background: 'rgba(255,255,255,0.03)', border: `1px solid rgba(255,255,255,0.08)`, borderRadius: 12, padding: 16, transition: 'border-color 0.2s' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <span style={{ fontSize: 16 }}>{icon}</span>
                    <span style={{ fontSize: 14, fontWeight: 700, color: '#f8fafc' }}>{name}</span>
                    <span style={{ fontSize: 10, color: statusCfg.color, background: `${statusCfg.color}15`, border: `1px solid ${statusCfg.color}30`, borderRadius: 4, padding: '1px 6px' }}>
                        {loading ? <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}><Loader size={9} style={{ animation: 'spin 1s linear infinite' }} /> Consultando</span> : statusCfg.label}
                    </span>
                </div>
                {linkUrl && (
                    <a href={linkUrl} target="_blank" rel="noopener noreferrer"
                        style={{ fontSize: 11, color: '#475569', display: 'flex', alignItems: 'center', gap: 4, textDecoration: 'none' }}
                        onMouseEnter={e => e.currentTarget.style.color = '#06b6d4'}
                        onMouseLeave={e => e.currentTarget.style.color = '#475569'}>
                        Ver no site <ExternalLink size={11} />
                    </a>
                )}
            </div>

            {loading && (
                <div style={{ height: 40, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                    <Loader size={16} color="#06b6d4" style={{ animation: 'spin 1s linear infinite' }} />
                </div>
            )}

            {!loading && status === 'no_key' && (
                <div style={{ fontSize: 12, color: '#475569', display: 'flex', alignItems: 'center', gap: 6 }}>
                    <HelpCircle size={13} />
                    Configure uma API Key gratuita para ativar esta fonte de dados.
                </div>
            )}

            {!loading && (status === 'error' || status === 'cors_error') && data?.error && (
                <div style={{ fontSize: 12, color: '#f97316', display: 'flex', alignItems: 'center', gap: 6 }}>
                    <AlertTriangle size={13} /> {data.error}
                </div>
            )}

            {!loading && status === 'not_found' && (
                <div style={{ fontSize: 12, color: '#64748b' }}>Nenhum registro encontrado para este indicador.</div>
            )}

            {!loading && status === 'ok' && children}
        </div>
    );
}

// ─── Verdict Banner ───────────────────────────────────────────────────────────
function VerdictBanner({ verdict, vtData, abuseData, hasAnyData }) {
    if (!hasAnyData) return null;
    const { label, color, icon } = verdict;
    const abuseConf = abuseData?.abuseConfidenceScore;
    const abuseRep = abuseData?.totalReports;
    const vtMal = vtData?.last_analysis_stats?.malicious;
    const vtSus = vtData?.last_analysis_stats?.suspicious;
    const vtTotal = Object.values(vtData?.last_analysis_stats || {}).reduce((a, b) => a + b, 0);

    return (
        <div style={{
            background: `${color}10`, border: `2px solid ${color}40`,
            borderRadius: 12, padding: '16px 20px', marginBottom: 20,
            display: 'flex', alignItems: 'center', gap: 16, flexWrap: 'wrap'
        }}>
            <div style={{ fontSize: 36 }}>{icon}</div>
            <div style={{ flex: 1 }}>
                <div style={{ fontSize: 20, fontWeight: 900, color }}>{label}</div>
                <div style={{ fontSize: 13, color: '#94a3b8', marginTop: 4 }}>
                    {verdict.verdict === 'clean' && 'Nenhuma ameaça detectada nas fontes consultadas. Ainda assim, utilize com cautela.'}
                    {verdict.verdict === 'suspicious' && '⚠️ Atividade suspeita detectada. Revise os detalhes abaixo antes de confiar neste indicador.'}
                    {verdict.verdict === 'malicious' && '🚨 Indicador confirmado como malicioso. Bloqueie imediatamente e investigue os sistemas associados.'}
                    {verdict.verdict === 'unknown' && 'Configure API Keys para obter veredicto baseado em dados reais.'}
                </div>
            </div>
            <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
                {abuseConf !== undefined && (
                    <div style={{ textAlign: 'center', background: 'rgba(0,0,0,0.2)', borderRadius: 8, padding: '8px 14px' }}>
                        <div style={{ fontSize: 22, fontWeight: 900, color: abuseConf > 60 ? '#ef4444' : abuseConf > 20 ? '#f97316' : '#22c55e' }}>{abuseConf}%</div>
                        <div style={{ fontSize: 10, color: '#64748b' }}>AbuseIPDB Score</div>
                        <div style={{ fontSize: 11, color: '#94a3b8' }}>{abuseRep} reports</div>
                    </div>
                )}
                {vtMal !== undefined && (
                    <div style={{ textAlign: 'center', background: 'rgba(0,0,0,0.2)', borderRadius: 8, padding: '8px 14px' }}>
                        <div style={{ fontSize: 22, fontWeight: 900, color: vtMal > 2 ? '#ef4444' : vtMal > 0 ? '#f97316' : '#22c55e' }}>{vtMal}/{vtTotal}</div>
                        <div style={{ fontSize: 10, color: '#64748b' }}>VirusTotal Engines</div>
                        <div style={{ fontSize: 11, color: '#94a3b8' }}>{vtSus} suspeitas</div>
                    </div>
                )}
            </div>
        </div>
    );
}

// ─── IP Result ────────────────────────────────────────────────────────────────
function IPResult({ query, results, loading, onOpenSettings }) {
    const { ipInfo, abuseipdb, virustotal } = results;
    const vtAttrs = virustotal?.data;
    const abuseAttrs = abuseipdb?.data;
    const ipAttrs = ipInfo?.data;

    const hasAnyData = !!(ipAttrs || vtAttrs || abuseAttrs);
    const verdict = calcVerdict(vtAttrs, abuseAttrs, ipAttrs);

    return (
        <div className="animate-slide-in-up">
            {/* Header */}
            <div style={{ marginBottom: 16, display: 'flex', alignItems: 'center', gap: 12 }}>
                <Globe size={18} color="#64748b" />
                <span style={{ fontSize: 22, fontWeight: 900, fontFamily: "'Fira Code', monospace", color: '#f8fafc' }}>{query}</span>
                <button onClick={() => navigator.clipboard?.writeText(query)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#64748b' }} title="Copiar"><Copy size={13} /></button>
                {ipAttrs?.country && <span style={{ fontSize: 12, color: '#94a3b8' }}>· {ipAttrs.country} · {ipAttrs.org}</span>}
            </div>

            {/* Geo info grátis */}
            {ipAttrs && !ipAttrs.bogon && (
                <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 16 }}>
                    {[
                        { l: 'País', v: ipAttrs.country },
                        { l: 'Cidade', v: ipAttrs.city },
                        { l: 'Região', v: ipAttrs.region },
                        { l: 'ISP/Org', v: ipAttrs.org },
                        { l: 'Hostname', v: ipAttrs.hostname },
                        { l: 'Timezone', v: ipAttrs.timezone },
                    ].filter(x => x.v).map(({ l, v }) => (
                        <div key={l} style={{ background: 'rgba(255,255,255,0.04)', borderRadius: 8, padding: '6px 12px' }}>
                            <div style={{ fontSize: 10, color: '#64748b' }}>{l}</div>
                            <div style={{ fontSize: 12, color: '#94a3b8', fontFamily: "'Fira Code', monospace" }}>{v}</div>
                        </div>
                    ))}
                </div>
            )}

            {ipAttrs?.bogon && (
                <div style={{ background: 'rgba(34,197,94,0.08)', border: '1px solid rgba(34,197,94,0.2)', borderRadius: 8, padding: '10px 14px', marginBottom: 16, fontSize: 13, color: '#22c55e' }}>
                    ✅ IP privado/reservado (RFC 1918/bogon) — não roteável na internet pública.
                </div>
            )}

            {/* Verdict */}
            <VerdictBanner verdict={verdict} vtData={vtAttrs} abuseData={abuseAttrs} hasAnyData={hasAnyData} />

            {/* Service Cards */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>

                {/* AbuseIPDB */}
                <ServiceCard name="AbuseIPDB" icon="🚨" status={abuseipdb?.status} data={abuseipdb}
                    linkUrl={`https://www.abuseipdb.com/check/${query}`} loading={loading.abuseipdb}>
                    {abuseAttrs && (
                        <div>
                            <div style={{ display: 'flex', gap: 16, marginBottom: 12, flexWrap: 'wrap' }}>
                                <div>
                                    <div style={{ fontSize: 28, fontWeight: 900, color: abuseAttrs.abuseConfidenceScore > 60 ? '#ef4444' : abuseAttrs.abuseConfidenceScore > 20 ? '#f97316' : '#22c55e' }}>
                                        {abuseAttrs.abuseConfidenceScore}%
                                    </div>
                                    <div style={{ fontSize: 11, color: '#64748b' }}>Confidence Score</div>
                                </div>
                                <div>
                                    <div style={{ fontSize: 28, fontWeight: 900, color: abuseAttrs.totalReports > 0 ? '#f97316' : '#22c55e' }}>{abuseAttrs.totalReports}</div>
                                    <div style={{ fontSize: 11, color: '#64748b' }}>Reports (90 dias)</div>
                                </div>
                                <div>
                                    <div style={{ fontSize: 28, fontWeight: 900, color: '#94a3b8' }}>{abuseAttrs.numDistinctUsers || 0}</div>
                                    <div style={{ fontSize: 11, color: '#64748b' }}>Usuários distintos</div>
                                </div>
                            </div>
                            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 8 }}>
                                {[
                                    { l: 'País', v: abuseAttrs.countryCode },
                                    { l: 'ISP', v: abuseAttrs.isp },
                                    { l: 'Uso', v: abuseAttrs.usageType },
                                    { l: 'Domínio', v: abuseAttrs.domain },
                                    { l: 'Último report', v: abuseAttrs.lastReportedAt ? new Date(abuseAttrs.lastReportedAt).toLocaleDateString('pt-BR') : null },
                                    { l: 'Whitelisted', v: abuseAttrs.isWhitelisted ? '✅ Sim' : '❌ Não' },
                                ].map(({ l, v }) => (
                                    <div key={l} style={{ background: 'rgba(255,255,255,0.03)', borderRadius: 6, padding: '7px 10px' }}>
                                        <div style={{ fontSize: 10, color: '#64748b' }}>{l}</div>
                                        <div style={{ fontSize: 11, color: '#94a3b8', fontFamily: "'Fira Code', monospace", wordBreak: 'break-all' }}>{fmt(v)}</div>
                                    </div>
                                ))}
                            </div>
                            {abuseAttrs.totalReports === 0 && (
                                <div style={{ marginTop: 10, fontSize: 12, color: '#22c55e', display: 'flex', alignItems: 'center', gap: 6 }}>
                                    <CheckCircle2 size={13} /> Nenhum report nos últimos 90 dias.
                                </div>
                            )}
                            {abuseAttrs.totalReports > 0 && (
                                <div style={{ marginTop: 10, fontSize: 12, color: '#f97316', display: 'flex', alignItems: 'center', gap: 6 }}>
                                    <AlertTriangle size={13} /> {abuseAttrs.totalReports} reporte(s) recebido(s). Use com cautela.
                                </div>
                            )}
                        </div>
                    )}
                </ServiceCard>

                {/* VirusTotal */}
                <ServiceCard name="VirusTotal" icon="🦠" status={virustotal?.status} data={virustotal}
                    linkUrl={`https://www.virustotal.com/gui/ip-address/${query}`} loading={loading.virustotal}>
                    {vtAttrs && (
                        <div>
                            <div style={{ display: 'flex', gap: 16, marginBottom: 12, flexWrap: 'wrap' }}>
                                {Object.entries(vtAttrs.last_analysis_stats || {}).map(([k, v]) => {
                                    const colors = { malicious: '#ef4444', suspicious: '#f97316', harmless: '#22c55e', undetected: '#64748b', timeout: '#94a3b8' };
                                    const labels = { malicious: 'Maliciosas', suspicious: 'Suspeitas', harmless: 'Limpas', undetected: 'Não detectadas', timeout: 'Timeout' };
                                    return (
                                        <div key={k} style={{ textAlign: 'center' }}>
                                            <div style={{ fontSize: 22, fontWeight: 900, color: colors[k] || '#94a3b8' }}>{v}</div>
                                            <div style={{ fontSize: 10, color: '#64748b' }}>{labels[k] || k}</div>
                                        </div>
                                    );
                                })}
                            </div>
                            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 8 }}>
                                {[
                                    { l: 'País', v: vtAttrs.country },
                                    { l: 'AS Owner', v: vtAttrs.as_owner },
                                    { l: 'Reputação', v: fmt(vtAttrs.reputation) },
                                    { l: 'Network', v: vtAttrs.network },
                                    { l: 'Continente', v: vtAttrs.continent },
                                    { l: 'Últ. Análise', v: vtAttrs.last_analysis_date ? new Date(vtAttrs.last_analysis_date * 1000).toLocaleDateString('pt-BR') : null },
                                ].map(({ l, v }) => (
                                    <div key={l} style={{ background: 'rgba(255,255,255,0.03)', borderRadius: 6, padding: '7px 10px' }}>
                                        <div style={{ fontSize: 10, color: '#64748b' }}>{l}</div>
                                        <div style={{ fontSize: 11, color: '#94a3b8', fontFamily: "'Fira Code', monospace", wordBreak: 'break-all' }}>{fmt(v)}</div>
                                    </div>
                                ))}
                            </div>
                        </div>
                    )}
                </ServiceCard>

                {/* ipinfo.io — sempre presente */}
                <ServiceCard name="IPInfo.io" icon="🌐" status={ipInfo?.status || 'ok'} data={ipInfo}
                    linkUrl={`https://ipinfo.io/${query}`} loading={loading.ipInfo}>
                    {ipAttrs && !ipAttrs.isPrivate && (
                        <div style={{ fontSize: 12, color: '#64748b' }}>
                            Dados básicos de geolocalização gratuitos (sem threat intel). Use AbuseIPDB/VirusTotal para reputação.
                        </div>
                    )}
                </ServiceCard>

                {/* Links externos sempre disponíveis */}
                <div style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 12, padding: '12px 16px' }}>
                    <div style={{ fontSize: 11, fontWeight: 700, color: '#475569', marginBottom: 10, textTransform: 'uppercase', letterSpacing: '0.05em' }}>🔗 Verificar também</div>
                    <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                        {[
                            { n: 'IBM X-Force', u: `https://exchange.xforce.ibmcloud.com/ip/${query}` },
                            { n: 'Shodan', u: `https://www.shodan.io/host/${query}` },
                            { n: 'URLScan.io', u: `https://urlscan.io/search/#ip%3A${query}` },
                            { n: 'GreyNoise', u: `https://www.greynoise.io/viz/ip/${query}` },
                            { n: 'Talos', u: `https://talosintelligence.com/reputation_center/lookup?search=${query}` },
                        ].map(({ n, u }) => (
                            <a key={n} href={u} target="_blank" rel="noopener noreferrer" className="btn-ghost" style={{ fontSize: 12 }}>
                                {n} <ExternalLink size={11} />
                            </a>
                        ))}
                    </div>
                </div>
            </div>
        </div>
    );
}

// ─── Hash Result ──────────────────────────────────────────────────────────────
function HashResult({ query, results, loading }) {
    const vtAttrs = results.virustotal?.data;
    const vtMal = vtAttrs?.last_analysis_stats?.malicious || 0;
    const vtTotal = Object.values(vtAttrs?.last_analysis_stats || {}).reduce((a, b) => a + b, 0);
    const verdict = calcVerdict(vtAttrs, null, null);

    return (
        <div className="animate-slide-in-up">
            <div style={{ marginBottom: 16, display: 'flex', alignItems: 'center', gap: 12 }}>
                <Hash size={18} color="#64748b" />
                <span style={{ fontSize: 14, fontWeight: 700, fontFamily: "'Fira Code', monospace", color: '#06b6d4', wordBreak: 'break-all' }}>{query}</span>
                <button onClick={() => navigator.clipboard?.writeText(query)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#64748b' }} title="Copiar"><Copy size={13} /></button>
            </div>

            {vtAttrs && <VerdictBanner verdict={verdict} vtData={vtAttrs} hasAnyData={true} />}

            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                <ServiceCard name="VirusTotal" icon="🦠" status={results.virustotal?.status} data={results.virustotal}
                    linkUrl={`https://www.virustotal.com/gui/file/${query}`} loading={loading.virustotal}>
                    {vtAttrs && (
                        <div>
                            <div style={{ display: 'flex', gap: 20, marginBottom: 14, flexWrap: 'wrap' }}>
                                <div>
                                    <div style={{ fontSize: 32, fontWeight: 900, color: vtMal > 10 ? '#ef4444' : vtMal > 0 ? '#f97316' : '#22c55e' }}>{vtMal}/{vtTotal}</div>
                                    <div style={{ fontSize: 11, color: '#64748b' }}>Engines detectaram</div>
                                </div>
                                {vtAttrs.reputation !== undefined && (
                                    <div>
                                        <div style={{ fontSize: 32, fontWeight: 900, color: vtAttrs.reputation < 0 ? '#ef4444' : '#22c55e' }}>{vtAttrs.reputation}</div>
                                        <div style={{ fontSize: 11, color: '#64748b' }}>Community Score</div>
                                    </div>
                                )}
                            </div>
                            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 8 }}>
                                {[
                                    { l: 'Nome', v: vtAttrs.meaningful_name || vtAttrs.name },
                                    { l: 'Tipo', v: vtAttrs.type_description },
                                    { l: 'Tamanho', v: vtAttrs.size ? `${Math.round(vtAttrs.size / 1024)} KB` : null },
                                    { l: 'SHA256', v: vtAttrs.sha256 },
                                    { l: 'MD5', v: vtAttrs.md5 },
                                    { l: 'SHA1', v: vtAttrs.sha1 },
                                ].map(({ l, v }) => (
                                    <div key={l} style={{ background: 'rgba(255,255,255,0.03)', borderRadius: 6, padding: '7px 10px' }}>
                                        <div style={{ fontSize: 10, color: '#64748b' }}>{l}</div>
                                        <div style={{ fontSize: 11, color: '#94a3b8', fontFamily: "'Fira Code', monospace", wordBreak: 'break-all' }}>{fmt(v)}</div>
                                    </div>
                                ))}
                            </div>
                            {vtAttrs.popular_threat_classification?.popular_threat_name && (
                                <div style={{ marginTop: 10 }}>
                                    <span style={{ fontSize: 11, background: 'rgba(239,68,68,0.1)', color: '#f87171', border: '1px solid rgba(239,68,68,0.2)', borderRadius: 4, padding: '2px 8px' }}>
                                        {vtAttrs.popular_threat_classification.popular_threat_name.map(t => t.value).join(', ')}
                                    </span>
                                </div>
                            )}
                        </div>
                    )}
                </ServiceCard>

                <div style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 12, padding: '12px 16px' }}>
                    <div style={{ fontSize: 11, fontWeight: 700, color: '#475569', marginBottom: 10, textTransform: 'uppercase', letterSpacing: '0.05em' }}>🔗 Verificar também</div>
                    <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                        {[
                            { n: 'Hybrid Analysis', u: `https://www.hybrid-analysis.com/search?query=${query}` },
                            { n: 'Any.run', u: `https://app.any.run/tasks/?hash=${query}` },
                            { n: 'MalwareBazaar', u: `https://bazaar.abuse.ch/browse.php?search=sha256_hash:${query}` },
                            { n: 'Triage', u: `https://tria.ge/s?q=${query}` },
                        ].map(({ n, u }) => (
                            <a key={n} href={u} target="_blank" rel="noopener noreferrer" className="btn-ghost" style={{ fontSize: 12 }}>{n} <ExternalLink size={11} /></a>
                        ))}
                    </div>
                </div>
            </div>
        </div>
    );
}

// ─── Domain Result ────────────────────────────────────────────────────────────
function DomainResult({ query, results, loading }) {
    const vtAttrs = results.virustotal?.data;
    const verdict = calcVerdict(vtAttrs, null, null);

    return (
        <div className="animate-slide-in-up">
            <div style={{ marginBottom: 16, display: 'flex', alignItems: 'center', gap: 12 }}>
                <Link2 size={18} color="#64748b" />
                <span style={{ fontSize: 20, fontWeight: 900, fontFamily: "'Fira Code', monospace", color: '#f8fafc' }}>{query}</span>
                <button onClick={() => navigator.clipboard?.writeText(query)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#64748b' }}><Copy size={13} /></button>
            </div>

            {vtAttrs && <VerdictBanner verdict={verdict} vtData={vtAttrs} hasAnyData={true} />}

            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                <ServiceCard name="VirusTotal" icon="🦠" status={results.virustotal?.status} data={results.virustotal}
                    linkUrl={`https://www.virustotal.com/gui/domain/${query}`} loading={loading.virustotal}>
                    {vtAttrs && (
                        <div>
                            <div style={{ display: 'flex', gap: 20, marginBottom: 12, flexWrap: 'wrap' }}>
                                {Object.entries(vtAttrs.last_analysis_stats || {}).map(([k, v]) => {
                                    const colors = { malicious: '#ef4444', suspicious: '#f97316', harmless: '#22c55e', undetected: '#64748b' };
                                    const labels = { malicious: 'Maliciosas', suspicious: 'Suspeitas', harmless: 'Limpas', undetected: 'Não detectadas' };
                                    return (
                                        <div key={k} style={{ textAlign: 'center' }}>
                                            <div style={{ fontSize: 22, fontWeight: 900, color: colors[k] || '#94a3b8' }}>{v}</div>
                                            <div style={{ fontSize: 10, color: '#64748b' }}>{labels[k] || k}</div>
                                        </div>
                                    );
                                })}
                            </div>
                            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
                                {[
                                    { l: 'Registrador', v: vtAttrs.registrar },
                                    { l: 'Criação', v: vtAttrs.creation_date ? new Date(vtAttrs.creation_date * 1000).toLocaleDateString('pt-BR') : null },
                                    { l: 'Reputação VT', v: fmt(vtAttrs.reputation) },
                                    { l: 'Categorias', v: Object.values(vtAttrs.categories || {}).slice(0, 3).join(', ') },
                                ].map(({ l, v }) => (
                                    <div key={l} style={{ background: 'rgba(255,255,255,0.03)', borderRadius: 6, padding: '7px 10px' }}>
                                        <div style={{ fontSize: 10, color: '#64748b' }}>{l}</div>
                                        <div style={{ fontSize: 11, color: '#94a3b8', fontFamily: "'Fira Code', monospace", wordBreak: 'break-all' }}>{fmt(v)}</div>
                                    </div>
                                ))}
                            </div>
                        </div>
                    )}
                </ServiceCard>

                <div style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 12, padding: '12px 16px' }}>
                    <div style={{ fontSize: 11, fontWeight: 700, color: '#475569', marginBottom: 10 }}>🔗 Verificar também</div>
                    <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                        {[
                            { n: 'URLScan.io', u: `https://urlscan.io/search/#domain:${query}` },
                            { n: 'IBM X-Force', u: `https://exchange.xforce.ibmcloud.com/url/${query}` },
                            { n: 'WHOIS', u: `https://who.is/whois/${query}` },
                            { n: 'Shodan', u: `https://www.shodan.io/search?query=hostname:${query}` },
                        ].map(({ n, u }) => (
                            <a key={n} href={u} target="_blank" rel="noopener noreferrer" className="btn-ghost" style={{ fontSize: 12 }}>{n} <ExternalLink size={11} /></a>
                        ))}
                    </div>
                </div>
            </div>
        </div>
    );
}

// ─── CVE Result ───────────────────────────────────────────────────────────────
function CveResult({ query, results, loading }) {
    const d = results.nvd?.data;
    const cvss = d?.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore
        || d?.metrics?.cvssMetricV30?.[0]?.cvssData?.baseScore
        || d?.metrics?.cvssMetricV2?.[0]?.cvssData?.baseScore;
    const severity = d?.metrics?.cvssMetricV31?.[0]?.cvssData?.baseSeverity
        || d?.metrics?.cvssMetricV30?.[0]?.cvssData?.baseSeverity || '';
    const cvssColor = cvss >= 9 ? '#ef4444' : cvss >= 7 ? '#f97316' : cvss >= 4 ? '#eab308' : '#22c55e';
    const desc = d?.descriptions?.find(x => x.lang === 'en')?.value || '';

    return (
        <div className="animate-slide-in-up">
            <div style={{ marginBottom: 16, display: 'flex', alignItems: 'center', gap: 12 }}>
                <Shield size={18} color="#64748b" />
                <span style={{ fontSize: 22, fontWeight: 900, fontFamily: "'Fira Code', monospace", color: '#f8fafc' }}>{query}</span>
            </div>

            <ServiceCard name="NIST NVD (National Vulnerability Database)" icon="⚠️"
                status={results.nvd?.status} data={results.nvd}
                linkUrl={`https://nvd.nist.gov/vuln/detail/${query}`} loading={loading.nvd}>
                {d && (
                    <div>
                        <div style={{ display: 'flex', gap: 16, marginBottom: 16, alignItems: 'flex-start' }}>
                            {cvss !== undefined && (
                                <div style={{ textAlign: 'center', flexShrink: 0 }}>
                                    <div style={{ fontSize: 36, fontWeight: 900, color: cvssColor }}>{cvss}</div>
                                    <div style={{ fontSize: 10, color: '#64748b' }}>CVSSv3</div>
                                    <span style={{ fontSize: 11, background: `${cvssColor}18`, color: cvssColor, border: `1px solid ${cvssColor}30`, borderRadius: 4, padding: '1px 8px', fontWeight: 700 }}>{severity}</span>
                                </div>
                            )}
                            <p style={{ fontSize: 13, color: '#94a3b8', lineHeight: 1.7, flex: 1 }}>{desc}</p>
                        </div>
                        <div style={{ display: 'flex', gap: 8, marginTop: 12 }}>
                            <a href={`https://nvd.nist.gov/vuln/detail/${query}`} target="_blank" rel="noopener noreferrer" className="btn-ghost" style={{ fontSize: 12 }}>NIST NVD <ExternalLink size={11} /></a>
                            <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" target="_blank" rel="noopener noreferrer" className="btn-ghost" style={{ fontSize: 12 }}>CISA KEV <ExternalLink size={11} /></a>
                            <a href={`https://www.exploit-db.com/search?cve=${query}`} target="_blank" rel="noopener noreferrer" className="btn-ghost" style={{ fontSize: 12 }}>Exploit-DB <ExternalLink size={11} /></a>
                        </div>
                    </div>
                )}
            </ServiceCard>
        </div>
    );
}

// ─── Main Component ───────────────────────────────────────────────────────────
export default function IOCLookup() {
    const [searchParams] = useSearchParams();
    const [query, setQuery] = useState(searchParams.get('q') || '');
    const [submitted, setSubmitted] = useState('');
    const [results, setResults] = useState({});
    const [loading, setLoading] = useState({});
    const [showSettings, setShowSettings] = useState(false);
    const [apiKeys, setApiKeys] = useState(loadApiKeys);

    const type = detectType(submitted);

    const doLookup = useCallback(async (val) => {
        if (!val?.trim()) return;
        const ioc = val.trim();
        const t = detectType(ioc);
        const keys = loadApiKeys();
        setApiKeys(keys);
        setResults({});
        setSubmitted(ioc);

        if (t === 'ip') {
            // Busca paralela em todas as fontes
            setLoading({ ipInfo: true, abuseipdb: true, virustotal: true });

            // ipinfo.io - grátis, sem key
            fetchIPInfo(ioc).then(r => {
                setResults(prev => ({ ...prev, ipInfo: r }));
                setLoading(prev => ({ ...prev, ipInfo: false }));
            });

            // AbuseIPDB
            fetchAbuseIPDB(ioc, keys.abuseipdb).then(r => {
                setResults(prev => ({ ...prev, abuseipdb: r }));
                setLoading(prev => ({ ...prev, abuseipdb: false }));
            });

            // VirusTotal
            fetchVirusTotalIP(ioc, keys.virustotal).then(r => {
                setResults(prev => ({ ...prev, virustotal: r }));
                setLoading(prev => ({ ...prev, virustotal: false }));
            });
        }

        if (t === 'hash') {
            setLoading({ virustotal: true });
            fetchVirusTotalHash(ioc, keys.virustotal).then(r => {
                setResults(prev => ({ ...prev, virustotal: r }));
                setLoading(prev => ({ ...prev, virustotal: false }));
            });
        }

        if (t === 'domain') {
            setLoading({ virustotal: true });
            fetchVirusTotalDomain(ioc, keys.virustotal).then(r => {
                setResults(prev => ({ ...prev, virustotal: r }));
                setLoading(prev => ({ ...prev, virustotal: false }));
            });
        }

        if (t === 'cve') {
            setLoading({ nvd: true });
            fetchNVDCve(ioc).then(r => {
                setResults(prev => ({ ...prev, nvd: r }));
                setLoading(prev => ({ ...prev, nvd: false }));
            });
        }
    }, []);

    const handleSubmit = (e) => {
        e?.preventDefault();
        if (!query.trim()) return;
        doLookup(query.trim());
    };

    const hasKeys = apiKeys.virustotal || apiKeys.abuseipdb;

    return (
        <div className="animate-fade-in">
            {showSettings && <SettingsModal onClose={() => { setShowSettings(false); setApiKeys(loadApiKeys()); }} />}

            {/* Header */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 20 }}>
                <div>
                    <h1 style={{ fontSize: 22, fontWeight: 800, color: '#f8fafc', letterSpacing: -0.5 }}>IOC Lookup</h1>
                    <p style={{ fontSize: 13, color: '#64748b', marginTop: 4 }}>
                        Busca em tempo real: AbuseIPDB · VirusTotal · IPInfo · NVD · + links externos
                    </p>
                </div>
                <button onClick={() => setShowSettings(true)} className={hasKeys ? 'btn-ghost' : 'btn-primary'}
                    style={{ fontSize: 12, display: 'flex', alignItems: 'center', gap: 6 }}>
                    <Settings size={13} />
                    {hasKeys ? 'API Keys configuradas ✓' : 'Configurar API Keys'}
                </button>
            </div>

            {/* API key notice */}
            {!hasKeys && (
                <div style={{ background: 'rgba(234,179,8,0.08)', border: '1px solid rgba(234,179,8,0.2)', borderRadius: 10, padding: '10px 16px', marginBottom: 16, display: 'flex', alignItems: 'center', gap: 10 }}>
                    <AlertTriangle size={14} color="#eab308" />
                    <span style={{ fontSize: 12, color: '#94a3b8' }}>
                        Sem API Keys: apenas geolocalização gratuita (ipinfo.io) e links externos.{' '}
                        <button onClick={() => setShowSettings(true)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#eab308', fontSize: 12, textDecoration: 'underline' }}>
                            Configurar agora (grátis)
                        </button>
                    </span>
                </div>
            )}

            {/* Search */}
            <form onSubmit={handleSubmit} style={{ display: 'flex', gap: 10, marginBottom: 12, maxWidth: 680 }}>
                <div style={{ position: 'relative', flex: 1 }}>
                    <Search size={15} style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', color: '#64748b' }} />
                    <input className="search-input" style={{ width: '100%', paddingLeft: 36, fontSize: 13, boxSizing: 'border-box' }}
                        placeholder="IP, Hash MD5/SHA256, domínio, CVE-XXXX-XXXX..."
                        value={query} onChange={e => setQuery(e.target.value)} />
                </div>
                <button type="submit" className="btn-primary">Analisar</button>
            </form>

            {/* Quick examples */}
            <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginBottom: 24, alignItems: 'center' }}>
                <span style={{ fontSize: 11, color: '#475569' }}>Testar:</span>
                {[
                    { label: '77.32.148.44', v: '77.32.148.44' },
                    { label: '8.8.8.8 (Google DNS)', v: '8.8.8.8' },
                    { label: '185.220.101.47', v: '185.220.101.47' },
                    { label: 'CVE-2024-21887', v: 'CVE-2024-21887' },
                ].map(({ label, v }) => (
                    <button key={v} onClick={() => { setQuery(v); doLookup(v); }}
                        style={{ fontSize: 11, background: 'rgba(255,255,255,0.04)', color: '#94a3b8', border: '1px solid rgba(255,255,255,0.07)', borderRadius: 6, padding: '4px 10px', cursor: 'pointer', transition: 'color 0.15s' }}
                        onMouseEnter={e => e.target.style.color = '#06b6d4'}
                        onMouseLeave={e => e.target.style.color = '#94a3b8'}>{label}
                    </button>
                ))}
            </div>

            {/* Detected type */}
            {submitted && type && (
                <div style={{ marginBottom: 12, fontSize: 12, color: '#64748b' }}>
                    Tipo detectado: <span style={{ color: '#06b6d4', fontWeight: 600 }}>
                        {{ ip: '🌐 Endereço IP', hash: '# Hash de Arquivo', domain: '🌍 Domínio', url: '🔗 URL', cve: '⚠️ CVE' }[type] || type}
                    </span>
                </div>
            )}

            {/* Results */}
            {submitted && type === 'ip' && (
                <IPResult query={submitted} results={results} loading={loading} onOpenSettings={() => setShowSettings(true)} />
            )}
            {submitted && type === 'hash' && (
                <HashResult query={submitted} results={results} loading={loading} />
            )}
            {submitted && type === 'domain' && (
                <DomainResult query={submitted} results={results} loading={loading} />
            )}
            {submitted && type === 'cve' && (
                <CveResult query={submitted} results={results} loading={loading} />
            )}
            {submitted && !type && (
                <div style={{ textAlign: 'center', padding: 40, color: '#64748b' }}>
                    <AlertTriangle size={28} style={{ marginBottom: 10 }} />
                    <div style={{ fontSize: 14 }}>Formato não reconhecido.</div>
                    <div style={{ fontSize: 12, color: '#475569', marginTop: 4 }}>Aceitos: IPs (/^(\d{"{"}1,3{"}"}\.){"{"}3{"}"}...$/) · Hashes MD5/SHA1/SHA256 · Domínios · CVEs</div>
                </div>
            )}

            {/* Empty state */}
            {!submitted && (
                <div style={{ textAlign: 'center', padding: '56px 20px', color: '#334155' }}>
                    <Search size={44} style={{ marginBottom: 14, color: '#1e293b' }} />
                    <div style={{ fontSize: 15, color: '#475569', marginBottom: 6, fontWeight: 600 }}>Pesquis um indicador para iniciar</div>
                    <div style={{ fontSize: 12, color: '#334155', marginBottom: 20 }}>IPs · Hashes MD5/SHA1/SHA256 · Domínios · CVEs</div>
                    {!hasKeys && (
                        <button onClick={() => setShowSettings(true)} className="btn-primary" style={{ fontSize: 13 }}>
                            <Settings size={13} style={{ marginRight: 6 }} /> Configurar API Keys (grátis)
                        </button>
                    )}
                </div>
            )}
        </div>
    );
}
