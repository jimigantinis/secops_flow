import React, { useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
    ArrowLeft, Bot, Shield, Wifi, WifiOff, KeyRound, AlertOctagon,
    Clock, Monitor, User, Globe, Hash, Link2, ToggleLeft, ToggleRight,
    Terminal, Info, ChevronRight, X, CheckCircle2, Send, ExternalLink,
    Copy, ChevronDown, ChevronUp, Layers, Activity, Zap
} from 'lucide-react';
import { mockAlerts, severityConfig, mitreData } from '../data/mockData';

// ─── MITRE ATT&CK Widget ───────────────────────────────────────────────────────
function MitreWidget({ ttps }) {
    return (
        <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
                <div style={{ width: 6, height: 6, borderRadius: '50%', background: '#a78bfa' }} />
                <span style={{ fontSize: 12, fontWeight: 700, color: '#f8fafc' }}>MITRE ATT&CK Mapeado</span>
            </div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                {ttps.map(ttp => {
                    const info = mitreData[ttp] || {};
                    return (
                        <div
                            key={ttp}
                            className="mitre-tag"
                            style={{ cursor: 'pointer' }}
                            title={`${ttp} · ${info.name || ''} · Tática: ${info.tactic || ''}`}
                        >
                            <span>{ttp}</span>
                            {info.name && <span style={{ color: '#7c3aed', marginLeft: 4 }}>· {info.name}</span>}
                        </div>
                    );
                })}
            </div>
            <div style={{ marginTop: 10, display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                {[...new Set(ttps.map(t => mitreData[t]?.tactic).filter(Boolean))].map(tactic => (
                    <span key={tactic} style={{
                        fontSize: 10, background: 'rgba(99,102,241,0.1)', color: '#818cf8',
                        border: '1px solid rgba(99,102,241,0.2)', borderRadius: 4, padding: '2px 6px'
                    }}>{tactic}</span>
                ))}
            </div>
        </div>
    );
}

// ─── IoC Enrichment Card ───────────────────────────────────────────────────────
function IocCard({ ioc }) {
    const repClass = ioc.reputation === 'malicious' ? 'rep-malicious' : ioc.reputation === 'suspicious' ? 'rep-suspicious' : 'rep-clean';
    const repLabel = ioc.reputation === 'malicious' ? '🔴 Malicioso' : ioc.reputation === 'suspicious' ? '🟡 Suspeito' : '🟢 Limpo';
    const TypeIcon = ioc.type === 'ip' ? Globe : ioc.type === 'hash' ? Hash : Link2;

    return (
        <div className="card-sm" style={{ marginBottom: 8 }}>
            <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 8 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6, minWidth: 0 }}>
                    <TypeIcon size={13} color="#64748b" style={{ flexShrink: 0 }} />
                    <span style={{ fontSize: 11, fontFamily: "'Fira Code', monospace", color: '#cbd5e1', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {ioc.value}
                    </span>
                </div>
                <span className={`rep-tag ${repClass}`} style={{ flexShrink: 0, fontSize: 10 }}>{repLabel}</span>
            </div>
            {ioc.vtScore && (
                <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginTop: 6 }}>
                    <span style={{ fontSize: 10, color: '#64748b' }}>VirusTotal:</span>
                    <span style={{ fontSize: 11, fontWeight: 700, color: ioc.reputation === 'malicious' ? '#ef4444' : '#eab308', fontFamily: "'Fira Code', monospace" }}>
                        {ioc.vtScore}
                    </span>
                    {ioc.country && <span style={{ fontSize: 10, color: '#475569' }}>· {ioc.country}</span>}
                </div>
            )}
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginTop: 6 }}>
                {ioc.tags?.map(tag => (
                    <span key={tag} style={{
                        fontSize: 9, background: 'rgba(255,255,255,0.05)', color: '#64748b',
                        border: '1px solid rgba(255,255,255,0.08)', borderRadius: 3, padding: '1px 5px'
                    }}>{tag}</span>
                ))}
            </div>
        </div>
    );
}

// ─── Log Viewer ───────────────────────────────────────────────────────────────
function LogViewer({ alert }) {
    const [ocsf, setOcsf] = useState(false);

    const levelColor = { CRITICAL: '#ef4444', WARN: '#eab308', INFO: '#06b6d4', ERROR: '#ef4444', DEBUG: '#64748b' };

    return (
        <div>
            {/* Toggle OCSF */}
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <Terminal size={14} color="#64748b" />
                    <span style={{ fontSize: 12, color: '#94a3b8' }}>Visualizador de Logs</span>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <span style={{ fontSize: 11, color: ocsf ? '#06b6d4' : '#64748b' }}>Padrão OCSF</span>
                    <label className="toggle">
                        <input type="checkbox" checked={ocsf} onChange={() => setOcsf(!ocsf)} />
                        <span className="toggle-slider" />
                    </label>
                </div>
            </div>

            {ocsf ? (
                <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 8 }}>
                        <span style={{
                            background: 'rgba(6,182,212,0.1)', color: '#06b6d4',
                            fontSize: 10, fontWeight: 700, padding: '2px 8px', borderRadius: 4,
                            border: '1px solid rgba(6,182,212,0.2)'
                        }}>OCSF v1.1.0 — Schema Normalizado</span>
                        <span style={{ fontSize: 10, color: '#475569' }}>Todas as fontes unificadas</span>
                    </div>
                    <pre style={{
                        background: '#0f172a', borderRadius: 8, padding: 16,
                        fontSize: 11, fontFamily: "'Fira Code', monospace",
                        color: '#a5f3fc', overflowX: 'auto', lineHeight: 1.7,
                        border: '1px solid rgba(6,182,212,0.15)', maxHeight: 280, overflowY: 'auto'
                    }}>
                        {JSON.stringify(alert.ocsfLog, null, 2)
                            .replace(/"([^"]+)":/g, '"$1":')
                            .split('\n').map((line, i) => {
                                const isKey = line.includes('":');
                                const isValue = !isKey && line.trim();
                                return (
                                    <span key={i}>
                                        {line.replace(/"([^"]+)":/g, (m, k) => `"${k}":`)}\n
                                    </span>
                                );
                            })}
                    </pre>
                </div>
            ) : (
                <div style={{
                    background: '#0f172a', borderRadius: 8, padding: '12px 16px',
                    maxHeight: 280, overflowY: 'auto',
                    border: '1px solid rgba(255,255,255,0.07)'
                }}>
                    {alert.rawLogs.map((log, i) => (
                        <div key={i} className="log-line">
                            <span className="log-timestamp">{log.ts}</span>
                            <span style={{ color: levelColor[log.level] || '#94a3b8', fontWeight: 600, minWidth: 60 }}>[{log.level}]</span>
                            <span style={{ color: '#64748b', minWidth: 60 }}>[{log.src}]</span>
                            <span style={{ color: '#94a3b8', flex: 1 }}>{log.msg}</span>
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
}

// ─── Timeline ─────────────────────────────────────────────────────────────────
function Timeline({ events }) {
    const typeColor = { info: '#06b6d4', warn: '#eab308', error: '#ef4444', success: '#22c55e' };
    return (
        <div style={{ position: 'relative', paddingLeft: 0 }}>
            <div style={{ position: 'absolute', left: 16, top: 8, bottom: 8, width: 1, background: 'rgba(255,255,255,0.07)' }} />
            {events.map((e, i) => (
                <div key={i} style={{ position: 'relative', paddingLeft: 48, paddingBottom: 16 }}>
                    <div style={{
                        position: 'absolute', left: 10, top: 2,
                        width: 13, height: 13, borderRadius: '50%',
                        background: typeColor[e.type] || '#64748b',
                        border: '2px solid #0f172a',
                        boxShadow: `0 0 8px ${typeColor[e.type]}60`
                    }} />
                    <div style={{ fontSize: 11, color: '#64748b', fontFamily: "'Fira Code', monospace" }}>{e.time}</div>
                    <div style={{ fontSize: 13, color: '#cbd5e1', marginTop: 2 }}>{e.event}</div>
                </div>
            ))}
        </div>
    );
}

// ─── Post-Incident Report Modal ────────────────────────────────────────────────
function PostIncidentModal({ alert, onClose }) {
    const [approved, setApproved] = useState(false);
    const sev = severityConfig[alert.severity];

    if (approved) {
        return (
            <div className="modal-overlay" onClick={onClose}>
                <div className="modal-content" style={{ width: 440, padding: 40, textAlign: 'center' }} onClick={e => e.stopPropagation()}>
                    <div style={{ width: 64, height: 64, borderRadius: '50%', background: 'rgba(34,197,94,0.15)', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 16px' }}>
                        <CheckCircle2 size={32} color="#22c55e" />
                    </div>
                    <div style={{ fontSize: 20, fontWeight: 800, color: '#f8fafc', marginBottom: 8 }}>Incidente Fechado!</div>
                    <div style={{ fontSize: 14, color: '#94a3b8', marginBottom: 24 }}>
                        Relatório enviado ao SIEM. Alerta {alert.id} marcado como resolvido.
                    </div>
                    <button className="btn-primary" onClick={onClose} style={{ margin: '0 auto' }}>
                        Voltar à Fila <ArrowLeft size={14} />
                    </button>
                </div>
            </div>
        );
    }

    return (
        <div className="modal-overlay" onClick={onClose}>
            <div className="modal-content" onClick={e => e.stopPropagation()}>
                <div style={{ padding: '24px 28px', borderBottom: '1px solid rgba(255,255,255,0.07)' }}>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                            <Bot size={20} color="#06b6d4" />
                            <div>
                                <div style={{ fontSize: 16, fontWeight: 800, color: '#f8fafc' }}>Relatório Pós-Incidente (PIR)</div>
                                <div style={{ fontSize: 12, color: '#64748b' }}>Rascunho gerado automaticamente pela IA · Revisão obrigatória</div>
                            </div>
                        </div>
                        <button className="btn-ghost" onClick={onClose} style={{ padding: 8 }}><X size={16} /></button>
                    </div>
                </div>

                <div style={{ padding: '24px 28px', maxHeight: '60vh', overflowY: 'auto' }}>
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 20 }}>
                        {[
                            { label: 'ID do Incidente', value: alert.id },
                            { label: 'Severidade', value: sev.label },
                            { label: 'Host Afetado', value: alert.host },
                            { label: 'Usuário', value: alert.user },
                            { label: 'Data/Hora de Detecção', value: alert.timestamp },
                            { label: 'Analista Responsável', value: 'Ana Oliveira (N2)' },
                        ].map(({ label, value }) => (
                            <div key={label}>
                                <div style={{ fontSize: 10, color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 2 }}>{label}</div>
                                <div style={{ fontSize: 13, fontWeight: 600, color: '#f8fafc', fontFamily: label.includes('Host') || label.includes('Usuário') || label.includes('ID') ? "'Fira Code', monospace" : undefined }}>
                                    {value}
                                </div>
                            </div>
                        ))}
                    </div>

                    <div className="divider" style={{ marginBottom: 20 }} />

                    {[
                        {
                            title: '1. Resumo Executivo',
                            content: `Incidente de segurança de severidade ${sev.label} detectado em ${alert.timestamp}. ${alert.title}. A ameaça foi contida com sucesso através de ações de resposta automatizada.`
                        },
                        {
                            title: '2. Cronologia do Ataque',
                            content: alert.timeline.map(e => `• ${e.time}: ${e.event}`).join('\n')
                        },
                        {
                            title: '3. Indicadores de Comprometimento (IoCs)',
                            content: alert.iocs.map(ioc => `• [${ioc.type.toUpperCase()}] ${ioc.value} — ${ioc.reputation} (VT: ${ioc.vtScore || 'N/A'})`).join('\n') || '• Nenhum IoC externo confirmado.'
                        },
                        {
                            title: '4. TTPs MITRE ATT&CK Identificados',
                            content: alert.ttps.map(t => `• ${t}: ${mitreData[t]?.name || 'Desconhecido'} (${mitreData[t]?.tactic || 'N/A'})`).join('\n')
                        },
                        {
                            title: '5. Ações Tomadas',
                            content: '• Host isolado da rede via CrowdStrike Falcon\n• IP malicioso bloqueado no firewall perimetral\n• Sessão do usuário revogada\n• Evidências coletadas para análise forense'
                        },
                        {
                            title: '6. Lições Aprendidas / Recomendações',
                            content: '• Revisar regra de filtragem de e-mails com anexos VBS/WSH\n• Implementar restrição de execução de PowerShell com bloqueio de scripts não assinados (WDAC)\n• Reforçar treinamento de phishing para usuários executivos'
                        },
                    ].map(({ title, content }) => (
                        <div key={title} style={{ marginBottom: 16 }}>
                            <div style={{ fontSize: 12, fontWeight: 700, color: '#06b6d4', marginBottom: 6 }}>{title}</div>
                            <div style={{
                                background: '#0f172a', borderRadius: 8, padding: 12,
                                fontSize: 12, color: '#94a3b8', whiteSpace: 'pre-line', lineHeight: 1.7,
                                fontFamily: title.includes('IoC') || title.includes('TTP') ? "'Fira Code', monospace" : undefined
                            }}>{content}</div>
                        </div>
                    ))}
                </div>

                <div style={{ padding: '16px 28px', borderTop: '1px solid rgba(255,255,255,0.07)', display: 'flex', justifyContent: 'flex-end', gap: 10 }}>
                    <button className="btn-ghost" onClick={onClose}>Cancelar</button>
                    <button className="btn-safe" onClick={() => setApproved(true)}>
                        <CheckCircle2 size={14} /> Aprovar e Fechar Incidente
                    </button>
                </div>
            </div>
        </div>
    );
}

// ─── Main Incident View ────────────────────────────────────────────────────────
export default function IncidentView() {
    const { id } = useParams();
    const navigate = useNavigate();
    const alert = mockAlerts.find(a => a.id === id) || mockAlerts[0];
    const sev = severityConfig[alert.severity];

    const [activeRightTab, setActiveRightTab] = useState('ai');
    const [showModal, setShowModal] = useState(false);
    const [actionDone, setActionDone] = useState({});

    const handleAction = (key) => {
        setActionDone(prev => ({ ...prev, [key]: true }));
        if (key === 'isolate') setTimeout(() => setShowModal(true), 600);
    };

    const soarActions = [
        { key: 'isolate', label: 'Isolar Dispositivo', icon: WifiOff, cls: 'btn-danger', desc: 'Isola o host via EDR' },
        { key: 'block', label: 'Bloquear IP no Firewall', icon: Shield, cls: 'btn-warning', desc: 'Bloqueia via API do FW' },
        { key: 'reset', label: 'Forçar Reset de Senha', icon: KeyRound, cls: 'btn-ghost', desc: 'Revoga sessão + reset AD' },
        { key: 'fp', label: 'Marcar Falso Positivo', icon: CheckCircle2, cls: 'btn-safe', desc: 'Treina modelo IA' },
    ];

    const rightTabs = [
        { id: 'ai', label: 'IA Co-Piloto', icon: Bot },
        { id: 'context', label: 'Contexto', icon: Info },
        { id: 'soar', label: 'Ações SOAR', icon: Zap },
    ];

    return (
        <div className="animate-fade-in" style={{ height: 'calc(100vh - 108px)', display: 'flex', flexDirection: 'column', gap: 0 }}>
            {/* Incident header */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 16, flexShrink: 0 }}>
                <button className="btn-ghost" onClick={() => navigate('/alertas')} style={{ padding: '6px 10px' }}>
                    <ArrowLeft size={15} />
                </button>
                <div style={{ width: 10, height: 10, borderRadius: '50%', background: sev.color }} />
                <div style={{ flex: 1, minWidth: 0 }}>
                    <h1 style={{ fontSize: 17, fontWeight: 800, color: '#f8fafc', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                        {alert.title}
                    </h1>
                    <div style={{ display: 'flex', gap: 10, alignItems: 'center', marginTop: 2 }}>
                        <span style={{ fontSize: 11, fontFamily: "'Fira Code', monospace", color: '#64748b' }}>{alert.id}</span>
                        <span className={`rep-tag ${sev.cls}`} style={{ fontSize: 11, borderRadius: 5, padding: '1px 7px' }}>{sev.label}</span>
                        <span style={{ fontSize: 11, color: '#64748b' }}>·</span>
                        <Clock size={11} color="#64748b" />
                        <span style={{ fontSize: 11, color: '#64748b' }}>{alert.timestamp}</span>
                        <span style={{ fontSize: 11, color: '#64748b' }}>·</span>
                        <Bot size={11} color="#06b6d4" />
                        <span style={{ fontSize: 11, color: '#06b6d4', fontWeight: 600 }}>Confiança IA: {alert.aiConfidence}%</span>
                    </div>
                </div>
                <div style={{ display: 'flex', gap: 8, flexShrink: 0 }}>
                    <button className="btn-ghost" style={{ fontSize: 12 }}><User size={13} /> Atribuir</button>
                    <button className="btn-primary" onClick={() => setShowModal(true)} style={{ fontSize: 12 }}>
                        <Send size={13} /> Gerar PIR
                    </button>
                </div>
            </div>

            {/* Split-screen layout */}
            <div style={{ flex: 1, display: 'grid', gridTemplateColumns: '1fr 400px', gap: 16, minHeight: 0 }}>

                {/* LEFT PANEL */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: 14, overflow: 'auto', minHeight: 0 }}>

                    {/* Attack timeline */}
                    <div className="card" style={{ flexShrink: 0 }}>
                        <div style={{ fontSize: 13, fontWeight: 700, color: '#f8fafc', marginBottom: 14, display: 'flex', alignItems: 'center', gap: 6 }}>
                            <Activity size={14} color="#06b6d4" /> Linha do Tempo do Ataque
                        </div>
                        <Timeline events={alert.timeline} />
                    </div>

                    {/* Log viewer */}
                    <div className="card" style={{ flexShrink: 0 }}>
                        <LogViewer alert={alert} />
                    </div>

                    {/* MITRE */}
                    <div className="card" style={{ flexShrink: 0 }}>
                        <MitreWidget ttps={alert.ttps} />
                    </div>
                </div>

                {/* RIGHT PANEL */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: 12, overflow: 'auto', minHeight: 0 }}>

                    {/* Tab bar */}
                    <div style={{
                        display: 'flex', gap: 4, background: '#111827',
                        borderRadius: 10, padding: 4, border: '1px solid rgba(255,255,255,0.07)', flexShrink: 0
                    }}>
                        {rightTabs.map(({ id, label, icon: Icon }) => (
                            <button
                                key={id}
                                onClick={() => setActiveRightTab(id)}
                                style={{
                                    flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 5,
                                    padding: '7px 10px', borderRadius: 7, fontSize: 12, fontWeight: 600,
                                    cursor: 'pointer', border: 'none', transition: 'all 0.2s',
                                    background: activeRightTab === id ? '#1e293b' : 'transparent',
                                    color: activeRightTab === id ? '#06b6d4' : '#64748b'
                                }}
                            >
                                <Icon size={13} />{label}
                            </button>
                        ))}
                    </div>

                    {/* AI Co-Pilot tab */}
                    {activeRightTab === 'ai' && (
                        <div style={{ display: 'flex', flexDirection: 'column', gap: 12, overflow: 'auto' }}>
                            <div className="copilot-box">
                                <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 10 }}>
                                    <Bot size={15} color="#06b6d4" />
                                    <span style={{ fontSize: 12, fontWeight: 700, color: '#06b6d4' }}>Análise do AI Co-Piloto</span>
                                    <span style={{ fontSize: 9, background: 'rgba(6,182,212,0.15)', color: '#06b6d4', borderRadius: 3, padding: '1px 5px', fontWeight: 600 }}>
                                        GPT-4o · Confiança {alert.aiConfidence}%
                                    </span>
                                </div>
                                <p style={{ fontSize: 12.5, color: '#cbd5e1', lineHeight: 1.75 }}
                                    dangerouslySetInnerHTML={{ __html: alert.aiSummary.replace(/\*\*([^*]+)\*\*/g, '<strong style="color:#f8fafc">$1</strong>').replace(/`([^`]+)`/g, '<code style="color:#a5f3fc;background:rgba(6,182,212,0.1);padding:1px 4px;border-radius:3px;font-family:\'Fira Code\',monospace;font-size:11px">$1</code>') }}
                                />
                            </div>

                            {/* Quick stats */}
                            <div className="card">
                                <div style={{ fontSize: 12, fontWeight: 700, color: '#f8fafc', marginBottom: 10 }}>Resumo Técnico</div>
                                <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                                    {[
                                        { label: 'Host Comprometido', value: alert.host, icon: Monitor },
                                        { label: 'Usuário', value: alert.user, icon: User },
                                        { label: 'IP Interno', value: alert.ip, icon: Globe },
                                        { label: 'IP Externo', value: alert.externalIp || '—', icon: Globe },
                                        { label: 'Fonte de Detecção', value: alert.source, icon: Activity },
                                    ].map(({ label, value, icon: Icon }) => (
                                        <div key={label} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                                            <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                                                <Icon size={12} color="#64748b" />
                                                <span style={{ fontSize: 11, color: '#64748b' }}>{label}</span>
                                            </div>
                                            <span style={{
                                                fontSize: 11, fontWeight: 600, color: '#94a3b8', textAlign: 'right', maxWidth: 160,
                                                fontFamily: label.includes('IP') || label.includes('Host') ? "'Fira Code', monospace" : undefined
                                            }}>{value}</span>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        </div>
                    )}

                    {/* Context tab */}
                    {activeRightTab === 'context' && (
                        <div style={{ display: 'flex', flexDirection: 'column', gap: 12, overflow: 'auto' }}>
                            {/* Business context */}
                            <div className="card">
                                <div style={{ fontSize: 12, fontWeight: 700, color: '#f8fafc', marginBottom: 12 }}>Contexto de Negócio</div>
                                <div style={{ display: 'flex', flex: 1, flexDirection: 'column', gap: 8 }}>
                                    {[
                                        { label: 'Máquina', value: alert.businessContext.machine },
                                        { label: 'Proprietário', value: alert.businessContext.owner },
                                        { label: 'Departamento', value: alert.businessContext.department },
                                        { label: 'Criticidade', value: alert.businessContext.criticality },
                                        { label: 'Valor do Ativo', value: alert.businessContext.assetValue },
                                    ].map(({ label, value }) => (
                                        <div key={label} style={{ display: 'flex', justifyContent: 'space-between', gap: 8 }}>
                                            <span style={{ fontSize: 11, color: '#64748b' }}>{label}</span>
                                            <span style={{ fontSize: 11, fontWeight: 600, color: '#cbd5e1', textAlign: 'right' }}>{value}</span>
                                        </div>
                                    ))}
                                </div>
                            </div>

                            {/* IoC Enrichment */}
                            <div className="card">
                                <div style={{ fontSize: 12, fontWeight: 700, color: '#f8fafc', marginBottom: 10 }}>
                                    Enriquecimento de IoCs
                                    <span style={{ fontSize: 10, color: '#64748b', fontWeight: 400, marginLeft: 6 }}>via VirusTotal + MISP</span>
                                </div>
                                {alert.iocs.length === 0 ? (
                                    <div style={{ fontSize: 12, color: '#64748b', textAlign: 'center', padding: 16 }}>Nenhum IoC externo mapeado.</div>
                                ) : (
                                    alert.iocs.map((ioc, i) => <IocCard key={i} ioc={ioc} />)
                                )}
                            </div>
                        </div>
                    )}

                    {/* SOAR Actions tab */}
                    {activeRightTab === 'soar' && (
                        <div style={{ display: 'flex', flexDirection: 'column', gap: 10, overflow: 'auto' }}>
                            <div className="copilot-box" style={{ marginBottom: 4 }}>
                                <div style={{ fontSize: 11, color: '#94a3b8', lineHeight: 1.6 }}>
                                    <strong style={{ color: '#f8fafc' }}>Ações de Resposta a Um Clique</strong> — cada ação é executada via API diretamente nas ferramentas integradas (CrowdStrike, Palo Alto, Active Directory).
                                </div>
                            </div>
                            {soarActions.map(({ key, label, icon: Icon, cls, desc }) => (
                                <div key={key} className="card-sm">
                                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                                        <div>
                                            <div style={{ fontSize: 12, fontWeight: 600, color: '#f8fafc', marginBottom: 2 }}>{label}</div>
                                            <div style={{ fontSize: 11, color: '#64748b' }}>{desc}</div>
                                        </div>
                                        <button
                                            className={actionDone[key] ? 'btn-safe' : cls}
                                            onClick={() => handleAction(key)}
                                            style={{ flexShrink: 0, minWidth: 110, justifyContent: 'center' }}
                                        >
                                            {actionDone[key] ? (
                                                <><CheckCircle2 size={13} /> Executado</>
                                            ) : (
                                                <><Icon size={13} /> {label.split(' ')[0]}</>
                                            )}
                                        </button>
                                    </div>
                                </div>
                            ))}

                            <div style={{ marginTop: 8 }}>
                                <button
                                    className="btn-primary"
                                    style={{ width: '100%', justifyContent: 'center', padding: '12px' }}
                                    onClick={() => setShowModal(true)}
                                >
                                    <Send size={14} /> Finalizar e Gerar Relatório (PIR)
                                </button>
                            </div>
                        </div>
                    )}
                </div>
            </div>

            {/* Post-Incident Modal */}
            {showModal && <PostIncidentModal alert={alert} onClose={() => setShowModal(false)} />}
        </div>
    );
}
