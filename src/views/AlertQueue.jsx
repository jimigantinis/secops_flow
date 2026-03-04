import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
    AlertTriangle, Bot, Filter, ChevronDown,
    Clock, User, Monitor, ArrowRight, RefreshCw, Layers, Info
} from 'lucide-react';
import { mockAlerts, severityConfig } from '../data/mockData';

const statusConfig = {
    open: { label: 'Aberto', color: '#f97316', bg: 'rgba(249,115,22,0.12)' },
    investigating: { label: 'Em Investigação', color: '#06b6d4', bg: 'rgba(6,182,212,0.12)' },
    closed: { label: 'Fechado', color: '#22c55e', bg: 'rgba(34,197,94,0.12)' },
};

function ConfidenceBar({ value }) {
    const color = value >= 90 ? '#ef4444' : value >= 75 ? '#f97316' : '#eab308';
    return (
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <div style={{ width: 70, height: 4, borderRadius: 2, background: 'rgba(255,255,255,0.08)', overflow: 'hidden' }}>
                <div style={{ width: `${value}%`, height: '100%', background: color, borderRadius: 2 }} />
            </div>
            <span style={{ fontSize: 11, fontWeight: 700, color, fontFamily: "'Fira Code', monospace" }}>{value}%</span>
        </div>
    );
}

export default function AlertQueue({ filterStatus }) {
    const navigate = useNavigate();
    const [severityFilter, setSeverityFilter] = useState('all');
    const [selectedId, setSelectedId] = useState(null);

    const alerts = filterStatus
        ? mockAlerts.filter(a => a.status === filterStatus)
        : mockAlerts;

    const filtered = severityFilter === 'all' ? alerts : alerts.filter(a => a.severity === severityFilter);

    return (
        <div className="animate-fade-in">
            {/* Header */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 20 }}>
                <div>
                    <h1 style={{ fontSize: 22, fontWeight: 800, color: '#f8fafc', letterSpacing: -0.5 }}>
                        {filterStatus === 'investigating' ? 'Investigações Ativas' : 'Fila de Triagem Inteligente'}
                    </h1>
                    <p style={{ fontSize: 13, color: '#64748b', marginTop: 4 }}>
                        Alertas correlacionados e priorizados pela IA · {filtered.length} incidentes
                    </p>
                </div>
                <div style={{ display: 'flex', gap: 8 }}>
                    <button className="btn-ghost" style={{ fontSize: 12 }}>
                        <RefreshCw size={13} /> Atualizar
                    </button>
                    <button className="btn-ghost" style={{ fontSize: 12 }}>
                        <Filter size={13} /> Filtros
                    </button>
                </div>
            </div>

            {/* AI Summary Banner */}
            <div className="copilot-box" style={{ marginBottom: 20 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
                    <Bot size={16} color="#06b6d4" />
                    <span style={{ fontSize: 13, fontWeight: 700, color: '#06b6d4' }}>Análise da IA da Fila Atual</span>
                    <span style={{ fontSize: 10, background: 'rgba(6,182,212,0.15)', color: '#06b6d4', borderRadius: 4, padding: '1px 6px', fontWeight: 600 }}>
                        GPT-4o
                    </span>
                </div>
                <p style={{ fontSize: 13, color: '#cbd5e1', lineHeight: 1.6 }}>
                    <strong style={{ color: '#f8fafc' }}>Situação atual:</strong> Detecto 2 incidentes críticos ativos que requerem atenção imediata.
                    O <strong style={{ color: '#ef4444' }}>INC-2024-0891</strong> (PowerShell + C2) mostra padrão de ataque em cadeia com tentativa de Credential Dumping no notebook do CEO.
                    O <strong style={{ color: '#ef4444' }}>INC-2024-0885</strong> (DNS Tunneling) sugere exfiltração ativa de dados do servidor de arquivos.
                    Recomendo triagem na ordem: <strong style={{ color: '#f8fafc' }}>INC-0891 → INC-0885 → INC-0889</strong>.
                </p>
            </div>

            {/* Severity filter tabs */}
            <div style={{ display: 'flex', gap: 6, marginBottom: 16 }}>
                {['all', 'critical', 'high', 'medium', 'low'].map(sev => {
                    const count = sev === 'all' ? alerts.length : alerts.filter(a => a.severity === sev).length;
                    const cfg = severityConfig[sev];
                    const isActive = severityFilter === sev;
                    return (
                        <button
                            key={sev}
                            onClick={() => setSeverityFilter(sev)}
                            style={{
                                padding: '6px 14px', borderRadius: 8, cursor: 'pointer', fontSize: 12, fontWeight: 600,
                                border: isActive
                                    ? `1px solid ${sev === 'all' ? 'rgba(6,182,212,0.4)' : cfg?.color + '50'}`
                                    : '1px solid rgba(255,255,255,0.07)',
                                background: isActive
                                    ? sev === 'all' ? 'rgba(6,182,212,0.1)' : cfg?.bg
                                    : 'rgba(255,255,255,0.04)',
                                color: isActive ? (sev === 'all' ? '#06b6d4' : cfg?.color) : '#94a3b8',
                                transition: 'all 0.2s'
                            }}
                        >
                            {sev === 'all' ? 'Todos' : cfg?.label} ({count})
                        </button>
                    );
                })}
            </div>

            {/* Table header */}
            <div style={{
                background: 'rgba(255,255,255,0.02)',
                borderRadius: '8px 8px 0 0',
                border: '1px solid rgba(255,255,255,0.07)',
                borderBottom: 'none',
                padding: '10px 16px',
                display: 'grid',
                gridTemplateColumns: '8px 1fr 110px 140px 95px 80px 110px 80px',
                gap: 12,
                alignItems: 'center',
            }}>
                {['', 'Incidente / Título', 'Severidade', 'Confiança IA', 'Status', 'Fonte', 'Host Afetado', 'Ações'].map((h) => (
                    <div key={h} className="section-title" style={{ fontSize: 10 }}>{h}</div>
                ))}
            </div>

            {/* Table body */}
            <div style={{
                border: '1px solid rgba(255,255,255,0.07)',
                borderRadius: '0 0 12px 12px',
                overflow: 'hidden',
                background: '#1e293b'
            }}>
                {filtered.length === 0 ? (
                    <div style={{ padding: 40, textAlign: 'center', color: '#64748b' }}>
                        Nenhum alerta para os filtros selecionados.
                    </div>
                ) : filtered.map((alert, idx) => {
                    const sev = severityConfig[alert.severity];
                    const st = statusConfig[alert.status];
                    const isSelected = selectedId === alert.id;

                    return (
                        <div
                            key={alert.id}
                            onClick={() => { setSelectedId(alert.id); navigate(`/alertas/${alert.id}`); }}
                            style={{
                                display: 'grid',
                                gridTemplateColumns: '8px 1fr 110px 140px 95px 80px 110px 80px',
                                gap: 12, alignItems: 'center',
                                padding: '14px 16px',
                                borderBottom: idx < filtered.length - 1 ? '1px solid rgba(255,255,255,0.05)' : 'none',
                                cursor: 'pointer',
                                background: isSelected ? 'rgba(6,182,212,0.05)' : 'transparent',
                                borderLeft: isSelected ? '2px solid #06b6d4' : '2px solid transparent',
                                transition: 'all 0.15s',
                            }}
                            onMouseEnter={e => { if (!isSelected) e.currentTarget.style.background = 'rgba(255,255,255,0.02)'; }}
                            onMouseLeave={e => { if (!isSelected) e.currentTarget.style.background = 'transparent'; }}
                        >
                            {/* Severity dot */}
                            <div style={{ position: 'relative' }}>
                                <div style={{ width: 8, height: 8, borderRadius: '50%', background: sev.color }} />
                                {alert.severity === 'critical' && (
                                    <div style={{
                                        position: 'absolute', inset: -3, borderRadius: '50%',
                                        border: `1px solid ${sev.color}`,
                                        animation: 'pulse-ring 1.5s ease-in-out infinite'
                                    }} />
                                )}
                            </div>

                            {/* Title + meta */}
                            <div>
                                <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 2 }}>
                                    {alert.isGrouped && (
                                        <span style={{
                                            background: 'rgba(167,139,250,0.12)', color: '#a78bfa',
                                            fontSize: 9, fontWeight: 700, borderRadius: 4,
                                            padding: '1px 5px', border: '1px solid rgba(167,139,250,0.25)'
                                        }}>
                                            <Layers size={8} style={{ display: 'inline', marginRight: 2 }} />
                                            +{alert.relatedAlerts} alertas
                                        </span>
                                    )}
                                    <span style={{ fontSize: 12, fontWeight: 700, color: '#f8fafc' }}>{alert.title}</span>
                                </div>
                                <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                                    <span style={{ fontSize: 10, color: '#64748b', fontFamily: "'Fira Code', monospace" }}>{alert.id}</span>
                                    <span style={{ fontSize: 10, color: '#475569' }}>·</span>
                                    <span style={{ fontSize: 11, color: '#64748b' }}>{alert.timestamp}</span>
                                    {alert.ttps.slice(0, 2).map(t => (
                                        <span key={t} className="mitre-tag" style={{ fontSize: 9, padding: '1px 5px' }}>{t}</span>
                                    ))}
                                </div>
                            </div>

                            {/* Severity badge */}
                            <span className={`rep-tag ${sev.cls}`} style={{ fontSize: 12, borderRadius: 6, textAlign: 'center', padding: '4px 10px' }}>
                                {sev.label}
                            </span>

                            {/* AI Confidence */}
                            <ConfidenceBar value={alert.aiConfidence} />

                            {/* Status */}
                            <span style={{
                                background: st.bg, color: st.color,
                                fontSize: 11, fontWeight: 600, borderRadius: 6,
                                padding: '4px 8px', textAlign: 'center'
                            }}>{st.label}</span>

                            {/* Source */}
                            <div style={{ fontSize: 11, color: '#64748b', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                                {alert.source.split(' + ')[0]}
                            </div>

                            {/* Host */}
                            <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                                <Monitor size={11} color="#64748b" />
                                <span style={{ fontSize: 11, color: '#94a3b8', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                                    {alert.host}
                                </span>
                            </div>

                            {/* Actions */}
                            <button
                                onClick={e => { e.stopPropagation(); navigate(`/alertas/${alert.id}`); }}
                                className="btn-primary"
                                style={{ padding: '5px 10px', fontSize: 11 }}
                            >
                                Investigar <ArrowRight size={11} />
                            </button>
                        </div>
                    );
                })}
            </div>
        </div>
    );
}
