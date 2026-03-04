import React from 'react';
import { useNavigate } from 'react-router-dom';
import {
    TrendingDown, TrendingUp, AlertTriangle, CheckCircle2,
    Bot, Activity, Clock, Shield, Flame, Zap, ArrowRight
} from 'lucide-react';
import { mockMetrics, mockAlerts, severityConfig } from '../data/mockData';

function MetricCard({ title, value, sub, icon: Icon, color, trend, borderColor }) {
    return (
        <div className="card" style={{ borderTop: `2px solid ${borderColor || 'rgba(255,255,255,0.07)'}`, position: 'relative', overflow: 'hidden' }}>
            <div style={{
                position: 'absolute', top: 12, right: 12,
                width: 40, height: 40, borderRadius: 10,
                background: `${color}18`, display: 'flex', alignItems: 'center', justifyContent: 'center'
            }}>
                <Icon size={20} color={color} />
            </div>
            <div className="metric-value" style={{ color }}>{value}</div>
            <div className="metric-label">{title}</div>
            {sub && <div style={{ fontSize: 12, color: '#64748b', marginTop: 4 }}>{sub}</div>}
            {trend !== undefined && (
                <div style={{ display: 'flex', alignItems: 'center', gap: 4, marginTop: 8 }}>
                    {trend < 0
                        ? <TrendingDown size={14} color="#22c55e" />
                        : <TrendingUp size={14} color="#ef4444" />}
                    <span style={{ fontSize: 12, color: trend < 0 ? '#22c55e' : '#ef4444', fontWeight: 600 }}>
                        {Math.abs(trend)}% vs. ontem
                    </span>
                </div>
            )}
        </div>
    );
}

function SeverityBar({ label, value, color, max }) {
    const pct = Math.round((value / max) * 100);
    return (
        <div style={{ marginBottom: 12 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                <span style={{ fontSize: 13, color: '#94a3b8' }}>{label}</span>
                <span style={{ fontSize: 13, fontWeight: 700, color }}>{value}</span>
            </div>
            <div style={{ height: 6, background: 'rgba(255,255,255,0.05)', borderRadius: 3, overflow: 'hidden' }}>
                <div style={{ width: `${pct}%`, height: '100%', background: color, borderRadius: 3, transition: 'width 1s ease' }} />
            </div>
        </div>
    );
}

function RecentAlertRow({ alert, onClick }) {
    const sev = severityConfig[alert.severity];
    return (
        <div
            onClick={onClick}
            style={{
                display: 'flex', alignItems: 'center', gap: 12,
                padding: '12px 0', borderBottom: '1px solid rgba(255,255,255,0.05)',
                cursor: 'pointer', transition: 'background 0.15s', borderRadius: 4,
            }}
            onMouseEnter={e => e.currentTarget.style.background = 'rgba(255,255,255,0.02)'}
            onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
        >
            <div style={{ width: 8, height: 8, borderRadius: '50%', background: sev.color, flexShrink: 0 }} />
            <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontSize: 13, fontWeight: 600, color: '#f8fafc', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                    {alert.title}
                </div>
                <div style={{ fontSize: 11, color: '#64748b', marginTop: 2 }}>{alert.host} · {alert.timestamp}</div>
            </div>
            <span className={`rep-tag ${sev.cls}`} style={{ flexShrink: 0, borderRadius: 6, padding: '3px 8px', fontSize: 11 }}>
                {sev.label}
            </span>
            <div style={{ fontSize: 11, color: '#06b6d4', fontWeight: 600, flexShrink: 0 }}>
                {alert.aiConfidence}% IA
            </div>
        </div>
    );
}

export default function Dashboard() {
    const navigate = useNavigate();
    const maxSeverity = Math.max(
        mockMetrics.pendingCritical, mockMetrics.pendingHigh,
        mockMetrics.pendingMedium, mockMetrics.pendingLow
    );
    const total = mockMetrics.pendingCritical + mockMetrics.pendingHigh + mockMetrics.pendingMedium + mockMetrics.pendingLow;

    return (
        <div className="animate-fade-in">
            {/* Page header */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 24 }}>
                <div>
                    <h1 style={{ fontSize: 22, fontWeight: 800, color: '#f8fafc', letterSpacing: -0.5 }}>Painel de Operações</h1>
                    <p style={{ fontSize: 13, color: '#64748b', marginTop: 4 }}>
                        Visão atualizada em tempo real · 01/03/2024 20:14 · Turno: Noturno
                    </p>
                </div>
                <div style={{ display: 'flex', gap: 8 }}>
                    <button className="btn-ghost" style={{ fontSize: 12 }}>
                        <Clock size={14} /> Últimas 24h
                    </button>
                    <button className="btn-primary" onClick={() => navigate('/alertas')}>
                        <Shield size={14} /> Ver Fila de Alertas
                    </button>
                </div>
            </div>

            {/* Alert banner */}
            <div style={{
                background: 'linear-gradient(135deg, rgba(239,68,68,0.1), rgba(249,115,22,0.08))',
                border: '1px solid rgba(239,68,68,0.25)',
                borderRadius: 12, padding: '12px 16px', marginBottom: 24,
                display: 'flex', alignItems: 'center', gap: 12
            }}>
                <div style={{
                    background: 'rgba(239,68,68,0.15)', borderRadius: 8,
                    width: 36, height: 36, display: 'flex', alignItems: 'center', justifyContent: 'center'
                }}>
                    <Flame size={18} color="#ef4444" />
                </div>
                <div style={{ flex: 1 }}>
                    <div style={{ fontSize: 13, fontWeight: 700, color: '#f8fafc' }}>
                        2 Incidentes Críticos Aguardam Triagem Imediata
                    </div>
                    <div style={{ fontSize: 12, color: '#94a3b8', marginTop: 2 }}>
                        INC-2024-0891: PowerShell ofuscado + C2 (CEO Laptop) · INC-2024-0885: Exfiltração DNS
                    </div>
                </div>
                <button className="btn-danger" onClick={() => navigate('/alertas')}>
                    Triagem Agora <ArrowRight size={14} />
                </button>
            </div>

            {/* Metrics row */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16, marginBottom: 24 }}>
                <MetricCard
                    title="MTTR (Tempo Médio de Resposta)"
                    value={mockMetrics.mttr}
                    sub="Média das últimas 24 horas"
                    icon={Clock}
                    color="#06b6d4"
                    trend={mockMetrics.mttrTrend}
                    borderColor="#06b6d4"
                />
                <MetricCard
                    title="Incidentes Hoje"
                    value={mockMetrics.incidentsToday}
                    sub={`${mockMetrics.resolvedToday} resolvidos`}
                    icon={Activity}
                    color="#f97316"
                    borderColor="#f97316"
                />
                <MetricCard
                    title="Auto-Descartados pela IA"
                    value={mockMetrics.aiAutoDiscarded}
                    sub={`${mockMetrics.aiAutoDiscardedRate}% do total — Ruído eliminado`}
                    icon={Bot}
                    color="#22c55e"
                    borderColor="#22c55e"
                />
                <MetricCard
                    title="Falsos Positivos (24h)"
                    value={mockMetrics.falsePositives}
                    sub="Feedback aplicado ao modelo"
                    icon={CheckCircle2}
                    color="#a78bfa"
                    borderColor="#a78bfa"
                />
            </div>

            {/* Main grid */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 320px', gap: 16 }}>
                {/* Recent alerts */}
                <div className="card">
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
                        <div>
                            <div style={{ fontSize: 15, fontWeight: 700, color: '#f8fafc' }}>Alertas Recentes</div>
                            <div style={{ fontSize: 12, color: '#64748b', marginTop: 2 }}>Ordenados por prioridade de IA</div>
                        </div>
                        <button className="btn-ghost" onClick={() => navigate('/alertas')} style={{ fontSize: 12 }}>
                            Ver todos <ArrowRight size={12} />
                        </button>
                    </div>
                    {mockAlerts.map(alert => (
                        <RecentAlertRow key={alert.id} alert={alert} onClick={() => navigate(`/alertas/${alert.id}`)} />
                    ))}
                </div>

                {/* Right column */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
                    {/* Severity breakdown */}
                    <div className="card">
                        <div style={{ fontSize: 15, fontWeight: 700, marginBottom: 4 }}>Alertas por Severidade</div>
                        <div style={{ fontSize: 12, color: '#64748b', marginBottom: 16 }}>Total: {total} pendentes</div>
                        <SeverityBar label="Crítico" value={mockMetrics.pendingCritical} color="#ef4444" max={total} />
                        <SeverityBar label="Alto" value={mockMetrics.pendingHigh} color="#f97316" max={total} />
                        <SeverityBar label="Médio" value={mockMetrics.pendingMedium} color="#eab308" max={total} />
                        <SeverityBar label="Baixo" value={mockMetrics.pendingLow} color="#3b82f6" max={total} />
                    </div>

                    {/* AI activity */}
                    <div className="card">
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
                            <Bot size={16} color="#06b6d4" />
                            <div style={{ fontSize: 15, fontWeight: 700 }}>IA Co-Piloto</div>
                            <span style={{
                                background: 'rgba(34,197,94,0.1)', color: '#22c55e',
                                fontSize: 10, fontWeight: 700, borderRadius: 6, padding: '2px 8px'
                            }}>ATIVO</span>
                        </div>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                            {[
                                { label: 'Alertas triados pela IA', value: '47', color: '#22c55e', icon: CheckCircle2 },
                                { label: 'Correlações automáticas', value: '12', color: '#06b6d4', icon: Zap },
                                { label: 'IoCs enriquecidos', value: '89', color: '#a78bfa', icon: Shield },
                            ].map(({ label, value, color, icon: Icon }) => (
                                <div key={label} style={{
                                    display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                                    background: 'rgba(255,255,255,0.03)', borderRadius: 8, padding: '8px 12px'
                                }}>
                                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                                        <Icon size={14} color={color} />
                                        <span style={{ fontSize: 12, color: '#94a3b8' }}>{label}</span>
                                    </div>
                                    <span style={{ fontSize: 15, fontWeight: 700, color }}>{value}</span>
                                </div>
                            ))}
                        </div>
                    </div>

                    {/* Sources */}
                    <div className="card">
                        <div style={{ fontSize: 15, fontWeight: 700, marginBottom: 12 }}>Fontes de Dados</div>
                        {[
                            { name: 'Microsoft Sentinel', status: 'ok', alerts: 14 },
                            { name: 'CrowdStrike Falcon', status: 'ok', alerts: 8 },
                            { name: 'Suricata IDS', status: 'ok', alerts: 5 },
                            { name: 'Azure AD IDP', status: 'ok', alerts: 2 },
                        ].map(({ name, status, alerts }) => (
                            <div key={name} style={{
                                display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                                padding: '8px 0', borderBottom: '1px solid rgba(255,255,255,0.05)'
                            }}>
                                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                                    <div className="status-dot" style={{ background: status === 'ok' ? '#22c55e' : '#ef4444' }} />
                                    <span style={{ fontSize: 12, color: '#94a3b8' }}>{name}</span>
                                </div>
                                <span style={{ fontSize: 12, fontWeight: 600, color: '#f97316' }}>{alerts} alertas</span>
                            </div>
                        ))}
                    </div>
                </div>
            </div>
        </div>
    );
}
