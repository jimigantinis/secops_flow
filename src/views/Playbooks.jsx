import React, { useState } from 'react';
import { FileText, Play, ChevronRight, CheckCircle2, Clock, Shield, Bot, Zap, AlertOctagon } from 'lucide-react';

const playbooks = [
    {
        id: 'PB-001',
        name: 'Resposta a Malware/Ransomware',
        category: 'Malware',
        severity: 'critical',
        steps: 9,
        automated: 6,
        avgTime: '22min',
        lastUsed: '28/02/2024',
        description: 'Procedimento padrão para contenção e erradicação de malware, incluindo isolamento de host, análise forense e restauração.',
        tags: ['EDR', 'Isolamento', 'Forense', 'SOAR'],
    },
    {
        id: 'PB-002',
        name: 'Account Takeover (ATO) - Credential Stuffing',
        category: 'Identidade',
        severity: 'high',
        steps: 7,
        automated: 4,
        avgTime: '15min',
        lastUsed: '01/03/2024',
        description: 'Playbook para investigação e resposta a tentativas de tomada de conta via credential stuffing ou phishing de credenciais.',
        tags: ['Azure AD', 'MFA', 'Reset de Senha', 'UEBA'],
    },
    {
        id: 'PB-003',
        name: 'Exfiltração de Dados - DNS Tunneling',
        category: 'Exfiltração',
        severity: 'critical',
        steps: 11,
        automated: 5,
        avgTime: '35min',
        lastUsed: '01/03/2024',
        description: 'Investigação e bloqueio de exfiltração de dados via protocolo DNS. Inclui análise de entropia e bloqueio seletivo.',
        tags: ['DNS', 'DLP', 'Firewall', 'Forense de Rede'],
    },
    {
        id: 'PB-004',
        name: 'Reconhecimento de Rede Interno',
        category: 'Movimento Lateral',
        severity: 'medium',
        steps: 6,
        automated: 3,
        avgTime: '18min',
        lastUsed: '27/02/2024',
        description: 'Resposta a descoberta de scanning de rede interno, mapeando a intenção, o escopo e contendo o host comprometido.',
        tags: ['IDS', 'Microsegmentação', 'NDR'],
    },
];

const reports = [
    { id: 'RPT-2024-031', title: 'Relatório Mensal SOC - Fevereiro 2024', date: '01/03/2024', status: 'finalizado', incidents: 89 },
    { id: 'RPT-2024-028', title: 'Análise de Campanha Phishing Q1/24', date: '28/02/2024', status: 'finalizado', incidents: 34 },
    { id: 'RPT-2024-018', title: 'Relatório Executivo Janeiro 2024', date: '01/02/2024', status: 'finalizado', incidents: 112 },
];

const sevCls = { critical: 'badge-critical', high: 'badge-high', medium: 'badge-medium' };
const sevLabel = { critical: 'Crítico', high: 'Alto', medium: 'Médio' };

export default function Playbooks() {
    const [activeTab, setActiveTab] = useState('playbooks');
    const [runningPb, setRunningPb] = useState(null);

    return (
        <div className="animate-fade-in">
            <div style={{ marginBottom: 20 }}>
                <h1 style={{ fontSize: 22, fontWeight: 800, color: '#f8fafc', letterSpacing: -0.5 }}>Relatórios & Playbooks</h1>
                <p style={{ fontSize: 13, color: '#64748b', marginTop: 4 }}>Procedimentos de resposta e relatórios de operações de segurança</p>
            </div>

            {/* Tabs */}
            <div style={{ display: 'flex', gap: 4, marginBottom: 20, borderBottom: '1px solid rgba(255,255,255,0.07)', paddingBottom: 0 }}>
                {[{ id: 'playbooks', label: 'Playbooks SOAR', icon: Shield }, { id: 'reports', label: 'Relatórios', icon: FileText }].map(({ id, label, icon: Icon }) => (
                    <button
                        key={id}
                        onClick={() => setActiveTab(id)}
                        style={{
                            padding: '8px 16px', fontSize: 13, fontWeight: 600, cursor: 'pointer',
                            border: 'none', background: 'transparent',
                            color: activeTab === id ? '#06b6d4' : '#64748b',
                            borderBottom: activeTab === id ? '2px solid #06b6d4' : '2px solid transparent',
                            display: 'flex', alignItems: 'center', gap: 6, marginBottom: -1, transition: 'all 0.2s'
                        }}
                    >
                        <Icon size={14} /> {label}
                    </button>
                ))}
            </div>

            {activeTab === 'playbooks' && (
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
                    {playbooks.map(pb => (
                        <div key={pb.id} className="card" style={{ position: 'relative', overflow: 'hidden' }}>
                            <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 12 }}>
                                <div>
                                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
                                        <span className={`rep-tag ${sevCls[pb.severity]}`} style={{ fontSize: 11 }}>{sevLabel[pb.severity]}</span>
                                        <span style={{ fontSize: 10, color: '#64748b', fontFamily: "'Fira Code', monospace" }}>{pb.id}</span>
                                    </div>
                                    <div style={{ fontSize: 15, fontWeight: 700, color: '#f8fafc' }}>{pb.name}</div>
                                </div>
                            </div>

                            <p style={{ fontSize: 12, color: '#94a3b8', marginBottom: 12, lineHeight: 1.6 }}>{pb.description}</p>

                            <div style={{ display: 'flex', gap: 16, marginBottom: 14 }}>
                                {[
                                    { label: 'Etapas', value: pb.steps, icon: ChevronRight },
                                    { label: 'Automatizadas', value: pb.automated, icon: Bot },
                                    { label: 'Tempo médio', value: pb.avgTime, icon: Clock },
                                ].map(({ label, value, icon: Icon }) => (
                                    <div key={label} style={{ textAlign: 'center', flex: 1 }}>
                                        <div style={{ fontSize: 16, fontWeight: 800, color: '#f8fafc' }}>{value}</div>
                                        <div style={{ fontSize: 10, color: '#64748b' }}>{label}</div>
                                    </div>
                                ))}
                            </div>

                            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginBottom: 14 }}>
                                {pb.tags.map(tag => (
                                    <span key={tag} style={{
                                        fontSize: 10, background: 'rgba(255,255,255,0.05)', color: '#64748b',
                                        border: '1px solid rgba(255,255,255,0.07)', borderRadius: 4, padding: '2px 7px'
                                    }}>{tag}</span>
                                ))}
                            </div>

                            <div style={{ display: 'flex', gap: 8 }}>
                                <button
                                    className={runningPb === pb.id ? 'btn-safe' : 'btn-primary'}
                                    style={{ flex: 1, justifyContent: 'center', fontSize: 12 }}
                                    onClick={() => setRunningPb(pb.id)}
                                >
                                    {runningPb === pb.id ? (
                                        <><CheckCircle2 size={13} /> Executando...</>
                                    ) : (
                                        <><Play size={13} /> Executar</>
                                    )}
                                </button>
                                <button className="btn-ghost" style={{ fontSize: 12 }}>
                                    <FileText size={13} /> Ver
                                </button>
                            </div>
                        </div>
                    ))}
                </div>
            )}

            {activeTab === 'reports' && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                    <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: 8 }}>
                        <button className="btn-primary" style={{ fontSize: 12 }}>
                            <Bot size={13} /> Gerar Novo Relatório com IA
                        </button>
                    </div>
                    {reports.map(r => (
                        <div key={r.id} className="card" style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
                            <div style={{
                                width: 44, height: 44, borderRadius: 10,
                                background: 'rgba(6,182,212,0.1)', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0
                            }}>
                                <FileText size={20} color="#06b6d4" />
                            </div>
                            <div style={{ flex: 1 }}>
                                <div style={{ fontSize: 14, fontWeight: 700, color: '#f8fafc', marginBottom: 3 }}>{r.title}</div>
                                <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
                                    <span style={{ fontSize: 11, fontFamily: "'Fira Code', monospace", color: '#64748b' }}>{r.id}</span>
                                    <span style={{ fontSize: 11, color: '#64748b' }}>{r.date}</span>
                                    <span style={{ fontSize: 11, color: '#94a3b8' }}>{r.incidents} incidentes analisados</span>
                                </div>
                            </div>
                            <span style={{ fontSize: 11, background: 'rgba(34,197,94,0.1)', color: '#22c55e', border: '1px solid rgba(34,197,94,0.2)', borderRadius: 6, padding: '3px 10px', fontWeight: 600 }}>
                                {r.status.charAt(0).toUpperCase() + r.status.slice(1)}
                            </span>
                            <button className="btn-ghost" style={{ fontSize: 12, flexShrink: 0 }}>Baixar PDF</button>
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
}
