import React, { useState } from 'react';
import { Search, ExternalLink, ChevronRight, X, AlertTriangle, CheckCircle2, Terminal, Users, Shield, Eye } from 'lucide-react';
import { mitreTactics, mitreTechniques } from '../data/knowledgeBase';
import { getTechniqueDetails } from '../data/techniqueDetails';

// Detecta se a busca é um ID de técnica MITRE (T1059, T1059.001, etc.)
function isTechniqueId(s) {
    return /^T\d{4}(\.\d{3})?$/i.test(s.trim());
}

// Gera URL para link direto no MITRE ATT&CK (sem Google)
function getMitreOfficialUrl(techId) {
    const parts = techId.toUpperCase().split('.');
    return parts.length > 1
        ? `https://attack.mitre.org/techniques/${parts[0]}/${parts[1]}/`
        : `https://attack.mitre.org/techniques/${parts[0]}/`;
}

function getMitreSearchUrl(query) {
    const q = query.trim();
    if (isTechniqueId(q)) return getMitreOfficialUrl(q);
    // Para keywords: vai direto ao MITRE ATT&CK (tem barra de busca integrada no topo)
    return 'https://attack.mitre.org/';
}

const severityColor = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#3b82f6' };
const SUB = (s) => s.split('.').length > 1;

// ─── Painel de detalhe da técnica ─────────────────────────────────────────────
function TechniqueDetailPanel({ tech, onClose }) {
    const [tab, setTab] = useState('overview');
    const details = getTechniqueDetails(tech.id);
    const tactic = mitreTactics.find(t => t.id === tech.tacticId);
    const sev = tech.severity || 'medium';
    const sevColor = severityColor[sev] || '#64748b';

    const tabs = [
        { id: 'overview', label: 'Visão Geral' },
        { id: 'investigation', label: `Investigação${details ? ` (${details.investigationSteps?.length})` : ''}` },
        { id: 'examples', label: 'Exemplos Reais' },
        { id: 'response', label: 'Resposta' },
        { id: 'detection', label: 'Detecção' },
    ];

    return (
        <div style={{ overflowY: 'auto', borderLeft: '1px solid rgba(255,255,255,0.07)', paddingLeft: 16 }}>
            {/* Header */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 12 }}>
                <div style={{ flex: 1 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                        <span style={{ fontSize: 13, fontFamily: "'Fira Code', monospace", color: '#06b6d4', fontWeight: 800 }}>{tech.id}</span>
                        {tactic && (
                            <span style={{ fontSize: 10, background: `${tactic.color}15`, color: tactic.color, border: `1px solid ${tactic.color}30`, borderRadius: 4, padding: '1px 6px' }}>
                                {tactic.icon} {tactic.nameP || tactic.namePT}
                            </span>
                        )}
                        <span style={{ fontSize: 10, background: `${sevColor}12`, color: sevColor, border: `1px solid ${sevColor}25`, borderRadius: 4, padding: '1px 6px', fontWeight: 700 }}>
                            {sev.charAt(0).toUpperCase() + sev.slice(1)}
                        </span>
                    </div>
                    <div style={{ fontSize: 16, fontWeight: 800, color: '#f8fafc', lineHeight: 1.3 }}>{tech.name}</div>
                </div>
                <button onClick={onClose} className="btn-ghost" style={{ padding: 6, flexShrink: 0 }}>
                    <X size={14} />
                </button>
            </div>

            {/* Tabs */}
            <div style={{ display: 'flex', gap: 4, marginBottom: 14, overflowX: 'auto', paddingBottom: 2, borderBottom: '1px solid rgba(255,255,255,0.07)' }}>
                {tabs.map(t => (
                    <button key={t.id} onClick={() => setTab(t.id)} style={{
                        fontSize: 11, fontWeight: 600, padding: '5px 10px', borderRadius: 6, whiteSpace: 'nowrap',
                        background: tab === t.id ? 'rgba(6,182,212,0.12)' : 'transparent',
                        color: tab === t.id ? '#06b6d4' : '#64748b',
                        border: `1px solid ${tab === t.id ? 'rgba(6,182,212,0.3)' : 'transparent'}`,
                        cursor: 'pointer', transition: 'all 0.15s'
                    }}>{t.label}</button>
                ))}
            </div>

            {/* Tab: Visão Geral */}
            {tab === 'overview' && (
                <div>
                    <p style={{ fontSize: 12, color: '#94a3b8', lineHeight: 1.75, marginBottom: 14 }}>
                        {details?.fullDesc || tech.desc}
                    </p>

                    {tech.subtecnicas?.length > 0 && (
                        <div style={{ marginBottom: 14 }}>
                            <div style={{ fontSize: 11, fontWeight: 700, color: '#64748b', marginBottom: 8, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                                Subtécnicas ({tech.subtecnicas.length})
                            </div>
                            {tech.subtecnicas.map(s => {
                                const parts = s.split(' - ');
                                const sid = parts[0];
                                return (
                                    <div key={s} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '5px 0', borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                                        <a href={getMitreOfficialUrl(sid)} target="_blank" rel="noopener noreferrer"
                                            style={{ fontSize: 11, fontFamily: "'Fira Code', monospace", color: '#06b6d4', textDecoration: 'none', fontWeight: 700 }}>
                                            {sid}
                                        </a>
                                        <span style={{ fontSize: 11, color: '#94a3b8' }}>{parts.slice(1).join(' - ')}</span>
                                    </div>
                                );
                            })}
                        </div>
                    )}

                    <div style={{ marginBottom: 14 }}>
                        <div style={{ fontSize: 11, fontWeight: 700, color: '#64748b', marginBottom: 8, textTransform: 'uppercase', letterSpacing: '0.06em' }}>Plataformas</div>
                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                            {tech.platforms?.map(p => (
                                <span key={p} style={{ fontSize: 11, background: 'rgba(255,255,255,0.05)', color: '#94a3b8', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 4, padding: '2px 8px' }}>{p}</span>
                            ))}
                        </div>
                    </div>

                    <a href={getMitreOfficialUrl(tech.id)} target="_blank" rel="noopener noreferrer"
                        className="btn-ghost" style={{ fontSize: 12, width: '100%', justifyContent: 'center' }}>
                        Ver {tech.id} no MITRE ATT&CK Oficial <ExternalLink size={12} />
                    </a>
                </div>
            )}

            {/* Tab: Investigação */}
            {tab === 'investigation' && (
                <div>
                    {details?.investigationSteps?.length > 0 ? (
                        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                            {details.investigationSteps.map((step) => (
                                <div key={step.step} style={{
                                    background: step.step === 1 ? 'rgba(239,68,68,0.06)' : 'rgba(255,255,255,0.02)',
                                    border: `1px solid ${step.step === 1 ? 'rgba(239,68,68,0.2)' : 'rgba(255,255,255,0.06)'}`,
                                    borderRadius: 8, padding: '10px 12px'
                                }}>
                                    <div style={{ display: 'flex', alignItems: 'flex-start', gap: 10 }}>
                                        <div style={{
                                            width: 22, height: 22, borderRadius: '50%', flexShrink: 0,
                                            background: step.step <= 2 ? 'rgba(239,68,68,0.15)' : 'rgba(6,182,212,0.12)',
                                            border: `1px solid ${step.step <= 2 ? 'rgba(239,68,68,0.35)' : 'rgba(6,182,212,0.25)'}`,
                                            display: 'flex', alignItems: 'center', justifyContent: 'center',
                                            fontSize: 11, fontWeight: 800, color: step.step <= 2 ? '#ef4444' : '#06b6d4'
                                        }}>{step.step}</div>
                                        <div style={{ flex: 1 }}>
                                            <div style={{ fontSize: 12, fontWeight: 700, color: '#f8fafc', marginBottom: 4 }}>{step.title}</div>
                                            <div style={{ fontSize: 11, color: '#94a3b8', lineHeight: 1.65 }}>{step.desc}</div>
                                        </div>
                                    </div>
                                </div>
                            ))}
                        </div>
                    ) : (
                        <div style={{ textAlign: 'center', padding: 24 }}>
                            <p style={{ fontSize: 12, color: '#64748b', marginBottom: 14 }}>Passos detalhados de investigação ainda não disponíveis para esta técnica na base local.</p>
                            <a href={getMitreOfficialUrl(tech.id)} target="_blank" rel="noopener noreferrer" className="btn-ghost" style={{ fontSize: 12 }}>
                                Consultar procedimentos no MITRE ATT&CK <ExternalLink size={12} />
                            </a>
                        </div>
                    )}

                    {/* Hunting Queries */}
                    {details?.huntingQueries?.length > 0 && (
                        <div style={{ marginTop: 16 }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 8 }}>
                                <Terminal size={13} color="#a78bfa" />
                                <span style={{ fontSize: 11, fontWeight: 700, color: '#a78bfa', textTransform: 'uppercase', letterSpacing: '0.06em' }}>Hunting Queries (SIEM/EDR)</span>
                            </div>
                            {details.huntingQueries.map((q, i) => (
                                <div key={i} style={{ fontFamily: "'Fira Code', monospace", fontSize: 10, color: '#94a3b8', background: 'rgba(0,0,0,0.3)', borderRadius: 6, padding: '8px 10px', marginBottom: 6, lineHeight: 1.6, whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
                                    {q}
                                </div>
                            ))}
                        </div>
                    )}
                </div>
            )}

            {/* Tab: Exemplos Reais */}
            {tab === 'examples' && (
                <div>
                    {details?.procedureExamples?.length > 0 ? (
                        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                            <p style={{ fontSize: 11, color: '#475569', marginBottom: 6 }}>Grupos de ameaça, malware e campanhas documentados usando esta técnica:</p>
                            {details.procedureExamples.map((ex, i) => (
                                <div key={i} style={{ background: 'rgba(167,139,250,0.05)', border: '1px solid rgba(167,139,250,0.15)', borderRadius: 8, padding: '12px 14px' }}>
                                    <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 6 }}>
                                        <Users size={13} color="#a78bfa" />
                                        <span style={{ fontSize: 12, fontWeight: 700, color: '#c4b5fd' }}>{ex.actor}</span>
                                    </div>
                                    <p style={{ fontSize: 11, color: '#94a3b8', lineHeight: 1.65, margin: 0 }}>{ex.desc}</p>
                                </div>
                            ))}
                        </div>
                    ) : (
                        <div style={{ textAlign: 'center', padding: 24 }}>
                            <p style={{ fontSize: 12, color: '#64748b', marginBottom: 14 }}>Exemplos de procedimentos ainda não disponíveis para esta técnica na base local.</p>
                            <a href={`${getMitreOfficialUrl(tech.id)}#examples`} target="_blank" rel="noopener noreferrer" className="btn-ghost" style={{ fontSize: 12 }}>
                                Ver procedimentos no MITRE ATT&CK <ExternalLink size={12} />
                            </a>
                        </div>
                    )}
                </div>
            )}

            {/* Tab: Resposta */}
            {tab === 'response' && (
                <div>
                    {(details?.responseActions?.length > 0 || tech.mitigations?.length > 0) ? (
                        <>
                            {details?.responseActions?.length > 0 && (
                                <div style={{ marginBottom: 16 }}>
                                    <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 10 }}>
                                        <AlertTriangle size={13} color="#f97316" />
                                        <span style={{ fontSize: 11, fontWeight: 700, color: '#f97316', textTransform: 'uppercase', letterSpacing: '0.06em' }}>Ações de Resposta ao Incidente</span>
                                    </div>
                                    {details.responseActions.map((action, i) => (
                                        <div key={i} style={{ display: 'flex', gap: 10, padding: '7px 0', borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
                                            <CheckCircle2 size={14} color="#22c55e" style={{ flexShrink: 0, marginTop: 1 }} />
                                            <span style={{ fontSize: 11, color: '#94a3b8', lineHeight: 1.6 }}>{action}</span>
                                        </div>
                                    ))}
                                </div>
                            )}
                            {tech.mitigations?.length > 0 && (
                                <div>
                                    <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 10 }}>
                                        <Shield size={13} color="#22c55e" />
                                        <span style={{ fontSize: 11, fontWeight: 700, color: '#22c55e', textTransform: 'uppercase', letterSpacing: '0.06em' }}>Mitigações MITRE (M-codes)</span>
                                    </div>
                                    {tech.mitigations.map(m => (
                                        <div key={m} style={{ display: 'flex', gap: 10, padding: '6px 0', borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                                            <span style={{ fontSize: 11, fontFamily: "'Fira Code', monospace", color: '#22c55e', fontWeight: 700, flexShrink: 0 }}>{m.split(' - ')[0]}</span>
                                            <span style={{ fontSize: 11, color: '#94a3b8' }}>{m.split(' - ').slice(1).join(' - ')}</span>
                                        </div>
                                    ))}
                                </div>
                            )}
                        </>
                    ) : (
                        <div style={{ textAlign: 'center', padding: 24 }}>
                            <p style={{ fontSize: 12, color: '#64748b', marginBottom: 14 }}>Ações de resposta detalhadas ainda não disponíveis para esta técnica.</p>
                            <a href={`${getMitreOfficialUrl(tech.id)}#mitigations`} target="_blank" rel="noopener noreferrer" className="btn-ghost" style={{ fontSize: 12 }}>
                                Ver mitigações no MITRE ATT&CK <ExternalLink size={12} />
                            </a>
                        </div>
                    )}
                </div>
            )}

            {/* Tab: Detecção */}
            {tab === 'detection' && (
                <div>
                    {tech.detections?.length > 0 ? (
                        <>
                            <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 10 }}>
                                <Eye size={13} color="#06b6d4" />
                                <span style={{ fontSize: 11, fontWeight: 700, color: '#06b6d4', textTransform: 'uppercase', letterSpacing: '0.06em' }}>Indicadores de Detecção</span>
                            </div>
                            {tech.detections.map(d => (
                                <div key={d} style={{ display: 'flex', gap: 10, padding: '7px 0', borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
                                    <Eye size={13} color="#64748b" style={{ flexShrink: 0, marginTop: 1 }} />
                                    <span style={{ fontSize: 11, color: '#94a3b8', lineHeight: 1.6 }}>{d}</span>
                                </div>
                            ))}

                            {details?.huntingQueries?.length > 0 && (
                                <div style={{ marginTop: 16 }}>
                                    <div style={{ fontSize: 11, fontWeight: 700, color: '#a78bfa', marginBottom: 8 }}>Hunting Queries</div>
                                    {details.huntingQueries.map((q, i) => (
                                        <div key={i} style={{ fontFamily: "'Fira Code', monospace", fontSize: 10, color: '#94a3b8', background: 'rgba(0,0,0,0.3)', borderRadius: 6, padding: '8px 10px', marginBottom: 6, lineHeight: 1.6, whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
                                            {q}
                                        </div>
                                    ))}
                                </div>
                            )}
                        </>
                    ) : (
                        <div style={{ textAlign: 'center', padding: 24 }}>
                            <a href={`${getMitreOfficialUrl(tech.id)}#detection`} target="_blank" rel="noopener noreferrer" className="btn-ghost" style={{ fontSize: 12 }}>
                                Ver detecções no MITRE ATT&CK <ExternalLink size={12} />
                            </a>
                        </div>
                    )}
                </div>
            )}
        </div>
    );
}

// ─── Componente principal ──────────────────────────────────────────────────────
export default function MitreExplorer() {
    const [search, setSearch] = useState('');
    const [selectedTactic, setSelectedTactic] = useState(null);
    const [selectedTech, setSelectedTech] = useState(null);

    const filteredTechniques = mitreTechniques.filter(t => {
        const s = search.toLowerCase();
        const matchSearch = !s || t.id.toLowerCase().includes(s) || t.name.toLowerCase().includes(s) || t.desc.toLowerCase().includes(s);
        const matchTactic = !selectedTactic || t.tacticId === selectedTactic;
        return matchSearch && matchTactic;
    });

    const getCountForTactic = (tacticId) => mitreTechniques.filter(t => t.tacticId === tacticId).length;

    return (
        <div className="animate-fade-in" style={{ display: 'flex', flexDirection: 'column', height: 'calc(100vh - 108px)', gap: 0 }}>
            <div style={{ marginBottom: 14, flexShrink: 0 }}>
                <h1 style={{ fontSize: 22, fontWeight: 800, color: '#f8fafc', letterSpacing: -0.5 }}>MITRE ATT&CK Explorer</h1>
                <p style={{ fontSize: 13, color: '#64748b', marginTop: 4 }}>
                    Base local: <strong style={{ color: '#94a3b8' }}>{mitreTechniques.length} técnicas indexadas</strong> com procedimentos, exemplos e hunting queries · ATT&CK Enterprise v14
                </p>
            </div>

            {/* Search + links */}
            <div style={{ display: 'flex', gap: 10, marginBottom: 14, alignItems: 'center', flexShrink: 0 }}>
                <div style={{ position: 'relative', flex: 1, maxWidth: 440 }}>
                    <Search size={14} style={{ position: 'absolute', left: 11, top: '50%', transform: 'translateY(-50%)', color: '#64748b' }} />
                    <input className="search-input" style={{ width: '100%', paddingLeft: 32, fontSize: 13 }}
                        placeholder="Buscar por ID (T1059, T1059.001), nome ou palavra-chave..."
                        value={search} onChange={e => setSearch(e.target.value)} />
                </div>
                {selectedTactic && (
                    <button onClick={() => setSelectedTactic(null)} className="btn-ghost" style={{ fontSize: 12 }}>
                        <X size={13} /> Limpar tática
                    </button>
                )}
                {search.trim() && (
                    <a href={getMitreSearchUrl(search)} target="_blank" rel="noopener noreferrer"
                        className="btn-ghost" style={{ fontSize: 12, color: '#06b6d4', borderColor: 'rgba(6,182,212,0.3)' }}>
                        {isTechniqueId(search) ? `Ver ${search.toUpperCase()} no MITRE ↗` : 'Buscar no MITRE ATT&CK ↗'}
                        <ExternalLink size={12} />
                    </a>
                )}
                <a href="https://attack.mitre.org/" target="_blank" rel="noopener noreferrer"
                    className="btn-ghost" style={{ fontSize: 12, marginLeft: search.trim() ? 0 : 'auto' }}>
                    MITRE ATT&CK Oficial <ExternalLink size={12} />
                </a>
            </div>

            <div style={{ flex: 1, display: 'grid', gridTemplateColumns: selectedTech ? '200px 1fr 420px' : '200px 1fr', gap: 14, minHeight: 0 }}>

                {/* Tactics sidebar */}
                <div style={{ overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 3 }}>
                    <div style={{ fontSize: 10, fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: '#475569', marginBottom: 6, paddingLeft: 4 }}>
                        14 Táticas
                    </div>
                    {mitreTactics.map(tactic => {
                        const isActive = selectedTactic === tactic.id;
                        const count = getCountForTactic(tactic.id);
                        return (
                            <button key={tactic.id}
                                onClick={() => setSelectedTactic(isActive ? null : tactic.id)}
                                style={{
                                    width: '100%', textAlign: 'left',
                                    background: isActive ? `${tactic.color}15` : 'rgba(255,255,255,0.03)',
                                    border: `1px solid ${isActive ? tactic.color + '40' : 'rgba(255,255,255,0.07)'}`,
                                    borderRadius: 7, padding: '7px 10px', cursor: 'pointer', transition: 'all 0.15s',
                                }}
                                onMouseEnter={e => { if (!isActive) { e.currentTarget.style.background = `${tactic.color}08`; e.currentTarget.style.borderColor = `${tactic.color}30`; } }}
                                onMouseLeave={e => { if (!isActive) { e.currentTarget.style.background = 'rgba(255,255,255,0.03)'; e.currentTarget.style.borderColor = 'rgba(255,255,255,0.07)'; } }}
                            >
                                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                                        <span style={{ fontSize: 13 }}>{tactic.icon}</span>
                                        <span style={{ fontSize: 11, fontWeight: 600, color: isActive ? tactic.color : '#94a3b8' }}>
                                            {tactic.nameP || tactic.namePT || tactic.name}
                                        </span>
                                    </div>
                                    <span style={{ fontSize: 10, color: '#64748b', background: 'rgba(255,255,255,0.05)', borderRadius: 4, padding: '1px 5px' }}>{count}</span>
                                </div>
                                <div style={{ fontSize: 9, fontFamily: "'Fira Code', monospace", color: '#475569', marginTop: 1 }}>{tactic.id}</div>
                            </button>
                        );
                    })}
                </div>

                {/* Techniques list */}
                <div style={{ overflowY: 'auto' }}>
                    <div style={{ fontSize: 10, fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: '#475569', marginBottom: 10, paddingLeft: 2 }}>
                        Técnicas ({filteredTechniques.length})
                    </div>
                    {filteredTechniques.length === 0 ? (
                        <div style={{ textAlign: 'center', padding: '36px 16px' }}>
                            <div style={{ fontSize: 30, marginBottom: 12 }}>🔍</div>
                            <div style={{ fontSize: 14, fontWeight: 700, color: '#94a3b8', marginBottom: 8 }}>
                                Não encontrado na base local
                            </div>
                            <div style={{ fontSize: 12, color: '#64748b', marginBottom: 20, lineHeight: 1.7 }}>
                                A base local tem {mitreTechniques.length} técnicas indexadas.<br />
                                O MITRE ATT&CK oficial possui 600+ técnicas e subtécnicas.
                            </div>
                            <a href={getMitreSearchUrl(search)} target="_blank" rel="noopener noreferrer"
                                className="btn-primary" style={{ fontSize: 13, display: 'inline-flex', gap: 8 }}>
                                {isTechniqueId(search)
                                    ? <>Ver <strong>{search.toUpperCase()}</strong> no MITRE ATT&CK</>
                                    : <>Buscar no MITRE ATT&CK</>}
                                <ExternalLink size={13} />
                            </a>
                            <div style={{ fontSize: 11, color: '#475569', marginTop: 10 }}>
                                {isTechniqueId(search)
                                    ? `Abre a página da técnica em attack.mitre.org`
                                    : 'Abre attack.mitre.org — use a barra de busca do site'}
                            </div>
                        </div>
                    ) : (
                        <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
                            {filteredTechniques.map(tech => {
                                const tactic = mitreTactics.find(t => t.id === tech.tacticId);
                                const isSelected = selectedTech?.id === tech.id;
                                const sev = tech.severity || 'medium';
                                const hasDetails = !!getTechniqueDetails(tech.id);
                                return (
                                    <div key={tech.id}
                                        onClick={() => setSelectedTech(isSelected ? null : tech)}
                                        style={{
                                            background: isSelected ? 'rgba(6,182,212,0.06)' : '#1e293b',
                                            border: `1px solid ${isSelected ? 'rgba(6,182,212,0.3)' : 'rgba(255,255,255,0.07)'}`,
                                            borderLeft: `3px solid ${severityColor[sev] || '#64748b'}`,
                                            borderRadius: 8, padding: '11px 13px', cursor: 'pointer', transition: 'all 0.15s'
                                        }}
                                        onMouseEnter={e => { if (!isSelected) e.currentTarget.style.background = 'rgba(255,255,255,0.03)'; }}
                                        onMouseLeave={e => { if (!isSelected) e.currentTarget.style.background = '#1e293b'; }}
                                    >
                                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 10 }}>
                                            <div style={{ flex: 1 }}>
                                                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 3 }}>
                                                    <span style={{ fontSize: 12, fontFamily: "'Fira Code', monospace", color: '#06b6d4', fontWeight: 700 }}>{tech.id}</span>
                                                    <span style={{ fontSize: 13, fontWeight: 700, color: '#f8fafc' }}>{tech.name}</span>
                                                    {hasDetails && (
                                                        <span style={{ fontSize: 9, background: 'rgba(34,197,94,0.12)', color: '#22c55e', border: '1px solid rgba(34,197,94,0.25)', borderRadius: 3, padding: '1px 5px', fontWeight: 700 }}>
                                                            DETALHADO
                                                        </span>
                                                    )}
                                                </div>
                                                <p style={{ fontSize: 11, color: '#64748b', lineHeight: 1.5, margin: 0 }}>
                                                    {tech.desc.slice(0, 100)}...
                                                </p>
                                                <div style={{ display: 'flex', gap: 5, marginTop: 5 }}>
                                                    {tactic && (
                                                        <span style={{ fontSize: 10, background: `${tactic.color}12`, color: tactic.color, border: `1px solid ${tactic.color}25`, borderRadius: 4, padding: '1px 6px' }}>
                                                            {tactic.icon} {tactic.nameP || tactic.namePT}
                                                        </span>
                                                    )}
                                                    <span style={{ fontSize: 10, background: `${severityColor[sev]}12`, color: severityColor[sev], border: `1px solid ${severityColor[sev]}25`, borderRadius: 4, padding: '1px 6px', fontWeight: 600 }}>
                                                        {sev.charAt(0).toUpperCase() + sev.slice(1)}
                                                    </span>
                                                </div>
                                            </div>
                                            <ChevronRight size={14} color={isSelected ? '#06b6d4' : '#334155'} style={{ flexShrink: 0, transition: 'transform 0.2s', transform: isSelected ? 'rotate(90deg)' : 'none' }} />
                                        </div>
                                    </div>
                                );
                            })}
                        </div>
                    )}
                </div>

                {/* Detail panel */}
                {selectedTech && (
                    <TechniqueDetailPanel
                        tech={selectedTech}
                        onClose={() => setSelectedTech(null)}
                    />
                )}
            </div>
        </div>
    );
}
