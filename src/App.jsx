import React, { useState } from 'react';
import { HashRouter, Routes, Route, NavLink } from 'react-router-dom';
import {
  Home as HomeIcon, Search, Mail, Map, Bot,
  Shield, Menu, Activity, Bell
} from 'lucide-react';
import Home from './views/Home';
import IOCLookup from './views/IOCLookup';
import EmailHeaderAnalyzer from './views/EmailHeaderAnalyzer';
import MitreExplorer from './views/MitreExplorer';
import AIConsultant from './views/AIConsultant';

const navItems = [
  { path: '/', icon: HomeIcon, label: 'Início', exact: true },
  { path: '/lookup', icon: Search, label: 'IOC Lookup' },
  { path: '/email-header', icon: Mail, label: 'Análise de E-mail' },
  { path: '/mitre', icon: Map, label: 'MITRE ATT&CK' },
  { path: '/consultor', icon: Bot, label: 'AI Consultor' },
];

const toolLinks = [
  { name: 'VirusTotal', url: 'https://www.virustotal.com/', color: '#3b82f6' },
  { name: 'AbuseIPDB', url: 'https://www.abuseipdb.com/', color: '#ef4444' },
  { name: 'IBM X-Force', url: 'https://exchange.xforce.ibmcloud.com/', color: '#06b6d4' },
  { name: 'Hybrid Analysis', url: 'https://www.hybrid-analysis.com/', color: '#f97316' },
  { name: 'MXToolbox', url: 'https://mxtoolbox.com/', color: '#22c55e' },
  { name: 'MITRE ATT&CK', url: 'https://attack.mitre.org/', color: '#a78bfa' },
];

function Sidebar({ collapsed, setCollapsed }) {
  return (
    <aside style={{
      width: collapsed ? 60 : 220,
      background: '#111827',
      borderRight: '1px solid rgba(255,255,255,0.07)',
      display: 'flex', flexDirection: 'column',
      transition: 'width 0.3s cubic-bezier(0.4,0,0.2,1)',
      overflow: 'hidden', flexShrink: 0,
    }}>
      {/* Logo */}
      <div style={{ padding: '18px 12px 14px', borderBottom: '1px solid rgba(255,255,255,0.07)', display: 'flex', alignItems: 'center', gap: 10 }}>
        <div style={{ width: 36, height: 36, borderRadius: 10, flexShrink: 0, background: 'linear-gradient(135deg, #06b6d4, #3b82f6)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <Shield size={20} color="white" strokeWidth={2.5} />
        </div>
        {!collapsed && (
          <div style={{ overflow: 'hidden', whiteSpace: 'nowrap' }}>
            <div style={{ fontWeight: 800, fontSize: 15, color: '#f8fafc', letterSpacing: -0.3 }}>SecOps Flow</div>
            <div style={{ fontSize: 10, color: '#64748b', fontWeight: 500, letterSpacing: 0.5 }}>ANALYST TOOLKIT</div>
          </div>
        )}
      </div>

      {/* Nav */}
      <nav style={{ flex: 1, padding: '10px 8px', display: 'flex', flexDirection: 'column', gap: 2 }}>
        {navItems.map(({ path, icon: Icon, label, exact }) => (
          <NavLink key={path} to={path} end={exact}
            className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
            style={{ justifyContent: collapsed ? 'center' : 'flex-start' }}
          >
            <Icon size={18} style={{ flexShrink: 0 }} />
            {!collapsed && <span style={{ whiteSpace: 'nowrap' }}>{label}</span>}
          </NavLink>
        ))}

        {/* Quick Links to real tools */}
        {!collapsed && (
          <>
            <div style={{ margin: '12px 4px 6px', fontSize: 10, fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: '#475569' }}>
              Ferramentas Externas
            </div>
            {toolLinks.map(({ name, url, color }) => (
              <a key={name} href={url} target="_blank" rel="noopener noreferrer"
                style={{
                  display: 'flex', alignItems: 'center', gap: 8,
                  padding: '7px 12px', borderRadius: 6, fontSize: 12,
                  color: '#64748b', textDecoration: 'none', transition: 'all 0.15s'
                }}
                onMouseEnter={e => { e.currentTarget.style.background = 'rgba(255,255,255,0.04)'; e.currentTarget.style.color = color; }}
                onMouseLeave={e => { e.currentTarget.style.background = 'transparent'; e.currentTarget.style.color = '#64748b'; }}
              >
                <div style={{ width: 6, height: 6, borderRadius: '50%', background: color, flexShrink: 0 }} />
                {name}
              </a>
            ))}
          </>
        )}
      </nav>

      {/* Toggle */}
      <div style={{ padding: '10px 8px', borderTop: '1px solid rgba(255,255,255,0.07)' }}>
        <button onClick={() => setCollapsed(!collapsed)} className="btn-ghost"
          style={{ width: '100%', justifyContent: 'center', padding: 8 }}>
          <Menu size={16} />
          {!collapsed && <span style={{ fontSize: 12 }}>Recolher</span>}
        </button>
      </div>
    </aside>
  );
}

function Header() {
  return (
    <header style={{
      height: 56, background: '#111827',
      borderBottom: '1px solid rgba(255,255,255,0.07)',
      display: 'flex', alignItems: 'center',
      padding: '0 20px', gap: 16, flexShrink: 0,
    }}>
      <div style={{ flex: 1 }} />

      {/* Status das ferramentas */}
      <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
        {[
          { label: 'VirusTotal', status: 'ok' },
          { label: 'AbuseIPDB', status: 'ok' },
          { label: 'IBM X-Force', status: 'ok' },
        ].map(({ label, status }) => (
          <div key={label} style={{
            display: 'flex', alignItems: 'center', gap: 5,
            background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.07)',
            borderRadius: 6, padding: '4px 8px', fontSize: 11, color: '#94a3b8'
          }}>
            <div className="status-dot" style={{ background: status === 'ok' ? '#22c55e' : '#ef4444', width: 6, height: 6 }} />
            {label}
          </div>
        ))}
      </div>
    </header>
  );
}

export default function App() {
  const [collapsed, setCollapsed] = useState(false);
  return (
    <HashRouter>
      <div style={{ display: 'flex', height: '100vh', overflow: 'hidden' }}>
        <Sidebar collapsed={collapsed} setCollapsed={setCollapsed} />
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
          <Header />
          <main style={{ flex: 1, overflow: 'auto', padding: 24, background: '#0f172a' }}>
            <Routes>
              <Route path="/" element={<Home />} />
              <Route path="/lookup" element={<IOCLookup />} />
              <Route path="/email-header" element={<EmailHeaderAnalyzer />} />
              <Route path="/mitre" element={<MitreExplorer />} />
              <Route path="/consultor" element={<AIConsultant />} />
            </Routes>
          </main>
        </div>
      </div>
    </HashRouter>
  );
}
