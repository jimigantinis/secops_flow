// ─── Threat Intel API Service ───────────────────────────────────────────────
// Todas as funções retornam um objeto { status, data, error }
// status: 'ok' | 'no_key' | 'error' | 'not_found' | 'cors_blocked'
//
// Em desenvolvimento (npm run dev): usa proxy do Vite → sem CORS
// Em produção (GitHub Pages): APIs com custom headers são bloqueadas pelo browser

const KEYS_STORAGE_KEY = 'secops_api_keys';

// Detecta se está em modo desenvolvimento (proxy Vite disponível)
const IS_DEV = import.meta.env.DEV;

export function loadApiKeys() {
    try {
        return JSON.parse(localStorage.getItem(KEYS_STORAGE_KEY) || '{}');
    } catch { return {}; }
}

export function saveApiKeys(keys) {
    localStorage.setItem(KEYS_STORAGE_KEY, JSON.stringify(keys));
}

// ─── IP Info (GRÁTIS, sem API key, CORS OK em qualquer ambiente) ──────────────
export async function fetchIPInfo(ip) {
    try {
        const res = await fetch(`https://ipinfo.io/${ip}/json`);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const d = await res.json();
        if (d.bogon) return { status: 'ok', data: { ...d, isPrivate: true } };
        return { status: 'ok', data: d };
    } catch (e) {
        return { status: 'error', error: e.message };
    }
}

// ─── AbuseIPDB ───────────────────────────────────────────────────────────────
// Em dev: usa /api/abuseipdb → proxy Vite → api.abuseipdb.com (sem CORS)
// Em produção: CORS bloqueia → retorna cors_blocked
export async function fetchAbuseIPDB(ip, apiKey) {
    if (!apiKey) return { status: 'no_key' };

    // Produção: browser não consegue fazer chamadas com custom headers a APIs externas
    if (!IS_DEV) {
        return {
            status: 'cors_blocked',
            error: 'Disponível apenas ao rodar localmente (npm run dev)',
        };
    }

    try {
        // Rota via proxy Vite: /api/abuseipdb → https://api.abuseipdb.com
        const url = `/api/abuseipdb/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90&verbose`;
        const res = await fetch(url, {
            headers: { 'Key': apiKey, 'Accept': 'application/json' },
        });
        if (res.status === 401) return { status: 'error', error: 'API Key inválida — verifique em abuseipdb.com' };
        if (res.status === 422) return { status: 'error', error: 'IP inválido' };
        if (res.status === 429) return { status: 'error', error: 'Rate limit atingido — aguarde e tente novamente' };
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const d = await res.json();
        return { status: 'ok', data: d.data };
    } catch (e) {
        return { status: 'error', error: e.message };
    }
}

// ─── VirusTotal ──────────────────────────────────────────────────────────────
// Em dev: usa /api/virustotal → proxy Vite → www.virustotal.com (sem CORS)
// Em produção: CORS bloqueia → retorna cors_blocked
export async function fetchVirusTotalIP(ip, apiKey) {
    if (!apiKey) return { status: 'no_key' };
    if (!IS_DEV) return { status: 'cors_blocked', error: 'Disponível apenas localmente (npm run dev)' };

    try {
        const res = await fetch(`/api/virustotal/api/v3/ip-addresses/${ip}`, {
            headers: { 'x-apikey': apiKey },
        });
        if (res.status === 401) return { status: 'error', error: 'API Key inválida' };
        if (res.status === 404) return { status: 'not_found' };
        if (res.status === 429) return { status: 'error', error: 'Rate limit — plano free: 4 req/min' };
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const d = await res.json();
        return { status: 'ok', data: d.data?.attributes };
    } catch (e) {
        return { status: 'error', error: e.message };
    }
}

export async function fetchVirusTotalHash(hash, apiKey) {
    if (!apiKey) return { status: 'no_key' };
    if (!IS_DEV) return { status: 'cors_blocked', error: 'Disponível apenas localmente (npm run dev)' };

    try {
        const res = await fetch(`/api/virustotal/api/v3/files/${hash}`, {
            headers: { 'x-apikey': apiKey },
        });
        if (res.status === 401) return { status: 'error', error: 'API Key inválida' };
        if (res.status === 404) return { status: 'not_found' };
        if (res.status === 429) return { status: 'error', error: 'Rate limit — plano free: 4 req/min' };
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const d = await res.json();
        return { status: 'ok', data: d.data?.attributes };
    } catch (e) {
        return { status: 'error', error: e.message };
    }
}

export async function fetchVirusTotalDomain(domain, apiKey) {
    if (!apiKey) return { status: 'no_key' };
    if (!IS_DEV) return { status: 'cors_blocked', error: 'Disponível apenas localmente (npm run dev)' };

    try {
        const res = await fetch(`/api/virustotal/api/v3/domains/${domain}`, {
            headers: { 'x-apikey': apiKey },
        });
        if (res.status === 401) return { status: 'error', error: 'API Key inválida' };
        if (res.status === 404) return { status: 'not_found' };
        if (res.status === 429) return { status: 'error', error: 'Rate limit — plano free: 4 req/min' };
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const d = await res.json();
        return { status: 'ok', data: d.data?.attributes };
    } catch (e) {
        return { status: 'error', error: e.message };
    }
}

// ─── NVD (CVE, GRÁTIS, sem key, CORS OK em qualquer ambiente) ────────────────
export async function fetchNVDCve(cveId) {
    try {
        const res = await fetch(`https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(cveId)}`);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const d = await res.json();
        const vuln = d.vulnerabilities?.[0]?.cve;
        if (!vuln) return { status: 'not_found' };
        return { status: 'ok', data: vuln };
    } catch (e) {
        return { status: 'error', error: e.message };
    }
}

// ─── Helper: calcular veredicto consolidado ──────────────────────────────────
export function calcVerdict(vtData, abuseData, ipInfoData) {
    const vtMalicious = vtData?.last_analysis_stats?.malicious || 0;
    const vtSuspicious = vtData?.last_analysis_stats?.suspicious || 0;
    const abuseScore = abuseData?.abuseConfidenceScore || 0;
    const abuseReports = abuseData?.totalReports || 0;

    if (vtMalicious > 2 || abuseScore >= 80) return { verdict: 'malicious', label: 'Malicioso', color: '#ef4444', icon: '🔴' };
    if (vtMalicious > 0 || vtSuspicious > 0 || abuseScore >= 25 || abuseReports >= 5) return { verdict: 'suspicious', label: 'Suspeito ⚠️', color: '#f97316', icon: '🟠' };
    if ((vtData || abuseData) && vtMalicious === 0 && abuseScore < 10) return { verdict: 'clean', label: 'Sem reports', color: '#22c55e', icon: '🟢' };
    return { verdict: 'unknown', label: 'Não verificado', color: '#64748b', icon: '⚪' };
}
