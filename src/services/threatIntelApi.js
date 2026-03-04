// ─── Threat Intel API Service ───────────────────────────────────────────────
// Todas as funções retornam um objeto { status, data, error }
// status: 'ok' | 'no_key' | 'error' | 'not_found'

const KEYS_STORAGE_KEY = 'secops_api_keys';

export function loadApiKeys() {
    try {
        return JSON.parse(localStorage.getItem(KEYS_STORAGE_KEY) || '{}');
    } catch { return {}; }
}

export function saveApiKeys(keys) {
    localStorage.setItem(KEYS_STORAGE_KEY, JSON.stringify(keys));
}

// ─── IP Info (GRÁTIS, sem API key, CORS OK) ──────────────────────────────────
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
export async function fetchAbuseIPDB(ip, apiKey) {
    if (!apiKey) return { status: 'no_key' };
    try {
        const url = `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90&verbose`;
        const res = await fetch(url, {
            headers: { 'Key': apiKey, 'Accept': 'application/json' },
        });
        if (res.status === 401) return { status: 'error', error: 'API Key inválida' };
        if (res.status === 429) return { status: 'error', error: 'Rate limit atingido' };
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const d = await res.json();
        return { status: 'ok', data: d.data };
    } catch (e) {
        // CORS error ou falha de rede
        if (e.message.includes('Failed to fetch') || e.message.includes('CORS')) {
            return { status: 'error', error: 'CORS — use a chave na extensão ou servidor proxy' };
        }
        return { status: 'error', error: e.message };
    }
}

// ─── VirusTotal ──────────────────────────────────────────────────────────────
export async function fetchVirusTotalIP(ip, apiKey) {
    if (!apiKey) return { status: 'no_key' };
    try {
        const res = await fetch(`https://www.virustotal.com/api/v3/ip-addresses/${ip}`, {
            headers: { 'x-apikey': apiKey },
        });
        if (res.status === 401) return { status: 'error', error: 'API Key inválida' };
        if (res.status === 404) return { status: 'not_found' };
        if (res.status === 429) return { status: 'error', error: 'Rate limit atingido (4 req/min)' };
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const d = await res.json();
        return { status: 'ok', data: d.data?.attributes };
    } catch (e) {
        if (e.message.includes('Failed to fetch') || e.message.includes('CORS')) {
            return { status: 'cors_error', error: 'CORS bloqueado pelo VirusTotal' };
        }
        return { status: 'error', error: e.message };
    }
}

export async function fetchVirusTotalHash(hash, apiKey) {
    if (!apiKey) return { status: 'no_key' };
    try {
        const res = await fetch(`https://www.virustotal.com/api/v3/files/${hash}`, {
            headers: { 'x-apikey': apiKey },
        });
        if (res.status === 401) return { status: 'error', error: 'API Key inválida' };
        if (res.status === 404) return { status: 'not_found' };
        if (res.status === 429) return { status: 'error', error: 'Rate limit (4 req/min free)' };
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const d = await res.json();
        return { status: 'ok', data: d.data?.attributes };
    } catch (e) {
        if (e.message.includes('Failed to fetch') || e.message.includes('CORS')) {
            return { status: 'cors_error', error: 'CORS bloqueado pelo VirusTotal' };
        }
        return { status: 'error', error: e.message };
    }
}

export async function fetchVirusTotalDomain(domain, apiKey) {
    if (!apiKey) return { status: 'no_key' };
    try {
        const res = await fetch(`https://www.virustotal.com/api/v3/domains/${domain}`, {
            headers: { 'x-apikey': apiKey },
        });
        if (res.status === 401) return { status: 'error', error: 'API Key inválida' };
        if (res.status === 404) return { status: 'not_found' };
        if (res.status === 429) return { status: 'error', error: 'Rate limit (4 req/min free)' };
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const d = await res.json();
        return { status: 'ok', data: d.data?.attributes };
    } catch (e) {
        if (e.message.includes('Failed to fetch') || e.message.includes('CORS')) {
            return { status: 'cors_error', error: 'CORS bloqueado pelo VirusTotal' };
        }
        return { status: 'error', error: e.message };
    }
}

// ─── NVD (CVE, GRÁTIS, sem key, CORS OK) ─────────────────────────────────────
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
    // VT: malicious > 0 = malicious, suspicious > 0 = suspicious
    const vtMalicious = vtData?.last_analysis_stats?.malicious || 0;
    const vtSuspicious = vtData?.last_analysis_stats?.suspicious || 0;
    const abuseScore = abuseData?.abuseConfidenceScore || 0;
    const abuseReports = abuseData?.totalReports || 0;

    if (vtMalicious > 2 || abuseScore >= 80) return { verdict: 'malicious', label: 'Malicioso', color: '#ef4444', icon: '🔴' };
    if (vtMalicious > 0 || vtSuspicious > 0 || abuseScore >= 25 || abuseReports >= 5) return { verdict: 'suspicious', label: 'Suspeito ⚠️', color: '#f97316', icon: '🟠' };
    if ((vtData || abuseData) && vtMalicious === 0 && abuseScore < 10) return { verdict: 'clean', label: 'Sem reports', color: '#22c55e', icon: '🟢' };
    return { verdict: 'unknown', label: 'Não verificado', color: '#64748b', icon: '⚪' };
}
