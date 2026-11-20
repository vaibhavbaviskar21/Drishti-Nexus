'use strict';
// Drishti Nexus dashboard. Log and alert content is attacker-controlled:
// every value reaches the DOM through textContent / createElement (see h()),
// never innerHTML.

const state = {
    stats: null, alerts: [], incidents: [], session: null, logs: [],
    paused: false, view: 'overview', drawerReturn: null,
};
const SEV_ORDER = ['critical', 'high', 'medium', 'low'];
const $ = (id) => document.getElementById(id);

// h builds an element; children may be strings (as text), nodes, or null.
function h(tag, attrs, ...children) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
        if (v === null || v === undefined || v === false) continue;
        if (k === 'class') el.className = v;
        else if (k === 'onclick') el.addEventListener('click', v);
        else el.setAttribute(k, v === true ? '' : String(v));
    }
    append(el, children);
    return el;
}
function append(el, children) {
    for (const c of children.flat(Infinity)) {
        if (c === null || c === undefined || c === false) continue;
        el.appendChild(c instanceof Node ? c : document.createTextNode(String(c)));
    }
}
function fill(el, ...children) { el.replaceChildren(); append(el, children); }

function fmtTime(t) {
    if (!t || t.startsWith('0001-')) return '—';
    return t.replace('T', ' ').replace(/\.\d+/, '').replace('Z', ' UTC');
}
function fmtNum(n) { return (n || 0).toLocaleString(); }
function sevBadge(sev) {
    const s = String(sev || 'unknown').toLowerCase();
    return h('span', { class: 'sev sev-' + (SEV_ORDER.includes(s) ? s : 'unknown') }, s);
}
// Plain link to the public ATT&CK page; the ID is validated so it cannot inject a URL.
function attackLink(id, name) {
    if (!/^T\d{4}(\.\d{3})?$/.test(id || '')) return null;
    const href = 'https://attack.mitre.org/techniques/' + id.replace('.', '/') + '/';
    return h('a', { href, target: '_blank', rel: 'noopener noreferrer', class: 'tech' }, id + (name ? ' · ' + name : ''));
}
function hostOf(a) {
    if (a.details && typeof a.details.source === 'string') return a.details.source;
    const m = /(?:^|\|)host=([^|]+)/.exec(a.correlation_key || '');
    return m ? m[1] : '';
}
function empty(text) { return h('p', { class: 'empty' }, text); }

async function getJSON(url) {
    const r = await fetch(url, { headers: { Accept: 'application/json' } });
    if (!r.ok) throw new Error(url + ': HTTP ' + r.status);
    return r.json();
}

// ---------- data loading ----------
async function loadAll() {
    try {
        const [stats, alerts, incidents, session] = await Promise.all([
            getJSON('/api/stats'), getJSON('/api/alerts'), getJSON('/api/incidents'), getJSON('/api/session'),
        ]);
        Object.assign(state, { stats, alerts: alerts || [], incidents: incidents || [], session });
        renderOverview(); renderIncidents(); populateAlertFilters(); renderAlerts(); renderCustody();
        $('lastUpdate').textContent = 'Updated ' + new Date().toLocaleTimeString();
    } catch (e) {
        setStatus('Error loading data', false);
        console.error(e);
    }
    loadLogs();
}
async function loadLogs() {
    if (state.paused) return;
    try {
        state.logs = (await getJSON('/api/logs')) || [];
        renderStream();
    } catch (e) { console.error(e); }
}

// ---------- overview ----------
function bars(el, rows, opts) {
    if (!rows.length) return fill(el, empty('No data'));
    const max = Math.max(...rows.map((r) => r.count), 1);
    fill(el, rows.map((r) => {
        const bar = h('span', { class: 'bar-fill' + (opts && opts.sev ? ' bg-' + r.name : '') });
        bar.style.width = Math.max(2, (r.count / max) * 100) + '%';
        return h('div', { class: 'bar-row' },
            h('span', { class: 'bar-label', title: r.name }, r.name),
            h('span', { class: 'bar-track', 'aria-hidden': 'true' }, bar),
            h('span', { class: 'bar-value' }, fmtNum(r.count)));
    }));
}
function renderOverview() {
    const s = state.stats || {};
    $('kpiLines').textContent = fmtNum(s.lines);
    $('kpiEntries').textContent = fmtNum(s.entries);
    $('kpiAlerts').textContent = fmtNum(s.alert_count);
    $('kpiIncidents').textContent = fmtNum(s.incident_count);
    $('kpiQuality').textContent = s.entries ? (s.clean_parse_pct || 0).toFixed(1) + '%' : '–';
    const q = s.parse_quality || {};
    $('kpiQualityNote').textContent = s.entries ? `${fmtNum(q.Partial)} partial · ${fmtNum(q.BestEffort)} best-effort` : '';
    $('incidentTabCount').textContent = s.incident_count ? String(s.incident_count) : '';
    $('alertTabCount').textContent = s.alert_count ? String(s.alert_count) : '';

    const bySev = s.alerts_by_severity || {};
    bars($('chartSeverity'), SEV_ORDER.filter((k) => bySev[k]).map((k) => ({ name: k, count: bySev[k] })), { sev: true });
    bars($('chartRules'), s.alerts_by_rule || []);
    bars($('chartSources'), s.top_sources || []);

    const top = state.incidents.slice(0, 5);
    fill($('overviewIncidents'), top.length ? h('ul', { class: 'mini-list' }, top.map((inc) =>
        h('li', null, h('button', { type: 'button', class: 'row-btn', onclick: () => openIncident(inc.id) },
            sevBadge(inc.max_severity), h('strong', null, inc.id),
            h('span', { class: 'muted' }, inc.alert_count + ' alert' + (inc.alert_count === 1 ? '' : 's')),
            h('span', { class: 'chips' }, inc.hosts.map((x) => h('span', { class: 'chip' }, x))),
            h('span', { class: 'muted push' }, fmtTime(inc.last_seen)))))) : empty('No incidents. Load evidence with: drishti serve -log <file|dir>'));
    renderChain();
}

// ---------- the latest incident, drawn as a chain across host lanes ----------
// An alert sits in its source host's lane; one that names a destination host
// (lateral movement) runs a leader across to that host's lane.
function alertLanes(a) {
    const d = a.details || {};
    const src = (typeof d.source_host === 'string' && d.source_host) || hostOf(a);
    const dst = typeof d.destination_host === 'string' && d.destination_host !== src ? d.destination_host : '';
    return { src, dst };
}
function clock(t) { return t && !t.startsWith('0001-') ? t.slice(11, 19) : ''; }
function renderChain() {
    const el = $('overviewChain'), inc = state.incidents[0];
    if (!inc) {
        $('chainMeta').textContent = '';
        return fill(el, empty('No incidents. Load evidence with: drishti serve -log <file|dir>'));
    }
    const alerts = inc.alerts.slice().sort((a, b) => (a.timestamp < b.timestamp ? -1 : a.timestamp > b.timestamp ? 1 : 0));
    const lanes = [];
    const lane = (x) => { if (x && !lanes.includes(x)) lanes.push(x); };
    alerts.forEach((a) => { const l = alertLanes(a); lane(l.src); lane(l.dst); });
    (inc.hosts || []).forEach(lane);
    if (!lanes.length) lanes.push('');
    $('chainMeta').textContent = fmtTime(inc.first_seen) + ' to ' + fmtTime(inc.last_seen);

    const grid = h('div', { class: 'lanes' });
    grid.style.setProperty('--lanes', String(lanes.length));
    grid.appendChild(h('span', { class: 'lane-corner' },
        h('button', { type: 'button', class: 'link-btn strong', onclick: () => openIncident(inc.id) }, inc.id)));
    lanes.forEach((x, i) => {
        const head = h('span', { class: 'lane-head', 'aria-hidden': 'true' }, x || 'unknown host');
        head.style.gridColumn = String(i + 2);
        grid.appendChild(head);
        const rule = h('span', { class: 'lane-rule', 'aria-hidden': 'true' });
        rule.style.gridColumn = String(i + 2);
        rule.style.gridRow = '1 / ' + (alerts.length + 2);
        grid.appendChild(rule);
    });
    alerts.forEach((a, r) => {
        const l = alertLanes(a), from = Math.max(0, lanes.indexOf(l.src)), to = l.dst ? lanes.indexOf(l.dst) : from;
        const lo = Math.min(from, to), hi = Math.max(from, to);
        const time = h('time', { class: 'lane-time', datetime: a.timestamp }, clock(a.timestamp));
        time.style.gridRow = String(r + 2);
        const step = h('div', { class: 'step sevtext-' + a.severity + (hi > lo ? ' step-move' + (to < from ? ' step-back' : '') : '') },
            h('div', { class: 'step-body' },
                h('div', { class: 'step-head' }, sevBadge(a.severity),
                    h('button', { type: 'button', class: 'link-btn strong', onclick: (e) => openAlert(a.id, e.currentTarget) }, a.rule_name)),
                h('div', { class: 'step-meta' },
                    h('span', { class: 'step-host' }, l.dst ? (to < from ? l.dst + ' to ' + l.src : l.src + ' to ' + l.dst) : l.src),
                    a.mitre_technique_id ? h('span', { class: 'chip chip-tech' }, a.mitre_technique_id) : null,
                    h('span', { class: 'muted small' }, a.id),
                    a.count > 1 ? h('span', { class: 'muted small' }, '×' + a.count) : null)),
            hi > lo ? h('span', { class: 'leader', 'aria-hidden': 'true' }) : null,
            hi > lo ? h('span', { class: 'leader-end' }, (to < from ? 'from ' : 'to ') + l.dst) : null);
        step.style.gridColumn = (lo + 2) + ' / ' + (hi + 3);
        step.style.gridRow = String(r + 2);
        grid.append(time, step);
    });
    fill(el, grid);
}

// ---------- incidents ----------
function renderIncidents() {
    const list = $('incidentList');
    if (!state.incidents.length) return fill(list, empty('No incidents detected.'));
    const open = new Set([...list.querySelectorAll('details[open]')].map((d) => d.dataset.id));
    fill(list, state.incidents.map((inc) => {
        const d = h('details', { class: 'incident sevline-' + inc.max_severity, 'data-id': inc.id, open: open.has(inc.id) },
            h('summary', null,
                sevBadge(inc.max_severity),
                h('span', { class: 'inc-id' }, inc.id),
                h('span', { class: 'inc-range' }, fmtTime(inc.first_seen) + ' → ' + fmtTime(inc.last_seen)),
                h('span', { class: 'chips' }, inc.hosts.map((x) => h('span', { class: 'chip' }, x))),
                h('span', { class: 'chips' }, inc.techniques.map((x) => h('span', { class: 'chip chip-tech' }, x))),
                h('span', { class: 'muted push' }, inc.alert_count + ' alert' + (inc.alert_count === 1 ? '' : 's'))),
            h('ol', { class: 'timeline' }, inc.alerts.map((a) => h('li', { class: 'tl-item' },
                h('time', { class: 'tl-time', datetime: a.timestamp }, clock(a.timestamp)),
                h('span', { class: 'tl-dot bg-' + a.severity, 'aria-hidden': 'true' }),
                h('div', { class: 'tl-body' },
                    h('div', { class: 'tl-head' },
                        sevBadge(a.severity),
                        h('button', { type: 'button', class: 'link-btn strong', onclick: (e) => openAlert(a.id, e.currentTarget) }, a.rule_name),
                        h('span', { class: 'muted small' }, a.id),
                        a.count > 1 ? h('span', { class: 'chip' }, '×' + a.count) : null),
                    h('div', { class: 'muted small' }, fmtTime(a.timestamp) + (a.last_seen !== a.timestamp ? ' → ' + fmtTime(a.last_seen) : '')),
                    h('p', { class: 'tl-desc' }, a.description),
                    relatedButtons(a.related_alerts))))));
        return d;
    }));
}
function relatedButtons(ids) {
    if (!ids || !ids.length) return null;
    return h('div', { class: 'related' }, h('span', { class: 'muted small' }, 'Linked:'),
        ids.map((id) => h('button', { type: 'button', class: 'chip chip-btn', onclick: (e) => openAlert(id, e.currentTarget) }, id)));
}
function openIncident(id) {
    selectTab('incidents');
    const d = [...$('incidentList').querySelectorAll('details')].find((x) => x.dataset.id === id);
    if (d) { d.open = true; d.scrollIntoView({ block: 'start' }); d.querySelector('summary').focus(); }
}

// ---------- alerts ----------
function setOptions(sel, values) {
    const cur = sel.value;
    fill(sel, h('option', { value: '' }, 'All'), values.map((v) => h('option', { value: v }, v)));
    sel.value = values.includes(cur) ? cur : '';
}
function populateAlertFilters() {
    const uniq = (f) => [...new Set(state.alerts.map(f).filter(Boolean))].sort();
    setOptions($('alertRule'), uniq((a) => a.rule_name));
    setOptions($('alertHost'), uniq(hostOf));
}
function filteredAlerts() {
    const q = $('alertSearch').value.trim().toLowerCase();
    const sev = $('alertSeverity').value, rule = $('alertRule').value, host = $('alertHost').value;
    return state.alerts.filter((a) => (!sev || a.severity === sev) && (!rule || a.rule_name === rule) && (!host || hostOf(a) === host) &&
        (!q || [a.id, a.incident_id, a.rule_name, a.description, a.correlation_key, a.mitre_technique_id].join(' ').toLowerCase().includes(q)));
}
function renderAlerts() {
    const rows = filteredAlerts();
    $('alertCountLabel').textContent = `${rows.length} of ${state.alerts.length}`;
    if (!rows.length) return fill($('alertRows'), h('tr', null, h('td', { colspan: 7 }, empty(state.alerts.length ? 'No alerts match the filters.' : 'No alerts detected.'))));
    fill($('alertRows'), rows.map((a) => {
        const tr = h('tr', { tabindex: 0, class: 'clickable', 'aria-label': `${a.severity} ${a.rule_name} ${a.id}, open details` },
            h('td', null, sevBadge(a.severity)),
            h('td', { class: 'nowrap' }, fmtTime(a.timestamp)),
            h('td', null, a.rule_name),
            h('td', { class: 'nowrap' }, hostOf(a)),
            h('td', { class: 'nowrap' }, a.mitre_technique_id || ''),
            h('td', { class: 'num' }, fmtNum(a.count)),
            h('td', { class: 'desc' }, a.description));
        tr.addEventListener('click', () => openAlert(a.id, tr));
        tr.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); openAlert(a.id, tr); } });
        return tr;
    }));
}

function download(name, type, content) {
    const url = URL.createObjectURL(new Blob([content], { type }));
    const a = h('a', { href: url, download: name });
    document.body.appendChild(a); a.click(); a.remove();
    URL.revokeObjectURL(url);
}
// Neutralise spreadsheet formula injection from attacker-controlled text.
function csvCell(v) {
    let s = String(v === undefined || v === null ? '' : v);
    if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
    return '"' + s.replace(/"/g, '""') + '"';
}
function exportAlerts(fmt) {
    const rows = filteredAlerts(), day = new Date().toISOString().slice(0, 10);
    if (fmt === 'json') return download(`drishti-alerts-${day}.json`, 'application/json', JSON.stringify(rows, null, 2));
    const cols = ['id', 'incident_id', 'severity', 'timestamp', 'last_seen', 'rule_name', 'mitre_technique_id', 'count', 'correlation_key', 'description'];
    download(`drishti-alerts-${day}.csv`, 'text/csv', [cols.join(','), ...rows.map((a) => cols.map((c) => csvCell(a[c])).join(','))].join('\n'));
}

// ---------- alert drawer ----------
async function openAlert(id, opener) {
    state.drawerReturn = opener || document.activeElement;
    const body = $('drawerBody');
    $('drawerTitle').textContent = id;
    fill(body, empty('Loading…'));
    $('scrim').hidden = false; $('drawer').hidden = false;
    $('drawer').focus();
    let a;
    try { a = await getJSON('/api/alerts/' + encodeURIComponent(id)); } catch (e) { return fill(body, empty('Could not load ' + id + '.')); }
    $('drawerTitle').textContent = a.rule_name;
    const kv = (k, v) => (v === null || v === undefined || v === '' ? null : [h('dt', null, k), h('dd', null, v)]);
    const details = Object.keys(a.details || {}).sort().map((k) => {
        const v = a.details[k];
        return kv(k, typeof v === 'object' ? JSON.stringify(v) : String(v));
    });
    fill(body,
        h('div', { class: 'drawer-meta' }, sevBadge(a.severity), h('span', { class: 'muted' }, a.id),
            a.incident_id ? h('button', { type: 'button', class: 'chip chip-btn', onclick: () => { closeDrawer(); openIncident(a.incident_id); } }, a.incident_id) : null),
        h('p', { class: 'drawer-desc' }, a.description),
        h('dl', { class: 'kv' },
            kv('First seen', fmtTime(a.timestamp)), kv('Last seen', fmtTime(a.last_seen)), kv('Matches', fmtNum(a.count)),
            kv('Hosts', (a.hosts || []).join(', ')), kv('Correlation key', a.correlation_key),
            kv('ATT&CK', a.mitre_technique_id ? h('span', null, attackLink(a.mitre_technique_id, a.mitre_technique_name), a.mitre_tactic ? h('span', { class: 'muted' }, ' (' + a.mitre_tactic + ')') : null) : null)),
        relatedButtons(a.related_alerts),
        details.length ? [h('h3', null, 'Details'), h('dl', { class: 'kv' }, details)] : null,
        h('h3', null, `Evidence (${(a.evidence || []).length} cited line${(a.evidence || []).length === 1 ? '' : 's'})`),
        (a.evidence || []).length ? h('ol', { class: 'evidence' }, a.evidence.map((e) => h('li', null,
            h('div', { class: 'ev-id' }, e.id),
            e.found ? h('pre', null, e.raw_log) : h('p', { class: 'muted small' }, 'Entry no longer in memory; see the source file at this line.')))) : empty('No evidence lines cited.'));
}
function closeDrawer() {
    if ($('drawer').hidden) return;
    $('drawer').hidden = true; $('scrim').hidden = true;
    if (state.drawerReturn && document.contains(state.drawerReturn)) state.drawerReturn.focus();
}
function trapFocus(e) {
    if (e.key !== 'Tab' || $('drawer').hidden) return;
    const f = [...$('drawer').querySelectorAll('button, a[href], [tabindex]:not([tabindex="-1"])')];
    if (!f.length) return;
    const first = f[0], last = f[f.length - 1];
    if (e.shiftKey && (document.activeElement === first || document.activeElement === $('drawer'))) { e.preventDefault(); last.focus(); }
    else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
}

// ---------- live stream ----------
const LOG_SEV = ['debug', 'info', 'notice', 'warning', 'error', 'critical', 'alert', 'emergency'];
function renderStream() {
    const q = $('logSearch').value.trim().toLowerCase();
    const logs = state.logs.slice().reverse().filter((l) => !q || (l.raw_log || l.message || '').toLowerCase().includes(q) || (l.source || '').toLowerCase().includes(q));
    $('streamState').textContent = (state.paused ? 'Paused · ' : 'Live · ') + logs.length + ' recent entries';
    if (!logs.length) return fill($('logStream'), empty(state.logs.length ? 'No lines match.' : 'No log entries loaded.'));
    fill($('logStream'), logs.map((l) => h('div', { class: 'log-line' },
        h('span', { class: 'log-time' }, fmtTime(l.timestamp)),
        h('span', { class: 'log-sev lsev-' + (LOG_SEV[l.severity] || 'info') }, (LOG_SEV[l.severity] || '?').toUpperCase()),
        h('span', { class: 'log-src' }, l.source || ''),
        h('span', { class: 'log-msg' }, l.message || l.raw_log || ''))));
}
function togglePause() {
    state.paused = !state.paused;
    $('pauseBtn').textContent = state.paused ? 'Resume' : 'Pause';
    $('pauseBtn').setAttribute('aria-pressed', String(state.paused));
    if (!state.paused) loadLogs(); else renderStream();
}
function setStatus(text, ok) {
    $('statusText').textContent = text;
    $('statusDot').className = 'status-dot ' + (ok ? 'ok' : 'bad');
}
function initWebSocket() {
    const ws = new WebSocket((location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host + '/api/ws');
    ws.onopen = () => setStatus('Live', true);
    ws.onclose = () => { setStatus('Disconnected, retrying…', false); setTimeout(initWebSocket, 5000); };
    ws.onmessage = loadAll;
}

// ---------- chain of custody ----------
function table(headers, rows) {
    return h('div', { class: 'table-wrap' }, h('table', { class: 'data-table' },
        h('thead', null, h('tr', null, headers.map((x) => h('th', { scope: 'col' }, x)))),
        h('tbody', null, rows.map((r) => h('tr', null, r.map((c) => h('td', null, c)))))));
}
function renderCustody() {
    const s = state.session, el = $('custody');
    if (!s) return fill(el, h('article', { class: 'card' }, h('h2', null, 'Chain of custody'),
        empty('No evidence loaded in this session. Start the dashboard with: drishti serve -log <file|dir>')));
    const kv = (k, v) => (v ? [h('dt', null, k), h('dd', null, v)] : null);
    const c = s.config || {};
    const hashOk = (e) => (e.unchanged === true ? h('span', { class: 'ok-badge' }, 'verified unchanged') : e.unchanged === false ? h('span', { class: 'bad-badge' }, 'CHANGED') : h('span', { class: 'muted' }, 'pending'));
    fill(el,
        h('article', { class: 'card' }, h('h2', null, 'Audit session'),
            h('dl', { class: 'kv two-col' },
                kv('Session ID', h('code', null, s.session_id)), kv('Status', s.status), kv('Command', [s.command].concat(s.args || []).join(' ')),
                kv('Started', fmtTime(s.started_at)), kv('Finished', s.finished_at ? fmtTime(s.finished_at) : ''),
                kv('Tool version', s.tool_version), kv('Go / platform', s.go_version + ' · ' + s.platform),
                kv('OS user', s.os_user), kv('Host', s.hostname))),
        h('article', { class: 'card' }, h('h2', null, `Evidence files (${(s.evidence || []).length})`),
            h('p', { class: 'muted small' }, 'Each file is SHA-256 hashed before analysis, opened read-only, and re-hashed when the session finishes.'),
            table(['Label', 'Path', 'Size', 'SHA-256', 'Integrity'], (s.evidence || []).map((e) => [
                e.label, e.abs_path || e.path, fmtNum(e.size_bytes) + ' B', h('code', { class: 'hash' }, e.sha256), hashOk(e)]))),
        h('article', { class: 'card' }, h('h2', null, 'Effective configuration'),
            h('dl', { class: 'kv two-col' },
                kv('Config file', c.config_path || 'built-in defaults'), kv('Config SHA-256', c.config_sha256 ? h('code', { class: 'hash' }, c.config_sha256) : ''),
                kv('Normal hours', c.normal_hours), kv('Incident gap', c.incident_gap), kv('Assumed timezone', c.assumed_timezone), kv('Storage', c.storage)),
            (c.warnings || []).length ? h('ul', { class: 'warnings' }, c.warnings.map((w) => h('li', null, w))) : null,
            table(['Rule', 'Enabled', 'Severity', 'Threshold', 'Window'], (c.rules || []).map((r) => [
                r.name, r.enabled ? 'yes' : 'no', sevBadge(r.severity), r.threshold ? String(r.threshold) : '—', r.time_window || '—']))));
}

// ---------- tabs, theme ----------
const TABS = ['overview', 'incidents', 'alerts', 'stream', 'custody'];
function selectTab(name, focus) {
    if (!TABS.includes(name)) name = 'overview';
    state.view = name;
    for (const t of TABS) {
        const on = t === name, tab = $('tab-' + t);
        tab.setAttribute('aria-selected', String(on));
        tab.tabIndex = on ? 0 : -1;
        $('view-' + t).hidden = !on;
        if (on && focus) tab.focus();
    }
    if (location.hash !== '#' + name) history.replaceState(null, '', '#' + name);
}
function tabKeys(e) {
    const i = TABS.indexOf(state.view);
    const next = { ArrowRight: i + 1, ArrowLeft: i - 1, Home: 0, End: TABS.length - 1 }[e.key];
    if (next === undefined) return;
    e.preventDefault();
    selectTab(TABS[(next + TABS.length) % TABS.length], true);
}
function isDark() {
    const t = document.documentElement.getAttribute('data-theme');
    return t ? t === 'dark' : matchMedia('(prefers-color-scheme: dark)').matches;
}
function toggleTheme() {
    const t = isDark() ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', t);
    try { localStorage.setItem('drishti-theme', t); } catch (e) { /* not persisted */ }
    syncThemeBtn();
}
function syncThemeBtn() {
    const dark = isDark();
    $('themeBtn').setAttribute('aria-pressed', String(dark));
    $('themeBtn').setAttribute('aria-label', dark ? 'Switch to light mode' : 'Switch to dark mode');
    $('themeBtn').title = dark ? 'Switch to light mode' : 'Switch to dark mode';
}

document.addEventListener('DOMContentLoaded', () => {
    for (const t of TABS) $('tab-' + t).addEventListener('click', () => selectTab(t));
    document.querySelector('.tabs').addEventListener('keydown', tabKeys);
    document.querySelectorAll('[data-goto]').forEach((b) => b.addEventListener('click', () => selectTab(b.dataset.goto, true)));
    ['alertSearch', 'alertSeverity', 'alertRule', 'alertHost'].forEach((id) => $(id).addEventListener('input', renderAlerts));
    $('exportCsv').addEventListener('click', () => exportAlerts('csv'));
    $('exportJson').addEventListener('click', () => exportAlerts('json'));
    $('logSearch').addEventListener('input', renderStream);
    $('pauseBtn').addEventListener('click', togglePause);
    $('refreshBtn').addEventListener('click', loadAll);
    $('themeBtn').addEventListener('click', toggleTheme);
    matchMedia('(prefers-color-scheme: dark)').addEventListener('change', syncThemeBtn);
    $('drawerClose').addEventListener('click', closeDrawer);
    $('scrim').addEventListener('click', closeDrawer);
    document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeDrawer(); trapFocus(e); });

    syncThemeBtn();
    selectTab(location.hash.slice(1));
    window.addEventListener('hashchange', () => selectTab(location.hash.slice(1)));
    initWebSocket();
    loadAll();
    setInterval(loadAll, 15000);
});
