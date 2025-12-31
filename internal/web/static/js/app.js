// Dashboard state
let stats = {};
let logs = [];
let alerts = [];
let allLogs = [];
let allAlerts = [];
let ws = null;

// Initialize dashboard
document.addEventListener('DOMContentLoaded', () => {
    initWebSocket();
    loadStats();
    loadLogs();
    loadAlerts();
    populateSourceFilter();
    
    // Refresh data every 30 seconds
    setInterval(loadStats, 30000);
    setInterval(loadLogs, 30000);
    setInterval(loadAlerts, 30000);
});

// WebSocket connection for real-time updates
function initWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/api/ws`;
    
    ws = new WebSocket(wsUrl);
    
    ws.onopen = () => {
        console.log('WebSocket connected');
        updateStatus('Connected', true);
    };
    
    ws.onclose = () => {
        console.log('WebSocket disconnected');
        updateStatus('Disconnected', false);
        // Attempt to reconnect after 5 seconds
        setTimeout(initWebSocket, 5000);
    };
    
    ws.onerror = (error) => {
        console.error('WebSocket error:', error);
        updateStatus('Error', false);
    };
    
    ws.onmessage = (event) => {
        const data = JSON.parse(event.data);
        handleRealtimeUpdate(data);
    };
}

function updateStatus(text, isConnected) {
    const statusDot = document.getElementById('statusDot');
    const statusText = document.getElementById('statusText');
    
    statusText.textContent = text;
    statusDot.style.background = isConnected ? 'var(--accent-green)' : 'var(--accent-red)';
}

function handleRealtimeUpdate(data) {
    // Refresh displays when new data arrives
    loadStats();
    loadLogs();
    loadAlerts();
}

// Load statistics
async function loadStats() {
    try {
        const response = await fetch('/api/stats');
        stats = await response.json();
        
        document.getElementById('totalLogs').textContent = formatNumber(stats.log_count);
        document.getElementById('totalAlerts').textContent = formatNumber(stats.alert_count);
        document.getElementById('criticalAlerts').textContent = formatNumber(stats.alerts_by_severity?.critical || 0);
        document.getElementById('highAlerts').textContent = formatNumber(stats.alerts_by_severity?.high || 0);
        
        renderSeverityChart(stats.severity_breakdown);
        updateTimestamp();
    } catch (error) {
        console.error('Failed to load stats:', error);
    }
}

// Load logs
async function loadLogs() {
    try {
        const response = await fetch('/api/logs');
        allLogs = await response.json();
        logs = allLogs;
        renderLogs();
    } catch (error) {
        console.error('Failed to load logs:', error);
    }
}

// Load alerts
async function loadAlerts() {
    try {
        const response = await fetch('/api/alerts');
        allAlerts = await response.json();
        alerts = allAlerts;
        renderAlerts();
    } catch (error) {
        console.error('Failed to load alerts:', error);
    }
}

// Render alerts
function renderAlerts() {
    const alertList = document.getElementById('alertList');
    
    if (!alerts || alerts.length === 0) {
        alertList.innerHTML = '<p class="empty-state">No alerts detected</p>';
        return;
    }
    
    // Show most recent 20 alerts
    const recentAlerts = alerts.slice(0, 20);
    
    alertList.innerHTML = recentAlerts.map(alert => {
        const time = new Date(alert.timestamp).toLocaleString();
        const severity = (alert.severity || 'medium').toLowerCase();
        return `
            <div class="alert-item ${severity}">
                <div class="alert-header">
                    <span class="alert-rule">${escapeHtml(alert.rule_name)}</span>
                    <span class="alert-severity ${severity}">${alert.severity || 'Medium'}</span>
                </div>
                <div class="alert-description">${escapeHtml(alert.description)}</div>
                <div class="alert-time">${time}</div>
            </div>
        `;
    }).join('');
}

// Render logs
function renderLogs() {
    const logList = document.getElementById('logList');
    
    if (!logs || logs.length === 0) {
        logList.innerHTML = '<p class="empty-state">No logs available</p>';
        return;
    }
    
    // Apply filter
    const filter = document.getElementById('severityFilter').value;
    let filteredLogs = logs;
    
    if (filter !== 'all') {
        filteredLogs = logs.filter(log => {
            const logSeverity = getSeverityName(log.severity);
            return logSeverity === filter;
        });
    }
    
    // Reverse to show newest first
    filteredLogs = [...filteredLogs].reverse();
    
    logList.innerHTML = filteredLogs.map(log => {
        const time = new Date(log.timestamp).toLocaleTimeString();
        const severity = getSeverityName(log.severity);
        return `
            <div class="log-entry">
                <span class="log-time">${time}</span>
                <span class="log-severity ${severity}">${severity}</span>
                <span class="log-source">${escapeHtml(log.source)}</span>
                <span class="log-message">${escapeHtml(log.message)}</span>
            </div>
        `;
    }).join('');
}

// Render severity chart
function renderSeverityChart(breakdown) {
    const chart = document.getElementById('severityChart');
    
    if (!breakdown) {
        chart.innerHTML = '<p class="empty-state">No data</p>';
        return;
    }
    
    const severities = ['DEBUG', 'INFO', 'NOTICE', 'WARNING', 'ERROR', 'CRITICAL', 'ALERT', 'EMERGENCY'];
    
    chart.innerHTML = severities.map(sev => {
        const count = breakdown[sev] || 0;
        if (count === 0) return '';
        
        return `
            <div class="severity-item">
                <div class="severity-item-label">${sev}</div>
                <div class="severity-item-count">${formatNumber(count)}</div>
            </div>
        `;
    }).join('');
}

// Utility functions
function getSeverityName(level) {
    const names = ['DEBUG', 'INFO', 'NOTICE', 'WARNING', 'ERROR', 'CRITICAL', 'ALERT', 'EMERGENCY'];
    return names[level] || 'UNKNOWN';
}

function formatNumber(num) {
    if (num >= 1000000) return (num / 1000000).toFixed(1) + 'M';
    if (num >= 1000) return (num / 1000).toFixed(1) + 'K';
    return num.toString();
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function updateTimestamp() {
    const now = new Date().toLocaleString();
    document.getElementById('lastUpdate').textContent = now;
}

// Interactive functions
function refreshLogs() {
    loadLogs();
}

function refreshAlerts() {
    loadAlerts();
}

function filterLogs() {
    const search = document.getElementById('logSearch').value.toLowerCase();
    const severity = document.getElementById('severityFilter').value;
    const source = document.getElementById('sourceFilter').value;
    const date = document.getElementById('dateFilter').value;
    
    logs = allLogs.filter(log => {
        // Search filter
        if (search && !log.message.toLowerCase().includes(search) && 
            !log.source.toLowerCase().includes(search)) {
            return false;
        }
        
        // Severity filter
        if (severity !== 'all') {
            const logSeverity = getSeverityName(log.severity);
            if (logSeverity !== severity) return false;
        }
        
        // Source filter
        if (source !== 'all' && log.source !== source) {
            return false;
        }
        
        // Date filter
        if (date) {
            const logDate = new Date(log.timestamp).toISOString().split('T')[0];
            if (logDate !== date) return false;
        }
        
        return true;
    });
    
    renderLogs();
}

function filterAlerts() {
    const search = document.getElementById('alertSearch').value.toLowerCase();
    const severity = document.getElementById('alertSeverityFilter').value;
    
    alerts = allAlerts.filter(alert => {
        // Search filter
        if (search && !alert.rule_name.toLowerCase().includes(search) && 
            !alert.description.toLowerCase().includes(search)) {
            return false;
        }
        
        // Severity filter
        if (severity !== 'all') {
            const alertSeverity = (alert.severity || 'medium').toLowerCase();
            if (alertSeverity !== severity) return false;
        }
        
        return true;
    });
    
    renderAlerts();
}

function populateSourceFilter() {
    const sourceFilter = document.getElementById('sourceFilter');
    const sources = new Set(allLogs.map(log => log.source));
    
    sources.forEach(source => {
        const option = document.createElement('option');
        option.value = source;
        option.textContent = source;
        sourceFilter.appendChild(option);
    });
}
// Report generation functions
function generateReport() {
    const modal = document.getElementById('reportModal');
    modal.classList.add('show');
}

function closeReportModal() {
    const modal = document.getElementById('reportModal');
    modal.classList.remove('show');
}

function generateReportFile() {
    const includeAlerts = document.getElementById('reportAlerts').checked;
    const includeStats = document.getElementById('reportStats').checked;
    const includeLogs = document.getElementById('reportLogs').checked;
    const includeSeverity = document.getElementById('reportSeverity').checked;
    const format = document.getElementById('reportFormat').value;
    
    let reportData = {
        timestamp: new Date().toISOString(),
        title: 'Drishti Nexus Security Report'
    };
    
    if (includeStats) {
        reportData.statistics = {
            totalLogs: stats.log_count || 0,
            totalAlerts: stats.alert_count || 0,
            critical: stats.alerts_by_severity?.critical || 0,
            high: stats.alerts_by_severity?.high || 0
        };
    }
    
    if (includeAlerts) {
        reportData.alerts = allAlerts.map(alert => ({
            timestamp: alert.timestamp,
            rule: alert.rule_name,
            severity: alert.severity || 'Medium',
            description: alert.description
        }));
    }
    
    if (includeLogs) {
        reportData.logs = allLogs.map(log => ({
            timestamp: log.timestamp,
            severity: getSeverityName(log.severity),
            source: log.source,
            message: log.message
        }));
    }
    
    if (includeSeverity) {
        reportData.severityDistribution = stats.severity_breakdown || {};
    }
    
    let fileContent, fileName, mimeType;
    
    if (format === 'json') {
        fileContent = JSON.stringify(reportData, null, 2);
        fileName = `security-report-${new Date().toISOString().split('T')[0]}.json`;
        mimeType = 'application/json';
    } else if (format === 'csv') {
        fileContent = generateCSVReport(reportData);
        fileName = `security-report-${new Date().toISOString().split('T')[0]}.csv`;
        mimeType = 'text/csv';
    } else if (format === 'html') {
        fileContent = generateHTMLReport(reportData);
        fileName = `security-report-${new Date().toISOString().split('T')[0]}.html`;
        mimeType = 'text/html';
    }
    
    downloadFile(fileContent, fileName, mimeType);
    closeReportModal();
}

function generateCSVReport(data) {
    let csv = 'Security Report\n';
    csv += `Generated: ${data.timestamp}\n\n`;
    
    if (data.statistics) {
        csv += 'STATISTICS\n';
        csv += `Total Logs,${data.statistics.totalLogs}\n`;
        csv += `Total Alerts,${data.statistics.totalAlerts}\n`;
        csv += `Critical,${data.statistics.critical}\n`;
        csv += `High Priority,${data.statistics.high}\n\n`;
    }
    
    if (data.alerts && data.alerts.length > 0) {
        csv += 'ALERTS\n';
        csv += 'Timestamp,Rule,Severity,Description\n';
        data.alerts.forEach(alert => {
            const description = alert.description.replace(/"/g, '""');
            csv += `"${alert.timestamp}","${alert.rule}","${alert.severity}","${description}"\n`;
        });
        csv += '\n';
    }
    
    if (data.logs && data.logs.length > 0) {
        csv += 'LOG ENTRIES\n';
        csv += 'Timestamp,Severity,Source,Message\n';
        data.logs.slice(0, 1000).forEach(log => { // Limit to 1000 logs in CSV
            const message = log.message.replace(/"/g, '""');
            csv += `"${log.timestamp}","${log.severity}","${log.source}","${message}"\n`;
        });
    }
    
    return csv;
}

function generateHTMLReport(data) {
    let html = `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Security Report</title>
    <style>
        body { font-family: Arial, sans-serif; background: #f5f5f5; color: #333; margin: 0; padding: 20px; }
        .container { max-width: 1000px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
        h1 { color: #1a2238; border-bottom: 3px solid #3b82f6; padding-bottom: 10px; }
        h2 { color: #1a2238; margin-top: 30px; }
        table { width: 100%; border-collapse: collapse; margin: 15px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #f8f9fa; font-weight: bold; color: #1a2238; }
        tr:hover { background: #f9f9f9; }
        .stat-box { display: inline-block; margin: 10px 20px 10px 0; padding: 15px; background: #f0f4f8; border-radius: 5px; }
        .stat-value { font-size: 24px; font-weight: bold; color: #3b82f6; }
        .stat-label { font-size: 12px; color: #666; }
        .critical { color: #dc2626; }
        .high { color: #ea580c; }
        .warning { color: #f59e0b; }
        .info { color: #3b82f6; }
        .timestamp { font-size: 12px; color: #999; margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 Drishti Nexus Security Report</h1>
        <p><strong>Generated:</strong> ${new Date().toLocaleString()}</p>
`;
    
    if (data.statistics) {
        html += `
        <h2>Statistics</h2>
        <div class="stat-box">
            <div class="stat-label">Total Logs</div>
            <div class="stat-value">${data.statistics.totalLogs.toLocaleString()}</div>
        </div>
        <div class="stat-box">
            <div class="stat-label">Total Alerts</div>
            <div class="stat-value" style="color: #f59e0b;">${data.statistics.totalAlerts.toLocaleString()}</div>
        </div>
        <div class="stat-box">
            <div class="stat-label critical">Critical</div>
            <div class="stat-value critical">${data.statistics.critical}</div>
        </div>
        <div class="stat-box">
            <div class="stat-label high">High Priority</div>
            <div class="stat-value high">${data.statistics.high}</div>
        </div>
`;
    }
    
    if (data.alerts && data.alerts.length > 0) {
        html += `
        <h2>Security Alerts</h2>
        <table>
            <thead>
                <tr>
                    <th>Timestamp</th>
                    <th>Rule</th>
                    <th>Severity</th>
                    <th>Description</th>
                </tr>
            </thead>
            <tbody>
`;
        data.alerts.forEach(alert => {
            const severityClass = alert.severity.toLowerCase();
            html += `
                <tr>
                    <td>${alert.timestamp}</td>
                    <td>${escapeHtml(alert.rule)}</td>
                    <td><span class="${severityClass}">${alert.severity}</span></td>
                    <td>${escapeHtml(alert.description)}</td>
                </tr>
`;
        });
        html += `
            </tbody>
        </table>
`;
    }
    
    if (data.logs && data.logs.length > 0) {
        html += `
        <h2>Log Entries</h2>
        <table>
            <thead>
                <tr>
                    <th>Timestamp</th>
                    <th>Severity</th>
                    <th>Source</th>
                    <th>Message</th>
                </tr>
            </thead>
            <tbody>
`;
        data.logs.slice(0, 500).forEach(log => {
            const severityClass = log.severity.toLowerCase();
            html += `
                <tr>
                    <td>${log.timestamp}</td>
                    <td><span class="${severityClass}">${log.severity}</span></td>
                    <td>${escapeHtml(log.source)}</td>
                    <td>${escapeHtml(log.message)}</td>
                </tr>
`;
        });
        html += `
            </tbody>
        </table>
`;
    }
    
    html += `
        <p class="timestamp">This report was automatically generated by Drishti Nexus</p>
    </div>
</body>
</html>
`;
    return html;
}

function downloadFile(content, fileName, mimeType) {
    const blob = new Blob([content], { type: mimeType });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = fileName;
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);
}

function exportLogs() {
    const csv = generateCSVReport({ logs: allLogs.map(log => ({
        timestamp: log.timestamp,
        severity: getSeverityName(log.severity),
        source: log.source,
        message: log.message
    })) });
    
    downloadFile(csv, `logs-export-${new Date().toISOString().split('T')[0]}.csv`, 'text/csv');
}

// Close modal when clicking outside
document.addEventListener('click', (event) => {
    const modal = document.getElementById('reportModal');
    if (event.target === modal) {
        closeReportModal();
    }
});