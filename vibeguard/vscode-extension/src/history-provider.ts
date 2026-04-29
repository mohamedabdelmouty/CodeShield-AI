import * as vscode from 'vscode';

export interface ScanHistoryEntry {
    timestamp: string;
    target: string;
    score: number;
    grade: string;
    issueCount: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
}

export class VulnerabilityHistoryProvider {
    private static readonly STORAGE_KEY = 'vibeguard.scanHistory';
    private static readonly MAX_ENTRIES = 50;

    constructor(private readonly context: vscode.ExtensionContext) {}

    /** Add a new scan result to history. */
    addEntry(entry: ScanHistoryEntry): void {
        const history = this.getHistory();
        history.unshift(entry); // newest first
        if (history.length > VulnerabilityHistoryProvider.MAX_ENTRIES) {
            history.pop();
        }
        this.context.globalState.update(VulnerabilityHistoryProvider.STORAGE_KEY, history);
    }

    /** Retrieve all stored scan history entries. */
    getHistory(): ScanHistoryEntry[] {
        return this.context.globalState.get<ScanHistoryEntry[]>(
            VulnerabilityHistoryProvider.STORAGE_KEY, []
        );
    }

    /** Clear all history. */
    clearHistory(): void {
        this.context.globalState.update(VulnerabilityHistoryProvider.STORAGE_KEY, []);
    }

    /** Get the last N entries for chart display. */
    getRecentEntries(n: number = 10): ScanHistoryEntry[] {
        return this.getHistory().slice(0, n).reverse(); // chronological for chart
    }

    /** Generate a history report webview HTML. */
    getHistoryHtml(): string {
        const entries = this.getRecentEntries(20);
        const labels = JSON.stringify(entries.map(e => e.timestamp.slice(0, 16)));
        const scores = JSON.stringify(entries.map(e => e.score));

        const rows = [...this.getHistory()].slice(0, 30).map(e => `
            <tr>
                <td class="mono">${e.timestamp}</td>
                <td class="target">${escHtml(e.target)}</td>
                <td class="score" style="color:${scoreColor(e.score)}">${e.score}</td>
                <td><span class="grade" style="color:${scoreColor(e.score)}">${e.grade}</span></td>
                <td>${e.issueCount}</td>
                <td class="crit">${e.critical}</td>
                <td class="high">${e.high}</td>
            </tr>`).join('');

        return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <title>VibeGuard Scan History</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
  <style>
    :root{--bg:#0d1117;--surface:#161b22;--border:#30363d;--text:#e6edf3;--muted:#7d8590;--accent:#58a6ff;}
    body{background:var(--bg);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;font-size:13px;padding:24px;margin:0;}
    h1{font-size:20px;font-weight:700;margin-bottom:24px;}
    .chart-wrap{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:20px;margin-bottom:24px;}
    table{width:100%;border-collapse:collapse;}
    th{text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:.8px;color:var(--muted);padding:8px 12px;border-bottom:1px solid var(--border);}
    td{padding:8px 12px;border-bottom:1px solid #1c2128;}
    tr:hover td{background:rgba(255,255,255,.03);}
    .mono{font-family:'Courier New',monospace;font-size:11px;color:var(--muted);}
    .target{max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
    .score{font-weight:700;font-size:16px;}
    .grade{font-weight:800;font-size:13px;}
    .crit{color:#ff4757;} .high{color:#ff6b6b;}
    .empty{text-align:center;padding:48px;color:var(--muted);}
    .clear-btn{background:rgba(255,71,87,.15);border:1px solid rgba(255,71,87,.3);color:#ff4757;padding:6px 14px;border-radius:6px;cursor:pointer;font-size:12px;float:right;}
  </style>
</head>
<body>
  <h1>🛡️ VibeGuard Scan History
    <button class="clear-btn" onclick="clearHistory()">Clear History</button>
  </h1>
  <div class="chart-wrap">
    <canvas id="historyChart" height="120"></canvas>
  </div>
  ${rows ? `<table><thead><tr><th>Time</th><th>Target</th><th>Score</th><th>Grade</th><th>Issues</th><th>Critical</th><th>High</th></tr></thead><tbody>${rows}</tbody></table>` : '<div class="empty">No scan history yet. Run a scan to start tracking.</div>'}
  <script>
    const vscode = acquireVsCodeApi();
    const labels = ${labels};
    const scores = ${scores};
    if(labels.length){
      new Chart(document.getElementById('historyChart'),{
        type:'line',
        data:{
          labels,
          datasets:[{label:'Security Score',data:scores,borderColor:'#58a6ff',backgroundColor:'rgba(88,166,255,.1)',tension:.4,fill:true,pointBackgroundColor:'#58a6ff',pointRadius:4}]
        },
        options:{
          responsive:true,plugins:{legend:{labels:{color:'#7d8590'}}},
          scales:{
            x:{ticks:{color:'#7d8590',font:{size:10}},grid:{color:'rgba(255,255,255,.05)'}},
            y:{min:0,max:100,ticks:{color:'#7d8590'},grid:{color:'rgba(255,255,255,.05)'}}
          }
        }
      });
    }
    function clearHistory(){ vscode.postMessage({command:'clearHistory'}); }
  </script>
</body>
</html>`;
    }
}

function escHtml(s: string): string {
    return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

function scoreColor(score: number): string {
    return score >= 75 ? '#69db7c' : score >= 50 ? '#ffd43b' : '#ff4757';
}
