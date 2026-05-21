import { Formatter } from './formatter-interface';
import { FormatterType } from './formatter-interface';
import { ScanResult } from '../core/scanner-interface';
import { ScanSummary } from '../core/result';
import { Severity } from '../core/severity';

export class HTMLFormatter implements Formatter {
  readonly name = 'HTML Formatter';

  getType(): FormatterType {
    return FormatterType.HTML;
  }

  format(results: string): string {
    return results;
  }

  formatResults(results: ScanResult[], summary: ScanSummary): string {
    const duration = (summary.scanDurationMs / 1000).toFixed(2);

    const severityColors: Record<Severity, string> = {
      [Severity.Info]: '#3b82f6',
      [Severity.Low]: '#06b6d4',
      [Severity.Medium]: '#eab308',
      [Severity.High]: '#f97316',
      [Severity.Critical]: '#ef4444',
    };

    const resultsHTML = results
      .map((result) => {
        const color = severityColors[result.severity];
        return `
        <div class="result" style="border-left: 4px solid ${color}">
          <div class="result-header">
            <span class="category">${result.category}</span>
            <span class="severity" style="color: ${color}">${result.severity.toUpperCase()}</span>
          </div>
          <div class="location">${result.filePath}:${result.lineNumber}</div>
          <div class="description">${result.description}</div>
          ${result.evidence ? `<div class="evidence"><code>${this.escapeHtml(result.evidence)}</code></div>` : ''}
          ${result.suggestion ? `<div class="suggestion">💡 ${result.suggestion}</div>` : ''}
        </div>
      `;
      })
      .join('');

    const summaryHTML = Object.entries(summary.issuesBySeverity)
      .filter(([_, count]) => count > 0)
      .map(([severity, count]) => {
        const color = severityColors[severity as Severity];
        return `<li style="color: ${color}">${severity}: ${count}</li>`;
      })
      .join('');

    return `<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>AIAgentAntivirus Scan Report</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; background: #f8fafc; }
    .container { background: white; border-radius: 8px; padding: 30px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
    h1 { color: #1e293b; margin-bottom: 5px; }
    .meta { color: #64748b; font-size: 14px; margin-bottom: 30px; }
    .summary { background: #f1f5f9; padding: 20px; border-radius: 6px; margin-bottom: 30px; }
    .summary h2 { margin-top: 0; }
    .summary ul { list-style: none; padding: 0; margin: 0; }
    .summary li { padding: 8px 0; }
    .result { background: #f8fafc; padding: 20px; margin-bottom: 16px; border-radius: 6px; padding-left: 16px; }
    .result-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }
    .category { font-weight: 600; color: #1e293b; }
    .severity { font-weight: 600; text-transform: uppercase; font-size: 12px; }
    .location { color: #64748b; font-size: 13px; margin-bottom: 8px; }
    .description { margin-bottom: 8px; }
    .evidence { background: #1e293b; padding: 12px; border-radius: 4px; margin: 8px 0; overflow-x: auto; }
    .evidence code { color: #e2e8f0; font-size: 13px; }
    .suggestion { color: #0891b2; font-style: italic; }
    .no-results { text-align: center; padding: 40px; color: #10b981; font-size: 18px; }
  </style>
</head>
<body>
  <div class="container">
    <h1>🔍 AIAgentAntivirus Scan Report</h1>
    <div class="meta">Generated: ${new Date().toLocaleString()}</div>

    <div class="summary">
      <h2>📊 Summary</h2>
      <ul>
        <li>Files scanned: ${summary.totalFilesScanned}</li>
        <li>Total issues: ${summary.totalIssuesFound}</li>
        <li>Duration: ${duration}s</li>
      </ul>
      <ul>${summaryHTML}</ul>
    </div>

    ${
      results.length === 0
        ? '<div class="no-results">✓ No security issues found!</div>'
        : resultsHTML
    }
  </div>
</body>
</html>`;
  }

  private escapeHtml(text: string): string {
    return text
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }
}
