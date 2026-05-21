import { Formatter } from './formatter-interface';
import { FormatterType } from './formatter-interface';
import { ScanResult } from '../core/scanner-interface';
import { ScanSummary } from '../core/result';

export class JSONFormatter implements Formatter {
  readonly name = 'JSON Formatter';

  getType(): FormatterType {
    return FormatterType.JSON;
  }

  format(results: string): string {
    return results;
  }

  formatResults(results: ScanResult[], summary: ScanSummary): string {
    const output = {
      version: '0.0.1',
      timestamp: new Date().toISOString(),
      summary: {
        totalFilesScanned: summary.totalFilesScanned,
        totalIssuesFound: summary.totalIssuesFound,
        issuesBySeverity: summary.issuesBySeverity,
        issuesByCategory: summary.issuesByCategory,
        scanDurationMs: summary.scanDurationMs,
      },
      results: results.map((r) => ({
        id: r.id,
        filePath: r.filePath,
        lineNumber: r.lineNumber,
        severity: r.severity,
        category: r.category,
        description: r.description,
        evidence: r.evidence,
        suggestion: r.suggestion,
        scannerType: r.scannerType,
      })),
    };

    return JSON.stringify(output, null, 2);
  }
}
