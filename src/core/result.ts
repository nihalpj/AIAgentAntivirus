import { ScanResult } from './scanner-interface';
import { Severity } from './severity';

export interface ScanSummary {
  totalFilesScanned: number;
  totalIssuesFound: number;
  issuesBySeverity: Partial<Record<Severity, number>>;
  issuesByCategory: Record<string, number>;
  scanDurationMs: number;
}

export interface ScanOutput {
  results: ScanResult[];
  summary: ScanSummary;
  exitCode: number;
}

export class ResultAggregator {
  private results: ScanResult[] = [];

  add(result: ScanResult): void {
    this.results.push(result);
  }

  addAll(results: ScanResult[]): void {
    this.results.push(...results);
  }

  getResults(): ScanResult[] {
    return [...this.results];
  }

  getSummary(filesScanned: number, durationMs: number): ScanSummary {
    const issuesBySeverity = this.groupBySeverity();
    const issuesByCategory = this.groupByCategory();

    return {
      totalFilesScanned: filesScanned,
      totalIssuesFound: this.results.length,
      issuesBySeverity,
      issuesByCategory,
      scanDurationMs: durationMs
    };
  }

  getExitCode(): number {
    if (this.results.some(r => r.severity === Severity.Critical)) {
      return 2;
    }
    if (this.results.length > 0) {
      return 1;
    }
    return 0;
  }

  private groupBySeverity(): Record<string, number> {
    return this.results.reduce((acc, result) => {
      const severity = result.severity as string;
      acc[severity] = (acc[severity] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);
  }

  private groupByCategory(): Record<string, number> {
    return this.results.reduce((acc, result) => {
      acc[result.category] = (acc[result.category] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);
  }
}