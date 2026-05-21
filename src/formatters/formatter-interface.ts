import { ScanResult } from '../core/scanner-interface';
import { ScanSummary } from '../core/result';

export interface Formatter {
  format(results: string): string;
  formatResults(results: ScanResult[], summary: ScanSummary): string;
}

export enum FormatterType {
  Console = 'console',
  JSON = 'json',
  Markdown = 'markdown',
  HTML = 'html',
  SARIF = 'sarif',
}
