import chalk from 'chalk';
import { Formatter } from './formatter-interface';
import { FormatterType } from './formatter-interface';
import { ScanResult } from '../core/scanner-interface';
import { ScanSummary } from '../core/result';
import { SEVERITY_CONFIGS, Severity } from '../core/severity';

export class ConsoleFormatter implements Formatter {
  private useColors: boolean;

  constructor(useColors: boolean = true) {
    this.useColors = useColors;
  }

  getType(): FormatterType {
    return FormatterType.Console;
  }

  format(results: string): string {
    if (!this.useColors) {
      return results;
    }

    return this.applyColorCoding(results);
  }

  formatResults(results: ScanResult[], summary: ScanSummary): string {
    const lines: string[] = [];

    lines.push(this.formatHeader(summary));
    lines.push('');

    if (results.length === 0) {
      lines.push(chalk.green('No security issues found!'));
      return lines.join('\n');
    }

    lines.push(this.formatResultsBySeverity(results));
    lines.push('');

    lines.push(this.formatSummary(summary));

    return lines.join('\n');
  }

  private applyColorCoding(text: string): string {
    let colored = text;

    colored = colored.replace(/\[INFO\]/g, chalk.blue('[INFO]'));
    colored = colored.replace(/\[LOW\]/g, chalk.cyan('[LOW]'));
    colored = colored.replace(/\[MEDIUM\]/g, chalk.yellow('[MEDIUM]'));
    colored = colored.replace(/\[HIGH\]/g, chalk.hex('#FFA500')('[HIGH]'));
    colored = colored.replace(/\[CRITICAL\]/g, chalk.red('[CRITICAL]'));
    colored = colored.replace(/\[ERROR\]/g, chalk.bold.red('[ERROR]'));
    colored = colored.replace(/\[SUCCESS\]/g, chalk.green('[SUCCESS]'));
    colored = colored.replace(/\[WARNING\]/g, chalk.yellow('[WARNING]'));
    colored = colored.replace(/\[DEBUG\]/g, chalk.gray('[DEBUG]'));

    colored = colored.replace(/Error: .*/g, (match) => chalk.red.bold(match));
    colored = colored.replace(/Warning: .*/g, (match) => chalk.yellow(match));
    colored = colored.replace(/Success: .*/g, (match) => chalk.green.bold(match));

    return colored;
  }

  formatSimpleSummary(filesScanned: number, issuesFound: number, durationMs: number): string {
    const duration = (durationMs / 1000).toFixed(2);
    return this.format(
      `\n${chalk.bold.cyan('=== Scan Summary ===')}\n` +
        `Files scanned: ${chalk.green(filesScanned.toString())}\n` +
        `Issues found: ${issuesFound > 0 ? chalk.red(issuesFound.toString()) : chalk.green(issuesFound.toString())}\n` +
        `Duration: ${chalk.gray(duration + 's')}\n`
    );
  }

  formatIssue(file: string, line: number, severity: string, message: string): string {
    const severityUpper = severity.toUpperCase();
    let severityColor: (text: string) => string;

    switch (severityUpper) {
      case 'CRITICAL':
        severityColor = chalk.red.bold;
        break;
      case 'HIGH':
        severityColor = chalk.hex('#FFA500').bold;
        break;
      case 'MEDIUM':
        severityColor = chalk.yellow.bold;
        break;
      case 'LOW':
        severityColor = chalk.cyan.bold;
        break;
      case 'INFO':
        severityColor = chalk.blue.bold;
        break;
      default:
        severityColor = chalk.white.bold;
    }

    const fileLocation = this.useColors ? chalk.gray(`${file}:${line}`) : `${file}:${line}`;

    const severityLabel = this.useColors
      ? severityColor(`[${severityUpper}]`)
      : `[${severityUpper}]`;

    return `${fileLocation} ${severityLabel} ${message}`;
  }

  enableColors(enabled: boolean): void {
    this.useColors = enabled;
  }

  isColorsEnabled(): boolean {
    return this.useColors;
  }

  private formatHeader(summary: ScanSummary): string {
    const duration = (summary.scanDurationMs / 1000).toFixed(2);
    return chalk.bold(`Scan Complete - ${summary.totalFilesScanned} files scanned in ${duration}s`);
  }

  private formatResultsBySeverity(results: ScanResult[]): string {
    const lines: string[] = [];
    const sortedResults = this.sortBySeverity(results);

    for (const result of sortedResults) {
      lines.push(this.formatResult(result));
      lines.push('');
    }

    return lines.join('\n');
  }

  private formatResult(result: ScanResult): string {
    const config = SEVERITY_CONFIGS[result.severity];
    const color = this.getChalkColor(config.color);

    const lines = [
      `${color(config.icon)} ${result.category} [${result.severity.toUpperCase()}]`,
      chalk.gray(`  ${result.filePath}:${result.lineNumber}`),
      chalk.white(`  ${result.description}`),
    ];

    if (result.evidence) {
      lines.push(chalk.gray(`  Evidence: ${this.truncate(result.evidence, 80)}`));
    }

    if (result.suggestion) {
      lines.push(chalk.cyan(`  ${result.suggestion}`));
    }

    return lines.join('\n');
  }

  private formatSummary(summary: ScanSummary): string {
    const lines: string[] = [];
    lines.push(chalk.bold('Summary:'));

    for (const [severity, count] of Object.entries(summary.issuesBySeverity)) {
      if (count > 0) {
        const config = SEVERITY_CONFIGS[severity as Severity];
        const color = this.getChalkColor(config.color);
        lines.push(`  ${color(config.icon)} ${severity}: ${count}`);
      }
    }

    lines.push(chalk.gray(`  Files scanned: ${summary.totalFilesScanned}`));
    lines.push(chalk.gray(`  Total issues: ${summary.totalIssuesFound}`));

    return lines.join('\n');
  }

  private sortBySeverity(results: ScanResult[]): ScanResult[] {
    return [...results].sort((a, b) => {
      return SEVERITY_CONFIGS[b.severity].score - SEVERITY_CONFIGS[a.severity].score;
    });
  }

  private getChalkColor(color: string): chalk.Chalk {
    switch (color) {
      case 'red':
        return chalk.red;
      case 'orange':
        return chalk.hex('#FFA500');
      case 'yellow':
        return chalk.yellow;
      case 'cyan':
        return chalk.cyan;
      case 'blue':
        return chalk.blue;
      default:
        return chalk.white;
    }
  }

  private truncate(str: string, maxLength: number): string {
    if (str.length <= maxLength) return str;
    return str.substring(0, maxLength - 3) + '...';
  }
}
